# 0036 — Predictive matching, version 0

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review; it returned accept-with-changes for the set of eight and the changes
are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted against the maintainer's scope
> decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification at the
> maintainer's delegation. The review's
> findings folded into this ADR: station-local period stamps, integer widening and the scoring instant are stated.
> Implementation tickets are written against this ratified text.

## Context

The design overview names predictive matching a selected core feature (§9.4):
rather than waiting for a listing and a need to coincide, the platform "models
community production cycles and proactively surfaces trade opportunities." It
is a Phase 3 deliverable ("first version, basic surplus/needs correlation") and
one of the four Phase 3 exit criteria (§12): *predictive matching surfaces at
least one trade that would not have happened through manual search.*

Three forces shape what "version 0" can honestly be:

- **Everything derived must be re-derivable** (repository conventions; ADR-0009's posture
  for reputation). A suggestion is advice, not a fact on the log, but an
  organizer will act on it, so two stations holding the same inputs must
  produce the same list, and a reader must be able to see *why* a match was
  surfaced. A learned model cannot offer that: its output is not a function of
  the log anyone can replay.
- **The only cross-community data that exists is what federation carries.**
  Under [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md)
  a partner sees this community's `federation_visible` listings and its
  announced needs, cached from federation bundles — and nothing else. There is
  no location data anywhere in the system (§9.4's "geographic proximity"
  ranking has no input), and a Trade-depth partner has no standing for our
  members (only Recognition depth carries portable histories).
- **The station is a Pi.** A nightly pass over a few thousand records is fine;
  a model that needs training is not, and the project has no labelled outcome
  data to train one on anyway.

The maintainer's decision is a **deterministic correlation** over the records
that already exist, exposed as a cache, with no learning component
**(maintainer decision, 2026-09-23)**. This ADR fixes the algorithm precisely
enough that two implementations agree byte-for-byte on the ordering of
suggestions, and states what the exit criterion measures.

## Decision

**Predictive matching v0 is a pure function from the marketplace records a
station holds — its own log's listings and needs plus the `foreign_listings`
and `foreign_needs` caches federation fills — to a bounded, ranked list of
`MatchSuggestion`s, computed by a sweep into a cache table, read over an
organizer-facing RPC and CLI command, never signed and never logged.** Eight
sub-decisions follow.

### 1. Inputs come through a trait; `rrn-marketplace` gains no federation dependency

The algorithm lives in `rrn-marketplace::matching` and reads its inputs
through a `MatchingSource` trait the station implements:

```rust
pub trait MatchingSource {
    /// This community's identity (the genesis charter hash, ADR-0029; the
    /// `CommunityId` newtype lives in `rrn-storage`, below this crate).
    fn home(&self) -> CommunityId;
    /// Every listing the station holds, home and foreign, with provenance.
    fn listings(&self) -> Result<Vec<SourcedListing>>;
    /// Every announced need, home and foreign, with provenance.
    fn needs(&self) -> Result<Vec<SourcedNeed>>;
    /// Communities reachable for trade from `a`: `Some(depth)` when an Active
    /// treaty of at least Trade depth exists between `a` and `b` (ADR-0030),
    /// `Some(TreatyDepth::Same)` when `a == b`, else `None`. `TreatyDepth` is
    /// ADR-0030's depth enum (`Trade | Recognition`) plus a `Same` sentinel that
    /// exists only inside matching; it is never a treaty field.
    fn treaty_depth(&self, a: &CommunityId, b: &CommunityId) -> Option<TreatyDepth>;
    /// Composite standing of a provider, if this station has one: from the
    /// home scorer for home members, from `foreign_standing` (ADR-0032) for
    /// foreign members. `None` when unknown.
    /// Scored at the run's `computed_at` (§3) for home members; the cached
    /// profile as verified for foreign members.
    fn composite_of(&self, provider: &Address, community: &CommunityId) -> Option<f32>;
    /// Settled transactions between two communities in a category over the
    /// trailing twelve months, from settlement records linked to a listing.
    fn settled_between(&self, a: &CommunityId, b: &CommunityId, category: &str) -> u64;
    /// Whether any inquiry or transaction ever linked a provider in `supplier`
    /// to a seeker in `demander` in `category` (the novelty test, §6).
    fn prior_contact(&self, supplier: &CommunityId, demander: &CommunityId, category: &str) -> bool;
}
```

`SourcedListing { listing: Listing, community: CommunityId, received_at: i64 }`
and `SourcedNeed { need: Need, community: CommunityId, received_at: i64 }`.
`received_at` is the **local admission time** for a home record (the log
entry's `created_at`, ADR-0022 — station-local, re-stamped on a replica, so two
stations may bucket the same record into adjacent periods; consistent with
suggestions being never authoritative) and the **local cache-receipt time** for a
foreign record (when this station accepted it from a federation bundle). No
timestamp inside a signed record is read: `created_at` on a listing and
`valid_until` on a need are testimony (ADR-0022 §3) and stay out of the
arithmetic. The trait keeps the crate layering intact: `rrn-marketplace`
stays below `rrn-federation`, and the station wires the caches in.

### 2. Period, supply, and demand are integer aggregates per calendar month

- A **period** is a calendar month in UTC, keyed `(year, month)`; a record's
  period is the month of its `received_at`.
- For each `(community, category, period)`:
  - `supply` = Σ over listings of that community, category and period of
    `availability.capacity.unwrap_or(1)`, counting a listing with
    `availability.status == Unavailable` as `0`. `None` capacity is "unlimited"
    on a listing but counts as one unit of supply here — a listing is evidence
    of *production*, not a promise of volume.
  - `demand` = Σ over needs of that community, category and period of
    `quantity_needed`.
- Only listings with `federation_visible = true` and only announced needs
  contribute to a *cross-community* match; a home-only listing feeds only
  same-community matches. Closed listings (`listing_closed`) and needs past
  their `valid_until` **as judged by admission order** — i.e. a need superseded
  by a later need from the same seeker, or closed by the sweep — still count
  for the period in which they were received: history is what the projection
  is built from.

All of this is `u64` arithmetic (`capacity` is `Option<u32>` and
`quantity_needed` is `u32` in the records; the aggregates widen). The category
set is the fixed `CATEGORIES`
list (eight values), so the aggregate table is small: communities × 8 ×
months.

### 3. Projection is "same month last year, else trailing three-month mean"

For a target period `T` (the month after the one containing `computed_at`)
and each `(community, category)`:

```
present(c, cat, p)      := at least one listing or need of (c, cat) was received in p
projected_supply(c,cat) :=
    if present(c, cat, T − 12 months) then supply(c, cat, T − 12 months)
    else floor( (supply(c,cat,T−1) + supply(c,cat,T−2) + supply(c,cat,T−3)) / 3 )
projected_demand        := the same rule over demand
```

Integer division floors. A community with no records at all in the three
trailing months and none a year ago projects `0` and never matches. This is
deliberately crude: it captures "Valley Farm posts grain every September"
(the same-month rule) and "Blue Ridge has been posting timber lately" (the
trailing mean), which is exactly the §9.4 sketch and nothing more.

### 4. A match is a supplier community, a demander community, and a category

A candidate `(S, D, cat)` is a **match** iff:

- `projected_supply(S, cat) > 0` and `projected_demand(D, cat) > 0`, and
- `S == D`, or `treaty_depth(S, D)` is `Some(Trade | Recognition)` — an
  **Active** treaty (ADR-0030 state machine); a Suspended or Terminated
  treaty yields no cross-community match.

Same-community matches are included so the feature is useful to a lone
community before it federates, and so the three-community exit harness can
compare the two.

### 5. Score: treaty depth × provider standing × trade history

Scores are `f64`, computed from integers and a bounded standing input, and
**never signed or logged** (invariant 8 of the federation spine).

```
depth_weight(S, D) := 1.0 if S == D
                      1.0 if treaty depth is Recognition
                      0.7 if treaty depth is Trade

standing_factor(S, cat) :=
    let composites = for each distinct provider P of a contributing listing of
                     (S, cat) in the source periods of §3:
                       composite_of(P, S).unwrap_or(1.0)   -- at computed_at
    mean(composites) / 5.0                      -- in (0, 1]

history_factor(S, D, cat) :=
    let n = settled_between(S, D, cat)          -- u64, trailing 12 months
    1.0 + min(3, bit_length(1 + n) − 1) as f64  -- integer floor(log2(1+n)), capped at 3

score := depth_weight × standing_factor × history_factor   -- in (0, 4]
```

`unwrap_or(1.0)` is the stated prior for a provider whose standing this
station does not hold — every foreign provider under a Trade-depth treaty, and
any home member the scorer has not anchored. `1.0` is the ADR-0009 anchoring
cap per dimension: an unknown provider is ranked like an unanchored one, not
like nobody. `bit_length(x) − 1` is `floor(log2 x)` computed on integers, so
no platform's `log2` rounding can reorder two stations' lists. Every
`DIMENSION_MAX` (5.0) and weight referenced is the locked ADR-0009 constant.

### 6. Output: a bounded, deterministically ordered list with provenance and a novelty flag

```rust
pub struct MatchSuggestion {
    pub supplier_community: CommunityId,
    pub demander_community: CommunityId,
    pub category: String,             // one of CATEGORIES
    pub period: (i32, u8),            // target month T
    pub projected_supply: u64,
    pub projected_demand: u64,
    pub score: f64,
    pub novel: bool,                  // §6 below
    pub evidence: Vec<Hash>,          // content hashes of every listing/need record that
                                      // contributed to the two projections, in log/cache order
    pub source_staleness: Vec<(CommunityId, i64)>, // newest received_at per foreign community used
}

pub struct MatchReport {
    pub computed_at: i64,             // the sweep's admission-clock instant
    pub home: CommunityId,
    pub suggestions: Vec<MatchSuggestion>,   // ≤ MAX_SUGGESTIONS = 200
}
```

Ordering is total and reproducible: by `score` descending, then
`supplier_community` bytes, then `demander_community` bytes, then `category`
bytes. Ties in `f64` are exact because the inputs are the same integers.

**`novel`** is the exit-criterion predicate: `true` iff
`prior_contact(S, D, cat)` is false — no inquiry, settled transaction, or
service contract has ever linked a provider in `S` to a seeker in `D` in that
category, on this station's log or in its federation caches, before
`computed_at`. A suggestion with `novel = true` that is later followed by a
settled cross-community transaction in that category is what "surfaces a trade
that would not have happened through manual search" *means* for the Phase 3
exit statement; the exit harness records the suggestion's `evidence` hashes
and the later settlement hash side by side.

**Provenance and staleness** are part of the output, not a footnote, because
two stations *will* disagree: a foreign cache reflects what federation
carriage has delivered so far, which differs per station and per carrier
delay. Given identical inputs the function is bit-identical (it is a pure
function of `MatchingSource` and `computed_at`); given different caches it is
identical up to the missing records, and `source_staleness` tells the reader
how old each foreign community's contribution is. A suggestion is never
authoritative and no station ever asks another to agree on one.

### 7. Where it lives: a cache table, a sweep, an RPC, a CLI command

- `match_suggestions` — a station-local cache table (documented as such,
  rebuilt from scratch on every run; never a log record). Rows are the
  serialized `MatchReport`.
- A sweep, `matching_refresh_interval_secs` (default 86 400 — once a day),
  recomputes the report on the single-writer core thread with the injected
  clock; `rrn marketplace forecast --refresh` forces a run.
- RPC `marketplace_forecast { period?, community?, category?, limit?,
  novel_only? }` returns the filtered report. It is an **organizer** surface
  on the operator socket and the member channel alike (read-only on the member
  channel: the request is still a signed ADR-0008 envelope, but it writes nothing).
- CLI `rrn marketplace forecast [--category cat] [--community rrnc1…]
  [--novel] [--limit n] [--refresh]`, and `rrn wallet forecast` for a paired
  member wallet reading the same RPC.
- Mobile: the FFI needs nothing (no signing, no verification); a "Trade
  forecast" screen is a later mobile ticket reading `marketplace_forecast`.

### 8. Non-goals, stated so nobody fills them in quietly

Not in v0, deferred to Phase 4 (design overview §12 "advanced predictive
matching"): machine learning of any kind; seasonal modelling beyond the
same-month rule; geographic proximity (no location data exists and none is
added — adding it is a privacy decision for its own ADR); price modelling
(`max_price_centi` and `pricing` are ignored); ranking by individual seeker;
push notifications; and any signed or gossiped suggestion. A community's
projected *shortage* is computed but never exported — the report is read
locally; a partner sees only the needs it was already sent.

## Consequences

- **Reproducible advice.** Two stations with the same caches produce the same
  report; a reader can follow `evidence` back to the records and recompute
  the score by hand. That is the property a replay-everything system owes
  even to its non-authoritative outputs.
- **Honest about its crudeness.** Same-month-last-year plus a trailing mean
  will miss a first-time surplus and over-trust a one-off spike. The ranking
  is a starting point for a trade coordinator's conversation, not a plan; the
  organizer docs must say so.
- **Trade-depth partners rank lower than Recognition partners, twice.** Once
  through `depth_weight` (0.7) and again because their providers' standing is
  unknown and takes the 1.0 prior. That is intended: a deeper treaty carries
  more information, and the score says so rather than pretending otherwise.
- **The exit criterion becomes measurable.** `novel` plus a later settlement
  is a concrete, log-checkable event the three-community harness (Phase 3
  exit) can assert, instead of a judgement call.
- **Marketplace metadata leaks across the boundary — as it already does.**
  Matching adds no new export; it reads what ADR-0032 already carries. But it
  makes the *aggregate* legible: a partner who receives our needs can run the
  same arithmetic and infer our projected shortage by category. That is a
  consequence of announcing needs at all, and the threat-model entry says so.
- **Follow-up work.** A `MatchingSource` implementation in the station over
  the log plus the ADR-0032 caches; the sweep timer; the RPC/CLI; the
  organizer runbook page; the threat-model section (below); and the exit
  harness assertion.

### Threat-model obligations (for the implementation ticket)

`rrn-marketplace::matching` section: **steering by spam** — a member (or a
partner community's member) who floods listings or needs in a category moves
the projections; mitigations are the existing per-record signature and
membership gates, listing-length/expiry sweeps, the `federation_visible`
opt-in, and the fact that a suggestion moves no credit — residual: no rate
limit (a standing Phase 2 residual). **Shortage inference** — announced needs
reveal projected scarcity to every treaty partner; mitigation is that needs
are member-authored and optional, and the report is never exported;
residual: aggregate inference from records a community chose to publish.
**Cache poisoning** — a foreign listing or need enters only through
federation ingest (partner-writer outbox chain, ADR-0029), so a forged record
needs a partner writer key; residual: a hostile partner can inflate its own
supply, which affects only suggestions naming it.

## Alternatives Considered

- **A learned model (regression or collaborative filtering over trade
  history).** Rejected for v0: not replayable, no training data at pilot
  scale, and unrunnable on the target hardware without a second runtime. The
  overview places it in Phase 4.
- **Gravity-style scoring with distance.** Rejected: no location data exists;
  introducing it is a privacy decision, not a matching one.
- **Signing and gossiping suggestions between stations.** Rejected: a
  suggestion is derived, non-authoritative advice; putting it on the wire
  invites treating it as a fact and adds a record kind with no verifier.
- **Ranking by price fit (`max_price_centi` vs `pricing`).** Deferred: prices
  are negotiable per listing and cross-community price discovery is exactly
  what the inquiry flow exists for; a v0 that pre-judged price would mislead
  more than it helps.
- **Rolling 30-day windows instead of calendar months.** Rejected: calendar
  months make "same month last year" exact and the tables human-readable;
  the precision a rolling window adds is illusory at this data volume.

## References

- Design overview §9.4 "Predictive Matching", §12 Phase 3 deliverables and
  exit criteria, §12 Phase 4 "Advanced predictive matching"
- [ADR-0009](0009-universal-reputation-algorithm.md) — `DIMENSION_MAX`, the
  anchoring cap that sets the 1.0 prior, and the derived-never-stored posture
- [ADR-0010](0010-marketplace-data-model.md) — listings, needs, `CATEGORIES`,
  `federation_visible`
- [ADR-0022](0022-admission-clock-time-trust.md) — why periods key on local
  admission/receipt time, never on signed timestamps
- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) — `CommunityId`
  and federation ingest, the only path a foreign record takes into a cache
- [ADR-0030](0030-treaties-ratification-depth-lifecycle.md) — treaty depth and
  the Active state a cross-community match requires
- [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md)
  — the `foreign_listings`, `foreign_needs`, and `foreign_standing` caches
- [`docs/threat-model.md`](../threat-model.md) — to gain the section above
