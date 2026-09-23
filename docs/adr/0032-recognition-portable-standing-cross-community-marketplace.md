# 0032 — Recognition: portable standing across communities and the cross-community marketplace

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review; it returned accept-with-changes for the set of eight and the changes
are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted against the maintainer's scope
> decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification at the
> maintainer's delegation. The review's
> findings folded into this ADR: the Tier-4 validator's read of witness standing joins the exhaustive use list; `foreign_standing` is keyed by `(subject, home)`; the `min_reputation` conversion and the `to_seq` pin are stated.
> Implementation tickets are written against this ratified text.

## Context

A Recognition treaty (ADR-0030) is the second of the two treaty depths Phase 3
ships. The design overview (§8.4) says it adds, over a Trade treaty, "mutual
identity vouching recognized, reputation scores portable, citizens can apply for
residency in either community." The overview's §5.6 is precise about *how*
reputation travels: "as a signed history, not just a score … The universal
algorithm then produces the same score it would produce anywhere. No community
can inflate someone's reputation artificially."

Most of that machinery already exists, built for a federation that did not yet
exist. `rrn_reputation::portability` exports a `PortableReputationHistory` — every
log entry bearing on a member, in log order, under a writer-signed `HistoryRoot`
(kind `rrn.reputation.history_root.v1`) whose Merkle root commits to the
selection — and `verify_history` re-derives the profile by loading the entries
into a scratch in-memory log and running the ordinary scorer over it, at the
root's `computed_at`, so decay reproduces exactly. Since ADR-0009 locked one
formula for every station, the receiving station's replay and the exporting
station's are the same computation. What is missing is everything around it:

- `verify_history` checks the root's signature but takes **no expected signer**.
  The caller has to compare `signed_root.signer` to the partner's writer key or
  any key at all can vouch for a history. And the scratch replay's station-signed
  records (settlements, cancellations, certificate and equivocation records) are
  pinned, since the ledger signer-pinning work, to *a* station key — today the
  runtime key of whichever station is replaying, which is the wrong key for a
  foreign history. The pin has to be the *exporting* writer's key, and, once
  ADR-0035 lands, that key at each entry's position rather than one key forever.
- Nothing requests, answers, carries, or caches a history. There is no record for
  "please export what you hold about X," no payload kind to carry the answer, and
  no place to keep the verified result.
- The marketplace has two federation fields that are validated to `false`:
  `Listing.federation_visible` ("nothing honors it in Phase 1") and
  `Requirements.federation_only`. `Requirements.min_reputation` is evaluated
  against local standing only. There is no notion of a foreign listing, need, or
  inquirer.
- The community a listing or vouch names is a string — `Listing.community`,
  `VouchBody.community` — and in the station, the CLI wallet, and the
  cross-platform test it is the hard-coded constant `VOUCH_COMMUNITY =
  "rrn-phase0"`. The `Charter.community_id` string exists but nothing derives the
  running community's name from it, and the federation identity (ADR-0029) is the
  genesis charter hash, not any string.

Three maintainer decisions bound the design **(maintainer decision, 2026-09-23)**:

1. **Verify and score locally.** Under a Recognition treaty the partner station
   verifies the home writer's signed portable history and runs the universal
   algorithm on it locally; the result gates tiers and stakes for cross-community
   transactions. No residency, no membership on the foreign log.
2. **Trade and Recognition only.** Alliance and Full Federation, which carry
   residency and shared governance, are Phase 4.
3. **Federation-scoped exchange only.** Partner stations exchange profiles,
   treaties, cross-community transaction records, portable histories on demand,
   and treaty-state changes. Never full logs.

The forces to reconcile: reputation must stay derived, never asserted (ADR-0009);
one log, one writer (ADR-0020) — a foreign history is evidence *about* a member
of another community, not a record *of* this one; every window and freshness
judgment reads this station's clock (ADR-0022); and the overview's rejection of
"reputation inheritance" — a score does not transfer, evidence does.

## Decision

**A partner station recognizes a foreign member by re-deriving their standing
from the home writer's signed evidence, never by accepting a number, and it uses
that derived standing only at the marketplace and oracle boundaries where a
foreign party meets a local rule. Recognized standing is a cache about a
stranger, not membership: it never enters this community's electorate, its jury
or tribunal pools, or any of its own members' scores. Under a Trade treaty the
marketplace crosses the boundary — listings and needs travel as the member-signed
records they already are — and under a Recognition treaty the standing-bearing
gates on those listings can finally be evaluated against a foreign taker.**
Eight sub-decisions follow.

### 1. Portable histories are requested, answered, and carried as evidence

A history is fetched on demand, one subject at a time, across the ADR-0029
federation carriage:

| Kind | Signer | Fields |
|---|---|---|
| `rrn.fed.history_request` | requesting writer | `subject: Address`, `requested_by: CommunityId`, `nonce: [u8; 32]`, `requested_at: i64` |

The request rides the requesting station's federation outbox to the subject's
**home** writer (the community whose log holds the subject's vouches, per the
treaty under which the subject was encountered). The home writer answers with
`export_history_at(db, subject, writer_key, now)` — the existing export,
unchanged — carried back as payload kind **`0x03` PortableReputationHistory**.
The answer is **evidence, not a record**: it is never appended to either log. A
station may also hand a history to its own member for carriage on paper as
`PaperKind::History` (`'h'`) — the "letter of introduction" for a person, the
counterpart of the community profile for a community.

The request is a log record on the requester's log (so a replica can see what
was asked for, and so the partner's federation outbox chain proves it was or was
not answered) and is admitted on the home log as a foreign writer-signed record
under ADR-0029's carriage rules; like every writer-signed federation record it
carries `home_seq` (the requester's own log seq of the record, ADR-0029 §4), which
is what the home pins it against. A home writer answers at most one export per
`(subject, requested_by)` per `history_refresh_min_secs` (default 1 day) so a
partner cannot use requests as a replay-work amplifier; a repeat inside that
bound is answered from the last export.

### 2. Verification pins the exporting writer, lineage-aware

`verify_history` gains a required expected-signer parameter:

```rust
pub fn verify_history_from(
    history: &PortableReputationHistory,
    expected_writer: &WriterLineage,   // ADR-0035 §5; a single key before succession exists
) -> Result<ReputationProfile>
```

It refuses (`HistoryError::WrongSigner`) unless `signed_root.signer` is the
writer the lineage names at `to_seq`, and the scratch replay's `ScoringContext`
is pinned to that lineage rather than to the verifying station's runtime key, so
the exporting community's settlement, cancellation, certificate, and equivocation
records are honored inside the replay and every other station-signed record is
skipped exactly as the ledger readers skip it (skip, never halt). The existing
`verify_history` becomes a thin wrapper that a caller with no expected key may
use only in tests. The rest of the check is unchanged: root signature, address
match, strictly increasing `seq`, per-entry signature and content-hash
re-verification, Merkle root, then `score` at `computed_at`.

The expected lineage is the partner-side `WriterLineage` of ADR-0035 §5, and it
is **derived on replay from this station's own log**, never from the directory
cache: its root is the `rrn.fed.partner_pin` record this station appended when it
first pinned the home community's writer (ADR-0029 §2, §4), advanced by the
foreign `rrn.gov.succession` records this station has admitted under ADR-0035 §7
(each admitted in the same batch as a fresh `partner_pin`). The `at_seq`
boundaries fall in the home community's own seq space, which is the space
`to_seq` lives in, and **the pin is evaluated at `to_seq`, not at the lineage's
current key**: a history the *old* writer exported before a succession and that
arrives late is signed by `writer_at(to_seq)` and is valid. Only a history signed
by a key outside the lineage at `to_seq` is forgery — an implementer who pins at
the current key would wrongly reject every such late history.

Anchoring inside the replay is the foreign community's own: the vouches in the
history are the vouches the home log holds, so `is_anchored` evaluates them as
the home station would. **No vouch is re-evaluated against, or added to, this
community's vouch graph.** "Mutual identity vouching recognized" (overview §8.4)
means exactly this — the foreign community's vouches are believed inside its own
evidence — and nothing more: there is no cross-community vouch record kind, a
member of this community cannot vouch for a foreigner on this log, and a foreign
vouch never anchors anyone here.

### 3. Recognized standing is a cache with provenance, stale after 30 days

A verified profile is stored in a station-local cache table, documented as
derived state (ADR-0020 discipline: caches are caches):

```
foreign_standing (STRICT)
  subject      BLOB                -- Address
  home         BLOB                -- CommunityId
  PRIMARY KEY (subject, home)      -- one key may be anchored in two communities
  profile      BLOB                -- canonical ReputationProfile (kind rrn.reputation.profile.v1)
  computed_at  INTEGER             -- the root's computed_at (home clock: testimony)
  verified_at  INTEGER             -- THIS station's clock when verified (admission-class)
  root_hash    BLOB                -- blake3 of the signed root, for audit/refresh dedupe
```

Freshness is judged by **`verified_at` on this station's clock** (ADR-0022
extension, ADR-0029 §8): an entry older than `foreign_standing_ttl_secs`
(default 30 days) is **stale**. A stale entry is still displayed, marked stale,
but it satisfies no gate; a gate that needs fresh standing triggers a new
`history_request` and refuses the current attempt with the typed slug
`fed-standing-stale` so the member retries once the answer lands — for a
cross-community *proposal* that means the payer signs a fresh proposal with a
new nonce after the history round trip, a cost this ADR accepts over admitting
against stale standing. `computed_at`
is carried for display and to reproduce the exact profile; it is never compared
to this station's clock. A replica rebuilds the cache from carried histories
exactly as the writer does; nothing about it is authoritative.

### 4. Where recognized standing may be used — and where it never may

Recognized standing is an input to **exactly** these decisions, and to nothing
else:

- **Marketplace gates on a foreign taker** (§6): `Requirements.min_reputation`
  and `Requirements.federation_only` on a listing this community holds, evaluated
  against the inquirer's or payer's recognized composite.
- **Display with provenance**: a foreign counterparty's band and composite, always
  labelled with the home community and `verified_at`, never shown as if local.
- **Tier-4 validator choice** (ADR-0033): a station picking the neutral
  Recognition partner to validate a Tier-4 transaction may read the parties'
  recognized standing as one input.
- **Tier-4 validation itself** (ADR-0033 §6(b)): the validator community's
  attestors read each *witness's* recognized standing when they check a
  cross-community Tier-4 transaction — a read of `foreign_standing` of the same
  safety class as the marketplace gate, and no more.

It is **never** an input to:

- this community's **electorate** (governance quorum, votes, co-signs, emergency
  declarations, succession activations);
- any **jury, tribunal, or arbitration pool** of this community (ADR-0014,
  ADR-0025, ADR-0034) — a foreign member is not eligible to judge here, full stop
  (a *recusal-only* read of `foreign_standing` — ADR-0034 §8 for arbitration
  jurors, ADR-0033 §6(b) for validation attestors — excludes a person and is not
  an eligibility input);
- **any local member's score** — `ScoringContext` over this log reads this log
  only; a foreign history is never merged into it;
- **Tier-2 stake evaluation** — the confirmer's stake is evaluated by the
  confirmer's *home* station on its own log (ADR-0031 §8), never from a
  recognized profile;
- **bootstrap grace, established-member counts, or the vouch velocity cap.**

The reason is the one ADR-0012 §5 gave for the electorate: standing that
originates outside this log cannot be re-derived from this log, so it can be
withheld, replayed at a chosen moment, or presented selectively by the home
station (§7). It is safe to consult when the worst case is a refused inquiry;
it is not safe where it would change who governs or who judges.

### 5. No residency, no recognized-member state

**(maintainer decision, 2026-09-23.)** Phase 3 creates no membership-like state
for a foreign member on this log: no "recognized member" record, no guest
balance, no ability to hold a listing or a need here, no ability to be vouched
for here, no residency application. A foreign member interacts with this
community only through the records ADR-0031 and this ADR name: a cross-community
proposal, a confirmation, an inquiry thread on one of this community's listings,
an artifact or witness record on a transaction they are party to (ADR-0033), and
an arbitration request (ADR-0034). The overview's "citizens can apply for
residency in either community" belongs with Alliance and Full Federation — it
needs a second admission path in `rrn-identity` and an electorate rule for
resident non-founders — and is Phase 4 along with them.

### 6. The marketplace crosses the boundary at Trade depth

Under an Active treaty of depth ≥ `trade` with `listing_visibility = true`:

**What travels.** A listing whose `federation_visible` is `true`, and every need,
is carried in the federation outbox **as the member-signed record it already is**
(`rrn.marketplace.listing.v1`, `listing_updated.v1`, `listing_closed.v1`,
`stock_consumed.v1`, `need_announced.v1`), together with the later records that
change it. Nothing is re-signed or re-wrapped; the partner verifies the member's
signature and the carrying writer's outbox entry (ADR-0029 §3 carriage attestation and §4 pin check). A
listing with `federation_visible = false` never leaves the home log, and the
Phase-1 validation that refused `true` is lifted: a provider may set it once the
station has a published genesis charter (there is nothing to be visible *to*
before that). `federation_only = true` remains a listing-side requirement that
only a foreign taker satisfies; it too is now accepted.

**Where it lands.** Foreign listings and needs are **caches, not log records**:

```
foreign_listings (STRICT)   listing_id BLOB PK, home BLOB, provider BLOB, record BLOB,
                            state TEXT, category TEXT, oracle_tier INTEGER,
                            federation_only INTEGER, min_reputation_centi INTEGER,
                            expires_at INTEGER, received_at INTEGER
foreign_needs (STRICT)      need_hash BLOB PK, home BLOB, seeker BLOB, record BLOB,
                            category TEXT, valid_until INTEGER, received_at INTEGER
```

`received_at` is this station's admission-class clock. `min_reputation_centi` is
derived from the listing's `Requirements.min_reputation: f32` as
`round_half_up(min_reputation × 100)`, fixed here so the gate below is the same
integer comparison on every station. A foreign listing's
`expires_at` is honored as the *home's* statement of intent — the cache drops it
when a `listing_closed` arrives or when its own sweep passes `expires_at` on
this station's clock, whichever first — and a closed or expired foreign listing
is never re-opened by a late-arriving earlier record (the cache keeps the
highest-`created_at` record per listing and applies close monotonically). The
cache is bounded (`foreign_listings_max`, default 5 000 per partner; oldest
`received_at` evicted) so a partner cannot fill this station's disk.

**Search.** `marketplace_search` gains `scope: local | federation | all`
(default `local`). Foreign results carry `home: CommunityId`, the home's display
`community_id`, and `received_at`, and are never interleaved with local results
without that provenance. The existing local index is untouched; the foreign
cache has its own.

**Gates on a foreign taker.** A foreign taker must first be a **home member** of
its own community in the ADR-0031 §3 sense — anchored on its home log, or a
genesis founder there; a carried inquiry or proposal from an address its home
writer cannot vouch as a home member is refused `fed-foreign-party-unknown`
(ADR-0029 §4), and a *local* address presenting itself as a foreign taker is
refused `fed-not-home`. Past that door, when a foreign member opens an inquiry
on, or pays for, a listing this community holds:

| Listing requirement | Trade depth | Recognition depth |
|---|---|---|
| `community_member_only = true` | refused, `fed-members-only` | refused, `fed-members-only` |
| `federation_only = true` | satisfied by any foreign taker | satisfied |
| `min_reputation > 0` | refused, `fed-standing-unavailable` — no standing can exist under Trade | evaluated against fresh recognized composite; stale → `fed-standing-stale` (and a `history_request` is issued); below → the existing below-minimum refusal |
| `min_reputation = 0` | allowed | allowed |

So a Trade-only partner's members can take open listings and `federation_only`
listings, and cannot take standing-gated ones; a Recognition partner's members
can take all three once their history has been verified. The rule is evaluated
by the **listing's home station** at admission of the inquiry-open or the
cross-community proposal, on its own log; the taker's home station does not
pre-check it (it lacks the listing's authoritative state).

**Inquiries.** `inquiry_opened`, `inquiry_message`, and `inquiry_closed` records
between a foreign inquirer and a local provider are **admitted to the listing's
home log only**. The inquirer's home station keeps the thread in a
`foreign_inquiries` cache (the same record bytes, plus provenance) so the
inquirer's device can render it, and carries the inquirer's outgoing records in
its federation outbox. The provider's replies travel the other way and land in
that cache; nothing about the thread is on the inquirer's home log. This keeps
one authority per thread and matches ADR-0010's model, where the listing's
lifecycle is the provider's community's business.

**Payment.** Paying for a foreign listing is an ADR-0031 cross-community
proposal carrying both `listing_id` and `receiver_community`; the listing's home
station applies the listing gates above and the ADR-0010 listing-linkage checks
when it admits the proposal as a foreign record, exactly as it applies them to
a local payer. **Service contracts do not cross the boundary in Phase 3**: a
`service_contract.v1` naming a foreign party is refused (`fed-contract-unsupported`);
recurring cross-community charges need the treaty-position accounting to run on a
schedule and are deferred with Alliance depth.

### 7. The community string is the charter's `community_id`; the hash is the authority

The strings that listings and vouches carry (`Listing.community`,
`VouchBody.community`) stay strings — changing their type would change every
content-addressed id on every existing log — but they stop being a constant.
**A station's community string is `effective_charter().community_id`**, and the
`VOUCH_COMMUNITY` constant in `rrn-station::core`, `rrn-cli::wallet`, and the
cross-platform vouch test is retired:

- `whoami` reports `community` from the effective charter; a station with no
  published charter reports the legacy `"rrn-phase0"` and has **no
  `CommunityId`** — it cannot federate, publish a profile, or accept a treaty
  until it has a genesis (ADR-0029 §1), and its `dispute_anchor()` stays empty
  exactly as today (ADR-0034 §2 seeds on the `CommunityId` only once one exists).
- The mobile client and `rrn wallet` learn the string from `whoami` at pairing
  and after every sync, and write it into the vouches and listings they sign.
- Admission validates the string equals the effective charter's `community_id`
  (or the legacy constant while no charter exists); replay does **not**
  re-validate — a vouch or listing already on the log keeps its string, so a
  charter amendment that renames the community leaves history intact and only
  new records carry the new name.
- The string is **display and a sanity check, never authority.** Two communities
  may share a string; the `CommunityId` (genesis charter hash) is what treaties,
  the directory, foreign caches, and every gate in this ADR key on. Anything that
  matched on the string before (there is nothing outside tests) must match on
  the hash.

### 8. Threat-model obligations

The `rrn-federation` section that ADR-0029 opens gains these entries, and the
`rrn-reputation` and `rrn-marketplace` sections are extended:

- **History withholding or selective export by a home station.** A home writer
  attests to the *selection*; it can decline to export at all, or export a
  history that omits nothing it holds but was computed when the subject looked
  best. Mitigation: the Merkle root and per-entry signatures make *tampering*
  impossible; the `(subject, requested_by)` request on the home log makes
  *refusal* visible to the home community's own members and replicas; the
  30-day staleness bound caps how long a flattering snapshot serves. Residual:
  a home station can refuse to let its member be recognized elsewhere, and can
  time an export; the member's remedy is social (their own community) and, in
  the limit, ADR-0034 arbitration against their own community.
- **Stale standing.** Bounded by `verified_at` on the verifier's clock; a
  partner's clock is never consulted, so a partner cannot extend freshness by
  lying about `computed_at`.
- **Foreign standing leaking into local authority.** Structural: no code path
  from `foreign_standing` into `ScoringContext`, the electorate, or any pool;
  the reviewer for the implementing ticket must grep for it, and a test asserts
  a foreign member with Senior standing is absent from every pool and electorate.
- **Foreign listing and need spam.** Per-partner cache bound and eviction; a
  partner that floods is a governance matter (`TreatySuspend`, ADR-0030), and
  the airtime budget already classes marketplace traffic as `Bulk`, so it can
  never starve money on a constrained carrier.
- **Inquiry metadata leakage.** An inquiry thread with a foreign party is on the
  listing's home log in the clear, as every inquiry already is
  (community-public content, ADR-0010), and it now also sits in a cache on the
  inquirer's home station and in the carrying bundles. The threat model's
  cleartext-carriage residual (Phase 2 exit residual 2) extends to it unchanged;
  field-level encryption of free text remains the open item the 2026-08 audit
  named.
- **Cross-community Sybil.** A partner community with lax vouching can present
  well-anchored members cheaply. Recognized standing gates listings and Tier-4
  validator choice only; it never gates credit exposure, which is bounded by the
  treaty's `credit_limit_centi` (ADR-0031), so the blast radius of a Sybil
  partner is a treaty limit, and the remedy is treaty suspension.

## Consequences

- **Reputation stays derived everywhere.** No station ever stores or trusts a
  number about a foreigner; it stores a verified profile it computed itself from
  signed evidence, with the evidence's root hash beside it. The overview's "no
  community can inflate someone's reputation artificially" holds by construction.
- **`portability.rs` finally has its second station.** The module was built for
  this and changes only at its edge (expected signer, lineage pin). The
  "Phase 2 can prove one entry's membership without shipping the rest" note in
  its docs stays future work; Phase 3 ships whole histories, which are small at
  pilot scale.
- **`federation_visible` and `federation_only` become live**, and the Phase-1
  validation that refused them is lifted behind "the station has a genesis."
  Every marketplace record keeps its bytes and id.
- **The `VOUCH_COMMUNITY` constant is retired** in three places; existing
  `"rrn-phase0"` vouches remain valid forever. A mobile handoff note is required
  (the app hard-codes nothing today but must read the string from `whoami`).
- **New caches, no new authority**: `foreign_standing`, `foreign_listings`,
  `foreign_needs`, `foreign_inquiries`, each bounded, each rebuildable from
  carried evidence, each documented as station-local derived state.
- **One new record kind** (`rrn.fed.history_request`), one new payload kind
  (`0x03`), one new paper kind (`'h'`), one generalized verifier; fixtures for
  each. No change to `rrn-crypto`.
- **Accepted costs.** A Trade-only partner's members cannot take standing-gated
  listings at all; a Recognition partner's members see a one-round-trip delay
  (refuse, request, retry) the first time and every 30 days. Threads with a
  foreign party exist in two places (one authoritative, one cache). Contracts
  do not cross the boundary. Residency does not exist.
- **Follow-up work created**: Phase 4 residency/recognized-member state under
  Alliance depth; succinct Merkle membership proofs for large histories; a
  reentry/refresh policy for very active traders whose histories grow past what
  LoRa comfortably carries (a history over a constrained carrier is `Bulk`
  class and may take hours — acceptable, documented).

## Alternatives Considered

- **Trust the home station's score** (carry `rrn.reputation.profile.v1` alone).
  Rejected: it is exactly the "community-level reputation interpretation" the
  overview rejects — a home station could inflate; nothing could be re-verified.
- **Recognized-member state on the partner log.** Rejected for Phase 3
  (maintainer decision): it needs an electorate rule excluding residents, a
  second identity admission path, and vouch semantics across logs; it is the
  Alliance/Full Federation deliverable.
- **Merge foreign histories into the local `ScoringContext`** so one scorer sees
  everything. Rejected: it makes a local member's score depend on evidence that
  can be withheld or re-presented, breaking ADR-0009's "re-derivable from the
  log" for the local log, and it opens the electorate and pools to foreign
  standing by accident.
- **Push histories proactively with every profile.** Rejected: a profile is
  small and public; a history is per-member, potentially large, and only
  needed when a gate asks. On-demand keeps LoRa airtime for money.
- **Admit inquiries on both home logs.** Rejected: two authorities for one
  thread; the listing's community owns the listing's lifecycle (ADR-0010), and
  the inquirer needs a cache, not a record.
- **Replace the community string with the `CommunityId` in listings and
  vouches.** Rejected: it would change the canonical bytes, and so the content
  id, of every existing record kind that carries it. The string is display; the
  hash is authority; both can coexist.

## References

- Design overview §5.6 (Reputation Portability), §8.4 (treaty depths), §8.7
  (Level 3 sanction: loss of recognition), §9 (Marketplace), §14.2 (rejected:
  reputation inheritance, community-level reputation interpretation)
- [ADR-0009](0009-universal-reputation-algorithm.md) — one locked formula,
  derived from the log, never stored authoritatively
- [ADR-0010](0010-marketplace-data-model.md) — listing/need/inquiry records and
  the additive-field discipline
- [ADR-0012](0012-charter-format-and-amendments.md) — `Charter.community_id`;
  the electorate is established members
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — caches are caches; one
  writer per log
- [ADR-0022](0022-admission-clock-time-trust.md) — freshness on this station's
  clock only
- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) — `CommunityId`,
  federation outbox and ingest, payload/paper kinds, the time-trust extension
- [ADR-0030](0030-treaties-ratification-depth-lifecycle.md) — treaty depth and
  `listing_visibility`
- [ADR-0031](0031-cross-community-credit-treaty-accounts.md) — paying for a
  foreign listing; Tier-2 stake evaluated at home
- [ADR-0033](0033-oracle-tiers-3-and-4.md) — Tier-4 validator choice
- [ADR-0034](0034-community-tribunal-and-federation-arbitration.md) — pools
  exclude foreign members; appeal against one's own community
- [ADR-0035](0035-writer-succession-and-lineage-pinning.md) — `WriterLineage`, the
  expected-signer pin
- `crates/rrn-reputation/src/portability.rs`, `context.rs`;
  `crates/rrn-marketplace/src/listing.rs` (`federation_visible`,
  `Requirements`); `crates/rrn-station/src/core.rs` (`VOUCH_COMMUNITY`)
- `docs/threat-model.md` — `rrn-reputation`, `rrn-marketplace`, and the
  `rrn-federation` section to be added
