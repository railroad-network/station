# 0034 — The community tribunal and federation arbitration

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review; it returned accept-with-changes for the set of eight and the changes
are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted against the maintainer's scope
> decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification at the
> maintainer's delegation. The review's
> findings folded into this ADR: a station-signed `rrn.dispute.tribunal_opened` anchor pins the tribunal's pool, weights, reserved seat and window; the home checks only its own treaty with the forum; the `dispute_anchor` change is gated by position as a migration; §10/§11 follow the corrected ADR-0031 settlement order and the suppression residual.
> Implementation tickets are written against this ratified text.

## Context

The design overview (§7.3) describes a four-layer resolution stack. Phase 1
built Layer 2 — the three-juror sortition jury of
[ADR-0014](0014-phase-1-dispute-resolution.md) — and Phase 2 added the
equivocation case kind on the same primitives
([ADR-0025](0025-equivocation-dispute-cases.md)). Layer 1 (automated
resolution) is the settlement window and expiry machinery itself. Two layers
remain, and Phase 3 needs both:

- **Layer 3 — the community tribunal.** The overview asks for a seven-member
  panel "including at least one elected official", structured evidence, a
  longer deliberation window, and **written reasoning** that accretes into a
  body of case law. Nothing in the system today produces reasoning: a
  `JurorVerdict` is a bare `uphold: bool`. That is adequate for a
  three-Common disagreement and inadequate for the Tier-3 amounts (50 to under
  500 Commons) that [ADR-0033](0033-oracle-tiers-3-and-4.md) now admits, where
  three witnesses and an artifact are on the record and a ruling should say
  *why* it read them the way it did. The overview assigns Layer 3 to no phase;
  the maintainer assigned it to Phase 3 alongside Layer 4 **(maintainer
  decision, 2026-09-23)**.
- **Layer 4 — federation arbitration.** ADR-0014 stated the constraint
  plainly: "Single community, no outside arbiter." Phase 3 federation creates
  disputes with no single home — a payment from a member of one community to a
  member of another ([ADR-0031](0031-cross-community-credit-treaty-accounts.md)) — and creates,
  for the first time, a party that *can* be neutral: a third community with a
  treaty relationship to both. The overview's Layer 4 is "a cross-community
  panel from neutral third communities … slow, expensive to invoke, but
  genuinely independent", also open to "a member [who] alleges their own
  community treated them unfairly". Phase 3's exit criterion (ADR-0017) is
  literally "at least one inter-community dispute resolved" — this layer is
  the phase's "system has teeth" milestone.

Forces that shape both layers:

- **The panel must be log-derivable and position-bounded.** ADR-0014 §2 built
  sortition as a deterministic function of the log so anyone replaying it can
  prove the station did not hand-pick jurors, and ADR-0022 §5 / the Phase 2
  conformance pass made every pool, electorate, and weight a function of the
  log *prefix* at the anchoring admission position. Both new layers inherit
  this or they are not worth building.
- **There are no elected offices.** The overview's "elected official" does
  not exist in the governance model (ADR-0012: direct ballots by established
  members; no council, no executive, per ADR-0023's explicit refusal to create
  a role). Inventing an office to seat a tribunal is a governance change with
  its own capture surface; the maintainer chose a reserved seat instead
  **(maintainer decision, 2026-09-23)**.
- **A forum's ruling has to land on two logs that trust different clocks.**
  ADR-0020 keeps one writer per log; ADR-0029 fixes that each station judges
  every window by its own admission clock and that, where two logs must agree
  on an outcome, one of them is *home* and the other mirrors. An arbitration
  verdict is a station-signed record of a *third* community; each home admits
  it as a foreign record and enacts it under its own rules.
- **Every path must fail open to the status quo.** ADR-0014 §5's rule — a
  bounded window, and a non-ruling leaves the confirmed transaction standing —
  is the single most load-bearing property of the dispute system. Slower,
  heavier layers make it *more* important, not less: a tribunal that cannot
  seat seven, or a forum that never answers, must not freeze credit forever.
- **Reasoning is a new kind of content.** Free text signed onto a permanent,
  replicated log by a juror is a coercion and doxxing channel the system has
  not had before (the threat model already flags free-text fields as an
  open federation question). Bounds and a stated posture are required.

## Decision

**Phase 3 adds the two remaining layers of the resolution stack on the ADR-0014
sortition primitives, unchanged: a seven-member community tribunal with
written reasoning for Tier-3-and-above disputes and for appeals of Layer-2
verdicts at those tiers, and a federation arbitration forum — a neutral third
community named in the treaty — for cross-community disputes and for a
member's appeal against their own community. Both layers are log-derivable,
position-bounded, windowed on the adjudicating station's own admission clock,
and fail open to the status quo. The tribunal's seventh seat is reserved for
the highest-standing eligible member the draw did not pick; no elected office
is created. Precedent is an index over signed reasoning, never a binding
rule.**

The stack after this ADR:

| Layer | What it is now | Forum of first instance for | Appeal from |
|---|---|---|---|
| 1 — Automated | Settlement windows, proposal/certificate expiry, the ADR-0021 certificate accounting, the equivocation *detection* of ADR-0025 | — | — |
| 2 — Sortition jury | ADR-0014 three-juror panel; ADR-0025 equivocation cases | Tier 1–2 transaction disputes; all equivocation cases | — |
| 3 — Community tribunal | **This ADR §1–§6**: seven seats, written reasoning, precedent index | Tier 3–4 transaction disputes | Layer-2 transaction verdicts at Tier ≥ 3 (see §5) |
| 4 — Federation arbitration | **This ADR §7–§12**: the treaty's forum community seats an ADR-0014 panel of its own members | Cross-community transaction disputes (ADR-0031) **on request by either party** — an admitted request supersedes the home panel (§12); otherwise the home Layer 2/3 hears them | A tribunal verdict of the appellant's own community (§11) |

Sub-decisions follow. §1–§6 are the tribunal (`rrn-dispute::tribunal`);
§7–§12 are arbitration (`rrn-federation::arbitration`); §13 is shared; the
threat-model obligations are the unnumbered closing section.

### 1. A tribunal case is opened by a signed request, and the case is keyed like an equivocation case

A tribunal is convened by a member-signed **`rrn.dispute.tribunal_request`**:

| field | type | meaning |
|---|---|---|
| `case` | `CaseRef { kind: "tx" \| "equivocation" \| "tribunal", id: Hash }` | what is being judged — a disputed transaction (`kind = "tx"`, `id = tx_id`) or, for an appeal, the Layer-2 ruling's transaction |
| `requester` | Address | a party to the case (sender or receiver), or — for an appeal — the party contesting the ruling |
| `basis` | `"first-instance"` \| `"appeal"` | first instance at Tier ≥ 3 (Tier 3 or Tier 4), or an appeal of a Layer-2 verdict (§5) |
| `requested_at` | i64 | testimony (ADR-0022 §3) |

The front door admits a `first-instance` request only while the named transaction is
`Disputed` (an ADR-0014 §1 `DisputeRecord` exists and its window is open) and
its effective tier is ≥ 3; an `appeal` request only while a terminal Layer-2
ruling exists for a Tier ≥ 3 transaction and ADR-0014's appeal window
(`appeal_window_seconds`, default 2 days) is open. A duplicate request for the
same `CaseRef` is `known`, never a second case — the case is **keyed by
`CaseRef`, not by the request's content address**, exactly as ADR-0025 §1
keys equivocation cases by identity. The `"tribunal"` `CaseRef` kind exists
for the Layer-4 appeal-own-community basis (§11), where the case *is* a
tribunal verdict.

Atomically with the request (`LogBatch`), the station appends a
station-signed **`rrn.dispute.tribunal_opened { request_hash: Hash, seq: u64,
opened_at: i64 }`** — the attested pin for the case, mirroring
`rrn.fed.arbitration_opened` (§7) and ADR-0027's single-attested-pin
discipline. `seq` is the request's admission seq; `opened_at` is the
station's admission clock at that seq. Every input below that needs a
position reads `seq`, and every input that needs an instant reads
`opened_at` — never the request's `created_at`, which a replica re-stamps
(ADR-0022 §1) and which would otherwise let two copies of one log seat two
different panels. Replay validates the pin as it validates any station
attestation: a `tribunal_opened` not immediately following its request is
skipped, and a case with no validated pin seats nothing.

Opening a Tier-3 dispute (`raise_dispute` on a Tier ≥ 3 transaction) does
**not** seat a Layer-2 jury. Tier ≥ 3 disputes go to the tribunal directly:
the `DisputeRecord` freezes settlement per ADR-0014 §1, and the tribunal
request is the act that seats a panel. A Tier ≥ 3 dispute with no tribunal
request by the end of the dispute-resolution window lapses and settles as
confirmed, per ADR-0014 §5 — a party who freezes a large transfer must also
ask for a ruling.

### 2. Seven seats: six by sortition, one reserved for standing **(maintainer decision, 2026-09-23)**

`TRIBUNAL_SIZE = 7`. The panel is seated from the ADR-0014 §2 eligible pool
— established members (composite ≥ `BAND_MEMBER_MIN`), or the ADR-0015 grace
electorate, **minus both parties, minus direct vouchers of either party** —
computed with the position-bounded readers (`eligible_pool_excluding`,
`vouchers_of_until`, `established_members_asof`) at the **`(seq, opened_at)`
pin of the case's `tribunal_opened` record** (§1) — position-bounded at `seq`,
decay-evaluated at `opened_at`. Nothing admitted after that position can change
the pool (ADR-0022 §5).

- **Six seats by the draw.** `draw_sequence(pool, seed)` with
  `seed = blake3("rrn.dispute.tribunal" ‖ canonical(CaseRef) ‖ seq_be ‖
  dispute_anchor)`, where `seq_be` is the `tribunal_opened` pin's `seq` as
  8 big-endian bytes and `dispute_anchor` is the community's `CommunityId`
  (ADR-0029 §1). `Core::dispute_anchor()` — empty since ADR-0014 with the
  comment "a stable per-community anchor drops in here when federation
  arrives" — returns the genesis charter hash for every draw (jury,
  equivocation, tribunal) **whose anchoring record is admitted at or after
  the log's first own `rrn.fed.profile` record** (ADR-0029 §2); a case
  anchored before that position keeps the empty anchor it was drawn with.
  This gate is the migration: concluded Layer-2 and equivocation cases on an
  existing log re-derive the panel they were actually seated with, and their
  recorded verdicts still match their jurors on replay; only cases opened
  after the community publishes its profile use the new anchor, so two
  communities running the same code never produce the same panel for the
  same case id. This is the one change to a Layer-2 input, and it is a
  strict improvement in the already-ratified direction. A station with no
  published genesis charter has no `CommunityId`: its anchor stays empty,
  exactly as today, and such a station cannot federate (ADR-0032). The first
  six addresses the sequence yields, in order, are seats 1–6; the sequence
  continues to supply no-show replacements (§4).
- **The seventh seat is reserved.** Seat 7 is the eligible member with the
  **highest raw composite standing** at the pin
  (`ScoringContext::score_raw` at `opened_at`, over the prefix ending at
  `seq`) who was *not* drawn into seats 1–6. Ties break by ascending address
  bytes. This is the overview's "at least one elected official" without an
  election: the community's most-established member sits by right of
  standing, which is the only rank the system computes and which cannot be
  bought faster than the ADR-0009 velocity limit allows. The reserved seat is
  filled *after* the six are drawn and is excluded from the replacement
  sequence — a reserved member who goes silent is replaced by the *next*
  highest-standing undrawn member (§4), not by the draw.
- **Pool too small.** If the recused pool holds fewer than 7, voucher-recusal
  relaxes before party-recusal exactly as ADR-0014 §5 provides; if still
  fewer than 7, the tribunal **cannot seat** and the request is refused at the
  front door with slug `tribunal-cannot-seat`. A community that cannot seat
  seven has no tribunal; its Tier ≥ 3 disputes fall back to the **Layer-2
  jury** (a `first-instance` request refused for this reason is followed by an
  ordinary jury draw on the same `DisputeRecord`, so the freeze is still
  adjudicated). A tribunal is a large-community instrument; the fallback
  keeps small communities' Tier-3 trade adjudicable rather than frozen.

### 3. A ballot carries written reasoning, bounded, and is the precedent's raw material

Each seated member casts a member-signed **`rrn.dispute.tribunal_ballot`**:

| field | type | bound |
|---|---|---|
| `case` | `CaseRef` | must match a seated case |
| `juror` | Address | must hold a seat |
| `decision` | `"uphold"` \| `"reject"` | same semantics as `JurorVerdict::uphold` — `uphold` voids the transfer |
| `reasoning` | String | **≥ 200 and ≤ 4 000 bytes of UTF-8**, required |
| `voted_at` | i64 | testimony |

The lower bound is the point: a tribunal ballot with no reasoning is refused
(`reasoning-too-short`), so a ruling always says why. The upper bound is the
usual permanence-cost cap on any member-written field. Reasoning is
**signed content** — it is the juror's attributable statement, permanent and
replicated like every other log record. The threat-model section this ADR
requires (see the threat-model obligations below) states the consequence: reasoning must not name third parties
or evidence beyond what the case record already contains, and the app/CLI
surfaces show that rule before the field is signed. The system does not
parse or moderate the text; a juror who writes something harmful has done so
under their own signature, which is the same accountability posture the
vouch `statement` already takes.

A juror may cast one ballot per case; a second ballot from the same seat is
refused (`already-voted`), never a change of vote.

### 4. Majority of seven, windows, no-shows, and fail-open

- **Ruling.** Four or more ballots with the same `decision` is the ruling
  (`tally` generalizes ADR-0014 §3 from "2 of 3" to "≥ ⌈n/2⌉ + 0 of 7" — the
  constant is `TRIBUNAL_MAJORITY = 4`). The ruling is reached at the admission
  seq of the fourth concurring ballot (`ruling_reached_at`, the same
  primitive).
- **Windows, on this station's admission clock.** The tribunal runs inside
  its own **`tribunal_window_secs`, default 21 days**, from the pin's
  `opened_at` — replacing, for this case, ADR-0014's 14-day dispute-resolution
  window (the `DisputeRecord`'s freeze is extended to the tribunal window's
  end; the station's sweep reads the longer of the two for a transaction with
  a seated tribunal). Each juror has a **response deadline of 5 days**
  (`tribunal_juror_response_secs`) from their seating instant (`opened_at`
  for the initial seven; the no-show's deadline instant for a replacement).
- **No-shows are redrawn around.** A drawn juror past their deadline with no
  ballot is replaced by the next address in the draw sequence not already
  seated or recused; the reserved-seat member is replaced by the next
  highest-standing undrawn eligible member. No reputation penalty for a
  no-show in Phase 3, as in ADR-0014 §4.
- **Fail-open.** If the window closes with fewer than four concurring
  ballots, the case is recorded as lapsed and the transaction settles **as
  confirmed** (ADR-0014 §5's status quo). For an appeal (§5), lapse leaves
  the Layer-2 ruling standing. A lapsed tribunal case is not re-seatable —
  unlike ADR-0025's equivocation cases, a transaction dispute has one bite,
  because its freeze is what a griefer would otherwise renew.
- **Superseded by arbitration.** If an `rrn.fed.arbitration_request` for the
  same `CaseRef` is admitted on this log before a ruling is reached (§12), the
  case's derived terminal state is **`Superseded`** — a further terminal state beside
  a ruling and a lapse: no further
  ballots are counted, no `tribunal_verdict` is appended, and the case enacts
  nothing. The forum's verdict (§10) is the only outcome for that case. The
  same rule applies to a Layer-2 jury on a cross-community transaction.

The station appends a station-signed **`rrn.dispute.tribunal_verdict`** when a
ruling is reached or the window lapses:

| field | type | meaning |
|---|---|---|
| `case` | `CaseRef` | |
| `outcome` | `"uphold"` \| `"reject"` \| `"lapsed"` | |
| `ballots` | [Hash] | content hashes of the ballots counted, in admission order |
| `reasoning_digest` | Hash | blake3 over the concurring ballots' `reasoning`, in admission order — a stable handle for the precedent index |
| `decided_at` | i64 | the station's admission clock; attested |

The verdict is a station attestation in the ADR-0005 sense (like
`rrn.gov.proposal_implemented`): replay recomputes the ruling from the ballots
and *validates* the verdict against it; a verdict that disagrees with its
ballots is skipped on replay, never trusted. It is pinned to the writer key
under ADR-0035's lineage rule.

### 5. Where the tribunal sits in the ladder: first instance at Tier ≥ 3, appeal above the jury at Tier ≥ 3

- **First instance.** A Tier-3 or Tier-4 transaction dispute
  ([ADR-0033](0033-oracle-tiers-3-and-4.md) transactions) is heard by the
  tribunal, not a jury (§1). The witness records and artifact hashes on the
  log are its evidence; the parties' `DisputeRecord` and
  `rrn.tx.dispute.response` statements remain the thin channel ADR-0014 §1
  defined. Nothing new is invented for evidence *submission* — the
  ADR-0033 artifact and witness kinds are already on the log before the
  dispute opens.
- **Appeal.** For a transaction of effective tier **≥ 3** that a Layer-2
  jury nonetheless ruled on (only reachable through the §2 cannot-seat
  fallback, and then only if the eligible pool has grown since the
  first-instance refusal — the same pool and recusals at a later position
  will usually fail to seat again, so this is a near-dead path kept for
  completeness), a party may appeal the jury ruling to the tribunal within
  the appeal window. The tribunal's ruling replaces the jury's. For Tier 1–2,
  **nothing changes**: the ADR-0014 §5 electorate appeal (`EscalationReason::Appeal`)
  and `CannotSeat` escalation remain the only paths; a `tribunal_request` on
  a Tier ≤ 2 transaction is refused (`tier-below-tribunal`). Small disputes do
  not get a seven-person hearing.
- **Equivocation cases are unchanged.** ADR-0025 cases stay at Layer 2 with
  their own verdict kind and re-seat rule; the tribunal does not hear them.
  A `CaseRef { kind: "equivocation" }` is reserved for a later ADR and is
  refused today (`case-kind-unsupported`).

### 6. Enactment is ADR-0014 §6; precedent is an index, not a rule

An `uphold` verdict enacts exactly as a Layer-2 uphold: the pending transfer
is **voided** (`Disputed → Cancelled`, `CancelReason::DisputeUpheld`), the
confirmer's confirmation is recorded as proven wrong for `attestation_accuracy`,
and — new under ADR-0033 — each **witness** who attested the voided
transaction takes the same inaccurate-attestation input. A `reject` or
`lapsed` verdict lets the transaction settle as confirmed. For a
cross-community transaction, the home log's tribunal verdict is carried to
the partner as part of the ADR-0031 outcome (an `uphold` becomes the home's
`rrn.fed.abort { reason: "dispute-upheld" }`), and the partner mirrors — it
never runs its own tribunal on a transaction whose home is elsewhere.

**Precedent** is a **cache table** `precedents` (migration in `rrn-storage`;
the builder that decodes the dispute kinds lives in `rrn-dispute`, since
storage decodes no application kind), rebuilt by replay from tribunal (and
arbitration, §10) verdicts and their ballots: one
row per verdict with `case`, `outcome`, the transaction's `category` (from
its listing, when any) and effective tier, `decided_at`, and the concurring
ballots' reasoning. It is served read-only by an RPC `dispute_precedents`
(filter by category / outcome / tier) and `rrn dispute precedents`, and is
shown to seated jurors alongside the case. **Precedent binds nothing.** No
rule, window, or threshold reads it; it is the overview's "body of case law"
in the only form a replayable system can honestly offer — prior signed
reasoning, searchable. Communities that want precedent to *constrain* future
tribunals do so through statute, which the tribunal's members are expected
to read; the software does not enforce it. A later ADR may add precedent
linking (a ballot citing prior verdict hashes); Phase 3 does not.

### 7. Arbitration is convened at the treaty's forum, and only if the forum is neutral by treaty at that moment

A federation arbitration is requested by a member-signed
**`rrn.fed.arbitration_request`**, admitted first on the requester's **home**
log and carried by the home writer's federation outbox (ADR-0029) to the
forum:

| field | type | meaning |
|---|---|---|
| `case` | `CaseRef` | `kind = "tx"` for a cross-community transaction dispute; `kind = "tribunal"` for an own-community appeal (§11), `id` = the tribunal verdict's `CaseRef` transaction id |
| `tx_id` | Hash, omitted when `case.kind ≠ "tx"` | the cross-community transaction |
| `requester` | Address | a party (cross-community) or the appellant (own-community) |
| `home` | `CommunityId` | the requester's home |
| `counterparty_community` | `CommunityId` | the other party's home (cross-community), or `home` again for an own-community appeal |
| `forum` | `CommunityId` | the community asked to arbitrate |
| `basis` | `"cross-community"` \| `"appeal-own-community"` | |
| `requested_at` | i64 | testimony |

**Forum selection is by treaty.** For a cross-community case, `forum` must
equal the `forum` field of the Active treaty between `home` and
`counterparty_community` (ADR-0030); the home front door refuses a request
naming any other community (`forum-not-in-treaty`). For an own-community
appeal, `forum` may be the `forum` of *any* Active Recognition treaty the
home holds (§11). The home judges only what its own log holds: it refuses
the request unless, at the request's admission position on the home log,
the forum holds an **Active treaty of Recognition depth with the home**
(`forum-not-neutral`) — a Trade-depth treaty carries no reputation
recognition, so such a forum could not even read the parties' standing. The
forum's relationship with the *counterparty's* community is not on the home
log (the cached partner profile's `active_treaties` is testimony), so the
home applies at most a non-authoritative pre-check against that cache and
never refuses on it; the **forum** judges forum↔counterparty neutrality on
its own log (below). If the treaty names no forum, or the named forum fails
either side's test at its position, the request is refused and **there is
no Layer 4 for that case**: it stays at the layer that heard it, and the
status quo of that layer's outcome holds.
Arbitration is an instrument communities choose to have when they sign a
treaty; the protocol does not conjure a forum.

The forum, on ingesting the request as a foreign record (carried in the home
writer's outbox, signer pinned per ADR-0029 §4), re-checks neutrality
**at its own admission position** against its own treaty state — it must
hold an **Active Recognition treaty with each of the two communities
involved** — and refuses (`refused/forum-not-neutral` in the delivery
receipt) if it does not; the forum's log is authoritative for whether the
forum sits. It admits the
request and, atomically with it (`LogBatch`), appends a forum-writer-signed
**`rrn.fed.arbitration_opened { request_hash: Hash, panel_seed_seq: u64,
opened_at: i64, home_seq: u64 }`** — the attested pin that anchors the panel
and the window. `panel_seed_seq` is the request's admission seq on the forum
log; `home_seq` is the opened record's own seq on the forum log (ADR-0029 §4:
every writer-signed federation record carries the seq at which its issuer
appends it, so a receiving station can pin it to `writer_at(home_seq)`).

### 8. The panel is the forum's own three-member jury, seated by ADR-0014 sortition on the forum's log

The forum seats a **three-member panel** (`PANEL_SIZE`, unchanged) from the
**forum's own** eligible pool — its established members at `panel_seed_seq`,
minus any forum member who is a direct voucher of either party in a foreign
history the forum holds (ADR-0032's `foreign_standing` cache; in practice
empty, since vouching does not cross the boundary, but the rule is stated so
a future cross-community vouch cannot quietly bypass recusal). The seed is
`blake3("rrn.fed.arbitration" ‖ request_hash ‖ panel_seed_seq_be ‖ forum
CommunityId)`; the draw is `draw_sequence`. The parties are never forum
members by construction (a forum is neither party's home), which is exactly
why it is neutral. Reserved seats, seven-member panels, and written reasoning
above a minimum are *not* required at Layer 4 — the forum's independence is
the guarantee, and a three-member panel keeps the carriage cost of the
verdict and its ballots small enough for a constrained carrier (ADR-0013).
Reasoning is permitted and bounded (≤ 4 000 bytes), not required (§9).

Jurors are forum members; the forum station shows them the request, the
transaction's prepare/commit records as carried (ADR-0031), any witness and
artifact records carried with the request, and the parties' statements. The
forum station holds no balance for either party and settles nothing.

### 9. Ballots and the forum's verdict

**`rrn.fed.arbitration_ballot`** — member-signed by a seated forum juror:
`{ request_hash: Hash, juror: Address, decision: "uphold" | "reject",
reasoning: String (≤ 4 000 bytes, may be empty), voted_at: i64 }`. Same
one-ballot-per-seat rule as §3. Majority of three rules (`tally`, unchanged).
Juror response deadline `arbitration_juror_response_secs = 5 days`; no-shows
redrawn from the sequence.

**`rrn.fed.arbitration_verdict`** — forum-writer-signed on ruling or lapse:
`{ request_hash: Hash, outcome: "uphold" | "reject" | "lapsed", ballots:
[Hash], decided_at: i64, home_seq: u64 }` (`home_seq` per ADR-0029 §4). As
with §4, replay validates the verdict against
its ballots and skips a verdict its ballots do not support. The forum
appends it to its own log and carries it — with the ballots — in its
federation outbox to **both** homes.

**Windows run on the forum's clock.** The case's window is
`arbitration_window_secs = 30 days` from `opened_at` (the forum's admission
instant, attested in `arbitration_opened`). If the forum admits fewer than two
concurring ballots by then it appends a `lapsed` verdict. The homes do not run
a window of their own for the arbitration; they run their **own** ADR-0031
freeze (the transaction's home settlement window is suspended while a request
the home admitted is unanswered) bounded by **`arbitration_wait_secs`, default
45 days** on the home's clock — 30 for the forum plus carriage slack — after
which the home treats the case as lapsed *for itself* even if a verdict
later arrives (a late `uphold` becomes record-only, §10). This is ADR-0029
§8 applied: the forum's clock decides the ruling; each home's clock
decides how long it will wait for one.

### 10. Enactment on each home: abort before settlement, record-only after, no clawback

Each home admits the forum's verdict as a foreign record, pinned to
`writer_at(home_seq)` on the forum's partner-side `WriterLineage` — derived
from this home's own `rrn.fed.partner_pin` record and the forum's admitted
`rrn.gov.succession` records (ADR-0029 §4, ADR-0035 §5), never from the
directory cache, so a replica or a restored station re-derives the same
pin. Enactment on the
transaction's **home** log (the paying side, ADR-0031):

- **`uphold`, transaction not yet settled** — the home appends
  `rrn.fed.abort { reason: "dispute-upheld" }`, the transaction goes
  `Disputed → Cancelled(DisputeUpheld)`, and the abort is carried to the
  counterparty's home, which mirrors (nothing moved on either side: the
  counterparty appends its `rrn.fed.settlement{import}` only on admission of
  the home's terminal `rrn.fed.settlement{export}`, ADR-0031 §9, which an
  aborted transaction never produces). The
  confirmer's — and any witnesses' — attestations are recorded as proven
  wrong, as in §6.
- **`uphold`, transaction already settled** (the verdict arrived after the
  home's `arbitration_wait_secs`, or the request was admitted after
  settlement) — the verdict is admitted and **recorded only**. Balances are
  not reversed. There is no clawback primitive in Phase 3: a settled
  cross-community transfer has moved the treaty position on two logs, and
  reversing it would be a new cross-community transaction that neither
  party has signed. The attestation-accuracy consequence still applies. This
  is a stated residual (threat-model obligations), consistent with ADR-0014 §6's "voided, not
  reversed" posture.
- **`reject` / `lapsed`** — the freeze lifts and settlement proceeds under
  the home's window, which resumes from the verdict's (or the wait
  deadline's) admission instant.

The counterparty's home enacts nothing on its own initiative; it mirrors the
home's `abort` or settlement exactly as it does for any ADR-0031 transaction.
A verdict reaching the counterparty first is held in the `arbitration_cases`
cache until the home's outcome arrives — the counterparty never acts on a
forum verdict directly, so the two logs cannot diverge on the outcome.

### 11. A member may appeal their own community's tribunal to a forum, and the forum can lift reputation effects only

The `"appeal-own-community"` basis exists so a member has somewhere to go
when their community has ruled against them — the overview's right to appeal
(§2.5.1) and Layer 4's "member alleges their own community treated them
unfairly". Its scope in Phase 3 is deliberately narrow:

- **Appealable:** a **tribunal verdict** (§4) of the appellant's home
  community in which the appellant was a party (sender, receiver, or witness
  whose attestation was recorded as proven wrong). Not appealable at Layer 4:
  Layer-2 jury rulings (they have the tribunal or electorate above them),
  equivocation cases, governance outcomes, or membership decisions (none of
  which exist as records to appeal in Phase 3).
- **Window:** requested within `appeal_window_seconds` (2 days) of the
  tribunal verdict's admission on the home log, in the home's clock; the
  request must be admitted on the home log first. A *courier* who drops the
  carried request leaves a gap in the home's federation outbox chain that the
  forum can see (ADR-0020 §2, ADR-0029 §3); the home *writer* itself, which
  assigns those positions, can decline to admit or enqueue the request with
  no gap at all — a residual visible only to the home's own members and
  replicas, who see the request refused or absent on their log.
- **Forum:** any community `F` that is the `forum` named in some Active
  Recognition treaty the home holds with a partner `P`, **and** that itself
  holds an Active Recognition treaty with the home; the request names which.
- **Enactment on `uphold`:** the home appends a station-signed
  `rrn.dispute.tribunal_verdict_lifted { case: CaseRef, arbitration_verdict:
  Hash, lifted_at }` whose only effect is that the **reputation
  consequences** of the tribunal verdict (the proven-wrong attestation inputs
  of §6) are neutralized on replay, exactly as ADR-0025's `Overturn` lifts an
  equivocation penalty. The transfer's disposition is **not** revisited: a
  voided transfer stays voided, a settled one stays settled. Money is not
  moved by a foreign community's ruling on a home community's internal case;
  standing, which is a federation-wide quantity under ADR-0009, can be.

The forum's neutrality test for this basis (§7) is with respect to the home
alone (both "communities involved" are the home), so it reduces to: `F` is
named as `forum` in an Active Recognition treaty the home holds, and `F`
itself holds an Active Recognition treaty with the home. The forum's panel,
records, windows, and fail-open are §8–§9 unchanged.

### 12. Carriage, spam, and idempotency

- All Layer-4 records travel in federation outboxes (ADR-0029): home → forum
  (request, plus the case's transaction records if the forum lacks them),
  forum → both homes (opened, verdict, ballots). A conductor can carry them
  on paper; the forum can be days away. This is why the windows are long.
- A home admits **one** arbitration request per `CaseRef`; a second is
  `known`. A requester who is not a party is refused (`not-a-party`). A
  cross-community request is admitted only while the home's ADR-0031 freeze
  is in force for that transaction or within the tribunal appeal window —
  never against a transaction with no live dispute. **An admitted request
  supersedes any home panel for that `CaseRef` from its admission position:**
  no jury or tribunal is seated for the case after it, and a panel already
  seated stops counting ballots — its case is recorded `Superseded` (§4),
  record-only, enacting nothing. If a home panel has *already* reached a
  terminal ruling, a request is admissible only as an appeal of that ruling:
  basis `appeal-own-community` for a tribunal verdict (§11); a Layer-2 jury
  ruling on a Tier 1–2 cross-community transaction, once terminal, keeps
  ADR-0014 §5's electorate appeal and is not reviewable by the forum in
  Phase 3 (a cross-community request against it is refused,
  `case-kind-unsupported`).
- The forum bounds its exposure: it admits at most
  `arbitration_max_open_per_partner` (default 8) open cases per requesting
  community at once; beyond that a request is refused
  (`forum-busy`) and the home's freeze lapses on its own clock. A forum is
  doing unpaid work for its neighbours; the cap keeps a hostile partner from
  turning it into a denial-of-service on the forum's members' time. The
  threat model records that this is a residual, not a defense.

### 13. Everything is position-bounded, and every derived view is a cache

The tribunal's pool, reserved seat, and draw are functions of the log prefix
at the `tribunal_opened` pin's `seq`, evaluated at its `opened_at`; the forum's pool and draw are functions of
the forum's log prefix at `panel_seed_seq`; neutrality is judged at the
request's admission position on each log that judges it. Nothing admitted
later changes a seat, a threshold, or an eligibility (ADR-0022 §5). The
`tribunal_cases`, `arbitration_cases`, and `precedents` tables are caches
rebuilt by replay; the log records above are the only authority.

## Consequences

- **The stack is complete.** Every layer the overview described exists, each
  with a defined forum of first instance and appeal path, and each failing
  open to the same status quo. The Phase 3 exit criterion's "inter-community
  dispute resolved" has a concrete mechanism and a concrete record
  (`rrn.fed.arbitration_verdict`) to point at.
- **Written reasoning enters the log.** This is new content with new risks
  (threat-model obligations) and a new cost: a seven-ballot tribunal can put ~28 KB of prose on
  the permanent log per case. Bounded, and only at Tier ≥ 3, where the
  transaction is worth ≥ 50 Commons; acceptable.
- **`dispute_anchor()` becomes the `CommunityId`, gated by position.** Only
  cases anchored at or after the log's first own `rrn.fed.profile` use the
  new anchor (§2); every earlier case, live or concluded, replays with the
  empty anchor it was drawn with, so no existing log re-seats a historical
  panel. Test vectors that pin a panel for an empty anchor stay valid for
  pre-profile positions; new vectors cover the post-profile draw.
- **Small communities get a fallback, not a tribunal.** Fewer than seven
  eligible after recusal means the Layer-2 jury hears Tier-3 disputes. Honest
  about scale; the tribunal appears as the community grows, with no
  configuration.
- **Arbitration depends entirely on treaty design.** A treaty with no
  `forum`, or a forum that has not signed Recognition treaties with both
  sides, yields no Layer 4. Communities must choose a forum when they
  federate, and the docs must say that plainly. Three mutually-recognizing
  communities — the exit-criterion topology — are the minimum for any of
  them to serve as forum for a dispute between the other two.
- **A forum's verdict is slow to land.** Thirty days on the forum's clock
  plus carriage, and a 45-day home wait. A cross-community Tier-2 transaction
  can be frozen for six weeks. That is the overview's "slow, expensive to
  invoke" by design; the alternative is a fast ruling by a party.
- **No clawback.** A verdict after settlement changes standing, not
  balances. Stated as a residual; the fix is a cross-community reversal
  primitive both parties sign, which is Phase 4 at the earliest.
- **Reputation now has a second proven-wrong input source** (witnesses,
  ADR-0033) and a second neutralization source (§11); both are locked-formula
  revisions in the ADR-0009 sense and are stated in ADR-0033 and here.
- **New records.** Tribunal: `rrn.dispute.tribunal_request`, `tribunal_opened`
  (station-signed pin), `tribunal_ballot`, `tribunal_verdict`,
  `tribunal_verdict_lifted`. Arbitration:
  `rrn.fed.arbitration_request`, `arbitration_opened`, `arbitration_ballot`,
  `arbitration_verdict`. Each: distinct discriminator, dCBOR fixture, mobile
  handoff for the member-signed ones (`tribunal_request`, `tribunal_ballot`,
  `arbitration_request`, `arbitration_ballot` are signed on member devices).
- **Caches.** `tribunal_cases`, `arbitration_cases`, `precedents` — derived,
  documented as such, rebuilt by replay.
- **New config.** `tribunal_window_secs` (21 d), `tribunal_juror_response_secs`
  (5 d), `arbitration_window_secs` (30 d, forum), `arbitration_juror_response_secs`
  (5 d), `arbitration_wait_secs` (45 d, home), `arbitration_max_open_per_partner`
  (8). All station-configured like the ADR-0014 windows; the tribunal and
  arbitration windows are candidates for treaty terms in a later ADR.

## Alternatives Considered

- **Create an elected "arbiter" office and seat one arbiter plus six by
  sortition.** Rejected for Phase 3 **(maintainer decision, 2026-09-23)**: it
  introduces an office primitive — terms, elections, removal — into a
  governance model that ADR-0023 deliberately kept role-free, and an elected
  seat is a standing capture target. The reserved standing seat delivers the
  overview's intent (one seat that is not a lottery) with a rank the system
  already computes.
- **Seven by pure sortition, no reserved seat.** Simpler, and considered.
  Rejected because the overview's asymmetry is deliberate: a large-stakes
  panel should contain at least one member whose standing is the community's
  highest, not seven names from a hat. The cost is one deterministic rule.
- **Tribunal as the forum for *all* disputes, replacing the jury.** Rejected:
  a seven-person hearing with mandatory essays for a three-Common
  disagreement is friction the overview's tiered model exists to avoid, and
  most communities cannot seat seven after recusal.
- **Binding precedent — a ballot must cite, and a verdict must follow, prior
  verdicts.** Rejected: the software cannot judge whether a case is "like" a
  prior one; encoding that judgment would make precedent a rule engine with
  a capture surface. An index is honest; statute is the tool for binding
  rules.
- **Arbitration panel drawn from *both* parties' communities.** Rejected:
  such a panel is two partisans and a coin, and it requires each home to
  trust the other's pool computation. A neutral third community's own pool,
  computed on its own log, is verifiable by anyone with that log and has no
  party in it by construction.
- **Federation-wide arbitration pool or a standing federation court.**
  Rejected for Phase 3: it needs the delegate assembly (Phase 4) to
  constitute, and a standing court is the single largest capture target the
  overview warns about. Treaty-named forums are bilateral, revocable, and
  need no federation-level body.
- **Multiple forums / forum by lot among all mutual partners.** Rejected: the
  requester would forum-shop, and the neutrality test would have to run over
  every partner at every request. One named forum per treaty is auditable.
- **Cross-community clawback on a late `uphold`.** Rejected for Phase 3: a
  reversal is a new signed cross-community transfer; nobody has signed it,
  and the station cannot sign on a member's behalf (ADR-0006). Record-only is
  the honest outcome; the residual is stated.
- **Layer-4 appeal of governance and membership decisions.** Rejected as
  out of scope: expulsion and membership governance are not built (ADR-0012
  Follow-up), so there is no record to appeal. The basis is defined narrowly
  enough to extend later without a new record kind.
- **Home-run windows for arbitration.** Rejected: two homes would disagree on
  whether a verdict was in time. The forum's attested `opened_at` is the one
  clock the ruling is judged by; each home's wait bound is its own affair and
  never changes the ruling, only whether that home enacts it (ADR-0029
  §8).

## Threat-model obligations (for the implementation tickets)

The `rrn-dispute` and new `rrn-federation` sections of
[`docs/threat-model.md`](../threat-model.md) must gain, in the same PRs:

- **Forum capture.** A forum's electorate is the forum's own; a captured
  forum can rule against a partner's members at will. Mitigations: the forum
  must be Recognition-depth with both sides (the parties chose it); either
  home can suspend the treaty (ADR-0030) and thereby end the forum's
  standing; verdicts are record-only after settlement, so a captured forum
  cannot move money it does not hold. Residual: a captured forum can void
  unsettled transfers until the treaty is suspended.
- **Reasoning as a coercion or doxxing channel.** Signed free text on a
  permanent replicated log. Mitigations: bounds; attributable signature; the
  client surfaces state the rule (no third parties, no evidence beyond the
  record). Residual: the system does not moderate; harm is answered
  socially and by the vouch/reputation consequences of a proven-bad-faith
  ballot, which Phase 3 does not automate.
- **Cross-community juror bribery.** A forum juror is anonymous to the
  parties only until the verdict's ballots are carried (they are signed).
  Mitigation: position-bounded sortition on the forum's log makes the panel
  unpredictable before the request is admitted there; the forum's own
  standing/velocity limits bound how fast a bribed juror can be manufactured.
  Residual: a determined party who learns the forum's log can predict the
  panel once the request is admitted, as with Layer 2 (ADR-0014's accepted
  jury-preview residual, now cross-community).
- **Request spam / forum denial of service.** Mitigations: one request per
  `CaseRef`; requester must be a party; a live freeze or appeal window must
  exist; `arbitration_max_open_per_partner`. Residual: no per-member rate
  limiting (standing residual); a hostile partner can fill its quota with
  frivolous cases against its own members' counterparties, and a griefer
  *inside* one community can exhaust that community's own quota against
  everyone, since the cap is per requesting community, not per member.
- **Tribunal pool packing.** Mitigated by position-bounding at the request
  seq and by the reserved seat's standing rank (velocity-limited).
- **Late or suppressed verdict carriage.** A courier that drops a carried
  request or verdict leaves a visible gap in the issuing writer's federation
  outbox chain (ADR-0020 §2 / ADR-0029 §3); a home writer that never
  *enqueues* the request, or a forum writer that never enqueues its verdict,
  leaves no gap — that suppression is visible only to that community's own
  members and replicas (ADR-0029 §3 residual). Either way the injured side's
  home lapses on its own clock and the status quo holds. Residual: a
  suppressed request is delay, not loss.

## References

- [ADR-0014](0014-phase-1-dispute-resolution.md) — the sortition primitives,
  windows, fail-open rule, and enactment this ADR reuses unchanged for Layer
  2 and extends to Layers 3 and 4
- [ADR-0025](0025-equivocation-dispute-cases.md) — case identity keyed by
  `CaseRef`-style identity, admission-anchored seeds, neutralize-only
  enactment (the model for §11)
- [ADR-0022](0022-admission-clock-time-trust.md) — §5 position-bounded
  electorates; the admission clock every window here reads
- [ADR-0015](0015-electorate-bootstrap-grace.md) — the grace electorate that
  stands in for the pool in a young community
- [ADR-0009](0009-universal-reputation-algorithm.md) — standing (the reserved
  seat's rank) and the attestation-accuracy input this ADR extends to
  witnesses and neutralizes on §11
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — one writer per log;
  outbox-chain gaps make suppression visible
- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) —
  `CommunityId` (now the dispute anchor), federation outboxes, foreign-record
  admission and lineage-aware pinning, the per-station-clock rule
- [ADR-0030](0030-treaties-ratification-depth-lifecycle.md) — the treaty
  `forum` field, Recognition depth, suspension
- [ADR-0031](0031-cross-community-credit-treaty-accounts.md) — the prepare/commit/abort
  protocol a Layer-4 verdict enacts through, and the home/mirror rule
- [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md) —
  `foreign_standing`, read by the forum's recusal rule
- [ADR-0033](0033-oracle-tiers-3-and-4.md) — the Tier-3/4 transactions,
  witnesses, and artifacts the tribunal hears
- [ADR-0035](0035-writer-succession-and-lineage-pinning.md) — lineage-aware
  pinning of the station-signed verdict records
- Design overview §7.3 (the four-layer stack), §7.2 (core principles), §2.5.1
  (right to appeal), §12 Phase 3 ("the interesting milestone")
- `crates/rrn-dispute/src/{sortition,panel,verdict,escalation,equivocation}.rs`
  — the primitives; `crates/rrn-station/src/core.rs` `dispute_anchor()`
- [`docs/threat-model.md`](../threat-model.md) — `rrn-dispute` section, to be
  extended per the obligations above
