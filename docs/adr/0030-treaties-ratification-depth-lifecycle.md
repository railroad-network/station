# 0030 — Treaties: ratification, depth, lifecycle, and suspension

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review to a Fable 5.1 reviewer, which returned ACCEPT-WITH-CHANGES for the set of
eight; the changes are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted by Fable 5.1 against the maintainer's
> scope decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification by an
> independent Fable 5.1 reviewer at the maintainer's delegation. The review's
> findings folded into this ADR: a `PartnerAccepted` state for partner-first acceptance; the succession routing carve-out so a successor's first entry can be evaluated; the true convergence bound; the checkpoint-rollback row follows ADR-0029's structural rule.
> Implementation tickets are written against this ratified text.

## Context

Federation is *protocol, not merger* (design overview §8.1): two communities
agree on a shared unit, a shared identity standard, a minimum rights floor, and
an inter-community dispute interface, and stay sovereign over everything else.
The instrument that records that agreement is the **treaty** (§8.2, §8.4). The
overview sketches its lifecycle — discovery, proposal, internal ratification
"with a meaningful approval threshold", signing by "both governance keys",
active federation — and a four-rung ladder of depth (Trade, Recognition,
Alliance, Full Federation). It leaves open what a treaty *is* as bytes, how a
partner verifies that the other side genuinely ratified it, what happens to a
treaty when a charter changes, and how a treaty ends.

The shipped system constrains the answers:

- **There is no governance key distinct from the writer key.** ADR-0005 makes
  the station's Ed25519 key the signer of every station attestation, and
  ADR-0012 makes the charter self-authenticating through a founder multisig and
  amendments through the vote lifecycle. "Both governance keys sign" has to be
  mapped onto keys and records that exist.
- **Ratification already has one path.** ADR-0012 §4 deliberately chose the
  proposal/vote lifecycle over a second member-multisig mechanism for charter
  amendments, so there is exactly one ratification path to audit. A treaty is a
  constitutional-weight commitment — it lets credit leave the community — and
  should not reintroduce the parallel mechanism ADR-0012 rejected.
- **The charter hash is the federation anchor** (ADR-0012 §1: "the stable
  federation anchor the overview asks for"), and the overview §8.3 already
  distinguishes an *amendment* (lineage intact, same community evolving) from a
  *replacement* (no lineage, renegotiate). ADR-0029 fixes the community's
  federation identity as its genesis charter hash **(maintainer decision,
  2026-09-23)**, so a treaty pins a lineage, not a snapshot.
- **One log, one writer** (ADR-0020). A treaty must be a fact each community's
  own writer admits to its own log, derivable by replay, and the partner's
  ratification must arrive as a foreign record carried in the partner writer's
  federation outbox (ADR-0029 §3) — never as a merged state.
- **Emergency governance exists** (ADR-0023, ADR-0027) and compresses exactly
  one window for exactly one proposal kind. A treaty must not become a way to
  federate in a hurry during a declared emergency, and an emergency in one
  community must not silently unwind its partners' positions.

Two forces shape the depth question. Alliance and Full Federation (shared
commons pools, joint governance of shared resources, a shared council, free
movement) presuppose the delegate assembly and federation governance body the
overview schedules for Phase 4; building the treaty *records* for them now
would encode obligations nothing can enforce. Trade and Recognition, by
contrast, are fully expressible with the Phase 2 stack plus the ADRs in this
set: credit up to a bilateral limit (ADR-0031), listing visibility (ADR-0032),
and portable standing (ADR-0032).

Finally, sanctions. The overview §8.7 describes four federation-wide sanction
levels propagated to every member community. That requires a federation-level
decision body; without one, the only party who can sanction a partner is the
other party to the treaty. Phase 3 therefore builds **bilateral** suspension
and termination and defers multi-party sanctions **(maintainer decision,
2026-09-23)**.

## Decision

**A treaty is a canonical-dCBOR payload identified by its content hash, agreed
between exactly two communities, at one of two depths (Trade or Recognition).
Each community ratifies it through its ordinary governance at the
charter-amendment bar; on passage its writer appends a station-signed
acceptance that names the passed proposal and its tally, so the partner can
verify the ratification and not merely a signature. A treaty is Active on a log
once both communities' acceptances are admitted there. It is suspended,
resumed, or terminated by governance, or suspended automatically on log-derived
evidence of partner misbehaviour; suspension and termination freeze the treaty
position and hide listings but net nothing. Everything is derived from each
community's own log; nothing is merged.**

### 1. The treaty payload and its identity

A `Treaty` is a canonical dCBOR map (ADR-0002). It is a *payload*, not itself a
log record: it is carried inside the governance proposal that ratifies it and
restated inside the acceptance record.

| field | type | meaning |
|---|---|---|
| `version` | u32 | `1` |
| `parties` | `[CommunityId; 2]` | the two genesis charter hashes, **sorted ascending by bytes** so both communities compute the same `TreatyId` |
| `depth` | string | `"trade"` or `"recognition"` (§2) |
| `credit_limit_centi` | i64 (> 0) | the bilateral limit on the treaty position, symmetric in both directions (ADR-0031) |
| `prepare_ttl_secs` | i64 (> 0) | how long a cross-community prepare may wait for a confirmation, judged by the home station's admission clock (ADR-0031) |
| `settlement_window_secs` | i64 (> 0) | the settlement window for cross-community transactions, on each station's own clock (ADR-0031) |
| `listing_visibility` | bool | whether `federation_visible` listings and needs cross this boundary (ADR-0032) |
| `forum` | `CommunityId`, **omitted when absent** | the neutral third community that arbitrates disputes under this treaty (ADR-0034, §8 below) |
| `previous_treaty` | `TreatyId`, **omitted when absent** | the treaty this one replaces (renegotiation / depth change) |
| `proposed_by` | `CommunityId` | which party authored the text |
| `created_at` | i64 | author's clock; testimony only (ADR-0022) |

`TreatyId = blake3(to_canonical_bytes(treaty))`. Because `parties` is sorted
and the encoding is deterministic, the two communities agree on the identity of
what they are ratifying without any negotiation protocol beyond "here is the
text." Optional fields are omitted from the map when absent (ADR-0010
discipline), so a Phase-4 treaty with new fields keeps every Phase-3 treaty's
identity stable.

`credit_limit_centi` is a single number for both directions. The overview's
example ("mutual credit limit: 500 Commons") is symmetric, and an asymmetric
limit is a renegotiation (a new treaty with `previous_treaty` set), not a
second field — Phase 3 keeps the treaty text minimal so the ratification
question a member votes on is legible.

### 2. Two depths in Phase 3: Trade and Recognition

**(maintainer decision, 2026-09-23)** Phase 3 implements the first two rungs of
the overview §8.4 ladder and no more:

| depth | grants |
|---|---|
| `trade` | cross-community payments up to `credit_limit_centi` (ADR-0031); `federation_visible` listings and needs visible across the boundary when `listing_visibility` is set (ADR-0032); transaction disputes at the forum, if the treaty names one that is Recognition-partnered with both parties (ADR-0034 §7). No identity or standing crosses. |
| `recognition` | everything in `trade`, plus: the partner's writer-signed portable reputation histories are verified and scored locally (ADR-0032); vouches inside such a history count as anchoring in that foreign replay; a Recognition partner may act as a Tier-4 validator (ADR-0033) and, when named as `forum`, as an arbitration venue (ADR-0034). |

Alliance and Full Federation are **deferred to Phase 4**. Their content —
mutual defence obligations, shared commons pool contributions, joint governance
of shared resources, a shared governance council, free movement, a unified
marketplace — presupposes the federation governance body (delegate assembly,
protocol change voting) the overview schedules for Phase 4, and a treaty record
that promises obligations no code can enforce would be a false statement on a
signed log. The `depth` field is a string precisely so the two later values are
additive.

A depth change between the same two parties is a new treaty with
`previous_treaty` set, ratified exactly like the first (§3); on activation the
predecessor is terminated by construction (§6) and its position carries over
(§7).

### 3. Ratification: a `Treaty` proposal at the charter-amendment bar

**(maintainer decision, 2026-09-23)** Governance gains a proposal kind:

```rust
ProposalKind::Treaty { treaty: Treaty }
```

It runs through the ordinary lifecycle (`rrn.gov.proposal`, co-signs, votes,
station-signed `proposal_window` and `proposal_implemented` attestations,
ADR-0012 / ADR-0022) at the **charter-amendment bar**: `amendment_rules
.charter_deliberation_window_days` (default 30), `charter_quorum_pct` (default
50), `charter_approval_pct` (default 75), followed by the ordinary
`implementation_delay_days`. `window_for` treats `Treaty` exactly like
`CharterAmendment`: non-immediate, never compressed (§9).

Why the charter bar and not the statute bar: a treaty lets Commons leave the
community and lets outsiders' standing bear on local decisions (Recognition).
That is the same order of consequence as changing the community's own
constitution, and the overview asks for "a meaningful approval threshold".
A statute-bar treaty (simple majority, 30 % quorum, 7 days) would let a bare
majority of a quiet week federate a community; a charter-bar treaty cannot.

Either community may author the text; `proposed_by` records which. The other
community ratifies the *identical* bytes (same `TreatyId`) or nothing. There is
no counter-offer protocol on the wire in Phase 3: negotiation happens between
people, and the result is one text both put to a vote.

### 4. The acceptance record: station-signed, chained to the tally

**(maintainer decision, 2026-09-23)** When a `Treaty` proposal is implemented,
the writer appends to its own log a station-signed **`rrn.fed.treaty_acceptance`**:

| field | type | meaning |
|---|---|---|
| `treaty` | `Treaty` | the full text, restated so the record is self-contained |
| `treaty_id` | `TreatyId` | `blake3(canonical(treaty))` |
| `community` | `CommunityId` | the accepting community (must be one of `treaty.parties`) |
| `proposal_id` | Hash | the `rrn.gov.proposal` that carried this treaty |
| `tally` | map | `{ yes: u32, no: u32, abstain: u32, electorate: u32 }` as computed by `tally::tally` at implementation |
| `charter_hash` | Hash | the accepting community's *current* charter hash at acceptance — the lineage pin the partner holds (§7) |
| `accepted_at` | i64 | the writer's admission clock at implementation |
| `home_seq` | u64 | the issuer's own log seq at which this record is appended (known at signing under the single-writer lock; appended in the same `LogBatch`). Every writer-signed federation record carries it; the partner pins the record to `writer_at(home_seq)` on its partner-side lineage (ADR-0029 §4) |

The acceptance is then carried to the partner in the federation outbox
(ADR-0029 §3) and admitted there as a foreign record, pinned to the partner's
writer key.

**Why chain to the proposal and tally rather than sign the treaty alone.** A
bare station signature over a `Treaty` proves only that whoever holds the
writer key agreed — which is exactly the "administrator clicked a button" the
overview §8.2 forbids. Naming the proposal and restating the tally makes the
acceptance a *claim about the log*: this proposal, at this position, passed
with these numbers under this charter's bar. A partner cannot replay our log
(it never receives it, ADR-0029 §4), so it cannot recompute the tally; what
it *can* do is hold the writer to a specific, falsifiable statement. If the
community's members later see an acceptance whose tally does not match their
own replay, the writer has signed a false attestation on its own log, which
every member and replica can prove. Accountability to the community, not
verification by the partner, is the security property — the same posture as
ADR-0005's settlement attestations.

**Why not an electorate multisig.** A `MultiSignedPayload<Treaty>` carrying
every yes-voter's signature would let a partner verify the ratification
directly. It was rejected: (a) ADR-0012 §4 already chose the vote lifecycle
over a parallel multisig for exactly this kind of decision, and a treaty
multisig would be the second ratification mechanism that ADR rejected; (b) the
partner still could not verify that the signers *were* the electorate without
our log, so the "direct verification" is illusory — it would verify N
signatures from N keys it has no reason to trust; (c) a treaty with forty
signatures is heavy on LoRa and paper, and the federation outbox is meant to
ride both. The station-signed, tally-chained acceptance is smaller and its
trust model is honest about where the trust lives.

### 5. Activation: both acceptances on one log

A treaty is **Active on a given log** when that log holds both parties'
`rrn.fed.treaty_acceptance` records for the same `treaty_id`: its own (appended
at implementation) and the partner's (admitted as a foreign record). The state
is derived per log by replay; there is no activation record. On replay the
partner's acceptance is pinned to the partner-side `WriterLineage` derived from
this log's own station-signed `rrn.fed.partner_pin` records and the admitted
foreign `rrn.gov.succession` records that precede it (ADR-0029 §4, ADR-0035 §5)
— never from the directory cache, so a replica or a station restored from
backup re-derives every Active treaty from its log alone.

Our own acceptance is admitted only if our `CommunityId ∈ treaty.parties`; a
proposal carrying a treaty we are not party to passes or fails as a vote but
produces no acceptance.

Order does not matter. Pre-treaty routing (ADR-0029 §4) admits the partner's
acceptance whether or not ours exists yet, so the derived state before `Active`
is one of two: **`Proposed`** — our acceptance only — or **`PartnerAccepted`** —
the partner's only. Either becomes `Active` when the other acceptance is
admitted.

Consequences of "per log":

- The two logs may activate at different admission instants and, during a
  partition, one may be Active while the other still shows Proposed. Nothing
  crosses the boundary until *both* are Active, because every cross-community
  record is admitted only under an Active treaty on the admitting log (ADR-0031
  §1, ADR-0032). A prepare admitted at home while the partner is still Proposed
  is refused on arrival there, aborts at home on expiry, and moves nothing.
- Activation is monotone: once both acceptances are admitted they are never
  un-admitted. Later states (§6) are additional records, so a replica replaying
  the same log derives the same state at every position (ADR-0020).
- Before a treaty is Active, the only foreign records a station admits from
  that partner are the ADR-0029 pre-treaty kinds (profile, charter lineage,
  hello, this acceptance, and the cache-only leading checkpoint).

### 6. Lifecycle and state machine

The derived state of a treaty on a log:

```
                 own acceptance admitted
   (none) ─────────────────────────────────► Proposed ──────────┐
      │                                                          │ partner
      │ partner acceptance admitted                              │ acceptance
      └──────────────────────────────────► PartnerAccepted ──────┤ admitted /
                                                                 │ own acceptance
                                                                 ▼ admitted
                                             Active ◄────────────────────────┐
                                                │                             │
      ┌─────────────────────────────────────────┼──────────────────┐          │
      │ governance suspension (either side)     │ evidence         │          │
      │ TreatySuspend → treaty_suspension       │ suspension       │          │
      │   reason = "governance"                 │ (automatic,      │          │
      ▼                                         │  §6.2)           │          │
   Suspended ◄──────────────────────────────────┘                  │          │
      │                                                            │          │
      │ resumption records per §6.3                                │          │
      └────────────────────────────────────────────────────────────┼──────────┘
                                                                   │
      Active | Suspended ── termination (either side) ────────────►│ Terminated (final)
                            TreatyTerminate → treaty_termination
      Active ── successor treaty (previous_treaty = this) Active ─► Terminated (final, §2)
```

#### 6.1 Governance transitions

| proposal kind | bar | record on passage |
|---|---|---|
| `ProposalKind::TreatySuspend { treaty: TreatyId, reason: String }` | statute | `rrn.fed.treaty_suspension { treaty_id, community, reason: "governance", proposal_id, suspended_at }` |
| resumption (a `TreatySuspend` counterpart: `ProposalKind::TreatyResume { treaty: TreatyId }`) | statute | `rrn.fed.treaty_resumption { treaty_id, community, proposal_id, resumed_at }` |
| `ProposalKind::TreatyTerminate { treaty: TreatyId }` | charter-amendment | `rrn.fed.treaty_termination { treaty_id, community, proposal_id, terminated_at }` |

Suspension is deliberately cheaper than ratification (statute bar): pausing
credit flow with a partner is a defensive act a community must be able to take
quickly and reverse. Termination is as expensive as ratification (charter bar):
it is the mirror of the commitment.

All three records are writer-signed, appended to the acting community's own
log, carried to the partner, and admitted there as foreign records. A
suspension or termination from *either* side moves the state on *both* logs
once admitted; a treaty is bilateral, so one party's withdrawal binds both.

#### 6.2 Evidence suspensions (automatic)

The writer appends `rrn.fed.treaty_suspension` **without a proposal** when its
own log-derived evidence proves the partner is misbehaving. `proposal_id` is
omitted; `evidence` carries the proof bytes; `reason` is one of:

| reason | evidence | source |
|---|---|---|
| `"partner-fork"` | two valid partner federation-outbox entries at one position with different `entry_hash` | ADR-0029 §3 (outbox fork = writer equivocation), detected by the existing DTN fork tracking on ingest |
| `"partner-rollback"` | two partner-signed checkpoints at one `seq` with different `content_hash`, or — within the partner's federation-outbox chain — a checkpoint at a **higher outbox position** carrying a **lower `seq`** than an earlier one; the ordering is structural (outbox position), and the checkpoint's `issued_at` is display only, never compared | ADR-0029 §5 `rrn.fed.checkpoint` |
| `"charter-reroot"` | a partner profile whose `charter_hash` has no `previous_hash` lineage back to the `charter_hash` in the partner's acceptance | §7 |
| `"expired-checkpoint"` | `now − received_at > checkpoint_ttl_secs` (default 90 d), where `received_at` is **our** admission-clock instant of the last partner checkpoint we stored — the partner's `issued_at` is testimony and never enters this comparison (ADR-0029 §8) — while cross-community records are pending | ADR-0029 §5; a liveness guard so a dead partner's pending prepares do not hold the position open forever |
| `"writer-unverified"` | a `rrn.gov.succession` record signed by a key that is not the `successor` named in the partner profile we have pinned (ADR-0035 §7); a *profile* from an unpinned key is silently refused per ADR-0029 §2 and suspends nothing | ADR-0029 §2 (TOFU-then-pin), ADR-0035 §7 |

Each is a **write-path decision of the sole writer**, judged at its own
admission instant (ADR-0022), and replay trusts the record — a replica does not
re-adjudicate the evidence, it derives `Suspended` from the record's presence,
exactly as replay trusts an ADR-0027 `emergency_refused` marker. The evidence
bytes are there so a member or auditor *can* check it.

`"expired-checkpoint"` and `"writer-unverified"` are the two reasons that are not
proof of misbehaviour. The first is proof of silence: it exists so that the
ADR-0031 pending-exposure accounting cannot be pinned open by a partner that
vanished. The second is proof of an *unverified* change of writer — a succession
we cannot check against the pin — and it holds the treaty until a human has
verified the new writer out of band. Both are lifted by rules of their own (§6.3).

How a succession record reaches that check at all needs one carve-out in the
ADR-0029 §4 routing rule, because a succession arrives in an outbox chain
*authored by the new key*, which the rule would otherwise refuse
`fed-writer-unpinned` before any succession logic runs. The carve-out: an outbox
entry from an unknown `author`, at position 0 of a fresh chain, carrying exactly
one `rrn.gov.succession` whose `previous_writer` equals the writer we have
pinned for that community, is dispatched to succession verification (ADR-0029
§4, ADR-0035 §7). If the record verifies
(`previous_writer` and `at_hash` match our pinned lineage) *and* `new_writer`
equals the pinned `successor`, the pin advances — a `rrn.fed.partner_pin` is
appended with it — and the new key's per-partner chain continues from that
position-0 entry. If it verifies but `new_writer` is **not** the pinned
`successor`, that is the `"writer-unverified"` evidence above. If it does not
verify, or comes from any other unpinned key, it is refused `fed-writer-unpinned`
and **nothing is suspended**: a stranger with a fresh key cannot grief a treaty
into `Suspended`.

#### 6.3 Resumption rules

- A **governance** suspension is lifted when the log holds a
  `rrn.fed.treaty_resumption` from **every** side that suspended. If both sides
  suspended, both must resume.
- An **evidence** suspension is lifted only by a `rrn.fed.treaty_resumption`
  from the **injured side** — the community whose writer appended the evidence
  suspension — passed at its statute bar. The accused side cannot talk its way
  back in by appending its own resumption; nothing it signs is trusted to
  undo evidence of its own equivocation. Never auto-resume from evidence
  suspensions.
- Exception: `"expired-checkpoint"` lifts on either side's resumption, or
  automatically on admission of a fresh partner checkpoint (it is silence, not
  guilt).
- Exception: `"writer-unverified"` lifts **only** by a `rrn.fed.treaty_resumption`
  from the suspending side, passed at its statute bar (`TreatyResume`) after its
  operator has verified the partner's new writer out of band (ADR-0035 §7). It
  never lifts automatically — not on a later profile, not on a later succession
  record, not on anything the unverified key signs.
- Resumption never re-activates a Terminated treaty. Terminated is final; a
  community that wants to trade again ratifies a new treaty (with
  `previous_treaty` set, so the position history is linked).

### 7. Lineage: amendments keep a treaty, re-roots suspend it

The acceptance's `charter_hash` is the lineage pin. Each community's profile
(ADR-0029) republishes its current `charter_hash` and `charter_version` on
every charter change. On admitting a partner profile, the station walks the
partner's charter lineage as ADR-0012 defines it — from the new hash back
through `previous_hash` links to the pinned hash — using the writer-signed
`rrn.fed.charter_lineage` record the partner carries in its federation outbox
whenever its `charter_hash` changes and on every treaty acceptance (ADR-0029
§3). That record holds the canonical `Charter` payload bytes from genesis to
current, in order; it is cached in the directory next to the profile and is
never a record on our log. The walk checks three things: the first charter's
hash equals the pinned genesis `CommunityId`, every `previous_hash` links to
the hash before it, and the last hash equals the profile's `charter_hash`.

- **Lineage intact** (every link is a `version + 1` with `previous_hash` equal
  to the prior hash): the treaty is unchanged. The *working* pin — the hash held in the directory
  cache beside the profile — advances to the new hash; the on-log pin stays the
  acceptance's `charter_hash`, and the walk always starts from it.
  A community amending its own constitution under its own rules is "the same
  community evolving" (overview §8.3).
- **No lineage** (a charter whose chain does not reach the pinned hash — a
  replacement founder charter, a re-root): the writer appends
  `treaty_suspension("charter-reroot")`. The treaty stays Suspended until the
  re-rooted community's *new* constitution ratifies a new treaty (`previous_
  treaty` set), which on activation terminates this one (§2, §6). The re-rooted
  side cannot resume the old treaty: it is, for federation purposes, a new
  polity, and the overview's "automatic renegotiation requirement" applies.

Lineage walking needs the whole chain, which is why the record carries it
rather than a delta. A profile whose lineage cannot be *walked* — no
`charter_lineage` record yet, or one whose chain does not reach the profile's
hash — is treated as unverified, not as a re-root: the station keeps the old
pin, logs the gap, and waits for a complete record; it does not suspend on
incompleteness, only on proven replacement. What the partner cannot verify is
that each amendment *passed*: it cannot replay our votes. The writer's
signature on the record is its attestation that every link was ratified under
the charter's own rules, and a false one is a signed false statement on the
writer's part — the same standing the acceptance's tally claim has (§4). This
is a stated residual, not a gap the walk can close.

### 8. The forum

`treaty.forum`, when present, names the community that arbitrates disputes
arising under the treaty (ADR-0034). Two rules bind it here:

- **Eligibility is checked at arbitration request, not at ratification.** The
  forum must hold an Active Recognition treaty with **both** parties at the
  admission of the `rrn.fed.arbitration_request`. A treaty may be ratified
  naming a forum whose treaties are not yet in place; that only means no
  arbitration can be opened until they are.
- **When the forum's treaties lapse**, nothing changes in *this* treaty's state.
  An arbitration request naming an ineligible forum is refused at admission
  (slug `forum-not-neutral`), and the parties fall back to what ADR-0034 §7
  provides for a treaty without a usable forum: the transaction dispute runs on
  the home log under ADR-0014/ADR-0034 Layer 3, with no cross-community appeal.
  Changing the forum is a new treaty with `previous_treaty` set.

A treaty with no `forum` is valid at Trade depth. At Recognition depth a forum
is **required** at ratification (a `Treaty` proposal with `depth =
"recognition"` and no `forum` is refused at proposal admission), because
Recognition is what lets foreign standing bear on local decisions, and a
member harmed by that must have somewhere to appeal (overview §2.5.1, right to
appeal).

### 9. Interaction with emergency governance

- A `Treaty`, `TreatySuspend`, `TreatyResume`, or `TreatyTerminate` proposal is
  **never on the compressed path**. ADR-0023 §1 compresses only
  `ProposalKind::Emergency`; these are distinct kinds and run their full
  windows regardless of an active declaration. A community cannot federate, or
  un-federate, in hours during a crisis. (ADR-0023 §3(b) freezes the charter
  doors during an emergency; treaty proposals are not charter amendments and
  are not frozen — they simply take their full 30 days, which outlasts the
  7-day emergency ceiling.)
- **An active emergency in one community does not suspend its treaties.** The
  partner sees the emergency only through the ADR-0029 profile's testimony, if
  at all, and takes no automatic action. A community that wants its partner's
  crisis to pause credit flow passes its own `TreatySuspend` at the statute bar.
- An `Emergency`-kind measure cannot change treaty state: its `title`/`body`
  are free text with no enforcement (ADR-0023 §1), and the treaty state
  machine reads only the records in §6.

### 10. What suspension and termination do — and do not do

**Position freezes.** From the admission of a suspension or termination on a
log, that station admits no new `rrn.fed.prepare` for the treaty and refuses
incoming prepares (slug `fed-treaty-inactive`). Cross-community transactions
already past the home writer's final `rrn.fed.commit` continue to their
outcome on both logs — the credit was committed under an Active treaty and
un-committing it would be a clawback. The counterparty settles its side only
on admission of the home's terminal `rrn.fed.settlement{export}` (ADR-0031 §9),
never on a window of its own run from the commit, so the two logs cannot land
on different outcomes for one transaction. Transactions still in
`Proposed`/prepared state abort at home on their prepare expiry
(`abort("expired")`) as they would have anyway. So the treaty position
converges to a fixed number on both logs, but only once every in-flight
transaction has reached its terminal record at home and that record has been
carried: the bound is `prepare_ttl_secs + settlement_window_secs` plus, for a
disputed transaction, the dispute window (14 d), the tribunal window
(`tribunal_window_secs`, 21 d) and the home's `arbitration_wait_secs` (45 d)
(ADR-0034), plus carriage in each direction. A frozen treaty with an open
arbitration can therefore take months to reach its final position; the
position is never *wrong* in the meantime, only not yet final.

**Nothing nets.** The overview says an expelled community's "credit balances
[are] settled per treaty terms." Phase 3 defines no settlement-of-position
mechanism: a frozen position of +230 on one log and −230 on the other simply
stands, as a signed, replayable fact, until the parties ratify a successor
treaty whose position starts from it (§2, `previous_treaty`) or settle it off
the ledger. This is an accepted residual: a netting instrument (a
station-to-station transfer against the position, or a physical delivery
attested Tier-3 style) is Phase 4 work and needs its own ADR. The threat model
must state plainly that a terminated treaty can strand a positive position.

**Listings hide.** Under `Suspended` or `Terminated`, the partner's
`federation_visible` listings and needs are hidden from search on this log
(the `foreign_listings`/`foreign_needs` caches are filtered by treaty state, not
deleted — ADR-0032), and this community's listings stop being carried to the
partner. Recognized standing already cached (ADR-0032 `foreign_standing`) is
retained but marked as under a non-Active treaty and is not used for any gate.

**Bilateral only.** **(maintainer decision, 2026-09-23)** A suspension or
termination binds the two parties and no one else. There is no propagation to
third communities, no federation-wide notice, and no sanction level. The
overview §8.7 ladder (warning, trade suspension, recognition suspension,
expulsion) is a Phase 4 deliverable riding on the federation governance body;
the Phase 3 primitives — a statute-bar suspension and a charter-bar
termination — are what that ladder will be built from, and are named so that
Level 2 (trade suspension) and Level 4 (expulsion) map onto them directly.
Innocent members are not punished by construction: a suspension freezes the
*inter-community* position and hides listings; every member's own balance,
identity, and standing on their home log are untouched (overview §8.7,
"critical principle").

## Consequences

- **One ratification path, again.** A treaty is a proposal like any other:
  co-signed, voted, tallied, implemented, attested. Every member device that
  can vote on a charter amendment can vote on a treaty with no new signing
  surface. The mobile repo needs a proposal-detail rendering for the new kinds,
  not a new record kind to sign.
- **The partner holds the writer to a falsifiable claim.** The acceptance
  names the proposal and the tally; a writer that lies has signed a false
  attestation on its own log. This is weaker than verification and stronger
  than a bare signature, and the ADR says so rather than pretending otherwise.
- **State is per log and derived.** Two logs can disagree transiently
  (partition) and converge as records arrive; nothing crosses until both are
  Active; every state is a pure function of the records admitted. Replicas
  derive the identical state.
- **Depth is honest.** Trade and Recognition are fully enforceable with the
  ADR set; Alliance and Full Federation wait for the body that could enforce
  them. The string-typed `depth` makes them additive.
- **Suspension is cheap and defensive; termination is expensive and mirrors
  ratification.** Evidence suspensions need no vote and cannot be undone by the
  accused. Of the two non-guilt reasons, `expired-checkpoint` lifts on either
  side and `writer-unverified` only by the suspending side's own vote.
- **Positions can strand.** No netting in Phase 3; a terminated treaty's
  position stands as a fact. Recorded as a residual for Phase 4.
- **New surfaces for implementing tickets:** four `ProposalKind` variants
  (`Treaty`, `TreatySuspend`, `TreatyResume`, `TreatyTerminate`) with
  `window_for` rules and fixtures; five `rrn.fed.*` record kinds
  (`treaty_acceptance`, `treaty_suspension`, `treaty_resumption`,
  `treaty_termination`, plus the `Treaty` payload fixture); the derived treaty
  state reader in `rrn-federation`; the lineage walk; the federation-ingest
  gate "Active treaty required" that ADR-0031/0032 rely on; RPC and `rrn
  federation treaty …` surfaces; the docs site's organizer pages.
- **Threat-model obligations** for the implementing tickets, in the same PR:
  a `rrn-federation` treaty section covering — a writer forging an acceptance
  without a vote (mitigated by tally-chaining and member/replica audit;
  residual: a writer and a captured supermajority together); replay of a
  partner's old acceptance for a superseded treaty (content-addressed, dedup
  on ingest, `previous_treaty` termination rule); a partner spamming
  suspensions to grief (each is one record, position freeze is the intended
  effect, resumption from the injured side only); re-root detection evasion
  by withholding the charter lineage record (unverified ≠ re-root; the station
  waits, does not suspend, and cross-community records still require the
  lineage to verify before Recognition standing is used); the stranded
  position after termination (stated residual); forum ineligibility as a
  denial of appeal (fallback to Layer 3, stated).

## Alternatives Considered

- **Electorate multisig over the treaty** (`MultiSignedPayload<Treaty>` by the
  yes-voters). Rejected — §4: second ratification mechanism ADR-0012 already
  rejected, illusory partner verification, heavy on constrained carriers.
- **Ratification at the statute bar.** Rejected — §3: a bare majority in a
  quiet week should not be able to let credit leave the community; the
  overview asks for a meaningful threshold and the charter bar is the one the
  community already chose for constitutional-weight decisions.
- **All four depths now.** Rejected — §2: Alliance and Full Federation encode
  obligations only the Phase 4 governance body can enforce; a signed promise
  nothing enforces is a false record.
- **Automatic resumption when evidence "clears."** Rejected — §6.3: there is
  no log-derived event that proves a fork was innocent; only the injured side
  can forgive, by a vote.
- **Suspend on any charter change.** Rejected — §7: ADR-0012 lineage exists
  precisely so an amendment is verifiably the same community; suspending on
  every amendment would punish ordinary constitutional maintenance.
- **A negotiation protocol on the wire** (offers, counter-offers, versions).
  Rejected for Phase 3: people negotiate; the protocol ratifies one text.
  `previous_treaty` gives renegotiation a durable link without a state machine
  for haggling.
- **Netting the position at termination** (a station-to-station transfer to
  zero it). Deferred to Phase 4: it is a new credit-moving primitive between
  writers and needs its own ADR and its own audit; stated as a residual.
- **Federation-wide sanction propagation.** Deferred — §10: needs the Phase 4
  body; the bilateral primitives are shaped to be its building blocks.

## References

- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) — `CommunityId`,
  writer key, federation outbox, checkpoints, profiles, directory; the
  pre-treaty record kinds and the ingest path this ADR's records ride
- [ADR-0031](0031-cross-community-credit-treaty-accounts.md) — the treaty
  position, `credit_limit_centi`, `prepare_ttl_secs`, `settlement_window_secs`,
  and the freeze behaviour under suspension
- [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md) — what
  `recognition` depth and `listing_visibility` grant
- [ADR-0033](0033-oracle-tiers-3-and-4.md) — a Recognition partner as Tier-4
  validator
- [ADR-0034](0034-community-tribunal-and-federation-arbitration.md) — the
  `forum`, its eligibility, and the fallback when none is usable
- [ADR-0035](0035-writer-succession-and-lineage-pinning.md) — writer key lineage
  that the acceptance's signer pin follows across succession
- [ADR-0012](0012-charter-format-and-amendments.md) — charter hash as the
  federation anchor, `previous_hash` lineage, the vote lifecycle as the single
  ratification path, `amendment_rules`
- [ADR-0005](0005-station-signed-settlement.md) — station attestations as
  accountable, auditable claims on the community's own log
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — one writer per log;
  per-log derived state
- [ADR-0022](0022-admission-clock-time-trust.md) — each station's own admission
  clock; partner instants as testimony
- [ADR-0023](0023-emergency-governance-modes.md), [ADR-0027](0027-emergency-declaration-activation-and-ttl.md)
  — the compressed path treaty kinds never ride; replay trusting station
  markers (the pattern evidence suspensions follow)
- Design overview §2.5.1 (right to appeal), §8.1–8.4 (federation as protocol,
  handshake, profile, treaty depths), §8.7 (sanctions; innocent members), §12
  Phase 3 / Phase 4 deliverables
