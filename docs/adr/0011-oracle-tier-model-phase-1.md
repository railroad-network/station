# 0011 — The Phase-1 oracle ladder: two serviceable tiers, a blocked ceiling, and a derived reputation stake

## Status

Accepted

Date: 2026-08-06

## Context

The design overview (Section 4.3, "The Tiered Oracle Model") describes four rungs
of scrutiny that scale with what a transaction is worth. A three-Common thank-you
does not deserve the same friction as a fifty-Common purchase, and a
cross-community trade deserves more than either. The four tiers:

- **Tier 1** — bilateral confirmation plus a delayed settlement window. Low
  value, low friction; some fraud is tolerable at micro scale.
- **Tier 2** — Tier 1 plus a reputation **stake** by the confirmer, and a longer
  window that doubles as the dispute window.
- **Tier 3** — physical-artifact evidence and three community witnesses.
- **Tier 4** — cross-community validation and governance approval.

M0.5 already shipped Tier 1 in all but name: every transaction is
bilaterally confirmed and waits out a settlement window before balances move.
M1.8 adds Tier 2 and pins down what Phase 1 does — and does not — implement, so
that a receiving station and the federation protocol agree on how a transaction
is classified and what that classification costs.

Two forces shape the decision beyond "just do Section 4.3":

- **Tiers 3 and 4 need machinery Phase 1 does not have** — no artifact-evidence
  channel, no witness quorum, no cross-community validation, and (deliberately,
  see below) no dispute-resolution system. A high-value transaction therefore
  *cannot* be given the scrutiny its amount demands. The question is what to do
  with it in the meantime.

- **Reputation is derived from the log, never stored** (ADR-0009, T1.5.7). Any
  new reputation-affecting fact inherits that constraint: it has to be
  reconstructible by replay, or it cannot feed the score on a second station.
  The naive sketch of a stake — a mutable "locked reputation" balance and a
  standalone `AttestationStake` record threaded through settlement and dispute —
  pulls against that, and against the eighteen signed-record sites and the
  cross-platform CBOR fixtures that a new signed record would touch.

## Decision

**Phase 1 implements Tier 1 and Tier 2 only. Tiers 3 and 4 are deferred to
Phase 2.** Three sub-decisions follow.

### 1. The tier is derived from the amount; only an opt-*up* is recorded

Classification is a pure function of the transaction's amount, computed on the
**absolute** value so a refund or Commons draw carries the same tier — and the
same protection — as the equivalent payment (`rrn-ledger::tier::tier_floor`):

| Amount (centicommons) | Tier |
| --- | --- |
| `abs < 500` (< 5 Commons) | 1 |
| `500 ≤ abs < 5_000` (5–<50 Commons) | 2 |
| `abs ≥ 5_000` (≥ 50 Commons) | 3 → **blocked**, see below |

Because both the sender and the settling station compute the floor identically,
nothing about the tier needs to travel on the wire. The one exception is an
**opt-up**: a party or a listing electing a *higher* tier than the amount alone
requires (`TransactionProposal.oracle_tier`, an omit-when-`None` CBOR field so
plain proposals stay byte-identical). The tier that governs a transaction is
`effective_tier` = the higher of the amount floor and any opt-up. The boundary
values are fixed here at the protocol level for Phase 2 interoperability; they
are **not** per-community tunable.

### 2. A tier above the serviceable ceiling is blocked, never clamped

Phase 1's serviceable ceiling is Tier 2 (`MAX_PHASE1_TIER`). A transaction whose
`effective_tier` exceeds it — a ≥ 50-Common transfer, or an opt-up above Tier 2 —
is **rejected** at the engine before it touches the log
(`Error::TierNotSupported`), surfacing to the caller as an invalid-parameters
RPC error.

This is a deliberate departure from reading Section 4.3 as "everything at or
above 5 Commons is Tier 2." *Clamping* a fifty-Common transaction down to Tier 2
would silently give it less scrutiny than its value demands — exactly the
weakening the tier ladder exists to prevent. The overview's rule is that value
*sets the floor* and the floor is never lowered; honoring that means a
transaction the network cannot yet scrutinize properly does not happen at all
until Phase 2 supplies Tier 3. Members split a large payment or wait; the ledger
never records a large transfer under thin protection.

### 3. The Tier-2 reputation stake is a derived eligibility gate, not a stored balance

Confirming a Tier-2 transaction puts the confirmer's reputation behind it. Phase
1 realizes that as an **eligibility gate evaluated at confirmation time**, not as
a stored `AttestationStake` record:

- **Who may confirm a Tier 2.** The confirmer must clear a hard Member-band floor
  (composite reputation ≥ 2.0) — *or*, while the community is still bootstrapping
  (**fewer than three** members have reached that floor), any member may, so a
  young community is not deadlocked. The grace sunsets automatically, by
  condition (≥ 3 established members), with no genesis clock or founder roster.
- **What is staked.** The confirmer's raw (uncapped) composite reputation at the
  instant of confirmation, ×100 centipoints. It is not written to the
  confirmation record: it is a pure function of the log at `confirmed_at`,
  replayable through `score_raw_at`, which is what dispute review (Phase 2) will
  recompute when it needs the number.

Nothing is deducted from a spendable balance and nothing is released on
settlement, because there is no stored stake to release. The forfeiture path —
a proven-fraudulent Tier-2 confirmation costing the confirmer the staked amount —
is **Phase 2** work, gated on the dispute-resolution system Phase 1 omits; the
value it will claw back is already reconstructible from the log.

### Settlement windows per tier

Tier 1 settles on a **24h** window, Tier 2 on **48h**
(`SettlementConfig::{tier1,tier2}_window_seconds`; `DEFAULT_TIER1_WINDOW_SECONDS`
/ `DEFAULT_TIER2_WINDOW_SECONDS`). The window a transaction serves is derived
from its tier, so — like the tier itself — it is reconstructible from the signed
proposal and never separately recorded. A demo or test may collapse both to a
few seconds with a single uniform override (`SettlementConfig::uniform`, exposed
as `[settlement] window_seconds` in station config). Per-community window tuning
is deferred to M1.9 governance; the defaults apply until then.

## Consequences

- **Positive.** Classification and window are free at the protocol level —
  derived identically everywhere, nothing extra on the wire or in the log. The
  reputation-stake mechanic ships without a new signed record, without mutating
  the eighteen signed-record sites or the cross-platform fixtures, and without a
  mutable "locked reputation" balance that would fight ADR-0009's replayability.
  The blocked ceiling keeps a value the network cannot scrutinize off the ledger
  entirely, which is the safe failure.
- **Negative / accepted.** A ≥ 50-Common transfer simply cannot happen in Phase
  1; members must split it or wait for Phase 2. The stake is currently
  *consequence-free* — there is no forfeiture until the dispute system lands — so
  in Phase 1 it functions as an eligibility filter and an audit anchor more than
  a live deterrent. Both are intended.
- **Follow-up.** Phase 2 adds Tier 3 (artifact evidence + three witnesses), Tier
  4 (cross-community validation), the dispute-resolution system, and the
  stake-forfeiture path that gives the Tier-2 stake teeth. Storing the stake as a
  signed record later is an additive, omit-when-zero change if a future
  requirement wants it on the wire. The mobile surface for tier + countdown and
  the bootstrap-grace banner is a tracked follow-up (T1.8.6).

## Alternatives Considered

- **Clamp a high-value transaction to Tier 2 instead of blocking it.** Rejected:
  it silently weakens scrutiny for exactly the transactions that most need it,
  contradicting "value sets the floor and the floor is never lowered."
- **A stored `AttestationStake` signed record with a locked-reputation balance
  and a `StakeReleased` entry on settlement.** Rejected for Phase 1: it adds a
  new signed record and a mutable balance that fights the derive-from-log
  invariant, for a mechanic that has no forfeiture path to exercise it yet. The
  derived gate is reversible — the record can be added additively in Phase 2.
- **A flat 5%-of-reputation stake with no eligibility floor (the original task
  sketch).** Rejected: with no forfeiture in Phase 1 a flat percentage is
  inert, whereas an eligibility floor delivers a real Phase-1 property — only
  members who have earned standing may vouch for a deliberate purchase — while
  the bootstrap grace keeps a new community usable.
- **Per-community tunable tier boundaries.** Rejected: the boundaries are fixed
  at the protocol level so classification is identical across the federation
  (Phase 2 interop). Only the *windows* are earmarked for per-community tuning,
  and only from M1.9.

## References

- Design overview, Section 4.3 — "The Tiered Oracle Model"; Section 4.1 — "The
  Attack Surface" (oracle attacks); Section 7 — dispute layer (Phase 2).
- [ADR-0005](0005-station-signed-settlement.md) — station-signed settlement and
  the settlement window this tiers.
- [ADR-0009](0009-universal-reputation-algorithm.md) — reputation is derived
  from the log; the composite the stake reads.
- [ADR-0010](0010-marketplace-data-model.md) — listings declare an `oracle_tier`
  floor that opts a transaction up.
- Threat model — `rrn-ledger` § "Oracle tiering and the reputation stake".
