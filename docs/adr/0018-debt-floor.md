# 0018 — A debt floor bounds how far a member can sign themselves into debt

## Status

Proposed

Date: 2026-08-25

## Context

Mutual credit runs on negative balances: when you receive value, your balance
goes down, and that is the system working as designed (Overview §3.1). But
nothing anywhere bounded *how far* down. The threat model has carried the gap
since Phase 0 — "**No credit limits / no debt bound.** A sender can settle into
arbitrary debt" — and Phase 1 shipped M1.11 pilot readiness without closing it.
A design review (2026-08-25) flagged the combination that makes it urgent
before a real 90-day pilot:

- **Unbounded debt is a walk-away subsidy.** A member can accept value until
  their balance is arbitrarily negative and then stop participating. In a
  zero-sum ledger the loss does not vanish; it is held, permanently, by
  everyone whose positive balances the debtor's spending created. The Overview
  names the **right to exit** as a universal right (§2.5.1) — exit must stay
  free, which means the *exposure* has to be bounded up front, not clawed back
  at the door.
- **The settlement window multiplies the hole.** Balances only move at
  settlement (24h/48h, ADR-0011), so a purely settled-balance check would let a
  member stack any number of proposals inside one window, each seen against a
  balance that none of the others had touched yet.
- **A payment request debits its receiver.** A negative-amount proposal is a
  request the *receiver* pays (the sign convention in
  `SettlementRecord::amount_centi`). The receiver has signed nothing at
  proposal time, so proposal-time enforcement alone would either miss that path
  or punish a receiver for a request they never accepted.

The forces on the *value* of the bound: too tight and new members — who start
at zero and, in a mutual-credit economy, typically go negative before they go
positive — cannot participate; too loose and the walk-away subsidy is material.
Reputation-scaled limits (Overview §5.7, "reputation as collateral") are the
eventual answer, but they need a reputation input the young community does not
have and a governance surface (M1.9 statutes) nothing yet wires to
configuration.

## Decision

**The transaction engine refuses any debit whose signer would thereby be
committed below a debt floor. The floor is a protocol default of −20 Commons
(−2,000 centicommons), overridable per station via `[credit]
debt_floor_centi`, and is evaluated against the member's *committed position*:
settled balance minus every pending debit they have already signed.**

Concretely (`rrn-ledger::credit`, enforced by the `Engine` front door):

1. **Enforcement happens where the signature happens.** A positive-amount
   proposal binds its sender: checked in `submit_proposal`. A negative-amount
   proposal (a payment request) binds its receiver only when they confirm:
   checked in `submit_confirmation`. Nothing is enforced against a party who
   has not signed the debit.
2. **Pending commitments count.** The projected position sums the settled
   balance (the PN-Counter) and every `Proposed`/`Confirmed`/`Disputed`
   transaction the member has signed as debtor. `Disputed` counts — a frozen
   transaction may yet settle as confirmed. Pending *credits* do **not**
   count: an unsettled inflow can still cancel, and headroom must never be
   borrowed against it. A cancelled proposal releases its headroom, and so
   does a still-`Proposed` one that passes its `expires_at` (plus the clock-skew
   tolerance) without being confirmed: past that boundary the engine refuses
   the confirmation by its own clock, so the debit can never land — otherwise a
   counterparty who simply ignored a proposal would consume the sender's
   headroom forever.
3. **The check is a front-door rejection, like the tier ceiling.** A breaching
   proposal or confirmation never reaches the log (`Error::DebtFloorExceeded`,
   surfacing over RPC as invalid-parameters with both the floor and the
   projected position, so the client can render "you can spend up to X").
   Settlement itself is unchanged: anything that legally entered the log
   settles exactly as before, so replay and the sweep are untouched, and no
   new signed record exists.
4. **The default is sized to a new member's runway, erring tight.** −20
   Commons covers a realistic first few weeks of consumption at the
   Overview's reference prices — a 3-Common consultation, an 8-Common grain
   purchase, a handful of Tier-1 trades — before the member has earned
   anything, which is the legitimate need the floor must not choke. Above
   that, generosity is asymmetrically risky: **raising a floor later is a
   painless config change; tightening one strands every member already below
   the new line** (they can receive but not spend until they earn back above
   it — mechanically sound, socially corrosive). So the default starts
   conservative and communities loosen it as trust warrants, not the reverse.
   Four times the Tier-1 boundary, well under the Tier-2 ceiling: a member at
   the floor got there through several deliberate, visible transactions, not
   one. A starter value in the ADR-0009 sense — defensible, recorded, not
   claimed optimal.
5. **The floor is station-configured, community-tuned later.** Like the
   settlement windows (ADR-0011), the floor is an operator config value until
   M1.9+ governance grows a surface for enacting economic parameters. It is
   deliberately *not* per-member: individual limits are the
   reputation-collateral feature (Overview §5.7), a later milestone.

## Consequences

- **The pilot's worst-case walk-away loss is bounded and known** (−20 Commons
  per departing member at the default — about two and a half of the Overview's
  reference grain purchases), instead of unbounded. The threat-model bullet is
  updated from "no debt bound" to the residual risks below.
- **New members can still participate.** The floor is four times the Tier-1
  ceiling; a member can run a realistic few weeks of consumption before
  earning, without touching it.
- **Residual: the contract-charge path is not floor-checked.** A recurring
  service contract's per-period `ContractCharge` (T1.7.7) debits the buyer
  directly, station-signed, without passing `submit_proposal`. The buyer did
  sign the *contract*, so the commitment story is coherent, but total contract
  exposure is not counted against the floor and a charge can land a buyer
  below it. Accepted for Phase 1 (contract terms are bounded and visible);
  folding contract obligations into the committed position is the named
  follow-up.
- **Residual: the floor is per-station configuration.** Until a governance
  surface exists, a station operator can raise or effectively remove the floor
  (`debt_floor_centi = i64::MIN`). This is the same trust already vested in
  the operator for settlement windows, and the config default is safe.
- **Residual: exit-with-debt is bounded, not resolved.** What a community does
  about a departed member's debt — absorb it in a commons pool, socialize it,
  write it off — is a governance and Overview §3 design question this ADR
  deliberately does not answer. The floor caps the size of the question.
- **Gossip replicas re-derive, they do not re-enforce.** The floor gates log
  *admission* on the station that accepts the write (there is one such station
  per community in Phase 1). Replayed entries on a replica are applied as
  received — same posture as the tier ceiling, to be revisited with federation
  (Phase 3) admission rules.

## Alternatives Considered

- **No floor until reputation-scaled credit limits exist.** Rejected: that is
  the status quo, and it puts an unbounded liability under a real pilot. A
  flat floor now does not preclude scaled limits later — the check is one
  function with one config input.
- **Enforce at settlement time instead of signing time.** Rejected: by
  settlement the receiver has delivered value against a commitment the system
  had already accepted; refusing to settle then punishes the creditor, not the
  debtor. Refusal must happen before the counterparty relies on the promise.
- **Count pending inflows toward headroom.** Rejected: an unsettled inflow can
  cancel or be disputed; spending against it converts one member's revocable
  promise into another's accepted commitment.
- **A −50 Commons default (the Tier-3 boundary, ADR-0011).** The first draft,
  with the tidy rationale "the most a member can walk away owing equals the
  largest transaction the phase can express." Rejected as too generous: the
  tier boundary measures per-transaction scrutiny, not cumulative exposure,
  and at the Overview's reference prices −50 is one to two *months* of
  consumption — far past the bootstrap-runway need. The
  loosening-is-easy/tightening-strands-people asymmetry says the starter
  default should sit at the low end of defensible, and −50 does not.
- **A per-member floor scaled by reputation.** Deferred, not rejected — it is
  the Overview §5.7 direction. It needs standing data a young community lacks
  (the ADR-0015 problem all over again) and a governance surface for the
  scale; the flat floor is the bootstrap-compatible base case.
- **Block exit while in debt.** Rejected outright: violates the universal
  right to exit (§2.5.1), and is unenforceable anyway against someone who
  simply stops showing up.

## References

- Design overview §3.1 (mutual credit), §2.5.1 (right to exit), §5.7
  (reputation as collateral — the successor mechanism)
- [ADR-0011](0011-oracle-tier-model-phase-1.md) — the tier ceiling this
  default mirrors, and the front-door-rejection pattern it reuses
- [ADR-0009](0009-universal-reputation-algorithm.md) — the "starter value,
  locked and recorded" convention
- `docs/threat-model.md` — `rrn-ledger` § elevation of privilege; "Known
  limitations" (the bullet this ADR retires)
- `crates/rrn-ledger/src/credit.rs`, `crates/rrn-ledger/src/engine.rs`
