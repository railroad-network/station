# 0025 — Equivocation cases are a distinct jury case kind, failing to the evidence

## Status

Proposed — **DRAFT STUB, pending human ratification.**

This ADR is a placeholder created alongside T2.3.3 to record the design question
and the intended direction. The `EquivocationRecord`, its evidence
verification, the station's detection wiring, and the reputation input shipped in
T2.3.3; the jury machinery this ADR governs is **not yet built**. The follow-up
ticket (T2.3.4) fleshes out and ratifies this ADR before implementing the jury
path. Do not treat the Decision below as locked until this ADR is Accepted.

Date: 2026-09-04

## Context

ADR-0021 §5 says a proven equivocation (a certificate overspend or an
outbox-chain fork) "automatically opens an ADR-0014 dispute … flowing to a jury
like any other." T2.3.3 implemented everything except the jury, and building the
jury revealed that an equivocation case is **not** "a dispute like any other":

- ADR-0014's `rrn-dispute` machinery is welded to transactions at every layer. A
  case is derived on demand from a ledger transaction in `TransactionState::Disputed`;
  every touchpoint (`find_disputed`, `DisputedInfo { sender, receiver, .. }`,
  `sortition_seed(tx_id, ..)`, `JurorVerdict.proposal_id: TransactionId`, and the
  two enactment primitives `uphold_dispute` / `Settler::settle`) is keyed by a
  `TransactionId` and a two-party model.
- An equivocation case has **one subject** (the equivocator), not two parties;
  its evidence is **cryptographic proof**, not a contested statement; it has **no
  transfer to void** (the verdict only gates a reputation input); and it must fail
  to a **different default** than ADR-0014.

`JurorVerdict.proposal_id` is inside a signed, mobile-verified payload, so it
cannot be re-typed without breaking a shipped wire format — which rules out
generalizing ADR-0014's records in place. Per repo convention (CLAUDE.md), a
decision that deviates from a locked ADR gets its own ADR rather than an implicit
change in code review; this is that ADR.

## Decision

*(Draft — to be finalized in T2.3.4.)*

Equivocation cases are a **distinct case kind** adjudicated by the same ADR-0014
sortition primitives (`eligible_pool`, `draw_sequence`, `sortition_seed`,
`vouchers_of`) reused as-is, but with their own case derivation and records,
leaving the transaction-dispute path untouched:

1. **Case identity and discovery.** A case is derived by replay from an
   `EquivocationRecord` on the log, keyed by its content-addressed
   `equivocation_id` (which also seeds sortition), not by a `TransactionId`.
2. **Recusal by subject.** The excluded set is `{ equivocator } ∪
   vouchers_of(equivocator)` — a single-subject generalization of ADR-0014's
   two-party recusal.
3. **Verdict records.** A new `EquivocationVerdictRecord` kind (defined in
   `rrn-ledger::escrow` in T2.3.3) with decisions `Confirm | Overturn`, distinct
   from `JurorVerdict` so no shipped wire format changes.
4. **Fails to the evidence, not to the status quo.** An unruled or lapsed case
   leaves the recorded proof standing (`Confirm`); only an affirmative `Overturn`
   neutralizes the record for scoring. This **inverts ADR-0014's fail-open-to-
   status-quo default by design**, because here the status quo *is* cryptographic
   proof of double-commitment.
5. **Neutralize-only enactment.** An equivocation verdict voids no transfer and
   settles nothing; `Overturn` simply lifts the reputation penalty (already wired
   in T2.3.3's scoring). No new ledger enactment primitive touches balances.

## Consequences

- The shipped ADR-0014 transaction-dispute path is not modified, so its
  regression surface is untouched.
- Some sortition/tally scaffolding is duplicated for the new case kind rather
  than generalized — accepted to keep the wire format and the working path
  stable.
- Until T2.3.4 lands, an equivocation counts against reputation with **no jury
  recourse**; T2.3.3's `verify_evidence` re-check during scoring is the interim
  guard against a malicious/buggy station (see the threat model).
- Compensating the stranded receiver of a refused cert-backed spend remains out
  of scope (a governance question; ADR-0021 residual).

## Alternatives Considered

- **Generalize `rrn-dispute`'s core types to host both case kinds.** Rejected:
  re-typing `JurorVerdict.proposal_id` breaks a shipped signed wire format, and
  threading a `case_kind` branch through `resolution.rs` risks a wrong default
  silently flipping a real transaction dispute in a subsystem already in pilot use.
- **Ship the full jury path inside T2.3.3.** Rejected: it forces this ADR's
  question to be answered implicitly in code review rather than explicitly here,
  and makes an already-large ticket larger.
- **Reuse ADR-0014's fail-open default unchanged.** Rejected: failing an
  equivocation case open to "no consequence" would discard cryptographic proof on
  mere jury inaction — the opposite of what the evidence warrants.

## References

- ADR-0021 §5 — charters the equivocation record, dispute, and reputation input.
- ADR-0014 — the sortition jury this case kind reuses and deliberately diverges
  from (status-quo default).
- ADR-0009 — the locked scoring formula the equivocation input feeds.
- ADR-0020 §2 — outbox forks, one of the two equivocation bases.
- T2.3.3 (this milestone) — records, verification, detection, and reputation
  input; T2.3.4 — the jury path this ADR governs.
