# 0025 — Equivocation cases are a distinct jury case kind with a Lapsed default and identity-anchored sortition

## Status

Proposed — **DRAFT, direction maintainer-ratified 2026-09-04; formally Accepted in T2.3.4.**

The `EquivocationRecord`, its evidence verification, the station's detection
wiring, and the reputation input shipped in T2.3.3 (PR #29); the jury machinery
this ADR governs is **not yet built**. The design below was reviewed and its key
choices ratified by the maintainer (the reputation consequence, the `Lapsed`
default, identity-anchored sortition, payee recusal, and the cert-issuance gate);
the follow-up ticket T2.3.4 finalizes the details and flips this to Accepted when
it implements the jury path. Treat the *directions* as settled and the *exact
mechanics* as subject to T2.3.4.

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

Equivocation cases are a **distinct case kind** adjudicated by the same ADR-0014
sortition primitives (`eligible_pool`, `draw_sequence`, `vouchers_of`) reused
verbatim, but with their own case derivation, seed, recusal set, verdict record,
and enactment, leaving the transaction-dispute path untouched. **The pool and the
draw are one shared rule; only the recusal set, the verdict type, and the
enactment vary by case kind** — no case-kind-specific eligibility or draw tweaks.

1. **Case identity and discovery.** A case is derived by replay from the
   `EquivocationRecord`s on the log, but is **keyed by the equivocation identity
   `(subject, kind, cert_id | chain_position)`, not by the record's
   content-address.** Two different valid proofs of the *same* offence (e.g. two
   admissible subsets of the same overspend) are **one case** with attached
   evidence and **one penalty**, never two.
2. **Sortition seed anchored to admission, not to accused-authored content.** The
   accused authors the evidence (both fork entries; the spend set and its
   ordering), so seeding the draw from the record's content-address would let a
   planner *grind* their second commitment until the seed draws a friendly panel.
   The seed is instead `hash(case identity ‖ admission log position of the first
   admitted record ‖ genesis anchor)` — the same admission-time anchoring ADR-0022
   / PR #19 already rely on. The station retains only its pre-existing coarse
   timing influence (an accepted ADR-0014 residual); the accused and the reporter
   have none.
3. **Recusal by subject *and* injured party.** The excluded set is
   `{ subject } ∪ vouchers_of(subject) ∪ payees_of(the conflicting commitments)`
   — the single-subject generalization of ADR-0014's recusal, plus the
   counterparties who are about to eat the loss (an interested party ADR-0014's
   two-party model recused automatically). **The recusal set is computed from
   vouch/party state at the admission log position**, so a voucher cannot revoke
   to become seatable nor a friend vouch to get recused. Voucher-recusal relaxes
   before subject-recusal if that is what seats a panel, exactly as ADR-0014 does;
   the subject is never eligible to judge their own case.
4. **Verdict records.** A new `EquivocationVerdictRecord` kind (defined in
   `rrn-ledger::escrow` in T2.3.3) with decisions `Confirm | Overturn`, distinct
   from `JurorVerdict` so no shipped wire format changes. The T2.3.3 record names a
   single `equivocation_id` (a content address) and scoring neutralizes per record;
   because a case is keyed by *identity* (§1), **an `Overturn` must neutralize every
   record attached to that identity, not just the one content-address it names** —
   T2.3.4 either keys the verdict by the case identity or emits one `Overturn` per
   attached record. Until then the honest single-writer station holds exactly one
   record per identity (dedup, §1), so the distinction is latent; the jury path must
   not inherit it silently.
5. **Three log-derived terminal states; a lapse is `Lapsed`, not a synthesized
   `Confirm`.** The reputation penalty applies at **record verification**, not at
   verdict (T2.3.3), so the status quo after a verified record is *already*
   "penalty applied." A case therefore has three terminal states, each derived
   from the log: `Confirmed` (a jury affirmed the evidence), `Overturned` (a jury
   invalidated it — the penalty lifts), and `Lapsed` (the window closed with no
   ruling). **A lapse leaves the already-applied penalty standing — this is
   ADR-0014's fail-open with the status quo correctly identified, not an inversion
   of it** — but it is recorded as `Lapsed`, never as a `Confirm` no juror signed.
   A `Lapsed` case is **re-seatable** on request by any established member (small
   communities in bootstrap grace, ADR-0015, may lapse routinely and must be able
   to try again); a `Confirmed` case is final. Crucially, any consequence *heavier
   than the reputation penalty* that the path later gains (see §7) requires an
   affirmative `Confirmed`, so jury inaction never enacts anything new.
6. **Neutralize-only enactment.** An equivocation verdict voids no transfer and
   settles nothing; `Overturn` simply lifts the reputation penalty (already wired
   in T2.3.3's scoring), and `Confirmed`/`Lapsed` append nothing to the ledger.
   No new ledger enactment primitive touches balances.
7. **The reputation consequence, and the cert-issuance gate.** A verified,
   un-overturned equivocation **zeroes both live reputation dimensions** — trade
   reliability (the highest-weighted dimension, the one a counterparty reads
   before accepting an offline spend — a false headroom claim) and attestation
   accuracy (a signed statement proven false) — de-establishing the member
   (ADR-0009 bands). Because a member with little reputation to lose is barely
   touched by that alone, a verified un-overturned equivocation **also disqualifies
   the member from issuing new headroom certificates** until it is overturned — a
   derived eligibility gate in the spirit of ADR-0011's Tier-2 stake: you
   double-committed offline credit, you get no fresh offline credit until a jury
   says otherwise. (The reputation zeroing shipped in T2.3.3; the cert-issuance
   gate is T2.3.4.)

## Consequences

- The shipped ADR-0014 transaction-dispute path is not modified, so its
  regression surface is untouched.
- Some sortition/tally scaffolding is duplicated for the new case kind rather
  than generalized — accepted to keep the wire format and the working path
  stable.
- Identity-keyed cases and admission-anchored seeding cost a little more
  bookkeeping than content-address keying but close a real panel-grinding vector
  and prevent double-penalizing one offence proved two ways.
- Until T2.3.4 lands, a verified equivocation zeroes reputation with **no jury
  recourse**; T2.3.3's `verify_evidence` re-check during scoring is the interim
  guard against a malicious/buggy station (see the threat model). A good-faith
  outbox fork from a wallet restored from backup is the canonical `Overturn`
  ground — and the station refuses to record a "fork" whose two entries are
  payload-identical (a duplicate, not a fork), so an honest re-send is never
  itself an equivocation.
- Compensating the stranded receiver of a refused cert-backed spend remains out
  of scope (a governance question; ADR-0021 residual).
- **Anchoring cascade.** Zeroing a member's dimensions drops their composite, so
  if they were the *sole* anchor of another identity (ADR-0009 identity anchoring),
  that identity falls back to the anchor cap until re-anchored. This is the intended
  chain-of-trust cost of vouching for someone who then equivocates, but T2.3.4
  should surface it (a de-anchored member is not themselves accused).
- **Overturn signer trust (T2.3.4).** Scoring currently accepts an `Overturn` from
  any signer (`overturned_equivocations`); safe today because no path but the
  station can append one (the verdict kind is `UnroutableKind` on DTN with no RPC
  surface), but a peer-gossiped member-signed `Overturn` would lift a penalty once
  cross-station sync admits foreign records. T2.3.4 gates it on the station signer
  (there is a `// T2.3.4:` marker in the code).

## Alternatives Considered

- **Generalize `rrn-dispute`'s core types to host both case kinds.** Rejected:
  re-typing `JurorVerdict.proposal_id` breaks a shipped signed wire format, and
  threading a `case_kind` branch through `resolution.rs` risks a wrong default
  silently flipping a real transaction dispute in a subsystem already in pilot use.
- **Confirm-on-lapse (invert ADR-0014's fail-open).** Rejected: with the penalty
  already applied at verification, a lapse standing *is* fail-open — no inversion
  is needed, and synthesizing a `Confirm` no juror signed derives a terminal state
  from a timer rather than from a log entry, and would silently pre-authorize any
  heavier future consequence. A distinct `Lapsed` state is strictly clearer.
- **Seed sortition from the record's content-address.** Rejected: the accused
  authors the evidence, so a content-address seed is grindable for a friendly
  panel. Admission-position anchoring removes that lever.
- **Recuse only the subject and their vouchers.** Rejected: it drops the injured
  payees ADR-0014's two-party model recused for free.
- **A fixed sub-cap reputation penalty (e.g. −1.0).** Rejected: at any value that
  keeps a maxed member's composite in the Member band it leaves the equivocator
  established (vote + jury seat) — no governance consequence — and it is
  regressive (invisible on a newcomer, trivial on a veteran). Zeroing the two live
  dimensions is the heaviest expressible, proportional, and fully reversible
  consequence within ADR-0009's locked, floored formula.
- **A single dented dimension.** Rejected: equivocation is two proven-wrong facts
  (a false headroom claim *and* a failed settlement) and fills both of ADR-0009's
  reserved negative slots; denting only attestation accuracy would leave trade
  reliability — the dimension a counterparty actually reads — pristine.
- **Ship the full jury path inside T2.3.3.** Rejected: it forces this ADR's
  question to be answered implicitly in code review rather than explicitly here,
  and makes an already-large ticket larger.

## References

- ADR-0021 §5 — charters the equivocation record, dispute, and reputation input.
- ADR-0014 — the sortition jury whose pool/draw/voucher primitives this case kind
  reuses verbatim; its fail-open rule is preserved (the status quo here is the
  applied penalty), with `Lapsed` made an explicit terminal state.
- ADR-0011 — the Tier-2 stake as a derived eligibility gate; the cert-issuance
  disqualification follows the same pattern.
- ADR-0009 — the locked scoring formula the equivocation input feeds (both live
  dimensions zeroed).
- ADR-0015 — bootstrap grace, why small communities lapse and must re-seat.
- ADR-0020 §2 — outbox forks, one of the two equivocation bases.
- ADR-0022 / PR #19 — admission-time anchoring, reused for the sortition seed.
- T2.3.3 (this milestone) — records, verification, detection, and reputation
  input; T2.3.4 — the jury path this ADR governs.
