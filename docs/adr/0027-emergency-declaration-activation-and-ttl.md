# 0027 — Emergency declaration activation is a single first-crossing event, and a part-signed declaration expires

## Status

Proposed — revised 2026-09-10 after an adversarial Fable review (see "Review history").

Date: 2026-09-10

This ADR is a **design sketch for ratification**, opened to resolve two findings a
second review (2026-09-10) raised against [ADR-0023](0023-emergency-governance-modes.md)
and recorded there as open, ratification-pending Clarifications. It supersedes those two
Clarification entries once accepted. It is **not yet implemented**; §"Decision" states a
proposed rule and the specific sub-choices a maintainer must settle before code lands.

The design carries **two independent parts** — D1 (activation is a single first-crossing
event) and D2 (a declaration time-to-live). D1 is a corrected reading of ADR-0023 §2 with
its one open mechanism now settled (D1b, below) and is ready to accept; D2 is a genuinely
new mechanism whose *justification* and *alternative* the maintainer should weigh. They
are kept in one ADR because they share the "make it a signed, replay-derivable fact"
discipline, but **D1 may be accepted independently of D2** — a reviewer suggested a split,
and a maintainer who wants D1 now can accept §D1/§D3 and hold §D2 for a further round.

## Context

ADR-0023 §2 says an emergency "takes force at the admission of the co-signature that
brings the count of distinct electorate signatures to at least the threshold," anchored
on the admission clock and restated in a station-signed `emergency_activated` record so
every replica agrees on the boundary (ADR-0022 §1). The T2.8.2 implementation
(`rrn_governance::emergency`) has two gaps in *when* that activation fires and *how long*
a declaration may wait to fire it.

**1. Activation is a standing condition, not a single event.** `try_activate` runs on
every `emergency_declaration` / `emergency_cosign` append for a declaration and activates
whenever the distinct-eligible count stands at or above the threshold *and*
`chain_decision` admits it at that append's admission instant. Two consequences:

- A crossing that `chain_decision` **refuses** — because a §4 cap binds (the renewal
  count cap, or the 14-day total-active duration cap) — leaves **no record**. A later
  distinct-eligible co-signature, admitted once the cooldown has passed, re-satisfies the
  standing condition and **revives** the declaration, activating on consents gathered for
  the earlier, refused crisis. *(Note the precise trigger: a crossing merely* within *the
  §4 cooldown is a §4* continuation *and activates normally — `chain_decision` returns
  `Some(count+1)`; only a bound cap returns `None`. ADR-0023 §4 states both "a
  continuation inherits the prior chain's count" and "within the cooldown simply does not
  activate"; the code resolves them as "continuation unless a cap binds", and this ADR
  uses that resolution. The revival hole is about cap-refused crossings, not continuations.)*
- There is no bound on how long a declaration may sit part-signed. The threat is not a
  colluding faction (which has a better off-log strategy — see D2 residuals) but a
  **non-colluding** stale consent: member X co-signs a genuine storm declaration that
  falls one short; months later a different group obtains one more signature and fires the
  emergency on X's months-old consent. Re-judging every co-signer's eligibility at the
  crossing position (which the implementation already does) drops signers who have since
  left the electorate, but a still-eligible X's stale consent still counts.

**2. Neither rule is enforceable by a writer-side check alone.** Emergency state must be
*re-derivable from the signed log for all time* (ADR-0023 §5, invariant 1). A refused
crossing writes nothing, so replay cannot know an earlier crossing was refused; and the
declaration's admission instant is `entry.created_at`, which each replica **re-stamps on
its own clock** (ADR-0022 §1) — it is the exact reason `emergency_activated` restates the
*activation* instant, and the reason `proposal.rs::find_proposal` refuses to substitute
`created_at` for a window's signed `admitted_at`. So both rules need a **station-signed**
fact at a fixed log position, evaluated at that fact's own single attested pin — the same
single-pin discipline that makes today's activation replica-deterministic.

## Decision (proposed — sub-choices marked ⟨decide⟩)

### D1. Activation is the *first* threshold-crossing position, and only it

> An emergency activates at the **first** declaration/co-sign position `p` for its
> declaration at which `count(p) ≥ threshold(p)`, where the distinct-eligible count and
> the threshold denominator `N` are judged at `p`'s pin. If `chain_decision` refuses that
> first crossing (a §4 count or duration cap binds), the declaration is **dead**: it does
> not activate, and no later append revives it. A first crossing that `chain_decision`
> *admits* — including one inside the cooldown, which is a §4 continuation — activates
> normally.

"First position where `count ≥ threshold`" is deliberately *not* "the record that is the
Nth signature": candidate positions are only admitted declaration/co-sign records, and a
repeat or ineligible signer is refused at the door and is not a candidate, so activation
always requires a fresh member act and the station never writes an attestation on the
admission of an unrelated record. (The earlier draft's "a shrinking N would mean no
record is ever the Nth, so it would never activate" is dropped as overstated — both
readings require a fresh signing act; the difference is only *which* record is named.)

**Making D1 replay-derivable — D1b, a station-signed refusal record (chosen).** When the
station admits a first crossing that `chain_decision` refuses, it writes

```
emergency_refused { declaration_hash: Hash, crossing_seq: u64, refused_instant: i64 }   // station-signed
```

Replay validates it the same way it validates an activation — at the single attested pin
`(refused_instant, crossing_seq)`: `count(crossing_seq) ≥ threshold(crossing_seq)` **and**
`chain_decision(prior-legitimate-activations, refused_instant, refused_instant +
clamp(duration), max_renewals) == None`. `emergency_timeline` keeps a `dead_decls` set
beside today's `seen_decls`; an `emergency_activated` for a declaration with a validated
refusal at an earlier position is ignored. Both checks read only signed values at one
pin, so they are replica-identical.

*Rejected: D1a (a `crossing_seq` field on `emergency_activated`, replay recomputing "was
this the first crossing").* Recomputing the first crossing means evaluating
`count/threshold` at *earlier* candidate positions, which have **no** station-signed time;
the only value available is the re-stamped `created_at`, and the reputation scorer uses
time arithmetically (decay), so replicas would disagree on where the first crossing was —
replay could even reject the station's own legitimate attestation. D1a is also redundant:
the attestation is appended immediately after the crossing record, so `crossing_seq =
activation_seq − 1` on every honest path — it carries no independently-checkable
information. D1b confines every evaluation to one attested pin and so avoids this.

### D2. A declaration has a time-to-live

> A declaration and its co-signatures cease to count toward activation if the first
> crossing is not reached within `EMERGENCY_DECLARATION_TTL` of the declaration's
> **station-signed** admission instant. `EMERGENCY_DECLARATION_TTL` is a hard constant,
> proposed **7 days** (= `EMERGENCY_DURATION_CEILING`): a crisis whose supermajority
> cannot be assembled within the longest single emergency is no longer the same crisis.

*Why it is worth its cost.* D2 protects the **non-colluding stale consent** of Context §1
— a case that is on-log by construction (the honest signer submitted their co-sign), so
the TTL closes it completely and the off-log residual below does not apply. It does *not*
defend against a colluding faction, which has a better strategy (see residuals); the ADR
does not claim it does.

**The signed anchor — the eager admission attestation (chosen).** The station writes

```
emergency_declaration_admitted { declaration_hash: Hash, admitted_at: i64 }   // station-signed
```

when it admits the declaration, and both the writer and replay check
`crossing_instant − admitted_at ≤ EMERGENCY_DECLARATION_TTL` against that signed value.
This is the shape of `ProposalWindow.admitted_at` and survives station re-bootstrap by
outbox replay (ADR-0020).

*Rejected: a `declaration_admitted_at` field restated on `emergency_activated`.* It is
only written when activation is attempted, so the check would read the declaration's
admission time from the unsigned `created_at`; on a station re-bootstrapped from outbox
replay every `created_at` is re-stamped to replay time, the TTL silently restarts, and the
"restated" value the station then signs is wrong with no way for replay to detect it —
the exact invariant-1 breach D2 exists to prevent.

⟨decide⟩ **the boundary** (`≤` vs `<` at exactly the TTL) — pin it, as ADR-0023's
2026-09-09 clarification (ii) did for the active span. Proposed `≤`.

**D2 residuals (stated, not resolved).**
- **Off-log sleeper.** The TTL bounds the *gathering* window between the declaration's
  admission and the crossing, measured on signed admission instants. A *colluding* faction
  can hold the whole signed bundle (declaration + co-signs) off the log and courier it in
  together; admissions are then near-simultaneous and the TTL is trivially satisfied, so
  the stale-intent attack survives in its less-visible form. Bounding *signature* age
  (not gathering-window age) is a different mechanism — see Alternatives.
- **DTN carriage.** A gathering window is a carriage-latency question (unlike §4's
  *duration* ceiling, which deliberately is not). A 7-day TTL can void a legitimate
  declaration whose co-signs ride a slow courier. The expected usage is §2's own pattern —
  co-present members co-sign locally and the whole bundle is couriered together, keeping
  admissions close; a declaration admitted early over a good link with co-signs trickling
  in over slow carriers is the penalised case.

### D3. Front-door behaviour is explicit (typed refusals)

Under D1/D2 a declaration has three inert states — **dead** (cap-refused), **expired**
(TTL), **already-activated**. A co-signature toward one is **refused at admission with a
typed error** (`DeclarationDead`, `DeclarationExpired`, `AlreadyActivated`), not silently
appended as dead weight — the same choice ADR-0023 §1(i) made for over-Tier amounts, so a
member learns why. The §6 accountability report surfaces refused/dead declarations, not
only activated ones. A cap-refused declaration's honest remedy (when the *duration* cap
bound) is a fresh declaration with a shorter `duration_secs`; the typed error should say so.

### Preconditions and pinned edges

- **Station-signer pinning.** `emergency_timeline` does not today verify that an
  `emergency_activated` envelope is signed by the station key; its authority rests on "the
  facts it restates." Every record this ADR adds (`emergency_refused`,
  `emergency_declaration_admitted`) has authority **only** "the station said so," so
  signer-pinning of station attestations is a **precondition** of this ADR (it is already
  the noted priority follow-up from the T2.8.2 reviews).
- **Two new record kinds, both station-signed** — `emergency_refused` and
  `emergency_declaration_admitted` — bringing ADR-0023's four to six. The mobile side
  decodes them (fixtures) but never produces them.
- The TTL applies to **declarations only**, not lapse motions (a stale lift is the safe
  direction, and `append_lapse` already requires an active emergency).
- Only **admitted** records are candidate crossing positions; a `SignerMismatch` or
  ineligible co-sign refused at the door is not a candidate and "uses up" nothing.
- The writer's crossing instant is `now.max(tail.created_at)` (`next_admission`); pin that
  a station clock regression cannot push it past `admitted_at + TTL` while wall time has
  not (immaterial, but pinned as the 2026-09-09 clarification did for the span).

## Consequences

- **Positive.** Closes the cap-refusal revival path (D1b) and the on-log non-colluding
  stale consent (D2); makes "when did this activate / why is it dead" a single, auditable,
  replay-derivable, signer-pinned fact; D3 gives members a reason instead of silence.
- **Negative / cost.** Two new station-signed record kinds, their CBOR fixtures, and the
  mobile byte-identical-encoding handoff; the TTL adds a fail-closed way for a
  slow-carriage declaration to expire; the off-log residual remains (Alternatives names
  the mechanism that would close it).
- **Determinism.** Every rule reads a station-signed value at a fixed log position and is
  evaluated at that record's single attested pin, so it is replica-identical — the whole
  point of D1b over D1a and of the eager anchor over the restated field.
- **Follow-up.** Station-signer pinning (precondition) must land first or alongside. A
  general position-bounded charter resolution (ADR-0023 clarification (ii)) is unrelated
  here — the TTL is a hard constant.

## Alternatives Considered

- **Leave activation a standing condition (status quo).** Rejected: the cap-refusal
  revival and non-colluding stale-consent paths are real, and "activate only on the first
  crossing" is the more faithful reading of §2.
- **D1a — `crossing_seq` on the attestation, replay recomputes.** Rejected: not
  replica-deterministic (earlier candidate positions have no signed time; decay makes the
  threshold time-dependent) and redundant (`crossing_seq = activation_seq − 1`). See D1.
- **D2 restated-field anchor.** Rejected: does not survive outbox re-bootstrap. See D2.
- **TTL from `created_at` directly.** Rejected: `created_at` is re-stamped per replica.
- **A signed timestamp on `emergency_cosign` to bound signature age.** Rejected:
  reintroduces the author-clock trust ADR-0022 removed.
- **A log-head freshness witness on the declaration/co-sign (⟨decide⟩ — the live
  alternative for the off-log residual).** Each co-sign (and the declaration) carries the
  hash of a log head the signer had seen; a signer cannot know a future head, so the
  witness is an unforgeable lower bound on signing position that the station verifies
  structurally, with **no clock trust**. This bounds *signature age* (the off-log residual
  D2 leaves open) rather than the gathering window, at D1b's wire-cost class, penalising
  only a signer whose last sync predates the window — the honest physics ADR-0020/0022
  already accept. It is a **direction, not a finished design**: turning the witness into a
  *time* bound still needs a station-signed instant near the witnessed head. The maintainer
  should decide whether to evaluate this before locking D2's admission-anchored TTL, or to
  ship D2 as the cheaper on-log defence and treat the witness as separate future work.

## Review history

- **2026-09-10 — adversarial Fable review (revise-and-resubmit).** Flipped the preferred
  activation marker from D1a to **D1b** (D1a's replay verification is not
  replica-deterministic and is redundant); restated the "dead" trigger as *cap-refused*,
  not *within-cooldown* (a continuation is allowed); pinned D2's anchor to the **eager**
  admission attestation and dropped the restated-field option (fails re-bootstrap);
  reframed D2's justification around the **non-colluding** stale consent (the colluding
  case has an off-log escape); added **D3** typed front-door refusals; recorded the
  **log-head freshness witness** as the live alternative for the off-log residual; made
  station-signer pinning an explicit precondition; and noted D1 may be accepted
  independently of D2.

## References

- [ADR-0023](0023-emergency-governance-modes.md) — emergency governance modes (§2
  activation, §4 expiry/lapse/caps/cooldown, §5 replica-determinism; §1(i) typed-refusal
  precedent; 2026-09-10 Clarifications this ADR supersedes).
- [ADR-0022](0022-admission-clock-time-trust.md) — the admission clock; why `created_at`
  is re-stamped and boundaries must be station-signed.
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — the single-writer log, outbox
  chains, and replay; the station re-bootstrap-by-replay case D2's anchor and D1b must
  survive.
- `crates/rrn-governance/src/emergency.rs` — `try_activate`, `emergency_timeline`
  (`seen_decls`/`chain_pairs`), `eligible_signatures`, `crossing_seq`, `chain_decision`;
  `crates/rrn-governance/src/window.rs` — `ProposalWindow.admitted_at`, the eager-anchor
  template; `crates/rrn-reputation/src/scoring.rs` — `score_at_position` (why an unattested
  position has no deterministic time).
- The lapse-aggregation counterpart finding (ADR-0023 2026-09-10 clarification) shipped as
  option A in the same review round.
