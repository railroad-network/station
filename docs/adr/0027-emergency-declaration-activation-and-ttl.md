# 0027 — Emergency declaration activation is a single first-crossing event, and a part-signed declaration expires

## Status

Proposed

Date: 2026-09-10

This ADR is a **design sketch for ratification**, opened to resolve two findings a
second review (2026-09-10) raised against [ADR-0023](0023-emergency-governance-modes.md)
and recorded there as open, ratification-pending Clarifications. It supersedes those two
Clarification entries once accepted. It is **not yet implemented**; §"Decision" states a
proposed rule and the specific sub-choices a maintainer must settle before code lands.

## Context

ADR-0023 §2 says an emergency "takes force at the admission of the co-signature that
brings the count of distinct electorate signatures to at least the threshold," anchored
on the admission clock and restated in a station-signed `emergency_activated` record so
every replica agrees on the boundary (ADR-0022 §1). The T2.8.2 implementation
(`rrn_governance::emergency`) has two gaps in *when* that activation fires and *how long*
a declaration may wait to fire it.

**1. Activation is a standing condition, not a single event.** `try_activate` runs on
every `emergency_declaration` / `emergency_cosign` append for a declaration and activates
whenever the distinct-eligible count stands at or above the threshold *and* the §4
caps/cooldown admit it at that append's admission instant. Two consequences:

- A crossing the §4 caps refuse — e.g. it falls inside a chain cooldown, where ADR-0023
  says the declaration "simply does not activate" — leaves **no record**. A later
  distinct-eligible co-signature, admitted once the cooldown has passed, re-satisfies the
  standing condition and **revives** the declaration, activating on consents gathered for
  the earlier, refused crisis.
- There is no bound on how long a declaration may sit part-signed. A faction can gather
  `threshold − 1` co-signatures and hold one back, firing it much later as a pre-signed
  trigger. Re-judging every co-signer's eligibility at the crossing position (which the
  implementation already does in derivation) drops signers who have since left the
  electorate, but a still-eligible member's months-old signature still counts — and the
  *off-log* variant (hold the whole signed bundle off the log and courier it in together
  later) defeats any admission-anchored bound entirely, because `emergency_cosign`
  carries no timestamp and `created_at` is testimony-only (ADR-0022).

**2. Neither rule is enforceable by a writer-side check alone.** Emergency state must be
*re-derivable from the signed log for all time* (ADR-0023 §5, invariant 1). A rule the
station applies only at append time, with nothing signed into the log to record it, is
not a property a late replica can reconstruct. In particular: a refused crossing writes
nothing, so replay cannot know an earlier crossing was refused; and the declaration's
admission instant is `entry.created_at`, which each replica **re-stamps on its own clock**
(ADR-0022 §1) — it is the exact reason `emergency_activated` restates the *activation*
instant, and the reason `proposal.rs::find_proposal` refuses to substitute `created_at`
for a window's signed `admitted_at`. So any TTL "measured from the declaration's
admission" is *not* replica-deterministic unless it reads a **station-signed** statement
of that admission.

## Decision (proposed — sub-choices marked ⟨decide⟩)

### D1. Activation is the *first* threshold-crossing position, and only it

Define the crossing as an **event over log positions**, not "the Nth signature by seq":

> An emergency activates at the **first** declaration/co-sign position `p` for its
> declaration at which `count(p) ≥ threshold(p)`, where both the distinct-eligible count
> and the threshold denominator `N` are judged at `p`'s pin. If the §4 caps/cooldown
> refuse activation at `p`, the declaration is **dead** — it does not activate, and no
> later append revives it.

Defining it as "the record that is the threshold-th signature" is wrong: if `N` shrinks
after an earlier co-sign, no single later record is ever "the Nth", and a legitimately
supported declaration would never activate. "First position where count ≥ threshold" has
no such gap.

To make D1 **replay-derivable**, the log must record which position was the first
crossing and whether it was refused. ⟨decide⟩ one of:

- **D1a — restate the first-crossing seq on `emergency_activated`.** Add a
  `crossing_seq: u64` field; replay believes an attestation only if its `crossing_seq` is
  genuinely the first position at which `count ≥ threshold` (recomputed) and the caps
  admitted *that* position. A refused first crossing then simply has no valid attestation
  and no later one can name a different crossing. *(New signed field → CBOR fixture bump,
  mobile handoff.)*
- **D1b — a station-signed `emergency_refused` record.** When the station admits a
  crossing the caps refuse, it writes `emergency_refused{declaration_hash, crossing_seq}`;
  replay treats a declaration with a refusal as dead. *(New record kind → discriminator +
  fixtures; more log traffic, but an explicit, auditable "we refused this" fact.)*

D1a is the smaller surface and is preferred unless the auditability of an explicit
refusal record is wanted.

### D2. A declaration has a time-to-live

> A declaration and its co-signatures cease to count toward activation if the first
> crossing is not reached within **`TTL`** of the declaration's **station-signed**
> admission instant.

- ⟨decide⟩ **`TTL` value.** Proposed `EMERGENCY_DURATION_CEILING` (7 days): a crisis
  whose supermajority cannot be assembled within the longest single emergency is no
  longer the same crisis. If `EMERGENCY_DURATION_CEILING` remains charter-tunable it must
  be resolved from the **genesis** charter, like the other legitimacy parameters
  (ADR-0023 2026-09-10 clarification (ii)).
- ⟨decide⟩ **the signed anchor.** The TTL must be checked against a station-signed
  declaration-admission instant, not `created_at`. Options: a station-signed
  `emergency_declaration_admitted{declaration_hash, admitted_at}` attestation written when
  the station admits the declaration (mirrors the proposal-window attestation), **or** a
  `declaration_admitted_at: i64` field restated on `emergency_activated` and checked in
  replay. The attestation is written eagerly (every declaration) and bounds even
  declarations that never activate; the restated field is cheaper but only exists once
  activation is attempted.
- ⟨decide⟩ **the boundary.** Pin `≤` vs `<` at exactly `TTL` (ADR-0023's 2026-09-09
  clarification (ii) did this for the active span).

### D2 residuals (stated, not resolved by this ADR)

- **Off-log sleeper.** The TTL bounds only the *gathering* window between the
  declaration's admission and the crossing. A bundle held entirely off-log and couriered
  in together has near-simultaneous admission and satisfies any admission-anchored TTL, so
  the stale-intent attack survives in its less-visible form. Bounding *signature* age
  would need a signed timestamp on `emergency_cosign`, which ADR-0022's author-clock
  distrust deliberately avoids; out of scope here, named honestly.
- **DTN carriage.** A gathering window is a carriage-latency question (unlike §4's
  *duration* ceiling, which is deliberately not). A 7-day TTL can void a legitimate
  declaration whose co-signs ride a slow courier. The expected usage — §2's own pattern,
  where co-present members co-sign locally and the whole bundle is couriered together —
  keeps admissions close; a declaration admitted early over a good link with co-signs
  trickling in over slow carriers is the penalised case.

## Consequences

- **Positive.** Closes the cooldown-revival path and the on-log pre-signed-trigger; makes
  "when did this activate" a single, auditable, replay-derivable fact; the TTL keeps stale
  declarations from lingering as latent levers.
- **Negative / cost.** New signed surface (a field or a record kind, plus CBOR fixtures
  and the mobile byte-identical-encoding handoff); the TTL adds a fail-closed way for a
  slow-carriage declaration to expire; the off-log residual remains.
- **Determinism.** Every rule here reads a station-signed value at a fixed log position,
  so it is replica-identical — the whole point of routing D1/D2 through signed records
  rather than the append-time clock.
- **Follow-up.** A general position-bounded charter resolution (wanted by the ordinary
  tally thresholds too — ADR-0023 clarification (ii)) would let the TTL's ceiling track an
  amendable charter safely; until then it is genesis-resolved.

## Alternatives Considered

- **Leave activation as a standing condition (status quo).** Rejected: the revival and
  pre-signed-trigger paths are real, and "activate only on crossing" is already the more
  faithful reading of §2's "the co-signature that brings the count to ≥ threshold".
- **Writer-side-only enforcement (no signed marker).** Rejected: not reconstructible by a
  replica (ADR-0023 §5), so it would silently diverge across replicas.
- **TTL measured from `created_at`.** Rejected: `created_at` is re-stamped per replica
  (ADR-0022 §1); the check would not be deterministic.
- **A signed timestamp on `emergency_cosign` to bound signature age directly.** Rejected
  for now: reintroduces the author-clock trust ADR-0022 removed; the off-log residual is
  documented instead.

## References

- [ADR-0023](0023-emergency-governance-modes.md) — emergency governance modes (§2
  activation, §4 expiry/lapse, §5 replica-determinism; 2026-09-10 Clarifications this ADR
  supersedes).
- [ADR-0022](0022-admission-clock-time-trust.md) — the admission clock; why `created_at`
  is re-stamped and boundaries must be station-signed.
- `crates/rrn-governance/src/emergency.rs` — `try_activate`, `emergency_timeline`,
  `eligible_signatures`, `crossing_seq`.
- The lapse-aggregation counterpart finding (ADR-0023 2026-09-10 clarification) ships as
  option A in the same review round.
