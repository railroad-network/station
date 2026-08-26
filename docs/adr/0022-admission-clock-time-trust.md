# 0022 — The admission clock: the station's clock at admission is the only window-bearing clock

## Status

Accepted

Date: 2026-08-26

## Context

Every window in the system — settlement (ADR-0011), dispute (ADR-0014),
proposal expiry, and now certificate validity (ADR-0021) — reads timestamps.
Phase 1 got away with a simple regime: the single station is the trusted clock
(ADR-0005), and every party-asserted timestamp is bounded to ±5 minutes of the
station's clock at receipt (`CLOCK_SKEW_TOLERANCE_SECS`), with ADR-0019
closing the last gap (`confirmed_at`). ADR-0019 explicitly declared its own
expiry: delay-tolerant sync will deliver *genuinely* old records late, and the
freshness bound would refuse them all. The design overview's third entrance
criterion (§12) states the requirement: say whose clock is trusted for what,
and anchor cross-node ordering in unforgeable structure — log position, not
claimed wall-clock time — because under multi-hop carriage any rule of the
form "signed before the deadline wins" is defeated by backdating.

ADR-0020 sharpens the question nicely: there is exactly one admission point,
so there is exactly one candidate for a trusted clock, and the log's arrival
order is already the system's one unforgeable order.

What a timestamp *in a signed record* can and cannot be, under carriage:

- It **cannot** be verified. A device's clock is self-asserted; a malicious
  party sets it freely; an honest offline device drifts.
- It **can** be bounded for plausibility at admission (not in the future
  relative to the admitting clock; internally consistent within a record
  chain).
- It **must not** decide anything zero-sum. Window starts, deadlines, and
  ordering decide who keeps money; a self-asserted timestamp deciding them is
  an attacker-controlled input.

## Decision

**The station's clock at the moment of admission is the only clock that bears
on windows, deadlines, ordering, and eligibility. Party-asserted timestamps
are retained in records as plausibility-bounded testimony — display and
evidence, never arithmetic. Cross-record order is log order.**

Concretely:

1. **Admission time is the log entry's local receipt time.**
   `log_entries.created_at` — already stored per entry — becomes semantically
   load-bearing on the admitting station: it is *this station's* attestation
   of when it admitted the entry. It is station-local metadata, not signed
   content; a replica replaying the chain re-derives identical *state* but
   does not inherit the admitting station's clock readings. That is correct:
   only the admitting station makes window decisions (ADR-0020), and every
   decision with downstream effect is restated in a station-signed record
   (settlement, cancellation, equivocation — ADR-0005's pattern), which *is*
   signed content and replays everywhere.
2. **Settlement windows run from confirmation admission.** A transaction
   becomes eligible when `admitted_at(confirmation) + window(tier) <= now`.
   The dispute-open deadline is the same instant — the dispute window *is* the
   settlement window, now measured from when the community's ledger learned of
   the confirmation. A confirmation carried by paper for three days serves its
   *full* 24/48-hour dispute window starting on arrival. Late knowledge
   delays settlement; it never truncates protection.
3. **`confirmed_at` becomes testimony.** The freshness refusal of ADR-0019
   (`Error::StaleConfirmation`) is removed — this is the supersession ADR-0019
   scheduled for itself. What remains at admission, for every party-asserted
   timestamp (`proposed_at`, `confirmed_at`, `opened_at`, `responded_at`,
   `requested_at`, …): it may not exceed the admission clock plus
   `CLOCK_SKEW_TOLERANCE_SECS` (**no future-dating** — a record from the
   future is a forgery or a broken clock, refuse it), and it must be
   internally consistent (`proposed_at <= expires_at`; a confirmation's
   `confirmed_at` not before its proposal's `proposed_at` minus skew).
   Arbitrarily *old* is now legal everywhere: old means carried.
4. **Proposal expiry is judged by the admission clock.** A confirmation is
   admitted only while `now <= expires_at + CLOCK_SKEW_TOLERANCE_SECS` — the
   existing rule, unchanged and now the *only* expiry rule (the parallel check
   against the claimed `confirmed_at` is dropped as meaningless testimony).
   `expires_at` remains a sender-chosen bound on how long their offer stands,
   so wallets signing records destined for slow carriers must set expiries to
   match (ADR-0021 point 4). ADR-0018's headroom-release boundary is
   unchanged: it already keys off the same admission-clock expiry rule.
5. **Ordering is log order, full stop.** No admission decision, replay
   computation, or reconciliation rule may compare two records' asserted
   timestamps to decide precedence. Where the system needs "first," it means
   first admitted (ADR-0021's certificate accounting is the paradigm case).
   Deterministic iteration in replay continues to use structural keys
   (`TransactionId` order, log seq) as today.
6. **The station's clock is an operational trust root, stated as such.** The
   operator keeps the station clock roughly right (NTP when networked; manual
   or GPS discipline when not); the threat model gains the entry that a
   station clock wildly wrong stretches or compresses *everyone's* windows
   uniformly — a station-operator trust already accepted in ADR-0005, not a
   new per-member attack surface. Monotonicity: admission times are clamped
   monotone non-decreasing per the log's own order, so a backwards clock step
   cannot reorder windows against log order.

## Consequences

- **Backdating and future-dating are dead as attacks.** No self-asserted
  timestamp reaches any window or ordering computation. ADR-0019's protection
  is preserved and generalized rather than widened into a hole.
- **DTN carriage works.** A record is never refused for being old. The
  legitimately-delayed-confirmation case ADR-0019 called "theoretical until
  delay-tolerant transports exist" is now the design center.
- **Settlement latency becomes partition-shaped.** Balances move at
  reconnection + window rather than signing + window. This is the honest
  physics of ADR-0020 and is surfaced in UX (§11.6 "offline mode feels like
  normal mode running slightly slower").
- **Code changes are localized but cut across crates.** `find_eligible` and
  dispute-deadline checks move from `confirmed_at` to admission time;
  `LedgerSnapshot` must carry admission metadata alongside derived states;
  `Error::StaleConfirmation` is retired; every view/RPC that reports "settles
  at / dispute closes at" re-anchors. `settled_at`/`cancelled_at` in
  station-signed records already carry the admission-clock reading outward.
- **Replicas display, the station decides.** A replica's locally re-stamped
  `created_at` values are cosmetic; any consumer needing authoritative times
  reads the station-signed records. Stated in the threat model.
- **ADR-0019 is superseded for admission semantics** (its context and the
  invariant "no party timestamp beyond skew *into the future*" survive; the
  stale-side refusal does not). ADR-0019 remains accurate history for Phase 1.

## Alternatives Considered

- **Widen the freshness bound for DTN records (days).** Minimal diff;
  reopens exactly the ADR-0019 attack scaled to the widened bound — a
  receiver could erase a multi-day dispute window entirely. Rejected.
- **Hybrid `max(confirmed_at, admitted_at)` anchoring.** Neutralizes
  backdating but keeps two clocks in every window computation forever, for no
  benefit over the pure admission clock (future-dating is refused anyway).
  Rejected for permanent complexity with zero security gain.
- **Signed time beacons / external timestamping (Roughtime-style).** Useful
  against a *malicious station* — but the station already decides settlement
  itself (ADR-0005); hardening its clock without hardening its authority buys
  nothing at this trust level. Reconsider at Phase 3 where *another*
  community must trust our windows.
- **Vector/Lamport clocks in records.** Solves causality across multiple
  writers — a problem ADR-0020 removed. Log order is already a total order
  with stronger properties than any logical clock we could add.

## References

- ADR-0019 — the freshness bound this ADR supersedes, and the charter for it
- ADR-0005 — the station as trusted attestor; the pattern of restating
  decisions in station-signed records
- ADR-0020 — single admission point; arrival order as the one true order
- ADR-0021 — certificate validity and delivery grace, judged by this clock
- ADR-0011 / ADR-0014 — the windows being re-anchored
- Design overview §12 entrance criterion 3 (the time-trust requirement),
  §11.6 (offline UX)
- `crates/rrn-ledger/src/settlement.rs` (`find_eligible`),
  `crates/rrn-ledger/src/engine.rs` (admission checks),
  `crates/rrn-storage/src/log.rs` (`created_at`)
