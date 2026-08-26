# 0019 — A freshness bound on `confirmed_at` protects the dispute window

## Status

Accepted

Date: 2026-08-25

## Context

The settlement window is the Phase-1 oracle's dispute window (ADR-0011,
ADR-0014): a confirmed transaction waits 24h (Tier 1) or 48h (Tier 2) before
balances move, and that wait is the only time a party can raise a dispute and
freeze it. Both clocks — the settler's eligibility check and the engine's
dispute-open deadline — are measured from the confirmation's `confirmed_at`.

`confirmed_at` is a receiver-supplied, receiver-signed timestamp. Until this
ADR, the engine accepted any `confirmed_at` up to the proposal's expiry: a
receiver confirming late — but validly — could backdate `confirmed_at` toward
`proposed_at`, shrinking the sender's dispute window or skipping it entirely.
Concretely: a proposal valid for 24h with a 24h Tier-1 window, confirmed at the
end of its validity with `confirmed_at` stamped at its start, is already
"window elapsed" on the next settlement sweep. The sender gets the dispute
window ADR-0014 assumes only if the receiver is honest about the timestamp —
which makes it no protection at all.

The 2026-08 design review's code review surfaced this alongside two adjacent
holes it did fix directly (an expired proposal permanently consuming debt-floor
headroom, and a backdated confirmation reviving an expired proposal). This one
needed a decision, because the obvious fixes trade differently against the
Phase-2 roadmap: delay-tolerant sync (ADR-0017's resequenced Phase 2) will one
day deliver *genuinely* old confirmations late, and the design overview (§12)
already gates Phase 2 on a time-trust ADR — "no self-asserted timestamps in
reconciliation rules".

The engine already bounds every other party-asserted timestamp against the
station's clock at receipt: a proposal's `proposed_at` may not be future-dated
beyond `CLOCK_SKEW_TOLERANCE_SECS` (±5 minutes), a dispute's `opened_at` and a
response's `responded_at` are both bounded by `now` plus skew. `confirmed_at`
was the one signed timestamp with window-bearing consequences and no bound
against the receiving clock.

## Decision

**The engine admits a confirmation only when its `confirmed_at` is within
`CLOCK_SKEW_TOLERANCE_SECS` (±5 minutes) of the station's own clock at
receipt.** A staler timestamp is refused as `Error::StaleConfirmation`; a more
future-dated one as `Error::FutureDated`. Like every other admission check,
this is a front-door rejection — nothing reaches the log.

Consequences of the bound, not separate rules:

- Every window measured from `confirmed_at` — settlement eligibility and the
  dispute-open deadline — is now trustworthy to the skew tolerance. The
  worst-case dispute-window shrinkage is 5 minutes of a 24–48 hour window.
- The rule completes an invariant that can be stated in one line: **no
  party-asserted timestamp is accepted more than clock-skew tolerance from the
  station's clock at receipt.** `confirmed_at` was the last exception.
- The settler and dispute layers are untouched; `confirmed_at` remains the
  single window anchor, now backed by an admission-time guarantee rather than
  receiver honesty.

This is a **Phase-1 rule with a declared expiry**: the Phase-2 time-trust ADR
(already an entrance criterion in Overview §12) owns how timestamps are
trusted under delay-tolerant sync and supersedes this bound there. That ADR
must answer what this one deliberately does not: when a genuinely old
confirmation arrives days late over LoRa or paper, *which* clock starts the
dispute window it serves.

## Consequences

- A receiver can no longer shorten or skip the settlement/dispute window by
  backdating, nor defer settlement by future-dating. The threat-model residual
  for this is closed for Phase 1.
- Confirming devices must have a clock within ±5 minutes of their station's —
  already true of the proposal path, so this adds no new operational
  requirement for the pilot's synchronous transports (local RPC).
- A legitimately delayed confirmation (a mobile that signed while offline and
  delivered the signed record much later) is refused and must be re-signed
  with a fresh timestamp. In Phase 1 the mobile signs at the moment of
  submission over a live channel, so this path is theoretical until
  delay-tolerant transports exist — at which point the superseding time-trust
  ADR applies.
- `Error::FutureDated` now covers confirmations as well as proposals; its
  message text is correspondingly generalized.

## Alternatives Considered

- **Clamp the window start to the log entry's local receipt time**
  (`max(confirmed_at, entry.created_at)`) instead of bounding admission.
  Forward-compatible with delay-tolerant sync — a late confirmation would
  serve a full window from when the station learned of it — but it puts
  per-replica, unsigned local state into window arithmetic, requires plumbing
  receipt times through `LedgerSnapshot` and changing the dispute-deadline
  check in lockstep, and pre-empts exactly the design space the Phase-2
  time-trust ADR is chartered to own. Rejected as premature: the simple bound
  is sufficient for Phase-1 transports and is explicitly superseded later.
- **Bound only the past side.** Future-dating `confirmed_at` merely defers
  settlement — less harmful — but leaving it unbounded would break the
  one-line invariant and let a receiver park a confirmation arbitrarily far
  into the future. The symmetric bound costs nothing.
- **Do nothing until Phase 2.** The dispute window is the *only* Phase-1
  protection on a confirmed transaction; shipping the pilot with it spoofable
  by one party undermines ADR-0014's design premise.

## References

- ADR-0011 — oracle tiers; the settlement window as the dispute window
- ADR-0014 — Phase-1 dispute resolution ("the dispute window *is* the
  settlement window")
- ADR-0017 / Overview §12 — Phase-2 entrance criteria, including the
  time-trust ADR that supersedes this bound for delay-tolerant sync
- ADR-0018 — the debt floor; the adjacent expiry-boundary fixes from the same
  review
- `docs/threat-model.md` — "Tampering — backdating `confirmed_at`" section
