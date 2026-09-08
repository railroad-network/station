# Phase 2 exit evidence — the 72-hour outage simulation

This document is the human-facing exit evidence for **Phase 2 — Single-Community
Resilience** (ADR-0017). It explains what the outage simulation harness proves,
what it deliberately cannot prove, and how to run it.

## The exit criterion, made executable

ADR-0017 resequenced single-community resilience ahead of federation and set its
exit bar: a community must survive a prolonged, total connectivity loss with real
economic activity, then reconcile with **no credits lost, no ledger forks, and no
credit limit violated**. The harness (`crates/rrn-station/tests/outage_72h.rs`)
turns that sentence into a mechanical, seeded, fast test.

It stands up **one real `station` daemon** on an injected manual clock, driven
over its Unix socket exactly as a production operator's tools would drive it, and
runs a community of ~20 members through:

- **T0 — normal operations.** Settled payments spread a realistic balance sheet;
  one member is deliberately steered to within ~300 centicommons of the debt
  floor.
- **T1 — connectivity lost.** The station keeps running with no reachable link.
  Seventy-two *simulated* hours of activity flow in over every offline channel:
  - direct courier bundles (`bundle_submit`, ADR-0020 §3);
  - multi-courier carriage with **delay, duplication, gaps, and one lost-forever
    bundle** whose author re-exports it at reconnect;
  - a **paper leg** round-tripped through the T2.5.2 paper codec
    (`rrn_protocol::paper`);
  - a **mock constrained-carrier (LoRa) leg** across a lossy, airtime-budgeted
    channel via the `DtnSyncer` (T2.6.2), then ingested through the DTN front door.
  Woven through the activity are the offence cases: the operator's **headroom
  certificate** flow with an at-cap spend and a planted **double-spend**, a planted
  **outbox fork**, an engineered **debt-floor bounce**, and adversarial garnish (a
  forged-authorship bundle, a tampered inner record, and a replayed old bundle).
- **T2 — reconnect.** All queued and lost carriage drains.
- **T3 — settlement horizon.** Every settlement window elapses and the station
  settles the confirmed ledger.

Simulated time (injected clocks end to end, ADR/CLAUDE.md discipline) collapses
the 72 hours to a few seconds of wall-clock.

## What it asserts — the nine invariants

Each is a named check with a legible failure message:

1. **No forks.** The hash-chained log verifies (`verify_chain`) and every entry's
   signature verifies.
2. **Conservation.** The sum of all settled balances is exactly zero at T0, T2,
   and T3 (a zero-sum mutual-credit ledger).
3. **Full reconciliation (no credits lost).** The harness keeps its own ledger of
   *intent* — what each submitted record was meant to become — and diffs it against
   the station's receipts (per-record `admitted` / `known` / `refused-with-reason`)
   and against every member's final settled balance. Nothing is lost or conjured.
4. **Floor invariant at every prefix.** Replaying the final log, at *every* prefix,
   every debtor's projected position (settled balance minus committed debits) is at
   or above the floor — the very invariant the engine enforces at each admission
   (ADR-0018), re-checked independently.
5. **Escrow honored.** No certificate is consumed beyond its cap, and the at-cap
   cert-backed spend was admitted on its reserved headroom (ADR-0021).
6. **Equivocation.** *Exactly* the planted double-spend and outbox fork produced
   equivocation records — one cert-overspend, one outbox-fork — and the innocent
   look-alikes (the at-cap spend, the duplicated carriage) produced none.
7. **Windows.** No transaction settled before its confirmation-admission time plus
   the settlement window (ADR-0022 metadata vs. each settlement record).
8. **Adversarial.** Tampered, forged, and replayed inputs left nothing but refusals
   and `known` — they admitted nothing new to the log.
9. **Determinism.** The whole run is a pure function of its seed: repeating a seed
   yields a byte-identical final chain digest. CI runs seeds {1, 2, 3}; the
   property is the point, the seeds are spot checks.

## What it does *not* prove

The harness is a software integration test. It stands in for, but cannot replace:

- **Real radios and real airtime.** The LoRa/SMS legs use a *mock* carrier
  (drop / duplicate / reorder at the design's punishing airtime budget). Actual
  RF behaviour, duty-cycle regulation, and hardware bring-up are the field
  tickets' job (**T2.6.3** RNode/M1 bring-up, **T2.7.x** SMS).
- **Real clocks and real humans.** Time is injected and the "couriers" are code.
  Wall-clock skew between real devices, human courier latency and error, and paper
  handling in the field are only approximated here.
- **Scale.** The cast is ~20 members by design (ADR-0017's community size), not a
  load test. Log sizes are noted in the PR for curiosity, not stressed.

The real live drill — a scheduled, staffed 72-hour exercise on real hardware — is
the human sign-off this harness makes *ready*, not the sign-off itself. The field
tickets above and that drill close the remaining gap.

## How to run it

```sh
# The full exit gate: seeds {1,2,3} plus the determinism check (a few seconds).
cargo test -p rrn-station --test outage_72h

# A single seed, narrated for a human (timeline + each invariant in turn):
scripts/demo-phase-2-outage.sh 1
```

The harness is **demonstrably capable of failing**: break any invariant it guards
(for example, tighten the floor the prefix checker asserts against, or expect the
engineered bounce to be admitted) and the corresponding named assertion fails with
a message naming the breach — e.g.

```
floor invariant violated at log prefix seq 7: rrn1660cl4x… projected -1700 < floor -1600
```
