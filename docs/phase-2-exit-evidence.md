# The 72-hour outage simulation

Railroad Network is designed to keep working when the internet does not — degrading
from full connectivity down to local mesh, long-range radio, and, in the last
resort, records carried on paper. This document describes the automated simulation
that tests that promise, what it verifies, what it deliberately leaves to field
testing, and how to run it yourself.

The simulation lives at `crates/rrn-station/tests/outage_72h.rs` and runs as an
ordinary `cargo test`. Because it drives simulated time, a full 72-hour scenario
completes in a few seconds.

## What it demonstrates

A community should be able to lose all connectivity for days, keep transacting over
whatever offline channels remain, and — once reconnected — reconcile cleanly, with:

- **no value lost or created** — every credit is accounted for,
- **no forks or tampering** — the shared ledger stays consistent and verifiable,
- **no credit limit bypassed** — no member is driven past their debt limit, and
- **no double-spend that goes undetected**.

The simulation turns those guarantees into mechanical checks that either pass or
fail with a precise message.

## The scenario

The test stands up one real station daemon — the same software an operator runs —
and a community of about twenty members. Time is injected rather than read from the
system clock, so the daemon behaves exactly as it would in production while the
harness fast-forwards through three simulated days.

**Stage 1 — Normal operations.** Members transact and settle a realistic spread of
balances. One member is deliberately steered close to their debt limit, so a later
offline spend will test the limit under pressure.

**Stage 2 — Connectivity is lost.** The station keeps running with no reachable
network. Over the next 72 simulated hours, economic activity flows in over every
offline channel the platform supports:

- **couriers** carrying batched, signed records between devices — including the
  messy realities of the field: delayed delivery, the same batch carried by two
  couriers, partial and out-of-order batches, and a batch lost entirely and later
  re-sent by its author;
- **paper** — records encoded to printable payloads, then read back and submitted;
- **long-range radio** — records crossing a lossy, bandwidth-constrained link that
  drops, duplicates, and reorders frames, exactly as a real radio would.

Interleaved with the honest traffic are the cases the system must catch: a member
who tries to spend the same reserved credit twice, a member who signs two
conflicting versions of the same record, a spend that would breach the debt limit,
and outright hostile inputs — a forged record, a tampered record, and a replayed
old batch.

**Stage 3 — Reconnect.** All queued, delayed, and re-sent traffic drains in.

**Stage 4 — Settlement.** Every settlement window elapses and the station finalizes
the confirmed ledger.

## What it verifies

After the scenario runs, the harness checks the following. Each is an independent
assertion that fails loudly, naming the exact record or ledger position at fault.

**Ledger integrity.** The append-only, hash-linked log verifies end to end, and
every record's signature checks out — no entry can have been altered, dropped, or
reordered.

**Value conservation.** Because credit is mutual, all balances must sum to zero.
The harness confirms this before the outage, at reconnect, and after final
settlement.

**Full reconciliation.** The harness keeps its own independent record of what every
submitted transaction was *meant* to do, and reconciles it against the station's
signed receipts and against every member's final balance. Every record is accounted
for as accepted, already-known, or refused-with-a-reason — nothing is silently lost
or conjured, and nothing appears on the log that was not accepted.

**Credit limit upheld at every step.** Re-deriving balances from the log after each
and every entry, no member is ever projected past their debt limit — the same rule
the engine enforces when it accepts a transaction, checked here independently and
exhaustively.

**Reserved credit honored.** A member can reserve credit ahead of time so an offline
spend clears even when their live balance could not cover it. The harness confirms
such spends are accepted on their reservation, and that no reservation is ever
overspent.

**Double-spends and conflicting records are caught — and only those.** Exactly the
one planted double-spend and the one planted conflicting-record case are flagged;
the honest look-alikes (a legitimate spend that happens to use a reservation to the
last unit, and the same batch delivered twice) are not.

**Settlement windows respected.** No transaction settles before its settlement
window has fully elapsed, measured from when the station admitted the confirmation —
so a delayed record cannot shortcut the dispute window.

**Hostile inputs leave no trace.** Forged, tampered, and replayed inputs are all
refused; none adds anything to the ledger.

**Determinism.** The entire run is reproducible: repeating it produces a
byte-for-byte identical ledger. Continuous integration runs several independent
scenarios; every one satisfies every check above.

## What it does not prove

The simulation is a software test. It stands in for, but cannot replace, testing in
the real world:

- **Real radios and airtime.** The long-range-radio and SMS paths use a faithful
  *software* model of a lossy, bandwidth-limited link. Actual radio behavior,
  regulatory duty-cycle limits, and hardware bring-up require testing on physical
  devices.
- **Real clocks and real people.** Time is simulated and the couriers are code. Clock
  skew between real devices, human delay and error, and the handling of physical
  paper can only be approximated here.
- **Scale.** The community is deliberately kept to about twenty members — the target
  size for a single community — rather than stress-tested for load.

The definitive proof is a scheduled, staffed 72-hour exercise on real hardware. This
simulation is what makes the team confident enough to run that exercise; it is not a
substitute for it.

## Running it

```sh
# The full run: several independent scenarios plus the reproducibility check.
cargo test -p rrn-station --test outage_72h

# A single scenario, narrated step by step for a human reader.
scripts/demo-phase-2-outage.sh
```

## Confidence that the checks have teeth

A test suite is only as trustworthy as its ability to fail. Each check here is
designed to break loudly when its invariant is violated. For example, tightening the
debt limit the harness checks against — so that a member who is legitimately within
the real limit now appears to exceed the tightened one — produces:

```
floor invariant violated at log prefix seq 7: rrn1660cl4x… settled 0 - committed 1700 = -1700 < floor -1600
```

naming the exact ledger position and the amounts involved. Every other check fails
in the same specific, legible way.

## Further reading

The design decisions this simulation exercises — mutual credit and the debt limit,
delay-tolerant delivery of signed records, reserved-credit certificates, and the
detection of conflicting commitments — are documented in the project's Architecture
Decision Records under [`docs/adr/`](adr/), with the overall design in
[`docs/design/`](design/).
