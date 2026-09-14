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

---

## Phase 2 exit statement

*Appended 2026-09-13 at the Phase 2 consolidation. This is the one page to read
to declare Phase 2 (single-community resilience, ADR-0017) done, or to name what
remains. Every "met" cites the evidence; every "pending" names the human step.*

### The exit criterion (ADR-0017)

ADR-0017: "One community survives a simulated 72-hour full connectivity loss
with real economic activity — full reconciliation, no credits lost, no ledger
forks." The design overview §12 adds a fourth clause — "no credit limit (debt
floor, treaty limit, tier boundary) violated by any merge" — which the table
carries as well.

| Criterion | Status | Evidence |
| --- | --- | --- |
| Survives a simulated 72-hour full connectivity loss with real economic activity | **Met (simulation)** | `crates/rrn-station/tests/outage_72h.rs`: three independent seeded scenarios (`outage_72h_seed_1..3`) drive one real daemon and ~20 members through 72 simulated hours over courier, paper, and a lossy radio model; runs in CI. |
| Full reconciliation | **Met (simulation)** | `assert_no_phantom_admissions` + the harness's independent intent ledger reconciled against every receipt and final balance; `outage_lost_then_reexport` proves a lost bundle re-exports and lands. |
| No credits lost | **Met (simulation)** | `assert_conservation` (balances sum to zero) at T0, at reconnect, and after settlement; `assert_conservation_from_log` re-derives it from the log. |
| No ledger forks | **Met (by construction + simulation)** | ADR-0020 single writer; `assert_no_forks` over the final chain; `outage_72h_is_deterministic` reproduces a byte-identical chain digest. |
| No credit limit violated by any merge | **Met (simulation + property test)** | `assert_floor_invariant_every_prefix` re-derives every member's committed position after every log entry; `rrn-ledger` proptest `the_floor_is_never_breached_by_admitted_operations` over arbitrary interleavings (ADR-0021 §6). Tier ceiling: Tier-3 amounts are refused, never clamped. |
| Reproducible | **Met** | `outage_72h_is_deterministic`; `scripts/demo-phase-2-outage.sh` narrates any scenario. |

### The deliverables (design overview §12) and the physical red team

| Deliverable | Status | Evidence / what remains |
| --- | --- | --- |
| Offline-first hardening | **Met** | `crates/rrn-station/tests/offline_lifecycle.rs`; no NTP, bounded peer dial, `rrn status` connectivity block. |
| Delay-tolerant networking | **Met** | Outbox chains, bundles, receipts, courier relay, station-originated push and receipt correlation (`rrn dtn push/status`). |
| LoRa radio integration | **Software met; field sign-off pending** | RNode templating, airtime budget, `scripts/field-test-lora.sh` (dry-run in CI); two radios bench-verified over the air on 2026-09-11 (RSSI −40 dBm, SNR 12–14 dB). **Human step:** record the §5 field-acceptance checklist of `docs/lora-radio-bringup.md` at real range. **Scope note:** the field run proves bundle-push + receipt; a full propose → confirm → settle round-trip over radio waits on a station-side outbox export (no CLI wallet exists — needs an ADR). |
| SMS interface | **Seam met; gateway not built** | Codec, sender registry, per-sender cap, money-first relay, all against a mock gateway (`crates/rrn-station/tests/sms_carrier.rs`). **Open:** the physical modem gateway (a human-gated hardware ticket). The custodial feature-phone model is out of scope by decision (ADR-0006). |
| Physical credential layer | **Met** | `rrn paper` family, `scripts/demo-phase-2-paper.sh` end to end. |
| Emergency governance | **Met** | ADR-0023 + ADR-0027 implemented and tested (`crates/rrn-governance/tests/{emergency_governance,emergency_activation_ttl,station_signer_pinning}.rs`). |
| Node seizure resistance | **Met (opt-in, Linux)** | ADR-0024 encrypted profile; `crates/rrn-station/tests/at_rest_dmcrypt.rs` and the `at-rest-dmcrypt` CI lane; `scripts/drill-seizure-recovery.sh`. **Human step:** verify Adiantum throughput on a Raspberry Pi 4 in the field; a mobile client that reproduces the ceremony fingerprint. |
| "Red team the physical security" | **Checklist delivered; exercise pending** | `docs/security/phase-2-redteam.md` (by attacker, each defense traced to code, residuals stated); the community outage drill facilitator's guide in `docs/community-setup.md` Part 6. **Human step:** run the drill with real people; the independent professional audit is still pending. |

### Open residuals accepted at exit

Stated fully in the threat model's "Known limitations"; the ones a reader
should weigh before calling the phase done:

1. **No per-member rate limiting** on any surface (bundle submission, receipt
   fetch, governance, vouches, marketplace, the socket, the peer port). Accepted
   at ~20-member pilot scale behind the pairing gate.
2. **Cleartext carriage.** Bundles, receipts, and sheets are readable by whoever
   carries them; SMS exposes metadata to the phone network; radio exposes
   location. Content is community-public; the residual is metadata.
3. **Hidden certificate history** — an offline receiver sees only the history
   the payer presents; the cap bounds the loss (ADR-0021).
4. **The station is the liveness single point of failure** (ADR-0020);
   recovery is restore + outbox replay, or the holder ceremony.
5. **Running-node seizure is not defended** (ADR-0024).
6. **Ledger station-signed records are unpinned on replay**, and the gossip
   pull path applies no front-door gate. Both are reachable only through a
   configured gossip peer; the pilot configures none.
7. **Emergency governance's structural residuals** (ADR-0023): a standing
   two-thirds faction; a ≤ 2-member grace electorate; scope as testimony; the
   off-log stale-consent bundle (ADR-0027 D2).
8. **The dispute/jury electorates are time-bounded**, not position-bounded like
   governance's. *Closed:* `rrn-dispute` now computes every pool, electorate, and
   weight over `grace_electorate_asof`/`tier2_stake_centi_asof` at the anchoring
   admission seq (the dispute entry's seq for the jury, the escalation entry's for
   its electorate, the round's own for equivocation), so back-dated standing
   admitted after a round opened cannot pack it (ADR-0022 §5).

### Findings surfaced by the consolidation, for the maintainer

- **Founder-charter door not frozen during an emergency.** *Closed (this PR).*
  ADR-0023 §3(b) requires freezing the replacement founder charter, not only the
  amendment path. Both founder-charter write doors (`charter::store_charter` and
  the ceremony's `store_pending_charter`) now refuse, at the monotone-clamped
  admission instant, any charter that would re-root the community while an
  emergency holds (`CharterError::FrozenByEmergency` via `check_charter_freeze`;
  a write-path guard on the sole writer, replay trusts the log). The guard keys
  on "a root already exists", so an equal-version re-root — the reachable shape,
  since construction paths pin version 1 — is caught too. The one surviving
  vector is a charter injected via the ungated gossip front door, which the
  gossip-gate follow-up addresses.
- **Declaration threshold is `ceil(2N/3)` in code** (`declaration_threshold`)
  where ADR-0023 §2's prose says `ceil(N × 67 / 100)`; the ADR's own worked
  examples match the code, and its dated Clarification of 2026-09-09 records
  the two-thirds reading. That clarification is still marked "for maintainer
  ratification" — the ratification is what remains.
- **ADR-0027's status text said "not yet implemented"** while the code had
  shipped; corrected in this pass with a dated implementation note.

### Verdict

By the ADR-0017 criterion the phase exits on simulation evidence today. Two
deliverables stop at a software seam by design (SMS gateway, LoRa field
sign-off) and are recorded as human-gated follow-ups rather than blockers; the
90-day community pilot and the professional audit remain the gates to real
value, as they were before Phase 2.
