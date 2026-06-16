# 0005 — The station signs settlement and cancellation records

## Status

Accepted

Date: 2026-06-16

## Context

A mutual-credit transaction in Railroad Network has a lifecycle:
`Proposed → Confirmed → Settled` (or `→ Cancelled`). The append-only,
hash-chained log (`rrn-storage::log`) is the source of truth: every transition
is recorded as a log entry, and a transaction's current state is *derived* by
replaying those entries (CLAUDE.md, "The log is the source of truth").

The log only accepts **signed** entries: `AppendLog::append` takes a
`SignedPayload<T>` and verifies the signature before writing. That is
deliberate — it is what makes the log non-repudiable. Two of the four
transitions have an obvious signer:

- a **proposal** is signed by the **sender** (it debits the sender);
- a **confirmation** is signed by the **receiver** (it accepts the debit).

But the other two do not:

- **settlement** happens *automatically* once the settlement window elapses.
  No transacting party performs an action at that moment — a background sweep
  does. Yet settlement must be recorded in the log (M0.5 exit criterion and
  T0.5.8 require a settlement entry, and `verify_chain` must still pass), so
  *someone* must sign it.
- **cancellation** (withdrawal, rejection, or expiry) likewise may be triggered
  by expiry with no party present, and an expired/rejected proposal still needs
  an immutable record of *why* it ended.

The M0.5 task specs sketched `Settler::new(db, config)` and an `Engine` with no
signing key, which cannot append to the log. The specs predate the realization
that the log is signature-gated; this is the kind of stale-signature gap the
project has hit before (see the reconciliations in M0.1–M0.4).

## Decision

The local **station** — the running `station` software, which owns its own
Ed25519 keypair — signs settlement and cancellation records with that key.

Concretely:

- `Settler::new(db, station: Keypair, config)` and
  `Engine::new(db, station: Keypair)` both take the station keypair.
- Settlement appends a station-signed `SettlementRecord`; cancellation appends a
  station-signed `CancellationRecord`. Each restates the transaction id (and,
  for settlement, the parties and amount) so balances remain fully re-derivable
  from the log alone.
- The station's public key doubles as this node's `ReplicaId` for the
  per-replica PN-Counter that materializes balances.

A settlement/cancellation record is therefore an attestation by the station
that "I observed this transaction reach this terminal state at this time." In
Phase 0 there is one station per community and it is trusted to run the
protocol; the signature makes its actions auditable and attributable rather than
anonymous log mutations.

## Consequences

- **Positive.** Every log entry is attributable to a key, so `verify_chain`
  plus per-entry signature checks cover the whole lifecycle — there is no
  unsigned, unauthenticated entry type. Balances stay derivable from the log
  (the materialized `balances` table is just a cache).
- **Positive.** The `ReplicaId = station key` identity is exactly what the
  per-replica PN-Counter needs, and what cross-station federation (Phase 1+)
  will build on: a settlement is already labelled with which station performed
  it.
- **Negative / follow-up.** Settlement is not performed inside a single SQL
  transaction spanning *both* the log append and the balance write: the log's
  `append` commits its own transaction, and SQLite has no nested transactions.
  The log entry is written first and is authoritative; the materialized balance
  update follows. A crash between the two leaves balances stale but recoverable
  by replay (the settlement record is in the log). A future change could expose
  a lower-level "append within an existing transaction" API in `rrn-storage` to
  make the pair atomic.
- **Neutral.** Phase 0 trusts the single station to settle honestly (it cannot
  forge a *proposal* or *confirmation* — those need the parties' keys — but it
  decides *when* settlement happens). Dispute handling, multi-station settlement
  authority, and the question of who may settle in a federated setting are
  Phase 1+ concerns.

## Alternatives Considered

- **An unsigned settlement entry type.** Rejected: it would punch a hole in the
  "every log entry is signed" invariant and in `verify_chain`'s guarantees, for
  the single most security-sensitive transition (the one that moves money).
- **Re-sign settlement with the sender's or receiver's key.** Impossible: the
  parties are not present at settlement time, and the station does not hold
  their secret keys.
- **Don't log settlement at all; only mutate the materialized `balances`
  table.** Rejected: it contradicts "the log is the source of truth" and the
  M0.5 exit criterion, and would make balances unauditable and
  non-reconstructible.
- **Derive `Settled` purely from the passage of time at read-time** (no entry,
  compute "settled if confirmed_at + window <= now"). Rejected: settlement has a
  real side effect (the balance change) that must happen exactly once and be
  recorded; a purely computed state cannot carry `settled_at` provenance or
  survive a window-config change.

## References

- CLAUDE.md — "The log is the source of truth"; ledger overview
- [ADR-0002](0002-canonical-serialization-dcbor.md) — canonical CBOR, which the
  signed records use
- `crates/rrn-ledger/src/settlement.rs`, `crates/rrn-ledger/src/engine.rs`
- `docs/threat-model.md` — `rrn-ledger` section
- Design overview, Section 10.8 — "Security Architecture" (replay protection)
