# 0020 — The community log keeps one writer; resilience is delay-tolerant submission, not multi-writer merge

## Status

Accepted

Date: 2026-08-26

## Context

Phase 2 (Single-Community Resilience, ADR-0017) requires members of one
community to keep transacting through a total connectivity loss and reconcile
cleanly afterward. The design overview (§12, Phase 2 entrance criteria) framed
the log question as a forced choice: "the structure must become per-node chains
with defined merge semantics or a Merkle-DAG," because store-and-forward
between nodes "guarantees concurrent appends."

Examining what the existing architecture already commits us to dissolves that
framing. The system has *two* distinct kinds of authorship:

- **Party commitments** — proposals signed by senders, confirmations signed by
  receivers, votes, vouches, dispute records. These are the value-bearing acts.
  They are signed on member devices and are already created *away from* the
  log: the log has never been where commitment happens, only where admission
  happens.
- **Admission** — the station verifying, ordering, and appending those signed
  records, plus its own attestations (settlement, cancellation — ADR-0005).

Concurrent *commitment* during a partition is unavoidable and already
supported: two members can sign a proposal and confirmation with no
connectivity at all. Concurrent *admission* is a design choice, and everything
expensive about the multi-writer options exists only to support it:

- ADR-0009 reputation and ADR-0014 sortition are deterministic *because* replay
  order is total. Per-node chains or a DAG require a merge-stable linearization
  under which every derived result (scores, jury selection, tallies) is
  invariant across re-merges — a property that must then be proven and fuzzed
  forever.
- ADR-0018's debt floor is checked sequentially at one front door. Multiple
  admission points each need a reserved slice of every member's headroom plus a
  rebalancing protocol (the bounded-counter design), and a violation-on-merge
  policy besides.
- Equivocation detection, fork choice, and "no ledger forks" (the Phase 2 exit
  criterion) all become live protocol surfaces instead of impossibilities.

Meanwhile the deployment reality of the Phase 1/2 target — one community of
20-ish members, one station on local hardware (a Pi on the community LAN) — is
that "full connectivity loss" means loss of *internet*, not loss of the
station. The station needs no internet to admit records. The scenario that
actually strands members is being out of reach of the station's local network:
at the far end of the valley, on the road, at a market. What those members need
is not a second log writer; it is a way for their *signed records* to travel —
over LoRa, by SMS, on paper, in another member's phone — and land at the
station later, with proof of delivery.

ADR-0017's retrofit-risk argument ("federation gossip and delay-tolerant sync
are the same machinery") is served either way: the store-and-forward carriage
layer built here is exactly what Phase 3 federation gossip rides on. And Phase
3's own log topology is *already* "multiple single-writer chains" — one per
community — so merge semantics get built exactly once, at the inter-community
boundary where they are unavoidable, rather than twice.

## Decision

**The community log remains a single linear hash chain with a single writer —
the community's station. Phase 2 builds delay-tolerant *submission*: signed
records travel store-and-forward from member devices to the station over any
carrier, in tamper-evident per-device outbox chains, and the station remains
the sole admission point.**

Concretely:

1. **One chain, one writer, unchanged.** `rrn-storage::log` keeps its current
   structure (seq, `prev_hash`, `content_hash`). `verify_chain` and replay
   determinism are untouched. "No ledger forks" holds by construction.
2. **Per-device outbox chains.** Every signing device (mobile wallet, CLI
   wallet) maintains its own append-only, hash-chained **outbox**: each entry
   wraps one signed record the device has authored, chained by hash to the
   device's previous outbox entry and signed by the device key. The outbox
   chain is *not* the ledger — it is a carriage and evidence structure. It
   makes a carried bundle tamper-evident, makes selective suppression by a
   courier detectable (a gap in the chain), and makes double-authorship by the
   *device owner* (two outbox entries with the same position — an outbox fork)
   provable equivocation, which ADR-0021 builds on.
3. **Bundles and receipts.** Records are carried in **bundles**: a manifest
   plus a run of outbox entries from one or more devices. Any device or peer
   station may carry any bundle (couriers are dumb). The station answers an
   ingested bundle with a station-signed **delivery receipt** enumerating, per
   record, admitted / already-known / refused-with-reason. Receipts travel back
   by the same carriers. Ingestion is idempotent: re-submitting a bundle can
   only produce the same receipt content, never a duplicate admission.
4. **Admission order is arrival order.** The station admits records through the
   existing engine front door in the order bundles reach it (within a bundle,
   in outbox order). No reordering by claimed timestamp — ADR-0022 governs
   time. Front-door refusals (bad signature, nonce, floor, tier, expiry) apply
   to DTN-carried records exactly as to live submissions, with one carve-out
   defined by ADR-0021 (certificate-backed spends).
5. **What a partitioned member can and cannot do.** With the station
   unreachable, members can sign anything (proposals, confirmations, votes,
   vouches, dispute openings), exchange and verify each other's signed records
   directly, and spend against ADR-0021 certificates with a receiver who can
   verify them offline. Nothing *settles*, no dispute clock runs, and no
   governance tally closes until the records reach the station — delay-tolerant
   means delayed, and every window is served in full once admission happens
   (ADR-0022). This is the accepted cost of the single writer.
6. **Station loss is availability loss, not integrity loss.** If the station
   itself is destroyed or seized, the community cannot admit new records until
   it re-bootstraps from the encrypted backup (ADR-0016); member outboxes
   preserve everything signed in the interim and are replayed into the restored
   station. Multi-station availability is explicitly *not* pursued in Phase 2.
7. **The Phase 0 gossip stub is retired in place.** Read-replica gossip
   (`rrn-station::gossip`) continues to exist for replica copies of the chain,
   but the DTN bundle path is the canonical resilience mechanism; the two share
   the principle that replicas re-derive and never re-enforce (ADR-0018).

## Consequences

- **Everything derived stays deterministic for free.** Reputation, sortition,
  tallies, and balances replay identically everywhere because there is still
  exactly one order of events. No merge-invariance proofs, no fork choice, no
  equivocation handling *at the ledger layer*.
- **The exit criterion's hard half gets a mechanism.** "No credit limit
  violated by any merge" is discharged by there being no merge: limits are
  checked at one front door in one order, with ADR-0021 certificates making
  offline commitments safe against that order.
- **Latency is honest.** A confirmation carried for three days settles three
  days late, and its dispute window opens on arrival (ADR-0022). The system
  never pretends an offline transaction settled offline.
- **The station is a single point of *liveness* failure.** Bounded by ADR-0016
  re-bootstrap plus outbox replay; accepted for one-community scale. Phase 3
  may add succession/failover; it starts from an architecture where that is an
  additive feature, not a redesign.
- **The outbox becomes a second chain implementation.** Small, but it must be
  built with the same care as the log (hashing, signatures, fixtures); it is
  the evidence base for ADR-0021 equivocation proofs.
- **Phase 3 inherits the right shape.** Federation = several single-writer
  community chains + a carriage layer that already exists. The deferred
  multi-writer questions (cross-chain ordering, treaty-bounded credit) land
  where they belong, in the federation ADRs.

## Alternatives Considered

- **Per-node chains (a small set of co-equal station-class writers), merged
  deterministically.** The overview's first framing. Rejected for Phase 2: it
  buys settlement progress inside a partition — a convenience — at the cost of
  making every derived computation merge-invariant and every bounded invariant
  a distributed-reservation problem. At 20-member scale, the convenience is
  worth almost nothing; the cost and audit surface are enormous.
- **Merkle-DAG.** Most general; rejected for the same reasons, plus the
  largest rework of `verify_chain`, replay, and wire formats, and the least
  legible evidence structure for a community operator.
- **Multi-writer "lite": second station as hot standby with write authority
  failover.** Deferred to Phase 3 with federation-grade tooling; a failover
  protocol done casually is a fork generator, and ADR-0016 already covers the
  Phase-2 availability story.
- **Route everything through live RPC only (status quo).** Fails the phase:
  members out of the station's radio/LAN reach could not transact at all, and
  the pilot's own deliverables (LoRa, SMS, paper) would have no substrate.

## References

- ADR-0017 — resequencing that created this phase; the retrofit-risk argument
- ADR-0005 — the station as settlement/cancellation signer; the admission
  attestation model this extends
- ADR-0016 — encrypted backup and re-bootstrap (the station-loss story)
- ADR-0018 — debt floor at the single front door; "replicas re-derive, they do
  not re-enforce"
- [ADR-0021](0021-escrowed-offline-spending-certificates.md) — the offline
  commitment mechanism this log shape presupposes
- [ADR-0022](0022-admission-clock-time-trust.md) — the time model; admission
  order and admission clocks
- Design overview §12 (Phase 2 entrance criteria — the multi-writer framing
  this ADR answers and revises), §10.3 (degradation ladder)
- `crates/rrn-storage/src/log.rs`, `crates/rrn-station/src/gossip.rs`
