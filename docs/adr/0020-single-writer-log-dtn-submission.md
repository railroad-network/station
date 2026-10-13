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

## Clarification (2026-09-14) — the writer never pulls; a replica never admits

Decision §7 says read-replica gossip "continues to exist for replica copies of
the chain," and Decision §1 that there is one writer. This clarifies how those
two hold together *in code*, not only in configuration, and does not change the
decision.

Until now, the single-writer property was enforced only by convention: an
operator set `[peers] list = []` on the writer, and the read-replica gossip
apply path (`Core::do_append_entries` → `append_raw`) appended any
signature-valid entry a configured peer served, with no front-door gate. That
left a bypass — a member record couriered to a *hostile* peer instead of the
station could land on the writer's chain ungated (no eligibility, duplicate,
window, debt-floor, tier, or emergency check). ADR-0027 D1b already closed the
one activation-bearing case (a markerless emergency-cosign crossing is
fail-closed); this clarifies the general rule.

A station now carries an explicit role (`[network] role = "writer" | "replica"`,
default `writer`):

- **A writer never pulls.** It does not run the gossip client at all; a writer
  configured with a non-empty `[peers] list` refuses to start (appliance
  discipline, as with the sidecar version pin). It still *serves* the peer port,
  so replicas can copy the chain from it. `Core::do_append_entries` refuses on a
  writer as defence in depth — the property holds however the path is reached,
  not only because the loop was not spawned.
- **A replica never admits.** It pulls the writer's chain and re-derives state by
  replay (ADR-0018 "replicas re-derive, never re-enforce"), but every write
  surface it exposes — the operator socket's writes, the mobile channel's writes
  (including courier `bundle_submit`), and transport DTN ingest (Reticulum, SMS)
  — refuses with a typed *read-replica* error naming the writer as the place to
  submit. Its log-appending sweep timers (settlement/cancellation, expiry,
  contract charges, governance enactment, dispute resolution) do not run. A
  replica is a warm second copy for audit/backup; it is **not** a failover
  standby (writer succession stays Phase 3, per Consequences).

A replica re-derives station-signed state (balances from settlement, governance
tallies, emergencies) by replaying records the *writer* signed, but the ledger
and governance readers pin those records to *this* station's signer (the
station-signer-pinning work, decision (a); see the threat model's `rrn-governance`
residual list). A replica's own key is not the writer's, so those readers
correctly decline the writer-signed records: a replica faithfully copies the
*chain*, and its derived station-signed views read as "genesis and nothing else"
rather than mirroring the writer's.
Making a replica's derived views match the writer's would require a
replica-supplied expected-writer key at the pinning boundary; that is left as a
follow-up, not part of this clarification.

## Clarification (2026-10-13) — receipt idempotency

Decision §3 says "re-submitting a bundle can only produce the same receipt
content, never a duplicate admission." The guarantee the design needs is the
second half; the first was over-strong, and implementing it literally let one
presentation answer for another. The internal security review (RRN-A-018)
showed a third party re-presenting a member's record under a forged outer
signature: the station cached the forged copy's `bad-signature` refusal under
a key built from record hashes alone (which cover neither the presenter nor
the signature) and served it, unevaluated, to the member's genuine
presentation. The same cache froze order-dependent answers: a confirmation
carried ahead of its proposal kept its `not-proposed` refusal forever. This
narrows §3 and does not change the decision.

Ingestion never admits a record twice. A station re-issues a stored receipt
verbatim only when every outcome in it is final (admitted, known, or a refusal
re-presentation cannot change); a presentation whose receipt carries a refusal
that can change (nonce gap, debt floor, not enrolled, not proposed, Tier-2
stake, the catch-all) is re-evaluated, so the same bytes may later be admitted.
A presentation is identified by its exact entry envelopes, never by record
hashes alone.

In code: each refusal slug declares its finality (`RefusalReason::is_final`,
an exhaustive match, and the **Final?** column of the registry in
`docs/spec/dtn-bundles.md` §3), so a new slug cannot be added without deciding
it. Re-evaluation cannot double-admit: an already-admitted record answers
`known` from the log's own dedup, and the engine's duplicate guard backs it.
The outbound push id is unchanged — it still hashes the ordered record hashes,
because a receipt carries only record hashes and correlation must rebuild it
from one. Receipt-delivery rows are per `(record, presenting author)`, so a
record re-wrapped by someone else never takes over its author's row; a row
whose answer was transient is re-pointed at the re-evaluated receipt and
delivered again.

## Clarification (2026-10-13) — a confirmation of a closed transaction

The receipt-idempotency Clarification above re-evaluates a presentation whose
receipt carries a transient refusal. One transient slug, `not-proposed`, covered
two different facts: the referenced transaction is *absent* (its proposal may
still arrive, so a re-evaluation can admit the confirmation), or it *exists but
is past the proposed state* — already confirmed by another confirmation,
settled, cancelled, or disputed. The second never changes: a transaction never
returns to the proposed state. Answered as transient, it kept a member's wallet
carrying the confirmation forever.

The two facts now have two slugs. An absent transaction stays `not-proposed`
(transient). A confirmation of a transaction that exists but is no longer open
is refused **`tx-closed`**, which is **final**: its receipt is re-issued verbatim
and a wallet acks it on the first answer. `tx-closed` is added to the closed
refusal set and its registry (`docs/spec/dtn-bundles.md` §3); a receipt decoder
built before it rejects a receipt carrying the slug, as with `not-enrolled`.
ADR-0031 §10's late-confirmation walkthrough (a confirmation reaching a home that has
already cancelled the transaction, "refused `not-proposed`") reads `tx-closed`
under this rule, and `tx-closed` joins the domestic slugs that ADR-0031 §13 says
apply unchanged at either front door.

The other permanent faults the catch-all `rejected` carries (a confirmer who is
not the receiver, a self-payment, inconsistent timestamps) stay on the transient
`rejected`: a member's wallet can stop carrying such a record by abandoning it
(`rrn wallet abandon`), and a second, final catch-all slug was judged not worth
its wire cost.

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
