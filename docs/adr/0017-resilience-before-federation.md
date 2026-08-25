# 0017 — Single-community resilience comes before federation

## Status

Accepted

Date: 2026-08-25

## Context

The original roadmap (design overview §12) sequenced the phases as: Phase 2 —
Multi-Community Federation (months 11-18), then Phase 3 — Resilience Layer
(months 19-26). Resilience — offline-first operation, delay-tolerant
networking, LoRa/SMS transports, paper fallback — is the project's stated core
differentiator, yet it was scheduled *after* the federation protocol.

Three forces argued against that order:

1. **Retrofit risk.** Delay-tolerant sync and federation gossip are largely
   the same machinery. A federation protocol designed first, under an implicit
   assumption of reasonable connectivity, would need redesign when
   store-and-forward semantics arrived. Built in the other order, federation
   inherits partition-tolerance as its default posture. The existing
   architecture (append-only log as source of truth, CRDT state derived by
   replay — see the storage design and ADR-0013's pluggable collapse
   transport) already leans offline-first; sequencing federation first risked
   eroding that.
2. **Early-adopter fit.** Phase 1's target adopters — rural communities with
   weak connectivity, mutual aid networks, ecovillages — benefit from offline
   hardening, SMS, and paper fallback before they benefit from trading with
   other communities. Resilience-next preserves the roadmap's own principle
   that every phase delivers standalone value; federation only delivers value
   once there are several communities to federate.
3. **Legal sequencing.** Per §13.1, federation is the step that makes the
   system look like an unlicensed payment network to financial regulators,
   while single-community resilience fits the disaster-preparedness /
   mutual-aid framing §13.6 recommends. At one-community scale the resilience
   layer's national-security exposure is negligible.

A wholesale swap of the two phases did not work, however: several resilience
deliverables presuppose federation. The Conductor role is defined as
*inter-community* sync carriage, and the resilience exit criterion (72-hour
connectivity loss across 3 communities) literally requires three federated
communities.

## Decision

Split the old Resilience Layer phase rather than move it wholesale:

- **New Phase 2 — Single-Community Resilience (months 11-16):** offline-first
  hardening, delay-tolerant store-and-forward between nodes within a
  community, LoRa and SMS transports, physical/QR credential layer, emergency
  governance modes, node seizure resistance. Exit criterion: one community
  survives a simulated 72-hour full connectivity loss with real economic
  activity — full reconciliation, no credits lost, no ledger forks.
- **New Phase 3 — Multi-Community Federation (months 17-26):** everything from
  the old federation phase, plus the federation-dependent resilience pieces:
  Conductor role formalization and the 3-community 72-hour outage
  reconciliation test, which becomes part of this phase's exit criteria.

Phases 0, 1, 4, and 5 are unchanged; current M0.x work is unaffected.

## Consequences

- Federation protocol design starts from a stack already proven under
  partition, so disconnection is its default assumption rather than a patch.
- Phase 1's early adopters get the offline/radio/paper capabilities one phase
  (≈8 months) sooner.
- The "system has teeth" milestone — the first inter-community dispute
  resolved through federation arbitration — moves out roughly 8 months,
  delaying the strongest proof-of-concept for oracle Tiers 3/4.
- LoRa is a hardware-and-spectrum-regulation long pole (§12.1) and is now on
  the critical path earlier; the per-geography spectrum research must stay
  parallelized.
- The §13.1 regulatory-perception sequence changes: single-community
  resilience is still mostly invisible, while federation now arrives with
  resilience transports already built in, so financial-regulator and
  national-security attention land together at Phase 3.
- **Renumbering hazard.** Documents written before this ADR use the old
  numbering ("Phase 2" = federation, "Phase 3" = resilience). The threat model
  is a living document and has been updated to the new numbering. ADRs
  0001–0016 and `docs/security/audit-2026-08.md` are point-in-time records and
  keep the old numbering as written — when reading them, "Phase 2" generally
  means the federation phase, which is now Phase 3.

## Alternatives Considered

- **Keep the original order (federation first).** Rejected: retrofit risk on
  the sync layer, and the core differentiator stays hypothetical for another
  phase while the stated early adopters wait on capabilities they need more
  than federation.
- **Wholesale swap of Phases 2 and 3.** Rejected: the Conductor role and the
  3-community outage exit criterion presuppose federation; the phase had to be
  split, not moved.
- **Interleave resilience work inside the federation phase.** Rejected: loses
  the clean single-community exit criterion and the standalone-value property;
  a 16-month combined phase with no intermediate exit gate invites drift.

## References

- Design overview §12 (Development Roadmap) and §13.1 (regulatory perception
  by phase) — both updated by this decision
- [ADR-0013](0013-federation-transport-reticulum.md) — pluggable
  federation/collapse transport (Reticulum), the transport layer both phases
  share
