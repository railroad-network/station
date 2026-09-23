# Architecture Decision Records

An Architecture Decision Record (ADR) captures a single significant design
decision, the context that motivated it, and the alternatives that were
considered and rejected. ADRs answer the question a future contributor (or
auditor) will inevitably ask: "why did we do it this way?"

## When to write one

Write an ADR whenever a decision is **locked** — meaning the project commits
to it and treats deviation as requiring a new decision, not a quiet drift.
Examples: choice of a core language or library, a cryptographic primitive, a
wire format, a storage engine, a licensing model, or a security boundary.

Small implementation details that are easy to change later (variable names,
internal module layout, etc.) do not need an ADR.

## Format

ADRs follow the [MADR](https://adr.github.io/madr/) (Markdown Architecture
Decision Records) convention, using the structure in
[`template.md`](template.md):

- **Status** — proposed, accepted, rejected, deprecated, or superseded
- **Context** — the forces and constraints that motivate the decision
- **Decision** — what was decided
- **Consequences** — what becomes easier or harder as a result
- **Alternatives Considered** — what else was evaluated, and why it lost

## Numbering and lifecycle

- Files are named `NNNN-kebab-case-title.md`, numbered sequentially starting
  at `0001`.
- **ADRs are append-only.** If a decision changes, write a new ADR that
  supersedes the old one (and mark the old one's Status accordingly) — don't
  edit history.
- Keep each ADR to a single decision; don't bundle unrelated choices.

## Index

The **Status** column is the ADR's own status line. An ADR marked *Proposed*
whose decision has shipped is one the maintainer has not yet formally ratified;
the code follows it regardless, and ratification is recorded as a dated note in
the ADR, never by rewriting it. Phase numbers inside ADRs 0001–0016 use the old
scheme (ADR-0017 renumbered: Phase 2 is now single-community resilience).

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-rust-workspace-and-dual-license.md) | Rust workspace and dual license | Accepted |
| [0002](0002-canonical-serialization-dcbor.md) | Canonical serialization via deterministic CBOR (`dcbor`) | Accepted |
| [0003](0003-bech32-address-format.md) | Human-readable address format: bech32m with HRP `rrn` | Accepted |
| [0004](0004-own-shamir-implementation.md) | Own Shamir's Secret Sharing implementation over GF(256) | Accepted |
| [0005](0005-station-signed-settlement.md) | The station signs settlement and cancellation records | Accepted |
| [0006](0006-m1-client-architecture.md) | The mobile client holds the keys; the station is a local backend | Accepted |
| [0007](0007-rust-mobile-ffi-uniffi.md) | uniffi-rs generates the mobile bindings to our Rust crypto | Accepted |
| [0008](0008-mobile-station-transport.md) | The mobile↔station envelope is the security boundary; the transport is a dumb carrier | Accepted |
| [0009](0009-universal-reputation-algorithm.md) | One reputation formula runs on every station and no community can tune it | Accepted |
| [0010](0010-marketplace-data-model.md) | A listing is a signed record on the log; the search index is a view that can be thrown away | Accepted |
| [0011](0011-oracle-tier-model-phase-1.md) | The Phase-1 oracle ladder: two serviceable tiers, a blocked ceiling, and a derived reputation stake | Accepted |
| [0012](0012-charter-format-and-amendments.md) | The Charter: a self-bootstrapping constitutional document, and how a community changes it | Accepted |
| [0013](0013-federation-transport-reticulum.md) | Federation and collapse-mode transport is pluggable; Reticulum is the adopted backend, run as an external sidecar | Accepted |
| [0014](0014-phase-1-dispute-resolution.md) | Phase-1 dispute resolution: a sortition jury with a governance backstop, and the Tier-2 stake that finally bites | Proposed |
| [0015](0015-electorate-bootstrap-grace.md) | Bootstrapping the electorate: a governance and dispute grace so a young community can actually govern | Proposed |
| [0016](0016-station-backup-and-key-recovery.md) | Station backup and key recovery: an encrypted archive whose key survives a lost passphrase | Proposed |
| [0017](0017-resilience-before-federation.md) | Single-community resilience comes before federation | Accepted |
| [0018](0018-debt-floor.md) | A debt floor bounds how far a member can sign themselves into debt | Proposed |
| [0019](0019-confirmation-freshness-bound.md) | A freshness bound on `confirmed_at` protects the dispute window | Accepted (superseded for delay-tolerant sync by ADR-0022) |
| [0020](0020-single-writer-log-dtn-submission.md) | The community log keeps one writer; resilience is delay-tolerant submission, not multi-writer merge | Accepted |
| [0021](0021-escrowed-offline-spending-certificates.md) | Escrowed offline spending certificates bound the debt floor under partition | Accepted |
| [0022](0022-admission-clock-time-trust.md) | The admission clock: the station's clock at admission is the only window-bearing clock | Accepted |
| [0023](0023-emergency-governance-modes.md) | Emergency governance: deciding faster in a crisis without building a coup lever | Accepted |
| [0024](0024-station-at-rest-encryption-key-ceremony.md) | Station at-rest encryption: a member-keyed encrypted volume unlocked by a boot ceremony | Accepted |
| [0025](0025-equivocation-dispute-cases.md) | Equivocation cases are a distinct jury case kind with a Lapsed default and identity-anchored sortition | Accepted |
| [0026](0026-reticulum-sidecar-ratified.md) | The Reticulum sidecar is ratified: pinned `rnsd` 1.5, driven from the station, native Rust deferred | Accepted |
| [0027](0027-emergency-declaration-activation-and-ttl.md) | Emergency declaration activation is a single first-crossing event, and a part-signed declaration expires | Accepted |
| [0028](0028-non-mobile-member-wallet.md) | A self-custody CLI member wallet: the non-mobile member device, a sealed-channel client with an offline outbox | Accepted |
| [0029](0029-federation-identity-profiles-and-carriage.md) | Federation identity, community profiles, and the federation carriage protocol | Accepted |
| [0030](0030-treaties-ratification-depth-lifecycle.md) | Treaties: ratification, depth, lifecycle, and suspension | Accepted |
| [0031](0031-cross-community-credit-treaty-accounts.md) | Cross-community credit: treaty accounts and the prepare/commit protocol | Accepted |
| [0032](0032-recognition-portable-standing-cross-community-marketplace.md) | Recognition: portable standing across communities and the cross-community marketplace | Accepted |
| [0033](0033-oracle-tiers-3-and-4.md) | Oracle Tiers 3 and 4: artifact evidence, witnesses, and cross-community validation | Accepted |
| [0034](0034-community-tribunal-and-federation-arbitration.md) | The community tribunal and federation arbitration | Accepted |
| [0035](0035-writer-succession-and-lineage-pinning.md) | Writer succession and lineage-aware signer pinning | Accepted |
| [0036](0036-predictive-matching-v0.md) | Predictive matching, version 0 | Accepted |

See also [`docs/threat-model.md`](../threat-model.md) for the project's living
threat model, which references decisions recorded here, and the docs site's
[ADR index](https://railroad-network.github.io/reference/adrs.html), generated
from this directory.
