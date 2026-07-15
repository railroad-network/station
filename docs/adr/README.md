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

- [0001 — Rust workspace and dual license](0001-rust-workspace-and-dual-license.md)
- [0002 — Canonical serialization via deterministic CBOR (`dcbor`)](0002-canonical-serialization-dcbor.md)
- [0003 — Human-readable address format: bech32m with HRP `rrn`](0003-bech32-address-format.md)
- [0004 — Own Shamir's Secret Sharing implementation over GF(256)](0004-own-shamir-implementation.md)
- [0005 — The station signs settlement and cancellation records](0005-station-signed-settlement.md)
- [0006 — The mobile client holds the keys; the station is a local backend](0006-m1-client-architecture.md)
- [0007 — uniffi-rs generates the mobile bindings to our Rust crypto](0007-rust-mobile-ffi-uniffi.md)
- [0008 — The mobile↔station envelope is the security boundary; the transport is a dumb carrier](0008-mobile-station-transport.md)

See also [`docs/threat-model.md`](../threat-model.md) for the project's living
threat model, which references decisions recorded here.
