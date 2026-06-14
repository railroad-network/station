# 0001 — Rust workspace and dual license

## Status

Accepted

Date: 2026-06-14

## Context

Railroad Network's `station` daemon and `rrn` CLI need to run across a wide
range of hardware, from full nodes down to low-power ARM "light nodes"
(smartphones, single-board computers, and eventually dedicated community
node/LoRa hardware). The runtime needs predictable latency without
garbage-collection pauses, since it participates in local consensus and
cryptographic operations on constrained devices.

The project also commits to an "audit everything" security posture: the
Phase 0 exit criterion is an external cryptographic audit of the core ledger
and identity code before any real value moves through the system, and the
threat model treats the cryptographic layer as the highest-stakes surface.
That favors a memory-safe systems language with a mature, well-reviewed
cryptography ecosystem, and a structure that lets `unsafe` code be confined
to a single, small, clearly-bounded crate.

Per the Repository Strategy document, Phase 0 has a single developer, one
language/ecosystem, one release cadence, and no external implementations to
coordinate with — none of the "natural seams" (different ecosystem, different
audience, different release cadence, independent reusability) that would
justify splitting the implementation across multiple repositories exist yet.

Finally, the project wants to be approachable to outside contributors and to
the security auditors referenced above, without imposing licensing
obligations on communities that adopt, fork, or self-host the software.

## Decision

1. Implement the `station` daemon and `rrn` CLI in **Rust**.
2. Organize the Phase 0 implementation as a **single Cargo workspace** in this
   repository (`station`), containing all crates (`rrn-crypto`,
   `rrn-storage`, `rrn-identity`, `rrn-ledger`, `rrn-protocol`,
   `rrn-station`, `rrn-cli`) — not split across multiple repositories or
   workspaces.
3. License the project under a **dual Apache-2.0 OR MIT** license.

## Consequences

- Cross-compiles cleanly to low-power ARM targets with no GC pauses, and
  gains access to a mature, widely-reviewed Rust cryptography ecosystem
  (`ed25519-dalek`, `blake3`, RustCrypto's `chacha20poly1305`, etc.).
- A workspace-wide lint can forbid `unsafe` outside `rrn-crypto`, giving
  auditors a single, explicit boundary to focus on.
- One `Cargo.toml`/`Cargo.lock`, one CI pipeline, one issue tracker — low
  coordination overhead while the project is small. `deny.toml` (T0.0.3)
  centrally governs the licenses and sources allowed for dependencies across
  every crate.
- Rust has a steeper learning curve and slower compile times than some
  alternatives; accepted as a cost of the memory-safety and performance
  requirements above.
- A single workspace means all crates currently share one Rust edition and
  toolchain version and run through the same CI jobs. This is revisited if a
  natural seam appears (e.g., the Phase 1 split of the mobile client into its
  own repository, per the Repository Strategy).
- The permissive dual license imposes no copyleft obligations on communities
  that fork, modify, or self-host `station`, and is the de facto convention
  for Rust projects, easing both contribution and the planned external
  security audit.
- Follow-up ADRs are expected for sub-decisions built on this one (e.g.,
  specific cryptographic primitives, the Shamir implementation).

## Alternatives Considered

- **Go**: also memory-safe with simpler syntax and faster compiles, and
  reasonable ARM support. Rejected: GC pauses are undesirable for a node
  participating in local consensus and crypto operations on constrained
  hardware, and Go's broader unsafe-by-default runtime behavior is a worse
  fit for the project's "isolate `unsafe` to one audited crate" posture than
  Rust's type system. Rust's crypto crate ecosystem is also more mature for
  this project's needs.
- **Multiple repositories (one per crate, or one per layer)**: rejected per
  the Repository Strategy — Phase 0 has a single developer, single ecosystem,
  single release cadence, and no external implementers, so none of the
  documented "natural seam" criteria for splitting apply. Splitting now would
  add cross-repo PR coordination, version skew, and fragmented CI/issue
  tracking for no offsetting benefit; Cargo workspaces exist precisely so
  related crates don't need separate repos.
- **GPL-family copyleft (GPLv3/AGPLv3)**: rejected because it would impose
  copyleft (and, for AGPL, network-use) obligations on communities that fork,
  modify, or self-host `station`, conflicting with the goal of communities
  freely adapting the software to local needs. A permissive license also
  lowers friction for the external security audits the project depends on.

## References

- Design overview, Section 10.9 "The Technology Stack"
  (`docs/design/Railroad-Network-Overview.md`)
- Design overview, Section 12 "Development Roadmap" — Phase 0 exit criteria
  (external cryptographic audit before real users)
- Repository Strategy document — "Phase 0 — One repo", "What does NOT get its
  own repo", and "Locked names"
- `CLAUDE.md` — Locked technical decisions table
