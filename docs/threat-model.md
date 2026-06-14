# Threat Model

This is a **living document**. It grows incrementally as each crate is built:
every crate's task spec includes a "threat model entry" acceptance item, which
is where that crate's section gets filled in. Sections below are scaffolded
now with `TODO:` placeholders so the structure is in place from the start.

Auditors should read this document first.

## Scope

Phase 0 (this repo, through milestone M0.7) covers:

- Cryptographic primitives: Ed25519 signing, Blake3 hashing, canonical CBOR
  (`rrn-crypto`)
- Local storage, CRDT merge (PN-Counter, OR-Set, LWW-Register), and the
  append-only signed log (`rrn-storage`)
- Identity wallet: key storage, address derivation, social vouching
  (`rrn-identity`)
- Shamir-based social recovery (`rrn-identity::recovery`, own implementation
  per ADR-0004)
- Transaction/ledger state machine, settlement, and replay protection
  (`rrn-ledger`)
- The daemon/CLI boundary and local IPC for the two-station demo
  (`rrn-station`, `rrn-cli`)

## Out of Scope

Deferred to Phase 1 and beyond:

- **Federation protocol** — cross-community sync, treaties, gossip beyond the
  Phase 0 stub (`rrn-protocol` contains stubs only in Phase 0)
- **Oracle mechanisms above Tier 2** — physical evidence (Tier 3), and
  cross-community validation / governance approval (Tier 4); see design
  overview Section 4.3, "The Tiered Oracle Model". Phase 0 only needs Tier
  1/2 (bilateral confirmation + settlement window + reputation stake)
- **Marketplace** — goods/services listings and matching
- **Governance** — voting, charters, dispute tribunals beyond automated
  Tier 1/2 escalation
- **Radio (LoRa) and mesh transport-specific threats** — Phase 0 runs over
  local network/loopback only

## Trust Assumptions

- TODO: The local operating system, filesystem, and kernel are trusted — we
  do not defend against a compromised OS on the user's own device.
- TODO: The Rust compiler/toolchain and the cryptographic crates we depend on
  (`ed25519-dalek`, `blake3`, `chacha20poly1305`, `argon2`) are trusted to
  correctly implement their published algorithms. Supply-chain risk on the
  dependency tree is mitigated by `cargo audit` and `cargo deny` (T0.0.3).
- TODO: The OS-provided CSPRNG (via `getrandom`) provides sufficient entropy
  for key generation and nonces.
- TODO: Our own Shamir's Secret Sharing implementation (`rrn-identity`, per
  ADR-0004) is *not* covered by the "trusted dependency" assumption above —
  it is in-scope for audit precisely because it is hand-rolled.

## Attacker Capabilities

- TODO: Can observe and record all network traffic between nodes (passive
  eavesdropper on an untrusted network).
- TODO: Can run arbitrary code on hardware they control, including a modified
  `station`/`rrn` binary, and can hold one or more valid identities (bounded
  by social vouching — see design overview Section 6, Identity Layer).
- TODO: Can replay, reorder, delay, or drop previously observed protocol
  messages.
- TODO: Can submit malformed, oversized, or adversarially-crafted CBOR
  payloads to any parsing boundary.
- TODO: Cannot break Ed25519, Blake3, or XChaCha20-Poly1305 (assumed
  cryptographically hard); cannot forge a signature without the private key.
- TODO: May physically seize a node's storage media (see design overview
  Section 10.8, "Physical node seizure").

## Per-Component Threats

Each subsection uses STRIDE (Spoofing, Tampering, Repudiation, Information
disclosure, Denial of service, Elevation of privilege) as a checklist, without
being rigidly bound by it. Populated as each crate's milestone lands.

### `rrn-crypto`

*Populated in M0.1 — Crypto Primitives.*

- TODO: Spoofing
- TODO: Tampering
- TODO: Repudiation
- TODO: Information disclosure
- TODO: Denial of service
- TODO: Elevation of privilege

### `rrn-storage`

*Populated in M0.2 — Storage and CRDTs.*

- TODO: Spoofing
- TODO: Tampering
- TODO: Repudiation
- TODO: Information disclosure
- TODO: Denial of service
- TODO: Elevation of privilege

### `rrn-identity`

*Populated in M0.3 — Identity Layer and M0.4 — Shamir Secret Sharing.*

- TODO: Spoofing
- TODO: Tampering
- TODO: Repudiation
- TODO: Information disclosure
- TODO: Denial of service
- TODO: Elevation of privilege

### `rrn-ledger`

*Populated in M0.5 — Transaction Engine.*

- TODO: Spoofing
- TODO: Tampering
- TODO: Repudiation
- TODO: Information disclosure
- TODO: Denial of service
- TODO: Elevation of privilege

### `rrn-protocol`

*Phase 0 contains stubs only; populated as the federation protocol is built
(Phase 1+).*

- TODO: Spoofing
- TODO: Tampering
- TODO: Repudiation
- TODO: Information disclosure
- TODO: Denial of service
- TODO: Elevation of privilege

### `rrn-station` / `rrn-cli`

*Populated in M0.6 — CLI and Two-Station Demo.*

- TODO: Spoofing
- TODO: Tampering
- TODO: Repudiation
- TODO: Information disclosure
- TODO: Denial of service
- TODO: Elevation of privilege

## Mitigations

TODO: For each threat above, record the corresponding mitigation here as it
is implemented. Anticipated mitigations carried over from the design overview
(Section 10.8, "Security Architecture") include:

- TODO: Replay attack → monotonically increasing per-identity nonce plus
  timestamp, enforced in `rrn-ledger` (T0.5.6)
- TODO: Physical node seizure → data at rest encrypted with keys held by
  community members (`rrn-identity` wallet encryption, argon2id + XChaCha20-
  Poly1305)
- TODO: Eclipse attack, ledger fork, Sybil federation → deferred to Phase 1+
  (`rrn-protocol`), out of scope for Phase 0 per above

## References

- Design overview, Section 4.1 — "The Attack Surface" (oracle attacks)
- Design overview, Section 4.3 — "The Tiered Oracle Model"
- Design overview, Section 10.8 — "Security Architecture"
- [ADR-0001](adr/0001-rust-workspace-and-dual-license.md) — Rust workspace
  and dual license
