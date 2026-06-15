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

The audit boundary. Provides Ed25519 signing (`keypair`), Blake3 hashing
(`hash`), canonical deterministic CBOR (`serialize`), and the
`SignedPayload<T>` wrapper (`signed`). Everything downstream trusts these
primitives, so the threats here are the highest-stakes in the system.

**Assets:** Ed25519 secret keys; the integrity of the sign→verify relation;
the byte-for-byte determinism of canonical encoding; the collision resistance
of content hashes.

#### Spoofing — forging a signature / impersonating a signer

- *Threat:* an attacker produces a `SignedPayload` that verifies under a
  victim's public key without holding the secret key.
- *Mitigations:* Ed25519 over `ed25519-dalek` v2 (a reviewed implementation);
  forging requires breaking the discrete-log assumption, which the threat
  model takes as hard. The signed bytes are the *canonical CBOR of the
  payload* (`signed.rs`), never an attacker-malleable wire envelope, so there
  is no encoding wiggle room to exploit.
- *Residual risk:* compromise of the secret key itself (see Information
  disclosure) defeats this entirely — the cryptography assumes the key is
  secret.

#### Tampering — altering a signed value, or signature malleability

- *Threat (payload tampering):* modify `payload` after signing and have it
  still verify.
- *Mitigation:* `verify()` re-serializes the payload to canonical bytes and
  checks the signature against those bytes; any change to the payload changes
  the bytes and fails verification. Property-tested (flip-a-bit in message
  fails verify).
- *Threat (signature malleability):* Ed25519 admits non-canonical `S`
  components and small-order public keys that some verifiers accept, letting a
  third party mint a *different* valid signature for the same message
  (transaction-malleability style).
- *Mitigation:* verification uses `verify_strict`, which rejects non-canonical
  `S` and small-order keys. Property-tested (flip-a-bit in signature fails
  verify).
- *Residual risk:* this crate guarantees a unique encoding *only* for types
  routed through canonical CBOR; a downstream type that signs ad-hoc bytes
  bypasses the guarantee. Enforced by convention (sign via `SignedPayload`),
  not the type system.

#### Repudiation

- *Threat:* a signer denies having signed a value.
- *Mitigation:* a valid Ed25519 signature is non-repudiable evidence under the
  key-secrecy assumption; the append-only log (`rrn-storage`) preserves signed
  history. Largely an `rrn-ledger`/`rrn-storage` concern; `rrn-crypto` only
  supplies the primitive.

#### Information disclosure — secret-key leakage

- *Threat:* secret key material leaks via memory, logs, debug output, or
  accidental serialization.
- *Mitigations:* `SecretKey` holds only the 32-byte seed and is
  `Zeroize + ZeroizeOnDrop` (wiped on drop); its `Debug` prints
  `SecretKey([REDACTED])` and `Keypair`'s `Debug` shows only the public key —
  both unit-tested to never emit key bytes. `SecretKey` deliberately does not
  implement `serde::Serialize`/`Deserialize`, so it cannot be serialized by
  accident. At-rest encryption of persisted keys is `rrn-identity`'s job
  (argon2id + XChaCha20-Poly1305), out of scope here.
- *Residual risk:* secrets are necessarily in plaintext in RAM while in use; a
  compromised OS / memory scraper (out of scope per Trust Assumptions) can
  read them. `zeroize` narrows but does not eliminate the window.

#### Denial of service — malicious inputs at parsing boundaries

- *Threat:* adversarial bytes fed to `PublicKey::from_bytes`,
  `Signature::from_bytes`, `verify`, or canonical decode cause a panic or
  unbounded work.
- *Mitigations:* all parsers return `Result` and never panic on malformed
  input (off-curve keys → `InvalidEncoding`); a `cargo-fuzz` target
  (`verify_signature`) asserts no panic on arbitrary `(pubkey, sig, message)`.
  Ed25519 verify is fixed-cost in the input size.
- *Residual risk:* CBOR decode work is bounded by input length; very large
  inputs are a caller/transport concern (message size limits live in
  `rrn-protocol`, Phase 1+).

#### Elevation of privilege

- Not directly applicable at this layer: `rrn-crypto` has no notion of roles
  or authority. Authorization is built on top of verified signatures in
  `rrn-identity`/`rrn-ledger`. The relevant obligation here is *correctness*:
  a `verify` that wrongly returns `Ok` would let any forged value escalate.

#### Weak randomness

- *Threat:* predictable key generation undermines every guarantee above.
- *Mitigation:* `Keypair::generate` draws from the OS CSPRNG (`OsRng`, backed
  by `getrandom`); no userspace PRNG seeds key material. Per Trust
  Assumptions, the OS CSPRNG is trusted to provide sufficient entropy.

#### Side channels

- *Mitigation:* `ed25519-dalek` performs constant-time scalar arithmetic and
  constant-time signature verification internally; we do not hand-roll
  comparisons of secret-dependent values.
- *Residual risk:* full side-channel resistance (cache/timing/EM) on arbitrary
  hardware is not claimed; physical-access attackers are bounded by the
  device-trust assumption.

### `rrn-storage`

Local persistence (SQLite, `db`/`migrations`), the three CRDTs (`crdt`), and the
hash-chained append-only signed log (`log`). The log is the **source of truth**;
CRDT state is derived by replaying it and is never authoritative on its own.

**Assets:** the integrity and ordering of the append-only log; the deterministic
convergence of CRDT merges; the on-disk schema as a stable contract; durability
of committed writes.

> Populated through M0.2 (SQLite schema, the three CRDTs, and the hash-chained
> log). Replay-derived state and any further residual risks are revisited as the
> ledger (M0.5) builds on this layer.

#### Spoofing

- *Threat:* a forged record (attestation, transaction, log entry) is written as
  though it came from a legitimate identity.
- *Mitigation:* authenticity is not the database's job — every record destined
  for the log is a `rrn-crypto::SignedPayload`, and `AppendLog::append` verifies
  the signature before writing (T0.2.6). The raw SQLite tables enforce structure
  (foreign key `attestations.signer → identities.pubkey`), not authenticity.
- *Residual risk:* a row inserted directly via SQL bypasses signature checks;
  that is the Tampering threat below, caught on read by chain verification, not
  prevented at write time.

#### Tampering — database file and log chain

- *Threat (database file):* an attacker with filesystem access edits, inserts,
  or deletes rows directly — altering a balance, rewriting an attestation,
  excising a transaction.
- *Mitigation:* the append-only log chains each entry to the Blake3
  `content_hash` of the previous one (`prev_hash`), so any in-place edit,
  reorder, or deletion breaks the chain and is detected by
  `AppendLog::verify_chain` (T0.2.6). CRDT state is rebuilt from the log
  (T0.2.7), so a tampered derived row (e.g. `balances`) is overwritten by replay
  — the log wins. Append operations are wrapped in a single SQLite transaction
  so an entry is never half-written.
- *Threat (schema drift):* the on-disk schema silently diverges from the code's
  expectations — a hand-edited table, a skipped or reordered migration, a partly
  applied migration.
- *Mitigation:* migrations are immutable and versioned, applied once each inside
  a transaction and recorded in `_migrations` with a Blake3 checksum of the SQL
  text; re-running is a no-op. A golden-schema test (`tests/schema.golden.sql`)
  fails CI on any unintended change to table or index definitions. Tables are
  declared `STRICT` so column types are enforced rather than coerced.
- *Residual risk:* the hash chain proves *integrity and order within one log*,
  not *uniqueness* — two replicas can still fork (conflicting valid chains).
  Fork detection across replicas is out of scope for Phase 0 (Phase 1+
  `rrn-protocol`). An attacker who truncates the log to a prior valid prefix
  produces a still-consistent shorter chain; detecting rollback needs external
  anchoring (later).

#### Repudiation

- *Threat:* a participant denies an action recorded in storage.
- *Mitigation:* log entries carry the signer's `SignedPayload`; the chained,
  append-only structure preserves a tamper-evident signed history. Non-
  repudiation rests on the `rrn-crypto` key-secrecy assumption.

#### Information disclosure

- *Threat:* the SQLite file is read by anyone with filesystem access, exposing
  balances, transaction graphs, and social-vouch relationships (a privacy-
  sensitive social graph), or a seized device discloses all of it.
- *Mitigation:* at-rest encryption of secret key material is `rrn-identity`'s
  responsibility (argon2id + XChaCha20-Poly1305); this crate stores no secret
  keys. Whole-database encryption for the social-graph metadata is noted as
  future work (physical-seizure mitigation, design overview §10.8).
- *Residual risk:* in Phase 0 the database is plaintext on disk; the metadata it
  contains is exposed to a local attacker or seized media. Accepted for now per
  the device-trust assumption.

#### Denial of service

- *Threat:* adversarial input or pathological state — a corrupt/oversized BLOB,
  an enormous log forcing full-scan `verify_chain`/replay, unbounded CRDT growth
  (OR-Set tombstones).
- *Mitigation:* all storage operations return `Result` and do not panic on
  malformed rows; `verify_chain` and replay are O(N) but Phase 0 logs are small,
  with snapshotting deferred (T0.2.7 supports replay `from_seq` as the
  foundation). OR-Set tombstone garbage collection is a known, documented
  deferral.
- *Residual risk:* no size limits on log/CRDT growth yet; a local writer can bloat
  the database. Bounded only by disk in Phase 0.

#### Elevation of privilege

- *Threat:* using storage to grant authority not legitimately held (e.g. forging
  a balance or membership to gain standing).
- *Mitigation:* storage has no notion of authority; balances and memberships are
  CRDTs derived from signed log entries, so privilege follows verified
  signatures, not direct row writes (which replay overwrites). Authorization
  rules live in `rrn-ledger`/`rrn-identity`.

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
