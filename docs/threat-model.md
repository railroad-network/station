# Threat Model

This is a **living document**. It grew incrementally as each crate was built:
every crate's task spec included a "threat model entry" acceptance item, which
is where that crate's section was filled in. As of M0.7 (audit prep) it has had
a comprehensive end-to-end pass: every Phase 0 crate has a populated section,
the cross-cutting threats are analyzed, and the residual risks and known
limitations are stated explicitly.

**Phase 1 (from M1.0) is now being layered on top.** The sections it adds — the
mobile client and its transport to the station, and the marketplace, reputation,
and governance crates — describe threats against code that is largely still
*scaffolding*. To keep the auditor's "every mitigation claim is traceable to
code" contract intact, these sections mark their defenses as **Planned
mitigation** and name the task that will implement them, rather than claiming a
protection that does not yet exist. As each Phase 1 crate lands, its
implementation task promotes the relevant entries from *planned* to *shipped*
(with the concrete function/module, exactly as the Phase 0 sections do).

**Auditors should read this document first.** Every mitigation claim is meant to
be traceable to specific code; where a claim names a behavior (`verify_strict`,
`append_raw` re-chaining, idempotent settlement), the corresponding code lives
in the named crate/module and is covered by a unit or property test. If you find
a claim here that the code does not support, that discrepancy is itself a
finding — report it.

The one deliberately-empty section is `rrn-protocol`, whose federation surface
is a Phase 0 stub; its threats are Phase 1+ work and are marked as such rather
than guessed at.

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

Phase 1 (from M1.0) extends the scope with:

- The **mobile client** as the authoritative key-holder (per
  [ADR-0006](adr/0006-m1-client-architecture.md)) — device-level protection of
  the member's keypair, and the on-device Rust crypto shipped via uniffi-rs
  ([ADR-0007](adr/0007-rust-mobile-ffi-uniffi.md))
- The **mobile↔station transport** — per-request authentication by the mobile's
  signature, and the one-time pairing bond
- **Marketplace** — signed goods/services listings, inquiries, and search
  (`rrn-marketplace`)
- **Reputation** — transaction- and attestation-derived scores with time decay
  (`rrn-reputation`)
- **Governance** — proposals and one-member-one-vote balloting (`rrn-governance`)

## Out of Scope

Deferred to Phase 1 and beyond:

- **Federation protocol** — cross-community sync, treaties, gossip beyond the
  Phase 0 stub (`rrn-protocol` contains stubs only in Phase 0)
- **Oracle mechanisms above Tier 2** — physical evidence (Tier 3), and
  cross-community validation / governance approval (Tier 4); see design
  overview Section 4.3, "The Tiered Oracle Model". Phase 0 only needs Tier
  1/2 (bilateral confirmation + settlement window + reputation stake)
- **Governance beyond direct balloting** — charters and dispute tribunals;
  Phase 1's `rrn-governance` covers proposals and one-member-one-vote voting,
  not tribunal adjudication or oracle escalation above Tier 2
- **Radio (LoRa) and mesh transport-specific threats** — Phase 0 runs over
  local network/loopback only; Phase 1's mobile↔station transport section
  covers the *local-network* case, not radio/mesh links

## Trust Assumptions

- The local operating system, filesystem, and kernel are trusted — we
  do not defend against a compromised OS on the user's own device.
- The Rust compiler/toolchain and the cryptographic crates we depend on
  (`ed25519-dalek`, `blake3`, `chacha20poly1305`, `argon2`) are trusted to
  correctly implement their published algorithms. Supply-chain risk on the
  dependency tree is mitigated by `cargo audit` and `cargo deny` (T0.0.3).
- The OS-provided CSPRNG (via `getrandom`) provides sufficient entropy
  for key generation and nonces.
- Our own Shamir's Secret Sharing implementation (`rrn-identity`, per
  ADR-0004) is *not* covered by the "trusted dependency" assumption above —
  it is in-scope for audit precisely because it is hand-rolled.

## Attacker Capabilities

- Can observe and record all network traffic between nodes (passive
  eavesdropper on an untrusted network).
- Can run arbitrary code on hardware they control, including a modified
  `station`/`rrn` binary, and can hold one or more valid identities (bounded
  by social vouching — see design overview Section 6, Identity Layer).
- Can replay, reorder, delay, or drop previously observed protocol
  messages.
- Can submit malformed, oversized, or adversarially-crafted CBOR
  payloads to any parsing boundary.
- Cannot break Ed25519, Blake3, or XChaCha20-Poly1305 (assumed
  cryptographically hard); cannot forge a signature without the private key.
- May physically seize a node's storage media (see design overview
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

Turns raw keys into identities: bech32m addresses (`address`), the
passphrase-encrypted wallet (`wallet`), the generic signed `Attestation`
(`attestation`), and the first concrete attestation — the `vouch`. Social
recovery (`recovery`, ADR-0004) is the highest-stakes part of this crate and is
populated separately in M0.4.

**Assets:** the wallet's secret key at rest (the whole identity — lose it or
leak it and the identity is forged or gone); the secret key in memory while
unlocked; the binding between a public key and its human-readable address; the
authenticity of vouches (a forged vouch is a fake social relationship).

> Populated through M0.3 (addresses, wallet encryption, attestation, vouch).
> Shamir social recovery threats are added in M0.4; the social-graph /
> Sybil-resistance analysis of vouching is a Phase 1+ concern (vouch *content*
> trust, as opposed to vouch *authenticity*, is out of scope here).

#### Spoofing — forged identity or forged vouch

- *Threat:* an attacker presents a vouch (or other attestation) as though it
  came from a victim's identity, or claims an address that is not theirs.
- *Mitigation:* every attestation is an `rrn-crypto::SignedPayload` signed over
  its canonical CBOR; `create_vouch` signs with the voucher's keypair and
  `SignedPayload::verify` checks it against the signer's public key. An address
  *is* a public key, so claiming an address you don't hold means signing without
  the matching secret key — reducible to the `rrn-crypto` forgery assumption.
- *Residual risk:* authenticity is not authority. A *validly signed* vouch from a
  real-but-malicious identity, or a Sybil cluster of mutually-vouching keys, is
  cryptographically sound; defending against that is reputation/Sybil analysis
  deferred to Phase 1+, not a signature problem.

#### Tampering — altered wallet, altered address, altered vouch

- *Threat (wallet at rest):* an attacker with filesystem access edits the
  `.rrnwallet` file to corrupt or substitute key material.
- *Mitigation:* the wallet ciphertext is sealed with XChaCha20-Poly1305; any
  edit to the ciphertext, nonce, or KDF params fails the Poly1305 tag and
  `decrypt` returns `WalletError::Decrypt` rather than yielding a tampered key
  (unit-tested: flipping a ciphertext byte fails). The address is *not* stored in
  the wallet — it is re-derived from the decrypted secret key — so a tampered
  address can never disagree with the key it claims to represent.
- *Threat (address typo / wrong network):* a mistyped or cross-network address is
  accepted as a different valid key, sending value to the wrong identity.
- *Mitigation:* bech32m carries a checksum, so a single-character typo is
  rejected at parse time; the HRP must be `rrn` (a `bc1…` address is rejected);
  only a 32-byte payload that decodes to a canonical curve point is accepted; and
  decoding strictly requires the bech32m checksum variant (ADR-0003). Tested with
  bad-checksum, wrong-HRP, wrong-length, and non-m-variant cases.
- *Threat (attestation tampering):* modify a stored vouch and have it still
  verify.
- *Mitigation:* the signature covers the canonical CBOR of the attestation; the
  append-only log stores the exact signed bytes, and altering them fails
  verification (tested: flipping a stored body byte breaks `payload.verify()`).

#### Repudiation

- *Threat:* a voucher denies having issued a vouch.
- *Mitigation:* a vouch is a non-repudiable Ed25519 signature, persisted in the
  hash-chained append-only log (`rrn-storage`); the signed history is
  tamper-evident. Rests on the `rrn-crypto` key-secrecy assumption.

#### Information disclosure — secret-key leakage

- *Threat:* the wallet's secret key leaks — via a weak passphrase brute-forced
  offline, theft of the wallet file, a world-readable file, memory dumps, or
  debug output.
- *Mitigations:*
  - *Passphrase / offline brute force:* the file-encryption key is derived with
    **argon2id** (m_cost 64 MiB, t_cost 3, p_cost 4), making each guess
    expensive; parameters are stored per-wallet and tunable upward via the
    versioned format. A weak passphrase is still the user's risk — passphrase
    *strength enforcement* is a deferred UI concern, noted as residual risk.
  - *File theft / at rest:* the secret key is never on disk in the clear; only
    the argon2id+XChaCha20-Poly1305 ciphertext is. A random 32-byte salt and
    24-byte nonce are generated per save.
  - *File permissions:* the wallet is written `0o600` (owner-only) on Unix, via
    an atomic write-to-temp-then-rename so a crash never leaves a truncated or
    world-readable file at the real path.
  - *Memory / debug:* `WalletContents` is `Zeroize + ZeroizeOnDrop` (the secret
    key is wiped on drop); the derived AEAD key and the decrypted plaintext
    buffer are explicitly zeroized after use; `WalletContents`' `Debug` redacts
    the secret key, and `SecretKey` itself is non-serde and redacted (per
    `rrn-crypto`).
- *Residual risk:* the key is necessarily plaintext in RAM while the wallet is
  unlocked; a compromised OS or memory scraper (out of scope per Trust
  Assumptions) can read it. `zeroize` narrows but does not close that window. A
  weak user passphrase undermines the KDF regardless of cost parameters.

#### Denial of service — malicious wallet or address input

- *Threat:* adversarial bytes fed to the wallet decoder or address parser cause a
  panic or unbounded work — a corrupt `.rrnwallet`, a hostile bech32 string, a
  malformed attestation CBOR.
- *Mitigation:* all parsers return `Result` and never panic on malformed input
  (corrupt wallet → `WalletError::Corrupt`/`Decrypt`; bad address → an
  `AddressParseError` variant). Canonical CBOR decode is bounded by input length.
  argon2id memory cost is bounded by the stored parameters; the version is
  checked before key derivation, so an unsupported-version file is rejected
  cheaply rather than triggering an expensive KDF.
- *Residual risk:* the stored KDF parameters are attacker-influenceable in a
  hostile wallet file — a forged file could specify a very large `m_cost` to
  force a big allocation on `decrypt`. Phase 0 accepts this (you only decrypt
  your own wallet); a future hardening is to clamp accepted parameter ranges.

#### Elevation of privilege

- *Threat:* using identity primitives to gain standing not legitimately held.
- *Mitigation:* this crate grants no authority on its own — it produces and
  verifies signatures and stores attestations. Authority derived from vouches
  (reputation, membership) lives in `rrn-ledger` and later governance layers;
  `reputation_stake_centi` is recorded but deliberately *not* enforced in Phase 0
  (no reputation system yet). Privilege therefore follows verified signatures,
  not anything mintable here.

### `rrn-identity::recovery` (Shamir social recovery)

Splits the wallet's Ed25519 secret key into `N` shards via an **own**
implementation of Shamir's Secret Sharing over GF(256) (`gf256`, `shamir`, per
ADR-0004), seals each shard to a holder's identity key (`encryption`), and
reconstructs the key from any `K` decrypted shards (`flow`). This is the
highest-stakes code in the crate: it handles the secret key in the clear during
split and reconstruction, and the shards it produces are, in aggregate, the key
itself.

**Assets:** the secret key while it is split / reconstructed in memory; the
`K`-of-`N` confidentiality property (any `K-1` shards must reveal *nothing*); the
confidentiality of each shard in transit and at rest with its holder; the
correctness of the field arithmetic and interpolation (a bug silently corrupts
or leaks the key).

> Populated through T0.4.7 (GF(256) arithmetic, the split/reconstruct, shard
> encryption, and the recovery package/flow).

#### Tampering / spoofing — the recovery package and flow

- *Threat:* an attacker edits a stored `.rrnrecovery` package — swapping in their
  own shards, lowering the threshold, or substituting the recorded address — so a
  later reconstruction yields a key they control.
- *Mitigation:* the shards are individually sealed (above), so they cannot be
  read or forged without the holders' keys. On reconstruction,
  `reconstruct_wallet` re-derives the address from the recovered key and rejects
  it unless it matches the package's `original_address`
  (`RecoveryError::AddressMismatch`) — wrong, insufficient, or substituted shards
  reconstruct to a *different* key and are caught (unit-tested). The package is
  canonical CBOR, so it decodes deterministically.
- *Residual risk:* the package metadata (threshold, original address, creation
  time) is intentionally plaintext — a reader learns *that* an identity has a
  recovery package and its parameters, but not the key. An attacker who tampers
  with `original_address` itself only causes recovery to fail (denial of service
  against the owner's own backup), not key disclosure. Whole-package
  confidentiality is out of scope by design: secrecy rests on the per-shard
  encryption and the threshold.

#### Information disclosure — the `K-1` confidentiality property

- *Threat:* a holder (or a thief) with fewer than `K` shards learns something
  about the secret key.
- *Mitigation:* Shamir is information-theoretically secure — a degree-`K-1`
  polynomial is undetermined by any `K-1` points, so `K-1` shards are
  consistent with *every* possible secret and reveal nothing (the secret byte at
  index `0` is the polynomial's constant term, and `0` is forbidden as a share
  index so it is never handed out). The random coefficients come from a
  caller-supplied `CryptoRng`, and are zeroized after the shards are evaluated.
- *Residual risk:* the property holds only if the coefficients are truly random;
  a weak RNG breaks it (the caller is trusted to pass a real `CryptoRng`).
  Holder *collusion* up to `K` is by design out of scope — that is the recovery
  trust model, not an attack.

#### Information disclosure / Tampering — shards in distribution and at rest

- *Threat (interception):* an attacker intercepts a shard while it travels to its
  holder, or reads it from a holder's storage. With `K` intercepted shards the
  secret key is reconstructable; even one shard erodes the `K`-of-`N` margin.
- *Mitigation:* a shard is never distributed raw — it is sealed
  (`encryption::encrypt_shard`) to the holder's identity key via X25519 ECDH +
  `blake3::derive_key` + XChaCha20-Poly1305 with a fresh ephemeral keypair and
  random 24-byte nonce per shard. Only the holder's secret key can derive the
  AEAD key, so an interceptor without it learns nothing; fresh ephemerals mean
  shards sealed to the same holder share no key material.
- *Threat (tampering / wrong shard):* an attacker alters a sealed shard, or a
  holder returns a corrupted one, so reconstruction silently yields a wrong key
  (raw Shamir has no integrity check).
- *Mitigation:* XChaCha20-Poly1305 is authenticated and the KDF input binds the
  full transcript (`shared ‖ ephemeral_pub ‖ holder_pub`); any change to the
  ciphertext, nonce, or ephemeral key fails the Poly1305 tag and
  `decrypt_shard` returns an error rather than a wrong shard (unit-tested:
  flipped ciphertext byte and flipped ephemeral key both fail). The AEAD is thus
  the integrity check the bare Shamir layer lacks.
- *Residual risk:* a **compromised holder** (their identity secret key stolen, or
  the holder themselves malicious) can decrypt their own shard — that is inherent
  to entrusting them a shard, and is bounded by the `K`-of-`N` threshold (an
  attacker needs `K` compromised/colluding holders). Choosing trustworthy holders
  and a sound `K` is the user's responsibility; refresh/revocation
  (`flow::refresh`) lets a user re-split to a new holder set if a relationship
  sours. Reuse of the long-term Ed25519 identity key for ECDH is an accepted
  simplification (holders are identified by one key); the ephemeral-static
  construction still gives per-shard key separation.

#### Side channels — GF(256) table-lookup cache timing

- *Threat:* field multiplication indexes the `LOG`/`EXP` tables by secret bytes
  (secret values, polynomial coefficients, shard data). The cache line touched
  depends on the secret, so an attacker able to observe this process's cache
  (e.g. a co-resident process measuring cache timing) can learn information about
  the operands.
- *Mitigation:* the *algorithmic* control flow is constant-time — `mul` has no
  data-dependent branch (the zero-operand case is selected branchlessly via
  `subtle`); `inv`/`div` branch only on the *public* shard indices, never on a
  secret. What remains is the data-dependent table *index*.
- *Residual risk (accepted):* full cache-timing resistance is not claimed.
  Recovery is a rare, interactive, local operation: it runs on the user's own
  device, against the user's own shards, with no co-resident remote attacker in
  the Phase 0 deployment model (consistent with the device-trust assumption
  above). Constant-time table-free multiplication is noted as a possible future
  hardening if the deployment model ever admits a co-resident attacker.

### `rrn-ledger`

The mutual-credit transaction engine: the signed [`transaction`] records, the
`Proposed → Confirmed → Settled`/`Cancelled` state machine, the settlement
window, and the balance changes that close it. It is the most security-sensitive
layer in Phase 0 — it is the code that moves Commons.

**Assets:** the integrity of each balance (no value created or destroyed except
by a settled, doubly-signed transaction); the *exactly-once* application of a
settlement; the per-sender nonce sequence; the authenticity of every lifecycle
transition; the derivability of all state from the log.

> Populated in M0.5. The engine derives all transaction state by replaying the
> append-only log; the materialized `balances` table is a cache. Settlement and
> cancellation entries are signed by the local station — see
> [ADR-0005](adr/0005-station-signed-settlement.md).

#### Spoofing — forging a proposal, confirmation, or settlement

- *Threat:* an attacker submits a proposal that debits someone else, confirms a
  transaction addressed to a different receiver, or fabricates a settlement.
- *Mitigation:* every record is a `rrn-crypto::SignedPayload`, verified at the
  engine boundary *and* re-verified by `AppendLog::append`. A proposal is
  rejected unless its signer is the named `sender` (`Error::SenderMismatch`); a
  confirmation unless its signer is, and it names, the proposal's `receiver`
  (`Error::ConfirmerMismatch`). Settlement and cancellation are signed by the
  station key (ADR-0005), so even those terminal transitions are attributable,
  not anonymous log writes.
- *Residual risk:* anyone holding a party's secret key acts as that party — non-
  repudiation rests on the `rrn-crypto` key-secrecy assumption. The single
  Phase 0 station is trusted to decide *when* to settle (it cannot forge a
  proposal or confirmation); multi-station settlement authority is Phase 1+.

#### Tampering — altering an amount, a balance, or the lifecycle

- *Threat:* a stored proposal's amount or receiver is edited; a balance row is
  rewritten; a transaction is advanced to `Settled` without a confirmation.
- *Mitigation:* a `TransactionId` is the Blake3 hash of the proposal's canonical
  bytes (content-addressed), and the proposal is signed — altering any field
  breaks both the id and the signature. State is *derived from the log*, not
  from a mutable status column, and the log is hash-chained
  (`verify_chain`), so an edited or reordered entry is detected. A `Settled`
  state is only ever derived from a `Confirmed` state plus a station settlement
  record; the balance table is a cache that replay can rebuild (the log wins).
- *Residual risk:* a direct SQL edit of the `balances` cache is not detected
  until the next replay rebuilds it; like `rrn-storage`, integrity is enforced
  on read (replay) rather than prevented at write. Phase 0 logs are plaintext on
  disk per the device-trust assumption.

#### Repudiation

- *Threat:* a sender denies proposing, or a receiver denies confirming, a
  transaction that moved their balance.
- *Mitigation:* the settled transaction's `proposal` and `confirmation` are both
  retained in the log as signed payloads; the chained, append-only structure
  preserves a tamper-evident, attributable history of who agreed to what and
  when. `settled_at` and the station signature record who settled it.

#### Information disclosure

- *Threat:* the transaction graph (who paid whom, how much, with what memo) is a
  privacy-sensitive social/economic graph; reading the database exposes it.
- *Mitigation:* this crate stores no secret keys. Amounts and memos live in the
  log and `transactions`/`balances` tables in plaintext; whole-database
  encryption is deferred (noted under `rrn-storage`).
- *Residual risk:* in Phase 0 the ledger is plaintext on disk and exposed to a
  local attacker or seized media. Accepted per the device-trust assumption.

#### Denial of service

- *Threat:* adversarial input or pathological state — a flood of proposals to
  grow the log, malformed records, or a `now` that forces large sweeps; deriving
  state by full log replay is O(N) per operation.
- *Mitigation:* all engine/settler operations return `Result` and never panic on
  malformed records (unrecognized log payloads are ignored during replay).
  Replay is O(N) but Phase 0 logs are small; the materialized `balances` cache
  already avoids re-summing on every read, and a `transactions` snapshot/index
  is the natural optimization when logs grow (reserved, not yet needed).
- *Residual risk:* unbounded log growth and the O(N) replay cost are real at
  scale; snapshotting and rate-limiting are post-Phase-0 work.

#### Elevation of privilege — replay and double-spend

- *Threat:* a signed proposal is a bearer token; replaying it could apply the
  same debit twice (a double-spend), or a settlement could be applied twice.
- *Mitigation:* **replay protection** (T0.5.6) — each sender has a monotonic
  nonce with no gaps and no duplicates (`Error::BadNonce`), and a proposal whose
  content-addressed id is already in the log is rejected
  (`Error::DuplicateProposal`). A proposal is only valid inside its time window
  `proposed_at <= now <= expires_at`, with **±5 minutes** (`CLOCK_SKEW_TOLERANCE_SECS`)
  of drift tolerance, so a stale capture cannot be replayed indefinitely.
  Settlement is **idempotent**: `Settler::settle` checks the derived state is
  not already `Settled` *before* any balance write, so settling twice can never
  double-apply (T0.5.5, T0.5.7).
- *Residual risk:* the nonce is per-sender on a single replica; cross-replica
  nonce coordination (a sender acting on two stations) is a Phase 1+ federation
  problem. Credit limits are not enforced — a sender can settle into arbitrary
  debt in Phase 0 (Phase 1). The ±5 minute drift window is a deliberate
  usability/security trade-off recorded here.

### `rrn-protocol`

**Intentionally unpopulated in Phase 0.** This crate contains only stubs — there
is no wire format, no cross-community sync, no treaty or gossip *protocol* to
analyze yet (the Phase 0 two-station demo's minimal gossip lives in
`rrn-station`, and its threats are covered in that section). The federation
attack surface — eclipse attacks, ledger forks across communities, Sybil
federation, treaty abuse, transport authentication and encryption — is real but
belongs to the design it will implement, and is **out of scope for the Phase 0
audit** (see [Scope](#scope) and [Known limitations](#known-limitations)). A
full STRIDE section per protocol message is added as the protocol is built in
Phase 1+, so it is not pre-filled with speculation here.

### `rrn-station` / `rrn-cli`

The daemon that holds an open database and decrypted wallet, runs the settlement
sweep on a timer, gossips log entries with peers, and serves the `rrn` CLI; plus
the CLI itself. This layer adds three new boundaries the lower crates did not
have: a **local IPC socket** (CLI ↔ daemon), a **peer TCP surface** (the gossip
stub), and a **long-lived process holding key material in memory**.

**Assets:** the in-memory station secret key (held decrypted for the daemon's
lifetime); the integrity of the local log under entries pulled from peers; the
confidentiality and integrity of the CLI↔daemon channel; the availability of the
daemon (one local user, one writer).

> Populated in M0.6. The CLI and the gossip layer speak the same line-delimited
> JSON envelope ([`rpc`]) over two different transports. The gossip stub is
> deliberately minimal (T0.6.6) and is replaced wholesale in Phase 2; several
> residual risks below are explicitly its problem to solve.

#### Spoofing — impersonating the CLI user, or a peer

- *Threat:* a different local user connects to the daemon's Unix socket and
  issues commands as the station; or a machine on the network impersonates a
  configured peer and feeds the station log entries.
- *Mitigation:* the Unix socket is the authorization boundary — it is created
  with owner-only (`0o600`) permissions, so only the user who launched the
  daemon can call it; there is no in-band CLI auth, by design. Peer entries are
  *not* trusted on the basis of their source: every entry pulled over gossip is
  re-verified with `AppendLog::append_raw`, which checks `signer.verify(bytes,
  signature)` before storing — an entry whose signature does not match its bytes
  is dropped (and never aborts the batch).
- *Residual risk:* a valid signature only proves *authorship*, not *authority*.
  A peer can serve a correctly-signed entry that is semantically hostile (a
  station-signed settlement crediting itself); Phase 0's two-station demo runs
  between trusting parties, and authority/fork resolution is Phase 1+. The peer
  TCP port has no transport authentication or encryption at all.

#### Tampering — the IPC channel, and peer-supplied entries

- *Threat:* a request or response on the wire is altered; a peer reorders or
  forks its log so replication corrupts the local chain.
- *Mitigation:* the JSON envelope is operational plumbing, not a signed payload —
  the *authenticated* content is the `StoredPayload` inside, whose signature and
  Blake3 content hash are checked on append. Replicated entries are appended via
  `append_raw`, which re-chains them onto the *local* tail (it does not import a
  peer's `prev_hash`), dedupes by content hash, and leaves `verify_chain`
  intact; a peer cannot splice a break into our chain. Balances are *derived*
  from settlement records keyed by `proposal_id`, so a replayed or duplicated
  settlement record cannot double-apply.
- *Residual risk:* fork detection across replicas is out of scope (the gossip
  stub logs a warning and skips conflicting entries). The local DB and socket
  are plaintext on disk per the device-trust assumption.

#### Repudiation

- *Threat:* the station denies having authored a settlement or vouch it wrote.
- *Mitigation:* every log entry the station writes — proposals, confirmations,
  vouches, and station-signed settlement/cancellation records — is signed by the
  station key and hash-chained, so authorship is attributable and tamper-evident
  (inherited from `rrn-ledger`/`rrn-storage`). The daemon's `tracing` logs record
  operations but are not themselves authenticated.
- *Residual risk:* as everywhere, non-repudiation rests on key secrecy; a holder
  of the station key acts as the station.

#### Information disclosure — the long-lived in-memory key

- *Threat:* the station secret key, decrypted once at `station run` and held for
  the process lifetime, leaks via a core dump, swap, `/proc`, or a memory-scraping
  attacker on the host.
- *Mitigation:* the passphrase is read without echo (`rpassword`) or from
  `RRN_PASSPHRASE` for non-interactive use; the wallet is argon2id +
  XChaCha20-Poly1305 at rest (`rrn-identity`). The socket's `0o600` mode keeps
  other local users out of the IPC channel. The wire protocol never carries the
  secret key (recovery moves *sealed* shards; reconstruction happens from
  holder-decrypted shards supplied as files).
- *Residual risk:* a daemon necessarily holds the key decrypted in RAM while
  running; per the device-trust assumption an attacker with code execution as the
  same user, or with physical memory access, can recover it. `RRN_PASSPHRASE`, if
  used, is visible in the process environment. Phase 0 does not lock memory or
  guard against swap.

#### Denial of service — malformed input, peer flooding, the single writer

- *Threat:* a malformed CLI line or peer message crashes the daemon; a peer
  floods the gossip port; the single-writer core is starved.
- *Mitigation:* a malformed request line is answered with an `INVALID_REQUEST`
  error and the connection kept open — one bad line never takes down the daemon
  (covered by the `ipc` integration test). Each connection is handled on its own
  task but funnels through the single-threaded core, so there is no data race;
  the core processes commands serially. Peer reads are bounded by line framing,
  and a peer that errors only fails *that* gossip round.
- *Residual risk:* there is no rate-limiting, connection cap, or message-size
  cap on either the socket or the peer port (Phase 0 logs are small and the
  demo is local/trusted); the gossip stub pulls a peer's whole log each round,
  which does not scale. Both are explicitly Phase 2's to fix.

#### Elevation of privilege

- *Threat:* a CLI client performs an action it should not, or a peer's data
  causes the daemon to take a privileged action.
- *Mitigation:* the CLI has no privileges the socket owner does not already have
  (it *is* the owner); there is no privilege separation to escalate across in
  Phase 0. Peer input can only ever result in appending validly-signed entries
  the derivation layer already constrains (nonce ordering, signer/receiver
  checks, exactly-once settlement) — it cannot invoke arbitrary daemon
  operations, because the gossip surface exposes only `peer_handshake`,
  `log_tail`, and `log_range`.
- *Residual risk:* replay/double-spend protection lives in `rrn-ledger` (see its
  Elevation-of-privilege entry); the station layer adds no new ledger authority.

### `rrn-marketplace`

Discovery and intent on top of the ledger: signed listings, inquiries against
them, and search over open listings. It adds no new money path — a completed
sale settles as an ordinary `rrn-ledger` transaction — so its threats are about
*fraud, gaming, and spam* on the discovery layer rather than about credit
integrity (which the ledger already owns).

**Assets:** the authorship and content integrity of a listing; the binding
between a listing and the transaction that fulfils it; fair discovery (open
listings actually surface); a buyer's protection against a lister who takes
credit and never delivers.

> Phase 1 scaffold (M1.0). The crate is a skeleton; the mitigations below are
> **planned**, named by the task that will ship them, not yet implemented.

#### Listing fraud — the lister never delivers

- *Threat:* a member posts a listing, the buyer transacts, and the good or
  service never arrives.
- *Planned mitigation (M1 marketplace task, building on `rrn-ledger`):* a sale
  is not final on posting — it settles through the ledger's bilateral
  confirmation + settlement window (the Tier 1/2 oracle), so credit is not
  released until the buyer confirms delivery, and a non-delivery leaves the
  transaction unconfirmed/disputed and dents the lister's reputation
  (`rrn-reputation`).
- *Residual risk:* a scam conducted entirely off-ledger (payment arranged
  outside the system) is out of scope; the first victim of a new defrauder is
  unprotected — reputation only punishes *after* the fact.

#### Reputation gaming via fake transactions

- *Threat:* colluding identities run wash sales against each other's listings to
  manufacture positive transaction history and inflate standing.
- *Planned mitigation (M1 marketplace + `rrn-reputation`):* reputation inputs are
  weighted by the counterparties' position in the social vouching graph
  (`rrn-identity`) and by counterparty diversity, and decay over time, so a tight
  ring of self-dealing accounts yields little durable score. Sybil creation is
  bounded by the cost of getting vouched in.
- *Residual risk:* collusion among genuinely-vouched real members is hard to
  distinguish from honest trade; quantitative detection is deferred to Phase 2.

#### Listing spam

- *Threat:* an identity floods the marketplace with junk listings to bury real
  ones or degrade discovery.
- *Planned mitigation (M1 marketplace task):* listings are signed, so they are
  attributable and rate-limitable per identity; identity creation is Sybil-
  bounded by vouching; search ranking demotes low-reputation and unvouched
  listers.
- *Residual risk:* no rate limit exists yet (planned, not shipped); a vouched
  member can still post up to whatever limit is chosen.

### `rrn-reputation`

A member's standing, *derived* from signed evidence (settled transactions,
attestations) rather than asserted. Because a score is a computation over the
log, the threats are attempts to poison the evidence set or to manufacture
standing, not to tamper with a stored number (which hash-chaining already
prevents).

**Assets:** the re-derivability of a score from signed, content-addressed
evidence; the honesty of the evidence set; resistance to manufactured or
inherited standing.

> Phase 1 scaffold (M1.0). Mitigations below are **planned**.

#### Reputation laundering / whitewashing

- *Threat:* a member with bad standing abandons the identity and starts fresh,
  or attempts to carry standing to a clean identity, to escape a bad history.
- *Planned mitigation (M1 reputation task):* reputation is **non-transferable** —
  it is bound to the identity keypair, not a token that can be moved, and a fresh
  identity starts from zero and must be vouched in (a social cost).
- *Residual risk:* identity churn is only as expensive as vouching makes it;
  whitewashing by starting over is *mitigated, not eliminated*, and is a known
  limitation carried from the identity layer.

#### Attestation farming

- *Threat:* colluding identities issue each other positive attestations to
  inflate scores.
- *Planned mitigation (M1 reputation task):* attestations are weighted by the
  attester's own standing and vouch-graph position, reciprocal/clustered
  attestations are discounted, and all inputs decay with time.
- *Residual risk:* sophisticated collusion inside a real vouch cluster is hard to
  detect; a full quantitative model is deferred to Phase 2.

#### Time-decay gaming

- *Threat:* a member times their behavior to exploit the decay curve — front-load
  good conduct, then coast on a slowly-decaying score.
- *Planned mitigation (M1 reputation task):* continuous (not stepped) decay so
  there is no cliff or window to game, with recent evidence dominating the score.
- *Residual risk:* the decay parameters are a policy tradeoff; gaming the exact
  curve is bounded but nonzero.

### `rrn-governance`

Binding collective decisions: signed proposals, one-member-one-vote balloting,
and a verifiable tally. The defining control — vote weight is a property of a
vouched identity, not of stake or reputation — is what most of these threats
push against.

**Assets:** the one-member-one-vote invariant; the integrity of a tally
(re-derivable from signed ballots); the availability of the proposal channel.

> Phase 1 scaffold (M1.0). Mitigations below are **planned**.

#### Proposal flooding

- *Threat:* an identity submits a flood of proposals to bury real ones or force
  the community into constant voting (a governance DoS).
- *Planned mitigation (M1 governance task):* proposals are signed and
  rate-limitable per identity, and a proposal must clear a sponsorship/second
  threshold before it reaches a ballot; identity is Sybil-bounded by vouching.
- *Residual risk:* rate limiting is not yet implemented; a coordinated group of
  real members can still consume community attention.

#### Vote buying

- *Threat:* an actor pays members (in Commons or off-system) to vote a chosen
  way.
- *Planned mitigation (M1 governance task):* one-member-one-vote caps the value
  of any single vote, which lowers the return on buying it; social accountability
  around signed votes raises the cost.
- *Residual risk:* off-system bribery and coercion are fundamentally hard to
  prevent technically; deferred to community norms and to keeping each vote
  low-value. Ballot-secrecy tradeoffs (which would reduce buyability) are a
  Phase 2 design question.

#### Ballot stuffing (Sybil voting)

- *Threat:* one person casts multiple votes by controlling multiple identities.
- *Planned mitigation (M1 governance task):* one-member-one-vote is enforced at
  eligibility — only vouched identities may vote (`rrn-identity`) — and duplicate
  ballots from the same identity on the same proposal are rejected at tally.
- *Residual risk:* Sybil resistance is only as strong as the vouching graph; a
  compromised or careless voucher chain admits fake members who each get a vote.

## Mobile client (Phase 1)

The mobile client is new in Phase 1 and, per
[ADR-0006](adr/0006-m1-client-architecture.md), is the **authoritative
key-holder** — the member's Ed25519 secret key lives on the device, not on the
station. That moves the highest-stakes asset in the system into the member's
pocket and onto a consumer OS, which is a materially different environment from
the station's. Two surfaces matter: the device itself, and the link from the
device to the station.

> Phase 1, M1.1 in progress. The crypto/FFI layer has begun landing — the
> `SecureStore` component below is **implemented** (T1.1.2), and its subsection
> reflects shipped behaviour. The remaining mitigations are still **planned**,
> named by the task (M1.1 crypto/FFI, M1.2 auth/UI, M1.3 transport, M1.3.3
> pairing) that will ship them.

### Device attack surface

**Assets:** the member's Ed25519 secret key at rest on the device; the wallet
passphrase; the integrity of the app doing the signing.

- **Device theft.** *Threat:* the phone is stolen and the thief tries to extract
  or use the key. *Planned mitigation (M1.1/M1.2):* the key is held in the OS
  secure store (iOS Keychain / Android Keystore), gated behind the device
  biometric/passcode, and the wallet is encrypted at rest (argon2id +
  XChaCha20-Poly1305, the same scheme `rrn-identity` uses on the station); a lost
  device is recovered via Shamir social recovery ([ADR-0004](adr/0004-own-shamir-implementation.md)).
  *Residual risk:* a thief with an *unlocked* device, or who coerces the member,
  acts as the member.
- **Malware on the phone.** *Threat:* a malicious app or compromised OS reads the
  key or invokes signing. *Planned mitigation:* secure-store access control ties
  key use to our app plus a biometric prompt. *Residual risk:* per the project's
  device-trust assumption (carried from Phase 0), a compromised OS is *outside*
  the trust boundary — app-level controls cannot defend against it.
- **OS-level key extraction.** *Threat:* the secret key is lifted out of secure
  storage. *Planned mitigation (M1.1):* prefer hardware-backed, non-exportable
  keys (Secure Enclave / StrongBox) where possible. *Residual risk / open design
  question:* our Rust crypto (via uniffi, [ADR-0007](adr/0007-rust-mobile-ffi-uniffi.md))
  must *use* the signing key, so it may not be able to live as a non-exportable
  hardware key. M1.1 must resolve this — likely a hardware-backed wrapping key
  that protects an exportable signing key — and the residual extraction risk
  depends on that resolution. Flagged, not yet settled.
- **Shoulder surfing during passphrase entry.** *Threat:* an observer reads the
  passphrase as it is typed. *Planned mitigation (M1.2):* secure (non-echoing)
  text entry, with biometric unlock as the default so the passphrase is seldom
  typed at all. *Residual risk:* direct physical observation is reduced, not
  eliminated.
- **Biometric spoofing.** *Threat:* a fake fingerprint or face defeats the
  unlock. *Planned mitigation (M1.2):* rely on the platform's biometric liveness
  (Face ID / Touch ID / BiometricPrompt); the biometric only *gates access* to
  the key store, it is not itself the key. *Residual risk:* the platform
  biometric's strength is the ceiling — a defeated biometric equals device
  access.

### `mobile/src/crypto/SecureStore`

*Implemented in M1.1 (T1.1.2).* The one API through which the mobile app writes
sensitive bytes — foremost the wallet secret — to OS-backed storage. A single TS
interface (`save`/`load`/`delete`/`has`) over `react-native-keychain`, with
per-platform hardening. This subsection makes concrete the "secure store"
mitigation referenced above under *Device theft* and *OS-level key extraction*.

**Assets:** the bytes held under each key namespace (`WALLET_SECRET`,
`STATION_PAIRING_TOKEN`, `RECOVERY_SHARDS`); the access-control policy that gates
their retrieval.

- **OS-level protections in force.** *iOS:* items are stored with
  `WHEN_UNLOCKED_THIS_DEVICE_ONLY` (readable only while the device is unlocked;
  never synced to iCloud or migrated to another device) and access-controlled by
  `BIOMETRY_ANY` (Face ID / Touch ID). *Android:* the Keystore entry prefers
  `SECURE_HARDWARE` (TEE / StrongBox), falling back to `SECURE_SOFTWARE` only
  where no secure hardware exists, stored as a biometric-gated AES-GCM key
  (`WHEN_UNLOCKED`). *Residual risk:* on the software-fallback path the key
  material is protected by the OS keystore but not by dedicated hardware; the
  fallback is silent, so a device without secure hardware is not distinguished at
  the API from one with it.
- **Layered with passphrase encryption.** *Threat:* an attacker who extracts the
  stored bytes (see *OS-level key extraction* above) obtains the secret. *Mitigation:*
  double protection — the wallet secret is passphrase-encrypted (argon2id +
  XChaCha20-Poly1305, the `.rrnwallet` format, T1.1.5) *before* it is written
  here, so Keychain/Keystore extraction yields ciphertext, not the key.
  SecureStore's job is OS-level isolation and biometric gating; confidentiality
  of the secret does not rest on it alone. *Residual risk:* a weak user passphrase
  narrows the argon2id margin.
- **Biometric bypass.** *Threat:* an attacker defeats the biometric gate (spoofed
  face/fingerprint, or coercion of the member) and calls `load`. *Mitigation:* the
  OS renders and enforces the biometric prompt — the app never draws its own auth
  UI (which would be a phishing vector) — so platform liveness detection is the
  control. `has` deliberately does **not** decrypt, so existence checks never
  surface a prompt or the value. *Residual risk:* the platform biometric's
  strength is the ceiling; a defeated biometric on an unlocked device equals
  access. Biometric only gates access, it is not the key.
- **Jailbreak / root.** *Threat:* on a jailbroken (iOS) or rooted (Android)
  device, the keychain/keystore protections and app sandbox can be subverted, and
  stored items read directly. *Mitigation:* per the project's device-trust
  assumption (carried from Phase 0), a compromised OS is *outside* the trust
  boundary — the passphrase layer above is the only defense that still holds, and
  it holds only as ciphertext-at-rest, not against a keylogger capturing the
  passphrase on the same compromised OS. *Residual risk:* accepted and
  documented; app-level controls cannot defend a rooted device. Runtime
  jailbreak/root *detection* is out of scope for M1.1 (deferred to hardening).
- **Data lifetime.** Modern iOS/Android wipe keychain/keystore entries on app
  uninstall, so secrets do not survive removal of the app; and device-only
  accessibility keeps them off backups/other devices. *Residual risk:* none
  beyond the above; noted so the property is not silently relied upon without
  being stated.

### `mobile` crypto FFI surface (`rrn-mobile-ffi`, wallet file)

*Implemented in M1.1 (T1.1.3–T1.1.7).* The mobile app performs **no**
cryptography of its own: address parsing, signing, Blake3 hashing, the
`.rrnwallet` file format, and canonical-dCBOR signed payloads all cross into the
pure-Rust `rrn-crypto` / `rrn-identity` code through a single, narrow uniffi
surface (`rrn-mobile-ffi`, ADR-0007). The TS wrappers (`crypto/address.ts`,
`crypto/sign.ts`, `crypto/hash.ts`, `crypto/cbor.ts`, `crypto/SignedPayload.ts`,
`wallet/Wallet.ts`) marshal bytes and strings; they hold no keys and branch on
no crypto. This subsection covers that boundary; the OS storage it feeds is the
`SecureStore` subsection above.

**Assets:** the wallet secret while decrypted in the identity handle; the
integrity of the `.rrnwallet` bytes; the parity guarantee that mobile and
station agree byte-for-byte on addresses, signatures, and wallet files.

- **Secret never crosses the boundary.** *Threat:* the FFI exports a path to pull
  the raw secret seed into JS, where it cannot be zeroized and may be captured by
  a JS-level compromise. *Mitigation:* `SecretKey` is deliberately **not** in the
  UDL. `WalletContents` is opaque — it exposes `public_key()`, `address()`,
  `created_at()`, `metadata()`, and `keypair()` (for signing), but no accessor
  returns secret bytes; signing happens inside Rust and only a `Signature` comes
  back. The secret lives in the Rust `WalletContents`, which is
  `Zeroize + ZeroizeOnDrop`. *Residual risk:* the decrypted secret exists in
  native memory for the handle's lifetime (unavoidable — it must sign); a native
  memory-scraping attacker on a compromised OS is out of the trust boundary.
- **No divergent second implementation.** *Threat:* a reimplemented bech32 /
  Ed25519 / wallet-format on the mobile side subtly disagrees with the station,
  so a wallet or signature made on one is rejected or misread on the other.
  *Mitigation:* there is exactly one implementation (Rust), reached from both
  sides; mobile carries no parallel codec. The agreement is locked by committed
  cross-platform fixtures generated by the station and consumed by mobile CI —
  `cross_platform_address.json` (T1.1.3), `cross_platform_sign.json` (T1.1.4,
  byte-identical signatures), `cross_platform_wallet.json` (T1.1.5, each
  station-sealed `.rrnwallet` decrypts to its recorded identity), the
  consolidated `ffi_invariants.json` (T1.1.6, incl. Blake3 hash determinism), and
  `cross_platform_canonical.json` + `cross_platform_signed_payload.json` (T1.1.7,
  canonical dCBOR and a `SignedPayload<TransactionProposal>` that signs to
  byte-identical bytes). *Residual risk:* the fixtures cover the invariants
  enumerated, not the entire input space; the Rust property tests (T1.1.6) widen
  that coverage.
- **Signed-payload canonicalization is Rust's, not a mobile encoder.** *Threat:*
  the same logical payload canonicalizes to *different* bytes on mobile than on
  the station, so a mobile-signed message is rejected — or, worse, two distinct
  values collide to one signature. *Mitigation:* `canonical_bytes` (T1.1.7) takes
  a **tagged value model** as transport JSON and re-encodes it with the one dCBOR
  encoder in Rust; the JSON is never itself the signed form. The tagged model
  carries what plain JSON cannot — byte strings (addresses/hashes/keys) and exact
  i64/u64 integers as decimal strings — so a large amount or nonce cannot silently
  round to a different signed value the way a JSON double would. dCBOR then sorts
  map keys and rejects non-canonical encodings, so there is one byte sequence per
  value. *Residual risk:* a payload type whose mobile-built tagged shape does not
  match its station `Into<CBOR>` mapping would diverge; this is pinned per type by
  the signed-payload fixture (proposal today) rather than assumed.
- **Floats forbidden in signed payloads.** *Threat:* a float in a signed amount
  introduces precision/representation ambiguity (ADR-0002), so the "same" amount
  signs inconsistently. *Mitigation:* enforced twice — the TS `int()` builder
  rejects a non-integer `number` before the FFI is called, and the Rust encoder
  has no float tag and returns a named `PayloadError::FloatForbidden`. A malformed
  or unrecognized node is **rejected**, never coerced to a lenient encoding, so a
  bad payload fails loudly instead of signing to an unintended value.
- **Wrong passphrase / tampered wallet bytes.** *Threat:* a corrupted or
  attacker-substituted `.rrnwallet`, or a wrong passphrase, yields a garbage key
  that is then used to sign. *Mitigation:* decryption is the crate's AEAD path —
  a wrong passphrase or any ciphertext/tag alteration fails the Poly1305 tag and
  surfaces as `WalletError` (`Decrypt` / `Corrupt`), never partial or garbage
  plaintext (see `rrn-identity` *Tampering* above). The mobile wrappers propagate
  the error and never fall back to an unauthenticated path. *Residual risk:* a
  weak user passphrase narrows the argon2id margin (shared with SecureStore).
- **Double protection at rest.** The `.rrnwallet` bytes mobile persists are
  already passphrase-encrypted *before* they reach `SecureStore` under
  `WALLET_FILE`, so OS-store extraction yields ciphertext, not the key — the
  layering described in the SecureStore subsection. The address is never stored;
  it is re-derived from the secret on decrypt, so a tampered address cannot
  disagree with the key.
- **Passphrase in the JS heap.** *Threat:* the passphrase is a JS string passed
  into the FFI, and JS strings are immutable and not zeroizable, so it may linger
  in the interpreter heap. *Mitigation:* the passphrase is used only to derive the
  argon2id key inside Rust (where the derived key *is* zeroized); it is not
  retained by the wrappers. *Residual risk:* the passphrase string's lifetime in
  the JS heap is at the runtime's discretion — accepted, and noted so it is not
  silently assumed away. On-device execution of the real bindings is still
  pending the RN-wrapper build (ADR-0007 accepted risk); until then the wrappers
  are exercised against Rust-generated fixtures, not the live native module.

### `mobile` social-recovery UI surface (M1.2)

*Implemented in M1.2 (T1.2.3).* The wallet UI for Shamir social recovery
([ADR-0004](adr/0004-own-shamir-implementation.md)): the owner splits their key
across a circle of holders and hands each a sealed shard (`ChooseHolders` →
`RecoverySplit` → `DistributeShards`), and a holder receives a shard sent to them
(`HeldShards`). The split, sealing, and shard parsing are the Rust engine's,
reached through the crypto FFI surface above (`RecoveryPackage`,
`parse_shard_payload`); the shards themselves cross device-to-device as QR codes.
This subsection covers the UI/transport of that ceremony — the FFI's guarantees
and `SecureStore`'s at-rest protections are the two subsections above.

**Assets:** the owner's key while split into shards; the confidentiality of each
sealed shard in transit and while held on a holder's device; the recovery
config (holder addresses + local nicknames) persisted on the owner's device.

- **Shard interception during distribution.** *Threat:* an attacker photographs
  or otherwise captures a shard QR as it is shown holder-to-holder. *Mitigation:*
  each shard is **sealed to its holder's public key** (per-holder ephemeral-key
  encryption in `rrn-identity::recovery`), so a captured QR yields ciphertext an
  interceptor cannot open without that holder's secret; and any single shard is
  **below the reconstruction threshold** `K`, so it reveals nothing about the key
  even if opened. Distribution is designed as an in-person, one-at-a-time hand-off
  (`DistributeShards` shows one holder's QR at a time). *Residual risk:* an
  attacker who both compromises a specific holder's key *and* intercepts that
  holder's shard gains one share — still short of `K`; collecting `K` such pairs
  is the threshold assumption itself.
- **Holder app / device compromise.** *Threat:* an attacker with access to a
  holder's device reads the shards it is holding for others
  (`SecureStoreKeys.RECOVERY_SHARDS`). *Mitigation:* held shards are stored as the
  **sealed ciphertext** exactly as received — decryptable only with the holder's
  wallet secret, which is itself passphrase-encrypted and behind the OS
  biometric/passcode (`SecureStore`) — and each is one share below threshold. For
  that reason the held-shard store carries **no biometric gate of its own**
  (`requireBiometric: false`): gating already-sealed, sub-threshold material would
  prompt the holder on every read without adding a defense the payload encryption
  does not already provide. *Residual risk:* a fully compromised OS is outside the
  trust boundary (carried device-trust assumption); even so, the attacker holds
  sealed shares below threshold, not the friend's key.
- **Wallet handle is re-acquired, not carried, for recovery.** *Threat:* keeping
  the decrypted wallet or the passphrase alive after onboarding — so it is around
  when recovery setup runs — widens the window a JS/native compromise could scrape
  it. *Mitigation:* onboarding seals the wallet and immediately drops both the
  passphrase and the in-memory handle; recovery setup **re-unlocks** at its own
  gate (`RecoveryUnlock`, biometric-first with passphrase fallback), the single
  path for both the post-onboarding and the Settings entry points. The handle
  lives only for the duration of the flow and is cleared on completion.
  *Residual risk:* the passphrase's transient lifetime in the JS heap during
  unlock — the same accepted risk noted under the crypto FFI surface.
- **Passphrase kept out of navigation state.** *Threat:* React Navigation
  serializes route params into persisted navigation state, so a passphrase (or
  wallet handle) passed as a param could be written to disk. *Mitigation:* the
  transient recovery secrets are held in an in-memory React context
  (`RecoveryContext`), never in route params; only a non-secret `origin` string
  is routed. *Residual risk:* none beyond the in-heap-lifetime risk above.
- **Malicious or malformed shard fed to a holder.** *Threat:* a holder is tricked
  into scanning a crafted QR (a plain address, an unrelated code, or corrupt
  bytes) that mis-parses into a bad stored entry. *Mitigation:* `HeldShards`
  accepts a QR only if it carries the `rrnrecovery:` scheme *and* the Rust
  `parse_shard_payload` accepts its bytes; anything else is rejected with an
  explanation and nothing is stored. Parsing reads only non-secret routing
  metadata and never decrypts the shard. *Residual risk:* a holder can still be
  socially engineered into storing a validly-formed shard from an impersonator —
  harmless to the holder (they only hold it), and surfaced to the owner as a
  wrong/missing holder at reconstruction time.
- **Self-attested delivery.** *Threat:* the owner believes recovery is in place
  when it is not. *Mitigation:* delivery is explicitly self-attested — the owner
  taps "Scanned" per holder — and finishing is blocked until at least `K` are
  marked delivered, so the config cannot claim a working circle below threshold.
  *Residual risk:* an owner who mis-attests (marks a holder who did not actually
  receive the shard) records a circle that will not reconstruct; this is a
  usability/honesty limit of an offline hand-off, not a confidentiality break.
- **Recovery config is non-secret.** The persisted config
  (`SecureStoreKeys.RECOVERY_CONFIG`) holds holder addresses, local nicknames,
  the threshold, and per-holder delivery flags — **no shard material** — so it is
  stored without a biometric gate (like the held-shard store) and, if extracted,
  discloses only the social graph of the circle, not the key. *Residual risk:*
  that social-graph metadata (who holds for whom) is itself mildly sensitive and
  is accepted as local-only, device-protected data.

### Mobile–station transport

**Assets:** the authenticity of each mobile→station request; the confidentiality
of request/response contents on the wire; the integrity of ledger data
replicated across the link; the pairing bond between a specific mobile and a
specific station.

The transport is **plain HTTP over local TCP** ([ADR-0008](adr/0008-mobile-station-transport.md));
the security boundary is the **application-layer sealed-and-signed envelope**,
not the channel. A request is a canonical-dCBOR envelope
(`method`/`params`/`signer`/`recipient`/`nonce`/`timestamp`) signed by the
mobile's Ed25519 identity key, framed with that signature, then **sealed** to the
station's public key (anonymous X25519→blake3→XChaCha20-Poly1305 box, the same
`rrn-identity::sealed` construction recovery uses). The station opens it, and the
mitigations below are what the shipped `rpc_envelope` / `core::do_rpc_request`
pipeline enforces (T1.3.4).

- **MITM on the local network.** *Threat:* an attacker on the same LAN intercepts
  or alters traffic between mobile and station. *Mitigation (shipped, T1.3.4):*
  every request carries the mobile's signature over the exact payload bytes, so
  any tampering fails verification regardless of the channel; and the payload is
  sealed to the station's key, so a snooper reads only ciphertext. TLS is
  deliberately *not* used — the envelope already provides both properties and
  survives store-and-forward carriers TLS cannot (ADR-0008). *Residual risk:*
  traffic-analysis metadata (below), and any exposure before pairing completes.
- **Replay.** *Threat:* a captured sealed request is replayed to repeat its
  effect. *Mitigation (shipped, T1.3.4):* **two independent nonces** apply. The
  channel enforces a **per-mobile monotonic transport nonce**, persisted in
  `paired_mobiles.json` (`PairedMobiles::accept_nonce`) and checked before
  dispatch, plus a ±5-minute timestamp-skew bound (`TIMESTAMP_SKEW_SECS`) — a
  request must be strictly newer and fresh. Independently, any *transaction* it
  carries is still subject to the ledger's own content-addressing and per-sender
  gap-free nonce (see [Replay across crates](#replay-across-crates)). The nonce
  high-water mark is persisted **before** dispatch, so a replay cannot slip in
  even if the method then fails. *Residual risk:* replay within the ±5-minute
  window is bounded by its width; a request whose transport nonce was burned but
  never reached the ledger is simply refused on retry (the mobile skips to the
  next nonce).
- **Station impersonation.** *Threat:* a rogue host poses as the member's paired
  station. *Mitigation (shipped, T1.3.3/T1.3.4):* the request is sealed to the
  paired station's public key, so only the real station can open it; the
  `recipient` key is **bound inside the mobile's signature**, so a station cannot
  peel a signed request out of its envelope and re-seal it to a third party; and
  the station signs its reply, which the mobile verifies against the paired key.
  *Residual risk:* see TOFU below — the bind is only as trustworthy as the moment
  pairing was made.
- **Signer impersonation / unpaired access.** *Threat:* a device that is not the
  member — an unpaired key, or one paired mobile trying to act as another —
  submits requests. *Mitigation (shipped, T1.3.4):* the station authorizes on the
  `signer` recovered from the verified signature: it must be in
  `paired_mobiles`, and because `signer` is inside the signed bytes a mobile
  cannot claim another's identity. Write methods additionally bind the *submitter*
  to the authenticated signer (a mobile cannot relay a proposal/confirmation
  signed by someone else), and the ledger re-verifies the record's own signature.
  Unpaired or badly-signed requests get a 401-equivalent with no sealed body.
  *Residual risk:* none beyond key compromise (below).
- **Paired-mobile compromise.** *Threat:* an attacker obtains a member's unlocked
  device or identity key and acts as that member until noticed. *Mitigation
  (shipped):* the mobile holds the key sealed at rest (passphrase + keychain) and
  the app gates on a lock screen that drops the unlocked wallet when backgrounded
  (T1.3.4), narrowing the window; either side can revoke the bond at any time
  (operator `station unpair <address>`, or the mobile from Settings), after which
  the next request is rejected as unpaired. *Residual risk:* actions taken with a
  live key before revocation stand — this is the inherent limit of a bearer key,
  the same as any self-custody wallet.
- **Envelope confidentiality / traffic analysis.** *Threat:* an observer learns
  content or metadata from the link. *Mitigation (shipped, T1.3.4):* the sealed
  box keeps request and response *contents* confidential to the two endpoints on
  plain HTTP. *Residual risk (accepted):* the seal has **no forward secrecy** —
  it uses the station's long-term key, so a future compromise of that secret
  would open previously-recorded traffic; ADR-0008 scopes per-request FS out for
  Phase 1, with Noise_KK as the named upgrade path (a superseding ADR, since
  pairing already establishes both static keys). Metadata — that a given mobile
  talked to a given station, when, and roughly how much — is **not** hidden and
  is out of scope.
- **Pairing-time TOFU.** *Threat:* pairing is trust-on-first-use, so an attacker
  present at the *first* contact can interpose and become the "trusted" station.
  *Mitigation (shipped, T1.3.3):* an out-of-band **short authentication string** —
  an 8-hex code derived from *both* static public keys (`blake3(tag ‖ station_pk
  ‖ mobile_pk)`), displayed by the station operator (`station pair-mobile`) and on
  the mobile, which a human compares in person. A man-in-the-middle would have to
  present its own key, which changes the code, so the comparison catches it. (The
  spec's QR-scanned-by-CLI was rejected — a headless Pi cannot scan, and one QR
  cannot carry both keys.) *Residual risk:* if users skip the comparison, TOFU is
  only as safe as the pairing environment; this remains a user-facing risk.
- **Push updates over the long-poll (`/subscribe`).** *Threat:* the push channel
  could leak a member's events to an eavesdropper, deliver a forged event, or be
  used to exhaust the station. *Mitigation (shipped, T1.3.5):* `/subscribe` reuses
  the **same sealed, signed envelope** as `/rpc` — authenticated by the mobile's
  key, sealed to the station, replay-bound by the same per-request transport
  nonce, skew-checked, and gated on the paired list — so all of the MITM, replay,
  impersonation, and confidentiality properties above apply unchanged. Each event
  is derived from an already-signed, engine-verified log entry and delivered
  inside the station-signed sealed reply; the station relays only what it
  cryptographically accepted on ingest (the mobile carries no dCBOR decoder, so it
  does not independently re-verify the embedded originator signature — a
  documented consequence of ADR-0008, not a gap). Directional relevance means a
  member only ever receives events it is a party to (a proposal to it, its own
  proposal confirmed, a settlement or cancellation it is in), so the channel
  cannot be used to enumerate other members' activity. *Residual risk (accepted
  for Phase 1):* a paired mobile can hold a connection (and a task) open for the
  ~30s hold, so a compromised paired device could tie up connections; the bound is
  the paired-member set (an unpaired key cannot authenticate to open one at all).
  A per-mobile single-flight/connection cap is the named hardening if this
  matters at scale.

## Cross-cutting threats

Some threats are not owned by a single crate — they emerge from how the layers
compose. These are the ones an auditor should reason about end-to-end.

### Replay across crates

Every signed value (`rrn-crypto::SignedPayload`) is, on its own, a bearer token:
holding the bytes lets you re-present them. Replay protection is therefore not a
property of any one signature but of the *log + ledger* enforcing single use:

- A proposal is **content-addressed** (its `TransactionId` is the Blake3 hash of
  its canonical bytes), so a verbatim replay collides with the existing id and
  is rejected (`Error::DuplicateProposal`).
- Each sender carries a **monotonic, gap-free nonce**; a replayed or out-of-order
  proposal fails `Error::BadNonce`.
- A proposal is valid only inside `proposed_at ≤ now ≤ expires_at` (±5 min skew,
  `CLOCK_SKEW_TOLERANCE_SECS`), so a stale capture cannot be replayed forever.
- Settlement is **idempotent**: `Settler::settle` checks the derived state is not
  already `Settled` *before* any balance write, and balances are derived from
  settlement records keyed by `proposal_id`, so a duplicated settlement entry
  (including one re-delivered over gossip) cannot double-apply.
- Replicated entries arrive via `AppendLog::append_raw`, which **dedupes by
  Blake3 content hash** before writing, so a replayed log entry is dropped.

*Residual:* the nonce sequence is per-sender on a *single* replica. A sender
acting on two stations, or cross-replica nonce coordination generally, is a
Phase 1+ federation problem (no global ordering in Phase 0).

### Log fork / rollback

The append-only log proves *integrity and order within one log*, not
*uniqueness across replicas*. Within a replica, `verify_chain` detects any edit,
reorder, deletion, or splice (each entry chains to the Blake3 `content_hash` of
the previous), and `append_raw` re-chains replicated entries onto the **local**
tail rather than importing a peer's `prev_hash` — a peer cannot inject a break
into our chain. What is *not* defended:

- **Forking** — two replicas extending into conflicting-but-individually-valid
  chains. The Phase 0 gossip stub logs a warning and skips conflicting entries;
  real fork *resolution* is Phase 1+ (`rrn-protocol`).
- **Rollback / truncation** — truncating the log to an earlier valid prefix
  yields a shorter but still-consistent chain. Detecting this needs external
  anchoring (e.g. cross-replica checkpoints), also Phase 1+.

### Key-compromise impact analysis

What an attacker gains by stealing each kind of secret key, since the whole
system reduces to "a valid signature ⇒ authentic" under the key-secrecy
assumption:

- **A user's identity key** (the wallet secret): full impersonation — propose
  payments as them, confirm payments to them, issue vouches as them. Bounded
  only by the ledger rules (nonce/window), not prevented. This is *the* asset;
  it is protected at rest by argon2id + XChaCha20-Poly1305 and in memory by
  `zeroize`. Social recovery (`recovery`) is the mitigation for *loss*, not for
  *theft* — a thief with the live key needs no recovery.
- **The station key**: authority to author settlement/cancellation records
  (ADR-0005) and to sign gossip handshakes. A compromised station can settle
  eligible confirmed transactions and serve hostile-but-valid entries to peers;
  it **cannot** forge a sender's proposal or a receiver's confirmation (those
  need the parties' keys). The single Phase 0 station is trusted to decide
  *when* to settle.
- **A recovery shard holder's key**: lets that holder decrypt *their own* shard.
  Inherent to entrusting them a shard, and bounded by the `K`-of-`N` threshold —
  an attacker needs `K` compromised/colluding holders to reconstruct the key;
  any `K-1` reveal nothing (Shamir is information-theoretically secure).

Compromise of any key is **non-recoverable by cryptography alone** — there is no
revocation list in Phase 0. Re-keying means creating a new identity (and, for
recovery, `flow::refresh` to re-split to a new holder set).

## Trust boundaries

The arrows are the boundaries an auditor should focus on: every place untrusted
or lower-trust data crosses into a higher-trust context. In Phase 0 the *only*
network boundary is the gossip stub; the CLI↔daemon boundary is local.

```
                        ┌──────────────────────────────────────────────┐
                        │  User's device (TRUSTED per device-trust       │
                        │  assumption: OS, kernel, RAM, disk)            │
                        │                                                │
   passphrase (no echo) │   ┌────────────┐   Unix socket 0o600          │
   ───────────────────► │   │  rrn (CLI) │◄───────────────┐             │
                        │   └────────────┘   (line-JSON)   │             │
                        │                                  ▼             │
                        │                          ┌───────────────┐     │
                        │   ┌──────────────┐       │ station daemon│     │
   .rrnwallet (disk) ──►│   │ wallet       │──key─► │ (holds key in │     │
   argon2id+AEAD at rest│   │ decrypt      │       │  RAM, decrypted│     │
                        │   └──────────────┘       │  for lifetime) │     │
                        │                          └───────┬───────┘     │
                        │   ┌──────────────────────────────▼─────────┐   │
                        │   │ rrn-ledger  (engine, settlement)        │   │
                        │   │  └─ verifies SignedPayload at boundary  │   │
                        │   ├─────────────────────────────────────────┤   │
                        │   │ rrn-storage (append-only log = truth;   │   │
                        │   │  append/append_raw RE-VERIFY signatures │   │
                        │   │  and hash-chain before writing)         │   │
                        │   │  CRDT/balance state ← replay(log)       │   │
                        │   ├─────────────────────────────────────────┤   │
                        │   │ rrn-crypto  (AUDIT BOUNDARY: sign/verify,│   │
                        │   │  canonical CBOR, hash; no rrn-* deps)    │   │
                        │   └─────────────────────────────────────────┘   │
                        │            ▲   SQLite file (plaintext on disk)   │
                        └────────────┼───────────────────────────────────┘
                                     │
              gossip (TCP) ──────────┘  ◄── UNTRUSTED NETWORK
              peer entries: NOT trusted by source; every entry
              re-verified (signature + content hash) and re-chained
              onto the local tail by append_raw before it is stored.
              No transport auth/encryption in Phase 0 (Phase 1+).
```

The load-bearing invariant: **untrusted bytes never become trusted state
without passing through `rrn-crypto` verification** — at the ledger boundary
*and* again at the log write (`append`/`append_raw`). State is always *derived
from* the verified log, never written authoritatively around it.

## Known limitations

Things Phase 0 explicitly does **not** mitigate, and why. Stating these plainly
is deliberate — the audit covers what is built, and these are the documented
edges of that scope.

- **No Sybil resistance.** Vouch *authenticity* is enforced cryptographically;
  vouch *trust* is not. A single-community Phase 0 deployment is assumed; a
  Sybil cluster of mutually-vouching keys is cryptographically valid. Reputation
  / Sybil analysis is Phase 1+.
- **No federation security.** Eclipse attacks, cross-replica ledger forks,
  rollback detection, and treaty abuse are out of scope (see
  [Log fork / rollback](#log-fork--rollback) and `rrn-protocol`).
- **No at-rest encryption of the database.** Only the wallet secret key is
  encrypted. Balances, the transaction graph, memos, and the social-vouch graph
  are plaintext on disk — exposed to a local attacker or seized media. Whole-DB
  encryption is future work (design §10.8).
- **No memory hardening beyond `zeroize`.** Keys are necessarily plaintext in
  RAM while in use; no `mlock`, no swap guard, no core-dump suppression. A
  same-user code-execution attacker or physical memory access defeats secrecy
  (per the device-trust assumption). `RRN_PASSPHRASE`, if used, is visible in
  the process environment.
- **No credit limits / no debt bound.** A sender can settle into arbitrary debt
  in Phase 0.
- **No rate limiting or resource caps** on the IPC socket or the gossip port,
  and no message-size cap; the gossip stub pulls a peer's whole log each round.
  O(N) full-log replay has no snapshotting yet. All Phase 1/2.
- **Unclamped wallet KDF parameters.** A hostile `.rrnwallet` can specify a very
  large argon2 `m_cost`, forcing a large allocation on `decrypt` (accepted: you
  only decrypt your own wallet; clamping is a noted future hardening). This is
  the documented caveat the `wallet_decrypt` fuzz target may surface.
- **GF(256) table-lookup timing in Shamir.** Field multiplication indexes
  `LOG`/`EXP` tables by secret bytes; full cache-timing resistance is not
  claimed. Recovery is a rare, local, interactive operation with no co-resident
  remote attacker in the Phase 0 model. Constant-time table-free multiplication
  is a noted future hardening.
- **No key revocation.** Compromise of any key is non-recoverable by
  cryptography alone in Phase 0 (see [Key-compromise impact
  analysis](#key-compromise-impact-analysis)).
- **No formal verification.** Correctness rests on unit tests, `proptest` for
  algebraic properties (CRDT laws, sign/verify, canonicalization), cross-crate
  integration tests, and the fuzz harnesses — not on machine-checked proofs.

## Mitigations summary

The mitigations are documented inline per component and per cross-cutting threat
above; this is the index. Anticipated mitigations from the design overview
(Section 10.8, "Security Architecture") map to Phase 0 as follows:

- **Replay attack** → per-sender monotonic nonce + ±5-minute timestamp window +
  content-addressed ids in `rrn-ledger` (T0.5.6), idempotent exactly-once
  settlement (T0.5.5/T0.5.7), content-hash dedupe on replication
  (`append_raw`). See [Replay across crates](#replay-across-crates).
- **Tampering / forgery** → `verify_strict` over canonical CBOR via
  `SignedPayload`, re-verified at the log write; hash-chained log detected by
  `verify_chain`; state derived from the log, never written around it.
- **Physical node seizure** → wallet key encrypted at rest (argon2id +
  XChaCha20-Poly1305, `0o600`, atomic write). Whole-database encryption is **not
  yet** done (see [Known limitations](#known-limitations)).
- **Eclipse attack, ledger fork, Sybil federation** → deferred to Phase 1+
  (`rrn-protocol`), out of scope for the Phase 0 audit per [Scope](#scope).

## References

- Design overview, Section 4.1 — "The Attack Surface" (oracle attacks)
- Design overview, Section 4.3 — "The Tiered Oracle Model"
- Design overview, Section 10.8 — "Security Architecture"
- [ADR-0001](adr/0001-rust-workspace-and-dual-license.md) — Rust workspace
  and dual license
