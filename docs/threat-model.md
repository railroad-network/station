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

- DONE (M0.5): Replay attack → monotonically increasing per-identity nonce plus
  a ±5-minute timestamp window, enforced in `rrn-ledger`'s engine (T0.5.6), with
  idempotent, exactly-once settlement (T0.5.5/T0.5.7). See the `rrn-ledger`
  Elevation of privilege entry above.
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
