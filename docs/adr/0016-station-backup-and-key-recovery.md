# 0016 — Station backup and key recovery: an encrypted archive whose key survives a lost passphrase

## Status

Proposed

Date: 2026-08-20

## Context

A station's data directory holds two things the community cannot afford to lose
and cannot reconstruct from anywhere else:

- **`wallet.rrnwallet`** — the station's identity key, sealed under a passphrase
  (Argon2id → XChaCha20-Poly1305, [`rrn-identity::wallet`]). This key *is* the
  station's address; every settlement the station has ever signed traces to it.
- **`station.db`** — the ledger: every transaction, dispute, governance
  proposal, vote, and the reputation history derived from them. It runs in WAL
  mode.

Two smaller files matter but are cheaper to lose: `paired_mobiles.json` (losing
it means re-pairing every phone) and `config.toml` (peers, settlement window).
The `marketplace_index/` directory is a derived Tantivy cache the station
rebuilds from the log on startup, so it never needs backing up.

Today there is no supported way to copy this state somewhere safe or to bring it
back on a new machine. Operators have resorted to ad-hoc directory copies, and
the project has twice lost a station passphrase outright — which, because the
wallet KDF is deliberately one-way, meant the identity was gone for good. A
Phase-1 pilot (a real community of 20+ for 90 days) cannot run on that footing:
a dead SD card or a forgotten passphrase would end the community's ledger
permanently.

Two forces shape the fix, and they pull against each other:

1. **A backup must be safe to store off-device.** Operators will keep backups on
   a USB stick, a laptop, or cloud storage. The wallet inside is already
   encrypted, but the ledger is not — it names every member and their whole
   transaction history in the clear. So the archive as a whole must be
   encrypted.

2. **A lost passphrase must still be survivable.** The reason to back up at all
   is disaster, and "I forgot the passphrase" is the most common disaster. But
   if the archive is encrypted *only* under the passphrase, then losing the
   passphrase locks the operator out of their own backup — the backup rescues
   everything except the one failure it most needs to. Encryption-at-rest and
   passphrase-loss recovery are therefore not two independent features; the
   encryption scheme has to be designed so that recovery can open it.

The project already owns the primitive for the recovery half: [ADR-0004]'s
Shamir secret sharing ([`rrn-identity::recovery`]), which splits a 32-byte
secret into `N` shards sealed to trustees such that any `K` reconstruct it and
`K−1` learn nothing. Mobile wallets already arm themselves with it and already
carry sealed shards between phones as `rrnrecovery:`-prefixed payloads. What does
not yet exist anywhere is the *reconstruction* ceremony — gathering `K` trustees'
decrypted shards and rebuilding — on either the station or the phone.

## Decision

Introduce `station backup` / `station restore` and a `station recovery` family,
built on one envelope design that makes encryption-at-rest and passphrase-loss
recovery compose.

### The backup archive and its dual-wrapped key

`station backup` produces a **single encrypted archive** of the irreplaceable
state:

- `station.db`, captured as a **consistent live snapshot via `VACUUM INTO`**
  from a separate read connection. Because the database is in WAL mode, this
  needs no exclusive lock and no daemon downtime — the running station keeps
  serving while the backup is taken.
- `wallet.rrnwallet` (copied verbatim; it is already encrypted).
- `paired_mobiles.json` and `config.toml`.
- The derived `marketplace_index/` is **excluded**; restore lets the station
  rebuild it.

The archive is encrypted with a fresh random 32-byte **data-encryption key
(DEK)** under XChaCha20-Poly1305. The DEK itself is then **wrapped two
independent ways**, and both wraps are stored in the archive header:

1. **Under the passphrase** — Argon2id (the wallet's parameters: 64 MiB, t=3,
   p=4, fresh salt) derives a key-encryption key that seals the DEK. This is the
   ordinary path: `station restore` prompts for the passphrase, re-derives the
   KEK, unwraps the DEK, decrypts.
2. **Sealed to the station's own public key** — the DEK is also sealed with
   [`rrn-identity::sealed`] to the station's identity public key (recorded in
   the header). Whoever can produce the station's *secret* key can open this
   wrap without the passphrase.

The security of the archive is unchanged from a single-wrap design: both wraps
protect the *same* DEK, and each independently requires a secret the attacker
does not have (the passphrase, or the station secret key). The second wrap is
what lets recovery re-enter: reconstructing the secret key via Shamir opens wrap
(2) even when the passphrase — and thus wrap (1) — is gone.

### Recovery: arm, then reconstruct

`station recovery setup --holder <addr>… --threshold K` splits the station's
secret key with `RecoveryPackage::create`, sealing one shard to each trustee's
address, and emits each shard in the existing `rrnrecovery:` payload format so a
trustee's phone can receive and store it exactly as it stores a personal-wallet
shard. The station keeps the non-secret `RecoveryPackage` (metadata + the sealed
shards' public parts) alongside its data dir.

`station recovery restore` is the ceremony that was missing everywhere: it
collects `K` trustees' **decrypted raw shards**, reconstructs the secret key with
`reconstruct_wallet` (which verifies the rebuilt key's address against the
package, so wrong or insufficient shards fail loudly), rewrites
`wallet.rrnwallet` under a new passphrase, and — critically — uses the recovered
secret key to open wrap (2) of a backup archive and restore the ledger. A
trustee produces their decrypted raw shard on their phone through a new
"contribute my shard" capability (new FFI + a mobile screen), returned to the
operator as an `rrnrecovery:`-style payload.

### Restore safety

`station restore` refuses to write into a data directory that already contains a
wallet or database, unless `--force` is given. Bringing a station back is a
new-machine / empty-dir operation by default; clobbering a live station is an
explicit, deliberate act.

## Consequences

- **The pilot becomes backup-safe and passphrase-loss-survivable.** As long as
  an operator keeps *either* their passphrase *or* a threshold of trustees, they
  can recover both the identity and the full ledger.
- **One envelope, two doors.** Encryption-at-rest and recovery share the DEK, so
  there is a single archive format to reason about, and the recovery path is not
  bolted on — it is a second key-wrap that was designed in from the start.
- **Live backups.** WAL + `VACUUM INTO` means routine or scheduled backups need
  no downtime, which is what makes "back up often" realistic advice for a
  non-expert operator.
- **The reconstruction path is net-new work on both repos.** Mobile gains a
  shard-contribution capability (FFI + screen) it did not have; the station
  gains the collect-and-rebuild ceremony. This ADR's scope covers building it.
- **Trustee compromise is a real risk to bound.** Any `K` trustees who collude
  can reconstruct the station key. Threshold choice is the operator's lever;
  the setup command should push a sensible default and refuse `K < 2`. Shards in
  transit and at rest are confidential (sealed per holder), so a single leaked
  shard reveals nothing.
- **The archive still leaks metadata by size/existence, not contents.** The DEK
  design encrypts contents; it does not hide that a backup exists or roughly how
  big the ledger is. That is acceptable for off-device storage.
- **Follow-up:** shard *refresh* (re-issuing to a new trustee set when a
  relationship sours) is already supported by `RecoveryPackage::refresh`; wiring
  a `station recovery refresh` is a small later addition, not required for the
  first cut.

## Alternatives Considered

- **Encrypt the archive under the passphrase only.** Simplest, and rejected as
  the central mistake this ADR exists to avoid: it makes the backup useless
  against the most likely disaster (a forgotten passphrase).
- **Leave the archive in cleartext (rely on the wallet's own encryption).** The
  ledger names every member and their history; a stolen USB stick would expose
  the whole community. Rejected.
- **Recover the passphrase itself** (escrow it, or split *it* with Shamir).
  Rejected: the passphrase is a human-chosen KDF input, not a fixed secret, and
  escrowing it would defeat the wallet's at-rest encryption. Splitting the
  *key* and letting recovery open a key-sealed wrap achieves the same end
  without ever handling the passphrase.
- **Require stopping the daemon to back up.** Bulletproof for consistency but
  hostile to routine use; WAL + `VACUUM INTO` gives the same consistency live,
  so the stop-first rule is unnecessary.
- **Back up over the Unix socket (SQLite Online Backup API in the daemon).**
  More moving parts inside the running server for no gain over an out-of-process
  `VACUUM INTO`; the offline CLI can take a consistent snapshot on its own.
- **Trustees are other stations rather than members' phones.** Rejected for
  Phase 1: a young community's trust lives in its founding members, who already
  hold phones and already understand the `rrnrecovery:` shard format from the
  personal-wallet flow. Reusing that path is far less to build and to explain.

## References

- [ADR-0004 — Own Shamir implementation](0004-own-shamir-implementation.md)
- [ADR-0009 — Universal reputation algorithm](0009-universal-reputation-algorithm.md)
- [`rrn-identity::wallet`], [`rrn-identity::sealed`], [`rrn-identity::recovery`]
- `rrn-storage::db` (WAL configuration)
- Mobile shard wire format: `mobile/src/wallet/recoveryShard.ts`

[ADR-0004]: 0004-own-shamir-implementation.md
[`rrn-identity::wallet`]: ../../crates/rrn-identity/src/wallet.rs
[`rrn-identity::sealed`]: ../../crates/rrn-identity/src/sealed.rs
[`rrn-identity::recovery`]: ../../crates/rrn-identity/src/recovery/mod.rs
