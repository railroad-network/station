# 0024 — Station at-rest encryption: a member-keyed encrypted volume unlocked by a boot ceremony

## Status

Accepted

Date: 2026-09-12

Ratified 2026-09-12. The recommended answers to the open questions are adopted as
the plan of record for the follow-up: (1) the seed-reuse path with the
holder-facing labelling caveat — no `rrnrecovery:` wire change, no new fixture;
(2) VMK rotation verifies keyslot-less `cryptsetup reencrypt` on the target and
otherwise uses the provision-new-container + `VACUUM INTO` fallback. (3)
Governance over custody stays deferred (config-only threshold) and is not a
first-cut dependency.

## Context

A station's data directory is, when powered off today, an unencrypted disclosure
of the whole community. Only `wallet.rrnwallet` — the identity secret key — is
encrypted at rest (Argon2id → XChaCha20-Poly1305, [`rrn-identity::wallet`]).
Everything else is plaintext on disk: `station.db` holds every balance,
transaction memo, dispute, vote, and the full vouch graph (the outbox lives in
this same database, not a separate store); a seized or imaged SD card yields all
of it (threat model, `rrn-storage` *Information disclosure* and *Residual risk*).
The design overview names the intended posture plainly (§10.8, "Physical node
seizure"): *"data at rest encrypted with keys held by community members, not
stored on the node, so a seized powered-off node yields an encrypted brick,"* and
it names the price in the same breath — *"member-held keys mean every reboot
needs a key ceremony."*

Three things are already true and shape the fix:

1. **The project owns the key-custody primitives it needs.** [ADR-0016] already
   splits a station key into `N` shards with [ADR-0004]'s Shamir implementation,
   seals each shard to a member's identity key, distributes them as
   `rrnrecovery:` payloads, and — crucially — implements the *reconstruction
   ceremony* on both station (`recovery::begin_restore` / `finish_restore`) and
   phone (the "contribute my shard" capability = `respond_to_recovery`). A
   member-held disk key is the same shape of problem as a member-recoverable
   backup key, and should reuse that machinery rather than grow a second one.

2. **The audit posture forbids the obvious shortcut.** The workspace's defining
   choice is Rust with no `unsafe` outside `rrn-crypto` so the whole binary
   stays auditable, and a locked, vetted crypto set (`rrn-crypto`:
   XChaCha20-Poly1305, Argon2id, ed25519, blake3). SQLCipher — the reflexive
   answer to "encrypt the SQLite file" — would link a C SQLite fork and a C
   crypto library into the daemon's own address space, expanding the audit
   surface of the exact binary the project promises to keep auditable, bypassing
   `rrn-crypto`, and superseding the locked "`rusqlite` bundled" row (technical
   decisions table). That cost has to be justified against alternatives that
   keep block encryption *out* of our address space.

3. **WAL crash safety is not negotiable.** `station.db` runs in WAL mode
   ([`rrn-storage::db`]); the ledger's integrity story depends on it. Any
   encryption scheme must leave SQLite seeing an ordinary filesystem with
   ordinary WAL semantics — an encryption layer that sits *below* the filesystem
   is therefore strongly preferred to one that reaches *into* the database file.

The node hardware that actually runs in the field is a Linux single-board
computer (overview §10.7 — the Class-1 reference is a Raspberry Pi 4). This
matters for cipher choice: the Pi 4's Cortex-A72 does **not** implement the
ARMv8 Cryptography Extensions (nor do the Pi 3 or Zero 2 W; only the Pi 5 does),
so AES on those boards is a pure-software path. Linux ships **Adiantum**
(`xchacha12,aes-adiantum-plain64`, best at `--sector-size 4096` and requiring
`CONFIG_CRYPTO_ADIANTUM` in the running kernel) precisely for AES-less ARM, and
that — not a wrong assumption of hardware AES — is what makes kernel block
encryption cheap enough on a Pi. Developer machines (macOS) and low-threat
deployments are a different case the design must accommodate without weakening
the field profile.

This ADR decides the *running* station's at-rest encryption and the ceremony
that unlocks it. Encrypted *backups* are already ADR-0016; this is the live
data directory. Two named obligations land here specifically: the threat model
defers whole-database at-rest encryption to this work (the "pending ADR-0024"
rows), and [ADR-0026] §7 assigns custody of the **Reticulum adapter identity**
to this ADR's at-rest scope. This document produces a design and stops for
review — the implementation is the seizure-resistance follow-up.

## Decision

Encrypt the station's mutable and secret state inside a **member-keyed encrypted
volume** whose master key is never written to disk and is reconstructed at boot
by a **quorum ceremony** built on ADR-0016's Shamir machinery. Block encryption
is done by the OS kernel (Linux `dm-crypt`/LUKS2) on a self-contained container
file; `rrn-crypto` handles only the *key*, never the bulk data.

### A two-root layout that keeps almost nothing in the clear

A station running the seizure-resistance profile splits its files into two
roots:

- An **unencrypted `boot_dir`** holding only what the node needs to configure
  itself and *begin* a ceremony while still locked: `config.toml` (peers,
  non-secret settings) and a minimal **VMK unlock descriptor** — the VMK's
  derived address and `K`/`N`, and nothing else. It deliberately does **not**
  contain the full `RecoveryPackage`, because that record serialises every
  holder's address (`flow.rs`) — a coercion-target map a seizer must not get
  from an imaged card. `begin_restore` needs only the target address, which the
  descriptor carries.
- An **encrypted `state_dir`**, the mount point of a LUKS2 **container file**
  (`state.img`), holding everything sensitive: `station.db` (with its
  `-wal`/`-shm` sidecars and the outbox tables inside it), `wallet.rrnwallet`
  (moved inside — see below), the full VMK `RecoveryPackage` (needed post-unlock
  for status/redelivery/refresh), `paired_mobiles.json`, the Reticulum adapter
  identity and `rnsd`'s storage (ADR-0026 §7), and the derived
  `marketplace_index/` — which **must** live inside, since the Tantivy index
  contains listing and need text that would otherwise leak.

Moving `wallet.rrnwallet` inside the container is a deliberate strengthening:
the station signing key gets the same brick protection as the ledger (today it
has only its passphrase), and — critically — it means the boot ceremony needs no
station keypair and therefore **no station passphrase on the plaintext boot
medium**. A passphrase in a systemd unit on the unencrypted root would hand a
seizer the signing key itself (impersonate the station, forge attestations) — a
worse outcome than ledger disclosure; keeping the wallet inside forecloses it.

Powered off, `state.img` is a LUKS2 brick with **no wrapped copy of the key on
the device**: it is opened keyslot-lessly with `cryptsetup open
--volume-key-file`, so the 32-byte Volume Master Key *is* the volume key. (The
LUKS2 header still records a non-invertible PBKDF2 *digest* of the volume key;
harmless for a 256-bit random key, but the follow-up MUST kill the throwaway
keyslot that `luksFormat` creates and post-check that the header has zero
keyslots — otherwise an Argon2-wrapped VMK survives under a provisioning
passphrase and the brick is not a brick.) Running, the volume is mapped by the
kernel and SQLite sees a normal ext4 filesystem — WAL, `foreign_keys`, and
`VACUUM INTO` behave exactly as today, and `db.rs` is unchanged.

Encryption thus lives entirely below our binary: the kernel's `dm-crypt`
(broadly deployed and audited) does block crypto — AES-XTS where crypto
extensions exist, Adiantum on the Pi 4, the cipher chosen by a deterministic
rule keyed on a `/proc/crypto` capability check and `cryptsetup benchmark` at
provisioning — while our audited code touches only a 32-byte key. No C crypto is
linked into the daemon, no `unsafe` is added, and the `rusqlite bundled`
decision stands.

The two-root split is **not** a no-op for `rrn-station`: the crate has ~22
`data_dir.join(...)` call sites assuming one flat directory (backup, recovery,
`Station::open`), plus a `Station::open` that opens the wallet and DB together
with no "locked, ceremony-only" serving mode. The follow-up must introduce the
`boot_dir`/`state_dir` distinction across those sites and a pre-unlock daemon
mode; `db.rs` and the storage layer stay untouched.

### The Volume Master Key and its custody

The container is unlocked by a random 32-byte **Volume Master Key (VMK)**,
generated once at provisioning and **never persisted in the clear anywhere**.
The VMK is Shamir-split with ADR-0016's `RecoveryPackage::create` among `N`
member holders at threshold `K`, each shard sealed to a holder's identity key
and delivered as an `rrnrecovery:` payload — the identical path members already
use for personal-wallet and station-key shards. The full package (with holder
identities) is persisted inside the container; only the descriptor is in
`boot_dir`.

Reusing `RecoveryPackage::create` unchanged has a concrete implication worth
stating: that call splits a *keypair* and tags the package and its
`rrnrecovery:` payloads with the derived `rrn1…` address. So the VMK is
generated as an **ed25519 seed**, and its derived address is what tags the VMK
package and the shards. Reconstruction is `reconstruct_wallet_for_address` as it
stands — its returned `WalletContents`' secret-key bytes *are* the 32-byte VMK
seed, so no new function is needed; wrong or insufficient shards fail loudly
against the recorded address. The cost of this reuse is a UX caveat: a holder's
phone shows the VMK shard as "a shard for `rrn1<vmk>`", indistinguishable from an
identity shard. The cleaner alternative — a `purpose` field in the
`rrnrecovery:` payload so phones can label "disk-unlock share" — is a
cross-platform CBOR wire change requiring a mobile fixture; it is listed under
Open Questions, with the seed-reuse-with-caveat recommended for the first cut.

The VMK is deliberately **distinct from the station identity key**: unlocking
the disk must not require exposing the signing key, and the two are rotated
independently. Rotating the VMK itself is a `cryptsetup reencrypt` of the
container — but keyslot-less online reencryption is only in recent `cryptsetup`
(≥ 2.7) and Raspberry Pi OS pins older builds, so the follow-up must verify it
on the target and otherwise fall back to *provision-new-container +
`VACUUM INTO`*. This is separate from *holder-set* rotation, which is
`RecoveryPackage::refresh` re-splitting the *same* VMK to a new trustee set;
because `refresh` needs the VMK seed in userspace, it is itself a quorum
ceremony (or runs inside an unlock, before the zeroize below) — not a background
operation.

Threshold defaults to **3-of-5**; provisioning refuses `K < 2` (matching
ADR-0016 `recovery::setup`). The ticket sketched threshold as
*charter-configurable*; this ADR diverges and recommends **config-only** for the
first cut, because the charter is a signed record living *inside* the encrypted
DB — unreadable while locked (chicken-and-egg at unlock and at re-bootstrap on
fresh hardware) and an additive charter field would be a signed-schema change.
VMK custody is local key material, not community-governed log state (the same
reasoning that keeps it off the log); governance *over* custody is a possible
later feature, not a first-cut dependency.

### The boot ceremony — wallet-free and console-anchored

Because the wallet is inside the container, no station keypair exists
pre-unlock, so the authenticated ADR-0008 mobile channel cannot run yet. The
ceremony is therefore **wallet-free** and reuses only the `begin_restore` /
`finish_restore` collect-and-reconstruct flow:

1. `station unlock` generates an ephemeral session key and shows a short
   **ceremony fingerprint** on the physical console.
2. `K` member holders contribute their decrypted raw shards, sealed to the
   session key. Two zero-internet paths: a **QR scan at the console** (the
   primary, needs no network), and an **unauthenticated pre-unlock LAN
   endpoint** that accepts only session-sealed `rrnrecover-resp:` blobs. Both
   require the holder to first confirm the console fingerprint out-of-band —
   this is what stops a seizer who imaged the descriptor from minting an
   ephemeral key and phishing shares (`RecoveryRequest` is itself unsigned, so
   the fingerprint, not the request, is the authenticator). A phone produces its
   shard through the ADR-0016 `respond_to_recovery` capability.
3. The station reconstructs the VMK in memory; wrong or insufficient shards fail
   loudly (the rebuilt key's derived address is checked against the descriptor).
4. A small **root-privileged mount helper** opens the LUKS container with the
   VMK and mounts it at `state_dir`. The helper MUST pass the key by file
   descriptor (`memfd`/pipe/`/proc/self/fd`), **never** a temp file, or the
   "never on disk" invariant is void at every unlock.
5. The daemon verifies `state_dir` is a **live dm-crypt mount** (a `statfs`/
   device check) *before touching any file* — otherwise a mis-ordered restart
   would create a fresh plaintext `station.db`, adapter identity, and index on
   the unencrypted root and serve them. It then opens the wallet (its passphrase
   prompted/supplied as today, now needed only *after* unlock) and begins
   serving.
6. The userspace copy of the VMK and the gathered shards are **zeroized**
   immediately. From then on the volume key lives only in the kernel's crypto
   state for as long as the volume is mapped.

### Key lifetime, crash, and reboot

- **Host reboot or power loss** unmaps the volume; the VMK is gone from memory
  and not on disk, so the node is a locked brick until a fresh ceremony. This is
  the availability cost, paid deliberately.
- **Daemon crash while the host stays up** does *not* require a ceremony. The
  `dm-crypt` mapping is kernel state owned by the mount helper / a systemd unit,
  not by the daemon process, so it outlives daemon death; a restarting daemon
  re-attaches to the already-mapped volume (after the step-5 mount check). This
  does not weaken seizure resistance: seizure means *powered off*; while the
  host is powered on the key is in kernel memory regardless of daemon restarts.

The VMK is **never** stashed in a systemd keyring or any store that survives a
power cycle — doing so would hand the key to the same seizure the design exists
to defeat.

### Availability trade, engaged honestly

Every unplanned power loss makes the station unavailable until `K` members
converge to contribute shards. Rough MTTR: where holders are co-located
(a shared building) this is within the hour; where they are dispersed it is a
*scheduled meetup* — plausibly days. Two mitigations, and one rejection:

- **A UPS is the primary mitigation** and the runbook's strongest
  recommendation: it turns power blips into non-events (no unmap, no ceremony)
  and, on low battery, performs a graceful shutdown that leaves the volume
  consistent. Most real availability loss is brownouts, not seizures; a UPS
  removes that class entirely.
- **The plaintext profile remains a supported deployment choice** for
  communities that do not face a seizure threat — it is today's behavior, not a
  degraded sub-mode of the encrypted profile, and it is selected at provisioning.
- **An operator-passphrase "degraded unlock" is rejected as seizure-resistance
  theater.** A passphrase the operator knows is precisely what coercion extracts,
  and it re-introduces the single seizable human the member-keyed design exists
  to eliminate. Communities that want single-operator unlock want the plaintext
  profile, and should be told so plainly rather than sold a passphrase that a
  rubber hose defeats.

### Scope of protection

- **Covered:** powered-off seizure of the node or its media — the volume is a
  LUKS brick, the VMK is not on the device, the wallet/ledger/adapter-identity
  are inside it, and no single seized holder can open it (< `K` shards reveal
  nothing, ADR-0004). The `boot_dir` descriptor discloses only the VMK address
  and `K`/`N`, not the holder set.
- **Not covered — stated plainly:** a node seized *while running* has the volume
  mapped and the key in kernel memory; cold-boot/RAM-remanence and live imaging
  can recover it. Mitigations are physical: custody, a tamper-evident enclosure,
  and **rapid re-bootstrap** on new hardware (ADR-0016). This ADR does not claim
  to defend a running node.
- **The sharp edges — as dangerous as the ciphertext is strong:**
  - **Swap and core dumps.** VMK bytes or plaintext DB pages can page out or land
    in a crash dump. The runbook MUST disable swap (or use encrypted swap) and
    suppress core dumps; this matches the existing "no mlock, no swap guard"
    residual in the threat model.
  - **`tracing` logs** must not be written to any plaintext partition if they
    carry sensitive fields.
  - **Backup and migration temporaries.** `station backup` today runs
    `VACUUM INTO` a system temp dir on the unencrypted root
    (`tempfile::tempdir()`), and `encrypt-in-place` will produce a plaintext
    snapshot too. On the encrypted profile these MUST be written to tmpfs or
    inside the container — otherwise routine weekly backups repeatedly deposit the
    whole plaintext ledger onto the very SD card seizure recovers. This is a
    required change in the follow-up.
  - **Ceremony-request authentication.** The pre-unlock endpoint is
    unauthenticated by necessity (no keypair yet); the console fingerprint is the
    only authenticator, and the residual is denial-of-service (junk sealed blobs)
    plus reliance on holders actually checking the fingerprint. Stated, not
    hidden.
- **Already elsewhere:** backup media (ADR-0016 dual-wrap archive); member phones
  (mobile repo — OS keychain + passphrase, out of scope here).

### Migration and re-bootstrap

- **Existing plaintext pilot stations** upgrade via a one-time, documented
  ceremony (`station encrypt-in-place`): provision the container (kill the
  throwaway keyslot, verify zero keyslots), arm the VMK Shamir split, move the
  wallet inside, `VACUUM INTO` the live DB across (to tmpfs/into the container,
  never the plaintext root), verify, then securely erase the plaintext. The
  runbook must state honestly that secure erase is unreliable on wear-levelled
  flash/SD — high-threat communities should **physically destroy the old card**,
  not trust `shred`.
- **Re-bootstrap after seizure** reuses ADR-0016 restore plus provisioning the
  new node's encrypted container, but is not free; the follow-up owns this
  checklist:
  1. Restore the backup archive onto fresh hardware and provision `state.img`.
  2. Replay member outboxes into the restored log (ADR-0020 point 6). A station
     restored from a backup taken at time *T* has rolled back its
     seen-outbox/receipt state, so re-submission of records members already hold
     receipts for can trip the `ConflictingAck` equivocation tripwire — the drill
     must reconcile receipts/acks after a rollback, not treat the collision as
     tampering.
  3. Re-arm the VMK (`RecoveryPackage`) to the (possibly changed) holder set.
  4. Re-bind the Reticulum adapter identity (ADR-0013 "bind, do not collapse")
     if it was seized with the old node.
  5. Re-pair mobiles (`paired_mobiles.json` is inside the container, so it does
     not survive a fresh provision without the backup).

### Implementation sketch (for the seizure-resistance follow-up)

- **`rrn-station`:** a `storage::volume` module wrapping the mount helper
  (open/close/status over `cryptsetup`+`losetup`, key via `memfd`, mount-check);
  a `vmk` module reusing `rrn-identity::recovery` to split/reconstruct the VMK;
  `station unlock`, `station encrypt-in-place`, VMK arming/refresh; the
  `boot_dir`/`state_dir` split across the ~22 flat `data_dir.join` call sites; a
  locked pre-unlock daemon mode plus the live-mount guard, and supervisor wiring
  so daemon restarts re-attach.
- **Config (`config.toml`):** `[storage] at_rest = "plaintext" | "encrypted"`;
  `[storage.encrypted] container_path`, `state_dir`; VMK holder set + threshold
  in config, `K` defaulting to 3, refusing `K < 2`.
- **Runbook:** UPS guidance; the unlock ceremony (console-QR + LAN, fingerprint
  confirmation); swap/log/core-dump hardening; the encrypt-in-place migration and
  its flash-erase caveat; the re-bootstrap drill above.
- **No new signed record kind** if the seed-reuse path is taken — the VMK is
  local key material, not logged state, so it adds no CBOR fixture; the tagged-
  payload alternative *would* add one (Open Question). The threat-model
  `rrn-storage` residual-risk rows are rewritten (from the "pending ADR-0024"
  deferral) to describe the shipped posture **in the follow-up, when it becomes
  true**, not here.
- **Platform:** Linux (`dm-crypt`) is the field target. macOS/dev falls back to
  the plaintext profile; a non-Linux production node is out of scope for the
  encrypted profile.

### Open questions for ratification

1. **Shard labelling.** Accept the holder-facing "shard for `rrn1<vmk>`" wart
   (recommended, no wire change), or add a `purpose` field to the `rrnrecovery:`
   payload (a cross-platform CBOR change needing a mobile fixture)?
2. **VMK rotation on pinned Pi OS.** Confirm keyslot-less `cryptsetup reencrypt`
   on the target `cryptsetup`, or standardise on the provision-new-container +
   `VACUUM INTO` fallback?
3. **Governance over custody, later.** Should threshold/holder-set move under the
   charter once a station is unlocked (post-first-cut), given custody is
   currently config-only for the chicken-and-egg reasons above?

## Consequences

- **A powered-off seized node becomes an encrypted brick** — ledger, wallet, and
  adapter identity all inside it — with no single human able to open it and no
  holder-list leaking from `boot_dir`. The overview §10.8 target, met for the
  running station and not only for backups.
- **The signing key gains at-rest brick protection** (previously passphrase-only)
  and the boot path needs no station passphrase on the plaintext medium — a
  strict improvement that also closes the "passphrase in the systemd unit" foot-gun.
- **Encryption stays out of our audited binary.** The kernel does block crypto;
  `rrn-crypto` touches only the 32-byte VMK. No C crypto is linked in, no
  `unsafe` is added, the `rusqlite bundled` decision holds, and `db.rs` is
  untouched — SQLite still sees ordinary WAL.
- **One custody model, reused,** at the cost of a holder-facing labelling wart
  unless the tagged-payload wire change is adopted.
- **Availability is genuinely worse, by design.** Every power loss costs a
  ceremony; dispersed holders can mean days. A UPS is now near-mandatory
  operational advice, and communities must choose the profile knowingly.
- **New surfaces to threat-model in the follow-up:** the root-privileged mount
  helper (holds the VMK transiently, drives `cryptsetup`, must pass the key by
  fd) and the unauthenticated pre-unlock ceremony endpoint (DoS, fingerprint
  reliance). Both need their own STRIDE subsections.
- **Linux-only for the protected profile.** The field hardware is Linux, so this
  is acceptable, but it is a real narrowing the human review should confirm.
- **Running-seizure is explicitly unsolved.** The honest boundary is stated;
  physical custody and rapid re-bootstrap are the answer, not this ADR.

## Alternatives Considered

- **SQLCipher (transparent full-DB page encryption).** The reflexive choice, and
  rejected here: it links a C SQLite fork + C crypto into the daemon's address
  space (expanding the audit surface of the binary the project promises to keep
  auditable), bypasses the vetted `rrn-crypto` primitives, and supersedes the
  locked `rusqlite bundled` row — all to encrypt only the DB, leaving the wallet,
  adapter identity, and search index still needing another scheme. Kernel block
  encryption of a container protects *everything* mutable at once and stays out
  of our binary.
- **Whole-disk / OS-native encryption left to the operator (LUKS root, FileVault).**
  Protects more (the whole OS), but pushes the hardest part — member-held key
  custody and the zero-internet ceremony — entirely into a runbook, is hostile to
  non-expert SBC operators, couples the design to each OS, and does not compose
  with our Shamir machinery. The container approach uses the same kernel
  primitive while owning the key ceremony in code where it can be tested.
- **Application-level page/record encryption inside SQLite (our own).** Would keep
  crypto in `rrn-crypto`, but reimplements what `dm-crypt` already does correctly,
  fights WAL and `VACUUM INTO` semantics, and is a large novel crypto surface to
  audit — the opposite of the project's "reuse vetted primitives" instinct.
- **A LUKS keyslot (Argon2-wrapped) instead of a keyslot-less volume key.**
  Cheaper rotation (`luksChangeKey`) and multiple keyslots, but the header then
  stores an Argon2-wrapped copy of the volume key, weakening the clean "no wrapped
  key on the device" claim. Since the VMK is already 32 bytes of full entropy,
  Argon2 stretching buys nothing; the keyslot-less `--volume-key-file` design is
  preferred, accepting reencrypt-on-rotation (or the container-swap fallback) as
  a rare cost.
- **Keeping the wallet in `boot_dir` and running the authenticated ADR-0008
  channel pre-unlock.** Rejected: it requires the station keypair — and thus a
  passphrase — available before unlock, which either lands the signing key on the
  plaintext boot medium or forces operator-plus-quorum at every boot. Moving the
  wallet inside and running a wallet-free, console-anchored ceremony is both safer
  and simpler.
- **An operator passphrase (alone, or as a degraded unlock alongside the quorum).**
  Rejected as seizure-resistance theater: a known passphrase is exactly what
  coercion extracts and re-creates the single seizable human the design removes.
- **Persist the reconstructed VMK in a systemd/kernel keyring across reboots to
  avoid re-ceremony.** Defeats the entire purpose — it puts a usable key where a
  powered-off (or rebooted-then-imaged) seizure recovers it. Rejected outright.
- **Split the station *identity* key and reuse it as the VMK.** Rejected:
  couples disk-unlock to identity exposure and forbids rotating one without the
  other. A separate random VMK, split with the same machinery, is cleaner.
- **Plausible-deniability / hidden-volume schemes (a decoy dataset under a
  second key).** Out of scope and noted as future-not-planned: they defend a
  *running/coerced* operator, which this ADR explicitly does not cover, and add
  large complexity for a threat the member-keyed quorum already addresses by
  removing the single coercible human.

## References

- [ADR-0016 — Station backup and key recovery](0016-station-backup-and-key-recovery.md)
  (the Shamir + sealed-envelope + contribute-shard machinery reused here)
- [ADR-0004 — Own Shamir implementation](0004-own-shamir-implementation.md)
- [ADR-0020 — Single-writer log & DTN submission](0020-single-writer-log-dtn-submission.md)
  (member outboxes for re-bootstrap, Decision point 6)
- [ADR-0013 — Federation transport is Reticulum](0013-federation-transport-reticulum.md),
  [ADR-0026 — Reticulum sidecar ratified](0026-reticulum-sidecar-ratified.md) §7
  (adapter-identity custody assigned to this at-rest scope)
- [ADR-0008 — Mobile↔station transport](0008-mobile-station-transport.md)
  (the authenticated LAN channel — usable only post-unlock)
- Design overview §10.7 (node hardware classes — Pi 4 reference), §10.8
  (physical node seizure)
- Threat model — `rrn-storage` *Information disclosure* / *Residual risk*
  (the "pending ADR-0024" rows this design will close)
- [`rrn-identity::recovery`], [`rrn-identity::wallet`], [`rrn-storage::db`],
  `rrn-station::backup`, `rrn-station::recovery`

[ADR-0016]: 0016-station-backup-and-key-recovery.md
[ADR-0004]: 0004-own-shamir-implementation.md
[ADR-0026]: 0026-reticulum-sidecar-ratified.md
[`rrn-identity::recovery`]: ../../crates/rrn-identity/src/recovery/mod.rs
[`rrn-identity::wallet`]: ../../crates/rrn-identity/src/wallet.rs
[`rrn-storage::db`]: ../../crates/rrn-storage/src/db.rs
