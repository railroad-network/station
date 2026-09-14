# 0028 — A self-custody CLI member wallet: the non-mobile member device and its outbox export

## Status

Proposed

Date: 2026-09-14

## Context

ADR-0006 fixed where a member's key lives: **the mobile client is the
authoritative key-holder, and the station never sees a secret key.** That
decision was made in Phase 1, when the only two pieces of software were the
`station` daemon and the React Native mobile client, and it encoded an
assumption in its own title — "the *mobile* client holds the keys." Everywhere
since, the shorthand hardened into "a member is a phone." The `rrn` CLI grew up
as the operator's station console: a thin pass-through that maps each subcommand
to one daemon RPC, holds no key, and signs nothing (`crates/rrn-cli/src/main.rs`
header; `rrn whoami` prints the *station's* address, `rrn pay`/`rrn confirm`
sign server-side with the station identity). The one CLI family that does local
crypto — `rrn paper` — verifies but "never signs and never opens a database"
(`crates/rrn-cli/src/paper.rs`).

Two things break that shorthand.

**The design always contemplated a non-phone member device.** The node-class
table (design overview §10.7) lists **Class 2 — "Smartphone *or low-power
laptop*. Holds personal wallet and identity."** The laptop half was never built.
The recent Class-3 note (2026-09-13) made the pattern explicit for the
feature-phone case: a device that is not a smartphone "needs a custody decision
in a new ADR." The laptop is the same shape of gap — a member with a computer
but no smartphone has no way to hold a key and transact in this system today.

**Phase 2's own deliverables are blocked on it.** ADR-0020 built delay-tolerant
submission: members sign records offline, wrap them in a per-device **outbox
chain**, and carry them to the station in bundles over LoRa/SMS/paper. ADR-0020
§2 names the two producers verbatim — "every signing device (**mobile wallet,
CLI wallet**) maintains its own append-only, hash-chained outbox." The mobile
wallet shipped with the mobile-FFI DTN work. The CLI wallet did not, and its
absence is load-bearing:

- `rrn_storage::outbox::OutboxStore::append` is **never called** anywhere in
  station code — there is no outbox *producer* in the system; `status`'s
  `pending_outbox` always reads 0.
- The LoRa radio bring-up could only be scoped to station-originated
  bundle-push; the phase-2 exit evidence, the LoRa runbook, the overview, and
  the threat model all record the same blocker in the same words: "a full
  propose → confirm → settle round-trip over radio waits on a station-side
  outbox export (no CLI wallet exists — needs an ADR)."
- `rrn paper` carved out `export-outbox` explicitly: "there is no non-mobile
  member wallet in the system today; that is deferred … behind a new ADR."

So the question is not whether to build a CLI wallet — ADR-0020 already assumed
one — but **what a non-mobile member device is**: who holds its key, where its
outbox lives, and how its records reach the station. That is a custody and
architecture decision, and ADR-0006 only ever answered it for the phone.

The forces:

- **Self-sovereign identity is the whole point (ADR-0006).** A member's key must
  live with the member, the station must never hold it, the secret must never
  leave the process in the clear (the "no-export-secret" rule), and signing must
  work with no station reachable. Any non-mobile wallet must keep all four.
- **A member may run no station at all.** The deployment is one community, one
  station, ~20 members. A member without a smartphone has a laptop, not a Pi
  running `station`. Their wallet cannot presuppose a local daemon, a local
  station database, or an operator socket.
- **The crypto and wire machinery already exist and are shared.** The
  `{signer, sig, body}` envelope, `rrn_protocol::{outbox,bundle,receipt}`,
  `rrn_ledger::escrow`, and `rrn_identity::wallet::{WalletContents,
  EncryptedWallet}` are consumed today by *both* `rrn-mobile-ffi` and
  `rrn-cli/src/paper.rs`. Nothing cryptographic is missing. What is missing is a
  *host* that owns a member key and an outbox — the role the phone app plays on
  mobile.
- **The mobile FFI is stateless on purpose, and that reason does not transfer.**
  `rrn-mobile-ffi` keeps no state and opens no database (ADR-0007): the React
  Native app is the stateful host that persists the encrypted key in the OS
  keychain and feeds the last outbox entry back as `prev_entry`. A CLI has no
  separate app behind it — the `rrn` process *is* the host, so the statelessness
  rationale is absent and a self-managed chain would be a footgun (a dropped
  `prev_entry` is a self-inflicted outbox fork, i.e. provable self-equivocation
  under ADR-0021 §5).
- **The audit posture must hold.** A new key-at-rest surface on a
  general-purpose computer is a real threat-model change and must be stated
  plainly; a laptop is not a phone's Secure Enclave.

## Decision

**Introduce a self-custody, non-mobile member wallet — the `rrn` CLI wallet —
as a first-class member device that mirrors the mobile wallet's key and outbox
model on a general-purpose computer. It holds its own member key under the
member's sole custody (the station never holds it), maintains its own
per-device outbox chain in its own local store, signs records offline, and
exports pending outbox entries as ADR-0020 bundles onto the existing paper/DTN
carriers. This generalizes ADR-0006 from "the mobile client holds the keys" to
"the member device holds the keys — mobile or CLI"; it does not change any
ADR-0006 invariant.**

Concretely:

1. **The CLI wallet is a client-side member device, distinct from the station in
   every way.** It is a new `rrn-cli` module (a `rrn wallet …` / `rrn paper
   export-outbox` surface), *not* a mode of the daemon and *not* the operator
   console. It reuses `rrn-identity`, `rrn-ledger`, `rrn-protocol`, and
   `rrn-crypto` directly as a native Rust binary — no `uniffi` layer (that shim
   exists only to reach React Native). It requires no running `station`, no
   operator Unix socket, and no station database. A member who owns only a
   laptop can run it in full.

2. **Key custody is the member's, and the ADR-0006 invariants are preserved
   verbatim.** The wallet holds a single member identity as an
   `rrn_identity::wallet::EncryptedWallet` on disk (the existing `.rrnwallet`
   format: one Ed25519 seed sealed with XChaCha20-Poly1305 under an argon2id key
   from the member's passphrase). The secret is decrypted into memory only for
   the duration of a signing command, is never written in the clear, never
   leaves the process, and is zeroized on drop (the type already is
   `ZeroizeOnDrop`). The station never receives it. The wallet key is a
   **member** identity and MUST be strictly separate from any station daemon key
   (`Core.wallet`): the two never share a file, a passphrase prompt, or an
   in-memory keypair, and the wallet refuses to operate on a station's data
   directory. Running your wallet is not running a station, and vice versa.

3. **The wallet is a stateful local host — it owns its outbox store.** Unlike
   `rrn-mobile-ffi`, the CLI wallet keeps durable state, because it *is* the
   host: a member-wallet home directory (default under the OS data dir, e.g.
   `~/.local/share/rrn/wallet`, overridable) holds the `.rrnwallet` file and a
   private SQLite database opened by the wallet itself. That database runs the
   existing `0005_outbox_entries` migration and is driven by the existing
   `rrn_storage::outbox::OutboxStore` (`append` with dense-position and
   `prev_hash` chain enforcement, `pending`, `apply_ack`, `prune_acked`). This
   is the store the migration comment already anticipated ("the CLI wallet …
   write here"). It is a **local, member-owned** database — never the station's,
   and it is not authoritative state: it is a carriage-and-evidence structure
   (ADR-0020 §2), re-derivable from the entries it carries.

4. **The wallet signs the same record set a partitioned member may author.**
   Reusing the existing signing paths, the wallet can produce: transaction
   proposals (including ADR-0021 certificate-backed spends via
   `TransactionProposal::with_certificate`), confirmations, votes, vouches,
   certificate requests and returns, and dispute openings. Each signed record is
   wrapped verbatim (never re-signed) into the next `SignedOutboxEntry`
   (`rrn_protocol::outbox::OutboxEntry::wrapping`) and appended to the wallet's
   outbox chain. Offline verification of a received cert-backed spend
   (ADR-0021 §3) is the same local-verify path `rrn paper`/`offline_spend_verify`
   already provide.

5. **`export-outbox` is a local operation, not a station RPC.** Because the
   outbox lives on the member's own device, exporting it needs no daemon. The
   command reads the wallet's own pending entries (`OutboxStore::pending`), wraps
   each row's opaque envelope into a `bundle::EntryEnvelope`, assembles a
   `bundle::Bundle`, and emits it either as raw bundle bytes (for `rrn dtn push`
   or file carriage) or as printable QR sheets via the **existing** codec —
   `encode_chunks(PaperKind::Bundle, &bundle.encode())` plus the existing
   `write_lines_and_render` sheet helpers. This is the `rrn paper ingest` path
   run in reverse. **No new signed record kind, no new `PaperKind`/wire format,
   and no new CBOR fixture are introduced** — `PaperKind::Bundle` already carries
   exactly this, and the station's `bundle_submit` ingest already accepts it, so
   the round trip closes with zero protocol change.

6. **Receipts close the loop back into the wallet.** When a station-signed
   delivery receipt returns (carried back by paper/DTN, verified against the
   station's public key with the existing `receipt::decode_signed` /
   `receipt_parse` path), the wallet applies each per-record outcome to its own
   outbox with `OutboxStore::apply_ack` (admitted / already-known / refused-with-
   reason) and may `prune_acked`. A member sees, on their own device, which of
   their carried records the station admitted and which it refused and why. The
   refused-with-reason set is exactly the ADR-0020 `RefusalReason` taxonomy.

7. **Submission uses the carriers that already exist; no new station surface is
   added for it.** An exported bundle reaches the station the same ways a mobile
   bundle does: physically as QR via `rrn paper ingest`, over Reticulum/LoRa via
   `rrn dtn push`, or over SMS. The station admits the carried records through
   its single front door in arrival order (ADR-0020 §4); certificate-backed
   spends take the ADR-0021 carve-out; everything else is floor/tier/nonce/expiry
   checked exactly as a live submission. The CLI wallet is a courier's payload
   source, never a second writer.

8. **Scope: the laptop/desktop self-custody node only.** This ADR covers a
   general-purpose computer on which the member holds their own key. It does
   **not** decide the feature-phone / hub-custody question (design overview §10.7
   Class 3, still open per its 2026-09-13 note), does not add hardware-wallet
   support (ADR-0006 left that to "Phase 2+ as an optional enhancement"; still
   deferred), and does not turn the wallet into a station or a second log writer.

## Consequences

- **The Phase-2 offline payment round-trip is unblocked.** A non-mobile member
  can now sign a proposal offline, export it, have it carried to the station,
  and get a receipt back — the missing producer that the LoRa bring-up, the
  exit evidence, and the overview all pointed at. The full propose → confirm
  → settle-over-radio path becomes exercisable end to end.
- **ADR-0006 is generalized, not superseded.** Every invariant holds: member
  self-custody, station never holds a member key, no-export-secret, offline
  signing. The only thing that changes is that "member device" now has two
  concrete forms. ADR-0006 stays Accepted; this ADR extends it.
- **A new key-at-rest surface, on less-hardened hardware.** A member key now
  lives on a laptop/desktop, which typically lacks a phone's Keychain/Keystore
  or Secure Enclave. The mitigation is the same `.rrnwallet` scheme (argon2id +
  XChaCha20-Poly1305, `0600`, atomic write) plus the OS's own at-rest options
  (full-disk encryption is the operator's responsibility, stated in the runbook).
  The residual — a laptop is more exposed than a Secure Enclave — is a
  threat-model addition this ADR's ticket must write (`rrn-cli` /
  member-wallet STRIDE section: assets = member key + outbox DB; threats =
  device theft, malware key-scrape, passphrase capture; mitigations as above;
  residual = general-purpose-OS exposure, and social recovery via ADR-0004 as
  the lost-device story, identical to mobile).
- **Self-equivocation is now a local footgun to guard against.** Because the
  wallet owns its outbox chain, copying the wallet directory to two machines and
  signing on both produces two entries at one position — a provable outbox fork
  (ADR-0021 §5), i.e. the member equivocates against themselves. The wallet must
  make this hard (single-writer file locking on the outbox DB, a loud warning in
  docs); it cannot make it impossible (a determined member can copy files). This
  is the desktop analogue of the mobile "don't restore your wallet onto two
  phones" caveat and belongs in the threat model.
- **No wire or fixture churn.** Reusing `PaperKind::Bundle` and the existing
  outbox/bundle/receipt formats means the mobile repo's cross-platform fixtures
  are untouched and the ingest side needs no change — a deliberately small
  blast radius for a member-facing feature.
- **The store is a cache, consistent with the log-is-truth rule.** The wallet's
  outbox DB is local, member-owned, unsigned metadata *about* signed entries;
  the entries inside are the signed evidence. Tampering with the DB can only
  break the chain, which is detected at ingest (position gap / hash mismatch) and
  is attributable — it cannot forge an admission.
- **A modest new maintenance surface.** A second stateful key-holder in the
  codebase (after the station daemon) means passphrase UX, wallet-home
  discovery, and file-locking to get right; the payoff is that members without
  smartphones are first-class, which the pilot's inclusivity goals require.
- **Follow-up is a ticket, not another ADR.** With this decision ratified, the
  implementation ticket builds it: the `rrn wallet`/`rrn paper export-outbox`
  surface, the wallet-home layout, the receipt-ack loop, and the threat-model
  section. No
  further locked decision is needed unless implementation surfaces a custody
  question this ADR did not answer.

## Alternatives Considered

- **Colocate the CLI wallet inside the station daemon; export via an RPC.** The
  reading hinted at by `status.pending_outbox` reading the station's own DB and
  by `cmd_export_receipts`'s RPC shape. Rejected: it conflates a member identity
  with the station host (the operator's key would double as a member key,
  eroding ADR-0006's separation), it serves only members who run a station —
  precisely not the target user, a member with a laptop and no Pi — and it is
  unnecessary, because the station never needs an outbox for its *own* records
  (as the sole writer, they self-admit at the front door; the outbox exists only
  for records that cannot reach the station promptly).
- **Stateless-over-files, mirroring `rrn-mobile-ffi` exactly (no local DB; the
  user hands `prev_entry` in and persists bytes out).** Rejected: the FFI is
  stateless because the phone app is the stateful host; on the CLI there is no
  such app, so this pushes chain bookkeeping onto the human, where a dropped or
  reused `prev_entry` becomes a self-inflicted outbox fork (provable
  equivocation). A small local store owned by the wallet is the correct host
  role and reuses `OutboxStore` unchanged.
- **No CLI wallet; require every member to own a smartphone.** Rejected: it
  excludes members without smartphones (against the project's inclusivity and
  resilience goals and the overview's own Class-2 laptop node), and it leaves the
  Phase-2 exit criterion's offline round-trip unexercisable for non-phone
  members.
- **Reach the existing member crypto through a `uniffi` shim from the CLI.**
  Rejected: `rrn-mobile-ffi` is shaped for React Native (opaque handles, byte
  APIs, no storage). A native CLI sits directly on `rrn-identity`/`rrn-ledger`/
  `rrn-protocol` with less indirection and no FFI surface to maintain for a
  same-language caller.
- **Invent a new "outbox export" wire format / `PaperKind`.** Rejected as
  needless: an outbox serializes to a `bundle::Bundle`, `PaperKind::Bundle`
  already carries one, and the station already ingests it. A new format would add
  fixtures, discriminators, and mobile-repo churn for no capability.

## References

- [ADR-0006](0006-m1-client-architecture.md) — the key-holder decision this
  generalizes; its four invariants (self-custody, station-never-holds-key,
  no-export-secret, offline signing) are preserved
- [ADR-0007](0007-rust-mobile-ffi-uniffi.md) — why the mobile FFI is stateless
  (the rationale that does not transfer to a CLI host)
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — §2 names the "CLI
  wallet" outbox producer this builds; bundles, receipts, arrival-order admission
- [ADR-0021](0021-escrowed-offline-spending-certificates.md) — certificate-backed
  offline spends the wallet can author; outbox-fork equivocation (§5)
- [ADR-0004](0004-own-shamir-implementation.md) — social recovery, the
  lost-device story for a member key, identical to mobile
- Design overview §10.7 (Class-2 "smartphone or low-power laptop"; the Class-3
  "needs a custody decision in a new ADR" precedent), §10.3 degradation ladder
- `crates/rrn-identity/src/wallet.rs` (`EncryptedWallet`, `WalletContents`),
  `crates/rrn-storage/src/outbox.rs` (`OutboxStore`) and
  `migrations/0005_outbox_entries.sql` (the anticipated CLI-wallet writer),
  `crates/rrn-protocol/src/{outbox,bundle,receipt,paper}.rs`,
  `crates/rrn-cli/src/paper.rs` (the export/ingest surface and the deferral note)
- `docs/threat-model.md`, `docs/phase-2-exit-evidence.md`,
  `docs/lora-radio-bringup.md` — the recorded "no CLI wallet — needs an ADR"
  blockers this closes
