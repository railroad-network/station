# 0028 — A self-custody CLI member wallet: the non-mobile member device, a sealed-channel client with an offline outbox

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
crypto — `rrn paper` — verifies but "never signs and never opens a database," and
the threat model cites that exact property as its elevation-of-privilege
mitigation (`crates/rrn-cli/src/paper.rs` header; `docs/threat-model.md`
paper-module section).

Two things break the "a member is a phone" shorthand.

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
  outbox export (no CLI wallet exists — needs an ADR)." (Those notes also say
  "station-side," which this ADR corrects: the export is *member-side* and needs
  no daemon.)
- `rrn paper` carved out `export-outbox` explicitly: "there is no non-mobile
  member wallet in the system today; that is deferred … behind a new ADR."

So the question is not whether to build a CLI wallet — ADR-0020 already assumed
one — but **what a non-mobile member device is**: who holds its key, where its
outbox lives, how it reads the state it needs to sign correctly, and how its
records reach the station. That is a custody and architecture decision, and
ADR-0006 only ever answered it for the phone.

The forces:

- **Self-sovereign identity is the whole point (ADR-0006).** A member's key must
  live with the member, the station must never hold it, and signing must work
  with no station reachable. The related "no-export-secret" rule — the secret
  seed never leaves the process in the clear — is not stated in ADR-0006 itself;
  it lives in the mobile FFI (`crates/rrn-mobile-ffi/src/lib.rs`: "the secret
  seed never crosses the FFI boundary") and the threat model. Any non-mobile
  wallet must keep all of these.
- **A member device is a client of the station, not just a producer.** ADR-0006's
  model is a device that *pairs once and then authenticates each request by its
  own signature*; ADR-0008 built that as the mobile↔station sealed channel. A
  member device that could only *emit* records but never *read* its own state
  (its next nonce, its outbox head, its balance) is not the ADR-0006 model — it
  is a lesser thing that cannot even sign a correctly-nonced proposal after a
  refusal. The nonce is a gapless per-sender counter checked at the front door
  (`crates/rrn-ledger/src/engine.rs`), and delivery receipts carry per-record
  outcomes only, never the next nonce. So a producer-only wallet locks itself
  out after its first refused proposal.
- **A member may run no station at all, and may be fully partitioned.** The
  deployment is one community, one station, ~20 members. A member without a
  smartphone has a laptop, not a Pi running `station`. Their wallet cannot
  presuppose the operator's Unix socket or a local station database — but it can
  pair with the community station over the LAN like a phone, and fall back to
  paper/DTN/SMS carriers when the station is unreachable.
- **The crypto and wire machinery already exist and are shared.** The
  `{signer, sig, body}` envelope, `rrn_protocol::{outbox,bundle,receipt,paper}`,
  `rrn_ledger::escrow`, `rrn_identity::wallet::{WalletContents, EncryptedWallet}`,
  and the ADR-0008 sealed channel are consumed today by *both* `rrn-mobile-ffi`
  and `rrn-cli`. Almost nothing new is needed. What is missing is a *host* that
  owns a member key and an outbox — the role the phone app plays on mobile.
- **The mobile FFI is stateless on purpose, and that reason does not transfer.**
  `rrn-mobile-ffi` keeps no state and opens no database (ADR-0007): the React
  Native app is the stateful host that persists the encrypted key and feeds the
  last outbox entry back as `prev_entry`. A CLI has no separate app behind it —
  the `rrn` process *is* the host, so the statelessness rationale is absent, and
  a self-managed chain would be a footgun (a dropped or re-created `prev_entry`
  is a self-inflicted outbox fork, i.e. provable self-equivocation under
  ADR-0021 §5, which ADR-0025 §7 punishes by zeroing reputation).
- **The audit posture must hold.** A new key-at-rest surface on a
  general-purpose computer is a real threat-model change and must be stated
  plainly; a laptop is not a phone's Secure Enclave. And the `rrn paper` module's
  "no key, no database" contract must survive — an auditor relies on it.

## Decision

**Introduce a self-custody, non-mobile member wallet — the `rrn wallet` command
family — as a first-class member device that mirrors the mobile wallet's key,
outbox, and station-client model on a general-purpose computer. It holds its own
member key under the member's sole custody (the station never holds it), keeps
its own per-device outbox chain and nonce cursor in its own local store, signs
records offline, and is a second client of the ADR-0008 member-authenticated
sealed channel — pairing once like a mobile, submitting and re-syncing over the
channel when the station is reachable, and falling back to the ADR-0020 paper/DTN/
SMS carriers when it is not. This generalizes ADR-0006 from "the mobile client
holds the keys" to "the member device holds the keys — mobile or CLI"; it changes
no ADR-0006 invariant.**

Concretely:

1. **The CLI wallet is a client-side member device, distinct from the station in
   every way.** It is a new `rrn-cli` module exposing an `rrn wallet …` command
   family, *not* a mode of the daemon and *not* the operator console. It reuses
   `rrn-identity`, `rrn-ledger`, `rrn-protocol`, `rrn-storage`, and `rrn-crypto`
   directly as a native Rust binary — no `uniffi` layer (that shim exists only to
   reach React Native). Like `rrn init`, the `rrn wallet` family runs without an
   operator socket connection. A member who owns only a laptop can run it in
   full. **The wallet never imports from the `paper` module in the reverse
   direction:** `wallet` calls `paper`'s render helpers, `paper` never touches a
   key, a wallet, or SQLite — so paper.rs's "no key, no database" contract, and
   the threat-model mitigation that cites it, stand verbatim.

2. **Key custody is the member's, and the ADR-0006 model carries over — now
   including its client half.** The wallet holds a single member identity as an
   `rrn_identity::wallet::EncryptedWallet` on disk (the existing `.rrnwallet`
   format: one Ed25519 seed sealed with XChaCha20-Poly1305 under an argon2id key
   from the member's passphrase, `ZeroizeOnDrop`, atomic `0600` write). The
   secret is decrypted into memory only for the duration of a signing command,
   is never written in the clear, never leaves the process, and is zeroized on
   drop. The station never receives it. Because the wallet also *pairs* with the
   station (point 5) and authenticates each request by its own signature, the
   full ADR-0006 relationship — one-time pairing, per-request signature auth —
   now genuinely applies to the CLI device, not just the phone; this is the one
   respect in which the earlier "producer-only" framing was incomplete. A member
   key is **not** a station key: the wallet and any station daemon never share a
   file, a passphrase, a passphrase environment variable (the wallet uses a
   distinct variable, or none — never the station's `RRN_PASSPHRASE`), or an
   in-memory keypair. One identity per wallet home; a member runs their key on
   **one** device at a time — the same key on a phone *and* a laptop is two
   outbox chains for one author, i.e. self-equivocation (point 8). A laptop
   wallet is an *alternative* to a phone for an identity, not an addition.

3. **The wallet is a stateful local host — it owns its store.** Unlike
   `rrn-mobile-ffi`, the CLI wallet keeps durable state, because it *is* the
   host: a member-wallet home directory (default under the OS data dir, e.g.
   `~/.local/share/rrn/wallet`, overridable by a documented flag/variable) holds
   the `.rrnwallet` file, a private SQLite database, the paired station's URL and
   **pinned public key**, and a local nonce cursor. The database runs the
   station's migration set and is driven by the existing
   `rrn_storage::outbox::OutboxStore` (`append` with dense-position and
   `prev_hash` chain enforcement, `pending`, `apply_ack`, `prune_acked`). It
   carries a positive **role marker** (a wallet-meta row and/or
   `metadata["role"]="member"` in the `.rrnwallet`), and the wallet refuses to
   operate on a station data directory, and defaults its home outside any
   `--data-dir`, so a stray `rrn wallet init` on the operator's Pi cannot shadow
   or corrupt the station. This local store is **not a cache and not
   re-derivable**: it is the *sole* member-held copy of the outbox chain head and
   of every signed-but-unsubmitted record. It is unsigned local metadata *about*
   signed evidence, but losing it is not free (see points 6 and 7); it therefore
   belongs in the member's backup story, not just the key.

4. **The wallet signs the record set a partitioned member may author, and owns
   the local counters that make those records valid.** Reusing the existing
   signing paths, the wallet can produce: transaction proposals (including
   ADR-0021 certificate-backed spends via
   `TransactionProposal::with_certificate`), confirmations, votes, vouches,
   certificate requests and returns, and dispute openings. Each signed record is
   wrapped verbatim (never re-signed) into the next `SignedOutboxEntry`
   (`rrn_protocol::outbox::OutboxEntry::wrapping`) and appended to the wallet's
   outbox chain at head+1. The wallet maintains a **nonce cursor** locally: it
   advances on each admitted proposal (learned from delivery receipts, which the
   wallet applies anyway) and is re-anchored from the station on resync (point
   6). Timestamps the wallet mints (`proposed_at`, `authored_at`,
   `assembled_at`) are **testimony**, never trusted by the station for window,
   ordering, or eligibility arithmetic (ADR-0022); the wallet must nonetheless
   (a) not future-date beyond the engine's clock-skew tolerance, and (b) for a
   certificate-backed spend, set `expires_at ≥ the certificate's expiry` and, for
   any record bound to a slow carrier, choose an expiry long enough to survive
   delivery (ADR-0021 §4, ADR-0022 §4) — the engine does not enforce these, so
   the wallet must.

5. **Online, the wallet is a sealed-channel client (ADR-0008).** It pairs once
   with the community station over the LAN/TCP sealed channel
   (`crates/rrn-station/src/mobile_server.rs` `/pair` + `/rpc`), exactly as a
   mobile does; pairing is where it **pins the station's public key** (TOFU),
   which every later receipt and certificate verification checks against (point
   6). While reachable it submits through the channel's member-reachable
   `bundle_submit` — **never** a direct `submit_proposal`/`submit_confirmation`
   — so every wallet record passes through the outbox chain and positions stay
   dense (ADR-0020 §2); online and offline then differ only in carrier. It reads
   its own state over the channel's existing member methods (`next_nonce`,
   `balance`, `transactions`, `receipts_fetch`) plus **one new
   member-authenticated read, `outbox_head`**, which returns the station's
   recorded `(position, entry_hash)` for the caller's own author from the
   already-stored `seen_outbox_heads` table. This is a read of existing state,
   member-authorized, with **no new signed-record kind and no CBOR wire-format or
   fixture change** — the only new station surface this ADR adds, and it exists to
   make restore safe (point 7). The operator Unix socket is *not* a member
   submission path.

6. **Receipts close the loop, and only a pinned station may close it.** When a
   station-signed delivery receipt returns — over the channel (`receipts_fetch`)
   or carried back on paper/DTN — the wallet verifies it against the **pinned**
   station key (`rrn_protocol::receipt::decode_signed`), and only then applies
   each per-record outcome to its outbox with `OutboxStore::apply_ack`
   (admitted / already-known / refused-with-reason) and optionally
   `prune_acked`. Verifying self-consistency alone is not enough: an unpinned
   receipt lets an attacker forge "admitted" outcomes, causing the wallet to
   prune records the real station never received — a silently lost payment.
   Certificate verification (ADR-0021 §3) checks the same pinned key.

7. **Resync and restore are explicit, because a producer-only wallet is unsafe.**
   The station remembers every `(author, position)` it has ever seen
   (`seen_outbox_entries`/`seen_outbox_heads`) and treats a different hash at a
   seen position as an outbox fork → equivocation (ADR-0021 §5, ADR-0025 §7). A
   wallet that lost or re-created its store — a dead laptop restored from only the
   `.rrnwallet`, or a key recovered via ADR-0004 social recovery — would restart
   at position 0 and **self-equivocate on its first submission**. Therefore:
   before signing on a fresh-but-existing identity (any wallet whose chain head is
   unknown to it), the wallet **must re-anchor its outbox head and nonce from the
   station** — over the channel (`outbox_head` + `next_nonce`) when reachable, or
   from a station-signed state artifact carried on paper when not — and resume at
   head+1. Restoring the key alone is insufficient; the recommended member backup
   includes the outbox store. A genuinely first-time identity legitimately starts
   at position 0 with an empty station history.

8. **`rrn wallet export` is a local operation.** Because the outbox lives on the
   member's own device, exporting it needs no daemon. The command reads the
   wallet's own pending entries (`OutboxStore::pending`), wraps each into a
   `bundle::EntryEnvelope`, assembles a `bundle::Bundle`, and emits it either as
   raw bundle bytes (for `rrn dtn push --bundle` or file/SMS carriage) or as
   printable QR sheets via the **existing** codec —
   `encode_chunks(PaperKind::Bundle, &bundle.encode())` plus the existing paper
   render helpers. This is the `rrn paper ingest` path run in reverse. **No new
   signed record kind, no new `PaperKind`, and no new CBOR fixture** — the
   station's `bundle_submit` ingest already accepts exactly this. `rrn paper`
   stays verify-only and unchanged; it is the wallet, not paper, that opens a key
   and a database. `export-outbox` under `rrn paper` (the originally-promised
   name) is *not* adopted — it would break the paper module's audit contract, and
   the promised name is stale on the "station-side" axis besides.

9. **Scope: the laptop/desktop self-custody node only.** This ADR covers a
   general-purpose computer on which the member holds their own key. It does
   **not** decide the feature-phone / hub-custody question (design overview §10.7
   Class 3, still open), does not add hardware-wallet support (ADR-0006 left that
   to "Phase 2+"; still deferred), does not support one key on multiple devices
   concurrently, and does not turn the wallet into a station or a second log
   writer. The member-key recovery *command surface* (guardian enrollment and
   reconstruction on the CLI) is left to the implementation ticket; recovery
   restores the key but, per point 7, also requires an outbox-head re-anchor
   before signing — so it is *not* "identical to mobile" until that exists.

## Consequences

- **The Phase-2 offline payment round-trip is unblocked, and correctly.** A
  non-mobile member can sign a proposal offline, export it, have it carried to
  the station, and get a receipt back — and, crucially, can also read the nonce
  and outbox head it needs so its *next* proposal is valid and does not fork.
  The full propose → confirm → settle path becomes exercisable end to end for a
  member who has no smartphone.
- **ADR-0006 is generalized, not superseded, and now truthfully so.** Every
  invariant holds: member self-custody, station-never-holds-key, no-export-secret,
  offline signing, *and* the pairing / per-request-auth client model — because
  the wallet is a sealed-channel client, not a bare producer. ADR-0006 stays
  Accepted; this ADR extends it.
- **One small new station surface, honestly.** The sealed channel gains one
  member-authenticated read, `outbox_head`, over already-stored state — no new
  record kind, no wire-format or fixture change, no new signed payload. Every
  other online interaction reuses existing channel methods. This is the
  narrowest addition that makes restore safe; a strictly carrier-only design
  (see Alternatives) avoided even this at the cost of a heavier station-exported
  artifact and no online-remote-member support.
- **A new key-at-rest surface, on less-hardened hardware.** A member key now
  lives on a laptop/desktop, typically without a phone's Keychain/Keystore or
  Secure Enclave. The mitigation is the same `.rrnwallet` scheme plus the OS's
  own at-rest options (full-disk encryption is the operator's responsibility,
  stated in the runbook). The implementation ticket owes an `rrn-cli`
  member-wallet STRIDE section covering: the member key and outbox DB as assets;
  device theft; malware key-scrape; passphrase exposure via environment/argv/
  shell history/`ps`; the secret in swap or a core dump (no `mlock`); an
  attacker-controlled wallet-home override (`RRN_*`/flag) pointing at a wrong or
  attacker-seeded chain (self-fork); outbox-DB deletion or rollback as a
  self-fork vector; unpinned receipts (mitigated by the point-6 pin); and QR
  export sheets exposing transaction metadata to anyone holding the paper.
  Residual: a general-purpose OS is more exposed than a Secure Enclave; social
  recovery (ADR-0004) is the lost-device story, subject to the point-7 re-anchor.
- **Self-equivocation is a real local footgun, now handled by design rather than
  by hope.** Point 7 (re-anchor before first sign) and point 2 (one key, one
  device) turn the "don't copy your wallet to two machines" caveat from a wish
  into a defined ceremony; single-writer file-locking on the outbox DB and loud
  docs remain the belt-and-braces. It cannot be made impossible — a determined
  member can copy files and sign in parallel — and that residual is a
  threat-model entry, but the honest paths (restore, recovery) no longer lead
  straight into an equivocation record.
- **Minimal wire/fixture churn.** Reusing `PaperKind::Bundle` and the existing
  outbox/bundle/receipt formats means the mobile repo's cross-platform fixtures
  are untouched and the ingest side needs no change; the only code the station
  gains is one read handler.
- **A modest new maintenance surface and several doc corrections.** The
  implementation ticket must, in the same PR: keep paper.rs's contract but
  replace its deferral note with a pointer to `rrn wallet`; correct the
  `rrn-cli` crate description and `main.rs` header (the "every subcommand is one
  RPC / holds no key / opens no database" claims are now scoped to the operator
  and the `paper` module, with `wallet` named as the member device); point
  `rrn init`'s message at `rrn wallet init` for members; rewrite the LoRa runbook
  and `field-test-lora.sh` steps to `rrn wallet export --format bundle` then
  `rrn dtn push --bundle`; and append dated "resolved by ADR-0028" notes to the
  exit-evidence and overview snapshots and the threat-model limitation. The
  payoff is that members without smartphones are first-class, which the pilot's
  inclusivity and resilience goals require.
- **Follow-up is a ticket, not another ADR.** With this decision ratified, the
  implementation ticket builds it: the `rrn wallet` surface (init, pair, the
  signing verbs, export, submit, receipts, sync, status), the wallet-home layout
  and role marker, the `outbox_head` channel read, the resync/restore ceremony,
  and the threat-model section. No further locked decision is needed unless
  implementation surfaces a custody question this ADR did not answer.

## Alternatives Considered

- **A producer-only wallet with no read path (carriers only, no channel).** The
  first framing of this ADR. Rejected: the nonce is a gapless front-door counter
  and receipts never carry it, so a producer-only wallet locks itself out after
  its first refused proposal; and a lost/restored store self-equivocates with no
  way to learn its head. Recovering those needs either the ADR-0008 channel
  (chosen) or a new station-exported signed state artifact carried on paper —
  which is a *larger* new surface than the single `outbox_head` read, and still
  cannot serve an online-remote member. Carriers remain the offline fallback,
  not the only path.
- **Colocate the CLI wallet inside the station daemon; export via an RPC.** The
  reading hinted at by `status.pending_outbox` reading the station's own DB.
  Rejected: it conflates a member identity with the station host (the operator's
  key would double as a member key, eroding ADR-0006's separation), serves only
  members who run a station — precisely not the target user — and is
  unnecessary, because the station never needs an outbox for its *own* records
  (as the sole writer they self-admit at the front door).
- **Put export under `rrn paper` (`rrn paper export-outbox`), or add a shim
  alias.** Rejected: the export command opens a key and a database, which breaks
  paper.rs's "no key, no SQLite" contract that the threat model cites as its
  elevation-of-privilege mitigation; clap has no cross-group alias, so a shim
  would have to be a `PaperCmd` variant calling wallet code — the exact boundary
  bleed to avoid; and the promised name is conceptually stale ("station-side").
  Discoverability is preserved by a one-line pointer in the `paper` group help
  and in `rrn init`'s output, with zero code coupling.
- **Stateless-over-files, mirroring `rrn-mobile-ffi` exactly.** Rejected: the FFI
  is stateless because the phone app is the stateful host; on the CLI there is no
  such app, so this pushes chain and nonce bookkeeping onto the human, where a
  dropped or reused `prev_entry` becomes a self-inflicted outbox fork. A small
  local store owned by the wallet is the correct host role and reuses
  `OutboxStore` unchanged.
- **No CLI wallet; require every member to own a smartphone.** Rejected: it
  excludes members without smartphones (against the project's inclusivity and
  resilience goals and the overview's own Class-2 laptop node) and leaves the
  Phase-2 exit criterion's offline round-trip unexercisable for them.
- **Reach the existing member crypto through a `uniffi` shim from the CLI.**
  Rejected: `rrn-mobile-ffi` is shaped for React Native (opaque handles, byte
  APIs, no storage). A native CLI sits directly on the underlying crates with
  less indirection and no FFI surface to maintain for a same-language caller.
- **Invent a new "outbox export" wire format / `PaperKind`.** Rejected as
  needless: an outbox serializes to a `bundle::Bundle`, `PaperKind::Bundle`
  already carries one, and the station already ingests it.

## References

- [ADR-0006](0006-m1-client-architecture.md) — the key-holder decision this
  generalizes; its invariants (self-custody, station-never-holds-key, offline
  signing) and its pairing / per-request-auth client model are preserved
- [ADR-0007](0007-rust-mobile-ffi-uniffi.md) — why the mobile FFI is stateless
  (the rationale that does not transfer to a CLI host); the no-export-secret rule
- [ADR-0008](0008-mobile-station-transport.md) — the member-authenticated sealed
  channel the CLI wallet now also uses (pair once, per-request signature auth)
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — §2 names the "CLI
  wallet" outbox producer this builds; bundles, receipts, `bundle_submit`
  ingest, arrival-order admission
- [ADR-0021](0021-escrowed-offline-spending-certificates.md) — certificate-backed
  offline spends the wallet authors; the `expires_at` obligation; outbox-fork
  equivocation (§5)
- [ADR-0022](0022-admission-clock-time-trust.md) — party timestamps are
  testimony; the wallet's clock obligations
- [ADR-0025](0025-equivocation-dispute-cases.md) — the reputation consequence a
  self-equivocation would trigger, which point 7 exists to avoid
- [ADR-0004](0004-own-shamir-implementation.md) — social recovery, the
  lost-device story for a member key (subject to the point-7 head re-anchor)
- Design overview §10.7 (Class-2 "smartphone or low-power laptop"; the Class-3
  "needs a custody decision in a new ADR" precedent), §10.3 degradation ladder
- `crates/rrn-identity/src/wallet.rs` (`EncryptedWallet`, `WalletContents`),
  `crates/rrn-storage/src/outbox.rs` (`OutboxStore`) and
  `migrations/0005_outbox_entries.sql` (the anticipated CLI-wallet writer),
  `crates/rrn-storage/migrations/0006_dtn_station_state.sql` (`seen_outbox_heads`,
  the restore re-anchor source), `crates/rrn-protocol/src/{outbox,bundle,receipt,
  paper}.rs`, `crates/rrn-station/src/mobile_server.rs` (the sealed channel),
  `crates/rrn-cli/src/paper.rs` (the verify-only contract this preserves)
- `docs/threat-model.md`, `docs/phase-2-exit-evidence.md`,
  `docs/lora-radio-bringup.md`, `docs/design/Railroad-Network-Overview.md` — the
  recorded "no CLI wallet — needs an ADR" blockers this closes
