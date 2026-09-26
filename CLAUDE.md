# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Railroad Network** is a federated platform for self-organizing communities: a mutual-credit
economy denominated in a single unit (the "Common"), decentralized identity with social
vouching and Shamir-based social recovery, a tiered oracle/dispute system, and a federation
protocol between communities — designed to degrade gracefully from full internet down to
local mesh, LoRa radio, and paper fallback.

This repo, **`station`**, is the canonical Rust implementation: a Cargo workspace of crates
that produce the `station` daemon binary and the `rrn` CLI binary. The React Native mobile
client lives in the sibling repo `../mobile` (TypeScript UI over this workspace's
`rrn-mobile-ffi` bindings, per ADR-0006/0007); cross-repo work (FFI surface, wire fixtures)
touches both.

## Current status: Phase 2 complete on simulation evidence; pilot and audit pending

Phase 0 (crypto core, storage/log, identity, ledger, daemon+CLI), Phase 1 (mobile
transport, vouching, reputation, marketplace, oracle tiers 1–2, governance, disputes,
pilot readiness), and **Phase 2 — Single-Community Resilience** have all landed. Phase 2
closed 2026-09-13 by the ADR-0017 criterion (`docs/phase-2-exit-evidence.md`): admission
clock (ADR-0022), single-writer log + delay-tolerant submission (ADR-0020), headroom
certificates + provable equivocation (ADR-0021/0025), paper fallback and the `rrn paper`
courier tools, the `rrn wallet` self-custody CLI member wallet (ADR-0028), Reticulum/LoRa
sidecar and transport (ADR-0013/0026), SMS codec + relay against a mock gateway,
emergency governance (ADR-0023/0027), the encrypted at-rest profile (ADR-0024), the
writer/replica role split, the 72-hour outage simulation, and — after the consolidation —
member key recovery on member devices (ADR-0016 Clarification; mobile PR too).

Still open, and the docs must say so:
- the 90-day community pilot and the independent professional audit (the gates to real value);
- two human-gated hardware follow-ups: the SMS modem gateway (not built) and the LoRa
  field-acceptance sign-off at real range (radios bench-verified 2026-09-11);
- **the phone app is online-only for signing** — the offline outbox, certificates, and
  paper export exist in `rrn-mobile-ffi` and ship in `rrn wallet`, but the mobile app has
  no screens for them. Do not describe the app as having an outbox.
- Phase 3 (federation) is not started.

**Phase numbering hazard (ADR-0017):** documents written before 2026-08-25 use the old
numbering ("Phase 2" = federation). Now: Phase 2 = single-community resilience, Phase 3 =
multi-community federation. ADRs 0001–0016 and the 2026-08 audit keep the old numbering as
written; the threat model, design overview, and docs site use the new one.

An internal AI-assisted security review is done (`docs/security/audit-2026-08.md`, no
High-severity findings) and the Phase 2 surface has a red-team checklist
(`docs/security/phase-2-redteam.md`); the independent professional audit is still
pending. **Do not use with real value.**

**The docs site.** The human-facing documentation is an mdBook in the sibling repo
`../railroad-network.github.io`, live at https://railroad-network.github.io, split by
audience (members / organizers / operators / reference). Its `rrn`/`station` command
pages and ADR index are generated from this checkout by `scripts/gen-reference.sh` there;
re-run it after a CLI help-string or ADR change. When the site and an ADR disagree, the
ADR wins and the site has a bug. Keep the three repos' status claims consistent.

## Planning documents and work tickets

The design overview is in-repo at `docs/design/Railroad-Network-Overview.md`; locked
decisions live in `docs/adr/`. Historical phase plans and per-task specs for Phases 0–1
(now complete) are retained in the maintainer's local planning workspace and are not
distributed with the code. Active development tickets, when present, live in the
gitignored `.tickets/` directory — read its `PROCESS.md` before starting any ticket.

**How to work from any spec or ticket:**
- Do tasks in dependency order; verify against the stated **Acceptance** criteria/commands
  before considering one done.
- Respect **Out of scope** — don't expand a task to cover adjacent work; another task covers it.
- If a spec is wrong or missing information, **stop and surface the question** rather than
  guessing — specs encode locked design decisions.
- Specs predate implementation and have repeatedly proven stale on dependency versions and
  API sketches (e.g. `Settler::new` without a keypair — see ADR-0005). Verify crate versions
  and existing in-repo APIs before coding from a spec; where spec and ADR conflict, the ADR
  wins.

## Repository structure (as built)

```
station/
├── Cargo.toml                  # workspace root, resolver = "2"
├── docs/
│   ├── design/                 # design overview (canonical, updated in place with dated notes)
│   ├── adr/                    # ADRs 0001–0037, MADR format — the locked-decision record
│   ├── threat-model.md         # living STRIDE document, grown per milestone
│   ├── security/               # audit-2026-08.md, phase-2-redteam.md
│   ├── spec/                   # wire formats: qr-payloads, dtn-bundles, sms-carrier, vmk-boot-ceremony
│   ├── community-setup.md      # operator runbook (Parts 1–6 + command appendix)
│   ├── background-reliability.md   # phones syncing when the app is closed, per vendor
│   ├── lora-radio-bringup.md   # RNode LoRa radio from unflashed hardware to station traffic
│   └── phase-2-exit-evidence.md    # the 72h simulation + the Phase 2 exit statement
├── crates/
│   ├── rrn-crypto/             # ed25519, blake3, canonical CBOR, SignedPayload — audit boundary, no rrn-* deps
│   ├── rrn-storage/            # SQLite, CRDTs (PN-Counter/OR-Set/LWW-Register), hash-chained signed log, replay
│   ├── rrn-identity/           # wallet, addresses, vouching, sealed envelopes, Shamir recovery
│   ├── rrn-ledger/             # tx state machine, settlement, tiers, credit (debt floor), escrow certs (ADR-0021), disputes (records), contracts
│   ├── rrn-reputation/         # ADR-0009 universal scoring (single-replay ScoringContext), staking gates, sybil velocity, portability
│   ├── rrn-governance/         # ADR-0012 charter, proposals, statutes, votes, tally; emergency mode (ADR-0023/0027)
│   ├── rrn-dispute/            # ADR-0014 sortition, panels, verdicts, escalation; equivocation cases (ADR-0025)
│   ├── rrn-marketplace/        # ADR-0010 listings, needs, inquiries, contracts, search
│   ├── rrn-protocol/           # ADR-0020 outbox chains, bundles, receipts, framing, airtime budget, paper codecs, net bindings
│   ├── rrn-mobile-ffi/         # uniffi surface for the mobile repo: crypto/identity + DTN/bundles/certs + recovery ceremony
│   ├── rrn-station/            # `station` daemon: core, RPC, mobile server, DTN loop, Reticulum sidecar, SMS relay, backup/recovery, at-rest encryption
│   └── rrn-cli/                # `rrn` binary: operator console, `rrn paper` courier tools, `rrn wallet` member wallet (ADR-0028)
├── tests/                      # cross-crate integration tests
├── fuzz/                       # cargo-fuzz targets (own nightly workspace)
└── scripts/                    # demos (phase-0, phase-2-{paper,wallet,outage}), drill-seizure-recovery, field-test-lora, test-{deep,timings}, target-hygiene, install-hooks
```

Layered dependencies: `rrn-crypto` → `rrn-storage` → `rrn-identity` → `rrn-ledger` →
{`rrn-reputation`, `rrn-governance`, `rrn-marketplace`} → `rrn-dispute` → `rrn-station` /
`rrn-cli`. `rrn-crypto` must never depend on other `rrn-*` crates — it's the audit boundary.

## Locked technical decisions

The authoritative record is `docs/adr/` (0001–0037, append-only). Don't deviate without a
new ADR. Core library choices:

| Concern | Choice |
|---|---|
| ed25519 | `ed25519-dalek` v2 (`verify_strict`) |
| Hashing | `blake3` |
| Canonical serialization | `dcbor` (Deterministic CBOR, RFC 8949 §4.2.1) — ADR-0002 |
| Address format | bech32m, HRP `rrn` (`rrn1...`) — ADR-0003 |
| Symmetric crypto | `chacha20poly1305` (XChaCha20-Poly1305, 24-byte nonces) |
| Key derivation | `argon2` (argon2id) |
| SQLite | `rusqlite` with `bundled`, WAL mode, `foreign_keys = ON`, STRICT tables |
| Shamir secret sharing | own implementation over GF(256) in `rrn-identity/src/recovery/` — ADR-0004 |
| Async runtime | `tokio`, only where needed (daemon/IPC) |
| Property tests | `proptest` |
| Errors | `thiserror` in library crates, `anyhow` in binary crates |
| Logging | `tracing` + `tracing-subscriber` |
| License | Apache-2.0 OR MIT (dual) |

Key protocol-level decisions (see the ADR for the full rule):
- **Reputation** is one locked formula, derived from the log, never stored authoritatively;
  snapshot tables are caches (ADR-0009).
- **Oracle tiers**: Phase 1 serves Tiers 1–2 only; a Tier-3+ amount (≥ 50 Commons) is
  *blocked*, never clamped; the Tier-2 stake is a derived eligibility gate (ADR-0011).
- **Disputes**: deterministic standing-weighted sortition, three jurors, bounded windows,
  every path fails open to the confirmed status quo (ADR-0014).
- **Bootstrap grace**: founders ∪ established members govern/judge while fewer than 3
  members are established; ends automatically (ADR-0015).
- **Debt floor**: the engine refuses a debit committing its signer below −20 Commons
  (default; `[credit] debt_floor_centi`), counting settled balance plus pending signed
  debits (ADR-0018).
- **Federation/collapse transport**: Reticulum as a supervised, version-pinned `rnsd`
  sidecar driven through a Python LXMF adapter, strictly a dumb carrier — never the
  identity, integrity, or encryption boundary (ADR-0013, ADR-0026).
- **One log, one writer** (ADR-0020): resilience is delay-tolerant *submission* (outbox
  chains → bundles → station-signed receipts), never a second writer or a CRDT merge of
  logs. A station is a `writer` (never pulls) or a `replica` (pulls, never admits).
- **Admission clock** (ADR-0022): the station's clock at admission and the log position are
  the only inputs to any window, deadline, ordering, or electorate; party-asserted
  timestamps are testimony. Governance and dispute electorates are position-bounded.
- **Offline spending** (ADR-0021, ADR-0025): headroom certificates reserve debt-floor
  headroom ahead of a partition; a certificate-backed spend skips the fresh floor check;
  an overspend or a conflicting outbox entry is recorded as provable equivocation, zeroes
  both reputation dimensions, and opens a distinct jury case kind.
- **Emergency governance** (ADR-0023, ADR-0027): activates at the first crossing of
  ceil(2N/3) electorate co-signatures, compresses only the emergency-proposal window (24h
  floor), freezes both charter doors, pins the electorate, enforces measure expiry; a
  part-signed declaration expires after 7 days.
- **Encrypted at rest** (ADR-0024, Linux, opt-in): member-keyed LUKS2 container, VMK
  Shamir-split via ADR-0016 machinery, wallet-free boot ceremony with a console fingerprint.
- **Station-signer pinning**: station-signed governance attestations and ledger records
  are pinned to the community station key on replay (skip, never halt). Consequence: a
  replica's derived balances/governance views are empty by design.
- **Member devices** (ADR-0006, ADR-0028): the phone and the `rrn wallet` CLI are the only
  key holders; the station never custodies a member key. Member key recovery runs the
  requester-side ceremony on the member's device (ADR-0016 Clarification).
- The station signs settlement/cancellation records; charters chain amendments via
  `previous_hash` lineage (ADR-0005, ADR-0012).

Amounts are always integer **centicommons** (1 Common = 100 centicommons) — never floats,
anywhere in a signed payload.

## Development commands

```sh
cargo build --workspace
cargo nextest run --workspace   # preferred: overlaps binaries, per-test times, slow warnings
cargo test --workspace          # still works; also runs doc-tests (nextest does not)
cargo test --workspace --doc    # doc-tests only (run alongside a nextest run)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo deny check          # license/advisory/bans/sources
cargo audit                # known CVEs

# single crate / single integration test
cargo test -p rrn-crypto
# each crate compiles its integration tests into one `it` binary; the former
# file name is the module (and a name filter): `--test it <module>`
cargo test --test it lifecycle -p rrn-ledger

# per-test timing (per-binary totals + slowest tests); libtest mode is the
# nextest-free path for when nextest's --list stalls (see hygiene note below)
scripts/test-timings.sh nextest
scripts/test-timings.sh libtest -p rrn-crypto

# deep property-test lane: every proptest at 1024 cases (PROPTEST_CASES
# overrides the fast per-test defaults). Slow by design — release/schedule only.
scripts/test-deep.sh

# fuzz targets (nightly toolchain, own workspace under fuzz/)
cargo +nightly fuzz run verify_signature

# end-to-end demos (all real binaries; safe to re-run)
./scripts/demo-phase-0.sh          # writer + replica converge
./scripts/demo-phase-2-paper.sh    # offline confirm → QR sheets → ingest → receipt back
./scripts/demo-phase-2-wallet.sh   # the rrn wallet laptop member, offline and online
./scripts/demo-phase-2-outage.sh   # the 72-hour outage simulation, narrated
./scripts/drill-seizure-recovery.sh --profile plaintext|encrypted
```

Install nextest once with `cargo install cargo-nextest --locked`.

**Build profiles.** The root `Cargo.toml` compiles *dependencies* at
`opt-level = 2` in the `dev` and `test` profiles (`[profile.dev.package."*"]`
and `[profile.test.package."*"]`) — the ed25519/blake3/argon2/dCBOR/SQLite work
every test does lives in dependencies and is 10–50× slower unoptimized.
Workspace crates stay at `opt-level = 0`, so our own code stays unoptimized for
debugging and coverage fidelity. Debug assertions and overflow checks remain on
everywhere (they are separate profile keys, unaffected by `opt-level`).
Debuginfo is trimmed to
`line-tables-only`: panics and `RUST_BACKTRACE` still show `file:line`, but
debuggers lose variable/type info — get it back with
`CARGO_PROFILE_DEV_DEBUG=2 cargo build`. Changing these settings forces a
one-time cold rebuild of all dependencies.

**Local build hygiene.** A `target/debug/deps` that grows to ~1M entries (tens
of GB) makes every freshly linked test binary stall tens of seconds before
`main()` on its first exec on macOS — a fresh binary runs in under a second
from any other directory, so it is that directory's accumulated size, not the
binary. When `target/` passes ~20 GB, or a test binary takes more than a few
seconds to start, sweep it: `cargo install cargo-sweep --locked` then
`cargo sweep --time 14` (keeps the last 14 days), or `cargo clean`.
`scripts/target-hygiene.sh` reports the size and entry count and, with
`--sweep`, runs the sweep.

CI (`.github/workflows/ci.yml`) runs once per push (a PR push runs the workflow a single
time — via `pull_request`; a push to a branch with no open PR runs nothing, so open a draft
PR to get CI). A superseded PR run is cancelled. On every PR: `test` (nextest + doc-tests),
`clippy`, `fmt`, `deny`, `audit`, `at-rest-dmcrypt`, and `fuzz-smoke` (only when a
fuzz-relevant crate, `fuzz/`, or `Cargo.lock` changed). On `main` pushes: all of the above
(`fuzz-smoke` always) plus `coverage` (cargo-llvm-cov). On the weekly schedule and manual
`workflow_dispatch`: the standard jobs (`test`, `clippy`, `fmt`, `deny`, `audit`,
`at-rest-dmcrypt`) plus coverage, `fuzz-smoke`, and the `deep` lane (`PROPTEST_CASES=1024`);
`reticulum-spike` is `workflow_dispatch`-only. `cargo fmt --check` is also enforced locally
via a pre-commit hook (`git config core.hooksPath .githooks`, set up by
`scripts/install-hooks.sh`).

## Conventions

- **No `unsafe` outside `rrn-crypto`** — a workspace-wide lint. This is the point of choosing
  Rust for the audit-everything posture.
- **ADRs**: every locked design decision gets `docs/adr/NNNN-kebab-case-title.md` (MADR
  format). ADRs are append-only — a changed decision gets a new ADR that supersedes the old
  one, not an edit.
- **Threat model**: `docs/threat-model.md` is a living document. Each crate adds a
  STRIDE-categorized section (assets, threats, mitigations, residual risks) as it's built —
  don't defer this to the end. "Known limitations" states plainly what is *not* mitigated.
- **The log is the source of truth**: the hash-chained signed log in `rrn-storage::log`;
  every other state — balances, transaction states, reputation, tallies, indexes — is
  derived by replay and must be re-derivable. Caches are caches.
- **Signed payloads**: anything signed goes through `rrn-crypto`'s `SignedPayload<T>` — the
  signature covers the canonical CBOR bytes of the payload, never the wire envelope. New
  signed record kinds need distinct `kind` discriminators and cross-platform CBOR fixtures
  (the mobile repo verifies byte-identical encodings).
- **Testing layers**: unit tests per crate; `proptest` for anything with algebraic structure
  (CRDT merge laws, sign/verify roundtrips, canonicalization stability); cross-crate
  integration tests in `/tests`.
- **Commits**: lightweight conventional commits.
- **No Claude session links**: never put a `claude.ai/code/session_...` link in a PR
  description, commit message, or any file. The "Generated with Claude Code" attribution
  line is fine; the session URL below it is not — omit it.
- **No AI-model or agent names in the repo**: never name a specific model or assistant
  (e.g. Claude, Fable, Opus, Sonnet) or `CLAUDE.md` in source, comments, doc-comments,
  ADRs, or docs; describe the process neutrally instead ("an AI model", "AI-assisted
  review", "the maintainer delegated the review"). The "Generated with Claude Code"
  attribution line and the `Co-Authored-By` trailer are the only allowed mentions. One
  deliberate exception: `docs/security/audit-2026-08.md` names the model on its
  "**Performed by:**" line as provenance for that security document — leave it.
- **No ticket numbers in code**: never write ticket identifiers (e.g. `T2.1.4`, `T1.9.7b`)
  into source, comments, doc-comments, commit messages, or PR descriptions. Tickets are
  ephemeral and gitignored; the code must stand on its own. Cite the durable record instead
  — the ADR (`ADR-00NN`) or a plain description of the behavior. (Existing pre-`T2.1.4`
  references are legacy; do not add new ones.)
- **Time**: Unix seconds as signed `i64` throughout. **Injected clocks** — ledger/settlement
  code takes `now: i64` as a parameter rather than reading the system clock, so tests
  fast-forward without sleeping. Anything window-bearing reads the admission clock
  (ADR-0022), never a timestamp inside a signed record.
- **Docs honesty**: README/status claims in all three repos must match what ships. Two
  recurring overstatements to avoid: the phone app having an offline outbox (it does not),
  and SMS being switchable on (no modem gateway).

## The "station" terminology overload

"Station" means two things — keep them distinct in code and docs:
- **the software** — the `station` daemon binary, this repo. e.g. "update your station to v0.4".
- **community** — the social/political entity in the federation (per the Underground Railroad
  mapping: stations = communities). Prefer "community" for the federation entity in protocol
  docs/code, and "station" for the running software.

## Domain glossary (for code comprehension)

- **Common / centicommons** — the universal mutual-credit unit; ledger amounts are signed
  integer centicommons.
- **Vouch** — a signed attestation that a pubkey belongs to a real, known individual
  (`rrn-identity::vouch`); carries a reputation stake and feeds identity anchoring.
- **Settlement window** — delay between confirmation and balance movement (Tier 1: 24h,
  Tier 2: 48h; uniform override for demos/tests); doubles as the dispute window. Runs from
  the confirmation's *admission* (ADR-0022).
- **Outbox / bundle / receipt** — a member's chained signed records awaiting delivery; the
  unsigned carriage envelope a courier/radio/paper carries; the station's signed per-record
  answer (admitted / known / refused) (ADR-0020, `docs/spec/dtn-bundles.md`).
- **Headroom certificate** — a station-signed reservation of debt-floor headroom requested
  while connected, spent against offline; capped, time-limited, returnable (ADR-0021).
- **Equivocation** — two conflicting commitments signed by one member (two spends on one
  certificate, two entries at one outbox position); provable from the log, zeroes
  reputation, opens a jury case (ADR-0025).
- **Writer / replica** — the one station that owns and appends to a community's log, vs. a
  read-only copy that pulls the chain and admits nothing (ADR-0020 §7).
- **Courier** — anyone who physically carries bundles/receipts/sheets; needs no trust.
- **VMK** — the Volume Master Key of the encrypted at-rest container, Shamir-split among
  holders, never on disk; reconstructed by the boot ceremony (ADR-0024).
- **Debt floor** — the lowest projected balance a member may sign themselves down to
  (ADR-0018); enforced at propose (sender-debit) and confirm (receiver-debit of a payment
  request) against settled balance plus pending signed debits.
- **Established member** — anchored composite reputation ≥ 2.0 (`BAND_MEMBER_MIN`); the
  governance electorate and jury pool. Below 3 established members the community is in
  **bootstrap grace** (ADR-0015).
- **PN-Counter / OR-Set / LWW-Register** — the CRDTs in `rrn-storage::crdt`; balances are a
  PN-Counter derived from settlement records. Reputation is *not* a synced CRDT — it is
  recomputed from the log (ADR-0009).
- **Append-only log** — hash-chained signed log (`rrn-storage::log`); the source of truth.
  CRDT state is derived from replaying it, never the reverse.
