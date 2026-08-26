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

## Current status: Phase 1 complete (M1.1–M1.11), pilot-ready

Phase 0 (crypto core, storage/log, identity, ledger, daemon+CLI) and all of Phase 1 —
mobile transport, vouching, reputation, marketplace, oracle tiers 1–2, governance, dispute
resolution, and M1.11 pilot readiness — have landed. What remains of Phase 1 is running the
actual 90-day community pilot. The next build phase is **Phase 2 — Single-Community
Resilience** (offline-first hardening, delay-tolerant sync, LoRa/SMS, paper fallback), which
was resequenced *before* federation by ADR-0017.

**Phase numbering hazard (ADR-0017):** documents written before 2026-08-25 use the old
numbering ("Phase 2" = federation). Now: Phase 2 = single-community resilience, Phase 3 =
multi-community federation. ADRs 0001–0016 and the 2026-08 audit keep the old numbering as
written; the threat model and design overview use the new one.

An internal AI-assisted security review is done (`docs/security/audit-2026-08.md`, no
High-severity findings); the independent professional audit is still pending. **Do not use
with real value.**

## Planning documents

Detailed phase plans and per-task specs live outside this repo, in the maintainer's
local planning workspace (not distributed with the code): `Phase 0 Plan.md`, the
`Reticulum Assessment.md` behind ADR-0013, and per-task specs under `Phase 0 Tasks/`
and `Phase 1 Tasks/` (T`N.X.Y`: crate, dependencies, deliverable, hints,
acceptance criteria, out-of-scope).
The design overview itself is in-repo at `docs/design/Railroad-Network-Overview.md`.

**How to work from the task specs:**
- Do tasks in dependency order; every field in a spec is load-bearing.
- Verify against the spec's **Acceptance** criteria/commands before considering it done.
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
│   ├── adr/                    # ADRs 0001–0018, MADR format — the locked-decision record
│   ├── threat-model.md         # living STRIDE document, grown per milestone
│   ├── security/               # audit reports
│   ├── spec/                   # wire-format specs (QR payloads, ...)
│   ├── community-setup.md      # operator runbook
│   └── background-reliability.md
├── crates/
│   ├── rrn-crypto/             # ed25519, blake3, canonical CBOR, SignedPayload — audit boundary, no rrn-* deps
│   ├── rrn-storage/            # SQLite, CRDTs (PN-Counter/OR-Set/LWW-Register), hash-chained signed log, replay
│   ├── rrn-identity/           # wallet, addresses, vouching, sealed envelopes, Shamir recovery
│   ├── rrn-ledger/             # tx state machine, settlement, tiers, credit (debt floor), disputes (records), contracts
│   ├── rrn-reputation/         # ADR-0009 universal scoring, staking gates, sybil velocity, portability
│   ├── rrn-governance/         # ADR-0012 charter, proposals, statutes, votes, tally
│   ├── rrn-dispute/            # ADR-0014 sortition, panels, verdicts, escalation
│   ├── rrn-marketplace/        # ADR-0010 listings, needs, inquiries, contracts, search
│   ├── rrn-protocol/           # wire messages / transport seam (Reticulum backend per ADR-0013, Phase 2+)
│   ├── rrn-mobile-ffi/         # uniffi bindings over rrn-crypto/rrn-identity for the mobile repo
│   ├── rrn-station/            # `station` daemon: core, RPC, mobile server, gossip, backup/recovery
│   └── rrn-cli/                # `rrn` CLI binary
├── tests/                      # cross-crate integration tests
├── fuzz/                       # cargo-fuzz targets (own nightly workspace)
└── scripts/                    # demo-phase-0.sh, install-hooks.sh
```

Layered dependencies: `rrn-crypto` → `rrn-storage` → `rrn-identity` → `rrn-ledger` →
{`rrn-reputation`, `rrn-governance`, `rrn-marketplace`} → `rrn-dispute` → `rrn-station` /
`rrn-cli`. `rrn-crypto` must never depend on other `rrn-*` crates — it's the audit boundary.

## Locked technical decisions

The authoritative record is `docs/adr/` (0001–0018, append-only). Don't deviate without a
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
- **Federation/collapse transport**: Reticulum as a supervised sidecar, strictly a dumb
  carrier — never the identity, integrity, or encryption boundary (ADR-0013).
- The station signs settlement/cancellation records; charters chain amendments via
  `previous_hash` lineage (ADR-0005, ADR-0012).

Amounts are always integer **centicommons** (1 Common = 100 centicommons) — never floats,
anywhere in a signed payload.

## Development commands

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo deny check          # license/advisory/bans/sources
cargo audit                # known CVEs

# single crate / single integration test
cargo test -p rrn-crypto
cargo test --test lifecycle -p rrn-ledger

# fuzz targets (nightly toolchain, own workspace under fuzz/)
cargo +nightly fuzz run verify_signature

# end-to-end demo
./scripts/demo-phase-0.sh
```

CI (`.github/workflows/ci.yml`) runs `test`, `clippy`, `fmt`, `deny`, `audit` in parallel on
every push/PR. `cargo fmt --check` is also enforced locally via a pre-commit hook
(`git config core.hooksPath .githooks`, set up by `scripts/install-hooks.sh`).

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
- **Time**: Unix seconds as signed `i64` throughout. **Injected clocks** — ledger/settlement
  code takes `now: i64` as a parameter rather than reading the system clock, so tests
  fast-forward without sleeping.

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
  Tier 2: 48h; uniform override for demos/tests); doubles as the dispute window.
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
