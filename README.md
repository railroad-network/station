# Railroad Network — station

[![CI](https://github.com/railroad-network/station/actions/workflows/ci.yml/badge.svg)](https://github.com/railroad-network/station/actions/workflows/ci.yml)

> **Status:** Phase 2, single-community resilience, is complete on simulation
> evidence (closed 2026-09-13; see [`docs/phase-2-exit-evidence.md`](docs/phase-2-exit-evidence.md)).
> Phases 0 and 1 landed before it. What remains before anyone should trust this
> with real value: the 90-day community pilot, two human-gated hardware
> sign-offs, and an independent professional security audit. An internal
> AI-assisted review found no High-severity issues (see
> [Audit status](#audit-status)). **Do not use with real value.**

**Railroad Network** is a platform for self-organizing communities: a
mutual-credit economy denominated in a single unit (the "Common"),
decentralized identity with social vouching and Shamir-based social recovery,
a tiered oracle and dispute system for adjudicating real-world transactions,
community governance with a bounded emergency mode, and, eventually, a
federation protocol between communities. The whole stack is designed to
degrade gracefully, from full internet connectivity down to local mesh, LoRa
radio, text message, and paper.

This repository, **`station`**, is the canonical Rust implementation: a Cargo
workspace of crates that produce the `station` daemon and the `rrn`
command-line client. The Android app lives in the sibling repo
[`mobile`](https://github.com/railroad-network/mobile). The human-facing
documentation, written for members, organizers, and operators rather than for
the code, is at **<https://railroad-network.github.io>**; this repo holds the
engineering record (design overview, decision records, wire specs, threat
model, audits) that the site explains.

> This is research-stage software. It has had an internal AI-assisted security
> review, but the cryptography has **not** been independently audited by a
> professional firm. Do not use it to hold, transfer, or represent anything of
> real value.

## What works today

Everything below is implemented, tested, and exercised end to end by a script
in [`scripts/`](scripts/) or an integration test.

### Foundation (Phase 0)

- **Cryptographic core** (`rrn-crypto`): Ed25519 signing with strict
  verification, Blake3 hashing, deterministic canonical CBOR, and a
  `SignedPayload<T>` wrapper that signs the canonical bytes of a payload, never
  a wire envelope. No dependencies on other project crates; this is the audit
  boundary.
- **Local storage** (`rrn-storage`): bundled SQLite (WAL, strict tables,
  foreign keys), three CRDTs (PN-Counter, OR-Set, LWW-Register), and the
  hash-chained, append-only **signed log** that is the source of truth. Every
  other state (balances, standing, tallies, indexes) is derived by replaying
  it.
- **Identity** (`rrn-identity`): bech32m `rrn1…` addresses, a
  passphrase-encrypted wallet (argon2id + XChaCha20-Poly1305), signed
  attestations, vouches, sealed envelopes, and a from-scratch Shamir secret
  sharing implementation over GF(256) (ADR-0004).
- **Mutual-credit ledger** (`rrn-ledger`): the `Proposed → Confirmed →
  Settled / Cancelled` state machine, per-tier settlement windows, balances in
  integer centicommons, replay and double-spend protection, a debt floor
  (ADR-0018), and escrowed headroom certificates for offline spending
  (ADR-0021).

### One community (Phase 1)

- **Mobile transport**: sealed-envelope RPC over local HTTP (ADR-0008),
  in-person pairing with a short code comparison, long-poll push, and the
  `rrn-mobile-ffi` uniffi bindings the app builds on.
- **Vouching and standing** (`rrn-reputation`): one locked scoring formula
  derived from the log and never stored authoritatively (ADR-0009), decay,
  staking gates, Sybil velocity limits, identity anchoring.
- **Marketplace** (`rrn-marketplace`): listings, needs and matching, inquiries
  with counter-offers, recurring service contracts, listing-linked settlement
  (ADR-0010).
- **Oracle tiers 1 and 2** (ADR-0011): bilateral confirmation and
  community-attested settlement; a Tier-3 amount (50 Commons and up) is
  refused, never clamped.
- **Governance** (`rrn-governance`): the Charter with a distributed founding
  ceremony, proposals, co-signing, voting, statutes, amendments chained by
  hash (ADR-0012); bootstrap grace for young communities (ADR-0015).
- **Disputes** (`rrn-dispute`): standing-weighted sortition juries of three,
  escalation and appeal to the electorate, every path failing open to the
  status quo (ADR-0014).
- **Pilot readiness**: encrypted station backup and restore, station key
  recovery through member-held shards (ADR-0016), a signed sideloadable
  Android release, and operator runbooks.

### Resilience (Phase 2)

- **The admission clock** (ADR-0022): every window, deadline, and electorate
  is anchored on the station's clock at admission and the log position, never
  on a timestamp a device claims.
- **Delay-tolerant submission** (ADR-0020): the log keeps one writer; members'
  signed records travel later as outbox chains inside carriage bundles and are
  answered by station-signed delivery receipts. Courier relay, station-originated
  push, and the `rrn dtn` commands.
- **Offline spending that is bounded and provable** (ADR-0021, ADR-0025):
  headroom certificates reserved before a partition, certificate-backed
  spends, and double-spends recorded as provable equivocation that zeroes the
  member's standing and opens a jury case.
- **Paper fallback**: `rrnp:`, `rrncert:`, and `rrnspend:` QR formats and the
  `rrn paper` courier tools (inspect, ingest, print receipts and cards).
- **A self-custody command-line wallet** (`rrn wallet`, ADR-0028): a member
  with a computer and no phone holds their own key, signs offline into a
  durable outbox, carries records on paper or as a bundle, and syncs over the
  sealed channel. Includes member key recovery from a circle of holders
  (`rrn wallet recover`, ADR-0016).
- **Reticulum and LoRa** (ADR-0013, ADR-0026): a supervised `rnsd` sidecar,
  strictly a dumb carrier, with an airtime budget and an RNode radio interface
  templated from configuration. Bench-verified over the air.
- **SMS as a carrier**: the chunk codec, sender registry, rate cap, and relay,
  tested against a mock gateway.
- **Emergency governance** (ADR-0023, ADR-0027): a supermajority-declared
  state that compresses only the voting window for emergency-kind proposals,
  freezes the Charter, pins the electorate, and expires by itself.
- **Encrypted at rest** (ADR-0024, Linux, opt-in): the wallet and ledger live
  in a LUKS2 container whose key is Shamir-split among members and never
  stored on the machine; unlocked by a boot ceremony with a console
  fingerprint.
- **Writer and replica roles**: a station is the community's single writer or
  a read-only replica that pulls the chain for audit and admits nothing.
- **The 72-hour outage simulation**: one real daemon and about twenty members
  through three simulated days of courier, paper, and lossy-radio traffic,
  with conservation, floor, fork, and determinism checks
  ([`docs/phase-2-exit-evidence.md`](docs/phase-2-exit-evidence.md)).

## What does not work yet

Stated plainly, because the docs site and the runbooks promise only what is
here:

- **No federation.** Communities cannot see or trade with each other. A
  community is one writer station plus the devices that pair with it.
  Federation is Phase 3 (ADR-0017).
- **No Tier 3 or higher.** Payments of 50 Commons and up are refused.
- **The phone app is online-only for signing.** Sending, confirming, voting,
  and contesting from the app need the station reachable. The offline outbox,
  headroom certificates, and paper export exist today only in the
  command-line wallet; the Rust FFI for the phone side is built
  (`rrn-mobile-ffi`), the screens are not.
- **Two hardware sign-offs are pending.** The SMS modem gateway is not built
  (the codec and relay are), and the LoRa field-acceptance run at real range
  has not been recorded (the radios are bench-verified).
- **A replica is a copy of the chain, not a second balance oracle.**
  Station-signed records are pinned to the writer's key on replay, so a
  replica's derived balances read zero. The pilot runs a single writer.
- **No per-member rate limiting** on any surface. Accepted at pilot scale
  behind the pairing gate.
- **Android only, sideloaded. No iOS. No release binaries or crates.io
  publication.** Source-only, on purpose.
- **No independent audit.**

The full, STRIDE-organized analysis, including the **Known limitations** list
every claim above comes from, is [`docs/threat-model.md`](docs/threat-model.md).

## Building

A standard Cargo workspace on stable Rust:

```sh
cargo build --workspace
cargo nextest run --workspace   # preferred; `cargo test --workspace` also works
cargo test --workspace --doc    # doc-tests (nextest does not run them)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Run `./scripts/install-hooks.sh` once after cloning to enable the pre-commit
formatting check. CI runs the test suite, clippy, formatting, `cargo deny`,
`cargo audit`, the Linux at-rest-encryption lane, and a fuzz smoke check on
every pull request; coverage and a deep property-test lane run on `main` and
weekly. Dependencies compile optimized in the dev and test profiles because
the crypto every test does is 10 to 50 times slower unoptimized; workspace
crates stay unoptimized for debugging.

## Trying it out

Each script builds what it needs, runs against real binaries, cleans up after
itself, and is safe to re-run.

| Script | What it shows |
| --- | --- |
| `scripts/demo-phase-0.sh` | A writer station and a read replica converge on the same log and balances after a vouch, a payment, and settlement. |
| `scripts/demo-phase-2-paper.sh` | A member confirms a payment with no network at all; the confirmation travels to the station as printed QR sheets and the receipt travels back the same way. |
| `scripts/demo-phase-2-wallet.sh` | A laptop member with `rrn wallet`: pair, sync, confirm offline, export to paper, courier, ingest, apply receipts, pay back online. |
| `scripts/demo-phase-2-outage.sh` | The 72-hour outage simulation, narrated step by step. |
| `scripts/drill-seizure-recovery.sh` | The seizure-recovery drill: restore onto fresh storage (any platform) and prove the encrypted container leaks nothing (Linux). |
| `scripts/field-test-lora.sh` | The scripted radio field-acceptance run for two stations with RNode radios (`--dry-run` in CI). |

Under the hood the demos use the two binaries directly:

```sh
station init --data-dir <dir>   # generate an identity + initialize storage
station run  --data-dir <dir>   # run the daemon (serves the rrn CLI over a Unix socket)

rrn whoami                      # the station's own address
rrn status                      # connectivity, sidecar, and queue depths
rrn pay <addr> 3.00 --memo …    # propose a payment from the station wallet
rrn confirm <tx_id>             # the receiver confirms
rrn balance [<addr>]            # balances, derived from the log
rrn history                     # the local append-only log, decoded
```

The full `--help` of every command is on the docs site under
[Reference](https://railroad-network.github.io/reference/).

## Running a real community

The docs site has the plain-language guides for
[members](https://railroad-network.github.io/members/),
[organizers](https://railroad-network.github.io/organizers/), and
[operators](https://railroad-network.github.io/operators/). The complete
operator runbooks live here and are the site's source:

- [`docs/community-setup.md`](docs/community-setup.md): stand up a station,
  pair phones and laptops, found the community, back it up, arm key recovery,
  the encrypted at-rest profile, paper and radio carriers, emergency
  governance, and the community outage drill.
- [`docs/background-reliability.md`](docs/background-reliability.md): keeping
  members' phones syncing when the app is closed, per vendor.
- [`docs/lora-radio-bringup.md`](docs/lora-radio-bringup.md): an RNode-class
  LoRa radio from unflashed hardware to carrying station traffic.

The phone-side install guide is the mobile repo's
[`SIDELOAD.md`](https://github.com/railroad-network/mobile/blob/main/SIDELOAD.md).

## Audit status

**Internal AI-assisted review complete; independent professional audit
pending.** A full-workspace security review was performed on 2026-08-25 at
commit [`f59271c`](https://github.com/railroad-network/station/commit/f59271c),
covering the cryptographic core, identity and recovery, storage, the ledger,
and the station's network and ceremony surfaces. It reported **no
High-severity findings**, with 3 Medium, 5 Low, and 4 Info findings
concentrated at the protocol and exposure level. The full report is
[`docs/security/audit-2026-08.md`](docs/security/audit-2026-08.md). The
resilience surface Phase 2 added is covered by the living threat model and by
the attacker-by-attacker checklist in
[`docs/security/phase-2-redteam.md`](docs/security/phase-2-redteam.md),
written for the independent audit team and for communities running their own
outage drill.

Important: the August review was a **code review performed by an AI model**
operated by the maintainer, **not** a penetration test or an attestation by a
professional security firm. It was meant to raise the floor, not to clear the
stack for production. Absence of a finding is not evidence of absence, and an
independent professional audit remains warranted before any deployment where
real people depend on this software's guarantees. Per the project's
open-source posture, all audit reports are public.

## Repository map

| Path | What it is |
| --- | --- |
| `crates/rrn-crypto` | Ed25519, Blake3, canonical CBOR, `SignedPayload`. The audit boundary. |
| `crates/rrn-storage` | SQLite, CRDTs, the hash-chained signed log, replay, outbox and DTN stores. |
| `crates/rrn-identity` | Wallets, addresses, vouches, sealed envelopes, Shamir recovery. |
| `crates/rrn-ledger` | Transactions, settlement, tiers, the debt floor, headroom certificates, disputes as records. |
| `crates/rrn-reputation` | The one standing formula, staking gates, Sybil velocity, portability. |
| `crates/rrn-governance` | Charter, proposals, statutes, votes, tally, emergency mode. |
| `crates/rrn-dispute` | Sortition, panels, verdicts, escalation, equivocation cases. |
| `crates/rrn-marketplace` | Listings, needs, inquiries, contracts, search. |
| `crates/rrn-protocol` | Outbox chains, bundles, receipts, framing, airtime budget, paper codecs, bindings. |
| `crates/rrn-mobile-ffi` | The uniffi surface the mobile app builds on. |
| `crates/rrn-station` | The `station` daemon: core, RPC, mobile server, DTN loop, sidecar, SMS, backup, at-rest encryption. |
| `crates/rrn-cli` | The `rrn` client: operator console, paper tools, member wallet. |
| `docs/adr/` | Architecture decision records 0001 to 0028, the locked-decision record. |
| `docs/design/` | The design overview, updated in place with dated notes. |
| `docs/spec/` | Wire formats: QR payloads, DTN bundles, SMS carrier, the boot ceremony fingerprint. |
| `docs/threat-model.md` | The living STRIDE threat model. |
| `docs/security/` | The August 2026 audit and the Phase 2 red-team checklist. |
| `tests/`, `fuzz/` | Cross-crate integration tests and the nightly cargo-fuzz workspace. |

Layered dependencies: `rrn-crypto` → `rrn-storage` → `rrn-identity` →
`rrn-ledger` → {`rrn-reputation`, `rrn-governance`, `rrn-marketplace`} →
`rrn-dispute` → `rrn-station` / `rrn-cli`.

## Design documents

The design overview (vision, governance, economics, oracle, identity,
federation, technical architecture, roadmap) is in
[`docs/design/`](docs/design/README.md). Locked decisions are ADRs in
[`docs/adr/`](docs/adr/README.md); where the overview and an ADR disagree, the
ADR wins. Note the phase renumbering in ADR-0017: documents written before
2026-08-25 call federation "Phase 2".

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current contribution policy,
the development workflow, and the ADR process. Security issues go to the
address in [SECURITY.md](SECURITY.md), never to a public issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under
the same dual license, per [CONTRIBUTING.md](CONTRIBUTING.md).
