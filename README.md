# Railroad Network — station

[![CI](https://github.com/railroad-network/station/actions/workflows/ci.yml/badge.svg)](https://github.com/railroad-network/station/actions/workflows/ci.yml)

> **Status:** Phase 1 — M1.1–M1.11 landed: mobile transport, vouching,
> reputation, marketplace, oracle tiers 1–2, governance, dispute resolution,
> and pilot readiness (sideload packaging, guided onboarding, backup/recovery,
> and operator runbooks). An internal AI-assisted security review has been
> completed (no High-severity findings; see [Audit status](#audit-status)); an
> independent professional audit is still pending. **Do not use with real value.**

**Railroad Network** is a federated platform for self-organizing communities: a
mutual-credit economy denominated in a single unit (the "Common"),
decentralized identity with social vouching and Shamir-based social recovery,
a tiered oracle and dispute system for adjudicating real-world transactions,
and a federation protocol between communities. The whole stack is designed to
degrade gracefully — from full internet connectivity down to local mesh, LoRa
radio, and paper fallback.

This repository, **`station`**, is the canonical Rust implementation: a Cargo
workspace of crates that produce the `station` daemon binary and the `rrn`
command-line client. Phase 0's goal was a correct cryptographic and ledger
foundation, demonstrated end-to-end by two communities transacting locally.
That foundation is implemented and has been through an internal AI-assisted
security review; an independent professional audit is still pending (see
[Audit status](#audit-status)).

Phase 1 builds on it: mobile↔station transport, social vouching, reputation
scoring, the marketplace, oracle tiers 1–2, community governance, dispute
resolution, and pilot readiness — sideload packaging, guided onboarding,
backup/recovery, and operator documentation — have all landed. What remains is
to run the pilot itself: a real community using it day to day. This work is
pre-audit and experimental.

> This is research-stage software. It has had an internal AI-assisted security
> review, but the cryptography has **not** yet been independently audited by a
> professional firm. Do not use it to hold, transfer, or represent anything of
> real value.

## What works in Phase 0

Everything below is implemented, tested, and exercised end-to-end by the demo:

- **Cryptographic core** (`rrn-crypto`) — Ed25519 signing (`verify_strict`),
  Blake3 hashing, deterministic canonical CBOR, and a `SignedPayload<T>` wrapper
  that signs the canonical bytes of a payload, never a wire envelope.
- **Local storage** (`rrn-storage`) — bundled SQLite (WAL, `STRICT` tables,
  foreign keys), the three CRDTs (PN-Counter, OR-Set, LWW-Register), and the
  hash-chained, append-only **signed log** that is the source of truth (all
  other state is derived by replaying it).
- **Identity** (`rrn-identity`) — bech32m `rrn1…` addresses, a passphrase-
  encrypted wallet (argon2id + XChaCha20-Poly1305, `0o600`, atomic writes),
  signed attestations, and the first concrete one: a **vouch**.
- **Social recovery** (`rrn-identity::recovery`) — a from-scratch Shamir secret
  sharing implementation over GF(256) (per ADR-0004): split the wallet key into
  `N` shards sealed to trusted holders, reconstruct from any `K`.
- **Mutual-credit ledger** (`rrn-ledger`) — the signed transaction
  `Proposed → Confirmed → Settled / Cancelled` state machine, a settlement
  window, balances in integer centicommons, and replay/double-spend protection
  (per-sender monotonic nonce, content-addressed ids, ±5-minute time window,
  idempotent exactly-once settlement).
- **Daemon + CLI** (`rrn-station`, `rrn-cli`) — the `station` daemon (Unix-socket
  IPC to the CLI, a settlement-sweep timer, and a minimal gossip stub) and the
  `rrn` client, demonstrated by two independent stations converging on the same
  balances and the same log.

## What's landed in Phase 1

Built on the Phase 0 foundation, and exercised end-to-end with the
[`mobile`](https://github.com/railroad-network/mobile) app on a physical device:

- **Mobile↔station transport (M1.3).** Sealed-envelope RPC over local HTTP (per
  ADR-0008), pairing, push-style updates via long-poll subscription, and the
  `rrn-mobile-ffi` crate exposing the crypto core to the app over uniffi.
- **Vouching (M1.4).** The vouching surface end-to-end: attest, browse, and the
  read paths the app consumes.
- **Reputation (M1.5).** `rrn-reputation` — composite scoring (per ADR-0009),
  decay, portability, stake enforcement, Sybil velocity limits, and identity
  anchoring, with a snapshot cache and the Standing read path.
- **Marketplace (M1.6–M1.7).** `rrn-marketplace` — listings, needs and
  matching, inquiries with counter-offers, requirement enforcement, recurring
  service contracts, and listing-linked transaction settlement.
- **Oracle tiers 1–2 (M1.8).** Per ADR-0011: bilateral confirmation (Tier 1)
  and community-attested settlement (Tier 2) with per-tier settlement windows;
  Tier 3 escalates to a dispute rather than silently clamping.
- **Governance (M1.9).** `rrn-governance` per ADR-0012 — the community
  Charter (solo `charter-init` or a distributed founding ceremony where
  phone-held founders sign on-device), proposals, co-signing, direct voting,
  and statutes.
- **Dispute resolution (M1.10).** `rrn-dispute` per ADR-0014 —
  standing-weighted sortition juries over contested transactions, escalation
  and appeal to the electorate, and reputation forfeiture on upheld rulings.
- **Pilot readiness (M1.11).** Bootstrap-grace electorate for young
  communities (ADR-0015), encrypted station backup/restore plus Shamir-based
  station key recovery (ADR-0016), guided multi-device onboarding, a signed
  sideloadable Android release, and steward runbooks for community setup and
  background reliability.

## What does NOT work yet

Out of scope so far — deferred to later Phase 1+ work — and **not** implemented:

- **No federation.** `rrn-protocol` is stubs; the gossip surface is a minimal
  stub for the local demo, with no transport authentication or encryption, no
  fork resolution, and no cross-replica nonce coordination. A community is one
  station plus the phones that can reach it on the local network.
- **No higher oracle tiers.** Tier 3 (physical evidence) and Tier 4
  (cross-community/governance) are absent; Tier-3-requiring transactions are
  blocked rather than silently downgraded.
- **No at-rest encryption of the database** (the wallet key and backup
  archives are encrypted; the live database is not), no memory locking, and no
  defense against a compromised host OS.
- **No radio/LoRa or mesh transport.** Runs over loopback/local network only.
- **No production binaries or crates.io release.** Source-only, on purpose.

See [`docs/threat-model.md`](docs/threat-model.md) for the full, STRIDE-organized
analysis, including the explicit **Known limitations** and **Trust boundaries**.

## Building

This is a standard Cargo workspace:

```sh
cargo build --workspace
cargo test  --workspace
```

Run `./scripts/install-hooks.sh` after cloning to enable the local pre-commit
checks (formatting and lints). CI additionally runs clippy, `cargo deny`,
`cargo audit`, a coverage report, and a fuzz smoke check on every push.

### Trying it out (the two-station demo)

Run `./scripts/demo-phase-0.sh` to see Phase 0 in action. The script builds the
release binaries, brings up two independent `station` daemons on localhost
(Alice and Bob), and drives a full mutual-credit exchange through the `rrn`
CLI: Alice vouches for Bob, pays him 3 Commons, Bob confirms, the settlement
window elapses, and both stations independently converge on the same balances
(Alice −3.00, Bob +3.00 Commons) and the same hash-chained log. It cleans up
after itself and is safe to re-run.

Under the hood the demo uses the two binaries directly:

```sh
station init --data-dir <dir>   # generate an identity + initialize storage
station run  --data-dir <dir>   # run the daemon (serves the rrn CLI over a Unix socket)

rrn whoami                      # your address
rrn pay <addr> 3.00 --memo …    # propose a payment
rrn confirm <tx_id>             # the receiver confirms
rrn balance [<addr>]            # balances, derived from the log
rrn history                     # the local append-only log, decoded
```

### Running a real community

To stand up an actual pilot community — a station on an always-on machine,
members' phones sideloaded and paired, a founding Charter, backups, and key
recovery — follow the steward's runbook:
[`docs/community-setup.md`](docs/community-setup.md). Keeping members' phones
syncing reliably in the background (per-vendor battery quirks and a
verification drill) has a companion runbook:
[`docs/background-reliability.md`](docs/background-reliability.md). The
phone-side install guide is the mobile repo's
[`SIDELOAD.md`](https://github.com/railroad-network/mobile/blob/main/SIDELOAD.md).

## Audit status

**Internal AI-assisted review complete; independent professional audit
pending.** A full-workspace security review was performed on 2026-08-25 at
commit [`f59271c`](https://github.com/railroad-network/station/commit/f59271c),
covering the cryptographic core, identity/recovery, storage, ledger, and the
station's network and ceremony surfaces. It reported **no High-severity
findings** — the cryptographic core came out in notably good shape (strict
signature verification, canonical-by-construction serialization with domain
separation, disciplined zeroization, and a Shamir implementation matching its
ADR) — with **3 Medium, 5 Low, and 4 Info** findings concentrated at the
protocol and exposure level. The full report, with each finding's failure
scenario and a remediation order, is at
[`docs/security/audit-2026-08.md`](docs/security/audit-2026-08.md).

Important: this was a **code review performed by an AI model** operated by the
maintainer, **not** a penetration test or an attestation by a professional
security firm. It is intended to raise the floor, not to clear the stack for
production. Absence of a finding is not evidence of absence, and an independent
professional audit remains warranted before any deployment where real people
depend on this software's guarantees. The whole stack — Phase 0 foundation and
Phase 1 alike — stays experimental until that review lands. Per the project's
open-source posture, all audit reports are public.

## Design documents

The full design overview — vision, governance, economics, oracle, identity,
federation, and technical architecture — lives in
[`docs/design/`](docs/design/README.md). Locked technical decisions are recorded
as ADRs in [`docs/adr/`](docs/adr/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current contribution policy and
the architecture decision record (ADR) process.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under
the same dual license, per [CONTRIBUTING.md](CONTRIBUTING.md).
