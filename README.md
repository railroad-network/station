# Railroad Network — station

[![CI](https://github.com/railroad-network/station/actions/workflows/ci.yml/badge.svg)](https://github.com/railroad-network/station/actions/workflows/ci.yml)

> **Status:** Phase 0 — Foundation. Implementation complete. Pre-audit.
> **Do not use with real value.**

**Railroad Network** is a federated platform for self-organizing communities: a
mutual-credit economy denominated in a single unit (the "Common"),
decentralized identity with social vouching and Shamir-based social recovery,
a tiered oracle and dispute system for adjudicating real-world transactions,
and a federation protocol between communities. The whole stack is designed to
degrade gracefully — from full internet connectivity down to local mesh, LoRa
radio, and paper fallback.

This repository, **`station`**, is the canonical Rust implementation: a Cargo
workspace of crates that produce the `station` daemon binary and the `rrn`
command-line client. Phase 0's goal is a correct, externally-audited
cryptographic and ledger foundation, demonstrated end-to-end by two communities
transacting locally. That foundation is now implemented; the external audit is
the gate to Phase 1 (see [Audit status](#audit-status)).

> This is research-stage software. The cryptography has **not** yet been
> independently audited. Do not use it to hold, transfer, or represent anything
> of real value.

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

## What does NOT work in Phase 0

Out of scope by design — deferred to Phase 1+ — and **not** implemented here:

- **No federation.** `rrn-protocol` is stubs; the gossip surface is a minimal
  Phase 0 stub for the local two-station demo, with no transport authentication
  or encryption, no fork resolution, and no cross-replica nonce coordination.
- **No marketplace.** No listings, matching, or goods/services exchange.
- **No governance.** No voting, charters, or dispute tribunals beyond automated
  Tier 1/2 escalation.
- **No higher oracle tiers.** Only bilateral confirmation + settlement window;
  Tier 3 (physical evidence) and Tier 4 (cross-community/governance) are absent.
- **No Sybil resistance.** Vouch *authenticity* is enforced; vouch *trust* and
  Sybil/reputation analysis are not — Phase 0 assumes a single, trusting
  community.
- **No credit limits.** A sender can settle into arbitrary debt in Phase 0.
- **No at-rest encryption of the database** (only the wallet key is encrypted),
  no memory locking, and no defense against a compromised host OS.
- **No UI, no mobile app, no radio/LoRa or mesh transport.** Phase 0 runs over
  loopback/local network only.
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

## Audit status

**Pre-audit.** The Phase 0 implementation is feature-complete and is being
prepared for an external security audit (the gate to Phase 1). The audit-prep
materials — finalized threat model, expanded fuzz harnesses, and the coverage
report — live under [`docs/`](docs/) and the CI workflows.

This section will be updated as the audit progresses (planned → scheduled →
in progress → complete), and will link to the published report once received.
Per the project's open-source posture, the audit report will be public.

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
