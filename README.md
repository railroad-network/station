# Railroad Network — station

[![CI](https://github.com/railroad-network/station/actions/workflows/ci.yml/badge.svg)](https://github.com/railroad-network/station/actions/workflows/ci.yml)

**Railroad Network** is a federated platform for self-organizing communities: a
mutual-credit economy denominated in a single unit (the "Common"),
decentralized identity with social vouching and Shamir-based social recovery,
a tiered oracle and dispute system for adjudicating real-world transactions,
and a federation protocol between communities. The whole stack is designed to
degrade gracefully — from full internet connectivity down to local mesh, LoRa
radio, and paper fallback.

This repository, **`station`**, is the canonical Rust implementation: a Cargo
workspace of crates that produce the `station` daemon binary and the `rrn`
command-line client. **Current status: Phase 0 — Foundation, in progress.**
Phase 0's goal is a correct, externally-audited cryptographic and ledger
foundation, demonstrated end-to-end by two communities transacting locally.

> **This is research-stage software.** It is incomplete, unaudited, and not
> production-ready. Do not use it to hold, transfer, or represent anything of
> real value.

## Building

This is a standard Cargo workspace:

```sh
cargo build --workspace
cargo test --workspace
```

Run `./scripts/install-hooks.sh` after cloning to enable the local pre-commit
checks (formatting and lints).

## Trying it out

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

## Design documents

The full design overview — vision, governance, economics, oracle, identity,
federation, and technical architecture — lives in
[`docs/design/`](docs/design/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current contribution policy and
the architecture decision record (ADR) process.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under
the same dual license, per [CONTRIBUTING.md](CONTRIBUTING.md).
