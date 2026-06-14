# Railroad Network — station

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the current contribution policy and
the architecture decision record (ADR) process.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Contributions are accepted under
the same dual license, per [CONTRIBUTING.md](CONTRIBUTING.md).
