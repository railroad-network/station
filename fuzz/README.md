# Fuzz targets for `rrn-crypto`

Coverage-guided fuzz targets for the crypto crate's parsing/decoding boundaries,
built with [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) and
`libfuzzer-sys`. The goal in Phase 0 is a **panic baseline**: every target must
survive arbitrary input without panicking. All errors (off-curve keys,
non-canonical CBOR, non-verifying signatures) are expected, handled outcomes.

This crate is a standalone, nightly-only workspace (it is `exclude`d from the
root workspace); it never builds under `cargo build --workspace` on stable.

## Targets

| Target                | What it exercises                                                            |
| --------------------- | ---------------------------------------------------------------------------- |
| `verify_signature`    | `PublicKey::from_bytes` → `Signature::from_bytes` → `verify` over `(pk, sig, msg)`. |
| `canonical_roundtrip` | `from_canonical_bytes::<CBOR>` against arbitrary bytes (dCBOR decode).        |
| `hash_chain`          | Folding an arbitrary sequence of buffers through `Hash::of(prev ‖ next)`.     |

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

The `fuzz/rust-toolchain.toml` pins this directory to `nightly`, so the
`cargo fuzz` invocations below pick it up automatically.

## Running

```sh
# Run a target until it finds a crash (or forever). Ctrl-C to stop.
cargo +nightly fuzz run verify_signature

# Build all targets without running (what CI's smoke job compiles).
cargo +nightly fuzz build

# Time-boxed smoke run (what CI executes — 60s per target):
cargo +nightly fuzz run verify_signature    -- -max_total_time=60
cargo +nightly fuzz run canonical_roundtrip -- -max_total_time=60
cargo +nightly fuzz run hash_chain          -- -max_total_time=60
```

## Triaging a crash

When libFuzzer finds a crash it writes the offending input to
`fuzz/artifacts/<target>/crash-<hash>` and prints the path. To reproduce and
debug:

```sh
# Re-run the single crashing input (shows the panic + backtrace).
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>

# Minimize it to the smallest input that still crashes.
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
```

A crash here means an input reached a `panic!`/`unwrap`/overflow on a parsing
path that should only ever return `Result`. Fix the handling in `rrn-crypto`,
then add the minimized input to the target's corpus as a regression seed.

## Scope

Phase 0 runs these as a short CI smoke check (60s each). Long-running,
corpus-accumulating, coverage-tracked fuzzing on dedicated infrastructure is
Phase 5 — that is also where an exact nightly should be pinned for
reproducibility (see `rust-toolchain.toml`).
