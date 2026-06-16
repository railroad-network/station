# Fuzz targets

Coverage-guided fuzz targets for the workspace's parsing, decoding, and
state-transition boundaries, built with
[`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) and
`libfuzzer-sys`. The first three targets cover `rrn-crypto` (the M0.1 baseline);
the rest, added in M0.7 for audit prep, extend the same panic-baseline
discipline across `rrn-storage`, `rrn-identity`, and `rrn-ledger`.

The goal in Phase 0 is a **panic baseline**: every target must survive arbitrary
input without panicking. All errors (off-curve keys, non-canonical CBOR,
non-verifying signatures, malformed shards, wrong passphrases, bad addresses)
are expected, handled outcomes. Per the spec, the real bugs to expect are not in
the audited AEAD/signature libraries but in *our* parsers, state transitions,
and integer arithmetic — `state_machine` in particular pushes adversarial
amounts and timestamps through the balance and settlement-window math.

This crate is a standalone, nightly-only workspace (it is `exclude`d from the
root workspace); it never builds under `cargo build --workspace` on stable.

## Targets

| Target                | What it exercises                                                            |
| --------------------- | ---------------------------------------------------------------------------- |
| `verify_signature`    | `PublicKey::from_bytes` → `Signature::from_bytes` → `verify` over `(pk, sig, msg)`. |
| `canonical_roundtrip` | `from_canonical_bytes::<CBOR>` against arbitrary bytes (dCBOR decode).        |
| `hash_chain`          | Folding an arbitrary sequence of buffers through `Hash::of(prev ‖ next)`.     |
| `log_replay`          | Arbitrary signed buffers through `AppendLog::append_raw` → `verify_chain` → `replay_log` (the re-chaining + replay/derivation path). |
| `state_machine`       | A fuzz-driven script of `submit_proposal` / `submit_confirmation` / `settle` / `cancel_proposal` against a real in-memory ledger, with amount/nonce/timestamps from the input (integer-overflow hunting in balance + window math). |
| `shamir_reconstruct`  | Arbitrary bytes sliced into `RawShard`s and fed to `reconstruct_secret` (GF(256) interpolation, per ADR-0004). |
| `wallet_decrypt`      | Arbitrary bytes decoded as an `EncryptedWallet`, then `decrypt` under an arbitrary passphrase. |
| `address_parse`       | An arbitrary string parsed as an `Address` (bech32m decode + checksum + HRP + curve-point checks). |

The crypto-only targets keep `rrn-crypto` as their only `rrn-*` dependency; the
rest pull in `rrn-storage` / `rrn-identity` / `rrn-ledger` because that is the
surface they exercise.

> **`wallet_decrypt` caveat — a known, documented residual risk, not a parser
> bug.** `EncryptedWallet` carries its argon2id parameters in the file, and
> Phase 0 does not clamp them on decode (see `docs/threat-model.md`, the
> `rrn-identity` Denial-of-service entry). A coverage-guided run that learns to
> emit a structurally-valid wallet with a very large `m_cost` can trigger a big
> allocation rather than a panic. If `wallet_decrypt` reports an OOM, triage it
> against that residual risk before filing it as a new defect.

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

# Time-boxed smoke run (what CI's `ci.yml` fuzz-smoke job executes — 60s each):
cargo +nightly fuzz run verify_signature    -- -max_total_time=60
cargo +nightly fuzz run canonical_roundtrip -- -max_total_time=60
cargo +nightly fuzz run hash_chain          -- -max_total_time=60
cargo +nightly fuzz run log_replay          -- -max_total_time=60
cargo +nightly fuzz run state_machine       -- -max_total_time=60
cargo +nightly fuzz run shamir_reconstruct  -- -max_total_time=60
cargo +nightly fuzz run wallet_decrypt      -- -max_total_time=60
cargo +nightly fuzz run address_parse       -- -max_total_time=60
```

The longer **audit-prep** run (≥1 hour per target) is a separate, manually
triggered workflow (`.github/workflows/audit-prep.yml`), not part of the
per-PR CI — see that workflow and the "Scope" section below.

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

A crash here means an input reached a `panic!`/`unwrap`/overflow on a path that
should only ever return `Result`. The fix lives in the crate that owns the
target's surface (`rrn-crypto`, `rrn-storage`, `rrn-identity`, or `rrn-ledger`),
not in this fuzz crate. The full triage loop:

1. Reproduce with the saved artifact and `tmin`-minimize it (above).
2. Add the minimized input as a regression test in the owning crate, using the
   offending bytes directly — a unit test that asserts the parse/transition now
   returns an error instead of panicking.
3. Fix the handling in that crate, re-run the target, and keep the minimized
   input in the target's corpus as a seed so coverage does not regress.

(See the `wallet_decrypt` caveat under "Targets": an OOM there is most likely
the documented unclamped-`m_cost` residual risk, not a new bug.)

## Scope

Per-PR CI runs every target as a short **smoke check** (60s each, in `ci.yml`'s
`fuzz-smoke` job) — enough to catch a target that no longer builds or panics
immediately, cheap enough to gate every push.

The **audit-prep** workflow (`.github/workflows/audit-prep.yml`) is the deeper,
gated pass: it runs each target for **≥1 hour** and uploads any crash artifacts.
It is `workflow_dispatch`-only (manually triggered before an audit submission),
not on every PR. Any crash it surfaces must be triaged and fixed before the
codebase is handed to the auditor.

Long-running, corpus-accumulating, coverage-tracked fuzzing on dedicated
infrastructure is Phase 5 — that is also where an exact nightly should be pinned
for reproducibility (see `rust-toolchain.toml`).
