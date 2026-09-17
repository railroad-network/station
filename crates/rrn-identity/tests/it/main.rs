//! Single integration-test binary for `rrn-identity`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-identity --test it <name>`.
mod cross_platform_address;
mod cross_platform_wallet;
mod ffi_invariants;
mod shamir_reference_vectors;
mod social_recovery;
mod vouch_log;
