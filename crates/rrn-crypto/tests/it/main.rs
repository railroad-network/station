//! Single integration-test binary for `rrn-crypto`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-crypto --test it <name>`.
mod cross_platform_multisign;
mod cross_platform_sign;
