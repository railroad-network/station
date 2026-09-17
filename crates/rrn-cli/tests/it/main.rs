//! Single integration-test binary for `rrn-cli`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-cli --test it <name>`.
mod cli_e2e;
mod paper_roundtrip;
