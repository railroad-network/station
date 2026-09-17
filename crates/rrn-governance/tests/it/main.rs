//! Single integration-test binary for `rrn-governance`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-governance --test it <name>`.
mod cbor_fixtures;
mod emergency_activation_ttl;
mod emergency_governance;
mod station_signer_pinning;
