//! Single integration-test binary for `rrn-ledger`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-ledger --test it <name>`.
mod cert_backed_spends;
mod cross_platform_certificates;
mod cross_platform_equivocation;
mod cross_platform_signed_payload;
mod idempotency;
mod ledger_signer_pinning;
mod lifecycle;
mod replay_dispatch_equivalence;
mod tier_lifecycle;
