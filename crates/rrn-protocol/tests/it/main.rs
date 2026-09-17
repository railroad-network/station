//! Single integration-test binary for `rrn-protocol`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-protocol --test it <name>`.
mod cross_platform_binding;
mod cross_platform_dtn;
mod cross_platform_sms_binding;
mod framing_proptests;
mod paper_qr;
