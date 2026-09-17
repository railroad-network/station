//! Single integration-test binary for `rrn-station`.
//!
//! Each former `tests/<name>.rs` file is a module here, so the crate links and
//! stalls once for all its integration tests instead of once per file. Test
//! names keep a `<name>::` prefix; run one former file with
//! `cargo test -p rrn-station --test it <name>`.
#[cfg(target_os = "linux")]
mod at_rest_dmcrypt;
mod backup_recover;
mod cross_platform_contract;
mod cross_platform_inquiry;
mod cross_platform_listing;
mod cross_platform_listing_update;
mod cross_platform_pairing;
mod cross_platform_vouch;
#[cfg(unix)]
mod field_test_lora_dryrun;
mod ipc;
mod offline_lifecycle;
mod outage_72h;
mod pairing;
mod reticulum_spike;
mod rpc_channel;
mod sms_carrier;
mod two_station_e2e;
