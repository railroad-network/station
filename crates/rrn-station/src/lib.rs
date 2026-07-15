//! The Railroad Network **station** daemon, as a library.
//!
//! The `station` binary ([`main`](../station/index.html)) is a thin shell over
//! this crate so that the two-station end-to-end test ([`tests/two_station_e2e`])
//! can spin up stations *in-process* — as [`Station`] handles driven over their
//! Unix sockets — rather than shelling out to a built binary.
//!
//! # Shape
//!
//! A running station is an **actor**: one owner thread holds the
//! [`rrn_storage::db::Database`] and the wallet, and every operation — a CLI
//! request, a settlement sweep, a gossip exchange — is a [`core::Command`] sent
//! to it and answered over a [`tokio::sync::oneshot`] channel. This is forced by
//! the storage layer's single-writer model (`Database` is `!Sync`), and it
//! conveniently serializes all log writes through one place.
//!
//! Around that core sit four async surfaces, wired together by [`Station`]:
//! - [`server`] — the Unix-socket RPC listener the `rrn` CLI talks to ([`rpc`]).
//! - [`gossip`] — the TCP peer listener and the 5-second gossip loop that
//!   replicates log entries between communities (a deliberate Phase 0 stub).
//! - [`mdns`] — the local-network advertisement a mobile finds this station by.
//! - the settlement timer — wakes on an interval, reads the injected [`clock`],
//!   and asks the core to sweep newly-eligible transactions.
//!
//! # Time is injected
//!
//! Nothing here reads the system clock directly; the core carries a [`Clock`]
//! that is either real or a manually-advanced test clock, so the e2e test can
//! fast-forward across a settlement window without sleeping.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clock;
pub mod config;
pub mod core;
pub mod gossip;
pub mod history;
pub mod ledger_view;
pub mod mdns;
pub mod rpc;
pub mod rpc_client;
pub mod server;
pub mod station;

pub use clock::Clock;
pub use config::StationConfig;
pub use station::{Station, StationParams};
