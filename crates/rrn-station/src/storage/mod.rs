//! At-rest storage: the two-root layout, the Volume Master Key ceremony, and the
//! encrypted-volume mount helper (ADR-0024).
//!
//! A station runs one of two **at-rest profiles**, chosen at provisioning
//! ([`crate::config::AtRestProfile`]):
//!
//! - **plaintext** — today's behavior: a single flat data directory. The
//!   [`Layout`](layout::Layout) collapses to one root, and none of the machinery
//!   in [`volume`] or [`vmk`] runs.
//! - **encrypted** — the seizure-resistance profile: the station's mutable and
//!   secret state lives inside a member-keyed LUKS2 container ([`volume`]) unlocked
//!   at boot by a Shamir quorum of member holders ([`vmk`]). The Volume Master Key
//!   is never written to disk. This profile is **Linux-only**; a non-Linux host
//!   refuses `at_rest = "encrypted"` rather than silently serving plaintext.
//!
//! The split between what is encrypted and what is not is expressed once, in
//! [`Layout`](layout::Layout): the unencrypted **boot dir** holds only
//! `config.toml`, the CLI socket, the container file, and a tiny VMK unlock
//! descriptor; the encrypted **state dir** (the container's mount point) holds the
//! wallet, the ledger database, paired mobiles, the search index, the recovery
//! package, and the Reticulum adapter identity.

pub mod admin;
pub mod layout;
pub mod vmk;
pub mod volume;
