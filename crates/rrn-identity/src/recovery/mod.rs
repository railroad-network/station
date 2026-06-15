//! Shamir-based social recovery.
//!
//! If you lose your wallet file (and thus your only copy of your secret key),
//! the identity is normally gone for good — that is the deliberate property of
//! the encrypted wallet ([`crate::wallet`]). Social recovery is the escape
//! hatch: ahead of time, split the secret key into `N` shards distributed to
//! `N` trusted holders such that any `K` of them can reconstruct it, while any
//! `K-1` learn nothing. When disaster strikes, gather `K` holders, have each
//! decrypt their shard, and rebuild the wallet.
//!
//! The primitive underneath is **Shamir's Secret Sharing**, implemented here
//! from scratch over GF(256) rather than pulled from a crate — see
//! [ADR-0004](../../../../docs/adr/0004-own-shamir-implementation.md) for the
//! (deliberate) case against "don't roll your own crypto" in this specific
//! instance.
//!
//! # Layers
//!
//! - [`gf256`] — finite-field arithmetic, the mathematical foundation.
//! - [`shamir`] — split a 32-byte secret into raw shards and reconstruct it
//!   from any `K`. Raw shards carry no integrity check and no holder binding;
//!   on their own they are just field points.
//! - [`encryption`] — seal a raw shard to a specific holder's identity key, so
//!   only that holder can decrypt it (a raw shard plus `K-1` others reveals the
//!   secret, so shards in transit and at rest must be confidential).
//! - [`flow`] — the end-to-end ritual: build a recovery package from a wallet
//!   and a set of holders, persist it, and reconstruct the wallet from
//!   decrypted shards.

pub mod encryption;
pub mod flow;
pub mod gf256;
pub mod shamir;
