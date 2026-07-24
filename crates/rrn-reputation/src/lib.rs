//! Reputation for Railroad Network — a member's standing, derived from what
//! they have done, not asserted about themselves.
//!
//! Reputation is not a stored number a member controls; it is computed
//! ([`scoring`]) from evidence: settled transactions on the ledger and signed
//! vouches from other members. Old evidence counts for less than recent
//! evidence, so [`decay`] applies a time weighting — standing has to be
//! maintained, and a long-dormant identity cannot bank reputation indefinitely.
//! Because every input is signed and content-addressed, a score is fully
//! re-derivable from the log rather than trusted as materialized state.
//!
//! # Where it sits in the stack
//!
//! It depends on `rrn-crypto` (the signed, canonical inputs), `rrn-storage`
//! (materializing and caching scores), `rrn-identity` (reputation attaches to
//! an identity and is built from its attestations), and `rrn-ledger`
//! (transaction history is a primary input). The dependency arrows point up the
//! stack.
//!
//! The module layout follows ADR-0009 (the universal reputation algorithm):
//! [`model`] is the multidimensional profile and its composite/band view,
//! [`scoring`] replays the log into a profile, [`decay`] applies the time
//! weighting, [`portability`] makes a profile signed and replayable off its
//! home station, and [`sybil`] holds the velocity and identity-anchoring
//! defenses. Each module is a placeholder here (T1.5.2) and is filled in by its
//! own later M1.5 task.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod decay;
pub mod model;
pub mod portability;
pub mod scoring;
pub mod snapshot;
pub mod sybil;

/// Something went wrong reading the evidence a reputation score is derived from.
///
/// Scoring is a read over the log and the ledger view; the failures it can hit
/// are the underlying storage and ledger errors, surfaced unchanged. A payload
/// that simply is not a record this crate scores (e.g. a vouch when scanning for
/// transactions) is skipped, not an error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A failure reading the append-only log.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
    /// A failure replaying the ledger from the log.
    #[error("ledger: {0}")]
    Ledger(#[from] rrn_ledger::Error),
    /// A stored snapshot's bytes were not a decodable profile — a corrupted cache
    /// row (the log remains canonical; the snapshot can be recomputed).
    #[error("decoding a cached snapshot: {0}")]
    Decode(#[from] rrn_crypto::serialize::SerializeError),
}

/// Result specialized to this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
