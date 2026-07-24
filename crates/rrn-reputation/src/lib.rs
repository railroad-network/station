//! Reputation for Railroad Network — a member's standing, derived from what
//! they have done, not asserted about themselves.
//!
//! Reputation is not a stored number a member controls; it is [`score`]d from
//! evidence: settled transactions on the ledger and signed [`attestation`]s
//! from other members. Old evidence counts for less than recent evidence, so
//! [`decay`] applies a time weighting — standing has to be maintained, and a
//! long-dormant identity cannot bank reputation indefinitely. Because every
//! input is signed and content-addressed, a score is fully re-derivable from
//! the log rather than trusted as materialized state.
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
pub mod sybil;
