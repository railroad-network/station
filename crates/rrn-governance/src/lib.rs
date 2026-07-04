//! Governance for Railroad Network — how a community makes binding collective
//! decisions.
//!
//! A member raises a [`proposal`]; eligible members cast a signed [`vote`] on
//! it; a [`tally`] reduces the ballots to an outcome. The defining rule is
//! one member, one vote in direct voting — vote weight is a property of a
//! vouched identity, not of stake or reputation, which is what keeps a
//! community from being bought. Every proposal and ballot is a signed,
//! content-addressed log entry, so a tally is independently re-derivable and a
//! result is auditable rather than announced.
//!
//! # Where it sits in the stack
//!
//! It depends on `rrn-crypto` (signed, canonical ballots), `rrn-storage` (the
//! log proposals and votes are recorded in), and `rrn-identity` (eligibility
//! and one-member-one-vote weighting). It deliberately does *not* depend on
//! `rrn-ledger`: governance decides policy, it does not move credit. The
//! dependency arrows point up the stack.
//!
//! Phase 1 scaffold (M1.0). The modules below are placeholders; each is filled
//! in by its own later M1 task.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod proposal;
pub mod tally;
pub mod vote;
