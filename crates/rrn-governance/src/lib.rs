//! Governance for Railroad Network — how a community makes binding collective
//! decisions.
//!
//! A community's constitution is its [`charter`]: a multisig-signed, canonically
//! hashed document that fixes the governance parameters everything else keys
//! off. Within those parameters a member raises a [`proposal`] — a [`statute`],
//! an administrative rule, or a Charter amendment; eligible members cast a signed
//! [`vote`] on it; a [`tally`] reduces the ballots to an outcome; and the
//! [`lifecycle`] carries a passed proposal through its deliberation and
//! implementation-delay windows. Every Charter, proposal, and ballot is a signed,
//! content-addressed log entry, so a tally is independently re-derivable and a
//! result is auditable rather than announced.
//!
//! The defining rule is one member, one vote in direct voting. Phase 1 defines a
//! *member*, for both eligibility and the quorum denominator, as an **established
//! member** — one whose effective (anchored) composite reputation is at or above
//! the Member band (ADR-0012). That is what keeps a community from being captured:
//! a flood of fresh or Sybil identities carries no governance weight until it has
//! earned standing.
//!
//! # Where it sits in the stack
//!
//! It depends on `rrn-crypto` (multisig-signed, canonical documents and ballots),
//! `rrn-storage` (the log they are recorded in), `rrn-identity` (the founders and
//! members that sign), and `rrn-reputation` (the established-member electorate).
//! It deliberately does *not* depend on `rrn-ledger`: governance decides policy,
//! it does not move credit. The dependency arrows point up the stack.
//!
//! Phase 1 (M1.9): the Charter, statutes, and **direct voting only**. The other
//! voting mechanisms of the design overview are Phase 2+ (ADR-0012). The modules
//! below are filled in by the tasks that follow T1.9.2.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod charter;
pub mod lifecycle;
pub mod proposal;
pub mod statute;
pub mod tally;
pub mod vote;
