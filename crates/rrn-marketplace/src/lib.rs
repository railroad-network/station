//! Marketplace for Railroad Network — where members offer and find goods and
//! services denominated in the Common.
//!
//! This crate turns the mutual-credit ledger into a place people actually
//! transact: a member publishes a signed [`listing`] (an offer of a good or
//! service), other members raise an [`inquiry`] against it, and [`search`]
//! makes the set of open listings discoverable. A listing that leads to a
//! completed sale is settled as an ordinary transaction on `rrn-ledger`, so the
//! marketplace adds discovery and intent on top of the ledger rather than a
//! second money path.
//!
//! # Where it sits in the stack
//!
//! It depends on `rrn-crypto` (signed, content-addressed listings),
//! `rrn-storage` (the append-only log listings and inquiries are recorded in),
//! `rrn-identity` (listers and inquirers are identities; a listing is an
//! authored attestation), and `rrn-ledger` (a sale settles as a mutual-credit
//! transaction). The dependency arrows point up the stack — nothing lower
//! depends on this crate.
//!
//! Phase 1 scaffold (M1.0). The modules below are placeholders; each is filled
//! in by its own later M1 task.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod inquiry;
pub mod listing;
pub mod search;
