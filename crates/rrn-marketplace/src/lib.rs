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
//! # The log is canonical; the indexes are caches
//!
//! Per [ADR-0010](../../../docs/adr/0010-marketplace-data-model.md), a listing
//! is a *signed record on the append-only log*, and
//! its lifecycle ([`lifecycle`]) is derived by replaying that log — the same
//! posture transaction state and reputation already have. The materialized
//! table and the full-text index that [`search`] queries are rebuildable views
//! and are authoritative over nothing; deleting the full-text index is always a
//! safe repair.
//!
//! # Where it sits in the stack
//!
//! It depends on `rrn-crypto` (signed, content-addressed listings),
//! `rrn-storage` (the append-only log listings and inquiries are recorded in),
//! `rrn-identity` (listers and inquirers are identities; a listing is an
//! authored attestation), `rrn-ledger` (a sale settles as a mutual-credit
//! transaction), and `rrn-reputation` (provider standing ranks results and
//! bounds what a listing may demand of a buyer). The dependency arrows point up
//! the stack — nothing lower depends on this crate, which is why appending a
//! listing is a helper *here* over `AppendLog::append` rather than a method on
//! `rrn-storage`.
//!
//! Phase 1 skeleton (T1.6.2). The modules below are placeholders shaped to
//! ADR-0010; each is filled in by its own later M1.6 task.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod inquiry;
pub mod lifecycle;
pub mod listing;
pub mod search;
