//! Marketplace for Railroad Network — where members offer and find goods and
//! services denominated in the Common.
//!
//! This crate turns the mutual-credit ledger into a place people actually
//! transact: a member publishes a signed [`listing`] (an offer of a good or
//! service), other members raise an [`inquiry`] against it, and [`search`]
//! makes the set of open listings discoverable. Demand is stated as well as
//! supply — a [`need`] is a member saying what they are looking for, matched
//! against the offers already standing. A listing that leads to a completed sale
//! is settled as an ordinary transaction on `rrn-ledger`, so the marketplace
//! adds discovery and intent on top of the ledger rather than a second money
//! path.
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
//! [`listing`], [`lifecycle`], [`search`], and [`need`] are implemented
//! (T1.6.3–T1.6.7). [`inquiry`] is still the T1.6.2 placeholder and is filled in
//! by M1.7, which is where a buyer's approach to a provider gets a UI to arrive
//! from.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod inquiry;
pub mod lifecycle;
pub mod listing;
pub mod need;
pub mod search;

/// Anything that can go wrong in the marketplace.
///
/// The two policy variants are worth telling apart: [`Listing`](Error::Listing)
/// means a listing's own contents broke a rule, while
/// [`Lifecycle`](Error::Lifecycle) means the contents were fine but the writer
/// was not entitled to write them.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A failure reading or appending to the log.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
    /// A listing that breaks one of its own validation rules (ADR-0010).
    #[error("invalid listing: {0}")]
    Listing(#[from] listing::ListingError),
    /// A lifecycle record nobody was entitled to write, or that has nothing to
    /// act on.
    #[error("listing lifecycle: {0}")]
    Lifecycle(#[from] lifecycle::LifecycleError),
    /// A need that breaks its own rules, or that nobody was entitled to
    /// announce.
    #[error("need: {0}")]
    Need(#[from] need::NeedError),
    /// The full-text index could not be opened, written, or queried.
    #[error("search index: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
    /// The derived index is unusable for a reason of our own making — a corrupt
    /// stored row, an unreadable index directory, a query that would not parse.
    /// Distinct from [`Tantivy`](Error::Tantivy), which is the library
    /// reporting its own trouble.
    ///
    /// Never fatal to the log: both indexes are caches, and a rebuild
    /// ([`search::SearchIndex::rebuild`]) is always available (ADR-0010).
    #[error("index: {0}")]
    Index(String),
}

/// Result specialized to this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
