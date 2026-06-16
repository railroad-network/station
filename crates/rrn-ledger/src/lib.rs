//! Ledger and transaction engine for Railroad Network.
//!
//! This crate is the load-bearing core of Phase 0: it turns two signatures (a
//! sender's and a receiver's) plus the passage of time into a balance change,
//! recorded immutably. The pieces:
//!
//! - [`transaction`] — the canonical, content-addressed [`transaction::TransactionProposal`]
//!   and [`transaction::TransactionConfirmation`] records, each signed via
//!   [`rrn_crypto::signed::SignedPayload`].
//! - [`state`] — the [`state::TransactionState`] lifecycle
//!   (`Proposed → Confirmed → Settled` / `Cancelled`) and the rules for which
//!   transitions are legal. State is *derived from the log*, never the reverse.
//! - [`settlement`] — the [`settlement::Settler`], which sweeps confirmed
//!   transactions whose settlement window has elapsed and moves the Commons,
//!   plus [`settlement::BalanceView`] for reading materialized balances.
//! - [`engine`] — the [`engine::Engine`] front door: submit a proposal, submit a
//!   confirmation, cancel, or query state, with nonce + timestamp replay
//!   protection.
//!
//! # The log is the source of truth
//!
//! Every lifecycle transition appends a signed entry to
//! [`rrn_storage::log`]'s append-only, hash-chained log. The current
//! [`state::TransactionState`] of any transaction is *derived* by replaying
//! those entries (see [`state::LedgerSnapshot`]); the materialized `balances`
//! table (a PN-Counter per identity) is likewise derivable from the settlement
//! entries. If derived state and the log ever disagree, the log wins.
//!
//! # Who signs a settlement
//!
//! A proposal is signed by the sender and a confirmation by the receiver — but
//! settlement is *automatic* after the window elapses, so no transacting party
//! is present to sign it. The local **station** (the running software, which
//! owns a keypair) signs settlement and cancellation records with its own key.
//! This is why [`engine::Engine`] and [`settlement::Settler`] are constructed
//! with a station [`rrn_crypto::keypair::Keypair`], which the task spec's
//! sketches omitted (they predate the realization that the log only accepts
//! *signed* entries). The station key also identifies this replica for the
//! per-replica PN-Counter. See ADR-0005.
//!
//! # Time is injected
//!
//! No ledger code reads the system clock. Every operation that depends on "now"
//! takes `now: i64` (Unix seconds) as a parameter, so tests fast-forward across
//! settlement windows without sleeping.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod engine;
pub mod settlement;
pub mod state;
pub mod transaction;

/// Errors from the ledger and transaction engine.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error from the underlying storage layer (database, log).
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
    /// A presented signature did not verify against its claimed signer.
    #[error("signature verification failed")]
    BadSignature,
    /// A proposal's signer is not the sender it names — only the sender may
    /// propose a transaction that debits the sender.
    #[error("proposal signer does not match the named sender")]
    SenderMismatch,
    /// A confirmation was not signed by, or does not name, the proposal's
    /// receiver — only the receiver may confirm.
    #[error("confirmer does not match the proposal's receiver")]
    ConfirmerMismatch,
    /// A proposal with this id is already in the log; replaying it is rejected.
    #[error("duplicate proposal (already in the log)")]
    DuplicateProposal,
    /// The proposal's nonce is out of order for its sender (a gap or a
    /// duplicate) — either a bug or a replay/reorder attack.
    #[error("bad nonce for sender: expected {expected}, got {got}")]
    BadNonce {
        /// The next nonce the sender was expected to use.
        expected: u64,
        /// The nonce actually presented.
        got: u64,
    },
    /// The proposal's `proposed_at` is too far in the future to be plausible,
    /// even allowing for clock skew.
    #[error("proposal is dated too far in the future (beyond clock-skew tolerance)")]
    FutureDated,
    /// The proposal (or confirmation) is past its `expires_at`, allowing for
    /// clock skew.
    #[error("proposal has expired")]
    Expired,
    /// The proposal's window is degenerate: `proposed_at` is after `expires_at`.
    #[error("proposal window is invalid: proposed_at is after expires_at")]
    InvalidWindow,
    /// No transaction with the given id exists in the log.
    #[error("transaction not found")]
    UnknownTransaction,
    /// The transaction is not in `Proposed` state, so it cannot be confirmed or
    /// cancelled.
    #[error("transaction is not in the Proposed state")]
    NotProposed,
    /// The transaction is not in `Confirmed` state, so it cannot be settled.
    #[error("transaction is not in the Confirmed state")]
    NotConfirmed,
    /// A derived [`state::TransactionState`] failed its internal integrity check
    /// (e.g. an embedded signature did not verify).
    #[error("invalid transaction state: {0}")]
    Invalid(String),
}

/// Convenience alias for ledger results.
pub type Result<T> = std::result::Result<T, Error>;
