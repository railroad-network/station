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
//! - [`tier`] — the oracle tier ladder (Overview §4.3): a pure function from a
//!   transaction's amount to the scrutiny it needs (Tier 1 settlement-window
//!   only vs. Tier 2 reputation stake + dispute window), plus the opt-up rules.
//! - [`contract`] — the [`contract::ContractCharge`], a second station-signed
//!   balance record: the per-period direct debit a recurring service contract
//!   executes (T1.7.7), a sibling of the settlement record.
//! - [`credit`] — the debt floor (ADR-0018): the engine refuses a debit whose
//!   signer would be committed below a bounded negative balance, counting both
//!   the settled balance and every pending debit they have already signed.
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

pub mod contract;
pub mod credit;
pub mod dispute;
pub mod engine;
pub mod settlement;
pub mod state;
pub mod tier;
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
    /// The proposal's `proposed_at` — or a confirmation's `confirmed_at` — is
    /// too far in the future to be plausible, even allowing for clock skew. Under
    /// the admission clock (ADR-0022 §3) future-dating is the *only* freshness
    /// bound that survives: a record from the future is a forgery or a broken
    /// clock, but an arbitrarily *old* one is legal — old means carried.
    #[error("record is dated too far in the future (beyond clock-skew tolerance)")]
    FutureDated,
    /// The proposal (or confirmation) is past its `expires_at`, allowing for
    /// clock skew. Judged by the admission clock alone (ADR-0022 §4).
    #[error("proposal has expired")]
    Expired,
    /// A party-asserted timestamp is internally inconsistent with the record it
    /// belongs to: a confirmation's `confirmed_at` claims to predate its own
    /// proposal's `proposed_at` (beyond clock-skew tolerance). Under the
    /// admission clock old timestamps are legal — old means carried — but a
    /// confirmation cannot have happened before the proposal it confirms
    /// (ADR-0022 §3). Supersedes the ADR-0019 staleness refusal.
    #[error(
        "confirmation timestamp {confirmed_at} predates its proposal's \
         proposed_at {proposed_at} (beyond clock-skew tolerance)"
    )]
    InconsistentTimestamp {
        /// The confirmation's claimed `confirmed_at`.
        confirmed_at: i64,
        /// The proposal's `proposed_at`, which the confirmation cannot precede.
        proposed_at: i64,
    },
    /// The proposal's window is degenerate: `proposed_at` is after `expires_at`.
    #[error("proposal window is invalid: proposed_at is after expires_at")]
    InvalidWindow,
    /// The transaction's amount (or opt-up) puts it at an oracle tier Phase 1
    /// cannot service — Tier 3+ needs artifact evidence, community witnesses, or
    /// cross-community validation, none of which exist yet. Rejected rather than
    /// serviced at a lower tier, so a large transaction is never quietly stripped
    /// of the scrutiny its value demands (Overview §4.3; see [`tier`]).
    #[error("oracle tier {tier} is not supported in Phase 1 (max {max}); transaction too large")]
    TierNotSupported {
        /// The effective tier the transaction required.
        tier: u8,
        /// The highest tier Phase 1 can service ([`tier::MAX_PHASE1_TIER`]).
        max: u8,
    },
    /// Signing this debit would take the member's projected balance — settled
    /// balance minus every pending debit they have already signed — below the
    /// community's debt floor. Mutual credit runs on negative balances, but not
    /// unbounded ones: the floor caps what a member can owe the community when
    /// they stop participating (ADR-0018; see [`credit`]).
    #[error(
        "debt floor exceeded: this debit would take the projected balance to \
         {projected_centi} centicommons, below the floor of {floor_centi}"
    )]
    DebtFloorExceeded {
        /// The configured floor, in centicommons (≤ 0).
        floor_centi: i64,
        /// The balance the member would be committed to if this debit were
        /// accepted, in centicommons.
        projected_centi: i64,
    },
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
    /// The transaction is not in `Disputed` state, so a dispute resolution
    /// cannot be applied to it.
    #[error("transaction is not in the Disputed state")]
    NotDisputed,
    /// The dispute raiser is neither the sender nor the receiver of the disputed
    /// transaction; only a party may contest it.
    #[error("dispute raiser is not a party to the transaction")]
    NotAParty,
    /// The dispute was opened outside the transaction's settlement window — too
    /// early (before it confirmed) or too late (after it should have settled).
    #[error("dispute opened outside the transaction's settlement window")]
    DisputeWindowClosed,
    /// The dispute's free-text reason (or a response's statement) exceeds
    /// [`MAX_DISPUTE_REASON_BYTES`](dispute::MAX_DISPUTE_REASON_BYTES).
    #[error("dispute reason exceeds the maximum length")]
    DisputeReasonTooLong,
    /// The responder has already filed a response to this dispute; a party may
    /// respond at most once (bounds log growth from a frozen transaction).
    #[error("this party has already responded to the dispute")]
    AlreadyResponded,
    /// A derived [`state::TransactionState`] failed its internal integrity check
    /// (e.g. an embedded signature did not verify).
    #[error("invalid transaction state: {0}")]
    Invalid(String),
}

/// Convenience alias for ledger results.
pub type Result<T> = std::result::Result<T, Error>;
