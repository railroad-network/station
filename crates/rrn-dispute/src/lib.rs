//! Dispute resolution: a standing-weighted sortition jury over the ledger's
//! frozen `Disputed` state (ADR-0014).
//!
//! [`rrn-ledger`](rrn_ledger) laid the rail — a confirmed transaction a party
//! contests enters a real `Disputed` state and freezes, and the ledger exposes
//! the two primitives that close it: settle it (dispute rejected or lapsed) or
//! void it (dispute upheld). This crate is the machine that decides *which*, and
//! it decides by **sortition**: a jury of [`PANEL_SIZE`] members drawn from the
//! community by a deterministic, standing-weighted draw, majority rules, inside a
//! bounded window that fails open.
//!
//! # Everything derives from the log
//!
//! Nothing here is stored as mutable state. The eligible pool, the drawn
//! sequence, the seated panel, the tally, and the outcome are all *recomputed*
//! from the log on demand, exactly like a `LedgerSnapshot` or a governance tally.
//! The only new record a dispute writes is a juror's signed [`JurorVerdict`]; the
//! panel that juror sits on is derived, not appointed, so anyone replaying the log
//! recomputes the identical jury and can prove the station did not hand-pick it.
//!
//! # The pieces
//!
//! - [`sortition`] — the seed, the eligible pool (established members minus the
//!   parties and their vouchers), and the deterministic weighted draw.
//! - [`verdict`] — the signed juror verdict record and its replay.
//! - [`panel`] — seating the drawn jury, redrawing around a juror who goes
//!   silent past their deadline, and tallying a majority.
//! - [`resolution`] — appending a verdict (gated on a live seat) and the
//!   [`resolve`](resolution::resolve) sweep that enacts a terminal outcome, or
//!   lets an unresolved dispute lapse to the confirmed status quo.
//!
//! The optional governance escalation/appeal (ADR-0014 §5) reuses
//! `rrn-governance` and is not part of this first cut; the resolution seam is
//! shaped to accept it.

pub mod panel;
pub mod resolution;
pub mod sortition;
pub mod verdict;

pub use rrn_ledger::dispute::DEFAULT_DISPUTE_WINDOW_SECONDS;

/// The number of jurors on a panel: three, so a single bad or bought juror is
/// outvoted and a clean 2–1 still terminates (ADR-0014 §3).
pub const PANEL_SIZE: usize = 3;

/// How long a seated juror has to cast a verdict before they are a no-show and
/// the sortition redraws around them (ADR-0014 §4). Must be shorter than the
/// overall resolution window so several redraws can happen inside it.
pub const DEFAULT_JUROR_RESPONSE_SECONDS: i64 = 3 * 24 * 3600;

/// Tunable dispute-resolution parameters. Fixed for uniform Phase-1 behavior
/// (ADR-0014 says panel size and windows are not governance-tunable yet); a
/// demo/test collapses the windows so a resolution fires promptly.
#[derive(Clone, Copy, Debug)]
pub struct DisputeParams {
    /// The overall window a dispute freezes settlement for. Past it, an
    /// unresolved dispute lapses and the transaction settles as confirmed.
    pub window_seconds: i64,
    /// A single juror's response deadline, measured from when they were seated.
    pub juror_response_seconds: i64,
    /// The number of jurors on a panel.
    pub panel_size: usize,
}

impl Default for DisputeParams {
    fn default() -> Self {
        Self {
            window_seconds: DEFAULT_DISPUTE_WINDOW_SECONDS,
            juror_response_seconds: DEFAULT_JUROR_RESPONSE_SECONDS,
            panel_size: PANEL_SIZE,
        }
    }
}

impl DisputeParams {
    /// A config whose juror deadline equals its overall window `secs` and whose
    /// panel size is the default — the test/demo knob for a single-round jury with
    /// no redraw.
    pub fn uniform(secs: i64) -> Self {
        Self {
            window_seconds: secs,
            juror_response_seconds: secs,
            panel_size: PANEL_SIZE,
        }
    }
}

/// Errors from the dispute layer.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The underlying storage/log failed.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
    /// A ledger operation failed (deriving state, upholding, or settling).
    #[error("ledger: {0}")]
    Ledger(#[from] rrn_ledger::Error),
    /// A reputation query failed (scoring the eligible pool or a juror's weight).
    #[error("reputation: {0}")]
    Reputation(#[from] rrn_reputation::Error),
    /// The referenced transaction is not in the `Disputed` state, so there is no
    /// live dispute to seat a jury for or resolve.
    #[error("transaction is not in the Disputed state")]
    NotDisputed,
    /// A verdict's signature did not verify, or its signer is not the juror it
    /// names.
    #[error("verdict signature is invalid or does not match the named juror")]
    BadVerdict,
    /// The juror is not seated on the panel as of the verdict's timestamp — never
    /// drawn, already replaced as a no-show, or past their response deadline.
    #[error("juror does not hold a live seat on the panel")]
    NotSeated,
    /// The juror has already cast a verdict on this dispute; a verdict is final.
    #[error("juror has already voted on this dispute")]
    AlreadyVoted,
}

/// Convenience alias for dispute results.
pub type Result<T> = std::result::Result<T, Error>;
