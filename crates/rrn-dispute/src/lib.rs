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
//! The optional escalation/appeal path (ADR-0014 §5) layers on top: when the jury
//! cannot seat a panel, or a party contests its ruling, [`escalation`] puts the
//! question to the whole established-member electorate on a bounded sub-window that
//! also fails open.

pub mod escalation;
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

/// How long a jury ruling's enactment is held so a party may appeal it to the
/// electorate (ADR-0014 §5). A dispute nobody appeals waits this out, then enacts.
pub const DEFAULT_APPEAL_WINDOW_SECONDS: i64 = 2 * 24 * 3600;

/// How long an escalation vote runs before it fails open. A sub-window inside the
/// overall resolution window, which remains the hard outer bound.
pub const DEFAULT_ESCALATION_WINDOW_SECONDS: i64 = 5 * 24 * 3600;

/// Default share of the electorate that must turn out for an escalation to reach
/// quorum, mirroring the governance statute quorum.
pub const DEFAULT_ESCALATION_QUORUM_PCT: u8 = 30;

/// Default share of decisive escalation ballots that must uphold for the dispute to
/// be upheld; below it, the dispute is rejected and the transaction settles.
pub const DEFAULT_ESCALATION_APPROVAL_PCT: u8 = 50;

/// Tunable dispute-resolution parameters. Fixed for uniform Phase-1 behavior
/// (ADR-0014 says panel size and windows are not governance-tunable yet); a
/// demo/test collapses the windows so a resolution fires promptly.
#[derive(Clone, Copy, Debug)]
pub struct DisputeParams {
    /// The overall window a dispute freezes settlement for. Past it, an
    /// unresolved dispute lapses and the transaction settles as confirmed. This is
    /// the hard outer bound: every appeal and escalation deadline is clamped to it.
    pub window_seconds: i64,
    /// A single juror's response deadline, measured from when they were seated.
    pub juror_response_seconds: i64,
    /// The number of jurors on a panel.
    pub panel_size: usize,
    /// How long a jury ruling's enactment is held so a party may appeal it. Zero
    /// enacts a ruling immediately (the single-round test/demo behaviour).
    pub appeal_window_seconds: i64,
    /// How long an escalation vote runs before it fails open, clamped to the
    /// overall window.
    pub escalation_window_seconds: i64,
    /// Share of the electorate that must turn out for an escalation quorum.
    pub escalation_quorum_pct: u8,
    /// Share of decisive escalation ballots that must uphold for the dispute to be
    /// upheld.
    pub escalation_approval_pct: u8,
}

impl Default for DisputeParams {
    fn default() -> Self {
        Self {
            window_seconds: DEFAULT_DISPUTE_WINDOW_SECONDS,
            juror_response_seconds: DEFAULT_JUROR_RESPONSE_SECONDS,
            panel_size: PANEL_SIZE,
            appeal_window_seconds: DEFAULT_APPEAL_WINDOW_SECONDS,
            escalation_window_seconds: DEFAULT_ESCALATION_WINDOW_SECONDS,
            escalation_quorum_pct: DEFAULT_ESCALATION_QUORUM_PCT,
            escalation_approval_pct: DEFAULT_ESCALATION_APPROVAL_PCT,
        }
    }
}

impl DisputeParams {
    /// A config whose juror deadline equals its overall window `secs`, panel size is
    /// the default, and appeal/escalation windows are zero — the test/demo knob for
    /// a single-round jury with no redraw and no appeal delay.
    pub fn uniform(secs: i64) -> Self {
        Self {
            window_seconds: secs,
            juror_response_seconds: secs,
            panel_size: PANEL_SIZE,
            appeal_window_seconds: 0,
            escalation_window_seconds: secs,
            escalation_quorum_pct: DEFAULT_ESCALATION_QUORUM_PCT,
            escalation_approval_pct: DEFAULT_ESCALATION_APPROVAL_PCT,
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
    /// A `Disputed` transaction is missing its dispute admission-clock reading
    /// (ADR-0022) — a corrupt or partially-replayed log. The draw and resolution
    /// window key on the admitted time and refuse to fall back to the party's
    /// signed `opened_at`.
    #[error("disputed transaction is missing its admission-clock reading")]
    MissingAdmission,
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
    /// An escalation record's signature did not verify, its signer is not the named
    /// initiator, or the initiator is not a party to the disputed transaction.
    #[error("escalation signature is invalid, or the initiator is not a party")]
    BadEscalation,
    /// An escalation ballot's signature did not verify, or its signer is not the
    /// named voter.
    #[error("escalation ballot signature is invalid or does not match the named voter")]
    BadBallot,
    /// The escalation's reason does not match the dispute's state — an appeal with
    /// no jury ruling or outside the appeal window, or a cannot-seat escalation
    /// when the pool can in fact seat a panel.
    #[error("the dispute cannot be escalated for the stated reason right now")]
    NotEscalatable,
    /// The dispute has already been escalated; a dispute escalates at most once.
    #[error("this dispute has already been escalated")]
    AlreadyEscalated,
    /// The voter is not an established, non-party member of the escalation
    /// electorate as of the escalation's open time.
    #[error("voter is not eligible to vote in this escalation")]
    NotEligible,
    /// There is no open escalation on this dispute to vote in.
    #[error("this dispute has not been escalated")]
    NotEscalated,
}

/// Convenience alias for dispute results.
pub type Result<T> = std::result::Result<T, Error>;
