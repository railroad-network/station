//! Appending a juror's verdict, opening an escalation, casting an escalation
//! ballot, and enacting (or lapsing) a dispute.
//!
//! [`append_verdict`] is the jury write gate: it accepts a signed verdict only from
//! a juror who holds a live seat as of the moment they cast it. [`open_escalation`]
//! and [`append_escalation_ballot`] are the escalation write gates (ADR-0014 §5): a
//! party opens an escalation when the jury cannot seat a panel or to appeal its
//! ruling, and established members vote on it. [`resolve`] is the read-then-enact
//! sweep: it recomputes the jury panel and, layered on top, any escalation, and on
//! a terminal outcome calls the ledger primitive that closes the freeze —
//! [`Engine::uphold_dispute`](rrn_ledger::engine::Engine::uphold_dispute) to void the
//! transfer, or [`Settler::settle`](rrn_ledger::settlement::Settler::settle) to let
//! it settle. Every path is bounded by the resolution window and fails open: an
//! unresolved dispute **lapses** and settles as confirmed (ADR-0014 §5).

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{SettlementConfig, Settler};
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::escalation::{
    count_escalation, escalation_ballots, escalation_electorate, escalation_of, EscalationReason,
    EscalationRecord, SignedEscalation, SignedEscalationBallot,
};
use crate::panel::{resolve_panel, ruling_reached_at, tally, DisputeOutcome};
use crate::sortition::{disputed_info, draw_sequence, eligible_pool, sortition_seed, DisputedInfo};
use crate::verdict::{verdicts, SignedVerdict};
use crate::{DisputeParams, Error, Result};

/// The state of a dispute after a [`resolve`] pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// No majority yet and the window is still open — the jury is still sitting.
    Pending,
    /// A majority upheld the dispute; the transfer was voided this pass.
    Upheld,
    /// A majority rejected the dispute; the transaction was settled this pass.
    Rejected,
    /// The window closed with no majority; the dispute lapsed and the transaction
    /// was settled as confirmed (fail open).
    Lapsed,
    /// The jury reached a ruling, but its appeal window is still open — enactment is
    /// suspended in case a party escalates it to the electorate.
    AwaitingAppeal,
    /// An escalation vote is open; the electorate has not yet been tallied.
    EscalationPending,
    /// The electorate upheld the dispute; the transfer was voided this pass.
    EscalationUpheld,
    /// The electorate rejected the dispute; the transaction was settled this pass.
    EscalationRejected,
    /// The escalation window closed without quorum; the dispute lapsed and the
    /// transaction settled as confirmed (fail open).
    EscalationLapsed,
}

/// Every transaction currently in the `Disputed` state — the set a resolution
/// sweep iterates.
pub fn find_disputed(db: &Database) -> Result<Vec<TransactionId>> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db))?;
    Ok(snapshot
        .iter()
        .filter_map(|(id, state)| matches!(state, TransactionState::Disputed { .. }).then_some(*id))
        .collect())
}

/// Records a juror's signed verdict, after checking they hold a live seat.
///
/// Errors — without writing — on a bad signature or signer/juror mismatch, a
/// transaction that is not disputed, a second verdict from the same juror, a
/// verdict cast after the resolution window closed, or a juror who does not occupy
/// a live seat as of their `cast_at` (never drawn, already redrawn around, or past
/// their own response deadline).
pub fn append_verdict(
    db: &Database,
    founders: &[Address],
    params: &DisputeParams,
    anchor: &[u8],
    verdict: SignedVerdict,
    now: i64,
) -> Result<()> {
    verdict.verify().map_err(|_| Error::BadVerdict)?;
    // These are all `Copy`; take them out so the verdict can be moved into the log
    // at the end without holding a borrow.
    let (proposal_id, juror, uphold, cast_at) = (
        verdict.payload.proposal_id,
        verdict.payload.juror,
        verdict.payload.uphold,
        verdict.payload.cast_at,
    );
    if &verdict.signer != juror.public_key() {
        return Err(Error::BadVerdict);
    }

    let info = disputed_info(db, &proposal_id)?;
    // A verdict cannot predate the dispute, be dated into the future, or land
    // after the resolution window has closed (the dispute is lapsing by then).
    if cast_at < info.opened_at
        || cast_at > now
        || cast_at > info.opened_at.saturating_add(params.window_seconds)
    {
        return Err(Error::NotSeated);
    }

    let existing = verdicts(db, &proposal_id)?;
    if existing.contains_key(&juror) {
        return Err(Error::AlreadyVoted);
    }

    // Re-derive the panel as of the verdict's own instant. The juror must occupy a
    // seat that is still awaiting a verdict then — which also proves they are
    // within their response window (a lapsed occupant would have been redrawn).
    let pool = eligible_pool(db, founders, &info, info.opened_at, params)?;
    let sequence = draw_sequence(&pool, sortition_seed(&proposal_id, anchor));
    let panel = resolve_panel(&sequence, &existing, info.opened_at, params, cast_at);
    match panel.seat_of(&juror) {
        Some(seat) if seat.verdict.is_none() => {}
        _ => return Err(Error::NotSeated),
    }

    AppendLog::new(db).append(verdict, now)?;
    tracing::info!(tx = ?proposal_id, ?juror, uphold, "verdict recorded");
    Ok(())
}

/// Opens an escalation: a party puts the dispute to the established-member
/// electorate because the jury cannot seat a panel, or to appeal its ruling
/// (ADR-0014 §5).
///
/// Errors — without writing — on a bad signature, a signer who is not the named
/// initiator, or an initiator who is not a party ([`Error::BadEscalation`]); a
/// transaction that is not disputed ([`Error::NotDisputed`]); a dispute already
/// escalated ([`Error::AlreadyEscalated`]); or a reason that does not match the
/// dispute's state — an appeal without a live jury ruling in its appeal window, or a
/// cannot-seat escalation when the pool can in fact seat a panel
/// ([`Error::NotEscalatable`]).
pub fn open_escalation(
    db: &Database,
    founders: &[Address],
    params: &DisputeParams,
    anchor: &[u8],
    escalation: SignedEscalation,
    now: i64,
) -> Result<()> {
    escalation.verify().map_err(|_| Error::BadEscalation)?;
    let record = escalation.payload.clone();
    if &escalation.signer != record.initiator.public_key() {
        return Err(Error::BadEscalation);
    }

    let info = disputed_info(db, &record.proposal_id)?;
    if record.initiator != info.sender && record.initiator != info.receiver {
        return Err(Error::BadEscalation);
    }
    if escalation_of(db, &record.proposal_id)?.is_some() {
        return Err(Error::AlreadyEscalated);
    }
    // Applicability is judged at the admission instant — this record is about to be
    // appended at `now`, so `now` *is* its admission time (ADR-0022 §5). The signed
    // `opened_at` is testimony and enters no window arithmetic; a future-dated one is
    // still rejected as plainly bogus, but that is input hygiene, not a freshness
    // floor (ADR-0022 drops the floor: an old `opened_at` may be legitimately carried).
    if record.opened_at > now {
        return Err(Error::NotEscalatable);
    }

    let jury = jury_view(
        db,
        founders,
        &record.proposal_id,
        &info,
        params,
        anchor,
        now,
    )?;
    if !escalation_applies(&record, now, &info, &jury, params) {
        return Err(Error::NotEscalatable);
    }

    AppendLog::new(db).append(escalation, now)?;
    tracing::info!(tx = ?record.proposal_id, reason = ?record.reason, "escalation opened");
    Ok(())
}

/// Records an established member's signed ballot in an open escalation.
///
/// Errors — without writing — on a bad signature or signer/voter mismatch
/// ([`Error::BadBallot`]); a transaction that is not disputed
/// ([`Error::NotDisputed`]); no open escalation ([`Error::NotEscalated`]); a voter
/// who is not in the escalation electorate or a ballot cast outside the escalation
/// window ([`Error::NotEligible`]); or a second ballot from the same voter
/// ([`Error::AlreadyVoted`]).
pub fn append_escalation_ballot(
    db: &Database,
    founders: &[Address],
    params: &DisputeParams,
    ballot: SignedEscalationBallot,
    now: i64,
) -> Result<()> {
    ballot.verify().map_err(|_| Error::BadBallot)?;
    let (proposal_id, voter, cast_at) = (
        ballot.payload.proposal_id,
        ballot.payload.voter,
        ballot.payload.cast_at,
    );
    if &ballot.signer != voter.public_key() {
        return Err(Error::BadBallot);
    }

    let info = disputed_info(db, &proposal_id)?;
    let (_escalation, esc_admitted_at) =
        escalation_of(db, &proposal_id)?.ok_or(Error::NotEscalated)?;
    let close = escalation_close(esc_admitted_at, &info, params);

    let electorate = escalation_electorate(db, founders, &info, esc_admitted_at)?;
    if !electorate.contains(&voter) || cast_at < esc_admitted_at || cast_at > close || cast_at > now
    {
        return Err(Error::NotEligible);
    }

    if escalation_ballots(db, &proposal_id)?.contains_key(&voter) {
        return Err(Error::AlreadyVoted);
    }

    AppendLog::new(db).append(ballot, now)?;
    tracing::info!(tx = ?proposal_id, ?voter, "escalation ballot recorded");
    Ok(())
}

/// Recomputes a dispute's jury panel and any escalation, and enacts a terminal
/// outcome, holds a ruling in its appeal window, or lets the dispute lapse once its
/// window has closed. Idempotent in effect: enacting an outcome moves the
/// transaction out of `Disputed`, so a later call finds it no longer disputed.
///
/// `station` signs the settlement or void record; `anchor` is the community value
/// mixed into the sortition seed (see [`sortition_seed`]).
pub fn resolve(
    db: &Database,
    founders: &[Address],
    station: &Keypair,
    tx_id: &TransactionId,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Resolution> {
    let outcome = decide(db, founders, tx_id, params, anchor, now)?;
    enact_resolution(db, station, tx_id, outcome, now)?;
    Ok(outcome)
}

/// What a [`resolve`] pass *would* return right now, without touching the ledger —
/// the read-only twin the dispute views render. Same derivation, no enactment.
pub fn preview(
    db: &Database,
    founders: &[Address],
    tx_id: &TransactionId,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Resolution> {
    decide(db, founders, tx_id, params, anchor, now)
}

/// The pure decision: derives the jury and any escalation and reduces them to the
/// [`Resolution`] a pass would produce. Writes nothing — [`resolve`] enacts the
/// terminal ones, [`preview`] just reports them.
fn decide(
    db: &Database,
    founders: &[Address],
    tx_id: &TransactionId,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Resolution> {
    let info = disputed_info(db, tx_id)?;
    let main_close = info.opened_at.saturating_add(params.window_seconds);
    let jury = jury_view(db, founders, tx_id, &info, params, anchor, now)?;

    // A validly-opened escalation governs the outcome; a bogus or inapplicable one
    // is ignored, and the jury path resumes.
    if let Some((escalation, esc_admitted_at)) = escalation_of(db, tx_id)? {
        let by_party = escalation.initiator == info.sender || escalation.initiator == info.receiver;
        if by_party && escalation_applies(&escalation, esc_admitted_at, &info, &jury, params) {
            return decide_escalation(db, founders, tx_id, &info, esc_admitted_at, params, now);
        }
    }

    match jury.outcome {
        Some(outcome) => {
            // A ruling is not enacted until its appeal window closes, giving a party
            // the chance to escalate it — bounded, like everything, by the main
            // window.
            let appeal_deadline = jury
                .ruled_at
                .expect("a terminal tally has a ruling time")
                .saturating_add(params.appeal_window_seconds)
                .min(main_close);
            if now <= appeal_deadline {
                Ok(Resolution::AwaitingAppeal)
            } else {
                Ok(match outcome {
                    DisputeOutcome::Upheld => Resolution::Upheld,
                    DisputeOutcome::Rejected => Resolution::Rejected,
                })
            }
        }
        None if now >= main_close => Ok(Resolution::Lapsed),
        None => Ok(Resolution::Pending),
    }
}

/// The jury as of a given instant — the shared view [`resolve`] and
/// [`open_escalation`] both key off: the tallied outcome (if a majority has formed),
/// when that ruling formed, the eligible-pool size, and the majority threshold.
struct JuryView {
    /// The tallied outcome, once a majority of seated jurors agree.
    outcome: Option<DisputeOutcome>,
    /// When the ruling formed (the deciding verdict's instant), if it has.
    ruled_at: Option<i64>,
    /// How many members were eligible for the draw.
    pool_len: usize,
    /// Votes needed for a majority of the panel.
    majority: usize,
}

/// Derives the [`JuryView`] for a dispute as of `now`.
fn jury_view(
    db: &Database,
    founders: &[Address],
    tx_id: &TransactionId,
    info: &DisputedInfo,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<JuryView> {
    let pool = eligible_pool(db, founders, info, info.opened_at, params)?;
    let sequence = draw_sequence(&pool, sortition_seed(tx_id, anchor));
    let existing = verdicts(db, tx_id)?;
    let panel = resolve_panel(&sequence, &existing, info.opened_at, params, now);
    Ok(JuryView {
        outcome: tally(&panel, params),
        ruled_at: ruling_reached_at(&panel, &existing, params),
        pool_len: pool.len(),
        majority: params.panel_size / 2 + 1,
    })
}

/// Whether an escalation record is applicable given the dispute's state, judged at
/// the escalation's **admission time** (`admitted_at`), never the initiator's signed
/// `opened_at` (ADR-0022 §5). On the sole-writer station (ADR-0020) the admission
/// time is fixed in the log entry, so this stays deterministic on local replay.
fn escalation_applies(
    escalation: &EscalationRecord,
    admitted_at: i64,
    info: &DisputedInfo,
    jury: &JuryView,
    params: &DisputeParams,
) -> bool {
    let main_close = info.opened_at.saturating_add(params.window_seconds);
    match escalation.reason {
        // An appeal is valid only against a live jury ruling, and only inside that
        // ruling's appeal window.
        EscalationReason::Appeal => match (jury.outcome, jury.ruled_at) {
            (Some(_), Some(ruled_at)) => {
                let deadline = ruled_at
                    .saturating_add(params.appeal_window_seconds)
                    .min(main_close);
                admitted_at >= ruled_at && admitted_at <= deadline
            }
            _ => false,
        },
        // A cannot-seat escalation is valid only while the pool genuinely cannot
        // reach a majority, inside the overall window.
        EscalationReason::CannotSeat => {
            jury.pool_len < jury.majority
                && admitted_at >= info.opened_at
                && admitted_at <= main_close
        }
    }
}

/// Tallies an open escalation's electorate into the [`Resolution`] it implies:
/// pending while the sub-window is open, then upheld/rejected on a quorum, or lapsed
/// (fail open) once the window closes without one. Writes nothing.
fn decide_escalation(
    db: &Database,
    founders: &[Address],
    tx_id: &TransactionId,
    info: &DisputedInfo,
    admitted_at: i64,
    params: &DisputeParams,
    now: i64,
) -> Result<Resolution> {
    let close = escalation_close(admitted_at, info, params);
    if now < close {
        return Ok(Resolution::EscalationPending);
    }
    let electorate = escalation_electorate(db, founders, info, admitted_at)?;
    let ballots = escalation_ballots(db, tx_id)?;
    let tallied = count_escalation(&ballots, &electorate, params, admitted_at, close);
    Ok(match tallied.terminal_outcome() {
        Some(DisputeOutcome::Upheld) => Resolution::EscalationUpheld,
        Some(DisputeOutcome::Rejected) => Resolution::EscalationRejected,
        None => Resolution::EscalationLapsed,
    })
}

/// An escalation's effective close: its own sub-window, never past the dispute's
/// overall window — the hard outer bound that guarantees termination. Runs from the
/// escalation's admission time (`admitted_at`), never the signed `opened_at`
/// (ADR-0022 §5).
fn escalation_close(admitted_at: i64, info: &DisputedInfo, params: &DisputeParams) -> i64 {
    admitted_at
        .saturating_add(params.escalation_window_seconds)
        .min(info.opened_at.saturating_add(params.window_seconds))
}

/// Enacts a terminal [`Resolution`] through the ledger primitive that closes the
/// freeze — voiding the transfer (upheld) or settling it as confirmed
/// (rejected/lapsed). The non-terminal states (pending, awaiting appeal, escalation
/// pending) write nothing.
fn enact_resolution(
    db: &Database,
    station: &Keypair,
    tx_id: &TransactionId,
    outcome: Resolution,
    now: i64,
) -> Result<()> {
    match outcome {
        Resolution::Upheld | Resolution::EscalationUpheld => {
            Engine::new(db, station.clone()).uphold_dispute(tx_id, now)?;
            tracing::info!(tx = ?tx_id, ?outcome, "dispute upheld; transfer voided");
        }
        Resolution::Rejected
        | Resolution::Lapsed
        | Resolution::EscalationRejected
        | Resolution::EscalationLapsed => {
            settle_confirmed(db, station, tx_id, now)?;
            tracing::info!(tx = ?tx_id, ?outcome, "dispute closed; transaction settled");
        }
        Resolution::Pending | Resolution::AwaitingAppeal | Resolution::EscalationPending => {}
    }
    Ok(())
}

/// Settles a frozen (disputed) transaction as originally confirmed — the shared
/// enactment for a rejected or lapsed dispute. The settlement window config is
/// irrelevant here (the freeze already elapsed it), so a default suffices.
fn settle_confirmed(
    db: &Database,
    station: &Keypair,
    tx_id: &TransactionId,
    now: i64,
) -> Result<()> {
    Settler::new(db, station.clone(), SettlementConfig::default()).settle(tx_id, now)?;
    Ok(())
}
