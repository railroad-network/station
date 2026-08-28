//! Member- and operator-facing dispute reads (T1.10.5).
//!
//! M1.10 built the dispute engine — the frozen `Disputed` state in
//! [`rrn_ledger`], and the sortition jury in [`rrn_dispute`] — but exposed none of
//! it to a reader. This module is that read path: it turns the log-derived dispute
//! state into the flat, JSON-shaped views the `rrn dispute` CLI prints and the
//! mobile renders, so a party can see a dispute's grievance and responses, and a
//! juror (or anyone) can see the seated panel, the verdicts so far, and where the
//! dispute stands.
//!
//! Everything here is derived from the log on demand — the eligible pool, the
//! drawn sequence, the seated panel, and the tally are all *recomputed*, exactly
//! as [`rrn_dispute::resolution::resolve`] recomputes them before it enacts. A
//! view is therefore a read-only snapshot at the `now` it is asked for: its
//! `resolution` field says what a resolve pass *would* do at that instant
//! (`upheld`/`rejected` once a majority lands, `lapsed` once the window closes),
//! not a stored outcome — an actually-resolved transaction has already left the
//! `Disputed` state and no longer appears here.

use serde::{Deserialize, Serialize};

use rrn_dispute::escalation::{
    count_escalation, escalation_ballots, escalation_electorate, escalation_of, EscalationReason,
};
use rrn_dispute::panel::resolve_panel;
use rrn_dispute::resolution::{preview, Resolution};
use rrn_dispute::sortition::{disputed_info, draw_sequence, eligible_pool, sortition_seed};
use rrn_dispute::verdict::verdicts;
use rrn_dispute::DisputeParams;
use rrn_identity::address::Address;
use rrn_ledger::dispute::dispute_responses;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// A dispute as a browse row: the contested transaction, its parties, the
/// grievance, the window it is frozen for, and where it stands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisputeSummary {
    /// The disputed transaction's id, hex-encoded.
    pub tx_id: String,
    /// The transaction's sender `rrn1…` address.
    pub sender: String,
    /// The transaction's receiver (also the confirmer under contest).
    pub receiver: String,
    /// The party who raised the dispute.
    pub raiser: String,
    /// The grievance, free text (bounded).
    pub reason: String,
    /// The opening evidence hash, hex — present when the raiser attached one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    /// Unix seconds the dispute was opened — the start of its window.
    pub opened_at: i64,
    /// Unix seconds the resolution window closes; past it, an unresolved dispute
    /// lapses to the confirmed status quo.
    pub window_ends_at: i64,
    /// The seated jury's counts so far and the outcome a resolve pass would enact.
    pub tally: DisputeTallyView,
    /// The outcome a resolve pass would enact right now: `pending` (jury out, window
    /// open), `awaiting_appeal` (jury ruled, appeal window open), `upheld`,
    /// `rejected`, `lapsed` (window closed, no majority), or the `escalation_*`
    /// variants once a party has put the dispute to the electorate.
    pub resolution: String,
}

/// One dispute in full: the summary, the parties' responses, and the seated jury.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisputeDetail {
    /// The browse-row fields.
    #[serde(flatten)]
    pub summary: DisputeSummary,
    /// The responses each party filed, in the order they were made.
    pub responses: Vec<ResponseView>,
    /// The jury as seated right now: the occupied seats, each juror with their
    /// verdict if they have cast one.
    pub panel: Vec<PanelSeatView>,
    /// How many members were eligible for the draw (the pool the jury was seated
    /// from). A pool short of the panel size is why a jury may sit unfilled.
    pub eligible_pool_size: u32,
    /// The escalation to the electorate, if a party has opened one (ADR-0014 §5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalation: Option<EscalationView>,
}

/// An open escalation vote: why it was opened, its window, and the electorate's
/// ballots so far.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EscalationView {
    /// Why it was opened: `appeal` (of a jury ruling) or `cannot_seat` (the jury
    /// could not seat a panel).
    pub reason: String,
    /// The party who opened it, `rrn1…`.
    pub initiator: String,
    /// Unix seconds it was opened — the electorate is snapshotted here.
    pub opened_at: i64,
    /// Unix seconds its window closes (clamped to the dispute's overall window);
    /// past it, a quorum-less escalation fails open and the transaction settles.
    pub closes_at: i64,
    /// Ballots to uphold the dispute from eligible voters inside the window.
    pub uphold: u32,
    /// Ballots to reject the dispute from eligible voters inside the window.
    pub reject: u32,
    /// Established, non-party members eligible to vote.
    pub eligible: u32,
    /// Whether turnout has reached the escalation quorum.
    pub quorum_met: bool,
    /// Whether the uphold share of decisive ballots has cleared the approval bar.
    pub approval_met: bool,
}

/// A party's filed response to the dispute.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseView {
    /// The responding party's `rrn1…` address.
    pub responder: String,
    /// Their statement, free text (bounded).
    pub statement: String,
    /// Their evidence hash, hex — present when they attached one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
    /// Unix seconds the response was made.
    pub responded_at: i64,
}

/// One occupied seat on the jury as of the view's `now`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PanelSeatView {
    /// The juror in this seat, `rrn1…`.
    pub juror: String,
    /// Unix seconds they took the seat (the dispute's open time for the initial
    /// panel, or the moment the juror they replaced timed out).
    pub seated_at: i64,
    /// Their verdict: `uphold`, `reject`, or `awaiting` (no valid verdict yet).
    pub verdict: String,
}

/// The seated jury's verdict counts, flattened for the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisputeTallyView {
    /// Seated jurors who have voted to uphold.
    pub uphold: u32,
    /// Seated jurors who have voted to reject.
    pub reject: u32,
    /// Seated jurors yet to cast a valid verdict.
    pub awaiting: u32,
    /// The panel size a majority is measured against (3 in Phase 1).
    pub panel_size: u32,
}

/// Every disputed transaction as browse rows, most-recent-first (log order,
/// reversed), each with its live panel and the outcome a resolve pass would enact.
pub fn disputes_view(
    db: &Database,
    founders: &[Address],
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> rrn_dispute::Result<Vec<DisputeSummary>> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db))?;
    let mut rows = Vec::new();
    for (id, state) in snapshot.iter() {
        if let TransactionState::Disputed { .. } = state {
            rows.push(summarize(db, founders, id, state, params, anchor, now)?);
        }
    }
    // Newest first, by open time.
    rows.sort_by_key(|r| std::cmp::Reverse(r.opened_at));
    Ok(rows)
}

/// One dispute in full, or `None` if the transaction is not currently disputed.
pub fn dispute_view(
    db: &Database,
    founders: &[Address],
    tx_id: &TransactionId,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> rrn_dispute::Result<Option<DisputeDetail>> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db))?;
    let state = snapshot.get(tx_id);
    let Some(state @ TransactionState::Disputed { .. }) = state else {
        return Ok(None);
    };
    let summary = summarize(db, founders, tx_id, state, params, anchor, now)?;

    let responses = dispute_responses(db, tx_id)?
        .into_iter()
        .map(|r| ResponseView {
            responder: r.responder.to_string(),
            statement: r.statement,
            evidence_hash: r.evidence_hash.map(|h| h.to_string()),
            responded_at: r.responded_at,
        })
        .collect();

    // Re-derive the seated jury exactly as resolution does, for display — keyed
    // on the admitted dispute time, never the party's signed `opened_at`
    // (ADR-0022), so this view cannot drift from the resolution path.
    let info = disputed_info(db, tx_id)?;
    let pool = eligible_pool(db, founders, &info, info.opened_at, params)?;
    let sequence = draw_sequence(&pool, sortition_seed(tx_id, anchor));
    let cast = verdicts(db, tx_id)?;
    let panel = resolve_panel(&sequence, &cast, info.opened_at, params, now);
    let panel = panel
        .seats
        .iter()
        .map(|s| PanelSeatView {
            juror: s.juror.to_string(),
            seated_at: s.seated_at,
            verdict: match s.verdict {
                Some(true) => "uphold",
                Some(false) => "reject",
                None => "awaiting",
            }
            .to_string(),
        })
        .collect();

    // An open, applicable escalation, with its live electorate tally.
    let escalation = escalation_of(db, tx_id)?
        .map(|esc| -> rrn_dispute::Result<EscalationView> {
            let closes_at = esc
                .opened_at
                .saturating_add(params.escalation_window_seconds)
                .min(info.opened_at.saturating_add(params.window_seconds));
            let electorate = escalation_electorate(db, founders, &info, esc.opened_at)?;
            let ballots = escalation_ballots(db, tx_id)?;
            let t = count_escalation(&ballots, &electorate, params, esc.opened_at, closes_at);
            Ok(EscalationView {
                reason: match esc.reason {
                    EscalationReason::Appeal => "appeal",
                    EscalationReason::CannotSeat => "cannot_seat",
                }
                .to_string(),
                initiator: esc.initiator.to_string(),
                opened_at: esc.opened_at,
                closes_at,
                uphold: t.uphold,
                reject: t.reject,
                eligible: t.eligible,
                quorum_met: t.quorum_met,
                approval_met: t.approval_met,
            })
        })
        .transpose()?;

    Ok(Some(DisputeDetail {
        summary,
        responses,
        panel,
        eligible_pool_size: pool.len() as u32,
        escalation,
    }))
}

/// Builds a browse row for one disputed transaction: its grievance, window, live
/// jury tally, and the outcome a resolve pass would enact right now.
fn summarize(
    db: &Database,
    founders: &[Address],
    tx_id: &TransactionId,
    state: &TransactionState,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> rrn_dispute::Result<DisputeSummary> {
    let TransactionState::Disputed {
        proposal, dispute, ..
    } = state
    else {
        return Err(rrn_dispute::Error::NotDisputed);
    };
    let p = &proposal.payload;
    let d = &dispute.payload;

    // Keyed on the admitted dispute time, never the party's signed `opened_at`
    // (ADR-0022), so the summary matches the resolution path exactly.
    let info = disputed_info(db, tx_id)?;
    let pool = eligible_pool(db, founders, &info, info.opened_at, params)?;
    let sequence = draw_sequence(&pool, sortition_seed(tx_id, anchor));
    let cast = verdicts(db, tx_id)?;
    let panel = resolve_panel(&sequence, &cast, info.opened_at, params, now);

    let uphold = panel
        .seats
        .iter()
        .filter(|s| s.verdict == Some(true))
        .count() as u32;
    let reject = panel
        .seats
        .iter()
        .filter(|s| s.verdict == Some(false))
        .count() as u32;
    let awaiting = panel.seats.iter().filter(|s| s.verdict.is_none()).count() as u32;

    let window_ends_at = info.opened_at.saturating_add(params.window_seconds);
    // The full layered outcome — jury, appeal window, and any escalation — exactly
    // as a resolve pass would decide it, without enacting.
    let resolution = resolution_str(preview(db, founders, tx_id, params, anchor, now)?).to_string();

    Ok(DisputeSummary {
        tx_id: tx_id.0.to_string(),
        sender: p.sender.to_string(),
        receiver: p.receiver.to_string(),
        raiser: d.raiser.to_string(),
        reason: d.reason.clone(),
        evidence_hash: d.evidence_hash.map(|h| h.to_string()),
        opened_at: info.opened_at,
        window_ends_at,
        tally: DisputeTallyView {
            uphold,
            reject,
            awaiting,
            panel_size: params.panel_size as u32,
        },
        resolution,
    })
}

/// The wire string for a [`Resolution`] — the outcome a resolve pass would enact.
fn resolution_str(r: Resolution) -> &'static str {
    match r {
        Resolution::Pending => "pending",
        Resolution::AwaitingAppeal => "awaiting_appeal",
        Resolution::Upheld => "upheld",
        Resolution::Rejected => "rejected",
        Resolution::Lapsed => "lapsed",
        Resolution::EscalationPending => "escalation_pending",
        Resolution::EscalationUpheld => "escalation_upheld",
        Resolution::EscalationRejected => "escalation_rejected",
        Resolution::EscalationLapsed => "escalation_lapsed",
    }
}
