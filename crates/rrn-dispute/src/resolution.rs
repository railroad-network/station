//! Appending a juror's verdict, and enacting (or lapsing) a dispute.
//!
//! [`append_verdict`] is the write gate: it accepts a signed verdict only from a
//! juror who holds a live seat as of the moment they cast it, re-deriving the
//! panel to check. [`resolve`] is the read-then-enact sweep: it recomputes the
//! panel and tally and, on a terminal majority, calls the ledger primitive that
//! closes the freeze — [`Engine::uphold_dispute`](rrn_ledger::engine::Engine::uphold_dispute)
//! to void the transfer, or [`Settler::settle`](rrn_ledger::settlement::Settler::settle)
//! to let it settle. A dispute that reaches its window with no majority **lapses**:
//! it settles as confirmed, the fail-open default (ADR-0014 §5).

use rrn_crypto::keypair::Keypair;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{SettlementConfig, Settler};
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::panel::{resolve_panel, tally, DisputeOutcome};
use crate::sortition::{disputed_info, draw_sequence, eligible_pool, sortition_seed};
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
    let pool = eligible_pool(db, &info, info.opened_at, params)?;
    let sequence = draw_sequence(&pool, sortition_seed(&proposal_id, anchor));
    let panel = resolve_panel(&sequence, &existing, info.opened_at, params, cast_at);
    match panel.seat_of(&juror) {
        Some(seat) if seat.verdict.is_none() => {}
        _ => return Err(Error::NotSeated),
    }

    AppendLog::new(db).append(verdict)?;
    tracing::info!(tx = ?proposal_id, ?juror, uphold, "verdict recorded");
    Ok(())
}

/// Recomputes a dispute's panel and tally and enacts a terminal outcome, or lets
/// the dispute lapse once its window has closed. Idempotent in effect: enacting an
/// outcome moves the transaction out of `Disputed`, so a later call finds it no
/// longer disputed.
///
/// `station` signs the settlement or void record; `anchor` is the community value
/// mixed into the sortition seed (see [`sortition_seed`]).
pub fn resolve(
    db: &Database,
    station: &Keypair,
    tx_id: &TransactionId,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Resolution> {
    let info = disputed_info(db, tx_id)?;
    let pool = eligible_pool(db, &info, info.opened_at, params)?;
    let sequence = draw_sequence(&pool, sortition_seed(tx_id, anchor));
    let existing = verdicts(db, tx_id)?;
    let panel = resolve_panel(&sequence, &existing, info.opened_at, params, now);

    match tally(&panel, params) {
        Some(DisputeOutcome::Upheld) => {
            Engine::new(db, station.clone()).uphold_dispute(tx_id, now)?;
            tracing::info!(tx = ?tx_id, "dispute upheld by jury");
            Ok(Resolution::Upheld)
        }
        Some(DisputeOutcome::Rejected) => {
            settle_confirmed(db, station, tx_id, now)?;
            tracing::info!(tx = ?tx_id, "dispute rejected by jury");
            Ok(Resolution::Rejected)
        }
        None => {
            if now >= info.opened_at.saturating_add(params.window_seconds) {
                settle_confirmed(db, station, tx_id, now)?;
                tracing::info!(tx = ?tx_id, "dispute lapsed; settled as confirmed");
                Ok(Resolution::Lapsed)
            } else {
                Ok(Resolution::Pending)
            }
        }
    }
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
