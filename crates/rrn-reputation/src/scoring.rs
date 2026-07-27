//! Scoring — replay the log into a [`ReputationProfile`].
//!
//! [`ReputationScorer`] walks the evidence involving an address and folds each
//! qualifying event into the relevant dimension, then applies time decay so the
//! result is always "as of" the scoring instant. The log is canonical; a profile
//! is a derived view — the same log and the same clock always reduce to the same
//! profile, on any station.
//!
//! # Phase 1 inputs
//!
//! Only two dimensions have live inputs (ADR-0009); the other three are
//! structurally zero until later milestones.
//!
//! - **Trade reliability** — each settled transaction the address is a party to
//!   (sender or receiver) is one positive event. Cancelled proposals are neutral
//!   (they contribute nothing); the disputed-against slot is reserved and never
//!   populated in Phase 1.
//! - **Attestation accuracy** — each signed statement the address made about a
//!   transaction or another member: the vouches it signed, plus the transaction
//!   confirmations it signed as a receiver. No fraud-finding mechanism exists in
//!   Phase 1, so every attestation counts as accurate and the dimension is driven
//!   by volume.
//!
//! # The count-to-score mapping
//!
//! A dimension's raw value is [`EVENT_INCREMENT`] per qualifying event, capped at
//! [`DIMENSION_MAX`]; [`crate::decay`] then subtracts its monthly rate per 30-day
//! month since that dimension's most recent event. These constants are
//! protocol-locked alongside the ADR-0009 weights: they must be identical on
//! every station, or a reputation exported from one would not reconcile on
//! another.

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionConfirmation;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::decay::decayed;
use crate::model::{ReputationProfile, DIMENSION_MAX};
use crate::Result;

/// Points one qualifying event contributes to its dimension, before capping and
/// decay. Protocol-locked (ADR-0009): 10 lifetime events reach [`DIMENSION_MAX`].
const EVENT_INCREMENT: f32 = 0.5;

/// Computes reputation profiles by replaying the log behind a borrowed database.
pub struct ReputationScorer<'db> {
    db: &'db Database,
}

impl<'db> ReputationScorer<'db> {
    /// Wraps a database handle for scoring.
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    /// The address's reputation as of `now`.
    ///
    /// Equivalent to [`score_at`](Self::score_at) at `now`; the whole log is
    /// replayed each call (`O(N)`), which is fine at Phase 1 scale — T1.5.5 adds
    /// a cached snapshot for hot paths.
    pub fn score(&self, address: &Address, now: i64) -> Result<ReputationProfile> {
        self.score_at(address, now)
    }

    /// The address's reputation as it stood at `at_time`.
    ///
    /// Only evidence whose own signed timestamp is at or before `at_time` counts,
    /// and decay is measured to `at_time` — so a historical profile is exactly
    /// what this station would have computed then, which is what makes portability
    /// and dispute review replayable. Timestamps come from the signed payloads
    /// (`settled_at`, `confirmed_at`, `issued_at`), never the log's per-replica
    /// append time, so two stations with the same log agree byte-for-byte.
    pub fn score_at(&self, address: &Address, at_time: i64) -> Result<ReputationProfile> {
        let log = AppendLog::new(self.db);

        let mut trade = DimensionTally::default();
        let mut attestation = DimensionTally::default();

        // Trade reliability and confirmations-as-attestations come from the
        // replayed ledger state, which has already folded proposals, confirmations
        // and settlements into per-transaction lifecycle states.
        let ledger = LedgerSnapshot::derive(&log)?;
        for (_, state) in ledger.iter() {
            if let TransactionState::Settled {
                proposal,
                settled_at,
                ..
            } = state
            {
                let p = &proposal.payload;
                if (p.sender == *address || p.receiver == *address) && *settled_at <= at_time {
                    trade.record(*settled_at);
                }
            }
            // A confirmation is an attestation by the confirmer whether or not the
            // transaction has settled yet, so it is read from the state directly.
            if let Some(confirmation) = confirmation_of(state) {
                if confirmation.confirmer == *address && confirmation.confirmed_at <= at_time {
                    attestation.record(confirmation.confirmed_at);
                }
            }
        }

        // Vouches are written by `rrn-identity` and ignored by the ledger replay,
        // so they need a direct scan. A payload that is not a vouch is skipped.
        for entry in log.iter_from(1) {
            let entry = entry?;
            let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) else {
                continue;
            };
            let voucher = Address::from_public_key(entry.payload.signer);
            if voucher == *address && vouch.issued_at <= at_time {
                attestation.record(vouch.issued_at);
            }
        }

        let mut profile = ReputationProfile::empty(*address);
        profile.trade_reliability = trade.score(at_time);
        profile.attestation_accuracy = attestation.score(at_time);
        // governance_participation, community_contribution and domain_competence
        // stay at their `empty()` zeros — no Phase 1 inputs (ADR-0009).
        profile.last_updated = at_time;
        Ok(profile)
    }
}

/// The confirmation embedded in a transaction state, if it carries one.
fn confirmation_of(state: &TransactionState) -> Option<&TransactionConfirmation> {
    match state {
        TransactionState::Confirmed { confirmation, .. }
        | TransactionState::Settled { confirmation, .. } => Some(&confirmation.payload),
        _ => None,
    }
}

/// Running tally for one dimension: how many qualifying events, and when the most
/// recent one happened (for decay).
#[derive(Default)]
struct DimensionTally {
    count: u32,
    last_activity: Option<i64>,
}

impl DimensionTally {
    /// Folds in one event that occurred at `event_time`.
    fn record(&mut self, event_time: i64) {
        self.count += 1;
        self.last_activity = Some(match self.last_activity {
            Some(prev) => prev.max(event_time),
            None => event_time,
        });
    }

    /// The dimension's score as of `at_time`: capped linear accrual, then decayed
    /// from the most recent event, floored at zero. Zero when there is no evidence.
    fn score(&self, at_time: i64) -> f32 {
        let Some(last) = self.last_activity else {
            return 0.0;
        };
        let raw = (EVENT_INCREMENT * self.count as f32).min(DIMENSION_MAX);
        decayed(raw, last, at_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::state::{CancelReason, CancellationRecord};
    use rrn_ledger::transaction::TransactionProposal;
    use rrn_storage::migrations;

    use crate::model::ReputationBand;

    const MONTH: i64 = 30 * 86_400;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// Appends a proposal → confirmation → settlement chain for one transaction,
    /// fully controlling `settled_at` (and the confirmer's `confirmed_at`).
    fn append_settled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        station: &Keypair,
        nonce: u64,
        at: i64,
    ) {
        let mut log = AppendLog::new(db);
        let proposal = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            300,
            None,
            nonce,
            1,
            i64::MAX / 2,
        );
        let pid = proposal.id;
        log.append(SignedPayload::sign(proposal, sender)).unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, receiver))
            .unwrap();
        let settlement = SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        };
        log.append(SignedPayload::sign(settlement, station))
            .unwrap();
    }

    /// Appends a proposal that is then cancelled (never confirmed or settled).
    fn append_cancelled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        station: &Keypair,
        nonce: u64,
        at: i64,
    ) {
        let mut log = AppendLog::new(db);
        let proposal = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            300,
            None,
            nonce,
            1,
            i64::MAX / 2,
        );
        let pid = proposal.id;
        log.append(SignedPayload::sign(proposal, sender)).unwrap();
        let cancellation = CancellationRecord {
            proposal_id: pid,
            reason: CancelReason::Expired,
            cancelled_at: at,
        };
        log.append(SignedPayload::sign(cancellation, station))
            .unwrap();
    }

    /// Appends a vouch from `voucher` for `subject`, issued at `at`.
    fn append_vouch(db: &Database, voucher: &Keypair, subject: &Address, at: i64) {
        let mut log = AppendLog::new(db);
        let vouch = Attestation {
            kind: VouchKind,
            body: VouchBody {
                community: "commons".into(),
                statement: "trustworthy".into(),
                reputation_stake_centi: 0,
            },
            subject: *subject,
            issued_at: at,
            expires_at: None,
        };
        log.append(vouch.sign(voucher)).unwrap();
    }

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn known_sequence_yields_known_profile() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;

        // Trade: alice sends one, receives one → 2 settled → raw 1.0.
        append_settled(&db, &alice, &bob, &station, 0, t);
        append_settled(&db, &bob, &alice, &station, 0, t);
        // Attestation: alice confirmed the one she received (1) + one vouch (1)
        // → 2 attestations → raw 1.0.
        append_vouch(&db, &alice, &addr(&bob), t);

        // Scored exactly at the activity instant, so no decay applies.
        let p = ReputationScorer::new(&db).score(&addr(&alice), t).unwrap();
        assert!(
            approx(p.trade_reliability, 1.0),
            "trade = {}",
            p.trade_reliability
        );
        assert!(
            approx(p.attestation_accuracy, 1.0),
            "attn = {}",
            p.attestation_accuracy
        );
        // 0.30·1.0 + 0.25·1.0 = 0.55.
        assert!(approx(p.composite(), 0.55), "composite = {}", p.composite());
        assert_eq!(p.band(), ReputationBand::New);
        assert_eq!(p.last_updated, t);
    }

    #[test]
    fn cancelled_transactions_contribute_nothing() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        append_cancelled(&db, &alice, &bob, &station, 0, t);

        let p = ReputationScorer::new(&db).score(&addr(&alice), t).unwrap();
        assert!(approx(p.trade_reliability, 0.0));
        assert!(approx(p.attestation_accuracy, 0.0));
    }

    #[test]
    fn accrual_caps_at_five() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        // 12 settled sends → raw 6.0 before the cap → clamped to 5.0.
        for nonce in 0..12 {
            append_settled(&db, &alice, &bob, &station, nonce, t);
        }
        let p = ReputationScorer::new(&db).score(&addr(&alice), t).unwrap();
        assert!(
            approx(p.trade_reliability, DIMENSION_MAX),
            "trade = {}",
            p.trade_reliability
        );
    }

    #[test]
    fn decay_reduces_a_dimension_over_time() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        // 2 settled sends → raw 1.0.
        append_settled(&db, &alice, &bob, &station, 0, t);
        append_settled(&db, &alice, &bob, &station, 1, t);

        let scorer = ReputationScorer::new(&db);
        let now = scorer.score(&addr(&alice), t).unwrap();
        assert!(approx(now.trade_reliability, 1.0));
        // Two months later: 1.0 − 0.1·2 = 0.8.
        let later = scorer.score(&addr(&alice), t + 2 * MONTH).unwrap();
        assert!(
            approx(later.trade_reliability, 0.8),
            "decayed = {}",
            later.trade_reliability
        );
    }

    #[test]
    fn score_at_excludes_events_after_the_cutoff() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let settled_at = 5 * MONTH;
        append_settled(&db, &alice, &bob, &station, 0, settled_at);

        let scorer = ReputationScorer::new(&db);
        // One second before settlement: the event has not happened yet.
        let before = scorer.score_at(&addr(&alice), settled_at - 1).unwrap();
        assert!(approx(before.trade_reliability, 0.0));
        // At settlement: one event → raw 0.5, no decay.
        let at = scorer.score_at(&addr(&alice), settled_at).unwrap();
        assert!(
            approx(at.trade_reliability, 0.5),
            "trade = {}",
            at.trade_reliability
        );
    }

    #[test]
    fn two_stations_with_the_same_log_agree() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 7 * MONTH;

        // Same keypairs and fields → identical signed bytes on both databases.
        let build = |db: &Database| {
            append_settled(db, &alice, &bob, &station, 0, t);
            append_settled(db, &bob, &alice, &station, 0, t);
            append_vouch(db, &alice, &addr(&bob), t);
        };
        let db_a = fresh_db();
        let db_b = fresh_db();
        build(&db_a);
        build(&db_b);

        let now = t + 3 * MONTH;
        let pa = ReputationScorer::new(&db_a)
            .score(&addr(&alice), now)
            .unwrap();
        let pb = ReputationScorer::new(&db_b)
            .score(&addr(&alice), now)
            .unwrap();
        assert_eq!(pa, pb);
    }
}
