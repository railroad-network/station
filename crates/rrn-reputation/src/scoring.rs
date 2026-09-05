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
//!   (they contribute nothing). Its reserved negative slot is now populated by a
//!   proven equivocation (a false headroom claim; ADR-0021 §5), which zeroes it.
//! - **Attestation accuracy** — each signed statement the address made about a
//!   transaction or another member: the vouches it signed, plus the transaction
//!   confirmations it signed as a receiver. Each counts as accurate *unless later
//!   proven wrong*: a dispute upheld against a confirmation (ADR-0014) both strips
//!   its positive credit and levies a penalty, dragging the dimension below
//!   neutral — the "proven wrong" negative event ADR-0009 always reserved for this
//!   dimension, and the forfeiture the Tier-2 stake finally pays. A proven
//!   equivocation zeroes this dimension too (ADR-0021 §5 / ADR-0025).
//!
//! # The count-to-score mapping
//!
//! A dimension's raw value is `EVENT_INCREMENT` (0.5) per qualifying event,
//! capped at
//! [`DIMENSION_MAX`]; [`crate::decay`] then subtracts its monthly rate per 30-day
//! month since that dimension's most recent event. These constants are
//! protocol-locked alongside the ADR-0009 weights: they must be identical on
//! every station, or a reputation exported from one would not reconcile on
//! another.

use std::collections::HashSet;

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_ledger::escrow::{
    EquivocationBasis, EquivocationId, EquivocationRecord, EquivocationVerdictRecord,
    VerdictDecision,
};
use rrn_ledger::state::{CancelReason, LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionConfirmation;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::decay::decayed;
use crate::model::{ReputationProfile, DIMENSION_MAX};
use crate::sybil::{anchored_profile, is_anchored};
use crate::Result;

/// Points one qualifying event contributes to its dimension, before capping and
/// decay. Protocol-locked (ADR-0009): 10 lifetime events reach [`DIMENSION_MAX`].
const EVENT_INCREMENT: f32 = 0.5;

/// Penalty weight a proven equivocation levies on **each** of the two dimensions
/// it dents (ADR-0021 §5, ADR-0009). **Maintainer-ratified 2026-09-04** (ADR-0025).
///
/// ADR-0009's scoring is additive/linear and floors each dimension at zero, so it
/// has no signed negative-weight table to scale. Rather than a fixed small
/// subtraction — which is regressive (invisible on a newcomer, trivial on a
/// veteran) and, at any value that keeps a maxed member's composite ≥ the Member
/// band, leaves the equivocator established with their vote and jury seat intact —
/// the penalty is [`DIMENSION_MAX`], which **zeroes** whichever dimension it is
/// applied to. That is the heaviest expressible consequence within the locked,
/// floored formula, and the only one with a governance effect (de-establishment).
/// It is fully reversible: the penalty is derived on replay and lifted the instant
/// a jury `Overturn` verdict lands (ADR-0021 §5). While it stands the dimension is
/// pinned at zero (a deliberate, proportional cost for a proven, deliberate act);
/// the newcomer-with-no-history case is covered out-of-formula by an
/// equivocation → cert-issuance disqualification gate (ADR-0025 / T2.3.4).
///
/// Equivocation is dented on **both** live dimensions — a signed statement proven
/// false (attestation accuracy, ADR-0009's "proven wrong" slot) *and* the paradigm
/// disputed-against trade (trade reliability, its reserved negative slot, and the
/// highest-weighted dimension a counterparty reads before accepting an offline
/// spend). It is two proven-wrong facts (a false headroom claim and a failed
/// settlement), not one event double-counted.
pub const EQUIVOCATION_WEIGHT: f32 = DIMENSION_MAX;

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
    /// Equivalent to [`score_at`](Self::score_at) at `now`. The whole log is
    /// replayed each call, once for the address and once more per member who has
    /// vouched for it (to judge the anchor), so the cost is `O(V·N)` — fine at
    /// Phase 1 scale, and [`crate::snapshot`] caches the result for hot paths.
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
    ///
    /// An identity no established member has vouched for is held to
    /// [`ANCHOR_DIMENSION_CAP`](crate::sybil::ANCHOR_DIMENSION_CAP) — the
    /// evidence still accrues underneath, so being anchored later reveals the
    /// score rather than starting it.
    pub fn score_at(&self, address: &Address, at_time: i64) -> Result<ReputationProfile> {
        let raw = self.score_raw_at(address, at_time)?;
        let anchored = is_anchored(self.db, address, at_time)?;
        Ok(anchored_profile(&raw, anchored))
    }

    /// The address's reputation from evidence alone, before identity anchoring.
    ///
    /// This is what [`crate::sybil::anchoring_voucher`] judges a prospective
    /// voucher on, and the two functions must not be swapped: scoring a voucher
    /// through [`score_at`](Self::score_at) would call back into anchoring and
    /// recurse without terminating on a pair of members who vouch for each other.
    pub(crate) fn score_raw_at(
        &self,
        address: &Address,
        at_time: i64,
    ) -> Result<ReputationProfile> {
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
            // A dispute upheld against a confirmation is the "proven wrong" event
            // ADR-0009's attestation-accuracy dimension was documented to hold and
            // ADR-0014 §6 delivers: the transaction is now
            // `Cancelled { DisputeUpheld }`, which already strips the confirmer's
            // positive credit (a cancelled state carries no confirmation), and this
            // penalty drags the dimension *below* neutral so the Tier-2 stake
            // actually costs them. The confirmer is always the proposal's receiver
            // (a confirmation can only come from the receiver), so it is derivable
            // even though the cancelled state no longer carries the confirmation.
            // Gated on `cancelled_at` so a profile scored before the ruling is not
            // dented — the attestation was not yet proven wrong then.
            if let TransactionState::Cancelled {
                proposal,
                reason: CancelReason::DisputeUpheld,
                cancelled_at,
            } = state
            {
                if proposal.payload.receiver == *address && *cancelled_at <= at_time {
                    attestation.penalize();
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

        // A proven equivocation zeroes both live dimensions — trade reliability and
        // attestation accuracy (ADR-0021 §5 / ADR-0025). Like vouches, equivocation
        // records are standalone station-signed log entries the ledger replay
        // ignores, so they need a direct scan. Two guards
        // make this a pure function of the log that convicts no one wrongly:
        //   1. A jury `Overturn` verdict (ADR-0021 §5) neutralizes the record — its
        //      penalty lifts. Gated on the verdict's `decided_at <= at_time` so a
        //      profile scored before the ruling still carries the penalty and one
        //      scored after does not (mirroring the upheld-dispute `cancelled_at`
        //      gate). The jury *path* is a follow-up ticket; the verdict record kind
        //      is defined now so this neutralization is exact and testable.
        //   2. [`EquivocationRecord::verify_evidence`] re-derives the conflict from
        //      the embedded member-signed artifacts, so a hostile log copy's bogus
        //      record — tampered evidence, amounts within cap, a mislabeled member —
        //      produces no penalty. The cap for a cert-overspend basis is read from
        //      the certificate on the same log.
        let overturned = overturned_equivocations(&log, at_time)?;
        for entry in log.iter_from(1) {
            let entry = entry?;
            let Ok(record) = from_canonical_bytes::<EquivocationRecord>(&entry.payload.bytes)
            else {
                continue;
            };
            if record.member != *address || record.recorded_at > at_time {
                continue;
            }
            if overturned.contains(&record.equivocation_id) {
                continue;
            }
            let cap = match record.basis {
                EquivocationBasis::CertOverspend => record
                    .cert_id
                    .and_then(|c| ledger.certificate(&c))
                    .map(|c| c.certificate.payload.cap_centi),
                EquivocationBasis::OutboxFork => None,
            };
            if record.verify_evidence(cap) {
                // Zero both live dimensions (ADR-0025): a false headroom claim
                // (trade reliability, the dimension a counterparty reads) and a
                // signed statement proven false (attestation accuracy).
                trade.penalize_by(EQUIVOCATION_WEIGHT);
                attestation.penalize_by(EQUIVOCATION_WEIGHT);
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

/// The set of equivocation records overturned by a jury as of `at_time` — those
/// with an [`Overturn`](VerdictDecision::Overturn) verdict whose `decided_at` is
/// at or before `at_time`. An overturned record levies no reputation penalty
/// (ADR-0021 §5). A non-verdict payload is skipped.
fn overturned_equivocations(log: &AppendLog, at_time: i64) -> Result<HashSet<EquivocationId>> {
    let mut out = HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(verdict) = from_canonical_bytes::<EquivocationVerdictRecord>(&entry.payload.bytes)
        else {
            continue;
        };
        // T2.3.4: once the jury path can *produce* verdicts, gate this on the
        // verdict's signer being the station, so a member-relayed `Overturn`
        // cannot neutralize their own penalty. Today no such path exists — the
        // verdict kind is `UnroutableKind` on DTN and has no RPC surface — so an
        // overturn can only come from the station that wrote the log.
        if verdict.decision == VerdictDecision::Overturn && verdict.decided_at <= at_time {
            out.insert(verdict.equivocation_id);
        }
    }
    Ok(out)
}

/// Running tally for one dimension: how many qualifying positive events, the
/// total penalty weight counted against it, and when the most recent positive
/// event happened (for decay).
#[derive(Default)]
struct DimensionTally {
    count: u32,
    /// Total penalty weight subtracted from the dimension. An upheld dispute adds
    /// [`EVENT_INCREMENT`]; a proven equivocation adds the heavier
    /// [`EQUIVOCATION_WEIGHT`]. Held as a weight (not a count) so inputs of
    /// different severities compose.
    penalty: f32,
    last_activity: Option<i64>,
}

impl DimensionTally {
    /// Folds in one positive event that occurred at `event_time`.
    fn record(&mut self, event_time: i64) {
        self.count += 1;
        self.last_activity = Some(match self.last_activity {
            Some(prev) => prev.max(event_time),
            None => event_time,
        });
    }

    /// Counts one upheld-dispute penalty against the dimension — a positive
    /// contribution later proven wrong (ADR-0014 §6). Subtracts a full
    /// [`EVENT_INCREMENT`].
    fn penalize(&mut self) {
        self.penalize_by(EVENT_INCREMENT);
    }

    /// Subtracts `weight` from the dimension. Deliberately does *not* touch
    /// `last_activity`: a penalty must not reset the decay clock and thereby
    /// preserve more of the positive score it is meant to erode. A dimension with
    /// no positive events stays at zero regardless — a dimension floors at zero,
    /// so there is nothing below neutral to reach.
    fn penalize_by(&mut self, weight: f32) {
        self.penalty += weight;
    }

    /// The dimension's score as of `at_time`: capped linear accrual less its
    /// penalties, then decayed from the most recent positive event, floored at
    /// zero. Zero when there is no positive evidence.
    fn score(&self, at_time: i64) -> f32 {
        let Some(last) = self.last_activity else {
            return 0.0;
        };
        let earned = (EVENT_INCREMENT * self.count as f32).min(DIMENSION_MAX);
        let net = earned - self.penalty;
        // `decayed` floors at zero, so a net driven negative by penalties reads as
        // a bottomed-out dimension rather than an impossible negative one.
        decayed(net, last, at_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::dispute::{DisputeRecord, SignedDispute};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::state::{CancelReason, CancellationRecord};
    use rrn_ledger::transaction::TransactionProposal;
    use rrn_storage::migrations;

    use crate::model::ReputationBand;
    use crate::sybil::ANCHOR_DIMENSION_CAP;

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
        log.append(SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, receiver), 0)
            .unwrap();
        let settlement = SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        };
        log.append(SignedPayload::sign(settlement, station), 0)
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
        log.append(SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        let cancellation = CancellationRecord {
            proposal_id: pid,
            reason: CancelReason::Expired,
            cancelled_at: at,
        };
        log.append(SignedPayload::sign(cancellation, station), 0)
            .unwrap();
    }

    /// Appends a proposal → confirmation → dispute → upheld-cancellation chain,
    /// leaving the transaction `Cancelled { DisputeUpheld }`. The receiver is the
    /// confirmer whose attestation is thereby proven wrong; `sender` raises the
    /// dispute (a party).
    fn append_disputed_upheld(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        station: &Keypair,
        nonce: u64,
        confirmed_at: i64,
        resolved_at: i64,
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
        log.append(SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at,
        };
        log.append(SignedPayload::sign(confirmation, receiver), 0)
            .unwrap();
        let dispute = DisputeRecord {
            proposal_id: pid,
            raiser: addr(sender),
            reason: "goods never arrived".into(),
            evidence_hash: None,
            opened_at: confirmed_at,
        };
        log.append(SignedDispute::sign(dispute, sender), 0).unwrap();
        let cancellation = CancellationRecord {
            proposal_id: pid,
            reason: CancelReason::DisputeUpheld,
            cancelled_at: resolved_at,
        };
        log.append(SignedPayload::sign(cancellation, station), 0)
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
        log.append(vouch.sign(voucher), 0).unwrap();
    }

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    // --- equivocation (T2.3.3) ----------------------------------------------

    use rrn_ledger::escrow::{CertId, CertificateRequest, EvidenceItem, HeadroomCertificate};

    /// Puts a `cap`-centi certificate for `member` on the log (request then
    /// station grant, request-first per ADR-0021 §1), returning its id so an
    /// overspend proof can reference it and scoring can read the cap.
    fn append_certificate(
        db: &Database,
        member: &Keypair,
        station: &Keypair,
        cap: i64,
        nonce: u64,
        at: i64,
    ) -> CertId {
        let mut log = AppendLog::new(db);
        let req = CertificateRequest::new(addr(member), cap, nonce, at);
        let rid = req.request_id;
        log.append(SignedPayload::sign(req, member), 0).unwrap();
        let cert = HeadroomCertificate::new(addr(member), cap, rid, at, at + 1_000_000);
        let cid = cert.cert_id;
        log.append(SignedPayload::sign(cert, station), 0).unwrap();
        cid
    }

    /// A `member`-signed cert-backed spend against `cert`, as an evidence item.
    fn cert_evidence(member: &Keypair, cert: CertId, amount: i64, nonce: u64) -> EvidenceItem {
        let p = TransactionProposal::new(
            addr(member),
            addr(&Keypair::generate()),
            amount,
            None,
            nonce,
            1,
            i64::MAX / 2,
        )
        .with_certificate(cert);
        EvidenceItem::from_signed(&SignedPayload::sign(p, member))
    }

    /// Appends a station-signed cert-overspend equivocation against `member`
    /// (two 300-spends over a 500 cap), returning its id.
    fn append_equivocation(
        db: &Database,
        member: &Keypair,
        station: &Keypair,
        cert: CertId,
        recorded_at: i64,
    ) -> EquivocationId {
        let evidence = vec![
            cert_evidence(member, cert, 300, 1),
            cert_evidence(member, cert, 300, 2),
        ];
        let record = EquivocationRecord::new(
            addr(member),
            EquivocationBasis::CertOverspend,
            Some(cert),
            evidence,
            recorded_at,
        );
        let id = record.equivocation_id;
        AppendLog::new(db)
            .append(SignedPayload::sign(record, station), 0)
            .unwrap();
        id
    }

    /// Appends a station-signed `Overturn` verdict neutralizing `id`.
    fn append_overturn(db: &Database, station: &Keypair, id: EquivocationId, decided_at: i64) {
        let verdict = EquivocationVerdictRecord {
            equivocation_id: id,
            decision: VerdictDecision::Overturn,
            decided_at,
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(verdict, station), 0)
            .unwrap();
    }

    /// Gives `member` three vouch attestations (raw 1.5) as a clean baseline the
    /// equivocation penalty can visibly erode.
    fn seed_attestation_baseline(db: &Database, member: &Keypair, at: i64) {
        for _ in 0..3 {
            append_vouch(db, member, &addr(&Keypair::generate()), at);
        }
    }

    /// Gives `member` a two-trade, three-vouch baseline (trade 1.0, attestation
    /// 1.5) so the equivocation penalty can be seen to zero **both** live
    /// dimensions. `member` is the *sender* of both trades, so the trades give no
    /// attestation credit (the receiver confirms), keeping the two dimensions
    /// independent.
    fn seed_trade_and_attestation_baseline(db: &Database, member: &Keypair, at: i64) {
        let other = Keypair::generate();
        append_settled(db, member, &other, &Keypair::generate(), 0, at);
        append_settled(db, member, &other, &Keypair::generate(), 1, at);
        seed_attestation_baseline(db, member, at);
    }

    #[test]
    fn a_proven_equivocation_zeroes_both_live_dimensions() {
        let db = fresh_db();
        let (mallory, station) = (Keypair::generate(), Keypair::generate());
        let t = 10 * MONTH;

        seed_trade_and_attestation_baseline(&db, &mallory, t);
        let base = ReputationScorer::new(&db)
            .score_raw_at(&addr(&mallory), t)
            .unwrap();
        assert!(
            approx(base.trade_reliability, 1.0),
            "trade base {}",
            base.trade_reliability
        );
        assert!(
            approx(base.attestation_accuracy, 1.5),
            "attn base {}",
            base.attestation_accuracy
        );

        let cert = append_certificate(&db, &mallory, &station, 500, 2, t);
        append_equivocation(&db, &mallory, &station, cert, t);

        let after = ReputationScorer::new(&db)
            .score_raw_at(&addr(&mallory), t)
            .unwrap();
        // Both live dimensions floor at zero — the equivocator is de-established.
        assert!(
            approx(after.trade_reliability, 0.0),
            "trade {}",
            after.trade_reliability
        );
        assert!(
            approx(after.attestation_accuracy, 0.0),
            "attn {}",
            after.attestation_accuracy
        );
        assert!(
            approx(after.composite(), 0.0),
            "composite {}",
            after.composite()
        );
    }

    #[test]
    fn an_overturned_equivocation_is_neutralized() {
        let db = fresh_db();
        let (mallory, station) = (Keypair::generate(), Keypair::generate());
        let t = 10 * MONTH;

        seed_trade_and_attestation_baseline(&db, &mallory, t);
        let cert = append_certificate(&db, &mallory, &station, 500, 2, t);
        let id = append_equivocation(&db, &mallory, &station, cert, t);
        append_overturn(&db, &station, id, t);

        let after = ReputationScorer::new(&db)
            .score_raw_at(&addr(&mallory), t)
            .unwrap();
        // The overturn lifts the penalty on both dimensions: clean baseline.
        assert!(
            approx(after.trade_reliability, 1.0),
            "trade {}",
            after.trade_reliability
        );
        assert!(
            approx(after.attestation_accuracy, 1.5),
            "attn {}",
            after.attestation_accuracy
        );
    }

    #[test]
    fn a_bogus_equivocation_record_convicts_no_one() {
        let db = fresh_db();
        let (mallory, station) = (Keypair::generate(), Keypair::generate());
        let t = 10 * MONTH;

        seed_trade_and_attestation_baseline(&db, &mallory, t);
        let cert = append_certificate(&db, &mallory, &station, 500, 2, t);

        // A station-signed record whose evidence has been tampered: one embedded
        // signature no longer verifies, so `verify_evidence` rejects it.
        let mut evidence = vec![
            cert_evidence(&mallory, cert, 300, 1),
            cert_evidence(&mallory, cert, 300, 2),
        ];
        let last = evidence[0].bytes.len() - 1;
        evidence[0].bytes[last] ^= 0x01;
        let record = EquivocationRecord::new(
            addr(&mallory),
            EquivocationBasis::CertOverspend,
            Some(cert),
            evidence,
            t,
        );
        AppendLog::new(&db)
            .append(SignedPayload::sign(record, &station), 0)
            .unwrap();

        // No penalty: both baselines stand.
        let after = ReputationScorer::new(&db)
            .score_raw_at(&addr(&mallory), t)
            .unwrap();
        assert!(
            approx(after.trade_reliability, 1.0),
            "trade {}",
            after.trade_reliability
        );
        assert!(
            approx(after.attestation_accuracy, 1.5),
            "bogus record must not dent: {}",
            after.attestation_accuracy
        );
    }

    #[test]
    fn equivocation_scoring_is_deterministic_across_replays() {
        // Two independent replays of the same log reduce to the same score — the
        // property `verify_history` and dispute review depend on — both with and
        // without the overturning verdict present.
        let db = fresh_db();
        let (mallory, station) = (Keypair::generate(), Keypair::generate());
        let t = 10 * MONTH;
        seed_trade_and_attestation_baseline(&db, &mallory, t);
        let cert = append_certificate(&db, &mallory, &station, 500, 2, t);
        let id = append_equivocation(&db, &mallory, &station, cert, t);

        let replay = || {
            let p = ReputationScorer::new(&db)
                .score_raw_at(&addr(&mallory), t)
                .unwrap();
            (p.trade_reliability, p.attestation_accuracy)
        };
        assert_eq!(replay(), replay(), "two replays agree (penalty present)");
        assert_eq!(replay(), (0.0, 0.0));

        append_overturn(&db, &station, id, t);
        assert_eq!(
            replay(),
            replay(),
            "two replays agree (penalty neutralized)"
        );
        let (trade, attn) = replay();
        assert!(approx(trade, 1.0) && approx(attn, 1.5));
    }

    #[test]
    fn the_equivocation_penalty_applies_only_from_recorded_at_onward() {
        let db = fresh_db();
        let (mallory, station) = (Keypair::generate(), Keypair::generate());
        let t = 10 * MONTH;

        seed_trade_and_attestation_baseline(&db, &mallory, t);
        let cert = append_certificate(&db, &mallory, &station, 500, 2, t);
        // The equivocation is recorded a month after the baseline activity.
        append_equivocation(&db, &mallory, &station, cert, t + MONTH);

        // Scored before the record exists: no penalty.
        let before = ReputationScorer::new(&db)
            .score_raw_at(&addr(&mallory), t)
            .unwrap();
        assert!(
            approx(before.attestation_accuracy, 1.5),
            "before {}",
            before.attestation_accuracy
        );

        // Scored at the record's instant: both dimensions are zeroed.
        let at = ReputationScorer::new(&db)
            .score_raw_at(&addr(&mallory), t + MONTH)
            .unwrap();
        assert!(
            approx(at.trade_reliability, 0.0),
            "trade {}",
            at.trade_reliability
        );
        assert!(
            approx(at.attestation_accuracy, 0.0),
            "attn {}",
            at.attestation_accuracy
        );
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
    fn an_upheld_dispute_dents_the_confirmers_attestation_accuracy() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;

        // Bob confirms two clean settled trades → 2 attestations, raw 1.0.
        append_settled(&db, &alice, &bob, &station, 0, t);
        append_settled(&db, &alice, &bob, &station, 1, t);
        let base = ReputationScorer::new(&db)
            .score_raw_at(&addr(&bob), t)
            .unwrap();
        assert!(
            approx(base.attestation_accuracy, 1.0),
            "baseline attn = {}",
            base.attestation_accuracy
        );

        // A third trade Bob confirmed is disputed and upheld against him. It earns
        // no attestation credit (a cancelled state carries no confirmation) *and*
        // levies a 0.5 penalty: 1.0 − 0.5 = 0.5, below the clean baseline.
        append_disputed_upheld(&db, &alice, &bob, &station, 2, t, t);
        let after = ReputationScorer::new(&db)
            .score_raw_at(&addr(&bob), t)
            .unwrap();
        assert!(
            approx(after.attestation_accuracy, 0.5),
            "dented attn = {}",
            after.attestation_accuracy
        );
        // The raiser (alice) is untouched — the dent lands only on the confirmer.
        let alice_p = ReputationScorer::new(&db)
            .score_raw_at(&addr(&alice), t)
            .unwrap();
        assert!(approx(alice_p.attestation_accuracy, 0.0));
    }

    #[test]
    fn the_attestation_dent_applies_only_from_the_ruling_onward() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;

        // One clean confirmation by Bob at `t` (raw 0.5), plus a trade he
        // confirmed at `t` that is upheld-disputed a month later.
        let ruling = t + MONTH;
        append_settled(&db, &alice, &bob, &station, 0, t);
        append_disputed_upheld(&db, &alice, &bob, &station, 1, t, ruling);

        // Scored at `t`, before the ruling: the disputed confirmation is not yet
        // proven wrong, so no penalty — only the clean 0.5 remains (the disputed
        // one already carries no confirmation credit). Scored at its own instant,
        // so no decay either.
        let before = ReputationScorer::new(&db)
            .score_raw_at(&addr(&bob), t)
            .unwrap();
        assert!(
            approx(before.attestation_accuracy, 0.5),
            "pre-ruling attn = {}",
            before.attestation_accuracy
        );

        // Scored at the ruling: the 0.5 penalty applies, bottoming the dimension
        // out at zero (a dimension floors at zero, not below) — 0.5 earned − 0.5
        // penalty, then a month of decay, all floored.
        let at_ruling = ReputationScorer::new(&db)
            .score_raw_at(&addr(&bob), ruling)
            .unwrap();
        assert!(
            approx(at_ruling.attestation_accuracy, 0.0),
            "at-ruling attn = {}",
            at_ruling.attestation_accuracy
        );
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
        let p = ReputationScorer::new(&db)
            .score_raw_at(&addr(&alice), t)
            .unwrap();
        assert!(
            approx(p.trade_reliability, DIMENSION_MAX),
            "trade = {}",
            p.trade_reliability
        );
    }

    #[test]
    fn an_unvouched_identity_is_held_at_the_anchor_cap() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        for nonce in 0..12 {
            append_settled(&db, &alice, &bob, &station, nonce, t);
        }

        // Nobody has vouched for alice, so the evidence accrues but does not show.
        let scorer = ReputationScorer::new(&db);
        let scored = scorer.score(&addr(&alice), t).unwrap();
        assert!(
            approx(scored.trade_reliability, ANCHOR_DIMENSION_CAP),
            "trade = {}",
            scored.trade_reliability
        );
        assert!(approx(
            scorer
                .score_raw_at(&addr(&alice), t)
                .unwrap()
                .trade_reliability,
            DIMENSION_MAX
        ));
    }

    #[test]
    fn an_anchoring_vouch_reveals_the_score_already_earned() {
        let db = fresh_db();
        let (alice, bob, patron, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        for nonce in 0..12 {
            append_settled(&db, &alice, &bob, &station, nonce, t);
        }
        // The patron earns enough standing to anchor: ten settled trades plus ten
        // vouches written puts their composite over the Member-band threshold.
        for nonce in 0..10 {
            append_settled(&db, &patron, &station, &station, nonce, t);
        }
        for _ in 0..10 {
            append_vouch(&db, &patron, &addr(&Keypair::generate()), t);
        }

        let scorer = ReputationScorer::new(&db);
        assert!(approx(
            scorer.score(&addr(&alice), t).unwrap().trade_reliability,
            ANCHOR_DIMENSION_CAP
        ));

        // One vouch, and the history alice already had reads at full value —
        // the cap hid it, it did not erase it.
        append_vouch(&db, &patron, &addr(&alice), t);
        assert!(approx(
            scorer.score(&addr(&alice), t).unwrap().trade_reliability,
            DIMENSION_MAX
        ));
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
