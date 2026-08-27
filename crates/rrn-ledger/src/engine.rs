//! The transaction engine: the front door for submitting and querying
//! transactions, with replay protection.
//!
//! A signed proposal is just bytes — without replay protection the same one
//! could be processed many times. The [`Engine`] enforces, on the way in:
//!
//! - **signatures** verify, and a proposal is signed by the sender it names (a
//!   confirmation by the receiver it names);
//! - a **per-sender monotonic nonce** with no gaps and no duplicates;
//! - a **timestamp window**: `proposed_at <= now <= expires_at`, with
//!   [`CLOCK_SKEW_TOLERANCE_SECS`] of drift allowance either side;
//! - **uniqueness**: a proposal whose id is already in the log is rejected;
//! - the **debt floor** ([`crate::credit`], ADR-0018): a debit whose signer
//!   would be committed below the floor — counting settled balance and every
//!   pending debit they already signed — is rejected at the point they sign it
//!   (propose for the sender, confirm for a payment request's receiver).
//!
//! Each accepted operation appends one signed entry to the log; the engine keeps
//! no mutable state of its own, deriving everything from the log on demand.

use rrn_crypto::keypair::Keypair;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use rrn_identity::address::Address;

use crate::credit::{committed_debits_centi, CreditConfig};
use crate::dispute::{dispute_responses, SignedDispute, SignedDisputeResponse};
use crate::settlement::{BalanceView, SettlementConfig};
use crate::state::{CancelReason, CancellationRecord, LedgerSnapshot, TransactionState};
use crate::transaction::{SignedConfirmation, SignedProposal, TransactionId};
use crate::{Error, Result};

/// How much clock drift to tolerate when checking a proposal's time window, in
/// seconds (±5 minutes). Documented in the threat model.
pub const CLOCK_SKEW_TOLERANCE_SECS: i64 = 5 * 60;

/// The transaction engine over a borrowed [`Database`].
///
/// Holds the station keypair so it can sign cancellation records (withdrawals,
/// rejections, and expiries are not signed by a transacting party).
pub struct Engine<'db> {
    station: Keypair,
    db: &'db Database,
    credit: CreditConfig,
}

impl<'db> Engine<'db> {
    /// Creates an engine over `db`, signing station-authored records (e.g.
    /// cancellations) with `station`. Uses the default [`CreditConfig`]; see
    /// [`Engine::with_credit_config`] to override the debt floor.
    pub fn new(db: &'db Database, station: Keypair) -> Self {
        Self {
            station,
            db,
            credit: CreditConfig::default(),
        }
    }

    /// Overrides the credit parameters (the debt floor) this engine enforces.
    pub fn with_credit_config(mut self, credit: CreditConfig) -> Self {
        self.credit = credit;
        self
    }

    /// Rejects a new `debit_centi` (> 0) against `debtor` that would commit
    /// them below the debt floor: settled balance, minus the pending debits
    /// they have already signed, minus this one (ADR-0018; see [`crate::credit`]).
    fn check_debt_floor(
        &self,
        snapshot: &LedgerSnapshot,
        debtor: &Address,
        debit_centi: i64,
        now: i64,
    ) -> Result<()> {
        let settled = BalanceView::new(self.db).balance_of(debtor)?;
        let projected = settled
            .saturating_sub(committed_debits_centi(snapshot, debtor, now))
            .saturating_sub(debit_centi);
        if projected < self.credit.debt_floor_centi {
            return Err(Error::DebtFloorExceeded {
                floor_centi: self.credit.debt_floor_centi,
                projected_centi: projected,
            });
        }
        Ok(())
    }

    /// Submits a sender-signed proposal, enforcing replay protection.
    ///
    /// Errors (without writing) on a bad signature, a sender/signer mismatch, a
    /// time window violation, an out-of-order nonce, or a duplicate id.
    pub fn submit_proposal(&mut self, proposal: SignedProposal, now: i64) -> Result<()> {
        proposal.verify().map_err(|_| Error::BadSignature)?;
        let p = &proposal.payload;

        // The signer must be the sender it claims to be — otherwise anyone could
        // author a debit against someone else's account.
        if &proposal.signer != p.sender.public_key() {
            return Err(Error::SenderMismatch);
        }

        // Time window, with clock-skew tolerance on both ends.
        if p.proposed_at > p.expires_at {
            return Err(Error::InvalidWindow);
        }
        if p.proposed_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::FutureDated);
        }
        if now > p.expires_at.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::Expired);
        }

        // Oracle tier: Phase 1 services Tiers 1 and 2 only. A transaction whose
        // amount (or opt-up) reaches Tier 3+ is refused here, at the front door,
        // so it never reaches the log — value sets the floor and is never lowered
        // to fit what the phase can do (Overview §4.3).
        let tier = p.effective_tier();
        if !crate::tier::is_phase1_serviceable(tier) {
            return Err(Error::TierNotSupported {
                tier,
                max: crate::tier::MAX_PHASE1_TIER,
            });
        }

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;

        // Uniqueness: never process the same proposal twice.
        if snapshot.get(&p.id).is_some() {
            return Err(Error::DuplicateProposal);
        }

        // Nonce ordering: exactly the next expected value for this sender.
        let expected = snapshot.next_nonce(&p.sender.public_key().to_bytes());
        if p.nonce != expected {
            return Err(Error::BadNonce {
                expected,
                got: p.nonce,
            });
        }

        // Debt floor: a positive amount debits the sender, and their signature
        // on this proposal is their commitment to it. A negative amount (a
        // payment request) debits the receiver, who has signed nothing yet —
        // that side is checked at confirmation time instead.
        if p.amount_centi > 0 {
            self.check_debt_floor(&snapshot, &p.sender, p.amount_centi, now)?;
        }

        let (id, nonce) = (p.id, p.nonce);
        AppendLog::new(self.db).append(proposal, now)?;
        tracing::info!(tx = ?id, nonce, "proposal accepted");
        Ok(())
    }

    /// Submits a receiver-signed confirmation of an existing proposal.
    ///
    /// Errors on a bad signature, an unknown or non-`Proposed` transaction, a
    /// confirmer that is not the receiver, a proposal past expiry *by the
    /// admission clock*, a `confirmed_at` dated into the future beyond clock-skew
    /// tolerance, or a `confirmed_at` that predates its own proposal.
    ///
    /// Under the admission clock (ADR-0022 §3), `confirmed_at` is testimony, not
    /// a window anchor: an arbitrarily *old* confirmation is admissible — old
    /// means carried by a slow transport — because the settlement and dispute
    /// windows run from when this station admits the confirmation, not from the
    /// receiver's claim. This supersedes ADR-0019's staleness refusal.
    pub fn submit_confirmation(
        &mut self,
        confirmation: SignedConfirmation,
        now: i64,
    ) -> Result<()> {
        confirmation.verify().map_err(|_| Error::BadSignature)?;
        let c = &confirmation.payload;

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        let proposal = match snapshot.get(&c.proposal_id) {
            Some(TransactionState::Proposed { proposal }) => proposal,
            Some(_) => return Err(Error::NotProposed),
            None => return Err(Error::UnknownTransaction),
        };
        let p = &proposal.payload;

        // The confirmer must be the named receiver, and must have signed it.
        if c.confirmer != p.receiver || &confirmation.signer != p.receiver.public_key() {
            return Err(Error::ConfirmerMismatch);
        }

        // Proposal expiry is judged by the admission clock alone (ADR-0022 §4):
        // the station admits a confirmation only while `now` is still within the
        // sender's offer window (plus skew). The parallel check against the
        // claimed `confirmed_at` is dropped — it was testimony comparison, now
        // meaningless. This boundary is also what lets the debt floor release the
        // headroom of an expired unconfirmed proposal: past it the debit can
        // never land (see [`crate::credit`]).
        if now > p.expires_at.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::Expired);
        }

        // `confirmed_at` is plausibility-bounded testimony (ADR-0022 §3), not a
        // window anchor: the only bounds left are that it may not be dated into
        // the future beyond skew (a record from the future is a forgery or a
        // broken clock), and that it must be internally consistent — a
        // confirmation cannot claim to predate its own proposal. Arbitrarily
        // *old* is legal: the settlement/dispute windows run from admission.
        if c.confirmed_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::FutureDated);
        }
        if c.confirmed_at < p.proposed_at.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::InconsistentTimestamp {
                confirmed_at: c.confirmed_at,
                proposed_at: p.proposed_at,
            });
        }

        // Debt floor: confirming a negative-amount proposal (a payment request)
        // is the receiver signing a debit against themselves — the still-
        // `Proposed` request is not yet in their committed debits, so it is
        // added explicitly here. (Positive amounts debit the sender, checked
        // when the proposal was submitted.)
        if p.amount_centi < 0 {
            self.check_debt_floor(&snapshot, &p.receiver, p.amount_centi.saturating_abs(), now)?;
        }

        let proposal_id = c.proposal_id;
        AppendLog::new(self.db).append(confirmation, now)?;
        tracing::info!(tx = ?proposal_id, "confirmation accepted");
        Ok(())
    }

    /// Cancels a still-`Proposed` transaction (withdrawal, rejection, or
    /// expiry), appending a station-signed cancellation record.
    pub fn cancel_proposal(
        &mut self,
        tx_id: &TransactionId,
        reason: CancelReason,
        now: i64,
    ) -> Result<()> {
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        match snapshot.get(tx_id) {
            Some(TransactionState::Proposed { .. }) => {}
            Some(_) => return Err(Error::NotProposed),
            None => return Err(Error::UnknownTransaction),
        }

        let record = CancellationRecord {
            proposal_id: *tx_id,
            reason,
            cancelled_at: now,
        };
        AppendLog::new(self.db).append(
            rrn_crypto::signed::SignedPayload::sign(record, &self.station),
            now,
        )?;
        tracing::info!(tx = ?tx_id, ?reason, "proposal cancelled");
        Ok(())
    }

    /// Raises a party-signed dispute against a `Confirmed` transaction, freezing
    /// its settlement (ADR-0014). Appends the [`SignedDispute`] after validating,
    /// without writing on failure.
    ///
    /// Errors on a bad signature, an over-long reason, an unknown or
    /// non-`Confirmed` transaction, a raiser who is not a party (or did not sign
    /// it), or a dispute opened outside the transaction's settlement window — the
    /// same window a settlement would otherwise fire at, so a dispute must land
    /// before the transfer settles. `settlement` supplies that window per tier.
    pub fn raise_dispute(
        &mut self,
        dispute: SignedDispute,
        settlement: &SettlementConfig,
        now: i64,
    ) -> Result<()> {
        dispute.verify().map_err(|_| Error::BadSignature)?;
        let d = &dispute.payload;
        if !d.reason_within_bound() {
            return Err(Error::DisputeReasonTooLong);
        }

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        // The window now runs from confirmation *admission* (below), not from any
        // field of the confirmation record, so only the proposal is bound here.
        let proposal = match snapshot.get(&d.proposal_id) {
            Some(TransactionState::Confirmed { proposal, .. }) => proposal,
            Some(_) => return Err(Error::NotConfirmed),
            None => return Err(Error::UnknownTransaction),
        };
        let p = &proposal.payload;

        // Only a party may contest, and they must have signed the dispute.
        if (d.raiser != p.sender && d.raiser != p.receiver)
            || &dispute.signer != d.raiser.public_key()
        {
            return Err(Error::NotAParty);
        }

        // The dispute window is the settlement window, measured from when this
        // station *admitted* the confirmation (ADR-0022 §2) — not from the
        // receiver's claimed `confirmed_at`, which is testimony. A confirmation
        // carried offline for days therefore serves its full window from arrival.
        // The station's own clock decides the window is shut ("first" means first
        // admitted, §5); the raiser's `opened_at` is testimony too, bounded only
        // against future-dating. A dispute that arrives after settlement finds the
        // transaction already `Settled` and fails the `Confirmed` check above.
        let window = settlement.window_for(p.effective_tier()) as i64;
        let admitted_at = snapshot
            .admission(&d.proposal_id)
            .and_then(|a| a.confirmation_admitted_at)
            .ok_or_else(|| {
                Error::Invalid(
                    "confirmed transaction missing confirmation admission metadata".into(),
                )
            })?;
        let deadline = admitted_at
            .saturating_add(window)
            .saturating_add(CLOCK_SKEW_TOLERANCE_SECS);
        if d.opened_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::FutureDated);
        }
        if now > deadline {
            return Err(Error::DisputeWindowClosed);
        }

        let proposal_id = d.proposal_id;
        let raiser = d.raiser;
        AppendLog::new(self.db).append(dispute, now)?;
        tracing::info!(tx = ?proposal_id, ?raiser, "dispute raised");
        Ok(())
    }

    /// Upholds a dispute against a `Disputed` transaction: voids the pending
    /// transfer by appending a station-signed cancellation with
    /// [`CancelReason::DisputeUpheld`] (ADR-0014 §6). No balance moved (the freeze
    /// preceded settlement), so there is nothing to reverse.
    ///
    /// The complementary "dispute rejected / lapsed" outcome settles the frozen
    /// transaction instead — see [`Settler::settle`](crate::settlement::Settler::settle).
    /// Deciding *which* outcome applies is the dispute layer's job; this method is
    /// the ledger primitive that enacts an upheld ruling.
    pub fn uphold_dispute(&mut self, tx_id: &TransactionId, now: i64) -> Result<()> {
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        match snapshot.get(tx_id) {
            Some(TransactionState::Disputed { .. }) => {}
            Some(_) => return Err(Error::NotDisputed),
            None => return Err(Error::UnknownTransaction),
        }

        let record = CancellationRecord {
            proposal_id: *tx_id,
            reason: CancelReason::DisputeUpheld,
            cancelled_at: now,
        };
        AppendLog::new(self.db).append(
            rrn_crypto::signed::SignedPayload::sign(record, &self.station),
            now,
        )?;
        tracing::info!(tx = ?tx_id, "dispute upheld: transfer voided");
        Ok(())
    }

    /// Records a party's signed response to a live dispute — their side of the
    /// story for the jury (ADR-0014 §1). Appends the [`SignedDisputeResponse`]
    /// after validating, without writing on failure. Unlike raising a dispute,
    /// this changes no ledger state; the transaction stays `Disputed`.
    ///
    /// Errors on a bad signature, an over-long statement, an unknown or
    /// non-`Disputed` transaction, a responder who is not a party (or did not sign
    /// it), a response dated implausibly into the future, or a party who has
    /// already responded (one response per party — [`Error::AlreadyResponded`]).
    pub fn respond_to_dispute(&mut self, response: SignedDisputeResponse, now: i64) -> Result<()> {
        response.verify().map_err(|_| Error::BadSignature)?;
        let r = &response.payload;
        if !r.statement_within_bound() {
            return Err(Error::DisputeReasonTooLong);
        }
        if r.responded_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::FutureDated);
        }

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        let proposal = match snapshot.get(&r.proposal_id) {
            Some(TransactionState::Disputed { proposal, .. }) => proposal,
            Some(_) => return Err(Error::NotDisputed),
            None => return Err(Error::UnknownTransaction),
        };
        let p = &proposal.payload;

        // Only a party may respond, and they must have signed the response.
        if (r.responder != p.sender && r.responder != p.receiver)
            || &response.signer != r.responder.public_key()
        {
            return Err(Error::NotAParty);
        }

        // One response per party: the record is a bounded statement, but an
        // unbounded stream of them would let a frozen transaction bloat the log.
        if dispute_responses(self.db, &r.proposal_id)?
            .iter()
            .any(|existing| existing.responder == r.responder)
        {
            return Err(Error::AlreadyResponded);
        }

        let (proposal_id, responder) = (r.proposal_id, r.responder);
        AppendLog::new(self.db).append(response, now)?;
        tracing::info!(tx = ?proposal_id, ?responder, "dispute response recorded");
        Ok(())
    }

    /// The current derived state of a transaction, or `None` if unknown.
    pub fn get_state(&self, tx_id: &TransactionId) -> Result<Option<TransactionState>> {
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        Ok(snapshot.get(tx_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_identity::address::Address;
    use rrn_storage::migrations;

    use crate::transaction::{TransactionConfirmation, TransactionProposal};

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    fn signed_proposal(
        sender: &Keypair,
        receiver: &Keypair,
        nonce: u64,
        proposed_at: i64,
        expires_at: i64,
    ) -> SignedProposal {
        let p = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            300,
            None,
            nonce,
            proposed_at,
            expires_at,
        );
        SignedProposal::sign(p, sender)
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p0 = signed_proposal(&alice, &bob, 0, 100, 100_000);
        engine.submit_proposal(p0, 100).unwrap();

        // A second proposal reusing nonce 0 is a duplicate id → rejected.
        let again = signed_proposal(&alice, &bob, 0, 100, 100_000);
        assert!(matches!(
            engine.submit_proposal(again, 100),
            Err(Error::DuplicateProposal)
        ));
    }

    #[test]
    fn a_tier_three_amount_is_rejected_at_the_front_door() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // 50 Commons (5_000 centi) is Tier 3, which Phase 1 cannot service.
        let p = TransactionProposal::new(addr(&alice), addr(&bob), 5_000, None, 0, 100, 100_000);
        let signed = SignedProposal::sign(p, &alice);
        assert!(matches!(
            engine.submit_proposal(signed, 100),
            Err(Error::TierNotSupported { tier: 3, max: 2 })
        ));

        // Nothing was written: the next nonce is still 0, so a valid Tier-1/2
        // proposal can follow without a gap.
        let ok = signed_proposal(&alice, &bob, 0, 100, 100_000);
        assert!(engine.submit_proposal(ok, 100).is_ok());
    }

    #[test]
    fn nonce_gap_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Skipping nonce 0 and going straight to 1 (here labelled 2 in the spec
        // wording: "nonce 2 skipping 1") is rejected.
        let skip = signed_proposal(&alice, &bob, 2, 100, 100_000);
        assert!(matches!(
            engine.submit_proposal(skip, 100),
            Err(Error::BadNonce {
                expected: 0,
                got: 2
            })
        ));
    }

    #[test]
    fn future_dated_beyond_skew_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // proposed_at far in the future relative to `now`.
        let p = signed_proposal(&alice, &bob, 0, 10_000, 100_000);
        assert!(matches!(
            engine.submit_proposal(p, 100),
            Err(Error::FutureDated)
        ));
    }

    #[test]
    fn expired_proposal_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // expires_at well before `now`.
        let p = signed_proposal(&alice, &bob, 0, 100, 200);
        assert!(matches!(
            engine.submit_proposal(p, 100_000),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn proposal_signed_by_a_stranger_is_rejected() {
        let db = fresh_db();
        let (alice, bob, mallory, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Mallory signs a proposal that names Alice as the sender.
        let p = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 100, 100_000);
        let forged = SignedProposal::sign(p, &mallory);
        assert!(matches!(
            engine.submit_proposal(forged, 100),
            Err(Error::SenderMismatch)
        ));
    }

    #[test]
    fn nonces_advance_in_order() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        for nonce in 0..3 {
            let p = signed_proposal(&alice, &bob, nonce, 100, 100_000);
            engine.submit_proposal(p, 100).unwrap();
        }
    }

    #[test]
    fn confirm_then_state_is_confirmed() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p = signed_proposal(&alice, &bob, 0, 100, 100_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Proposed { .. })
        ));

        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 200,
        };
        engine
            .submit_confirmation(SignedConfirmation::sign(c, &bob), 200)
            .unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Confirmed { .. })
        ));
    }

    #[test]
    fn confirmation_by_non_receiver_is_rejected() {
        let db = fresh_db();
        let (alice, bob, mallory, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p = signed_proposal(&alice, &bob, 0, 100, 100_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        // Mallory tries to confirm a transaction addressed to Bob.
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&mallory),
            confirmed_at: 200,
        };
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &mallory), 200),
            Err(Error::ConfirmerMismatch)
        ));
    }

    #[test]
    fn cancel_moves_proposed_to_cancelled() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p = signed_proposal(&alice, &bob, 0, 100, 100_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();
        engine
            .cancel_proposal(&id, CancelReason::WithdrawnBySender, 150)
            .unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Cancelled {
                reason: CancelReason::WithdrawnBySender,
                ..
            })
        ));

        // A cancelled proposal can no longer be confirmed.
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 200,
        };
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), 200),
            Err(Error::NotProposed)
        ));
    }

    #[test]
    fn a_proposal_below_the_debt_floor_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine =
            Engine::new(&db, station).with_credit_config(crate::credit::CreditConfig {
                debt_floor_centi: -500,
            });

        // 5 Commons (500 centi) down to exactly the floor: allowed.
        let at_floor =
            TransactionProposal::new(addr(&alice), addr(&bob), 500, None, 0, 100, 100_000);
        engine
            .submit_proposal(SignedProposal::sign(at_floor, &alice), 100)
            .unwrap();

        // One more centicommon of committed debt breaches the floor. The pending
        // (unsettled) 500 must count: the projected position is -501.
        let over = TransactionProposal::new(addr(&alice), addr(&bob), 1, None, 1, 100, 100_000);
        assert!(matches!(
            engine.submit_proposal(SignedProposal::sign(over, &alice), 100),
            Err(Error::DebtFloorExceeded {
                floor_centi: -500,
                projected_centi: -501,
            })
        ));

        // Nothing was written: nonce 1 is still free for a proposal that fits.
        let recipient_pays =
            TransactionProposal::new(addr(&alice), addr(&bob), -300, None, 1, 100, 100_000);
        engine
            .submit_proposal(SignedProposal::sign(recipient_pays, &alice), 100)
            .unwrap();
    }

    #[test]
    fn confirming_a_payment_request_checks_the_receivers_floor() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine =
            Engine::new(&db, station).with_credit_config(crate::credit::CreditConfig {
                debt_floor_centi: -500,
            });

        // Alice requests 501 from Bob (negative amount = receiver pays). The
        // proposal itself is fine — Bob has signed nothing yet.
        let request =
            TransactionProposal::new(addr(&alice), addr(&bob), -501, None, 0, 100, 100_000);
        let id = request.id;
        engine
            .submit_proposal(SignedProposal::sign(request, &alice), 100)
            .unwrap();

        // Bob's confirmation is his signature on the debit, and it breaches
        // his floor.
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 200,
        };
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), 200),
            Err(Error::DebtFloorExceeded {
                floor_centi: -500,
                projected_centi: -501,
            })
        ));
    }

    #[test]
    fn settled_debt_counts_against_the_floor() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine =
            Engine::new(&db, station.clone()).with_credit_config(crate::credit::CreditConfig {
                debt_floor_centi: -500,
            });

        // Alice pays Bob 300 and it settles: her settled balance is -300.
        let id = confirmed(&mut engine, &alice, &bob, 200);
        let mut settler =
            crate::settlement::Settler::new(&db, station, SettlementConfig::uniform(10));
        settler.settle(&id, 1_000).unwrap();

        // `confirmed` used amount 300, so Alice sits at -300 settled. 200 more
        // reaches -500 exactly; 201 would breach.
        let breach =
            TransactionProposal::new(addr(&alice), addr(&bob), 201, None, 1, 2_000, 100_000);
        assert!(matches!(
            engine.submit_proposal(SignedProposal::sign(breach, &alice), 2_000),
            Err(Error::DebtFloorExceeded {
                floor_centi: -500,
                projected_centi: -501,
            })
        ));
        let fits = TransactionProposal::new(addr(&alice), addr(&bob), 200, None, 1, 2_000, 100_000);
        engine
            .submit_proposal(SignedProposal::sign(fits, &alice), 2_000)
            .unwrap();
    }

    #[test]
    fn a_cancelled_proposal_releases_its_headroom() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine =
            Engine::new(&db, station).with_credit_config(crate::credit::CreditConfig {
                debt_floor_centi: -500,
            });

        let p = signed_proposal(&alice, &bob, 0, 100, 100_000); // 300 centi
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        // With 300 pending, another 300 would project to -600: rejected.
        let too_much =
            TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 1, 100, 100_000);
        assert!(engine
            .submit_proposal(SignedProposal::sign(too_much, &alice), 100)
            .is_err());

        // Withdrawing the first releases its 300; the same amount now fits.
        engine
            .cancel_proposal(&id, CancelReason::WithdrawnBySender, 150)
            .unwrap();
        let fits = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 1, 100, 100_000);
        engine
            .submit_proposal(SignedProposal::sign(fits, &alice), 100)
            .unwrap();
    }

    #[test]
    fn an_expired_unconfirmed_proposal_releases_its_headroom() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine =
            Engine::new(&db, station).with_credit_config(crate::credit::CreditConfig {
                debt_floor_centi: -500,
            });

        // Alice signs 500 down to exactly the floor; Bob never confirms.
        let stale = TransactionProposal::new(addr(&alice), addr(&bob), 500, None, 0, 100, 1_000);
        engine
            .submit_proposal(SignedProposal::sign(stale, &alice), 100)
            .unwrap();

        // While the stale proposal is still confirmable, its 500 stays committed.
        let blocked = TransactionProposal::new(addr(&alice), addr(&bob), 100, None, 1, 100, 9_000);
        assert!(matches!(
            engine.submit_proposal(SignedProposal::sign(blocked, &alice), 500),
            Err(Error::DebtFloorExceeded { .. })
        ));

        // Once it is past expiry (plus skew) it can never land, so the same
        // amount fits again — without anyone writing a cancellation.
        let after = 1_000 + CLOCK_SKEW_TOLERANCE_SECS + 1;
        let fits = TransactionProposal::new(addr(&alice), addr(&bob), 100, None, 1, 100, 9_000);
        engine
            .submit_proposal(SignedProposal::sign(fits, &alice), after)
            .unwrap();
    }

    #[test]
    fn a_backdated_confirmation_of_an_expired_proposal_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p = signed_proposal(&alice, &bob, 0, 100, 1_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        // Long after expiry, Bob backdates `confirmed_at` into the window. The
        // station's own clock still refuses it — otherwise the expiry boundary
        // (and the debt-floor headroom released past it) would be spoofable.
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 900,
        };
        let after = 1_000 + CLOCK_SKEW_TOLERANCE_SECS + 1;
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), after),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn an_old_confirmation_is_admissible() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Propose at t=100 with a long validity window.
        let p = signed_proposal(&alice, &bob, 0, 100, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        // A confirmation carried offline arrives at t=500_000 still claiming an
        // old `confirmed_at=150`. Under the admission clock this is admissible —
        // old means carried; the windows run from admission (ADR-0022 §3). Under
        // the retired ADR-0019 staleness refusal it would have been rejected.
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 150,
        };
        engine
            .submit_confirmation(SignedConfirmation::sign(c, &bob), 500_000)
            .unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Confirmed { .. })
        ));
    }

    #[test]
    fn a_confirmation_predating_its_proposal_is_refused() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Proposed at t=10_000; a confirmation cannot claim to have happened
        // before that (beyond skew) — that is not "carried", it is inconsistent
        // testimony (ADR-0022 §3).
        let p = signed_proposal(&alice, &bob, 0, 10_000, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 10_000).unwrap();

        let confirmed_at = 10_000 - CLOCK_SKEW_TOLERANCE_SECS - 1;
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at,
        };
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), 20_000),
            Err(Error::InconsistentTimestamp {
                confirmed_at: got_confirmed,
                proposed_at: 10_000,
            }) if got_confirmed == confirmed_at
        ));
    }

    #[test]
    fn expiry_is_judged_by_the_admission_clock() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Offer stands only until t=1_000. A confirmation admitted past that
        // boundary (plus skew) is `Expired` regardless of a small, in-window
        // `confirmed_at` — expiry is the admission clock's call alone (§4).
        let p = signed_proposal(&alice, &bob, 0, 100, 1_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 150,
        };
        let after = 1_000 + CLOCK_SKEW_TOLERANCE_SECS + 1;
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), after),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn a_future_dated_confirmation_is_still_refused() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p = signed_proposal(&alice, &bob, 0, 100, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        // A `confirmed_at` ahead of the station clock (beyond skew) would defer
        // the settlement clock; it is refused symmetrically.
        let now = 500;
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: now + CLOCK_SKEW_TOLERANCE_SECS + 1,
        };
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), now),
            Err(Error::FutureDated)
        ));
    }

    #[test]
    fn a_confirmation_within_skew_of_the_station_clock_is_accepted() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        let p = signed_proposal(&alice, &bob, 0, 100, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();

        // A mobile clock a full skew tolerance behind the station's is
        // legitimate testimony — accepted, as any non-future, internally
        // consistent `confirmed_at` now is (ADR-0022 §3).
        let now = 200_000;
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: now - CLOCK_SKEW_TOLERANCE_SECS,
        };
        engine
            .submit_confirmation(SignedConfirmation::sign(c, &bob), now)
            .unwrap();
    }

    #[test]
    fn get_state_unknown_is_none() {
        let db = fresh_db();
        let station = Keypair::generate();
        let engine = Engine::new(&db, station);
        let missing = TransactionId(rrn_crypto::hash::Hash::of(b"missing"));
        assert!(engine.get_state(&missing).unwrap().is_none());
    }

    /// Proposes and confirms a transaction through the engine, returning its id
    /// in the `Confirmed` state.
    fn confirmed(
        engine: &mut Engine,
        alice: &Keypair,
        bob: &Keypair,
        confirmed_at: i64,
    ) -> TransactionId {
        let p = signed_proposal(alice, bob, 0, 100, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(bob),
            confirmed_at,
        };
        engine
            .submit_confirmation(SignedConfirmation::sign(c, bob), confirmed_at)
            .unwrap();
        id
    }

    /// Proposes and confirms a transaction, admitting the confirmation at a
    /// `admitted_at` distinct from its claimed `confirmed_at`, so window
    /// arithmetic can be tested against admission time specifically.
    fn confirmed_with_admission(
        engine: &mut Engine,
        alice: &Keypair,
        bob: &Keypair,
        confirmed_at: i64,
        admitted_at: i64,
    ) -> TransactionId {
        let p = signed_proposal(alice, bob, 0, 100, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(bob),
            confirmed_at,
        };
        engine
            .submit_confirmation(SignedConfirmation::sign(c, bob), admitted_at)
            .unwrap();
        id
    }

    fn signed_dispute(id: TransactionId, raiser: &Keypair, opened_at: i64) -> SignedDispute {
        let d = crate::dispute::DisputeRecord {
            proposal_id: id,
            raiser: addr(raiser),
            reason: "goods never arrived".into(),
            evidence_hash: None,
            opened_at,
        };
        SignedDispute::sign(d, raiser)
    }

    #[test]
    fn raise_dispute_freezes_a_confirmed_transaction() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = confirmed(&mut engine, &alice, &bob, 200);
        // The sender contests it inside the window.
        engine
            .raise_dispute(signed_dispute(id, &alice, 300), &cfg, 300)
            .unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Disputed { .. })
        ));
    }

    #[test]
    fn dispute_window_runs_from_confirmation_admission() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let w = 5_000i64;
        let cfg = SettlementConfig::uniform(w as u64);

        // Confirmed with a backdated `confirmed_at=100` but admitted at 10_000.
        // The window is measured from admission, so it closes at 10_000 + w, not
        // at the claimed 100 + w (which is already long past).
        let id = confirmed_with_admission(&mut engine, &alice, &bob, 100, 10_000);

        // Just inside the window from admission → admitted, even with an ancient
        // claimed `opened_at` (testimony is not staleness-checked, ADR-0022 §5).
        engine
            .raise_dispute(signed_dispute(id, &alice, 100), &cfg, 10_000 + w - 1)
            .unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Disputed { .. })
        ));

        // Past the window from admission (plus skew) → refused, even though the
        // same `now` is well within `confirmed_at + w` under the old anchor.
        let db2 = fresh_db();
        let (a2, b2, s2) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine2 = Engine::new(&db2, s2);
        let id2 = confirmed_with_admission(&mut engine2, &a2, &b2, 100, 10_000);
        let too_late = 10_000 + w + CLOCK_SKEW_TOLERANCE_SECS + 1;
        assert!(matches!(
            engine2.raise_dispute(signed_dispute(id2, &a2, too_late), &cfg, too_late),
            Err(Error::DisputeWindowClosed)
        ));
    }

    #[test]
    fn dispute_by_a_stranger_is_rejected() {
        let db = fresh_db();
        let (alice, bob, mallory, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = confirmed(&mut engine, &alice, &bob, 200);
        assert!(matches!(
            engine.raise_dispute(signed_dispute(id, &mallory, 300), &cfg, 300),
            Err(Error::NotAParty)
        ));
        // Nothing was frozen.
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Confirmed { .. })
        ));
    }

    #[test]
    fn dispute_after_the_window_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = confirmed(&mut engine, &alice, &bob, 200);
        // Opened well past confirmed_at + window (+ skew).
        assert!(matches!(
            engine.raise_dispute(signed_dispute(id, &bob, 50_000), &cfg, 50_000),
            Err(Error::DisputeWindowClosed)
        ));
    }

    #[test]
    fn disputing_an_unconfirmed_transaction_is_rejected() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        // Proposed but not confirmed.
        let p = signed_proposal(&alice, &bob, 0, 100, 1_000_000);
        let id = p.payload.id;
        engine.submit_proposal(p, 100).unwrap();
        assert!(matches!(
            engine.raise_dispute(signed_dispute(id, &alice, 300), &cfg, 300),
            Err(Error::NotConfirmed)
        ));
    }

    #[test]
    fn upholding_a_dispute_voids_the_transfer() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = confirmed(&mut engine, &alice, &bob, 200);
        engine
            .raise_dispute(signed_dispute(id, &bob, 300), &cfg, 300)
            .unwrap();
        engine.uphold_dispute(&id, 400).unwrap();
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Cancelled {
                reason: CancelReason::DisputeUpheld,
                ..
            })
        ));
    }

    #[test]
    fn upholding_requires_a_disputed_transaction() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Confirmed but never disputed.
        let id = confirmed(&mut engine, &alice, &bob, 200);
        assert!(matches!(
            engine.uphold_dispute(&id, 400),
            Err(Error::NotDisputed)
        ));
    }

    fn signed_response(
        id: TransactionId,
        responder: &Keypair,
        responded_at: i64,
    ) -> SignedDisputeResponse {
        let r = crate::dispute::DisputeResponse {
            proposal_id: id,
            responder: addr(responder),
            statement: "the goods were delivered on time".into(),
            evidence_hash: None,
            responded_at,
        };
        SignedDisputeResponse::sign(r, responder)
    }

    /// Confirms a transaction and freezes it with a dispute the sender raised,
    /// returning its id in the `Disputed` state.
    fn disputed(
        engine: &mut Engine,
        alice: &Keypair,
        bob: &Keypair,
        cfg: &SettlementConfig,
    ) -> TransactionId {
        let id = confirmed(engine, alice, bob, 200);
        engine
            .raise_dispute(signed_dispute(id, alice, 300), cfg, 300)
            .unwrap();
        id
    }

    #[test]
    fn counterparty_can_respond_to_a_dispute() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = disputed(&mut engine, &alice, &bob, &cfg);
        // The receiver (the confirmer under contest) states their side.
        engine
            .respond_to_dispute(signed_response(id, &bob, 400), 400)
            .unwrap();
        // A response changes no state — the transaction stays frozen.
        assert!(matches!(
            engine.get_state(&id).unwrap(),
            Some(TransactionState::Disputed { .. })
        ));
        let responses = crate::dispute::dispute_responses(&db, &id).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].responder, addr(&bob));
    }

    #[test]
    fn a_stranger_cannot_respond() {
        let db = fresh_db();
        let (alice, bob, mallory, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = disputed(&mut engine, &alice, &bob, &cfg);
        assert!(matches!(
            engine.respond_to_dispute(signed_response(id, &mallory, 400), 400),
            Err(Error::NotAParty)
        ));
        assert!(crate::dispute::dispute_responses(&db, &id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_party_responds_only_once() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);
        let cfg = SettlementConfig::uniform(10_000);

        let id = disputed(&mut engine, &alice, &bob, &cfg);
        engine
            .respond_to_dispute(signed_response(id, &bob, 400), 400)
            .unwrap();
        assert!(matches!(
            engine.respond_to_dispute(signed_response(id, &bob, 500), 500),
            Err(Error::AlreadyResponded)
        ));
        // Both parties may respond, so the raiser adding their own is fine.
        engine
            .respond_to_dispute(signed_response(id, &alice, 500), 500)
            .unwrap();
        assert_eq!(
            crate::dispute::dispute_responses(&db, &id).unwrap().len(),
            2
        );
    }

    #[test]
    fn responding_requires_a_disputed_transaction() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let mut engine = Engine::new(&db, station);

        // Confirmed but never disputed.
        let id = confirmed(&mut engine, &alice, &bob, 200);
        assert!(matches!(
            engine.respond_to_dispute(signed_response(id, &bob, 400), 400),
            Err(Error::NotDisputed)
        ));
    }
}
