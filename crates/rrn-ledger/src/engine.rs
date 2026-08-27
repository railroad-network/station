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
    /// confirmer that is not the receiver, a confirmation past expiry, or a
    /// `confirmed_at` outside clock-skew tolerance of the station's own clock
    /// (ADR-0019).
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

        // A receiver may refuse to confirm an expired proposal; enforce it — by
        // the station's own clock, not just the receiver-supplied `confirmed_at`
        // (which a late confirmer could backdate). This is also what lets the
        // debt floor release the headroom of an expired unconfirmed proposal:
        // past this boundary the debit can never land (see [`crate::credit`]).
        if now > p.expires_at.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::Expired);
        }
        if c.confirmed_at > p.expires_at.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::Expired);
        }

        // `confirmed_at` anchors both the settlement window and the dispute-
        // open deadline, so it must be *fresh* — within clock-skew tolerance
        // of the station's clock at receipt. Without this, a receiver
        // confirming late but inside the validity window could backdate
        // `confirmed_at` and shrink (or wholly skip) the dispute window the
        // Phase-1 oracle rests on (ADR-0019).
        if c.confirmed_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::FutureDated);
        }
        if c.confirmed_at < now.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::StaleConfirmation);
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
        let (proposal, confirmation) = match snapshot.get(&d.proposal_id) {
            Some(TransactionState::Confirmed {
                proposal,
                confirmation,
            }) => (proposal, confirmation),
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

        // The dispute must fall inside the settlement window: no earlier than the
        // confirmation it contests, and no later than the moment the sweep would
        // have settled it (with clock-skew tolerance, as elsewhere). A dispute
        // that arrives after settlement finds the transaction already `Settled`
        // and fails the `Confirmed` check above; this bounds the honest case.
        let window = settlement.window_for(p.effective_tier()) as i64;
        let confirmed_at = confirmation.payload.confirmed_at;
        let deadline = confirmed_at
            .saturating_add(window)
            .saturating_add(CLOCK_SKEW_TOLERANCE_SECS);
        if d.opened_at < confirmed_at.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS)
            || d.opened_at > deadline
            || d.opened_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS)
        {
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
    fn a_backdated_confirmation_inside_the_validity_window_is_rejected() {
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

        // Long before expiry, Bob confirms — but stamps `confirmed_at` back at
        // the start of the validity window. Accepting it would start the
        // settlement clock in the past and eat the dispute window, so anything
        // staler than the skew tolerance is refused.
        let c = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(&bob),
            confirmed_at: 100,
        };
        assert!(matches!(
            engine.submit_confirmation(SignedConfirmation::sign(c, &bob), 200_000),
            Err(Error::StaleConfirmation)
        ));
    }

    #[test]
    fn a_future_dated_confirmation_is_rejected() {
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

        // Exactly at the stale boundary: a mobile clock a full skew tolerance
        // behind the station's is still legitimate.
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
