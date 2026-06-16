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
//! - **uniqueness**: a proposal whose id is already in the log is rejected.
//!
//! Each accepted operation appends one signed entry to the log; the engine keeps
//! no mutable state of its own, deriving everything from the log on demand.

use rrn_crypto::keypair::Keypair;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

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
}

impl<'db> Engine<'db> {
    /// Creates an engine over `db`, signing station-authored records (e.g.
    /// cancellations) with `station`.
    pub fn new(db: &'db Database, station: Keypair) -> Self {
        Self { station, db }
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

        let (id, nonce) = (p.id, p.nonce);
        AppendLog::new(self.db).append(proposal)?;
        tracing::info!(tx = ?id, nonce, "proposal accepted");
        Ok(())
    }

    /// Submits a receiver-signed confirmation of an existing proposal.
    ///
    /// Errors on a bad signature, an unknown or non-`Proposed` transaction, a
    /// confirmer that is not the receiver, or a confirmation past expiry.
    pub fn submit_confirmation(
        &mut self,
        confirmation: SignedConfirmation,
        now: i64,
    ) -> Result<()> {
        let _ = now; // `now` is reserved for future freshness checks on confirmations.
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

        // A receiver may refuse to confirm an expired proposal; enforce it.
        if c.confirmed_at > p.expires_at.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
            return Err(Error::Expired);
        }

        let proposal_id = c.proposal_id;
        AppendLog::new(self.db).append(confirmation)?;
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
        AppendLog::new(self.db).append(rrn_crypto::signed::SignedPayload::sign(
            record,
            &self.station,
        ))?;
        tracing::info!(tx = ?tx_id, ?reason, "proposal cancelled");
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
    fn get_state_unknown_is_none() {
        let db = fresh_db();
        let station = Keypair::generate();
        let engine = Engine::new(&db, station);
        let missing = TransactionId(rrn_crypto::hash::Hash::of(b"missing"));
        assert!(engine.get_state(&missing).unwrap().is_none());
    }
}
