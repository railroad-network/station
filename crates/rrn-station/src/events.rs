//! Deriving a member's push events from the append-only log (T1.3.5).
//!
//! The mobile long-poll (`/subscribe`) needs to answer one question: *what has
//! happened, relevant to this member, since the last thing it saw?* We answer it
//! straight from the log rather than maintaining a separate per-mobile queue: the
//! log already stores every proposal / confirmation / settlement / cancellation
//! as a numbered ([`seq`](rrn_storage::log::StoredEntry::seq)), originator-signed
//! entry that survives a restart, so "events since you last looked" is just "log
//! entries after your cursor that concern you". The mobile holds the cursor (a
//! log seq) and sends it each subscribe; the station stays delivery-stateless.
//! See ADR-0008 and the M1.3 exit criterion.
//!
//! **Directional relevance, not merely party-hood.** A member is not notified of
//! their *own* action — the sender already knows they proposed. So:
//! `proposal_received` → the receiver; `confirmation_received` → the original
//! sender (the receiver did the confirming); `settlement` → both parties;
//! `cancellation` → the counterparty of whoever caused it (both, on expiry). The
//! display payload is the same member-relative [`TransactionRow`] the wallet
//! already renders (reusing [`transaction_view::row_for`]).

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::attestation::Attestation;
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::{CancelReason, CancellationRecord, LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::{TransactionConfirmation, TransactionId, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use serde::Serialize;

use crate::rpc::TransactionRow;
use crate::transaction_view::row_for;

/// The kind of a push event. The full set is the T1.3.5 wire contract so the
/// mobile router can handle a future type gracefully; only the first four have a
/// live ledger source in M1.3 (the rest arrive with later milestones).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A payment was proposed to this member (delivered to the receiver).
    ProposalReceived,
    /// This member's proposal was confirmed (delivered to the sender).
    ConfirmationReceived,
    /// A transaction this member is party to settled (delivered to both).
    Settlement,
    /// A proposal this member is party to was cancelled/expired (delivered to
    /// the counterparty of whoever caused it; to both on expiry).
    Cancellation,
    /// Someone vouched for this member (delivered to the subject; T1.4.1).
    VouchReceived,
    /// M1.6/M1.7 — no live source yet.
    ListingMatch,
    /// M1.9 — no live source yet.
    GovernanceProposal,
    /// M1.9 — no live source yet.
    VoteNeeded,
}

/// One push event: its id (the log seq), its kind, and the payload the wallet
/// renders — a transaction row for the ledger kinds, a vouch row for a vouch.
/// Exactly one of the two payload fields is present; the absent one is omitted
/// from the wire so the T1.3.5 payment-event shape is unchanged.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// The event id — the log entry's seq. Monotonic; the mobile acks by sending
    /// the highest it has seen as its next `last_seen_event_id`.
    pub id: u64,
    /// What happened.
    pub kind: EventKind,
    /// The transaction, from `member`'s vantage point (T1.3.4 shape). Present
    /// for the four ledger kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionRow>,
    /// The vouch, for a `vouch_received` event (T1.4.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vouch: Option<VouchRow>,
}

/// The display payload of a `vouch_received` event: who vouched, in which
/// community, with what statement and stake. Mirrors what `submit_vouch`
/// recorded; the `vouch_id` is the same content address it returned.
#[derive(Debug, Clone, Serialize)]
pub struct VouchRow {
    /// Content address: hex of the Blake3 hash of the signed canonical bytes.
    pub vouch_id: String,
    /// The voucher's bech32m `rrn1…` address (the log entry's signer).
    pub voucher_address: String,
    /// The community the vouch was stamped into.
    pub community: String,
    /// The voucher's free-text statement about the subject.
    pub statement: String,
    /// Reputation staked, in centipoints.
    pub stake_centi: u64,
    /// Unix seconds when the vouch was issued.
    pub issued_at: i64,
}

/// The events after `after_seq` (exclusive) through `tail` (inclusive) that are
/// relevant to `member`, oldest first. Bounds are log seqs; `after_seq` is the
/// mobile's cursor and `tail` the current log tail the caller already observed.
pub fn events_since(db: &Database, member: &Address, after_seq: u64, tail: u64) -> Vec<Event> {
    let log = AppendLog::new(db);
    let snapshot = match LedgerSnapshot::derive(&log) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "events_since: could not derive snapshot");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for entry in log.iter_from(after_seq + 1) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "events_since: log read error");
                break;
            }
        };
        if entry.seq > tail {
            break; // past the observed tail (iter is ascending)
        }
        if let Some((kind, tx_id)) = classify(&entry.payload.bytes, member, &snapshot) {
            if let Some(row) = snapshot.get(&tx_id).and_then(|s| row_for(s, member)) {
                out.push(Event {
                    id: entry.seq,
                    kind,
                    transaction: Some(row),
                    vouch: None,
                });
            }
        } else if let Some(row) =
            classify_vouch(&entry.payload.bytes, &entry.payload.signer, member)
        {
            out.push(Event {
                id: entry.seq,
                kind: EventKind::VouchReceived,
                transaction: None,
                vouch: Some(row),
            });
        }
    }
    out
}

/// Classifies one stored log payload into `(kind, transaction id)` **if** it is
/// a ledger event `member` should receive, applying the directional relevance
/// rules. Returns `None` for a non-ledger record (a vouch — see
/// [`classify_vouch`]) or a transition that does not target this member.
fn classify(
    bytes: &[u8],
    member: &Address,
    snapshot: &LedgerSnapshot,
) -> Option<(EventKind, TransactionId)> {
    if let Ok(proposal) = from_canonical_bytes::<TransactionProposal>(bytes) {
        // The sender already knows they proposed; notify only the receiver.
        return (member == &proposal.receiver)
            .then_some((EventKind::ProposalReceived, proposal.id));
    }
    if let Ok(confirmation) = from_canonical_bytes::<TransactionConfirmation>(bytes) {
        // The confirmer is the receiver; notify the original sender.
        let (sender, _receiver) = parties(snapshot, &confirmation.proposal_id)?;
        return (member == &sender)
            .then_some((EventKind::ConfirmationReceived, confirmation.proposal_id));
    }
    if let Ok(settlement) = from_canonical_bytes::<SettlementRecord>(bytes) {
        return (member == &settlement.sender || member == &settlement.receiver)
            .then_some((EventKind::Settlement, settlement.proposal_id));
    }
    if let Ok(cancellation) = from_canonical_bytes::<CancellationRecord>(bytes) {
        let (sender, receiver) = parties(snapshot, &cancellation.proposal_id)?;
        let targets_member = match cancellation.reason {
            CancelReason::WithdrawnBySender => member == &receiver,
            CancelReason::RejectedByReceiver => member == &sender,
            CancelReason::Expired => member == &sender || member == &receiver,
        };
        return targets_member.then_some((EventKind::Cancellation, cancellation.proposal_id));
    }
    None
}

/// Classifies one stored log payload into a [`VouchRow`] **if** it is a vouch
/// whose subject is `member`. The voucher already knows they vouched, so only
/// the subject is notified. The voucher's address comes from the entry's signer
/// (the attestation carries no issuer field — the signature envelope is the
/// issuer), and the `vouch_id` is the Blake3 hash of the stored canonical bytes,
/// matching what `submit_vouch` returned to the voucher.
fn classify_vouch(bytes: &[u8], signer: &PublicKey, member: &Address) -> Option<VouchRow> {
    let vouch = from_canonical_bytes::<Attestation<VouchKind, VouchBody>>(bytes).ok()?;
    if member != &vouch.subject {
        return None;
    }
    Some(VouchRow {
        vouch_id: Hash::of(bytes).to_hex(),
        voucher_address: Address::from_public_key(*signer).to_string(),
        community: vouch.body.community,
        statement: vouch.body.statement,
        stake_centi: vouch.body.reputation_stake_centi,
        issued_at: vouch.issued_at,
    })
}

/// The `(sender, receiver)` of the transaction `id` in the snapshot, if present.
fn parties(snapshot: &LedgerSnapshot, id: &TransactionId) -> Option<(Address, Address)> {
    let proposal = match snapshot.get(id)? {
        TransactionState::Proposed { proposal }
        | TransactionState::Confirmed { proposal, .. }
        | TransactionState::Settled { proposal, .. }
        | TransactionState::Cancelled { proposal, .. } => &proposal.payload,
        TransactionState::DisputedStub => return None,
    };
    Some((proposal.sender, proposal.receiver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_ledger::transaction::{SignedConfirmation, SignedProposal};
    use rrn_storage::migrations;

    /// Include everything appended (the handler passes the real observed tail).
    const ALL: u64 = u64::MAX;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    fn append_proposal(
        db: &Database,
        sender: &Keypair,
        receiver: &Address,
        nonce: u64,
    ) -> TransactionId {
        let p = TransactionProposal::new(
            addr(sender),
            *receiver,
            500,
            Some("m".into()),
            nonce,
            1_000,
            1_000 + 86_400,
        );
        let id = p.id;
        AppendLog::new(db)
            .append(SignedProposal::sign(p, sender))
            .unwrap();
        id
    }

    fn append_confirmation(db: &Database, receiver: &Keypair, proposal_id: TransactionId) {
        let c = TransactionConfirmation {
            proposal_id,
            confirmer: addr(receiver),
            confirmed_at: 1_100,
        };
        AppendLog::new(db)
            .append(SignedConfirmation::sign(c, receiver))
            .unwrap();
    }

    fn append_settlement(
        db: &Database,
        station: &Keypair,
        sender: &Address,
        receiver: &Address,
        proposal_id: TransactionId,
    ) {
        let rec = SettlementRecord {
            proposal_id,
            sender: *sender,
            receiver: *receiver,
            amount_centi: 500,
            settled_at: 2_000,
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(rec, station))
            .unwrap();
    }

    fn append_cancellation(
        db: &Database,
        station: &Keypair,
        proposal_id: TransactionId,
        reason: CancelReason,
    ) {
        let rec = CancellationRecord {
            proposal_id,
            reason,
            cancelled_at: 1_500,
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(rec, station))
            .unwrap();
    }

    fn kinds(events: &[Event]) -> Vec<EventKind> {
        events.iter().map(|e| e.kind).collect()
    }

    #[test]
    fn proposal_notifies_the_receiver_not_the_sender() {
        let db = fresh_db();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        append_proposal(&db, &alice, &addr(&bob), 0);

        let to_bob = events_since(&db, &addr(&bob), 0, ALL);
        assert_eq!(kinds(&to_bob), vec![EventKind::ProposalReceived]);
        assert_eq!(to_bob[0].transaction.as_ref().unwrap().direction, "in");
        assert_eq!(to_bob[0].id, 1);

        // The sender is never told about their own proposal.
        assert!(events_since(&db, &addr(&alice), 0, ALL).is_empty());
    }

    #[test]
    fn confirmation_notifies_the_original_sender_not_the_confirmer() {
        let db = fresh_db();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        let id = append_proposal(&db, &alice, &addr(&bob), 0);
        append_confirmation(&db, &bob, id);

        let to_alice = events_since(&db, &addr(&alice), 0, ALL);
        assert_eq!(kinds(&to_alice), vec![EventKind::ConfirmationReceived]);
        assert_eq!(to_alice[0].transaction.as_ref().unwrap().state, "confirmed");
        assert_eq!(to_alice[0].id, 2);

        // Bob (the confirmer/receiver) only ever saw the proposal, not his own confirmation.
        assert_eq!(
            kinds(&events_since(&db, &addr(&bob), 0, ALL)),
            vec![EventKind::ProposalReceived]
        );
    }

    #[test]
    fn settlement_notifies_both_parties() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = append_proposal(&db, &alice, &addr(&bob), 0);
        append_confirmation(&db, &bob, id);
        append_settlement(&db, &station, &addr(&alice), &addr(&bob), id);

        assert!(kinds(&events_since(&db, &addr(&alice), 0, ALL)).contains(&EventKind::Settlement));
        assert!(kinds(&events_since(&db, &addr(&bob), 0, ALL)).contains(&EventKind::Settlement));
    }

    #[test]
    fn rejection_notifies_the_sender_not_the_rejecting_receiver() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = append_proposal(&db, &alice, &addr(&bob), 0);
        append_cancellation(&db, &station, id, CancelReason::RejectedByReceiver);

        let to_alice = events_since(&db, &addr(&alice), 0, ALL);
        assert_eq!(kinds(&to_alice), vec![EventKind::Cancellation]);
        assert_eq!(to_alice[0].transaction.as_ref().unwrap().state, "cancelled");

        // Bob rejected it, so he is not notified of the cancellation.
        assert!(!kinds(&events_since(&db, &addr(&bob), 0, ALL)).contains(&EventKind::Cancellation));
    }

    #[test]
    fn expiry_notifies_both_parties() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = append_proposal(&db, &alice, &addr(&bob), 0);
        append_cancellation(&db, &station, id, CancelReason::Expired);

        assert!(kinds(&events_since(&db, &addr(&alice), 0, ALL)).contains(&EventKind::Cancellation));
        assert!(kinds(&events_since(&db, &addr(&bob), 0, ALL)).contains(&EventKind::Cancellation));
    }

    #[test]
    fn the_cursor_excludes_already_seen_events() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = append_proposal(&db, &alice, &addr(&bob), 0); // seq 1
        append_confirmation(&db, &bob, id); // seq 2
        append_settlement(&db, &station, &addr(&alice), &addr(&bob), id); // seq 3

        // From the start, Bob sees the proposal (1) and the settlement (3).
        let all = events_since(&db, &addr(&bob), 0, ALL);
        assert_eq!(all.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 3]);

        // With the cursor past seq 1, only the settlement remains.
        let after_one = events_since(&db, &addr(&bob), 1, ALL);
        assert_eq!(after_one.iter().map(|e| e.id).collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn the_tail_bound_excludes_newer_events() {
        let db = fresh_db();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        append_proposal(&db, &alice, &addr(&bob), 0); // seq 1
        append_proposal(&db, &alice, &addr(&bob), 1); // seq 2

        // Observing tail = 1 must not leak the seq-2 proposal.
        let bounded = events_since(&db, &addr(&bob), 0, 1);
        assert_eq!(bounded.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1]);
    }

    #[test]
    fn a_vouch_notifies_the_subject_not_the_voucher() {
        let db = fresh_db();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        let vouch = rrn_identity::vouch::create_vouch(
            &alice,
            &addr(&bob),
            "rrn-phase0",
            "I know Bob in person",
            150,
        );
        let expected_id = vouch.payload_hash().to_hex();
        rrn_identity::vouch::append_vouch(&mut AppendLog::new(&db), vouch).unwrap();

        let to_bob = events_since(&db, &addr(&bob), 0, ALL);
        assert_eq!(kinds(&to_bob), vec![EventKind::VouchReceived]);
        assert!(to_bob[0].transaction.is_none());
        let row = to_bob[0].vouch.as_ref().unwrap();
        assert_eq!(row.vouch_id, expected_id);
        assert_eq!(row.voucher_address, addr(&alice).to_string());
        assert_eq!(row.community, "rrn-phase0");
        assert_eq!(row.statement, "I know Bob in person");
        assert_eq!(row.stake_centi, 150);

        // The voucher already knows they vouched; they are not notified.
        assert!(events_since(&db, &addr(&alice), 0, ALL).is_empty());
    }

    #[test]
    fn a_vouch_for_someone_else_is_not_delivered() {
        let db = fresh_db();
        let (alice, bob, carol) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let vouch = rrn_identity::vouch::create_vouch(&alice, &addr(&bob), "rrn-phase0", "", 0);
        rrn_identity::vouch::append_vouch(&mut AppendLog::new(&db), vouch).unwrap();

        assert!(events_since(&db, &addr(&carol), 0, ALL).is_empty());
    }

    #[test]
    fn a_stranger_gets_nothing() {
        let db = fresh_db();
        let (alice, bob, carol, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = append_proposal(&db, &alice, &addr(&bob), 0);
        append_confirmation(&db, &bob, id);
        append_settlement(&db, &station, &addr(&alice), &addr(&bob), id);

        assert!(events_since(&db, &addr(&carol), 0, ALL).is_empty());
    }
}
