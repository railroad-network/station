//! Station-signer pinning for the station-signed ledger record kinds (ADR-0005,
//! ADR-0020, ADR-0021 §5) — the ledger counterpart of the governance
//! signer-pinning suite.
//!
//! Every record whose authority is "the station said so" — settlement,
//! cancellation, headroom certificate, equivocation record, and equivocation
//! verdict — is trusted at replay only when its envelope signer is the community
//! station key. A record of one of those kinds signed by any other key (the shape
//! a hostile gossip peer injects via `append_raw`) is **skipped** during
//! derivation, never a hard error, so it is inert: it moves no balance, reserves
//! no headroom, occupies no dedup slot, and lifts no penalty — and the genuine
//! record still applies. Each forgery is raw-appended *before* the genuine record,
//! so it is the signer pin, not log ordering, that makes the genuine one win.

use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::credit::{committed_debits_centi, CreditConfig};
use rrn_ledger::engine::Engine;
use rrn_ledger::escrow::{
    CertificateRequest, EquivocationBasis, EquivocationRecord, EquivocationVerdictRecord,
    EvidenceItem, HeadroomCertificate, VerdictDecision,
};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::{CancelReason, CancellationRecord, LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_ledger::Error;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

/// A signed proposal → confirmation pair for one transaction, both member-signed.
fn confirmed(
    sender: &Keypair,
    receiver: &Keypair,
    amount: i64,
) -> (SignedProposal, SignedConfirmation) {
    let p = TransactionProposal::new(addr(sender), addr(receiver), amount, None, 0, 1_000, 2_000);
    let signed = SignedProposal::sign(p, sender);
    let c = TransactionConfirmation {
        proposal_id: signed.payload.id,
        confirmer: addr(receiver),
        confirmed_at: 1_500,
    };
    (signed.clone(), SignedConfirmation::sign(c, receiver))
}

// --- settlement -------------------------------------------------------------

#[test]
fn a_forged_settlement_moves_no_balance_and_leaves_the_tx_confirmed() {
    let db = fresh_db();
    let (station, mallory) = (Keypair::generate(), Keypair::generate());
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let (proposal, confirmation) = confirmed(&alice, &bob, 300);
    let id = proposal.payload.id;

    let settlement = SettlementRecord {
        proposal_id: id,
        sender: addr(&alice),
        receiver: addr(&bob),
        amount_centi: 300,
        settled_at: 9_000,
    };

    {
        let mut log = AppendLog::new(&db);
        log.append(proposal, 1_000).unwrap();
        log.append(confirmation, 1_500).unwrap();
        // The forgery lands FIRST, signed by a non-station key.
        log.append(SignedPayload::sign(settlement.clone(), &mallory), 8_000)
            .unwrap();
    }

    // Under the station key: the forged settlement is skipped — the tx is still
    // Confirmed, eligible for a genuine settlement.
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(matches!(
        snap.get(&id),
        Some(TransactionState::Confirmed { .. })
    ));

    // The genuine station-signed settlement then settles it.
    AppendLog::new(&db)
        .append(SignedPayload::sign(settlement, &station), 9_000)
        .unwrap();
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(matches!(
        snap.get(&id),
        Some(TransactionState::Settled {
            settled_at: 9_000,
            ..
        })
    ));
}

// --- cancellation -----------------------------------------------------------

#[test]
fn a_forged_cancellation_leaves_the_state_unchanged() {
    let db = fresh_db();
    let (station, mallory) = (Keypair::generate(), Keypair::generate());
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let p = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 1_000, 2_000);
    let signed = SignedProposal::sign(p, &alice);
    let id = signed.payload.id;

    let cancellation = CancellationRecord {
        proposal_id: id,
        reason: CancelReason::Expired,
        cancelled_at: 5_000,
    };

    {
        let mut log = AppendLog::new(&db);
        log.append(signed, 1_000).unwrap();
        log.append(SignedPayload::sign(cancellation.clone(), &mallory), 4_000)
            .unwrap();
    }
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(matches!(
        snap.get(&id),
        Some(TransactionState::Proposed { .. })
    ));

    // The genuine station cancellation retires it.
    AppendLog::new(&db)
        .append(SignedPayload::sign(cancellation, &station), 5_000)
        .unwrap();
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(matches!(
        snap.get(&id),
        Some(TransactionState::Cancelled {
            reason: CancelReason::Expired,
            ..
        })
    ));
}

// --- headroom certificate ---------------------------------------------------

#[test]
fn a_forged_certificate_reserves_nothing_and_a_spend_naming_it_is_unknown() {
    let db = fresh_db();
    let (station, mallory, alice) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let member = addr(&alice);

    // A genuine, member-signed request (member records consent), then a certificate
    // forged by a non-station key naming that request.
    let req = CertificateRequest::new(member, 500, 0, 100);
    let request_id = req.request_id;
    let cert = HeadroomCertificate::new(member, 500, request_id, 100, 100 + 604_800);
    let cert_id = cert.cert_id;
    {
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(req, &alice), 100).unwrap();
        log.append(SignedPayload::sign(cert, &mallory), 100)
            .unwrap();
    }

    // The forged certificate reserves no headroom: it is not in the snapshot at all.
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(snap.certificate(&cert_id).is_none());
    assert_eq!(
        committed_debits_centi(&snap, &member, 200, &CreditConfig::default()),
        0
    );

    // A cert-backed spend naming the forged certificate is refused UnknownCertificate.
    let mut engine = Engine::new(&db, station.clone());
    let spend = TransactionProposal::new(member, addr(&mallory), 100, None, 1, 200, 1_000_000)
        .with_certificate(cert_id);
    assert!(matches!(
        engine.submit_proposal(SignedPayload::sign(spend, &alice), 200),
        Err(Error::UnknownCertificate)
    ));
}

#[test]
fn certificate_check_order_forged_signer_skipped_station_mismatch_errors() {
    // Invariant 5 / Precondition 3: signer pin is checked *before* the
    // request-consistency invariant. A forged-signer certificate whose request is
    // ALSO unknown is skipped (not a hard error); a genuine station-signed
    // certificate whose request is unknown is still `Error::Invalid`.
    let db = fresh_db();
    let (station, mallory, alice) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let member = addr(&alice);

    // Forged signer + unknown request: must be skipped, replay completes cleanly.
    let ghost = rrn_ledger::escrow::RequestId(rrn_crypto::hash::Hash::of(b"ghost"));
    let forged = HeadroomCertificate::new(member, 500, ghost, 100, 700_000);
    {
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(forged, &mallory), 100)
            .unwrap();
    }
    assert!(LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).is_ok());

    // Station-signed + unknown request: the hard derive error survives the pin.
    let db2 = fresh_db();
    let station_signed_bad = HeadroomCertificate::new(member, 500, ghost, 100, 700_000);
    {
        let mut log = AppendLog::new(&db2);
        log.append(SignedPayload::sign(station_signed_bad, &station), 100)
            .unwrap();
    }
    assert!(matches!(
        LedgerSnapshot::derive(&AppendLog::new(&db2), &station.public_key()),
        Err(Error::Invalid(_))
    ));
}

// --- equivocation record ----------------------------------------------------

/// A verifying cert-overspend equivocation record over `cert_id` held by `member`.
fn overspend_record(
    member: Address,
    cert_id: rrn_ledger::escrow::CertId,
    member_kp: &Keypair,
) -> EquivocationRecord {
    let evidence = |amount: i64, nonce: u64| {
        let p = TransactionProposal::new(member, member, amount, None, nonce, 1, 9_000)
            .with_certificate(cert_id);
        EvidenceItem::from_signed(&SignedPayload::sign(p, member_kp))
    };
    EquivocationRecord::new(
        member,
        EquivocationBasis::CertOverspend,
        Some(cert_id),
        vec![evidence(300, 1), evidence(300, 2)],
        8_000,
    )
}

#[test]
fn a_forged_equivocation_record_takes_no_slot_and_the_genuine_one_still_lands() {
    let db = fresh_db();
    let (station, member) = (Keypair::generate(), Keypair::generate());
    let member_addr = addr(&member);
    let cap = 500;

    // A certificate on the log so the overspend cap resolves at replay.
    let cert_id = {
        let mut log = AppendLog::new(&db);
        let req = CertificateRequest::new(member_addr, cap, 0, 1_000);
        let rid = req.request_id;
        log.append(SignedPayload::sign(req, &member), 0).unwrap();
        let cert = HeadroomCertificate::new(member_addr, cap, rid, 1_000, 1_000_000);
        let cid = cert.cert_id;
        log.append(SignedPayload::sign(cert, &station), 0).unwrap();
        cid
    };

    // A record that carries genuine, verifying member-signed evidence of the
    // member's own overspend — but is signed by the MEMBER, not the station, to try
    // to win the first-wins dedup slot. It must be skipped.
    let record = overspend_record(member_addr, cert_id, &member);
    AppendLog::new(&db)
        .append(SignedPayload::sign(record.clone(), &member), 0)
        .unwrap();

    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(
        !snap.has_cert_equivocation(&cert_id),
        "member-signed record must not occupy the dedup slot"
    );
    assert!(!snap.has_active_equivocation(&member_addr));
    assert_eq!(snap.equivocations().count(), 0);

    // The station's genuine record then lands and applies.
    AppendLog::new(&db)
        .append(SignedPayload::sign(record, &station), 0)
        .unwrap();
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(snap.has_cert_equivocation(&cert_id));
    assert!(snap.has_active_equivocation(&member_addr));
    assert_eq!(snap.equivocations().count(), 1);
}

// --- equivocation verdict ---------------------------------------------------

#[test]
fn a_forged_overturn_lifts_nothing_a_station_overturn_does() {
    let db = fresh_db();
    let (station, member) = (Keypair::generate(), Keypair::generate());
    let member_addr = addr(&member);
    let cap = 500;

    let cert_id = {
        let mut log = AppendLog::new(&db);
        let req = CertificateRequest::new(member_addr, cap, 0, 1_000);
        let rid = req.request_id;
        log.append(SignedPayload::sign(req, &member), 0).unwrap();
        let cert = HeadroomCertificate::new(member_addr, cap, rid, 1_000, 1_000_000);
        let cid = cert.cert_id;
        log.append(SignedPayload::sign(cert, &station), 0).unwrap();
        cid
    };
    let record = overspend_record(member_addr, cert_id, &member);
    let equivocation_id = record.equivocation_id;
    AppendLog::new(&db)
        .append(SignedPayload::sign(record, &station), 0)
        .unwrap();

    // A member-signed Overturn of their own equivocation must lift nothing.
    let overturn = EquivocationVerdictRecord {
        equivocation_id,
        decision: VerdictDecision::Overturn,
        decided_at: 9_000,
    };
    AppendLog::new(&db)
        .append(SignedPayload::sign(overturn, &member), 0)
        .unwrap();
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(
        !snap.is_equivocation_overturned(&equivocation_id),
        "a member-signed Overturn must not neutralize the record"
    );
    assert!(snap.has_active_equivocation(&member_addr));

    // The station's Overturn does lift it.
    AppendLog::new(&db)
        .append(SignedPayload::sign(overturn, &station), 0)
        .unwrap();
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(snap.is_equivocation_overturned(&equivocation_id));
    assert!(!snap.has_active_equivocation(&member_addr));
}

// --- legible replica failure (Invariant 3) ----------------------------------

#[test]
fn deriving_under_a_different_key_yields_no_station_signed_state() {
    // Decision (a): a gossip read-replica deriving under its OWN (different) key
    // sees no settlements, no certificates, no equivocations — a loud, diagnosable
    // failure, never a silent partial.
    let db = fresh_db();
    let (station, other) = (Keypair::generate(), Keypair::generate());
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let (proposal, confirmation) = confirmed(&alice, &bob, 300);
    let id = proposal.payload.id;
    let settlement = SettlementRecord {
        proposal_id: id,
        sender: addr(&alice),
        receiver: addr(&bob),
        amount_centi: 300,
        settled_at: 9_000,
    };
    // A genuine certificate too.
    let req = CertificateRequest::new(addr(&alice), 500, 1, 100);
    let rid = req.request_id;
    let cert = HeadroomCertificate::new(addr(&alice), 500, rid, 100, 700_000);
    let cert_id = cert.cert_id;
    {
        let mut log = AppendLog::new(&db);
        log.append(proposal, 1_000).unwrap();
        log.append(confirmation, 1_500).unwrap();
        log.append(SignedPayload::sign(settlement, &station), 9_000)
            .unwrap();
        log.append(SignedPayload::sign(req, &alice), 100).unwrap();
        log.append(SignedPayload::sign(cert, &station), 100)
            .unwrap();
    }

    // Under the writer's key everything derives.
    let good = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(matches!(
        good.get(&id),
        Some(TransactionState::Settled { .. })
    ));
    assert!(good.certificate(&cert_id).is_some());

    // Under a different key: no settlement, no certificate — legibly empty.
    let replica = LedgerSnapshot::derive(&AppendLog::new(&db), &other.public_key()).unwrap();
    assert!(
        matches!(replica.get(&id), Some(TransactionState::Confirmed { .. })),
        "a replica under the wrong key sees the tx unsettled, never a partial settlement"
    );
    assert!(replica.certificate(&cert_id).is_none());
}

// --- skip-not-halt (Invariant 4) --------------------------------------------

#[test]
fn forged_records_interleaved_with_genuine_ones_derive_to_completion() {
    let db = fresh_db();
    let (station, mallory) = (Keypair::generate(), Keypair::generate());
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let (proposal, confirmation) = confirmed(&alice, &bob, 300);
    let id = proposal.payload.id;
    let settlement = SettlementRecord {
        proposal_id: id,
        sender: addr(&alice),
        receiver: addr(&bob),
        amount_centi: 300,
        settled_at: 9_000,
    };
    let forged_cancel = CancellationRecord {
        proposal_id: id,
        reason: CancelReason::WithdrawnBySender,
        cancelled_at: 4_000,
    };
    {
        let mut log = AppendLog::new(&db);
        log.append(proposal, 1_000).unwrap();
        // A forged cancellation interleaved with genuine records.
        log.append(SignedPayload::sign(forged_cancel, &mallory), 4_000)
            .unwrap();
        log.append(confirmation, 1_500).unwrap();
        log.append(SignedPayload::sign(settlement, &station), 9_000)
            .unwrap();
    }
    // Derivation completes (no error) and reaches the genuine terminal state.
    let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
    assert!(matches!(
        snap.get(&id),
        Some(TransactionState::Settled { .. })
    ));
}
