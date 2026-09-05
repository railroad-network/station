//! Certificate-backed spends: admission against escrowed headroom (T2.3.2,
//! ADR-0021 §3–§5).
//!
//! A cert-backed proposal draws against a headroom certificate whose full cap
//! was reserved at issuance, so it is admitted **without a fresh debt-floor
//! check** and its amount is consumed from the certificate monotonically. This
//! suite is the ticket's real deliverable: the admission checks, the
//! monotone-consumption asymmetry, and — the load-bearing one — the ADR-0021 §6
//! floor invariant under arbitrary op interleavings.

use proptest::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::credit::{committed_debits_centi, CreditConfig};
use rrn_ledger::engine::Engine;
use rrn_ledger::escrow::{spend_admissible_until, CertId, CertificateRequest};
use rrn_ledger::settlement::{BalanceView, SettlementConfig, Settler};
use rrn_ledger::state::{CancelReason, LedgerSnapshot};
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
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

fn snapshot(db: &Database) -> LedgerSnapshot {
    LedgerSnapshot::derive(&AppendLog::new(db)).unwrap()
}

fn next_nonce(db: &Database, kp: &Keypair) -> u64 {
    snapshot(db).next_nonce(&kp.public_key().to_bytes())
}

/// Issues a certificate through the engine front door, returning its content id.
/// Takes the db explicitly for the shared-nonce lookup (the engine does not
/// expose its borrowed handle).
fn issue(engine: &mut Engine, db: &Database, member: &Keypair, cap_centi: i64, now: i64) -> CertId {
    let nonce = next_nonce(db, member);
    let req = CertificateRequest::new(addr(member), cap_centi, nonce, now);
    engine
        .submit_certificate_request(SignedPayload::sign(req, member), now)
        .unwrap()
        .payload
        .cert_id
}

/// A cert-backed proposal from `sender`, drawing `amount_centi` against `cert`.
fn cert_proposal(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    amount_centi: i64,
    cert: CertId,
    now: i64,
) -> SignedProposal {
    let nonce = next_nonce(db, sender);
    let p = TransactionProposal::new(
        addr(sender),
        addr(receiver),
        amount_centi,
        None,
        nonce,
        now,
        now + 1_000_000,
    )
    .with_certificate(cert);
    SignedProposal::sign(p, sender)
}

/// A plain (uncertificated) proposal from `sender`.
fn plain_proposal(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    amount_centi: i64,
    now: i64,
) -> SignedProposal {
    let nonce = next_nonce(db, sender);
    let p = TransactionProposal::new(
        addr(sender),
        addr(receiver),
        amount_centi,
        None,
        nonce,
        now,
        now + 1_000_000,
    );
    SignedProposal::sign(p, sender)
}

fn confirm(receiver: &Keypair, id: TransactionId, now: i64) -> SignedConfirmation {
    let c = TransactionConfirmation {
        proposal_id: id,
        confirmer: addr(receiver),
        confirmed_at: now,
    };
    SignedConfirmation::sign(c, receiver)
}

// --- Named-scenario tests ---------------------------------------------------

#[test]
fn a_cert_backed_spend_admits_with_no_floor_headroom_remaining() {
    // Happy path (ticket): cap 500, balance 0, default floor −2000, with ordinary
    // committed debits engineered right up to the floor. A cert-backed 300 spend
    // still admits (the escrow honors it); a plain 1-centi spend refuses.
    let db = fresh_db();
    let (alice, bob, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let cfg = CreditConfig::default(); // floor -2000
    let mut engine = Engine::new(&db, station.clone()).with_credit_config(cfg);
    let now = 1_000;

    // Reserve a 500 certificate (committed rises to 500; headroom left 1500).
    let cert = issue(&mut engine, &db, &alice, 500, now);

    // Add ordinary pending debits taking alice's committed position to the floor:
    // 500 (cert) + 1500 (plain) = 2000 = |floor|, so projected = −2000.
    let fill = plain_proposal(&db, &alice, &bob, 1_500, now);
    engine.submit_proposal(fill, now).unwrap();
    assert_eq!(
        committed_debits_centi(&snapshot(&db), &addr(&alice), now, &cfg),
        2_000
    );

    // A plain 1-centi spend now breaches the floor.
    let over = plain_proposal(&db, &alice, &bob, 1, now);
    assert!(matches!(
        engine.submit_proposal(over, now),
        Err(Error::DebtFloorExceeded { .. })
    ));

    // The cert-backed 300 spend admits regardless — the headroom was paid for at
    // issuance (nonce reused, since the refused plain spend wrote nothing).
    let spend = cert_proposal(&db, &alice, &bob, 300, cert, now);
    let spend_id = spend.payload.id;
    engine.submit_proposal(spend, now).unwrap();

    // Consumption is recorded against the certificate.
    let snap = snapshot(&db);
    assert_eq!(snap.certificate(&cert).unwrap().consumed_centi, 300);

    // Confirm, run the window, settle; balances move by the spend.
    engine
        .submit_confirmation(confirm(&bob, spend_id, now), now)
        .unwrap();
    let mut settler = Settler::new(&db, station, SettlementConfig::uniform(10));
    settler.settle(&spend_id, now + 100).unwrap();
    let balances = BalanceView::new(&db);
    assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), -300);
    assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 300);
}

#[test]
fn overspend_is_refused_with_the_three_amounts() {
    let db = fresh_db();
    let (alice, bob, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let mut engine = Engine::new(&db, station).with_credit_config(CreditConfig::default());
    let now = 1_000;
    let cert = issue(&mut engine, &db, &alice, 500, now);

    engine
        .submit_proposal(cert_proposal(&db, &alice, &bob, 300, cert, now), now)
        .unwrap();
    // 300 already consumed; a 201 spend would reach 501 > 500.
    let over = cert_proposal(&db, &alice, &bob, 201, cert, now);
    assert!(matches!(
        engine.submit_proposal(over, now),
        Err(Error::CertificateOverspent {
            cap_centi: 500,
            consumed_centi: 300,
            attempted_centi: 201,
        })
    ));
}

#[test]
fn spending_to_exactly_the_cap_admits() {
    let db = fresh_db();
    let (alice, bob, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let mut engine = Engine::new(&db, station).with_credit_config(CreditConfig::default());
    let now = 1_000;
    let cert = issue(&mut engine, &db, &alice, 500, now);

    engine
        .submit_proposal(cert_proposal(&db, &alice, &bob, 300, cert, now), now)
        .unwrap();
    // consumed 300 + attempted 200 == cap 500: admits.
    engine
        .submit_proposal(cert_proposal(&db, &alice, &bob, 200, cert, now), now)
        .unwrap();
    assert_eq!(
        snapshot(&db).certificate(&cert).unwrap().consumed_centi,
        500
    );

    // One more centicommon is now an overspend.
    let over = cert_proposal(&db, &alice, &bob, 1, cert, now);
    assert!(matches!(
        engine.submit_proposal(over, now),
        Err(Error::CertificateOverspent {
            cap_centi: 500,
            consumed_centi: 500,
            attempted_centi: 1,
        })
    ));
}

#[test]
fn expiry_boundary_is_the_shared_escrow_instant() {
    let db = fresh_db();
    let (alice, bob, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let cfg = CreditConfig::default();
    let mut engine = Engine::new(&db, station).with_credit_config(cfg);
    let issued_at = 1_000;
    let cert = issue(&mut engine, &db, &alice, 500, issued_at);

    let cert_payload = snapshot(&db)
        .certificate(&cert)
        .unwrap()
        .certificate
        .payload
        .clone();
    let bound = spend_admissible_until(&cert_payload, &cfg);

    // One second past the boundary: refused as expired (nothing written).
    let too_late = cert_proposal(&db, &alice, &bob, 300, cert, bound + 1);
    assert!(matches!(
        engine.submit_proposal(too_late, bound + 1),
        Err(Error::CertificateExpired)
    ));

    // At exactly the boundary: admitted — the same instant T2.3.1's reservation
    // release is coupled to.
    let at_bound = cert_proposal(&db, &alice, &bob, 300, cert, bound);
    engine.submit_proposal(at_bound, bound).unwrap();
    assert_eq!(
        snapshot(&db).certificate(&cert).unwrap().consumed_centi,
        300
    );
}

#[test]
fn wrong_member_returned_negative_and_unknown_are_each_refused() {
    let db = fresh_db();
    let (alice, bob, mallory, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let mut engine = Engine::new(&db, station).with_credit_config(CreditConfig::default());
    let now = 1_000;
    let cert = issue(&mut engine, &db, &alice, 500, now);

    // Unknown certificate.
    let ghost = CertId(rrn_crypto::hash::Hash::of(b"ghost"));
    let unknown = cert_proposal(&db, &alice, &bob, 100, ghost, now);
    assert!(matches!(
        engine.submit_proposal(unknown, now),
        Err(Error::UnknownCertificate)
    ));

    // Wrong member: mallory signs a spend against alice's certificate.
    let wrong = cert_proposal(&db, &mallory, &bob, 100, cert, now);
    assert!(matches!(
        engine.submit_proposal(wrong, now),
        Err(Error::CertificateWrongMember)
    ));

    // Neither a negative amount (a payment request) nor a zero amount is a spend
    // that can ride an escrow — the holder must be the debtor.
    for bad_amount in [-100, 0] {
        let misuse = cert_proposal(&db, &alice, &bob, bad_amount, cert, now);
        assert!(matches!(
            engine.submit_proposal(misuse, now),
            Err(Error::CertificateMisuse)
        ));
    }

    // Returned certificate.
    let ret = rrn_ledger::escrow::CertificateReturn {
        member: addr(&alice),
        cert_id: cert,
        returned_at: now,
    };
    engine
        .submit_certificate_return(SignedPayload::sign(ret, &alice), now)
        .unwrap();
    let after_return = cert_proposal(&db, &alice, &bob, 100, cert, now);
    assert!(matches!(
        engine.submit_proposal(after_return, now),
        Err(Error::CertificateNotOutstanding)
    ));
}

#[test]
fn consumption_is_monotone_across_cancellation() {
    // Admit a 300 cert-backed spend, cancel it (RejectedByReceiver), then attempt
    // another 300 → overspent (300 stays consumed, 300+300 > 500); a 200 admits.
    // The committed position drops by 300 on the cancel (pending debit gone)
    // while consumed stays 300 (ADR-0021 §5).
    let db = fresh_db();
    let (alice, bob, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let cfg = CreditConfig::default();
    let mut engine = Engine::new(&db, station).with_credit_config(cfg);
    let now = 1_000;
    let cert = issue(&mut engine, &db, &alice, 500, now);

    let first = cert_proposal(&db, &alice, &bob, 300, cert, now);
    let first_id = first.payload.id;
    engine.submit_proposal(first, now).unwrap();

    // Committed = pending 300 (the spend) + remaining cap 200 = 500.
    assert_eq!(
        committed_debits_centi(&snapshot(&db), &addr(&alice), now, &cfg),
        500
    );

    // Cancel the spend. Consumed stays 300; the pending debit disappears.
    engine
        .cancel_proposal(&first_id, CancelReason::RejectedByReceiver, now)
        .unwrap();
    let snap = snapshot(&db);
    assert_eq!(snap.certificate(&cert).unwrap().consumed_centi, 300);
    // Committed dropped by 300 → just the remaining cap 200.
    assert_eq!(committed_debits_centi(&snap, &addr(&alice), now, &cfg), 200);

    // Another 300 would reach 600 > cap 500: overspent.
    let again = cert_proposal(&db, &alice, &bob, 300, cert, now);
    assert!(matches!(
        engine.submit_proposal(again, now),
        Err(Error::CertificateOverspent {
            cap_centi: 500,
            consumed_centi: 300,
            attempted_centi: 300,
        })
    ));

    // But 200 (to exactly the cap) admits.
    engine
        .submit_proposal(cert_proposal(&db, &alice, &bob, 200, cert, now), now)
        .unwrap();
    assert_eq!(
        snapshot(&db).certificate(&cert).unwrap().consumed_centi,
        500
    );
}

#[test]
fn nonces_interleave_across_request_cert_backed_and_plain() {
    // A certificate request (nonce 0), a cert-backed proposal (nonce 1), and a
    // plain proposal (nonce 2) all admit in order — the shared nonce sequence.
    let db = fresh_db();
    let (alice, bob, station) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let mut engine = Engine::new(&db, station).with_credit_config(CreditConfig::default());
    let now = 1_000;

    let req = CertificateRequest::new(addr(&alice), 500, 0, now);
    let cert = engine
        .submit_certificate_request(SignedPayload::sign(req, &alice), now)
        .unwrap()
        .payload
        .cert_id;

    let backed = TransactionProposal::new(addr(&alice), addr(&bob), 100, None, 1, now, now + 1_000)
        .with_certificate(cert);
    engine
        .submit_proposal(SignedProposal::sign(backed, &alice), now)
        .unwrap();

    let plain = TransactionProposal::new(addr(&alice), addr(&bob), 50, None, 2, now, now + 1_000);
    engine
        .submit_proposal(SignedProposal::sign(plain, &alice), now)
        .unwrap();

    assert_eq!(next_nonce(&db, &alice), 3);
}

// --- The ADR-0021 §6 floor invariant proptest --------------------------------

/// One generated operation against the ledger. The generator proposes each; the
/// engine accepts or refuses, and the property is asserted only after acceptances
/// (a refusal is fine — the property is about what admission *allows*).
#[derive(Clone, Debug)]
enum Op {
    /// alice requests a certificate with the given cap.
    IssueCert(i64),
    /// alice signs a plain positive-amount spend to bob.
    PlainSpend(i64),
    /// alice signs a cert-backed spend to bob against her `idx`-th issued cert.
    CertSpend(usize, i64),
    /// bob confirms the `idx`-th still-open alice→bob proposal.
    Confirm(usize),
    /// the `idx`-th still-open alice→bob proposal is cancelled.
    Cancel(usize),
    /// alice returns her `idx`-th issued certificate.
    ReturnCert(usize),
    /// time advances by `secs` and the settler sweeps eligible transactions.
    Sweep(i64),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (1i64..=1_000).prop_map(Op::IssueCert),
        (1i64..=800).prop_map(Op::PlainSpend),
        (0usize..6, 1i64..=1_000).prop_map(|(i, a)| Op::CertSpend(i, a)),
        (0usize..12).prop_map(Op::Confirm),
        (0usize..12).prop_map(Op::Cancel),
        (0usize..6).prop_map(Op::ReturnCert),
        // Mostly small advances (the run stays inside every certificate's
        // validity, so reservations remain held and meaningful); occasionally a
        // multi-week jump that crosses `spend_admissible_until`, so the property
        // also exercises certificate expiry / reservation release mid-sequence.
        prop_oneof![9 => 0i64..300, 1 => 1_000_000i64..2_500_000].prop_map(Op::Sweep),
    ]
}

proptest! {
    // No explicit `cases` here: `ProptestConfig::default()` honors the
    // `PROPTEST_CASES` env var, so the ticket's acceptance command
    // (`PROPTEST_CASES=1024 cargo test -p rrn-ledger`) actually runs 1024 cases;
    // absent the env var it defaults to 256.
    #![proptest_config(ProptestConfig::default())]

    /// After every admitted operation, in any interleaving, every member's
    /// committed position stays at or above the debt floor:
    /// `settled_balance − committed_debits >= floor`. Because `committed_debits`
    /// is non-negative, this also pins `settled_balance >= floor` at every step —
    /// so no admitted sequence can ever land a member below the floor, which is
    /// the exit criterion ADR-0021 §6 closes by construction. Refused operations
    /// are skipped (the generator tries them; refusal is fine).
    #[test]
    fn the_floor_is_never_breached_by_admitted_operations(ops in prop::collection::vec(op_strategy(), 1..40)) {
        let db = fresh_db();
        let alice = Keypair::from_secret(rrn_crypto::keypair::SecretKey::from_bytes(
            rrn_crypto::hash::Hash::of(b"proptest-alice").to_bytes(),
        ));
        let bob = Keypair::from_secret(rrn_crypto::keypair::SecretKey::from_bytes(
            rrn_crypto::hash::Hash::of(b"proptest-bob").to_bytes(),
        ));
        let station = Keypair::from_secret(rrn_crypto::keypair::SecretKey::from_bytes(
            rrn_crypto::hash::Hash::of(b"proptest-station").to_bytes(),
        ));
        let cfg = CreditConfig::default();
        let settle_cfg = SettlementConfig::uniform(100);
        let mut engine = Engine::new(&db, station.clone()).with_credit_config(cfg);

        let mut now: i64 = 1_000;
        let mut certs: Vec<CertId> = Vec::new();

        let members = [addr(&alice), addr(&bob)];
        let assert_floor = |db: &Database, now: i64| {
            let snap = snapshot(db);
            let balances = BalanceView::new(db);
            for m in &members {
                let settled = balances.balance_of(m).unwrap();
                let committed = committed_debits_centi(&snap, m, now, &cfg);
                prop_assert!(
                    settled - committed >= cfg.debt_floor_centi,
                    "committed position {} below floor {} for member (settled {}, committed {})",
                    settled - committed,
                    cfg.debt_floor_centi,
                    settled,
                    committed,
                );
                prop_assert!(settled >= cfg.debt_floor_centi, "settled {} below floor", settled);
            }
            Ok(())
        };

        // The open alice→bob proposals available to confirm / cancel.
        let open_proposals = |db: &Database| -> Vec<TransactionId> {
            let snap = snapshot(db);
            snap.iter()
                .filter_map(|(id, st)| {
                    matches!(st, rrn_ledger::state::TransactionState::Proposed { .. }).then_some(*id)
                })
                .collect()
        };

        for op in ops {
            match op {
                Op::IssueCert(cap) => {
                    let nonce = next_nonce(&db, &alice);
                    let req = CertificateRequest::new(addr(&alice), cap, nonce, now);
                    if let Ok(signed) =
                        engine.submit_certificate_request(SignedPayload::sign(req, &alice), now)
                    {
                        certs.push(signed.payload.cert_id);
                    }
                }
                Op::PlainSpend(amount) => {
                    let p = plain_proposal(&db, &alice, &bob, amount, now);
                    let _ = engine.submit_proposal(p, now);
                }
                Op::CertSpend(idx, amount) => {
                    if !certs.is_empty() {
                        let cert = certs[idx % certs.len()];
                        let p = cert_proposal(&db, &alice, &bob, amount, cert, now);
                        let _ = engine.submit_proposal(p, now);
                    }
                }
                Op::Confirm(idx) => {
                    let open = open_proposals(&db);
                    if !open.is_empty() {
                        let id = open[idx % open.len()];
                        let _ = engine.submit_confirmation(confirm(&bob, id, now), now);
                    }
                }
                Op::Cancel(idx) => {
                    let open = open_proposals(&db);
                    if !open.is_empty() {
                        let id = open[idx % open.len()];
                        let _ = engine.cancel_proposal(&id, CancelReason::RejectedByReceiver, now);
                    }
                }
                Op::ReturnCert(idx) => {
                    if !certs.is_empty() {
                        let cert = certs[idx % certs.len()];
                        let ret = rrn_ledger::escrow::CertificateReturn {
                            member: addr(&alice),
                            cert_id: cert,
                            returned_at: now,
                        };
                        let _ = engine
                            .submit_certificate_return(SignedPayload::sign(ret, &alice), now);
                    }
                }
                Op::Sweep(secs) => {
                    now = now.saturating_add(secs.max(1));
                    let mut settler = Settler::new(&db, station.clone(), settle_cfg);
                    settler.sweep(now).unwrap();
                }
            }
            assert_floor(&db, now)?;
        }

        // Finally, fast-forward well past every settlement window and sweep: any
        // remaining confirmed transaction settles. The invariant must still hold
        // on the fully-swept ledger (a stronger statement than any mid-run step,
        // since more debt has moved from pending to settled).
        now = now.saturating_add(10_000);
        let mut settler = Settler::new(&db, station, settle_cfg);
        settler.sweep(now).unwrap();
        assert_floor(&db, now)?;
    }
}
