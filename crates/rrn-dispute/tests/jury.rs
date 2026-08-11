//! End-to-end tests for the sortition jury: deterministic draw, recusal, verdict
//! gating, majority enactment (uphold voids / reject settles), no-show redraw, and
//! the fail-open lapse.

use std::collections::HashMap;

use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::attestation::Attestation;
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_ledger::dispute::{DisputeRecord, SignedDispute};
use rrn_ledger::settlement::{BalanceView, SettlementRecord};
use rrn_ledger::state::{CancelReason, LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::{TransactionConfirmation, TransactionId, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

use rrn_dispute::escalation::{
    EscalationBallot, EscalationReason, EscalationRecord, SignedEscalation, SignedEscalationBallot,
};
use rrn_dispute::panel::resolve_panel;
use rrn_dispute::resolution::{
    append_escalation_ballot, append_verdict, find_disputed, open_escalation, resolve, Resolution,
};
use rrn_dispute::sortition::{disputed_info, draw_sequence, eligible_pool, sortition_seed};
use rrn_dispute::verdict::{verdicts, JurorVerdict, SignedVerdict};
use rrn_dispute::DisputeParams;

const ANCHOR: &[u8] = b"commons";
/// Ten 30-day months in, so seeded standing is decay-free at scoring time.
const T: i64 = 10 * 30 * 86_400;

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

// --- Reputation seeding (mirrors rrn-reputation's own test helpers) -----------

fn append_settled(db: &Database, sender: &Keypair, receiver: &Keypair, nonce: u64, at: i64) {
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
    log.append(SignedPayload::sign(
        TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        },
        receiver,
    ))
    .unwrap();
    log.append(SignedPayload::sign(
        SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        },
        receiver, // any signer works for the test log; the station is not modeled here
    ))
    .unwrap();
}

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

fn earn_raw_standing(db: &Database, who: &Keypair, at: i64) {
    let station = Keypair::generate();
    for nonce in 0..10 {
        append_settled(db, who, &station, nonce, at);
    }
    for _ in 0..10 {
        append_vouch(db, who, &addr(&Keypair::generate()), at);
    }
}

/// `n` established members anchored in a ring, so exactly `n` count toward the
/// electorate as of `at`.
fn established_members(db: &Database, n: usize, at: i64) -> Vec<Keypair> {
    let members: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
    for m in &members {
        earn_raw_standing(db, m, at);
    }
    for i in 0..n {
        append_vouch(db, &members[(i + 1) % n], &addr(&members[i]), at);
    }
    members
}

// --- Dispute setup ------------------------------------------------------------

/// Appends proposal → confirmation → dispute so `sender`→`receiver` is Disputed.
fn append_disputed(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    amount: i64,
    at: i64,
) -> TransactionId {
    let mut log = AppendLog::new(db);
    let proposal = TransactionProposal::new(
        addr(sender),
        addr(receiver),
        amount,
        None,
        0,
        1,
        i64::MAX / 2,
    );
    let id = proposal.id;
    log.append(SignedPayload::sign(proposal, sender)).unwrap();
    log.append(SignedPayload::sign(
        TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(receiver),
            confirmed_at: at,
        },
        receiver,
    ))
    .unwrap();
    let dispute = DisputeRecord {
        proposal_id: id,
        raiser: addr(sender),
        reason: "goods never arrived".into(),
        evidence_hash: None,
        opened_at: at,
    };
    log.append(SignedDispute::sign(dispute, sender)).unwrap();
    id
}

fn params() -> DisputeParams {
    DisputeParams {
        window_seconds: 1000,
        juror_response_seconds: 500,
        panel_size: 3,
        // No appeal delay: these jury-only tests enact a ruling immediately.
        appeal_window_seconds: 0,
        escalation_window_seconds: 500,
        escalation_quorum_pct: 30,
        escalation_approval_pct: 50,
    }
}

/// The deterministic seating order for a dispute.
fn sequence(db: &Database, tx_id: &TransactionId, p: &DisputeParams) -> Vec<Address> {
    let info = disputed_info(db, tx_id).unwrap();
    let pool = eligible_pool(db, &info, info.opened_at, p).unwrap();
    draw_sequence(&pool, sortition_seed(tx_id, ANCHOR))
}

fn kp_for<'a>(members: &'a [Keypair], who: &Address) -> &'a Keypair {
    members
        .iter()
        .find(|m| &addr(m) == who)
        .expect("juror keypair")
}

fn signed_verdict(
    tx_id: &TransactionId,
    juror: &Keypair,
    uphold: bool,
    cast_at: i64,
) -> SignedVerdict {
    SignedVerdict::sign(
        JurorVerdict {
            proposal_id: *tx_id,
            juror: addr(juror),
            uphold,
            cast_at,
        },
        juror,
    )
}

// --- Escalation setup ---------------------------------------------------------

/// Params with a real appeal window and escalation sub-window, both comfortably
/// inside a long overall window.
fn esc_params() -> DisputeParams {
    DisputeParams {
        window_seconds: 100_000,
        juror_response_seconds: 500,
        panel_size: 3,
        appeal_window_seconds: 1000,
        escalation_window_seconds: 5000,
        escalation_quorum_pct: 30,
        escalation_approval_pct: 50,
    }
}

fn signed_escalation(
    tx_id: &TransactionId,
    initiator: &Keypair,
    reason: EscalationReason,
    opened_at: i64,
) -> SignedEscalation {
    SignedEscalation::sign(
        EscalationRecord {
            proposal_id: *tx_id,
            initiator: addr(initiator),
            reason,
            opened_at,
        },
        initiator,
    )
}

fn signed_ballot(
    tx_id: &TransactionId,
    voter: &Keypair,
    uphold: bool,
    cast_at: i64,
) -> SignedEscalationBallot {
    SignedEscalationBallot::sign(
        EscalationBallot {
            proposal_id: *tx_id,
            voter: addr(voter),
            uphold,
            cast_at,
        },
        voter,
    )
}

/// A dispute whose jury pool is too small to seat a panel: three established
/// members, two of whom are the parties, leaving a single eligible member. Returns
/// the parties, the lone eligible member, and the disputed transaction id.
fn cannot_seat_setup(db: &Database) -> (Keypair, Keypair, Keypair, TransactionId) {
    let members = established_members(db, 3, T);
    let [alice, bob, lone] = <[Keypair; 3]>::try_from(members).ok().unwrap();
    let tx = append_disputed(db, &alice, &bob, 300, T);
    (alice, bob, lone, tx)
}

// --- Tests --------------------------------------------------------------------

#[test]
fn the_draw_is_deterministic_and_covers_the_pool() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();

    let seq1 = sequence(&db, &tx, &p);
    let seq2 = sequence(&db, &tx, &p);
    assert_eq!(seq1, seq2, "the draw must be a pure function of the log");
    // Every established member (none is a party) appears exactly once.
    assert_eq!(seq1.len(), members.len());
    for m in &members {
        assert!(seq1.contains(&addr(m)));
    }
}

#[test]
fn parties_and_their_vouchers_are_recused() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    // Make one established member a party, and have another vouch for that party.
    let alice = members[0].clone(); // sender is an established member
    let bob = Keypair::generate();
    append_vouch(&db, &members[1], &addr(&alice), T); // members[1] vouches for the party
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();

    let info = disputed_info(&db, &tx).unwrap();
    let pool = eligible_pool(&db, &info, info.opened_at, &p).unwrap();
    let pool_addrs: Vec<Address> = pool.iter().map(|(a, _)| *a).collect();

    // The party (members[0]) and its voucher (members[1]) are both excluded;
    // the other three remain.
    assert!(!pool_addrs.contains(&addr(&alice)));
    assert!(!pool_addrs.contains(&addr(&members[1])));
    assert_eq!(pool_addrs.len(), 3);
}

#[test]
fn voucher_recusal_relaxes_before_the_panel_goes_unseated() {
    let db = fresh_db();
    // Exactly enough established members that recusing a party's voucher would
    // drop the pool below the panel size, forcing the relaxation.
    let members = established_members(&db, 4, T);
    let alice = members[0].clone();
    let bob = Keypair::generate();
    // Everyone else vouches for the party, so strict recusal leaves 0 eligible.
    append_vouch(&db, &members[1], &addr(&alice), T);
    append_vouch(&db, &members[2], &addr(&alice), T);
    append_vouch(&db, &members[3], &addr(&alice), T);
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();

    let info = disputed_info(&db, &tx).unwrap();
    let pool = eligible_pool(&db, &info, info.opened_at, &p).unwrap();
    let pool_addrs: Vec<Address> = pool.iter().map(|(a, _)| *a).collect();
    // Relaxed pool = established minus the party only: the three vouchers return.
    assert_eq!(pool_addrs.len(), 3);
    assert!(!pool_addrs.contains(&addr(&alice)));
}

#[test]
fn two_uphold_verdicts_void_the_transfer() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();
    let seq = sequence(&db, &tx, &p);
    let station = Keypair::generate();

    // The first two seated jurors uphold.
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), true, T + 10),
        T + 10,
    )
    .unwrap();

    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 20).unwrap();
    assert_eq!(outcome, Resolution::Upheld);

    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Cancelled {
            reason: CancelReason::DisputeUpheld,
            ..
        })
    ));
}

#[test]
fn two_reject_verdicts_settle_the_transaction() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();
    let seq = sequence(&db, &tx, &p);
    let station = Keypair::generate();

    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), false, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), false, T + 10),
        T + 10,
    )
    .unwrap();

    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 20).unwrap();
    assert_eq!(outcome, Resolution::Rejected);

    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Settled { .. })
    ));
    // The confirmed transfer moved: alice -300, bob +300.
    let balances = BalanceView::new(&db);
    assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), -300);
    assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 300);
}

#[test]
fn a_silent_juror_is_redrawn_around() {
    let db = fresh_db();
    let members = established_members(&db, 6, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    // Short juror deadline so a no-show is quick; long overall window.
    let p = DisputeParams {
        window_seconds: 1000,
        juror_response_seconds: 10,
        panel_size: 3,
        appeal_window_seconds: 0,
        escalation_window_seconds: 500,
        escalation_quorum_pct: 30,
        escalation_approval_pct: 50,
    };
    let seq = sequence(&db, &tx, &p);

    // seq[0] votes in time; seq[1] and seq[2] go silent past their deadline.
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 5),
        T + 5,
    )
    .unwrap();

    // After the deadline, the panel redraws seq[1]/seq[2] to seq[3]/seq[4].
    let existing = verdicts(&db, &tx).unwrap();
    let panel = resolve_panel(&seq, &existing, T, &p, T + 15);
    assert!(
        panel.seat_of(&seq[0]).is_some(),
        "the responder keeps the seat"
    );
    assert!(
        panel.seat_of(&seq[1]).is_none(),
        "the no-show was redrawn around"
    );
    assert!(panel.seat_of(&seq[3]).is_some(), "a replacement was seated");

    // A redrawn juror can now cast a valid verdict within its own window, and a
    // second uphold reaches the majority.
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[3]), true, T + 12),
        T + 12,
    )
    .unwrap();
    let station = Keypair::generate();
    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 15).unwrap();
    assert_eq!(outcome, Resolution::Upheld);
}

#[test]
fn an_unresolved_dispute_lapses_and_settles() {
    let db = fresh_db();
    let _members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();
    let station = Keypair::generate();

    // No verdicts. Before the window closes: still pending.
    assert_eq!(
        resolve(&db, &station, &tx, &p, ANCHOR, T + 500).unwrap(),
        Resolution::Pending
    );
    // At the window's close: it lapses to the confirmed status quo.
    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 1000).unwrap();
    assert_eq!(outcome, Resolution::Lapsed);
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Settled { .. })
    ));
}

#[test]
fn a_non_juror_verdict_is_refused() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();
    let seq = sequence(&db, &tx, &p);

    // seq[3] is in the redraw queue, not on the initial panel, so before any
    // no-show it holds no live seat.
    let err = append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[3]), true, T + 1),
        T + 1,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotSeated)));

    // A party (never eligible) is likewise refused.
    let err = append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, &alice, true, T + 1),
        T + 1,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotSeated)));
}

#[test]
fn a_second_verdict_from_a_juror_is_refused() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = params();
    let seq = sequence(&db, &tx, &p);

    let j0 = kp_for(&members, &seq[0]);
    append_verdict(&db, &p, ANCHOR, signed_verdict(&tx, j0, true, T + 5), T + 5).unwrap();
    let err = append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, j0, false, T + 6),
        T + 6,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::AlreadyVoted)));
}

// --- Escalation & appeal (ADR-0014 §5) ----------------------------------------

#[test]
fn cannot_seat_escalation_upheld_by_the_electorate_voids_the_transfer() {
    let db = fresh_db();
    let (alice, _bob, lone, tx) = cannot_seat_setup(&db);
    let p = esc_params();
    let station = Keypair::generate();

    // A party escalates because the jury cannot seat a panel, then the lone
    // eligible member (the whole electorate here) upholds.
    open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();
    append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, true, T + 10), T + 10).unwrap();

    // While the escalation window is open, it is pending.
    assert_eq!(
        resolve(&db, &station, &tx, &p, ANCHOR, T + 100).unwrap(),
        Resolution::EscalationPending
    );
    // Once the window closes, the electorate's ruling enacts.
    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 6000).unwrap();
    assert_eq!(outcome, Resolution::EscalationUpheld);
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Cancelled {
            reason: CancelReason::DisputeUpheld,
            ..
        })
    ));
}

#[test]
fn cannot_seat_escalation_rejected_by_the_electorate_settles() {
    let db = fresh_db();
    let (alice, bob, lone, tx) = cannot_seat_setup(&db);
    let p = esc_params();
    let station = Keypair::generate();

    open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();
    append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, false, T + 10), T + 10).unwrap();

    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 6000).unwrap();
    assert_eq!(outcome, Resolution::EscalationRejected);
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Settled { .. })
    ));
    let balances = BalanceView::new(&db);
    assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), -300);
    assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 300);
}

#[test]
fn an_escalation_without_quorum_lapses_open_and_settles() {
    let db = fresh_db();
    let (alice, _bob, _lone, tx) = cannot_seat_setup(&db);
    let p = esc_params();
    let station = Keypair::generate();

    // Escalated, but nobody votes.
    open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();

    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 6000).unwrap();
    assert_eq!(outcome, Resolution::EscalationLapsed);
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Settled { .. })
    ));
}

#[test]
fn a_party_appeals_a_jury_ruling_and_the_electorate_overturns_it() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = esc_params();
    let seq = sequence(&db, &tx, &p);
    let station = Keypair::generate();

    // The jury upholds the dispute (2 of 3).
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), true, T + 10),
        T + 10,
    )
    .unwrap();

    // Before enactment, the ruling sits in its appeal window.
    assert_eq!(
        resolve(&db, &station, &tx, &p, ANCHOR, T + 20).unwrap(),
        Resolution::AwaitingAppeal
    );

    // The losing party (sender) appeals; the electorate rejects the dispute,
    // overturning the jury.
    open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::Appeal, T + 20),
        T + 20,
    )
    .unwrap();
    for m in &members[0..3] {
        append_escalation_ballot(&db, &p, signed_ballot(&tx, m, false, T + 30), T + 30).unwrap();
    }

    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 6000).unwrap();
    assert_eq!(outcome, Resolution::EscalationRejected);
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(
        matches!(snapshot.get(&tx), Some(TransactionState::Settled { .. })),
        "the electorate overturned the jury's uphold, so the transfer settles"
    );
}

#[test]
fn an_unappealed_jury_ruling_enacts_once_the_appeal_window_closes() {
    let db = fresh_db();
    let members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = esc_params();
    let seq = sequence(&db, &tx, &p);
    let station = Keypair::generate();

    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), true, T + 10),
        T + 10,
    )
    .unwrap();

    // Ruling at T+10; appeal window is 1000. Inside it: held. Past it: enacted.
    assert_eq!(
        resolve(&db, &station, &tx, &p, ANCHOR, T + 500).unwrap(),
        Resolution::AwaitingAppeal
    );
    let outcome = resolve(&db, &station, &tx, &p, ANCHOR, T + 2000).unwrap();
    assert_eq!(outcome, Resolution::Upheld);
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    assert!(matches!(
        snapshot.get(&tx),
        Some(TransactionState::Cancelled {
            reason: CancelReason::DisputeUpheld,
            ..
        })
    ));
}

#[test]
fn escalation_and_ballot_gates_refuse_the_illegitimate() {
    let db = fresh_db();
    // Five established members: the pool can seat a panel, so CannotSeat is invalid.
    let _members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let p = esc_params();

    // Escalate CannotSeat when the pool (5) can seat a panel: refused.
    let err = open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotEscalatable)));

    // Appeal with no jury ruling yet: refused.
    let err = open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::Appeal, T + 5),
        T + 5,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotEscalatable)));

    // A non-party cannot open an escalation.
    let stranger = Keypair::generate();
    let err = open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &stranger, EscalationReason::CannotSeat, T + 5),
        T + 5,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::BadEscalation)));
}

#[test]
fn escalation_ballot_gate_refuses_ineligible_double_and_out_of_window() {
    let db = fresh_db();
    let (alice, _bob, lone, tx) = cannot_seat_setup(&db);
    let p = esc_params();

    open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();

    // A non-established stranger is not in the electorate.
    let stranger = Keypair::generate();
    let err =
        append_escalation_ballot(&db, &p, signed_ballot(&tx, &stranger, true, T + 10), T + 10);
    assert!(matches!(err, Err(rrn_dispute::Error::NotEligible)));

    // A ballot before the escalation opened is out of window.
    let err = append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, true, T + 1), T + 10);
    assert!(matches!(err, Err(rrn_dispute::Error::NotEligible)));

    // The lone member votes once, then a second ballot is refused.
    append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, true, T + 10), T + 10).unwrap();
    let err = append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, false, T + 11), T + 11);
    assert!(matches!(err, Err(rrn_dispute::Error::AlreadyVoted)));

    // A second escalation on the same dispute is refused.
    let err = open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 12),
        T + 12,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::AlreadyEscalated)));
}

#[test]
fn the_escalation_window_is_clamped_to_the_main_window() {
    let db = fresh_db();
    let (alice, _bob, lone, tx) = cannot_seat_setup(&db);
    // Main window closes at T+100, well before the 5000s escalation window would.
    let p = DisputeParams {
        window_seconds: 100,
        escalation_window_seconds: 5000,
        ..esc_params()
    };

    open_escalation(
        &db,
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 50),
        T + 50,
    )
    .unwrap();

    // A ballot at T+90 (before the clamped close at T+100) is accepted...
    append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, true, T + 90), T + 90).unwrap();
    // ...but one at T+150 — inside the raw 5000s window, past the clamped close — is not.
    let err = append_escalation_ballot(&db, &p, signed_ballot(&tx, &lone, true, T + 150), T + 150);
    assert!(matches!(err, Err(rrn_dispute::Error::NotEligible)));
}

#[test]
fn find_disputed_lists_the_frozen_transaction() {
    let db = fresh_db();
    let _members = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    assert_eq!(find_disputed(&db).unwrap(), vec![tx]);

    // No verdicts cast yet.
    let empty: HashMap<Address, (bool, i64)> = HashMap::new();
    assert_eq!(verdicts(&db, &tx).unwrap(), empty);
}
