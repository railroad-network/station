//! End-to-end tests for the sortition jury: deterministic draw, recusal, verdict
//! gating, majority enactment (uphold voids / reject settles), no-show redraw, and
//! the fail-open lapse.

use std::collections::HashMap;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
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
    escalation_electorate, escalation_of, EscalationBallot, EscalationReason, EscalationRecord,
    SignedEscalation, SignedEscalationBallot,
};
use rrn_dispute::panel::resolve_panel;
use rrn_dispute::resolution::{
    append_escalation_ballot, append_verdict, find_disputed, open_escalation, resolve, Resolution,
};
use rrn_dispute::sortition::{
    disputed_info, draw_sequence, eligible_pool, sortition_seed, DisputedInfo,
};
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
    log.append(SignedPayload::sign(proposal, sender), 0)
        .unwrap();
    log.append(
        SignedPayload::sign(
            TransactionConfirmation {
                proposal_id: pid,
                confirmer: addr(receiver),
                confirmed_at: at,
            },
            receiver,
        ),
        0,
    )
    .unwrap();
    log.append(
        SignedPayload::sign(
            SettlementRecord {
                proposal_id: pid,
                sender: addr(sender),
                receiver: addr(receiver),
                amount_centi: 300,
                settled_at: at,
            },
            receiver, // any signer works for the test log; the station is not modeled here
        ),
        0,
    )
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
    log.append(vouch.sign(voucher), 0).unwrap();
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

/// Appends proposal → confirmation → dispute so `sender`→`receiver` is Disputed,
/// admitting the dispute entry at `at`. The raiser's signed `opened_at` also reads
/// `at`, matching the admission time.
fn append_disputed(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    amount: i64,
    at: i64,
) -> TransactionId {
    append_disputed_admitted(db, sender, receiver, amount, at, at)
}

/// Like [`append_disputed`], but lets the raiser's signed `opened_at`
/// (`party_opened_at`) diverge from the station's admission time (`admit_at`) for
/// the dispute entry. The sortition draw and resolution window must key on
/// `admit_at`, never on `party_opened_at` (ADR-0022).
fn append_disputed_admitted(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    amount: i64,
    admit_at: i64,
    party_opened_at: i64,
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
    log.append(SignedPayload::sign(proposal, sender), 0)
        .unwrap();
    log.append(
        SignedPayload::sign(
            TransactionConfirmation {
                proposal_id: id,
                confirmer: addr(receiver),
                confirmed_at: admit_at,
            },
            receiver,
        ),
        0,
    )
    .unwrap();
    let dispute = DisputeRecord {
        proposal_id: id,
        raiser: addr(sender),
        reason: "goods never arrived".into(),
        evidence_hash: None,
        opened_at: party_opened_at,
    };
    log.append(SignedDispute::sign(dispute, sender), admit_at)
        .unwrap();
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
    let pool = eligible_pool(db, &[], &info, info.opened_at, info.opened_seq, p).unwrap();
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
fn party_opened_at_is_ignored_for_the_draw_and_window() {
    // The raiser signs an `opened_at` far from the truth in both directions; the
    // station admits the dispute at the real time `T`. `disputed_info` must report
    // the admitted time, and the sortition draw must be identical to an honest
    // dispute admitted at the same instant — a lying party cannot shift the jury
    // or the resolution window (ADR-0022).
    for lie in [T - 5_000_000, T + 5_000_000] {
        let honest = fresh_db();
        let liar = fresh_db();
        let members: Vec<Keypair> = (0..5).map(|_| Keypair::generate()).collect();
        for db in [&honest, &liar] {
            for m in &members {
                earn_raw_standing(db, m, T);
            }
            for i in 0..members.len() {
                append_vouch(db, &members[(i + 1) % members.len()], &addr(&members[i]), T);
            }
        }
        let (alice, bob) = (Keypair::generate(), Keypair::generate());

        // Same parties, same amount, same admission time; only the signed
        // `opened_at` differs between the two logs.
        let tx_honest = append_disputed(&honest, &alice, &bob, 300, T);
        let tx_liar = append_disputed_admitted(&liar, &alice, &bob, 300, T, lie);
        assert_eq!(tx_honest, tx_liar, "same parties/amount/nonce ⇒ same tx id");

        let info = disputed_info(&liar, &tx_liar).unwrap();
        assert_eq!(
            info.opened_at, T,
            "opened_at must be the admitted time, not the party's signed lie ({lie})"
        );

        let p = params();
        assert_eq!(
            sequence(&liar, &tx_liar, &p),
            sequence(&honest, &tx_honest, &p),
            "the draw must not depend on the party's signed opened_at ({lie})"
        );
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
    let pool = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
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
    let pool = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), true, T + 10),
        T + 10,
    )
    .unwrap();

    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 20).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), false, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), false, T + 10),
        T + 10,
    )
    .unwrap();

    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 20).unwrap();
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
        &[],
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
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[3]), true, T + 12),
        T + 12,
    )
    .unwrap();
    let station = Keypair::generate();
    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 15).unwrap();
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
        resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 500).unwrap(),
        Resolution::Pending
    );
    // At the window's close: it lapses to the confirmed status quo.
    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 1000).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[3]), true, T + 1),
        T + 1,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotSeated)));

    // A party (never eligible) is likewise refused.
    let err = append_verdict(
        &db,
        &[],
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
    append_verdict(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, j0, true, T + 5),
        T + 5,
    )
    .unwrap();
    let err = append_verdict(
        &db,
        &[],
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
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();
    append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, true, T + 10),
        T + 10,
    )
    .unwrap();

    // While the escalation window is open, it is pending.
    assert_eq!(
        resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 100).unwrap(),
        Resolution::EscalationPending
    );
    // Once the window closes, the electorate's ruling enacts.
    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 6000).unwrap();
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
fn escalation_opened_at_is_ignored_for_the_window_and_electorate() {
    // The initiator signs an `opened_at` far in the past (T - 4000), but the station
    // admits the escalation at T + 5. Both the sub-window and the ballot-counting
    // window must run from the admission time, never the signed lie (ADR-0022 §5).
    //
    // The ballot is cast at T + 2000: inside the admission-anchored window
    // [T+5, T+5+5000], but OUTSIDE the window the lie would imply
    // ([T-4000, T-4000+5000] = [T-4000, T+1000]). If the escalation still keyed on
    // the signed `opened_at`, this ballot would fall outside the window and the
    // escalation would lapse; anchored on admission, it is counted and upholds.
    let db = fresh_db();
    let (alice, _bob, lone, tx) = cannot_seat_setup(&db);
    let p = esc_params();
    let station = Keypair::generate();

    open_escalation(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T - 4000),
        T + 5, // admission time
    )
    .unwrap();
    append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, true, T + 2000),
        T + 2000,
    )
    .unwrap();

    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 6000).unwrap();
    assert_eq!(
        outcome,
        Resolution::EscalationUpheld,
        "the ballot must be counted against the admission-anchored window, not the signed opened_at"
    );
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
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();
    append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, false, T + 10),
        T + 10,
    )
    .unwrap();

    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 6000).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();

    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 6000).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), true, T + 10),
        T + 10,
    )
    .unwrap();

    // Before enactment, the ruling sits in its appeal window.
    assert_eq!(
        resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 20).unwrap(),
        Resolution::AwaitingAppeal
    );

    // The losing party (sender) appeals; the electorate rejects the dispute,
    // overturning the jury.
    open_escalation(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::Appeal, T + 20),
        T + 20,
    )
    .unwrap();
    for m in &members[0..3] {
        append_escalation_ballot(&db, &[], &p, signed_ballot(&tx, m, false, T + 30), T + 30)
            .unwrap();
    }

    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 6000).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[0]), true, T + 10),
        T + 10,
    )
    .unwrap();
    append_verdict(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_verdict(&tx, kp_for(&members, &seq[1]), true, T + 10),
        T + 10,
    )
    .unwrap();

    // Ruling at T+10; appeal window is 1000. Inside it: held. Past it: enacted.
    assert_eq!(
        resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 500).unwrap(),
        Resolution::AwaitingAppeal
    );
    let outcome = resolve(&db, &[], &station, &tx, &p, ANCHOR, T + 2000).unwrap();
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
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotEscalatable)));

    // Appeal with no jury ruling yet: refused.
    let err = open_escalation(
        &db,
        &[],
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
        &[],
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
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();

    // A non-established stranger is not in the electorate.
    let stranger = Keypair::generate();
    let err = append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &stranger, true, T + 10),
        T + 10,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotEligible)));

    // A ballot before the escalation opened is out of window.
    let err =
        append_escalation_ballot(&db, &[], &p, signed_ballot(&tx, &lone, true, T + 1), T + 10);
    assert!(matches!(err, Err(rrn_dispute::Error::NotEligible)));

    // The lone member votes once, then a second ballot is refused.
    append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, true, T + 10),
        T + 10,
    )
    .unwrap();
    let err = append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, false, T + 11),
        T + 11,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::AlreadyVoted)));

    // A second escalation on the same dispute is refused.
    let err = open_escalation(
        &db,
        &[],
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
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 50),
        T + 50,
    )
    .unwrap();

    // A ballot at T+90 (before the clamped close at T+100) is accepted...
    append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, true, T + 90),
        T + 90,
    )
    .unwrap();
    // ...but one at T+150 — inside the raw 5000s window, past the clamped close — is not.
    let err = append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &lone, true, T + 150),
        T + 150,
    );
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

// --- Bootstrap grace (ADR-0015) ---------------------------------------------

#[test]
fn grace_seats_founders_in_the_jury_pool() {
    // A brand-new community: no established members, so the jury pool would be
    // empty and every dispute would lapse — unless the founders are seated.
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let founder_addrs: Vec<Address> = founders.iter().map(addr).collect();

    // The two parties are not founders and are always recused.
    let (sender, receiver) = (Keypair::generate(), Keypair::generate());
    let info = DisputedInfo {
        sender: addr(&sender),
        receiver: addr(&receiver),
        opened_at: T,
        // No real dispute entry in this synthetic case; the pool is bounded by the
        // explicit `max_seq` argument below, so a whole-log bound stands in.
        opened_seq: u64::MAX,
    };
    let p = params();

    // With founders supplied, the pool is exactly the four founders (none is a
    // party), enough to seat a panel of three.
    let pool = eligible_pool(&db, &founder_addrs, &info, T, u64::MAX, &p).unwrap();
    let members: Vec<Address> = pool.iter().map(|(a, _)| *a).collect();
    assert_eq!(members.len(), 4);
    for f in &founder_addrs {
        assert!(members.contains(f));
    }
    assert!(pool.len() >= p.panel_size);

    // Without founders (the steady-state call), the fresh community seats no one.
    let empty = eligible_pool(&db, &[], &info, T, u64::MAX, &p).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn grace_still_recuses_a_party_who_is_a_founder() {
    // A founder who is also a party to the dispute is never eligible on it.
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let founder_addrs: Vec<Address> = founders.iter().map(addr).collect();

    // Make founder[0] the sender.
    let receiver = Keypair::generate();
    let info = DisputedInfo {
        sender: addr(&founders[0]),
        receiver: addr(&receiver),
        opened_at: T,
        opened_seq: u64::MAX,
    };
    let p = params();

    let pool = eligible_pool(&db, &founder_addrs, &info, T, u64::MAX, &p).unwrap();
    let members: Vec<Address> = pool.iter().map(|(a, _)| *a).collect();
    assert_eq!(members.len(), 3);
    assert!(!members.contains(&addr(&founders[0])));
}

// --- Position-bounded pool, electorate, and weights (ADR-0022 §5) --------------
//
// The jury pool, its recusal graph, and every draw weight are computed over the log
// prefix ending at the dispute's admission seq, never the whole log filtered by
// time. Nothing admitted after the dispute opened — whatever timestamp it back-dates
// to (ADR-0022 §3 makes arbitrarily-old testimony legal) — may enter the pool,
// recuse a candidate, or shift a weight. These port the governance regression
// (`a_back_dated_member_admitted_after_open_does_not_join_the_electorate`) to the
// three dispute-native derivations.

/// A deterministic keypair from a label, so two builds produce identical logs — the
/// basis of the cross-replica determinism test (mirrors `equivocation.rs::kp`).
fn kp(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(Hash::of(label.as_bytes()).to_bytes()))
}

fn pool_has(pool: &[(Address, u64)], a: &Address) -> bool {
    pool.iter().any(|(x, _)| x == a)
}

fn pool_weight(pool: &[(Address, u64)], a: &Address) -> u64 {
    pool.iter().find(|(x, _)| x == a).map(|(_, w)| *w).unwrap()
}

#[test]
fn a_back_dated_vouch_cannot_pack_the_jury_pool() {
    // Invariant 1: a member established by a vouch admitted *after* the dispute
    // opened — back-dated so its issued_at predates the open — must not join that
    // dispute's pool, and the drawn panel is byte-identical to the one drawn before
    // the vouch landed.
    let db = fresh_db();
    let jurors = established_members(&db, 4, T);
    // A would-be juror with raw standing over the band but *unanchored* (nobody has
    // vouched for them): capped below the band, so not yet in the electorate.
    let newcomer = Keypair::generate();
    earn_raw_standing(&db, &newcomer, T);

    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let info = disputed_info(&db, &tx).unwrap();
    let p = params();

    let pool_before = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
    let draw_before = sequence(&db, &tx, &p);
    assert!(!pool_has(&pool_before, &addr(&newcomer)));
    assert_eq!(
        pool_before.len(),
        4,
        "the four jurors; both parties recused"
    );

    // A back-dated anchoring vouch for the newcomer, admitted *after* the dispute's
    // seq: legal old testimony (ADR-0022 §3) that anchors them and reveals their
    // over-band raw composite.
    append_vouch(&db, &jurors[0], &addr(&newcomer), T);

    // Bounded at the dispute's admission seq, the pool and the draw are unchanged.
    let pool_after = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
    assert!(!pool_has(&pool_after, &addr(&newcomer)));
    assert_eq!(pool_after.len(), 4);
    assert_eq!(
        draw_before,
        sequence(&db, &tx, &p),
        "the drawn panel is byte-identical after the back-dated vouch lands"
    );

    // The vector is real: without the bound (whole log) the newcomer packs the pool.
    let unbounded = eligible_pool(&db, &[], &info, info.opened_at, u64::MAX, &p).unwrap();
    assert!(
        pool_has(&unbounded, &addr(&newcomer)),
        "the back-dated vouch anchors the newcomer in the unbounded pool"
    );
    assert_eq!(unbounded.len(), 5);
}

#[test]
fn a_back_dated_settlement_does_not_shift_a_draw_weight() {
    // Invariant 4: a settlement admitted after the dispute opened must not change a
    // juror's draw weight for that dispute. In bootstrap grace the founders are
    // seated at the floor weight (1); a back-dated settlement raises a founder's raw
    // standing only in the unbounded view, never in the bounded pool.
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
    let founder_addrs: Vec<Address> = founders.iter().map(addr).collect();
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let info = disputed_info(&db, &tx).unwrap();
    let p = params();

    let seed = sortition_seed(&tx, ANCHOR);
    let pool_before = eligible_pool(
        &db,
        &founder_addrs,
        &info,
        info.opened_at,
        info.opened_seq,
        &p,
    )
    .unwrap();
    let draw_before = draw_sequence(&pool_before, seed);
    assert_eq!(
        pool_weight(&pool_before, &addr(&founders[0])),
        1,
        "a zero-standing founder is floored at weight 1"
    );

    // Back-dated settled trades for founders[0], admitted after the dispute seq.
    for nonce in 0..5 {
        append_settled(&db, &founders[0], &Keypair::generate(), nonce, T);
    }

    let pool_after = eligible_pool(
        &db,
        &founder_addrs,
        &info,
        info.opened_at,
        info.opened_seq,
        &p,
    )
    .unwrap();
    assert_eq!(
        pool_weight(&pool_after, &addr(&founders[0])),
        1,
        "the weight is bounded at the dispute seq — still the floor"
    );
    assert_eq!(
        draw_before,
        draw_sequence(&pool_after, seed),
        "the draw is unchanged"
    );

    // Unbounded, the extra trades raise the weight — proof the bound bites.
    let unbounded =
        eligible_pool(&db, &founder_addrs, &info, info.opened_at, u64::MAX, &p).unwrap();
    assert!(
        pool_weight(&unbounded, &addr(&founders[0])) > 1,
        "the back-dated settlements raise the weight only in the unbounded view"
    );
}

#[test]
fn a_voucher_admitted_after_the_open_neither_recuses_nor_seats() {
    // Invariant 5: recusal graph and pool agree on one prefix. A vouch from a juror
    // for a party, admitted after the dispute opened, must not recuse that juror.
    let db = fresh_db();
    let jurors = established_members(&db, 4, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T);
    let info = disputed_info(&db, &tx).unwrap();
    let p = params();

    let pool_before = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
    assert!(pool_has(&pool_before, &addr(&jurors[0])));

    // jurors[0] vouches for a party (alice) *after* the dispute opened, back-dated.
    append_vouch(&db, &jurors[0], &addr(&alice), T);

    // Bounded at the dispute seq, jurors[0] is still eligible (not recused).
    let pool_after = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
    assert!(
        pool_has(&pool_after, &addr(&jurors[0])),
        "a vouch admitted after the open does not recuse the voucher"
    );
    assert_eq!(pool_after.len(), 4);

    // Unbounded, the same vouch recuses jurors[0] (proof the bound bites): with four
    // jurors, strict recusal leaves exactly a panel of three, so no relaxation.
    let unbounded = eligible_pool(&db, &[], &info, info.opened_at, u64::MAX, &p).unwrap();
    assert!(
        !pool_has(&unbounded, &addr(&jurors[0])),
        "unbounded, the voucher of a party is recused"
    );
    assert_eq!(unbounded.len(), 3);
}

#[test]
fn two_replicas_with_post_open_back_dated_evidence_draw_the_same_panel() {
    // Invariant 6 (jury): the draw is a pure function of the bounded log, so two
    // replicas built from the same operations — including a vouch admitted after the
    // dispute opened — seat a byte-identical panel. Deterministic keypairs make the
    // two builds identical logs.
    let build = || {
        let db = fresh_db();
        let jurors: Vec<Keypair> = (0..4).map(|i| kp(&format!("juror:{i}"))).collect();
        for m in &jurors {
            earn_raw_standing(&db, m, T);
        }
        for i in 0..jurors.len() {
            append_vouch(&db, &jurors[(i + 1) % jurors.len()], &addr(&jurors[i]), T);
        }
        let newcomer = kp("newcomer");
        earn_raw_standing(&db, &newcomer, T);
        let (alice, bob) = (kp("alice"), kp("bob"));
        let tx = append_disputed(&db, &alice, &bob, 300, T);
        // Post-open, back-dated anchoring vouch — inert under the bound on both.
        append_vouch(&db, &jurors[0], &addr(&newcomer), T);
        sequence(&db, &tx, &params())
    };
    let (a, b) = (build(), build());
    assert_eq!(a, b, "two identical chains draw the identical panel");
    assert!(!a.is_empty());
}

#[test]
fn a_back_dated_vouch_cannot_pack_the_escalation_electorate() {
    // Invariant 2: a member established by a vouch admitted after the escalation's
    // admission seq is neither in its electorate nor counted; their ballot is refused.
    let db = fresh_db();
    let (alice, _bob, lone, tx) = cannot_seat_setup(&db);
    let p = esc_params();

    // A valid cannot-seat escalation (the pool is too small to seat a panel).
    open_escalation(
        &db,
        &[],
        &p,
        ANCHOR,
        signed_escalation(&tx, &alice, EscalationReason::CannotSeat, T + 5),
        T + 5,
    )
    .unwrap();
    let (_esc, esc_at, esc_seq) = escalation_of(&db, &tx).unwrap().unwrap();
    let info = disputed_info(&db, &tx).unwrap();

    // The electorate is the lone eligible member (both parties recused).
    let before = escalation_electorate(&db, &[], &info, esc_at, esc_seq).unwrap();
    assert!(before.contains(&addr(&lone)));
    assert_eq!(before.len(), 1);

    // A newcomer earns over-band raw standing, then is anchored by a back-dated vouch
    // admitted *after* the escalation opened.
    let newcomer = Keypair::generate();
    earn_raw_standing(&db, &newcomer, T);
    append_vouch(&db, &lone, &addr(&newcomer), T);

    // Bounded at the escalation's seq the newcomer never joins the electorate.
    let after = escalation_electorate(&db, &[], &info, esc_at, esc_seq).unwrap();
    assert!(!after.contains(&addr(&newcomer)));
    assert_eq!(
        after.len(),
        1,
        "the electorate is bounded at the escalation seq"
    );

    // Unbounded, the newcomer would join — proof the bound bites.
    let unbounded = escalation_electorate(&db, &[], &info, esc_at, u64::MAX).unwrap();
    assert!(unbounded.contains(&addr(&newcomer)));

    // And the newcomer's ballot is refused (not in the bounded electorate).
    let err = append_escalation_ballot(
        &db,
        &[],
        &p,
        signed_ballot(&tx, &newcomer, true, esc_at + 10),
        esc_at + 10,
    );
    assert!(matches!(err, Err(rrn_dispute::Error::NotEligible)));
}

#[test]
fn a_tail_anchored_dispute_bounds_to_the_whole_log() {
    // Invariant 8: when the dispute entry is the current tail, the prefix [1, seq] is
    // the whole log, so the bounded pool, weights, and draw equal the unbounded
    // (time-only) computation — a guard against an off-by-one in the bound.
    let db = fresh_db();
    let _jurors = established_members(&db, 5, T);
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let tx = append_disputed(&db, &alice, &bob, 300, T); // the dispute is the tail
    let info = disputed_info(&db, &tx).unwrap();
    let p = params();
    // Nothing is admitted after the dispute, so opened_seq is exactly the tail.
    assert_eq!(
        info.opened_seq,
        AppendLog::new(&db).tail().unwrap().unwrap().seq
    );

    let bounded = eligible_pool(&db, &[], &info, info.opened_at, info.opened_seq, &p).unwrap();
    let whole = eligible_pool(&db, &[], &info, info.opened_at, u64::MAX, &p).unwrap();

    // Same members and weights (compare as pubkey-sorted vectors), and same draw.
    let sort = |mut v: Vec<(Address, u64)>| {
        v.sort_by_key(|(a, _)| a.public_key().to_bytes());
        v
    };
    assert_eq!(sort(bounded.clone()), sort(whole.clone()));
    assert_eq!(
        draw_sequence(&bounded, sortition_seed(&tx, ANCHOR)),
        draw_sequence(&whole, sortition_seed(&tx, ANCHOR)),
    );
    assert_eq!(bounded.len(), 5, "the five jurors; both parties recused");
}
