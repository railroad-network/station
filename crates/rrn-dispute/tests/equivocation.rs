//! End-to-end tests for the equivocation jury (ADR-0025): identity-keyed case
//! discovery, subject/payee recusal, the admission-anchored draw, the three
//! terminal states with a re-seatable lapse, neutralize-only overturn enactment
//! (and its reputation + certificate-gate effects), and cross-replica determinism.

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::attestation::Attestation;
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_ledger::escrow::{
    CertId, CertificateRequest, EquivocationBasis, EquivocationId, EquivocationRecord,
    EvidenceItem, HeadroomCertificate, VerdictDecision,
};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::LedgerSnapshot;
use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

use rrn_dispute::equivocation::{
    append_equivocation_ballot, append_equivocation_reseat, equivocation_cases,
    preview_equivocation, resolve_equivocation, EquivResolution, EquivocationBallot,
    EquivocationReseat,
};
use rrn_dispute::{DisputeParams, Error};
use rrn_reputation::scoring::ReputationScorer;

const ANCHOR: &[u8] = b"commons";
/// Ten 30-day months in, so seeded standing is decay-free at scoring time.
const T: i64 = 10 * 30 * 86_400;
const CAP: i64 = 500;

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

/// A deterministic keypair from a label, so two identical builds produce identical
/// logs (and identical juries) — the basis of the determinism test.
fn kp(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(Hash::of(label.as_bytes()).to_bytes()))
}

fn addr(k: &Keypair) -> Address {
    Address::from_public_key(k.public_key())
}

fn params() -> DisputeParams {
    DisputeParams {
        window_seconds: 1000,
        juror_response_seconds: 1000,
        panel_size: 3,
        appeal_window_seconds: 0,
        escalation_window_seconds: 1000,
        escalation_quorum_pct: 30,
        escalation_approval_pct: 50,
    }
}

// --- reputation seeding (mirrors rrn-reputation / jury.rs helpers) -------------

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
            receiver,
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

/// Gives `who` a raw standing baseline. The receiving sink and the vouch subjects
/// are unique per `tag`, so — like the `Keypair::generate()` in the reputation
/// helpers — no shared counterparty accumulates enough standing to leak into the
/// electorate.
fn earn_raw_standing(db: &Database, who: &Keypair, tag: &str, at: i64) {
    let sink = kp(&format!("equiv:sink:{tag}"));
    for nonce in 0..10 {
        append_settled(db, who, &sink, nonce, at);
    }
    for i in 0..10 {
        append_vouch(
            db,
            who,
            &addr(&kp(&format!("equiv:randsubj:{tag}:{i}"))),
            at,
        );
    }
}

/// `members`, each with raw standing and anchored in a ring, so all count toward
/// the established electorate as of `at`.
fn establish_ring(db: &Database, members: &[Keypair], at: i64) {
    for (i, m) in members.iter().enumerate() {
        earn_raw_standing(db, m, &format!("m{i}"), at);
    }
    let n = members.len();
    for i in 0..n {
        append_vouch(db, &members[(i + 1) % n], &addr(&members[i]), at);
    }
}

// --- equivocation setup -------------------------------------------------------

fn append_certificate(db: &Database, member: &Keypair, station: &Keypair, at: i64) -> CertId {
    let mut log = AppendLog::new(db);
    let req = CertificateRequest::new(addr(member), CAP, 100, at);
    let rid = req.request_id;
    log.append(SignedPayload::sign(req, member), 0).unwrap();
    let cert = HeadroomCertificate::new(addr(member), CAP, rid, at, at + 1_000_000);
    let cid = cert.cert_id;
    log.append(SignedPayload::sign(cert, station), 0).unwrap();
    cid
}

/// A `member`-signed cert-backed spend paying `receiver`, as an evidence item.
fn cert_spend(
    member: &Keypair,
    receiver: &Address,
    cert: CertId,
    amount: i64,
    nonce: u64,
) -> EvidenceItem {
    let p = TransactionProposal::new(
        addr(member),
        *receiver,
        amount,
        None,
        nonce,
        1,
        i64::MAX / 2,
    )
    .with_certificate(cert);
    EvidenceItem::from_signed(&SignedPayload::sign(p, member))
}

/// Appends a station-signed cert-overspend equivocation against `subject`, paying
/// `payee`, with the given `(amount, nonce)` spends (their sum must exceed CAP).
fn append_overspend(
    db: &Database,
    subject: &Keypair,
    station: &Keypair,
    payee: &Address,
    cert: CertId,
    spends: &[(i64, u64)],
    at: i64,
) -> EquivocationId {
    let evidence: Vec<EvidenceItem> = spends
        .iter()
        .map(|(amount, nonce)| cert_spend(subject, payee, cert, *amount, *nonce))
        .collect();
    let record = EquivocationRecord::new(
        addr(subject),
        EquivocationBasis::CertOverspend,
        Some(cert),
        evidence,
        at,
    );
    assert!(
        record.verify_evidence(Some(CAP)),
        "evidence must prove the overspend"
    );
    let id = record.equivocation_id;
    AppendLog::new(db)
        .append(SignedPayload::sign(record, station), at)
        .unwrap();
    id
}

fn cast(
    db: &Database,
    id: EquivocationId,
    juror: &Keypair,
    round: u64,
    decision: VerdictDecision,
    cast_at: i64,
    now: i64,
) -> Result<(), Error> {
    let signed = SignedPayload::sign(
        EquivocationBallot {
            equivocation_id: id,
            juror: addr(juror),
            round,
            decision,
            cast_at,
        },
        juror,
    );
    append_equivocation_ballot(db, &[], &params(), ANCHOR, signed, now)
}

/// A five-member established community with a subject, a payee (both established),
/// a station, a cert on the log, and one cert-overspend equivocation. Returns the
/// members, subject, payee, station, and the equivocation id.
struct Fixture {
    db: Database,
    members: Vec<Keypair>,
    subject: Keypair,
    payee: Keypair,
    station: Keypair,
    id: EquivocationId,
}

fn setup() -> Fixture {
    let db = fresh_db();
    let station = kp("equiv:station");
    // A self-contained ring of five established jurors. The payee is members[1] (a
    // juror, recused as an injured party); the subject is a *separate* member,
    // anchored by members[0] — so zeroing the subject's reputation does not
    // de-anchor any juror (the anchoring cascade flows voucher → subject, ADR-0009).
    let members: Vec<Keypair> = (0..5).map(|i| kp(&format!("equiv:member:{i}"))).collect();
    establish_ring(&db, &members, T);
    let subject = kp("equiv:subject");
    earn_raw_standing(&db, &subject, "subject", T);
    append_vouch(&db, &members[0], &addr(&subject), T);
    let payee = members[1].clone();
    let cert = append_certificate(&db, &subject, &station, T);
    let id = append_overspend(
        &db,
        &subject,
        &station,
        &addr(&payee),
        cert,
        &[(300, 1), (300, 2)],
        T,
    );
    // With the subject recused (and zeroed) and the payee (members[1]) plus the
    // subject's voucher (members[0]) recused, the seated jury is members[2..5].
    Fixture {
        db,
        members,
        subject,
        payee,
        station,
        id,
    }
}

// --- tests --------------------------------------------------------------------

#[test]
fn case_opens_by_replay_with_the_right_subject() {
    let fx = setup();
    let cases = equivocation_cases(&fx.db).unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].subject, addr(&fx.subject));
    assert_eq!(cases[0].basis, EquivocationBasis::CertOverspend);
    assert_eq!(cases[0].attached, vec![fx.id]);
    // The payee is recused as an injured party.
    assert!(cases[0].payees.contains(&addr(&fx.payee)));
}

#[test]
fn two_proofs_of_one_offence_are_one_case() {
    let fx = setup();
    // A second, distinct valid proof of the *same* (subject, cert) overspend
    // (different spend amounts ⇒ different content address). The honest station
    // dedups these; a raw append models a hostile log copy that did not.
    let cert = fx.the_cert();
    let id2 = append_overspend(
        &fx.db,
        &fx.subject,
        &fx.station,
        &addr(&fx.payee),
        cert,
        &[(400, 3), (400, 4)],
        T + 1,
    );
    assert_ne!(fx.id, id2);
    let cases = equivocation_cases(&fx.db).unwrap();
    assert_eq!(cases.len(), 1, "two proofs of one offence are one case");
    assert_eq!(cases[0].attached.len(), 2);
}

#[test]
fn the_subject_and_payee_cannot_sit_on_the_jury() {
    let fx = setup();
    // members[2..5] are the only eligible jurors (subject + payee recused); they
    // can cast. The subject and payee are not seated.
    assert!(cast(
        &fx.db,
        fx.id,
        &fx.members[2],
        0,
        VerdictDecision::Confirm,
        T + 10,
        T + 10
    )
    .is_ok());
    assert!(matches!(
        cast(
            &fx.db,
            fx.id,
            &fx.subject,
            0,
            VerdictDecision::Confirm,
            T + 10,
            T + 10
        ),
        Err(Error::NotSeated)
    ));
    assert!(matches!(
        cast(
            &fx.db,
            fx.id,
            &fx.payee,
            0,
            VerdictDecision::Confirm,
            T + 10,
            T + 10
        ),
        Err(Error::NotSeated)
    ));
}

#[test]
fn a_majority_overturn_neutralizes_the_penalty_end_to_end() {
    let fx = setup();
    // Before any ruling the equivocation is active and blocks issuance, and the
    // penalty has zeroed the subject's trade reliability in scoring.
    let snap = LedgerSnapshot::derive(&AppendLog::new(&fx.db)).unwrap();
    assert!(snap.has_active_equivocation(&addr(&fx.subject)));
    let scorer = ReputationScorer::new(&fx.db);
    assert_eq!(
        scorer
            .score(&addr(&fx.subject), T + 5)
            .unwrap()
            .trade_reliability,
        0.0,
        "the equivocation zeroes trade reliability while it stands"
    );

    // A majority of the seated jury (members[2..5]) overturns.
    for m in &fx.members[2..5] {
        cast(
            &fx.db,
            fx.id,
            m,
            0,
            VerdictDecision::Overturn,
            T + 10,
            T + 10,
        )
        .unwrap();
    }
    let outcome = resolve_equivocation(
        &fx.db,
        &[],
        &fx.station,
        &equivocation_cases(&fx.db).unwrap()[0],
        &params(),
        ANCHOR,
        T + 20,
    )
    .unwrap();
    assert_eq!(outcome, EquivResolution::Overturned);

    // The station-signed terminal Overturn neutralizes the record: no longer active,
    // and scoring restores the subject's trade reliability end-to-end.
    let snap = LedgerSnapshot::derive(&AppendLog::new(&fx.db)).unwrap();
    assert!(snap.is_equivocation_overturned(&fx.id));
    assert!(!snap.has_active_equivocation(&addr(&fx.subject)));
    assert!(
        scorer
            .score(&addr(&fx.subject), T + 30)
            .unwrap()
            .trade_reliability
            > 0.0,
        "an overturned equivocation levies no penalty, so standing returns"
    );

    // Idempotent: a second pass appends nothing new and still reports Overturned.
    let tail = AppendLog::new(&fx.db).tail().unwrap().unwrap().seq;
    let again = resolve_equivocation(
        &fx.db,
        &[],
        &fx.station,
        &equivocation_cases(&fx.db).unwrap()[0],
        &params(),
        ANCHOR,
        T + 30,
    )
    .unwrap();
    assert_eq!(again, EquivResolution::Overturned);
    assert_eq!(AppendLog::new(&fx.db).tail().unwrap().unwrap().seq, tail);
}

#[test]
fn a_majority_confirm_is_final_and_leaves_the_penalty_standing() {
    let fx = setup();
    for m in &fx.members[2..5] {
        cast(
            &fx.db,
            fx.id,
            m,
            0,
            VerdictDecision::Confirm,
            T + 10,
            T + 10,
        )
        .unwrap();
    }
    let outcome = resolve_equivocation(
        &fx.db,
        &[],
        &fx.station,
        &equivocation_cases(&fx.db).unwrap()[0],
        &params(),
        ANCHOR,
        T + 20,
    )
    .unwrap();
    assert_eq!(outcome, EquivResolution::Confirmed);
    let snap = LedgerSnapshot::derive(&AppendLog::new(&fx.db)).unwrap();
    // A confirm records finality but leaves the penalty (and the gate) standing.
    assert!(!snap.is_equivocation_overturned(&fx.id));
    assert!(snap.has_active_equivocation(&addr(&fx.subject)));
}

#[test]
fn an_unruled_case_lapses_then_can_be_reseated() {
    let fx = setup();
    let case = &equivocation_cases(&fx.db).unwrap()[0];
    // Before its window closes: pending. After: lapsed (penalty stands).
    assert_eq!(
        preview_equivocation(&fx.db, &[], case, &params(), ANCHOR, T + 500).unwrap(),
        EquivResolution::Pending
    );
    assert_eq!(
        preview_equivocation(&fx.db, &[], case, &params(), ANCHOR, T + 1000).unwrap(),
        EquivResolution::Lapsed
    );

    // The subject may not re-seat their own case; an established juror may.
    let reseat_by = |who: &Keypair, round: u64, now: i64| {
        let signed = SignedPayload::sign(
            EquivocationReseat {
                equivocation_id: fx.id,
                requester: addr(who),
                round,
                requested_at: now,
            },
            who,
        );
        append_equivocation_reseat(&fx.db, &[], &params(), ANCHOR, signed, now)
    };
    assert!(matches!(
        reseat_by(&fx.subject, 1, T + 1000),
        Err(Error::NotReseatable)
    ));
    reseat_by(&fx.members[2], 1, T + 1000).unwrap();

    // Round 1 is open again; a fresh majority in round 1 confirms.
    let case = &equivocation_cases(&fx.db).unwrap()[0];
    assert_eq!(
        preview_equivocation(&fx.db, &[], case, &params(), ANCHOR, T + 1100).unwrap(),
        EquivResolution::Pending
    );
    for m in &fx.members[2..5] {
        cast(
            &fx.db,
            fx.id,
            m,
            1,
            VerdictDecision::Confirm,
            T + 1100,
            T + 1100,
        )
        .unwrap();
    }
    let outcome = resolve_equivocation(
        &fx.db,
        &[],
        &fx.station,
        &equivocation_cases(&fx.db).unwrap()[0],
        &params(),
        ANCHOR,
        T + 1200,
    )
    .unwrap();
    assert_eq!(outcome, EquivResolution::Confirmed);
}

#[test]
fn a_ballot_in_the_wrong_round_or_by_a_non_juror_is_refused() {
    let fx = setup();
    // Round 1 does not exist yet (case is in round 0).
    assert!(matches!(
        cast(
            &fx.db,
            fx.id,
            &fx.members[2],
            1,
            VerdictDecision::Confirm,
            T + 10,
            T + 10
        ),
        Err(Error::NotSeated)
    ));
    // A double vote by the same juror is refused.
    cast(
        &fx.db,
        fx.id,
        &fx.members[2],
        0,
        VerdictDecision::Confirm,
        T + 10,
        T + 10,
    )
    .unwrap();
    assert!(matches!(
        cast(
            &fx.db,
            fx.id,
            &fx.members[2],
            0,
            VerdictDecision::Overturn,
            T + 20,
            T + 20
        ),
        Err(Error::AlreadyVoted)
    ));
}

#[test]
fn two_identical_logs_reach_identical_outcomes() {
    // The whole path is a pure function of the log: two replicas built from the
    // same deterministic operations seat the same jury and reach the same verdict.
    let build = || {
        let fx = setup();
        for m in &fx.members[2..5] {
            cast(
                &fx.db,
                fx.id,
                m,
                0,
                VerdictDecision::Overturn,
                T + 10,
                T + 10,
            )
            .unwrap();
        }
        let case = equivocation_cases(&fx.db).unwrap().remove(0);
        let id = case.case_id;
        let outcome =
            resolve_equivocation(&fx.db, &[], &fx.station, &case, &params(), ANCHOR, T + 20)
                .unwrap();
        (id, outcome)
    };
    assert_eq!(build(), build());
}

#[test]
fn overturn_neutralizes_every_attached_proof() {
    let fx = setup();
    // A second, distinct proof of the same offence (hostile-copy shape). The case
    // attaches both; an Overturn must neutralize both (ADR-0025 §4).
    let id2 = append_overspend(
        &fx.db,
        &fx.subject,
        &fx.station,
        &addr(&fx.payee),
        fx.the_cert(),
        &[(400, 3), (400, 4)],
        T + 1,
    );
    for m in &fx.members[2..5] {
        cast(
            &fx.db,
            fx.id,
            m,
            0,
            VerdictDecision::Overturn,
            T + 10,
            T + 10,
        )
        .unwrap();
    }
    let case = equivocation_cases(&fx.db).unwrap().remove(0);
    assert_eq!(case.attached.len(), 2);
    resolve_equivocation(&fx.db, &[], &fx.station, &case, &params(), ANCHOR, T + 20).unwrap();

    // One terminal Overturn per attached record — both are neutralized.
    let snap = LedgerSnapshot::derive(&AppendLog::new(&fx.db)).unwrap();
    assert!(snap.is_equivocation_overturned(&fx.id));
    assert!(snap.is_equivocation_overturned(&id2));
    assert!(!snap.has_active_equivocation(&addr(&fx.subject)));
}

#[test]
fn a_small_pool_relaxes_voucher_recusal() {
    // A four-member ring; the payee is members[0] and members[1] is the subject's
    // voucher. Strict recusal leaves only members[2..4] (2 < panel 3), so the
    // voucher-recusal relaxes and members[1] is seated — exactly as ADR-0014 does.
    let db = fresh_db();
    let station = kp("relax:station");
    let members: Vec<Keypair> = (0..4).map(|i| kp(&format!("relax:member:{i}"))).collect();
    establish_ring(&db, &members, T);
    let subject = kp("relax:subject");
    earn_raw_standing(&db, &subject, "relaxsubject", T);
    append_vouch(&db, &members[1], &addr(&subject), T); // members[1] vouches the subject
    let cert = append_certificate(&db, &subject, &station, T);
    let id = append_overspend(
        &db,
        &subject,
        &station,
        &addr(&members[0]),
        cert,
        &[(300, 1), (300, 2)],
        T,
    );

    // The voucher (members[1]) is seated only because the strict pool cannot fill a
    // panel; the payee (members[0]) stays recused.
    assert!(cast(
        &db,
        id,
        &members[1],
        0,
        VerdictDecision::Confirm,
        T + 10,
        T + 10
    )
    .is_ok());
    assert!(matches!(
        cast(
            &db,
            id,
            &members[0],
            0,
            VerdictDecision::Confirm,
            T + 10,
            T + 10
        ),
        Err(Error::NotSeated)
    ));
}

impl Fixture {
    /// Recomputes the subject's certificate id the same way `append_certificate`
    /// built it, for the test that adds a second proof of the same offence.
    fn the_cert(&self) -> CertId {
        let req = CertificateRequest::new(addr(&self.subject), CAP, 100, T);
        HeadroomCertificate::new(addr(&self.subject), CAP, req.request_id, T, T + 1_000_000).cert_id
    }
}
