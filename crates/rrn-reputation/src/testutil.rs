//! Shared test helpers: write the records that earn standing under ADR-0038
//! straight to a log, bypassing the admission doors.
//!
//! Compiled for this crate's tests and, through the `test-util` feature, for the
//! dev-dependencies of the crates downstream of it, so every test that needs
//! established members builds them the same way under the same rules.

use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::attestation::Attestation;
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_ledger::enrollment::{append_enrollment, EnrollmentAction, EnrollmentBasis};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// One week, in seconds — the velocity cap's window.
pub const WEEK: i64 = 7 * 86_400;

/// The amount of every helper trade, in centicommons.
const TRADE_CENTI: i64 = 300;

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

/// Appends a station-signed enrollment of `member` with `basis` (ADR-0038 §1).
pub fn enroll(db: &Database, station: &Keypair, member: &Address, basis: EnrollmentBasis, at: i64) {
    append_enrollment(
        &mut AppendLog::new(db),
        station,
        *member,
        EnrollmentAction::Enroll,
        basis,
        at,
    )
    .expect("append enrollment");
}

/// Appends the operator's revocation of `member` (ADR-0038 §5).
pub fn revoke(db: &Database, station: &Keypair, member: &Address, at: i64) {
    append_enrollment(
        &mut AppendLog::new(db),
        station,
        *member,
        EnrollmentAction::Revoke,
        EnrollmentBasis::Operator,
        at,
    )
    .expect("append revocation");
}

/// Appends a whole trade from `from` to `to` — proposal, the receiver's
/// confirmation, and the station-signed settlement at `settled_at`. `nonce` is
/// the sender's proposal nonce and must be fresh for `from`.
pub fn settle_trade(
    db: &Database,
    station: &Keypair,
    from: &Keypair,
    to: &Keypair,
    nonce: u64,
    settled_at: i64,
) {
    let mut log = AppendLog::new(db);
    let proposal = TransactionProposal::new(
        addr(from),
        addr(to),
        TRADE_CENTI,
        None,
        nonce,
        1,
        i64::MAX / 2,
    );
    let pid = proposal.id;
    log.append(SignedPayload::sign(proposal, from), settled_at)
        .expect("append proposal");
    let confirmation = TransactionConfirmation {
        proposal_id: pid,
        confirmer: addr(to),
        confirmed_at: settled_at,
    };
    log.append(SignedPayload::sign(confirmation, to), settled_at)
        .expect("append confirmation");
    let settlement = SettlementRecord {
        proposal_id: pid,
        sender: addr(from),
        receiver: addr(to),
        amount_centi: TRADE_CENTI,
        settled_at,
    };
    log.append(SignedPayload::sign(settlement, station), settled_at)
        .expect("append settlement");
}

/// Appends a vouch from `voucher` for `subject`, issued at `at`.
pub fn vouch(db: &Database, voucher: &Keypair, subject: &Address, at: i64) {
    let vouch = Attestation {
        kind: VouchKind,
        body: VouchBody {
            community: "commons".into(),
            statement: "known in person".into(),
            reputation_stake_centi: 0,
        },
        subject: *subject,
        issued_at: at,
        expires_at: None,
    };
    AppendLog::new(db)
        .append(vouch.sign(voucher), at)
        .expect("append vouch");
}

/// `n` fresh members established as of `at` — see [`establish`]. Needs
/// `n >= 2` (a ring of one is a self-send) and `at >= 11 WEEK`.
pub fn establish_members(db: &Database, station: &Keypair, n: usize, at: i64) -> Vec<Keypair> {
    assert!(n >= 2, "a ring needs at least two members");
    let members: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
    establish(db, station, &members, at);
    members
}

/// Establishes `members` as of `at`: each enrolled as a `founder` (a root, so
/// anchored by definition) at `at − 11 WEEK`, then ten weekly ring trades
/// `i → (i+1) % n` at `at − (10 − w) WEEK` for `w` in `0..10`. One credited
/// trade and one credited confirmation per member per week, ten weeks running,
/// fills both live dimensions. Needs at least two members, none of whom has
/// proposed before (the ring uses nonces `0..10`), and `at >= 11 WEEK`.
pub fn establish(db: &Database, station: &Keypair, members: &[Keypair], at: i64) {
    let n = members.len();
    assert!(n >= 2, "a ring needs at least two members");
    assert!(
        at >= 11 * WEEK,
        "establishment needs eleven weeks of history before `at`"
    );
    for m in members {
        enroll(
            db,
            station,
            &addr(m),
            EnrollmentBasis::Founder,
            at - 11 * WEEK,
        );
    }
    for w in 0..10 {
        let t = at - (10 - w) * WEEK;
        for i in 0..n {
            settle_trade(db, station, &members[i], &members[(i + 1) % n], w as u64, t);
        }
    }
}

/// Gives `who` raw standing over the Member band as of `at`, without anchoring
/// it: `who` and `partner` enrolled `pairing` at `at − 11 WEEK` (a no-op for one
/// already enrolled), then ten weekly trades `partner → who` ending at
/// `at − WEEK` — a credited trade and a credited confirmation for `who` each
/// week. `partner` must not have proposed before (it uses nonces `0..10`).
pub fn earn_standing(db: &Database, station: &Keypair, who: &Keypair, partner: &Keypair, at: i64) {
    assert!(
        at >= 11 * WEEK,
        "standing needs eleven weeks of history before `at`"
    );
    enroll(
        db,
        station,
        &addr(who),
        EnrollmentBasis::Pairing,
        at - 11 * WEEK,
    );
    enroll(
        db,
        station,
        &addr(partner),
        EnrollmentBasis::Pairing,
        at - 11 * WEEK,
    );
    for w in 0..10 {
        settle_trade(db, station, partner, who, w as u64, at - (10 - w) * WEEK);
    }
}

/// Makes `newcomer` established as of `at`, anchored by `voucher` (who must be
/// established — anchored, raw over the band — at `at`): [`earn_standing`] with a
/// fresh partner, then `voucher`'s vouch at `at`. Everything is appended now, so
/// position-bounded tests see it all land after whatever came before.
pub fn establish_newcomer(
    db: &Database,
    station: &Keypair,
    newcomer: &Keypair,
    voucher: &Keypair,
    at: i64,
) {
    earn_standing(db, station, newcomer, &Keypair::generate(), at);
    vouch(db, voucher, &addr(newcomer), at);
}
