//! Equivalence proof for the kind-dispatch rewrite of [`LedgerSnapshot`] replay.
//!
//! Replay used to trial-decode every ledger record type against each log entry;
//! it now parses the entry once and dispatches on the `kind` discriminator to a
//! single `TryFrom`. The two paths share every mutation — `apply` and
//! `apply_reference` both fold a decoded record through the same `apply_*`
//! methods — so what this test isolates is the *routing*: whether kind dispatch
//! selects the same record (or the same skip) as trial decoding, for any bytes.
//!
//! [`LedgerSnapshot::derive_to`] (dispatch) is asserted equal to
//! [`LedgerSnapshot::derive_to_reference`] (trial decode) over randomly generated
//! logs that mix every ledger kind — proposals, confirmations, settlements,
//! cancellations, disputes, certificate requests/certificates/returns,
//! cert-backed spends, equivocations and their verdicts — with vouches and
//! synthetic marketplace/governance records (wrong-kind for the ledger),
//! forged-signer station records, malformed bytes, and maps carrying a known
//! `kind` over the wrong shape. Equality is asserted at the whole log and at a
//! random prefix bound. A `LedgerSnapshot` is compared with its derived
//! `PartialEq`, so states, nonces, admissions, certificates, equivocations and
//! verdicts must all match.
//!
//! Run the deep lane before opening a PR: `PROPTEST_CASES=512 cargo nextest run
//! -p rrn-ledger --test it replay_dispatch_equivalence` (proptest honors the env
//! var; the default is 64 cases).

use std::collections::HashMap;

use proptest::prelude::*;

use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::dispute::{DisputeRecord, SignedDispute};
use rrn_ledger::escrow::{
    CertId, CertificateRequest, CertificateReturn, EquivocationBasis, EquivocationRecord,
    EquivocationVerdictRecord, EvidenceItem, HeadroomCertificate, VerdictDecision,
};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::{CancelReason, CancellationRecord, LedgerSnapshot};
use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, StoredPayload};
use rrn_storage::migrations;

use dcbor::prelude::Map;

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

// --- log builders (well-formed chains, plus the hostile shapes replay tolerates) --

fn append_settled(db: &Database, s: &Keypair, r: &Keypair, station: &Keypair, nonce: u64, at: i64) {
    let mut log = AppendLog::new(db);
    let proposal = TransactionProposal::new(addr(s), addr(r), 300, None, nonce, 1, i64::MAX / 2);
    let pid = proposal.id;
    log.append(SignedPayload::sign(proposal, s), 0).unwrap();
    let confirmation = TransactionConfirmation {
        proposal_id: pid,
        confirmer: addr(r),
        confirmed_at: at,
    };
    log.append(SignedPayload::sign(confirmation, r), 0).unwrap();
    let settlement = SettlementRecord {
        proposal_id: pid,
        sender: addr(s),
        receiver: addr(r),
        amount_centi: 300,
        settled_at: at,
    };
    log.append(SignedPayload::sign(settlement, station), 0)
        .unwrap();
}

/// A proposal the station then cancels (expiry) — exercises the cancellation arm.
fn append_cancelled(db: &Database, s: &Keypair, r: &Keypair, station: &Keypair, nonce: u64) {
    let mut log = AppendLog::new(db);
    let proposal = TransactionProposal::new(addr(s), addr(r), 300, None, nonce, 1, i64::MAX / 2);
    let pid = proposal.id;
    log.append(SignedPayload::sign(proposal, s), 0).unwrap();
    let cancellation = CancellationRecord {
        proposal_id: pid,
        reason: CancelReason::Expired,
        cancelled_at: 1_000,
    };
    log.append(SignedPayload::sign(cancellation, station), 0)
        .unwrap();
}

fn append_disputed_upheld(
    db: &Database,
    s: &Keypair,
    r: &Keypair,
    station: &Keypair,
    nonce: u64,
    confirmed_at: i64,
    resolved_at: i64,
) {
    let mut log = AppendLog::new(db);
    let proposal = TransactionProposal::new(addr(s), addr(r), 300, None, nonce, 1, i64::MAX / 2);
    let pid = proposal.id;
    log.append(SignedPayload::sign(proposal, s), 0).unwrap();
    let confirmation = TransactionConfirmation {
        proposal_id: pid,
        confirmer: addr(r),
        confirmed_at,
    };
    log.append(SignedPayload::sign(confirmation, r), 0).unwrap();
    let dispute = DisputeRecord {
        proposal_id: pid,
        raiser: addr(s),
        reason: "goods never arrived".into(),
        evidence_hash: None,
        opened_at: confirmed_at,
    };
    log.append(SignedDispute::sign(dispute, s), 0).unwrap();
    let cancellation = CancellationRecord {
        proposal_id: pid,
        reason: CancelReason::DisputeUpheld,
        cancelled_at: resolved_at,
    };
    log.append(SignedPayload::sign(cancellation, station), 0)
        .unwrap();
}

fn append_certificate(
    db: &Database,
    member: &Keypair,
    station: &Keypair,
    cap: i64,
    nonce: u64,
    at: i64,
) -> CertId {
    let mut log = AppendLog::new(db);
    let req = CertificateRequest::new(addr(member), cap, nonce, at);
    let rid = req.request_id;
    log.append(SignedPayload::sign(req, member), 0).unwrap();
    let cert = HeadroomCertificate::new(addr(member), cap, rid, at, at + 1_000_000);
    let cid = cert.cert_id;
    log.append(SignedPayload::sign(cert, station), 0).unwrap();
    cid
}

/// Retires a member's certificate (member-signed return).
fn append_cert_return(db: &Database, member: &Keypair, cert: CertId) {
    let ret = CertificateReturn {
        cert_id: cert,
        member: addr(member),
        returned_at: 2_000,
    };
    AppendLog::new(db)
        .append(SignedPayload::sign(ret, member), 0)
        .unwrap();
}

/// A cert-backed spend proposal (consumes from the certificate).
fn append_cert_spend(db: &Database, member: &Keypair, cert: CertId, amount: i64, nonce: u64) {
    let p = TransactionProposal::new(
        addr(member),
        addr(&Keypair::generate()),
        amount,
        None,
        nonce,
        1,
        i64::MAX / 2,
    )
    .with_certificate(cert);
    AppendLog::new(db)
        .append(SignedPayload::sign(p, member), 0)
        .unwrap();
}

fn cert_evidence(member: &Keypair, cert: CertId, amount: i64, nonce: u64) -> EvidenceItem {
    let p = TransactionProposal::new(
        addr(member),
        addr(&Keypair::generate()),
        amount,
        None,
        nonce,
        1,
        i64::MAX / 2,
    )
    .with_certificate(cert);
    EvidenceItem::from_signed(&SignedPayload::sign(p, member))
}

/// A station-signed cert-overspend equivocation (two 300-spends) with an optional
/// verdict. Verified when `cap < 600`, an inert (non-overspend) record otherwise.
fn append_equivocation(
    db: &Database,
    member: &Keypair,
    station: &Keypair,
    cert: CertId,
    recorded_at: i64,
    verdict: Option<VerdictDecision>,
) {
    let evidence = vec![
        cert_evidence(member, cert, 300, 1),
        cert_evidence(member, cert, 300, 2),
    ];
    let record = EquivocationRecord::new(
        addr(member),
        EquivocationBasis::CertOverspend,
        Some(cert),
        evidence,
        recorded_at,
    );
    let id = record.equivocation_id;
    AppendLog::new(db)
        .append(SignedPayload::sign(record, station), 0)
        .unwrap();
    if let Some(decision) = verdict {
        let v = EquivocationVerdictRecord {
            equivocation_id: id,
            decision,
            decided_at: recorded_at + 1,
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(v, station), 0)
            .unwrap();
    }
}

/// Appends raw bytes with a genuine signature over them (any signer).
fn append_raw_signed(db: &Database, signer: &Keypair, bytes: Vec<u8>) {
    let signature = signer.sign(&bytes);
    let stored = StoredPayload {
        bytes,
        signer: signer.public_key(),
        signature,
    };
    AppendLog::new(db).append_raw(stored, 0).unwrap();
}

/// A CBOR map carrying `kind` and one arbitrary extra field — either a real
/// non-ledger kind (the ledger must skip it), a known ledger kind over the wrong
/// shape (Precondition 1: the matched `TryFrom` must still reject it), or an
/// unknown kind.
fn kinded_garbage(kind: &str) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("kind", kind);
    m.insert("junk", 1u64);
    to_canonical_bytes(m)
}

// --- generated plan -----------------------------------------------------------

#[derive(Clone, Debug)]
enum Action {
    Settle {
        s: usize,
        r: usize,
        at: i64,
    },
    Cancel {
        s: usize,
        r: usize,
    },
    DisputeUpheld {
        s: usize,
        r: usize,
        at: i64,
    },
    Certificate {
        m: usize,
        cap: i64,
    },
    CertReturn {
        m: usize,
    },
    CertSpend {
        m: usize,
        amount: i64,
    },
    Equivocate {
        m: usize,
        cap: i64,
        verdict: Option<bool>,
    },
    Vouch {
        voucher: usize,
        subject: usize,
    },
    /// A station-kind record forged by a non-station member (signer-pin skip).
    ForgedSettlement {
        s: usize,
        r: usize,
    },
    /// Wrong-kind, wrong-shape or unknown map — a known-kind index picks which.
    Garbage {
        which: usize,
    },
    /// Malformed / non-canonical / non-map raw bytes.
    Malformed {
        which: usize,
    },
}

fn action_strategy(n: usize) -> impl Strategy<Value = Action> {
    let time = 0i64..=10_000;
    let idx = 0..n;
    prop_oneof![
        (idx.clone(), 0..n, time.clone()).prop_map(|(s, r, at)| Action::Settle { s, r, at }),
        (idx.clone(), 0..n).prop_map(|(s, r)| Action::Cancel { s, r }),
        (idx.clone(), 0..n, time).prop_map(|(s, r, at)| Action::DisputeUpheld { s, r, at }),
        (idx.clone(), prop::sample::select(vec![300i64, 500, 700]))
            .prop_map(|(m, cap)| Action::Certificate { m, cap }),
        idx.clone().prop_map(|m| Action::CertReturn { m }),
        (idx.clone(), prop::sample::select(vec![100i64, 300, 400]))
            .prop_map(|(m, amount)| Action::CertSpend { m, amount }),
        (
            idx.clone(),
            prop::sample::select(vec![300i64, 500, 700]),
            prop::option::of(any::<bool>()),
        )
            .prop_map(|(m, cap, verdict)| Action::Equivocate { m, cap, verdict }),
        (idx.clone(), 0..n).prop_map(|(voucher, subject)| Action::Vouch { voucher, subject }),
        (idx, 0..n).prop_map(|(s, r)| Action::ForgedSettlement { s, r }),
        (0usize..8).prop_map(|which| Action::Garbage { which }),
        (0usize..4).prop_map(|which| Action::Malformed { which }),
    ]
}

fn plan_strategy() -> impl Strategy<Value = (usize, Vec<Action>)> {
    (2usize..=6).prop_flat_map(|n| {
        proptest::collection::vec(action_strategy(n), 0..=24).prop_map(move |actions| (n, actions))
    })
}

#[derive(Default)]
struct Nonces(HashMap<[u8; 32], u64>);

impl Nonces {
    fn next(&mut self, kp: &Keypair) -> u64 {
        let slot = self.0.entry(kp.public_key().to_bytes()).or_insert(0);
        let n = *slot;
        *slot += 1;
        n
    }
}

/// The eight `kinded_garbage` variants: real non-ledger kinds, known ledger kinds
/// over the wrong shape, and an unknown kind — all of which replay must skip.
const GARBAGE_KINDS: [&str; 8] = [
    "rrn.marketplace.listing.v1",
    "rrn.marketplace.listing_updated.v1",
    "rrn.tx.dispute.response",
    "rrn.tx.contract_charge",
    "vouch",
    "rrn.tx.proposal",   // known ledger kind, wrong shape → matched TryFrom rejects
    "rrn.tx.settlement", // known ledger kind, wrong shape
    "rrn.unknown.kind.v1", // unknown kind
];

fn build_log(db: &Database, members: &[Keypair], station: &Keypair, plan: &[Action]) -> u64 {
    let mut nonces = Nonces::default();
    // The most recently issued certificate per member, so returns/spends have a
    // real target.
    let mut certs: HashMap<usize, CertId> = HashMap::new();
    for action in plan {
        match action {
            Action::Settle { s, r, at } => {
                let n = nonces.next(&members[*s]);
                append_settled(db, &members[*s], &members[*r], station, n, *at);
            }
            Action::Cancel { s, r } => {
                let n = nonces.next(&members[*s]);
                append_cancelled(db, &members[*s], &members[*r], station, n);
            }
            Action::DisputeUpheld { s, r, at } => {
                let n = nonces.next(&members[*s]);
                append_disputed_upheld(db, &members[*s], &members[*r], station, n, *at, *at);
            }
            Action::Certificate { m, cap } => {
                let n = nonces.next(&members[*m]);
                let cid = append_certificate(db, &members[*m], station, *cap, n, 1_000);
                certs.insert(*m, cid);
            }
            Action::CertReturn { m } => {
                if let Some(cid) = certs.get(m) {
                    append_cert_return(db, &members[*m], *cid);
                }
            }
            Action::CertSpend { m, amount } => {
                if let Some(cid) = certs.get(m) {
                    let n = nonces.next(&members[*m]);
                    append_cert_spend(db, &members[*m], *cid, *amount, n);
                }
            }
            Action::Equivocate { m, cap, verdict } => {
                let n = nonces.next(&members[*m]);
                let cid = append_certificate(db, &members[*m], station, *cap, n, 1_000);
                certs.insert(*m, cid);
                let decision = verdict.map(|overturn| {
                    if overturn {
                        VerdictDecision::Overturn
                    } else {
                        VerdictDecision::Confirm
                    }
                });
                append_equivocation(db, &members[*m], station, cid, 1_000, decision);
            }
            Action::Vouch { voucher, subject } => {
                let vouch = rrn_identity::vouch::create_vouch(
                    &members[*voucher],
                    &addr(&members[*subject]),
                    "commons",
                    "trustworthy",
                    0,
                );
                AppendLog::new(db).append(vouch, 0).unwrap();
            }
            Action::ForgedSettlement { s, r } => {
                // A settlement record signed by a member, not the station: replay
                // must skip it on the signer pin (both paths identically).
                let settlement = SettlementRecord {
                    proposal_id: TransactionProposal::new(
                        addr(&members[*s]),
                        addr(&members[*r]),
                        300,
                        None,
                        0,
                        1,
                        i64::MAX / 2,
                    )
                    .id,
                    sender: addr(&members[*s]),
                    receiver: addr(&members[*r]),
                    amount_centi: 300,
                    settled_at: 5_000,
                };
                AppendLog::new(db)
                    .append(SignedPayload::sign(settlement, &members[*s]), 0)
                    .unwrap();
            }
            Action::Garbage { which } => {
                append_raw_signed(db, station, kinded_garbage(GARBAGE_KINDS[*which]));
            }
            Action::Malformed { which } => {
                let bytes = match which {
                    0 => vec![0x18, 0x17],         // non-canonical integer
                    1 => to_canonical_bytes(9u64), // a non-map value
                    2 => {
                        // a map with no `kind` key
                        let mut m = Map::new();
                        m.insert("a", 1u64);
                        to_canonical_bytes(m)
                    }
                    _ => {
                        // a map whose `kind` is a non-string
                        let mut m = Map::new();
                        m.insert("kind", 7u64);
                        to_canonical_bytes(m)
                    }
                };
                append_raw_signed(db, station, bytes);
            }
        }
    }
    AppendLog::new(db)
        .tail()
        .unwrap()
        .map(|e| e.seq)
        .unwrap_or(0)
}

/// Property-test case budget: `PROPTEST_CASES` if set (the deep lane sets
/// 1024), else `default_cases`. Unlike `ProptestConfig::with_cases`, this
/// honors the env var, so the deep lane deepens this equivalence proof too.
fn cases(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default_cases);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cases(64))]

    /// Dispatch replay reproduces trial-decode replay exactly, at the whole log
    /// and at a random prefix bound.
    #[test]
    fn dispatch_matches_trial_decode(
        (num_members, plan) in plan_strategy(),
        max_seq_pick in prop_oneof![Just(None), (0u64..=100).prop_map(Some)],
    ) {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let station = Keypair::generate();
        let members: Vec<Keypair> = (0..num_members).map(|_| Keypair::generate()).collect();

        let tail = build_log(&db, &members, &station, &plan);
        let max_seq = match max_seq_pick {
            None => u64::MAX,
            Some(pct) => tail * pct / 100,
        };
        let station_pub = station.public_key();
        let log = AppendLog::new(&db);

        let dispatched = LedgerSnapshot::derive_to(&log, max_seq, &station_pub).unwrap();
        let reference = LedgerSnapshot::derive_to_reference(&log, max_seq, &station_pub).unwrap();
        prop_assert!(
            dispatched == reference,
            "dispatch and trial-decode snapshots differ at max_seq={max_seq}"
        );
    }
}

/// A hand-built log that provably lands on every ledger arm — a full settle, a
/// dispute-upheld cancellation, a certificate consumed by a cert-backed spend
/// then returned, a verified equivocation with a confirming verdict, and every
/// flavour of garbage — asserting dispatch equals trial decode across a matrix of
/// prefix bounds. Non-vacuity: the whole-log snapshot is non-empty.
#[test]
fn a_deterministic_rich_log_matches_and_is_non_empty() {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    let station = Keypair::generate();
    let station_pub = station.public_key();
    let (alice, bob) = (Keypair::generate(), Keypair::generate());
    let mut nonces = Nonces::default();

    let n = nonces.next(&alice);
    append_settled(&db, &alice, &bob, &station, n, 5_000);
    let n = nonces.next(&bob);
    append_disputed_upheld(&db, &bob, &alice, &station, n, 4_000, 4_500);
    let n = nonces.next(&alice);
    append_cancelled(&db, &alice, &bob, &station, n);

    let n = nonces.next(&alice);
    let cert = append_certificate(&db, &alice, &station, 500, n, 1_000);
    let n = nonces.next(&alice);
    append_cert_spend(&db, &alice, cert, 400, n);

    let n = nonces.next(&bob);
    let equiv_cert = append_certificate(&db, &bob, &station, 500, n, 1_000);
    append_equivocation(
        &db,
        &bob,
        &station,
        equiv_cert,
        1_000,
        Some(VerdictDecision::Confirm),
    );

    // Garbage of every flavour.
    for k in GARBAGE_KINDS {
        append_raw_signed(&db, &station, kinded_garbage(k));
    }
    append_raw_signed(&db, &station, vec![0x18, 0x17]);
    append_raw_signed(&db, &station, to_canonical_bytes(9u64));

    let tail = AppendLog::new(&db).tail().unwrap().unwrap().seq;
    let log = AppendLog::new(&db);

    // The whole-log snapshot must be non-empty, or the equivalence below is vacuous.
    let whole = LedgerSnapshot::derive(&log, &station_pub).unwrap();
    assert_ne!(
        whole,
        LedgerSnapshot::default(),
        "the fixture must derive state"
    );

    for max_seq in [0, 3, 6, 9, tail, u64::MAX] {
        let dispatched = LedgerSnapshot::derive_to(&log, max_seq, &station_pub).unwrap();
        let reference = LedgerSnapshot::derive_to_reference(&log, max_seq, &station_pub).unwrap();
        assert!(
            dispatched == reference,
            "dispatch and trial-decode differ at max_seq={max_seq}"
        );
    }
}
