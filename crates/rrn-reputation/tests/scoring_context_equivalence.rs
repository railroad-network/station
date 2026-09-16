//! Equivalence proof for [`rrn_reputation::context::ScoringContext`].
//!
//! The context replaced a per-address scorer that re-derived the ledger and
//! re-scanned the log once per address (and again per voucher). This test keeps
//! that old implementation, copied verbatim into [`reference`], as an oracle and
//! asserts the context reproduces it **bit for bit** — every dimension compared by
//! `f32::to_bits`, anchoring vouchers compared as addresses, established sets
//! compared as sets — over randomly generated logs that exercise settlements,
//! self/member/throwaway/duplicate/late vouches, upheld disputes, and proven and
//! overturned equivocations, at random scoring instants and prefix bounds.
//!
//! Run the deep lane before opening a PR: `PROPTEST_CASES=512 cargo nextest run
//! -p rrn-reputation --test scoring_context_equivalence` (proptest honors the env
//! var; the default is 64 cases).

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;

use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::attestation::Attestation;
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_ledger::dispute::{DisputeRecord, SignedDispute};
use rrn_ledger::escrow::{
    CertId, CertificateRequest, EquivocationBasis, EquivocationId, EquivocationRecord,
    EquivocationVerdictRecord, EvidenceItem, HeadroomCertificate, VerdictDecision,
};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::{CancelReason, CancellationRecord};
use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

use rrn_reputation::context::ScoringContext;

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

// --- log builders (the same well-formed chains the crate's unit tests use) ----

fn append_settled(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    station: &Keypair,
    nonce: u64,
    at: i64,
) {
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
    let confirmation = TransactionConfirmation {
        proposal_id: pid,
        confirmer: addr(receiver),
        confirmed_at: at,
    };
    log.append(SignedPayload::sign(confirmation, receiver), 0)
        .unwrap();
    let settlement = SettlementRecord {
        proposal_id: pid,
        sender: addr(sender),
        receiver: addr(receiver),
        amount_centi: 300,
        settled_at: at,
    };
    log.append(SignedPayload::sign(settlement, station), 0)
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

fn append_disputed_upheld(
    db: &Database,
    sender: &Keypair,
    receiver: &Keypair,
    station: &Keypair,
    nonce: u64,
    confirmed_at: i64,
    resolved_at: i64,
) {
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
    let confirmation = TransactionConfirmation {
        proposal_id: pid,
        confirmer: addr(receiver),
        confirmed_at,
    };
    log.append(SignedPayload::sign(confirmation, receiver), 0)
        .unwrap();
    let dispute = DisputeRecord {
        proposal_id: pid,
        raiser: addr(sender),
        reason: "goods never arrived".into(),
        evidence_hash: None,
        opened_at: confirmed_at,
    };
    log.append(SignedDispute::sign(dispute, sender), 0).unwrap();
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

/// A station-signed cert-overspend equivocation (two 300-spends). Verified when
/// `cap < 600`, an inert (non-overspend) record otherwise — both branches matter.
fn append_equivocation(
    db: &Database,
    member: &Keypair,
    station: &Keypair,
    cert: CertId,
    recorded_at: i64,
) -> EquivocationId {
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
    id
}

fn append_overturn(db: &Database, station: &Keypair, id: EquivocationId, decided_at: i64) {
    let verdict = EquivocationVerdictRecord {
        equivocation_id: id,
        decision: VerdictDecision::Overturn,
        decided_at,
    };
    AppendLog::new(db)
        .append(SignedPayload::sign(verdict, station), 0)
        .unwrap();
}

/// Hands out a strictly increasing nonce per member, so proposals and certificate
/// requests from the same member are always admitted (ADR-0021 §1 shares the
/// sequence).
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

// --- the reference implementation: today's scorer, copied verbatim ------------

mod reference {
    use super::*;
    use rrn_crypto::keypair::PublicKey;
    use rrn_crypto::serialize::from_canonical_bytes;
    use rrn_identity::vouch::Vouch;
    use rrn_ledger::state::{LedgerSnapshot, TransactionState};
    use rrn_reputation::decay::decayed;
    use rrn_reputation::model::{ReputationProfile, BAND_MEMBER_MIN, DIMENSION_MAX};
    use rrn_reputation::sybil::{anchored_profile, ANCHOR_VOUCHER_MIN_COMPOSITE};
    use rrn_reputation::Result;

    const EVENT_INCREMENT: f32 = 0.5;
    const EQUIVOCATION_WEIGHT: f32 = DIMENSION_MAX;

    #[derive(Default)]
    struct DimensionTally {
        count: u32,
        penalty: f32,
        last_activity: Option<i64>,
    }

    impl DimensionTally {
        fn record(&mut self, event_time: i64) {
            self.count += 1;
            self.last_activity = Some(match self.last_activity {
                Some(prev) => prev.max(event_time),
                None => event_time,
            });
        }
        fn penalize(&mut self) {
            self.penalize_by(EVENT_INCREMENT);
        }
        fn penalize_by(&mut self, weight: f32) {
            self.penalty += weight;
        }
        fn score(&self, at_time: i64) -> f32 {
            let Some(last) = self.last_activity else {
                return 0.0;
            };
            let earned = (EVENT_INCREMENT * self.count as f32).min(DIMENSION_MAX);
            let net = earned - self.penalty;
            decayed(net, last, at_time)
        }
    }

    fn confirmation_of(state: &TransactionState) -> Option<&TransactionConfirmation> {
        match state {
            TransactionState::Confirmed { confirmation, .. }
            | TransactionState::Settled { confirmation, .. } => Some(&confirmation.payload),
            _ => None,
        }
    }

    fn overturned_equivocations(
        log: &AppendLog,
        station: &PublicKey,
        at_time: i64,
        max_seq: u64,
    ) -> Result<HashSet<EquivocationId>> {
        let mut out = HashSet::new();
        for entry in log.iter_from(1) {
            let entry = entry?;
            if entry.seq > max_seq {
                break;
            }
            let Ok(verdict) =
                from_canonical_bytes::<EquivocationVerdictRecord>(&entry.payload.bytes)
            else {
                continue;
            };
            if entry.payload.signer != *station {
                continue;
            }
            if verdict.decision == VerdictDecision::Overturn && verdict.decided_at <= at_time {
                out.insert(verdict.equivocation_id);
            }
        }
        Ok(out)
    }

    pub fn score_raw_at_bounded(
        db: &Database,
        address: &Address,
        at_time: i64,
        max_seq: u64,
        station: &PublicKey,
    ) -> Result<ReputationProfile> {
        let log = AppendLog::new(db);

        let mut trade = DimensionTally::default();
        let mut attestation = DimensionTally::default();

        let ledger = LedgerSnapshot::derive_to(&log, max_seq, station)?;
        for (_, state) in ledger.iter() {
            if let TransactionState::Settled {
                proposal,
                settled_at,
                ..
            } = state
            {
                let p = &proposal.payload;
                if (p.sender == *address || p.receiver == *address) && *settled_at <= at_time {
                    trade.record(*settled_at);
                }
            }
            if let Some(confirmation) = confirmation_of(state) {
                if confirmation.confirmer == *address && confirmation.confirmed_at <= at_time {
                    attestation.record(confirmation.confirmed_at);
                }
            }
            if let TransactionState::Cancelled {
                proposal,
                reason: CancelReason::DisputeUpheld,
                cancelled_at,
            } = state
            {
                if proposal.payload.receiver == *address && *cancelled_at <= at_time {
                    attestation.penalize();
                }
            }
        }

        for entry in log.iter_from(1) {
            let entry = entry?;
            if entry.seq > max_seq {
                break;
            }
            let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) else {
                continue;
            };
            let voucher = Address::from_public_key(entry.payload.signer);
            if voucher == *address && vouch.issued_at <= at_time {
                attestation.record(vouch.issued_at);
            }
        }

        let overturned = overturned_equivocations(&log, station, at_time, max_seq)?;
        for entry in log.iter_from(1) {
            let entry = entry?;
            if entry.seq > max_seq {
                break;
            }
            if entry.payload.signer != *station {
                continue;
            }
            let Ok(record) = from_canonical_bytes::<EquivocationRecord>(&entry.payload.bytes)
            else {
                continue;
            };
            if record.member != *address || record.recorded_at > at_time {
                continue;
            }
            if overturned.contains(&record.equivocation_id) {
                continue;
            }
            let cap = match record.basis {
                EquivocationBasis::CertOverspend => record
                    .cert_id
                    .and_then(|c| ledger.certificate(&c))
                    .map(|c| c.certificate.payload.cap_centi),
                EquivocationBasis::OutboxFork => None,
            };
            if record.verify_evidence(cap) {
                trade.penalize_by(EQUIVOCATION_WEIGHT);
                attestation.penalize_by(EQUIVOCATION_WEIGHT);
            }
        }

        let mut profile = ReputationProfile::empty(*address);
        profile.trade_reliability = trade.score(at_time);
        profile.attestation_accuracy = attestation.score(at_time);
        profile.last_updated = at_time;
        Ok(profile)
    }

    pub fn anchoring_voucher_bounded(
        db: &Database,
        address: &Address,
        at_time: i64,
        max_seq: u64,
        station: &PublicKey,
    ) -> Result<Option<Address>> {
        let log = AppendLog::new(db);
        for entry in log.iter_from(1) {
            let entry = entry?;
            if entry.seq > max_seq {
                break;
            }
            let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) else {
                continue;
            };
            if vouch.subject != *address || vouch.issued_at > at_time {
                continue;
            }
            let voucher = Address::from_public_key(entry.payload.signer);
            if voucher == *address {
                continue;
            }
            if score_raw_at_bounded(db, &voucher, at_time, max_seq, station)?.composite()
                >= ANCHOR_VOUCHER_MIN_COMPOSITE
            {
                return Ok(Some(voucher));
            }
        }
        Ok(None)
    }

    pub fn score_at_position(
        db: &Database,
        address: &Address,
        at_time: i64,
        max_seq: u64,
        station: &PublicKey,
    ) -> Result<ReputationProfile> {
        let raw = score_raw_at_bounded(db, address, at_time, max_seq, station)?;
        let anchored = anchoring_voucher_bounded(db, address, at_time, max_seq, station)?.is_some();
        Ok(anchored_profile(&raw, anchored))
    }

    pub fn known_addresses(db: &Database, station: &PublicKey) -> Result<Vec<Address>> {
        let log = AppendLog::new(db);
        let mut addresses: HashSet<Address> = HashSet::new();

        let ledger = LedgerSnapshot::derive(&log, station)?;
        for (_, state) in ledger.iter() {
            let (sender, receiver) = match state {
                TransactionState::Proposed { proposal }
                | TransactionState::Confirmed { proposal, .. }
                | TransactionState::Settled { proposal, .. }
                | TransactionState::Cancelled { proposal, .. }
                | TransactionState::Disputed { proposal, .. } => {
                    (proposal.payload.sender, proposal.payload.receiver)
                }
            };
            addresses.insert(sender);
            addresses.insert(receiver);
        }

        for entry in log.iter_from(1) {
            let entry = entry?;
            if let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) {
                addresses.insert(Address::from_public_key(entry.payload.signer));
                addresses.insert(vouch.subject);
            }
        }

        Ok(addresses.into_iter().collect())
    }

    pub fn established_members_asof(
        db: &Database,
        at_time: i64,
        max_seq: u64,
        station: &PublicKey,
    ) -> Result<Vec<Address>> {
        let mut members = Vec::new();
        for address in known_addresses(db, station)? {
            if score_at_position(db, &address, at_time, max_seq, station)?.composite()
                >= BAND_MEMBER_MIN
            {
                members.push(address);
            }
        }
        Ok(members)
    }
}

// --- the generated plan -------------------------------------------------------

#[derive(Clone, Debug)]
enum Subject {
    Member(usize),
    SelfVouch,
    Throwaway,
}

#[derive(Clone, Debug)]
enum Action {
    Settle {
        s: usize,
        r: usize,
        at: i64,
    },
    Vouch {
        voucher: usize,
        subject: Subject,
        at: i64,
    },
    DisputeUpheld {
        s: usize,
        r: usize,
        confirmed_at: i64,
        resolved_at: i64,
    },
    Equivocate {
        member: usize,
        cap: i64,
        recorded_at: i64,
        overturn_at: Option<i64>,
    },
}

fn action_strategy(n: usize) -> impl Strategy<Value = Action> {
    let time = 0i64..=10_000;
    let idx = 0..n;
    prop_oneof![
        (idx.clone(), 0..n, time.clone()).prop_map(|(s, r, at)| Action::Settle { s, r, at }),
        (
            idx.clone(),
            prop_oneof![
                (0..n).prop_map(Subject::Member),
                Just(Subject::SelfVouch),
                Just(Subject::Throwaway),
            ],
            time.clone(),
        )
            .prop_map(|(voucher, subject, at)| Action::Vouch {
                voucher,
                subject,
                at
            }),
        (idx.clone(), 0..n, time.clone(), time.clone()).prop_map(
            |(s, r, confirmed_at, resolved_at)| Action::DisputeUpheld {
                s,
                r,
                confirmed_at,
                resolved_at: confirmed_at.max(resolved_at),
            }
        ),
        (
            idx,
            prop::sample::select(vec![300i64, 500, 700]),
            time.clone(),
            prop::option::of(time),
        )
            .prop_map(
                |(member, cap, recorded_at, overturn_at)| Action::Equivocate {
                    member,
                    cap,
                    recorded_at,
                    overturn_at,
                }
            ),
    ]
}

fn plan_strategy() -> impl Strategy<Value = (usize, Vec<Action>)> {
    (3usize..=8).prop_flat_map(|n| {
        proptest::collection::vec(action_strategy(n), 0..=20).prop_map(move |actions| (n, actions))
    })
}

/// Applies a generated plan to a fresh in-memory log, returning the log's tail
/// sequence (0 when empty).
fn build_log(db: &Database, members: &[Keypair], station: &Keypair, plan: &[Action]) -> u64 {
    let mut nonces = Nonces::default();
    for action in plan {
        match action {
            Action::Settle { s, r, at } => {
                let n = nonces.next(&members[*s]);
                append_settled(db, &members[*s], &members[*r], station, n, *at);
            }
            Action::Vouch {
                voucher,
                subject,
                at,
            } => {
                let subject_addr = match subject {
                    Subject::Member(i) => addr(&members[*i]),
                    Subject::SelfVouch => addr(&members[*voucher]),
                    Subject::Throwaway => addr(&Keypair::generate()),
                };
                append_vouch(db, &members[*voucher], &subject_addr, *at);
            }
            Action::DisputeUpheld {
                s,
                r,
                confirmed_at,
                resolved_at,
            } => {
                let n = nonces.next(&members[*s]);
                append_disputed_upheld(
                    db,
                    &members[*s],
                    &members[*r],
                    station,
                    n,
                    *confirmed_at,
                    *resolved_at,
                );
            }
            Action::Equivocate {
                member,
                cap,
                recorded_at,
                overturn_at,
            } => {
                let n = nonces.next(&members[*member]);
                let cert =
                    append_certificate(db, &members[*member], station, *cap, n, *recorded_at);
                let id = append_equivocation(db, &members[*member], station, cert, *recorded_at);
                if let Some(oat) = overturn_at {
                    append_overturn(db, station, id, *oat);
                }
            }
        }
    }
    AppendLog::new(db)
        .tail()
        .unwrap()
        .map(|e| e.seq)
        .unwrap_or(0)
}

fn bits_eq(want: f32, got: f32) -> bool {
    want.to_bits() == got.to_bits()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For every generated log, prefix bound and scoring instant, the context's
    /// score, anchoring voucher and established set match the reference oracle
    /// exactly (dimensions compared bit for bit).
    #[test]
    fn context_matches_reference(
        (num_members, plan) in plan_strategy(),
        at_time in 0i64..=12_000,
        // `None` is the whole log; `Some(pct)` picks a bound at that percentage of
        // the tail, so bounded cases land inside `[0, tail]` (per the ticket) rather
        // than mostly past it.
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

        let ctx = ScoringContext::new(&db, &station_pub, max_seq).unwrap();

        for address in reference::known_addresses(&db, &station_pub).unwrap() {
            let want = reference::score_at_position(&db, &address, at_time, max_seq, &station_pub)
                .unwrap();
            let got = ctx.score(&address, at_time);

            prop_assert!(
                bits_eq(want.trade_reliability, got.trade_reliability),
                "trade_reliability differs: want {} got {} (addr {address})",
                want.trade_reliability,
                got.trade_reliability
            );
            prop_assert!(
                bits_eq(want.attestation_accuracy, got.attestation_accuracy),
                "attestation_accuracy differs: want {} got {} (addr {address})",
                want.attestation_accuracy,
                got.attestation_accuracy
            );
            prop_assert!(
                bits_eq(want.composite(), got.composite()),
                "composite differs: want {} got {} (addr {address})",
                want.composite(),
                got.composite()
            );
            // The dormant dimensions, address and last_updated must match too.
            prop_assert_eq!(&want, &got, "full profile differs for {}", address);

            let want_anchor =
                reference::anchoring_voucher_bounded(&db, &address, at_time, max_seq, &station_pub)
                    .unwrap();
            let got_anchor = ctx.anchoring_voucher(&address, at_time);
            prop_assert_eq!(
                want_anchor,
                got_anchor,
                "anchoring voucher differs for {}",
                address
            );
        }

        let want_established: HashSet<Address> =
            reference::established_members_asof(&db, at_time, max_seq, &station_pub)
                .unwrap()
                .into_iter()
                .collect();
        let got_established: HashSet<Address> =
            ctx.established_members(at_time).into_iter().collect();
        prop_assert_eq!(
            want_established,
            got_established,
            "established set differs"
        );
    }
}

const MONTH: i64 = 30 * 86_400;

/// Asserts the context reproduces the reference for every known address at one
/// `(at_time, max_seq)` — scores bit for bit, anchoring vouchers, established set.
fn assert_equiv(
    db: &Database,
    station: &rrn_crypto::keypair::PublicKey,
    at_time: i64,
    max_seq: u64,
) {
    let ctx = ScoringContext::new(db, station, max_seq).unwrap();
    for address in reference::known_addresses(db, station).unwrap() {
        let want = reference::score_at_position(db, &address, at_time, max_seq, station).unwrap();
        let got = ctx.score(&address, at_time);
        assert!(
            bits_eq(want.trade_reliability, got.trade_reliability)
                && bits_eq(want.attestation_accuracy, got.attestation_accuracy),
            "score differs at (at_time={at_time}, max_seq={max_seq}) for {address}: want {want:?} got {got:?}"
        );
        assert_eq!(want, got, "full profile differs for {address}");
        assert_eq!(
            reference::anchoring_voucher_bounded(db, &address, at_time, max_seq, station).unwrap(),
            ctx.anchoring_voucher(&address, at_time),
            "anchoring voucher differs for {address}"
        );
    }
    let want: HashSet<Address> = reference::established_members_asof(db, at_time, max_seq, station)
        .unwrap()
        .into_iter()
        .collect();
    let got: HashSet<Address> = ctx.established_members(at_time).into_iter().collect();
    assert_eq!(want, got, "established set differs at max_seq={max_seq}");
}

/// A hand-built log that provably lands on every fold the proptest reaches only
/// probabilistically: an anchored member whose verified equivocation zeroes both
/// dimensions and is later overturned, an upheld dispute against a confirmer, and
/// a `max_seq` pinned just before the equivocation. The equivalence is asserted
/// across a matrix of instants and prefix bounds, and the non-vacuity assertions
/// confirm the verified-equivocation and overturn branches actually fire (so a
/// context that silently ignored them could not pass).
#[test]
fn a_deterministic_rich_log_matches_the_reference_and_fires_every_branch() {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    let station = Keypair::generate();
    let station_pub = station.public_key();
    let (mallory, bob, patron) = (
        Keypair::generate(),
        Keypair::generate(),
        Keypair::generate(),
    );
    let t = 10 * MONTH;
    let mut nonces = Nonces::default();

    // A patron earns raw standing (ten settles + ten vouches → composite 2.75) so
    // their vouch can anchor, then anchors mallory and bob.
    for _ in 0..10 {
        let n = nonces.next(&patron);
        append_settled(&db, &patron, &station, &station, n, t);
    }
    for _ in 0..10 {
        append_vouch(&db, &patron, &addr(&Keypair::generate()), t);
    }
    append_vouch(&db, &patron, &addr(&mallory), t);
    append_vouch(&db, &patron, &addr(&bob), t);

    // Mallory: two sends (trade 1.0) and three vouches (attestation 1.5) raw.
    for _ in 0..2 {
        let n = nonces.next(&mallory);
        append_settled(&db, &mallory, &bob, &station, n, t);
    }
    for _ in 0..3 {
        append_vouch(&db, &mallory, &addr(&Keypair::generate()), t);
    }
    let cert = {
        let n = nonces.next(&mallory);
        append_certificate(&db, &mallory, &station, 500, n, t)
    };
    let seq_before_equiv = AppendLog::new(&db).tail().unwrap().unwrap().seq;
    // A verified cert-overspend (two 300s over the 500 cap), overturned a month on.
    let equiv_id = append_equivocation(&db, &mallory, &station, cert, t);
    let seq_after_equiv = AppendLog::new(&db).tail().unwrap().unwrap().seq;
    append_overturn(&db, &station, equiv_id, t + MONTH);

    // An upheld dispute against a confirmation bob made dents bob's attestation.
    let n = nonces.next(&patron);
    append_disputed_upheld(&db, &patron, &bob, &station, n, t, t);

    let tail = AppendLog::new(&db).tail().unwrap().unwrap().seq;

    // Non-vacuity: the reference itself must show the verified-equivocation fold
    // firing (mallory positive before the record, zeroed at it) and the overturn
    // lifting it — otherwise the equivalence below would be vacuous on these folds.
    let m = addr(&mallory);
    let before = reference::score_at_position(&db, &m, t, seq_before_equiv, &station_pub).unwrap();
    assert!(
        before.attestation_accuracy > 0.9,
        "baseline before the equivocation must be positive, got {}",
        before.attestation_accuracy
    );
    let at_record = reference::score_at_position(&db, &m, t, u64::MAX, &station_pub).unwrap();
    assert_eq!(
        at_record.attestation_accuracy, 0.0,
        "a verified, un-overturned equivocation must zero attestation"
    );
    assert_eq!(at_record.trade_reliability, 0.0, "and trade reliability");
    let after_overturn =
        reference::score_at_position(&db, &m, t + MONTH, u64::MAX, &station_pub).unwrap();
    assert!(
        after_overturn.attestation_accuracy > 0.9,
        "the overturn must lift the penalty, got {}",
        after_overturn.attestation_accuracy
    );

    // Equivalence across a matrix of instants (straddling the equivocation record
    // and its overturn) and prefix bounds (before/after the equivocation, the
    // whole log, the empty prefix, the tail).
    for at_time in [t - 1, t, t + MONTH - 1, t + MONTH, t + 2 * MONTH] {
        for max_seq in [0, seq_before_equiv, seq_after_equiv, tail, u64::MAX] {
            assert_equiv(&db, &station_pub, at_time, max_seq);
        }
    }
}
