//! Station-signer pinning conformance suite.
//!
//! Every governance record whose authority is "the station said so" — the proposal
//! window, the enactment record, and the three emergency attestations (admission
//! anchor, activation, refusal) — carries admission-clock instants that a replica
//! cannot re-derive, so it is trusted *because the station signed it* (ADR-0022 §2,
//! ADR-0027). These tests forge each such record under a **non-station** key and
//! prove replay skips it — a forged attestation can move no window, no electorate
//! pin, no TTL anchor, and no activation/refusal decision.
//!
//! A forgery is a raw self-consistent signed record on the log (what a hostile
//! gossip peer's `append_raw` would deliver): the envelope signature verifies, but
//! the signer is the attacker's key, not the community station key. The community is
//! a bootstrap-grace one (founders are the electorate, ADR-0015) so no reputation
//! seeding is needed.

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, StoredPayload};
use rrn_storage::migrations;

use rrn_governance::charter::{
    create_charter, store_charter, AmendmentRules, Charter, CharterParams, GovernanceStructure,
};
use rrn_governance::emergency::{
    self, DeclarationStatus, EmergencyActivated, EmergencyCosign, EmergencyDeclaration,
    EmergencyDeclarationAdmitted, EmergencyRefused, InertDisposition, EMERGENCY_DECLARATION_TTL,
};
use rrn_governance::proposal::{
    all_proposals, append_cosign, append_proposal, Proposal, ProposalCosign, ProposalKind,
};
use rrn_governance::statute::{enacted_statutes, record_implementation, ProposalImplemented};
use rrn_governance::tally::{effective_charter, tally, ProposalOutcome};
use rrn_governance::vote::{append_vote, Vote, VoteChoice};
use rrn_governance::window::{build_window, window_and_seq_of, ProposalWindow};

const DAY: i64 = 86_400;

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

/// The community's fixed station key (the writer's key, per the maintainer decision (a)).
fn station() -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes([0x11; 32]))
}

/// The attacker's key — a second `init`ed gossip peer whose forged station-kind
/// records the pin must reject. Deliberately *not* the station key.
fn attacker() -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes([0xee; 32]))
}

fn spk() -> PublicKey {
    station().public_key()
}

fn charter_body() -> Charter {
    Charter {
        version: 1,
        community_id: "commons".into(),
        founding_principles: vec![],
        rights_floor: vec![],
        governance_structure: GovernanceStructure::default(),
        amendment_rules: AmendmentRules::default(),
        created_at: 0,
        founders: vec![],
        previous_hash: None,
    }
}

/// Publishes a founder-signed genesis charter for `commons`; the founders are the
/// grace electorate.
fn publish_charter(db: &Database, founders: &[Keypair]) {
    let body = charter_body();
    let params = CharterParams {
        version: 1,
        community_id: body.community_id,
        founding_principles: body.founding_principles,
        rights_floor: body.rights_floor,
        governance_structure: body.governance_structure,
        amendment_rules: body.amendment_rules,
        founders: founders.iter().map(addr).collect(),
        created_at: 0,
        previous_hash: None,
    };
    let signed = create_charter(params, founders).unwrap();
    let mut log = AppendLog::new(db);
    store_charter(&mut log, &founders[0], signed, 0).unwrap();
}

/// A 3-founder bootstrap-grace community with its charter published.
fn three_founder_community() -> (Database, Vec<Keypair>) {
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    publish_charter(&db, &founders);
    (db, founders)
}

/// Files a statute authored by `author`, admitted at `at` (genuine station window).
fn propose_statute(db: &Database, author: &Keypair, at: i64) -> Proposal {
    let p = Proposal::new(
        addr(author),
        "Quiet hours".into(),
        "No power tools after 9pm.".into(),
        ProposalKind::Statute,
        at,
    )
    .unwrap();
    let id = p.proposal_id;
    let mut log = AppendLog::new(db);
    append_proposal(
        &mut log,
        SignedPayload::sign(p, author),
        db,
        &station(),
        &charter_body(),
        at,
    )
    .unwrap();
    rrn_governance::proposal::proposal_records(&AppendLog::new(db), &id, db, &spk())
        .unwrap()
        .proposal
        .unwrap()
}

fn declare(db: &Database, author: &Keypair, duration_secs: i64, at: i64) -> Hash {
    let decl = EmergencyDeclaration {
        community_id: "commons".into(),
        author: addr(author),
        reason: "storm".into(),
        scope: "flood".into(),
        duration_secs,
        stated_renewal_index: 0,
        previous_declaration_hash: None,
        created_at: at,
    };
    let hash = decl.hash();
    let mut log = AppendLog::new(db);
    emergency::append_declaration(
        &mut log,
        SignedPayload::sign(decl, author),
        db,
        &station(),
        at,
    )
    .unwrap();
    hash
}

fn em_cosign(db: &Database, signer: &Keypair, target: Hash, at: i64) {
    let c = EmergencyCosign {
        declaration_hash: target,
        signer: addr(signer),
    };
    let mut log = AppendLog::new(db);
    emergency::append_cosign(&mut log, SignedPayload::sign(c, signer), db, &station(), at).unwrap();
}

/// Raw-appends `record` signed by `signer` — the shape a gossip peer's `append_raw`
/// delivers. Used to inject forgeries the pin must reject.
fn raw_append<T: Clone + Into<dcbor::CBOR>>(db: &Database, record: T, signer: &Keypair, at: i64) {
    let mut log = AppendLog::new(db);
    log.append(SignedPayload::sign(record, signer), at).unwrap();
}

fn stored<T: Clone + Into<dcbor::CBOR>>(signed: SignedPayload<T>) -> StoredPayload {
    StoredPayload {
        bytes: to_canonical_bytes(signed.payload),
        signer: signed.signer,
        signature: signed.signature,
    }
}

/// A *markerless* crossing co-signature: it reaches the log by gossip `append_raw`,
/// bypassing the front door, so no genuine station activation/refusal marker is
/// written. The distinct-eligible crossing is nonetheless reached — which is what
/// lets a *forged* station activation/refusal validate structurally, so the signer
/// pin is the only thing that removes it (the non-vacuous construction).
fn markerless_cosign(db: &Database, signer: &Keypair, target: Hash, at: i64) {
    let c = EmergencyCosign {
        declaration_hash: target,
        signer: addr(signer),
    };
    AppendLog::new(db)
        .append_raw(stored(SignedPayload::sign(c, signer)), at)
        .unwrap();
}

/// Builds a count-capped chain of three 1-day activations; returns the instant at
/// which a fourth continuation would be cap-refused (renewal_count 3 > cap 2).
fn capped_chain(db: &Database, founders: &[Keypair]) -> i64 {
    let mut instant = 1_000_000;
    for _ in 0..3 {
        let h = declare(db, &founders[0], DAY, instant);
        em_cosign(db, &founders[1], h, instant); // genuine crossing → activates
        let e = emergency::active_emergency_at(db, instant + 1, u64::MAX, &spk())
            .unwrap()
            .unwrap();
        instant = e.scheduled_expiry + 1; // within the 14-day cooldown ⇒ a continuation
    }
    instant
}

// --- Invariant 1: window pin -------------------------------------------------

#[test]
fn a_forged_window_opens_no_window_and_the_genuine_one_still_wins() {
    let (db, founders) = three_founder_community();
    let at = 1_000_000;

    // A proposal on the log with only a *forged* (attacker-signed) window.
    let p = Proposal::new(
        addr(&founders[0]),
        "Quiet hours".into(),
        "No power tools.".into(),
        ProposalKind::Statute,
        at,
    )
    .unwrap();
    let pid = p.proposal_id;
    {
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(p.clone(), &founders[0]), at)
            .unwrap();
    }
    let forged = ProposalWindow {
        proposal_id: pid,
        admitted_at: at,
        voting_ends_at: at + 7 * DAY,
        implementation_at: at + 14 * DAY,
        charter_hash: charter_body().hash(),
    };
    raw_append(&db, forged, &attacker(), at);

    // The forged window is invisible to the station-pinned reader.
    let log = AppendLog::new(&db);
    assert!(
        window_and_seq_of(&log, &pid, &spk()).is_none(),
        "a non-station window attestation must not open a window"
    );
    // ...so the proposal is not among the authorized set, and the electorate cannot
    // pin on the forged attestation's seq.
    assert!(
        all_proposals(&log, &db, &spk()).unwrap().is_empty(),
        "a proposal with only a forged window is not authorized"
    );

    // The genuine station window (appended later) is the one that wins.
    let genuine = build_window(
        &station(),
        pid,
        &ProposalKind::Statute,
        &charter_body(),
        at,
        None,
    );
    let genuine_seq = {
        let mut log = AppendLog::new(&db);
        log.append(genuine, at).unwrap().seq
    };
    let (_, seq) = window_and_seq_of(&AppendLog::new(&db), &pid, &spk())
        .expect("the genuine station window is found");
    assert_eq!(
        seq, genuine_seq,
        "the first *validated* (station-signed) window wins, not the earlier forged one"
    );
    // Positive control: with the genuine window present the proposal *is* authorized —
    // so the earlier `all_proposals` emptiness was the forged window being skipped, not
    // an unrelated exclusion.
    assert_eq!(
        all_proposals(&AppendLog::new(&db), &db, &spk())
            .unwrap()
            .len(),
        1,
        "the proposal is authorized once its genuine station window lands"
    );
}

// --- Invariant 2: implemented pin --------------------------------------------

#[test]
fn a_forged_enactment_neither_marks_a_statute_nor_blocks_a_genuine_one() {
    let (db, founders) = three_founder_community();
    let at = 1_000_000;
    let statute = pass_a_statute(&db, &founders, at);

    // A forged enactment for the passed statute, signed by the attacker.
    let due = statute.implementation_at;
    raw_append(
        &db,
        ProposalImplemented {
            proposal_id: statute.proposal_id,
            implemented_at: due,
        },
        &attacker(),
        due,
    );

    // Consequence (a): it does not enter the in-force set.
    assert!(
        enacted_statutes(&db, due, &spk()).unwrap().is_empty(),
        "a non-station enactment record must not put a statute in force"
    );

    // Consequence (b): it does not block the genuine enactment (no false
    // AlreadyImplemented), because the forged record is invisible to the guard.
    let mut log = AppendLog::new(&db);
    let genuine = record_implementation(&mut log, &db, &station(), &statute, due);
    assert!(
        genuine.is_ok(),
        "the forged enactment must not trip the AlreadyImplemented guard: {genuine:?}"
    );
    assert_eq!(
        enacted_statutes(&db, due, &spk()).unwrap().len(),
        1,
        "the genuine enactment now stands, exactly once"
    );
}

#[test]
fn a_forged_amendment_enactment_does_not_fold_into_the_effective_charter() {
    let (db, founders) = three_founder_community();
    let at = 1_000_000;
    let amendment = pass_an_amendment(&db, &founders, at);

    // Forge the amendment's enactment record (attacker-signed).
    raw_append(
        &db,
        ProposalImplemented {
            proposal_id: amendment.proposal_id,
            implemented_at: amendment.implementation_at,
        },
        &attacker(),
        amendment.implementation_at,
    );

    // The effective charter must stay at genesis (version 1): the amendment folds in
    // only on a *station-signed* enactment, which the forgery is not.
    assert_eq!(
        effective_charter(&db, &spk()).unwrap().unwrap().version,
        1,
        "a forged amendment enactment must not advance the effective charter"
    );

    // Positive control — the negative assertion above is live: a *genuine*
    // station-signed enactment of the very same amendment does fold it to version 2.
    {
        let mut log = AppendLog::new(&db);
        record_implementation(
            &mut log,
            &db,
            &station(),
            &amendment,
            amendment.implementation_at,
        )
        .unwrap();
    }
    assert_eq!(
        effective_charter(&db, &spk()).unwrap().unwrap().version,
        2,
        "a station-signed enactment of the same amendment must fold — proving the pin, \
         not an unrelated fold failure, kept the forged one out"
    );
}

// --- Invariant 3: admission-anchor pin (D2), both TTL directions -------------

#[test]
fn a_forged_far_past_anchor_does_not_expire_a_declaration() {
    let (db, founders) = three_founder_community();
    let t0 = 1_000_000;

    // Pre-inject a forged anchor with admitted_at = 0 (far past): if believed, the
    // declaration's TTL would have elapsed long ago and it could never activate.
    let decl = EmergencyDeclaration {
        community_id: "commons".into(),
        author: addr(&founders[0]),
        reason: "storm".into(),
        scope: "flood".into(),
        duration_secs: 72 * 3600,
        stated_renewal_index: 0,
        previous_declaration_hash: None,
        created_at: t0,
    };
    let h = decl.hash();
    raw_append(
        &db,
        EmergencyDeclarationAdmitted {
            declaration_hash: h,
            admitted_at: 0,
        },
        &attacker(),
        t0,
    );

    // Genuine declaration + anchor land now (append_declaration writes the genuine
    // station anchor atomically).
    let h2 = declare(&db, &founders[0], 72 * 3600, t0);
    assert_eq!(h, h2);

    // The genuine anchor is the earliest *validated* one: the declaration is Pending
    // (not Expired) and, once co-signed, activates.
    assert_eq!(
        emergency::declaration_status(&db, &h, t0 + 1, &spk()).unwrap(),
        DeclarationStatus::Pending,
        "the forged far-past anchor must not make the declaration read Expired"
    );
    assert!(
        emergency::inert_declarations(&db, t0 + 1, &spk())
            .unwrap()
            .is_empty(),
        "the forged far-past anchor must not list the declaration as inert/expired"
    );
    em_cosign(&db, &founders[1], h, t0);
    assert!(
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &spk())
            .unwrap()
            .is_some(),
        "the declaration must still activate — the forged stale anchor was skipped"
    );
}

#[test]
fn a_forged_far_future_anchor_does_not_extend_the_ttl() {
    let (db, founders) = three_founder_community();
    let t0 = 1_000_000;

    let decl = EmergencyDeclaration {
        community_id: "commons".into(),
        author: addr(&founders[0]),
        reason: "storm".into(),
        scope: "flood".into(),
        duration_secs: 72 * 3600,
        stated_renewal_index: 0,
        previous_declaration_hash: None,
        created_at: t0,
    };
    let h = decl.hash();
    // A forged anchor far in the future: if believed, the TTL would never elapse.
    raw_append(
        &db,
        EmergencyDeclarationAdmitted {
            declaration_hash: h,
            admitted_at: t0 + 100 * DAY,
        },
        &attacker(),
        t0,
    );
    let h2 = declare(&db, &founders[0], 72 * 3600, t0);
    assert_eq!(h, h2);

    // Past the TTL of the *genuine* anchor (t0), the declaration is Expired — the
    // forged future anchor did not extend it.
    assert_eq!(
        emergency::declaration_status(&db, &h, t0 + EMERGENCY_DECLARATION_TTL + 1, &spk()).unwrap(),
        DeclarationStatus::Expired,
        "the forged far-future anchor must not extend the declaration TTL"
    );
}

// --- Invariant 4: activation / refusal pin -----------------------------------

#[test]
fn a_forged_activation_does_not_enter_the_timeline() {
    let (db, founders) = three_founder_community();
    let t0 = 1_000_000;
    // A declaration whose crossing is genuinely reached — but *markerless* (the 2nd
    // co-signature arrives by gossip, so the front door writes no station activation
    // marker). A markerless crossing is not activatable on the writer, so nothing is
    // active; but the crossing being reached is what makes a *forged* activation
    // structurally valid, so only the signer pin removes it (non-vacuous).
    let h = declare(&db, &founders[0], 72 * 3600, t0);
    markerless_cosign(&db, &founders[1], h, t0);
    assert!(
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &spk())
            .unwrap()
            .is_none(),
        "a markerless crossing is not activatable — no genuine activation exists"
    );

    // Forge an attacker-signed activation with a correctly-recomputed scheduled_expiry
    // (`activation_instant + clamp(72h)`; 72h is within [24h, 7d]). Without the pin
    // this validates — anchor present, crossing reached, expiry matches, caps admit —
    // and enters the timeline; the pin skips it.
    raw_append(
        &db,
        EmergencyActivated {
            declaration_hash: h,
            activation_instant: t0,
            scheduled_expiry: t0 + 72 * 3600,
            renewal_count: 0,
        },
        &attacker(),
        t0,
    );
    assert!(
        emergency::emergency_timeline(&db, &spk())
            .unwrap()
            .is_empty(),
        "a non-station activation attestation must not enter the timeline, \
         even over a genuine markerless crossing"
    );
}

#[test]
fn a_forged_refusal_does_not_kill_a_declaration() {
    let (db, founders) = three_founder_community();
    // A count-capped chain, then a fourth declaration whose crossing is markerless:
    // the §4 caps WOULD refuse this crossing, so a forged station refusal for it is
    // structurally valid (crossing reached, caps bind) — only the signer pin keeps
    // it from marking the declaration dead (non-vacuous; the crossing-never-reached
    // and station-signed cases are covered in emergency_activation_ttl.rs).
    let instant = capped_chain(&db, &founders);
    let dead = declare(&db, &founders[0], DAY, instant);
    markerless_cosign(&db, &founders[1], dead, instant);

    raw_append(
        &db,
        EmergencyRefused {
            declaration_hash: dead,
            refused_instant: instant,
        },
        &attacker(),
        instant,
    );

    // With the pin, the forged refusal is skipped: the declaration is not dead.
    assert_eq!(
        emergency::declaration_status(&db, &dead, instant + 1, &spk()).unwrap(),
        DeclarationStatus::Pending,
        "a non-station refusal must not mark a declaration dead"
    );
    assert!(
        !emergency::inert_declarations(&db, instant + 1, &spk())
            .unwrap()
            .iter()
            .any(|d| d.declaration_hash == dead && d.disposition == InertDisposition::Refused),
        "the declaration is not listed as refused"
    );
}

// --- Invariant 6: legible replica failure under a different key --------------

#[test]
fn deriving_under_a_different_key_yields_genesis_and_nothing_else() {
    let (db, founders) = three_founder_community();
    let t0 = 1_000_000;

    // Genuine governance activity, all station-signed by `station()`.
    let statute = pass_a_statute(&db, &founders, t0);
    let h = declare(&db, &founders[0], 72 * 3600, t0);
    em_cosign(&db, &founders[1], h, t0);
    {
        let mut log = AppendLog::new(&db);
        record_implementation(
            &mut log,
            &db,
            &station(),
            &statute,
            statute.implementation_at,
        )
        .unwrap();
    }

    // Under the writer's key, everything derives.
    assert!(!all_proposals(&AppendLog::new(&db), &db, &spk())
        .unwrap()
        .is_empty());
    assert!(!emergency::emergency_timeline(&db, &spk())
        .unwrap()
        .is_empty());
    assert!(!enacted_statutes(&db, statute.implementation_at, &spk())
        .unwrap()
        .is_empty());

    // Under a *different* key (the gossip-replica situation, decision (a)): the
    // failure is loud and diagnosable — the effective charter is still the genesis
    // charter (member-multisig root) and *nothing else* derives. Never a silent
    // partial.
    let wrong = attacker().public_key();
    let eff = effective_charter(&db, &wrong).unwrap().unwrap();
    assert_eq!(
        eff.version, 1,
        "genesis charter still resolves under any key"
    );
    assert!(
        all_proposals(&AppendLog::new(&db), &db, &wrong)
            .unwrap()
            .is_empty(),
        "no proposals derive under the wrong key"
    );
    assert!(
        emergency::emergency_timeline(&db, &wrong)
            .unwrap()
            .is_empty(),
        "no emergencies derive under the wrong key"
    );
    assert!(
        enacted_statutes(&db, statute.implementation_at, &wrong)
            .unwrap()
            .is_empty(),
        "no statutes derive under the wrong key"
    );
    assert!(
        tally(&db, &statute.proposal_id, statute.implementation_at, &wrong).is_err(),
        "a tally under the wrong key fails (proposal is unwindowed) — a loud failure"
    );
}

// --- Invariant 7: skip, don't halt -------------------------------------------

#[test]
fn a_forged_record_interleaved_with_genuine_ones_derives_to_completion() {
    let (db, founders) = three_founder_community();
    let t0 = 1_000_000;

    // Genuine statute, then a forged activation for a never-declared hash wedged in,
    // then a genuine emergency. Derivation must run past the forgery.
    let _statute = propose_statute(&db, &founders[0], t0);
    raw_append(
        &db,
        EmergencyActivated {
            declaration_hash: Hash::from_bytes([0xab; 32]),
            activation_instant: t0,
            scheduled_expiry: t0 + 72 * 3600,
            renewal_count: 0,
        },
        &attacker(),
        t0,
    );
    let h = declare(&db, &founders[0], 72 * 3600, t0 + 10);
    em_cosign(&db, &founders[1], h, t0 + 10);

    // The genuine emergency is derived; the forgery is simply absent.
    let timeline = emergency::emergency_timeline(&db, &spk()).unwrap();
    assert_eq!(
        timeline.len(),
        1,
        "replay completes; only the genuine activation stands"
    );
    assert_eq!(timeline[0].declaration_hash, h);
    assert!(!all_proposals(&AppendLog::new(&db), &db, &spk())
        .unwrap()
        .is_empty());
}

// --- Shared: pass a statute / an amendment through a real vote ----------------

/// Files a statute, co-signs it to publish, votes it through by all three founders,
/// and returns it (with its window fields populated). It is *passed* but not yet
/// enacted.
fn pass_a_statute(db: &Database, founders: &[Keypair], at: i64) -> Proposal {
    let p = propose_statute(db, &founders[0], at);
    let mut log = AppendLog::new(db);
    for c in &founders[1..3] {
        append_cosign(
            &mut log,
            SignedPayload::sign(
                ProposalCosign {
                    proposal_id: p.proposal_id,
                    cosigner: addr(c),
                    cosigned_at: at,
                },
                c,
            ),
            db,
            &spk(),
            at,
        )
        .unwrap();
    }
    for m in founders {
        append_vote(
            &mut log,
            SignedPayload::sign(
                Vote {
                    proposal_id: p.proposal_id,
                    voter: addr(m),
                    choice: VoteChoice::Yes,
                    cast_at: at,
                },
                m,
            ),
            db,
            &spk(),
            at,
        )
        .unwrap();
    }
    assert_eq!(
        tally(db, &p.proposal_id, p.voting_ends_at + 1, &spk())
            .unwrap()
            .outcome,
        Some(ProposalOutcome::Passed),
        "the statute should pass its vote"
    );
    p
}

/// Files a charter amendment (to version 2), passes it through a vote, and returns
/// it (passed, not enacted). The station window is genuine.
fn pass_an_amendment(db: &Database, founders: &[Keypair], at: i64) -> Proposal {
    // v2 must chain onto the *resolved* genesis root (`version + 1`, `previous_hash`
    // = the root's hash), or `effective_charter` rejects the fold before it ever
    // consults `is_implemented` — which would make the pin test vacuous.
    let base = effective_charter(db, &spk()).unwrap().unwrap();
    let mut v2 = base.clone();
    v2.version = base.version + 1;
    v2.previous_hash = Some(base.hash());
    let p = Proposal::new(
        addr(&founders[0]),
        "Amend the charter".into(),
        "Bump to v2.".into(),
        ProposalKind::CharterAmendment { new_charter: v2 },
        at,
    )
    .unwrap();
    let id = p.proposal_id;
    let mut log = AppendLog::new(db);
    append_proposal(
        &mut log,
        SignedPayload::sign(p, &founders[0]),
        db,
        &station(),
        &base,
        at,
    )
    .unwrap();
    let amendment =
        rrn_governance::proposal::proposal_records(&AppendLog::new(db), &id, db, &spk())
            .unwrap()
            .proposal
            .unwrap();
    for c in &founders[1..3] {
        append_cosign(
            &mut log,
            SignedPayload::sign(
                ProposalCosign {
                    proposal_id: id,
                    cosigner: addr(c),
                    cosigned_at: at,
                },
                c,
            ),
            db,
            &spk(),
            at,
        )
        .unwrap();
    }
    for m in founders {
        append_vote(
            &mut log,
            SignedPayload::sign(
                Vote {
                    proposal_id: id,
                    voter: addr(m),
                    choice: VoteChoice::Yes,
                    cast_at: at,
                },
                m,
            ),
            db,
            &spk(),
            at,
        )
        .unwrap();
    }
    assert_eq!(
        tally(db, &id, amendment.voting_ends_at + 1, &spk())
            .unwrap()
            .outcome,
        Some(ProposalOutcome::Passed),
        "the amendment should pass its vote"
    );
    amendment
}
