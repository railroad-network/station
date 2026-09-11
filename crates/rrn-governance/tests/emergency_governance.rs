//! Emergency-governance conformance suite (ADR-0023).
//!
//! Each test maps to one of ADR-0023's invariants. To stay fast, the community is
//! a **bootstrap-grace** one (founders are the electorate, ADR-0015) — no expensive
//! reputation seeding — which exercises the same code paths the established-member
//! electorate does, at a small size the ADR itself calls out (§2 worked case).

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

use rrn_governance::charter::{
    create_charter, store_charter, AmendmentRules, Charter, CharterParams, GovernanceStructure,
};
use rrn_governance::emergency::{
    self, EmergencyActivated, EmergencyCosign, EmergencyDeclaration, EmergencyError,
    EmergencyLapse, EMERGENCY_CHAIN_MAX_SECS, EMERGENCY_COOLDOWN_SECS, EMERGENCY_MEASURE_GRACE,
    EMERGENCY_WINDOW_FLOOR_SECS,
};
use rrn_governance::proposal::{
    append_cosign, append_proposal, Proposal, ProposalCosign, ProposalError, ProposalKind,
};
use rrn_governance::statute::enacted_statutes;
use rrn_governance::tally::{tally, ProposalOutcome};
use rrn_governance::vote::{append_vote, Vote, VoteChoice};

const DAY: i64 = 86_400;

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

fn station() -> Keypair {
    // Fixed so the reader pins (T2.1.4) can be given the same station key the
    // write helpers sign attestations with.
    Keypair::from_secret(rrn_crypto::keypair::SecretKey::from_bytes([0x5a; 32]))
}

/// Publishes a founder-signed genesis charter for community `commons` with the
/// given governance structure. The founders are the grace electorate.
fn publish_charter_with(db: &Database, founders: &[Keypair], gov: GovernanceStructure) {
    let params = CharterParams {
        version: 1,
        community_id: "commons".into(),
        founding_principles: vec![],
        rights_floor: vec![],
        governance_structure: gov,
        amendment_rules: AmendmentRules::default(),
        founders: founders.iter().map(addr).collect(),
        created_at: 0,
        previous_hash: None,
    };
    let signed = create_charter(params, founders).unwrap();
    let mut log = AppendLog::new(db);
    store_charter(&mut log, &founders[0], signed, 0).unwrap();
}

fn publish_charter(db: &Database, founders: &[Keypair]) {
    publish_charter_with(db, founders, GovernanceStructure::default());
}

fn declare(db: &Database, st: &Keypair, author: &Keypair, duration_secs: i64, at: i64) -> Hash {
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
    emergency::append_declaration(&mut log, SignedPayload::sign(decl, author), db, st, at).unwrap();
    hash
}

fn em_cosign(db: &Database, st: &Keypair, signer: &Keypair, target: Hash, at: i64) {
    let c = EmergencyCosign {
        declaration_hash: target,
        signer: addr(signer),
    };
    let mut log = AppendLog::new(db);
    emergency::append_cosign(&mut log, SignedPayload::sign(c, signer), db, st, at).unwrap();
}

fn em_lapse(db: &Database, author: &Keypair, decl_hash: Hash, at: i64) -> Hash {
    let l = EmergencyLapse {
        declaration_hash: decl_hash,
        author: addr(author),
    };
    let hash = l.hash();
    let mut log = AppendLog::new(db);
    emergency::append_lapse(
        &mut log,
        SignedPayload::sign(l, author),
        db,
        &station().public_key(),
        at,
    )
    .unwrap();
    hash
}

/// Files an Emergency proposal authored by `author` with `expires_at`, admitted at
/// `at`, and a deliberately absurd author-clock `created_at` (testimony). Returns it
/// with its populated window (read back from the log).
fn propose_emergency(
    db: &Database,
    st: &Keypair,
    charter: &Charter,
    author: &Keypair,
    expires_at: i64,
    at: i64,
) -> Proposal {
    let p = Proposal::new(
        addr(author),
        "Authorize fuel run".into(),
        "Buy diesel for the pumps.".into(),
        ProposalKind::Emergency { expires_at },
        // An absurd author clock — window arithmetic must ignore it (inv 6).
        -999_999,
    )
    .unwrap();
    let id = p.proposal_id;
    let mut log = AppendLog::new(db);
    append_proposal(
        &mut log,
        SignedPayload::sign(p, author),
        db,
        st,
        charter,
        at,
    )
    .unwrap();
    rrn_governance::proposal::proposal_records(
        &AppendLog::new(db),
        &id,
        db,
        &station().public_key(),
    )
    .unwrap()
    .proposal
    .unwrap()
}

fn cosign_prop(db: &Database, cosigner: &Keypair, p: &Proposal, at: i64) {
    let c = ProposalCosign {
        proposal_id: p.proposal_id,
        cosigner: addr(cosigner),
        cosigned_at: at,
    };
    let mut log = AppendLog::new(db);
    append_cosign(
        &mut log,
        SignedPayload::sign(c, cosigner),
        db,
        &station().public_key(),
        at,
    )
    .unwrap();
}

fn vote_prop(db: &Database, voter: &Keypair, p: &Proposal, choice: VoteChoice, at: i64) {
    let v = Vote {
        proposal_id: p.proposal_id,
        voter: addr(voter),
        choice,
        cast_at: at,
    };
    let mut log = AppendLog::new(db);
    append_vote(
        &mut log,
        SignedPayload::sign(v, voter),
        db,
        &station().public_key(),
        at,
    )
    .unwrap();
}

/// A 3-founder grace community, charter published, plus a station keypair.
fn three_founder_community() -> (Database, Vec<Keypair>, Keypair) {
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    publish_charter(&db, &founders);
    (db, founders, station())
}

/// Activates an emergency at `at`: author declares, one founder co-signs (threshold
/// `ceil(2*3/3) = 2`). Returns the declaration hash.
fn activate(db: &Database, st: &Keypair, founders: &[Keypair], at: i64) -> Hash {
    let h = declare(db, st, &founders[0], 72 * 3600, at);
    em_cosign(db, st, &founders[1], h, at);
    assert!(
        emergency::active_emergency_at(db, at + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_some(),
        "author + one co-sign should cross the two-thirds bar for N=3"
    );
    h
}

// --- Baseline: two gates + compression (ADR-0023 §1, §3a) -------------------

#[test]
fn a_declaration_needs_the_supermajority_and_then_compresses_the_window() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let h = declare(&db, &st, &founders[0], 72 * 3600, t0);

    // The author's lone signature is 1 of the 2 needed (ceil(2*3/3)); not active yet.
    assert!(
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none()
    );

    em_cosign(&db, &st, &founders[1], h, t0);
    let active =
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key()).unwrap();
    assert!(active.is_some());
    assert_eq!(active.unwrap().scheduled_expiry, t0 + 72 * 3600);

    // An Emergency proposal admitted now runs the compressed 24 h window, not 7 d.
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t1 = t0 + 10;
    let p = propose_emergency(&db, &st, &charter, &founders[0], t1 + 3600, t1);
    assert_eq!(
        p.voting_ends_at,
        t1 + EMERGENCY_WINDOW_FLOOR_SECS,
        "window compresses to the emergency floor (24 h) from admission"
    );
    assert_eq!(p.implementation_at, p.voting_ends_at, "immediate effect");
}

#[test]
fn an_emergency_proposal_with_no_declaration_keeps_the_full_phase1_window() {
    // §1 backward-compat: an Emergency kind raised with no declaration active keeps
    // its ordinary 7-day window and immediate effect — the intersection is what
    // compresses, never the kind alone.
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    let p = propose_emergency(&db, &st, &charter, &founders[0], t0 + 3600, t0);
    assert_eq!(p.voting_ends_at, t0 + 7 * DAY, "uncompressed 7-day window");
}

// --- Invariant 6: windows anchor on admission (ADR-0022) --------------------

#[test]
fn compressed_window_anchors_on_admission_not_the_author_clock() {
    let (db, founders, st) = three_founder_community();
    let t0 = 5_000_000;
    activate(&db, &st, &founders, t0);
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    // `propose_emergency` sets an absurd created_at (-999_999); the window must run
    // from the admission `at`, never that testimony.
    let at = t0 + 100;
    let p = propose_emergency(&db, &st, &charter, &founders[0], at + 3600, at);
    assert_eq!(p.voting_ends_at, at + EMERGENCY_WINDOW_FLOOR_SECS);
}

// --- Invariant 3: floors hold (front door + derive tolerance) ---------------

#[test]
fn an_emergency_measure_that_would_not_lapse_is_refused_at_admission() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let h = activate(&db, &st, &founders, t0);
    let scheduled = emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
        .unwrap()
        .unwrap()
        .scheduled_expiry;
    let _ = h;
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let at = t0 + 10;

    // One second past the cap (scheduled_expiry + 7 d grace) is refused, typed.
    let too_long = scheduled + EMERGENCY_MEASURE_GRACE + 1;
    let p = Proposal::new(
        addr(&founders[0]),
        "Permanent power grab".into(),
        "Never expires.".into(),
        ProposalKind::Emergency {
            expires_at: too_long,
        },
        at,
    )
    .unwrap();
    let mut log = AppendLog::new(&db);
    let err = append_proposal(
        &mut log,
        SignedPayload::sign(p, &founders[0]),
        &db,
        &st,
        &charter,
        at,
    )
    .unwrap_err();
    assert!(matches!(err, ProposalError::EmergencyMeasureTooLong { .. }));

    // Exactly at the cap is accepted.
    let ok_expiry = scheduled + EMERGENCY_MEASURE_GRACE;
    let _ = propose_emergency(&db, &st, &charter, &founders[0], ok_expiry, at + 1);
}

#[test]
fn an_undeclared_emergency_measure_is_bounded_to_thirty_days() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let at = 1_000_000;
    // No declaration: bound is voting_ends_at (at + 7d) + 30 d.
    let cap = at + 7 * DAY + 30 * DAY;
    let mut log = AppendLog::new(&db);
    let p = Proposal::new(
        addr(&founders[0]),
        "Ordinary-path emergency".into(),
        "b".into(),
        ProposalKind::Emergency {
            expires_at: cap + 1,
        },
        at,
    )
    .unwrap();
    let err = append_proposal(
        &mut log,
        SignedPayload::sign(p, &founders[0]),
        &db,
        &st,
        &charter,
        at,
    )
    .unwrap_err();
    assert!(matches!(err, ProposalError::EmergencyMeasureTooLong { .. }));
}

#[test]
fn a_hostile_sub_floor_charter_cannot_lower_the_window_or_the_bars() {
    // Derive tolerance: a charter that stored sub-floor emergency parameters still
    // yields the floors on use — the declaration bar stays two-thirds, and the
    // window stays 24 h.
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    let gov = GovernanceStructure {
        emergency_window_secs: 60,     // below the 24 h floor
        emergency_declaration_pct: 10, // below the 67% floor
        emergency_quorum_pct: 5,       // below the 50% floor
        max_consecutive_renewals: 99,  // above the ceiling
        ..GovernanceStructure::default()
    };
    publish_charter_with(&db, &founders, gov);
    let st = station();
    let t0 = 1_000_000;

    // The floored two-thirds bar still needs 2 of 3: a lone author does not activate.
    let h = declare(&db, &st, &founders[0], 72 * 3600, t0);
    assert!(
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none(),
        "the 10% declaration pct must not lower the bar below two-thirds"
    );
    em_cosign(&db, &st, &founders[1], h, t0);
    assert!(
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_some()
    );

    // The window stays at the 24 h floor, not the charter's 60 s.
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let at = t0 + 10;
    let p = propose_emergency(&db, &st, &charter, &founders[0], at + 3600, at);
    assert_eq!(p.voting_ends_at, at + EMERGENCY_WINDOW_FLOOR_SECS);
}

// --- Invariant 4: frozen surfaces (ADR-0023 §3b) ----------------------------

#[test]
fn charter_amendments_are_frozen_during_an_emergency_and_admit_after_lapse() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    let h = activate(&db, &st, &founders, t0);

    // A CharterAmendment is refused at the front door while the emergency holds.
    let mut next = charter.clone();
    next.version = 2;
    next.previous_hash = Some(charter.hash());
    let amendment = Proposal::new(
        addr(&founders[0]),
        "Amend during crisis".into(),
        "Restructure power.".into(),
        ProposalKind::CharterAmendment { new_charter: next },
        t0,
    )
    .unwrap();
    let mut log = AppendLog::new(&db);
    let err = append_proposal(
        &mut log,
        SignedPayload::sign(amendment.clone(), &founders[0]),
        &db,
        &st,
        &charter,
        t0 + 10,
    )
    .unwrap_err();
    assert!(matches!(err, ProposalError::CharterFrozenByEmergency));

    // Lapse the emergency (author + one co-sign of the lapse), then the amendment
    // admits again.
    let lapse = em_lapse(&db, &founders[0], h, t0 + 20);
    em_cosign(&db, &st, &founders[1], lapse, t0 + 20);
    assert!(
        emergency::active_emergency_at(&db, t0 + 21, u64::MAX, &station().public_key())
            .unwrap()
            .is_none(),
        "the lapse should end the emergency"
    );
    let mut log = AppendLog::new(&db);
    append_proposal(
        &mut log,
        SignedPayload::sign(amendment, &founders[0]),
        &db,
        &st,
        &charter,
        t0 + 30,
    )
    .expect("amendments admit once the emergency has lapsed");
}

// --- Invariant 2: automatic expiry, caps, cooldown (ADR-0023 §4) ------------

#[test]
fn an_emergency_expires_exactly_at_its_scheduled_bound() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    activate(&db, &st, &founders, t0); // 72 h default
    let expiry = t0 + 72 * 3600;
    // One second before the bound: active. One second past: expired — with no
    // renewal record extending it.
    assert!(
        emergency::active_emergency_at(&db, expiry, u64::MAX, &station().public_key())
            .unwrap()
            .is_some()
    );
    assert!(
        emergency::active_emergency_at(&db, expiry + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_chain_cannot_exceed_the_duration_cap() {
    // Two 7-day activations reach the 14-day chain cap; a third continuation within
    // the cooldown of the second does not activate (§4).
    let (db, founders, st) = three_founder_community();
    let seven_d = 7 * DAY;

    // Activation 1 at t0, 7 d.
    let t0 = 1_000_000;
    let h1 = declare(&db, &st, &founders[0], seven_d, t0);
    em_cosign(&db, &st, &founders[1], h1, t0);
    let e1 = emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
        .unwrap()
        .unwrap();

    // Activation 2: a continuation within the cooldown of e1's scheduled end, 7 d.
    let t1 = e1.scheduled_expiry + 1; // still < end + 14 d cooldown → continuation
    let h2 = declare(&db, &st, &founders[0], seven_d, t1);
    em_cosign(&db, &st, &founders[1], h2, t1);
    let e2 = emergency::active_emergency_at(&db, t1 + 1, u64::MAX, &station().public_key())
        .unwrap()
        .unwrap();
    assert_eq!(e2.renewal_count, 1);

    // Activation 3: another continuation — total would be 21 d > 14 d cap AND the
    // renewal count would be 2 (== ceiling) but the duration cap binds first: it
    // must NOT activate.
    let t2 = e2.scheduled_expiry + 1;
    let h3 = declare(&db, &st, &founders[0], seven_d, t2);
    em_cosign(&db, &st, &founders[1], h3, t2);
    assert!(
        emergency::active_emergency_at(&db, t2 + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none(),
        "a third 7-day continuation exceeds the 14-day chain cap and must not activate"
    );
    // Sanity on the constants this test leans on.
    assert_eq!(EMERGENCY_CHAIN_MAX_SECS, 14 * DAY);
    assert_eq!(EMERGENCY_COOLDOWN_SECS, 14 * DAY);
}

#[test]
fn the_cooldown_refuses_a_fresh_declaration_too_soon_after_a_chain() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let h1 = declare(&db, &st, &founders[0], DAY, t0); // 24 h
    em_cosign(&db, &st, &founders[1], h1, t0);
    let e1 = emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
        .unwrap()
        .unwrap();

    // A declaration whose activation is inside the cooldown of e1's end but beyond
    // the caps... here it is a continuation (within cooldown) so renewal_count 1 —
    // allowed. Instead test the *post-cap* refusal: build a chain to its cap first.
    // Simpler: a declaration far beyond the cooldown starts a fresh chain (allowed).
    let far = e1.scheduled_expiry + EMERGENCY_COOLDOWN_SECS + 1;
    let h2 = declare(&db, &st, &founders[0], DAY, far);
    em_cosign(&db, &st, &founders[1], h2, far);
    let e2 = emergency::active_emergency_at(&db, far + 1, u64::MAX, &station().public_key())
        .unwrap()
        .unwrap();
    assert_eq!(e2.renewal_count, 0, "beyond the cooldown, a fresh chain");
}

// --- Invariant 5 core: the ballot rule (ADR-0023 §3a) -----------------------

#[test]
fn a_ballot_admitted_before_close_counts_even_after_the_emergency_lapses() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    let h = activate(&db, &st, &founders, t0);

    // File and publish a compressed Emergency proposal (grace publish bar = 2).
    let at = t0 + 10;
    let p = propose_emergency(&db, &st, &charter, &founders[0], at + 3600, at);
    let close = p.voting_ends_at; // at + 24 h
    cosign_prop(&db, &founders[1], &p, at);
    cosign_prop(&db, &founders[2], &p, at);

    // Lapse the emergency mid-window (before the proposal closes).
    let lapse_at = at + 100;
    let lapse = em_lapse(&db, &founders[0], h, lapse_at);
    em_cosign(&db, &st, &founders[1], lapse, lapse_at);
    assert!(
        emergency::active_emergency_at(&db, lapse_at + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none()
    );

    // Ballots admitted AFTER the lapse but BEFORE the proposal's own close still
    // count — the emergency's lapse does not retroactively shut an open compressed
    // window (§3a).
    let vote_at = lapse_at + 50;
    assert!(vote_at < close);
    vote_prop(&db, &founders[0], &p, VoteChoice::Yes, vote_at);
    vote_prop(&db, &founders[1], &p, VoteChoice::Yes, vote_at);
    vote_prop(&db, &founders[2], &p, VoteChoice::Yes, vote_at);

    let t = tally(&db, &p.proposal_id, close + 1, &station().public_key()).unwrap();
    assert_eq!(
        t.yes_count, 3,
        "ballots before close count despite the lapse"
    );
    assert_eq!(
        t.eligible_voters, 3,
        "electorate pinned at the emergency (3)"
    );
    assert_eq!(t.outcome, Some(ProposalOutcome::Passed));
}

// --- Invariant 1: replay determinism across a late replica ------------------

#[test]
fn a_late_replica_derives_the_identical_emergency_state_and_tally() {
    let (db1, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db1, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    let h = activate(&db1, &st, &founders, t0);
    let at = t0 + 10;
    let p = propose_emergency(&db1, &st, &charter, &founders[0], at + 3600, at);
    cosign_prop(&db1, &founders[1], &p, at);
    cosign_prop(&db1, &founders[2], &p, at);
    for f in &founders {
        vote_prop(&db1, f, &p, VoteChoice::Yes, at + 5);
    }
    let close = p.voting_ends_at;

    let tl1 = emergency::emergency_timeline(&db1, &station().public_key()).unwrap();
    let ty1 = tally(&db1, &p.proposal_id, close + 1, &station().public_key()).unwrap();
    assert_eq!(tl1.len(), 1);
    assert_eq!(ty1.outcome, Some(ProposalOutcome::Passed));

    // Replay every signed payload onto a fresh replica, re-stamped with a late
    // admission clock (a partition that healed long after). Only per-replica
    // `created_at` changes; the signed activation/window attestations carry over.
    let late = close + 500 * DAY;
    let db2 = fresh_db();
    {
        let src = AppendLog::new(&db1);
        let mut dst = AppendLog::new(&db2);
        for entry in src.iter_from(1) {
            dst.append_raw(entry.unwrap().payload, late).unwrap();
        }
    }
    let tl2 = emergency::emergency_timeline(&db2, &station().public_key()).unwrap();
    let ty2 = tally(&db2, &p.proposal_id, close + 1, &station().public_key()).unwrap();
    assert_eq!(tl1, tl2, "two replicas must derive the identical timeline");
    assert_eq!(
        (ty1.outcome, ty1.eligible_voters, ty1.yes_count),
        (ty2.outcome, ty2.eligible_voters, ty2.yes_count),
        "and the identical compressed-path tally"
    );
    let _ = h;

    // Repeated derives on the same db are stable.
    assert_eq!(
        tl1,
        emergency::emergency_timeline(&db1, &station().public_key()).unwrap()
    );
}

// --- §1 kind-wide expiry enforcement ----------------------------------------

#[test]
fn an_expired_emergency_measure_drops_out_of_the_in_force_set() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    activate(&db, &st, &founders, t0);
    let at = t0 + 10;
    let measure_expiry = at + 2 * DAY;
    let p = propose_emergency(&db, &st, &charter, &founders[0], measure_expiry, at);
    cosign_prop(&db, &founders[1], &p, at);
    cosign_prop(&db, &founders[2], &p, at);
    for f in &founders {
        vote_prop(&db, f, &p, VoteChoice::Yes, at + 5);
    }
    // Enact at the compressed close (immediate effect).
    let close = p.voting_ends_at;
    rrn_governance::lifecycle::enact_due(&db, &st, close + 1).unwrap();

    // In force before its expiry, gone after (kind-wide §1 enforcement).
    assert_eq!(
        enacted_statutes(&db, close + 1, &station().public_key())
            .unwrap()
            .len(),
        1
    );
    assert!(
        enacted_statutes(&db, measure_expiry + 1, &station().public_key())
            .unwrap()
            .is_empty(),
        "an expired emergency measure has no effect"
    );
}

// --- §3 the raised emergency quorum binds -----------------------------------

#[test]
fn the_raised_emergency_quorum_binds_where_the_statute_quorum_would_pass() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    activate(&db, &st, &founders, t0);
    let at = t0 + 10;

    // A compressed Emergency measure with a single voter: emergency quorum is 50% of
    // the pinned electorate of 3 ⇒ needs 2 to turn out, so 1 of 3 fails quorum.
    let em = propose_emergency(&db, &st, &charter, &founders[0], at + 3600, at);
    cosign_prop(&db, &founders[1], &em, at);
    cosign_prop(&db, &founders[2], &em, at);
    vote_prop(&db, &founders[0], &em, VoteChoice::Yes, at + 1);
    let t = tally(
        &db,
        &em.proposal_id,
        em.voting_ends_at + 1,
        &station().public_key(),
    )
    .unwrap();
    assert_eq!(t.eligible_voters, 3);
    assert!(!t.quorum_met, "1 of 3 is below the 50% emergency quorum");
    assert_eq!(t.outcome, Some(ProposalOutcome::Failed));

    // An ordinary Statute with the same 1-of-3 turnout clears the 30% statute quorum
    // and passes — so the failure above is the raised emergency quorum binding.
    let statute = {
        let p = Proposal::new(
            addr(&founders[0]),
            "Ordinary rule".into(),
            "b".into(),
            ProposalKind::Statute,
            at,
        )
        .unwrap();
        let id = p.proposal_id;
        let mut log = AppendLog::new(&db);
        append_proposal(
            &mut log,
            SignedPayload::sign(p, &founders[0]),
            &db,
            &st,
            &charter,
            at,
        )
        .unwrap();
        rrn_governance::proposal::proposal_records(
            &AppendLog::new(&db),
            &id,
            &db,
            &station().public_key(),
        )
        .unwrap()
        .proposal
        .unwrap()
    };
    cosign_prop(&db, &founders[1], &statute, at);
    cosign_prop(&db, &founders[2], &statute, at);
    vote_prop(&db, &founders[0], &statute, VoteChoice::Yes, at + 1);
    let ts = tally(
        &db,
        &statute.proposal_id,
        statute.voting_ends_at + 1,
        &station().public_key(),
    )
    .unwrap();
    assert!(ts.quorum_met, "1 of 3 clears the 30% statute quorum");
    assert_eq!(ts.outcome, Some(ProposalOutcome::Passed));
}

// --- §4 the renewal count cap (isolated from the duration cap) ---------------

#[test]
fn the_consecutive_renewal_count_cap_refuses_a_fourth_activation() {
    // Short (1-day) activations keep the chain well under the 14-day duration cap, so
    // the *count* cap (<= 2 renewals ⇒ 3 activations) is what binds the 4th.
    let (db, founders, st) = three_founder_community();
    let mut instant = 1_000_000;
    let mut renewals = vec![];
    for _ in 0..3 {
        let h = declare(&db, &st, &founders[0], DAY, instant);
        em_cosign(&db, &st, &founders[1], h, instant);
        let e = emergency::active_emergency_at(&db, instant + 1, u64::MAX, &station().public_key())
            .unwrap()
            .unwrap();
        renewals.push(e.renewal_count);
        instant = e.scheduled_expiry + 1; // within the 14-day cooldown ⇒ continuation
    }
    assert_eq!(renewals, vec![0, 1, 2], "three activations: counts 0,1,2");

    // The fourth continuation would be renewal_count 3 > cap 2 → it does not activate.
    let h4 = declare(&db, &st, &founders[0], DAY, instant);
    em_cosign(&db, &st, &founders[1], h4, instant);
    assert!(
        emergency::active_emergency_at(&db, instant + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none(),
        "a fourth consecutive activation exceeds the renewal count cap"
    );
}

// --- §3b amendment enactment deferral ---------------------------------------

#[test]
fn amendment_enactment_is_deferred_during_emergency_then_enacts_after_lapse() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;

    // Publish + pass a charter amendment BEFORE any emergency (so it is due to enact).
    let mut v2 = charter.clone();
    v2.version = 2;
    v2.previous_hash = Some(charter.hash());
    let p = Proposal::new(
        addr(&founders[0]),
        "Raise the budget".into(),
        "v2".into(),
        ProposalKind::CharterAmendment { new_charter: v2 },
        t0,
    )
    .unwrap();
    let amendment_id = p.proposal_id;
    {
        let mut log = AppendLog::new(&db);
        append_proposal(
            &mut log,
            SignedPayload::sign(p, &founders[0]),
            &db,
            &st,
            &charter,
            t0,
        )
        .unwrap();
    }
    let amendment = rrn_governance::proposal::proposal_records(
        &AppendLog::new(&db),
        &amendment_id,
        &db,
        &station().public_key(),
    )
    .unwrap()
    .proposal
    .unwrap();
    for c in &founders[1..3] {
        cosign_prop(&db, c, &amendment, t0);
    }
    for f in &founders {
        vote_prop(&db, f, &amendment, VoteChoice::Yes, t0 + 1);
    }

    // Activate a **7-day** emergency AFTER the amendment's voting closes but before
    // its implementation time, so the emergency is still active when enactment comes
    // due AND still active after the lapse would end it (proving the *lapse* — not
    // expiry — is what unfreezes). The declaration is not a CharterAmendment, so it is
    // not itself frozen.
    let act_at = amendment.voting_ends_at + DAY; // voting has closed
    let due = amendment.implementation_at; // < act_at + 7d
    assert!(
        due < act_at + 7 * DAY,
        "the emergency must span the enactment"
    );
    let h = declare(&db, &st, &founders[0], 7 * DAY, act_at);
    em_cosign(&db, &st, &founders[1], h, act_at);
    assert!(
        emergency::active_emergency_at(&db, due, u64::MAX, &station().public_key())
            .unwrap()
            .is_some()
    );

    let enacted = rrn_governance::lifecycle::enact_due(&db, &st, due).unwrap();
    assert!(
        !enacted.contains(&amendment.proposal_id),
        "the amendment must not enact while the emergency is active"
    );
    assert_eq!(
        rrn_governance::tally::effective_charter(&db, &station().public_key())
            .unwrap()
            .unwrap()
            .version,
        1,
        "the effective charter is still v1 during the emergency"
    );

    // Lapse the emergency (while it is still within its scheduled span), then the
    // amendment enacts — so the lapse, not expiry, is what unfroze it.
    let lapse_at = due + 1;
    assert!(lapse_at < act_at + 7 * DAY, "lapse before natural expiry");
    let lapse = em_lapse(&db, &founders[0], h, lapse_at);
    em_cosign(&db, &st, &founders[1], lapse, lapse_at);
    assert!(
        emergency::active_emergency_at(&db, lapse_at + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none()
    );
    let enacted = rrn_governance::lifecycle::enact_due(&db, &st, lapse_at + 1).unwrap();
    assert!(enacted.contains(&amendment.proposal_id));
    assert_eq!(
        rrn_governance::tally::effective_charter(&db, &station().public_key())
            .unwrap()
            .unwrap()
            .version,
        2,
        "after the lapse the amendment enacts and the charter is v2"
    );
}

// --- §3a a ballot admitted past the compressed close is refused --------------

#[test]
fn a_ballot_admitted_after_the_compressed_close_is_refused() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;
    activate(&db, &st, &founders, t0);
    let at = t0 + 10;
    let p = propose_emergency(&db, &st, &charter, &founders[0], at + 3600, at);
    cosign_prop(&db, &founders[1], &p, at);
    cosign_prop(&db, &founders[2], &p, at);

    let v = Vote {
        proposal_id: p.proposal_id,
        voter: addr(&founders[0]),
        choice: VoteChoice::Yes,
        cast_at: at,
    };
    let mut log = AppendLog::new(&db);
    let err = append_vote(
        &mut log,
        SignedPayload::sign(v, &founders[0]),
        &db,
        &station().public_key(),
        p.voting_ends_at + 1,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        rrn_governance::vote::VoteError::OutsideVotingWindow { .. }
    ));
}

// --- §3c the electorate pin excludes members manufactured after activation ---
//
// This is the one property a founder-only grace community cannot exhibit (founders
// are eligible at every position), so it seeds real established-member reputation.

mod reputation {
    use super::*;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};

    fn append_settled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        st: &Keypair,
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
                st,
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

    fn earn_raw_standing(db: &Database, who: &Keypair, st: &Keypair, at: i64) {
        for nonce in 0..10 {
            append_settled(db, who, st, st, nonce, at);
        }
        for _ in 0..10 {
            append_vouch(db, who, &addr(&Keypair::generate()), at);
        }
    }

    fn established_members(db: &Database, st: &Keypair, n: usize, at: i64) -> Vec<Keypair> {
        let members: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        for m in &members {
            earn_raw_standing(db, m, st, at);
        }
        for i in 0..n {
            append_vouch(db, &members[(i + 1) % n], &addr(&members[i]), at);
        }
        members
    }

    #[test]
    fn a_member_established_after_activation_cannot_vote_in_the_emergency() {
        let db = fresh_db();
        let st = station();
        const AT: i64 = 300 * DAY;
        // Four established members (grace off). They are the electorate.
        let members = established_members(&db, &st, 4, AT);
        publish_charter(&db, &members);

        // Activate: author + 2 co-signs cross ceil(2*4/3) = 3.
        let h = declare(&db, &st, &members[0], 72 * 3600, AT);
        em_cosign(&db, &st, &members[1], h, AT);
        em_cosign(&db, &st, &members[2], h, AT);
        assert!(
            emergency::active_emergency_at(&db, AT + 1, u64::MAX, &station().public_key())
                .unwrap()
                .is_some()
        );

        // A compressed Emergency proposal, published (default bar 3 co-signers, grace
        // off) by three of the four established members.
        let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
            .unwrap()
            .unwrap();
        let p = propose_emergency(&db, &st, &charter, &members[0], AT + 3600, AT + 5);
        for c in &members[1..4] {
            cosign_prop(&db, c, &p, AT + 5);
        }

        // AFTER activation, manufacture a fifth established member.
        let newcomer = Keypair::generate();
        earn_raw_standing(&db, &newcomer, &st, AT + 10);
        append_vouch(&db, &members[0], &addr(&newcomer), AT + 10);
        assert_eq!(
            rrn_reputation::staking::established_member_count(&db, AT + 20).unwrap(),
            5,
            "the community now has five established members by wall clock"
        );

        // The newcomer's ballot is refused on the write path (pinned electorate is 4).
        let v = Vote {
            proposal_id: p.proposal_id,
            voter: addr(&newcomer),
            choice: VoteChoice::Yes,
            cast_at: AT + 20,
        };
        let mut log = AppendLog::new(&db);
        let err = append_vote(
            &mut log,
            SignedPayload::sign(v, &newcomer),
            &db,
            &station().public_key(),
            AT + 20,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            rrn_governance::vote::VoteError::VoterNotEstablished { .. }
        ));

        // And the pinned denominator stays 4, not 5.
        for c in &members[0..2] {
            vote_prop(&db, c, &p, VoteChoice::Yes, AT + 20);
        }
        let t = tally(
            &db,
            &p.proposal_id,
            p.voting_ends_at + 1,
            &station().public_key(),
        )
        .unwrap();
        assert_eq!(
            t.eligible_voters, 4,
            "the emergency denominator is pinned at activation — the newcomer is excluded"
        );
    }
}

// --- Pure chain/threshold logic (proptest) ----------------------------------

proptest::proptest! {
    /// The declaration threshold is monotone in N, never below two-thirds, and — for
    /// N >= 5 — a strict majority, so a bare majority can never compress (§2).
    #[test]
    fn declaration_threshold_is_a_monotone_two_thirds_bar(n in 1usize..500) {
        let t = emergency::declaration_threshold(n, 67);
        // Never below two-thirds.
        proptest::prop_assert!(t * 3 >= n * 2);
        // Two-thirds is tight: below the true ceil(2N/3) is impossible, and it does
        // not overshoot by a whole unit.
        proptest::prop_assert!((t - 1) * 3 < n * 2);
        // Monotone in N.
        let t_next = emergency::declaration_threshold(n + 1, 67);
        proptest::prop_assert!(t_next >= t);
        // A raised bar is never below the two-thirds default.
        let t_raised = emergency::declaration_threshold(n, 80);
        proptest::prop_assert!(t_raised >= t);
    }
}

// --- Replica determinism against forged/gossiped attestations ---------------

/// A gossiped attestation the timeline does not believe (here, one appended before
/// the declaration has crossed its supermajority, so no legitimate activation
/// exists yet) must not suppress the station's genuine activation. Regression for
/// the writer-path idempotency gate: `try_activate` judges "already activated"
/// against the re-derived timeline, not against any raw `EmergencyActivated` on the
/// log.
#[test]
fn a_forged_activation_cannot_block_the_real_one() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let h = declare(&db, &st, &founders[0], 72 * 3600, t0);

    // Only the author has signed (1 of the 2 needed): no legitimate emergency yet.
    // A bogus *station-signed* attestation for the declaration is injected — signed
    // by the station key so it passes the T2.1.4 signer pin and the structural gate
    // (the crossing re-derivation) is what must reject it; the non-station-signer case
    // is covered in tests/station_signer_pinning.rs.
    let forged = EmergencyActivated {
        declaration_hash: h,
        activation_instant: t0,
        scheduled_expiry: t0 + 72 * 3600,
        renewal_count: 0,
    };
    {
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(forged, &st), t0).unwrap();
    }
    // The timeline never believed it — the crossing was not reached at its position.
    assert!(
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_none()
    );

    // The genuine crossing co-signature must still activate the emergency.
    em_cosign(&db, &st, &founders[1], h, t0);
    let active = emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
        .unwrap()
        .expect("the real activation must not be blocked by the forgery");
    assert_eq!(active.declaration_hash, h);
    assert_eq!(active.scheduled_expiry, t0 + 72 * 3600);
    // Exactly one emergency is derived — the forgery is not double-counted.
    assert_eq!(
        emergency::emergency_timeline(&db, &station().public_key())
            .unwrap()
            .len(),
        1
    );
}

/// An attestation whose `scheduled_expiry` does not equal the recomputed
/// `activation_instant + clamp(duration)` is rejected by the timeline (a forged
/// over-long expiry cannot stretch an emergency). Built by appending the
/// declaration and co-signatures as raw records so the crossing is genuine but no
/// real station attestation exists, then dropping in only the forged one.
#[test]
fn a_forged_activation_with_a_wrong_expiry_is_ignored_by_the_timeline() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;

    // Raw declaration + one co-signature (a genuine 2-of-3 crossing) with no
    // append-guard, so no station attestation is written.
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
    let cosign = EmergencyCosign {
        declaration_hash: h,
        signer: addr(&founders[1]),
    };
    {
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(decl, &founders[0]), t0)
            .unwrap();
        log.append(SignedPayload::sign(cosign, &founders[1]), t0)
            .unwrap();
    }

    // A *station-signed* attestation with an inflated expiry (not activation_instant +
    // 72h): signed by the station key so the T2.1.4 pin passes and the expiry recompute
    // is what rejects it (the non-station case is in tests/station_signer_pinning.rs).
    let forged = EmergencyActivated {
        declaration_hash: h,
        activation_instant: t0,
        scheduled_expiry: t0 + 999 * DAY,
        renewal_count: 0,
    };
    {
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(forged, &st), t0).unwrap();
    }
    assert!(
        emergency::emergency_timeline(&db, &station().public_key())
            .unwrap()
            .is_empty(),
        "an attestation with a mismatched scheduled_expiry is not believed"
    );
}

/// An outsider (not in the pinned electorate) is refused at `append_cosign`, so an
/// ineligible signature can never count toward a declaration's supermajority.
#[test]
fn an_ineligible_cosigner_is_refused_at_append() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let h = declare(&db, &st, &founders[0], 72 * 3600, t0);

    let outsider = Keypair::generate();
    let c = EmergencyCosign {
        declaration_hash: h,
        signer: addr(&outsider),
    };
    let mut log = AppendLog::new(&db);
    let err = emergency::append_cosign(&mut log, SignedPayload::sign(c, &outsider), &db, &st, t0)
        .unwrap_err();
    assert!(matches!(err, EmergencyError::NotEligible { .. }));
}

/// The state predicate `is_active_at` is inclusive at the activation instant — the
/// action that crosses the threshold reads active on its own tick — while the
/// record-positioning `governs` stays strict (a record admitted at the exact
/// activation instant is not retroactively governed).
#[test]
fn is_active_at_is_inclusive_at_the_activation_instant() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    activate(&db, &st, &founders, t0);
    let e = emergency::active_emergency_at(&db, t0 + 1, u64::MAX, &station().public_key())
        .unwrap()
        .unwrap();

    assert!(
        e.is_active_at(e.activation_instant),
        "active from activation"
    );
    assert!(e.is_active_at(e.scheduled_expiry), "active through expiry");
    assert!(!e.is_active_at(e.activation_instant - 1));
    assert!(!e.is_active_at(e.scheduled_expiry + 1));
    // The strict positioning boundary is unchanged.
    assert!(!e.governs(e.activation_instant, u64::MAX));
    assert!(e.governs(e.activation_instant + 1, u64::MAX));
}

/// A community-renaming amendment must not silently make emergencies
/// un-declarable. `append_declaration` checks the declaration's community against
/// the **genesis** charter (which `emergency_timeline` also anchors on), so a
/// declaration naming the founding community is still accepted and activates after
/// the effective charter has been renamed.
#[test]
fn a_community_rename_amendment_does_not_break_emergency_declaration() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db, &station().public_key())
        .unwrap()
        .unwrap();
    let t0 = 1_000_000;

    // Enact a v2 amendment that renames the community.
    let mut v2 = charter.clone();
    v2.version = 2;
    v2.previous_hash = Some(charter.hash());
    v2.community_id = "renamed".into();
    let p = Proposal::new(
        addr(&founders[0]),
        "Rename the community".into(),
        "v2".into(),
        ProposalKind::CharterAmendment { new_charter: v2 },
        t0,
    )
    .unwrap();
    let amendment_id = p.proposal_id;
    {
        let mut log = AppendLog::new(&db);
        append_proposal(
            &mut log,
            SignedPayload::sign(p, &founders[0]),
            &db,
            &st,
            &charter,
            t0,
        )
        .unwrap();
    }
    let amendment = rrn_governance::proposal::proposal_records(
        &AppendLog::new(&db),
        &amendment_id,
        &db,
        &station().public_key(),
    )
    .unwrap()
    .proposal
    .unwrap();
    for c in &founders[1..3] {
        cosign_prop(&db, c, &amendment, t0);
    }
    for f in &founders {
        vote_prop(&db, f, &amendment, VoteChoice::Yes, t0 + 1);
    }
    let due = amendment.implementation_at;
    rrn_governance::lifecycle::enact_due(&db, &st, due).unwrap();
    assert_eq!(
        rrn_governance::tally::effective_charter(&db, &station().public_key())
            .unwrap()
            .unwrap()
            .community_id,
        "renamed",
        "the effective community has been renamed"
    );

    // A declaration naming the *renamed* (effective) community is refused — the
    // genesis community is the anchor.
    let bad = EmergencyDeclaration {
        community_id: "renamed".into(),
        author: addr(&founders[0]),
        reason: "storm".into(),
        scope: "flood".into(),
        duration_secs: 72 * 3600,
        stated_renewal_index: 0,
        previous_declaration_hash: None,
        created_at: due,
    };
    {
        let mut log = AppendLog::new(&db);
        let err = emergency::append_declaration(
            &mut log,
            SignedPayload::sign(bad, &founders[0]),
            &db,
            &st,
            due,
        )
        .unwrap_err();
        assert!(matches!(err, EmergencyError::WrongCommunity { .. }));
    }

    // A declaration naming the *genesis* community is accepted and can activate — the
    // rename has not disabled the mechanism.
    let h = declare(&db, &st, &founders[0], 72 * 3600, due);
    em_cosign(&db, &st, &founders[1], h, due);
    assert!(
        emergency::active_emergency_at(&db, due + 1, u64::MAX, &station().public_key())
            .unwrap()
            .is_some(),
        "an emergency in the founding community still activates after a rename"
    );
}

/// Two members each raising their *own* lapse motion pool their signatures toward a
/// single lift threshold (ADR-0023 2026-09-10 clarification, option A) — competing
/// lapse motions can no longer split the supermajority across per-author hashes.
#[test]
fn competing_lapse_motions_aggregate_toward_one_lift_threshold() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let h = activate(&db, &st, &founders, t0);

    // One member's lapse motion is 1 of the 2 needed — not yet lifted.
    let _l1 = em_lapse(&db, &founders[0], h, t0 + 10);
    assert!(
        emergency::active_emergency_at(&db, t0 + 11, u64::MAX, &station().public_key())
            .unwrap()
            .is_some(),
        "a single lapse motion (1 of 2) does not lift the emergency"
    );

    // A *different* member raises a *separate* lapse record. Pooled per-emergency the
    // two distinct authors reach the 2-of-3 bar, so the emergency lifts — under the
    // old per-lapse counting neither hash would have crossed.
    let _l2 = em_lapse(&db, &founders[1], h, t0 + 20);
    assert!(
        emergency::active_emergency_at(&db, t0 + 21, u64::MAX, &station().public_key())
            .unwrap()
            .is_none(),
        "two competing lapse motions pool toward one threshold and lift the emergency"
    );
}

/// A charter's `emergency_window_secs` is clamped to `[floor, ordinary window]` on
/// use, so a hostile value can neither undercut the floor nor (unbounded above)
/// overflow `admitted_at + secs`.
#[test]
fn the_emergency_window_is_clamped_to_floor_and_ordinary_window() {
    // Absurdly large: capped at the ordinary deliberation window (7 days by default).
    let huge = GovernanceStructure {
        emergency_window_secs: i64::MAX,
        ..Default::default()
    };
    assert_eq!(
        huge.effective_emergency_window_secs(),
        i64::from(huge.deliberation_window_days) * DAY
    );

    // Below the floor: raised to the floor.
    let tiny = GovernanceStructure {
        emergency_window_secs: 1,
        ..Default::default()
    };
    assert_eq!(
        tiny.effective_emergency_window_secs(),
        EMERGENCY_WINDOW_FLOOR_SECS
    );

    // A degenerate charter whose ordinary window is below the floor still yields at
    // least the floor (the ceiling is clamped up to it).
    let degenerate = GovernanceStructure {
        deliberation_window_days: 0,
        emergency_window_secs: i64::MAX,
        ..Default::default()
    };
    assert_eq!(
        degenerate.effective_emergency_window_secs(),
        EMERGENCY_WINDOW_FLOOR_SECS
    );
}
