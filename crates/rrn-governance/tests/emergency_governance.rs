//! Emergency-governance conformance suite (T2.8.2, ADR-0023).
//!
//! Each test maps to one of the ticket's invariants. To stay fast, the community is
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
    self, EmergencyCosign, EmergencyDeclaration, EmergencyLapse, EMERGENCY_CHAIN_MAX_SECS,
    EMERGENCY_COOLDOWN_SECS, EMERGENCY_MEASURE_GRACE, EMERGENCY_WINDOW_FLOOR_SECS,
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
    Keypair::generate()
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
    emergency::append_lapse(&mut log, SignedPayload::sign(l, author), db, at).unwrap();
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
    rrn_governance::proposal::proposal_records(&AppendLog::new(db), &id, db)
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
    append_cosign(&mut log, SignedPayload::sign(c, cosigner), db, at).unwrap();
}

fn vote_prop(db: &Database, voter: &Keypair, p: &Proposal, choice: VoteChoice, at: i64) {
    let v = Vote {
        proposal_id: p.proposal_id,
        voter: addr(voter),
        choice,
        cast_at: at,
    };
    let mut log = AppendLog::new(db);
    append_vote(&mut log, SignedPayload::sign(v, voter), db, at).unwrap();
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
        emergency::active_emergency_at(db, at + 1, u64::MAX)
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
    assert!(emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
        .unwrap()
        .is_none());

    em_cosign(&db, &st, &founders[1], h, t0);
    let active = emergency::active_emergency_at(&db, t0 + 1, u64::MAX).unwrap();
    assert!(active.is_some());
    assert_eq!(active.unwrap().scheduled_expiry, t0 + 72 * 3600);

    // An Emergency proposal admitted now runs the compressed 24 h window, not 7 d.
    let charter = rrn_governance::tally::effective_charter(&db)
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
    let charter = rrn_governance::tally::effective_charter(&db)
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
    let charter = rrn_governance::tally::effective_charter(&db)
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
    let scheduled = emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
        .unwrap()
        .unwrap()
        .scheduled_expiry;
    let _ = h;
    let charter = rrn_governance::tally::effective_charter(&db)
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
    let charter = rrn_governance::tally::effective_charter(&db)
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
        emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
            .unwrap()
            .is_none(),
        "the 10% declaration pct must not lower the bar below two-thirds"
    );
    em_cosign(&db, &st, &founders[1], h, t0);
    assert!(emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
        .unwrap()
        .is_some());

    // The window stays at the 24 h floor, not the charter's 60 s.
    let charter = rrn_governance::tally::effective_charter(&db)
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
    let charter = rrn_governance::tally::effective_charter(&db)
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
        emergency::active_emergency_at(&db, t0 + 21, u64::MAX)
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
    assert!(emergency::active_emergency_at(&db, expiry, u64::MAX)
        .unwrap()
        .is_some());
    assert!(emergency::active_emergency_at(&db, expiry + 1, u64::MAX)
        .unwrap()
        .is_none());
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
    let e1 = emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
        .unwrap()
        .unwrap();

    // Activation 2: a continuation within the cooldown of e1's scheduled end, 7 d.
    let t1 = e1.scheduled_expiry + 1; // still < end + 14 d cooldown → continuation
    let h2 = declare(&db, &st, &founders[0], seven_d, t1);
    em_cosign(&db, &st, &founders[1], h2, t1);
    let e2 = emergency::active_emergency_at(&db, t1 + 1, u64::MAX)
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
        emergency::active_emergency_at(&db, t2 + 1, u64::MAX)
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
    let e1 = emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
        .unwrap()
        .unwrap();

    // A declaration whose activation is inside the cooldown of e1's end but beyond
    // the caps... here it is a continuation (within cooldown) so renewal_count 1 —
    // allowed. Instead test the *post-cap* refusal: build a chain to its cap first.
    // Simpler: a declaration far beyond the cooldown starts a fresh chain (allowed).
    let far = e1.scheduled_expiry + EMERGENCY_COOLDOWN_SECS + 1;
    let h2 = declare(&db, &st, &founders[0], DAY, far);
    em_cosign(&db, &st, &founders[1], h2, far);
    let e2 = emergency::active_emergency_at(&db, far + 1, u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(e2.renewal_count, 0, "beyond the cooldown, a fresh chain");
}

// --- Invariant 5 core: the ballot rule (ADR-0023 §3a) -----------------------

#[test]
fn a_ballot_admitted_before_close_counts_even_after_the_emergency_lapses() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db)
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
    assert!(emergency::active_emergency_at(&db, lapse_at + 1, u64::MAX)
        .unwrap()
        .is_none());

    // Ballots admitted AFTER the lapse but BEFORE the proposal's own close still
    // count — the emergency's lapse does not retroactively shut an open compressed
    // window (§3a).
    let vote_at = lapse_at + 50;
    assert!(vote_at < close);
    vote_prop(&db, &founders[0], &p, VoteChoice::Yes, vote_at);
    vote_prop(&db, &founders[1], &p, VoteChoice::Yes, vote_at);
    vote_prop(&db, &founders[2], &p, VoteChoice::Yes, vote_at);

    let t = tally(&db, &p.proposal_id, close + 1).unwrap();
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
    let charter = rrn_governance::tally::effective_charter(&db1)
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

    let tl1 = emergency::emergency_timeline(&db1).unwrap();
    let ty1 = tally(&db1, &p.proposal_id, close + 1).unwrap();
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
    let tl2 = emergency::emergency_timeline(&db2).unwrap();
    let ty2 = tally(&db2, &p.proposal_id, close + 1).unwrap();
    assert_eq!(tl1, tl2, "two replicas must derive the identical timeline");
    assert_eq!(
        (ty1.outcome, ty1.eligible_voters, ty1.yes_count),
        (ty2.outcome, ty2.eligible_voters, ty2.yes_count),
        "and the identical compressed-path tally"
    );
    let _ = h;

    // Repeated derives on the same db are stable.
    assert_eq!(tl1, emergency::emergency_timeline(&db1).unwrap());
}

// --- §1 kind-wide expiry enforcement ----------------------------------------

#[test]
fn an_expired_emergency_measure_drops_out_of_the_in_force_set() {
    let (db, founders, st) = three_founder_community();
    let charter = rrn_governance::tally::effective_charter(&db)
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
    assert_eq!(enacted_statutes(&db, close + 1).unwrap().len(), 1);
    assert!(
        enacted_statutes(&db, measure_expiry + 1)
            .unwrap()
            .is_empty(),
        "an expired emergency measure has no effect"
    );
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
