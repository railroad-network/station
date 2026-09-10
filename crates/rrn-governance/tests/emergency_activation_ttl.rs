//! ADR-0027 conformance: emergency activation is a single first-crossing event
//! that never revives (D1/D1b), a part-signed declaration has a time-to-live
//! (D2), and the front door returns typed refusals (D3).
//!
//! The community is a 3-founder **bootstrap-grace** one (founders are the
//! electorate, ADR-0015) — the same small size the ADR's worked cases use — so
//! the declaration threshold is `ceil(2*3/3) = 2` (author plus one co-signer).

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

use rrn_governance::charter::{
    create_charter, store_charter, AmendmentRules, CharterParams, GovernanceStructure,
};
use rrn_governance::emergency::{
    self, DeclarationStatus, EmergencyActivated, EmergencyCosign, EmergencyDeclaration,
    EmergencyError, EmergencyRefused, InertDisposition, EMERGENCY_DECLARATION_TTL,
};

const DAY: i64 = 86_400;

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

fn publish_charter(db: &Database, founders: &[Keypair]) {
    let params = CharterParams {
        version: 1,
        community_id: "commons".into(),
        founding_principles: vec![],
        rights_floor: vec![],
        governance_structure: GovernanceStructure::default(),
        amendment_rules: AmendmentRules::default(),
        founders: founders.iter().map(addr).collect(),
        created_at: 0,
        previous_hash: None,
    };
    let signed = create_charter(params, founders).unwrap();
    let mut log = AppendLog::new(db);
    store_charter(&mut log, &founders[0], signed, 0).unwrap();
}

fn three_founder_community() -> (Database, Vec<Keypair>, Keypair) {
    let db = fresh_db();
    let founders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    publish_charter(&db, &founders);
    (db, founders, Keypair::generate())
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

/// Co-signs `target` and returns the append result, so a test can assert the
/// typed refusal on the D3 front door.
fn try_cosign(
    db: &Database,
    st: &Keypair,
    signer: &Keypair,
    target: Hash,
    at: i64,
) -> Result<(), EmergencyError> {
    let c = EmergencyCosign {
        declaration_hash: target,
        signer: addr(signer),
    };
    let mut log = AppendLog::new(db);
    emergency::append_cosign(&mut log, SignedPayload::sign(c, signer), db, st, at).map(|_| ())
}

fn cosign(db: &Database, st: &Keypair, signer: &Keypair, target: Hash, at: i64) {
    try_cosign(db, st, signer, target, at).unwrap();
}

fn is_active(db: &Database, decl: Hash, now: i64) -> bool {
    emergency::active_emergency_at(db, now, u64::MAX)
        .unwrap()
        .is_some_and(|e| e.declaration_hash == decl)
}

/// Whether the log carries a station `emergency_refused` marker for `decl`.
fn has_refused_marker(db: &Database, decl: Hash) -> bool {
    let log = AppendLog::new(db);
    log.iter_from(1).any(|e| {
        from_canonical_bytes::<EmergencyRefused>(&e.unwrap().payload.bytes)
            .is_ok_and(|r| r.declaration_hash == decl)
    })
}

/// Replicates every log entry into a fresh DB via `append_raw`, re-stamping
/// `created_at` at a *different* clock to prove the derivation ignores it.
fn replicate(src: &Database) -> Database {
    let dst = fresh_db();
    let src_log = AppendLog::new(src);
    let mut dst_log = AppendLog::new(&dst);
    for entry in src_log.iter_from(1) {
        let entry = entry.unwrap();
        dst_log
            .append_raw(entry.payload.clone(), entry.created_at + 9_999)
            .unwrap();
    }
    dst
}

/// Builds a count-capped chain of three 1-day activations, then a fourth
/// declaration whose first crossing the renewal-count cap refuses. Returns the
/// dead declaration's hash and the instant its refused crossing landed.
fn chain_to_a_cap_refusal(db: &Database, founders: &[Keypair], st: &Keypair) -> (Hash, i64) {
    let mut instant = 1_000_000;
    for _ in 0..3 {
        let h = declare(db, st, &founders[0], DAY, instant);
        cosign(db, st, &founders[1], h, instant);
        let e = emergency::active_emergency_at(db, instant + 1, u64::MAX)
            .unwrap()
            .unwrap();
        instant = e.scheduled_expiry + 1; // within the 14-day cooldown ⇒ continuation
    }
    // The fourth continuation would be renewal_count 3 > cap 2 → cap-refused.
    let dead = declare(db, st, &founders[0], DAY, instant);
    cosign(db, st, &founders[1], dead, instant);
    (dead, instant)
}

// --- Invariant 1: revival closed (D1/D1b) -----------------------------------

#[test]
fn a_cap_refused_first_crossing_writes_a_refusal_and_never_revives() {
    let (db, founders, st) = three_founder_community();
    let (dead, refused_at) = chain_to_a_cap_refusal(&db, &founders, &st);

    // The writer wrote a refusal marker; the declaration is dead and inactive.
    assert!(has_refused_marker(&db, dead), "a refusal marker is written");
    assert!(!is_active(&db, dead, refused_at + 1));
    assert_eq!(
        emergency::declaration_status(&db, &dead, refused_at + 1).unwrap(),
        DeclarationStatus::Dead
    );

    // A later, distinct-eligible co-signature — even long after the §4 cooldown
    // has passed — is refused at the door and never revives the emergency.
    let long_after = refused_at + 30 * DAY;
    let err = try_cosign(&db, &st, &founders[2], dead, long_after).unwrap_err();
    assert!(
        matches!(err, EmergencyError::DeclarationDead { .. }),
        "{err:?}"
    );
    assert!(
        !is_active(&db, dead, long_after + 1),
        "no revival on the writer"
    );
}

#[test]
fn an_independent_replay_of_a_refused_chain_never_revives() {
    let (db, founders, st) = three_founder_community();
    let (dead, refused_at) = chain_to_a_cap_refusal(&db, &founders, &st);

    // Replicate the whole chain to a fresh replica and inject a *later* eligible
    // co-signature toward the dead declaration directly (a gossiped record that
    // bypasses the front door). Replay must still refuse to revive it.
    let replica = replicate(&db);
    let later = EmergencyCosign {
        declaration_hash: dead,
        signer: addr(&founders[2]),
    };
    AppendLog::new(&replica)
        .append_raw(
            stored(SignedPayload::sign(later, &founders[2])),
            refused_at + 30 * DAY,
        )
        .unwrap();

    assert_eq!(
        emergency::declaration_status(&replica, &dead, refused_at + 31 * DAY).unwrap(),
        DeclarationStatus::Dead,
        "the dead set survives replication; the extra co-sign does not revive it"
    );
    assert!(!is_active(&replica, dead, refused_at + 31 * DAY));
}

// --- Invariant 2: continuation still works ----------------------------------

#[test]
fn a_within_cooldown_continuation_activates_without_a_refusal() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d0 = declare(&db, &st, &founders[0], DAY, t0);
    cosign(&db, &st, &founders[1], d0, t0);
    let e0 = emergency::active_emergency_at(&db, t0 + 1, u64::MAX)
        .unwrap()
        .unwrap();

    // A second declaration inside the cooldown is a §4 continuation the caps
    // admit: it activates as renewal 1, and no refusal is written for it.
    let t1 = e0.scheduled_expiry + 1;
    let d1 = declare(&db, &st, &founders[0], DAY, t1);
    cosign(&db, &st, &founders[1], d1, t1);
    let e1 = emergency::active_emergency_at(&db, t1 + 1, u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(e1.declaration_hash, d1);
    assert_eq!(e1.renewal_count, 1, "a within-cooldown continuation");
    assert!(
        !has_refused_marker(&db, d1),
        "a continuation writes no refusal"
    );
}

// --- Invariant 3: TTL (D2) --------------------------------------------------

#[test]
fn a_crossing_exactly_at_the_ttl_boundary_still_activates() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0);
    // The crossing co-sign lands at exactly admitted_at + TTL (boundary `<=`).
    cosign(&db, &st, &founders[1], d, t0 + EMERGENCY_DECLARATION_TTL);
    assert!(
        is_active(&db, d, t0 + EMERGENCY_DECLARATION_TTL + 1),
        "a crossing at exactly admitted_at + TTL activates"
    );
    // And the identical timeline is derived on an independent replica.
    let replica = replicate(&db);
    assert!(is_active(&replica, d, t0 + EMERGENCY_DECLARATION_TTL + 1));
}

#[test]
fn a_crossing_past_the_ttl_is_refused_and_never_activates() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0);

    // One second past the TTL: the front door refuses the crossing co-sign as
    // expired, and the declaration never activates.
    let past = t0 + EMERGENCY_DECLARATION_TTL + 1;
    assert_eq!(
        emergency::declaration_status(&db, &d, past).unwrap(),
        DeclarationStatus::Expired
    );
    let err = try_cosign(&db, &st, &founders[1], d, past).unwrap_err();
    assert!(
        matches!(err, EmergencyError::DeclarationExpired { .. }),
        "{err:?}"
    );
    assert!(!is_active(&db, d, past + 1));
}

#[test]
fn replay_ignores_a_forged_activation_beyond_the_ttl() {
    // A declaration + anchor whose crossing is gathered past the TTL (co-signs
    // injected directly), plus a forged station activation at that late instant.
    // Replay must ignore the activation: the signed anchor bounds the TTL.
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0); // writes the anchor at t0
    let late = t0 + EMERGENCY_DECLARATION_TTL + DAY;

    let mut log = AppendLog::new(&db);
    // A genuine, eligible co-signature — but gathered past the TTL.
    log.append_raw(
        stored(SignedPayload::sign(
            EmergencyCosign {
                declaration_hash: d,
                signer: addr(&founders[1]),
            },
            &founders[1],
        )),
        late,
    )
    .unwrap();
    // A station activation forged at the late crossing instant.
    log.append_raw(
        stored(SignedPayload::sign(
            EmergencyActivated {
                declaration_hash: d,
                activation_instant: late,
                scheduled_expiry: late + DAY,
                renewal_count: 0,
            },
            &st,
        )),
        late,
    )
    .unwrap();

    assert!(
        !is_active(&db, d, late + 1),
        "an activation whose crossing is past the signed-anchor TTL is ignored"
    );
}

// --- Invariant 4: fail-closed on a missing anchor ---------------------------

#[test]
fn an_activation_without_a_validated_anchor_never_activates() {
    // Build a log by hand with NO admission anchor: a self-signed declaration, an
    // eligible crossing co-signature, and a well-formed station activation. Replay
    // fails closed — without a validated anchor the activation is ignored — and
    // only once the anchor is supplied does the same activation take force.
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let decl = EmergencyDeclaration {
        community_id: "commons".into(),
        author: addr(&founders[0]),
        reason: "storm".into(),
        scope: "flood".into(),
        duration_secs: DAY,
        stated_renewal_index: 0,
        previous_declaration_hash: None,
        created_at: t0,
    };
    let d = decl.hash();
    let mut log = AppendLog::new(&db);
    log.append(SignedPayload::sign(decl, &founders[0]), t0)
        .unwrap();
    log.append(
        SignedPayload::sign(
            EmergencyCosign {
                declaration_hash: d,
                signer: addr(&founders[1]),
            },
            &founders[1],
        ),
        t0,
    )
    .unwrap();
    log.append(
        SignedPayload::sign(
            EmergencyActivated {
                declaration_hash: d,
                activation_instant: t0,
                scheduled_expiry: t0 + DAY,
                renewal_count: 0,
            },
            &st,
        ),
        t0,
    )
    .unwrap();

    assert!(
        !is_active(&db, d, t0 + 1),
        "fail closed: a crossing with no validated admission anchor never activates"
    );

    // The anchor is the only missing fact: the identical declaration and crossing
    // built through the normal path — which commits the anchor atomically, before
    // the crossing (ADR-0027 D2) — does take force.
    let (anchored_db, founders2, st2) = three_founder_community();
    let d2 = declare(&anchored_db, &st2, &founders2[0], DAY, t0);
    cosign(&anchored_db, &st2, &founders2[1], d2, t0);
    assert!(
        is_active(&anchored_db, d2, t0 + 1),
        "with the anchor committed before the crossing, the activation takes force"
    );
}

// --- Invariant 5: atomicity at the governance layer -------------------------

#[test]
fn a_declaration_lands_with_its_anchor_and_a_crossing_with_its_marker() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;

    // append_declaration commits the declaration and its anchor together.
    let d = declare(&db, &st, &founders[0], DAY, t0);
    assert_eq!(
        emergency::declaration_status(&db, &d, t0).unwrap(),
        DeclarationStatus::Pending,
        "one co-signer short of the bar, but anchored and live"
    );
    // The anchor is present (else the status probe could never report Expired).
    assert_ne!(
        emergency::declaration_status(&db, &d, t0 + EMERGENCY_DECLARATION_TTL + 1).unwrap(),
        DeclarationStatus::Pending,
        "past the TTL the anchored declaration reads Expired, proving the anchor landed"
    );

    // The crossing co-sign commits with its activation marker.
    cosign(&db, &st, &founders[1], d, t0);
    assert_eq!(
        emergency::declaration_status(&db, &d, t0 + 1).unwrap(),
        DeclarationStatus::Activated
    );
}

// --- Invariant 6: D3 typed refusals + the §6 report -------------------------

#[test]
fn a_cosign_toward_an_activated_declaration_is_refused_as_already_activated() {
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0);
    cosign(&db, &st, &founders[1], d, t0); // crosses → active

    let err = try_cosign(&db, &st, &founders[2], d, t0 + 1).unwrap_err();
    assert!(
        matches!(err, EmergencyError::AlreadyActivated { .. }),
        "{err:?}"
    );
}

#[test]
fn the_section_six_report_surfaces_dead_and_expired_declarations() {
    let (db, founders, st) = three_founder_community();

    // A dead (cap-refused) declaration.
    let (dead, refused_at) = chain_to_a_cap_refusal(&db, &founders, &st);

    // An expired declaration: raised, one short of the bar, left to age out.
    let expired = declare(&db, &st, &founders[0], DAY, refused_at + 1);

    let now = refused_at + 1 + EMERGENCY_DECLARATION_TTL + DAY;
    let inert = emergency::inert_declarations(&db, now).unwrap();

    let dead_entry = inert
        .iter()
        .find(|d| d.declaration_hash == dead)
        .expect("dead declaration surfaced");
    assert_eq!(dead_entry.disposition, InertDisposition::Refused);

    let expired_entry = inert
        .iter()
        .find(|d| d.declaration_hash == expired)
        .expect("expired declaration surfaced");
    assert_eq!(expired_entry.disposition, InertDisposition::Expired);
}

// --- Writer fail-closed on a gossip-injected (markerless) crossing (D1b) -----

#[test]
fn a_markerless_gossip_crossing_is_not_activatable_by_a_later_front_door_cosign() {
    // ADR-0027 D1b: a crossing that reaches the log by gossip `append_raw` (bypassing
    // the front door, so no marker is written) is not activatable — on the writer as
    // on replay. This is the writer-side half that closes the cap-refusal revival: a
    // later front-door co-signature must not fire an emergency on a markerless crossing.
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0); // 1 of 2, anchored
    assert_eq!(
        emergency::declaration_status(&db, &d, t0).unwrap(),
        DeclarationStatus::Pending
    );

    // The crossing co-signature arrives by gossip, bypassing the front door: no
    // try_activate runs, so no station marker is written.
    AppendLog::new(&db)
        .append_raw(
            stored(SignedPayload::sign(
                EmergencyCosign {
                    declaration_hash: d,
                    signer: addr(&founders[1]),
                },
                &founders[1],
            )),
            t0,
        )
        .unwrap();
    assert!(
        !is_active(&db, d, t0 + 1),
        "markerless crossing: replay fails closed"
    );
    assert_eq!(
        emergency::declaration_status(&db, &d, t0 + 1).unwrap(),
        DeclarationStatus::Pending,
        "markerless, not dead and not active"
    );

    // A later distinct-eligible co-signature through the front door is admitted but
    // must NOT revive the markerless crossing.
    try_cosign(&db, &st, &founders[2], d, t0 + 2).unwrap();
    assert!(
        !is_active(&db, d, t0 + 3),
        "the writer does not activate a markerless crossing via a later front-door co-sign"
    );
}

// --- D3 idempotency ordering + negative replay of the refusal marker ---------

#[test]
fn re_carriage_of_a_cosign_after_activation_stays_already_cosigned() {
    // The stated design point (ADR-0027 D3): benign re-carriage of an already-present
    // co-sign toward a now-activated declaration is AlreadyCosigned (→ Known on DTN),
    // not the fresh AlreadyActivated refusal — the idempotency check precedes the state
    // check.
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0);
    cosign(&db, &st, &founders[1], d, t0); // crosses → active
    let err = try_cosign(&db, &st, &founders[1], d, t0 + 1).unwrap_err();
    assert!(
        matches!(err, EmergencyError::AlreadyCosigned { .. }),
        "{err:?}"
    );
}

#[test]
fn replay_ignores_a_refusal_whose_crossing_was_never_reached() {
    // A forged station refusal for a declaration that never crossed the bar is
    // ignored — it does not kill the declaration, which can still activate on a
    // genuine crossing.
    let (db, founders, st) = three_founder_community();
    let t0 = 1_000_000;
    let d = declare(&db, &st, &founders[0], DAY, t0); // 1 of 2 — no crossing
    AppendLog::new(&db)
        .append_raw(
            stored(SignedPayload::sign(
                EmergencyRefused {
                    declaration_hash: d,
                    refused_instant: t0,
                },
                &st,
            )),
            t0,
        )
        .unwrap();
    assert_eq!(
        emergency::declaration_status(&db, &d, t0 + 1).unwrap(),
        DeclarationStatus::Pending,
        "a refusal without a genuine crossing does not stick"
    );
    // The genuine crossing then still activates it.
    cosign(&db, &st, &founders[1], d, t0 + 1);
    assert!(is_active(&db, d, t0 + 2));
}

/// Encodes a freshly signed payload as the [`rrn_storage::log::StoredPayload`]
/// `append_raw` takes — the exact `{signer, sig, bytes}` a replica would receive.
fn stored<T: Clone + Into<dcbor::CBOR>>(
    signed: SignedPayload<T>,
) -> rrn_storage::log::StoredPayload {
    rrn_storage::log::StoredPayload {
        bytes: to_canonical_bytes(signed.payload),
        signer: signed.signer,
        signature: signed.signature,
    }
}
