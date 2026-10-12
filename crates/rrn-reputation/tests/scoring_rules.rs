//! Property tests of the ADR-0038 standing rules over generated logs: the
//! velocity cap credits at most one event per dimension per trailing week, a
//! profile does not depend on the order events were inserted, and self-sends and
//! events naming an unenrolled party earn nothing.

use proptest::prelude::*;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_identity::address::Address;
use rrn_ledger::enrollment::EnrollmentBasis;
use rrn_reputation::context::ScoringContext;
use rrn_reputation::sybil::{credited_events, CREDITED_EVENTS_PER_WINDOW, VELOCITY_WINDOW_SECS};
use rrn_reputation::testutil::{enroll, settle_trade, vouch, WEEK};
use rrn_storage::db::Database;
use rrn_storage::migrations;

/// Property-test case budget: `PROPTEST_CASES` if set (the deep lane sets
/// 1024), else `default_cases` — sized so the default run stays fast.
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

fn fresh_db() -> Database {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();
    db
}

/// A fixed keypair per index, so two logs built from one case name the same
/// identities.
fn key(i: u8) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes([i.wrapping_add(1); 32]))
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

const STATION: u8 = 200;
const T0: i64 = 100 * WEEK;
/// Members 0..MEMBERS are enrolled; MEMBERS..2·MEMBERS never are.
const MEMBERS: u8 = 3;

/// A trade `(sender, receiver, offset)`, settled at `T0 + offset`.
fn trade() -> impl Strategy<Value = (u8, u8, i64)> {
    (0..MEMBERS, 0..MEMBERS, 0..20 * WEEK)
}

/// Builds a log: enroll every member, then append `trades` in order, each
/// sender's nonces counting up in that order.
fn build(trades: &[(u8, u8, i64)]) -> Database {
    let db = fresh_db();
    let station = key(STATION);
    for i in 0..MEMBERS {
        enroll(&db, &station, &addr(&key(i)), EnrollmentBasis::Pairing, 0);
    }
    let mut nonces = [0u64; MEMBERS as usize];
    for &(from, to, offset) in trades {
        let nonce = &mut nonces[from as usize];
        settle_trade(&db, &station, &key(from), &key(to), *nonce, T0 + offset);
        *nonce += 1;
    }
    db
}

proptest! {
    #![proptest_config(cases(64))]

    #[test]
    fn credited_events_never_exceed_one_per_window(times in prop::collection::vec(0..40 * WEEK, 0..40)) {
        let credited = credited_events(&times);
        prop_assert!(credited.windows(2).all(|w| w[0] <= w[1]), "ascending");
        // No trailing window holds more than the cap...
        for (i, &t) in credited.iter().enumerate() {
            let in_window = credited[..=i]
                .iter()
                .filter(|&&c| c > t - VELOCITY_WINDOW_SECS)
                .count();
            prop_assert!(in_window <= CREDITED_EVENTS_PER_WINDOW as usize);
        }
        // ...and an uncredited event was blocked by a credited one in its window.
        for &t in &times {
            if !credited.contains(&t) {
                prop_assert!(credited.iter().any(|&c| c <= t && c > t - VELOCITY_WINDOW_SECS));
            }
        }
        // Order-independent.
        let mut reversed = times.clone();
        reversed.reverse();
        prop_assert_eq!(credited_events(&reversed), credited);
    }

    #[test]
    fn a_profile_does_not_depend_on_insertion_order(
        trades in prop::collection::vec(trade(), 0..16)
            .prop_map(|ts| ts.into_iter().filter(|(a, b, _)| a != b).collect::<Vec<_>>()),
    ) {
        let station = key(STATION).public_key();
        let mut reversed = trades.clone();
        reversed.reverse();
        let (a, b) = (build(&trades), build(&reversed));
        let (ca, cb) = (
            ScoringContext::unbounded(&a, &station).unwrap(),
            ScoringContext::unbounded(&b, &station).unwrap(),
        );
        let at = T0 + 20 * WEEK;
        for i in 0..MEMBERS {
            let who = addr(&key(i));
            prop_assert_eq!(ca.score_raw(&who, at), cb.score_raw(&who, at));
        }
    }

    #[test]
    fn self_sends_and_unenrolled_events_score_zero(
        events in prop::collection::vec((0..2 * MEMBERS, 0..2 * MEMBERS, 0..20 * WEEK, any::<bool>()), 0..16),
    ) {
        let db = fresh_db();
        let station = key(STATION);
        for i in 0..MEMBERS {
            enroll(&db, &station, &addr(&key(i)), EnrollmentBasis::Pairing, 0);
        }
        let mut nonce = 0u64;
        for (from, to, offset, is_vouch) in events {
            // Keep only events no rule may credit: a self-send/self-vouch, or one
            // naming an unenrolled identity (index >= MEMBERS).
            let creditable = from != to && from < MEMBERS && to < MEMBERS;
            if creditable {
                continue;
            }
            if is_vouch {
                vouch(&db, &key(from), &addr(&key(to)), T0 + offset);
            } else {
                settle_trade(&db, &station, &key(from), &key(to), nonce, T0 + offset);
                nonce += 1;
            }
        }
        let c = ScoringContext::unbounded(&db, &station.public_key()).unwrap();
        let at = T0 + 20 * WEEK;
        for i in 0..2 * MEMBERS {
            prop_assert_eq!(c.score_raw(&addr(&key(i)), at).composite(), 0.0);
        }
    }
}
