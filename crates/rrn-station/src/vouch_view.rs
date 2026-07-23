//! Member-relative vouch tallies for the "your vouching chain" display (T1.4.4).
//!
//! After a successful vouch the mobile shows two truthful numbers: how many
//! *people* this member has vouched for (`given`) and how many have vouched for
//! them (`received`). These count **distinct counterparties**, not log entries:
//! the web of trust is about breadth of trust, so re-vouching for the same
//! person (the log is append-only; nothing dedups) counts once, and the "N
//! people" the mobile renders stays truthful.
//!
//! Like [`crate::history`] and [`crate::transaction_view`], this is a live scan
//! of the append-only log — correctness now, without an index. M1.5's reputation
//! indexing will make it O(1); until then a linear scan is fine at Phase-0 log
//! sizes and keeps the phone a renderer of numbers the station computes once.

use std::collections::HashSet;

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// A member's vouch tallies: how many distinct people they vouched for
/// (`given`) and how many distinct people vouched for them (`received`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VouchCounts {
    /// Distinct people this member has vouched for.
    pub given: u64,
    /// Distinct people who have vouched for this member.
    pub received: u64,
}

/// Scans the log and counts the distinct people `member` vouched for and was
/// vouched for by.
///
/// The voucher is a log entry's *signer*; the vouched-for key is the vouch
/// attestation's `subject`. Only vouch entries decode as a [`Vouch`]; other
/// records (proposals, confirmations, settlements, …) fail that decode and are
/// skipped. Distinct addresses are collected into sets, so repeated vouches
/// between the same pair count once. A self-vouch cannot occur (the mobile UI
/// and `channel_submit_vouch`'s signer binding both prevent vouching for your
/// own address).
pub fn member_vouch_counts(db: &Database, member: &Address) -> rrn_storage::Result<VouchCounts> {
    let log = AppendLog::new(db);
    let mut vouched_for: HashSet<Address> = HashSet::new();
    let mut vouched_by: HashSet<Address> = HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) else {
            continue;
        };
        let voucher = Address::from_public_key(entry.payload.signer);
        if voucher == *member {
            vouched_for.insert(vouch.subject);
        }
        if vouch.subject == *member {
            vouched_by.insert(voucher);
        }
    }
    Ok(VouchCounts {
        given: vouched_for.len() as u64,
        received: vouched_by.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_identity::vouch::{append_vouch, create_vouch};

    fn fresh_log_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        db
    }

    fn vouch(db: &Database, voucher: &Keypair, subject: &Address) {
        let signed = create_vouch(voucher, subject, "demo", "I know them", 0);
        let mut log = AppendLog::new(db);
        append_vouch(&mut log, signed).unwrap();
    }

    #[test]
    fn empty_log_is_all_zero() {
        let db = fresh_log_db();
        let who = Address::from_public_key(Keypair::generate().public_key());
        assert_eq!(
            member_vouch_counts(&db, &who).unwrap(),
            VouchCounts {
                given: 0,
                received: 0
            }
        );
    }

    #[test]
    fn a_vouch_counts_as_given_for_the_voucher_and_received_for_the_subject() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        let alice_addr = Address::from_public_key(alice.public_key());
        let bob_addr = Address::from_public_key(Keypair::generate().public_key());

        vouch(&db, &alice, &bob_addr);

        assert_eq!(
            member_vouch_counts(&db, &alice_addr).unwrap(),
            VouchCounts {
                given: 1,
                received: 0
            },
            "voucher gave one, received none"
        );
        assert_eq!(
            member_vouch_counts(&db, &bob_addr).unwrap(),
            VouchCounts {
                given: 0,
                received: 1
            },
            "subject received one, gave none"
        );
    }

    #[test]
    fn tallies_accumulate_across_many_vouches() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        let alice_addr = Address::from_public_key(alice.public_key());
        let bob = Keypair::generate();
        let bob_addr = Address::from_public_key(bob.public_key());
        let carol_addr = Address::from_public_key(Keypair::generate().public_key());

        // Alice vouches for Bob and Carol; Bob vouches for Alice.
        vouch(&db, &alice, &bob_addr);
        vouch(&db, &alice, &carol_addr);
        vouch(&db, &bob, &alice_addr);

        assert_eq!(
            member_vouch_counts(&db, &alice_addr).unwrap(),
            VouchCounts {
                given: 2,
                received: 1
            }
        );
        assert_eq!(
            member_vouch_counts(&db, &bob_addr).unwrap(),
            VouchCounts {
                given: 1,
                received: 1
            }
        );
        assert_eq!(
            member_vouch_counts(&db, &carol_addr).unwrap(),
            VouchCounts {
                given: 0,
                received: 1
            }
        );
    }

    #[test]
    fn repeated_vouches_between_the_same_pair_count_once() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        let alice_addr = Address::from_public_key(alice.public_key());
        let bob = Keypair::generate();
        let bob_addr = Address::from_public_key(bob.public_key());

        // Bob vouches for Alice three times (re-vouching is not deduped in the
        // append-only log); Alice vouches for Bob twice.
        vouch(&db, &bob, &alice_addr);
        vouch(&db, &bob, &alice_addr);
        vouch(&db, &bob, &alice_addr);
        vouch(&db, &alice, &bob_addr);
        vouch(&db, &alice, &bob_addr);

        // Counts are distinct *people*, so each pair counts once.
        assert_eq!(
            member_vouch_counts(&db, &alice_addr).unwrap(),
            VouchCounts {
                given: 1,
                received: 1
            }
        );
        assert_eq!(
            member_vouch_counts(&db, &bob_addr).unwrap(),
            VouchCounts {
                given: 1,
                received: 1
            }
        );
    }

    #[test]
    fn a_stranger_has_no_vouches() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        let bob_addr = Address::from_public_key(Keypair::generate().public_key());
        vouch(&db, &alice, &bob_addr);

        let stranger = Address::from_public_key(Keypair::generate().public_key());
        assert_eq!(
            member_vouch_counts(&db, &stranger).unwrap(),
            VouchCounts {
                given: 0,
                received: 0
            }
        );
    }
}
