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

use serde::Serialize;

use rrn_crypto::hash::Hash;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::core::hex;

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

/// One vouch as the browser lists it (T1.4.5): both parties' addresses plus the
/// attestation's community, statement, stake, and issue time. Unlike the
/// push-only [`crate::events::VouchRow`] — which carries only the voucher, since
/// the subject is the notification's recipient — a list row names *both* sides,
/// so the mobile renders the "made" and "received" lists from one shape.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VouchListRow {
    /// Content address: hex of the Blake3 hash of the signed canonical bytes.
    pub vouch_id: String,
    /// The voucher's bech32m `rrn1…` address (the log entry's signer).
    pub voucher_address: String,
    /// The vouched-for member's bech32m `rrn1…` address (attestation subject).
    pub subject_address: String,
    /// The community the vouch was stamped into.
    pub community: String,
    /// The voucher's free-text statement about the subject.
    pub statement: String,
    /// Reputation staked, in centipoints.
    pub stake_centi: u64,
    /// Unix seconds when the vouch was issued.
    pub issued_at: i64,
}

/// A member's vouches split by direction: `given` are the ones they signed,
/// `received` are the ones naming them as subject. Both newest-first.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct VouchLists {
    /// Vouches this member signed (they are the voucher).
    pub given: Vec<VouchListRow>,
    /// Vouches naming this member as the subject.
    pub received: Vec<VouchListRow>,
}

/// Scans the log for `member`'s vouches, split by direction and newest-first.
///
/// `given` = the member is the entry's signer (the voucher); `received` = the
/// member is the attestation's subject. Unlike [`member_vouch_counts`], which
/// dedups to distinct people, this keeps **one row per log entry** — each vouch
/// is a distinct attestation with its own statement, stake, and date, so a
/// re-vouch for the same person appears as a separate row.
///
/// `offset` then `limit` window each list independently after ordering. Like
/// [`member_vouch_counts`] this is a live log scan (correctness without an
/// index); M1.5's reputation indexing will make it O(1).
pub fn member_vouches(
    db: &Database,
    member: &Address,
    limit: Option<u64>,
    offset: u64,
) -> rrn_storage::Result<VouchLists> {
    let log = AppendLog::new(db);
    let mut given: Vec<VouchListRow> = Vec::new();
    let mut received: Vec<VouchListRow> = Vec::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) else {
            continue;
        };
        let voucher = Address::from_public_key(entry.payload.signer);
        let is_given = voucher == *member;
        let is_received = vouch.subject == *member;
        if !is_given && !is_received {
            continue;
        }
        // `entry.payload.bytes` are exactly the canonical bytes that were signed,
        // so their Blake3 hash is the same content address `submit_vouch`
        // returned (`SignedVouch::payload_hash`).
        let row = VouchListRow {
            vouch_id: hex(&Hash::of(&entry.payload.bytes).to_bytes()),
            voucher_address: voucher.to_string(),
            subject_address: vouch.subject.to_string(),
            community: vouch.body.community,
            statement: vouch.body.statement,
            stake_centi: vouch.body.reputation_stake_centi,
            issued_at: vouch.issued_at,
        };
        if is_given {
            given.push(row.clone());
        }
        if is_received {
            received.push(row);
        }
    }
    // Newest first; ties broken by vouch_id so the order is stable.
    let by_recency = |a: &VouchListRow, b: &VouchListRow| {
        b.issued_at
            .cmp(&a.issued_at)
            .then_with(|| a.vouch_id.cmp(&b.vouch_id))
    };
    given.sort_by(by_recency);
    received.sort_by(by_recency);
    window(&mut given, limit, offset);
    window(&mut received, limit, offset);
    Ok(VouchLists { given, received })
}

/// Applies `offset` then `limit` to an ordered row list in place.
fn window(rows: &mut Vec<VouchListRow>, limit: Option<u64>, offset: u64) {
    let offset = (offset as usize).min(rows.len());
    rows.drain(0..offset);
    if let Some(limit) = limit {
        rows.truncate(limit as usize);
    }
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

    /// Like [`vouch`] but returns the content-address the browser will show,
    /// computed the same way `submit_vouch` does (`payload_hash`).
    fn vouch_returning_id(db: &Database, voucher: &Keypair, subject: &Address) -> String {
        let signed = create_vouch(voucher, subject, "demo", "I know them", 0);
        let id = hex(&signed.payload_hash().to_bytes());
        let mut log = AppendLog::new(db);
        append_vouch(&mut log, signed).unwrap();
        id
    }

    #[test]
    fn member_vouches_splits_given_and_received() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        let alice_addr = Address::from_public_key(alice.public_key());
        let bob = Keypair::generate();
        let bob_addr = Address::from_public_key(bob.public_key());
        let carol_addr = Address::from_public_key(Keypair::generate().public_key());

        let a_to_bob = vouch_returning_id(&db, &alice, &bob_addr);
        let a_to_carol = vouch_returning_id(&db, &alice, &carol_addr);
        let bob_to_a = vouch_returning_id(&db, &bob, &alice_addr);

        let lists = member_vouches(&db, &alice_addr, None, 0).unwrap();
        let given_ids: HashSet<_> = lists.given.iter().map(|r| r.vouch_id.clone()).collect();
        let recv_ids: HashSet<_> = lists.received.iter().map(|r| r.vouch_id.clone()).collect();
        assert_eq!(
            given_ids,
            HashSet::from([a_to_bob.clone(), a_to_carol]),
            "given = the two Alice signed"
        );
        assert_eq!(
            recv_ids,
            HashSet::from([bob_to_a]),
            "received = Bob's vouch"
        );

        // A row names both parties and carries the attestation body.
        let bob_row = lists.given.iter().find(|r| r.vouch_id == a_to_bob).unwrap();
        assert_eq!(bob_row.voucher_address, alice_addr.to_string());
        assert_eq!(bob_row.subject_address, bob_addr.to_string());
        assert_eq!(bob_row.community, "demo");
        assert_eq!(bob_row.statement, "I know them");
    }

    #[test]
    fn member_vouches_stranger_is_empty() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        let bob_addr = Address::from_public_key(Keypair::generate().public_key());
        vouch(&db, &alice, &bob_addr);

        let stranger = Address::from_public_key(Keypair::generate().public_key());
        assert_eq!(
            member_vouches(&db, &stranger, None, 0).unwrap(),
            VouchLists::default()
        );
    }

    #[test]
    fn member_vouches_windows_with_offset_and_limit() {
        let db = fresh_log_db();
        let alice = Keypair::generate();
        for _ in 0..5 {
            let subject = Address::from_public_key(Keypair::generate().public_key());
            vouch(&db, &alice, &subject);
        }
        let alice_addr = Address::from_public_key(alice.public_key());

        let all = member_vouches(&db, &alice_addr, None, 0).unwrap();
        assert_eq!(all.given.len(), 5);

        // `offset` then `limit` selects a stable sub-slice of the full ordering.
        let page = member_vouches(&db, &alice_addr, Some(2), 1).unwrap();
        assert_eq!(page.given, all.given[1..3].to_vec());

        // An offset past the end is empty, not an error.
        let empty = member_vouches(&db, &alice_addr, Some(2), 99).unwrap();
        assert!(empty.given.is_empty());
    }
}
