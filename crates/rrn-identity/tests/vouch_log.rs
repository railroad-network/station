//! Cross-crate integration: two identities, one vouches for the other, and the
//! vouch lands in the append-only log (rrn-identity + rrn-storage + rrn-crypto).

use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::{append_vouch, create_vouch, Vouch};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

#[test]
fn identity_a_vouches_for_identity_b() {
    // Two distinct identities.
    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let bob_addr = Address::from_public_key(bob.public_key());

    // A fresh, migrated database with an empty log.
    let db = Database::open_in_memory().unwrap();
    rrn_storage::migrations::run(&db).unwrap();
    let mut log = AppendLog::new(&db);
    assert_eq!(log.verify_chain().unwrap(), 0, "log starts empty");

    // Alice vouches for Bob; the vouch is appended.
    let vouch = create_vouch(&alice, &bob_addr, "demo-community", "known in person", 500);
    let entry = append_vouch(&mut log, vouch).unwrap();

    // Exactly one entry, and the chain verifies.
    assert_eq!(entry.seq, 1);
    assert_eq!(log.verify_chain().unwrap(), 1, "log has one entry");
    assert!(log.get(2).unwrap().is_none(), "no second entry");

    // The stored entry is Alice's signature over a vouch about Bob.
    let stored = log.get(1).unwrap().unwrap();
    assert_eq!(stored.payload.signer, alice.public_key());
    assert!(stored.payload.verify().is_ok());

    let decoded: Vouch = from_canonical_bytes(&stored.payload.bytes).unwrap();
    assert_eq!(decoded.subject, bob_addr);
    assert_eq!(decoded.body.community, "demo-community");
    assert_eq!(decoded.body.reputation_stake_centi, 500);
}
