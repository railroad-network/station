//! The end-to-end "lose your phone" scenario (T0.4.9), written as a story.
//!
//! Alice splits her identity key across five friends. She loses her phone — the
//! wallet file is gone. Three of her friends decrypt their shards, and her wallet
//! is rebuilt and signs as the original Alice. Run with `--nocapture` to read the
//! narration:
//!
//! ```sh
//! cargo test --test social_recovery -p rrn-identity -- --nocapture
//! ```

use rrn_crypto::keypair::Keypair;
use rrn_identity::recovery::encryption::decrypt_shard;
use rrn_identity::recovery::flow::{reconstruct_wallet, RecoveryPackage};
use rrn_identity::recovery::shamir::RawShard;
use rrn_identity::wallet::WalletContents;
use tracing::info;

/// Installs a tracing subscriber that writes to the test harness's captured
/// output, so `info!` lines show up under `--nocapture`. Idempotent across tests.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .try_init();
}

#[test]
fn lose_your_phone_and_recover_via_social_shards() {
    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    const PASSPHRASE: &str = "alice-correct-horse-battery-staple";

    // 1. Alice generates her identity.
    let alice = WalletContents::create_new();
    let alice_pubkey = Keypair::from_secret(alice.secret_key.clone()).public_key();
    let alice_address = alice.address;
    info!(address = %alice_address, "Alice creates her identity");

    // 2. Five friends agree to hold a shard each.
    let names = ["Bob", "Carol", "Dan", "Eve", "Frank"];
    let holders: Vec<Keypair> = names.iter().map(|_| Keypair::generate()).collect();
    let holder_pubkeys: Vec<_> = holders.iter().map(|h| h.public_key()).collect();
    info!(holders = ?names, "Alice lines up five trusted friends");

    // 3. Alice creates a 3-of-5 recovery package.
    let package = RecoveryPackage::create(&alice, &holder_pubkeys, 3).unwrap();
    info!(
        threshold = package.threshold,
        total = package.total,
        "Alice splits her key — any 3 of 5 can restore it"
    );

    // 4. The recovery package is saved...
    let package_path = dir.path().join("alice.rrnrecovery");
    package.save_to_file(&package_path).unwrap();
    // 5. ...and so is the wallet (encrypted under Alice's passphrase).
    let wallet_path = dir.path().join("alice.rrnwallet");
    alice.save_to_file(&wallet_path, PASSPHRASE).unwrap();
    info!("Alice backs up her wallet and her recovery package");

    // Forget the in-memory wallet too, so nothing but the files remains.
    drop(alice);

    // 6. Disaster: the phone is lost and the wallet file is destroyed.
    std::fs::remove_file(&wallet_path).unwrap();
    assert!(!wallet_path.exists());
    assert!(
        WalletContents::load_from_file(&wallet_path, PASSPHRASE).is_err(),
        "the wallet must be truly gone"
    );
    info!("Alice loses her phone — the wallet file is destroyed");

    // 7. Load the recovery package from its backup.
    let loaded = RecoveryPackage::load_from_file(&package_path).unwrap();

    // 8. Any three friends — say Bob, Carol, and Eve — decrypt their shards.
    let rescuers = [0usize, 1, 3];
    let decrypted: Vec<RawShard> = rescuers
        .iter()
        .map(|&i| {
            info!(holder = names[i], "decrypts their shard for Alice");
            decrypt_shard(&loaded.shards[i], holders[i].secret_key()).unwrap()
        })
        .collect();

    // 9. The wallet is reconstructed from the three shards.
    let recovered = reconstruct_wallet(&loaded, &decrypted).unwrap();
    info!(address = %recovered.address, "Alice's wallet is reconstructed");

    // 10. The recovered wallet is genuinely Alice: same address, and it signs
    //     under her original public key. This is the assertion that matters.
    assert_eq!(
        recovered.address, alice_address,
        "recovered address must match the original"
    );
    let recovered_keypair = Keypair::from_secret(recovered.secret_key.clone());
    let message = b"Alice is back.";
    let signature = recovered_keypair.sign(message);
    assert!(
        alice_pubkey.verify(message, &signature).is_ok(),
        "the recovered wallet must sign as the original Alice"
    );
    info!("The recovered wallet signs as the original Alice — recovery complete");
}
