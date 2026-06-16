//! The end-to-end transaction lifecycle (T0.5.8), written as a narrative.
//!
//! Two identities, one transaction, the whole arc: Alice proposes, Bob confirms,
//! the settlement window elapses, balances move, and the append-only log tells
//! the story immutably. Run with `--nocapture` to read the narration:
//!
//! ```sh
//! cargo test --test lifecycle -p rrn-ledger -- --nocapture
//! ```

use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{BalanceView, SettlementConfig, SettlementRecord, Settler};
use rrn_ledger::state::TransactionState;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;
use tracing::info;

/// Captures `info!` output under `--nocapture`. Idempotent across tests.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::INFO)
        .without_time()
        .try_init();
}

/// A fresh identity and its signing keypair, created through `rrn-identity`.
fn new_identity() -> (Keypair, Address) {
    let contents = WalletContents::create_new();
    let keypair = Keypair::from_secret(contents.secret_key.clone());
    (keypair, contents.address)
}

/// Counts how many log entries decode as each ledger record type.
fn log_entry_counts(db: &Database) -> (usize, usize, usize) {
    let log = AppendLog::new(db);
    let (mut proposals, mut confirmations, mut settlements) = (0, 0, 0);
    for entry in log.iter_from(1) {
        let bytes = &entry.unwrap().payload.bytes;
        if from_canonical_bytes::<TransactionProposal>(bytes).is_ok() {
            proposals += 1;
        } else if from_canonical_bytes::<TransactionConfirmation>(bytes).is_ok() {
            confirmations += 1;
        } else if from_canonical_bytes::<SettlementRecord>(bytes).is_ok() {
            settlements += 1;
        }
    }
    (proposals, confirmations, settlements)
}

#[test]
fn full_transaction_lifecycle() {
    init_tracing();

    // A short settlement window so the test fast-forwards quickly; `now` is
    // injected throughout, so no real time elapses.
    const WINDOW: u64 = 100;
    const T0: i64 = 1_700_000_000;
    const ONE_DAY: i64 = 24 * 3600;

    // 1. Two identities, created via rrn-identity.
    let (alice_kp, alice) = new_identity();
    let (bob_kp, bob) = new_identity();
    // 1b. The local station, which signs settlement records.
    let station = Keypair::generate();
    info!(%alice, %bob, "two identities created");

    // 2. In-memory database with migrations applied.
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();

    let mut engine = Engine::new(&db, station.clone());
    let mut settler = Settler::new(
        &db,
        station.clone(),
        SettlementConfig {
            window_seconds: WINDOW,
        },
    );
    let balances = BalanceView::new(&db);

    // 3. Alice proposes a 3-Common (300 centi) payment to Bob, nonce 0, 24h
    //    expiry.
    let proposal =
        TransactionProposal::new(alice, bob, 300, Some("thanks!".into()), 0, T0, T0 + ONE_DAY);
    let tx_id = proposal.id;
    engine
        .submit_proposal(SignedProposal::sign(proposal, &alice_kp), T0)
        .unwrap();
    info!(tx = ?tx_id, "Alice proposes 300 centi to Bob");

    // 4. State is Proposed; both balances are zero.
    assert!(matches!(
        engine.get_state(&tx_id).unwrap(),
        Some(TransactionState::Proposed { .. })
    ));
    assert_eq!(balances.balance_of(&alice).unwrap(), 0);
    assert_eq!(balances.balance_of(&bob).unwrap(), 0);

    // 5. Bob confirms; state is Confirmed; balances still zero.
    let confirmed_at = T0 + 60;
    let confirmation = TransactionConfirmation {
        proposal_id: tx_id,
        confirmer: bob,
        confirmed_at,
    };
    engine
        .submit_confirmation(
            SignedConfirmation::sign(confirmation, &bob_kp),
            confirmed_at,
        )
        .unwrap();
    info!(tx = ?tx_id, "Bob confirms");
    assert!(matches!(
        engine.get_state(&tx_id).unwrap(),
        Some(TransactionState::Confirmed { .. })
    ));
    assert_eq!(balances.balance_of(&alice).unwrap(), 0);
    assert_eq!(balances.balance_of(&bob).unwrap(), 0);

    // 6. Advance the clock past the settlement window and sweep.
    let now = confirmed_at + WINDOW as i64;
    let settled = settler.sweep(now).unwrap();
    assert_eq!(settled, 1, "exactly one transaction should settle");
    info!(tx = ?tx_id, now, "settlement window elapsed; swept");

    // 7. State is Settled; Alice -300, Bob +300.
    assert!(matches!(
        engine.get_state(&tx_id).unwrap(),
        Some(TransactionState::Settled { .. })
    ));
    assert_eq!(balances.balance_of(&alice).unwrap(), -300);
    assert_eq!(balances.balance_of(&bob).unwrap(), 300);
    info!(
        alice = balances.balance_of(&alice).unwrap(),
        bob = balances.balance_of(&bob).unwrap(),
        "balances settled"
    );

    // 8. The log holds exactly one proposal, one confirmation, one settlement.
    let (proposals, confirmations, settlements) = log_entry_counts(&db);
    assert_eq!((proposals, confirmations, settlements), (1, 1, 1));

    // 9. The hash chain is intact.
    assert_eq!(AppendLog::new(&db).verify_chain().unwrap(), 3);
    info!("append-only log verified: 1 proposal, 1 confirmation, 1 settlement");
}
