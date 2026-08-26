//! The oracle tier ladder, end to end through the [`Engine`] (T1.8.5).
//!
//! [`lifecycle.rs`](super) already tells the single-transaction story; this test
//! adds the Phase-1 tier dimension: a low-value Tier-1 transfer clears on the
//! shorter 24h window while a deliberate Tier-2 purchase serves the full 48h,
//! and 5.00 Commons exactly lands in Tier 2. The clock is injected throughout,
//! so the real default windows run without any real time elapsing.
//!
//! ```sh
//! cargo test --test tier_lifecycle -p rrn-ledger -- --nocapture
//! ```

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{
    SettlementConfig, Settler, DEFAULT_TIER1_WINDOW_SECONDS, DEFAULT_TIER2_WINDOW_SECONDS,
};
use rrn_ledger::state::TransactionState;
use rrn_ledger::tier::{effective_tier, tier_floor, TIER_2_FLOOR_CENTI};
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_storage::db::Database;
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

/// Proposes `amount_centi` from `sender` to `receiver` and confirms it, leaving
/// the transaction in `Confirmed` at `confirmed_at`. Returns its id.
#[allow(clippy::too_many_arguments)]
fn propose_and_confirm(
    engine: &mut Engine,
    sender: (&Keypair, Address),
    receiver: (&Keypair, Address),
    amount_centi: i64,
    nonce: u64,
    proposed_at: i64,
    confirmed_at: i64,
) -> rrn_ledger::transaction::TransactionId {
    let (sender_kp, sender_addr) = sender;
    let (receiver_kp, receiver_addr) = receiver;
    let expiry = proposed_at + 24 * 3600;
    let proposal = TransactionProposal::new(
        sender_addr,
        receiver_addr,
        amount_centi,
        None,
        nonce,
        proposed_at,
        expiry,
    );
    let tx_id = proposal.id;
    engine
        .submit_proposal(SignedProposal::sign(proposal, sender_kp), proposed_at)
        .unwrap();
    let confirmation = TransactionConfirmation {
        proposal_id: tx_id,
        confirmer: receiver_addr,
        confirmed_at,
    };
    engine
        .submit_confirmation(
            SignedConfirmation::sign(confirmation, receiver_kp),
            confirmed_at,
        )
        .unwrap();
    tx_id
}

fn is_settled(engine: &Engine, tx_id: &rrn_ledger::transaction::TransactionId) -> bool {
    matches!(
        engine.get_state(tx_id).unwrap(),
        Some(TransactionState::Settled { .. })
    )
}

/// The boundary the whole ladder pivots on: under 5 Commons is Tier 1; 5.00
/// Commons exactly, and everything above, is Tier 2 (boundary inclusive on the
/// higher side). Sign never lowers it.
#[test]
fn five_commons_exactly_is_tier_two() {
    assert_eq!(TIER_2_FLOOR_CENTI, 500);
    assert_eq!(tier_floor(499), 1);
    assert_eq!(tier_floor(500), 2);
    assert_eq!(
        tier_floor(-500),
        2,
        "absolute value: a refund classifies alike"
    );
    // No opt-up: the amount's own floor governs.
    assert_eq!(effective_tier(300, None), 1);
    assert_eq!(effective_tier(2_500, None), 2);
}

#[test]
fn tiers_settle_on_their_own_windows() {
    init_tracing();
    assert_eq!(DEFAULT_TIER1_WINDOW_SECONDS, 24 * 3600);
    assert_eq!(DEFAULT_TIER2_WINDOW_SECONDS, 48 * 3600);

    const T0: i64 = 1_700_000_000;
    const HOUR: i64 = 3600;

    let (alice_kp, alice) = new_identity();
    let (bob_kp, bob) = new_identity();
    let station = Keypair::generate();

    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();

    // This test is about tier windows, not credit: Alice commits 28 Commons of
    // pending debits at once, past the default −20 Commons debt floor
    // (ADR-0018), so widen the floor explicitly to keep the subjects separate.
    let mut engine =
        Engine::new(&db, station.clone()).with_credit_config(rrn_ledger::credit::CreditConfig {
            debt_floor_centi: -10_000,
        });
    // The real production defaults — 24h Tier 1, 48h Tier 2.
    let mut settler = Settler::new(&db, station.clone(), SettlementConfig::default());

    let confirmed_at = T0 + 60;
    // A 3-Common transfer (Tier 1) and a 25-Common purchase (Tier 2), both
    // confirmed at the same instant.
    let tier1 = propose_and_confirm(
        &mut engine,
        (&alice_kp, alice),
        (&bob_kp, bob),
        300,
        0,
        T0,
        confirmed_at,
    );
    let tier2 = propose_and_confirm(
        &mut engine,
        (&alice_kp, alice),
        (&bob_kp, bob),
        2_500,
        1,
        T0,
        confirmed_at,
    );
    info!("Tier-1 (300c) and Tier-2 (2500c) both confirmed");

    // One hour before the Tier-1 window closes, nothing settles.
    assert_eq!(settler.sweep(confirmed_at + 23 * HOUR).unwrap(), 0);

    // At the 24h mark, the Tier-1 transfer settles; the Tier-2 purchase waits.
    assert_eq!(settler.sweep(confirmed_at + 24 * HOUR).unwrap(), 1);
    assert!(
        is_settled(&engine, &tier1),
        "Tier 1 settles on the 24h window"
    );
    assert!(
        !is_settled(&engine, &tier2),
        "Tier 2 must keep waiting past the Tier-1 window"
    );
    info!("24h: Tier-1 settled, Tier-2 still holding");

    // Between the windows it still waits.
    assert_eq!(settler.sweep(confirmed_at + 47 * HOUR).unwrap(), 0);

    // At the 48h mark, the Tier-2 purchase settles too.
    assert_eq!(settler.sweep(confirmed_at + 48 * HOUR).unwrap(), 1);
    assert!(
        is_settled(&engine, &tier2),
        "Tier 2 settles on the 48h window"
    );
    info!("48h: Tier-2 settled");
}
