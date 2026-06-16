//! Replaying ledger operations is safe (T0.5.7).
//!
//! "Idempotent" here does *not* mean "every operation can be called twice with
//! no error." Some operations correctly *error* on a duplicate (resubmitting a
//! proposal, or confirming an already-settled transaction); others are genuine
//! no-ops (settling again). What must hold is that the *resulting state* — the
//! derived transaction state and both balances — is identical whether each step
//! ran once or was replayed. This test asserts exactly that, and does it over
//! ten independent runs to catch any nondeterminism.

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{BalanceView, SettlementConfig, Settler};
use rrn_ledger::state::TransactionState;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_ledger::Error;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

const WINDOW: u64 = 100;

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

/// Drives one full propose → confirm → settle sequence, then replays every step
/// a second time, asserting the replay does not change the outcome. Returns the
/// final `(alice_balance, bob_balance, log_len)` so the caller can confirm it is
/// stable across runs.
fn run_once() -> (i64, i64, u64) {
    let db = Database::open_in_memory().unwrap();
    migrations::run(&db).unwrap();

    let alice = Keypair::generate();
    let bob = Keypair::generate();
    let station = Keypair::generate();

    let mut engine = Engine::new(&db, station.clone());
    let mut settler = Settler::new(
        &db,
        station.clone(),
        SettlementConfig {
            window_seconds: WINDOW,
        },
    );
    let balances = BalanceView::new(&db);

    // --- propose ---
    let proposal = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 0, 1_000_000);
    let tx_id = proposal.id;
    let signed_proposal = SignedProposal::sign(proposal, &alice);
    engine.submit_proposal(signed_proposal.clone(), 0).unwrap();
    // Replay: a duplicate proposal must ERROR (not silently re-apply).
    assert!(matches!(
        engine.submit_proposal(signed_proposal, 0),
        Err(Error::DuplicateProposal)
    ));

    // --- confirm ---
    let confirmation = TransactionConfirmation {
        proposal_id: tx_id,
        confirmer: addr(&bob),
        confirmed_at: 10,
    };
    let signed_confirmation = SignedConfirmation::sign(confirmation, &bob);
    engine
        .submit_confirmation(signed_confirmation.clone(), 10)
        .unwrap();

    // --- settle ---
    let now = 10 + WINDOW as i64;
    settler.settle(&tx_id, now).unwrap();
    // Replay: settling again is a genuine NO-OP (returns Ok, no double-apply).
    settler.settle(&tx_id, now + 5).unwrap();

    // Replay the confirmation now that the tx is settled: it must ERROR, because
    // the transaction is no longer in the Proposed state.
    assert!(matches!(
        engine.submit_confirmation(signed_confirmation, 10),
        Err(Error::NotProposed)
    ));

    // Final state is Settled, and balances reflect exactly one application.
    assert!(matches!(
        engine.get_state(&tx_id).unwrap(),
        Some(TransactionState::Settled { .. })
    ));
    let alice_balance = balances.balance_of(&addr(&alice)).unwrap();
    let bob_balance = balances.balance_of(&addr(&bob)).unwrap();
    assert_eq!((alice_balance, bob_balance), (-300, 300));

    // The log holds proposal + confirmation + a single settlement (replayed
    // operations that errored or no-op'd appended nothing).
    let log_len = AppendLog::new(&db).verify_chain().unwrap();
    assert_eq!(log_len, 3, "no extra entries from replayed operations");

    (alice_balance, bob_balance, log_len)
}

#[test]
fn replayed_operations_do_not_change_final_state() {
    // Ten independent runs: the outcome must be identical every time.
    let first = run_once();
    for _ in 0..9 {
        assert_eq!(run_once(), first);
    }
    assert_eq!(first, (-300, 300, 3));
}
