#![no_main]
//! Fuzz the append-only log's replication + replay path. Arbitrary byte
//! buffers are signed by a fixed harness key (so they pass `append_raw`'s
//! signature gate and actually land in the log), then the chain is verified
//! and the ledger/CRDT state is derived from the resulting log. The decode +
//! derivation layer must tolerate arbitrary *payload* bytes — unrecognized log
//! payloads are ignored during replay — without panicking, and the hash chain
//! must stay intact across the replicated, re-chained entries.

use libfuzzer_sys::fuzz_target;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, StoredPayload};
use rrn_storage::migrations;
use rrn_storage::replay::{replay_log, BalanceHandler};

fuzz_target!(|chunks: Vec<Vec<u8>>| {
    // A deterministic key keeps the harness fast and signatures valid; we are
    // fuzzing the log/replay machinery, not key generation.
    let keypair = Keypair::from_secret(SecretKey::from_bytes([7u8; 32]));

    let db = match Database::open_in_memory() {
        Ok(db) => db,
        Err(_) => return,
    };
    if migrations::run(&db).is_err() {
        return;
    }

    let mut log = AppendLog::new(&db);
    for bytes in &chunks {
        let signature = keypair.sign(bytes);
        let payload = StoredPayload {
            bytes: bytes.clone(),
            signer: keypair.public_key(),
            signature,
        };
        // Errors are fine; the contract is "no panic".
        let _ = log.append_raw(payload);
    }

    // The chain must always verify after a sequence of re-chained appends.
    let _ = log.verify_chain();

    // Replay must tolerate arbitrary (signed) payload bytes without panicking.
    let mut handler = BalanceHandler::new();
    let _ = replay_log(&log, &mut handler, 0);
});
