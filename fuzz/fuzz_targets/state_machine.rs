#![no_main]
//! Fuzz the ledger state machine end-to-end. Arbitrary bytes are interpreted
//! as a script of lifecycle operations (propose / confirm / settle / cancel)
//! against a real in-memory ledger, with the amount, nonce, and all timestamps
//! drawn from the fuzz input. Every proposal/confirmation is correctly signed
//! by a fixed harness key, so operations actually reach the engine's replay
//! checks, the settlement balance math, and the `Proposed → Confirmed →
//! Settled / Cancelled` transitions rather than bouncing off a signature error.
//!
//! The goal is the panic baseline plus, specifically, integer-overflow hunting:
//! adversarial `amount_centi` and timestamp values flow into balance updates
//! and window arithmetic, which the spec calls out as the likely real bug area.

use libfuzzer_sys::fuzz_target;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_identity::address::Address;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{SettlementConfig, Settler};
use rrn_ledger::state::CancelReason;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
};
use rrn_storage::db::Database;
use rrn_storage::migrations;

/// A little big-endian cursor over the fuzz bytes; returns `None` once the
/// input is exhausted, ending the op loop cleanly.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u64(&mut self) -> Option<u64> {
        let end = self.pos.checked_add(8)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(u64::from_be_bytes(slice.try_into().unwrap()))
    }

    fn i64(&mut self) -> Option<i64> {
        Some(self.u64()? as i64)
    }
}

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

fuzz_target!(|data: &[u8]| {
    let db = match Database::open_in_memory() {
        Ok(db) => db,
        Err(_) => return,
    };
    if migrations::run(&db).is_err() {
        return;
    }

    // Fixed, deterministic identities — we are fuzzing the engine, not keygen.
    let alice = Keypair::from_secret(SecretKey::from_bytes([1u8; 32]));
    let bob = Keypair::from_secret(SecretKey::from_bytes([2u8; 32]));
    let station = Keypair::from_secret(SecretKey::from_bytes([3u8; 32]));

    let mut engine = Engine::new(&db, station.clone());
    let mut settler = Settler::new(&db, station.clone(), SettlementConfig::default());

    // Proposal ids we have created, so confirm/settle/cancel can target them.
    let mut ids: Vec<TransactionId> = Vec::new();

    let mut cur = Cursor { data, pos: 0 };

    // Bound the script length so one input can't run unboundedly long.
    for _ in 0..256 {
        let op = match cur.u8() {
            Some(b) => b % 4,
            None => break,
        };
        match op {
            0 => {
                // propose, with fuzz-controlled amount / nonce / window / now
                let (amount, nonce, proposed_at, expires_at, now) =
                    match (cur.i64(), cur.u64(), cur.i64(), cur.i64(), cur.i64()) {
                        (Some(a), Some(n), Some(p), Some(e), Some(now)) => (a, n, p, e, now),
                        _ => break,
                    };
                let proposal = TransactionProposal::new(
                    addr(&alice),
                    addr(&bob),
                    amount,
                    None,
                    nonce,
                    proposed_at,
                    expires_at,
                );
                ids.push(proposal.id);
                let signed = SignedProposal::sign(proposal, &alice);
                let _ = engine.submit_proposal(signed, now);
            }
            1 => {
                // confirm a tracked proposal
                let (sel, confirmed_at, now) = match (cur.u8(), cur.i64(), cur.i64()) {
                    (Some(s), Some(c), Some(now)) => (s, c, now),
                    _ => break,
                };
                if ids.is_empty() {
                    continue;
                }
                let id = ids[sel as usize % ids.len()];
                let confirmation = TransactionConfirmation {
                    proposal_id: id,
                    confirmer: addr(&bob),
                    confirmed_at,
                };
                let signed = SignedConfirmation::sign(confirmation, &bob);
                let _ = engine.submit_confirmation(signed, now);
            }
            2 => {
                // settle a tracked transaction
                let (sel, now) = match (cur.u8(), cur.i64()) {
                    (Some(s), Some(now)) => (s, now),
                    _ => break,
                };
                if ids.is_empty() {
                    continue;
                }
                let id = ids[sel as usize % ids.len()];
                let _ = settler.settle(&id, now);
            }
            _ => {
                // cancel a tracked proposal
                let (sel, now) = match (cur.u8(), cur.i64()) {
                    (Some(s), Some(now)) => (s, now),
                    _ => break,
                };
                if ids.is_empty() {
                    continue;
                }
                let id = ids[sel as usize % ids.len()];
                let _ = engine.cancel_proposal(&id, CancelReason::WithdrawnBySender, now);
            }
        }
    }
});
