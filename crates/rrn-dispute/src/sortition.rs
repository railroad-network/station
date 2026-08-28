//! The sortition draw: who is eligible, and the deterministic weighted order the
//! jury is seated from.
//!
//! The draw is a **pure function of the log**, not a call to a random-number
//! generator (ADR-0014 §2). A seed derived from the disputed transaction and a
//! community anchor drives an integer, float-free, weighted selection over the
//! eligible pool; anyone replaying the log recomputes the identical order and can
//! prove the station did not choose the jury. Every juror's chance is
//! proportional to their raw standing, so a heavier-staked member is more likely
//! to be called, but never certain to be.

use std::collections::HashSet;

use rrn_crypto::hash::Hash;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionId;
use rrn_reputation::staking::{grace_electorate, tier2_stake_centi};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::{DisputeParams, Error, Result};

/// Domain-separation tag mixed into the sortition seed so a dispute seed can never
/// collide with any other Blake3 hash in the protocol.
const SORTITION_DOMAIN: &[u8] = b"rrn.dispute.sortition.v1";

/// The parties to a disputed transaction and when the dispute opened — the inputs
/// the draw and the resolution both need.
#[derive(Clone, Copy, Debug)]
pub struct DisputedInfo {
    /// The transaction's sender.
    pub sender: Address,
    /// The transaction's receiver (also the confirmer under contest).
    pub receiver: Address,
    /// The admission-clock reading (`created_at`) of the dispute record — the
    /// instant standing is judged at, and the start of the resolution window.
    ///
    /// This is the station's admission time for the dispute entry, **not** the
    /// `opened_at` the raiser signs into their [`DisputeRecord`]. A party's
    /// asserted timestamp is testimony and must never enter window, ordering, or
    /// eligibility arithmetic (ADR-0022); the sortition draw and the resolution
    /// window both key on this admitted value so a lying party cannot shift the
    /// jury or the ballot window.
    ///
    /// [`DisputeRecord`]: rrn_ledger::dispute::DisputeRecord
    pub opened_at: i64,
}

/// Reads the parties and admitted open time of a transaction that must currently
/// be in the `Disputed` state.
///
/// `opened_at` is taken from the station's admission metadata for the dispute
/// entry (ADR-0022), never from the `opened_at` the raiser signed — see
/// [`DisputedInfo::opened_at`]. A `Disputed` state exists only because a dispute
/// entry was admitted, which records `dispute_admitted_at`; its absence means a
/// corrupt or partially-replayed log and is a hard error rather than a fall-back
/// to the party's value.
pub fn disputed_info(db: &Database, tx_id: &TransactionId) -> Result<DisputedInfo> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db))?;
    disputed_info_from_snapshot(&snapshot, tx_id)
}

/// [`disputed_info`] against a snapshot the caller already holds, so a caller in a
/// loop (or one that has just derived a snapshot for other reasons) does not pay for
/// a second full-log replay. The anchoring rule is identical — `opened_at` comes from
/// the dispute entry's admission time, never the party's signed value.
pub fn disputed_info_from_snapshot(
    snapshot: &LedgerSnapshot,
    tx_id: &TransactionId,
) -> Result<DisputedInfo> {
    match snapshot.get(tx_id) {
        Some(TransactionState::Disputed { proposal, .. }) => {
            let opened_at = snapshot
                .admission(tx_id)
                .and_then(|a| a.dispute_admitted_at)
                .ok_or(Error::MissingAdmission)?;
            Ok(DisputedInfo {
                sender: proposal.payload.sender,
                receiver: proposal.payload.receiver,
                opened_at,
            })
        }
        _ => Err(Error::NotDisputed),
    }
}

/// The seed that drives a dispute's draw: `Blake3(domain ‖ tx_id ‖ anchor)`. The
/// `anchor` is a stable community value (e.g. its genesis Charter hash) supplied
/// by the caller, so the same transaction id in two communities draws two
/// different juries; an empty anchor is fine for a single community.
pub fn sortition_seed(tx_id: &TransactionId, anchor: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(SORTITION_DOMAIN.len() + 32 + anchor.len());
    buf.extend_from_slice(SORTITION_DOMAIN);
    buf.extend_from_slice(&tx_id.to_bytes());
    buf.extend_from_slice(anchor);
    Hash::of(&buf).to_bytes()
}

/// The distinct members who have vouched for `subject`, read from the vouch graph
/// on the log. These are recused from judging that party's dispute (the obvious
/// collusion edge — ADR-0014 §2).
pub fn vouchers_of(db: &Database, subject: &Address) -> Result<HashSet<Address>> {
    let log = AppendLog::new(db);
    let mut vouchers = HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        if let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) {
            if vouch.subject == *subject {
                vouchers.insert(Address::from_public_key(entry.payload.signer));
            }
        }
    }
    Ok(vouchers)
}

/// The eligible jury pool for a dispute, each candidate paired with the
/// raw-standing weight the draw uses, as of `at_time` (the dispute's open time).
///
/// Eligibility is the governance electorate — established members (effective
/// composite ≥ the Member band), plus the genesis `founders` while the community
/// is in bootstrap grace (ADR-0015) — **minus both parties** (recusal) and
/// **minus each party's direct vouchers**. Per ADR-0014 §5 the voucher-recusal
/// relaxes before the panel goes unseated: if the strict pool cannot fill a
/// panel, the voucher exclusion is dropped (the two parties are still never
/// eligible). The returned pool may still be smaller than the panel — the caller
/// treats an unseatable jury as a dispute that will lapse.
///
/// `founders` is supplied by the caller (from the effective Charter); it is only
/// consulted while the community is bootstrapping, matching
/// [`rrn_reputation::staking::grace_electorate`].
pub fn eligible_pool(
    db: &Database,
    founders: &[Address],
    info: &DisputedInfo,
    at_time: i64,
    params: &DisputeParams,
) -> Result<Vec<(Address, u64)>> {
    let electorate = grace_electorate(db, founders, at_time)?;
    let parties: HashSet<Address> = [info.sender, info.receiver].into_iter().collect();

    let mut vouchers = vouchers_of(db, &info.sender)?;
    vouchers.extend(vouchers_of(db, &info.receiver)?);

    // The strict pool recuses parties and their vouchers.
    let weigh = |db: &Database, addr: &Address| -> Result<(Address, u64)> {
        // Established members hold composite ≥ the Member band, so their raw
        // standing is positive; a founder seated during grace may have none, so the
        // `max(1)` floor — defensive against a zero weight stalling the draw — is
        // what keeps such a founder selectable.
        Ok((*addr, tier2_stake_centi(db, addr, at_time)?.max(1)))
    };

    let mut strict = Vec::new();
    for addr in &electorate {
        if !parties.contains(addr) && !vouchers.contains(addr) {
            strict.push(weigh(db, addr)?);
        }
    }
    if strict.len() >= params.panel_size {
        return Ok(strict);
    }

    // Relax: drop voucher-recusal, keep party-recusal, and try again.
    let mut relaxed = Vec::new();
    for addr in &electorate {
        if !parties.contains(addr) {
            relaxed.push(weigh(db, addr)?);
        }
    }
    Ok(relaxed)
}

/// Orders the whole pool by a deterministic, standing-weighted draw: repeatedly
/// selects a candidate with probability proportional to its weight, without
/// replacement, until the pool is exhausted. The result is the seating order — the
/// first [`panel_size`](DisputeParams::panel_size) are the initial jury, and the
/// rest are the redraw queue for no-shows.
///
/// Integer arithmetic only (no floats), so every replica computes the identical
/// order.
pub fn draw_sequence(pool: &[(Address, u64)], seed: [u8; 32]) -> Vec<Address> {
    // Sort by public-key bytes for a stable starting order independent of how the
    // pool was assembled, so the draw depends only on the seed and the weights.
    let mut remaining: Vec<(Address, u64)> = pool.to_vec();
    remaining.sort_by(|a, b| {
        a.0.public_key()
            .to_bytes()
            .cmp(&b.0.public_key().to_bytes())
    });

    let mut order = Vec::with_capacity(remaining.len());
    let mut round: u64 = 0;
    while !remaining.is_empty() {
        let total: u128 = remaining.iter().map(|(_, w)| *w as u128).sum();
        // total is always ≥ remaining.len() ≥ 1 (weights are floored at 1).
        let r = (draw_u64(&seed, round) as u128) % total;
        let mut acc: u128 = 0;
        let mut chosen = 0;
        for (i, (_, w)) in remaining.iter().enumerate() {
            acc += *w as u128;
            if r < acc {
                chosen = i;
                break;
            }
        }
        order.push(remaining.remove(chosen).0);
        round += 1;
    }
    order
}

/// A 64-bit draw for `round`, `Blake3(seed ‖ round)` truncated. Distinct rounds
/// give independent draws, and the whole thing is a pure function of the seed.
fn draw_u64(seed: &[u8; 32], round: u64) -> u64 {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&round.to_le_bytes());
    let digest = Hash::of(&buf).to_bytes();
    u64::from_le_bytes(digest[..8].try_into().expect("32-byte digest has 8 bytes"))
}
