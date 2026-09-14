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
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionId;
use rrn_reputation::staking::{grace_electorate_asof, tier2_stake_centi_asof};
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
    /// The **admission log position** (`seq`) of the dispute entry — the prefix the
    /// jury pool, its recusal graph, and every draw weight are bounded to (ADR-0022
    /// §5). Nothing admitted after this seq may enter the pool or shift a weight,
    /// whatever timestamp it claims, so a vouch or settlement back-dated past the
    /// dispute's open cannot pack the jury. Paired with [`opened_at`](Self::opened_at)
    /// exactly as governance pairs `(pin_time, pin_seq)`; sourced from the same
    /// dispute-entry admission metadata as `opened_at`
    /// ([`AdmissionTimes::dispute_seq`](rrn_ledger::state::AdmissionTimes::dispute_seq)).
    pub opened_seq: u64,
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
pub fn disputed_info(
    db: &Database,
    tx_id: &TransactionId,
    station: &PublicKey,
) -> Result<DisputedInfo> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db), station)?;
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
            // Both the admitted open time and the admitted open *position* come from
            // the same dispute-entry metadata (ADR-0022). A `Disputed` state exists
            // only because a dispute entry was admitted, which records both, so a
            // missing value means a corrupt or partially-replayed log — a hard error,
            // never a fall-back to a party's signed value.
            let admission = snapshot.admission(tx_id).ok_or(Error::MissingAdmission)?;
            let opened_at = admission
                .dispute_admitted_at
                .ok_or(Error::MissingAdmission)?;
            let opened_seq = admission.dispute_seq.ok_or(Error::MissingAdmission)?;
            Ok(DisputedInfo {
                sender: proposal.payload.sender,
                receiver: proposal.payload.receiver,
                opened_at,
                opened_seq,
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

/// The distinct members who have vouched for `subject` over the whole vouch graph on
/// the log — the unbounded convenience wrapper over [`vouchers_of_until`]. These are
/// recused from judging that party's dispute (the obvious collusion edge — ADR-0014
/// §2). Both dispute paths now recuse over a bounded prefix (ADR-0022 §5), so this
/// whole-graph form has no in-crate caller today; it stays as the natural public
/// reader of the full graph.
pub fn vouchers_of(db: &Database, subject: &Address) -> Result<HashSet<Address>> {
    vouchers_of_until(db, subject, u64::MAX)
}

/// [`vouchers_of`] restricted to vouches admitted at log sequence `until_seq` or
/// earlier — the vouch graph *as of an admission position*, not the present.
///
/// Both dispute paths recuse over the same admission prefix their pool is bounded to
/// (ADR-0022 §5): the transaction jury passes the dispute entry's seq (via
/// [`eligible_pool`]), and the equivocation jury the round's admission position
/// (ADR-0025 §3), so a voucher cannot revoke to become seatable, nor a friend vouch
/// to get recused, after a round's seed is fixed. Entries arrive in `seq` order, so
/// the scan stops at the first entry past the bound.
pub fn vouchers_of_until(
    db: &Database,
    subject: &Address,
    until_seq: u64,
) -> Result<HashSet<Address>> {
    let log = AppendLog::new(db);
    let mut vouchers = HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        if entry.seq > until_seq {
            break;
        }
        if let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) {
            if vouch.subject == *subject {
                vouchers.insert(Address::from_public_key(entry.payload.signer));
            }
        }
    }
    Ok(vouchers)
}

/// The eligible jury pool for a dispute, each candidate paired with the
/// raw-standing weight the draw uses, as of `at_time` (the dispute's open time) and
/// the log prefix `[1, max_seq]` (the dispute's admission position — pass
/// [`DisputedInfo::opened_seq`]).
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
/// The electorate, the weights, **and** the recusal (voucher) graph are all bounded
/// to the same `max_seq` prefix (ADR-0022 §5), so nothing admitted after the dispute
/// opened — whatever timestamp it back-dates to — can enter the pool, recuse a
/// candidate, or change a draw weight. Pool and recusal agree on one prefix.
///
/// `founders` is supplied by the caller (from the effective Charter); it is only
/// consulted while the community is bootstrapping, matching
/// [`rrn_reputation::staking::grace_electorate_asof`].
pub fn eligible_pool(
    db: &Database,
    founders: &[Address],
    info: &DisputedInfo,
    at_time: i64,
    max_seq: u64,
    params: &DisputeParams,
    station: &PublicKey,
) -> Result<Vec<(Address, u64)>> {
    // The two parties are never eligible (hard recusal); their vouchers are
    // recused too but relax first if that is the only way to seat a panel. The
    // voucher graph is read as of the same admission prefix as the electorate, so a
    // vouch admitted after the dispute opened neither recuses nor seats anyone.
    let parties: HashSet<Address> = [info.sender, info.receiver].into_iter().collect();
    let mut vouchers = vouchers_of_until(db, &info.sender, max_seq)?;
    vouchers.extend(vouchers_of_until(db, &info.receiver, max_seq)?);
    eligible_pool_excluding(
        db, founders, at_time, max_seq, params, &parties, &vouchers, station,
    )
}

/// The shared sortition pool with an explicit two-tier recusal set — the one rule
/// both the transaction-dispute jury and the equivocation jury (ADR-0025 §2) draw
/// from, so pool and draw stay identical across case kinds and only the *recusal
/// set* varies.
///
/// `hard_excluded` are never eligible (the parties, or an equivocation's subject
/// and injured payees). `soft_excluded` (each party's vouchers) are recused from
/// the strict pool but dropped if the strict pool cannot fill a panel — the
/// ADR-0014 §5 relaxation — so a small community can still seat jurors; the hard
/// set is never relaxed. Weights are raw standing as of `at_time`, floored at 1 so
/// a zero-standing founder seated during grace stays selectable. The returned pool
/// may still be smaller than the panel; the caller treats an unseatable jury as a
/// case that will lapse.
///
/// The electorate and the weights are computed over only the log prefix
/// `[1, max_seq]` (ADR-0022 §5): a member established, or a weight lifted, by
/// evidence admitted after the case's anchoring seq is excluded whatever timestamp
/// that evidence claims. Callers pass the anchoring admission position — the dispute
/// entry's seq for a transaction jury, the round's anchoring seq for an equivocation
/// round — so the recusal set (also bounded at `max_seq` by the caller) and the pool
/// agree on one prefix.
#[allow(clippy::too_many_arguments)]
pub fn eligible_pool_excluding(
    db: &Database,
    founders: &[Address],
    at_time: i64,
    max_seq: u64,
    params: &DisputeParams,
    hard_excluded: &HashSet<Address>,
    soft_excluded: &HashSet<Address>,
    station: &PublicKey,
) -> Result<Vec<(Address, u64)>> {
    let electorate = grace_electorate_asof(db, founders, at_time, max_seq, station)?;

    let weigh = |db: &Database, addr: &Address| -> Result<(Address, u64)> {
        // Established members hold composite ≥ the Member band, so their raw
        // standing is positive; a founder seated during grace may have none, so the
        // `max(1)` floor — defensive against a zero weight stalling the draw — is
        // what keeps such a founder selectable. Bounded to the same prefix as the
        // electorate so a back-dated settlement cannot shift a draw weight.
        Ok((
            *addr,
            tier2_stake_centi_asof(db, addr, at_time, max_seq, station)?.max(1),
        ))
    };

    let mut strict = Vec::new();
    for addr in &electorate {
        if !hard_excluded.contains(addr) && !soft_excluded.contains(addr) {
            strict.push(weigh(db, addr)?);
        }
    }
    if strict.len() >= params.panel_size {
        return Ok(strict);
    }

    // Relax: drop the soft recusal, keep the hard recusal, and try again.
    let mut relaxed = Vec::new();
    for addr in &electorate {
        if !hard_excluded.contains(addr) {
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
