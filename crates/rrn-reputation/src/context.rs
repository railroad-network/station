//! Scoring context — one replay of the log prefix, reused for a whole query.
//!
//! Every reputation question (a single score, an electorate, a jury draw, the
//! hourly snapshot sweep) is a pure function of the log. The naive shape scores
//! each address by re-deriving the ledger and re-scanning the log — and then, to
//! judge an anchor, re-scores every voucher the same way. On a community with `A`
//! known addresses, `V` vouchers each, over an `N`-entry log, one electorate
//! query is `O(A·V·N)`: the same replay, thrown away and redone tens of times per
//! operation.
//!
//! [`ScoringContext`] builds the derived views **once** for a `(station,
//! max_seq)` pair — one [`LedgerSnapshot::derive_to`] and one log scan — indexes
//! the evidence by address, memoizes each raw profile, and answers every
//! per-address question from those in-memory tables. That restores the `O(N + A)`
//! per query ADR-0009 always intended ("O(N) in log size per fresh computation"),
//! without storing anything: a context is a stack value, lives for exactly one
//! query, and is dropped. The log stays the only source of truth, and
//! `reputation_snapshots` stays a cache (ADR-0009).
//!
//! The public entry points in [`crate::scoring`], [`crate::sybil`],
//! [`crate::staking`] and [`crate::snapshot`] keep their signatures; each now
//! builds a context and delegates. A caller making several queries at the same
//! `(at_time, max_seq)` can build one [`ScoringContext`] itself and reuse it.
//!
//! # Equivalence
//!
//! Results are **bit-identical** to the per-address scorer this replaced. The
//! events feeding each dimension are folded in the same order the old code used
//! — confirmations and upheld-dispute penalties in ledger (`TransactionId`)
//! order, then vouches, then equivocation penalties in log order — so the `f32`
//! arithmetic reduces to the same bits. The equivalence is proven by
//! `tests/scoring_context_equivalence.rs`, which keeps the old implementation as
//! an oracle and compares dimension bits over generated logs.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_ledger::escrow::{
    EquivocationBasis, EquivocationId, EquivocationRecord, EquivocationVerdictRecord,
    VerdictDecision,
};
use rrn_ledger::state::{CancelReason, LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::TransactionConfirmation;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::decay::decayed;
use crate::model::{ReputationProfile, BAND_MEMBER_MIN, DIMENSION_MAX};
use crate::staking::BOOTSTRAP_GRACE_THRESHOLD;
use crate::sybil::{anchored_profile, ANCHOR_VOUCHER_MIN_COMPOSITE};
use crate::Result;

/// Points one qualifying event contributes to its dimension, before capping and
/// decay. Protocol-locked (ADR-0009): 10 lifetime events reach [`DIMENSION_MAX`].
pub(crate) const EVENT_INCREMENT: f32 = 0.5;

/// Penalty weight a proven equivocation levies on **each** of the two dimensions
/// it dents (ADR-0021 §5, ADR-0009). **Maintainer-ratified 2026-09-04** (ADR-0025).
///
/// ADR-0009's scoring is additive/linear and floors each dimension at zero, so it
/// has no signed negative-weight table to scale. Rather than a fixed small
/// subtraction — which is regressive (invisible on a newcomer, trivial on a
/// veteran) and, at any value that keeps a maxed member's composite ≥ the Member
/// band, leaves the equivocator established with their vote and jury seat intact —
/// the penalty is [`DIMENSION_MAX`], which **zeroes** whichever dimension it is
/// applied to. That is the heaviest expressible consequence within the locked,
/// floored formula, and the only one with a governance effect (de-establishment).
/// It is fully reversible: the penalty is derived on replay and lifted the instant
/// a jury `Overturn` verdict lands (ADR-0021 §5). While it stands the dimension is
/// pinned at zero (a deliberate, proportional cost for a proven, deliberate act);
/// the newcomer-with-no-history case is covered out-of-formula by an
/// equivocation → cert-issuance disqualification gate (ADR-0025).
///
/// Equivocation is dented on **both** live dimensions — a signed statement proven
/// false (attestation accuracy, ADR-0009's "proven wrong" slot) *and* the paradigm
/// disputed-against trade (trade reliability, its reserved negative slot, and the
/// highest-weighted dimension a counterparty reads before accepting an offline
/// spend). It is two proven-wrong facts (a false headroom claim and a failed
/// settlement), not one event double-counted.
pub const EQUIVOCATION_WEIGHT: f32 = DIMENSION_MAX;

/// One vouch in the prefix, indexed for anchoring. `by_subject` lists preserve
/// ascending log order by construction (the scan is `iter_from(1)`), so the log
/// sequence itself need not be stored.
struct VouchRef {
    /// The address that signed the vouch (its author).
    voucher: Address,
    /// The vouch's self-asserted issue time.
    issued_at: i64,
}

/// A station-signed equivocation record in the prefix, against one member.
struct EquivEntry {
    /// The case id, so an `Overturn` verdict can neutralize it.
    equivocation_id: EquivocationId,
    /// When the record was recorded (the penalty applies from here onward).
    recorded_at: i64,
    /// Whether the embedded evidence re-derives the conflict
    /// ([`EquivocationRecord::verify_evidence`]) — precomputed once against the
    /// prefix's certificate cap, since it does not depend on the scoring instant.
    verified: bool,
}

/// A station-signed `Overturn` verdict in the prefix.
struct OverturnEntry {
    /// The case it overturns.
    equivocation_id: EquivocationId,
    /// When the jury decided (the overturn applies from here onward).
    decided_at: i64,
}

/// A read-only, in-memory view of the log prefix `[1, max_seq]` from which every
/// reputation question is answered without re-reading the log.
///
/// Built once per query (one ledger derivation, one log scan), used for as many
/// addresses as the query needs, then dropped. Nothing here is persisted: the log
/// stays the only source of truth (ADR-0009), and a context is exactly as
/// re-derivable as the profile it produces.
///
/// The evidence — ledger states, vouches, equivocations and their verdicts — is
/// bounded to `[1, max_seq]`, exactly where the old position-bounded scorer bounds
/// it (ADR-0022 §5). The [`known_addresses`](Self::known_addresses) set is *not*
/// position-bounded: it enumerates every party and voucher over the whole log, as
/// the old `known_addresses` did — an address whose evidence is all past `max_seq`
/// scores empty and is excluded from any established set either way.
///
/// The raw-profile memo is a `RefCell`, so a context is `!Sync`: it is meant to be
/// built, used, and dropped on one thread within a single query, not shared across
/// threads. Two queries on two threads build two contexts.
pub struct ScoringContext {
    /// The community station key records are pinned to (ADR-0020).
    station: PublicKey,
    /// The prefix bound this context was built for.
    max_seq: u64,
    /// Every identity that appears anywhere in the *whole* log, as a party or on
    /// either side of a vouch. Order is `HashSet`-derived (non-deterministic);
    /// callers that need a stable order sort it themselves.
    known: Vec<Address>,
    /// Settlement instants per party (one per settled transaction they are in).
    trade_times: HashMap<Address, Vec<i64>>,
    /// Attestation instants per address: confirmations they signed and vouches
    /// they wrote, merged (count and recency are order-independent).
    attestation_times: HashMap<Address, Vec<i64>>,
    /// Upheld-dispute penalty instants per confirmer, in ledger order — so the
    /// penalty sum matches the old code's fold order bit for bit.
    dispute_penalty_times: HashMap<Address, Vec<i64>>,
    /// Verified/unverified equivocation records per member, in log order.
    equivocations_by_member: HashMap<Address, Vec<EquivEntry>>,
    /// Every `Overturn` verdict in the prefix; an id's penalty lifts once its
    /// verdict's `decided_at` is at or before the scoring instant.
    overturns: Vec<OverturnEntry>,
    /// Vouches per subject, in ascending log order — the anchoring index.
    by_subject: HashMap<Address, Vec<VouchRef>>,
    /// Memoized raw profiles, keyed by `(address, at_time)`: a voucher scored to
    /// judge one anchor is not re-scored for the next subject.
    raw_memo: RefCell<HashMap<(Address, i64), ReputationProfile>>,
}

impl ScoringContext {
    /// Builds a context over the log prefix `[1, max_seq]`, pinning station-signed
    /// records to `station` (ADR-0020). `max_seq == u64::MAX` covers the whole log.
    pub fn new(db: &Database, station: &PublicKey, max_seq: u64) -> Result<Self> {
        let log = AppendLog::new(db);
        let station = *station;

        // Trade, confirmation, upheld-dispute evidence and certificate caps come
        // from the ledger state of the prefix.
        let ledger = LedgerSnapshot::derive_to(&log, max_seq, &station)?;

        // Known addresses are enumerated over the *whole* log (not the prefix), so
        // the established set matches the old `known_addresses`. When unbounded the
        // prefix ledger already is the whole ledger; otherwise derive it once more.
        let full_ledger_owned;
        let full_ledger: &LedgerSnapshot = if max_seq == u64::MAX {
            &ledger
        } else {
            full_ledger_owned = LedgerSnapshot::derive(&log, &station)?;
            &full_ledger_owned
        };

        let mut known: HashSet<Address> = HashSet::new();
        let mut trade_times: HashMap<Address, Vec<i64>> = HashMap::new();
        let mut attestation_times: HashMap<Address, Vec<i64>> = HashMap::new();
        let mut dispute_penalty_times: HashMap<Address, Vec<i64>> = HashMap::new();
        let mut equivocations_by_member: HashMap<Address, Vec<EquivEntry>> = HashMap::new();
        let mut overturns: Vec<OverturnEntry> = Vec::new();
        let mut by_subject: HashMap<Address, Vec<VouchRef>> = HashMap::new();

        // Ledger parties over the whole log seed the known set.
        for (_, state) in full_ledger.iter() {
            let (sender, receiver) = parties_of(state);
            known.insert(sender);
            known.insert(receiver);
        }

        // Trade / confirmation / upheld-dispute evidence from the *prefix* ledger,
        // folded in ledger (`TransactionId`) order.
        for (_, state) in ledger.iter() {
            if let TransactionState::Settled {
                proposal,
                settled_at,
                ..
            } = state
            {
                let p = &proposal.payload;
                trade_times.entry(p.sender).or_default().push(*settled_at);
                // A self-send is one trade event for the party, not two.
                if p.receiver != p.sender {
                    trade_times.entry(p.receiver).or_default().push(*settled_at);
                }
            }
            if let Some(confirmation) = confirmation_of(state) {
                attestation_times
                    .entry(confirmation.confirmer)
                    .or_default()
                    .push(confirmation.confirmed_at);
            }
            if let TransactionState::Cancelled {
                proposal,
                reason: CancelReason::DisputeUpheld,
                cancelled_at,
            } = state
            {
                dispute_penalty_times
                    .entry(proposal.payload.receiver)
                    .or_default()
                    .push(*cancelled_at);
            }
        }

        // One pass over the whole log: known vouchers/subjects (unbounded), plus
        // the prefix's vouches, equivocations and verdicts (bounded to `max_seq`).
        for entry in log.iter_from(1) {
            let entry = entry?;
            let signer = entry.payload.signer;
            let bytes = &entry.payload.bytes;

            if let Ok(vouch) = from_canonical_bytes::<Vouch>(bytes) {
                let voucher = Address::from_public_key(signer);
                // Known addresses span the whole log, whatever the prefix bound.
                known.insert(voucher);
                known.insert(vouch.subject);
                if entry.seq <= max_seq {
                    attestation_times
                        .entry(voucher)
                        .or_default()
                        .push(vouch.issued_at);
                    by_subject.entry(vouch.subject).or_default().push(VouchRef {
                        voucher,
                        issued_at: vouch.issued_at,
                    });
                }
                continue;
            }

            // Everything below is station-authored (ADR-0020) and prefix-bounded:
            // a record signed by any other key, or admitted past `max_seq`, is
            // inert — exactly as the old penalty and overturn loops treated it.
            if signer != station || entry.seq > max_seq {
                continue;
            }

            if let Ok(record) = from_canonical_bytes::<EquivocationRecord>(bytes) {
                // The cert-overspend cap is read from the prefix's certificate;
                // `verify_evidence` does not depend on the scoring instant, so the
                // verdict of "does the evidence re-derive the conflict" is settled
                // once here.
                let cap = match record.basis {
                    EquivocationBasis::CertOverspend => record
                        .cert_id
                        .and_then(|c| ledger.certificate(&c))
                        .map(|c| c.certificate.payload.cap_centi),
                    EquivocationBasis::OutboxFork => None,
                };
                let verified = record.verify_evidence(cap);
                equivocations_by_member
                    .entry(record.member)
                    .or_default()
                    .push(EquivEntry {
                        equivocation_id: record.equivocation_id,
                        recorded_at: record.recorded_at,
                        verified,
                    });
                continue;
            }

            if let Ok(verdict) = from_canonical_bytes::<EquivocationVerdictRecord>(bytes) {
                if verdict.decision == VerdictDecision::Overturn {
                    overturns.push(OverturnEntry {
                        equivocation_id: verdict.equivocation_id,
                        decided_at: verdict.decided_at,
                    });
                }
            }
        }

        Ok(Self {
            station,
            max_seq,
            known: known.into_iter().collect(),
            trade_times,
            attestation_times,
            dispute_penalty_times,
            equivocations_by_member,
            overturns,
            by_subject,
            raw_memo: RefCell::new(HashMap::new()),
        })
    }

    /// A context over the whole log.
    pub fn unbounded(db: &Database, station: &PublicKey) -> Result<Self> {
        Self::new(db, station, u64::MAX)
    }

    /// The community station key this context pins records to.
    pub fn station(&self) -> &PublicKey {
        &self.station
    }

    /// The prefix bound this context was built for.
    pub fn max_seq(&self) -> u64 {
        self.max_seq
    }

    /// Every identity that appears anywhere in the whole log — the enumeration an
    /// established-member sweep iterates. Order is not deterministic.
    pub fn known_addresses(&self) -> &[Address] {
        &self.known
    }

    /// The address's reputation from evidence alone, before identity anchoring —
    /// what [`anchoring_voucher`](Self::anchoring_voucher) judges a prospective
    /// voucher on. Memoized per `(address, at_time)`.
    pub fn score_raw(&self, address: &Address, at_time: i64) -> ReputationProfile {
        if let Some(cached) = self.raw_memo.borrow().get(&(*address, at_time)) {
            return cached.clone();
        }

        // The set of cases whose penalty has been lifted by a jury as of the
        // scoring instant (ADR-0021 §5).
        let overturned: HashSet<EquivocationId> = self
            .overturns
            .iter()
            .filter(|o| o.decided_at <= at_time)
            .map(|o| o.equivocation_id)
            .collect();

        let mut trade = DimensionTally::default();
        let mut attestation = DimensionTally::default();

        if let Some(times) = self.trade_times.get(address) {
            for &t in times {
                if t <= at_time {
                    trade.record(t);
                }
            }
        }
        if let Some(times) = self.attestation_times.get(address) {
            for &t in times {
                if t <= at_time {
                    attestation.record(t);
                }
            }
        }
        // Upheld-dispute penalties first, in ledger order — the old fold order.
        if let Some(times) = self.dispute_penalty_times.get(address) {
            for &t in times {
                if t <= at_time {
                    attestation.penalize();
                }
            }
        }
        // Then equivocation penalties, in log order: a proven, un-overturned
        // equivocation zeroes both live dimensions (ADR-0025).
        if let Some(entries) = self.equivocations_by_member.get(address) {
            for e in entries {
                if e.recorded_at > at_time || overturned.contains(&e.equivocation_id) {
                    continue;
                }
                if e.verified {
                    trade.penalize_by(EQUIVOCATION_WEIGHT);
                    attestation.penalize_by(EQUIVOCATION_WEIGHT);
                }
            }
        }

        let mut profile = ReputationProfile::empty(*address);
        profile.trade_reliability = trade.score(at_time);
        profile.attestation_accuracy = attestation.score(at_time);
        // The three dormant dimensions stay at their `empty()` zeros (ADR-0009).
        profile.last_updated = at_time;

        self.raw_memo
            .borrow_mut()
            .insert((*address, at_time), profile.clone());
        profile
    }

    /// The member whose vouch anchors `address`, if any: the first in log order to
    /// have vouched for it at or before `at_time` while holding a raw composite of
    /// at least [`ANCHOR_VOUCHER_MIN_COMPOSITE`]. The voucher is judged *raw* to
    /// keep the rule computable (a mutual vouch would otherwise not terminate).
    pub fn anchoring_voucher(&self, address: &Address, at_time: i64) -> Option<Address> {
        let refs = self.by_subject.get(address)?;
        for v in refs {
            if v.issued_at > at_time || v.voucher == *address {
                continue;
            }
            if self.score_raw(&v.voucher, at_time).composite() >= ANCHOR_VOUCHER_MIN_COMPOSITE {
                return Some(v.voucher);
            }
        }
        None
    }

    /// Whether `address` has an anchoring voucher as of `at_time`.
    pub fn is_anchored(&self, address: &Address, at_time: i64) -> bool {
        self.anchoring_voucher(address, at_time).is_some()
    }

    /// The address's **effective** reputation as of `at_time`: its raw profile held
    /// to the anchor cap when unanchored (ADR-0009).
    pub fn score(&self, address: &Address, at_time: i64) -> ReputationProfile {
        let raw = self.score_raw(address, at_time);
        anchored_profile(&raw, self.is_anchored(address, at_time))
    }

    /// Every known member whose effective composite is at or above the Member band
    /// as of `at_time`. Order follows [`known_addresses`](Self::known_addresses).
    pub fn established_members(&self, at_time: i64) -> Vec<Address> {
        self.known
            .iter()
            .filter(|a| self.score(a, at_time).composite() >= BAND_MEMBER_MIN)
            .copied()
            .collect()
    }

    /// How many members are established as of `at_time`.
    pub fn established_member_count(&self, at_time: i64) -> usize {
        self.known
            .iter()
            .filter(|a| self.score(a, at_time).composite() >= BAND_MEMBER_MIN)
            .count()
    }

    /// The governing electorate as of `at_time` (ADR-0015): the established set,
    /// unioned with `founders` while the community is still in bootstrap grace.
    pub fn grace_electorate(&self, founders: &[Address], at_time: i64) -> Vec<Address> {
        let mut electorate = self.established_members(at_time);
        if electorate.len() < BOOTSTRAP_GRACE_THRESHOLD {
            for founder in founders {
                if !electorate.contains(founder) {
                    electorate.push(*founder);
                }
            }
        }
        electorate
    }
}

/// The (sender, receiver) of a transaction state. Every lifecycle state carries
/// the proposal, so this is always defined.
fn parties_of(state: &TransactionState) -> (Address, Address) {
    match state {
        TransactionState::Proposed { proposal }
        | TransactionState::Confirmed { proposal, .. }
        | TransactionState::Settled { proposal, .. }
        | TransactionState::Cancelled { proposal, .. }
        | TransactionState::Disputed { proposal, .. } => {
            (proposal.payload.sender, proposal.payload.receiver)
        }
    }
}

/// The confirmation embedded in a transaction state, if it carries one.
fn confirmation_of(state: &TransactionState) -> Option<&TransactionConfirmation> {
    match state {
        TransactionState::Confirmed { confirmation, .. }
        | TransactionState::Settled { confirmation, .. } => Some(&confirmation.payload),
        _ => None,
    }
}

/// Running tally for one dimension: how many qualifying positive events, the total
/// penalty weight counted against it, and when the most recent positive event
/// happened (for decay).
#[derive(Default)]
struct DimensionTally {
    count: u32,
    /// Total penalty weight subtracted from the dimension. An upheld dispute adds
    /// [`EVENT_INCREMENT`]; a proven equivocation adds the heavier
    /// [`EQUIVOCATION_WEIGHT`]. Held as a weight (not a count) so inputs of
    /// different severities compose.
    penalty: f32,
    last_activity: Option<i64>,
}

impl DimensionTally {
    /// Folds in one positive event that occurred at `event_time`.
    fn record(&mut self, event_time: i64) {
        self.count += 1;
        self.last_activity = Some(match self.last_activity {
            Some(prev) => prev.max(event_time),
            None => event_time,
        });
    }

    /// Counts one upheld-dispute penalty against the dimension — a positive
    /// contribution later proven wrong (ADR-0014 §6). Subtracts a full
    /// [`EVENT_INCREMENT`].
    fn penalize(&mut self) {
        self.penalize_by(EVENT_INCREMENT);
    }

    /// Subtracts `weight` from the dimension. Deliberately does *not* touch
    /// `last_activity`: a penalty must not reset the decay clock and thereby
    /// preserve more of the positive score it is meant to erode. A dimension with
    /// no positive events stays at zero regardless — a dimension floors at zero,
    /// so there is nothing below neutral to reach.
    fn penalize_by(&mut self, weight: f32) {
        self.penalty += weight;
    }

    /// The dimension's score as of `at_time`: capped linear accrual less its
    /// penalties, then decayed from the most recent positive event, floored at
    /// zero. Zero when there is no positive evidence.
    fn score(&self, at_time: i64) -> f32 {
        let Some(last) = self.last_activity else {
            return 0.0;
        };
        let earned = (EVENT_INCREMENT * self.count as f32).min(DIMENSION_MAX);
        let net = earned - self.penalty;
        // `decayed` floors at zero, so a net driven negative by penalties reads as
        // a bottomed-out dimension rather than an impossible negative one.
        decayed(net, last, at_time)
    }
}
