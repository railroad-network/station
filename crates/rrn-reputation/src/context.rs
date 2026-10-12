//! Scoring context — one replay of the log prefix, reused for a whole query.
//!
//! Every reputation question (a single score, an electorate, a jury draw, the
//! hourly snapshot sweep) is a pure function of the log. [`ScoringContext`]
//! builds the derived views **once** for a `(station, max_seq)` pair — one
//! [`LedgerSnapshot::derive_to`] and one log scan — indexes the evidence by
//! address, memoizes each raw profile, and answers every per-address question
//! from those in-memory tables, `O(N + A)` per query as ADR-0009 intends. Nothing
//! is stored: a context is a stack value, lives for exactly one query, and is
//! dropped. The log stays the only source of truth, and `reputation_snapshots`
//! stays a cache (ADR-0009).
//!
//! The public entry points in [`crate::scoring`], [`crate::sybil`],
//! [`crate::staking`] and [`crate::snapshot`] keep their signatures; each builds a
//! context and delegates. A caller making several queries at the same
//! `(at_time, max_seq)` can build one [`ScoringContext`] itself and reuse it.
//!
//! # How standing accrues (ADR-0038 Part B)
//!
//! - **Eligibility (§7, §8).** A positive event counts only when every party it
//!   names was enrolled before the entry that admitted it: both parties of a
//!   trade before its confirmation's entry, voucher and subject before the
//!   vouch's. A self-send earns nothing. A confirmation is credited to its
//!   confirmer only once its transaction settles. Penalties are not gated.
//! - **Event times (§9).** Trades and confirmations count at the station-signed
//!   `settled_at`; vouches at `issued_at`, which the live vouch doors bound to
//!   the station clock. No event time is a log entry's `created_at`.
//! - **The velocity cap (§10).** Each dimension credits at most one event per
//!   trailing week ([`crate::sybil::credited_events`]); an uncredited eligible
//!   event still counts as activity for decay.
//! - **Anchoring (§11).** A chain of trust from the `founder`-basis roots. Each
//!   anchoring edge is judged once, at the vouch, over the strictly shorter
//!   prefix before it; a later revocation of either party voids it for good.
//!   Decay never unanchors. The station identity is never anchored.
//! - **Established (§12).** Enrolled at the prefix end, anchored, effective
//!   composite at least the Member band, and not the station identity.
//!
//! To judge an edge "over the prefix before the vouch", every piece of evidence
//! carries the log position at which it entered the prefix, and a raw profile can
//! be taken over any shorter prefix ([`ScoringContext::score_raw_before`]).

use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::{decode_kinded, KindedCbor};
use rrn_identity::address::Address;
use rrn_identity::vouch::{Vouch, VOUCH_KIND_TAG};
use rrn_ledger::enrollment::{EnrollmentAction, EnrollmentBasis};
use rrn_ledger::escrow::{
    EquivocationBasis, EquivocationId, EquivocationRecord, EquivocationVerdictRecord,
    VerdictDecision, EQUIVOCATION_KIND, EQUIVOCATION_VERDICT_KIND,
};
use rrn_ledger::state::{CancelReason, LedgerSnapshot, TransactionState};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::decay::decayed;
use crate::model::{ReputationProfile, BAND_MEMBER_MIN, DIMENSION_MAX};
use crate::staking::BOOTSTRAP_GRACE_THRESHOLD;
use crate::sybil::{anchored_profile, credited_events, ANCHOR_VOUCHER_MIN_COMPOSITE};
use crate::Result;

/// Points one credited event contributes to its dimension, before capping and
/// decay. Protocol-locked (ADR-0009): 10 credited events reach [`DIMENSION_MAX`].
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

/// One scoring input: when it happened (the instant it is scored at) and the log
/// position at which it entered the prefix (so a raw profile can be taken over a
/// shorter prefix).
#[derive(Clone, Copy)]
struct Event {
    /// The event time: `settled_at` for a trade or confirmation, `issued_at` for
    /// a vouch, the record's own instant for a penalty or overturn.
    time: i64,
    /// Log seq of the entry that brought the event into the prefix.
    seq: u64,
}

/// One eligible vouch in the prefix (ADR-0038 §8): voucher and subject distinct,
/// both enrolled before the vouch's entry. Kept in ascending log order.
struct VouchRef {
    /// The address that signed the vouch (its author).
    voucher: Address,
    /// The vouched-for address.
    subject: Address,
    /// The vouch's signed issue time, bounded at the live doors (ADR-0038 §9).
    issued_at: i64,
    /// Log seq of the vouch's entry.
    seq: u64,
}

/// An anchoring edge (ADR-0038 §11): an eligible vouch whose voucher, over the
/// prefix strictly before the vouch, was anchored and held a raw composite of at
/// least [`ANCHOR_VOUCHER_MIN_COMPOSITE`] at the vouch's `issued_at`. Judged once,
/// when formed; never re-judged.
struct Edge {
    voucher: Address,
    subject: Address,
    issued_at: i64,
    seq: u64,
    /// The edge through which the voucher was anchored when this edge formed, or
    /// `None` when the voucher was a root then — the chain a portable history
    /// must carry for a verifier to form this edge the same way.
    witness: Option<usize>,
}

/// The anchored set at the prefix end, as of one scoring instant: each anchored
/// identity with the edge that first reached it (`None` for a root). Parent edges
/// always point at an identity added earlier, so following them never cycles and
/// always ends at a root.
type AnchoredSet = HashMap<Address, Option<usize>>;

/// A station-signed equivocation record in the prefix, against one member.
struct EquivEntry {
    /// The case id, so an `Overturn` verdict can neutralize it.
    equivocation_id: EquivocationId,
    /// When the record was recorded (the penalty applies from here onward).
    recorded_at: i64,
    /// Log seq of the record's entry.
    seq: u64,
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
    /// Log seq of the verdict's entry.
    seq: u64,
}

/// A read-only, in-memory view of the log prefix `[1, max_seq]` from which every
/// reputation question is answered without re-reading the log.
///
/// Built once per query (one ledger derivation, one log scan), used for as many
/// addresses as the query needs, then dropped. Nothing here is persisted: the log
/// stays the only source of truth (ADR-0009), and a context is exactly as
/// re-derivable as the profile it produces.
///
/// The evidence — ledger states, vouches, enrollments, equivocations and their
/// verdicts — is bounded to `[1, max_seq]` (ADR-0022 §5). The
/// [`known_addresses`](Self::known_addresses) set is *not* position-bounded: it
/// enumerates every party and voucher over the whole log — an address whose
/// evidence is all past `max_seq` scores empty and is excluded from any
/// established set either way.
///
/// The memos are `RefCell`s, so a context is `!Sync`: it is meant to be built,
/// used, and dropped on one thread within a single query.
pub struct ScoringContext {
    /// The community station key records are pinned to (ADR-0020).
    station: PublicKey,
    /// The station's own identity: never anchored, never established
    /// (ADR-0038 §1, §12).
    station_address: Address,
    /// The prefix bound this context was built for.
    max_seq: u64,
    /// The position just past the prefix — where "enrolled at the prefix" and
    /// "roots at the prefix" are judged (ADR-0038 §1, §11).
    end: u64,
    /// The prefix ledger, kept for its enrollment fold.
    ledger: LedgerSnapshot,
    /// Every identity that appears anywhere in the *whole* log, as a party or on
    /// either side of a vouch. Order is `HashSet`-derived (non-deterministic);
    /// callers that need a stable order sort it themselves.
    known: Vec<Address>,
    /// Eligible trade events per party.
    trade: HashMap<Address, Vec<Event>>,
    /// Eligible attestation events per address: confirmations of settled
    /// transactions and eligible vouches written.
    attestation: HashMap<Address, Vec<Event>>,
    /// Upheld-dispute penalties per confirmer, in ledger order.
    dispute_penalties: HashMap<Address, Vec<Event>>,
    /// Verified/unverified equivocation records per member, in log order.
    equivocations_by_member: HashMap<Address, Vec<EquivEntry>>,
    /// Every `Overturn` verdict in the prefix.
    overturns: Vec<OverturnEntry>,
    /// Every eligible vouch, in ascending log order.
    vouches: Vec<VouchRef>,
    /// The anchoring edges, in log order — formed lazily on the first anchoring
    /// question, since forming them scores each voucher.
    edges: OnceCell<Vec<Edge>>,
    /// Memoized raw profiles, keyed by `(address, at_time, before_seq)`.
    raw_memo: RefCell<HashMap<(Address, i64, u64), ReputationProfile>>,
    /// Memoized anchored sets at the prefix end, keyed by scoring instant.
    anchored_memo: RefCell<HashMap<i64, Rc<AnchoredSet>>>,
}

impl ScoringContext {
    /// Builds a context over the log prefix `[1, max_seq]`, pinning station-signed
    /// records to `station` (ADR-0020). `max_seq == u64::MAX` covers the whole log.
    pub fn new(db: &Database, station: &PublicKey, max_seq: u64) -> Result<Self> {
        let log = AppendLog::new(db);
        let station = *station;

        // Trade, confirmation, upheld-dispute evidence, certificate caps and the
        // enrollment fold come from the ledger state of the prefix.
        let ledger = LedgerSnapshot::derive_to(&log, max_seq, &station)?;

        // Known addresses are enumerated over the *whole* log (not the prefix).
        // When unbounded the prefix ledger already is the whole ledger; otherwise
        // derive it once more.
        let full_ledger_owned;
        let full_ledger: &LedgerSnapshot = if max_seq == u64::MAX {
            &ledger
        } else {
            full_ledger_owned = LedgerSnapshot::derive(&log, &station)?;
            &full_ledger_owned
        };

        let mut known: HashSet<Address> = HashSet::new();
        let mut trade: HashMap<Address, Vec<Event>> = HashMap::new();
        let mut attestation: HashMap<Address, Vec<Event>> = HashMap::new();
        let mut dispute_penalties: HashMap<Address, Vec<Event>> = HashMap::new();
        let mut equivocations_by_member: HashMap<Address, Vec<EquivEntry>> = HashMap::new();
        let mut overturns: Vec<OverturnEntry> = Vec::new();
        let mut vouches: Vec<VouchRef> = Vec::new();

        // Ledger parties over the whole log seed the known set.
        for (_, state) in full_ledger.iter() {
            let (sender, receiver) = parties_of(state);
            known.insert(sender);
            known.insert(receiver);
        }

        // Trade / confirmation / upheld-dispute evidence from the *prefix* ledger,
        // folded in ledger (`TransactionId`) order.
        for (id, state) in ledger.iter() {
            let admission = ledger.admission(id).copied().unwrap_or_default();
            match state {
                TransactionState::Settled {
                    proposal,
                    confirmation,
                    settled_at,
                } => {
                    let p = &proposal.payload;
                    // A self-send earns nothing, for anyone (ADR-0038 §7).
                    if p.sender == p.receiver {
                        continue;
                    }
                    // Both parties enrolled before the confirmation's entry
                    // (ADR-0038 §8); the event enters the prefix with its
                    // settlement.
                    let (Some(cseq), Some(sseq)) =
                        (admission.confirmation_seq, admission.settlement_seq)
                    else {
                        continue;
                    };
                    if !(ledger.is_enrolled_at(&p.sender, cseq)
                        && ledger.is_enrolled_at(&p.receiver, cseq))
                    {
                        continue;
                    }
                    let event = Event {
                        time: *settled_at,
                        seq: sseq,
                    };
                    trade.entry(p.sender).or_default().push(event);
                    trade.entry(p.receiver).or_default().push(event);
                    attestation
                        .entry(confirmation.payload.confirmer)
                        .or_default()
                        .push(event);
                }
                TransactionState::Cancelled {
                    proposal,
                    reason: CancelReason::DisputeUpheld,
                    cancelled_at,
                } => {
                    // Penalties are not gated on enrollment (ADR-0038 §8).
                    dispute_penalties
                        .entry(proposal.payload.receiver)
                        .or_default()
                        .push(Event {
                            time: *cancelled_at,
                            seq: admission.cancellation_seq.unwrap_or(0),
                        });
                }
                _ => {}
            }
        }

        // One pass over the whole log: known vouchers/subjects (unbounded), plus
        // the prefix's vouches, equivocations and verdicts (bounded to `max_seq`).
        // Each entry is parsed once and dispatched on its `kind` discriminator; a
        // malformed or unknown-kind entry is skipped.
        for entry in log.iter_from(1) {
            let entry = entry?;
            let signer = entry.payload.signer;
            let Ok(KindedCbor {
                kind: Some(kind),
                cbor,
            }) = decode_kinded(&entry.payload.bytes)
            else {
                continue;
            };

            if kind == VOUCH_KIND_TAG {
                let Ok(vouch) = Vouch::try_from(cbor) else {
                    continue;
                };
                let voucher = Address::from_public_key(signer);
                // Known addresses span the whole log, whatever the prefix bound.
                known.insert(voucher);
                known.insert(vouch.subject);
                // Eligible only when voucher and subject are distinct and both
                // enrolled before the vouch's own entry (ADR-0038 §8).
                if entry.seq <= max_seq
                    && voucher != vouch.subject
                    && ledger.is_enrolled_at(&voucher, entry.seq)
                    && ledger.is_enrolled_at(&vouch.subject, entry.seq)
                {
                    attestation.entry(voucher).or_default().push(Event {
                        time: vouch.issued_at,
                        seq: entry.seq,
                    });
                    vouches.push(VouchRef {
                        voucher,
                        subject: vouch.subject,
                        issued_at: vouch.issued_at,
                        seq: entry.seq,
                    });
                }
                continue;
            }

            // Everything below is station-authored (ADR-0020) and prefix-bounded:
            // a record signed by any other key, or admitted past `max_seq`, is
            // inert.
            if signer != station || entry.seq > max_seq {
                continue;
            }

            if kind == EQUIVOCATION_KIND {
                let Ok(record) = EquivocationRecord::try_from(cbor) else {
                    continue;
                };
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
                        seq: entry.seq,
                        verified,
                    });
                continue;
            }

            if kind == EQUIVOCATION_VERDICT_KIND {
                let Ok(verdict) = EquivocationVerdictRecord::try_from(cbor) else {
                    continue;
                };
                if verdict.decision == VerdictDecision::Overturn {
                    overturns.push(OverturnEntry {
                        equivocation_id: verdict.equivocation_id,
                        decided_at: verdict.decided_at,
                        seq: entry.seq,
                    });
                }
            }
        }

        Ok(Self {
            station,
            station_address: Address::from_public_key(station),
            max_seq,
            end: max_seq.saturating_add(1),
            ledger,
            known: known.into_iter().collect(),
            trade,
            attestation,
            dispute_penalties,
            equivocations_by_member,
            overturns,
            vouches,
            edges: OnceCell::new(),
            raw_memo: RefCell::new(HashMap::new()),
            anchored_memo: RefCell::new(HashMap::new()),
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

    /// Whether `address` is enrolled at the end of the prefix (ADR-0038 §1). The
    /// station identity is enrolled by derivation.
    pub fn is_enrolled(&self, address: &Address) -> bool {
        self.ledger.is_enrolled_at(address, self.end)
    }

    /// The address's reputation from evidence alone, before identity anchoring —
    /// what an anchoring edge judges a voucher on. Memoized per
    /// `(address, at_time)`.
    pub fn score_raw(&self, address: &Address, at_time: i64) -> ReputationProfile {
        self.score_raw_before(address, at_time, self.end)
    }

    /// [`score_raw`](Self::score_raw) over the shorter prefix of entries strictly
    /// before log position `before` — what judges a voucher at its vouch
    /// (ADR-0038 §11). `before` at or past the prefix end is the whole prefix.
    pub fn score_raw_before(
        &self,
        address: &Address,
        at_time: i64,
        before: u64,
    ) -> ReputationProfile {
        let before = before.min(self.end);
        let key = (*address, at_time, before);
        if let Some(cached) = self.raw_memo.borrow().get(&key) {
            return cached.clone();
        }
        let counts = |e: &Event| e.time <= at_time && e.seq < before;

        // The set of cases whose penalty has been lifted by a jury as of the
        // scoring instant (ADR-0021 §5).
        let overturned: HashSet<EquivocationId> = self
            .overturns
            .iter()
            .filter(|o| o.decided_at <= at_time && o.seq < before)
            .map(|o| o.equivocation_id)
            .collect();

        let mut trade = DimensionTally::default();
        let mut attestation = DimensionTally::default();

        for e in self.trade.get(address).into_iter().flatten() {
            if counts(e) {
                trade.record(e.time);
            }
        }
        for e in self.attestation.get(address).into_iter().flatten() {
            if counts(e) {
                attestation.record(e.time);
            }
        }
        // Upheld-dispute penalties first, in ledger order.
        for e in self.dispute_penalties.get(address).into_iter().flatten() {
            if counts(e) {
                attestation.penalize();
            }
        }
        // Then equivocation penalties, in log order: a proven, un-overturned
        // equivocation zeroes both live dimensions (ADR-0025).
        for e in self
            .equivocations_by_member
            .get(address)
            .into_iter()
            .flatten()
        {
            if e.recorded_at > at_time || e.seq >= before || overturned.contains(&e.equivocation_id)
            {
                continue;
            }
            if e.verified {
                trade.penalize_by(EQUIVOCATION_WEIGHT);
                attestation.penalize_by(EQUIVOCATION_WEIGHT);
            }
        }

        let mut profile = ReputationProfile::empty(*address);
        profile.trade_reliability = trade.score(at_time);
        profile.attestation_accuracy = attestation.score(at_time);
        // The three dormant dimensions stay at their `empty()` zeros (ADR-0009).
        profile.last_updated = at_time;

        self.raw_memo.borrow_mut().insert(key, profile.clone());
        profile
    }

    /// Whether `address` is a root at log position `p`: enrolled there with
    /// current basis `founder` (ADR-0038 §11). The station identity has no basis,
    /// so it is never a root.
    fn is_root(&self, address: &Address, p: u64) -> bool {
        *address != self.station_address
            && self.ledger.enrollment_basis_at(address, p) == Some(EnrollmentBasis::Founder)
    }

    /// Whether `address` was revoked by an effective revocation admitted strictly
    /// between positions `after` and `before`.
    fn revoked_between(&self, address: &Address, after: u64, before: u64) -> bool {
        self.ledger
            .enrollment_events(address)
            .iter()
            .any(|e| e.action == EnrollmentAction::Revoke && e.seq > after && e.seq < before)
    }

    /// Whether `edge` is void at position `p`: either party was revoked after it
    /// formed and before `p`, even if later re-enrolled (ADR-0038 §11).
    fn is_void_at(&self, edge: &Edge, p: u64) -> bool {
        self.revoked_between(&edge.voucher, edge.seq, p)
            || self.revoked_between(&edge.subject, edge.seq, p)
    }

    /// The anchored set at position `p` over `edges`, counting only edges formed
    /// before `p`, not void at `p`, and issued at or before `at_time` — the least
    /// fixed point of ADR-0038 §11, grown from the roots at `p`. Each member maps
    /// to the edge that first reached it (`None` for a root).
    fn reach(&self, edges: &[Edge], p: u64, at_time: i64) -> AnchoredSet {
        let live: Vec<usize> = (0..edges.len())
            .filter(|&i| {
                let e = &edges[i];
                e.seq < p && e.issued_at <= at_time && !self.is_void_at(e, p)
            })
            .collect();
        let mut set = AnchoredSet::new();
        // Monotone over a finite set of identities: each pass either adds one
        // or stops.
        loop {
            let mut grew = false;
            for &i in &live {
                let e = &edges[i];
                if set.contains_key(&e.subject) || e.subject == self.station_address {
                    continue;
                }
                // A voucher not yet reached joins as a root, or the edge waits.
                if let std::collections::hash_map::Entry::Vacant(slot) = set.entry(e.voucher) {
                    if !self.is_root(&e.voucher, p) {
                        continue;
                    }
                    slot.insert(None);
                }
                let parent = if self.is_root(&e.subject, p) {
                    None
                } else {
                    Some(i)
                };
                set.insert(e.subject, parent);
                grew = true;
            }
            if !grew {
                return set;
            }
        }
    }

    /// The anchoring edges, formed in log order on first use. An eligible vouch
    /// forms an edge when, over the prefix strictly before it, its voucher was
    /// anchored and held a raw composite of at least
    /// [`ANCHOR_VOUCHER_MIN_COMPOSITE`] at the vouch's `issued_at` (ADR-0038 §11).
    /// Whether an edge forms depends only on earlier edges, so this is
    /// well-founded.
    fn edges(&self) -> &[Edge] {
        self.edges.get_or_init(|| {
            let mut edges: Vec<Edge> = Vec::new();
            for v in &self.vouches {
                if v.voucher == self.station_address || v.subject == self.station_address {
                    continue;
                }
                let witness = if self.is_root(&v.voucher, v.seq) {
                    None
                } else {
                    match self.reach(&edges, v.seq, i64::MAX).get(&v.voucher) {
                        Some(&parent) => parent,
                        None => continue,
                    }
                };
                if self
                    .score_raw_before(&v.voucher, v.issued_at, v.seq)
                    .composite()
                    < ANCHOR_VOUCHER_MIN_COMPOSITE
                {
                    continue;
                }
                edges.push(Edge {
                    voucher: v.voucher,
                    subject: v.subject,
                    issued_at: v.issued_at,
                    seq: v.seq,
                    witness,
                });
            }
            edges
        })
    }

    /// The anchored set at the prefix end, counting edges issued at or before
    /// `at_time`. Memoized per instant.
    fn anchored_set(&self, at_time: i64) -> Rc<AnchoredSet> {
        if let Some(set) = self.anchored_memo.borrow().get(&at_time) {
            return Rc::clone(set);
        }
        let set = Rc::new(self.reach(self.edges(), self.end, at_time));
        self.anchored_memo
            .borrow_mut()
            .insert(at_time, Rc::clone(&set));
        set
    }

    /// Whether `address` is anchored at the prefix end as of `at_time`: a root, or
    /// reached from a root over non-void anchoring edges (ADR-0038 §11). The
    /// station identity never is.
    pub fn is_anchored(&self, address: &Address, at_time: i64) -> bool {
        if *address == self.station_address {
            return false;
        }
        self.is_root(address, self.end) || self.anchored_set(at_time).contains_key(address)
    }

    /// The member whose vouch anchors `address` on its chain to a root, as of
    /// `at_time`. `None` for a root (anchored by definition) and for an
    /// unanchored identity — so callers asking "is it anchored" use
    /// [`is_anchored`](Self::is_anchored).
    pub fn anchoring_voucher(&self, address: &Address, at_time: i64) -> Option<Address> {
        if !self.is_anchored(address, at_time) || self.is_root(address, self.end) {
            return None;
        }
        let parent = (*self.anchored_set(at_time).get(address)?)?;
        Some(self.edges()[parent].voucher)
    }

    /// Every identity a verifier needs the evidence of to reach the same
    /// anchoring verdict for `address` (ADR-0038 §11, ADR-0032 §1): each voucher
    /// on its chain to a root at the prefix end, and, for each edge on that
    /// chain, the chain that anchored its voucher when the edge formed — down to
    /// the roots. Empty for a root or an unanchored identity. Order is
    /// unspecified.
    pub fn anchor_chain(&self, address: &Address, at_time: i64) -> Vec<Address> {
        if !self.is_anchored(address, at_time) {
            return Vec::new();
        }
        let edges = self.edges();
        let set = self.anchored_set(at_time);
        let mut pending: Vec<usize> = Vec::new();
        let mut cursor = *address;
        let mut on_path: HashSet<Address> = HashSet::new();
        while let Some(&Some(i)) = set.get(&cursor) {
            if !on_path.insert(cursor) {
                break;
            }
            pending.push(i);
            cursor = edges[i].voucher;
        }
        let mut seen_edges: HashSet<usize> = HashSet::new();
        let mut seen: HashSet<Address> = HashSet::new();
        let mut chain = Vec::new();
        while let Some(i) = pending.pop() {
            if !seen_edges.insert(i) {
                continue;
            }
            let voucher = edges[i].voucher;
            if seen.insert(voucher) {
                chain.push(voucher);
            }
            if let Some(w) = edges[i].witness {
                pending.push(w);
            }
        }
        chain
    }

    /// The address's **effective** reputation as of `at_time`: its raw profile held
    /// to the anchor cap when unanchored (ADR-0009).
    pub fn score(&self, address: &Address, at_time: i64) -> ReputationProfile {
        let raw = self.score_raw(address, at_time);
        anchored_profile(&raw, self.is_anchored(address, at_time))
    }

    /// Whether `address` is established as of `at_time` (ADR-0038 §12): enrolled
    /// at the prefix end, anchored, effective composite at or above the Member
    /// band, and not the station identity.
    fn is_established(&self, address: &Address, at_time: i64) -> bool {
        *address != self.station_address
            && self.is_enrolled(address)
            && self.score(address, at_time).composite() >= BAND_MEMBER_MIN
    }

    /// Every known member who is established as of `at_time` (ADR-0038 §12).
    /// Order follows [`known_addresses`](Self::known_addresses).
    pub fn established_members(&self, at_time: i64) -> Vec<Address> {
        self.known
            .iter()
            .filter(|a| self.is_established(a, at_time))
            .copied()
            .collect()
    }

    /// How many members are established as of `at_time`.
    pub fn established_member_count(&self, at_time: i64) -> usize {
        self.known
            .iter()
            .filter(|a| self.is_established(a, at_time))
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

/// Running tally for one dimension: the eligible positive event times and the
/// total penalty weight counted against it.
#[derive(Default)]
struct DimensionTally {
    /// Eligible positive event times, in any order — the credit is a pure
    /// function of the sorted times ([`credited_events`]).
    events: Vec<i64>,
    /// Total penalty weight subtracted from the dimension. An upheld dispute adds
    /// [`EVENT_INCREMENT`]; a proven equivocation adds the heavier
    /// [`EQUIVOCATION_WEIGHT`]. Held as a weight (not a count) so inputs of
    /// different severities compose.
    penalty: f32,
}

impl DimensionTally {
    /// Folds in one eligible positive event that occurred at `event_time`.
    fn record(&mut self, event_time: i64) {
        self.events.push(event_time);
    }

    /// Counts one upheld-dispute penalty against the dimension — a positive
    /// contribution later proven wrong (ADR-0014 §6). Subtracts a full
    /// [`EVENT_INCREMENT`].
    fn penalize(&mut self) {
        self.penalize_by(EVENT_INCREMENT);
    }

    /// Subtracts `weight` from the dimension. A penalty is not activity: it does
    /// not reset the decay clock and thereby preserve more of the positive score
    /// it is meant to erode. A dimension with no positive events stays at zero
    /// regardless — a dimension floors at zero.
    fn penalize_by(&mut self, weight: f32) {
        self.penalty += weight;
    }

    /// The dimension's score as of `at_time`: the credited events' capped linear
    /// accrual (at most one per trailing week, ADR-0038 §10) less its penalties,
    /// decayed from the most recent eligible event — credited or not, since an
    /// active member is not decaying — and floored at zero. Zero when there is no
    /// positive evidence.
    fn score(&self, at_time: i64) -> f32 {
        let Some(&last) = self.events.iter().max() else {
            return 0.0;
        };
        let credited = credited_events(&self.events).len();
        let earned = (EVENT_INCREMENT * credited as f32).min(DIMENSION_MAX);
        let net = earned - self.penalty;
        // `decayed` floors at zero, so a net driven negative by penalties reads as
        // a bottomed-out dimension rather than an impossible negative one.
        decayed(net, last, at_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionId, TransactionProposal};
    use rrn_storage::migrations;

    use crate::model::BAND_MEMBER_MIN;
    use crate::testutil::{enroll, establish_members, revoke, settle_trade, vouch, WEEK};

    const MONTH: i64 = 30 * 86_400;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    fn ctx(db: &Database, station: &Keypair) -> ScoringContext {
        ScoringContext::unbounded(db, &station.public_key()).unwrap()
    }

    fn enrolled(db: &Database, station: &Keypair, who: &Keypair) {
        enroll(db, station, &addr(who), EnrollmentBasis::Pairing, 0);
    }

    /// A proposal and its confirmation, raw-appended and left unsettled.
    fn propose_and_confirm(
        db: &Database,
        from: &Keypair,
        to: &Keypair,
        nonce: u64,
        at: i64,
    ) -> TransactionId {
        let mut log = AppendLog::new(db);
        let proposal =
            TransactionProposal::new(addr(from), addr(to), 300, None, nonce, 1, i64::MAX / 2);
        let id = proposal.id;
        log.append(SignedPayload::sign(proposal, from), at).unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(to),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, to), at)
            .unwrap();
        id
    }

    fn settle(
        db: &Database,
        station: &Keypair,
        id: TransactionId,
        from: &Keypair,
        to: &Keypair,
        at: i64,
    ) {
        let settlement = SettlementRecord {
            proposal_id: id,
            sender: addr(from),
            receiver: addr(to),
            amount_centi: 300,
            settled_at: at,
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(settlement, station), at)
            .unwrap();
    }

    /// An enrolled, non-root member with raw standing over the band: ten weekly
    /// trades in from `partner` (enrolled), ending at `last`.
    fn raw_standing(
        db: &Database,
        station: &Keypair,
        partner: &Keypair,
        nonce0: u64,
        last: i64,
    ) -> Keypair {
        let who = Keypair::generate();
        enrolled(db, station, &who);
        for w in 0..10 {
            settle_trade(
                db,
                station,
                partner,
                &who,
                nonce0 + w,
                last - (9 - w as i64) * WEEK,
            );
        }
        who
    }

    #[test]
    fn self_sends_on_the_log_earn_nothing() {
        // Raw-appended past the engine's front door (ADR-0038 §7).
        let db = fresh_db();
        let (alice, station) = (Keypair::generate(), Keypair::generate());
        enrolled(&db, &station, &alice);
        for w in 0..10 {
            settle_trade(&db, &station, &alice, &alice, w, MONTH + w as i64 * WEEK);
        }
        let raw = ctx(&db, &station).score_raw(&addr(&alice), 6 * MONTH);
        assert_eq!(raw.composite(), 0.0);
    }

    #[test]
    fn an_unenrolled_party_earns_nothing_for_either_side() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 6 * MONTH;
        enrolled(&db, &station, &alice);
        // Bob is not enrolled: the trade credits neither side.
        settle_trade(&db, &station, &alice, &bob, 0, t);
        let c = ctx(&db, &station);
        assert_eq!(c.score_raw(&addr(&alice), t).composite(), 0.0);
        assert_eq!(c.score_raw(&addr(&bob), t).composite(), 0.0);

        // Enrolling bob afterwards does not credit the earlier trade...
        enrolled(&db, &station, &bob);
        let c = ctx(&db, &station);
        assert_eq!(c.score_raw(&addr(&alice), t).composite(), 0.0);
        assert_eq!(c.score_raw(&addr(&bob), t).composite(), 0.0);

        // ...but a trade after it counts for both.
        settle_trade(&db, &station, &alice, &bob, 1, t + WEEK);
        let c = ctx(&db, &station);
        assert!(approx(
            c.score_raw(&addr(&alice), t + WEEK).trade_reliability,
            0.5
        ));
        assert!(approx(
            c.score_raw(&addr(&bob), t + WEEK).trade_reliability,
            0.5
        ));
        assert!(approx(
            c.score_raw(&addr(&bob), t + WEEK).attestation_accuracy,
            0.5
        ));
    }

    #[test]
    fn a_confirmation_is_credited_only_once_settled() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 6 * MONTH;
        enrolled(&db, &station, &alice);
        enrolled(&db, &station, &bob);
        let id = propose_and_confirm(&db, &alice, &bob, 0, t);
        let raw = ctx(&db, &station).score_raw(&addr(&bob), t + WEEK);
        assert_eq!(
            raw.composite(),
            0.0,
            "a confirmed, unsettled trade credits no one"
        );

        settle(&db, &station, id, &alice, &bob, t + WEEK);
        let raw = ctx(&db, &station).score_raw(&addr(&bob), t + WEEK);
        assert!(approx(raw.attestation_accuracy, 0.5));
        assert!(approx(raw.trade_reliability, 0.5));
        // Credited at the settlement, not the confirmation.
        assert_eq!(
            ctx(&db, &station).score_raw(&addr(&bob), t).composite(),
            0.0
        );
    }

    #[test]
    fn one_event_per_dimension_per_week() {
        let trade_after = |gap: i64| {
            let db = fresh_db();
            let (alice, bob, station) = (
                Keypair::generate(),
                Keypair::generate(),
                Keypair::generate(),
            );
            enrolled(&db, &station, &alice);
            enrolled(&db, &station, &bob);
            let t0 = 6 * MONTH;
            for i in 0..10 {
                settle_trade(&db, &station, &alice, &bob, i, t0 + i as i64 * gap);
            }
            let last = t0 + 9 * gap;
            ctx(&db, &station)
                .score_raw(&addr(&alice), last)
                .trade_reliability
        };
        // Ten trades in one day credit once.
        assert!(approx(trade_after(60), 0.5));
        // Ten trades exactly a week apart all credit.
        assert!(approx(trade_after(WEEK), 5.0));
        // A second short of a week: every other one credits.
        assert!(approx(trade_after(WEEK - 1), 2.5));
    }

    #[test]
    fn an_uncredited_event_still_counts_as_activity_for_decay() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        enrolled(&db, &station, &alice);
        enrolled(&db, &station, &bob);
        let t0 = 6 * MONTH;
        settle_trade(&db, &station, &alice, &bob, 0, t0);
        // Inside the window, so uncredited — but it moves the decay clock.
        settle_trade(&db, &station, &alice, &bob, 1, t0 + WEEK - 1);
        let at = t0 + WEEK - 1;
        assert!(approx(
            ctx(&db, &station)
                .score_raw(&addr(&alice), at)
                .trade_reliability,
            0.5
        ));
    }

    #[test]
    fn an_established_but_unanchored_voucher_cannot_anchor() {
        let db = fresh_db();
        let station = Keypair::generate();
        let partner = Keypair::generate();
        enrolled(&db, &station, &partner);
        let t = 30 * WEEK;
        let a = raw_standing(&db, &station, &partner, 0, t);
        let b = raw_standing(&db, &station, &partner, 10, t);
        // Both clear the band raw, and vouch for each other: neither is a root,
        // so neither is anchored (the patient pair ADR-0009 left open).
        vouch(&db, &a, &addr(&b), t);
        vouch(&db, &b, &addr(&a), t);
        let c = ctx(&db, &station);
        assert!(c.score_raw(&addr(&a), t).composite() >= ANCHOR_VOUCHER_MIN_COMPOSITE);
        assert!(!c.is_anchored(&addr(&a), t));
        assert!(!c.is_anchored(&addr(&b), t));

        // An established root vouches for `a`: anchored.
        let root = establish_members(&db, &station, 2, t).remove(0);
        vouch(&db, &root, &addr(&a), t + 1);
        let c = ctx(&db, &station);
        assert!(c.is_anchored(&addr(&a), t + 1));
        assert_eq!(c.anchoring_voucher(&addr(&a), t + 1), Some(addr(&root)));
        // `a`'s earlier vouch for `b` was made before `a` qualified: it is never
        // judged again, so `b` stays unanchored.
        assert!(!c.is_anchored(&addr(&b), t + 1));

        // A fresh vouch from the now-anchored `a` forms the second link.
        vouch(&db, &a, &addr(&b), t + 2);
        let c = ctx(&db, &station);
        assert!(c.is_anchored(&addr(&b), t + 2));
        assert_eq!(c.anchoring_voucher(&addr(&b), t + 2), Some(addr(&a)));
        let chain: HashSet<Address> = c.anchor_chain(&addr(&b), t + 2).into_iter().collect();
        assert_eq!(chain, HashSet::from([addr(&a), addr(&root)]));
    }

    #[test]
    fn a_root_anchors_only_once_established() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (founder, partner, newcomer) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        enroll(&db, &station, &addr(&founder), EnrollmentBasis::Founder, 0);
        enrolled(&db, &station, &partner);
        enrolled(&db, &station, &newcomer);
        let t0 = 6 * MONTH;
        // A founder is a root, but with no standing yet its vouch forms no edge.
        vouch(&db, &founder, &addr(&newcomer), t0);
        let c = ctx(&db, &station);
        assert!(c.is_anchored(&addr(&founder), t0));
        assert!(!c.is_anchored(&addr(&newcomer), t0));

        // The founder earns standing over ten weeks...
        for w in 0..10 {
            settle_trade(
                &db,
                &station,
                &partner,
                &founder,
                w,
                t0 + (w as i64 + 1) * WEEK,
            );
        }
        let t1 = t0 + 10 * WEEK;
        // ...which does not revive the earlier vouch.
        assert!(!ctx(&db, &station).is_anchored(&addr(&newcomer), t1));
        // A fresh vouch does anchor.
        vouch(&db, &founder, &addr(&newcomer), t1);
        assert!(ctx(&db, &station).is_anchored(&addr(&newcomer), t1));
    }

    #[test]
    fn decay_never_unanchors() {
        let db = fresh_db();
        let station = Keypair::generate();
        let subject = Keypair::generate();
        enrolled(&db, &station, &subject);
        let t = 20 * WEEK;
        let root = establish_members(&db, &station, 2, t).remove(0);
        vouch(&db, &root, &addr(&subject), t);
        // Thirty months on, the root's standing has decayed below the anchoring
        // bar, but the edge was judged at the vouch and stands.
        let later = t + 30 * MONTH;
        let c = ctx(&db, &station);
        assert!(c.score_raw(&addr(&root), later).composite() < ANCHOR_VOUCHER_MIN_COMPOSITE);
        assert!(c.is_anchored(&addr(&subject), later));
    }

    #[test]
    fn an_edge_is_judged_over_the_prefix_before_the_vouch() {
        // The founder's trades are confirmed before its vouch but settled only
        // after it, with settlement times that precede the vouch's `issued_at`.
        // At the vouch the founder had no standing on the log, so no edge forms.
        let db = fresh_db();
        let station = Keypair::generate();
        let (founder, partner, subject) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        enroll(&db, &station, &addr(&founder), EnrollmentBasis::Founder, 0);
        enrolled(&db, &station, &partner);
        enrolled(&db, &station, &subject);
        let t0 = 6 * MONTH;
        let ids: Vec<TransactionId> = (0..10)
            .map(|w| propose_and_confirm(&db, &partner, &founder, w, t0))
            .collect();
        let at_vouch = t0 + 10 * WEEK;
        vouch(&db, &founder, &addr(&subject), at_vouch);
        for (w, id) in ids.into_iter().enumerate() {
            settle(&db, &station, id, &partner, &founder, t0 + w as i64 * WEEK);
        }
        let c = ctx(&db, &station);
        assert!(c.score_raw(&addr(&founder), at_vouch).composite() >= ANCHOR_VOUCHER_MIN_COMPOSITE);
        assert!(!c.is_anchored(&addr(&subject), at_vouch));
    }

    #[test]
    fn a_revoked_voucher_stops_anchoring() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (partner, subject) = (Keypair::generate(), Keypair::generate());
        enrolled(&db, &station, &partner);
        enrolled(&db, &station, &subject);
        let t = 20 * WEEK;
        let root = establish_members(&db, &station, 2, t).remove(0);
        // root → link → subject.
        let link = raw_standing(&db, &station, &partner, 0, t);
        vouch(&db, &root, &addr(&link), t);
        vouch(&db, &link, &addr(&subject), t + 1);
        assert!(ctx(&db, &station).is_anchored(&addr(&subject), t + 1));

        // Revoking the root voids its edge, and the chain behind it cascades.
        revoke(&db, &station, &addr(&root), t + 2);
        let c = ctx(&db, &station);
        assert!(!c.is_anchored(&addr(&root), t + 2));
        assert!(!c.is_anchored(&addr(&link), t + 2));
        assert!(!c.is_anchored(&addr(&subject), t + 2));

        // Re-enrolling the root restores neither its root status (basis
        // `pairing` now) nor the void edge.
        enrolled(&db, &station, &root);
        let c = ctx(&db, &station);
        assert!(c.is_enrolled(&addr(&root)));
        assert!(!c.is_anchored(&addr(&root), t + 2));
        assert!(!c.is_anchored(&addr(&subject), t + 2));
    }

    #[test]
    fn established_requires_current_enrollment() {
        let db = fresh_db();
        let station = Keypair::generate();
        let t = 20 * WEEK;
        let members = establish_members(&db, &station, 3, t);
        assert_eq!(ctx(&db, &station).established_member_count(t), 3);

        revoke(&db, &station, &addr(&members[0]), t);
        let c = ctx(&db, &station);
        assert_eq!(c.established_member_count(t), 2);
        assert!(!c.established_members(t).contains(&addr(&members[0])));
        // Revocation does not erase standing already earned (ADR-0038 §5).
        assert!(c.score_raw(&addr(&members[0]), t).composite() >= BAND_MEMBER_MIN);
    }

    #[test]
    fn the_station_is_never_anchored_or_established() {
        let db = fresh_db();
        let station = Keypair::generate();
        let partner = Keypair::generate();
        enrolled(&db, &station, &partner);
        let t = 20 * WEEK;
        let root = establish_members(&db, &station, 2, t).remove(0);
        // The station identity trades (eligible: it is enrolled by derivation)
        // and an established root vouches for it.
        for w in 0..10 {
            settle_trade(&db, &station, &partner, &station, w, t + w as i64 * WEEK);
        }
        let at = t + 10 * WEEK;
        vouch(&db, &root, &addr(&station), at);
        let c = ctx(&db, &station);
        assert!(c.score_raw(&addr(&station), at).composite() >= BAND_MEMBER_MIN);
        assert!(!c.is_anchored(&addr(&station), at));
        assert!(!c.established_members(at).contains(&addr(&station)));
        // Its trades still count for the enrolled member on the other side.
        assert!(c.score_raw(&addr(&partner), at).trade_reliability > 0.0);
    }
}
