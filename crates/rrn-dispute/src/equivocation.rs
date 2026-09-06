//! Equivocation cases: a distinct sortition-jury case kind (ADR-0025).
//!
//! A proven equivocation — a certificate overspend or an outbox-chain fork
//! (ADR-0021 §5) — is *not* "a dispute like any other". It has one subject (the
//! equivocator), not two parties; its evidence is cryptographic proof, not a
//! contested statement; it voids no transfer; and it must fail to a different
//! default than a transaction dispute. So per ADR-0025 it is adjudicated by the
//! **same** ADR-0014 sortition primitives — [`eligible_pool_excluding`],
//! [`draw_sequence`], [`resolve_panel`], [`tally`] — reused verbatim, but with its
//! own case derivation, seed, recusal set, ballot record, and enactment, leaving
//! the transaction-dispute path (and its shipped wire formats) untouched.
//!
//! # What differs from the transaction jury
//!
//! - **Case identity, not content address.** A case is keyed by the *offence*
//!   `(subject, basis, cert_id | fork position)`, so two proofs of one overspend
//!   are one case with one penalty, never two (ADR-0025 §1).
//! - **Admission-anchored seed.** The accused authors the evidence, so the draw is
//!   seeded from the *admission log position* of the round's opening record, never
//!   from accused-authored content — closing a panel-grinding vector (ADR-0025 §2).
//! - **Recusal by subject and injured payees.** The excluded set is
//!   `{subject} ∪ vouchers_of(subject) ∪ payees(conflicting commitments)`, computed
//!   at the round's admission position; voucher-recusal relaxes first, exactly as
//!   ADR-0014 does (ADR-0025 §3).
//! - **Jurors sign [`EquivocationBallot`]s** (a new kind); on a majority the
//!   *station* appends the terminal, station-signed
//!   [`EquivocationVerdictRecord`](rrn_ledger::escrow::EquivocationVerdictRecord)
//!   that reputation reads (ADR-0025 §4, and see the crate layering note below).
//! - **Three terminal states, and a lapse is [`Lapsed`](EquivResolution::Lapsed),
//!   never a synthesized confirm** (ADR-0025 §5). The reputation penalty applies at
//!   record verification (T2.3.3), so a lapse leaving it standing *is* ADR-0014's
//!   fail-open. A `Lapsed` case is **re-seatable** by any established member via an
//!   [`EquivocationReseat`] record, which opens a fresh round anchored to its own
//!   admission position.
//! - **Neutralize-only enactment.** `Overturn` lifts the reputation penalty (and
//!   the certificate-issuance gate); `Confirmed`/`Lapsed` touch no balances.
//!
//! # Why the station, not the jurors, writes the terminal record
//!
//! `rrn-reputation` sits *below* `rrn-dispute` in the dependency graph, so it
//! cannot re-derive a jury panel to learn a case's outcome. It reads one
//! authoritative, station-signed terminal `EquivocationVerdictRecord` instead —
//! which is exactly why the reputation `Overturn`-neutralization is gated on the
//! station signer. Juror ballots are a *separate* record kind
//! (`rrn.dispute.equivocation_ballot`) that reputation never decodes, so a juror's
//! ballot can never be mistaken for the terminal ruling.

use std::collections::{BTreeMap, HashMap, HashSet};

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::escrow::{
    CertId, EquivocationBasis, EquivocationId, EquivocationVerdictRecord, VerdictDecision,
};
use rrn_ledger::state::LedgerSnapshot;
use rrn_ledger::transaction::TransactionProposal;
use rrn_protocol::outbox::OutboxEntry;
use rrn_reputation::staking::grace_electorate;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::panel::{resolve_panel, tally, DisputeOutcome, Panel};
use crate::sortition::{draw_sequence, eligible_pool_excluding, vouchers_of_until};
use crate::{DisputeParams, Error, Result};

/// Domain-separation tag mixed into an equivocation case's sortition seed, kept
/// distinct from the transaction-dispute tag so the two case kinds can never draw
/// a colliding seed.
const EQUIV_SORTITION_DOMAIN: &[u8] = b"rrn.dispute.equivocation.sortition.v1";

/// Discriminant string carried in an [`EquivocationBallot`]'s canonical CBOR.
pub(crate) const EQUIV_BALLOT_KIND: &str = "rrn.dispute.equivocation_ballot";
/// Discriminant string carried in an [`EquivocationReseat`]'s canonical CBOR.
pub(crate) const EQUIV_RESEAT_KIND: &str = "rrn.dispute.equivocation_reseat";

/// A seated juror's signed ballot on an equivocation case (ADR-0025 §4).
///
/// Distinct from the transaction jury's [`JurorVerdict`](crate::verdict::JurorVerdict)
/// (keyed by `TransactionId`) and from the station's terminal
/// [`EquivocationVerdictRecord`](rrn_ledger::escrow::EquivocationVerdictRecord): a
/// ballot carries its `juror` and its `round`, so same-round ballots by different
/// jurors never collide on content-address dedup, and a ballot is never mistaken
/// for the terminal ruling reputation reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationBallot {
    /// A record id attached to the case being ruled on (any of the case's attached
    /// records; the derivation resolves it to the case identity).
    pub equivocation_id: EquivocationId,
    /// The juror casting the ballot (must hold a live seat in `round`'s panel).
    pub juror: Address,
    /// Which round of the case this ballot is cast in — a `Lapsed` case re-opens in
    /// a later round, and a ballot counts only in the round it names.
    pub round: u64,
    /// The juror's ruling: [`Confirm`](VerdictDecision::Confirm) affirms the
    /// evidence, [`Overturn`](VerdictDecision::Overturn) invalidates it.
    pub decision: VerdictDecision,
    /// Unix seconds when the juror says they cast the ballot. **Testimony only**
    /// (ADR-0022): the seat-window and tally arithmetic key on the ballot's
    /// admission time, never this value, so a late juror cannot backdate a ballot
    /// into their window.
    pub cast_at: i64,
}

/// An [`EquivocationBallot`] signed by the juror who cast it.
pub type SignedEquivocationBallot = SignedPayload<EquivocationBallot>;

/// An established member's signed request to re-seat a `Lapsed` equivocation case
/// (ADR-0025 §5).
///
/// A lapse leaves the reputation penalty standing (fail-open), but a small
/// community in bootstrap grace (ADR-0015) may lapse routinely and must be able to
/// try again. A re-seat opens a fresh round whose sortition seed and window are
/// anchored to *this record's own admission log position*, so the requester cannot
/// grind the seed by choosing when to ask (they do not choose their admission seq).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationReseat {
    /// A record id attached to the case to re-seat.
    pub equivocation_id: EquivocationId,
    /// The established member requesting the re-seat (must be the signer, and not
    /// the subject).
    pub requester: Address,
    /// The round this request opens — must be exactly one past the current
    /// (lapsed) round.
    pub round: u64,
    /// Unix seconds when the request was made (testimony/display only; the round's
    /// window runs from admission, not this value — ADR-0022).
    pub requested_at: i64,
}

/// An [`EquivocationReseat`] signed by the member who requested it.
pub type SignedEquivocationReseat = SignedPayload<EquivocationReseat>;

impl From<EquivocationBallot> for CBOR {
    fn from(b: EquivocationBallot) -> Self {
        let mut m = Map::new();
        m.insert("kind", EQUIV_BALLOT_KIND);
        m.insert("equivocation_id", b.equivocation_id);
        m.insert("juror", b.juror);
        m.insert("round", b.round);
        m.insert("decision", b.decision.as_str());
        m.insert("cast_at", b.cast_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EquivocationBallot {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != EQUIV_BALLOT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let decision = decision_from_str(&map.extract::<&str, String>("decision")?)
            .ok_or(dcbor::Error::WrongType)?;
        Ok(EquivocationBallot {
            equivocation_id: map.extract::<&str, EquivocationId>("equivocation_id")?,
            juror: map.extract::<&str, Address>("juror")?,
            round: map.extract::<&str, u64>("round")?,
            decision,
            cast_at: map.extract::<&str, i64>("cast_at")?,
        })
    }
}

impl From<EquivocationReseat> for CBOR {
    fn from(r: EquivocationReseat) -> Self {
        let mut m = Map::new();
        m.insert("kind", EQUIV_RESEAT_KIND);
        m.insert("equivocation_id", r.equivocation_id);
        m.insert("requester", r.requester);
        m.insert("round", r.round);
        m.insert("requested_at", r.requested_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EquivocationReseat {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != EQUIV_RESEAT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EquivocationReseat {
            equivocation_id: map.extract::<&str, EquivocationId>("equivocation_id")?,
            requester: map.extract::<&str, Address>("requester")?,
            round: map.extract::<&str, u64>("round")?,
            requested_at: map.extract::<&str, i64>("requested_at")?,
        })
    }
}

/// `Confirm`/`Overturn` string, shared with the terminal verdict's own encoding.
fn decision_from_str(s: &str) -> Option<VerdictDecision> {
    match s {
        "confirm" => Some(VerdictDecision::Confirm),
        "overturn" => Some(VerdictDecision::Overturn),
        _ => None,
    }
}

/// The terminal (or in-progress) state of an equivocation case after a resolution
/// pass — the equivocation analogue of [`Resolution`](crate::resolution::Resolution).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EquivResolution {
    /// The current round's jury is still sitting and its window is open.
    Pending,
    /// A jury affirmed the evidence; the penalty stands (terminal, final).
    Confirmed,
    /// A jury invalidated the evidence; the penalty was lifted this pass
    /// (neutralize-only enactment — a station `Overturn` verdict was appended).
    Overturned,
    /// The current round's window closed with no majority; the already-applied
    /// penalty stands (fail-open), and the case is re-seatable.
    Lapsed,
}

/// The offence an equivocation case is about, independent of how many records
/// prove it — the case's identity key (ADR-0025 §1).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IdentityKey {
    subject: [u8; 32],
    basis: u8,
    cert: Option<[u8; 32]>,
    position: Option<u64>,
}

/// One derived equivocation case: an offence identity, every record that proves
/// it, the injured payees, and round 0's admission anchor.
pub struct EquivCase {
    /// The case handle: the opening (earliest-admitted) record's content address.
    /// Ballots and re-seats may name any attached record; this is the canonical id.
    pub case_id: EquivocationId,
    /// The equivocator.
    pub subject: Address,
    /// What proved the equivocation.
    pub basis: EquivocationBasis,
    /// The certificate overspent, for a cert-overspend case.
    pub cert_id: Option<CertId>,
    /// The forked chain position, for an outbox-fork case.
    pub position: Option<u64>,
    /// Every verified record id attached to this offence (one on an honest
    /// station; more only on a hostile log copy). A terminal `Overturn` must
    /// neutralize *all* of them (ADR-0025 §4).
    pub attached: Vec<EquivocationId>,
    /// The counterparties about to eat the loss — recused as injured parties
    /// (ADR-0025 §3).
    pub payees: HashSet<Address>,
    /// Round 0's admission anchor: the opening record's `(seq, created_at)`.
    anchor_seq0: u64,
    opened_at0: i64,
}

impl EquivCase {
    /// The hard-recused set for this case: the subject and the injured payees, who
    /// are never eligible to judge it (ADR-0025 §3). Vouchers are the *soft* set,
    /// added per round from the round's admission position.
    fn hard_excluded(&self) -> HashSet<Address> {
        let mut set = self.payees.clone();
        set.insert(self.subject);
        set
    }

    /// The sortition seed for a round anchored at `anchor_seq` in community
    /// `anchor` (ADR-0025 §2): `Blake3(domain ‖ subject ‖ basis ‖ cert|position ‖
    /// anchor_seq ‖ community)`. Depends only on the offence identity and an
    /// admission log position — never on accused-authored content.
    fn seed(&self, anchor_seq: u64, anchor: &[u8]) -> [u8; 32] {
        let mut buf =
            Vec::with_capacity(EQUIV_SORTITION_DOMAIN.len() + 32 + 1 + 32 + 8 + anchor.len());
        buf.extend_from_slice(EQUIV_SORTITION_DOMAIN);
        buf.extend_from_slice(&self.subject.public_key().to_bytes());
        buf.push(basis_byte(self.basis));
        match self.basis {
            EquivocationBasis::CertOverspend => {
                if let Some(cert) = self.cert_id {
                    buf.extend_from_slice(&cert.to_bytes());
                }
            }
            EquivocationBasis::OutboxFork => {
                buf.extend_from_slice(&self.position.unwrap_or(0).to_le_bytes());
            }
        }
        buf.extend_from_slice(&anchor_seq.to_le_bytes());
        buf.extend_from_slice(anchor);
        Hash::of(&buf).to_bytes()
    }
}

/// The stable wire byte for a basis, used in the identity key and the seed.
fn basis_byte(basis: EquivocationBasis) -> u8 {
    match basis {
        EquivocationBasis::CertOverspend => 0,
        EquivocationBasis::OutboxFork => 1,
    }
}

/// The payees (loss-bearing counterparties) named in an equivocation's evidence —
/// the receivers of the conflicting commitments, recused as injured parties
/// (ADR-0025 §3). A cert-overspend item is a bare [`TransactionProposal`]; an
/// outbox-fork item is an [`OutboxEntry`] whose payee sits inside its wrapped
/// `record_bytes`. Evidence that wraps a non-payment record contributes no payee.
fn payees_of(evidence_bytes: &[Vec<u8>]) -> HashSet<Address> {
    let mut payees = HashSet::new();
    for b in evidence_bytes {
        if let Ok(p) = from_canonical_bytes::<TransactionProposal>(b) {
            payees.insert(p.receiver);
        } else if let Ok(entry) = from_canonical_bytes::<OutboxEntry>(b) {
            if let Ok(p) = from_canonical_bytes::<TransactionProposal>(&entry.record_bytes) {
                payees.insert(p.receiver);
            }
        }
    }
    payees
}

/// Derives every equivocation case on the log, keyed by offence identity
/// (ADR-0025 §1) — the set a resolution sweep iterates.
///
/// Records that did not verify at replay are already absent from
/// [`LedgerSnapshot::equivocations`], so every case here rests on proven evidence.
pub fn equivocation_cases(db: &Database) -> Result<Vec<EquivCase>> {
    let log = AppendLog::new(db);
    let snapshot = LedgerSnapshot::derive(&log)?;

    // Gather each verified record with its admission position, grouped by identity.
    struct Attached {
        id: EquivocationId,
        seq: u64,
        opened_at: i64,
        payees: HashSet<Address>,
    }
    let mut groups: BTreeMap<IdentityKey, Vec<Attached>> = BTreeMap::new();
    for rec in snapshot.equivocations() {
        let r = &rec.payload;
        // A verified record was admitted, so its admission position exists.
        let Some((seq, opened_at)) = log.admission_of(&r.equivocation_id.0)? else {
            continue;
        };
        let evidence: Vec<Vec<u8>> = r.evidence.iter().map(|e| e.bytes.clone()).collect();
        let key = IdentityKey {
            subject: r.member.public_key().to_bytes(),
            basis: basis_byte(r.basis),
            cert: r.cert_id.map(|c| c.to_bytes()),
            position: r.fork_position(),
        };
        groups.entry(key).or_default().push(Attached {
            id: r.equivocation_id,
            seq,
            opened_at,
            payees: payees_of(&evidence),
        });
    }

    let mut cases = Vec::with_capacity(groups.len());
    for (_key, mut attached) in groups {
        // Deterministic: the opener is the earliest-admitted record (min seq); ties
        // (impossible on one writer) break by content id.
        attached.sort_by(|a, b| {
            a.seq
                .cmp(&b.seq)
                .then(a.id.0.to_bytes().cmp(&b.id.0.to_bytes()))
        });
        let opener = &attached[0];
        // Recover the typed subject/basis/cert/position from the opening record.
        let rec = snapshot
            .equivocations()
            .find(|r| r.payload.equivocation_id == opener.id)
            .expect("opener came from this snapshot");
        let r = &rec.payload;
        let mut payees = HashSet::new();
        for a in &attached {
            payees.extend(a.payees.iter().copied());
        }
        cases.push(EquivCase {
            case_id: opener.id,
            subject: r.member,
            basis: r.basis,
            cert_id: r.cert_id,
            position: r.fork_position(),
            attached: attached.iter().map(|a| a.id).collect(),
            payees,
            anchor_seq0: opener.seq,
            opened_at0: opener.opened_at,
        });
    }
    Ok(cases)
}

/// The equivocation case a ballot or re-seat's `equivocation_id` belongs to, if
/// any — resolves any attached record id to its case identity (ADR-0025 §1).
pub fn case_for_record(db: &Database, id: &EquivocationId) -> Result<Option<EquivCase>> {
    Ok(equivocation_cases(db)?
        .into_iter()
        .find(|c| c.attached.contains(id)))
}

/// One round of a case: its index and its admission anchor.
#[derive(Clone, Copy)]
struct Round {
    index: u64,
    anchor_seq: u64,
    opened_at: i64,
}

/// The rounds a case has opened, in order, as of `now` — round 0 at the opening
/// record, then one per *valid* [`EquivocationReseat`] (ADR-0025 §5). A re-seat is
/// valid only if it opens the round after the current one, its previous round has
/// lapsed (window closed with no majority), and its requester was an established
/// non-subject member at its admission.
fn rounds(
    db: &Database,
    founders: &[Address],
    case: &EquivCase,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Vec<Round>> {
    let mut rounds = vec![Round {
        index: 0,
        anchor_seq: case.anchor_seq0,
        opened_at: case.opened_at0,
    }];

    let log = AppendLog::new(db);
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(reseat) = from_canonical_bytes::<EquivocationReseat>(&entry.payload.bytes) else {
            continue;
        };
        if !case.attached.contains(&reseat.equivocation_id) {
            continue;
        }
        // Admission time is the log entry's own `created_at` (ADR-0022); a re-seat
        // not yet admitted as of `now` does not open a round in this view.
        if entry.created_at > now {
            continue;
        }
        // The signer must be the requester (also enforced at append; re-checked so a
        // hostile log copy cannot smuggle a mismatched record into a round).
        if Address::from_public_key(entry.payload.signer) != reseat.requester {
            continue;
        }
        let cur = *rounds.last().expect("round 0 is always present");
        if reseat.round != cur.index + 1 {
            continue;
        }
        // The previous round must have lapsed: its window closed with no majority.
        let closed = cur.opened_at.saturating_add(params.window_seconds);
        if entry.created_at < closed {
            continue;
        }
        if round_decision(db, founders, case, &cur, params, anchor, entry.created_at)?.is_some() {
            continue;
        }
        // The requester must be an established, non-subject member at admission.
        if !reseat_eligible(db, founders, case, &reseat.requester, entry.created_at)? {
            continue;
        }
        rounds.push(Round {
            index: reseat.round,
            anchor_seq: entry.seq,
            opened_at: entry.created_at,
        });
    }
    Ok(rounds)
}

/// Whether `requester` is an established, non-subject member of the case's
/// electorate at `at_time` (ADR-0025 §5, using the grace electorate per ADR-0015).
fn reseat_eligible(
    db: &Database,
    founders: &[Address],
    case: &EquivCase,
    requester: &Address,
    at_time: i64,
) -> Result<bool> {
    if *requester == case.subject {
        return Ok(false);
    }
    Ok(grace_electorate(db, founders, at_time)?.contains(requester))
}

/// The seated panel for one round of a case as of `now` — the shared derivation
/// [`round_decision`] and the ballot append-gate both key off.
fn round_panel(
    db: &Database,
    founders: &[Address],
    case: &EquivCase,
    round: &Round,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Panel> {
    let hard = case.hard_excluded();
    let soft = vouchers_of_until(db, &case.subject, round.anchor_seq)?;
    let pool = eligible_pool_excluding(db, founders, round.opened_at, params, &hard, &soft)?;
    let sequence = draw_sequence(&pool, case.seed(round.anchor_seq, anchor));
    let ballots = round_ballots(db, case, round.index)?;
    Ok(resolve_panel(
        &sequence,
        &ballots,
        round.opened_at,
        params,
        now,
    ))
}

/// The decision a round has reached as of `now`, if a majority has formed —
/// mapping the shared [`tally`] onto the equivocation verdict space
/// (`Upheld` ⇒ `Overturn`, `Rejected` ⇒ `Confirm`). `None` while the jury is short
/// of a majority.
fn round_decision(
    db: &Database,
    founders: &[Address],
    case: &EquivCase,
    round: &Round,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<Option<VerdictDecision>> {
    let panel = round_panel(db, founders, case, round, params, anchor, now)?;
    Ok(tally(&panel, params).map(|o| match o {
        DisputeOutcome::Upheld => VerdictDecision::Overturn,
        DisputeOutcome::Rejected => VerdictDecision::Confirm,
    }))
}

/// Every juror's ballot in `round` of the case, keyed by juror, as
/// `(is_overturn, admitted_at)` — the map [`resolve_panel`] consumes. The time is
/// the ballot's **admission** `created_at`, never the juror-asserted `cast_at`
/// (ADR-0022): a party-signed timestamp must not enter seat-window or ordering
/// arithmetic, or a juror past their deadline could backdate a ballot inside their
/// window and flip (or, via `rounds()`, retroactively invalidate) a round. Keeps
/// the first ballot each juror was *admitted* with (a ballot is final), and only
/// from a signer who is the juror they name.
fn round_ballots(
    db: &Database,
    case: &EquivCase,
    round: u64,
) -> Result<HashMap<Address, (bool, i64)>> {
    let log = AppendLog::new(db);
    let mut out: HashMap<Address, (bool, i64)> = HashMap::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(ballot) = from_canonical_bytes::<EquivocationBallot>(&entry.payload.bytes) else {
            continue;
        };
        if ballot.round != round || !case.attached.contains(&ballot.equivocation_id) {
            continue;
        }
        // The signer must be the named juror (defends a hostile log copy).
        if Address::from_public_key(entry.payload.signer) != ballot.juror {
            continue;
        }
        out.entry(ballot.juror).or_insert((
            ballot.decision == VerdictDecision::Overturn,
            entry.created_at,
        ));
    }
    Ok(out)
}

/// What a resolution pass *would* return for a case as of `now`, without touching
/// the log — the read-only twin views render.
pub fn preview_equivocation(
    db: &Database,
    founders: &[Address],
    case: &EquivCase,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<EquivResolution> {
    decide_equivocation(db, founders, case, params, anchor, now)
}

/// The pure decision for a case as of `now`. A station-signed terminal ruling, if
/// one is on the log, is final; otherwise the current round's tally governs, and a
/// window that has closed with no majority is a lapse. Writes nothing.
fn decide_equivocation(
    db: &Database,
    founders: &[Address],
    case: &EquivCase,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<EquivResolution> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db))?;
    if let Some(decision) = terminal_of(&snapshot, case) {
        return Ok(match decision {
            VerdictDecision::Overturn => EquivResolution::Overturned,
            VerdictDecision::Confirm => EquivResolution::Confirmed,
        });
    }

    let rounds = rounds(db, founders, case, params, anchor, now)?;
    let cur = *rounds.last().expect("round 0 is always present");
    match round_decision(db, founders, case, &cur, params, anchor, now)? {
        Some(VerdictDecision::Overturn) => Ok(EquivResolution::Overturned),
        Some(VerdictDecision::Confirm) => Ok(EquivResolution::Confirmed),
        None if now >= cur.opened_at.saturating_add(params.window_seconds) => {
            Ok(EquivResolution::Lapsed)
        }
        None => Ok(EquivResolution::Pending),
    }
}

/// The station-signed terminal ruling recorded for any of a case's attached
/// records, if one exists (ADR-0025 §4: one terminal per attached record).
fn terminal_of(snapshot: &LedgerSnapshot, case: &EquivCase) -> Option<VerdictDecision> {
    case.attached
        .iter()
        .find_map(|id| snapshot.equivocation_terminal(id))
}

/// Resolves a case as of `now`: recomputes its current round and, on a terminal
/// decision, appends the station-signed terminal ruling — one
/// [`EquivocationVerdictRecord`] per attached record (ADR-0025 §4), so reputation's
/// per-record neutralization applies to every proof of the offence. Enactment is
/// **neutralize-only**: `Overturn` lifts the penalty and the issuance gate;
/// `Confirmed` records finality; neither touches a balance. Idempotent — once a
/// terminal ruling is on the log a later pass appends nothing.
pub fn resolve_equivocation(
    db: &Database,
    founders: &[Address],
    station: &Keypair,
    case: &EquivCase,
    params: &DisputeParams,
    anchor: &[u8],
    now: i64,
) -> Result<EquivResolution> {
    let outcome = decide_equivocation(db, founders, case, params, anchor, now)?;
    let decision = match outcome {
        EquivResolution::Overturned => VerdictDecision::Overturn,
        EquivResolution::Confirmed => VerdictDecision::Confirm,
        EquivResolution::Pending | EquivResolution::Lapsed => return Ok(outcome),
    };

    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db))?;
    for id in &case.attached {
        // Idempotent: never append a second terminal for a record already ruled on.
        if snapshot.equivocation_terminal(id).is_some() {
            continue;
        }
        let record = EquivocationVerdictRecord {
            equivocation_id: *id,
            decision,
            decided_at: now,
        };
        let signed = SignedPayload::sign(record, station);
        AppendLog::new(db).append(signed, now)?;
    }
    tracing::info!(case = ?case.case_id, subject = %case.subject, ?decision, "equivocation case ruled");
    Ok(outcome)
}

/// Records a juror's signed [`EquivocationBallot`], after checking they hold a live
/// seat in the named round (ADR-0025 §4).
///
/// Errors — without writing — on a bad signature or signer/juror mismatch
/// ([`Error::BadEquivocationBallot`]); no case for the named record
/// ([`Error::NoEquivocationCase`]); a ballot in an unknown round, cast outside that
/// round's window, or from a juror who does not hold a live seat then
/// ([`Error::NotSeated`]); or a second ballot from the same juror in that round
/// ([`Error::AlreadyVoted`]).
pub fn append_equivocation_ballot(
    db: &Database,
    founders: &[Address],
    params: &DisputeParams,
    anchor: &[u8],
    ballot: SignedEquivocationBallot,
    now: i64,
) -> Result<()> {
    ballot.verify().map_err(|_| Error::BadEquivocationBallot)?;
    let (equivocation_id, juror, round) = (
        ballot.payload.equivocation_id,
        ballot.payload.juror,
        ballot.payload.round,
    );
    if &ballot.signer != juror.public_key() {
        return Err(Error::BadEquivocationBallot);
    }

    let case = case_for_record(db, &equivocation_id)?.ok_or(Error::NoEquivocationCase)?;
    let rounds = rounds(db, founders, &case, params, anchor, now)?;
    let round_anchor = rounds
        .iter()
        .find(|r| r.index == round)
        .ok_or(Error::NotSeated)?;

    let existing = round_ballots(db, &case, round)?;
    if existing.contains_key(&juror) {
        return Err(Error::AlreadyVoted);
    }

    // Seat the juror as of the ballot's **admission** instant (`now`), never its
    // asserted `cast_at` (ADR-0022): the ballot is being admitted now, so the juror
    // must occupy a seat still awaiting a ruling as of now. A juror whose response
    // window already closed has had their seat redrawn, so this fails — a late
    // ballot cannot be backdated in. `cast_at` is retained on the record as
    // testimony only and enters no arithmetic.
    let panel = round_panel(db, founders, &case, round_anchor, params, anchor, now)?;
    match panel.seat_of(&juror) {
        Some(seat) if seat.verdict.is_none() => {}
        _ => return Err(Error::NotSeated),
    }

    AppendLog::new(db).append(ballot, now)?;
    tracing::info!(case = ?case.case_id, ?juror, round, "equivocation ballot recorded");
    Ok(())
}

/// Records an established member's signed [`EquivocationReseat`], re-opening a
/// `Lapsed` case in a fresh round (ADR-0025 §5).
///
/// Errors — without writing — on a bad signature or signer/requester mismatch
/// ([`Error::BadReseat`]); no case for the named record
/// ([`Error::NoEquivocationCase`]); or a request that does not open the round after
/// a genuinely lapsed current round, or whose requester is not an established
/// non-subject member ([`Error::NotReseatable`]).
pub fn append_equivocation_reseat(
    db: &Database,
    founders: &[Address],
    params: &DisputeParams,
    anchor: &[u8],
    reseat: SignedEquivocationReseat,
    now: i64,
) -> Result<()> {
    reseat.verify().map_err(|_| Error::BadReseat)?;
    let (equivocation_id, requester, round) = (
        reseat.payload.equivocation_id,
        reseat.payload.requester,
        reseat.payload.round,
    );
    if &reseat.signer != requester.public_key() {
        return Err(Error::BadReseat);
    }

    let case = case_for_record(db, &equivocation_id)?.ok_or(Error::NoEquivocationCase)?;

    // The case must currently be lapsed, and this request must open the very next
    // round. A terminal (confirmed/overturned) or still-pending case is not
    // re-seatable, and a round that does not follow the current one is refused.
    if decide_equivocation(db, founders, &case, params, anchor, now)? != EquivResolution::Lapsed {
        return Err(Error::NotReseatable);
    }
    let rounds = rounds(db, founders, &case, params, anchor, now)?;
    let cur = rounds.last().expect("round 0 is always present");
    if round != cur.index + 1 {
        return Err(Error::NotReseatable);
    }
    if !reseat_eligible(db, founders, &case, &requester, now)? {
        return Err(Error::NotReseatable);
    }

    AppendLog::new(db).append(reseat, now)?;
    tracing::info!(case = ?case.case_id, %requester, round, "equivocation case re-seated");
    Ok(())
}
