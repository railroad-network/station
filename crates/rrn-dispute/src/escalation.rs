//! The optional governance escalation and appeal path (ADR-0014 §5).
//!
//! A sortition jury is the primary adjudicator, but two contested cases have no
//! jury answer: the eligible pool is too small to seat a panel at all
//! ([`EscalationReason::CannotSeat`]), or a party contests the jury's ruling
//! ([`EscalationReason::Appeal`]). For those, a party may put the question to the
//! whole established-member electorate — the same "one member, one vote" body
//! `rrn-governance` uses — on a **bounded sub-window that fails open**.
//!
//! This is a *dispute-native* vote, not a governance proposal: a single aggrieved
//! party opens it (no co-sign gate), and it runs on the dispute's own short window
//! (not the Charter's multi-week deliberation window), so it resolves inside the
//! 14-day settlement freeze. It reuses governance's electorate and its
//! integer-arithmetic quorum/approval *shape*, not its `Proposal` lifecycle.
//!
//! Two signed records drive it, mirroring [`crate::verdict`]:
//!
//! - an [`EscalationRecord`] a party appends to open the vote, and
//! - an [`EscalationBallot`] each established member appends to vote.
//!
//! Everything else — the electorate, the tally, the outcome — is *derived* from the
//! log on demand, exactly like the jury.

use std::collections::{HashMap, HashSet};

use dcbor::prelude::*;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::transaction::TransactionId;
use rrn_reputation::staking::grace_electorate;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::panel::DisputeOutcome;
use crate::sortition::DisputedInfo;
use crate::{DisputeParams, Result};

/// Discriminant string carried in an escalation record's canonical CBOR.
pub(crate) const ESCALATION_KIND: &str = "rrn.dispute.escalation";
/// Discriminant string carried in an escalation ballot's canonical CBOR.
pub(crate) const ESCALATION_BALLOT_KIND: &str = "rrn.dispute.escalation_ballot";

/// Why an escalation was opened — which decides what the vote is *for* and how it
/// is validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscalationReason {
    /// A party contests a jury ruling; the electorate can overturn it. Valid only
    /// while a terminal jury ruling exists and the appeal window is open.
    Appeal,
    /// The jury pool was too small to ever reach a majority; the electorate rules
    /// where the jury could not. Valid only while the pool cannot seat a panel.
    CannotSeat,
}

impl EscalationReason {
    fn as_str(self) -> &'static str {
        match self {
            EscalationReason::Appeal => "appeal",
            EscalationReason::CannotSeat => "cannot_seat",
        }
    }
}

/// A party's signed request to put a dispute to the established-member electorate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationRecord {
    /// The disputed transaction this escalation concerns.
    pub proposal_id: TransactionId,
    /// The party opening the escalation (must be the sender or receiver).
    pub initiator: Address,
    /// Why the escalation is warranted.
    pub reason: EscalationReason,
    /// Unix seconds when the escalation was opened — the instant the electorate is
    /// snapshotted at, and the start of the escalation sub-window.
    pub opened_at: i64,
}

/// An [`EscalationRecord`] signed by the party who opened it.
pub type SignedEscalation = SignedPayload<EscalationRecord>;

/// An established member's signed ballot in an escalation vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscalationBallot {
    /// The disputed transaction this ballot rules on.
    pub proposal_id: TransactionId,
    /// The member casting the ballot (must be an established, non-party voter).
    pub voter: Address,
    /// `true` to uphold the dispute (void the transfer), `false` to reject it —
    /// identical semantics to a [`JurorVerdict`](crate::verdict::JurorVerdict), so a
    /// terminal escalation maps onto the same ledger primitive.
    pub uphold: bool,
    /// Unix seconds when the ballot was cast.
    pub cast_at: i64,
}

/// An [`EscalationBallot`] signed by the voter who cast it.
pub type SignedEscalationBallot = SignedPayload<EscalationBallot>;

impl From<EscalationRecord> for CBOR {
    fn from(e: EscalationRecord) -> Self {
        let mut m = Map::new();
        m.insert("kind", ESCALATION_KIND);
        m.insert("proposal_id", e.proposal_id);
        m.insert("initiator", e.initiator);
        m.insert("reason", e.reason.as_str());
        m.insert("opened_at", e.opened_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EscalationRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != ESCALATION_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let reason = match map.extract::<&str, String>("reason")?.as_str() {
            "appeal" => EscalationReason::Appeal,
            "cannot_seat" => EscalationReason::CannotSeat,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(EscalationRecord {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            initiator: map.extract::<&str, Address>("initiator")?,
            reason,
            opened_at: map.extract::<&str, i64>("opened_at")?,
        })
    }
}

impl From<EscalationBallot> for CBOR {
    fn from(b: EscalationBallot) -> Self {
        let mut m = Map::new();
        m.insert("kind", ESCALATION_BALLOT_KIND);
        m.insert("proposal_id", b.proposal_id);
        m.insert("voter", b.voter);
        // A binary ruling as a text discriminant, matching the juror verdict's
        // `ruling` field rather than a bare CBOR bool.
        m.insert("ruling", if b.uphold { "uphold" } else { "reject" });
        m.insert("cast_at", b.cast_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EscalationBallot {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != ESCALATION_BALLOT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let uphold = match map.extract::<&str, String>("ruling")?.as_str() {
            "uphold" => true,
            "reject" => false,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(EscalationBallot {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            voter: map.extract::<&str, Address>("voter")?,
            uphold,
            cast_at: map.extract::<&str, i64>("cast_at")?,
        })
    }
}

/// The open escalation on `tx_id`, if any — the **first** one appended (a dispute
/// escalates at most once; the append gate refuses a second, and replay keeps the
/// first regardless).
pub fn escalation_of(db: &Database, tx_id: &TransactionId) -> Result<Option<EscalationRecord>> {
    let log = AppendLog::new(db);
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(esc) = from_canonical_bytes::<EscalationRecord>(&entry.payload.bytes) else {
            continue;
        };
        if esc.proposal_id == *tx_id {
            return Ok(Some(esc));
        }
    }
    Ok(None)
}

/// Every ballot cast on `tx_id`'s escalation, keyed by voter, as `(uphold, cast_at)`.
///
/// Keeps the **first** ballot each voter cast (a ballot is final). Whether a ballot
/// *counts* is decided by [`count_escalation`], which credits only established,
/// non-party voters inside the sub-window.
pub fn escalation_ballots(
    db: &Database,
    tx_id: &TransactionId,
) -> Result<HashMap<Address, (bool, i64)>> {
    let log = AppendLog::new(db);
    let mut out: HashMap<Address, (bool, i64)> = HashMap::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(ballot) = from_canonical_bytes::<EscalationBallot>(&entry.payload.bytes) else {
            continue;
        };
        if ballot.proposal_id != *tx_id {
            continue;
        }
        out.entry(ballot.voter)
            .or_insert((ballot.uphold, ballot.cast_at));
    }
    Ok(out)
}

/// The electorate eligible to vote in an escalation, snapshotted as of `at` (the
/// escalation's open time) — the governance electorate (established members, plus
/// the genesis `founders` while the community is in bootstrap grace, per
/// ADR-0015) minus the two parties, who never vote on their own dispute. Vouchers
/// are *not* recused: unlike the jury, this is the whole community ruling.
pub fn escalation_electorate(
    db: &Database,
    founders: &[Address],
    info: &DisputedInfo,
    at: i64,
) -> Result<HashSet<Address>> {
    let parties: HashSet<Address> = [info.sender, info.receiver].into_iter().collect();
    Ok(grace_electorate(db, founders, at)?
        .into_iter()
        .filter(|a| !parties.contains(a))
        .collect())
}

/// The counted state of an escalation vote — a derived view, never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EscalationTally {
    /// Ballots to uphold the dispute, from eligible voters inside the window.
    pub uphold: u32,
    /// Ballots to reject the dispute, from eligible voters inside the window.
    pub reject: u32,
    /// Established, non-party members eligible to vote.
    pub eligible: u32,
    /// Whether turnout reached the escalation quorum.
    pub quorum_met: bool,
    /// Whether the uphold share of decisive votes cleared the approval bar.
    pub approval_met: bool,
}

/// Counts an escalation's ballots against its electorate and the quorum/approval
/// bars, in integer arithmetic (`count * 100` vs `pct * base`) so replicas cannot
/// disagree over rounding. Only ballots from an eligible voter cast within
/// `[opened_at, close]` are credited.
pub fn count_escalation(
    ballots: &HashMap<Address, (bool, i64)>,
    electorate: &HashSet<Address>,
    params: &DisputeParams,
    opened_at: i64,
    close: i64,
) -> EscalationTally {
    let mut uphold = 0u32;
    let mut reject = 0u32;
    for (voter, (up, cast_at)) in ballots {
        if !electorate.contains(voter) || *cast_at < opened_at || *cast_at > close {
            continue;
        }
        if *up {
            uphold += 1;
        } else {
            reject += 1;
        }
    }
    let eligible = electorate.len() as u32;
    let turnout = uphold + reject;
    let decisive = uphold + reject;
    // An escalation nobody votes in never meets quorum — it fails open (lapses),
    // rather than vacuously "meeting" a zero-vs-zero bar. This also guards the
    // degenerate empty-electorate case (0 eligible), which lapses to the confirmed
    // status quo instead of reading as an affirmative rejection.
    let quorum_met = turnout > 0
        && (turnout as u64) * 100 >= (params.escalation_quorum_pct as u64) * eligible as u64;
    let approval_met = decisive > 0
        && (uphold as u64) * 100 >= (params.escalation_approval_pct as u64) * decisive as u64;
    EscalationTally {
        uphold,
        reject,
        eligible,
        quorum_met,
        approval_met,
    }
}

impl EscalationTally {
    /// The terminal ruling once the escalation window has closed: quorum failure
    /// **fails open** (`None` → the transaction settles as confirmed), quorum with
    /// approval upholds, quorum without approval rejects.
    pub fn terminal_outcome(&self) -> Option<DisputeOutcome> {
        if !self.quorum_met {
            None
        } else if self.approval_met {
            Some(DisputeOutcome::Upheld)
        } else {
            Some(DisputeOutcome::Rejected)
        }
    }
}
