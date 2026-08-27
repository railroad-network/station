//! Statute — a passed proposal put into force, and the record that enacts it.
//!
//! # What enactment is
//!
//! A proposal that passes its vote does not take effect the instant the ballots
//! close. A non-emergency measure waits out its implementation delay
//! ([`Proposal::implementation_at`](crate::proposal::Proposal::implementation_at)) —
//! time for dissenters to exit, appeal, or organize — before it is put into force;
//! an emergency takes effect the moment it passes. Enactment is the station writing
//! that down: a [`ProposalImplemented`] record, station-signed, saying "this
//! proposal is now in force as of `implemented_at`". [`crate::lifecycle::enact_due`]
//! is the background sweep that appends these on time.
//!
//! # Applying the rule (Phase 1)
//!
//! What "applying" a passed proposal *does* is rule-specific. In Phase 1 it means
//! recording it as an enacted statute — a queryable fact derived from the log
//! ([`enacted_statutes`]) — and, for a [`CharterAmendment`](crate::proposal::ProposalKind::CharterAmendment),
//! letting the new Charter supersede the old (resolved by
//! [`effective_charter`](crate::tally::effective_charter), which folds an enacted
//! amendment onto the founder root). Any downstream effect a statute describes —
//! changing a config value, say — is spelled out in its body and applied by hand;
//! an automatic rule engine for those is Phase 2 (ADR-0012, task T1.9.7 scope).
//!
//! # Trust: written under a guard, believed only on re-derivation
//!
//! [`record_implementation`] is the guarded write path: it appends an enactment
//! only for a proposal that has genuinely passed ([`tally`](crate::tally::tally))
//! and whose implementation time has arrived, and never twice. But a
//! `ProposalImplemented` is an ordinary signed log entry, so a peer could gossip
//! one that dodged the guard. [`enacted_statutes`] therefore re-derives passage and
//! due-ness for every enactment record and returns only the legitimate ones — the
//! same "the log is canonical, replay re-checks it" discipline the rest of
//! governance follows. The bare structural check [`is_implemented`] is used only
//! where a cheap "has this already been enacted?" is needed (the sweep's
//! idempotency and the amendment fold), never as proof a statute is in force.

use dcbor::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};

use crate::proposal::{proposal_records, Proposal, ProposalError, ProposalId};
use crate::tally::{tally, ProposalOutcome, TallyError};

/// Discriminant carried in the `kind` field of a [`ProposalImplemented`]'s
/// canonical CBOR, so log replay can tell an enactment record apart.
pub(crate) const IMPLEMENTED_KIND: &str = "rrn.gov.proposal_implemented";

/// A station's record that a passed proposal has been put into force.
///
/// Station-signed on append. Its authority is not the signature but the facts it
/// points at: a proposal that passed and whose implementation time had come. Those
/// are re-derived wherever the record is believed (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalImplemented {
    /// The proposal put into force.
    pub proposal_id: ProposalId,
    /// Unix seconds the station enacted it — at or after the proposal's
    /// `implementation_at`.
    pub implemented_at: i64,
}

/// A [`ProposalImplemented`] signed by the enacting station.
pub type SignedImplementation = SignedPayload<ProposalImplemented>;

/// A passed proposal in force, with the moment it was enacted — the queryable
/// "statutes table" of Phase 1, derived from the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnactedStatute {
    /// The proposal now in force.
    pub proposal: Proposal,
    /// When it was enacted (from its [`ProposalImplemented`] record).
    pub implemented_at: i64,
}

/// The enactment record for `proposal_id`, if the log carries a structurally valid
/// one. A cheap existence check — it does *not* re-verify the proposal passed — so
/// it is used only for the sweep's idempotency and the amendment fold, never as
/// proof a statute is in force. Use [`enacted_statutes`] for that.
pub(crate) fn implementation_of(
    log: &AppendLog,
    proposal_id: &ProposalId,
) -> Option<ProposalImplemented> {
    for entry in log.iter_from(1) {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(record) = from_canonical_bytes::<ProposalImplemented>(&entry.payload.bytes) else {
            continue;
        };
        if record.proposal_id == *proposal_id {
            return Some(record);
        }
    }
    None
}

/// Whether the log already carries an enactment record for `proposal_id`.
pub(crate) fn is_implemented(log: &AppendLog, proposal_id: &ProposalId) -> bool {
    implementation_of(log, proposal_id).is_some()
}

/// Enacts a passed proposal: appends a station-signed [`ProposalImplemented`].
///
/// The guard on the write path. Rejects a proposal that has not passed its vote,
/// one whose implementation time has not yet arrived (`now < implementation_at`),
/// and one already enacted. `now` is the enacting time and is recorded as
/// `implemented_at`.
pub fn record_implementation(
    log: &mut AppendLog,
    db: &Database,
    station: &Keypair,
    proposal: &Proposal,
    now: i64,
) -> Result<LogEntry, StatuteError> {
    if is_implemented(log, &proposal.proposal_id) {
        return Err(StatuteError::AlreadyImplemented(proposal.proposal_id));
    }
    if tally(db, &proposal.proposal_id, now)?.outcome != Some(ProposalOutcome::Passed) {
        return Err(StatuteError::NotPassed(proposal.proposal_id));
    }
    if now < proposal.implementation_at {
        return Err(StatuteError::NotYetDue {
            proposal_id: proposal.proposal_id,
            implementation_at: proposal.implementation_at,
            now,
        });
    }
    let record = ProposalImplemented {
        proposal_id: proposal.proposal_id,
        implemented_at: now,
    };
    Ok(log.append(SignedPayload::sign(record, station), now)?)
}

/// Every proposal in force, derived from the log: for each enactment record, the
/// proposal it names, kept only when that proposal genuinely passed and its
/// enactment time was at or after its `implementation_at`.
///
/// This is the queryable statutes surface. It re-derives legitimacy so a gossiped
/// enactment record that should never have been written is not believed. Returned
/// in log order, each proposal once.
pub fn enacted_statutes(db: &Database) -> Result<Vec<EnactedStatute>, StatuteError> {
    let log = AppendLog::new(db);
    let mut out = Vec::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(record) = from_canonical_bytes::<ProposalImplemented>(&entry.payload.bytes) else {
            continue;
        };
        // The enactment must name a proposal this log holds as authorized...
        let Some(proposal) = proposal_records(&log, &record.proposal_id, db)?.proposal else {
            continue;
        };
        // ...that genuinely passed, at or after its implementation time.
        if record.implemented_at < proposal.implementation_at {
            continue;
        }
        if tally(db, &record.proposal_id, record.implemented_at)?.outcome
            != Some(ProposalOutcome::Passed)
        {
            continue;
        }
        if out
            .iter()
            .any(|s: &EnactedStatute| s.proposal.proposal_id == proposal.proposal_id)
        {
            continue;
        }
        out.push(EnactedStatute {
            proposal,
            implemented_at: record.implemented_at,
        });
    }
    Ok(out)
}

/// A reason an enactment could not be recorded, or a stored record could not be
/// believed.
#[derive(thiserror::Error, Debug)]
pub enum StatuteError {
    /// The proposal has not passed its vote, so there is nothing to enact.
    #[error("proposal {0} has not passed; nothing to enact")]
    NotPassed(ProposalId),
    /// The proposal passed but its implementation time has not yet arrived.
    #[error("proposal {proposal_id} is not due until {implementation_at} (now {now})")]
    NotYetDue {
        /// The proposal.
        proposal_id: ProposalId,
        /// When it becomes due.
        implementation_at: i64,
        /// The enacting time that was too early.
        now: i64,
    },
    /// The proposal is already enacted.
    #[error("proposal {0} is already enacted")]
    AlreadyImplemented(ProposalId),
    /// A tally error while verifying the proposal passed.
    #[error("tally: {0}")]
    Tally(#[from] TallyError),
    /// A proposal-record error while reading the log.
    #[error("proposal: {0}")]
    Proposal(#[from] ProposalError),
    /// A storage/log error while reading or appending.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
}

// --- Canonical CBOR ---------------------------------------------------------

impl From<ProposalImplemented> for CBOR {
    fn from(r: ProposalImplemented) -> Self {
        let mut m = Map::new();
        m.insert("kind", IMPLEMENTED_KIND);
        m.insert("proposal_id", r.proposal_id);
        m.insert("implemented_at", r.implemented_at);
        m.into()
    }
}

impl TryFrom<CBOR> for ProposalImplemented {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != IMPLEMENTED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ProposalImplemented {
            proposal_id: map.extract::<&str, ProposalId>("proposal_id")?,
            implemented_at: map.extract::<&str, i64>("implemented_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::hash::Hash;
    use rrn_crypto::serialize::to_canonical_bytes;

    #[test]
    fn proposal_implemented_cbor_roundtrips() {
        let record = ProposalImplemented {
            proposal_id: ProposalId(Hash::of(b"a proposal")),
            implemented_at: 1_700_000_000,
        };
        let back: ProposalImplemented = from_canonical_bytes(&to_canonical_bytes(record)).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn a_record_with_the_wrong_kind_is_not_an_implementation() {
        // A cosign shares no kind with an enactment, so its bytes must not decode
        // as one — the discriminant is what keeps the log's record types apart.
        let mut m = dcbor::Map::new();
        m.insert("kind", "rrn.gov.proposal_cosign");
        let bytes = to_canonical_bytes(CBOR::from(m));
        assert!(from_canonical_bytes::<ProposalImplemented>(&bytes).is_err());
    }
}
