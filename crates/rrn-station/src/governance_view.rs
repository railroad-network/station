//! Member- and operator-facing governance reads (T1.9.7b).
//!
//! M1.9 built the governance engine ([`rrn_governance`]) — the Charter, proposals,
//! voting, tallying, and enactment — but exposed none of it to a reader. This
//! module is that read path: it turns the log-derived governance state into the
//! flat, JSON-shaped views the `rrn governance` CLI prints and the mobile renders,
//! so a member can see the current Charter, browse proposals with their live tally
//! and phase, read one in full, and list the statutes in force.
//!
//! Everything here is derived from the log on demand (the governance engine keeps
//! no stored state), so a view is a snapshot at the `now` it is asked for. The
//! wire shapes are owned here, not by the engine's enums, so the CLI/mobile
//! contract does not move when an internal spelling changes.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use rrn_governance::proposal::{
    all_proposals, phase, proposal_records, Proposal, ProposalId, ProposalKind, ProposalPhase,
    DEFAULT_COSIGN_THRESHOLD,
};
use rrn_governance::statute::enacted_statutes;
use rrn_governance::tally::{effective_charter, tally, ProposalOutcome, VoteTally};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// The community's constitution as a reader sees it: the effective Charter
/// (founder root plus any enacted amendment) and its governing thresholds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CharterView {
    /// Whether any Charter has been published. `false` means the community is
    /// still bootstrapping — every other field is a default and means nothing yet.
    pub published: bool,
    /// The effective Charter version: 1 at genesis, +1 per enacted amendment.
    pub version: u32,
    /// The effective `charter_hash`, hex-encoded — the content address that
    /// reflects any enacted amendment.
    pub charter_hash: Option<String>,
    /// A stable identifier for the community.
    pub community_id: String,
    /// The founding principles, free text.
    pub founding_principles: Vec<String>,
    /// Rights guaranteed above the federation floor.
    pub rights_floor: Vec<String>,
    /// The genesis founders' `rrn1…` addresses (historical; retained across
    /// amendment).
    pub founders: Vec<String>,
    /// Statute-vote quorum, as a percentage of the electorate.
    pub statute_quorum_pct: u8,
    /// Statute-vote approval, as a percentage of decisive votes.
    pub statute_approval_pct: u8,
    /// Days a statute deliberates and votes before its window closes.
    pub deliberation_window_days: u8,
    /// Days between a non-emergency proposal passing and taking effect.
    pub implementation_delay_days: u8,
    /// The higher approval bar an emergency must clear.
    pub emergency_threshold_pct: u8,
    /// Charter-amendment quorum percentage.
    pub charter_quorum_pct: u8,
    /// Charter-amendment approval percentage.
    pub charter_approval_pct: u8,
    /// Days a charter-amendment deliberates and votes.
    pub charter_deliberation_window_days: u8,
    /// Distinct established co-signers a proposal needs to publish.
    pub cosign_threshold: u32,
}

/// A proposal as a browse row: identity, what it would do, where it is in its
/// lifecycle, and a summary of the vote so far.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposalSummary {
    /// The proposal's content address, hex-encoded.
    pub proposal_id: String,
    /// The author's `rrn1…` address.
    pub author: String,
    /// The short title.
    pub title: String,
    /// `statute`, `administrative_rule`, `charter_amendment`, or `emergency`.
    pub kind: String,
    /// The admin-rule scope, when the kind is `administrative_rule`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Unix seconds the proposal was created — the start of its window.
    pub created_at: i64,
    /// Unix seconds the combined deliberation/voting window closes.
    pub voting_ends_at: i64,
    /// Unix seconds a passed proposal takes effect.
    pub implementation_at: i64,
    /// `deliberation`, `voting`, or `concluded`.
    pub phase: String,
    /// Whether the proposal reached the co-sign threshold and opened for voting.
    pub published: bool,
    /// Distinct established co-signers gathered so far.
    pub cosigner_count: u32,
    /// The tally so far (live while open, settled once closed).
    pub tally: TallyView,
    /// Whether the proposal has been enacted (in force).
    pub enacted: bool,
}

/// One proposal in full: the summary plus its body and the addresses that have
/// co-signed it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposalDetail {
    /// The browse-row fields.
    #[serde(flatten)]
    pub summary: ProposalSummary,
    /// The full proposal text (markdown).
    pub body: String,
    /// The `rrn1…` addresses that have validly co-signed.
    pub cosigners: Vec<String>,
}

/// A proposal's counted ballots, flattened for the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TallyView {
    /// Ballots in favour.
    pub yes: u32,
    /// Ballots against.
    pub no: u32,
    /// Ballots explicitly abstaining.
    pub abstain: u32,
    /// Established members eligible to vote, as of the proposal's close.
    pub eligible_voters: u32,
    /// Whether participation reached the Charter's quorum.
    pub quorum_met: bool,
    /// Whether the yes share reached the Charter's approval bar.
    pub approval_met: bool,
    /// `passed`, `failed`, or `null` while voting is still open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

/// A statute in force: the proposal that carried, and when it took effect.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatuteSummary {
    /// The proposal's content address, hex-encoded.
    pub proposal_id: String,
    /// The title.
    pub title: String,
    /// The proposal kind.
    pub kind: String,
    /// Unix seconds it was enacted.
    pub implemented_at: i64,
}

/// The effective Charter as a view, or an unpublished placeholder while the
/// community is still bootstrapping.
pub fn charter_view(db: &Database) -> Result<CharterView, rrn_governance::tally::TallyError> {
    let Some(charter) = effective_charter(db)? else {
        return Ok(CharterView {
            published: false,
            version: 0,
            charter_hash: None,
            community_id: String::new(),
            founding_principles: vec![],
            rights_floor: vec![],
            founders: vec![],
            statute_quorum_pct: 0,
            statute_approval_pct: 0,
            deliberation_window_days: 0,
            implementation_delay_days: 0,
            emergency_threshold_pct: 0,
            charter_quorum_pct: 0,
            charter_approval_pct: 0,
            charter_deliberation_window_days: 0,
            cosign_threshold: DEFAULT_COSIGN_THRESHOLD,
        });
    };
    let gs = &charter.governance_structure;
    let ar = &charter.amendment_rules;
    Ok(CharterView {
        published: true,
        version: charter.version,
        charter_hash: Some(charter.hash().to_string()),
        community_id: charter.community_id.clone(),
        founding_principles: charter.founding_principles.clone(),
        rights_floor: charter.rights_floor.clone(),
        founders: charter.founders.iter().map(|a| a.to_string()).collect(),
        statute_quorum_pct: gs.statute_quorum_pct,
        statute_approval_pct: gs.statute_approval_pct,
        deliberation_window_days: gs.deliberation_window_days,
        implementation_delay_days: gs.implementation_delay_days,
        emergency_threshold_pct: gs.emergency_threshold_pct,
        charter_quorum_pct: ar.charter_quorum_pct,
        charter_approval_pct: ar.charter_approval_pct,
        charter_deliberation_window_days: ar.charter_deliberation_window_days,
        cosign_threshold: DEFAULT_COSIGN_THRESHOLD,
    })
}

/// Every proposal on the log as browse rows, each with its phase and live tally,
/// most-recent-first (the order [`all_proposals`] returns).
pub fn proposals_view(
    db: &Database,
    now: i64,
) -> Result<Vec<ProposalSummary>, GovernanceViewError> {
    let log = AppendLog::new(db);
    let proposals = all_proposals(&log, db)?;
    let enacted = enacted_ids(db)?;
    let mut rows = Vec::with_capacity(proposals.len());
    for proposal in proposals {
        rows.push(summarize(db, &log, &proposal, now, &enacted)?);
    }
    Ok(rows)
}

/// One proposal in full, or `None` if the log has no authorized record of it.
pub fn proposal_view(
    db: &Database,
    proposal_id: &ProposalId,
    now: i64,
) -> Result<Option<ProposalDetail>, GovernanceViewError> {
    let log = AppendLog::new(db);
    let records = proposal_records(&log, proposal_id, db)?;
    let Some(proposal) = records.proposal.clone() else {
        return Ok(None);
    };
    let summary = summarize(db, &log, &proposal, now, &enacted_ids(db)?)?;
    let mut cosigners: Vec<String> = records.cosigners.iter().map(|a| a.to_string()).collect();
    cosigners.sort();
    Ok(Some(ProposalDetail {
        summary,
        body: proposal.body.clone(),
        cosigners,
    }))
}

/// The statutes in force, derived from the log.
pub fn statutes_view(db: &Database) -> Result<Vec<StatuteSummary>, GovernanceViewError> {
    Ok(enacted_statutes(db)?
        .into_iter()
        .map(|s| StatuteSummary {
            proposal_id: s.proposal.proposal_id.to_string(),
            title: s.proposal.title.clone(),
            kind: kind_name(&s.proposal.kind).to_string(),
            implemented_at: s.implemented_at,
        })
        .collect())
}

/// The content addresses of every proposal in force, computed once so a browse
/// listing does not re-derive the (tally-heavy) statutes view per row.
fn enacted_ids(db: &Database) -> Result<HashSet<ProposalId>, GovernanceViewError> {
    Ok(enacted_statutes(db)?
        .into_iter()
        .map(|s| s.proposal.proposal_id)
        .collect())
}

/// Builds a browse row for one proposal: its phase, co-signers, live tally, and
/// whether it has been enacted.
fn summarize(
    db: &Database,
    log: &AppendLog,
    proposal: &Proposal,
    now: i64,
    enacted: &HashSet<ProposalId>,
) -> Result<ProposalSummary, GovernanceViewError> {
    let records = proposal_records(log, &proposal.proposal_id, db)?;
    let published = records.is_published(DEFAULT_COSIGN_THRESHOLD);
    let phase = phase(&records, DEFAULT_COSIGN_THRESHOLD, now)
        .map(phase_name)
        .unwrap_or("concluded")
        .to_string();
    // A tally needs a published Charter; before one exists (bootstrapping) there is
    // nothing to count against, so show an empty tally rather than failing the row.
    let tally_view = match tally(db, &proposal.proposal_id, now) {
        Ok(t) => tally_view(&t),
        Err(_) => TallyView {
            yes: 0,
            no: 0,
            abstain: 0,
            eligible_voters: 0,
            quorum_met: false,
            approval_met: false,
            outcome: None,
        },
    };
    let enacted = enacted.contains(&proposal.proposal_id);
    let scope = match &proposal.kind {
        ProposalKind::AdministrativeRule { scope } => Some(scope.clone()),
        _ => None,
    };
    Ok(ProposalSummary {
        proposal_id: proposal.proposal_id.to_string(),
        author: proposal.author.to_string(),
        title: proposal.title.clone(),
        kind: kind_name(&proposal.kind).to_string(),
        scope,
        created_at: proposal.created_at,
        voting_ends_at: proposal.voting_ends_at,
        implementation_at: proposal.implementation_at,
        phase,
        published,
        cosigner_count: records.cosigner_count(),
        tally: tally_view,
        enacted,
    })
}

fn tally_view(t: &VoteTally) -> TallyView {
    TallyView {
        yes: t.yes_count,
        no: t.no_count,
        abstain: t.abstain_count,
        eligible_voters: t.eligible_voters,
        quorum_met: t.quorum_met,
        approval_met: t.approval_met,
        outcome: t.outcome.map(|o| {
            match o {
                ProposalOutcome::Passed => "passed",
                ProposalOutcome::Failed => "failed",
            }
            .to_string()
        }),
    }
}

/// The wire name for a proposal kind. A stable string owned here, not a serde
/// derive on the engine's enum.
pub(crate) fn kind_name(kind: &ProposalKind) -> &'static str {
    match kind {
        ProposalKind::Statute => "statute",
        ProposalKind::AdministrativeRule { .. } => "administrative_rule",
        ProposalKind::CharterAmendment { .. } => "charter_amendment",
        ProposalKind::Emergency { .. } => "emergency",
    }
}

fn phase_name(p: ProposalPhase) -> &'static str {
    match p {
        ProposalPhase::Deliberation => "deliberation",
        ProposalPhase::Voting => "voting",
        ProposalPhase::Concluded { .. } => "concluded",
    }
}

/// A failure building a governance view. Wraps the engine's read errors so a
/// handler can turn any of them into one internal error.
#[derive(thiserror::Error, Debug)]
pub enum GovernanceViewError {
    /// A proposal-record read failed.
    #[error("proposal: {0}")]
    Proposal(#[from] rrn_governance::proposal::ProposalError),
    /// A tally read failed.
    #[error("tally: {0}")]
    Tally(#[from] rrn_governance::tally::TallyError),
    /// A statutes read failed.
    #[error("statute: {0}")]
    Statute(#[from] rrn_governance::statute::StatuteError),
}
