//! Tally — reducing the cast ballots on a proposal to a verifiable outcome.
//!
//! # What a tally is
//!
//! A [`VoteTally`] is a *derived* view, never stored: [`tally`] replays the log
//! into the valid ballots ([`votes`](crate::vote::votes)), counts them by choice,
//! measures them against the Charter's thresholds for the proposal's kind, and —
//! once voting has closed — reduces the result to a [`ProposalOutcome`]. Because it
//! is recomputed from the log, anyone can re-derive the same numbers: a result is
//! auditable, not announced.
//!
//! # Quorum and approval
//!
//! Two independent bars, both taken from the Charter and both keyed to the
//! proposal's kind (a statute and a Charter amendment answer to different numbers):
//!
//! - **Quorum** — enough of the electorate turned out: participation
//!   (yes + no + abstain) is at least `quorum_pct` of the eligible voters. An
//!   explicit [`Abstain`](crate::vote::VoteChoice::Abstain) counts toward turnout;
//!   *silence* — never casting — does not, which is exactly why abstain is a
//!   distinct choice.
//! - **Approval** — enough of the decisive votes said yes: `yes` is at least
//!   `approval_pct` of `yes + no`. Abstentions are not decisive and are excluded
//!   from this ratio. With no decisive votes at all, nothing was approved, so
//!   approval fails rather than dividing by zero.
//!
//! Both are compared in integer arithmetic (`count * 100` against `pct * base`), so
//! there is no floating-point rounding to disagree over between replicas.
//!
//! # Who is eligible, and why the count is pinned
//!
//! The eligible electorate is the community's **established members** — the same
//! effective-composite ≥ Member-band set that authors, co-signs, and votes — as of
//! the proposal's `voting_ends_at`. Pinning eligibility to the close (rather than
//! to wall-clock `now`) is what makes a concluded outcome **stable**: members who
//! join or lapse after voting ends cannot move a settled quorum. Before the close,
//! evaluating at `voting_ends_at` reads the same current membership (nothing on the
//! log post-dates now), so live counts stay meaningful too.
//!
//! # Outcome timing
//!
//! [`VoteTally::outcome`] is `None` while voting is open — a caller may still read
//! the live counts — and becomes `Some` only once `now` passes `voting_ends_at`,
//! when the ballots and the electorate are both frozen. A proposal that never
//! published has no counting ballots and concludes [`Failed`](ProposalOutcome::Failed).

use rrn_reputation::staking::established_member_count;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::charter::{Charter, CharterError};
use crate::proposal::{
    all_proposals, proposal_records, Proposal, ProposalError, ProposalId, ProposalKind,
};
use crate::statute::is_implemented;
use crate::vote::{votes, VoteChoice, VoteError};

/// Whether a concluded proposal carried or fell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// Quorum was met and approval cleared its bar.
    Passed,
    /// Quorum or approval fell short.
    Failed,
}

/// The counted result of a proposal's vote — a computed view of the log, not a
/// stored record. Re-derivable by anyone from the same log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoteTally {
    /// The proposal tallied.
    pub proposal_id: ProposalId,
    /// Ballots cast in favour.
    pub yes_count: u32,
    /// Ballots cast against.
    pub no_count: u32,
    /// Ballots explicitly abstaining — turnout, but not decisive.
    pub abstain_count: u32,
    /// Established members eligible to vote, as of the proposal's `voting_ends_at`.
    pub eligible_voters: u32,
    /// Whether participation reached the Charter's quorum for this kind.
    pub quorum_met: bool,
    /// Whether the yes share of decisive votes reached the Charter's approval bar.
    pub approval_met: bool,
    /// The settled result once voting has closed; `None` while it is still open.
    pub outcome: Option<ProposalOutcome>,
}

/// Tallies a proposal's ballots as of `now`, against the community's effective
/// Charter.
///
/// Resolves the governing thresholds from the [effective Charter](effective_charter)
/// — the founder root plus any enacted amendments — so a proposal answers to the
/// numbers actually in force when it is counted. Returns
/// [`TallyError::UnknownProposal`] if the log has no authorized record of the
/// proposal, and [`TallyError::NoCharter`] if no Charter has been published to
/// supply the thresholds.
pub fn tally(db: &Database, proposal_id: &ProposalId, now: i64) -> Result<VoteTally, TallyError> {
    let charter = effective_charter(db)?.ok_or(TallyError::NoCharter)?;
    count_against(db, proposal_id, now, &charter)
}

/// The community's effective Charter: the [founder root](crate::charter::founder_charter)
/// with every enacted amendment folded on top in lineage order, or `None` if no
/// Charter has been published yet.
///
/// An amendment folds in only when it has been enacted — a [`ProposalImplemented`](crate::statute::ProposalImplemented)
/// record for it exists ([`is_implemented`]) — *and* re-derives as passed when
/// tallied against the Charter it amends, chaining by `version + 1` and
/// `previous_hash`. The authority for an amendment is the vote, not a founder
/// signature, so its passage is re-verified here rather than trusted (ADR-0012 § 4).
/// Each fold strictly raises the version, so the walk terminates.
///
/// The amendment is judged against the *prior* Charter — the one already in hand —
/// never against [`tally`] (which would resolve the effective Charter again), so
/// there is no recursion.
pub fn effective_charter(db: &Database) -> Result<Option<Charter>, TallyError> {
    let Some(root) = crate::charter::founder_charter(db)? else {
        return Ok(None);
    };
    let mut current = root.charter().clone();
    let mut current_hash = root.charter_hash();

    let log = AppendLog::new(db);
    let amendments: Vec<Proposal> = all_proposals(&log, db)?
        .into_iter()
        .filter(|p| matches!(p.kind, ProposalKind::CharterAmendment { .. }))
        .collect();

    loop {
        let mut advanced = false;
        for p in &amendments {
            let ProposalKind::CharterAmendment { new_charter } = &p.kind else {
                continue;
            };
            if new_charter.version != current.version + 1
                || new_charter.previous_hash != Some(current_hash)
                || !is_implemented(&log, &p.proposal_id)
            {
                continue;
            }
            // Re-derive passage against the Charter this amendment supersedes.
            let passed = count_against(db, &p.proposal_id, p.implementation_at, &current)?.outcome
                == Some(ProposalOutcome::Passed);
            if !passed {
                continue;
            }
            current_hash = new_charter.hash();
            current = new_charter.clone();
            advanced = true;
            break;
        }
        if !advanced {
            break;
        }
    }
    Ok(Some(current))
}

/// The `charter_hash` of the [effective Charter](effective_charter), or `None` if
/// none is published. The content address the community profile and treaty
/// partners pin, reflecting any enacted amendment.
pub fn effective_charter_hash(db: &Database) -> Result<Option<rrn_crypto::hash::Hash>, TallyError> {
    Ok(effective_charter(db)?.map(|c| c.hash()))
}

/// Counts a proposal's ballots as of `now` against an explicit `governing`
/// Charter, without resolving which Charter governs.
///
/// The counting core behind [`tally`]; kept separate so [`effective_charter`] can
/// judge an amendment against the Charter it amends without re-entering charter
/// resolution.
fn count_against(
    db: &Database,
    proposal_id: &ProposalId,
    now: i64,
    governing: &Charter,
) -> Result<VoteTally, TallyError> {
    let log = AppendLog::new(db);

    let records = proposal_records(&log, proposal_id, db)?;
    let Some(proposal) = records.proposal.as_ref() else {
        return Err(TallyError::UnknownProposal(*proposal_id));
    };

    let (quorum_pct, approval_pct) = thresholds(&proposal.kind, governing);

    let (mut yes, mut no, mut abstain) = (0u32, 0u32, 0u32);
    for choice in votes(&log, proposal_id, db)?.into_values() {
        match choice {
            VoteChoice::Yes => yes += 1,
            VoteChoice::No => no += 1,
            VoteChoice::Abstain => abstain += 1,
        }
    }

    let eligible = established_member_count(db, proposal.voting_ends_at)? as u32;
    let participation = yes + no + abstain;
    let decisive = yes + no;

    // Integer comparisons, no floats: participation/eligible ≥ quorum_pct/100 and
    // yes/decisive ≥ approval_pct/100, cross-multiplied.
    let quorum_met = u64::from(participation) * 100 >= u64::from(quorum_pct) * u64::from(eligible);
    let approval_met =
        decisive > 0 && u64::from(yes) * 100 >= u64::from(approval_pct) * u64::from(decisive);

    let settled = if quorum_met && approval_met {
        ProposalOutcome::Passed
    } else {
        ProposalOutcome::Failed
    };
    let outcome = (now > proposal.voting_ends_at).then_some(settled);

    Ok(VoteTally {
        proposal_id: *proposal_id,
        yes_count: yes,
        no_count: no,
        abstain_count: abstain,
        eligible_voters: eligible,
        quorum_met,
        approval_met,
        outcome,
    })
}

/// The `(quorum_pct, approval_pct)` the Charter sets for a proposal of this kind.
///
/// A statute and an administrative rule answer to the ordinary statute bars; a
/// Charter amendment to the higher amendment bars; an emergency to the ordinary
/// quorum but the raised emergency approval bar (the Charter carries no separate
/// emergency quorum in Phase 1 — configurable emergency quorum is Phase 2).
fn thresholds(kind: &ProposalKind, charter: &Charter) -> (u8, u8) {
    let gs = &charter.governance_structure;
    match kind {
        ProposalKind::Statute | ProposalKind::AdministrativeRule { .. } => {
            (gs.statute_quorum_pct, gs.statute_approval_pct)
        }
        ProposalKind::CharterAmendment { .. } => {
            let ar = &charter.amendment_rules;
            (ar.charter_quorum_pct, ar.charter_approval_pct)
        }
        ProposalKind::Emergency { .. } => (gs.statute_quorum_pct, gs.emergency_threshold_pct),
    }
}

/// A reason a tally could not be produced.
#[derive(thiserror::Error, Debug)]
pub enum TallyError {
    /// The log has no authorized record of this proposal.
    #[error("no proposal {0} on this log")]
    UnknownProposal(ProposalId),
    /// No Charter has been published, so there are no thresholds to tally against.
    #[error("no Charter has been published; cannot determine voting thresholds")]
    NoCharter,
    /// An error reading ballots or proposal records from the log.
    #[error("vote: {0}")]
    Vote(#[from] VoteError),
    /// An error reading the proposal record from the log.
    #[error("proposal: {0}")]
    Proposal(#[from] ProposalError),
    /// An error reading the current Charter.
    #[error("charter: {0}")]
    Charter(#[from] CharterError),
    /// An error scoring the electorate for the eligible-voter count.
    #[error("reputation: {0}")]
    Reputation(#[from] rrn_reputation::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charter::{create_charter, AmendmentRules, CharterParams, GovernanceStructure};
    use crate::proposal::{append_cosign, append_proposal, Proposal, ProposalCosign, ProposalKind};
    use crate::vote::{append_vote, SignedVote, Vote};
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::address::Address;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
    use rrn_storage::log::AppendLog;
    use rrn_storage::migrations;

    const MONTH: i64 = 30 * 86_400;
    const NOW: i64 = 10 * MONTH;

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    // --- Reputation seeding (mirrors rrn-reputation's own test helpers) -------

    fn append_settled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        station: &Keypair,
        nonce: u64,
        at: i64,
    ) {
        let mut log = AppendLog::new(db);
        let proposal = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            300,
            None,
            nonce,
            1,
            i64::MAX / 2,
        );
        let pid = proposal.id;
        log.append(SignedPayload::sign(proposal, sender)).unwrap();
        log.append(SignedPayload::sign(
            TransactionConfirmation {
                proposal_id: pid,
                confirmer: addr(receiver),
                confirmed_at: at,
            },
            receiver,
        ))
        .unwrap();
        log.append(SignedPayload::sign(
            SettlementRecord {
                proposal_id: pid,
                sender: addr(sender),
                receiver: addr(receiver),
                amount_centi: 300,
                settled_at: at,
            },
            station,
        ))
        .unwrap();
    }

    fn append_vouch(db: &Database, voucher: &Keypair, subject: &Address, at: i64) {
        let mut log = AppendLog::new(db);
        let vouch = Attestation {
            kind: VouchKind,
            body: VouchBody {
                community: "commons".into(),
                statement: "trustworthy".into(),
                reputation_stake_centi: 0,
            },
            subject: *subject,
            issued_at: at,
            expires_at: None,
        };
        log.append(vouch.sign(voucher)).unwrap();
    }

    fn earn_raw_standing(db: &Database, who: &Keypair, station: &Keypair, at: i64) {
        for nonce in 0..10 {
            append_settled(db, who, station, station, nonce, at);
        }
        for _ in 0..10 {
            append_vouch(db, who, &addr(&Keypair::generate()), at);
        }
    }

    /// Builds `n` established members anchored in a ring, so exactly `n` count
    /// toward the electorate.
    fn established_members(db: &Database, station: &Keypair, n: usize, at: i64) -> Vec<Keypair> {
        let members: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        for m in &members {
            earn_raw_standing(db, m, station, at);
        }
        for i in 0..n {
            append_vouch(db, &members[(i + 1) % n], &addr(&members[i]), at);
        }
        members
    }

    fn test_charter_body() -> Charter {
        Charter {
            version: 1,
            community_id: "commons".into(),
            founding_principles: vec![],
            rights_floor: vec![],
            governance_structure: GovernanceStructure::default(),
            amendment_rules: AmendmentRules::default(),
            created_at: 0,
            founders: vec![],
            previous_hash: None,
        }
    }

    /// Publishes a genuine founder-signed Charter to the log so `current_charter`
    /// finds thresholds. `founders` are its authorizing signers.
    fn publish_charter(db: &Database, founders: &[Keypair]) {
        let body = test_charter_body();
        let params = CharterParams {
            version: body.version,
            community_id: body.community_id,
            founding_principles: body.founding_principles,
            rights_floor: body.rights_floor,
            governance_structure: body.governance_structure,
            amendment_rules: body.amendment_rules,
            founders: founders.iter().map(addr).collect(),
            created_at: body.created_at,
            previous_hash: body.previous_hash,
        };
        let signed = create_charter(params, founders).unwrap();
        // The log stores single-signer entries; wrap in a publisher envelope.
        let mut log = AppendLog::new(db);
        log.append(SignedPayload::sign(signed, &founders[0]))
            .unwrap();
    }

    fn statute(author: &Keypair, at: i64) -> Proposal {
        Proposal::new(
            addr(author),
            "Quiet hours in the workshop".into(),
            "No power tools after 9pm.".into(),
            ProposalKind::Statute,
            at,
            &test_charter_body(),
        )
        .unwrap()
    }

    fn cosign(cosigner: &Keypair, proposal: &Proposal, at: i64) -> SignedPayload<ProposalCosign> {
        SignedPayload::sign(
            ProposalCosign {
                proposal_id: proposal.proposal_id,
                cosigner: addr(cosigner),
                cosigned_at: at,
            },
            cosigner,
        )
    }

    fn vote(voter: &Keypair, proposal: &Proposal, choice: VoteChoice, at: i64) -> SignedVote {
        SignedPayload::sign(
            Vote {
                proposal_id: proposal.proposal_id,
                voter: addr(voter),
                choice,
                cast_at: at,
            },
            voter,
        )
    }

    /// A published statute with `member_count` established members (member `[0]`
    /// authored it, `[1..=3]` co-signed it) and a real Charter on the log.
    /// Returns `(members, proposal)`.
    fn published_statute(
        db: &Database,
        station: &Keypair,
        member_count: usize,
    ) -> (Vec<Keypair>, Proposal) {
        let members = established_members(db, station, member_count, NOW);
        publish_charter(db, &members);
        let author = members[0].clone();
        let mut log = AppendLog::new(db);
        let proposal = statute(&author, NOW);
        append_proposal(&mut log, SignedPayload::sign(proposal.clone(), &author), db).unwrap();
        for c in &members[1..4] {
            append_cosign(&mut log, cosign(c, &proposal, NOW), db).unwrap();
        }
        (members, proposal)
    }

    // --- Counting ------------------------------------------------------------

    #[test]
    fn known_votes_produce_a_known_tally() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Ten established members; author + 3 co-signers, then a spread of ballots.
        let (members, proposal) = published_statute(&db, &station, 10);
        let mut log = AppendLog::new(&db);

        // 5 yes, 2 no, 1 abstain — 8 of 10 participate.
        for m in &members[0..5] {
            append_vote(&mut log, vote(m, &proposal, VoteChoice::Yes, NOW), &db).unwrap();
        }
        for m in &members[5..7] {
            append_vote(&mut log, vote(m, &proposal, VoteChoice::No, NOW), &db).unwrap();
        }
        append_vote(
            &mut log,
            vote(&members[7], &proposal, VoteChoice::Abstain, NOW),
            &db,
        )
        .unwrap();

        let t = tally(&db, &proposal.proposal_id, proposal.voting_ends_at + 1).unwrap();
        assert_eq!(t.yes_count, 5);
        assert_eq!(t.no_count, 2);
        assert_eq!(t.abstain_count, 1);
        assert_eq!(t.eligible_voters, 10);
        // Turnout 8/10 = 80% ≥ 30% quorum; approval 5/7 ≈ 71% ≥ 50%.
        assert!(t.quorum_met);
        assert!(t.approval_met);
        assert_eq!(t.outcome, Some(ProposalOutcome::Passed));
    }

    #[test]
    fn quorum_shortfall_fails_even_with_unanimous_yes() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Ten members but only two vote — 20% turnout, under the 30% quorum.
        let (members, proposal) = published_statute(&db, &station, 10);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[0], &proposal, VoteChoice::Yes, NOW),
            &db,
        )
        .unwrap();
        append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
        )
        .unwrap();

        let t = tally(&db, &proposal.proposal_id, proposal.voting_ends_at + 1).unwrap();
        assert_eq!(t.eligible_voters, 10);
        assert!(!t.quorum_met);
        assert!(t.approval_met); // 2/2 yes clears approval on its own
        assert_eq!(t.outcome, Some(ProposalOutcome::Failed));
    }

    #[test]
    fn approval_shortfall_fails_even_with_quorum() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Four members, all vote: 1 yes, 3 no. Full turnout, approval 25% < 50%.
        let (members, proposal) = published_statute(&db, &station, 4);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[0], &proposal, VoteChoice::Yes, NOW),
            &db,
        )
        .unwrap();
        for m in &members[1..4] {
            append_vote(&mut log, vote(m, &proposal, VoteChoice::No, NOW), &db).unwrap();
        }

        let t = tally(&db, &proposal.proposal_id, proposal.voting_ends_at + 1).unwrap();
        assert!(t.quorum_met);
        assert!(!t.approval_met);
        assert_eq!(t.outcome, Some(ProposalOutcome::Failed));
    }

    #[test]
    fn abstentions_count_toward_quorum_but_not_approval() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Four members: 2 yes, 0 no, 2 abstain. Approval 2/2 = 100%; abstain lifts
        // turnout to 100% but is excluded from the yes/no ratio.
        let (members, proposal) = published_statute(&db, &station, 4);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[0], &proposal, VoteChoice::Yes, NOW),
            &db,
        )
        .unwrap();
        append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
        )
        .unwrap();
        append_vote(
            &mut log,
            vote(&members[2], &proposal, VoteChoice::Abstain, NOW),
            &db,
        )
        .unwrap();
        append_vote(
            &mut log,
            vote(&members[3], &proposal, VoteChoice::Abstain, NOW),
            &db,
        )
        .unwrap();

        let t = tally(&db, &proposal.proposal_id, proposal.voting_ends_at + 1).unwrap();
        assert_eq!(t.abstain_count, 2);
        assert!(t.quorum_met);
        assert!(t.approval_met);
        assert_eq!(t.outcome, Some(ProposalOutcome::Passed));
    }

    #[test]
    fn a_vote_of_only_abstentions_approves_nothing() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 4);
        let mut log = AppendLog::new(&db);

        for m in &members[0..4] {
            append_vote(&mut log, vote(m, &proposal, VoteChoice::Abstain, NOW), &db).unwrap();
        }

        let t = tally(&db, &proposal.proposal_id, proposal.voting_ends_at + 1).unwrap();
        assert!(t.quorum_met); // full turnout
        assert!(!t.approval_met); // no decisive votes → not approved
        assert_eq!(t.outcome, Some(ProposalOutcome::Failed));
    }

    // --- Outcome timing ------------------------------------------------------

    #[test]
    fn outcome_is_none_while_voting_is_open_but_counts_are_live() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 4);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[0], &proposal, VoteChoice::Yes, NOW),
            &db,
        )
        .unwrap();

        // Mid-window: live counts, no settled outcome yet.
        let t = tally(&db, &proposal.proposal_id, NOW + 1).unwrap();
        assert_eq!(t.yes_count, 1);
        assert_eq!(t.outcome, None);
    }

    #[test]
    fn outcome_is_stable_after_the_close_even_as_the_community_grows() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 4);
        let mut log = AppendLog::new(&db);

        for m in &members[0..3] {
            append_vote(&mut log, vote(m, &proposal, VoteChoice::Yes, NOW), &db).unwrap();
        }

        let closed = proposal.voting_ends_at + 1;
        let before = tally(&db, &proposal.proposal_id, closed).unwrap();
        assert_eq!(before.eligible_voters, 4);
        assert_eq!(before.outcome, Some(ProposalOutcome::Passed));

        // New members join *after* the close. They must not dilute the settled
        // quorum: eligibility is pinned at voting_ends_at, so the count stays 4
        // rather than growing to 8.
        let later = proposal.voting_ends_at + MONTH;
        established_members(&db, &station, 4, later);

        let after = tally(&db, &proposal.proposal_id, later + 1).unwrap();
        assert_eq!(after.eligible_voters, before.eligible_voters);
        assert_eq!(after.outcome, before.outcome);
    }

    // --- Kind-specific thresholds --------------------------------------------

    #[test]
    fn a_charter_amendment_answers_to_the_higher_amendment_bars() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        publish_charter(&db, &members);
        let author = members[0].clone();
        let mut log = AppendLog::new(&db);

        let mut next = test_charter_body();
        next.version = 2;
        let amendment = Proposal::new(
            addr(&author),
            "Amend the charter".into(),
            "Raise the workshop budget.".into(),
            ProposalKind::CharterAmendment { new_charter: next },
            NOW,
            &test_charter_body(),
        )
        .unwrap();
        append_proposal(
            &mut log,
            SignedPayload::sign(amendment.clone(), &author),
            &db,
        )
        .unwrap();
        for c in &members[1..4] {
            append_cosign(&mut log, cosign(c, &amendment, NOW), &db).unwrap();
        }

        // 3 yes, 1 no = 75% approval. The 50% statute bar would pass this; the 75%
        // charter bar it must meet exactly does too, and quorum (100%) clears 50%.
        for m in &members[0..3] {
            append_vote(&mut log, vote(m, &amendment, VoteChoice::Yes, NOW), &db).unwrap();
        }
        append_vote(
            &mut log,
            vote(&members[3], &amendment, VoteChoice::No, NOW),
            &db,
        )
        .unwrap();

        let t = tally(&db, &amendment.proposal_id, amendment.voting_ends_at + 1).unwrap();
        assert!(t.approval_met); // 3/4 = 75% ≥ 75%
        assert_eq!(t.outcome, Some(ProposalOutcome::Passed));
    }

    // --- Errors --------------------------------------------------------------

    #[test]
    fn tallying_an_unknown_proposal_is_an_error() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 2, NOW);
        publish_charter(&db, &members);
        let phantom = statute(&members[0], NOW);

        let err = tally(&db, &phantom.proposal_id, NOW).unwrap_err();
        assert!(matches!(err, TallyError::UnknownProposal(_)));
    }

    #[test]
    fn tallying_without_a_published_charter_is_an_error() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Members and a proposal, but no Charter on the log.
        let members = established_members(&db, &station, 4, NOW);
        let author = members[0].clone();
        let mut log = AppendLog::new(&db);
        let proposal = statute(&author, NOW);
        append_proposal(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
        )
        .unwrap();
        for c in &members[1..4] {
            append_cosign(&mut log, cosign(c, &proposal, NOW), &db).unwrap();
        }

        let err = tally(&db, &proposal.proposal_id, NOW).unwrap_err();
        assert!(matches!(err, TallyError::NoCharter));
    }
}
