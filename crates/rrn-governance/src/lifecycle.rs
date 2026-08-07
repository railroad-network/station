//! Lifecycle — carrying a passed proposal the last step, from decided to in force.
//!
//! Deliberation, voting, and the tally are read models over the log: they *observe*
//! where a proposal stands. Enactment is the one step that *writes* — the community
//! having decided, the station records that the decision now takes effect. A
//! non-emergency measure waits out its implementation delay first; an emergency
//! takes effect the moment it passes (its higher approval bar, not a shorter delay,
//! is what guarded the haste).
//!
//! [`enact_due`] is the sweep behind that step — the governance analogue of the
//! settlement sweep. Run periodically by the station, it finds every passed
//! proposal whose implementation time has arrived and is not yet enacted, and
//! appends a station-signed [`ProposalImplemented`](crate::statute::ProposalImplemented)
//! for each (via the guarded [`record_implementation`]). It is idempotent: a
//! proposal already enacted is skipped, so re-running after downtime catches up
//! what came due without re-enacting what did not.

use rrn_crypto::keypair::Keypair;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::proposal::{all_proposals, ProposalError, ProposalId};
use crate::statute::{is_implemented, record_implementation};
use crate::tally::{tally, ProposalOutcome};

/// Enacts every proposal that has passed and come due as of `now`, appending a
/// station-signed enactment record for each. Returns the ids enacted this pass.
///
/// A proposal is enacted when it has passed its vote, its `implementation_at` has
/// arrived (`now >= implementation_at`), and it is not already enacted. A proposal
/// that cannot be tallied yet — no Charter published, say — is simply left for a
/// later tick rather than failing the sweep; only a failure to read the proposal
/// set at all is surfaced.
pub fn enact_due(
    db: &Database,
    station: &Keypair,
    now: i64,
) -> Result<Vec<ProposalId>, LifecycleError> {
    let proposals = {
        let log = AppendLog::new(db);
        all_proposals(&log, db)?
    };

    let mut log = AppendLog::new(db);
    let mut enacted = Vec::new();
    for proposal in proposals {
        if is_implemented(&log, &proposal.proposal_id) {
            continue;
        }
        // A proposal we cannot tally this tick (e.g. no Charter yet) is not due to
        // be enacted; leave it for later rather than failing the whole sweep.
        let Ok(counted) = tally(db, &proposal.proposal_id, now) else {
            continue;
        };
        if counted.outcome != Some(ProposalOutcome::Passed) || now < proposal.implementation_at {
            continue;
        }
        // The write path re-checks passage, due-ness, and non-duplication; a lost
        // race just means we skip it and catch it on the next pass.
        if record_implementation(&mut log, db, station, &proposal, now).is_ok() {
            enacted.push(proposal.proposal_id);
        }
    }
    Ok(enacted)
}

/// A reason the enactment sweep could not run to completion.
#[derive(thiserror::Error, Debug)]
pub enum LifecycleError {
    /// The set of authorized proposals could not be read from the log.
    #[error("proposal: {0}")]
    Proposal(#[from] ProposalError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charter::{
        create_charter, AmendmentRules, Charter, CharterParams, GovernanceStructure,
    };
    use crate::proposal::{append_cosign, append_proposal, Proposal, ProposalCosign, ProposalKind};
    use crate::statute::{enacted_statutes, record_implementation, StatuteError};
    use crate::tally::{effective_charter, effective_charter_hash};
    use crate::vote::{append_vote, SignedVote, Vote, VoteChoice};
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::address::Address;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
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

    fn charter_body(version: u32, previous_hash: Option<rrn_crypto::hash::Hash>) -> Charter {
        Charter {
            version,
            community_id: "commons".into(),
            founding_principles: vec![],
            rights_floor: vec![],
            governance_structure: GovernanceStructure::default(),
            amendment_rules: AmendmentRules::default(),
            created_at: 0,
            founders: vec![],
            previous_hash,
        }
    }

    /// Publishes the founder-signed genesis (v1) Charter and returns its hash.
    fn publish_genesis(db: &Database, founders: &[Keypair]) -> rrn_crypto::hash::Hash {
        let body = charter_body(1, None);
        let params = CharterParams {
            version: body.version,
            community_id: body.community_id.clone(),
            founding_principles: body.founding_principles.clone(),
            rights_floor: body.rights_floor.clone(),
            governance_structure: body.governance_structure.clone(),
            amendment_rules: body.amendment_rules.clone(),
            founders: founders.iter().map(addr).collect(),
            created_at: body.created_at,
            previous_hash: body.previous_hash,
        };
        let signed = create_charter(params, founders).unwrap();
        let hash = signed.charter_hash();
        let mut log = AppendLog::new(db);
        log.append(SignedPayload::sign(signed, &founders[0]))
            .unwrap();
        hash
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

    /// Files `proposal` (author = members[0], co-signed by members[1..4]) and has
    /// every member cast `choice`. Leaves it published with ballots in.
    fn file_and_vote(db: &Database, members: &[Keypair], proposal: &Proposal, choice: VoteChoice) {
        let mut log = AppendLog::new(db);
        append_proposal(
            &mut log,
            SignedPayload::sign(proposal.clone(), &members[0]),
            db,
        )
        .unwrap();
        for c in &members[1..4] {
            append_cosign(&mut log, cosign(c, proposal, NOW), db).unwrap();
        }
        for m in members {
            append_vote(&mut log, vote(m, proposal, choice, NOW), db).unwrap();
        }
    }

    fn statute(author: &Keypair, charter: &Charter) -> Proposal {
        Proposal::new(
            addr(author),
            "Quiet hours in the workshop".into(),
            "No power tools after 9pm.".into(),
            ProposalKind::Statute,
            NOW,
            charter,
        )
        .unwrap()
    }

    // --- The sweep -----------------------------------------------------------

    #[test]
    fn a_passed_statute_is_deferred_until_its_time_then_enacted() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        publish_genesis(&db, &members);
        let charter = charter_body(1, None);
        let proposal = statute(&members[0], &charter);
        file_and_vote(&db, &members, &proposal, VoteChoice::Yes);

        // Voting has closed and it passed, but the implementation delay has not run:
        // the sweep enacts nothing yet.
        assert!(enact_due(&db, &station, proposal.voting_ends_at + 1)
            .unwrap()
            .is_empty());
        assert!(enacted_statutes(&db).unwrap().is_empty());

        // At implementation_at the sweep puts it into force.
        let enacted = enact_due(&db, &station, proposal.implementation_at).unwrap();
        assert_eq!(enacted, vec![proposal.proposal_id]);
        let in_force = enacted_statutes(&db).unwrap();
        assert_eq!(in_force.len(), 1);
        assert_eq!(in_force[0].proposal.proposal_id, proposal.proposal_id);
        assert_eq!(in_force[0].implemented_at, proposal.implementation_at);

        // Re-running is idempotent: nothing new is enacted.
        assert!(enact_due(&db, &station, proposal.implementation_at + MONTH)
            .unwrap()
            .is_empty());
        assert_eq!(enacted_statutes(&db).unwrap().len(), 1);
    }

    #[test]
    fn an_emergency_is_enacted_the_moment_it_passes() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        publish_genesis(&db, &members);
        let charter = charter_body(1, None);
        let emergency = Proposal::new(
            addr(&members[0]),
            "Close the workshop after the flood".into(),
            "No entry until the electrics are checked.".into(),
            ProposalKind::Emergency {
                expires_at: NOW + MONTH,
            },
            NOW,
            &charter,
        )
        .unwrap();
        // An emergency takes effect the instant it passes — no implementation delay.
        assert_eq!(emergency.implementation_at, emergency.voting_ends_at);
        file_and_vote(&db, &members, &emergency, VoteChoice::Yes);

        // The first sweep after the window closes enacts it immediately.
        let enacted = enact_due(&db, &station, emergency.voting_ends_at + 1).unwrap();
        assert_eq!(enacted, vec![emergency.proposal_id]);
    }

    #[test]
    fn a_failed_proposal_is_never_enacted() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        publish_genesis(&db, &members);
        let charter = charter_body(1, None);
        let proposal = statute(&members[0], &charter);
        // Everyone votes No: it fails approval.
        file_and_vote(&db, &members, &proposal, VoteChoice::No);

        assert!(enact_due(&db, &station, proposal.implementation_at + MONTH)
            .unwrap()
            .is_empty());
        assert!(enacted_statutes(&db).unwrap().is_empty());

        // And the guard refuses a direct attempt.
        let mut log = AppendLog::new(&db);
        let err = record_implementation(
            &mut log,
            &db,
            &station,
            &proposal,
            proposal.implementation_at,
        )
        .unwrap_err();
        assert!(matches!(err, StatuteError::NotPassed(_)));
    }

    #[test]
    fn the_guard_refuses_an_early_enactment() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        publish_genesis(&db, &members);
        let charter = charter_body(1, None);
        let proposal = statute(&members[0], &charter);
        file_and_vote(&db, &members, &proposal, VoteChoice::Yes);

        let mut log = AppendLog::new(&db);
        let err = record_implementation(
            &mut log,
            &db,
            &station,
            &proposal,
            proposal.voting_ends_at + 1,
        )
        .unwrap_err();
        assert!(matches!(err, StatuteError::NotYetDue { .. }));
    }

    // --- Charter amendment supersession (ADR-0012 § 4) -----------------------

    #[test]
    fn an_enacted_amendment_supersedes_the_charter() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        let v1_hash = publish_genesis(&db, &members);
        let v1 = charter_body(1, None);

        // A v2 that chains to v1.
        let v2 = charter_body(2, Some(v1_hash));
        let v2_hash = v2.hash();
        let amendment = Proposal::new(
            addr(&members[0]),
            "Raise the workshop budget".into(),
            "Version 2 of the charter.".into(),
            ProposalKind::CharterAmendment {
                new_charter: v2.clone(),
            },
            NOW,
            &v1,
        )
        .unwrap();
        // Unanimous yes clears the 75% charter-amendment approval bar.
        file_and_vote(&db, &members, &amendment, VoteChoice::Yes);

        // Before enactment the effective charter is still v1.
        assert_eq!(effective_charter(&db).unwrap().unwrap().version, 1);
        assert_eq!(effective_charter_hash(&db).unwrap(), Some(v1_hash));

        // The sweep enacts it once its implementation time arrives...
        let enacted = enact_due(&db, &station, amendment.implementation_at).unwrap();
        assert_eq!(enacted, vec![amendment.proposal_id]);

        // ...and now the effective charter is v2.
        let effective = effective_charter(&db).unwrap().unwrap();
        assert_eq!(effective.version, 2);
        assert_eq!(effective_charter_hash(&db).unwrap(), Some(v2_hash));
    }

    #[test]
    fn a_failed_amendment_does_not_supersede_even_if_a_record_is_forged() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 4, NOW);
        let v1_hash = publish_genesis(&db, &members);
        let v1 = charter_body(1, None);

        let v2 = charter_body(2, Some(v1_hash));
        let amendment = Proposal::new(
            addr(&members[0]),
            "A rejected amendment".into(),
            "Version 2 nobody wanted.".into(),
            ProposalKind::CharterAmendment { new_charter: v2 },
            NOW,
            &v1,
        )
        .unwrap();
        // It fails: everyone votes No.
        file_and_vote(&db, &members, &amendment, VoteChoice::No);

        // Forge an enactment record for the failed amendment, exactly as a
        // gossiped entry could carry one — bypassing the guard.
        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(
                crate::statute::ProposalImplemented {
                    proposal_id: amendment.proposal_id,
                    implemented_at: amendment.implementation_at,
                },
                &station,
            ))
            .unwrap();
        }

        // The effective charter re-derives passage and refuses to advance.
        assert_eq!(effective_charter(&db).unwrap().unwrap().version, 1);
        // And the statutes view drops the illegitimate record.
        assert!(enacted_statutes(&db).unwrap().is_empty());
    }
}
