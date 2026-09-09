//! Vote — a member's signed ballot on a proposal, one per eligible identity.
//!
//! # Shape
//!
//! A [`Vote`] names the [`ProposalId`] it answers, its [`voter`](Vote::voter),
//! a [`VoteChoice`] of `Yes` / `No` / `Abstain`, and the `cast_at` moment it was
//! made. The voter signs it, yielding a [`SignedVote`] appended to the log. There
//! is nothing else to a ballot: one member, one vote, the simplest direct
//! mechanism (ADR-0012, design overview § 2.3). Weighting, delegation, and
//! anonymity are all Phase 2.
//!
//! # When a ballot counts
//!
//! A vote is accepted — and, on replay, counted — only when every one of these
//! holds, so a station appending locally and a station replaying gossip reach the
//! same verdict:
//!
//! - it is **self-signed**: the envelope's signer is the named voter;
//! - the proposal exists and has **published** (cleared its co-sign threshold, so
//!   it is genuinely open for voting — a ballot on a motion still gathering
//!   endorsements does not count, matching the proposal module's rule that votes
//!   do not count in [`Deliberation`](crate::proposal::ProposalPhase::Deliberation));
//! - the ballot is **admitted within the proposal's window** — admitted by the
//!   attested `voting_ends_at`, judged on the admitting station's *admission*
//!   clock, not the voter's `cast_at` (ADR-0022 / T2.1.3). This bound is enforced
//!   on the **write path** ([`append_vote`]): the station takes a ballot only while
//!   its own admission clock is still inside the window. Replay does **not**
//!   re-apply the close — `created_at` is re-stamped per replica, so a wall-clock
//!   re-gate would make a late-syncing replica drop ballots the admitting station
//!   accepted. Instead, exactly as the ledger gates settlement at admission and
//!   then trusts the settled record on replay (ADR-0022 §2), [`votes`] trusts that
//!   a ballot on the log was admitted in-window by the station that took it, and
//!   counts every ballot admitted after the proposal's open *position*. Phase 1
//!   runs deliberation and voting as one window (ADR-0012).
//!   > Note: publication is monotonic (co-signatures only accrue), so a ballot
//!   > accepted while the proposal was published stays published — and valid —
//!   > under any later replay.
//! - the voter is in the **electorate pinned at the proposal's open log
//!   position** — an established member (or grace founder) then, the same
//!   frozen electorate that authors and co-signs (T2.1.3);
//! - the voter has **not already voted** on this proposal.
//!
//! The electorate is pinned by open *position* and the window is anchored on the
//! attested admission instant, never on the voter's `cast_at` (retained as
//! testimony only), so replay is replica-deterministic: two replicas replaying the
//! same log agree on which ballots count and on the electorate. The one residual —
//! a ballot raw-replicated onto a replica without ever being window-gated by an
//! honest station — is documented in the `rrn-governance` threat-model section.
//!
//! # No changing a vote (Phase 1)
//!
//! There is no replace-vote. The first ballot a member casts on a proposal is
//! their ballot; a second is refused on the write path and ignored on replay
//! ([`votes`] keeps the first). Vote *silence* is not abstain — a member who never
//! casts simply did not participate, which bears on quorum (T1.9.6) but is not a
//! choice. Abstain is an explicit third choice that does count toward quorum.
//!
//! # State is derived, never stored
//!
//! [`votes`] replays the log into the valid ballots for one proposal, and the
//! append guard [`append_vote`] applies the identical rules on the write path, so
//! authorization and replay cannot drift. The tally (T1.9.6) reduces [`votes`] to
//! an outcome; this module stops at the ballots.

use std::collections::HashMap;

use dcbor::prelude::*;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};

use crate::proposal::{
    composite_at_position, effective_cosign_threshold, founder_set, is_eligible_asof,
    proposal_records, ProposalError, ProposalId,
};

/// Discriminant carried in the `kind` field of a [`Vote`]'s canonical CBOR, so
/// log replay can tell a ballot apart from other records.
pub(crate) const VOTE_KIND: &str = "rrn.gov.vote";

/// How a member voted on a proposal. Silence is not one of these — a member who
/// never casts a ballot did not participate, which is not the same as an explicit
/// [`Abstain`](VoteChoice::Abstain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteChoice {
    /// In favour.
    Yes,
    /// Against.
    No,
    /// Present but declining to take a side — counts toward quorum, not approval.
    Abstain,
}

/// A member's signed ballot on a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vote {
    /// The proposal being voted on.
    pub proposal_id: ProposalId,
    /// Who is voting. Redundant with the envelope's signer and kept so the claim
    /// travels inside the signed content: replay checks both, and a ballot whose
    /// content disagrees with its signature is rejected, not resolved.
    pub voter: Address,
    /// The choice cast.
    pub choice: VoteChoice,
    /// Unix seconds the ballot was cast — the voter's clock. **Testimony only**
    /// (ADR-0022 / T2.1.3): the ballot's window membership runs on its admission,
    /// and the voter's standing is judged at the proposal's open log position;
    /// neither reads this.
    pub cast_at: i64,
}

/// A [`Vote`] signed by its voter — the record appended to the log.
pub type SignedVote = SignedPayload<Vote>;

/// Replays the log into the valid ballots on one proposal: voter to choice.
///
/// Empty when the proposal is unknown to this log or has not published — a motion
/// that never opened for voting has no ballots that count. A ballot counts only
/// when it is self-signed, lands within the proposal's window, and comes from an
/// established member as of when it was cast; the first ballot a member casts wins
/// and any later one from the same member is ignored (there is no vote-change in
/// Phase 1). These are the same rules [`append_vote`] enforces, applied here so a
/// gossiped entry that dodged the guards is not believed.
pub fn votes(
    log: &AppendLog,
    proposal_id: &ProposalId,
    db: &Database,
) -> Result<HashMap<Address, VoteChoice>, VoteError> {
    let records = proposal_records(log, proposal_id, db)?;
    if records.proposal.is_none() {
        return Ok(HashMap::new());
    }
    let (open_seq, open_time) = (records.open_seq, records.open_time);
    if !records.is_published(effective_cosign_threshold(db, open_time, open_seq)?) {
        return Ok(HashMap::new());
    }

    let founders = founder_set(db)?;
    let mut ballots: HashMap<Address, VoteChoice> = HashMap::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(vote) = from_canonical_bytes::<Vote>(&entry.payload.bytes) else {
            continue;
        };
        if vote.proposal_id != *proposal_id {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != vote.voter {
            continue;
        }
        // A ballot is admitted *after* the proposal opens; an entry at or before the
        // open position is never a ballot on this proposal (only reachable via
        // gossip injection). Log *position* orders the log — not the re-stamped
        // `created_at` — so this gate is replica-identical (ADR-0022 / T2.1.3).
        if entry.seq <= open_seq {
            continue;
        }
        // The voting-window bound is enforced on the *write* path (`append_vote`,
        // against the admitting station's own clock), just as the ledger gates
        // settlement at admission and thereafter trusts the settled log record on
        // replay (ADR-0022 §2). Replay does *not* re-apply a wall-clock close:
        // `created_at` is re-stamped per replica, so re-gating here would make a
        // late-syncing replica drop ballots the admitting station accepted and
        // split the tally. A ballot on the log was admitted in-window by the station
        // that took it; replay counts it. (Residual: a raw-replicated ballot never
        // gated by an honest station — see threat-model, `rrn-governance` STRIDE.)
        //
        // Voter eligibility is pinned at the proposal's open position — the frozen
        // electorate — not at the ballot's own admission.
        if !is_eligible_asof(db, &founders, &vote.voter, open_time, open_seq)? {
            continue;
        }
        // First ballot wins; a later one from the same voter is ignored.
        ballots.entry(vote.voter).or_insert(vote.choice);
    }
    Ok(ballots)
}

/// Records a member's ballot on a proposal: appends the voter's signed [`Vote`].
///
/// Rejects a ballot whose signer is not its voter, one against a proposal this log
/// has not seen or that has not yet published, one cast outside the proposal's
/// voting window, one from a member without standing, and a second ballot from a
/// member who has already voted.
pub fn append_vote(
    log: &mut AppendLog,
    signed: SignedVote,
    db: &Database,
    now: i64,
) -> Result<LogEntry, VoteError> {
    let vote = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != vote.voter {
        return Err(VoteError::SignerNotVoter {
            signer,
            voter: vote.voter,
        });
    }

    let records = proposal_records(log, &vote.proposal_id, db)?;
    let Some(proposal) = records.proposal.as_ref() else {
        return Err(VoteError::UnknownProposal(vote.proposal_id));
    };
    let (open_seq, open_time) = (records.open_seq, records.open_time);
    if !records.is_published(effective_cosign_threshold(db, open_time, open_seq)?) {
        return Err(VoteError::ProposalNotPublished(vote.proposal_id));
    }
    // The ballot will be admitted at the monotone-clamped `now`; the window is on
    // that admission, not the voter's `cast_at` (ADR-0022 / T2.1.3).
    let admitted_at = match log.tail()? {
        Some(t) => now.max(t.created_at),
        None => now,
    };
    if admitted_at > proposal.voting_ends_at {
        return Err(VoteError::OutsideVotingWindow {
            proposal_id: vote.proposal_id,
            admitted_at,
            open_time,
            voting_ends_at: proposal.voting_ends_at,
        });
    }

    if !is_eligible_asof(db, &founder_set(db)?, &vote.voter, open_time, open_seq)? {
        return Err(VoteError::VoterNotEstablished {
            voter: vote.voter,
            composite: composite_at_position(db, &vote.voter, open_time, open_seq)?,
        });
    }

    if votes(log, &vote.proposal_id, db)?.contains_key(&vote.voter) {
        return Err(VoteError::AlreadyVoted {
            proposal_id: vote.proposal_id,
            voter: vote.voter,
        });
    }

    Ok(log.append(signed, now)?)
}

/// A ballot the write path would not accept, or a record the replay would not
/// believe. One variant per rule, so a caller can tell which requirement failed.
#[derive(thiserror::Error, Debug)]
pub enum VoteError {
    /// The envelope's signer is not the ballot's voter.
    #[error("vote signed by {signer}, but its voter is {voter}")]
    SignerNotVoter {
        /// Who signed.
        signer: Address,
        /// Who the ballot names as voter.
        voter: Address,
    },
    /// No authorized proposal with this id — nothing to vote on.
    #[error("no proposal {0} on this log")]
    UnknownProposal(ProposalId),
    /// The proposal exists but has not cleared its co-sign threshold, so it is not
    /// yet open for voting.
    #[error("proposal {0} has not published; voting is not open")]
    ProposalNotPublished(ProposalId),
    /// The ballot was *admitted* after the proposal's window closed (ADR-0022:
    /// the window runs on admission, not the voter's `cast_at`).
    #[error(
        "vote on proposal {proposal_id} admitted at {admitted_at} is outside \
         the voting window [{open_time}, {voting_ends_at}]"
    )]
    OutsideVotingWindow {
        /// The proposal.
        proposal_id: ProposalId,
        /// When the ballot was admitted (the station clock at admission).
        admitted_at: i64,
        /// When the window opened (the proposal's admission).
        open_time: i64,
        /// When the window closes (the attested `voting_ends_at`).
        voting_ends_at: i64,
    },
    /// The voter is not an established member as of when they cast the ballot.
    #[error("voter {voter} is not an established member (composite {composite:.2} < 2.0)")]
    VoterNotEstablished {
        /// The voter.
        voter: Address,
        /// Their effective composite at the ballot's `cast_at`.
        composite: f32,
    },
    /// This member has already voted on this proposal, and Phase 1 does not allow
    /// changing a vote.
    #[error("{voter} has already voted on proposal {proposal_id}")]
    AlreadyVoted {
        /// The proposal.
        proposal_id: ProposalId,
        /// The member who tried to vote twice.
        voter: Address,
    },
    /// An error from the proposal layer while reading the log or evaluating the
    /// established-member gate (a storage or reputation failure).
    #[error("proposal layer: {0}")]
    Proposal(#[from] ProposalError),
    /// A storage/log error while appending.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
}

// --- Canonical CBOR ---------------------------------------------------------

impl From<VoteChoice> for CBOR {
    fn from(c: VoteChoice) -> Self {
        match c {
            VoteChoice::Yes => "yes".into(),
            VoteChoice::No => "no".into(),
            VoteChoice::Abstain => "abstain".into(),
        }
    }
}

impl TryFrom<CBOR> for VoteChoice {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        match String::try_from(cbor)?.as_str() {
            "yes" => Ok(VoteChoice::Yes),
            "no" => Ok(VoteChoice::No),
            "abstain" => Ok(VoteChoice::Abstain),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

impl From<Vote> for CBOR {
    fn from(v: Vote) -> Self {
        let mut m = Map::new();
        m.insert("kind", VOTE_KIND);
        m.insert("proposal_id", v.proposal_id);
        m.insert("voter", v.voter);
        m.insert("choice", v.choice);
        m.insert("cast_at", v.cast_at);
        m.into()
    }
}

impl TryFrom<CBOR> for Vote {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != VOTE_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(Vote {
            proposal_id: map.extract::<&str, ProposalId>("proposal_id")?,
            voter: map.extract::<&str, Address>("voter")?,
            choice: map.extract::<&str, VoteChoice>("choice")?,
            cast_at: map.extract::<&str, i64>("cast_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charter::{AmendmentRules, Charter, GovernanceStructure};
    use crate::proposal::{append_cosign, append_proposal, Proposal, ProposalCosign, ProposalKind};
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::to_canonical_bytes;
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
        log.append(SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        log.append(
            SignedPayload::sign(
                TransactionConfirmation {
                    proposal_id: pid,
                    confirmer: addr(receiver),
                    confirmed_at: at,
                },
                receiver,
            ),
            0,
        )
        .unwrap();
        log.append(
            SignedPayload::sign(
                SettlementRecord {
                    proposal_id: pid,
                    sender: addr(sender),
                    receiver: addr(receiver),
                    amount_centi: 300,
                    settled_at: at,
                },
                station,
            ),
            0,
        )
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
        log.append(vouch.sign(voucher), 0).unwrap();
    }

    fn earn_raw_standing(db: &Database, who: &Keypair, station: &Keypair, at: i64) {
        for nonce in 0..10 {
            append_settled(db, who, station, station, nonce, at);
        }
        for _ in 0..10 {
            append_vouch(db, who, &addr(&Keypair::generate()), at);
        }
    }

    /// Builds `n` established members: each earns raw standing over the Member
    /// band, then is anchored by a vouch from the next in a ring.
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

    fn test_charter() -> Charter {
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

    fn statute(author: &Keypair, at: i64) -> Proposal {
        let mut p = Proposal::new(
            addr(author),
            "Quiet hours in the workshop".into(),
            "No power tools after 9pm.".into(),
            ProposalKind::Statute,
            at,
        )
        .unwrap();
        // Populate the window cache the way the station attestation will (tests
        // append at `at`, so admitted_at == at).
        let (v, i) = crate::window::window_for(&test_charter(), &p.kind, at);
        p.voting_ends_at = v;
        p.implementation_at = i;
        p
    }

    /// Drop-in for the old `append_proposal(log, signed, db, at)`: supplies a
    /// station keypair and the default test charter for the window attestation.
    fn propose(
        log: &mut AppendLog,
        signed: crate::proposal::SignedProposal,
        db: &Database,
        at: i64,
    ) -> Result<LogEntry, ProposalError> {
        append_proposal(log, signed, db, &Keypair::generate(), &test_charter(), at)
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

    /// A published statute plus the members: `[0]` authored it, `[1..=3]`
    /// co-signed it to publication, and every member is established and eligible
    /// to vote. Returns `(log, members, proposal)`.
    fn published_statute(
        db: &Database,
        station: &Keypair,
        extra_voters: usize,
    ) -> (Vec<Keypair>, Proposal) {
        let members = established_members(db, station, 4 + extra_voters, NOW);
        let author = members[0].clone();
        let mut log = AppendLog::new(db);
        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            db,
            NOW,
        )
        .unwrap();
        for c in &members[1..4] {
            append_cosign(&mut log, cosign(c, &proposal, NOW), db, NOW).unwrap();
        }
        (members, proposal)
    }

    // --- Casting -------------------------------------------------------------

    #[test]
    fn a_member_can_cast_a_vote_and_it_lands_in_the_log() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap();

        let ballots = votes(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(ballots.get(&addr(&members[1])), Some(&VoteChoice::Yes));
        assert_eq!(ballots.len(), 1);
    }

    #[test]
    fn every_choice_round_trips_through_the_ballots() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[0], &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap();
        append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::No, NOW),
            &db,
            NOW,
        )
        .unwrap();
        append_vote(
            &mut log,
            vote(&members[2], &proposal, VoteChoice::Abstain, NOW),
            &db,
            NOW,
        )
        .unwrap();

        let ballots = votes(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(ballots.get(&addr(&members[0])), Some(&VoteChoice::Yes));
        assert_eq!(ballots.get(&addr(&members[1])), Some(&VoteChoice::No));
        assert_eq!(ballots.get(&addr(&members[2])), Some(&VoteChoice::Abstain));
    }

    #[test]
    fn the_author_may_vote_on_their_own_proposal() {
        // Unlike co-signing, voting by the author is allowed — a ballot is a
        // choice, not an endorsement that publishes the motion.
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[0], &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap();
        assert!(votes(&log, &proposal.proposal_id, &db)
            .unwrap()
            .contains_key(&addr(&members[0])));
    }

    // --- Rejections ----------------------------------------------------------

    #[test]
    fn a_vote_signed_by_someone_other_than_its_voter_is_refused() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        // Ballot names members[1] as voter but is signed by members[2].
        let forged = SignedPayload::sign(
            Vote {
                proposal_id: proposal.proposal_id,
                voter: addr(&members[1]),
                choice: VoteChoice::Yes,
                cast_at: NOW,
            },
            &members[2],
        );
        let err = append_vote(&mut log, forged, &db, NOW).unwrap_err();
        assert!(matches!(err, VoteError::SignerNotVoter { .. }));
    }

    #[test]
    fn a_double_vote_is_rejected() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap();
        // Even a different choice cannot replace the first ballot.
        let err = append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::No, NOW),
            &db,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, VoteError::AlreadyVoted { .. }));
    }

    #[test]
    fn a_vote_admitted_after_the_window_closes_is_rejected() {
        // The window runs on *admission* (T2.1.3): a ballot admitted after the
        // proposal's close is refused, whatever its `cast_at` claims.
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        let err = append_vote(
            &mut log,
            // An in-window `cast_at`, but admitted after close.
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
            proposal.voting_ends_at + 1,
        )
        .unwrap_err();
        assert!(matches!(err, VoteError::OutsideVotingWindow { .. }));
    }

    #[test]
    fn cast_at_is_testimony_the_window_runs_on_admission() {
        // A ballot with an out-of-range `cast_at` (before the proposal even
        // existed) is still counted when *admitted* inside the window: `cast_at`
        // is testimony, never the gate (ADR-0022 / T2.1.3).
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        append_vote(
            &mut log,
            vote(
                &members[1],
                &proposal,
                VoteChoice::Yes,
                proposal.created_at - 1,
            ),
            &db,
            NOW,
        )
        .expect("a ballot admitted in-window counts regardless of its cast_at");
        assert_eq!(
            votes(&log, &proposal.proposal_id, &db).unwrap().len(),
            1,
            "the back-dated-cast_at ballot is counted"
        );
    }

    #[test]
    fn a_non_member_may_not_vote() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (_members, proposal) = published_statute(&db, &station, 0);
        let outsider = Keypair::generate(); // no standing
        let mut log = AppendLog::new(&db);

        let err = append_vote(
            &mut log,
            vote(&outsider, &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, VoteError::VoterNotEstablished { .. }));
    }

    #[test]
    fn voting_on_an_unknown_proposal_is_refused() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 2, NOW);
        let mut log = AppendLog::new(&db);

        // A proposal that was never appended.
        let phantom = statute(&members[0], NOW);
        let err = append_vote(
            &mut log,
            vote(&members[1], &phantom, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, VoteError::UnknownProposal(_)));
    }

    #[test]
    fn voting_on_a_proposal_still_deliberating_is_refused() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Enough members to vote, but the proposal is never co-signed to publication.
        let members = established_members(&db, &station, 4, NOW);
        let author = members[0].clone();
        let mut log = AppendLog::new(&db);
        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();

        let err = append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, VoteError::ProposalNotPublished(_)));
        // And nothing counts while it is unpublished.
        assert!(votes(&log, &proposal.proposal_id, &db).unwrap().is_empty());
    }

    // --- Replay --------------------------------------------------------------

    #[test]
    fn replay_ignores_ballots_a_gossiped_entry_could_carry() {
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let outsider = Keypair::generate();
        let mut log = AppendLog::new(&db);

        // A legitimate ballot.
        append_vote(
            &mut log,
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            &db,
            NOW,
        )
        .unwrap();

        // Bypass the guards exactly as replication does: an outsider's ballot (no
        // standing), a ballot forged onto another member (signer != voter), and a
        // second ballot from members[1] (first-wins) must all be dropped by replay —
        // dropped by the electorate, signer, and dedup guards, none of which is the
        // window. (The window bound is a write-path gate, not re-applied on replay —
        // see `replay_counts_a_ballot_present_on_the_log`.)
        log.append(vote(&outsider, &proposal, VoteChoice::Yes, NOW), NOW)
            .unwrap();
        log.append(
            SignedPayload::sign(
                Vote {
                    proposal_id: proposal.proposal_id,
                    voter: addr(&members[3]),
                    choice: VoteChoice::No,
                    cast_at: NOW,
                },
                &members[2], // signer != voter
            ),
            NOW,
        )
        .unwrap();
        log.append(vote(&members[1], &proposal, VoteChoice::No, NOW), NOW)
            .unwrap();

        let ballots = votes(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(ballots.len(), 1);
        // The first ballot from members[1] stands; the later No is ignored.
        assert_eq!(ballots.get(&addr(&members[1])), Some(&VoteChoice::Yes));
    }

    #[test]
    fn replay_counts_a_ballot_present_on_the_log() {
        // The voting window is enforced on the *write* path (`append_vote`, against
        // the admitting station's clock); replay does not re-apply it. `created_at`
        // is re-stamped per replica (ADR-0022 §1), so re-gating on it here would make
        // a late-syncing replica drop ballots the admitting station accepted, and two
        // replicas of one chain would disagree. So a ballot present on the log — from
        // an eligible voter, positioned after the proposal's open — is counted on
        // replay whatever this replica's local admission clock reads. This is the
        // residual noted in the module docs and threat model: a raw-replicated ballot
        // is trusted to have been window-gated by the station that first took it.
        let db = fresh_db();
        let station = Keypair::generate();
        let (members, proposal) = published_statute(&db, &station, 0);
        let mut log = AppendLog::new(&db);

        // Raw-appended (as replication does, bypassing `append_vote`) and re-stamped
        // with an admission clock long past the close — yet counted.
        log.append(
            vote(&members[1], &proposal, VoteChoice::Yes, NOW),
            proposal.voting_ends_at + 1_000_000,
        )
        .unwrap();

        let ballots = votes(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(ballots.len(), 1);
        assert_eq!(ballots.get(&addr(&members[1])), Some(&VoteChoice::Yes));
    }

    // --- Model: CBOR ---------------------------------------------------------

    #[test]
    fn vote_cbor_roundtrips_for_every_choice() {
        let voter = Keypair::generate();
        let proposal = statute(&voter, NOW);
        for choice in [VoteChoice::Yes, VoteChoice::No, VoteChoice::Abstain] {
            let v = Vote {
                proposal_id: proposal.proposal_id,
                voter: addr(&voter),
                choice,
                cast_at: NOW,
            };
            let back: Vote = from_canonical_bytes(&to_canonical_bytes(v)).unwrap();
            assert_eq!(v, back);
        }
    }
}
