//! Proposal — a signed motion put to the community, and the lifecycle it moves
//! through.
//!
//! # Shape
//!
//! A [`Proposal`] is a member's motion: a title, a markdown body, and a
//! [`ProposalKind`] saying what it would do — a [`Statute`](ProposalKind::Statute),
//! an [`AdministrativeRule`](ProposalKind::AdministrativeRule), a
//! [`CharterAmendment`](ProposalKind::CharterAmendment) carrying a full
//! replacement Charter (ADR-0012 § 4), or an [`Emergency`](ProposalKind::Emergency)
//! measure. Its [`ProposalId`] is the Blake3 of its canonical bytes, so identity
//! is content and two stations name the same motion the same way. The author signs
//! it, yielding a [`SignedProposal`], and it is appended to the log directly —
//! there is no separate "drafted" wrapper, for the same reason a listing is (a log
//! entry already is a signed payload; ADR-0010).
//!
//! # Who may propose, and what publishes a proposal
//!
//! Authorship requires standing: the author must be an **established member** —
//! effective (anchored) composite reputation at or above the Member band
//! ([`BAND_MEMBER_MIN`]) — as of the proposal's **open log position**, the seq at
//! which the station admitted it (ADR-0012 § 5, ADR-0022 / T2.1.3). Reading the
//! gate at the admission position rather than the author's self-asserted
//! `created_at` is what makes replay deterministic *and* unspoofable: a back-dated
//! timestamp cannot change who was established when the proposal opened.
//!
//! A drafted proposal is not yet live. It **publishes** — advances from gathering
//! endorsements to open for voting — once at least [`DEFAULT_COSIGN_THRESHOLD`]
//! distinct established members other than the author have co-signed it (a
//! [`ProposalCosign`] each). Co-signers are the anti-spam gate the task calls for:
//! a motion nobody else with standing will endorse never reaches the ballot.
//!
//! # One window: deliberate and vote together (Phase 1)
//!
//! Phase 1 runs deliberation and voting as a **single window** (the concurrent
//! model chosen for M1.9): the window opens at the proposal's **admission** and
//! closes at `voting_ends_at = admitted_at + window_days`, where `window_days` is
//! the Charter's `deliberation_window_days` for a statute or admin rule and its
//! `charter_deliberation_window_days` for an amendment. The window is *not* author
//! testimony and *not* part of the signed proposal (ADR-0022): the station
//! restates it in a signed [`crate::window::ProposalWindow`] attestation on
//! admission, and it is populated back onto the [`Proposal`] on replay. Members
//! discuss and cast ballots (T1.9.5) over that one span. A passed non-emergency
//! proposal takes effect after `implementation_delay_days` more
//! ([`Proposal::implementation_at`]); an [`Emergency`](ProposalKind::Emergency)
//! takes effect immediately on passing (its higher approval bar, not a shorter
//! window, is what guards abuse — a dedicated emergency window is Phase 2).
//!
//! # State is derived, never stored
//!
//! [`proposal_records`] replays the log into the proposal and its valid
//! co-signatures, and [`phase`] reduces those plus `now` to a [`ProposalPhase`].
//! Nothing writes the phase down — the log is canonical. The append guards
//! ([`append_proposal`], [`append_cosign`]) enforce authorization on the local
//! write path, and [`proposal_records`] re-applies the very same rules in replay,
//! so a record a gossiped entry smuggled past the guards is ignored rather than
//! believed. Both read the log through one path, so they cannot drift apart.

use std::collections::HashSet;

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_reputation::model::BAND_MEMBER_MIN;
use rrn_reputation::scoring::ReputationScorer;
use rrn_reputation::staking::{grace_electorate_asof, in_grace_asof};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};

use crate::charter::{founder_charter, Charter, CharterError, VotingMechanism};
use crate::window::{build_window, window_and_seq_of};

/// Discriminant carried in the `kind` field of a [`Proposal`]'s canonical CBOR,
/// so log replay can tell a proposal apart from other records.
pub(crate) const PROPOSAL_KIND: &str = "rrn.gov.proposal";

/// Discriminant carried in the `kind` field of a [`ProposalCosign`]'s canonical
/// CBOR.
pub(crate) const COSIGN_KIND: &str = "rrn.gov.proposal_cosign";

/// Distinct established co-signers a proposal needs before it publishes and opens
/// for voting. The task's default of three; the Charter carries no field to
/// override it in Phase 1, so making it Charter-configurable is Phase 2.
pub const DEFAULT_COSIGN_THRESHOLD: u32 = 3;

/// Longest a proposal title may be, in bytes.
pub const MAX_TITLE_BYTES: usize = 200;

/// Longest a proposal body may be, in bytes. Generous, since the body is markdown.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The content address of a proposal: the Blake3 hash of its canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, std::hash::Hash, Debug)]
pub struct ProposalId(pub Hash);

impl ProposalId {
    /// The 32 raw hash bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Bare hex, the form a proposal id takes everywhere a person meets one — a CLI
/// argument, a wire field, an error message. `Debug` stays wrapped for panics and
/// assertions; error text uses this.
impl std::fmt::Display for ProposalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// A total order over the hash bytes — content, not chronology — so a `ProposalId`
// can key an ordered collection identically on every replica.
impl Ord for ProposalId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for ProposalId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<ProposalId> for CBOR {
    fn from(id: ProposalId) -> Self {
        CBOR::to_byte_string(id.0.to_bytes())
    }
}

impl TryFrom<CBOR> for ProposalId {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(ProposalId(Hash::from_bytes(bytes)))
    }
}

/// What a proposal would do. The variants share one lifecycle but differ in the
/// windows they run under and their downstream effect.
///
/// The kind carries only what is *specific* to it — the human-readable title and
/// body live on the [`Proposal`] regardless — so the same rationale is never
/// encoded twice (a deliberate tightening of the task sketch, which repeated a
/// `body` inside each variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalKind {
    /// An ordinary community rule, subordinate to the Charter.
    Statute,
    /// A narrower administrative rule scoped to some part of community operation.
    AdministrativeRule {
        /// What the rule governs — a free-text scope label.
        scope: String,
    },
    /// A replacement Charter, ratified through the vote lifecycle rather than a
    /// fresh founder multisig (ADR-0012 § 4). The `new_charter` sets
    /// `version = prior + 1` and links `previous_hash`; that lineage is checked
    /// when the amendment is enacted, not when it is proposed.
    CharterAmendment {
        /// The full Charter that would supersede the current one on passage.
        new_charter: Charter,
    },
    /// A measure that takes effect immediately on passing, at a higher approval
    /// bar. `expires_at` is when the measure itself lapses.
    Emergency {
        /// Unix seconds when the emergency measure expires.
        expires_at: i64,
    },
}

impl ProposalKind {
    /// Whether this is an [`Emergency`](ProposalKind::Emergency) — the one kind
    /// that takes effect the moment it passes.
    pub fn is_emergency(&self) -> bool {
        matches!(self, ProposalKind::Emergency { .. })
    }
}

/// A member's motion put to the community.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// The content address, derived from every other field. Not part of the
    /// signed content: it is recomputed on read, so it cannot be forged by
    /// setting it and it does not sign itself.
    pub proposal_id: ProposalId,
    /// The established member who authored and signed the proposal.
    pub author: Address,
    /// A short human-readable title.
    pub title: String,
    /// The full text, markdown allowed.
    pub body: String,
    /// What the proposal would do.
    pub kind: ProposalKind,
    /// Unix seconds the proposal was created — the author's clock. **Testimony
    /// only** (ADR-0022): plausibility-bounded display/evidence, never window
    /// arithmetic. The window runs from *admission*, not this (T2.1.3).
    pub created_at: i64,
    /// Unix seconds the deliberation/voting window closes. **Not signed and not
    /// author-set**: derived from the station's admission of the proposal and
    /// carried in the [`crate::window::ProposalWindow`] attestation, populated
    /// onto this struct by [`find_proposal`] on replay. Zero on a freshly
    /// constructed or just-decoded proposal until populated.
    pub voting_ends_at: i64,
    /// Unix seconds a passed proposal takes effect. Same provenance as
    /// [`voting_ends_at`](Self::voting_ends_at): attestation-derived, not signed.
    pub implementation_at: i64,
}

impl Proposal {
    /// Builds a proposal, deriving its window timestamps from `charter` and its id
    /// from its content.
    ///
    /// The windows follow the kind: a statute or admin rule uses the Charter's
    /// `deliberation_window_days`, an amendment its `charter_deliberation_window_days`,
    /// and every non-emergency kind adds `implementation_delay_days` before taking
    /// effect. An emergency runs the ordinary deliberation window but takes effect
    /// the instant it passes.
    pub fn new(
        author: Address,
        title: String,
        body: String,
        kind: ProposalKind,
        created_at: i64,
    ) -> Result<Self, ProposalError> {
        // The window fields are NOT author-set and NOT part of the signed content
        // (ADR-0022, T2.1.3): they are derived from the station's *admission* of
        // this proposal and carried in the station-signed [`crate::window::ProposalWindow`]
        // attestation, then populated back onto this struct on replay
        // ([`find_proposal`]). At construction/sign time they are placeholder zeros.
        let mut proposal = Proposal {
            proposal_id: ProposalId(Hash::from_bytes([0u8; 32])),
            author,
            title,
            body,
            kind,
            created_at,
            voting_ends_at: 0,
            implementation_at: 0,
        };
        proposal.validate()?;
        proposal.proposal_id = proposal.compute_id();
        Ok(proposal)
    }

    /// The content address of this proposal — the hash of its canonical bytes,
    /// which exclude `proposal_id` itself.
    fn compute_id(&self) -> ProposalId {
        ProposalId(Hash::of(&to_canonical_bytes(self.clone())))
    }

    /// Checks the proposal's own rules — the ones that must hold no matter who
    /// signed it or when.
    fn validate(&self) -> Result<(), ProposalError> {
        if self.title.trim().is_empty() {
            return Err(ProposalError::EmptyTitle);
        }
        if self.title.len() > MAX_TITLE_BYTES {
            return Err(ProposalError::TitleTooLong {
                len: self.title.len(),
                max: MAX_TITLE_BYTES,
            });
        }
        if self.body.trim().is_empty() {
            return Err(ProposalError::EmptyBody);
        }
        if self.body.len() > MAX_BODY_BYTES {
            return Err(ProposalError::BodyTooLong {
                len: self.body.len(),
                max: MAX_BODY_BYTES,
            });
        }
        // Phase 1 keeps the amendment on Direct voting — the same constraint the
        // genesis Charter is held to (ADR-0012).
        if let ProposalKind::CharterAmendment { new_charter } = &self.kind {
            if new_charter.governance_structure.voting_mechanism != VotingMechanism::Direct {
                return Err(ProposalError::NonDirectVotingMechanism);
            }
        }
        Ok(())
    }
}

/// A [`Proposal`] signed by its author — the record appended to the log.
pub type SignedProposal = SignedPayload<Proposal>;

/// A member's endorsement of a proposal: what carries it over the co-sign
/// threshold and publishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalCosign {
    /// The proposal being endorsed.
    pub proposal_id: ProposalId,
    /// Who is endorsing. Redundant with the envelope's signer and kept so the
    /// claim travels inside the signed content: replay checks both, and a record
    /// whose content disagrees with its signature is rejected, not resolved.
    pub cosigner: Address,
    /// Unix seconds the endorsement was made — the co-signer's clock. **Testimony
    /// only** (ADR-0022 / T2.1.3): the co-signer's standing is judged at the
    /// proposal's open log position, not here.
    pub cosigned_at: i64,
}

/// A [`ProposalCosign`] signed by the co-signer.
pub type SignedCosign = SignedPayload<ProposalCosign>;

/// Every record on the log concerning one proposal.
///
/// The single derivation behind both the append guards and [`phase`], so
/// authorization and replay can never read the log differently.
#[derive(Clone, Debug, Default)]
pub struct ProposalRecords {
    /// The proposal itself, absent if this log has no valid record of it. When
    /// present its window fields (`voting_ends_at`/`implementation_at`) are
    /// populated from the station's [`crate::window::ProposalWindow`] attestation.
    pub proposal: Option<Proposal>,
    /// The distinct established members who have validly co-signed it.
    pub cosigners: HashSet<Address>,
    /// The log seq at which the proposal was admitted — its *open* position. The
    /// electorate (co-sign threshold, voter eligibility, quorum denominator) is
    /// pinned here (T2.1.3), so nothing admitted later can pack it. `0` when
    /// `proposal` is absent.
    pub open_seq: u64,
    /// The station's admission-clock reading at the proposal's open position. `0`
    /// when `proposal` is absent.
    pub open_time: i64,
}

impl ProposalRecords {
    /// How many distinct established members have co-signed.
    pub fn cosigner_count(&self) -> u32 {
        self.cosigners.len() as u32
    }

    /// Whether the proposal exists and has reached the co-sign threshold — i.e.
    /// has published and may open for voting.
    pub fn is_published(&self, cosign_threshold: u32) -> bool {
        self.proposal.is_some() && self.cosigner_count() >= cosign_threshold
    }
}

/// Where a proposal stands, derived by replaying the log. A computed view, never
/// stored: the records are the facts, and the phase is what they add up to at a
/// given `now`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalPhase {
    /// On the log and within its window, but not yet at the co-sign threshold:
    /// still gathering the endorsements that would publish it. Votes do not count
    /// in this phase.
    Deliberation,
    /// Co-sign threshold met and the window still open: published, and open for
    /// direct voting (T1.9.5). Phase 1 deliberation and voting share this one
    /// window (ADR-0012).
    Voting,
    /// The window has closed. `published` says whether it ever cleared the
    /// co-sign threshold; one that did not never opened for voting and has lapsed.
    /// Whether a published proposal *passed* is the tally's call (T1.9.6).
    Concluded {
        /// Whether the proposal reached the co-sign threshold before closing.
        published: bool,
    },
}

/// The phase `records` are in at `now`, or `None` if this log has no valid
/// proposal for them.
///
/// Monotonic in `now`: a proposal moves Deliberation → Voting → Concluded and
/// never back, and never skips Voting to reach a passed conclusion — the linear
/// lifecycle the task requires.
pub fn phase(records: &ProposalRecords, cosign_threshold: u32, now: i64) -> Option<ProposalPhase> {
    let proposal = records.proposal.as_ref()?;
    let published = records.is_published(cosign_threshold);
    Some(if now > proposal.voting_ends_at {
        ProposalPhase::Concluded { published }
    } else if published {
        ProposalPhase::Voting
    } else {
        ProposalPhase::Deliberation
    })
}

/// The genesis founders named in the published founder Charter, or empty if no
/// Charter has been published yet. Resolved once per replay and threaded into
/// [`is_eligible_asof`] so a below-band check does not re-scan the log per entry.
pub(crate) fn founder_set(db: &Database) -> Result<Vec<Address>, ProposalError> {
    Ok(founder_charter(db)?
        .map(|c| c.charter().founders.clone())
        .unwrap_or_default())
}

/// The co-sign threshold in force for a proposal opened at `(open_time, open_seq)`
/// (ADR-0015 § 3, position-pinned per T2.1.3).
///
/// Outside bootstrap grace this is the configured [`DEFAULT_COSIGN_THRESHOLD`].
/// **During grace** it clamps down to the number of *other* eligible members — the
/// grace electorate as of the proposal's *open* log position, minus one for the
/// author, who cannot co-sign their own motion — so a founder set too small to
/// field the full threshold (a solo- or two-founder genesis) is not deadlocked by
/// a bar it can never clear. A one-member community publishes with zero
/// co-signers; the threshold only relaxes downward, never above the configured
/// value. Judging the electorate at the open position (not the author clock) keeps
/// the threshold replica-deterministic and unpackable after the proposal opens.
pub fn effective_cosign_threshold(
    db: &Database,
    open_time: i64,
    open_seq: u64,
) -> Result<u32, ProposalError> {
    if !in_grace_asof(db, open_time, open_seq)? {
        return Ok(DEFAULT_COSIGN_THRESHOLD);
    }
    let electorate =
        grace_electorate_asof(db, &founder_set(db)?, open_time, open_seq)?.len() as u32;
    Ok(DEFAULT_COSIGN_THRESHOLD.min(electorate.saturating_sub(1)))
}

/// The composite reputation `address` held at `at_time`, computed from the log
/// prefix `[1, max_seq]` (T2.1.3) — the composite as it stood at a window's *open*
/// log position, so evidence admitted after it cannot change the reading whatever
/// timestamp it claims. Used for the rich error the write path reports when the
/// established-member gate refuses. `max_seq == u64::MAX` is the whole log.
pub(crate) fn composite_at_position(
    db: &Database,
    address: &Address,
    at_time: i64,
    max_seq: u64,
) -> Result<f32, ProposalError> {
    Ok(ReputationScorer::new(db)
        .score_at_position(address, at_time, max_seq)?
        .composite())
}

/// [`is_eligible`] pinned at a log *position* (T2.1.3, ADR-0022 §5): whether
/// `address` was in the governing electorate as of the prefix `[1, max_seq]` at
/// `at_time` — an established member then, or a genesis `founder` while the
/// community was in bootstrap grace then. Governance judges every actor
/// (author, co-signer, voter) at the proposal's open position, so no standing
/// manufactured after a proposal opens can enter its electorate.
pub(crate) fn is_eligible_asof(
    db: &Database,
    founders: &[Address],
    address: &Address,
    at_time: i64,
    max_seq: u64,
) -> Result<bool, ProposalError> {
    if composite_at_position(db, address, at_time, max_seq)? >= BAND_MEMBER_MIN {
        return Ok(true);
    }
    Ok(in_grace_asof(db, at_time, max_seq)? && founders.contains(address))
}

/// Finds a proposal's authorized record without caring about its co-signatures.
///
/// Skips any entry that is not a proposal, one whose id does not match, one not
/// signed by its own author, one that breaks its own rules, one with no station
/// window attestation yet, and one whose author was not an established member as of
/// its **open position** — the same gate [`append_proposal`] applies, so replay
/// reaches the write path's verdict. Returns the authorized proposal with its
/// window fields populated from the station attestation, plus its *open* position
/// `(open_seq, open_time)` — the attestation's seq and attested admission instant
/// (ADR-0022 / T2.1.3), never the author's `created_at`.
fn find_proposal(
    log: &AppendLog,
    proposal_id: &ProposalId,
    db: &Database,
) -> Result<Option<(Proposal, u64, i64)>, ProposalError> {
    let founders = founder_set(db)?;
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(mut proposal) = from_canonical_bytes::<Proposal>(&entry.payload.bytes) else {
            continue;
        };
        if proposal.proposal_id != *proposal_id {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != proposal.author {
            continue;
        }
        if proposal.validate().is_err() {
            continue;
        }
        // The window comes from the station's signed attestation, the one
        // replica-identical statement of this proposal's admission (ADR-0022 §1).
        // A proposal with no attestation is not yet windowed — not authorized to
        // read — so skip it rather than fall back to this replica's re-stamped
        // `entry.created_at`, which differs per replica and would split the derived
        // window, electorate, and outcome across replicas (T2.1.3 acceptance 1).
        let Some((w, open_seq)) = window_and_seq_of(log, proposal_id) else {
            continue;
        };
        proposal.voting_ends_at = w.voting_ends_at;
        proposal.implementation_at = w.implementation_at;
        // The proposal's open position is the *attestation's* seq (ADR-0022 §5,
        // "the attestation's log seq") and the station-attested admission instant —
        // never `entry.created_at`, which each replica re-stamps on receipt, nor the
        // author's own proposal entry (a peer can pre-inject those bytes early, but
        // not forge the station's attestation). The author must have been eligible
        // at that open position.
        let open_time = w.admitted_at;
        if !is_eligible_asof(db, &founders, &proposal.author, open_time, open_seq)? {
            continue;
        }
        return Ok(Some((proposal, open_seq, open_time)));
    }
    Ok(None)
}

/// Collects the proposal and its valid co-signatures in one replay of the log.
///
/// Returns empty records for a proposal this log has never seen authorized. A
/// co-signature counts only when it is self-signed, from someone other than the
/// author, and from an established member as of when it was signed — the same
/// rules [`append_cosign`] enforces, applied here so a gossiped entry that dodged
/// the guards is not believed.
pub fn proposal_records(
    log: &AppendLog,
    proposal_id: &ProposalId,
    db: &Database,
) -> Result<ProposalRecords, ProposalError> {
    let Some((proposal, open_seq, open_time)) = find_proposal(log, proposal_id, db)? else {
        return Ok(ProposalRecords::default());
    };
    let author = proposal.author;
    let founders = founder_set(db)?;

    let mut cosigners = HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(cosign) = from_canonical_bytes::<ProposalCosign>(&entry.payload.bytes) else {
            continue;
        };
        if cosign.proposal_id != *proposal_id {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != cosign.cosigner {
            continue;
        }
        if cosign.cosigner == author {
            continue;
        }
        // Eligibility is pinned at the proposal's open position (T2.1.3): the
        // co-signing electorate is frozen when the proposal opens, so standing
        // manufactured during the window does not admit a co-signer.
        if !is_eligible_asof(db, &founders, &cosign.cosigner, open_time, open_seq)? {
            continue;
        }
        cosigners.insert(cosign.cosigner);
    }

    Ok(ProposalRecords {
        proposal: Some(proposal),
        cosigners,
        open_seq,
        open_time,
    })
}

/// Every authorized proposal on the log, most-recent-first by log order, each
/// appearing once.
///
/// Applies the same authorization the [`find_proposal`] read path does — self-
/// signed by its author, valid by its own rules, carrying a station window
/// attestation, author established as of its open position — so a gossiped entry
/// that dodged the guards is not returned. The
/// enactment sweep ([`crate::lifecycle::enact_due`]) walks this to find the passed
/// proposals it is due to put into force.
pub fn all_proposals(log: &AppendLog, db: &Database) -> Result<Vec<Proposal>, ProposalError> {
    let founders = founder_set(db)?;
    let mut seen = HashSet::new();
    let mut proposals = Vec::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(mut proposal) = from_canonical_bytes::<Proposal>(&entry.payload.bytes) else {
            continue;
        };
        if Address::from_public_key(entry.payload.signer) != proposal.author {
            continue;
        }
        if proposal.validate().is_err() {
            continue;
        }
        // The window (and the admission instant it carries) comes from the station
        // attestation, never this replica's re-stamped `created_at`; a proposal
        // with no attestation is not yet windowed and is not returned (T2.1.3).
        let Some((w, open_seq)) = window_and_seq_of(log, &proposal.proposal_id) else {
            continue;
        };
        proposal.voting_ends_at = w.voting_ends_at;
        proposal.implementation_at = w.implementation_at;
        // Author eligibility at the proposal's open position: the attestation's seq
        // and the attested admission instant (ADR-0022 §5, T2.1.3).
        let open_time = w.admitted_at;
        if !is_eligible_asof(db, &founders, &proposal.author, open_time, open_seq)? {
            continue;
        }
        if seen.insert(proposal.proposal_id) {
            proposals.push(proposal);
        }
    }
    Ok(proposals)
}

/// Publishes an author's proposal: appends the author-signed [`Proposal`], then
/// the station-signed [`crate::window::ProposalWindow`] attestation that anchors
/// its window on this admission (ADR-0022 / T2.1.3).
///
/// Rejects a proposal whose signer is not its author, one that breaks its own
/// rules, one whose author was not eligible at the proposal's *open* position, and
/// one already on this log. `charter` is the effective Charter the window is
/// computed against (the caller resolves it — governance unit tests pass a fixture
/// directly, the station resolves [`crate::tally::effective_charter`]). Returns the
/// proposal's own log entry.
pub fn append_proposal(
    log: &mut AppendLog,
    signed: SignedProposal,
    db: &Database,
    station: &Keypair,
    charter: &Charter,
    now: i64,
) -> Result<LogEntry, ProposalError> {
    let proposal = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != proposal.author {
        return Err(ProposalError::SignerNotAuthor {
            signer,
            author: proposal.author,
        });
    }
    proposal.validate()?;
    // The proposal's open position is the admission it is about to receive: the
    // next seq, at the monotone-clamped admission time. Eligibility is judged
    // there, matching the replay path (find_proposal), not the author's clock.
    let (open_seq, open_time) = match log.tail()? {
        Some(t) => (t.seq + 1, now.max(t.created_at)),
        None => (1, now),
    };
    if !is_eligible_asof(db, &founder_set(db)?, &proposal.author, open_time, open_seq)? {
        return Err(ProposalError::AuthorNotEstablished {
            author: proposal.author,
            composite: composite_at_position(db, &proposal.author, open_time, open_seq)?,
        });
    }
    if find_proposal(log, &proposal.proposal_id, db)?.is_some() {
        return Err(ProposalError::AlreadyProposed(proposal.proposal_id));
    }
    let proposal_id = proposal.proposal_id;
    let kind = proposal.kind.clone();
    let entry = log.append(signed, now)?;
    // Restate the admission-anchored window in a station-signed record so the
    // window is replica-identical (ADR-0022 §1). Its admission time is the
    // proposal's own admission (entry.created_at == open_time).
    let window = build_window(station, proposal_id, &kind, charter, entry.created_at);
    log.append(window, now)?;
    Ok(entry)
}

/// Records a member's endorsement of a proposal: appends the co-signer's signed
/// [`ProposalCosign`].
///
/// Rejects an endorsement whose signer is not its co-signer, one against a
/// proposal this log has not seen, one from the author (who cannot endorse their
/// own motion), one from a member without standing, and a repeat from a member
/// who has already co-signed.
pub fn append_cosign(
    log: &mut AppendLog,
    signed: SignedCosign,
    db: &Database,
    now: i64,
) -> Result<LogEntry, ProposalError> {
    let cosign = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != cosign.cosigner {
        return Err(ProposalError::SignerNotCosigner {
            signer,
            cosigner: cosign.cosigner,
        });
    }
    let records = proposal_records(log, &cosign.proposal_id, db)?;
    let Some(proposal) = records.proposal.as_ref() else {
        return Err(ProposalError::UnknownProposal(cosign.proposal_id));
    };
    if cosign.cosigner == proposal.author {
        return Err(ProposalError::AuthorCannotCosign);
    }
    // Co-signer eligibility is pinned at the proposal's open position (T2.1.3),
    // the same electorate replay counts, not the co-signer's own clock.
    let (open_seq, open_time) = (records.open_seq, records.open_time);
    if !is_eligible_asof(db, &founder_set(db)?, &cosign.cosigner, open_time, open_seq)? {
        return Err(ProposalError::CosignerNotEstablished {
            cosigner: cosign.cosigner,
            composite: composite_at_position(db, &cosign.cosigner, open_time, open_seq)?,
        });
    }
    if records.cosigners.contains(&cosign.cosigner) {
        return Err(ProposalError::AlreadyCosigned {
            proposal_id: cosign.proposal_id,
            cosigner: cosign.cosigner,
        });
    }
    Ok(log.append(signed, now)?)
}

/// A proposal or co-signature the write path would not accept, or a record the
/// replay would not believe. One variant per rule, so a caller can tell which
/// requirement was missing.
#[derive(thiserror::Error, Debug)]
pub enum ProposalError {
    /// The title was empty (or whitespace only).
    #[error("proposal title is empty")]
    EmptyTitle,
    /// The title was longer than [`MAX_TITLE_BYTES`].
    #[error("proposal title is {len} bytes, over the {max}-byte limit")]
    TitleTooLong {
        /// The title's length in bytes.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// The body was empty (or whitespace only).
    #[error("proposal body is empty")]
    EmptyBody,
    /// The body was longer than [`MAX_BODY_BYTES`].
    #[error("proposal body is {len} bytes, over the {max}-byte limit")]
    BodyTooLong {
        /// The body's length in bytes.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// A charter amendment named a voting mechanism other than Direct, which
    /// Phase 1 does not allow.
    #[error("a charter amendment must keep Direct voting in Phase 1")]
    NonDirectVotingMechanism,
    /// The envelope's signer is not the proposal's author.
    #[error("proposal signed by {signer}, but its author is {author}")]
    SignerNotAuthor {
        /// Who signed.
        signer: Address,
        /// Who the proposal names as author.
        author: Address,
    },
    /// The author is not an established member (effective composite below the
    /// Member band) as of the proposal's `created_at`.
    #[error("author {author} is not an established member (composite {composite:.2} < 2.0)")]
    AuthorNotEstablished {
        /// The author.
        author: Address,
        /// Their effective composite at the proposal's `created_at`.
        composite: f32,
    },
    /// A proposal with this id is already on the log.
    #[error("proposal {0} is already on the log")]
    AlreadyProposed(ProposalId),
    /// No authorized proposal with this id — nothing to co-sign.
    #[error("no proposal {0} on this log")]
    UnknownProposal(ProposalId),
    /// The co-signature's envelope signer is not its named co-signer.
    #[error("co-signature signed by {signer}, but its co-signer is {cosigner}")]
    SignerNotCosigner {
        /// Who signed.
        signer: Address,
        /// Who the record names as co-signer.
        cosigner: Address,
    },
    /// The author tried to co-sign their own proposal.
    #[error("an author may not co-sign their own proposal")]
    AuthorCannotCosign,
    /// The co-signer is not an established member as of when they co-signed.
    #[error("co-signer {cosigner} is not an established member (composite {composite:.2} < 2.0)")]
    CosignerNotEstablished {
        /// The co-signer.
        cosigner: Address,
        /// Their effective composite at the co-signature's `cosigned_at`.
        composite: f32,
    },
    /// This member has already co-signed this proposal.
    #[error("{cosigner} has already co-signed proposal {proposal_id}")]
    AlreadyCosigned {
        /// The proposal.
        proposal_id: ProposalId,
        /// The member who tried to co-sign twice.
        cosigner: Address,
    },
    /// A reputation-scoring error while evaluating the established-member gate.
    #[error("reputation: {0}")]
    Reputation(#[from] rrn_reputation::Error),
    /// Reading the founder Charter to resolve the genesis founders for the
    /// bootstrap-grace electorate failed (ADR-0015).
    #[error("charter: {0}")]
    Charter(#[from] CharterError),
    /// A storage/log error while reading or appending.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
}

// --- Canonical CBOR ---------------------------------------------------------

impl From<ProposalKind> for CBOR {
    fn from(k: ProposalKind) -> Self {
        let mut m = Map::new();
        match k {
            ProposalKind::Statute => {
                m.insert("type", "statute");
            }
            ProposalKind::AdministrativeRule { scope } => {
                m.insert("type", "administrative_rule");
                m.insert("scope", scope);
            }
            ProposalKind::CharterAmendment { new_charter } => {
                m.insert("type", "charter_amendment");
                m.insert("new_charter", new_charter);
            }
            ProposalKind::Emergency { expires_at } => {
                m.insert("type", "emergency");
                m.insert("expires_at", expires_at);
            }
        }
        m.into()
    }
}

impl TryFrom<CBOR> for ProposalKind {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        match map.extract::<&str, String>("type")?.as_str() {
            "statute" => Ok(ProposalKind::Statute),
            "administrative_rule" => Ok(ProposalKind::AdministrativeRule {
                scope: map.extract::<&str, String>("scope")?,
            }),
            "charter_amendment" => Ok(ProposalKind::CharterAmendment {
                new_charter: map.extract::<&str, Charter>("new_charter")?,
            }),
            "emergency" => Ok(ProposalKind::Emergency {
                expires_at: map.extract::<&str, i64>("expires_at")?,
            }),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

impl From<Proposal> for CBOR {
    fn from(p: Proposal) -> Self {
        // `proposal_id` is derived from these bytes, so it is deliberately not
        // among them — it cannot sign itself.
        let mut m = Map::new();
        m.insert("kind", PROPOSAL_KIND);
        m.insert("author", p.author);
        m.insert("title", p.title);
        m.insert("body", p.body);
        m.insert("proposal_kind", p.kind);
        m.insert("created_at", p.created_at);
        // `voting_ends_at`/`implementation_at` are deliberately NOT in the signed
        // content (T2.1.3): the window is not author testimony but a function of
        // the station's admission time, restated in the signed ProposalWindow
        // attestation. Including them would sign author-clock arithmetic and hash
        // it into `proposal_id`.
        m.into()
    }
}

impl TryFrom<CBOR> for Proposal {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != PROPOSAL_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let mut proposal = Proposal {
            proposal_id: ProposalId(Hash::from_bytes([0u8; 32])),
            author: map.extract::<&str, Address>("author")?,
            title: map.extract::<&str, String>("title")?,
            body: map.extract::<&str, String>("body")?,
            kind: map.extract::<&str, ProposalKind>("proposal_kind")?,
            created_at: map.extract::<&str, i64>("created_at")?,
            // Not signed; populated from the ProposalWindow attestation on replay.
            voting_ends_at: 0,
            implementation_at: 0,
        };
        proposal.proposal_id = proposal.compute_id();
        Ok(proposal)
    }
}

impl From<ProposalCosign> for CBOR {
    fn from(c: ProposalCosign) -> Self {
        let mut m = Map::new();
        m.insert("kind", COSIGN_KIND);
        m.insert("proposal_id", c.proposal_id);
        m.insert("cosigner", c.cosigner);
        m.insert("cosigned_at", c.cosigned_at);
        m.into()
    }
}

impl TryFrom<CBOR> for ProposalCosign {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != COSIGN_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ProposalCosign {
            proposal_id: map.extract::<&str, ProposalId>("proposal_id")?,
            cosigner: map.extract::<&str, Address>("cosigner")?,
            cosigned_at: map.extract::<&str, i64>("cosigned_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charter::{AmendmentRules, GovernanceStructure};
    use rrn_crypto::keypair::Keypair;
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
    /// band, then is anchored by a vouch from the next in a ring (anchoring needs
    /// only the voucher's *raw* composite, so the ring is not circular).
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
        let p = Proposal::new(
            addr(author),
            "Quiet hours in the workshop".into(),
            "No power tools after 9pm.".into(),
            ProposalKind::Statute,
            at,
        )
        .unwrap();
        with_window(p, at)
    }

    /// Populates a test proposal's window cache the way the station attestation
    /// will, using the default charter at admission time `at`. Tests append at
    /// `at`, so `admitted_at == at` and this matches the on-log attestation —
    /// letting tests keep reading `proposal.voting_ends_at` on the built object.
    fn with_window(mut p: Proposal, at: i64) -> Proposal {
        let (v, i) = crate::window::window_for(&test_charter(), &p.kind, at);
        p.voting_ends_at = v;
        p.implementation_at = i;
        p
    }

    /// Test helper: a drop-in for the old `propose(log, signed, db, at)`
    /// that supplies a station keypair and the default test charter (the window
    /// attestation's signer is not verified in replay, so a fresh key is fine).
    fn propose(
        log: &mut AppendLog,
        signed: SignedProposal,
        db: &Database,
        at: i64,
    ) -> Result<LogEntry, ProposalError> {
        append_proposal(log, signed, db, &Keypair::generate(), &test_charter(), at)
    }

    fn cosign(cosigner: &Keypair, proposal: &Proposal, at: i64) -> SignedCosign {
        SignedPayload::sign(
            ProposalCosign {
                proposal_id: proposal.proposal_id,
                cosigner: addr(cosigner),
                cosigned_at: at,
            },
            cosigner,
        )
    }

    // --- Reputation gate ------------------------------------------------------

    #[test]
    fn an_established_member_may_propose() {
        let db = fresh_db();
        let station = Keypair::generate();
        let author = established_members(&db, &station, 2, NOW)[0].clone();
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();

        assert!(find_proposal(&log, &proposal.proposal_id, &db)
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_below_band_member_may_not_propose() {
        let db = fresh_db();
        let newcomer = Keypair::generate(); // no standing at all
        let mut log = AppendLog::new(&db);

        let err = propose(
            &mut log,
            SignedPayload::sign(statute(&newcomer, NOW), &newcomer),
            &db,
            NOW,
        )
        .unwrap_err();

        assert!(matches!(err, ProposalError::AuthorNotEstablished { .. }));
        assert_eq!(log.iter_from(1).count(), 0);
    }

    #[test]
    fn a_proposal_signed_by_someone_other_than_its_author_is_refused() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 2, NOW);
        let mut log = AppendLog::new(&db);

        // Honestly authored by members[0] but signed by members[1].
        let err = propose(
            &mut log,
            SignedPayload::sign(statute(&members[0], NOW), &members[1]),
            &db,
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, ProposalError::SignerNotAuthor { .. }));
    }

    // --- Co-signing and publication ------------------------------------------

    #[test]
    fn a_proposal_needs_the_cosign_threshold_to_publish() {
        let db = fresh_db();
        let station = Keypair::generate();
        // Author plus three eligible co-signers.
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

        // Nothing endorsed yet: within the window but still deliberating.
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(records.cosigner_count(), 0);
        assert!(!records.is_published(DEFAULT_COSIGN_THRESHOLD));
        assert_eq!(
            phase(&records, DEFAULT_COSIGN_THRESHOLD, NOW + 1),
            Some(ProposalPhase::Deliberation)
        );

        // Two of three: still short of the threshold.
        append_cosign(&mut log, cosign(&members[1], &proposal, NOW), &db, NOW).unwrap();
        append_cosign(&mut log, cosign(&members[2], &proposal, NOW), &db, NOW).unwrap();
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(records.cosigner_count(), 2);
        assert!(!records.is_published(DEFAULT_COSIGN_THRESHOLD));
        assert_eq!(
            phase(&records, DEFAULT_COSIGN_THRESHOLD, NOW + 1),
            Some(ProposalPhase::Deliberation)
        );

        // The third publishes it: now open for voting.
        append_cosign(&mut log, cosign(&members[3], &proposal, NOW), &db, NOW).unwrap();
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(records.cosigner_count(), 3);
        assert!(records.is_published(DEFAULT_COSIGN_THRESHOLD));
        assert_eq!(
            phase(&records, DEFAULT_COSIGN_THRESHOLD, NOW + 1),
            Some(ProposalPhase::Voting)
        );
    }

    #[test]
    fn the_lifecycle_is_linear() {
        let db = fresh_db();
        let station = Keypair::generate();
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
        for c in &members[1..4] {
            append_cosign(&mut log, cosign(c, &proposal, NOW), &db, NOW).unwrap();
        }
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();

        // Deliberation/voting share one window; before it closes the published
        // proposal is Voting, after it closes it is Concluded — and never the
        // other way round.
        assert_eq!(
            phase(&records, DEFAULT_COSIGN_THRESHOLD, proposal.voting_ends_at),
            Some(ProposalPhase::Voting)
        );
        assert_eq!(
            phase(
                &records,
                DEFAULT_COSIGN_THRESHOLD,
                proposal.voting_ends_at + 1
            ),
            Some(ProposalPhase::Concluded { published: true })
        );
    }

    #[test]
    fn a_proposal_that_never_reaches_threshold_lapses() {
        let db = fresh_db();
        let station = Keypair::generate();
        let author = established_members(&db, &station, 2, NOW)[0].clone();
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();

        assert_eq!(
            phase(
                &records,
                DEFAULT_COSIGN_THRESHOLD,
                proposal.voting_ends_at + 1
            ),
            Some(ProposalPhase::Concluded { published: false })
        );
    }

    #[test]
    fn the_author_may_not_cosign_their_own_proposal() {
        let db = fresh_db();
        let station = Keypair::generate();
        let author = established_members(&db, &station, 2, NOW)[0].clone();
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();

        let err = append_cosign(&mut log, cosign(&author, &proposal, NOW), &db, NOW).unwrap_err();
        assert!(matches!(err, ProposalError::AuthorCannotCosign));
    }

    #[test]
    fn a_member_may_not_cosign_twice() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 2, NOW);
        let (author, cosigner) = (members[0].clone(), members[1].clone());
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();
        append_cosign(&mut log, cosign(&cosigner, &proposal, NOW), &db, NOW).unwrap();

        let err = append_cosign(&mut log, cosign(&cosigner, &proposal, NOW), &db, NOW).unwrap_err();
        assert!(matches!(err, ProposalError::AlreadyCosigned { .. }));
    }

    #[test]
    fn a_below_band_member_may_not_cosign() {
        let db = fresh_db();
        let station = Keypair::generate();
        let author = established_members(&db, &station, 2, NOW)[0].clone();
        let outsider = Keypair::generate(); // no standing
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();

        let err = append_cosign(&mut log, cosign(&outsider, &proposal, NOW), &db, NOW).unwrap_err();
        assert!(matches!(err, ProposalError::CosignerNotEstablished { .. }));
    }

    #[test]
    fn cosigning_an_unknown_proposal_is_refused() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 2, NOW);
        let mut log = AppendLog::new(&db);

        // A proposal that was never appended.
        let phantom = statute(&members[0], NOW);
        let err =
            append_cosign(&mut log, cosign(&members[1], &phantom, NOW), &db, NOW).unwrap_err();
        assert!(matches!(err, ProposalError::UnknownProposal(_)));
    }

    #[test]
    fn a_proposal_cannot_be_filed_twice() {
        let db = fresh_db();
        let station = Keypair::generate();
        let author = established_members(&db, &station, 2, NOW)[0].clone();
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();
        let err = propose(&mut log, SignedPayload::sign(proposal, &author), &db, NOW).unwrap_err();
        assert!(matches!(err, ProposalError::AlreadyProposed(_)));
    }

    #[test]
    fn replay_ignores_records_a_gossiped_entry_could_carry() {
        let db = fresh_db();
        let station = Keypair::generate();
        let members = established_members(&db, &station, 2, NOW);
        let (author, cosigner) = (members[0].clone(), members[1].clone());
        let outsider = Keypair::generate();
        let mut log = AppendLog::new(&db);

        let proposal = statute(&author, NOW);
        propose(
            &mut log,
            SignedPayload::sign(proposal.clone(), &author),
            &db,
            NOW,
        )
        .unwrap();

        // Bypass the guards exactly as replication does. An outsider's proposal
        // (author has no standing), an outsider's co-signature, and the author
        // self-co-signing must all be dropped by replay.
        let outsider_proposal = statute(&outsider, NOW);
        log.append(SignedPayload::sign(outsider_proposal.clone(), &outsider), 0)
            .unwrap();
        log.append(cosign(&outsider, &proposal, NOW), 0).unwrap();
        log.append(cosign(&author, &proposal, NOW), 0).unwrap();

        assert!(find_proposal(&log, &outsider_proposal.proposal_id, &db)
            .unwrap()
            .is_none());
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(records.cosigner_count(), 0);

        // A legitimate co-signature still counts.
        append_cosign(&mut log, cosign(&cosigner, &proposal, NOW), &db, NOW).unwrap();
        let records = proposal_records(&log, &proposal.proposal_id, &db).unwrap();
        assert_eq!(records.cosigner_count(), 1);
    }

    // --- Model: windows, id, CBOR --------------------------------------------

    #[test]
    fn the_proposal_id_is_the_content_hash_and_is_not_signed() {
        let author = Keypair::generate();
        let proposal = statute(&author, NOW);

        // Re-encoding the payload recomputes the same id, and a forged id does not
        // survive the round trip — it is derived, not carried.
        let mut forged = proposal.clone();
        forged.proposal_id = ProposalId(Hash::of(b"not this proposal"));
        let decoded: Proposal = from_canonical_bytes(&to_canonical_bytes(forged.clone())).unwrap();
        assert_eq!(decoded.proposal_id, proposal.proposal_id);
        assert_ne!(decoded.proposal_id, forged.proposal_id);
    }

    #[test]
    fn the_id_changes_when_any_field_changes() {
        let author = Keypair::generate();
        let a = statute(&author, NOW);
        let b = Proposal::new(
            addr(&author),
            "A different title".into(),
            "No power tools after 9pm.".into(),
            ProposalKind::Statute,
            NOW,
        )
        .unwrap();
        assert_ne!(a.proposal_id, b.proposal_id);
    }

    #[test]
    fn proposal_and_cosign_cbor_roundtrip() {
        let author = Keypair::generate();
        for kind in [
            ProposalKind::Statute,
            ProposalKind::AdministrativeRule {
                scope: "workshop".into(),
            },
            ProposalKind::CharterAmendment {
                new_charter: test_charter(),
            },
            ProposalKind::Emergency {
                expires_at: NOW + MONTH,
            },
        ] {
            let proposal =
                Proposal::new(addr(&author), "Title".into(), "Body.".into(), kind, NOW).unwrap();
            let back: Proposal =
                from_canonical_bytes(&to_canonical_bytes(proposal.clone())).unwrap();
            assert_eq!(proposal, back);

            let c = ProposalCosign {
                proposal_id: proposal.proposal_id,
                cosigner: addr(&author),
                cosigned_at: NOW,
            };
            let back: ProposalCosign = from_canonical_bytes(&to_canonical_bytes(c)).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn a_proposal_must_have_a_title_and_body() {
        let author = Keypair::generate();
        assert!(matches!(
            Proposal::new(
                addr(&author),
                "  ".into(),
                "b".into(),
                ProposalKind::Statute,
                NOW,
            ),
            Err(ProposalError::EmptyTitle)
        ));
        assert!(matches!(
            Proposal::new(
                addr(&author),
                "t".into(),
                "".into(),
                ProposalKind::Statute,
                NOW,
            ),
            Err(ProposalError::EmptyBody)
        ));
    }
}
