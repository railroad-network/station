//! Portability — reputation that travels as evidence, not as a number.
//!
//! A member's standing is worth something only if it survives leaving the
//! station that computed it. Handing another station a score would mean asking
//! it to trust us; per design doc Section 5.6 we hand it the *evidence* instead —
//! every log entry that bears on the member — plus a signed root committing to
//! exactly which entries those were. The receiving station replays them itself
//! and arrives at the same profile, because scoring is deterministic over the
//! log ([`crate::scoring`]).
//!
//! # What the signature and the root each buy
//!
//! [`HistoryRoot`] is signed by the exporting station, which vouches that this
//! bundle is what it holds about the address as of
//! [`computed_at`](HistoryRoot::computed_at). The
//! [`merkle_root`](HistoryRoot::merkle_root) commits to the entries themselves:
//! change, drop, reorder or add one and the recomputed root no longer matches the
//! signed one. Verification also re-checks every entry's own signature, so a
//! bundle carries two independent guarantees — the station attests to the
//! *selection*, and the original signers still attest to the *content*. A
//! dishonest exporter can withhold a whole bundle, but it cannot forge one.
//!
//! Using a Merkle root rather than a flat hash over the concatenation is
//! future-proofing: Phase 2 can prove one entry's membership without shipping the
//! rest.
//!
//! # Verifying is replaying
//!
//! [`verify_history`] loads the bundle into a scratch in-memory log and runs the
//! ordinary scorer over it, rather than reimplementing scoring against a slice.
//! One code path means an imported profile cannot drift from the exported one.
//! It scores at the root's `computed_at`, not at the verifier's clock, so decay
//! lands where the exporter left it and the comparison is exact.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use dcbor::prelude::*;
use rrn_crypto::hash::{Hash, Hasher};
use rrn_crypto::keypair::{Keypair, PublicKey};
use rrn_crypto::serialize::{decode_kinded, from_canonical_bytes_if_kind, KindedCbor};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::vouch::{Vouch, VOUCH_KIND_TAG};
use rrn_ledger::enrollment::{EnrollmentRecord, ENROLLMENT_KIND};
use rrn_ledger::settlement::{SettlementRecord, SETTLEMENT_KIND};
use rrn_ledger::state::{CancellationRecord, CANCELLATION_KIND};
use rrn_ledger::transaction::{
    TransactionConfirmation, TransactionId, TransactionProposal, CONFIRMATION_KIND, PROPOSAL_KIND,
};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};
use rrn_storage::migrations;

use crate::context::ScoringContext;
use crate::model::ReputationProfile;
use crate::scoring::ReputationScorer;
use crate::Result;

/// Discriminant string carried in a history root's canonical CBOR, and its
/// schema version: a later root shape takes a new tag rather than silently
/// reinterpreting these bytes.
const HISTORY_ROOT_KIND: &str = "rrn.reputation.history_root.v1";

/// Domain separator for a Merkle leaf, keeping leaf hashes disjoint from
/// interior-node hashes so no entry can be passed off as a subtree.
const LEAF_PREFIX: &[u8] = &[0x00];
/// Domain separator for a Merkle interior node.
const NODE_PREFIX: &[u8] = &[0x01];
/// Preimage for the Merkle root of no entries at all — a member with no history.
const EMPTY_MERKLE_DOMAIN: &[u8] = b"rrn.reputation.history.empty";

/// A member's reputation evidence, packaged to be carried to another station.
///
/// The bundle is self-contained: [`verify_history`] needs nothing but this value
/// to re-derive the profile, and the exporting station's key to recognize the
/// root's signer.
#[derive(Clone, Debug)]
pub struct PortableReputationHistory {
    /// The member whose history this is.
    pub address: Address,
    /// Every log entry bearing on [`address`](Self::address), in the exporting
    /// station's log order.
    pub log_entries: Vec<LogEntry>,
    /// The exporting station's signed commitment to the selection above.
    pub signed_root: SignedPayload<HistoryRoot>,
}

/// The signed commitment at the head of a [`PortableReputationHistory`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRoot {
    /// The member the bundle is about.
    pub address: Address,
    /// Sequence number of the first included entry (`0` when there are none).
    pub from_seq: u64,
    /// Sequence number of the last included entry (`0` when there are none).
    pub to_seq: u64,
    /// The instant the exporter scored at. A verifier replays at this instant so
    /// decay reproduces exactly.
    pub computed_at: i64,
    /// Merkle root over the included entries' content hashes, in order.
    pub merkle_root: Hash,
}

/// Why an exported history could not be trusted.
///
/// Each variant names what failed rather than reporting a generic "invalid",
/// because these distinguish an attack from a bug: a bad signature means forgery,
/// a Merkle mismatch means the selection was altered in flight.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HistoryError {
    /// The root's signature does not verify against its signer.
    #[error("the signed root does not verify")]
    RootSignature,
    /// The root commits to a different member than the bundle claims.
    #[error("the signed root is for a different address")]
    AddressMismatch,
    /// An included entry's signature does not verify — a forged or edited record.
    #[error("entry {seq} carries an invalid signature")]
    EntrySignature {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// An entry's `content_hash` is not the hash of its bytes, so the hash the
    /// Merkle tree commits to does not describe the payload beneath it.
    #[error("entry {seq} does not match its content hash")]
    ContentHash {
        /// Sequence number of the offending entry.
        seq: u64,
    },
    /// The entries are not in ascending order, or do not span the sequence range
    /// the root claims.
    #[error("the entries do not match the sequence range the root claims")]
    SequenceRange,
    /// The entries do not reproduce the root's Merkle root — one was changed,
    /// dropped, added or reordered.
    #[error("the entries do not reproduce the signed Merkle root")]
    MerkleRoot,
}

/// Packages everything this station holds about `address` and signs the result
/// with the station's `signer` key, scoring as of the current wall clock.
///
/// See [`export_history_at`] to pin the instant explicitly.
pub fn export_history(
    db: &Database,
    address: &Address,
    signer: &Keypair,
) -> Result<PortableReputationHistory> {
    export_history_at(db, address, signer, now_secs())
}

/// [`export_history`] with the scoring instant given rather than read from the
/// clock. The instant is recorded in the root, so this fixes what a verifier will
/// reproduce.
pub fn export_history_at(
    db: &Database,
    address: &Address,
    signer: &Keypair,
    computed_at: i64,
) -> Result<PortableReputationHistory> {
    // The exporter is this community's station, so its own key pins the
    // station-signed records (settlements, cancellations) selected into the
    // bundle: a record not signed by it is never exported.
    let log_entries = exportable_entries(db, address, computed_at, &signer.public_key())?;
    let root = HistoryRoot {
        address: *address,
        from_seq: log_entries.first().map(|e| e.seq).unwrap_or(0),
        to_seq: log_entries.last().map(|e| e.seq).unwrap_or(0),
        computed_at,
        merkle_root: merkle_root(&log_entries),
    };
    Ok(PortableReputationHistory {
        address: *address,
        log_entries,
        signed_root: SignedPayload::sign(root, signer),
    })
}

/// Checks a bundle end to end and returns the profile its evidence produces.
///
/// The returned profile is what the exporting station computed, re-derived rather
/// than taken on faith. Any tampering — with the root, an entry's bytes, its
/// content hash, or the set and order of the entries — fails instead of returning
/// a profile.
pub fn verify_history(history: &PortableReputationHistory) -> Result<ReputationProfile> {
    let root = &history.signed_root.payload;

    history
        .signed_root
        .verify()
        .map_err(|_| HistoryError::RootSignature)?;
    if root.address != history.address {
        return Err(HistoryError::AddressMismatch.into());
    }

    let mut previous_seq = 0u64;
    for entry in &history.log_entries {
        if entry.seq <= previous_seq {
            return Err(HistoryError::SequenceRange.into());
        }
        previous_seq = entry.seq;
        entry
            .payload
            .verify()
            .map_err(|_| HistoryError::EntrySignature { seq: entry.seq })?;
        // Without this the Merkle root would only commit to hashes, leaving the
        // bytes underneath them unconstrained.
        if entry.content_hash != Hash::of(&entry.payload.bytes) {
            return Err(HistoryError::ContentHash { seq: entry.seq }.into());
        }
    }

    let span = (
        history.log_entries.first().map(|e| e.seq).unwrap_or(0),
        history.log_entries.last().map(|e| e.seq).unwrap_or(0),
    );
    if span != (root.from_seq, root.to_seq) {
        return Err(HistoryError::SequenceRange.into());
    }
    if merkle_root(&history.log_entries) != root.merkle_root {
        return Err(HistoryError::MerkleRoot.into());
    }

    replay_into_profile(history, root.computed_at)
}

/// Replays the bundle's entries through a scratch log and scores it there.
///
/// The scratch log re-chains the entries as if they had been replicated in and
/// stamps its own `created_at` on each — neither of which scoring reads (it takes
/// every timestamp from the signed payloads), so the profile is unaffected.
fn replay_into_profile(
    history: &PortableReputationHistory,
    computed_at: i64,
) -> Result<ReputationProfile> {
    let db = Database::open_in_memory()?;
    migrations::run(&db)?;
    {
        let mut log = AppendLog::new(&db);
        for entry in &history.log_entries {
            // The scratch log re-stamps admission time itself (ADR-0022);
            // scoring ignores `created_at`, so `computed_at` is an arbitrary but
            // reasonable reading here.
            log.append_raw(entry.payload.clone(), computed_at)?;
        }
    }
    // A portable bundle carries records signed by the *exporting* station, which
    // is a different community than the verifier. The bundle's own attesting key
    // is `signed_root.signer` — already checked authentic by
    // [`verify_history`] before this runs — so it is what pins the station-signed
    // records on the verifier's replay, keeping the re-derived profile identical to
    // the one the exporter computed.
    ReputationScorer::new(&db, &history.signed_root.signer).score_at(&history.address, computed_at)
}

/// Everything a remote verifier needs to reach the exporter's profile
/// (ADR-0038 Interactions, ADR-0032 §1): the entries concerning `address`, the
/// entries concerning every identity on its anchor chain, and every enrollment
/// record — revocations included — naming anyone those entries name.
///
/// A verifier replays the bundle and must reach the same verdicts the exporter
/// did:
///
/// - **Eligibility (ADR-0038 §8)** is judged from enrollment records, so the
///   records of every party, voucher and subject in the selection travel too.
///   Eligibility is judged by log order, which the bundle preserves.
/// - **Anchoring (ADR-0038 §11)** is a chain of edges from a founder root, each
///   judged at its vouch over the shorter prefix before it. So the bundle carries
///   the evidence of each voucher on the chain, and — for each edge — of the
///   chain that anchored its voucher when the edge formed
///   ([`ScoringContext::anchor_chain`]), down to the roots, whose `founder`
///   enrollments come with the enrollment records.
///
/// Withholding *positive* evidence can only lower a raw composite, so a verifier
/// given less than this computes a capped profile rather than the exporter's.
/// Penalties are a different matter: the bundle carries no equivocation
/// records, and only the cancellations of the selected transactions. So for an
/// identity whose history is only partly selected — a voucher off the chain who
/// vouched for a chain member — a penalty the exporter counted can be missing,
/// and the verifier can read that identity higher, and may then form an
/// anchoring edge the exporter did not. Closing that needs the penalty evidence
/// of every voucher the bundle names; it is recorded as a residual for the
/// portable-standing work (ADR-0032). The cost of what is carried is
/// disclosure: the chain members' trade histories travel inside someone else's
/// bundle. A succinct proof of a voucher's standing is the later improvement.
fn exportable_entries(
    db: &Database,
    address: &Address,
    at_time: i64,
    station: &PublicKey,
) -> Result<Vec<LogEntry>> {
    let ctx = ScoringContext::unbounded(db, station)?;
    let mut people: HashSet<Address> = HashSet::new();
    people.insert(*address);
    people.extend(ctx.anchor_chain(address, at_time));
    entries_concerning(db, &people, station)
}

/// Every log entry bearing on any of `people`: the transactions one of them is a
/// party to — with the confirmation, settlement or cancellation that completed
/// them — the vouches one of them wrote or received, and every station-signed
/// enrollment record naming any party, voucher or subject of those entries. In
/// log order.
///
/// Transaction records are pulled in by proposal id rather than by signer,
/// because a settlement is signed by the station and a confirmation by the
/// counterparty: selecting only entries the member signed would ship an
/// incomplete lifecycle, which replays to a different profile.
fn entries_concerning(
    db: &Database,
    people: &HashSet<Address>,
    station: &PublicKey,
) -> Result<Vec<LogEntry>> {
    let log = AppendLog::new(db);

    let mut transactions: HashSet<TransactionId> = HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        // Only proposals name the parties; dispatch on kind so a non-proposal
        // entry is skipped without trial-decoding it as a proposal first.
        if let Ok(Some(proposal)) =
            from_canonical_bytes_if_kind::<TransactionProposal>(&entry.payload.bytes, PROPOSAL_KIND)
        {
            if people.contains(&proposal.sender) || people.contains(&proposal.receiver) {
                transactions.insert(proposal.id);
            }
        }
    }

    // Everyone the selection names: an event's eligibility turns on each of
    // their enrollments.
    let mut named: HashSet<Address> = people.clone();
    let mut selected = Vec::new();
    let mut enrollments = Vec::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        match concerns(&entry, people, &transactions, station) {
            Some(Concern::Names(addresses)) => {
                named.extend(addresses);
                selected.push(entry);
            }
            Some(Concern::Enrollment(member)) => enrollments.push((member, entry)),
            None => {}
        }
    }
    selected.extend(
        enrollments
            .into_iter()
            .filter(|(member, _)| named.contains(member))
            .map(|(_, entry)| entry),
    );
    selected.sort_by_key(|entry| entry.seq);
    Ok(selected)
}

/// How one log entry bears on a bundle.
enum Concern {
    /// It belongs in the bundle; these are the addresses it names.
    Names(Vec<Address>),
    /// A station-signed enrollment record for this member — included only if
    /// the selection names the member.
    Enrollment(Address),
}

/// Whether one entry belongs in a bundle about `people`. A settlement,
/// cancellation or enrollment record is considered only when signed by the
/// community `station`: a forged station-kind record is never shipped in a
/// bundle, and the verifier's replay pins the same key, so the two agree.
fn concerns(
    entry: &LogEntry,
    people: &HashSet<Address>,
    transactions: &HashSet<TransactionId>,
    station: &PublicKey,
) -> Option<Concern> {
    // Parse once and dispatch on the `kind` discriminator. A malformed or
    // unrelated-kind entry does not belong in the bundle.
    let Ok(KindedCbor {
        kind: Some(kind),
        cbor,
    }) = decode_kinded(&entry.payload.bytes)
    else {
        return None;
    };
    let from_station = entry.payload.signer == *station;
    let names = match kind.as_str() {
        PROPOSAL_KIND => TransactionProposal::try_from(cbor)
            .ok()
            .filter(|p| transactions.contains(&p.id))
            .map(|p| vec![p.sender, p.receiver]),
        CONFIRMATION_KIND => TransactionConfirmation::try_from(cbor)
            .ok()
            .filter(|c| transactions.contains(&c.proposal_id))
            .map(|c| vec![c.confirmer]),
        SETTLEMENT_KIND => SettlementRecord::try_from(cbor)
            .ok()
            .filter(|s| from_station && transactions.contains(&s.proposal_id))
            .map(|s| vec![s.sender, s.receiver]),
        CANCELLATION_KIND => CancellationRecord::try_from(cbor)
            .ok()
            .filter(|c| from_station && transactions.contains(&c.proposal_id))
            .map(|_| Vec::new()),
        // Vouches in both directions: the ones a member signed feed its own
        // attestation accuracy, and the ones it received are what a receiving
        // station needs in order to judge how it was anchored.
        VOUCH_KIND_TAG => Vouch::try_from(cbor).ok().and_then(|v| {
            let voucher = Address::from_public_key(entry.payload.signer);
            (people.contains(&v.subject) || people.contains(&voucher))
                .then(|| vec![voucher, v.subject])
        }),
        ENROLLMENT_KIND => {
            return EnrollmentRecord::try_from(cbor)
                .ok()
                .filter(|_| from_station)
                .map(|r| Concern::Enrollment(r.member));
        }
        _ => None,
    };
    names.map(Concern::Names)
}

/// The Merkle root over the entries' content hashes, in order.
///
/// A binary tree with domain-separated leaves and nodes; an odd node at any level
/// is promoted unchanged rather than paired with a copy of itself, which would
/// let a duplicated leaf produce the same root as a single one.
fn merkle_root(entries: &[LogEntry]) -> Hash {
    if entries.is_empty() {
        return Hash::of(EMPTY_MERKLE_DOMAIN);
    }
    let mut level: Vec<Hash> = entries
        .iter()
        .map(|entry| {
            let mut hasher = Hasher::new();
            hasher
                .update(LEAF_PREFIX)
                .update(&entry.content_hash.to_bytes());
            hasher.finalize()
        })
        .collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(match pair {
                [left, right] => {
                    let mut hasher = Hasher::new();
                    hasher
                        .update(NODE_PREFIX)
                        .update(&left.to_bytes())
                        .update(&right.to_bytes());
                    hasher.finalize()
                }
                [lone] => *lone,
                _ => unreachable!("chunks(2) yields one or two elements"),
            });
        }
        level = next;
    }
    level[0]
}

impl From<HistoryRoot> for CBOR {
    fn from(r: HistoryRoot) -> Self {
        let mut m = Map::new();
        m.insert("kind", HISTORY_ROOT_KIND);
        m.insert("address", r.address);
        m.insert("from_seq", r.from_seq);
        m.insert("to_seq", r.to_seq);
        m.insert("computed_at", r.computed_at);
        m.insert(
            "merkle_root",
            CBOR::to_byte_string(r.merkle_root.to_bytes()),
        );
        m.into()
    }
}

impl TryFrom<CBOR> for HistoryRoot {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != HISTORY_ROOT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let merkle_bytes: [u8; 32] = map
            .extract::<&str, CBOR>("merkle_root")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(HistoryRoot {
            address: map.extract::<&str, Address>("address")?,
            from_seq: map.extract::<&str, u64>("from_seq")?,
            to_seq: map.extract::<&str, u64>("to_seq")?,
            computed_at: map.extract::<&str, i64>("computed_at")?,
            merkle_root: Hash::from_bytes(merkle_bytes),
        })
    }
}

/// Current wall-clock Unix seconds, stamping an export that did not pin its own
/// instant.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::to_canonical_bytes;
    use rrn_ledger::enrollment::EnrollmentBasis;
    use rrn_storage::log::StoredPayload;

    use crate::testutil::{establish_members, settle_trade, vouch, WEEK};

    const MONTH: i64 = 30 * 86_400;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    fn enroll(db: &Database, station: &Keypair, who: &Keypair) {
        crate::testutil::enroll(db, station, &addr(who), EnrollmentBasis::Pairing, 0);
    }

    /// A station log where alice (enrolled) trades with bob both ways a week
    /// apart and vouches for him, while two other enrolled members transact and
    /// vouch among themselves.
    fn populated_db(alice: &Keypair, bob: &Keypair, station: &Keypair) -> Database {
        let db = fresh_db();
        let t = 6 * MONTH;
        enroll(&db, station, alice);
        enroll(&db, station, bob);
        settle_trade(&db, station, alice, bob, 0, t - WEEK);
        settle_trade(&db, station, bob, alice, 0, t);
        vouch(&db, alice, &addr(bob), t);

        let (carol, dave) = (Keypair::generate(), Keypair::generate());
        enroll(&db, station, &carol);
        enroll(&db, station, &dave);
        settle_trade(&db, station, &carol, &dave, 0, t);
        vouch(&db, &carol, &addr(&dave), t);
        db
    }

    /// The message `verify_history` fails with for a given cause.
    fn failure(cause: HistoryError) -> String {
        crate::Error::from(cause).to_string()
    }

    #[test]
    fn exported_history_verifies_to_the_profile_the_exporter_computed() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db_a = populated_db(&alice, &bob, &station);
        let now = 9 * MONTH;

        let expected = ReputationScorer::new(&db_a, &station.public_key())
            .score_at(&addr(&alice), now)
            .unwrap();
        let bundle = export_history_at(&db_a, &addr(&alice), &station, now).unwrap();

        // Station B holds none of this log — only the bundle.
        let imported = verify_history(&bundle).unwrap();
        assert_eq!(imported, expected);
        assert!(expected.trade_reliability > 0.0, "the fixture must score");
        assert!(
            expected.attestation_accuracy > 0.0,
            "the fixture must score"
        );
    }

    #[test]
    fn the_bundle_carries_whole_lifecycles_and_nobody_elses_business() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let bundle = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        // Alice's and bob's enrollments (each event's eligibility turns on them),
        // two transactions × (proposal, confirmation, settlement), and one vouch.
        // The other members' six entries are not alice's business.
        assert_eq!(bundle.log_entries.len(), 9);
        assert_eq!(bundle.signed_root.payload.from_seq, 1);
        assert_eq!(bundle.signed_root.payload.to_seq, 9);
    }

    #[test]
    fn export_carries_enrollments_and_the_anchor_chain() {
        // A two-link chain: root → link → subject (ADR-0038 §11). A verifier
        // holding only the subject's bundle must be able to form both edges,
        // which takes the link's and the root's evidence and enrollments too.
        let db = fresh_db();
        let station = Keypair::generate();
        let (link, subject, bob) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t0 = 20 * WEEK;
        let root = establish_members(&db, &station, 2, t0).remove(0);
        for who in [&link, &subject, &bob] {
            enroll(&db, &station, who);
        }
        // The root, established, vouches for the link.
        vouch(&db, &root, &addr(&link), t0);
        // The link earns standing over ten weeks, then vouches for the subject.
        for w in 0..10 {
            settle_trade(&db, &station, &bob, &link, w, t0 + w as i64 * WEEK);
            settle_trade(&db, &station, &bob, &subject, 10 + w, t0 + w as i64 * WEEK);
        }
        let now = t0 + 10 * WEEK;
        vouch(&db, &link, &addr(&subject), now);

        let expected = ReputationScorer::new(&db, &station.public_key())
            .score_at(&addr(&subject), now)
            .unwrap();
        assert!(
            expected.trade_reliability > 1.0,
            "the subject must be anchored"
        );

        let bundle = export_history_at(&db, &addr(&subject), &station, now).unwrap();
        assert_eq!(verify_history(&bundle).unwrap(), expected);

        // Withholding a link — here the root's founder enrollment, so the root is
        // no root to the verifier — yields the capped profile, never more.
        let is_roots_enrollment = |entry: &LogEntry| {
            from_canonical_bytes_if_kind::<EnrollmentRecord>(&entry.payload.bytes, ENROLLMENT_KIND)
                .ok()
                .flatten()
                .is_some_and(|r| r.member == addr(&root))
        };
        assert!(bundle.log_entries.iter().any(is_roots_enrollment));
        let withheld: Vec<LogEntry> = bundle
            .log_entries
            .iter()
            .filter(|e| !is_roots_enrollment(e))
            .cloned()
            .collect();
        let root_claim = HistoryRoot {
            address: addr(&subject),
            from_seq: withheld.first().map_or(0, |e| e.seq),
            to_seq: withheld.last().map_or(0, |e| e.seq),
            computed_at: now,
            merkle_root: merkle_root(&withheld),
        };
        let short = PortableReputationHistory {
            address: addr(&subject),
            log_entries: withheld,
            signed_root: SignedPayload::sign(root_claim, &station),
        };
        let capped = verify_history(&short).unwrap();
        assert!(capped.trade_reliability <= crate::sybil::ANCHOR_DIMENSION_CAP);
        assert!(capped.composite() < expected.composite());
    }

    #[test]
    fn a_member_with_no_history_exports_an_empty_bundle() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let stranger = Keypair::generate();

        let bundle = export_history_at(&db, &addr(&stranger), &station, 9 * MONTH).unwrap();
        assert!(bundle.log_entries.is_empty());
        assert_eq!(bundle.signed_root.payload.from_seq, 0);
        assert_eq!(bundle.signed_root.payload.to_seq, 0);

        let mut expected = ReputationProfile::empty(addr(&stranger));
        expected.last_updated = 9 * MONTH;
        assert_eq!(verify_history(&bundle).unwrap(), expected);
    }

    #[test]
    fn tampering_with_an_entrys_bytes_breaks_verification() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let mut bundle = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        // Flip a byte in a payload: the signature over it no longer holds.
        bundle.log_entries[0].payload.bytes[10] ^= 0xff;
        let seq = bundle.log_entries[0].seq;
        assert_eq!(
            verify_history(&bundle).unwrap_err().to_string(),
            failure(HistoryError::EntrySignature { seq })
        );
    }

    #[test]
    fn re_signing_a_tampered_entry_still_breaks_the_merkle_root() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let mut bundle = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        // The strongest forgery available to a holder of the bundle: swap in an
        // entry that is genuinely signed (by the attacker) and whose content hash
        // genuinely matches, so everything local about it is consistent.
        let attacker = Keypair::generate();
        let forged = SignedPayload::sign(
            TransactionProposal::new(
                addr(&attacker),
                addr(&alice),
                999_999,
                None,
                7,
                1,
                i64::MAX / 2,
            ),
            &attacker,
        );
        let bytes = to_canonical_bytes(forged.payload.clone());
        bundle.log_entries[0].content_hash = Hash::of(&bytes);
        bundle.log_entries[0].payload = StoredPayload {
            bytes,
            signer: forged.signer,
            signature: forged.signature,
        };

        // The station's signature over the root still pins the original entries.
        assert_eq!(
            verify_history(&bundle).unwrap_err().to_string(),
            failure(HistoryError::MerkleRoot)
        );
    }

    #[test]
    fn a_content_hash_that_does_not_describe_its_bytes_is_rejected() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let mut bundle = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        // Keep the Merkle tree intact by leaving the hash's *position* alone but
        // making it describe something else.
        bundle.log_entries[2].content_hash = Hash::of(b"a hash of nothing in this bundle");
        let seq = bundle.log_entries[2].seq;
        let err = verify_history(&bundle).unwrap_err().to_string();
        assert_eq!(err, failure(HistoryError::ContentHash { seq }));
    }

    #[test]
    fn dropping_or_reordering_entries_breaks_verification() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let original = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        // Drop an interior entry: the span still matches, so only the root catches it.
        let mut dropped = original.clone();
        dropped.log_entries.remove(3);
        assert_eq!(
            verify_history(&dropped).unwrap_err().to_string(),
            failure(HistoryError::MerkleRoot)
        );

        // Reorder: caught earlier, by the ascending-sequence check.
        let mut reordered = original.clone();
        reordered.log_entries.swap(1, 2);
        assert_eq!(
            verify_history(&reordered).unwrap_err().to_string(),
            failure(HistoryError::SequenceRange)
        );
    }

    #[test]
    fn a_root_that_does_not_match_its_entries_is_rejected() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let mut bundle = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        // Re-signed with the station's own key, so the signature is genuine and
        // only the Merkle comparison stands between the claim and belief.
        let mut root = bundle.signed_root.payload.clone();
        root.merkle_root = Hash::of(b"not the entries in this bundle");
        bundle.signed_root = SignedPayload::sign(root, &station);
        assert_eq!(
            verify_history(&bundle).unwrap_err().to_string(),
            failure(HistoryError::MerkleRoot)
        );

        // Editing the root without re-signing fails at the signature instead.
        let mut unsigned_edit = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();
        unsigned_edit.signed_root.payload.computed_at += 1;
        assert_eq!(
            verify_history(&unsigned_edit).unwrap_err().to_string(),
            failure(HistoryError::RootSignature)
        );
    }

    #[test]
    fn a_root_for_another_member_is_rejected() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let db = populated_db(&alice, &bob, &station);
        let mut bundle = export_history_at(&db, &addr(&alice), &station, 9 * MONTH).unwrap();

        let mut root = bundle.signed_root.payload.clone();
        root.address = addr(&bob);
        bundle.signed_root = SignedPayload::sign(root, &station);
        assert_eq!(
            verify_history(&bundle).unwrap_err().to_string(),
            failure(HistoryError::AddressMismatch)
        );
    }

    #[test]
    fn the_root_round_trips_through_cbor() {
        let station = Keypair::generate();
        let root = HistoryRoot {
            address: addr(&station),
            from_seq: 3,
            to_seq: 91,
            computed_at: 9 * MONTH,
            merkle_root: Hash::of(b"some entries"),
        };
        let cbor: CBOR = root.clone().into();
        assert_eq!(HistoryRoot::try_from(cbor).unwrap(), root);
    }

    #[test]
    fn two_stations_export_the_same_root() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        // Identical logs built independently — as after replication.
        let db_a = populated_db(&alice, &bob, &station);
        let db_b = populated_db(&alice, &bob, &station);

        let a = export_history_at(&db_a, &addr(&alice), &station, 9 * MONTH).unwrap();
        let b = export_history_at(&db_b, &addr(&alice), &station, 9 * MONTH).unwrap();
        assert_eq!(a.signed_root.payload, b.signed_root.payload);
    }
}
