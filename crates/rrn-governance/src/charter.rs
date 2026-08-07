//! Charter — a community's constitution: a multisig-signed, canonically hashed
//! document fixing its governance parameters, its founding set, and its lineage.
//!
//! # Shape
//!
//! A [`Charter`] is the constitutional *body* — governance parameters, founding
//! principles, the declared founding set, and the lineage link to the Charter it
//! replaces. Its founders authorize it by co-signing its canonical bytes, which
//! yields a [`SignedCharter`] (a [`MultiSignedPayload`] of the body). The
//! `charter_hash` treaty partners pin is the Blake3 of the *body* alone
//! ([`SignedCharter::charter_hash`]) — independent of how many founders signed —
//! so any change to the constitution changes the hash (ADR-0012, design overview
//! § 2.2.1 / § 8.3).
//!
//! # Founder authorization — trust on first use
//!
//! No roster or founder record exists anywhere else in the system (membership is
//! derived from the log), so the Charter *is* the source of truth for its own
//! founders: it names them in [`Charter::founders`] and is valid iff the distinct
//! valid founder-signers number at least `ceil(founders * 0.75)`
//! ([`founder_threshold`]). That ≥ 75 % bar is what stops any single named founder
//! from standing up a constitution alone. See [`SignedCharter::verify_founders`].
//!
//! # On the log
//!
//! The append-only log stores single-signer entries, so a [`SignedCharter`] is
//! published wrapped in a [`SignedPayload`] signed by the publishing founder —
//! the outer signature is log attribution; the inner multisig is the authority.
//! Its canonical form carries `kind = "rrn.gov.charter"` so replay can tell it
//! apart. The newest published, founder-authorized Charter (highest `version`)
//! is the community's genesis root; see [`founder_charter`]. The *effective*
//! Charter — that root plus any amendments the community has since enacted through
//! the vote lifecycle — is resolved a layer up, in [`crate::tally::effective_charter`]
//! (ADR-0012 § 4). Founder authorization lives here; amendment authority is a
//! tally, so it lives with the tally.

use std::collections::HashSet;

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, Signature};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::{MultiSignedPayload, MultiVerifyError, SignedPayload};
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};

/// Discriminant carried in the `kind` field of a [`SignedCharter`]'s canonical
/// CBOR, so log replay can tell it apart from other records.
pub(crate) const CHARTER_KIND: &str = "rrn.gov.charter";

/// The voting mechanism a community uses. Phase 1 ships direct voting only; the
/// design overview's other mechanisms (liquid, sortition, council, consent,
/// quadratic) are Phase 2+, and this enum is where they will be added (ADR-0012).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VotingMechanism {
    /// One established member, one vote.
    #[default]
    Direct,
}

/// The governance parameters a Charter fixes for ordinary (statute / admin-rule)
/// proposals. Defaults are ADR-0012's Phase-1 numbers; every field is a Charter
/// value, so a community may set its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceStructure {
    /// How votes are cast. Phase 1: [`VotingMechanism::Direct`].
    pub voting_mechanism: VotingMechanism,
    /// Minimum share of the electorate that must participate for a statute vote
    /// to be quorate.
    pub statute_quorum_pct: u8,
    /// Share of cast yes/no votes required to pass a statute.
    pub statute_approval_pct: u8,
    /// Days a statute proposal deliberates before its vote opens.
    pub deliberation_window_days: u8,
    /// Days between a non-emergency statute passing and taking effect.
    pub implementation_delay_days: u8,
    /// Approval share required for an emergency proposal (a higher bar; takes
    /// effect immediately).
    pub emergency_threshold_pct: u8,
}

impl Default for GovernanceStructure {
    fn default() -> Self {
        Self {
            voting_mechanism: VotingMechanism::Direct,
            statute_quorum_pct: 30,
            statute_approval_pct: 50,
            deliberation_window_days: 7,
            implementation_delay_days: 7,
            emergency_threshold_pct: 67,
        }
    }
}

/// The bar for amending the Charter itself — deliberately higher than for a
/// statute, since the Charter is the layer everything else references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmendmentRules {
    /// Minimum electorate participation for a Charter-amendment vote.
    pub charter_quorum_pct: u8,
    /// Share of cast yes/no votes required to ratify an amendment.
    pub charter_approval_pct: u8,
    /// Days a proposed amendment deliberates before its vote opens.
    pub charter_deliberation_window_days: u8,
}

impl Default for AmendmentRules {
    fn default() -> Self {
        Self {
            charter_quorum_pct: 50,
            charter_approval_pct: 75,
            charter_deliberation_window_days: 30,
        }
    }
}

/// A community's constitution: the signed, hashed, lineage-tracked body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Charter {
    /// 1 at genesis; incremented by one per amendment.
    pub version: u32,
    /// A stable identifier for the community this Charter governs.
    pub community_id: String,
    /// The founding principles, as free text.
    pub founding_principles: Vec<String>,
    /// Rights this community guarantees above the federation universal floor.
    pub rights_floor: Vec<String>,
    /// The governance parameters for ordinary proposals.
    pub governance_structure: GovernanceStructure,
    /// The (higher) bar for amending this Charter.
    pub amendment_rules: AmendmentRules,
    /// Unix seconds when the Charter was created.
    pub created_at: i64,
    /// The genesis founding set. Retained unchanged on amendment as a historical
    /// record — it is a genesis fact, not a live membership list.
    pub founders: Vec<Address>,
    /// The prior Charter's `charter_hash`, chaining the lineage; `None` at
    /// genesis.
    pub previous_hash: Option<Hash>,
}

impl Charter {
    /// The Blake3 hash of this body's canonical bytes — the same content address
    /// [`SignedCharter::charter_hash`] pins, computed from the body alone so a
    /// bare amended Charter (which carries no signatures of its own) can still be
    /// chained by `previous_hash` and matched against a prior Charter's hash.
    pub fn hash(&self) -> Hash {
        Hash::of(&to_canonical_bytes(self.clone()))
    }
}

/// The inputs to [`create_charter`]. Mirrors [`Charter`] minus the parts the
/// constructor derives from context — nothing here, currently, so the split is a
/// forward-looking seam. For genesis, set `version = 1` and `previous_hash =
/// None`; an amendment sets `version = prior + 1` and links `previous_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CharterParams {
    /// See [`Charter::version`].
    pub version: u32,
    /// See [`Charter::community_id`].
    pub community_id: String,
    /// See [`Charter::founding_principles`].
    pub founding_principles: Vec<String>,
    /// See [`Charter::rights_floor`].
    pub rights_floor: Vec<String>,
    /// See [`Charter::governance_structure`].
    pub governance_structure: GovernanceStructure,
    /// See [`Charter::amendment_rules`].
    pub amendment_rules: AmendmentRules,
    /// See [`Charter::founders`].
    pub founders: Vec<Address>,
    /// See [`Charter::created_at`].
    pub created_at: i64,
    /// See [`Charter::previous_hash`].
    pub previous_hash: Option<Hash>,
}

/// A [`Charter`] co-signed by its founders — the constitutional artifact.
///
/// Wraps a [`MultiSignedPayload`] whose signatures are over the Charter body's
/// canonical bytes. Verify founder authorization with
/// [`verify_founders`](Self::verify_founders); read the body with
/// [`charter`](Self::charter) and its pinned hash with
/// [`charter_hash`](Self::charter_hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCharter(MultiSignedPayload<Charter>);

/// Errors creating, authorizing, or storing a Charter.
#[derive(thiserror::Error, Debug)]
pub enum CharterError {
    /// The founding set was empty.
    #[error("the founding set is empty")]
    NoFounders,
    /// The same founder was listed more than once in the founding set.
    #[error("the founding set names the same founder more than once")]
    DuplicateFounder,
    /// A signing keypair is not among the declared founders.
    #[error("a signer is not one of the declared founders")]
    NonFounderSigner,
    /// The signatures were structurally malformed.
    #[error("charter signatures: {0}")]
    Signatures(#[from] MultiVerifyError),
    /// Too few founders signed to authorize the Charter.
    #[error("charter under-signed: {valid} of {founders} founders signed, need {required}")]
    BelowThreshold {
        /// Distinct valid founder-signers.
        valid: usize,
        /// The `ceil(founders * 0.75)` bar.
        required: usize,
        /// Size of the declared founding set.
        founders: usize,
    },
    /// A storage/log error while publishing or reading the Charter.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
}

/// The founder-signature bar: `ceil(n * 0.75)`, in integer arithmetic so it
/// matches on every platform. Genesis (`n = 0`) has a bar of 0.
pub fn founder_threshold(n: usize) -> usize {
    n.saturating_mul(3).div_ceil(4)
}

/// Builds and founder-signs a Charter.
///
/// `signers` are the founder keypairs co-signing at creation; they must each be
/// among `params.founders`. The result is not required to clear the threshold
/// here — that is [`SignedCharter::verify_founders`]'s job — so an intentionally
/// under-signed Charter can be constructed and then rejected on verification.
pub fn create_charter(
    params: CharterParams,
    signers: &[Keypair],
) -> Result<SignedCharter, CharterError> {
    if params.founders.is_empty() {
        return Err(CharterError::NoFounders);
    }
    let mut declared = HashSet::with_capacity(params.founders.len());
    for founder in &params.founders {
        if !declared.insert(*founder) {
            return Err(CharterError::DuplicateFounder);
        }
    }
    for kp in signers {
        if !declared.contains(&Address::from_public_key(kp.public_key())) {
            return Err(CharterError::NonFounderSigner);
        }
    }

    let charter = Charter {
        version: params.version,
        community_id: params.community_id,
        founding_principles: params.founding_principles,
        rights_floor: params.rights_floor,
        governance_structure: params.governance_structure,
        amendment_rules: params.amendment_rules,
        created_at: params.created_at,
        founders: params.founders,
        previous_hash: params.previous_hash,
    };
    Ok(SignedCharter(MultiSignedPayload::sign(charter, signers)))
}

impl SignedCharter {
    /// The constitutional body.
    pub fn charter(&self) -> &Charter {
        &self.0.payload
    }

    /// The Blake3 hash of the Charter *body*'s canonical bytes — the stable
    /// content address treaty partners and the community profile pin. Independent
    /// of the signatures, so co-signing does not change it.
    pub fn charter_hash(&self) -> Hash {
        self.0.payload_hash()
    }

    /// Verifies founder authorization: at least `ceil(founders * 0.75)` distinct
    /// declared founders produced a valid signature over the body.
    ///
    /// A signature from a key that is *not* a declared founder is ignored rather
    /// than fatal — it simply does not count toward the threshold — so a stray
    /// valid signature cannot grief an otherwise-authorized Charter. Structural
    /// signature faults (count mismatch, duplicated signer) are still hard errors.
    pub fn verify_founders(&self) -> Result<(), CharterError> {
        let valid = self.0.verify()?;
        let founders: HashSet<Address> = self.charter().founders.iter().copied().collect();
        let valid_founders = valid
            .iter()
            .filter(|pk| founders.contains(&Address::from_public_key(**pk)))
            .count();
        let required = founder_threshold(founders.len());
        if valid_founders < required {
            return Err(CharterError::BelowThreshold {
                valid: valid_founders,
                required,
                founders: founders.len(),
            });
        }
        Ok(())
    }
}

/// Publishes a founder-authorized Charter to the log, wrapped in a
/// single-signer envelope signed by `publisher` (attribution; the inner multisig
/// is the authority). Rejects a Charter that does not clear the founder threshold
/// before writing anything.
pub fn store_charter(
    log: &mut AppendLog,
    publisher: &Keypair,
    charter: SignedCharter,
) -> Result<LogEntry, CharterError> {
    charter.verify_founders()?;
    Ok(log.append(SignedPayload::sign(charter, publisher))?)
}

/// The community's genesis root Charter: the highest-`version`, founder-authorized
/// Charter on the log, or `None` if none has been published yet. Ties on version
/// break toward the later log entry.
///
/// This is the *founder* charter only — it does not fold in amendments enacted
/// through the vote lifecycle (those carry no founder authority). The effective,
/// possibly-amended Charter is [`crate::tally::effective_charter`], which builds
/// on this root.
///
/// Deviation from the task sketch's non-optional return: a community may legally
/// have no Charter yet (it is bootstrapping), which is an absence, not an error.
pub fn founder_charter(db: &Database) -> Result<Option<SignedCharter>, CharterError> {
    let log = AppendLog::new(db);
    let mut best: Option<(u32, u64, SignedCharter)> = None;
    for entry in log.iter_from(1) {
        let entry = entry?;
        // Non-Charter entries (and any that no longer decode) are simply skipped.
        let Ok(signed) = from_canonical_bytes::<SignedCharter>(&entry.payload.bytes) else {
            continue;
        };
        if signed.verify_founders().is_err() {
            continue;
        }
        let version = signed.charter().version;
        let supersedes = best
            .as_ref()
            .is_none_or(|(v, seq, _)| version > *v || (version == *v && entry.seq > *seq));
        if supersedes {
            best = Some((version, entry.seq, signed));
        }
    }
    Ok(best.map(|(_, _, signed)| signed))
}

/// The `charter_hash` of the [`founder_charter`], or `None` if none is published.
pub fn founder_charter_hash(db: &Database) -> Result<Option<Hash>, CharterError> {
    Ok(founder_charter(db)?.map(|signed| signed.charter_hash()))
}

// --- Canonical CBOR ---------------------------------------------------------
//
// `PublicKey`/`Signature` have no CBOR mapping of their own (they are wire-level
// byte arrays), so they are encoded here as CBOR byte strings; `Address` and the
// scalar fields carry their own mappings.

impl From<VotingMechanism> for CBOR {
    fn from(v: VotingMechanism) -> Self {
        match v {
            VotingMechanism::Direct => "direct".into(),
        }
    }
}

impl TryFrom<CBOR> for VotingMechanism {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        match String::try_from(cbor)?.as_str() {
            "direct" => Ok(VotingMechanism::Direct),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

impl From<GovernanceStructure> for CBOR {
    fn from(g: GovernanceStructure) -> Self {
        let mut m = Map::new();
        m.insert("voting_mechanism", g.voting_mechanism);
        m.insert("statute_quorum_pct", g.statute_quorum_pct as u64);
        m.insert("statute_approval_pct", g.statute_approval_pct as u64);
        m.insert(
            "deliberation_window_days",
            g.deliberation_window_days as u64,
        );
        m.insert(
            "implementation_delay_days",
            g.implementation_delay_days as u64,
        );
        m.insert("emergency_threshold_pct", g.emergency_threshold_pct as u64);
        m.into()
    }
}

impl TryFrom<CBOR> for GovernanceStructure {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(GovernanceStructure {
            voting_mechanism: map.extract::<&str, VotingMechanism>("voting_mechanism")?,
            statute_quorum_pct: extract_u8(&map, "statute_quorum_pct")?,
            statute_approval_pct: extract_u8(&map, "statute_approval_pct")?,
            deliberation_window_days: extract_u8(&map, "deliberation_window_days")?,
            implementation_delay_days: extract_u8(&map, "implementation_delay_days")?,
            emergency_threshold_pct: extract_u8(&map, "emergency_threshold_pct")?,
        })
    }
}

impl From<AmendmentRules> for CBOR {
    fn from(a: AmendmentRules) -> Self {
        let mut m = Map::new();
        m.insert("charter_quorum_pct", a.charter_quorum_pct as u64);
        m.insert("charter_approval_pct", a.charter_approval_pct as u64);
        m.insert(
            "charter_deliberation_window_days",
            a.charter_deliberation_window_days as u64,
        );
        m.into()
    }
}

impl TryFrom<CBOR> for AmendmentRules {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(AmendmentRules {
            charter_quorum_pct: extract_u8(&map, "charter_quorum_pct")?,
            charter_approval_pct: extract_u8(&map, "charter_approval_pct")?,
            charter_deliberation_window_days: extract_u8(&map, "charter_deliberation_window_days")?,
        })
    }
}

impl From<Charter> for CBOR {
    fn from(c: Charter) -> Self {
        let mut m = Map::new();
        m.insert("version", c.version as u64);
        m.insert("community_id", c.community_id);
        m.insert("founding_principles", string_list(c.founding_principles));
        m.insert("rights_floor", string_list(c.rights_floor));
        m.insert("governance_structure", c.governance_structure);
        m.insert("amendment_rules", c.amendment_rules);
        m.insert("created_at", c.created_at);
        m.insert(
            "founders",
            c.founders.into_iter().map(CBOR::from).collect::<Vec<_>>(),
        );
        // Lineage link is omitted at genesis rather than encoded as null, matching
        // the log's optional-field convention.
        if let Some(prev) = c.previous_hash {
            m.insert("previous_hash", CBOR::to_byte_string(prev.to_bytes()));
        }
        m.into()
    }
}

impl TryFrom<CBOR> for Charter {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let previous_hash = match map.get::<&str, CBOR>("previous_hash") {
            Some(cbor) => Some(hash_from_cbor(cbor)?),
            None => None,
        };
        Ok(Charter {
            version: extract_u32(&map, "version")?,
            community_id: map.extract::<&str, String>("community_id")?,
            founding_principles: string_vec(map.extract::<&str, CBOR>("founding_principles")?)?,
            rights_floor: string_vec(map.extract::<&str, CBOR>("rights_floor")?)?,
            governance_structure: map
                .extract::<&str, GovernanceStructure>("governance_structure")?,
            amendment_rules: map.extract::<&str, AmendmentRules>("amendment_rules")?,
            created_at: map.extract::<&str, i64>("created_at")?,
            founders: address_vec(map.extract::<&str, CBOR>("founders")?)?,
            previous_hash,
        })
    }
}

impl From<SignedCharter> for CBOR {
    fn from(sc: SignedCharter) -> Self {
        let MultiSignedPayload {
            payload,
            signers,
            signatures,
        } = sc.0;
        let mut m = Map::new();
        m.insert("kind", CHARTER_KIND);
        m.insert("charter", payload);
        m.insert(
            "signers",
            signers
                .iter()
                .map(|pk| CBOR::to_byte_string(pk.to_bytes()))
                .collect::<Vec<_>>(),
        );
        m.insert(
            "signatures",
            signatures
                .iter()
                .map(|s| CBOR::to_byte_string(s.to_bytes()))
                .collect::<Vec<_>>(),
        );
        m.into()
    }
}

impl TryFrom<CBOR> for SignedCharter {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CHARTER_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let payload = map.extract::<&str, Charter>("charter")?;
        let signers = pubkey_vec(map.extract::<&str, CBOR>("signers")?)?;
        let signatures = signature_vec(map.extract::<&str, CBOR>("signatures")?)?;
        Ok(SignedCharter(MultiSignedPayload {
            payload,
            signers,
            signatures,
        }))
    }
}

// --- CBOR helpers -----------------------------------------------------------

fn string_list(items: Vec<String>) -> Vec<CBOR> {
    items.into_iter().map(CBOR::from).collect()
}

fn extract_u8(map: &dcbor::Map, key: &str) -> Result<u8, dcbor::Error> {
    u8::try_from(map.extract::<&str, u64>(key)?).map_err(|_| dcbor::Error::WrongType)
}

fn extract_u32(map: &dcbor::Map, key: &str) -> Result<u32, dcbor::Error> {
    u32::try_from(map.extract::<&str, u64>(key)?).map_err(|_| dcbor::Error::WrongType)
}

fn string_vec(cbor: CBOR) -> Result<Vec<String>, dcbor::Error> {
    match cbor.into_case() {
        CBORCase::Array(items) => items.into_iter().map(String::try_from).collect(),
        _ => Err(dcbor::Error::WrongType),
    }
}

fn address_vec(cbor: CBOR) -> Result<Vec<Address>, dcbor::Error> {
    match cbor.into_case() {
        CBORCase::Array(items) => items.into_iter().map(Address::try_from).collect(),
        _ => Err(dcbor::Error::WrongType),
    }
}

fn hash_from_cbor(cbor: CBOR) -> Result<Hash, dcbor::Error> {
    let bytes: [u8; 32] = cbor
        .try_into_byte_string()?
        .as_slice()
        .try_into()
        .map_err(|_| dcbor::Error::WrongType)?;
    Ok(Hash::from_bytes(bytes))
}

fn pubkey_vec(cbor: CBOR) -> Result<Vec<PublicKey>, dcbor::Error> {
    match cbor.into_case() {
        CBORCase::Array(items) => items
            .into_iter()
            .map(|c| {
                let bytes: [u8; 32] = c
                    .try_into_byte_string()?
                    .as_slice()
                    .try_into()
                    .map_err(|_| dcbor::Error::WrongType)?;
                PublicKey::from_bytes(bytes).map_err(|_| dcbor::Error::WrongType)
            })
            .collect(),
        _ => Err(dcbor::Error::WrongType),
    }
}

fn signature_vec(cbor: CBOR) -> Result<Vec<Signature>, dcbor::Error> {
    match cbor.into_case() {
        CBORCase::Array(items) => items
            .into_iter()
            .map(|c| {
                let bytes: [u8; 64] = c
                    .try_into_byte_string()?
                    .as_slice()
                    .try_into()
                    .map_err(|_| dcbor::Error::WrongType)?;
                Signature::from_bytes(bytes).map_err(|_| dcbor::Error::WrongType)
            })
            .collect(),
        _ => Err(dcbor::Error::WrongType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::to_canonical_bytes;

    fn founder_keys(n: usize) -> Vec<Keypair> {
        (0..n).map(|_| Keypair::generate()).collect()
    }

    fn params_for(founders: &[Keypair]) -> CharterParams {
        CharterParams {
            version: 1,
            community_id: "rrn-testville".into(),
            founding_principles: vec!["mutual credit".into(), "one member one vote".into()],
            rights_floor: vec!["exit".into()],
            governance_structure: GovernanceStructure::default(),
            amendment_rules: AmendmentRules::default(),
            founders: founders
                .iter()
                .map(|kp| Address::from_public_key(kp.public_key()))
                .collect(),
            created_at: 1_700_000_000,
            previous_hash: None,
        }
    }

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        db
    }

    #[test]
    fn threshold_is_ceil_three_quarters() {
        assert_eq!(founder_threshold(0), 0);
        assert_eq!(founder_threshold(1), 1);
        assert_eq!(founder_threshold(2), 2); // ceil(1.5)
        assert_eq!(founder_threshold(3), 3); // ceil(2.25)
        assert_eq!(founder_threshold(4), 3); // ceil(3.0)
        assert_eq!(founder_threshold(5), 4); // ceil(3.75)
        assert_eq!(founder_threshold(8), 6);
    }

    #[test]
    fn four_founders_three_sign_is_valid() {
        let founders = founder_keys(4);
        let signed = create_charter(params_for(&founders), &founders[..3]).unwrap();
        assert!(signed.verify_founders().is_ok());
    }

    #[test]
    fn four_founders_two_sign_is_below_threshold() {
        let founders = founder_keys(4);
        let signed = create_charter(params_for(&founders), &founders[..2]).unwrap();
        assert!(matches!(
            signed.verify_founders(),
            Err(CharterError::BelowThreshold {
                valid: 2,
                required: 3,
                founders: 4,
            })
        ));
    }

    #[test]
    fn charter_hash_is_stable_across_runs_and_signer_sets() {
        let founders = founder_keys(4);
        let params = params_for(&founders);
        // Same body, signed by different founder subsets → identical body hash.
        let a = create_charter(params.clone(), &founders[..3]).unwrap();
        let b = create_charter(params.clone(), &founders[..4]).unwrap();
        assert_eq!(a.charter_hash(), b.charter_hash());
        // And stable against a fresh construction of the same params.
        let c = create_charter(params, &founders[..3]).unwrap();
        assert_eq!(a.charter_hash(), c.charter_hash());
    }

    #[test]
    fn a_non_founder_signature_does_not_count() {
        let founders = founder_keys(4);
        let mut signed = create_charter(params_for(&founders), &founders[..2]).unwrap();
        // A valid signature from an outsider must not push it over the threshold.
        signed.0.add_signature(&Keypair::generate());
        assert!(matches!(
            signed.verify_founders(),
            Err(CharterError::BelowThreshold { valid: 2, .. })
        ));
    }

    #[test]
    fn create_rejects_empty_and_duplicate_founders_and_outsiders() {
        let founders = founder_keys(3);
        let mut empty = params_for(&founders);
        empty.founders.clear();
        assert!(matches!(
            create_charter(empty, &founders),
            Err(CharterError::NoFounders)
        ));

        let mut dup = params_for(&founders);
        dup.founders.push(dup.founders[0]);
        assert!(matches!(
            create_charter(dup, &founders),
            Err(CharterError::DuplicateFounder)
        ));

        let outsider = Keypair::generate();
        assert!(matches!(
            create_charter(params_for(&founders), &[outsider]),
            Err(CharterError::NonFounderSigner)
        ));
    }

    #[test]
    fn signed_charter_cbor_roundtrips() {
        let founders = founder_keys(4);
        let signed = create_charter(params_for(&founders), &founders[..3]).unwrap();
        let bytes = to_canonical_bytes(signed.clone());
        let back = from_canonical_bytes::<SignedCharter>(&bytes).unwrap();
        assert_eq!(signed, back);
        assert_eq!(signed.charter_hash(), back.charter_hash());
        assert!(back.verify_founders().is_ok());
    }

    #[test]
    fn store_then_read_founder_charter() {
        let db = fresh_db();
        let founders = founder_keys(4);
        let signed = create_charter(params_for(&founders), &founders[..3]).unwrap();
        let want_hash = signed.charter_hash();
        {
            let mut log = AppendLog::new(&db);
            store_charter(&mut log, &founders[0], signed).unwrap();
        }
        let current = founder_charter(&db)
            .unwrap()
            .expect("a charter is published");
        assert_eq!(current.charter_hash(), want_hash);
        assert_eq!(founder_charter_hash(&db).unwrap(), Some(want_hash));
    }

    #[test]
    fn higher_version_supersedes() {
        let db = fresh_db();
        let founders = founder_keys(4);
        let v1 = create_charter(params_for(&founders), &founders[..3]).unwrap();

        let mut p2 = params_for(&founders);
        p2.version = 2;
        p2.previous_hash = Some(v1.charter_hash());
        let v2 = create_charter(p2, &founders[..4]).unwrap();
        let v2_hash = v2.charter_hash();

        let mut log = AppendLog::new(&db);
        store_charter(&mut log, &founders[0], v1).unwrap();
        store_charter(&mut log, &founders[1], v2).unwrap();

        let current = founder_charter(&db).unwrap().unwrap();
        assert_eq!(current.charter().version, 2);
        assert_eq!(current.charter_hash(), v2_hash);
    }

    #[test]
    fn store_rejects_under_signed_charter() {
        let db = fresh_db();
        let founders = founder_keys(4);
        let under = create_charter(params_for(&founders), &founders[..2]).unwrap();
        let mut log = AppendLog::new(&db);
        assert!(matches!(
            store_charter(&mut log, &founders[0], under),
            Err(CharterError::BelowThreshold { .. })
        ));
        // Nothing was written.
        assert!(founder_charter(&db).unwrap().is_none());
    }

    #[test]
    fn no_charter_yet_reads_as_none() {
        let db = fresh_db();
        assert!(founder_charter(&db).unwrap().is_none());
        assert!(founder_charter_hash(&db).unwrap().is_none());
    }
}
