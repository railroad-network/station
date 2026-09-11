//! Emergency governance (ADR-0023) — deciding faster in a crisis without building
//! a coup lever.
//!
//! An emergency is *declared* by a supermajority collective act of the ordinary
//! electorate, compresses a single parameter — the deliberation/voting window — for
//! a single narrow class of proposals ([`ProposalKind::Emergency`](crate::proposal::ProposalKind::Emergency)),
//! self-expires within days, freezes the constitution and pins the electorate while
//! it holds, and time-bounds every measure it passes. Its every effect is a
//! log-derived, replay-reconstructible fact anchored on the **admission clock**
//! (ADR-0022), never on any author's `created_at`.
//!
//! # Four record kinds, three member-signed and one station-signed
//!
//! - [`EmergencyDeclaration`] (`rrn.gov.emergency_declaration`, member-signed) — a
//!   member raises the crisis; its `duration_secs` is the requested lifetime.
//! - [`EmergencyCosign`] (`rrn.gov.emergency_cosign`, member-signed) — one
//!   electorate co-signature toward the declaration (or a lapse) threshold.
//! - [`EmergencyLapse`] (`rrn.gov.emergency_lapse`, member-signed) — ends an active
//!   emergency early; itself carries the same co-sign supermajority (reusing
//!   [`EmergencyCosign`], whose `declaration_hash` may target a declaration *or* a
//!   lapse).
//! - [`EmergencyActivated`] (`rrn.gov.emergency_activated`, **station-signed**) —
//!   the station's attestation, written when it admits the threshold-crossing
//!   co-signature, that freezes the **admission-clock** activation boundary into a
//!   signed, replicated fact. Admission time is station-local and re-stamped per
//!   replica (ADR-0022 §1; [`rrn_storage::log`]), so the boundary must be restated
//!   in a signed record — exactly as the ledger restates settlement and this crate
//!   restates a proposal's [window](crate::window) — or two replicas would disagree
//!   on which window governed a past vote (the replica-determinism invariant).
//!
//! A renewal is **not** a new kind — it is a fresh declaration whose *continuation*
//! status is derived from log proximity (§4). A compressed proposal's window end is
//! a station [window attestation](crate::window) on the proposal's admission, not a
//! fifth kind.
//!
//! # State is a pure function of the log
//!
//! [`emergency_timeline`] replays the log into the ordered [`ActiveEmergency`]s,
//! re-deriving each activation's legitimacy (enough eligible co-signatures, the §4
//! caps and cooldown) rather than trusting the attestation blindly — the same "the
//! log is canonical, replay re-checks it" discipline the rest of governance
//! follows. Every input it reads is a *signed* record at a definite log position
//! (the activation instant and scheduled expiry are signed onto the attestation;
//! the co-signature and lapse boundaries are log *positions*, which are replica-
//! identical), so every replica computes the identical timeline (replica
//! determinism). Whether a given proposal ran under an emergency is [`emergency_active_for`].

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_reputation::staking::grace_electorate_asof;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};

use crate::charter::{founder_charter, CharterError};
use crate::proposal::{founder_set, is_eligible_asof, ProposalError, ProposalKind};
use crate::tally::TallyError;

// --- Hard constants: floors, ceilings, and the chain bounds (ADR-0023 §4) ---
//
// These are the bars a Charter can never breach; the Charter's own emergency
// parameters are clamped to them on use (`GovernanceStructure::effective_*`).

/// Hard floor on the compressed decision window (ADR-0023 §3, "window floor"): a
/// statute that binds everyone must give the reachable-but-absent at least as much
/// notice as ADR-0011's Tier-1 24 h settlement window. Also the Phase-1 default —
/// the window is not charter-lowerable in Phase 2.
pub const EMERGENCY_WINDOW_FLOOR_SECS: i64 = 24 * 3600;

/// Hard floor on the declaration supermajority: two-thirds of the electorate. A
/// charter may raise this, never lower it (ADR-0023 §2).
pub const EMERGENCY_DECLARATION_PCT_FLOOR: u8 = 67;

/// Hard floor on the emergency measure quorum: a majority of the pinned electorate,
/// so the fast lane does not let a handful bind everyone (ADR-0023 §3).
pub const EMERGENCY_QUORUM_PCT_FLOOR: u8 = 50;

/// Hard floor on a single declaration's requested lifetime — an emergency shorter
/// than a day is not worth the ceremony (ADR-0023 §4).
pub const EMERGENCY_DURATION_FLOOR: i64 = 24 * 3600;

/// Hard ceiling on a single declaration's lifetime: half the ordinary
/// time-to-effect (`deliberation_window_days + implementation_delay_days` = 14 d),
/// so no one declaration runs longer than the process it substitutes for (§4).
pub const EMERGENCY_DURATION_CEILING: i64 = 7 * 86_400;

/// The default requested lifetime for an absent/typical request — a conservative
/// 72 h (ADR-0023 §4).
pub const EMERGENCY_DEFAULT_DURATION_SECS: i64 = 72 * 3600;

/// Hard time-to-live for a part-signed declaration (ADR-0027 D2): a declaration
/// and its co-signatures cease to count toward activation if the **first
/// threshold crossing** is not reached within this span of the declaration's
/// station-signed admission instant. A hard constant equal to
/// [`EMERGENCY_DURATION_CEILING`] (7 d) — a crisis whose supermajority cannot be
/// assembled within the longest single emergency is no longer the same crisis.
/// The boundary is inclusive (`≤`): a crossing at exactly `admitted_at + TTL`
/// still activates.
pub const EMERGENCY_DECLARATION_TTL: i64 = EMERGENCY_DURATION_CEILING;

/// Grace added to a compressed-path measure's maximum `expires_at` beyond the
/// emergency's scheduled expiry: one ordinary implementation delay (7 d), long
/// enough to legislate a durable replacement through the full process (ADR-0023 §1).
pub const EMERGENCY_MEASURE_GRACE: i64 = 7 * 86_400;

/// Maximum `expires_at` beyond `voting_ends_at` for an Emergency-kind measure passed
/// with **no** active declaration (the ordinary-path Emergency kind): 30 d, so it
/// cannot be a permanent law either (ADR-0023 §1).
pub const EMERGENCY_UNDECLARED_MEASURE_GRACE: i64 = 30 * 86_400;

/// Hard ceiling on total active time across one proximity-derived chain: the whole
/// ordinary time-to-effect (14 d). Whichever of this and the renewal count binds
/// first ends the chain (ADR-0023 §4).
pub const EMERGENCY_CHAIN_MAX_SECS: i64 = 14 * 86_400;

/// The fixed cooldown after a chain ends before another chain may activate: 14 d, a
/// plain constant `>= ` any 14-day-capped chain and strictly `>`
/// [`EMERGENCY_MEASURE_GRACE`], giving a `<= 50%` duty cycle (ADR-0023 §4).
pub const EMERGENCY_COOLDOWN_SECS: i64 = 14 * 86_400;

/// Hard ceiling on consecutive renewals in a chain: 2 (three activations). A charter
/// may set a stricter cap, never a looser one (ADR-0023 §4).
pub const MAX_CONSECUTIVE_RENEWALS_CEILING: u32 = 2;

/// Discriminant in the `kind` field of an [`EmergencyDeclaration`]'s canonical CBOR.
pub(crate) const DECLARATION_KIND: &str = "rrn.gov.emergency_declaration";
/// Discriminant in the `kind` field of an [`EmergencyCosign`]'s canonical CBOR.
pub(crate) const COSIGN_KIND: &str = "rrn.gov.emergency_cosign";
/// Discriminant in the `kind` field of an [`EmergencyLapse`]'s canonical CBOR.
pub(crate) const LAPSE_KIND: &str = "rrn.gov.emergency_lapse";
/// Discriminant in the `kind` field of an [`EmergencyActivated`]'s canonical CBOR.
pub(crate) const ACTIVATED_KIND: &str = "rrn.gov.emergency_activated";
/// Discriminant in the `kind` field of an [`EmergencyRefused`]'s canonical CBOR.
pub(crate) const REFUSED_KIND: &str = "rrn.gov.emergency_refused";
/// Discriminant in the `kind` field of an [`EmergencyDeclarationAdmitted`]'s
/// canonical CBOR.
pub(crate) const DECLARATION_ADMITTED_KIND: &str = "rrn.gov.emergency_declaration_admitted";

/// A member's signed declaration that a community is in an emergency (ADR-0023 §2).
///
/// It takes force only once a co-sign supermajority of the electorate (the author's
/// own signature included) has been gathered — the collective act is the primary
/// anti-abuse defense. Its identity is the Blake3 [`hash`](Self::hash) of its
/// canonical bytes, which co-signatures, lapses, and the activation attestation all
/// target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyDeclaration {
    /// The community this declares an emergency in (must match the effective
    /// Charter's `community_id`).
    pub community_id: String,
    /// The electorate member raising the declaration. Their own signature counts
    /// toward the threshold — a declaration is a signed act, not a motion seeking
    /// endorsement (ADR-0023 §2).
    pub author: Address,
    /// The crisis, human-readable. Testimony and display only (§6, Non-goals).
    pub reason: String,
    /// The declared emergency *domain*. Testimony and display only — the machine
    /// does not verify a measure is germane to it (§6, Non-goals).
    pub scope: String,
    /// Requested lifetime in seconds; clamped to
    /// `[EMERGENCY_DURATION_FLOOR, EMERGENCY_DURATION_CEILING]` on activation (§4).
    pub duration_secs: i64,
    /// The author's *claim* of position in a renewal chain. **Advisory** — the
    /// effective count is derived from log proximity (§4), so a self-reset index
    /// buys nothing.
    pub stated_renewal_index: u32,
    /// The declaration this claims to renew, linking a chain. **Omitted when
    /// absent** for an initial declaration (ADR-0010 additive-field discipline).
    pub previous_declaration_hash: Option<Hash>,
    /// The author's clock — retained as bounded testimony only, never arithmetic
    /// (ADR-0022).
    pub created_at: i64,
}

impl EmergencyDeclaration {
    /// The content address of this declaration: the Blake3 hash of its canonical
    /// bytes. Co-signatures, lapses, and the activation attestation target it.
    pub fn hash(&self) -> Hash {
        Hash::of(&to_canonical_bytes(self.clone()))
    }
}

/// An [`EmergencyDeclaration`] signed by its author.
pub type SignedDeclaration = SignedPayload<EmergencyDeclaration>;

/// A member's co-signature toward a declaration's — or a lapse's — supermajority
/// (ADR-0023 §2, §4). One kind serves both: `declaration_hash` may target an
/// [`EmergencyDeclaration`] or an [`EmergencyLapse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmergencyCosign {
    /// The declaration or lapse being co-signed (its [`EmergencyDeclaration::hash`]
    /// or [`EmergencyLapse::hash`]).
    pub declaration_hash: Hash,
    /// Who is co-signing. Redundant with the envelope's signer and kept so the claim
    /// travels inside the signed content: replay checks both.
    pub signer: Address,
}

/// An [`EmergencyCosign`] signed by the co-signer.
pub type SignedCosign = SignedPayload<EmergencyCosign>;

/// A member's signed motion to end an active emergency early (ADR-0023 §4). Carries
/// the same co-sign supermajority as a declaration (reusing [`EmergencyCosign`]),
/// drawn from the same position-pinned electorate. Its [`hash`](Self::hash) is what
/// those co-signatures target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyLapse {
    /// The declaration whose active emergency this would end.
    pub declaration_hash: Hash,
    /// The electorate member raising the lapse (their signature counts toward the
    /// lapse threshold).
    pub author: Address,
}

impl EmergencyLapse {
    /// The content address of this lapse — what its co-signatures target.
    pub fn hash(&self) -> Hash {
        Hash::of(&to_canonical_bytes(self.clone()))
    }
}

/// An [`EmergencyLapse`] signed by its author.
pub type SignedLapse = SignedPayload<EmergencyLapse>;

/// The station's attestation that an emergency has taken force (ADR-0023 §2, §5).
///
/// Station-signed on append, written when the station admits the threshold-crossing
/// co-signature. Its authority is not the signature but the facts it restates —
/// enough eligible co-signatures gathered, the §4 caps satisfied — which
/// [`emergency_timeline`] re-derives. What it *carries* that a replica cannot
/// recompute from its own re-stamped admission clock is the **activation instant**
/// and **scheduled expiry**: admission-clock readings frozen into a signed,
/// replicated fact so every replica agrees on the boundary (ADR-0022 §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmergencyActivated {
    /// The declaration that took force.
    pub declaration_hash: Hash,
    /// The station's admission-clock reading at the crossing co-signature — the
    /// instant the emergency became active (ADR-0022).
    pub activation_instant: i64,
    /// `activation_instant + effective duration` — when the emergency auto-expires
    /// absent an earlier lapse (§4).
    pub scheduled_expiry: i64,
    /// The log-derived renewal count of this activation within its proximity chain
    /// (§4). `0` for a fresh chain.
    pub renewal_count: u32,
}

/// An [`EmergencyActivated`] signed by the attesting station.
pub type SignedActivated = SignedPayload<EmergencyActivated>;

/// The station's attestation that a declaration's **first threshold crossing was
/// refused** by a §4 cap, and so the declaration is dead (ADR-0027 D1b).
///
/// Station-signed on append, written in the same transaction as the crossing
/// record when [`chain_decision`] refuses the first position at which the
/// distinct-eligible count reaches the threshold (a renewal count cap or the
/// 14-day total-active duration cap binds). Its authority is the fact it
/// restates — that the crossing at `(refused_instant, refused_seq)` genuinely
/// reached the threshold *and* the caps refused it — which the timeline
/// re-derives. No `crossing_seq` field: like the activation attestation, it is
/// appended immediately after the crossing record, so the crossing is the
/// nearest preceding declaration/co-sign record and a stored seq would carry no
/// independently-checkable information (ADR-0027 D1b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmergencyRefused {
    /// The declaration whose first crossing was cap-refused.
    pub declaration_hash: Hash,
    /// The station's admission-clock reading at the refused crossing (ADR-0022).
    pub refused_instant: i64,
}

/// An [`EmergencyRefused`] signed by the attesting station.
pub type SignedRefused = SignedPayload<EmergencyRefused>;

/// The station's attestation of **when it admitted a declaration** (ADR-0027 D2).
///
/// Station-signed and written in the same transaction as the declaration itself
/// (the eager admission attestation). Both the writer and replay measure the
/// declaration's time-to-live against this signed `admitted_at` — never against
/// the per-replica re-stamped `created_at` (ADR-0022 §1) — so the TTL bound is
/// replica-identical and survives an outbox re-bootstrap (ADR-0020) where a
/// rebuilt writer's `created_at` would differ. It exists from admission, so a
/// declaration that expires **without ever activating** still has a
/// replica-auditable admission fact (which a field restated only on
/// `emergency_activated` would lack — ADR-0027 D2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmergencyDeclarationAdmitted {
    /// The declaration this anchors.
    pub declaration_hash: Hash,
    /// The station's admission-clock reading when it admitted the declaration.
    pub admitted_at: i64,
}

/// An [`EmergencyDeclarationAdmitted`] signed by the attesting station.
pub type SignedDeclarationAdmitted = SignedPayload<EmergencyDeclarationAdmitted>;

// --- Canonical CBOR ---------------------------------------------------------

fn hash_to_cbor(h: Hash) -> CBOR {
    CBOR::to_byte_string(h.to_bytes())
}

fn hash_from_cbor(cbor: CBOR) -> Result<Hash, dcbor::Error> {
    let bytes: [u8; 32] = cbor
        .try_into_byte_string()?
        .as_slice()
        .try_into()
        .map_err(|_| dcbor::Error::WrongType)?;
    Ok(Hash::from_bytes(bytes))
}

impl From<EmergencyDeclaration> for CBOR {
    fn from(d: EmergencyDeclaration) -> Self {
        let mut m = Map::new();
        m.insert("kind", DECLARATION_KIND);
        m.insert("community_id", d.community_id);
        m.insert("author", d.author);
        m.insert("reason", d.reason);
        m.insert("scope", d.scope);
        m.insert("duration_secs", d.duration_secs);
        m.insert("stated_renewal_index", d.stated_renewal_index as u64);
        // Lineage link omitted at genesis rather than encoded as null (ADR-0010).
        if let Some(prev) = d.previous_declaration_hash {
            m.insert("previous_declaration_hash", hash_to_cbor(prev));
        }
        m.insert("created_at", d.created_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EmergencyDeclaration {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != DECLARATION_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let previous_declaration_hash = match map.get::<&str, CBOR>("previous_declaration_hash") {
            Some(cbor) => Some(hash_from_cbor(cbor)?),
            None => None,
        };
        Ok(EmergencyDeclaration {
            community_id: map.extract::<&str, String>("community_id")?,
            author: map.extract::<&str, Address>("author")?,
            reason: map.extract::<&str, String>("reason")?,
            scope: map.extract::<&str, String>("scope")?,
            duration_secs: map.extract::<&str, i64>("duration_secs")?,
            stated_renewal_index: u32::try_from(map.extract::<&str, u64>("stated_renewal_index")?)
                .map_err(|_| dcbor::Error::WrongType)?,
            previous_declaration_hash,
            created_at: map.extract::<&str, i64>("created_at")?,
        })
    }
}

impl From<EmergencyCosign> for CBOR {
    fn from(c: EmergencyCosign) -> Self {
        let mut m = Map::new();
        m.insert("kind", COSIGN_KIND);
        m.insert("declaration_hash", hash_to_cbor(c.declaration_hash));
        m.insert("signer", c.signer);
        m.into()
    }
}

impl TryFrom<CBOR> for EmergencyCosign {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != COSIGN_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EmergencyCosign {
            declaration_hash: hash_from_cbor(map.extract::<&str, CBOR>("declaration_hash")?)?,
            signer: map.extract::<&str, Address>("signer")?,
        })
    }
}

impl From<EmergencyLapse> for CBOR {
    fn from(l: EmergencyLapse) -> Self {
        let mut m = Map::new();
        m.insert("kind", LAPSE_KIND);
        m.insert("declaration_hash", hash_to_cbor(l.declaration_hash));
        m.insert("author", l.author);
        m.into()
    }
}

impl TryFrom<CBOR> for EmergencyLapse {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != LAPSE_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EmergencyLapse {
            declaration_hash: hash_from_cbor(map.extract::<&str, CBOR>("declaration_hash")?)?,
            author: map.extract::<&str, Address>("author")?,
        })
    }
}

impl From<EmergencyActivated> for CBOR {
    fn from(a: EmergencyActivated) -> Self {
        let mut m = Map::new();
        m.insert("kind", ACTIVATED_KIND);
        m.insert("declaration_hash", hash_to_cbor(a.declaration_hash));
        m.insert("activation_instant", a.activation_instant);
        m.insert("scheduled_expiry", a.scheduled_expiry);
        m.insert("renewal_count", a.renewal_count as u64);
        m.into()
    }
}

impl TryFrom<CBOR> for EmergencyActivated {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != ACTIVATED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EmergencyActivated {
            declaration_hash: hash_from_cbor(map.extract::<&str, CBOR>("declaration_hash")?)?,
            activation_instant: map.extract::<&str, i64>("activation_instant")?,
            scheduled_expiry: map.extract::<&str, i64>("scheduled_expiry")?,
            renewal_count: u32::try_from(map.extract::<&str, u64>("renewal_count")?)
                .map_err(|_| dcbor::Error::WrongType)?,
        })
    }
}

impl From<EmergencyRefused> for CBOR {
    fn from(r: EmergencyRefused) -> Self {
        let mut m = Map::new();
        m.insert("kind", REFUSED_KIND);
        m.insert("declaration_hash", hash_to_cbor(r.declaration_hash));
        m.insert("refused_instant", r.refused_instant);
        m.into()
    }
}

impl TryFrom<CBOR> for EmergencyRefused {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != REFUSED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EmergencyRefused {
            declaration_hash: hash_from_cbor(map.extract::<&str, CBOR>("declaration_hash")?)?,
            refused_instant: map.extract::<&str, i64>("refused_instant")?,
        })
    }
}

impl From<EmergencyDeclarationAdmitted> for CBOR {
    fn from(a: EmergencyDeclarationAdmitted) -> Self {
        let mut m = Map::new();
        m.insert("kind", DECLARATION_ADMITTED_KIND);
        m.insert("declaration_hash", hash_to_cbor(a.declaration_hash));
        m.insert("admitted_at", a.admitted_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EmergencyDeclarationAdmitted {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != DECLARATION_ADMITTED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EmergencyDeclarationAdmitted {
            declaration_hash: hash_from_cbor(map.extract::<&str, CBOR>("declaration_hash")?)?,
            admitted_at: map.extract::<&str, i64>("admitted_at")?,
        })
    }
}

/// A reason an emergency record could not be admitted, or a derived read failed.
#[derive(thiserror::Error, Debug)]
pub enum EmergencyError {
    /// The envelope's signer is not the record's named author/signer.
    #[error("emergency record signed by {signer}, but names {named}")]
    SignerMismatch {
        /// Who signed the envelope.
        signer: Address,
        /// Who the record's content names.
        named: Address,
    },
    /// The declaration's `community_id` does not match the effective Charter.
    #[error("declaration community {declared} does not match this community {expected}")]
    WrongCommunity {
        /// The community the declaration names.
        declared: String,
        /// The community the effective Charter names.
        expected: String,
    },
    /// The author/co-signer is not in the electorate at the judged position.
    #[error("{who} is not in the emergency electorate")]
    NotEligible {
        /// The address that was refused.
        who: Address,
    },
    /// The targeted declaration or lapse is not on this log.
    #[error("no emergency declaration/lapse {0} on this log")]
    UnknownTarget(Hash),
    /// This record is already on the log.
    #[error("emergency record is already on the log")]
    AlreadyPresent,
    /// A co-signer has already co-signed this target.
    #[error("{signer} has already co-signed {target}")]
    AlreadyCosigned {
        /// The repeat co-signer.
        signer: Address,
        /// The declaration or lapse hash.
        target: Hash,
    },
    /// A lapse targets a declaration with no active emergency to end.
    #[error("declaration {0} has no active emergency to lapse")]
    NotActive(Hash),
    /// A co-signature targets a declaration whose first threshold crossing was
    /// refused by a §4 cap, so the declaration is dead and never revives
    /// (ADR-0027 D1/D3). The remedy is a fresh declaration once the §4 cooldown
    /// has passed (count cap), or one with a shorter `duration_secs` while the
    /// chain still has headroom (duration cap).
    #[error(
        "declaration {declaration} is dead (its first crossing was cap-refused); \
         wait out the §4 cooldown and raise a fresh declaration, or — if the \
         duration cap bound — a fresh one with a shorter duration_secs"
    )]
    DeclarationDead {
        /// The dead declaration.
        declaration: Hash,
    },
    /// A co-signature targets a declaration whose first threshold crossing was
    /// not reached within [`EMERGENCY_DECLARATION_TTL`] of its admission, so it
    /// no longer counts toward activation (ADR-0027 D2/D3). Raise a fresh
    /// declaration.
    #[error(
        "declaration {declaration} has expired (no crossing within the {ttl}s \
         declaration TTL of its admission); raise a fresh declaration"
    )]
    DeclarationExpired {
        /// The expired declaration.
        declaration: Hash,
        /// The TTL that elapsed ([`EMERGENCY_DECLARATION_TTL`]).
        ttl: i64,
    },
    /// A co-signature targets a declaration that has already taken force; its
    /// supermajority is complete and further co-signatures are dead weight
    /// (ADR-0027 D3).
    #[error(
        "declaration {declaration} has already activated; no further co-signatures are needed"
    )]
    AlreadyActivated {
        /// The already-active declaration.
        declaration: Hash,
    },
    /// A reputation-scoring error while evaluating the electorate.
    #[error("reputation: {0}")]
    Reputation(#[from] rrn_reputation::Error),
    /// A proposal-layer error (founder resolution, eligibility).
    #[error("proposal: {0}")]
    Proposal(#[from] ProposalError),
    /// A charter-resolution error.
    #[error("charter: {0}")]
    Charter(#[from] CharterError),
    /// An error resolving the effective Charter's emergency parameters.
    #[error("tally: {0}")]
    Tally(#[from] TallyError),
    /// A storage/log error.
    #[error("storage: {0}")]
    Storage(#[from] rrn_storage::Error),
}

/// Distinct electorate co-signatures (author included) a declaration or lapse needs
/// to take force: `ceil(N × bar)` in integer arithmetic, the same
/// `saturating_mul(..).div_ceil(..)` shape as
/// [`founder_threshold`](crate::charter::founder_threshold) (ADR-0023 §2).
///
/// The Charter's `emergency_declaration_pct` is a `u8` percent, but the ADR's bar
/// is an exact **two-thirds** — a percent cannot spell 2/3, and the ADR's own
/// worked cases fix the meaning: a 3-member grace electorate needs 2 ("author plus
/// one"), a 20-member one needs 14, which is `ceil(2N/3)`, not `ceil(N × 67/100)`
/// (that would demand *unanimity* at N=3 and, generally, two-thirds+1 wherever N is
/// a multiple of 3). So the floor value 67 is implemented as exactly `ceil(2N/3)`;
/// a charter that *raises* the bar above the floor gets the literal share
/// `ceil(N × pct / 100)`, which is never below two-thirds and is monotone in both N
/// and `pct`. (ADR-0023 §2's `ceil(3 × 0.67) = 2` example reads two-thirds; the PR
/// carries a dated clarification for maintainer ratification.)
pub fn declaration_threshold(n: usize, pct: u8) -> usize {
    if pct <= EMERGENCY_DECLARATION_PCT_FLOOR {
        n.saturating_mul(2).div_ceil(3)
    } else {
        n.saturating_mul(usize::from(pct)).div_ceil(100)
    }
    // A declaration always needs at least its author's own signature; N >= 1
    // whenever the author is eligible, so the threshold is >= 1 in every reachable
    // case and no `.max(1)` is needed (an unreachable N=0 yields 0, like genesis).
}

/// An emergency that took force, as re-derived from the log — one entry per
/// legitimate [`EmergencyActivated`] attestation (ADR-0023 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveEmergency {
    /// The declaration that took force.
    pub declaration_hash: Hash,
    /// The crisis, for display (testimony).
    pub reason: String,
    /// The declared domain, for display (testimony).
    pub scope: String,
    /// The station-attested activation instant (ADR-0022).
    pub activation_instant: i64,
    /// The station-attested scheduled expiry (`activation_instant + duration`).
    pub scheduled_expiry: i64,
    /// The log-derived renewal count within the proximity chain (§4).
    pub renewal_count: u32,
    /// The log seq of the activation attestation — the single **pin position** for
    /// this emergency's electorate (denominator + eligibility), position-bounded so
    /// nothing admitted later can pack it (§3c).
    pub activation_seq: u64,
    /// If the emergency was ended early by a lapse, the log seq of the lapse's
    /// threshold-crossing co-signature. Compression, freeze, and pin hold for
    /// records whose position is **before** this; expiry is unconditional regardless
    /// (§4). `None` if it ran to its scheduled expiry.
    pub lapsed_at_seq: Option<u64>,
}

impl ActiveEmergency {
    /// Whether a record admitted at log position `seq` and station-admission
    /// instant `admitted_at` falls under this emergency's active span: after
    /// activation, at/before the scheduled expiry, and before any early lapse
    /// (ADR-0023 §5). The lapse bound is a log **position** (replica-identical),
    /// never a per-replica admission clock.
    pub fn governs(&self, admitted_at: i64, seq: u64) -> bool {
        seq > self.activation_seq
            && self.activation_instant < admitted_at
            && admitted_at <= self.scheduled_expiry
            && self.lapsed_at_seq.is_none_or(|lapse| seq < lapse)
    }

    /// Whether this emergency is in force *as a community-wide state* as of station
    /// instant `now`: activated at or before `now`, not past its scheduled expiry,
    /// and not ended by a lapse. Unlike [`governs`](Self::governs) — which positions
    /// a *record* strictly after activation — this is **inclusive** at the activation
    /// instant, because the emergency is active from the moment it takes force. It is
    /// a display/state predicate (status banners, action results), never used for
    /// replay positioning, so the boundary difference cannot affect which window
    /// governed a past vote.
    pub fn is_active_at(&self, now: i64) -> bool {
        self.lapsed_at_seq.is_none()
            && self.activation_instant <= now
            && now <= self.scheduled_expiry
    }
}

// --- Log reads --------------------------------------------------------------

/// The declaration with content hash `decl_hash`, self-signed by its author, and
/// the log seq it was admitted at. Skips a record whose envelope signer is not its
/// named author (a gossiped forgery).
fn find_declaration(
    log: &AppendLog,
    decl_hash: &Hash,
) -> Result<Option<(EmergencyDeclaration, u64)>, EmergencyError> {
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(decl) = from_canonical_bytes::<EmergencyDeclaration>(&entry.payload.bytes) else {
            continue;
        };
        if decl.hash() != *decl_hash {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != decl.author {
            continue;
        }
        return Ok(Some((decl, entry.seq)));
    }
    Ok(None)
}

/// The lapse with content hash `lapse_hash`, self-signed by its author, and its log
/// seq.
fn find_lapse(
    log: &AppendLog,
    lapse_hash: &Hash,
) -> Result<Option<(EmergencyLapse, u64)>, EmergencyError> {
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(lapse) = from_canonical_bytes::<EmergencyLapse>(&entry.payload.bytes) else {
            continue;
        };
        if lapse.hash() != *lapse_hash {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != lapse.author {
            continue;
        }
        return Ok(Some((lapse, entry.seq)));
    }
    Ok(None)
}

/// The `admitted_at` on the earliest (log-order) [`EmergencyDeclarationAdmitted`]
/// anchor for `decl_hash`, or `None` if the declaration carries no anchor
/// (a pre-ADR-0027 declaration, or one whose atomic declaration+anchor write
/// never landed). The earliest validated anchor wins, mirroring
/// [`crate::window::window_and_seq_of`]'s "first attestation" rule.
///
/// The anchor is a station attestation; its envelope signer is pinned to the
/// community `station` key (T2.1.4), so a forged anchor carrying a doctored
/// `admitted_at` is skipped and the genuine station anchor is the earliest
/// validated one.
fn declaration_admitted_at(
    log: &AppendLog,
    decl_hash: &Hash,
    station: &PublicKey,
) -> Result<Option<i64>, EmergencyError> {
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(anchor) = from_canonical_bytes::<EmergencyDeclarationAdmitted>(&entry.payload.bytes)
        else {
            continue;
        };
        if entry.payload.signer != *station {
            continue;
        }
        if anchor.declaration_hash == *decl_hash {
            return Ok(Some(anchor.admitted_at));
        }
    }
    Ok(None)
}

/// The distinct eligible signatures toward `target_hash` (a declaration or lapse)
/// among records at seq `<= upto_seq`, in log order, each with the seq it first
/// appeared. The `author` (whose record sits at `author_seq`) counts as the first
/// signature. Every signer's eligibility is judged at the single fixed pin
/// `(pin_time, pin_seq)` — the emergency's activation position — so a signer
/// manufactured after the pin never counts (§2, §3c).
#[allow(clippy::too_many_arguments)]
fn eligible_signatures(
    log: &AppendLog,
    db: &Database,
    founders: &[Address],
    target_hash: &Hash,
    author: &Address,
    author_seq: u64,
    pin_time: i64,
    pin_seq: u64,
    upto_seq: u64,
) -> Result<Vec<(u64, Address)>, EmergencyError> {
    let mut seen = std::collections::HashSet::new();
    let mut sigs: Vec<(u64, Address)> = Vec::new();

    if author_seq <= upto_seq
        && is_eligible_asof(db, founders, author, pin_time, pin_seq)?
        && seen.insert(*author)
    {
        sigs.push((author_seq, *author));
    }

    for entry in log.iter_from(1) {
        let entry = entry?;
        if entry.seq > upto_seq {
            break;
        }
        let Ok(cosign) = from_canonical_bytes::<EmergencyCosign>(&entry.payload.bytes) else {
            continue;
        };
        if cosign.declaration_hash != *target_hash {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != cosign.signer {
            continue;
        }
        if !is_eligible_asof(db, founders, &cosign.signer, pin_time, pin_seq)? {
            continue;
        }
        if seen.insert(cosign.signer) {
            sigs.push((entry.seq, cosign.signer));
        }
    }
    sigs.sort_by_key(|(seq, _)| *seq);
    Ok(sigs)
}

/// The log seq of the `threshold`-th distinct signature — when the count crosses —
/// or `None` if the threshold is not met among `sigs`.
fn crossing_seq(sigs: &[(u64, Address)], threshold: usize) -> Option<u64> {
    if threshold == 0 {
        return sigs.first().map(|(seq, _)| *seq);
    }
    sigs.get(threshold - 1).map(|(seq, _)| *seq)
}

// --- Chain caps and cooldown (ADR-0023 §4) ----------------------------------

struct ChainState {
    end_instant: i64,
    consecutive: u32,
    total_active: i64,
}

/// Folds the legitimate activations (each `(activation_instant, scheduled_expiry)`,
/// in log order) into the state of the chain the last one belongs to. Refused
/// activations are never in this list, so the last chain is always live.
fn fold_chain(activations: &[(i64, i64)]) -> Option<ChainState> {
    let mut chain: Option<ChainState> = None;
    for &(instant, expiry) in activations {
        let active = expiry - instant;
        match &mut chain {
            Some(cur) if instant < cur.end_instant + EMERGENCY_COOLDOWN_SECS => {
                cur.consecutive += 1;
                cur.total_active += active;
                // Monotone: a renewal that overlaps the prior activation (rare, but
                // permitted — a continuation may activate before the previous span
                // ends) must never move the chain end *backwards*, which would shorten
                // the cooldown and break the <= 50% duty cycle.
                cur.end_instant = cur.end_instant.max(expiry);
            }
            _ => {
                chain = Some(ChainState {
                    end_instant: expiry,
                    consecutive: 0,
                    total_active: active,
                });
            }
        }
    }
    chain
}

/// The renewal count a new activation would take, or `None` if the §4 caps or the
/// cooldown refuse it (it "simply does not activate"). `existing` is the legitimate
/// activations already on the log, in order.
fn chain_decision(
    existing: &[(i64, i64)],
    cand_instant: i64,
    cand_expiry: i64,
    max_renewals: u32,
) -> Option<u32> {
    let cand_active = cand_expiry - cand_instant;
    match fold_chain(existing) {
        None => Some(0),
        Some(cur) if cand_instant < cur.end_instant + EMERGENCY_COOLDOWN_SECS => {
            let new_consecutive = cur.consecutive + 1;
            let new_total = cur.total_active + cand_active;
            if new_consecutive > max_renewals || new_total > EMERGENCY_CHAIN_MAX_SECS {
                None
            } else {
                Some(new_consecutive)
            }
        }
        // Beyond the cooldown of the previous chain's end — a fresh chain.
        Some(_) => Some(0),
    }
}

/// Clamps a declaration's requested lifetime to
/// `[EMERGENCY_DURATION_FLOOR, EMERGENCY_DURATION_CEILING]` (§4).
fn clamp_duration(requested: i64) -> i64 {
    requested.clamp(EMERGENCY_DURATION_FLOOR, EMERGENCY_DURATION_CEILING)
}

// --- Timeline derivation ----------------------------------------------------

/// Every emergency that legitimately took force, in log order, re-derived from the
/// signed records (ADR-0023 §5). An [`EmergencyActivated`] attestation is believed
/// only when its declaration genuinely gathered the co-sign supermajority by the
/// attestation's position **and** the §4 caps/cooldown admitted it — so a gossiped
/// or forged attestation that should never have been written is ignored.
///
/// The activation instant and scheduled expiry are read from the (signed)
/// attestation, not recomputed from this replica's re-stamped admission clock; every
/// other input is a log position. So every replica computes the identical timeline
/// (replica determinism).
pub fn emergency_timeline(
    db: &Database,
    station: &PublicKey,
) -> Result<Vec<ActiveEmergency>, EmergencyError> {
    Ok(derive_emergencies(db, station)?.timeline)
}

/// The full replay of the emergency records: the legitimate activations, the
/// declarations whose first crossing was **cap-refused** (dead, ADR-0027 D1b),
/// and every declaration's signed **admission anchor** (ADR-0027 D2). All three
/// are a pure, replica-deterministic function of the signed log at fixed pins.
struct EmergencyDerivation {
    /// Legitimate activations, in log order (the public [`emergency_timeline`]).
    timeline: Vec<ActiveEmergency>,
    /// Declarations killed by a validated [`EmergencyRefused`] at their first
    /// crossing — they never activate and never revive.
    dead: std::collections::HashSet<Hash>,
    /// Each declaration's station-signed admission instant, from the earliest
    /// (log-order) [`EmergencyDeclarationAdmitted`] anchor.
    anchors: std::collections::HashMap<Hash, i64>,
}

/// One replay pass over the log, threading the §4 chain state so activations,
/// refusals, anchors, and TTL are all judged at a single attested pin each
/// (ADR-0023 §5, ADR-0027). A gossiped or forged marker that should never have
/// been written is ignored; the earliest **validated** marker (activation or
/// refusal) for a declaration wins and later ones for it are ignored.
fn derive_emergencies(
    db: &Database,
    station: &PublicKey,
) -> Result<EmergencyDerivation, EmergencyError> {
    let log = AppendLog::new(db);
    let founders = founder_set(db)?;

    // The community id, the declaration bar, and the renewal cap are resolved from
    // the **genesis (founder) charter**, never the amendable effective charter. The
    // founder charter and the founding set are immutable genesis facts (charter.rs:
    // founders are "retained unchanged on amendment"), so which past activations were
    // legitimate is a pure function of genesis + signed records that no later
    // amendment can rewrite — the replica-determinism invariant 1 demands this, and
    // deriving the bar from a signed-but-forgeable attestation field would instead let
    // a forged attestation set its own bar. (Divergence noted in the PR: this makes
    // the emergency-*legitimacy* parameters non-amendable in Phase 2; a general
    // position-bounded charter resolution — which the ordinary tally thresholds also
    // want — is recommended follow-up.) Reading founder_charter, not effective_charter,
    // also keeps the timeline off the tally/charter-resolution path entirely.
    let genesis = founder_charter(db)?;
    let community = genesis.as_ref().map(|c| c.charter().community_id.clone());
    let declaration_pct = genesis
        .as_ref()
        .map(|c| {
            c.charter()
                .governance_structure
                .effective_emergency_declaration_pct()
        })
        .unwrap_or(EMERGENCY_DECLARATION_PCT_FLOOR);
    let max_renewals = genesis
        .as_ref()
        .map(|c| {
            c.charter()
                .governance_structure
                .effective_max_consecutive_renewals()
        })
        .unwrap_or(MAX_CONSECUTIVE_RENEWALS_CEILING);

    let mut timeline: Vec<ActiveEmergency> = Vec::new();
    let mut chain_pairs: Vec<(i64, i64)> = Vec::new();
    let mut seen_decls = std::collections::HashSet::new();
    let mut dead: std::collections::HashSet<Hash> = std::collections::HashSet::new();
    let mut anchors: std::collections::HashMap<Hash, i64> = std::collections::HashMap::new();

    // Re-derives the distinct-eligible crossing for `decl` at the pin
    // `(pin_time, pin_seq)`: whether the threshold was reached by `pin_seq`.
    // Shared by the activation and refusal validators so both judge the crossing
    // identically.
    let crossing_reached = |decl: &EmergencyDeclaration,
                            decl_hash: &Hash,
                            decl_seq: u64,
                            pin_time: i64,
                            pin_seq: u64|
     -> Result<bool, EmergencyError> {
        let n = grace_electorate_asof(db, &founders, pin_time, pin_seq)?.len();
        let threshold = declaration_threshold(n, declaration_pct);
        let sigs = eligible_signatures(
            &log,
            db,
            &founders,
            decl_hash,
            &decl.author,
            decl_seq,
            pin_time,
            pin_seq,
            pin_seq,
        )?;
        Ok(crossing_seq(&sigs, threshold).is_some())
    };

    for entry in log.iter_from(1) {
        let entry = entry?;
        let bytes = &entry.payload.bytes;

        // T2.1.4: every marker this loop consumes — the admission anchor, the D1b
        // refusal, and the activation — is a station attestation, trusted precisely
        // because the station signed it (ADR-0022 §2). An entry whose envelope signer
        // is not the community station key is skipped here, exactly as a forged member
        // record is skipped in `find_declaration`, so a forged anchor/refusal/
        // activation is invisible to derivation and can move no window, TTL, or
        // activation decision. (Member records are not station-signed and never decode
        // as these kinds anyway, so the early skip changes nothing for them.)
        if entry.payload.signer != *station {
            continue;
        }

        // The declaration's admission anchor (ADR-0027 D2): record the earliest
        // one per declaration; it precedes any crossing in log order, so it is
        // in hand by the time an activation for the declaration is reached.
        if let Ok(anchor) = from_canonical_bytes::<EmergencyDeclarationAdmitted>(bytes) {
            anchors
                .entry(anchor.declaration_hash)
                .or_insert(anchor.admitted_at);
            continue;
        }

        // A cap-refusal marker (ADR-0027 D1b): the declaration's first crossing
        // reached the threshold at this pin *and* the §4 caps refused it. Kills
        // the declaration unless it is already decided (an earlier validated
        // activation or refusal for it stands).
        if let Ok(refused) = from_canonical_bytes::<EmergencyRefused>(bytes) {
            let dh = refused.declaration_hash;
            if seen_decls.contains(&dh) || dead.contains(&dh) {
                continue;
            }
            let Some((decl, decl_seq)) = find_declaration(&log, &dh)? else {
                continue;
            };
            if let Some(community) = &community {
                if decl.community_id != *community {
                    continue;
                }
            }
            let pin_time = refused.refused_instant;
            let refused_seq = entry.seq;
            if !crossing_reached(&decl, &dh, decl_seq, pin_time, refused_seq)? {
                continue; // never actually reached the supermajority — not a real refusal
            }
            let scheduled = pin_time.saturating_add(clamp_duration(decl.duration_secs));
            if chain_decision(&chain_pairs, pin_time, scheduled, max_renewals).is_some() {
                // The caps would have *admitted* this crossing — a genuine refusal
                // marker is written only when they bind. Ignore a spurious one.
                continue;
            }
            dead.insert(dh);
            continue;
        }

        let Ok(act) = from_canonical_bytes::<EmergencyActivated>(bytes) else {
            continue;
        };
        let activation_seq = entry.seq;

        // The declaration must exist, be self-signed, and name this community.
        let Some((decl, decl_seq)) = find_declaration(&log, &act.declaration_hash)? else {
            continue;
        };
        if let Some(community) = &community {
            if decl.community_id != *community {
                continue;
            }
        }
        // A declaration already decided — activated earlier (dedup) or killed by a
        // validated refusal (ADR-0027 D1b) — ignores this attestation. The check is
        // *after* the declaration/community checks, so a gossiped bogus attestation
        // that fails the checks below never blocks the station's real one.
        if seen_decls.contains(&act.declaration_hash) || dead.contains(&act.declaration_hash) {
            continue;
        }

        // Fail closed on the anchor + TTL (ADR-0027 D2): an activation with **no**
        // validated admission anchor never activates (a pre-0027 or crash-orphaned
        // declaration), and one whose first crossing is beyond the declaration TTL
        // of its signed admission is expired. Both read signed instants at one pin.
        let Some(&admitted_at) = anchors.get(&act.declaration_hash) else {
            continue; // markerless/anchorless declaration — never activatable
        };
        if act.activation_instant.saturating_sub(admitted_at) > EMERGENCY_DECLARATION_TTL {
            continue; // expired: crossing not reached within the TTL
        }

        // Re-derive the crossing: distinct eligible signatures, pinned at the
        // attestation's own position, must reach the threshold by that position.
        let pin_time = act.activation_instant;
        if !crossing_reached(
            &decl,
            &act.declaration_hash,
            decl_seq,
            pin_time,
            activation_seq,
        )? {
            continue; // never actually reached the supermajority
        }

        // The §4 caps/cooldown must have admitted it, and its scheduled expiry must
        // match `activation_instant + clamp(duration)` (a forged over-long expiry
        // is rejected by recomputing it).
        let scheduled = act
            .activation_instant
            .saturating_add(clamp_duration(decl.duration_secs));
        if act.scheduled_expiry != scheduled {
            continue;
        }
        let Some(renewal_count) = chain_decision(
            &chain_pairs,
            act.activation_instant,
            scheduled,
            max_renewals,
        ) else {
            continue; // caps/cooldown refused this activation
        };

        // Legitimate. Find any lapse that reached its own threshold, pinned at the
        // same activation position (the lapse answers to the same electorate and bar).
        let n = grace_electorate_asof(db, &founders, pin_time, activation_seq)?.len();
        let threshold = declaration_threshold(n, declaration_pct);
        let lapsed_at_seq = lapse_boundary(
            &log,
            db,
            &founders,
            &act.declaration_hash,
            pin_time,
            activation_seq,
            threshold,
        )?;

        seen_decls.insert(act.declaration_hash);
        chain_pairs.push((act.activation_instant, scheduled));
        timeline.push(ActiveEmergency {
            declaration_hash: act.declaration_hash,
            reason: decl.reason.clone(),
            scope: decl.scope.clone(),
            activation_instant: act.activation_instant,
            scheduled_expiry: scheduled,
            renewal_count,
            activation_seq,
            lapsed_at_seq,
        });
    }
    Ok(EmergencyDerivation {
        timeline,
        dead,
        anchors,
    })
}

/// The log seq at which a lift for `decl_hash` crossed the supermajority (drawn from
/// the emergency's own pinned electorate, §4), or `None` if no lift reached it.
/// `threshold` is the emergency's own crossing threshold — the lift answers to
/// exactly the same electorate and bar as the declaration.
///
/// Per the 2026-09-10 ADR-0023 clarification (option A), a lift's signatures are
/// pooled **per emergency, not per lapse record**: every distinct eligible signer
/// across *all* `emergency_lapse` records targeting this declaration (each lapse's
/// author) and *all* `emergency_cosign` records targeting any of those lapses counts
/// once, at the log position it first appears, and the lift crosses at the position
/// of the `threshold`-th such distinct signer. So two members each raising their own
/// lapse motion can no longer split the supermajority across two hashes. Aggregation
/// is over signed records at fixed log positions and eligibility is judged at the
/// emergency's pin, so it stays replica-deterministic (invariant 1); with a single
/// lapse record it reduces to the earlier per-lapse crossing.
#[allow(clippy::too_many_arguments)]
fn lapse_boundary(
    log: &AppendLog,
    db: &Database,
    founders: &[Address],
    decl_hash: &Hash,
    pin_time: i64,
    pin_seq: u64,
    threshold: usize,
) -> Result<Option<u64>, EmergencyError> {
    // Pass 1: every self-signed lapse record for this declaration — collect its hash
    // (a valid co-sign target) and count its author as a candidate signature.
    let mut lapse_targets = std::collections::HashSet::new();
    let mut candidates: Vec<(u64, Address)> = Vec::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(lapse) = from_canonical_bytes::<EmergencyLapse>(&entry.payload.bytes) else {
            continue;
        };
        if lapse.declaration_hash != *decl_hash {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != lapse.author {
            continue;
        }
        lapse_targets.insert(lapse.hash());
        candidates.push((entry.seq, lapse.author));
    }
    if lapse_targets.is_empty() {
        return Ok(None);
    }

    // Pass 2: every self-signed co-signature targeting any of those lapse records.
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(cosign) = from_canonical_bytes::<EmergencyCosign>(&entry.payload.bytes) else {
            continue;
        };
        if !lapse_targets.contains(&cosign.declaration_hash) {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != cosign.signer {
            continue;
        }
        candidates.push((entry.seq, cosign.signer));
    }

    // Order by log position, then keep each distinct *eligible* signer at the first
    // position it appears (a signer who both authored a lapse and co-signed another
    // is counted once, at whichever came first). The crossing is the threshold-th.
    candidates.sort_by_key(|(seq, _)| *seq);
    let mut seen = std::collections::HashSet::new();
    let mut sigs: Vec<(u64, Address)> = Vec::new();
    for (seq, addr) in candidates {
        if !is_eligible_asof(db, founders, &addr, pin_time, pin_seq)? {
            continue;
        }
        if seen.insert(addr) {
            sigs.push((seq, addr));
        }
    }
    Ok(crossing_seq(&sigs, threshold))
}

// --- Public predicates ------------------------------------------------------

/// The emergency, if any, that governs a record admitted at station instant
/// `admitted_at` and log position `seq` (ADR-0023 §5). `None` when no declaration's
/// active span covers it — the record then runs the ordinary regime. Returns the
/// first (earliest-activated) covering emergency; overlapping chains are rare but
/// possible, and the earliest governs.
pub fn active_emergency_at(
    db: &Database,
    admitted_at: i64,
    seq: u64,
    station: &PublicKey,
) -> Result<Option<ActiveEmergency>, EmergencyError> {
    Ok(emergency_timeline(db, station)?
        .into_iter()
        .find(|e| e.governs(admitted_at, seq)))
}

/// Whether *any* emergency is active (declared, unlapsed, and within its scheduled
/// span) as of station instant `now` — the community-wide predicate the charter
/// freeze keys off (ADR-0023 §3b). Independent of any one proposal's position.
pub fn is_emergency_active_now(
    db: &Database,
    now: i64,
    station: &PublicKey,
) -> Result<bool, EmergencyError> {
    Ok(active_emergency_at(db, now, u64::MAX, station)?.is_some())
}

/// A declaration's activation status, as re-derived from the log (ADR-0027).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclarationStatus {
    /// The declaration has taken force (an activation stands for it).
    Activated,
    /// The declaration's first crossing was cap-refused; it is dead and never
    /// revives (D1b).
    Dead,
    /// The declaration's first crossing was not reached within
    /// [`EMERGENCY_DECLARATION_TTL`] of its signed admission, judged as of the
    /// probe instant; it no longer counts toward activation (D2).
    Expired,
    /// The declaration is still gathering co-signatures — not yet crossed,
    /// activated, dead, or expired.
    Pending,
}

/// The [`DeclarationStatus`] of `decl_hash` as of station instant `probe_instant`
/// (ADR-0027 D3). `probe_instant` fixes the TTL comparison for the `Expired`
/// arm; the other arms are `probe_instant`-independent. The single front-door
/// test for whether a further co-signature toward the declaration is dead weight.
pub fn declaration_status(
    db: &Database,
    decl_hash: &Hash,
    probe_instant: i64,
    station: &PublicKey,
) -> Result<DeclarationStatus, EmergencyError> {
    let d = derive_emergencies(db, station)?;
    if d.timeline.iter().any(|e| e.declaration_hash == *decl_hash) {
        return Ok(DeclarationStatus::Activated);
    }
    if d.dead.contains(decl_hash) {
        return Ok(DeclarationStatus::Dead);
    }
    if let Some(&admitted_at) = d.anchors.get(decl_hash) {
        if probe_instant.saturating_sub(admitted_at) > EMERGENCY_DECLARATION_TTL {
            return Ok(DeclarationStatus::Expired);
        }
    }
    Ok(DeclarationStatus::Pending)
}

/// The emergency governing an [`Emergency`](crate::proposal::ProposalKind::Emergency)
/// proposal, keyed by the proposal's station-attested admission `(admitted_at,
/// window_seq)`. This is the single test for the compressed path: the window
/// compresses, the electorate pins, and the measure quorum rises iff this is
/// `Some` (ADR-0023 §1, §3).
pub fn emergency_for_proposal(
    db: &Database,
    admitted_at: i64,
    window_seq: u64,
    station: &PublicKey,
) -> Result<Option<ActiveEmergency>, EmergencyError> {
    active_emergency_at(db, admitted_at, window_seq, station)
}

/// The `(pin_time, pin_seq)` a proposal's **ballot eligibility and quorum
/// denominator** are pinned at (ADR-0023 §3c). For an `Emergency` proposal admitted
/// under an active declaration this is the emergency's activation position — so a
/// member whose standing is manufactured after the emergency began neither counts
/// in the denominator nor casts a valid ballot. For every other proposal it is the
/// proposal's own open position `(open_time, open_seq)`, unchanged (ADR-0022).
pub fn electorate_pin(
    db: &Database,
    is_emergency: bool,
    open_time: i64,
    open_seq: u64,
    station: &PublicKey,
) -> Result<(i64, u64), EmergencyError> {
    if is_emergency {
        if let Some(e) = emergency_for_proposal(db, open_time, open_seq, station)? {
            return Ok((e.activation_instant, e.activation_seq));
        }
    }
    Ok((open_time, open_seq))
}

// --- Derived accountability report (ADR-0023 §6) ----------------------------

/// One activation's accountability record: the emergency, the addresses that
/// co-signed its declaration into force, and every [`Emergency`](crate::proposal::ProposalKind::Emergency)
/// measure admitted under it (ADR-0023 §6).
#[derive(Clone, Debug)]
pub struct EmergencyReportActivation {
    /// The emergency itself.
    pub emergency: ActiveEmergency,
    /// The declaration's author and co-signers (distinct, self-signed).
    pub cosigners: Vec<Address>,
    /// Measures admitted under this emergency: `(proposal_id, title, expires_at)`.
    pub measures: Vec<(crate::proposal::ProposalId, String, i64)>,
}

/// The addresses that signed a declaration (its author included) — the co-signers
/// that carried it toward its supermajority. Self-signed cosigns only; not
/// eligibility-filtered (the report shows who signed, whatever their standing now).
pub fn declaration_cosigners(
    db: &Database,
    decl_hash: &Hash,
) -> Result<Vec<Address>, EmergencyError> {
    let log = AppendLog::new(db);
    let mut out = Vec::new();
    if let Some((decl, _)) = find_declaration(&log, decl_hash)? {
        out.push(decl.author);
    }
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(cosign) = from_canonical_bytes::<EmergencyCosign>(&entry.payload.bytes) else {
            continue;
        };
        if cosign.declaration_hash == *decl_hash
            && Address::from_public_key(entry.payload.signer) == cosign.signer
            && !out.contains(&cosign.signer)
        {
            out.push(cosign.signer);
        }
    }
    Ok(out)
}

/// The derived post-emergency report: for every legitimate activation, its
/// co-signers and every Emergency measure **admitted under it** (ADR-0023 §6) — the
/// honest superset, so a measure that was raised under the emergency and *failed* is
/// still surfaced for review, not hidden; whether each passed is the tally's call. A
/// pure read of the log — no new record kinds.
pub fn emergency_report(
    db: &Database,
    station: &PublicKey,
) -> Result<Vec<EmergencyReportActivation>, EmergencyError> {
    let timeline = emergency_timeline(db, station)?;
    let log = AppendLog::new(db);
    // Every Emergency-kind proposal, with its station-attested admission and window
    // position, so each can be attributed to the emergency that governed it.
    let mut emergency_proposals = Vec::new();
    for p in crate::proposal::all_proposals(&log, db, station)? {
        if let ProposalKind::Emergency { expires_at } = p.kind {
            if let Some((w, seq)) = crate::window::window_and_seq_of(&log, &p.proposal_id, station)
            {
                emergency_proposals.push((
                    p.proposal_id,
                    p.title.clone(),
                    expires_at,
                    w.admitted_at,
                    seq,
                ));
            }
        }
    }

    let mut out = Vec::with_capacity(timeline.len());
    for e in timeline {
        let cosigners = declaration_cosigners(db, &e.declaration_hash)?;
        let measures = emergency_proposals
            .iter()
            .filter(|(_, _, _, admitted_at, seq)| e.governs(*admitted_at, *seq))
            .map(|(id, title, expires_at, _, _)| (*id, title.clone(), *expires_at))
            .collect();
        out.push(EmergencyReportActivation {
            emergency: e,
            cosigners,
            measures,
        });
    }
    Ok(out)
}

/// Why a declaration is inert (never took force) in the §6 report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InertDisposition {
    /// Its first crossing was refused by a §4 cap (dead, ADR-0027 D1b).
    Refused,
    /// Its first crossing was not reached within the declaration TTL of its
    /// admission (expired, ADR-0027 D2), judged as of the report's `now`.
    Expired,
}

/// A declaration that gathered support but never activated — surfaced in the §6
/// accountability report so a cap-refused or expired declaration is visible for
/// review, not silently dropped (ADR-0027 D3 §6 promise).
#[derive(Clone, Debug)]
pub struct InertDeclaration {
    /// The declaration's content hash.
    pub declaration_hash: Hash,
    /// The crisis, for display (testimony).
    pub reason: String,
    /// The declared domain, for display (testimony).
    pub scope: String,
    /// Why it is inert.
    pub disposition: InertDisposition,
    /// Its author and co-signers (distinct, self-signed).
    pub cosigners: Vec<Address>,
}

/// Every declaration that is **dead** (cap-refused, D1b) or **expired** (past its
/// TTL with no activation, D2 — judged as of `now`), in log order, with its
/// co-signers (ADR-0027 §6). A pure replay; a declaration still gathering support
/// within its TTL, or one that activated, is not listed here.
pub fn inert_declarations(
    db: &Database,
    now: i64,
    station: &PublicKey,
) -> Result<Vec<InertDeclaration>, EmergencyError> {
    let derived = derive_emergencies(db, station)?;
    let log = AppendLog::new(db);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(decl) = from_canonical_bytes::<EmergencyDeclaration>(&entry.payload.bytes) else {
            continue;
        };
        // Self-signed only, and each distinct declaration once (in log order).
        if Address::from_public_key(entry.payload.signer) != decl.author {
            continue;
        }
        let dh = decl.hash();
        if !seen.insert(dh) {
            continue;
        }
        // An activation for it stands → not inert.
        if derived.timeline.iter().any(|e| e.declaration_hash == dh) {
            continue;
        }
        let disposition = if derived.dead.contains(&dh) {
            InertDisposition::Refused
        } else if derived
            .anchors
            .get(&dh)
            .is_some_and(|&a| now.saturating_sub(a) > EMERGENCY_DECLARATION_TTL)
        {
            InertDisposition::Expired
        } else {
            continue; // still pending within its TTL
        };
        out.push(InertDeclaration {
            declaration_hash: dh,
            reason: decl.reason.clone(),
            scope: decl.scope.clone(),
            disposition,
            cosigners: declaration_cosigners(db, &dh)?,
        });
    }
    Ok(out)
}

// --- Append guards ----------------------------------------------------------

/// The `(seq, admitted_at)` the next append will receive — the monotone-clamped
/// admission the write path anchors on (matches `append_proposal`).
fn next_admission(log: &AppendLog, now: i64) -> Result<(u64, i64), EmergencyError> {
    Ok(match log.tail()? {
        Some(t) => (t.seq + 1, now.max(t.created_at)),
        None => (1, now),
    })
}

/// The `(declaration_pct, max_renewals)` that govern emergency *legitimacy*, read
/// from the immutable **genesis (founder) charter** so the append-time activation
/// decision matches [`emergency_timeline`]'s re-derivation exactly and no later
/// amendment can move it. Falls back to the hard floors/ceiling if
/// no Charter is published.
fn emergency_params(db: &Database) -> Result<(u8, u32), EmergencyError> {
    Ok(match founder_charter(db)? {
        Some(c) => (
            c.charter()
                .governance_structure
                .effective_emergency_declaration_pct(),
            c.charter()
                .governance_structure
                .effective_max_consecutive_renewals(),
        ),
        None => (
            EMERGENCY_DECLARATION_PCT_FLOOR,
            MAX_CONSECUTIVE_RENEWALS_CEILING,
        ),
    })
}

/// Appends a member's [`EmergencyDeclaration`], then — if the author's own signature
/// already crosses the supermajority (an `N=1` grace community) and the §4 caps
/// admit it — the station-signed [`EmergencyActivated`] attestation (ADR-0023 §2).
///
/// Rejects a declaration whose signer is not its author, one for another community,
/// one whose author is not in the electorate at its admission position, and a
/// duplicate.
pub fn append_declaration(
    log: &mut AppendLog,
    signed: SignedDeclaration,
    db: &Database,
    station: &Keypair,
    now: i64,
) -> Result<LogEntry, EmergencyError> {
    let decl = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != decl.author {
        return Err(EmergencyError::SignerMismatch {
            signer,
            named: decl.author,
        });
    }
    // The community is checked against the immutable **genesis** charter, matching
    // `emergency_timeline`'s replay resolution. Checking the amendable *effective*
    // charter here would let a community-renaming amendment silently and permanently
    // make emergencies un-declarable: the front door would accept a declaration under
    // the new name while replay (anchored on genesis) would forever skip it.
    if let Some(genesis) = founder_charter(db)? {
        let expected = &genesis.charter().community_id;
        if decl.community_id != *expected {
            return Err(EmergencyError::WrongCommunity {
                declared: decl.community_id.clone(),
                expected: expected.clone(),
            });
        }
    }
    let decl_hash = decl.hash();
    if find_declaration(log, &decl_hash)?.is_some() {
        return Err(EmergencyError::AlreadyPresent);
    }
    let (open_seq, open_time) = next_admission(log, now)?;
    if !is_eligible_asof(db, &founder_set(db)?, &decl.author, open_time, open_seq)? {
        return Err(EmergencyError::NotEligible { who: decl.author });
    }
    // ADR-0027 D2 atomicity: the declaration and its station-signed admission
    // anchor commit in one transaction, and — if the author's own signature
    // already crosses — the crossing marker joins the same commit, so a crash can
    // never leave a declaration without its anchor or a crossing without its marker.
    let mut batch = log.begin_batch()?;
    let entry = batch.append(signed, now)?;
    let admitted_at = entry.created_at;
    batch.append(
        SignedPayload::sign(
            EmergencyDeclarationAdmitted {
                declaration_hash: decl_hash,
                admitted_at,
            },
            station,
        ),
        now,
    )?;
    // The declaration itself carries the author's crossing signature (an N=1 grace
    // community activates here), so it is the crossing record `try_activate` decides on.
    try_activate(&mut batch, db, station, &decl_hash, entry.seq, now)?;
    batch.commit()?;
    Ok(entry)
}

/// Appends an [`EmergencyCosign`] toward a declaration or a lapse, then — if it
/// carried a declaration across the supermajority — the station attestation.
///
/// Rejects a signer/envelope mismatch, a target this log has not seen, an
/// ineligible signer, a lapse co-signature for a declaration with no active
/// emergency, and a repeat co-signature.
pub fn append_cosign(
    log: &mut AppendLog,
    signed: SignedCosign,
    db: &Database,
    station: &Keypair,
    now: i64,
) -> Result<LogEntry, EmergencyError> {
    let cosign = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != cosign.signer {
        return Err(EmergencyError::SignerMismatch {
            signer,
            named: cosign.signer,
        });
    }
    let station_pk = station.public_key();
    let founders = founder_set(db)?;
    let target = cosign.declaration_hash;

    // The target is either a declaration (a declaration co-sign) or a lapse (a lapse
    // co-sign); the pin the signer's eligibility is judged at differs.
    let (is_declaration, pin_time, pin_seq) =
        if let Some((_decl, _seq)) = find_declaration(log, &target)? {
            // A declaration co-sign: judged at this co-sign's own admission position
            // (the derivation re-judges at the eventual activation position).
            let (seq, time) = next_admission(log, now)?;
            (true, time, seq)
        } else if let Some((lapse, _seq)) = find_lapse(log, &target)? {
            // A lapse co-sign: judged at the emergency's activation position — the
            // same electorate the emergency itself uses (§4). The emergency is
            // resolved at the monotone-clamped admission instant (not raw `now`), so
            // a station clock regression cannot spuriously report no active emergency.
            let (open_seq, open_time) = next_admission(log, now)?;
            let active = active_emergency_at(db, open_time, open_seq, &station_pk)?
                .filter(|e| e.declaration_hash == lapse.declaration_hash)
                .ok_or(EmergencyError::NotActive(lapse.declaration_hash))?;
            (false, active.activation_instant, active.activation_seq)
        } else {
            return Err(EmergencyError::UnknownTarget(target));
        };

    if !is_eligible_asof(db, &founders, &cosign.signer, pin_time, pin_seq)? {
        return Err(EmergencyError::NotEligible { who: cosign.signer });
    }
    // Idempotent re-carriage is answered before the D3 state check, so a benign
    // resubmission of a co-sign toward a now-activated declaration is still
    // `AlreadyCosigned` (Known on DTN), not a fresh `AlreadyActivated` refusal.
    if cosign_already_present(log, &target, &cosign.signer)? {
        return Err(EmergencyError::AlreadyCosigned {
            signer: cosign.signer,
            target,
        });
    }
    // ADR-0027 D3 front door: a *new* co-signature toward an inert declaration is
    // refused with a typed reason rather than appended as dead weight. The probe
    // instant is this co-sign's own prospective admission (`pin_time` for a
    // declaration target), which fixes the TTL comparison for the expired arm.
    if is_declaration {
        match declaration_status(db, &target, pin_time, &station_pk)? {
            DeclarationStatus::Activated => {
                return Err(EmergencyError::AlreadyActivated {
                    declaration: target,
                })
            }
            DeclarationStatus::Dead => {
                return Err(EmergencyError::DeclarationDead {
                    declaration: target,
                })
            }
            DeclarationStatus::Expired => {
                return Err(EmergencyError::DeclarationExpired {
                    declaration: target,
                    ttl: EMERGENCY_DECLARATION_TTL,
                })
            }
            DeclarationStatus::Pending => {}
        }
    }
    // A declaration co-sign may carry the crossing, so it and any station marker
    // (activation or D1b refusal) commit atomically; a lapse co-sign never writes
    // a marker, so it is a plain single append.
    if is_declaration {
        let mut batch = log.begin_batch()?;
        let entry = batch.append(signed, now)?;
        // This co-signature is the crossing record `try_activate` decides on.
        try_activate(&mut batch, db, station, &target, entry.seq, now)?;
        batch.commit()?;
        Ok(entry)
    } else {
        Ok(log.append(signed, now)?)
    }
}

/// Appends an [`EmergencyLapse`] against an active emergency. The lapse itself is
/// the first signature toward the lapse supermajority; it takes effect only once
/// [`EmergencyCosign`]s targeting *its* hash reach the same threshold (ADR-0023 §4),
/// which is re-derived from the log — no attestation is written.
///
/// Rejects a signer mismatch, a declaration with no active emergency, an ineligible
/// author, and a duplicate lapse.
pub fn append_lapse(
    log: &mut AppendLog,
    signed: SignedLapse,
    db: &Database,
    station: &PublicKey,
    now: i64,
) -> Result<LogEntry, EmergencyError> {
    let lapse = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != lapse.author {
        return Err(EmergencyError::SignerMismatch {
            signer,
            named: lapse.author,
        });
    }
    // Judge activity at the monotone-clamped admission instant the append will
    // receive (matching `append_proposal`/`record_implementation`), not raw `now`, so
    // a station clock regression below the activation instant cannot refuse a valid
    // lapse.
    let (open_seq, open_time) = next_admission(log, now)?;
    let active = active_emergency_at(db, open_time, open_seq, station)?
        .filter(|e| e.declaration_hash == lapse.declaration_hash)
        .ok_or(EmergencyError::NotActive(lapse.declaration_hash))?;
    if !is_eligible_asof(
        db,
        &founder_set(db)?,
        &lapse.author,
        active.activation_instant,
        active.activation_seq,
    )? {
        return Err(EmergencyError::NotEligible { who: lapse.author });
    }
    if find_lapse(log, &lapse.hash())?.is_some() {
        return Err(EmergencyError::AlreadyPresent);
    }
    Ok(log.append(signed, now)?)
}

/// Whether `signer` already has a co-signature on the log toward `target`.
fn cosign_already_present(
    log: &AppendLog,
    target: &Hash,
    signer: &Address,
) -> Result<bool, EmergencyError> {
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(cosign) = from_canonical_bytes::<EmergencyCosign>(&entry.payload.bytes) else {
            continue;
        };
        if cosign.declaration_hash == *target
            && cosign.signer == *signer
            && Address::from_public_key(entry.payload.signer) == cosign.signer
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Evaluates the just-appended crossing record (visible uncommitted in `batch`'s
/// open transaction) and, if it is the declaration's **first threshold crossing**,
/// writes the station marker into the **same** batch (ADR-0027 D1/D1b):
/// [`EmergencyActivated`] when the §4 caps admit it, or [`EmergencyRefused`] when a
/// cap binds. Silent when the threshold is not yet met, when the declaration is
/// already decided, or when the crossing is beyond the declaration TTL (D2, a
/// belt-and-suspenders to the front-door expiry refusal — the declaration simply
/// does not activate).
///
/// `crossing_record_seq` is the seq of the record this front-door call just
/// appended and is deciding on — the declaration (its author's signature) for
/// [`append_declaration`], or the co-signature for [`append_cosign`]. The marker is
/// written **only** when the threshold-th distinct signature sits at that seq, i.e.
/// this record *is* the first crossing. If the count already reached the threshold
/// at an earlier position that carries no marker — a crossing record that reached
/// the log by gossip [`append_raw`](rrn_storage::log::AppendLog::append_raw) rather
/// than through this front door — the crossing is **markerless** and ADR-0027 D1b
/// makes it *not activatable*: fail closed here, the same way replay does, so a
/// bypassed crossing can never be revived by a later front-door co-signature. (The
/// broader "gossip ingest bypasses every front-door gate" surface — eligibility,
/// duplicate co-signs, D3 — is a pre-existing residual tracked for the maintainer.)
///
/// Reads go through a fresh [`AppendLog`] over the same [`Database`] connection,
/// so they observe the crossing record already appended into the open batch.
fn try_activate(
    batch: &mut rrn_storage::log::LogBatch,
    db: &Database,
    station: &Keypair,
    decl_hash: &Hash,
    crossing_record_seq: u64,
    now: i64,
) -> Result<(), EmergencyError> {
    let log = AppendLog::new(db);
    let station_pk = station.public_key();

    // A declaration already decided — activated earlier, or killed by a validated
    // refusal (ADR-0027 D1b) — writes no further marker. Judged against the
    // re-derived view (the same one a replica computes), never against a raw
    // attestation on the log, so a gossiped bogus marker cannot suppress or fake a
    // decision. The derivation's activation pairs are reused as the chain input.
    let derived = derive_emergencies(db, &station_pk)?;
    if derived.dead.contains(decl_hash)
        || derived
            .timeline
            .iter()
            .any(|e| e.declaration_hash == *decl_hash)
    {
        return Ok(());
    }
    let Some((decl, decl_seq)) = find_declaration(&log, decl_hash)? else {
        return Ok(());
    };
    let founders = founder_set(db)?;
    let (act_seq, act_time) = next_admission(&log, now)?;
    let tail_seq = act_seq - 1;
    let (declaration_pct, max_renewals) = emergency_params(db)?;

    let n = grace_electorate_asof(db, &founders, act_time, act_seq)?.len();
    let threshold = declaration_threshold(n, declaration_pct);
    let sigs = eligible_signatures(
        &log,
        db,
        &founders,
        decl_hash,
        &decl.author,
        decl_seq,
        act_time,
        act_seq,
        tail_seq,
    )?;
    match crossing_seq(&sigs, threshold) {
        // This front-door record *is* the first crossing — write its marker.
        Some(cross) if cross == crossing_record_seq => {}
        // The threshold was already reached at an earlier position that carries no
        // marker (a crossing record admitted by gossip `append_raw`, bypassing this
        // front door). ADR-0027 D1b: a markerless crossing is not activatable — fail
        // closed, so no later front-door co-signature can revive it.
        Some(_) => return Ok(()),
        // Not the crossing yet.
        None => return Ok(()),
    }

    // ADR-0027 D2: fail closed on the TTL against the declaration's signed
    // admission anchor. A crossing later than the TTL does not activate (and the
    // front door already refuses such a co-sign); a declaration with no anchor
    // never activates. The anchor's signer is pinned to the station (T2.1.4), so a
    // forged anchor cannot supply a doctored `admitted_at`; saturating arithmetic
    // keeps the subtraction well-defined for any in-range instant regardless.
    let Some(admitted_at) = declaration_admitted_at(&log, decl_hash, &station_pk)? else {
        return Ok(());
    };
    if act_time.saturating_sub(admitted_at) > EMERGENCY_DECLARATION_TTL {
        return Ok(());
    }

    // This is the first crossing. Either the §4 caps admit it — write the
    // activation — or a cap binds — write the D1b refusal, killing the declaration
    // for good, in the same transaction as the crossing record.
    let scheduled = act_time + clamp_duration(decl.duration_secs);
    let existing: Vec<(i64, i64)> = derived
        .timeline
        .iter()
        .map(|e| (e.activation_instant, e.scheduled_expiry))
        .collect();
    match chain_decision(&existing, act_time, scheduled, max_renewals) {
        Some(renewal_count) => {
            batch.append(
                SignedPayload::sign(
                    EmergencyActivated {
                        declaration_hash: *decl_hash,
                        activation_instant: act_time,
                        scheduled_expiry: scheduled,
                        renewal_count,
                    },
                    station,
                ),
                now,
            )?;
        }
        None => {
            batch.append(
                SignedPayload::sign(
                    EmergencyRefused {
                        declaration_hash: *decl_hash,
                        refused_instant: act_time,
                    },
                    station,
                ),
                now,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod cbor_tests {
    use super::*;

    fn h(b: u8) -> Hash {
        Hash::from_bytes([b; 32])
    }
    fn a(b: u8) -> Address {
        Address::from_public_key(
            rrn_crypto::keypair::Keypair::from_secret(rrn_crypto::keypair::SecretKey::from_bytes(
                [b; 32],
            ))
            .public_key(),
        )
    }

    #[test]
    fn declaration_cbor_roundtrips_with_and_without_previous() {
        for prev in [None, Some(h(9))] {
            let d = EmergencyDeclaration {
                community_id: "commons".into(),
                author: a(1),
                reason: "storm".into(),
                scope: "flood-response".into(),
                duration_secs: 72 * 3600,
                stated_renewal_index: 0,
                previous_declaration_hash: prev,
                created_at: 1_700_000_000,
            };
            let back: EmergencyDeclaration =
                from_canonical_bytes(&to_canonical_bytes(d.clone())).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn absent_previous_hash_is_omitted_not_null() {
        // ADR-0010 discipline: an initial declaration's canonical map has no
        // `previous_declaration_hash` key at all, so its bytes differ from a
        // renewal's and the field is never a null.
        let initial = EmergencyDeclaration {
            community_id: "commons".into(),
            author: a(1),
            reason: "storm".into(),
            scope: "s".into(),
            duration_secs: 3600,
            stated_renewal_index: 0,
            previous_declaration_hash: None,
            created_at: 1,
        };
        let cbor = CBOR::from(initial);
        let CBORCase::Map(map) = cbor.into_case() else {
            panic!("map");
        };
        assert!(map.get::<&str, CBOR>("previous_declaration_hash").is_none());
    }

    #[test]
    fn cosign_lapse_activated_roundtrip() {
        let c = EmergencyCosign {
            declaration_hash: h(3),
            signer: a(2),
        };
        assert_eq!(
            c,
            from_canonical_bytes::<EmergencyCosign>(&to_canonical_bytes(c)).unwrap()
        );

        let l = EmergencyLapse {
            declaration_hash: h(3),
            author: a(2),
        };
        assert_eq!(
            l,
            from_canonical_bytes::<EmergencyLapse>(&to_canonical_bytes(l.clone())).unwrap()
        );

        let act = EmergencyActivated {
            declaration_hash: h(3),
            activation_instant: 1_700_000_000,
            scheduled_expiry: 1_700_000_000 + 72 * 3600,
            renewal_count: 1,
        };
        assert_eq!(
            act,
            from_canonical_bytes::<EmergencyActivated>(&to_canonical_bytes(act)).unwrap()
        );
    }

    #[test]
    fn refused_and_admitted_roundtrip() {
        let r = EmergencyRefused {
            declaration_hash: h(4),
            refused_instant: 1_700_000_123,
        };
        assert_eq!(
            r,
            from_canonical_bytes::<EmergencyRefused>(&to_canonical_bytes(r)).unwrap()
        );

        let adm = EmergencyDeclarationAdmitted {
            declaration_hash: h(4),
            admitted_at: 1_700_000_000,
        };
        assert_eq!(
            adm,
            from_canonical_bytes::<EmergencyDeclarationAdmitted>(&to_canonical_bytes(adm)).unwrap()
        );
    }

    #[test]
    fn kinds_do_not_cross_decode() {
        let c = EmergencyCosign {
            declaration_hash: h(1),
            signer: a(1),
        };
        let bytes = to_canonical_bytes(c);
        assert!(from_canonical_bytes::<EmergencyDeclaration>(&bytes).is_err());
        assert!(from_canonical_bytes::<EmergencyLapse>(&bytes).is_err());
        assert!(from_canonical_bytes::<EmergencyActivated>(&bytes).is_err());
        assert!(from_canonical_bytes::<EmergencyRefused>(&bytes).is_err());
        assert!(from_canonical_bytes::<EmergencyDeclarationAdmitted>(&bytes).is_err());

        // The two new station-signed kinds do not cross-decode as each other or as
        // the activation attestation (distinct `kind` discriminators).
        let refused_bytes = to_canonical_bytes(EmergencyRefused {
            declaration_hash: h(2),
            refused_instant: 5,
        });
        assert!(from_canonical_bytes::<EmergencyActivated>(&refused_bytes).is_err());
        assert!(from_canonical_bytes::<EmergencyDeclarationAdmitted>(&refused_bytes).is_err());
        let admitted_bytes = to_canonical_bytes(EmergencyDeclarationAdmitted {
            declaration_hash: h(2),
            admitted_at: 5,
        });
        assert!(from_canonical_bytes::<EmergencyActivated>(&admitted_bytes).is_err());
        assert!(from_canonical_bytes::<EmergencyRefused>(&admitted_bytes).is_err());
    }
}
