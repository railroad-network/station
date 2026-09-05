//! Escrowed offline spending certificates: the on-log records and the reserved
//! headroom they represent (ADR-0021).
//!
//! Under a partition, ADR-0020 keeps a single delay-tolerant front door, which
//! opens a gap on the receiver's side: a receiver who accepts a signed proposal
//! (and hands over goods) trusts that the sender's debit will still clear the
//! debt floor when it finally reaches the station — but the sender may have spent
//! the same headroom several times over during the same outage, and whichever
//! records arrive last are refused, stranding an honest receiver.
//!
//! A **headroom certificate** closes that gap by reserving the capacity to commit
//! *ahead of time*, while connected. A member requests a station-signed,
//! expiring, amount-capped certificate; issuing it reserves the full cap against
//! the member's debt-floor headroom, exactly as a pending signed debit does
//! ([`crate::credit::committed_debits_centi`]). A spend that references the
//! certificate, within its cap and validity, is later admitted without a fresh
//! floor check — the headroom was already paid for. (Spending against a
//! certificate is T2.3.2; this module delivers issuance, return, and the
//! reservation arithmetic.)
//!
//! Three signed record kinds carry the instrument, each following the
//! content-addressed, omit-when-`None` discipline of
//! [`crate::transaction`] (ADR-0002/ADR-0010):
//!
//! - [`CertificateRequest`] — member-signed, "I want a cap-`cap_centi`
//!   certificate". Content-addressed by [`RequestId`].
//! - [`HeadroomCertificate`] — station-signed grant, naming the request it
//!   honors. Content-addressed by [`CertId`].
//! - [`CertificateReturn`] — member-signed early return, releasing the reserved
//!   remainder before expiry.
//!
//! The request and the certificate are **both** appended to the log, request
//! first, so replay can prove member consent and the station's grant
//! independently.

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_protocol::outbox::{self, OutboxEntry, SignedOutboxEntry};
use serde::{Deserialize, Serialize};

use crate::credit::CreditConfig;

/// Discriminant strings carried in the `kind` field of each record's canonical
/// CBOR, so log replay can tell the record types apart unambiguously.
pub(crate) const CERT_REQUEST_KIND: &str = "rrn.credit.cert_request";
pub(crate) const CERTIFICATE_KIND: &str = "rrn.credit.certificate";
pub(crate) const CERT_RETURN_KIND: &str = "rrn.credit.cert_return";

/// The content address of a [`CertificateRequest`]: the Blake3 hash of its
/// canonical bytes. Like [`crate::transaction::TransactionId`] the id is derived,
/// not independent — it *is* the hash of everything else.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct RequestId(pub Hash);

/// The content address of a [`HeadroomCertificate`]: the Blake3 hash of its
/// canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CertId(pub Hash);

macro_rules! hash_newtype_cbor {
    ($ty:ident) => {
        impl $ty {
            /// The 32 raw hash bytes.
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0.to_bytes()
            }
        }

        // A total order over the hash bytes, so the id can key a `BTreeMap`
        // during log replay — content order, arbitrary but stable and identical
        // on every replica (mirrors `TransactionId`).
        impl Ord for $ty {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.to_bytes().cmp(&other.0.to_bytes())
            }
        }
        impl PartialOrd for $ty {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl From<$ty> for CBOR {
            fn from(id: $ty) -> Self {
                CBOR::to_byte_string(id.0.to_bytes())
            }
        }
        impl TryFrom<CBOR> for $ty {
            type Error = dcbor::Error;
            fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
                let bytes: [u8; 32] = cbor
                    .try_into_byte_string()?
                    .as_slice()
                    .try_into()
                    .map_err(|_| dcbor::Error::WrongType)?;
                Ok($ty(Hash::from_bytes(bytes)))
            }
        }
    };
}

hash_newtype_cbor!(RequestId);
hash_newtype_cbor!(CertId);

/// A member's signed request for a headroom certificate (ADR-0021 §1).
///
/// Content-addressed by [`request_id`](Self::request_id): the id is the Blake3
/// hash of every other field, omitted from the CBOR and recomputed on decode, so
/// a request names itself and cannot carry an id that disagrees with its
/// contents.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    /// Content address: Blake3 of this request's canonical bytes. Derived — see
    /// the type docs.
    pub request_id: RequestId,
    /// The member requesting (and signing) the certificate; must equal the
    /// signer.
    pub member: Address,
    /// The cap requested, in centicommons. Must be `> 0` and `<=` the engine's
    /// `cert_max_cap_centi`.
    pub cap_centi: i64,
    /// A per-member monotonic nonce that **shares the member's proposal nonce
    /// sequence** ([`LedgerSnapshot::next_nonce`](crate::state::LedgerSnapshot::next_nonce)):
    /// one sequence per key keeps replay protection single-tracked and gives a
    /// request replay protection for free.
    pub nonce: u64,
    /// Unix seconds the request was made — plausibility-bounded testimony
    /// (ADR-0022 §3), never a window anchor.
    pub requested_at: i64,
}

impl CertificateRequest {
    /// Builds a request and computes its content-addressed
    /// [`request_id`](Self::request_id).
    pub fn new(member: Address, cap_centi: i64, nonce: u64, requested_at: i64) -> Self {
        let mut req = Self {
            // Placeholder; overwritten immediately by `compute_id`, which hashes
            // every field *except* `request_id`.
            request_id: RequestId(Hash::from_bytes([0u8; 32])),
            member,
            cap_centi,
            nonce,
            requested_at,
        };
        req.request_id = req.compute_id();
        req
    }

    fn compute_id(&self) -> RequestId {
        use rrn_crypto::serialize::to_canonical_bytes;
        // `Into<CBOR>` (below) omits `request_id`, so this hashes only content.
        RequestId(Hash::of(&to_canonical_bytes(self.clone())))
    }
}

impl From<CertificateRequest> for CBOR {
    fn from(r: CertificateRequest) -> Self {
        let mut m = Map::new();
        // `request_id` is deliberately omitted — it is the hash of these bytes.
        m.insert("kind", CERT_REQUEST_KIND);
        m.insert("member", r.member);
        m.insert("cap_centi", r.cap_centi);
        m.insert("nonce", r.nonce);
        m.insert("requested_at", r.requested_at);
        m.into()
    }
}

impl TryFrom<CBOR> for CertificateRequest {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CERT_REQUEST_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(CertificateRequest::new(
            map.extract::<&str, Address>("member")?,
            map.extract::<&str, i64>("cap_centi")?,
            map.extract::<&str, u64>("nonce")?,
            map.extract::<&str, i64>("requested_at")?,
        ))
    }
}

/// A [`CertificateRequest`] signed by its member.
pub type SignedCertificateRequest = SignedPayload<CertificateRequest>;

/// A station-signed headroom certificate (ADR-0021 §1).
///
/// Content-addressed by [`cert_id`](Self::cert_id). Its remaining cap counts
/// against the member's committed position for as long as the certificate is
/// outstanding and a spend against it could still be admitted (see
/// [`spend_admissible_until`]).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeadroomCertificate {
    /// Content address: Blake3 of this certificate's canonical bytes. Derived.
    pub cert_id: CertId,
    /// The member the certificate is for — copied from the honored request.
    pub member: Address,
    /// The reserved cap, in centicommons — copied from the request.
    pub cap_centi: i64,
    /// The request this certificate honors, proving member consent to the
    /// reservation.
    pub request_id: RequestId,
    /// The admission-clock reading at issuance (ADR-0022).
    pub issued_at: i64,
    /// `issued_at + cert_validity_seconds`: after this (plus the DTN grace and
    /// skew — [`spend_admissible_until`]) no spend can be admitted, so the
    /// reservation releases.
    pub expires_at: i64,
}

impl HeadroomCertificate {
    /// Builds a certificate and computes its content-addressed
    /// [`cert_id`](Self::cert_id).
    pub fn new(
        member: Address,
        cap_centi: i64,
        request_id: RequestId,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        let mut cert = Self {
            cert_id: CertId(Hash::from_bytes([0u8; 32])),
            member,
            cap_centi,
            request_id,
            issued_at,
            expires_at,
        };
        cert.cert_id = cert.compute_id();
        cert
    }

    fn compute_id(&self) -> CertId {
        use rrn_crypto::serialize::to_canonical_bytes;
        CertId(Hash::of(&to_canonical_bytes(self.clone())))
    }
}

impl From<HeadroomCertificate> for CBOR {
    fn from(c: HeadroomCertificate) -> Self {
        let mut m = Map::new();
        // `cert_id` is deliberately omitted — it is the hash of these bytes.
        m.insert("kind", CERTIFICATE_KIND);
        m.insert("member", c.member);
        m.insert("cap_centi", c.cap_centi);
        m.insert("request_id", c.request_id);
        m.insert("issued_at", c.issued_at);
        m.insert("expires_at", c.expires_at);
        m.into()
    }
}

impl TryFrom<CBOR> for HeadroomCertificate {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CERTIFICATE_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(HeadroomCertificate::new(
            map.extract::<&str, Address>("member")?,
            map.extract::<&str, i64>("cap_centi")?,
            map.extract::<&str, RequestId>("request_id")?,
            map.extract::<&str, i64>("issued_at")?,
            map.extract::<&str, i64>("expires_at")?,
        ))
    }
}

/// A [`HeadroomCertificate`] signed by the station.
pub type SignedHeadroomCertificate = SignedPayload<HeadroomCertificate>;

/// A member's signed early return of an outstanding certificate (ADR-0021 §2),
/// releasing the reserved remainder before expiry.
///
/// Unlike [`CertificateRequest`] this is **not** nonce-tracked: returning is
/// idempotent (a second return of the same certificate is refused at the engine
/// as already-returned, and tolerated at derive by keeping the first), so it
/// needs no per-member ordering to be replay-safe — there is nothing to reorder.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CertificateReturn {
    /// The member returning the certificate; must equal the signer and the
    /// certificate's member.
    pub member: Address,
    /// The certificate being returned.
    pub cert_id: CertId,
    /// Unix seconds the return was made — testimony, used in no arithmetic.
    pub returned_at: i64,
}

impl From<CertificateReturn> for CBOR {
    fn from(r: CertificateReturn) -> Self {
        let mut m = Map::new();
        m.insert("kind", CERT_RETURN_KIND);
        m.insert("member", r.member);
        m.insert("cert_id", r.cert_id);
        m.insert("returned_at", r.returned_at);
        m.into()
    }
}

impl TryFrom<CBOR> for CertificateReturn {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CERT_RETURN_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(CertificateReturn {
            member: map.extract::<&str, Address>("member")?,
            cert_id: map.extract::<&str, CertId>("cert_id")?,
            returned_at: map.extract::<&str, i64>("returned_at")?,
        })
    }
}

/// A [`CertificateReturn`] signed by its member.
pub type SignedCertificateReturn = SignedPayload<CertificateReturn>;

/// Whether an outstanding certificate is live or has been returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateStatus {
    /// Live: unexpired-or-within-grace, unreturned, not fully spent. Its
    /// remaining cap is reserved against the member's headroom.
    Outstanding,
    /// Returned early by its member at log seq `at_seq`; reserves nothing.
    Returned {
        /// The log sequence of the admitting return entry.
        at_seq: u64,
    },
}

/// The derived state of one certificate in a [`LedgerSnapshot`](crate::state::LedgerSnapshot).
#[derive(Clone, Debug)]
pub struct CertificateState {
    /// The station-signed certificate itself.
    pub certificate: SignedHeadroomCertificate,
    /// Whether it is still outstanding or has been returned.
    pub status: CertificateStatus,
    /// Cumulative admitted cert-backed spend against it, in centicommons.
    /// **Always 0 in this ticket** — T2.3.2 populates it once cert-backed spends
    /// land; the reservation arithmetic already subtracts it so no follow-up
    /// touches [`crate::credit`].
    pub consumed_centi: i64,
}

/// The admission-clock instant past which no spend against `cert` can ever be
/// admitted, so its reserved headroom releases (ADR-0021 §2, ADR-0018 point 2).
///
/// This is the **single shared definition** of the escrow boundary: the
/// reservation-release condition in [`crate::credit::committed_debits_centi`] and
/// T2.3.2's cert-backed-spend admission bound are the same instant, derived here,
/// so over- and under-reservation cannot diverge. A spend is admissible while
/// `now <= spend_admissible_until(cert, config)` — the certificate's `expires_at`
/// extended by the DTN delivery grace and the engine's clock-skew tolerance.
pub fn spend_admissible_until(cert: &HeadroomCertificate, config: &CreditConfig) -> i64 {
    cert.expires_at
        .saturating_add(config.cert_delivery_grace_seconds)
        .saturating_add(crate::engine::CLOCK_SKEW_TOLERANCE_SECS)
}

// ===========================================================================
// Provable equivocation (ADR-0021 §5, T2.3.3)
// ===========================================================================
//
// Offline spending cannot be *prevented* under a partition — no connectivity,
// no coordination — but a member who overspends a certificate, or forks their
// own outbox chain, has signed conflicting commitments, and the conjunction of
// those member-signed artifacts is a self-contained *proof* of it. When the
// station refuses the excess spend (or the forked entry) it appends a
// station-signed [`EquivocationRecord`] bundling that proof. The record is
// on-log community-public state: a dispute case opens on it (the jury path is a
// follow-up ticket) and it is a negative reputation input (ADR-0009), gated by
// [`EquivocationRecord::verify_evidence`] so a bogus record convicts no one.
//
// Evidence is embedded **in full** (signer/sig/bytes envelope triples, the shape
// [`rrn_protocol::outbox::OutboxEntry`] carries a wrapped record as) rather than
// by content hash, because the refused spend that completes an overspend proof
// never entered the log — this record is the only place it is preserved.

/// Discriminant string carried in an [`EquivocationRecord`]'s canonical CBOR.
pub(crate) const EQUIVOCATION_KIND: &str = "rrn.credit.equivocation";
/// Discriminant string carried in an [`EquivocationVerdictRecord`]'s canonical
/// CBOR.
pub(crate) const EQUIVOCATION_VERDICT_KIND: &str = "rrn.credit.equivocation_verdict";

/// Maximum evidence items in one record — a front-door DoS bound (ADR-0021 §5).
pub const MAX_EVIDENCE_ITEMS: usize = 16;
/// Maximum embedded bytes in one evidence item — a front-door DoS bound.
pub const MAX_EVIDENCE_ITEM_BYTES: usize = 64 * 1024;

/// The content address of an [`EquivocationRecord`]: the Blake3 hash of its
/// canonical bytes. Derived, like the other ids in this module.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct EquivocationId(pub Hash);

hash_newtype_cbor!(EquivocationId);

/// What proved a member's equivocation (ADR-0021 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationBasis {
    /// Cert-referenced spends whose admitted+refused amounts jointly exceed the
    /// certificate's cap. `cert_id` names the certificate.
    CertOverspend,
    /// Two independently-valid outbox entries by the member at one chain
    /// position (ADR-0020 §2). Carries no `cert_id`.
    OutboxFork,
}

impl EquivocationBasis {
    /// The wire slug carried in the record's `basis` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            EquivocationBasis::CertOverspend => "cert-overspend",
            EquivocationBasis::OutboxFork => "outbox-fork",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "cert-overspend" => Some(EquivocationBasis::CertOverspend),
            "outbox-fork" => Some(EquivocationBasis::OutboxFork),
            _ => None,
        }
    }
}

/// One member-signed artifact embedded verbatim as equivocation evidence: the
/// signer, the signature, and the canonical signed bytes — the same
/// signer/sig/body envelope triple [`rrn_protocol::receipt::encode_signed`] and
/// [`rrn_protocol::outbox::OutboxEntry`]'s `record_*` fields use. Embedded in
/// full (not by hash) so the proof is self-contained even for the refused spend
/// that never reached the log.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EvidenceItem {
    /// Ed25519 public key that produced [`signature`](Self::signature).
    pub signer: PublicKey,
    /// Signature by [`signer`](Self::signer) over [`bytes`](Self::bytes).
    pub signature: Signature,
    /// The signed artifact's canonical dCBOR — the exact bytes its author
    /// signed.
    pub bytes: Vec<u8>,
}

impl EvidenceItem {
    /// Decomposes a signed envelope into its evidence triple, copying the
    /// signer and signature verbatim (never regenerated).
    pub fn from_signed<T: Clone + Into<CBOR>>(signed: &SignedPayload<T>) -> Self {
        use rrn_crypto::serialize::to_canonical_bytes;
        Self {
            signer: signed.signer,
            signature: signed.signature,
            bytes: to_canonical_bytes(signed.payload.clone()),
        }
    }

    /// Whether [`signature`](Self::signature) is a valid signature by
    /// [`signer`](Self::signer) over [`bytes`](Self::bytes).
    pub fn signature_verifies(&self) -> bool {
        self.signer.verify(&self.bytes, &self.signature).is_ok()
    }
}

impl From<EvidenceItem> for CBOR {
    fn from(e: EvidenceItem) -> Self {
        let mut m = Map::new();
        m.insert("signer", CBOR::to_byte_string(e.signer.to_bytes()));
        m.insert("sig", CBOR::to_byte_string(e.signature.to_bytes()));
        m.insert("body", CBOR::to_byte_string(e.bytes));
        m.into()
    }
}

impl TryFrom<CBOR> for EvidenceItem {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let signer: [u8; 32] = map
            .extract::<&str, CBOR>("signer")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        let sig: [u8; 64] = map
            .extract::<&str, CBOR>("sig")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(EvidenceItem {
            signer: PublicKey::from_bytes(signer).map_err(|_| dcbor::Error::WrongType)?,
            signature: Signature::from_bytes(sig).map_err(|_| dcbor::Error::WrongType)?,
            bytes: map
                .extract::<&str, CBOR>("body")?
                .try_into_byte_string()?
                .as_slice()
                .to_vec(),
        })
    }
}

/// A station-signed record that a member equivocated (ADR-0021 §5).
///
/// Content-addressed by [`equivocation_id`](Self::equivocation_id) — the Blake3
/// hash of every other field, omitted from the CBOR and recomputed on decode.
/// The record is only as convincing as [`verify_evidence`](Self::verify_evidence)
/// makes it: a replica re-checks every embedded member signature and re-derives
/// the conflict from the record itself, so the station cannot fabricate an
/// equivocation (it cannot forge member signatures) and a hostile log copy's
/// bogus record produces no reputation consequence.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EquivocationRecord {
    /// Content address: Blake3 of this record's canonical bytes. Derived.
    pub equivocation_id: EquivocationId,
    /// The equivocator.
    pub member: Address,
    /// What proved the equivocation.
    pub basis: EquivocationBasis,
    /// The certificate overspent — `Some` iff `basis` is
    /// [`CertOverspend`](EquivocationBasis::CertOverspend), omitted from the CBOR
    /// otherwise (ADR-0010 additive-field discipline).
    pub cert_id: Option<CertId>,
    /// The member-signed artifacts that jointly prove the conflict (see the
    /// module docs). Bounded by [`MAX_EVIDENCE_ITEMS`] /
    /// [`MAX_EVIDENCE_ITEM_BYTES`].
    pub evidence: Vec<EvidenceItem>,
    /// The admission-clock reading when the station recorded it (ADR-0022).
    pub recorded_at: i64,
}

impl EquivocationRecord {
    /// Builds a record and computes its content-addressed
    /// [`equivocation_id`](Self::equivocation_id).
    pub fn new(
        member: Address,
        basis: EquivocationBasis,
        cert_id: Option<CertId>,
        evidence: Vec<EvidenceItem>,
        recorded_at: i64,
    ) -> Self {
        let mut record = Self {
            equivocation_id: EquivocationId(Hash::from_bytes([0u8; 32])),
            member,
            basis,
            cert_id,
            evidence,
            recorded_at,
        };
        record.equivocation_id = record.compute_id();
        record
    }

    fn compute_id(&self) -> EquivocationId {
        use rrn_crypto::serialize::to_canonical_bytes;
        EquivocationId(Hash::of(&to_canonical_bytes(self.clone())))
    }

    /// Whether the embedded evidence genuinely proves the claimed equivocation.
    ///
    /// Re-checks every embedded member signature and re-derives the conflict
    /// **from the record and the supplied cap alone**, so a replica can validate
    /// the station's claim without trusting it:
    ///
    /// - **Cert-overspend** (`cap_centi` = the certificate's cap, looked up on
    ///   the log by the caller): every item is a distinct `TransactionProposal`
    ///   signed by `member`, referencing `cert_id`, with a positive amount, and
    ///   the amounts sum **past the cap**. Fewer than two items, a foreign
    ///   member, a mismatched or absent `cert_id`, a non-positive amount, a
    ///   duplicated proposal, or a sum within the cap all fail.
    /// - **Outbox-fork** (`cap_centi` ignored): exactly two items that
    ///   reconstruct to valid [`SignedOutboxEntry`]s which
    ///   [`is_fork`](rrn_protocol::outbox::is_fork) — same author (= `member`),
    ///   same position, different content.
    ///
    /// The DoS bounds ([`MAX_EVIDENCE_ITEMS`], [`MAX_EVIDENCE_ITEM_BYTES`]) are
    /// re-enforced here too: a decoded record that exceeds them verifies as
    /// false, never panicking.
    pub fn verify_evidence(&self, cap_centi: Option<i64>) -> bool {
        if self.evidence.len() > MAX_EVIDENCE_ITEMS {
            return false;
        }
        if self
            .evidence
            .iter()
            .any(|e| e.bytes.len() > MAX_EVIDENCE_ITEM_BYTES)
        {
            return false;
        }
        // Every embedded artifact must carry a signature that verifies over its
        // own bytes — the station cannot forge these.
        if !self.evidence.iter().all(EvidenceItem::signature_verifies) {
            return false;
        }
        match self.basis {
            EquivocationBasis::CertOverspend => self.verify_cert_overspend(cap_centi),
            EquivocationBasis::OutboxFork => self.verify_outbox_fork(),
        }
    }

    fn verify_cert_overspend(&self, cap_centi: Option<i64>) -> bool {
        let (Some(cert_id), Some(cap)) = (self.cert_id, cap_centi) else {
            return false;
        };
        if self.evidence.len() < 2 {
            return false;
        }
        let member_pk = self.member.public_key();
        let mut seen: std::collections::BTreeSet<crate::transaction::TransactionId> =
            std::collections::BTreeSet::new();
        let mut sum: i64 = 0;
        for item in &self.evidence {
            if &item.signer != member_pk {
                return false;
            }
            let Ok(p) =
                from_canonical_bytes::<crate::transaction::TransactionProposal>(&item.bytes)
            else {
                return false;
            };
            if p.cert_id != Some(cert_id) || p.sender != self.member || p.amount_centi <= 0 {
                return false;
            }
            // Distinct spends only — the same proposal listed twice is not proof
            // of two commitments.
            if !seen.insert(p.id) {
                return false;
            }
            sum = sum.saturating_add(p.amount_centi);
        }
        sum > cap
    }

    fn verify_outbox_fork(&self) -> bool {
        if self.cert_id.is_some() || self.evidence.len() != 2 {
            return false;
        }
        let (Some(a), Some(b)) = (
            self.reconstruct_entry(&self.evidence[0]),
            self.reconstruct_entry(&self.evidence[1]),
        ) else {
            return false;
        };
        // `is_fork` re-validates both entries (outer sig, author==signer, embedded
        // sig) and checks same author + same position + different content.
        outbox::is_fork(&a, &b)
            && a.payload.author == self.member
            && b.payload.author == self.member
    }

    fn reconstruct_entry(&self, item: &EvidenceItem) -> Option<SignedOutboxEntry> {
        let payload = from_canonical_bytes::<OutboxEntry>(&item.bytes).ok()?;
        Some(SignedOutboxEntry {
            payload,
            signer: item.signer,
            signature: item.signature,
        })
    }

    /// The forked chain position, for `basis` [`OutboxFork`](EquivocationBasis::OutboxFork)
    /// — the second half of the `(member, position)` dedup key. `None` for a
    /// cert-overspend record or unparseable fork evidence.
    pub fn fork_position(&self) -> Option<u64> {
        if self.basis != EquivocationBasis::OutboxFork {
            return None;
        }
        self.reconstruct_entry(self.evidence.first()?)
            .map(|e| e.payload.position)
    }
}

impl From<EquivocationRecord> for CBOR {
    fn from(r: EquivocationRecord) -> Self {
        let mut m = Map::new();
        // `equivocation_id` is deliberately omitted — it is the hash of these
        // bytes.
        m.insert("kind", EQUIVOCATION_KIND);
        m.insert("member", r.member);
        m.insert("basis", r.basis.as_str());
        // Omit-when-`None`: a fork record carries no `cert_id` key at all.
        if let Some(cid) = r.cert_id {
            m.insert("cert_id", cid);
        }
        let evidence: Vec<CBOR> = r.evidence.into_iter().map(CBOR::from).collect();
        m.insert("evidence", evidence);
        m.insert("recorded_at", r.recorded_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EquivocationRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != EQUIVOCATION_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let basis = EquivocationBasis::from_str(&map.extract::<&str, String>("basis")?)
            .ok_or(dcbor::Error::WrongType)?;
        let raw = match map.extract::<&str, CBOR>("evidence")?.into_case() {
            CBORCase::Array(items) => items,
            _ => return Err(dcbor::Error::WrongType),
        };
        let mut evidence = Vec::with_capacity(raw.len());
        for item in raw {
            evidence.push(EvidenceItem::try_from(item)?);
        }
        Ok(EquivocationRecord::new(
            map.extract::<&str, Address>("member")?,
            basis,
            // Absent decodes to `None`; present to `Some`.
            map.get::<&str, CertId>("cert_id"),
            evidence,
            map.extract::<&str, i64>("recorded_at")?,
        ))
    }
}

/// An [`EquivocationRecord`] signed by the station.
pub type SignedEquivocationRecord = SignedPayload<EquivocationRecord>;

/// A jury's terminal ruling on an equivocation case (ADR-0021 §5, ADR-0014).
///
/// The record kind and its two decisions are defined here so that reputation
/// scoring can read a ruling deterministically from the log (a
/// [`Overturn`](VerdictDecision::Overturn) neutralizes the equivocation as a
/// scoring input). The jury *that produces* this record — sortition, panel,
/// windows — is a follow-up ticket; until then the record is defined and
/// verifiable but never appended by this codebase, and an unruled equivocation
/// stands (the ADR-0021 §5 confirm-on-lapse default).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EquivocationVerdictRecord {
    /// The equivocation case being ruled on.
    pub equivocation_id: EquivocationId,
    /// The panel's terminal decision.
    pub decision: VerdictDecision,
    /// The admission-clock reading when the ruling was recorded.
    pub decided_at: i64,
}

/// A panel's terminal decision on an equivocation case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictDecision {
    /// The evidence stands; the equivocation is confirmed. This is also the
    /// default outcome when a panel lapses (ADR-0021 §5's deliberate inversion
    /// of ADR-0014's fail-open-to-status-quo default: the status quo *is* the
    /// cryptographic proof).
    Confirm,
    /// The panel found the station's evidence invalid (e.g. a buggy or malicious
    /// station); the record is neutralized as a scoring input.
    Overturn,
}

impl VerdictDecision {
    /// The wire slug carried in the record's `decision` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictDecision::Confirm => "confirm",
            VerdictDecision::Overturn => "overturn",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "confirm" => Some(VerdictDecision::Confirm),
            "overturn" => Some(VerdictDecision::Overturn),
            _ => None,
        }
    }
}

impl From<EquivocationVerdictRecord> for CBOR {
    fn from(v: EquivocationVerdictRecord) -> Self {
        let mut m = Map::new();
        m.insert("kind", EQUIVOCATION_VERDICT_KIND);
        m.insert("equivocation_id", v.equivocation_id);
        m.insert("decision", v.decision.as_str());
        m.insert("decided_at", v.decided_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EquivocationVerdictRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != EQUIVOCATION_VERDICT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EquivocationVerdictRecord {
            equivocation_id: map.extract::<&str, EquivocationId>("equivocation_id")?,
            decision: VerdictDecision::from_str(&map.extract::<&str, String>("decision")?)
                .ok_or(dcbor::Error::WrongType)?,
            decided_at: map.extract::<&str, i64>("decided_at")?,
        })
    }
}

/// An [`EquivocationVerdictRecord`] signed by the station (on behalf of the
/// jury tally, in the follow-up ticket).
pub type SignedEquivocationVerdict = SignedPayload<EquivocationVerdictRecord>;

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn addr() -> Address {
        Address::from_public_key(Keypair::generate().public_key())
    }

    #[test]
    fn request_canonical_roundtrip_and_content_address() {
        let req = CertificateRequest::new(addr(), 1_000, 3, 1_700_000_000);
        let bytes = to_canonical_bytes(req.clone());
        let decoded: CertificateRequest = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(req, decoded);
        // A decoded request recomputes the same content id.
        assert_eq!(decoded.request_id, req.request_id);
        // Changing any content field changes the id.
        let other = CertificateRequest::new(req.member, 1_001, 3, 1_700_000_000);
        assert_ne!(other.request_id, req.request_id);
    }

    #[test]
    fn certificate_canonical_roundtrip_and_content_address() {
        let req = CertificateRequest::new(addr(), 1_000, 0, 1_000);
        let cert = HeadroomCertificate::new(
            req.member,
            req.cap_centi,
            req.request_id,
            1_000,
            1_000 + 604_800,
        );
        let bytes = to_canonical_bytes(cert.clone());
        let decoded: HeadroomCertificate = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(cert, decoded);
        assert_eq!(decoded.cert_id, cert.cert_id);
    }

    #[test]
    fn return_canonical_roundtrip() {
        let ret = CertificateReturn {
            member: addr(),
            cert_id: CertId(Hash::of(b"cert")),
            returned_at: 42,
        };
        let bytes = to_canonical_bytes(ret.clone());
        let decoded: CertificateReturn = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(ret, decoded);
    }

    #[test]
    fn record_kinds_do_not_cross_decode() {
        use crate::transaction::TransactionProposal;

        // Each record's bytes must decode only as its own kind — the `kind`
        // discriminant keeps log replay unambiguous across the three new kinds
        // and the existing proposal one.
        let req = CertificateRequest::new(addr(), 1_000, 0, 1_000);
        let req_bytes = to_canonical_bytes(req.clone());
        assert!(from_canonical_bytes::<HeadroomCertificate>(&req_bytes).is_err());
        assert!(from_canonical_bytes::<CertificateReturn>(&req_bytes).is_err());

        let cert = HeadroomCertificate::new(req.member, 1_000, req.request_id, 1_000, 2_000);
        let cert_bytes = to_canonical_bytes(cert);
        assert!(from_canonical_bytes::<CertificateRequest>(&cert_bytes).is_err());
        assert!(from_canonical_bytes::<CertificateReturn>(&cert_bytes).is_err());

        let ret = CertificateReturn {
            member: addr(),
            cert_id: CertId(Hash::of(b"c")),
            returned_at: 1,
        };
        let ret_bytes = to_canonical_bytes(ret);
        assert!(from_canonical_bytes::<CertificateRequest>(&ret_bytes).is_err());
        assert!(from_canonical_bytes::<HeadroomCertificate>(&ret_bytes).is_err());

        // And a plain transaction proposal decodes as none of the cert kinds —
        // the guard that keeps `state::apply`'s decode chain unambiguous.
        let proposal_bytes =
            to_canonical_bytes(TransactionProposal::new(addr(), addr(), 300, None, 0, 1, 2));
        assert!(from_canonical_bytes::<CertificateRequest>(&proposal_bytes).is_err());
        assert!(from_canonical_bytes::<HeadroomCertificate>(&proposal_bytes).is_err());
        assert!(from_canonical_bytes::<CertificateReturn>(&proposal_bytes).is_err());
    }

    #[test]
    fn spend_admissible_until_extends_expiry_by_grace_and_skew() {
        let cfg = CreditConfig::default();
        let cert = HeadroomCertificate::new(addr(), 1_000, RequestId(Hash::of(b"r")), 1_000, 5_000);
        assert_eq!(
            spend_admissible_until(&cert, &cfg),
            5_000 + cfg.cert_delivery_grace_seconds + crate::engine::CLOCK_SKEW_TOLERANCE_SECS
        );
    }

    // --- equivocation records (T2.3.3) --------------------------------------

    use crate::transaction::TransactionProposal;
    use rrn_crypto::signed::SignedPayload;

    /// A `member`-signed cert-backed spend of `amount` against `cert`.
    fn cert_spend(
        member_kp: &Keypair,
        cert: CertId,
        amount: i64,
        nonce: u64,
    ) -> SignedPayload<TransactionProposal> {
        let member = Address::from_public_key(member_kp.public_key());
        let p = TransactionProposal::new(member, addr(), amount, None, nonce, 1_000, 9_000)
            .with_certificate(cert);
        SignedPayload::sign(p, member_kp)
    }

    /// A `member`-signed plain spend (no certificate link), for wrapping inside
    /// fork evidence where an embedded `cert_id` would confuse a byte-scan.
    fn plain_spend(
        member_kp: &Keypair,
        amount: i64,
        nonce: u64,
    ) -> SignedPayload<TransactionProposal> {
        let member = Address::from_public_key(member_kp.public_key());
        SignedPayload::sign(
            TransactionProposal::new(member, addr(), amount, None, nonce, 1_000, 9_000),
            member_kp,
        )
    }

    /// A `member`-authored outbox entry at `position` wrapping `inner`.
    fn signed_entry(
        member_kp: &Keypair,
        position: u64,
        inner: &SignedPayload<TransactionProposal>,
    ) -> SignedOutboxEntry {
        let author = Address::from_public_key(member_kp.public_key());
        let entry = OutboxEntry::wrapping(
            author,
            position,
            Hash::from_bytes([0u8; 32]),
            inner,
            position as i64,
        );
        SignedPayload::sign(entry, member_kp)
    }

    fn cert_overspend_record(member_kp: &Keypair) -> (EquivocationRecord, i64) {
        // cap 500; admitted 300 + refused 300 = 600 > cap → overspend.
        let cert = CertId(Hash::of(b"cert"));
        let cap = 500;
        let admitted = cert_spend(member_kp, cert, 300, 0);
        let refused = cert_spend(member_kp, cert, 300, 1);
        let member = Address::from_public_key(member_kp.public_key());
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::CertOverspend,
            Some(cert),
            vec![
                EvidenceItem::from_signed(&admitted),
                EvidenceItem::from_signed(&refused),
            ],
            7_000,
        );
        (record, cap)
    }

    #[test]
    fn equivocation_record_roundtrip_and_content_address() {
        let (record, _) = cert_overspend_record(&Keypair::generate());
        let bytes = to_canonical_bytes(record.clone());
        let decoded: EquivocationRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(record, decoded);
        assert_eq!(decoded.equivocation_id, record.equivocation_id);
    }

    #[test]
    fn fork_record_omits_cert_id_from_cbor() {
        let member_kp = Keypair::generate();
        let a = signed_entry(&member_kp, 0, &plain_spend(&member_kp, 100, 0));
        let b = signed_entry(&member_kp, 0, &plain_spend(&member_kp, 200, 1));
        let member = Address::from_public_key(member_kp.public_key());
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::OutboxFork,
            None,
            vec![EvidenceItem::from_signed(&a), EvidenceItem::from_signed(&b)],
            7_000,
        );
        let bytes = to_canonical_bytes(record.clone());
        // A fork record carries no `cert_id` key at all (omit-when-`None`).
        assert!(!bytes.windows(b"cert_id".len()).any(|w| w == b"cert_id"));
        let decoded: EquivocationRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn verify_evidence_accepts_a_genuine_overspend() {
        let (record, cap) = cert_overspend_record(&Keypair::generate());
        assert!(record.verify_evidence(Some(cap)));
    }

    #[test]
    fn verify_evidence_rejects_tampered_evidence_bytes() {
        let (mut record, cap) = cert_overspend_record(&Keypair::generate());
        // Flip a byte in an embedded artifact: its signature no longer verifies.
        let last = record.evidence[0].bytes.len() - 1;
        record.evidence[0].bytes[last] ^= 0x01;
        assert!(!record.verify_evidence(Some(cap)));
    }

    #[test]
    fn verify_evidence_rejects_amounts_within_cap() {
        let member_kp = Keypair::generate();
        let cert = CertId(Hash::of(b"cert"));
        let member = Address::from_public_key(member_kp.public_key());
        // 100 + 100 = 200, cap 500 → no conflict, not equivocation.
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::CertOverspend,
            Some(cert),
            vec![
                EvidenceItem::from_signed(&cert_spend(&member_kp, cert, 100, 0)),
                EvidenceItem::from_signed(&cert_spend(&member_kp, cert, 100, 1)),
            ],
            7_000,
        );
        assert!(!record.verify_evidence(Some(500)));
    }

    #[test]
    fn verify_evidence_rejects_wrong_member() {
        let member_kp = Keypair::generate();
        let (record, cap) = cert_overspend_record(&member_kp);
        // Re-label the record against a different member: the embedded proposals
        // are signed by the real member, so signer != claimed member.
        let stranger = Address::from_public_key(Keypair::generate().public_key());
        let mislabeled = EquivocationRecord::new(
            stranger,
            record.basis,
            record.cert_id,
            record.evidence.clone(),
            record.recorded_at,
        );
        assert!(!mislabeled.verify_evidence(Some(cap)));
    }

    #[test]
    fn verify_evidence_rejects_a_duplicated_spend() {
        let member_kp = Keypair::generate();
        let cert = CertId(Hash::of(b"cert"));
        let member = Address::from_public_key(member_kp.public_key());
        // The same 300-spend listed twice sums to 600 > cap 500, but it is one
        // commitment, not two — not proof of equivocation.
        let spend = cert_spend(&member_kp, cert, 300, 0);
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::CertOverspend,
            Some(cert),
            vec![
                EvidenceItem::from_signed(&spend),
                EvidenceItem::from_signed(&spend),
            ],
            7_000,
        );
        assert!(!record.verify_evidence(Some(500)));
    }

    #[test]
    fn verify_evidence_rejects_overspend_without_a_cap() {
        let (record, _) = cert_overspend_record(&Keypair::generate());
        // The cap is looked up from the on-log certificate; absent it, the claim
        // cannot be re-derived and convicts no one.
        assert!(!record.verify_evidence(None));
    }

    #[test]
    fn verify_evidence_accepts_a_genuine_fork_and_reports_its_position() {
        let member_kp = Keypair::generate();
        // Same author, same position 4, different content → a fork.
        let a = signed_entry(&member_kp, 4, &plain_spend(&member_kp, 100, 0));
        let b = signed_entry(&member_kp, 4, &plain_spend(&member_kp, 200, 1));
        let member = Address::from_public_key(member_kp.public_key());
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::OutboxFork,
            None,
            vec![EvidenceItem::from_signed(&a), EvidenceItem::from_signed(&b)],
            7_000,
        );
        assert!(record.verify_evidence(None));
        assert_eq!(record.fork_position(), Some(4));
    }

    #[test]
    fn verify_evidence_rejects_entries_at_different_positions() {
        let member_kp = Keypair::generate();
        // Different positions are not a fork (they are just two chain entries).
        let a = signed_entry(&member_kp, 0, &plain_spend(&member_kp, 100, 0));
        let b = signed_entry(&member_kp, 1, &plain_spend(&member_kp, 200, 1));
        let member = Address::from_public_key(member_kp.public_key());
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::OutboxFork,
            None,
            vec![EvidenceItem::from_signed(&a), EvidenceItem::from_signed(&b)],
            7_000,
        );
        assert!(!record.verify_evidence(None));
    }

    #[test]
    fn equivocation_kinds_do_not_cross_decode() {
        let (record, _) = cert_overspend_record(&Keypair::generate());
        let record_bytes = to_canonical_bytes(record.clone());
        let verdict = EquivocationVerdictRecord {
            equivocation_id: record.equivocation_id,
            decision: VerdictDecision::Overturn,
            decided_at: 8_000,
        };
        let verdict_bytes = to_canonical_bytes(verdict);
        // Neither decodes as the other, nor as a certificate kind.
        assert!(from_canonical_bytes::<EquivocationVerdictRecord>(&record_bytes).is_err());
        assert!(from_canonical_bytes::<EquivocationRecord>(&verdict_bytes).is_err());
        assert!(from_canonical_bytes::<CertificateRequest>(&record_bytes).is_err());
        assert!(from_canonical_bytes::<EquivocationRecord>(&record_bytes).is_ok());
    }

    #[test]
    fn verify_evidence_rejects_too_many_items() {
        let member_kp = Keypair::generate();
        let cert = CertId(Hash::of(b"cert"));
        let member = Address::from_public_key(member_kp.public_key());
        // 17 items exceeds MAX_EVIDENCE_ITEMS (16) — rejected before any semantic
        // check, so an over-cap record cannot be forced through.
        let evidence: Vec<EvidenceItem> = (0..(MAX_EVIDENCE_ITEMS as u64 + 1))
            .map(|n| EvidenceItem::from_signed(&cert_spend(&member_kp, cert, 300, n)))
            .collect();
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::CertOverspend,
            Some(cert),
            evidence,
            7_000,
        );
        assert!(!record.verify_evidence(Some(500)));
    }

    #[test]
    fn verify_evidence_rejects_an_oversized_item() {
        let member_kp = Keypair::generate();
        let cert = CertId(Hash::of(b"cert"));
        let member = Address::from_public_key(member_kp.public_key());
        // A genuine 300-spend plus a second item whose bytes exceed
        // MAX_EVIDENCE_ITEM_BYTES: the size guard rejects the record, so an
        // admitted-but-oversized artifact cannot poison a proof.
        let good = EvidenceItem::from_signed(&cert_spend(&member_kp, cert, 300, 0));
        let oversized = EvidenceItem {
            signer: good.signer,
            signature: good.signature,
            bytes: vec![0u8; MAX_EVIDENCE_ITEM_BYTES + 1],
        };
        let record = EquivocationRecord::new(
            member,
            EquivocationBasis::CertOverspend,
            Some(cert),
            vec![good, oversized],
            7_000,
        );
        assert!(!record.verify_evidence(Some(500)));
    }

    #[test]
    fn verify_evidence_rejects_a_fork_by_a_different_member() {
        let member_kp = Keypair::generate();
        let a = signed_entry(&member_kp, 0, &plain_spend(&member_kp, 100, 0));
        let b = signed_entry(&member_kp, 0, &plain_spend(&member_kp, 200, 1));
        // The entries are a genuine fork, but the record names a stranger as the
        // member — `verify_outbox_fork` requires the fork's author to be the
        // record's member.
        let stranger = Address::from_public_key(Keypair::generate().public_key());
        let record = EquivocationRecord::new(
            stranger,
            EquivocationBasis::OutboxFork,
            None,
            vec![EvidenceItem::from_signed(&a), EvidenceItem::from_signed(&b)],
            7_000,
        );
        assert!(!record.verify_evidence(None));
    }

    #[test]
    fn verdict_roundtrip() {
        let verdict = EquivocationVerdictRecord {
            equivocation_id: EquivocationId(Hash::of(b"eq")),
            decision: VerdictDecision::Confirm,
            decided_at: 8_000,
        };
        let bytes = to_canonical_bytes(verdict);
        let decoded: EquivocationVerdictRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(verdict, decoded);
    }
}
