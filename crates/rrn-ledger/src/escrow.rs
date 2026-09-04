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
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
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
}
