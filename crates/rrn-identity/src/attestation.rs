//! The generic signed attestation: "issuer says `body` about `subject`".
//!
//! An attestation is the shape every signed social claim in Railroad Network
//! takes — vouches, credentials, transaction confirmations are all
//! [`Attestation`]s with different `kind`/`body` types. Capturing the shape once
//! means the sign/verify and canonical-encoding machinery lives in exactly one
//! place.
//!
//! # `kind` and `body` are generic
//!
//! `kind` is a type marker (typically a unit struct or small enum, e.g.
//! [`crate::vouch::VouchKind`]) and `body` is the payload specific to that kind.
//! Keeping them generic lets each attestation family define its own strongly
//! typed body without a giant shared enum.
//!
//! # Signing covers canonical CBOR, not serde
//!
//! The task spec bounded `sign` on `Serialize`. Per ADR-0002 the signature
//! covers the *canonical CBOR* of the payload (via [`SignedPayload`]), so the
//! real bound is `Into<CBOR>` — each `kind`/`body` provides an explicit
//! `From<…> for CBOR` / `TryFrom<CBOR>` mapping. `sign` is also infallible
//! (canonical encoding cannot fail), so it returns the [`SignedAttestation`]
//! directly rather than the spec's `Result`; this matches
//! [`SignedPayload::sign`].
//!
//! # Expiry is not checked here
//!
//! `expires_at: None` means "never expires"; `Some(t)` means "invalid after
//! Unix second `t`". Signature verification deliberately ignores expiry — an
//! expired attestation can still be a *valid signature* over an *expired*
//! claim, and both facts are meaningful. Callers decide what to do about
//! expiry.

use dcbor::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use serde::{Deserialize, Serialize};

use crate::address::Address;

/// A signed-able claim: issuer (the signer, carried by the envelope) asserts
/// `body` of `kind` about `subject`, valid from `issued_at` until `expires_at`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Attestation<K, B> {
    /// Type marker identifying the attestation family (e.g. "vouch").
    pub kind: K,
    /// The claim payload, specific to `kind`.
    pub body: B,
    /// Who or what this attestation is about.
    pub subject: Address,
    /// Unix seconds when the attestation was issued.
    pub issued_at: i64,
    /// Unix seconds after which it is no longer valid; `None` = never expires.
    pub expires_at: Option<i64>,
}

/// An [`Attestation`] wrapped in a signature over its canonical bytes.
pub type SignedAttestation<K, B> = SignedPayload<Attestation<K, B>>;

impl<K, B> Attestation<K, B>
where
    K: Clone + Into<CBOR>,
    B: Clone + Into<CBOR>,
{
    /// Signs this attestation with `keypair`, producing a verifiable envelope.
    ///
    /// Infallible — see the module docs on why this is not a `Result`.
    pub fn sign(self, keypair: &Keypair) -> SignedAttestation<K, B> {
        SignedPayload::sign(self, keypair)
    }
}

impl<K, B> From<Attestation<K, B>> for CBOR
where
    K: Into<CBOR>,
    B: Into<CBOR>,
{
    fn from(a: Attestation<K, B>) -> Self {
        let mut m = Map::new();
        m.insert("kind", a.kind);
        m.insert("body", a.body);
        m.insert("subject", a.subject);
        m.insert("issued_at", a.issued_at);
        // `Option<i64>` has no dCBOR mapping, so encode it explicitly: an
        // integer when present, CBOR `null` when absent. Decoding mirrors this.
        match a.expires_at {
            Some(t) => m.insert("expires_at", t),
            None => m.insert("expires_at", CBOR::null()),
        }
        m.into()
    }
}

impl<K, B> TryFrom<CBOR> for Attestation<K, B>
where
    K: TryFrom<CBOR>,
    B: TryFrom<CBOR>,
{
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(Attestation {
            kind: map.extract::<&str, K>("kind")?,
            body: map.extract::<&str, B>("body")?,
            subject: map.extract::<&str, Address>("subject")?,
            issued_at: map.extract::<&str, i64>("issued_at")?,
            // A null (or absent) value decodes to `None`; an integer to `Some`.
            expires_at: map.get::<&str, i64>("expires_at"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    // A minimal concrete attestation family for exercising the generic plumbing.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestKind;
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestBody {
        note: String,
    }

    impl From<TestKind> for CBOR {
        fn from(_: TestKind) -> Self {
            "test".into()
        }
    }
    impl TryFrom<CBOR> for TestKind {
        type Error = dcbor::Error;
        fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
            match cbor.try_into_text()?.as_str() {
                "test" => Ok(TestKind),
                _ => Err(dcbor::Error::WrongType),
            }
        }
    }
    impl From<TestBody> for CBOR {
        fn from(b: TestBody) -> Self {
            let mut m = Map::new();
            m.insert("note", b.note);
            m.into()
        }
    }
    impl TryFrom<CBOR> for TestBody {
        type Error = dcbor::Error;
        fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
            match cbor.into_case() {
                CBORCase::Map(m) => Ok(TestBody {
                    note: m.extract::<&str, String>("note")?,
                }),
                _ => Err(dcbor::Error::WrongType),
            }
        }
    }

    fn sample() -> Attestation<TestKind, TestBody> {
        let subject = Address::from_public_key(Keypair::generate().public_key());
        Attestation {
            kind: TestKind,
            body: TestBody {
                note: "hello".into(),
            },
            subject,
            issued_at: 1_700_000_000,
            expires_at: Some(1_800_000_000),
        }
    }

    #[test]
    fn sign_then_verify_roundtrips_fields() {
        let kp = Keypair::generate();
        let att = sample();
        let signed = att.clone().sign(&kp);

        assert!(signed.verify().is_ok());
        assert_eq!(signed.signer, kp.public_key());
        assert_eq!(signed.payload, att);
    }

    #[test]
    fn canonical_roundtrip_with_and_without_expiry() {
        for expires_at in [Some(1_800_000_000_i64), None] {
            let mut att = sample();
            att.expires_at = expires_at;
            let bytes = to_canonical_bytes(att.clone());
            let decoded: Attestation<TestKind, TestBody> = from_canonical_bytes(&bytes).unwrap();
            assert_eq!(att, decoded);
        }
    }
}
