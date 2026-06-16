//! [`SignedPayload`]: a value plus a signature over its canonical bytes.
//!
//! Almost everything that flows through Railroad Network is "some data plus a
//! signature." This module captures that pattern once, so individual message
//! types never reimplement the sign/verify dance.
//!
//! # What is signed
//!
//! The signature covers `to_canonical_bytes(&payload)` — the deterministic
//! CBOR encoding of the *payload only* — never the wire form of the
//! `SignedPayload` envelope itself. This is why the envelope can be
//! re-serialized, transported, and reordered freely without invalidating the
//! signature: verification re-derives the canonical payload bytes and checks
//! them, so the only thing that matters is the payload's logical value.
//!
//! # Requirements on `T`
//!
//! Signing and verifying require `T: Clone + Into<CBOR>` (to produce canonical
//! bytes); the envelope's serde derives require `T: Serialize`/`Deserialize`
//! for wire transport. A payload type with non-deterministic or
//! interior-mutable serialization would make signatures spuriously fail — keep
//! `Into<CBOR>` a pure function of the value.

use dcbor::CBOR;
use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::keypair::{Keypair, PublicKey, Signature, VerifyError};
use crate::serialize::to_canonical_bytes;

/// A payload bundled with the public key of its signer and a signature over
/// the payload's canonical CBOR bytes.
///
/// `PartialEq`/`Eq` compare the payload, signer, and signature structurally;
/// two envelopes are equal iff all three match. Downstream state machines that
/// embed signed envelopes in an `Eq` enum (e.g. `rrn-ledger`'s
/// `TransactionState`) rely on this.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedPayload<T> {
    /// The signed value.
    pub payload: T,
    /// The public key that produced [`signature`](Self::signature).
    pub signer: PublicKey,
    /// Signature over `to_canonical_bytes(&payload)`.
    pub signature: Signature,
}

/// Convenient alias for [`SignedPayload`].
pub type Signed<T> = SignedPayload<T>;

impl<T> SignedPayload<T>
where
    T: Clone + Into<CBOR>,
{
    /// Signs `payload` with `keypair`, producing a verifiable envelope.
    ///
    /// Infallible: producing canonical bytes from a value cannot fail (see
    /// [`crate::serialize`]), so there is no serialization-error path. (The
    /// task spec's `SignError` is therefore omitted — under the deterministic
    /// CBOR model adopted in ADR-0002 it would be unconstructible.)
    pub fn sign(payload: T, keypair: &Keypair) -> Self {
        let signature = keypair.sign(&to_canonical_bytes(payload.clone()));
        Self {
            payload,
            signer: keypair.public_key(),
            signature,
        }
    }

    /// Verifies that [`signature`](Self::signature) is a valid signature by
    /// [`signer`](Self::signer) over the current payload.
    ///
    /// Re-serializes the payload internally, so any modification to `payload`
    /// after signing is detected as a verification failure.
    pub fn verify(&self) -> Result<(), VerifyError> {
        let bytes = to_canonical_bytes(self.payload.clone());
        self.signer.verify(&bytes, &self.signature)
    }

    /// Returns the Blake3 hash of the payload's canonical bytes — a stable
    /// content address for the signed value, independent of the envelope.
    pub fn payload_hash(&self) -> Hash {
        Hash::of(&to_canonical_bytes(self.payload.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcbor::prelude::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        n: u64,
        text: String,
    }

    impl From<Msg> for CBOR {
        fn from(v: Msg) -> Self {
            let mut m = Map::new();
            m.insert("n", v.n);
            m.insert("text", v.text);
            m.into()
        }
    }

    impl TryFrom<CBOR> for Msg {
        type Error = dcbor::Error;
        fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
            match cbor.into_case() {
                CBORCase::Map(map) => Ok(Msg {
                    n: map.extract::<&str, u64>("n")?,
                    text: map.extract::<&str, String>("text")?,
                }),
                _ => Err(dcbor::Error::WrongType),
            }
        }
    }

    fn sample() -> Msg {
        Msg {
            n: 42,
            text: "settle".into(),
        }
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let kp = Keypair::generate();
        let signed = SignedPayload::sign(sample(), &kp);
        assert!(signed.verify().is_ok());
        assert_eq!(signed.signer, kp.public_key());
    }

    #[test]
    fn mutated_payload_fails_verify() {
        let kp = Keypair::generate();
        let mut signed = SignedPayload::sign(sample(), &kp);
        signed.payload.n += 1;
        assert_eq!(signed.verify(), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn swapped_signer_fails_verify() {
        let kp = Keypair::generate();
        let other = Keypair::generate();
        let mut signed = SignedPayload::sign(sample(), &kp);
        signed.signer = other.public_key();
        assert_eq!(signed.verify(), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn payload_hash_is_canonical_payload_hash() {
        let kp = Keypair::generate();
        let signed = SignedPayload::sign(sample(), &kp);
        assert_eq!(
            signed.payload_hash(),
            Hash::of(&to_canonical_bytes(sample()))
        );
    }

    proptest! {
        #[test]
        fn envelope_roundtrips_through_serde(n in any::<u64>(), text in ".*") {
            let kp = Keypair::generate();
            let signed = SignedPayload::sign(Msg { n, text }, &kp);

            // The envelope travels over a non-canonical serde format (JSON
            // here); verification must still succeed on the far side.
            let json = serde_json::to_string(&signed).unwrap();
            let restored: SignedPayload<Msg> = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(&restored.payload, &signed.payload);
            prop_assert!(restored.verify().is_ok());
        }
    }
}
