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

use std::collections::HashSet;

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

/// A payload co-signed by several keys: N `(signer, signature)` pairs over the
/// *same* canonical payload bytes.
///
/// This is [`SignedPayload`]'s N-of-M sibling. It exists because some documents
/// — a community's Charter above all — must be authorized by more than one key,
/// and overloading `SignedPayload` (one signer, one signature) to sometimes mean
/// "several" would blur a security-critical type. Each `signatures[i]` is a
/// signature by `signers[i]` over `to_canonical_bytes(&payload)`, exactly the
/// same content-addressed model as `SignedPayload`, so the two share the CBOR
/// encoding and the cross-platform fixtures extend rather than fork.
///
/// # Threshold-agnostic by design
///
/// The primitive never decides *how many* valid signers are enough — it verifies
/// the pairs and reports the set of distinct valid signers, and the caller
/// applies its own threshold. The Charter, for instance, requires the valid
/// signers to be a ≥ 75 % subset of its declared founders (ADR-0012); the crypto
/// layer supplies verification, the Charter supplies the rule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MultiSignedPayload<T> {
    /// The co-signed value.
    pub payload: T,
    /// The public keys of the co-signers; `signers[i]` produced `signatures[i]`.
    pub signers: Vec<PublicKey>,
    /// Signatures over `to_canonical_bytes(&payload)`, positionally paired with
    /// [`signers`](Self::signers).
    pub signatures: Vec<Signature>,
}

/// Error verifying a [`MultiSignedPayload`].
///
/// These are *structural* faults that make the envelope ill-formed. An
/// individual signature that simply does not verify is **not** an error — it is
/// excluded from the returned set of valid signers, keeping the primitive
/// threshold-agnostic.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum MultiVerifyError {
    /// The signer and signature lists are different lengths, so the positional
    /// pairing is undefined.
    #[error("signer/signature count mismatch: {signers} signers, {signatures} signatures")]
    CountMismatch {
        /// Number of signers supplied.
        signers: usize,
        /// Number of signatures supplied.
        signatures: usize,
    },
    /// The same signer appears more than once. Rejected so a single key cannot
    /// be double-counted toward a threshold.
    #[error("a signer appears more than once")]
    DuplicateSigner,
}

impl<T> MultiSignedPayload<T>
where
    T: Clone + Into<CBOR>,
{
    /// Co-signs `payload` with each keypair in `keypairs`, in order.
    ///
    /// Each keypair signs the same canonical payload bytes. Passing the same
    /// keypair twice produces a duplicate signer, which [`verify`](Self::verify)
    /// then rejects — the caller is responsible for supplying distinct signers.
    pub fn sign(payload: T, keypairs: &[Keypair]) -> Self {
        let bytes = to_canonical_bytes(payload.clone());
        let signers = keypairs.iter().map(Keypair::public_key).collect();
        let signatures = keypairs.iter().map(|kp| kp.sign(&bytes)).collect();
        Self {
            payload,
            signers,
            signatures,
        }
    }

    /// Adds one more co-signer's signature over the payload.
    ///
    /// This is the incremental path — a Charter collected one founder at a time,
    /// or co-signed on a phone after the fact (ADR-0012) — as opposed to
    /// [`sign`](Self::sign), which takes every keypair at once.
    pub fn add_signature(&mut self, keypair: &Keypair) {
        let bytes = to_canonical_bytes(self.payload.clone());
        self.signers.push(keypair.public_key());
        self.signatures.push(keypair.sign(&bytes));
    }

    /// Verifies every `(signer, signature)` pair against the payload's canonical
    /// bytes and returns the **distinct valid signers**, in signer-list order.
    ///
    /// A count mismatch or a duplicated signer is a hard [`MultiVerifyError`]; an
    /// individual signature that fails to verify is silently excluded, so the
    /// returned set contains exactly those signers who provably signed *this*
    /// payload. The caller compares that set against its own threshold.
    pub fn verify(&self) -> Result<Vec<PublicKey>, MultiVerifyError> {
        if self.signers.len() != self.signatures.len() {
            return Err(MultiVerifyError::CountMismatch {
                signers: self.signers.len(),
                signatures: self.signatures.len(),
            });
        }
        let mut seen = HashSet::with_capacity(self.signers.len());
        for signer in &self.signers {
            if !seen.insert(signer) {
                return Err(MultiVerifyError::DuplicateSigner);
            }
        }
        let bytes = to_canonical_bytes(self.payload.clone());
        let valid = self
            .signers
            .iter()
            .zip(&self.signatures)
            .filter(|(signer, sig)| signer.verify(&bytes, sig).is_ok())
            .map(|(signer, _)| *signer)
            .collect();
        Ok(valid)
    }

    /// Returns the Blake3 hash of the payload's canonical bytes — a stable
    /// content address for the co-signed value, independent of the envelope and
    /// of how many signatures it carries.
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

    // --- MultiSignedPayload ------------------------------------------------

    #[test]
    fn multi_all_valid_returns_every_signer() {
        let kps = [
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        ];
        let signed = MultiSignedPayload::sign(sample(), &kps);
        let valid = signed.verify().unwrap();
        // Distinct valid signers, in signer-list order.
        let expected: Vec<_> = kps.iter().map(Keypair::public_key).collect();
        assert_eq!(valid, expected);
    }

    #[test]
    fn multi_excludes_a_bad_signature_but_keeps_the_rest() {
        let kps = [
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        ];
        let mut signed = MultiSignedPayload::sign(sample(), &kps);
        // Corrupt the middle signature; the other two must still count.
        signed.signatures[1] = Keypair::generate().sign(b"unrelated");
        let valid = signed.verify().unwrap();
        assert_eq!(valid, vec![kps[0].public_key(), kps[2].public_key()]);
    }

    #[test]
    fn multi_rejects_duplicate_signer() {
        let kp = Keypair::generate();
        // The same key signing twice must not be double-counted.
        let signed = MultiSignedPayload::sign(sample(), &[kp.clone(), kp]);
        assert_eq!(signed.verify(), Err(MultiVerifyError::DuplicateSigner));
    }

    #[test]
    fn multi_rejects_count_mismatch() {
        let kps = [Keypair::generate(), Keypair::generate()];
        let mut signed = MultiSignedPayload::sign(sample(), &kps);
        signed.signatures.pop();
        assert_eq!(
            signed.verify(),
            Err(MultiVerifyError::CountMismatch {
                signers: 2,
                signatures: 1,
            })
        );
    }

    #[test]
    fn multi_add_signature_extends_the_set() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let mut signed = MultiSignedPayload::sign(sample(), std::slice::from_ref(&a));
        signed.add_signature(&b);
        assert_eq!(
            signed.verify().unwrap(),
            vec![a.public_key(), b.public_key()]
        );
    }

    #[test]
    fn multi_mutated_payload_invalidates_all_signatures() {
        let kps = [Keypair::generate(), Keypair::generate()];
        let mut signed = MultiSignedPayload::sign(sample(), &kps);
        signed.payload.n += 1;
        // Every signature was over the old payload, so none verify now.
        assert_eq!(signed.verify().unwrap(), Vec::new());
    }

    #[test]
    fn multi_empty_verifies_to_no_signers() {
        let signed: MultiSignedPayload<Msg> = MultiSignedPayload::sign(sample(), &[]);
        assert_eq!(signed.verify().unwrap(), Vec::new());
    }

    #[test]
    fn multi_payload_hash_matches_canonical_payload_hash() {
        let kp = Keypair::generate();
        let signed = MultiSignedPayload::sign(sample(), &[kp]);
        assert_eq!(
            signed.payload_hash(),
            Hash::of(&to_canonical_bytes(sample()))
        );
    }

    proptest! {
        #[test]
        fn multi_envelope_roundtrips_through_serde(n in any::<u64>(), text in ".*") {
            let kps = [Keypair::generate(), Keypair::generate()];
            let signed = MultiSignedPayload::sign(Msg { n, text }, &kps);
            let json = serde_json::to_string(&signed).unwrap();
            let restored: MultiSignedPayload<Msg> = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&restored.payload, &signed.payload);
            prop_assert_eq!(restored.verify().unwrap().len(), 2);
        }
    }
}
