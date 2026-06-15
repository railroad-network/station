//! Ed25519 keypair generation, signing, and verification.
//!
//! Every signed message in Railroad Network is produced and checked here. The
//! public API is expressed in plain byte arrays and crate-local types —
//! `ed25519-dalek` is wrapped, never exposed — so the signing backend can be
//! swapped (behind an ADR) without rippling through downstream crates.
//!
//! Verification uses `verify_strict`, which rejects non-canonical `S` values
//! and small-order public keys, closing the ed25519 signature-malleability
//! gap. See `docs/threat-model.md` (`rrn-crypto`).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An Ed25519 keypair: a secret signing key plus its derived public key.
#[derive(Clone)]
pub struct Keypair {
    secret: SecretKey,
}

/// An Ed25519 secret (signing) key.
///
/// Stored as the raw 32-byte seed so it can be zeroized in place; the expanded
/// `SigningKey` is reconstructed on demand for signing. The seed is zeroized on
/// drop. `SecretKey` deliberately does **not** implement
/// `serde::Serialize`/`Deserialize`: secrets must never be serialized by
/// accident. Persisting a secret key is a separate, explicit concern handled by
/// the identity wallet (argon2id + XChaCha20-Poly1305).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Reconstructs the expanded `ed25519-dalek` signing key from the seed.
    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }

    /// Constructs a secret key from its raw 32-byte Ed25519 seed.
    ///
    /// This is the deliberate, explicit path for *restoring* a persisted
    /// secret key — `SecretKey` has no serde impl precisely so that secrets are
    /// never serialized by accident, so this byte constructor is the only way
    /// back in. Its sole intended caller is the identity wallet, which encrypts
    /// the seed at rest (argon2id + XChaCha20-Poly1305); keeping the byte API
    /// here, rather than a `serde` derive, keeps every persistence site
    /// greppable and inside the audit boundary.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// Returns a copy of the raw 32-byte Ed25519 seed.
    ///
    /// The returned array **is** the private key: treat it as secret material
    /// and zeroize the copy once done. Used only by the wallet to encrypt the
    /// seed at rest; nothing else should pull the bytes out in the clear.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// An Ed25519 public (verifying) key — 32 compressed bytes, validated as a
/// canonical curve point at construction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

/// An Ed25519 signature (64 bytes: `R` ‖ `S`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

/// Error verifying a signature.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature does not verify against this key and message (also
    /// returned for non-canonical or malleable signatures).
    #[error("signature verification failed")]
    InvalidSignature,
    /// The public key could not be decoded as a valid curve point.
    #[error("malformed public key")]
    MalformedKey,
}

/// Error parsing a key or signature from bytes.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input did not have the expected byte length.
    #[error("wrong length: expected {expected} bytes, got {actual}")]
    WrongLength {
        /// Number of bytes the type requires.
        expected: usize,
        /// Number of bytes actually supplied.
        actual: usize,
    },
    /// The bytes were the right length but not a valid encoding (e.g. a public
    /// key that is not a canonical curve point, or invalid base64).
    #[error("invalid encoding")]
    InvalidEncoding,
}

impl Keypair {
    /// Generates a fresh keypair using the operating-system CSPRNG (`OsRng`).
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self {
            secret: SecretKey(signing.to_bytes()),
        }
    }

    /// Reconstructs a keypair from a secret key (the public key is derived).
    pub fn from_secret(secret: SecretKey) -> Self {
        Self { secret }
    }

    /// Returns this keypair's public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.secret.signing_key().verifying_key().to_bytes())
    }

    /// Returns a reference to this keypair's secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Signs a message, producing a detached signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.secret.signing_key().sign(msg).to_bytes())
    }
}

impl PublicKey {
    /// Constructs a public key from its 32-byte compressed encoding, validating
    /// that the bytes decode to a canonical curve point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ParseError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| ParseError::InvalidEncoding)?;
        Ok(Self(bytes))
    }

    /// Returns the 32-byte compressed encoding of this public key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Verifies a detached signature over `msg`.
    ///
    /// Uses `verify_strict`, rejecting non-canonical `S` and small-order keys.
    /// Returns `Err` — never panics — on any mismatch.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), VerifyError> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| VerifyError::MalformedKey)?;
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        vk.verify_strict(msg, &dalek_sig)
            .map_err(|_| VerifyError::InvalidSignature)
    }
}

impl Signature {
    /// Constructs a signature from its 64-byte encoding.
    ///
    /// All 64-byte inputs are structurally accepted; semantic validity (the
    /// `R`/`S` relationship) is checked at [`PublicKey::verify`] time.
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, ParseError> {
        Ok(Self(bytes))
    }

    /// Returns the 64-byte encoding of this signature.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

// --- Debug impls: never print secret material ------------------------------

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &self.public_key())
            .field("secret_key", &self.secret)
            .finish()
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({})", BASE64.encode(self.0))
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({})", BASE64.encode(self.0))
    }
}

// --- serde: base64 string form for the wire envelope -----------------------
//
// These are for general (non-canonical) serialization — JSON wire envelopes,
// config, logs. The *signed* bytes never go through serde; see `serialize`.

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = BASE64.decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("public key must be 32 bytes"))?;
        PublicKey::from_bytes(arr).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = BASE64.decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 64] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))?;
        Signature::from_bytes(arr).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn debug_secret_key_is_redacted() {
        let kp = Keypair::generate();
        assert_eq!(format!("{:?}", kp.secret_key()), "SecretKey([REDACTED])");

        // The raw key bytes must not leak through any Debug surface.
        let raw = kp.secret_key().0;
        let hex_bytes = hex::encode(raw);
        let b64_bytes = BASE64.encode(raw);
        for surface in [format!("{kp:?}"), format!("{:?}", kp.secret_key())] {
            assert!(
                !surface.contains(&hex_bytes),
                "hex key bytes leaked: {surface}"
            );
            assert!(
                !surface.contains(&b64_bytes),
                "base64 key bytes leaked: {surface}"
            );
        }
    }

    #[test]
    fn secret_key_byte_roundtrip_preserves_identity() {
        // The wallet's persistence path: pull the seed out, put it back, and
        // the reconstructed keypair must be the same identity (same public key)
        // and produce the same signatures.
        let kp = Keypair::generate();
        let restored = Keypair::from_secret(SecretKey::from_bytes(kp.secret_key().to_bytes()));
        assert_eq!(kp.public_key(), restored.public_key());
        let sig = restored.sign(b"persisted");
        assert!(kp.public_key().verify(b"persisted", &sig).is_ok());
    }

    #[test]
    fn public_key_byte_roundtrip() {
        let pk = Keypair::generate().public_key();
        let back = PublicKey::from_bytes(pk.to_bytes()).unwrap();
        assert_eq!(pk, back);
    }

    #[test]
    fn rejects_off_curve_public_key() {
        // dalek's decompression rejects byte strings whose y-coordinate is not
        // on the curve (~half of all inputs). Find one and confirm from_bytes
        // surfaces it as ParseError::InvalidEncoding rather than accepting it.
        let mut bytes = [0u8; 32];
        let off_curve = (0u8..=255).find_map(|i| {
            bytes[0] = i;
            PublicKey::from_bytes(bytes).err().map(|e| (i, e))
        });
        let (i, err) = off_curve.expect("expected some off-curve encoding to be rejected");
        assert_eq!(err, ParseError::InvalidEncoding, "first byte {i:#x}");
    }

    #[test]
    fn serde_roundtrip_public_key_and_signature() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let sig = kp.sign(b"hello");

        let pk_json = serde_json::to_string(&pk).unwrap();
        assert_eq!(pk, serde_json::from_str::<PublicKey>(&pk_json).unwrap());

        let sig_json = serde_json::to_string(&sig).unwrap();
        assert_eq!(sig, serde_json::from_str::<Signature>(&sig_json).unwrap());
    }

    proptest! {
        #[test]
        fn sign_then_verify_succeeds(msg in proptest::collection::vec(any::<u8>(), 0..512)) {
            let kp = Keypair::generate();
            let sig = kp.sign(&msg);
            prop_assert!(kp.public_key().verify(&msg, &sig).is_ok());
        }

        #[test]
        fn flipped_signature_bit_fails(
            msg in proptest::collection::vec(any::<u8>(), 0..512),
            byte in 0usize..64,
            bit in 0u8..8,
        ) {
            let kp = Keypair::generate();
            let sig = kp.sign(&msg);
            let mut bytes = sig.to_bytes();
            bytes[byte] ^= 1 << bit;
            let tampered = Signature::from_bytes(bytes).unwrap();
            prop_assert!(kp.public_key().verify(&msg, &tampered).is_err());
        }

        #[test]
        fn flipped_message_bit_fails(
            msg in proptest::collection::vec(any::<u8>(), 1..512),
            bit in 0u8..8,
            byte_seed in any::<usize>(),
        ) {
            let kp = Keypair::generate();
            let sig = kp.sign(&msg);
            let mut tampered = msg.clone();
            let idx = byte_seed % tampered.len();
            tampered[idx] ^= 1 << bit;
            prop_assert!(kp.public_key().verify(&tampered, &sig).is_err());
        }

        #[test]
        fn wrong_key_fails(msg in proptest::collection::vec(any::<u8>(), 0..256)) {
            let kp = Keypair::generate();
            let other = Keypair::generate();
            let sig = kp.sign(&msg);
            prop_assert!(other.public_key().verify(&msg, &sig).is_err());
        }
    }
}
