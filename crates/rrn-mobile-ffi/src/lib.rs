//! uniffi binding surface for the Railroad Network mobile client.
//!
//! This crate is a thin, curated FFI wrapper over the pure-Rust `rrn-crypto`
//! and `rrn-identity` crates (ADR-0007). It exists so those audit-boundary
//! crates never have to carry uniffi's build machinery or its generated
//! `unsafe` FFI scaffolding — all of that is quarantined here.
//!
//! Every type below is a newtype over the real crate type. The wrappers only
//! marshal between FFI-friendly shapes (`Vec<u8>`, `String`, `Arc<T>`) and the
//! crates' native APIs (fixed-size arrays, borrowed slices); they contain no
//! cryptographic logic of their own. Two implementations would be two truth
//! sources, so there is exactly one — the Rust one, reached through here.
//!
//! # Why `unsafe` is not forbidden in this crate
//!
//! Unlike the rest of the workspace, this crate does not set
//! `#![forbid(unsafe_code)]`: `uniffi::include_scaffolding!` expands to the
//! generated `extern "C"` FFI functions, which are `unsafe` by nature. That
//! generated code is exercised by Mozilla's production users; we add none of
//! our own `unsafe`. The security-critical crypto stays in `rrn-crypto`, which
//! remains `#![deny(unsafe_code)]`.

#![warn(missing_docs)]

use std::sync::Arc;

use rrn_crypto::hash::Hash as CoreHash;
use rrn_crypto::keypair::{
    Keypair as CoreKeypair, ParseError, PublicKey as CorePublicKey, Signature as CoreSignature,
};
use rrn_identity::address::Address;

/// Error surfaced across the FFI boundary for fallible constructors.
///
/// A flat, field-less enum so it maps cleanly onto a uniffi `[Error]` and onto
/// the idiomatic error types in Swift/Kotlin/TS. It intentionally collapses the
/// crate-local error detail (exact expected/actual lengths) into stable coarse
/// variants — the mobile UI does not branch on the byte counts.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The supplied bytes were not the length this type requires.
    #[error("wrong length")]
    WrongLength,
    /// The bytes were the right length but not a valid encoding (e.g. a public
    /// key that is not a canonical curve point).
    #[error("invalid encoding")]
    InvalidEncoding,
    /// A signature failed to decode.
    #[error("invalid signature")]
    InvalidSignature,
    /// An address string was not a valid `rrn1…` address.
    #[error("invalid address")]
    InvalidAddress,
}

impl From<ParseError> for CryptoError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::WrongLength { .. } => CryptoError::WrongLength,
            ParseError::InvalidEncoding => CryptoError::InvalidEncoding,
        }
    }
}

/// FFI handle to an Ed25519 keypair. The secret seed never leaves Rust.
pub struct Keypair {
    inner: CoreKeypair,
}

impl Keypair {
    /// Generates a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            inner: CoreKeypair::generate(),
        }
    }

    /// Returns this keypair's public key.
    pub fn public_key(&self) -> Arc<PublicKey> {
        Arc::new(PublicKey {
            inner: self.inner.public_key(),
        })
    }

    /// Signs `message`, producing a detached signature.
    pub fn sign(&self, message: Vec<u8>) -> Arc<Signature> {
        Arc::new(Signature {
            inner: self.inner.sign(&message),
        })
    }
}

/// FFI handle to an Ed25519 public key.
pub struct PublicKey {
    inner: CorePublicKey,
}

impl PublicKey {
    /// Constructs a public key from its 32-byte compressed encoding, validating
    /// that the bytes decode to a canonical curve point.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, CryptoError> {
        let arr: [u8; 32] = data
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::WrongLength)?;
        Ok(Self {
            inner: CorePublicKey::from_bytes(arr)?,
        })
    }

    /// Returns the 32-byte compressed encoding of this public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Returns the bech32m `rrn1…` address for this key.
    pub fn to_address(&self) -> String {
        Address::from_public_key(self.inner).to_string()
    }

    /// Verifies a detached signature over `message`. Never throws — a bad
    /// signature, wrong key, or malformed key all return `false`.
    pub fn verify(&self, message: Vec<u8>, signature: Arc<Signature>) -> bool {
        self.inner.verify(&message, &signature.inner).is_ok()
    }
}

/// FFI handle to an Ed25519 signature.
pub struct Signature {
    inner: CoreSignature,
}

impl Signature {
    /// Constructs a signature from its 64-byte encoding. Structural only;
    /// semantic validity is checked at [`PublicKey::verify`] time.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, CryptoError> {
        let arr: [u8; 64] = data
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::WrongLength)?;
        Ok(Self {
            inner: CoreSignature::from_bytes(arr)?,
        })
    }

    /// Returns the 64-byte encoding of this signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

/// FFI handle to a Blake3 content hash.
pub struct Hash {
    inner: CoreHash,
}

impl Hash {
    /// Hashes `data` in one shot.
    pub fn of(data: Vec<u8>) -> Self {
        Self {
            inner: CoreHash::of(&data),
        }
    }

    /// Returns the 32 raw bytes of this hash.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Returns the lowercase hex encoding of this hash (64 characters).
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }
}

uniffi::include_scaffolding!("rrn_mobile_ffi");

#[cfg(test)]
mod tests {
    use super::*;

    // Smoke tests for the marshalling wrappers. The cryptographic behaviour
    // itself is tested in rrn-crypto / rrn-identity; here we only assert the
    // FFI-shaped conversions round-trip through the real types correctly. The
    // cross-platform (mobile == station) invariants land in T1.1.6.

    #[test]
    fn sign_verify_roundtrips_through_ffi_shapes() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let msg = b"the trains run on time".to_vec();
        let sig = kp.sign(msg.clone());
        assert!(pk.verify(msg, sig));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let sig = kp.sign(b"original".to_vec());
        assert!(!pk.verify(b"tampered".to_vec(), sig));
    }

    #[test]
    fn public_key_bytes_roundtrip_and_reject_bad_input() {
        let kp = Keypair::generate();
        let bytes = kp.public_key().to_bytes();
        assert_eq!(bytes.len(), 32);
        let reparsed = PublicKey::from_bytes(bytes.clone()).expect("valid pubkey bytes");
        assert_eq!(reparsed.to_bytes(), bytes);
        // Wrong length is the WrongLength variant, not a panic.
        assert!(matches!(
            PublicKey::from_bytes(vec![0u8; 31]),
            Err(CryptoError::WrongLength)
        ));
    }

    #[test]
    fn public_key_renders_bech32_address() {
        let addr = Keypair::generate().public_key().to_address();
        assert!(addr.starts_with("rrn1"), "unexpected address: {addr}");
    }

    #[test]
    fn hash_is_deterministic_hex() {
        let a = Hash::of(b"content".to_vec());
        let b = Hash::of(b"content".to_vec());
        assert_eq!(a.to_hex(), b.to_hex());
        assert_eq!(a.to_bytes().len(), 32);
        assert_eq!(a.to_hex().len(), 64);
    }
}
