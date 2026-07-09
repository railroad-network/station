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

use std::collections::HashMap;
use std::sync::Arc;

use rrn_crypto::hash::Hash as CoreHash;
use rrn_crypto::keypair::{
    Keypair as CoreKeypair, ParseError, PublicKey as CorePublicKey, Signature as CoreSignature,
};
use rrn_identity::address::{Address, AddressParseError};
use rrn_identity::wallet::{
    EncryptedWallet as CoreEncryptedWallet, WalletContents as CoreWalletContents,
    WalletError as CoreWalletError,
};

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

impl From<AddressParseError> for CryptoError {
    fn from(_: AddressParseError) -> Self {
        // The mobile UI does not branch on which way an address was malformed
        // (bad checksum vs wrong HRP vs bad length vs bad key) — it only needs
        // "this is not a valid address". The precise reason stays in Rust.
        CryptoError::InvalidAddress
    }
}

/// Whether `address` is a well-formed `rrn1…` address. Never throws.
pub fn is_valid_address(address: String) -> bool {
    address.parse::<Address>().is_ok()
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

    /// Parses a bech32m `rrn1…` address back into the public key it encodes.
    pub fn from_address(address: String) -> Result<Self, CryptoError> {
        let addr: Address = address.parse()?;
        Ok(Self {
            inner: *addr.public_key(),
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

/// Error surfaced across the FFI boundary for the fallible wallet operations.
///
/// Coarse by design: `Decrypt` covers both a wrong passphrase and a tampered
/// ciphertext — the two are not distinguished, matching the crate's own
/// posture — and the file-I/O variants of the underlying error do not occur on
/// this byte-oriented API (mobile does its own storage via the OS keychain).
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// Wrong passphrase, or the ciphertext / AEAD tag was altered.
    #[error("wrong passphrase or corrupt wallet")]
    Decrypt,
    /// The file's declared format version is not supported by this build.
    #[error("unsupported wallet version")]
    UnsupportedVersion,
    /// The bytes are not valid canonical CBOR, or do not match the wallet layout.
    #[error("corrupt wallet file")]
    Corrupt,
    /// Argon2id key derivation failed.
    #[error("key derivation failed")]
    Kdf,
}

impl From<CoreWalletError> for WalletError {
    fn from(e: CoreWalletError) -> Self {
        match e {
            CoreWalletError::Decrypt => WalletError::Decrypt,
            CoreWalletError::UnsupportedVersion(_) => WalletError::UnsupportedVersion,
            CoreWalletError::Corrupt(_) => WalletError::Corrupt,
            CoreWalletError::Kdf(_) => WalletError::Kdf,
            // The byte API never reads or writes files, so these cannot arise;
            // fold them into Corrupt rather than widen the FFI enum.
            CoreWalletError::NotFound(_) | CoreWalletError::Io(_) => WalletError::Corrupt,
        }
    }
}

/// FFI handle to a decrypted wallet's contents. The secret seed stays in Rust —
/// mobile reaches signing through [`WalletContents::keypair`], never raw bytes.
pub struct WalletContents {
    inner: CoreWalletContents,
}

impl WalletContents {
    /// Generates a brand-new identity (fresh keypair, empty metadata, `created_at`
    /// = now).
    pub fn create_new() -> Self {
        Self {
            inner: CoreWalletContents::create_new(),
        }
    }

    /// This identity's public key.
    pub fn public_key(&self) -> Arc<PublicKey> {
        Arc::new(PublicKey {
            inner: *self.inner.address.public_key(),
        })
    }

    /// The bech32m `rrn1…` address of this identity.
    pub fn address(&self) -> String {
        self.inner.address.to_string()
    }

    /// Unix seconds when the identity was created.
    pub fn created_at(&self) -> i64 {
        self.inner.created_at
    }

    /// A copy of the identity's non-secret metadata.
    pub fn metadata(&self) -> HashMap<String, String> {
        self.inner
            .metadata
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// The keypair for this identity, for signing. The secret seed never leaves
    /// Rust — this reconstructs a `Keypair` handle around the in-memory secret.
    pub fn keypair(&self) -> Arc<Keypair> {
        Arc::new(Keypair {
            inner: CoreKeypair::from_secret(self.inner.secret_key.clone()),
        })
    }
}

/// FFI handle to a sealed wallet. `to_bytes` is the `.rrnwallet` file content.
pub struct EncryptedWallet {
    inner: CoreEncryptedWallet,
}

impl EncryptedWallet {
    /// Seals `contents` under `passphrase` (argon2id + XChaCha20-Poly1305, fresh
    /// random salt and nonce).
    pub fn encrypt(contents: Arc<WalletContents>, passphrase: String) -> Result<Self, WalletError> {
        Ok(Self {
            inner: CoreEncryptedWallet::encrypt(&contents.inner, &passphrase)?,
        })
    }

    /// Parses the canonical-CBOR `.rrnwallet` bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, WalletError> {
        let inner: CoreEncryptedWallet =
            rrn_crypto::serialize::from_canonical_bytes(&data).map_err(|_| WalletError::Corrupt)?;
        Ok(Self { inner })
    }

    /// Opens the wallet, returning its decrypted contents.
    pub fn decrypt(&self, passphrase: String) -> Result<Arc<WalletContents>, WalletError> {
        Ok(Arc::new(WalletContents {
            inner: self.inner.decrypt(&passphrase)?,
        }))
    }

    /// The canonical-CBOR `.rrnwallet` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        rrn_crypto::serialize::to_canonical_bytes(self.inner.clone())
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
    fn address_roundtrips_to_identical_public_key() {
        let pk = Keypair::generate().public_key();
        let addr = pk.to_address();
        let reparsed = PublicKey::from_address(addr).expect("valid address");
        assert_eq!(reparsed.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn is_valid_address_accepts_real_and_rejects_garbage() {
        let addr = Keypair::generate().public_key().to_address();
        assert!(is_valid_address(addr.clone()));
        assert!(!is_valid_address("not-an-address".to_string()));
        // A tampered checksum (flip the last character) must be rejected, and
        // from_address must surface InvalidAddress rather than panic.
        let mut chars: Vec<char> = addr.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        assert!(!is_valid_address(tampered.clone()));
        assert!(matches!(
            PublicKey::from_address(tampered),
            Err(CryptoError::InvalidAddress)
        ));
    }

    #[test]
    fn hash_is_deterministic_hex() {
        let a = Hash::of(b"content".to_vec());
        let b = Hash::of(b"content".to_vec());
        assert_eq!(a.to_hex(), b.to_hex());
        assert_eq!(a.to_bytes().len(), 32);
        assert_eq!(a.to_hex().len(), 64);
    }

    const PASS: &str = "correct horse battery staple";

    #[test]
    fn wallet_encrypt_decrypt_roundtrips_through_ffi_shapes() {
        let contents = Arc::new(WalletContents::create_new());
        let address = contents.address();
        let pubkey = contents.public_key().to_bytes();

        let sealed = EncryptedWallet::encrypt(contents, PASS.to_string()).expect("encrypt");
        let bytes = sealed.to_bytes();

        // Reparse the bytes (the `.rrnwallet` file) and decrypt to the same id.
        let reparsed = EncryptedWallet::from_bytes(bytes).expect("from_bytes");
        let opened = reparsed.decrypt(PASS.to_string()).expect("decrypt");
        assert_eq!(opened.address(), address);
        assert_eq!(opened.public_key().to_bytes(), pubkey);
    }

    #[test]
    fn wallet_wrong_passphrase_is_decrypt_error() {
        let sealed =
            EncryptedWallet::encrypt(Arc::new(WalletContents::create_new()), PASS.to_string())
                .unwrap();
        assert!(matches!(
            sealed.decrypt("wrong passphrase".to_string()),
            Err(WalletError::Decrypt)
        ));
    }

    #[test]
    fn wallet_tampered_bytes_are_rejected() {
        let sealed =
            EncryptedWallet::encrypt(Arc::new(WalletContents::create_new()), PASS.to_string())
                .unwrap();
        let mut bytes = sealed.to_bytes();
        *bytes.last_mut().unwrap() ^= 0x01;
        // Either the CBOR no longer parses, or it parses but the AEAD tag fails.
        let opened = EncryptedWallet::from_bytes(bytes).and_then(|w| w.decrypt(PASS.to_string()));
        assert!(opened.is_err());
    }

    #[test]
    fn wallet_garbage_bytes_are_corrupt_error() {
        assert!(matches!(
            EncryptedWallet::from_bytes(vec![0xff, 0x00, 0x13]),
            Err(WalletError::Corrupt)
        ));
    }

    #[test]
    fn wallet_keypair_signs_and_the_public_key_verifies() {
        let contents = WalletContents::create_new();
        let kp = contents.keypair();
        let pk = contents.public_key();
        let msg = b"spend from this identity".to_vec();
        let sig = kp.sign(msg.clone());
        assert!(pk.verify(msg, sig));
        // The keypair's own public key matches the wallet's.
        assert_eq!(kp.public_key().to_bytes(), pk.to_bytes());
    }
}
