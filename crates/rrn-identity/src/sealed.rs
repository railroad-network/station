//! A general anonymous sealed box: encrypt bytes so that **only** one recipient's
//! Ed25519 identity key can open them, with no sender authentication of its own.
//!
//! This is the `libsodium`-`crypto_box_seal`–style construction that recovery
//! already uses to seal shards ([`crate::recovery::encryption`]), factored out
//! so the mobile↔station transport (ADR-0008) and recovery share **one** audited
//! sealing path rather than two. The transport signs *before* sealing to get
//! sender authentication (see the station's `rpc_envelope`); this layer only
//! provides confidentiality-to-a-recipient.
//!
//! ```text
//! ephemeral_x = random X25519 keypair
//! shared      = X25519(ephemeral_x.secret, recipient_x.public)      // ECDH
//! key         = blake3::derive_key(context, shared ‖ eph_pub ‖ recipient_pub)
//! ciphertext  = XChaCha20Poly1305(key, nonce).encrypt(plaintext)
//! ```
//!
//! The `context` string is the blake3 KDF domain separator: two callers that
//! pass different contexts derive independent keys, so a box sealed for one
//! purpose (a recovery shard) can never be opened as another (a transport
//! envelope), even to the same recipient. The KDF input binds the whole ECDH
//! transcript — `shared ‖ ephemeral_pub ‖ recipient_pub` — so a box cannot be
//! re-pointed at a different recipient or ephemeral key.
//!
//! Identity keys double as key-exchange keys via the standard Ed25519→X25519
//! birational map (`VerifyingKey::to_montgomery` / `SigningKey::to_scalar_bytes`);
//! this is acceptable because a recipient is identified by exactly one long-term
//! key. See [`crate::recovery::encryption`] for the fuller rationale — this
//! module is that module's mechanism, generalized to arbitrary plaintext.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey, StaticSecret};
use zeroize::Zeroize;

use rrn_crypto::keypair::{PublicKey, SecretKey};

/// blake3 KDF domain-separation context for the mobile↔station transport sealed
/// envelope (ADR-0008, T1.3.4). Distinct from the recovery-shard context
/// (`recovery::encryption::KDF_CONTEXT`) so the two sealing purposes derive
/// independent keys and a box sealed for one can never open as the other. Shared
/// here because both `rrn-station` (which opens requests / seals responses) and
/// `rrn-mobile-ffi` (which seals requests / opens responses) reach this crate;
/// changing the string is a wire break for every paired mobile.
pub const TRANSPORT_CONTEXT: &str = "railroad-network mobile-station transport v1 \
    x25519-ecdh blake3-derive-key xchacha20poly1305";

/// Length of the ephemeral X25519 public key.
const EPH_LEN: usize = 32;
/// Length of the XChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 24;
/// Length of the XChaCha20-Poly1305 authentication tag.
const TAG_LEN: usize = 16;
/// Smallest well-formed sealed box: `eph ‖ nonce ‖ tag` (empty plaintext).
const MIN_SEALED_LEN: usize = EPH_LEN + NONCE_LEN + TAG_LEN;

/// Errors from sealing or opening.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The recipient's public key is not a valid Ed25519 point and cannot be
    /// converted to X25519. (Unreachable for an `rrn-crypto` [`PublicKey`],
    /// which is validated at construction, but surfaced rather than panicked.)
    #[error("recipient public key is not a valid Ed25519 point")]
    MalformedRecipientKey,
    /// The sealed bytes are too short to contain an ephemeral key, nonce, and
    /// tag — malformed framing, not a crypto failure.
    #[error("sealed box is too short to be well-formed")]
    Truncated,
    /// Decryption failed: the wrong recipient key, the wrong context, or a
    /// tampered box. Deliberately does not distinguish these.
    #[error("sealed box decryption failed (wrong key, wrong context, or corrupt box)")]
    Decrypt,
}

/// A sealed box: an ephemeral X25519 public key, a nonce, and AEAD ciphertext.
///
/// Both the sealing and opening sides live in this crate (the station opens
/// with `rrn-identity` directly; the mobile opens through `rrn-mobile-ffi`,
/// which also wraps this crate), so the on-wire framing is a compact concat via
/// [`to_bytes`](Self::to_bytes) / [`from_bytes`](Self::from_bytes) with no CBOR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBox {
    /// The ephemeral X25519 public key for this box's ECDH.
    pub ephemeral_pubkey: [u8; 32],
    /// The XChaCha20-Poly1305 nonce (24 bytes; random per box).
    pub nonce: [u8; 24],
    /// The AEAD ciphertext (sealed plaintext plus the 16-byte tag).
    pub ciphertext: Vec<u8>,
}

impl SealedBox {
    /// Serializes to `eph(32) ‖ nonce(24) ‖ ciphertext` — the transport wire form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EPH_LEN + NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.ephemeral_pubkey);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parses the `eph ‖ nonce ‖ ciphertext` framing. [`SealError::Truncated`]
    /// if there is not even room for the fixed header and an AEAD tag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        if bytes.len() < MIN_SEALED_LEN {
            return Err(SealError::Truncated);
        }
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&bytes[..EPH_LEN]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[EPH_LEN..EPH_LEN + NONCE_LEN]);
        let ciphertext = bytes[EPH_LEN + NONCE_LEN..].to_vec();
        Ok(SealedBox {
            ephemeral_pubkey,
            nonce,
            ciphertext,
        })
    }
}

/// The recipient's X25519 public key, converted from their Ed25519 identity key.
fn recipient_x25519_public(pk: &PublicKey) -> Result<XPublicKey, SealError> {
    let vk =
        VerifyingKey::from_bytes(&pk.to_bytes()).map_err(|_| SealError::MalformedRecipientKey)?;
    Ok(XPublicKey::from(vk.to_montgomery().to_bytes()))
}

/// The recipient's X25519 secret (and matching public) from their Ed25519 seed.
/// The public is recomputed so the KDF transcript matches what [`seal`] bound.
fn recipient_x25519_secret(sk: &SecretKey) -> (StaticSecret, XPublicKey) {
    let mut seed = sk.to_bytes();
    let signing = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let static_secret = StaticSecret::from(signing.to_scalar_bytes());
    let public = XPublicKey::from(signing.verifying_key().to_montgomery().to_bytes());
    (static_secret, public)
}

/// Derives the 32-byte AEAD key, binding `context` and the whole ECDH transcript.
fn derive_key(
    context: &str,
    shared: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
) -> [u8; 32] {
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(shared);
    material[32..64].copy_from_slice(ephemeral_pub);
    material[64..].copy_from_slice(recipient_pub);
    let key = blake3::derive_key(context, &material);
    material.zeroize();
    key
}

/// Seals `plaintext` so only the holder of `recipient`'s secret key can open it,
/// under the given `context` (a blake3 KDF domain-separation string).
pub fn seal(
    recipient: &PublicKey,
    plaintext: &[u8],
    context: &str,
) -> Result<SealedBox, SealError> {
    let recipient_x_pub = recipient_x25519_public(recipient)?;

    // Fresh ephemeral keypair; ECDH against the recipient's X25519 public key.
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub = XPublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_x_pub);

    let mut key = derive_key(
        context,
        shared.as_bytes(),
        ephemeral_pub.as_bytes(),
        recipient_x_pub.as_bytes(),
    );

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key is valid");
    let result = cipher.encrypt(XNonce::from_slice(&nonce), plaintext);
    key.zeroize();
    let ciphertext = result.map_err(|_| SealError::Decrypt)?;

    Ok(SealedBox {
        ephemeral_pubkey: *ephemeral_pub.as_bytes(),
        nonce,
        ciphertext,
    })
}

/// Opens a [`SealedBox`] with the recipient's secret key, under `context`.
///
/// Returns [`SealError::Decrypt`] for the wrong key, the wrong context, or any
/// tampering, and never yields wrong plaintext on failure (the AEAD tag is the
/// integrity check).
pub fn open(
    sealed: &SealedBox,
    recipient_secret: &SecretKey,
    context: &str,
) -> Result<Vec<u8>, SealError> {
    let (static_secret, recipient_x_pub) = recipient_x25519_secret(recipient_secret);
    let ephemeral_pub = XPublicKey::from(sealed.ephemeral_pubkey);
    let shared = static_secret.diffie_hellman(&ephemeral_pub);

    let mut key = derive_key(
        context,
        shared.as_bytes(),
        &sealed.ephemeral_pubkey,
        recipient_x_pub.as_bytes(),
    );

    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key is valid");
    let result = cipher.decrypt(
        XNonce::from_slice(&sealed.nonce),
        sealed.ciphertext.as_slice(),
    );
    key.zeroize();
    result.map_err(|_| SealError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    const CTX: &str = "railroad-network sealed-box test context v1";

    #[test]
    fn roundtrips_arbitrary_plaintext() {
        let recipient = Keypair::generate();
        for plaintext in [
            b"".as_slice(),
            b"a".as_slice(),
            b"the quick brown fox jumps over the lazy dog".as_slice(),
            &[0xAB; 4096],
        ] {
            let sealed = seal(&recipient.public_key(), plaintext, CTX).unwrap();
            let opened = open(&sealed, recipient.secret_key(), CTX).unwrap();
            assert_eq!(opened, plaintext);
        }
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let recipient = Keypair::generate();
        let wrong = Keypair::generate();
        let sealed = seal(&recipient.public_key(), b"secret", CTX).unwrap();
        assert_eq!(
            open(&sealed, wrong.secret_key(), CTX).unwrap_err(),
            SealError::Decrypt
        );
    }

    #[test]
    fn wrong_context_fails() {
        let recipient = Keypair::generate();
        let sealed = seal(&recipient.public_key(), b"secret", CTX).unwrap();
        assert_eq!(
            open(&sealed, recipient.secret_key(), "a different context").unwrap_err(),
            SealError::Decrypt
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let recipient = Keypair::generate();
        let mut sealed = seal(&recipient.public_key(), b"secret", CTX).unwrap();
        *sealed.ciphertext.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            open(&sealed, recipient.secret_key(), CTX).unwrap_err(),
            SealError::Decrypt
        );
    }

    #[test]
    fn tampered_ephemeral_key_fails() {
        let recipient = Keypair::generate();
        let mut sealed = seal(&recipient.public_key(), b"secret", CTX).unwrap();
        sealed.ephemeral_pubkey[0] ^= 0x01;
        assert_eq!(
            open(&sealed, recipient.secret_key(), CTX).unwrap_err(),
            SealError::Decrypt
        );
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let recipient = Keypair::generate();
        let a = seal(&recipient.public_key(), b"secret", CTX).unwrap();
        let b = seal(&recipient.public_key(), b"secret", CTX).unwrap();
        assert_ne!(a.ephemeral_pubkey, b.ephemeral_pubkey);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(open(&a, recipient.secret_key(), CTX).unwrap(), b"secret");
        assert_eq!(open(&b, recipient.secret_key(), CTX).unwrap(), b"secret");
    }

    #[test]
    fn wire_bytes_roundtrip() {
        let recipient = Keypair::generate();
        let sealed = seal(&recipient.public_key(), b"framing", CTX).unwrap();
        let bytes = sealed.to_bytes();
        let parsed = SealedBox::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(
            open(&parsed, recipient.secret_key(), CTX).unwrap(),
            b"framing"
        );
    }

    #[test]
    fn truncated_wire_bytes_rejected() {
        assert_eq!(
            SealedBox::from_bytes(&[0u8; MIN_SEALED_LEN - 1]).unwrap_err(),
            SealError::Truncated
        );
        // Exactly the minimum (empty plaintext) parses.
        assert!(SealedBox::from_bytes(&[0u8; MIN_SEALED_LEN]).is_ok());
    }
}
