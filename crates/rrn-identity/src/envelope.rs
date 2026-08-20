//! A dual-wrapped secret envelope: seal arbitrary bytes under a fresh random
//! data-encryption key (DEK), then wrap that DEK **two independent ways** so
//! either a passphrase *or* a recipient's secret key can open the payload.
//!
//! This is the envelope behind [ADR-0016](../../../docs/adr/0016-station-backup-and-key-recovery.md)
//! (station backup). The motivating problem: a backup encrypted only under a
//! passphrase is useless against the most likely disaster — a *forgotten*
//! passphrase. So the DEK is wrapped both:
//!
//! 1. **under the passphrase** — Argon2id derives a key-encryption key that
//!    AEAD-seals the DEK (the everyday path), and
//! 2. **sealed to a recipient public key** — [`crate::sealed`] seals the DEK to
//!    an identity's public key, so whoever can produce the matching *secret*
//!    key can open the payload without the passphrase.
//!
//! Both wraps protect the *same* DEK, so the payload's confidentiality is no
//! weaker than either wrap alone: an attacker still needs the passphrase or the
//! recipient secret key. Wrap (2) is what lets social recovery
//! ([`crate::recovery`]) re-enter after a lost passphrase — reconstruct the
//! secret key from a threshold of trustees, open wrap (2), read the payload.
//!
//! # Layout
//!
//! ```text
//! DEK                 = random 32 bytes
//! payload ciphertext  = XChaCha20Poly1305(DEK, nonce).encrypt(plaintext)
//! wrap (1)            = XChaCha20Poly1305(Argon2id(passphrase, salt)).encrypt(DEK)
//! wrap (2)            = seal(recipient_pub, DEK)                 // crate::sealed
//! ```
//!
//! The struct is canonical-CBOR serializable; it carries no secret material in
//! the clear.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use dcbor::prelude::*;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use rrn_crypto::keypair::{PublicKey, SecretKey};

use crate::sealed::{self, SealError, SealedBox};

/// Current envelope format version.
pub const ENVELOPE_VERSION: u32 = 1;

/// blake3 KDF domain separator for the recipient-key wrap of the DEK. Distinct
/// from the shard-sealing and generic-seal contexts so a DEK wrap can never be
/// confused with another sealed object.
const DEK_SEAL_CONTEXT: &str = "rrn/envelope/dek-wrap/v1";

/// Argon2id memory cost in KiB (64 MiB) — matches the wallet's parameters.
const M_COST: u32 = 64 * 1024;
/// Argon2id iterations.
const T_COST: u32 = 3;
/// Argon2id parallelism.
const P_COST: u32 = 4;
/// DEK / derived-key length.
const KEY_LEN: usize = 32;

/// Errors from sealing and opening a [`DualWrapEnvelope`].
#[derive(thiserror::Error, Debug)]
pub enum EnvelopeError {
    /// The file's declared version is not supported by this build.
    #[error("unsupported envelope version {0} (this build supports {ENVELOPE_VERSION})")]
    UnsupportedVersion(u32),
    /// AEAD decryption failed: wrong passphrase, wrong key, or tampering.
    /// Deliberately does not distinguish the cause.
    #[error("envelope decryption failed (wrong passphrase/key or corrupt data)")]
    Decrypt,
    /// The recipient-key wrap could not be opened with the given secret key.
    #[error("could not open the recipient-key wrap: {0}")]
    Seal(#[from] SealError),
    /// Argon2id key derivation failed.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// The envelope bytes were not canonical CBOR or had the wrong shape.
    #[error("corrupt envelope: {0}")]
    Corrupt(String),
}

/// Convenience alias for envelope results.
pub type Result<T> = std::result::Result<T, EnvelopeError>;

/// Derives a 32-byte key from `passphrase` and `salt` with the fixed Argon2id
/// parameters. The returned key is secret material; callers zeroize it.
fn derive_kek(passphrase: &str, salt: &[u8; 32]) -> Result<[u8; KEY_LEN]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(M_COST, T_COST, P_COST, Some(KEY_LEN))
        .map_err(|e| EnvelopeError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| EnvelopeError::Kdf(e.to_string()))?;
    Ok(key)
}

/// AEAD-encrypts `plaintext` under `key` with a fresh random nonce.
fn aead_seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<([u8; 24], Vec<u8>)> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key is a valid AEAD key");
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| EnvelopeError::Decrypt)?;
    Ok((nonce, ciphertext))
}

/// AEAD-decrypts under `key`.
fn aead_open(key: &[u8; KEY_LEN], nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("32-byte key is a valid AEAD key");
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| EnvelopeError::Decrypt)
}

/// A payload sealed under a random DEK, with the DEK wrapped both under a
/// passphrase and to a recipient public key. Carries no plaintext secret.
#[derive(Clone, Debug)]
pub struct DualWrapEnvelope {
    version: u32,
    /// The recipient identity's public key — recorded so a recovery flow knows
    /// whose secret key opens wrap (2), and can verify it after reconstruction.
    recipient_pub: [u8; 32],
    /// Argon2id salt for wrap (1).
    salt: [u8; 32],
    /// Wrap (1): the DEK AEAD-sealed under the passphrase-derived key.
    pass_nonce: [u8; 24],
    pass_wrap: Vec<u8>,
    /// Wrap (2): the DEK sealed to `recipient_pub`.
    key_wrap: Vec<u8>,
    /// Payload AEAD nonce and ciphertext (under the DEK).
    payload_nonce: [u8; 24],
    payload: Vec<u8>,
}

impl DualWrapEnvelope {
    /// Seals `plaintext` under a fresh DEK, wrapping the DEK under `passphrase`
    /// and to `recipient_pub`.
    pub fn seal(plaintext: &[u8], passphrase: &str, recipient_pub: &PublicKey) -> Result<Self> {
        // Fresh DEK.
        let mut dek = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut dek);

        // Payload under the DEK.
        let (payload_nonce, payload) = aead_seal(&dek, plaintext)?;

        // Wrap (1): DEK under the passphrase.
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut kek = derive_kek(passphrase, &salt)?;
        let pass_result = aead_seal(&kek, &dek);
        kek.zeroize();
        let (pass_nonce, pass_wrap) = pass_result?;

        // Wrap (2): DEK sealed to the recipient's public key.
        let key_wrap = sealed::seal(recipient_pub, &dek, DEK_SEAL_CONTEXT)
            .map(|b| b.to_bytes())
            .map_err(EnvelopeError::Seal);
        dek.zeroize();
        let key_wrap = key_wrap?;

        Ok(Self {
            version: ENVELOPE_VERSION,
            recipient_pub: recipient_pub.to_bytes(),
            salt,
            pass_nonce,
            pass_wrap,
            key_wrap,
            payload_nonce,
            payload,
        })
    }

    /// The recipient public key whose secret opens wrap (2).
    pub fn recipient_public_key(&self) -> [u8; 32] {
        self.recipient_pub
    }

    /// Opens the payload via the passphrase (the everyday path).
    pub fn open_with_passphrase(&self, passphrase: &str) -> Result<Vec<u8>> {
        if self.version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version));
        }
        let mut kek = derive_kek(passphrase, &self.salt)?;
        let dek_result = aead_open(&kek, &self.pass_nonce, &self.pass_wrap);
        kek.zeroize();
        let mut dek_vec = dek_result?;
        let out = self.open_payload_with_dek(&dek_vec);
        dek_vec.zeroize();
        out
    }

    /// Opens the payload via the recipient's secret key (the recovery path,
    /// used when the passphrase is lost). See [`crate::recovery`].
    pub fn open_with_secret_key(&self, secret: &SecretKey) -> Result<Vec<u8>> {
        if self.version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version));
        }
        let sealed = SealedBox::from_bytes(&self.key_wrap)?;
        let mut dek_vec = sealed::open(&sealed, secret, DEK_SEAL_CONTEXT)?;
        let out = self.open_payload_with_dek(&dek_vec);
        dek_vec.zeroize();
        out
    }

    /// Decrypts the payload given the recovered DEK (exactly 32 bytes).
    fn open_payload_with_dek(&self, dek_bytes: &[u8]) -> Result<Vec<u8>> {
        let dek: [u8; KEY_LEN] = dek_bytes
            .try_into()
            .map_err(|_| EnvelopeError::Corrupt("DEK is not 32 bytes".into()))?;
        aead_open(&dek, &self.payload_nonce, &self.payload)
    }
}

// --- canonical CBOR ---------------------------------------------------------

impl From<DualWrapEnvelope> for CBOR {
    fn from(e: DualWrapEnvelope) -> Self {
        let mut m = Map::new();
        m.insert("v", e.version);
        m.insert("recipient", CBOR::to_byte_string(e.recipient_pub));
        m.insert("salt", CBOR::to_byte_string(e.salt));
        m.insert("pass_nonce", CBOR::to_byte_string(e.pass_nonce));
        m.insert("pass_wrap", CBOR::to_byte_string(e.pass_wrap));
        m.insert("key_wrap", CBOR::to_byte_string(e.key_wrap));
        m.insert("payload_nonce", CBOR::to_byte_string(e.payload_nonce));
        m.insert("payload", CBOR::to_byte_string(e.payload));
        m.into()
    }
}

impl TryFrom<CBOR> for DualWrapEnvelope {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let fixed = |key: &str, n: usize| -> core::result::Result<Vec<u8>, dcbor::Error> {
            let v = map
                .extract::<&str, CBOR>(key)?
                .try_into_byte_string()?
                .as_slice()
                .to_vec();
            if v.len() != n {
                return Err(dcbor::Error::WrongType);
            }
            Ok(v)
        };
        let to_arr32 = |v: Vec<u8>| -> [u8; 32] { v.try_into().expect("checked length 32") };
        let to_arr24 = |v: Vec<u8>| -> [u8; 24] { v.try_into().expect("checked length 24") };

        Ok(Self {
            version: map.extract::<&str, u32>("v")?,
            recipient_pub: to_arr32(fixed("recipient", 32)?),
            salt: to_arr32(fixed("salt", 32)?),
            pass_nonce: to_arr24(fixed("pass_nonce", 24)?),
            pass_wrap: map
                .extract::<&str, CBOR>("pass_wrap")?
                .try_into_byte_string()?
                .as_slice()
                .to_vec(),
            key_wrap: map
                .extract::<&str, CBOR>("key_wrap")?
                .try_into_byte_string()?
                .as_slice()
                .to_vec(),
            payload_nonce: to_arr24(fixed("payload_nonce", 24)?),
            payload: map
                .extract::<&str, CBOR>("payload")?
                .try_into_byte_string()?
                .as_slice()
                .to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    fn keypair() -> Keypair {
        Keypair::from_secret(SecretKey::from_bytes([7u8; 32]))
    }

    #[test]
    fn passphrase_round_trips() {
        let kp = keypair();
        let env = DualWrapEnvelope::seal(b"the ledger", "correct horse", &kp.public_key()).unwrap();
        assert_eq!(
            env.open_with_passphrase("correct horse").unwrap(),
            b"the ledger"
        );
    }

    #[test]
    fn secret_key_round_trips() {
        let kp = keypair();
        let env = DualWrapEnvelope::seal(b"the ledger", "correct horse", &kp.public_key()).unwrap();
        // The recovery path: no passphrase, just the recipient's secret key.
        assert_eq!(
            env.open_with_secret_key(kp.secret_key()).unwrap(),
            b"the ledger"
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let kp = keypair();
        let env = DualWrapEnvelope::seal(b"secret", "right", &kp.public_key()).unwrap();
        assert!(matches!(
            env.open_with_passphrase("wrong"),
            Err(EnvelopeError::Decrypt)
        ));
    }

    #[test]
    fn wrong_secret_key_fails() {
        let kp = keypair();
        let env = DualWrapEnvelope::seal(b"secret", "right", &kp.public_key()).unwrap();
        let other = Keypair::from_secret(SecretKey::from_bytes([9u8; 32]));
        assert!(env.open_with_secret_key(other.secret_key()).is_err());
    }

    #[test]
    fn cbor_round_trips_and_still_opens() {
        use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
        let kp = keypair();
        let env = DualWrapEnvelope::seal(b"payload bytes", "pw", &kp.public_key()).unwrap();
        let bytes = to_canonical_bytes(env);
        let back: DualWrapEnvelope = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back.recipient_public_key(), kp.public_key().to_bytes());
        assert_eq!(back.open_with_passphrase("pw").unwrap(), b"payload bytes");
        assert_eq!(
            back.open_with_secret_key(kp.secret_key()).unwrap(),
            b"payload bytes"
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let kp = keypair();
        let mut env = DualWrapEnvelope::seal(b"secret", "pw", &kp.public_key()).unwrap();
        if let Some(byte) = env.payload.first_mut() {
            *byte ^= 0xff;
        }
        assert!(env.open_with_passphrase("pw").is_err());
    }
}
