//! Sealing a raw shard to a single holder's identity key.
//!
//! A [`RawShard`] on its own reveals nothing about the secret, but `K` of them
//! together *are* the secret — so while a recovery package is distributed and
//! stored, each shard must be confidential to its intended holder. This module
//! seals a shard so that **only** the holder's secret key can open it, in a
//! libsodium-`crypto_box_seal`–style construction:
//!
//! ```text
//! ephemeral_x = random X25519 keypair
//! shared      = X25519(ephemeral_x.secret, holder_x.public)        // ECDH
//! key         = blake3::derive_key(CONTEXT, shared ‖ eph_pub ‖ holder_pub)
//! ciphertext  = XChaCha20Poly1305(key, nonce).encrypt(index ‖ data)
//! ```
//!
//! The holder reconstructs the same `shared` from their secret and the
//! ephemeral public key, derives the same `key`, and decrypts. Without the
//! holder's secret key the ECDH is infeasible, so no one else can derive the
//! key. The ephemeral keypair is fresh per shard, so two shards sealed to the
//! same holder share no key material.
//!
//! # Identity keys, reused for key exchange
//!
//! Holders are identified by their Ed25519 identity key. X25519 ECDH needs
//! Montgomery-form keys, so we convert: the holder's Ed25519 public key maps to
//! its birationally-equivalent Montgomery point
//! ([`VerifyingKey::to_montgomery`]), and the holder's Ed25519 secret seed maps
//! to the corresponding X25519 scalar ([`SigningKey::to_scalar_bytes`]). This is
//! the standard same-key-for-sign-and-DH conversion; it is acceptable here
//! because recovery holders are identified by exactly one long-term key.
//!
//! # On the KDF: blake3 native, not an HMAC-HKDF
//!
//! The task spec sketched "HKDF-Blake3". We use blake3's **own** key-derivation
//! mode ([`blake3::derive_key`]) instead, which is the blake3-native KDF
//! (domain-separated by a context string, extract-and-expand in one) and is
//! purpose-built for exactly this "derive a key from shared key material" step.
//! It avoids pulling an `hmac` + a second hash (`sha2`) and a conflicting
//! `digest` version into the tree just to bolt HMAC-HKDF onto a hash that
//! already provides a KDF. blake3 is already our hashing primitive
//! (`rrn-crypto`), so no new cryptographic dependency is introduced. The KDF
//! input binds the full DH transcript — `shared ‖ ephemeral_pub ‖ holder_pub` —
//! so a shard cannot be re-pointed at a different holder or ephemeral key.
//!
//! # What this does and does not protect
//!
//! XChaCha20-Poly1305 is authenticated: any modification of the ciphertext,
//! nonce, or ephemeral public key makes decryption fail rather than yield a
//! wrong shard — which is also what supplies the integrity check raw Shamir
//! lacks. A shard sealed to one identity cannot be re-sealed to another without
//! the original holder first decrypting it; re-issuing to new holders is a fresh
//! split (see [`super::flow`] refresh).

use dcbor::prelude::*;
use zeroize::Zeroize;

use rrn_crypto::keypair::{PublicKey, SecretKey};

use crate::address::Address;
use crate::sealed::{self, SealError, SealedBox};

use super::shamir::{RawShard, ShardIndex};

/// Domain-separation context for the shard-sealing KDF. blake3 requires this to
/// be a hardcoded, globally-unique, application-specific string; changing it
/// changes every derived key (a versioning lever if the scheme ever evolves).
const KDF_CONTEXT: &str = "railroad-network station recovery shard v1 \
    x25519-ecdh blake3-derive-key xchacha20poly1305";

/// Length of the AEAD plaintext: a 1-byte shard index followed by 32 bytes of
/// shard data.
const PLAINTEXT_LEN: usize = 1 + 32;

/// A [`RawShard`] sealed to a specific holder, openable only with that holder's
/// secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedShard {
    /// The identity that can decrypt this shard (its public key, for routing and
    /// display — not trusted for decryption, which derives everything from the
    /// holder's secret key).
    pub holder: Address,
    /// The ephemeral X25519 public key for this shard's ECDH.
    pub ephemeral_pubkey: [u8; 32],
    /// The XChaCha20-Poly1305 nonce (24 bytes; random per shard).
    pub nonce: [u8; 24],
    /// The AEAD ciphertext (sealed `index ‖ data`, plus the 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// Errors from sealing or opening a shard.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ShardCryptoError {
    /// The holder's public key is not a valid Ed25519 point and cannot be
    /// converted to X25519. (Unreachable for an `rrn-crypto` [`PublicKey`],
    /// which is validated at construction, but surfaced rather than panicked.)
    #[error("holder public key is not a valid Ed25519 point")]
    MalformedHolderKey,
    /// Decryption failed: the wrong holder key, or a tampered shard. Deliberately
    /// does not distinguish the two.
    #[error("shard decryption failed (wrong holder key or corrupt shard)")]
    Decrypt,
    /// Decryption authenticated but the plaintext was not the expected
    /// `index ‖ data` shape.
    #[error("decrypted shard had unexpected length")]
    CorruptPlaintext,
}

/// Maps a general [`SealError`] onto this module's shard-specific error. A
/// malformed holder key stays distinct; every crypto failure collapses to
/// [`ShardCryptoError::Decrypt`] (the same not-distinguished behavior as before).
fn from_seal_error(e: SealError) -> ShardCryptoError {
    match e {
        SealError::MalformedRecipientKey => ShardCryptoError::MalformedHolderKey,
        SealError::Truncated | SealError::Decrypt => ShardCryptoError::Decrypt,
    }
}

/// Seals `shard` so only the holder of `holder_pubkey`'s secret key can open it.
///
/// Delegates the sealing to [`crate::sealed`] under [`KDF_CONTEXT`], so recovery
/// and the mobile↔station transport share one construction; the context string
/// is what keeps a shard box and a transport box from ever opening as each other.
pub fn encrypt_shard(
    shard: &RawShard,
    holder_pubkey: &PublicKey,
) -> Result<EncryptedShard, ShardCryptoError> {
    // Plaintext: index ‖ data. The index is not secret, but sealing it under the
    // AEAD binds it so a holder cannot be handed a shard with a swapped index.
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[0] = shard.index.0;
    plaintext[1..].copy_from_slice(&shard.data);

    let sealed = sealed::seal(holder_pubkey, &plaintext, KDF_CONTEXT).map_err(from_seal_error);
    plaintext.zeroize();
    let sealed = sealed?;

    Ok(EncryptedShard {
        holder: Address::from_public_key(*holder_pubkey),
        ephemeral_pubkey: sealed.ephemeral_pubkey,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

/// Opens an [`EncryptedShard`] with the holder's secret key.
///
/// Returns [`ShardCryptoError::Decrypt`] for the wrong key or any tampering, and
/// never yields a wrong shard on failure (the AEAD tag is the integrity check).
pub fn decrypt_shard(
    encrypted: &EncryptedShard,
    holder_secret: &SecretKey,
) -> Result<RawShard, ShardCryptoError> {
    let sealed = SealedBox {
        ephemeral_pubkey: encrypted.ephemeral_pubkey,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext.clone(),
    };
    let mut plaintext =
        sealed::open(&sealed, holder_secret, KDF_CONTEXT).map_err(from_seal_error)?;

    if plaintext.len() != PLAINTEXT_LEN {
        plaintext.zeroize();
        return Err(ShardCryptoError::CorruptPlaintext);
    }
    let index = ShardIndex(plaintext[0]);
    let mut data = [0u8; 32];
    data.copy_from_slice(&plaintext[1..]);
    plaintext.zeroize();

    Ok(RawShard { index, data })
}

// --- canonical CBOR (for the recovery package, T0.4.7) ----------------------

impl From<EncryptedShard> for CBOR {
    fn from(s: EncryptedShard) -> Self {
        let mut m = Map::new();
        m.insert("holder", s.holder);
        m.insert("eph", CBOR::to_byte_string(s.ephemeral_pubkey));
        m.insert("nonce", CBOR::to_byte_string(s.nonce));
        m.insert("ct", CBOR::to_byte_string(s.ciphertext));
        m.into()
    }
}

impl TryFrom<CBOR> for EncryptedShard {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let ephemeral_pubkey: [u8; 32] = map
            .extract::<&str, CBOR>("eph")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        let nonce: [u8; 24] = map
            .extract::<&str, CBOR>("nonce")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(EncryptedShard {
            holder: map.extract::<&str, Address>("holder")?,
            ephemeral_pubkey,
            nonce,
            ciphertext: map.extract::<&str, CBOR>("ct")?.try_into_byte_string()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    fn sample_shard() -> RawShard {
        let mut data = [0u8; 32];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        RawShard {
            index: ShardIndex(7),
            data,
        }
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let holder = Keypair::generate();
        let shard = sample_shard();
        let sealed = encrypt_shard(&shard, &holder.public_key()).unwrap();
        let opened = decrypt_shard(&sealed, holder.secret_key()).unwrap();
        assert_eq!(opened, shard);
    }

    #[test]
    fn wrong_holder_key_fails() {
        let holder = Keypair::generate();
        let wrong = Keypair::generate();
        let sealed = encrypt_shard(&sample_shard(), &holder.public_key()).unwrap();
        let err = decrypt_shard(&sealed, wrong.secret_key()).unwrap_err();
        assert_eq!(err, ShardCryptoError::Decrypt);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let holder = Keypair::generate();
        let mut sealed = encrypt_shard(&sample_shard(), &holder.public_key()).unwrap();
        *sealed.ciphertext.last_mut().unwrap() ^= 0x01;
        let err = decrypt_shard(&sealed, holder.secret_key()).unwrap_err();
        assert_eq!(err, ShardCryptoError::Decrypt);
    }

    #[test]
    fn tampered_ephemeral_key_fails() {
        let holder = Keypair::generate();
        let mut sealed = encrypt_shard(&sample_shard(), &holder.public_key()).unwrap();
        sealed.ephemeral_pubkey[0] ^= 0x01;
        let err = decrypt_shard(&sealed, holder.secret_key()).unwrap_err();
        assert_eq!(err, ShardCryptoError::Decrypt);
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let holder = Keypair::generate();
        let shard = sample_shard();
        let a = encrypt_shard(&shard, &holder.public_key()).unwrap();
        let b = encrypt_shard(&shard, &holder.public_key()).unwrap();
        assert_ne!(a.ephemeral_pubkey, b.ephemeral_pubkey);
        assert_ne!(a.ciphertext, b.ciphertext);
        // Both still open to the same shard.
        assert_eq!(decrypt_shard(&a, holder.secret_key()).unwrap(), shard);
        assert_eq!(decrypt_shard(&b, holder.secret_key()).unwrap(), shard);
    }

    #[test]
    fn cbor_roundtrip() {
        use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
        let holder = Keypair::generate();
        let sealed = encrypt_shard(&sample_shard(), &holder.public_key()).unwrap();
        let bytes = to_canonical_bytes(sealed.clone());
        let decoded: EncryptedShard = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(sealed, decoded);
        // And the decoded shard still decrypts.
        assert_eq!(
            decrypt_shard(&decoded, holder.secret_key()).unwrap(),
            sample_shard()
        );
    }
}
