//! The end-to-end social-recovery ritual: turn a wallet into a distributable
//! recovery package, and rebuild the wallet from gathered shards.
//!
//! [`RecoveryPackage::create`] splits the wallet's secret key into one sealed
//! shard per holder (Shamir split + per-holder encryption) and records the
//! parameters and the original address. The package is persisted as canonical
//! CBOR (`.rrnrecovery`) and distributed: each holder keeps their own
//! [`EncryptedShard`] plus the public metadata. When recovery is needed, any `K`
//! holders decrypt their shards ([`super::encryption::decrypt_shard`]) and hand
//! the [`RawShard`]s back; [`reconstruct_wallet`] interpolates the secret and
//! rebuilds a working wallet, verifying the recovered address matches the one
//! the package was created for.
//!
//! # The package is deliberately not encrypted as a whole
//!
//! Only the individual shards are confidential. The package's metadata
//! (threshold, total, the original address, creation time) is readable so a
//! holder can see what is being asked of them. Confidentiality of the *key* lives
//! entirely in the per-shard encryption and the `K`-of-`N` threshold.

use std::collections::BTreeMap;
use std::path::Path;

use dcbor::prelude::*;
use rand_core::OsRng;
use zeroize::Zeroize;

use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

use crate::address::Address;
use crate::wallet::WalletContents;

use super::encryption::{encrypt_shard, EncryptedShard, ShardCryptoError};
use super::shamir::{
    reconstruct_secret, split_secret, RawShard, ReconstructError, SplitError, MAX_SHARES,
};

/// File extension for a saved recovery package.
pub const RECOVERY_EXTENSION: &str = "rrnrecovery";

/// Public, non-secret metadata describing a recovery package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryMetadata {
    /// The address of the identity this package recovers. The reconstructed
    /// wallet's derived address must equal this, or recovery is rejected.
    pub original_address: Address,
    /// Unix seconds when the package was created.
    pub created_at: i64,
}

/// A complete, distributable recovery package: the sealed shards plus the
/// parameters needed to reconstruct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPackage {
    /// `K` — how many decrypted shards are required to reconstruct.
    pub threshold: u8,
    /// `N` — how many shards (and holders) the secret was split across.
    pub total: u8,
    /// One sealed shard per holder, in holder order.
    pub shards: Vec<EncryptedShard>,
    /// Public metadata (original address, creation time).
    pub recovery_metadata: RecoveryMetadata,
}

/// Errors from creating, persisting, or reconstructing a recovery package.
#[derive(thiserror::Error, Debug)]
pub enum RecoveryError {
    /// More holders were supplied than the [`MAX_SHARES`] cap allows.
    #[error("too many holders: {holders} (max {max})")]
    TooManyHolders {
        /// The number of holder keys supplied.
        holders: usize,
        /// The cap ([`MAX_SHARES`]).
        max: u8,
    },
    /// The split parameters were invalid (e.g. threshold below 2 or above the
    /// holder count).
    #[error("invalid split parameters: {0}")]
    Split(#[from] SplitError),
    /// Reconstruction from the supplied shards failed.
    #[error("reconstruction failed: {0}")]
    Reconstruct(#[from] ReconstructError),
    /// A shard could not be sealed to its holder.
    #[error("shard encryption failed: {0}")]
    ShardCrypto(#[from] ShardCryptoError),
    /// The reconstructed wallet's address does not match the package's
    /// `original_address` — the shards were wrong, insufficient, or from a
    /// different identity.
    #[error("reconstructed address does not match the recovery package")]
    AddressMismatch,
    /// A filesystem error reading or writing the package.
    #[error("recovery package io error: {0}")]
    Io(#[from] std::io::Error),
    /// The package file was not valid canonical CBOR or had the wrong shape.
    #[error("corrupt recovery package: {0}")]
    Corrupt(String),
}

impl RecoveryPackage {
    /// Builds a recovery package: splits `wallet`'s secret key into one sealed
    /// shard per entry in `holder_pubkeys`, requiring `threshold` to reconstruct.
    ///
    /// The number of holders is the total `N`; `threshold` (`K`) must satisfy
    /// `2 <= K <= N <= MAX_SHARES`.
    pub fn create(
        wallet: &WalletContents,
        holder_pubkeys: &[PublicKey],
        threshold: u8,
    ) -> Result<Self, RecoveryError> {
        let total = holder_pubkeys.len();
        if total > MAX_SHARES as usize {
            return Err(RecoveryError::TooManyHolders {
                holders: total,
                max: MAX_SHARES,
            });
        }
        let total = total as u8;

        // Split the secret seed, taking care to wipe the plaintext copy whether
        // or not the split succeeds.
        let mut secret = wallet.secret_key.to_bytes();
        let split = split_secret(&secret, threshold, total, &mut OsRng);
        secret.zeroize();
        let raw_shards = split?;

        // Seal each raw shard to its holder. The raw shards are zeroized on drop
        // (RawShard's Drop) once this scope ends.
        let mut shards = Vec::with_capacity(raw_shards.len());
        for (raw, holder) in raw_shards.iter().zip(holder_pubkeys) {
            shards.push(encrypt_shard(raw, holder)?);
        }

        Ok(Self {
            threshold,
            total,
            shards,
            recovery_metadata: RecoveryMetadata {
                original_address: wallet.address,
                created_at: now_secs(),
            },
        })
    }

    /// Re-issues the recovery package to a new set of holders (and possibly a
    /// new threshold), revoking the old shards.
    ///
    /// This is a **completely fresh split** of the *same* secret key: new random
    /// coefficients, so the new shards are mathematically unrelated to the old
    /// ones — an old shard cannot be combined with new shards to reconstruct.
    /// The underlying secret (and thus the identity and its address) never
    /// changes; that continuity is the whole point. Use this when a relationship
    /// with a holder deteriorates: re-issue to a new holder set and stop honoring
    /// the old shards.
    ///
    /// Invalidating the *distribution* of the old shards is the caller's
    /// responsibility — a holder who kept their old shard can still try to use
    /// it, but it is now useless without `K-1` other *old* shards (which the new
    /// holder set does not have).
    ///
    /// `wallet` must be the identity this package was created for, or the refresh
    /// is rejected ([`RecoveryError::AddressMismatch`]).
    pub fn refresh(
        &self,
        wallet: &WalletContents,
        new_holder_pubkeys: &[PublicKey],
        new_threshold: u8,
    ) -> Result<Self, RecoveryError> {
        if wallet.address != self.recovery_metadata.original_address {
            return Err(RecoveryError::AddressMismatch);
        }
        Self::create(wallet, new_holder_pubkeys, new_threshold)
    }

    /// Writes the package to `path` as canonical CBOR.
    ///
    /// The package is not encrypted as a whole (only its shards are), so this is
    /// an ordinary write — no passphrase, no special permissions required.
    pub fn save_to_file(&self, path: &Path) -> Result<(), RecoveryError> {
        let bytes = to_canonical_bytes(self.clone());
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Reads and decodes a package from `path`.
    pub fn load_from_file(path: &Path) -> Result<Self, RecoveryError> {
        let bytes = std::fs::read(path)?;
        from_canonical_bytes(&bytes).map_err(|e| RecoveryError::Corrupt(e.to_string()))
    }
}

/// Reconstructs the wallet from `decrypted_shards` (any `threshold` of the
/// holders' opened shards).
///
/// Interpolates the secret key, re-derives the address, and verifies it matches
/// the package's `original_address` — so wrong or insufficient shards are caught
/// here (they reconstruct to a *different* key whose address won't match) rather
/// than silently returning a bogus wallet. The recovered wallet carries the
/// secret key and address; the original `metadata` and creation time are not in
/// the package and are not restored (creation time is set to the package's).
pub fn reconstruct_wallet(
    package: &RecoveryPackage,
    decrypted_shards: &[RawShard],
) -> Result<WalletContents, RecoveryError> {
    let mut secret = reconstruct_secret(decrypted_shards)?;
    let secret_key = SecretKey::from_bytes(secret);
    secret.zeroize();

    let address = Address::from_public_key(Keypair::from_secret(secret_key.clone()).public_key());
    if address != package.recovery_metadata.original_address {
        return Err(RecoveryError::AddressMismatch);
    }

    Ok(WalletContents {
        secret_key,
        address,
        created_at: package.recovery_metadata.created_at,
        metadata: BTreeMap::new(),
    })
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// --- canonical CBOR ---------------------------------------------------------

impl From<RecoveryMetadata> for CBOR {
    fn from(m: RecoveryMetadata) -> Self {
        let mut map = Map::new();
        map.insert("address", m.original_address);
        map.insert("created_at", m.created_at);
        map.into()
    }
}

impl TryFrom<CBOR> for RecoveryMetadata {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(RecoveryMetadata {
            original_address: map.extract::<&str, Address>("address")?,
            created_at: map.extract::<&str, i64>("created_at")?,
        })
    }
}

impl From<RecoveryPackage> for CBOR {
    fn from(p: RecoveryPackage) -> Self {
        let shards: Vec<CBOR> = p.shards.into_iter().map(Into::into).collect();
        let mut map = Map::new();
        map.insert("threshold", p.threshold as u64);
        map.insert("total", p.total as u64);
        map.insert("shards", shards);
        map.insert("metadata", p.recovery_metadata);
        map.into()
    }
}

impl TryFrom<CBOR> for RecoveryPackage {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let shards_cbor = map.extract::<&str, CBOR>("shards")?;
        let shards = match shards_cbor.into_case() {
            CBORCase::Array(items) => items
                .into_iter()
                .map(EncryptedShard::try_from)
                .collect::<core::result::Result<Vec<_>, _>>()?,
            _ => return Err(dcbor::Error::WrongType),
        };
        let threshold = u8::try_from(map.extract::<&str, u64>("threshold")?)
            .map_err(|_| dcbor::Error::WrongType)?;
        let total = u8::try_from(map.extract::<&str, u64>("total")?)
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(RecoveryPackage {
            threshold,
            total,
            shards,
            recovery_metadata: map.extract::<&str, RecoveryMetadata>("metadata")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::encryption::decrypt_shard;

    /// A wallet plus the keypairs of `n` holders.
    fn wallet_and_holders(n: usize) -> (WalletContents, Vec<Keypair>) {
        let wallet = WalletContents::create_new();
        let holders: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        (wallet, holders)
    }

    fn holder_pubkeys(holders: &[Keypair]) -> Vec<PublicKey> {
        holders.iter().map(|h| h.public_key()).collect()
    }

    #[test]
    fn full_create_distribute_recover_signs_as_original() {
        let (wallet, holders) = wallet_and_holders(5);
        let original_pub = Keypair::from_secret(wallet.secret_key.clone()).public_key();
        let original_addr = wallet.address;

        let package = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 3).unwrap();
        assert_eq!(package.threshold, 3);
        assert_eq!(package.total, 5);
        assert_eq!(package.shards.len(), 5);

        // Three holders (indices 0, 2, 4) decrypt their shards.
        let decrypted: Vec<RawShard> = [0usize, 2, 4]
            .iter()
            .map(|&i| decrypt_shard(&package.shards[i], holders[i].secret_key()).unwrap())
            .collect();

        let recovered = reconstruct_wallet(&package, &decrypted).unwrap();
        assert_eq!(recovered.address, original_addr);

        // The recovered wallet signs as the original identity.
        let recovered_kp = Keypair::from_secret(recovered.secret_key.clone());
        let sig = recovered_kp.sign(b"recovered and signing");
        assert!(original_pub.verify(b"recovered and signing", &sig).is_ok());
    }

    #[test]
    fn save_then_load_roundtrips_the_package() {
        let (wallet, holders) = wallet_and_holders(4);
        let package = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 2).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alice.rrnrecovery");
        package.save_to_file(&path).unwrap();
        let loaded = RecoveryPackage::load_from_file(&path).unwrap();
        assert_eq!(package, loaded);

        // Shards from the loaded package still decrypt and reconstruct.
        let decrypted: Vec<RawShard> = (0..2)
            .map(|i| decrypt_shard(&loaded.shards[i], holders[i].secret_key()).unwrap())
            .collect();
        let recovered = reconstruct_wallet(&loaded, &decrypted).unwrap();
        assert_eq!(recovered.address, wallet.address);
    }

    #[test]
    fn too_many_holders_is_rejected() {
        let (wallet, holders) = wallet_and_holders(17);
        let err = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 3).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::TooManyHolders { holders: 17, .. }
        ));
    }

    #[test]
    fn threshold_below_two_is_rejected() {
        let (wallet, holders) = wallet_and_holders(5);
        let err = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 1).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::Split(SplitError::InvalidThreshold)
        ));
    }

    #[test]
    fn refresh_to_new_holders_still_recovers_original() {
        let (wallet, holders) = wallet_and_holders(3);
        let package = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 2).unwrap();

        // Re-issue to a fresh set of holders, with a new threshold.
        let new_holders: Vec<Keypair> = (0..4).map(|_| Keypair::generate()).collect();
        let refreshed = package
            .refresh(&wallet, &holder_pubkeys(&new_holders), 3)
            .unwrap();
        assert_eq!(refreshed.total, 4);
        assert_eq!(refreshed.threshold, 3);
        assert_eq!(refreshed.recovery_metadata.original_address, wallet.address);

        // Recover from the new shards → still the original identity.
        let decrypted: Vec<RawShard> = (0..3)
            .map(|i| decrypt_shard(&refreshed.shards[i], new_holders[i].secret_key()).unwrap())
            .collect();
        let recovered = reconstruct_wallet(&refreshed, &decrypted).unwrap();
        assert_eq!(recovered.address, wallet.address);
    }

    #[test]
    fn old_and_new_shards_do_not_combine() {
        let (wallet, holders) = wallet_and_holders(3);
        let package = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 2).unwrap();
        let new_holders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        let refreshed = package
            .refresh(&wallet, &holder_pubkeys(&new_holders), 2)
            .unwrap();

        // One OLD shard (index 1) + one NEW shard (index 2): distinct indices, so
        // interpolation proceeds — but the shards lie on *different* polynomials,
        // so it reconstructs to a different key, caught by the address check.
        let old_shard = decrypt_shard(&package.shards[0], holders[0].secret_key()).unwrap();
        let new_shard = decrypt_shard(&refreshed.shards[1], new_holders[1].secret_key()).unwrap();
        let mixed = vec![old_shard, new_shard];

        let err = reconstruct_wallet(&refreshed, &mixed).unwrap_err();
        assert!(matches!(err, RecoveryError::AddressMismatch), "{err:?}");
    }

    #[test]
    fn refresh_rejects_a_different_identity() {
        let (wallet, holders) = wallet_and_holders(3);
        let package = RecoveryPackage::create(&wallet, &holder_pubkeys(&holders), 2).unwrap();
        let (other_wallet, other_holders) = wallet_and_holders(3);
        let err = package
            .refresh(&other_wallet, &holder_pubkeys(&other_holders), 2)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::AddressMismatch), "{err:?}");
    }

    #[test]
    fn wrong_shards_fail_with_address_mismatch() {
        // Reconstructing a different identity's package with this identity's
        // shards (or too few) yields a different key, caught by the address
        // check. Here we recover one wallet but check against another package.
        let (wallet_a, holders_a) = wallet_and_holders(3);
        let package_a = RecoveryPackage::create(&wallet_a, &holder_pubkeys(&holders_a), 2).unwrap();

        let (wallet_b, holders_b) = wallet_and_holders(3);
        let package_b = RecoveryPackage::create(&wallet_b, &holder_pubkeys(&holders_b), 2).unwrap();

        // Decrypt A's shards, but try to reconstruct against B's package.
        let decrypted_a: Vec<RawShard> = (0..2)
            .map(|i| decrypt_shard(&package_a.shards[i], holders_a[i].secret_key()).unwrap())
            .collect();
        let err = reconstruct_wallet(&package_b, &decrypted_a).unwrap_err();
        assert!(matches!(err, RecoveryError::AddressMismatch), "{err:?}");
    }
}
