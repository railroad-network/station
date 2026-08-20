//! The recovery *reconstruction* ceremony (T1.11.3 Slice D, ADR-0016).
//!
//! Arming ([`super::flow::RecoveryPackage::create`]) hands each holder a shard
//! sealed to them. Reconstruction is the reverse ritual, and this module is its
//! confidential transport:
//!
//! 1. The party rebuilding the identity (a station operator) generates a fresh
//!    ephemeral **recovery keypair** and publishes a [`RecoveryRequest`] — the
//!    recovery public key plus the address being recovered.
//! 2. Each holder's device turns their stored shard back into a raw Shamir share
//!    ([`build_response`]) and **re-seals it to the recovery public key**, so the
//!    raw share — which, with `K-1` others, *is* the secret — never travels in
//!    the clear.
//! 3. The operator opens each response with the ephemeral secret
//!    ([`open_response`]) and, once `K` are gathered, interpolates the key
//!    ([`super::flow::reconstruct_wallet_for_address`]).
//!
//! The ephemeral keypair is per-ceremony and discarded afterwards; capturing a
//! set of response payloads without it reveals nothing.

use dcbor::prelude::*;
use zeroize::Zeroize;

use rrn_crypto::keypair::{PublicKey, SecretKey};

use crate::address::Address;
use crate::sealed::{self, SealedBox};

use super::encryption::decrypt_shard;
use super::flow::{parse_shard_payload, RecoveryError};
use super::shamir::{RawShard, ShardIndex};

/// blake3 KDF domain separator for sealing a raw shard to the recovery key.
/// Distinct from the holder-sealing and generic-seal contexts so a response box
/// can never be opened — or mistaken — as another kind of sealed object.
const RESPONSE_SEAL_CONTEXT: &str = "rrn/recovery/response/v1";

/// Length of a serialized raw shard: one index byte plus 32 data bytes.
const RAW_SHARD_LEN: usize = 1 + 32;

/// A published request to reconstruct an identity: the ephemeral recovery public
/// key holders seal their shares to, and the address being recovered (so a
/// holder's device can select the right stored shard and refuse a mismatch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryRequest {
    /// The ephemeral public key to seal responses to.
    pub recovery_pubkey: PublicKey,
    /// The identity being recovered.
    pub target_address: Address,
}

impl RecoveryRequest {
    /// Serializes to canonical CBOR.
    pub fn to_bytes(&self) -> Vec<u8> {
        rrn_crypto::serialize::to_canonical_bytes(self.clone())
    }

    /// Parses from canonical CBOR.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryError> {
        rrn_crypto::serialize::from_canonical_bytes(bytes)
            .map_err(|e| RecoveryError::Corrupt(e.to_string()))
    }
}

impl From<RecoveryRequest> for CBOR {
    fn from(r: RecoveryRequest) -> Self {
        let mut m = Map::new();
        m.insert("rk", CBOR::to_byte_string(r.recovery_pubkey.to_bytes()));
        m.insert("addr", r.target_address);
        m.into()
    }
}

impl TryFrom<CBOR> for RecoveryRequest {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let rk: [u8; 32] = map
            .extract::<&str, CBOR>("rk")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(Self {
            recovery_pubkey: PublicKey::from_bytes(rk).map_err(|_| dcbor::Error::WrongType)?,
            target_address: map.extract::<&str, Address>("addr")?,
        })
    }
}

/// A holder's contribution: decrypt the shard they hold and re-seal the raw
/// share to the request's recovery key. `stored_shard_payload` is the
/// distributable payload the holder received and stored
/// ([`super::flow::RecoveryPackage::shard_payload`]).
///
/// Rejects a shard whose original address does not match the request, so a
/// holder cannot be tricked into contributing a share for a different identity.
/// The returned bytes are the sealed response to hand back to the operator.
pub fn build_response(
    stored_shard_payload: &[u8],
    holder_secret: &SecretKey,
    request: &RecoveryRequest,
) -> Result<Vec<u8>, RecoveryError> {
    let parsed = parse_shard_payload(stored_shard_payload)?;
    if parsed.original_address != request.target_address {
        return Err(RecoveryError::AddressMismatch);
    }

    let raw = decrypt_shard(&parsed.shard, holder_secret)
        .map_err(|_| RecoveryError::Corrupt("could not decrypt held shard".into()))?;

    let mut plaintext = [0u8; RAW_SHARD_LEN];
    plaintext[0] = raw.index.0;
    plaintext[1..].copy_from_slice(&raw.data);
    let sealed = sealed::seal(&request.recovery_pubkey, &plaintext, RESPONSE_SEAL_CONTEXT)
        .map_err(|e| RecoveryError::Corrupt(format!("seal response: {e}")));
    plaintext.zeroize();
    Ok(sealed?.to_bytes())
}

/// Opens a sealed response with the ceremony's ephemeral recovery secret,
/// recovering the holder's raw Shamir share.
pub fn open_response(
    response: &[u8],
    recovery_secret: &SecretKey,
) -> Result<RawShard, RecoveryError> {
    let sealed = SealedBox::from_bytes(response)
        .map_err(|e| RecoveryError::Corrupt(format!("response framing: {e}")))?;
    let mut plaintext = sealed::open(&sealed, recovery_secret, RESPONSE_SEAL_CONTEXT)
        .map_err(|_| RecoveryError::Corrupt("could not open response".into()))?;
    if plaintext.len() != RAW_SHARD_LEN {
        plaintext.zeroize();
        return Err(RecoveryError::Corrupt("response wrong length".into()));
    }
    let index = ShardIndex(plaintext[0]);
    let mut data = [0u8; 32];
    data.copy_from_slice(&plaintext[1..]);
    plaintext.zeroize();
    Ok(RawShard { index, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::flow::{reconstruct_wallet_for_address, RecoveryPackage};
    use crate::wallet::WalletContents;
    use rrn_crypto::keypair::Keypair;

    #[test]
    fn ceremony_reconstructs_the_original_wallet() {
        // Arm: split a wallet across 3 holders, 2-of-3.
        let wallet = WalletContents::create_new();
        let target = wallet.address;
        let holders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        let holder_pubs: Vec<_> = holders.iter().map(|k| k.public_key()).collect();
        let package = RecoveryPackage::create(&wallet, &holder_pubs, 2).unwrap();
        let payloads: Vec<Vec<u8>> = (0..3).map(|i| package.shard_payload(i).unwrap()).collect();

        // Ceremony: operator's ephemeral recovery keypair + request.
        let recovery = Keypair::generate();
        let request = RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: target,
        };

        // Two holders respond, sealing their raw shares to the recovery key.
        let resp0 = build_response(&payloads[0], holders[0].secret_key(), &request).unwrap();
        let resp2 = build_response(&payloads[2], holders[2].secret_key(), &request).unwrap();

        // Operator opens the responses and reconstructs.
        let s0 = open_response(&resp0, recovery.secret_key()).unwrap();
        let s2 = open_response(&resp2, recovery.secret_key()).unwrap();
        let recovered = reconstruct_wallet_for_address(&[s0, s2], &target).unwrap();
        assert_eq!(recovered.address, target);
        assert_eq!(
            recovered.secret_key.to_bytes(),
            wallet.secret_key.to_bytes(),
            "recovered the exact key"
        );
    }

    #[test]
    fn request_round_trips() {
        let recovery = Keypair::generate();
        let target = WalletContents::create_new().address;
        let req = RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: target,
        };
        let back = RecoveryRequest::from_bytes(&req.to_bytes()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn response_for_wrong_identity_is_rejected() {
        let wallet = WalletContents::create_new();
        let holder = Keypair::generate();
        let h2 = Keypair::generate();
        let package =
            RecoveryPackage::create(&wallet, &[holder.public_key(), h2.public_key()], 2).unwrap();
        let payload = package.shard_payload(0).unwrap();

        let recovery = Keypair::generate();
        // Request targets a *different* identity.
        let other = WalletContents::create_new().address;
        let request = RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: other,
        };
        assert!(matches!(
            build_response(&payload, holder.secret_key(), &request),
            Err(RecoveryError::AddressMismatch)
        ));
    }

    #[test]
    fn wrong_recovery_secret_cannot_open_response() {
        let wallet = WalletContents::create_new();
        let target = wallet.address;
        let h0 = Keypair::generate();
        let h1 = Keypair::generate();
        let package =
            RecoveryPackage::create(&wallet, &[h0.public_key(), h1.public_key()], 2).unwrap();
        let payload = package.shard_payload(0).unwrap();
        let recovery = Keypair::generate();
        let request = RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: target,
        };
        let resp = build_response(&payload, h0.secret_key(), &request).unwrap();
        let attacker = Keypair::generate();
        assert!(open_response(&resp, attacker.secret_key()).is_err());
    }
}
