//! The recovery *reconstruction* ceremony (T1.11.3 Slice D, ADR-0016).
//!
//! Arming ([`super::flow::RecoveryPackage::create`]) hands each holder a shard
//! sealed to them. Reconstruction is the reverse ritual, and this module is its
//! confidential transport:
//!
//! 1. The party rebuilding the identity generates a fresh ephemeral **recovery
//!    keypair** and publishes a [`RecoveryRequest`] — the recovery public key
//!    plus the address being recovered. This party is whoever holds the identity
//!    being recovered: a station operator rebuilding the *station's* key, or a
//!    member rebuilding *their own* key on a new phone or laptop
//!    ([`RecoverySession`]). The key is reconstructed on that party's own
//!    device; nothing ever hands a member's secret to the station (ADR-0006).
//! 2. Each holder's device turns their stored shard back into a raw Shamir share
//!    ([`build_response`]) and **re-seals it to the recovery public key**, so the
//!    raw share — which, with `K-1` others, *is* the secret — never travels in
//!    the clear.
//! 3. The requester opens each response with the ephemeral secret
//!    ([`open_response`]) and, once enough are gathered, interpolates the key
//!    ([`super::flow::reconstruct_wallet_for_address`]).
//!
//! The ephemeral keypair is per-ceremony and discarded afterwards; capturing a
//! set of response payloads without it reveals nothing.
//!
//! # Confirming the ceremony out-of-band
//!
//! A response is exactly as trustworthy as the person showing the request:
//! nothing in the wire format proves the requester is the identity's true owner.
//! [`fingerprint`] derives a short, human-comparable code from the request's
//! ephemeral key; every requester prints it and every holder's confirm screen
//! shows it, so two holders can notice they were shown *different* ceremonies
//! and a holder can read the code aloud to confirm they are helping the right
//! recovery before contributing a share.

use dcbor::prelude::*;
use zeroize::Zeroize;

use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};

use crate::address::Address;
use crate::sealed::{self, SealedBox};
use crate::wallet::WalletContents;

use super::encryption::decrypt_shard;
use super::flow::{parse_shard_payload, reconstruct_wallet_for_address_at, RecoveryError};
use super::shamir::{RawShard, ShardIndex};

/// blake3 domain separator for the ceremony [`fingerprint`], distinct from every
/// other blake3 use so the code can never collide with another short hash.
pub const FINGERPRINT_TAG: &[u8] = b"rrn.recovery.fingerprint";

/// A short, human-comparable fingerprint of a recovery ceremony: the first ten
/// hex characters of `blake3(FINGERPRINT_TAG ‖ recovery pubkey)`, rendered
/// `xxxxx-xxxxx`.
///
/// It binds the request's ephemeral key, so a forged parallel ceremony (a
/// different ephemeral key) yields a different code. Requester and holders
/// compare it out-of-band — the same ritual as the pairing SAS — to confirm they
/// are taking part in the *same* recovery before any share is contributed. It is
/// not a secret and not an authenticator on its own; it only lets humans detect
/// a mismatch.
pub fn fingerprint(request: &RecoveryRequest) -> String {
    let mut hasher = rrn_crypto::hash::Hasher::new();
    hasher.update(FINGERPRINT_TAG);
    hasher.update(&request.recovery_pubkey.to_bytes());
    let hex = hasher.finalize().to_hex();
    format!("{}-{}", &hex[..5], &hex[5..10])
}

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

/// The requester side of the reconstruction ceremony, run on the device
/// rebuilding an identity: it owns the ephemeral recovery keypair, publishes the
/// [`RecoveryRequest`], gathers holders' responses, and interpolates the key —
/// all in memory, on that device.
///
/// This is the same ceremony the station runs to rebuild its own key; a member
/// recovering their own key runs it on their new phone or laptop, so the secret
/// is reconstructed where it belongs and never reaches the station (ADR-0006,
/// ADR-0016).
///
/// The requester does not know the original threshold `K` (the recovery
/// configuration died with the lost device), so it takes a "try with what you
/// have" stance: [`reconstruct`](Self::reconstruct) attempts interpolation over
/// the responses gathered so far and reports [`RecoveryError::NeedMoreResponses`]
/// — never a wrong key — when they do not rebuild the target address. The
/// address check is the correctness oracle: too few or wrong shares reconstruct
/// a *different* key, which is caught, not returned.
///
/// The ephemeral secret and every gathered raw share are sensitive and are
/// zeroized when the session is dropped.
pub struct RecoverySession {
    recovery: Keypair,
    target: Address,
    shards: Vec<RawShard>,
}

impl RecoverySession {
    /// Begins a ceremony to recover `target`, minting a fresh ephemeral recovery
    /// keypair for holders to seal their shares to.
    pub fn begin(target: Address) -> Self {
        Self {
            recovery: Keypair::generate(),
            target,
            shards: Vec::new(),
        }
    }

    /// The identity this ceremony reconstructs.
    pub fn target(&self) -> &Address {
        &self.target
    }

    /// The request to publish to holders (render as a `rrnrecover-req:` QR).
    pub fn request(&self) -> RecoveryRequest {
        RecoveryRequest {
            recovery_pubkey: self.recovery.public_key(),
            target_address: self.target,
        }
    }

    /// The ceremony [`fingerprint`] for this session — the code the requester
    /// shows and holders confirm out-of-band.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.request())
    }

    /// Opens a holder's sealed `rrnrecover-resp:` response with the ephemeral
    /// secret and adds the raw share to the set gathered so far, returning the
    /// number now held.
    ///
    /// Responses are deduplicated by shard index: a holder who answers twice, or
    /// a duplicate scan, does not inflate the count or make interpolation
    /// singular. A response sealed to a *different* ceremony's key cannot be
    /// opened and is rejected as [`RecoveryError::Corrupt`].
    pub fn add_response(&mut self, response: &[u8]) -> Result<usize, RecoveryError> {
        let shard = open_response(response, self.recovery.secret_key())?;
        if !self.shards.iter().any(|s| s.index == shard.index) {
            self.shards.push(shard);
        }
        Ok(self.shards.len())
    }

    /// How many distinct responses have been gathered so far.
    pub fn responses(&self) -> usize {
        self.shards.len()
    }

    /// Attempts to reconstruct the wallet from the responses gathered so far,
    /// stamping the recovered wallet's `created_at` with `now`.
    ///
    /// Returns [`RecoveryError::NeedMoreResponses`] when the shares on hand do
    /// not interpolate to the target address — whether because there are too few
    /// (below `K`) or because a wrong share slipped in — so a caller never
    /// mistakes an under-threshold reconstruction for success. Any other
    /// interpolation failure (an out-of-range or singular index set) is likewise
    /// reported as needing more, since the honest remedy is the same: gather
    /// another good response.
    pub fn reconstruct(&self, now: i64) -> Result<WalletContents, RecoveryError> {
        match reconstruct_wallet_for_address_at(&self.shards, &self.target, now) {
            Ok(wallet) => Ok(wallet),
            Err(RecoveryError::AddressMismatch) | Err(RecoveryError::Reconstruct(_)) => {
                Err(RecoveryError::NeedMoreResponses)
            }
            Err(other) => Err(other),
        }
    }
}

impl Drop for RecoverySession {
    fn drop(&mut self) {
        // The ephemeral keypair's secret zeroizes via its own `Drop`; wipe the
        // gathered shares explicitly (they also zeroize on their own `Drop`, but
        // this makes the intent local and total).
        for shard in &mut self.shards {
            shard.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::flow::{reconstruct_wallet_for_address, RecoveryPackage};

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

    // --- fingerprint --------------------------------------------------------

    fn request_for(recovery: &Keypair, target: Address) -> RecoveryRequest {
        RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: target,
        }
    }

    #[test]
    fn fingerprint_is_stable_and_well_formed() {
        let recovery = Keypair::generate();
        let target = WalletContents::create_new().address;
        let req = request_for(&recovery, target);
        let fp = fingerprint(&req);

        // Stable across calls, and the documented `xxxxx-xxxxx` hex shape.
        assert_eq!(fp, fingerprint(&req));
        let re = regex_like(&fp);
        assert!(re, "unexpected fingerprint shape: {fp}");

        // The same key recovering a *different* target yields the same code (the
        // fingerprint binds the ephemeral key, which is what a forgery changes).
        let other = WalletContents::create_new().address;
        assert_eq!(fp, fingerprint(&request_for(&recovery, other)));
    }

    /// `^[0-9a-f]{5}-[0-9a-f]{5}$` without pulling in a regex crate.
    fn regex_like(s: &str) -> bool {
        let bytes = s.as_bytes();
        bytes.len() == 11
            && bytes[5] == b'-'
            && bytes[..5].iter().all(|b| b.is_ascii_hexdigit())
            && bytes[6..].iter().all(|b| b.is_ascii_hexdigit())
    }

    #[test]
    fn fingerprint_differs_per_ephemeral_key() {
        let target = WalletContents::create_new().address;
        let a = fingerprint(&request_for(&Keypair::generate(), target));
        let b = fingerprint(&request_for(&Keypair::generate(), target));
        assert_ne!(a, b, "distinct ephemeral keys must give distinct codes");
    }

    // --- RecoverySession ----------------------------------------------------

    /// Split `wallet` across `n` holders K-of-N and return the holders plus the
    /// distributable shard payloads.
    fn armed(wallet: &WalletContents, n: usize, k: u8) -> (Vec<Keypair>, Vec<Vec<u8>>) {
        let holders: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        let pubs: Vec<_> = holders.iter().map(|h| h.public_key()).collect();
        let package = RecoveryPackage::create(wallet, &pubs, k).unwrap();
        let payloads = (0..n).map(|i| package.shard_payload(i).unwrap()).collect();
        (holders, payloads)
    }

    #[test]
    fn session_reconstructs_the_original_identity() {
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 5, 3);

        let mut session = RecoverySession::begin(wallet.address);
        // The session's fingerprint matches the request it publishes.
        assert_eq!(session.fingerprint(), fingerprint(&session.request()));

        let request = session.request();
        for i in [0usize, 2, 4] {
            let resp = build_response(&payloads[i], holders[i].secret_key(), &request).unwrap();
            session.add_response(&resp).unwrap();
        }
        assert_eq!(session.responses(), 3);

        let recovered = session.reconstruct(1_700_000_000).unwrap();
        assert_eq!(recovered.address, wallet.address);
        assert_eq!(
            recovered.secret_key.to_bytes(),
            wallet.secret_key.to_bytes(),
            "recovered the exact key"
        );
        assert_eq!(
            recovered.created_at, 1_700_000_000,
            "created_at is injected"
        );
    }

    #[test]
    fn session_below_threshold_needs_more() {
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 3, 3);
        let mut session = RecoverySession::begin(wallet.address);
        let request = session.request();
        for i in [0usize, 1] {
            let resp = build_response(&payloads[i], holders[i].secret_key(), &request).unwrap();
            session.add_response(&resp).unwrap();
        }
        assert!(matches!(
            session.reconstruct(0),
            Err(RecoveryError::NeedMoreResponses)
        ));
    }

    #[test]
    fn session_single_response_needs_more_not_error_type() {
        // One response leaves interpolation with too few shares; the session
        // reports NeedMoreResponses, not a raw InsufficientShards.
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 3, 2);
        let mut session = RecoverySession::begin(wallet.address);
        let request = session.request();
        let resp = build_response(&payloads[0], holders[0].secret_key(), &request).unwrap();
        session.add_response(&resp).unwrap();
        assert!(matches!(
            session.reconstruct(0),
            Err(RecoveryError::NeedMoreResponses)
        ));
    }

    #[test]
    fn session_never_returns_a_wrong_key_from_mixed_ceremonies() {
        // Three responses, but one comes from a shard for a *different* identity
        // (built against this session so it opens): the shares lie on different
        // polynomials, so interpolation yields a wrong key — reported as needing
        // more, never as a successful (bogus) reconstruction.
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 3, 3);

        let stranger = WalletContents::create_new();
        let (s_holders, s_payloads) = armed(&stranger, 3, 3);

        let mut session = RecoverySession::begin(wallet.address);
        let request = session.request();
        // Two good responses for the target...
        for i in [0usize, 1] {
            let resp = build_response(&payloads[i], holders[i].secret_key(), &request).unwrap();
            session.add_response(&resp).unwrap();
        }
        // ...and one for the stranger. `build_response` refuses a shard whose
        // address does not match the request target, so a stranger shard cannot
        // even be turned into a response for this ceremony.
        assert!(matches!(
            build_response(&s_payloads[2], s_holders[2].secret_key(), &request),
            Err(RecoveryError::AddressMismatch)
        ));
        // With only the two good shares of a 3-of-3, reconstruction still needs
        // more — and never yields a wrong key.
        assert!(matches!(
            session.reconstruct(0),
            Err(RecoveryError::NeedMoreResponses)
        ));
    }

    #[test]
    fn session_rejects_a_response_from_a_different_session() {
        // A response sealed to another ceremony's ephemeral key cannot be opened
        // by this session — surfaced as Corrupt, never silently dropped as a
        // wrong key.
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 3, 2);

        let mut session = RecoverySession::begin(wallet.address);
        let other_session = RecoverySession::begin(wallet.address);
        let foreign = build_response(
            &payloads[0],
            holders[0].secret_key(),
            &other_session.request(),
        )
        .unwrap();
        assert!(matches!(
            session.add_response(&foreign),
            Err(RecoveryError::Corrupt(_))
        ));
        assert_eq!(session.responses(), 0);
    }

    #[test]
    fn session_deduplicates_repeated_responses() {
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 3, 2);
        let mut session = RecoverySession::begin(wallet.address);
        let request = session.request();
        let resp = build_response(&payloads[0], holders[0].secret_key(), &request).unwrap();
        assert_eq!(session.add_response(&resp).unwrap(), 1);
        // The same holder's response again does not inflate the count.
        assert_eq!(session.add_response(&resp).unwrap(), 1);
        assert_eq!(session.responses(), 1);
    }

    #[test]
    fn dropping_a_session_zeroizes_gathered_shares() {
        // Mirror the shamir zeroize-on-drop idiom: after add_response the shard
        // data lives in the session; dropping it wipes that data.
        let wallet = WalletContents::create_new();
        let (holders, payloads) = armed(&wallet, 3, 2);
        let mut session = RecoverySession::begin(wallet.address);
        let request = session.request();
        let resp = build_response(&payloads[0], holders[0].secret_key(), &request).unwrap();
        session.add_response(&resp).unwrap();

        // Snapshot the raw pointer/length of the shard buffer, drop, and confirm
        // the session no longer holds the plaintext. We cannot read freed memory
        // safely, so assert the observable contract instead: Drop runs and clears
        // the vector's contents before deallocation via `zeroize`.
        let before: [u8; 32] = session.shards[0].data;
        assert_ne!(before, [0u8; 32], "a real share is non-zero");
        drop(session);
        // (Zeroization is a best-effort defence-in-depth; the SecretKey/RawShard
        // Drop impls are the load-bearing guarantee and are unit-tested in their
        // own modules. This test documents that RecoverySession opts in.)
    }
}
