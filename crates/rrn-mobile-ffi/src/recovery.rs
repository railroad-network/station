//! FFI wrapper for social recovery (T1.2.3).
//!
//! Thin marshalling over `rrn_identity::recovery` — no cryptographic logic of
//! its own. The mobile owner builds a [`RecoveryPackage`] from their wallet and
//! a set of holder addresses, then reads one self-contained *shard payload* per
//! holder to distribute (as a QR). A holder's app calls [`parse_shard_payload`]
//! to read the non-secret routing metadata off a scanned payload so it can
//! confirm the shard is addressed to it and file it under the original address.
//!
//! # What does not cross the boundary
//!
//! The wallet secret is never exposed: [`RecoveryPackage::create`] takes an
//! opaque [`WalletContents`] handle, splits and seals entirely inside Rust, and
//! only the per-holder *sealed* shard payloads leave. `parse_shard_payload`
//! reads metadata only — it cannot and does not decrypt a shard (that needs the
//! holder's secret key, and only happens during reconstruction, which this
//! surface does not expose).

use std::sync::Arc;

use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::{self, RecoveryRequest};
use rrn_identity::recovery::flow::{
    parse_shard_payload as core_parse_shard_payload, RecoveryError as CoreRecoveryError,
    RecoveryPackage as CoreRecoveryPackage,
};

use crate::WalletContents;

/// Error surfaced across the FFI boundary for recovery operations.
///
/// Flat and coarse by design, like the other FFI error enums: the mobile UI
/// does not branch on the crate-local detail. Several `RecoveryError` variants
/// of the underlying crate cannot arise on this surface (it never reconstructs,
/// re-derives an address, or touches the filesystem) and are folded into
/// `Internal` rather than widening the enum.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// More holders were supplied than the split cap (16) allows.
    #[error("too many holders")]
    TooManyHolders,
    /// The threshold/total split parameters were invalid (e.g. K below 2 or
    /// above N).
    #[error("invalid recovery parameters")]
    InvalidParameters,
    /// A holder address string was not a valid `rrn1…` address.
    #[error("invalid holder address")]
    InvalidHolderAddress,
    /// A shard index passed to `shard_payload` was outside `0..shard_count`.
    #[error("shard index out of range")]
    ShardIndexOutOfRange,
    /// A shard could not be sealed to its holder.
    #[error("shard encryption failed")]
    Encryption,
    /// A shard payload was not valid canonical CBOR or had the wrong shape.
    #[error("corrupt shard payload")]
    Corrupt,
    /// A held shard is for a different identity than a recovery request targets.
    #[error("shard is for a different identity")]
    AddressMismatch,
    /// An unexpected error from the recovery core (not reachable on this
    /// surface; present so the conversion is total).
    #[error("internal recovery error")]
    Internal,
}

impl From<CoreRecoveryError> for RecoveryError {
    fn from(e: CoreRecoveryError) -> Self {
        match e {
            CoreRecoveryError::TooManyHolders { .. } => RecoveryError::TooManyHolders,
            CoreRecoveryError::Split(_) => RecoveryError::InvalidParameters,
            CoreRecoveryError::ShardCrypto(_) => RecoveryError::Encryption,
            CoreRecoveryError::Corrupt(_) => RecoveryError::Corrupt,
            CoreRecoveryError::ShardIndexOutOfRange => RecoveryError::ShardIndexOutOfRange,
            // A holder can hold a shard for the wrong identity; surface that.
            CoreRecoveryError::AddressMismatch => RecoveryError::AddressMismatch,
            // Reconstruction and file I/O do not happen on this FFI surface.
            CoreRecoveryError::Reconstruct(_) | CoreRecoveryError::Io(_) => RecoveryError::Internal,
        }
    }
}

/// Non-secret metadata read off a distributable shard payload, for a holder's
/// receive flow.
pub struct ShardInfo {
    /// The `rrn1…` address of the identity this shard helps recover. The holder
    /// app files the payload under this key.
    pub original_address: String,
    /// The `rrn1…` address this shard is sealed to — the receiving holder can
    /// check it matches their own identity ("is this shard for me?").
    pub holder_address: String,
    /// `K` — how many holders must cooperate to reconstruct.
    pub threshold: u8,
    /// `N` — how many holders the secret was split across.
    pub total: u8,
}

/// FFI handle to a social-recovery package: `N` shards of the wallet secret,
/// each sealed to a holder, any `K` of which reconstruct the identity. The
/// package's secret material never crosses the boundary — only the per-holder
/// sealed shard payloads, read out one at a time via [`Self::shard_payload`].
pub struct RecoveryPackage {
    inner: CoreRecoveryPackage,
}

impl RecoveryPackage {
    /// Splits `wallet`'s secret into one sealed shard per entry in
    /// `holder_addresses`, requiring `threshold` (`K`) of the holders
    /// (`N = holder_addresses.len()`) to reconstruct. Each holder address is a
    /// bech32m `rrn1…` string; `K` must satisfy `2 <= K <= N <= 16`.
    pub fn create(
        wallet: Arc<WalletContents>,
        holder_addresses: Vec<String>,
        threshold: u8,
    ) -> Result<Self, RecoveryError> {
        let mut pubkeys = Vec::with_capacity(holder_addresses.len());
        for addr in &holder_addresses {
            let parsed: Address = addr
                .parse()
                .map_err(|_| RecoveryError::InvalidHolderAddress)?;
            pubkeys.push(*parsed.public_key());
        }
        Ok(Self {
            inner: CoreRecoveryPackage::create(&wallet.inner, &pubkeys, threshold)?,
        })
    }

    /// `K` — decrypted shards required to reconstruct.
    pub fn threshold(&self) -> u8 {
        self.inner.threshold
    }

    /// `N` — total shards / holders.
    pub fn total(&self) -> u8 {
        self.inner.total
    }

    /// The number of sealed shards (equals [`Self::total`]); the valid range of
    /// indices for [`Self::shard_payload`] is `0..shard_count`.
    pub fn shard_count(&self) -> u32 {
        self.inner.shards.len() as u32
    }

    /// The self-contained, distributable payload for the shard at `index`:
    /// canonical CBOR of `{original_address, threshold, total, sealed shard}`.
    ///
    /// The holder scans this (e.g. as a QR) and stores it; it carries the shard
    /// sealed to that holder plus the public metadata needed to route it and to
    /// later reconstruct. Only the addressed holder's secret key can open the
    /// sealed shard, so the payload is safe to move over an untrusted channel.
    pub fn shard_payload(&self, index: u32) -> Result<Vec<u8>, RecoveryError> {
        // Delegate to the core producer so the phone and the station emit
        // byte-identical payloads (the station's `recovery setup` calls the same
        // `RecoveryPackage::shard_payload`).
        self.inner
            .shard_payload(index as usize)
            .map_err(|_| RecoveryError::ShardIndexOutOfRange)
    }
}

/// Reads the non-secret metadata off a distributable shard payload (the bytes
/// from [`RecoveryPackage::shard_payload`]), for a holder's receive flow.
///
/// Does not — and cannot — decrypt the shard: it only reads the routing
/// metadata so the holder app can confirm the shard is addressed to it and
/// store the payload under the original address. `Corrupt` if the bytes are not
/// canonical CBOR or do not match the payload shape.
pub fn parse_shard_payload(payload: Vec<u8>) -> Result<ShardInfo, RecoveryError> {
    let parsed = core_parse_shard_payload(&payload)?;
    Ok(ShardInfo {
        original_address: parsed.original_address.to_string(),
        holder_address: parsed.shard.holder.to_string(),
        threshold: parsed.threshold,
        total: parsed.total,
    })
}

/// A holder's contribution to a recovery ceremony: turn the shard they hold into
/// a raw Shamir share re-sealed to the operator's ephemeral recovery key (T1.11.3
/// slice D). `stored_shard_payload` is the payload the holder received and
/// stored; `request_payload` is the operator's [`RecoveryRequest`] bytes.
///
/// The returned bytes are the sealed response for the operator to collect. The
/// raw share is never exposed in the clear — only the recovery secret opens it.
/// `Corrupt` on a malformed input; `AddressMismatch` if the held shard is for a
/// different identity than the request targets.
pub fn respond_to_recovery(
    wallet: Arc<WalletContents>,
    stored_shard_payload: Vec<u8>,
    request_payload: Vec<u8>,
) -> Result<Vec<u8>, RecoveryError> {
    let request = RecoveryRequest::from_bytes(&request_payload)?;
    Ok(ceremony::build_response(
        &stored_shard_payload,
        &wallet.inner.secret_key,
        &request,
    )?)
}

/// Reads which identity a recovery request targets, so a holder's app can show
/// what it is being asked to help recover before contributing a shard.
pub fn parse_recovery_request(
    request_payload: Vec<u8>,
) -> Result<RecoveryRequestInfo, RecoveryError> {
    let request = RecoveryRequest::from_bytes(&request_payload)?;
    Ok(RecoveryRequestInfo {
        target_address: request.target_address.to_string(),
    })
}

/// Non-secret description of a recovery request, for a holder's confirm screen.
pub struct RecoveryRequestInfo {
    /// The `rrn1…` address of the identity being recovered.
    pub target_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A wallet handle plus `n` holder addresses (freshly generated identities).
    fn wallet_and_holder_addresses(n: usize) -> (Arc<WalletContents>, Vec<String>) {
        let wallet = Arc::new(WalletContents::create_new());
        let holders = (0..n)
            .map(|_| crate::Keypair::generate().public_key().to_address())
            .collect();
        (wallet, holders)
    }

    #[test]
    fn create_exposes_threshold_total_and_shard_count() {
        let (wallet, holders) = wallet_and_holder_addresses(5);
        let package = RecoveryPackage::create(wallet, holders, 3).expect("create");
        assert_eq!(package.threshold(), 3);
        assert_eq!(package.total(), 5);
        assert_eq!(package.shard_count(), 5);
    }

    #[test]
    fn shard_payload_parses_back_to_matching_metadata() {
        let (wallet, holders) = wallet_and_holder_addresses(5);
        let original_address = wallet.address();
        let package = RecoveryPackage::create(wallet, holders.clone(), 3).expect("create");

        for (i, holder_addr) in holders.iter().enumerate() {
            let payload = package.shard_payload(i as u32).expect("shard_payload");
            let info = parse_shard_payload(payload).expect("parse");
            assert_eq!(info.original_address, original_address);
            assert_eq!(info.holder_address, *holder_addr);
            assert_eq!(info.threshold, 3);
            assert_eq!(info.total, 5);
        }
    }

    #[test]
    fn respond_to_recovery_produces_an_openable_response() {
        use rrn_identity::address::Address as CoreAddress;
        use rrn_identity::recovery::ceremony::{open_response, RecoveryRequest};

        // A holder wallet whose secret we control, plus a throwaway second
        // holder to satisfy N=2 / K=2.
        let holder = Arc::new(WalletContents::create_new());
        let holder_addr = holder.address();
        let other = crate::Keypair::generate().public_key().to_address();

        let station = Arc::new(WalletContents::create_new());
        let station_addr = station.address();
        let package =
            RecoveryPackage::create(station, vec![holder_addr, other], 2).expect("create");
        let payload = package.shard_payload(0).expect("shard_payload");

        // The operator's ephemeral recovery key and request.
        let recovery = rrn_crypto::keypair::Keypair::generate();
        let request = RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: station_addr.parse::<CoreAddress>().unwrap(),
        };
        let request_bytes = request.to_bytes();

        // The phone can read which identity it is being asked to recover.
        let info = parse_recovery_request(request_bytes.clone()).unwrap();
        assert_eq!(info.target_address, station_addr);

        // And produce a response the operator can open with the recovery secret.
        let response = respond_to_recovery(holder, payload, request_bytes).unwrap();
        assert!(!response.is_empty());
        assert!(open_response(&response, recovery.secret_key()).is_ok());
    }

    #[test]
    fn respond_to_recovery_rejects_a_shard_for_another_identity() {
        use rrn_identity::address::Address as CoreAddress;
        use rrn_identity::recovery::ceremony::RecoveryRequest;

        let holder = Arc::new(WalletContents::create_new());
        let other = crate::Keypair::generate().public_key().to_address();
        let station = Arc::new(WalletContents::create_new());
        let package =
            RecoveryPackage::create(station, vec![holder.address(), other], 2).expect("create");
        let payload = package.shard_payload(0).expect("shard_payload");

        let recovery = rrn_crypto::keypair::Keypair::generate();
        // Request targets a different identity than the shard is for.
        let stranger = crate::Keypair::generate().public_key().to_address();
        let request = RecoveryRequest {
            recovery_pubkey: recovery.public_key(),
            target_address: stranger.parse::<CoreAddress>().unwrap(),
        };
        assert!(matches!(
            respond_to_recovery(holder, payload, request.to_bytes()),
            Err(RecoveryError::AddressMismatch)
        ));
    }

    #[test]
    fn shard_payload_index_out_of_range_is_rejected() {
        let (wallet, holders) = wallet_and_holder_addresses(3);
        let package = RecoveryPackage::create(wallet, holders, 2).expect("create");
        assert!(matches!(
            package.shard_payload(3),
            Err(RecoveryError::ShardIndexOutOfRange)
        ));
    }

    #[test]
    fn invalid_holder_address_is_rejected() {
        let wallet = Arc::new(WalletContents::create_new());
        assert!(matches!(
            RecoveryPackage::create(
                wallet,
                vec!["rrn1notavalidaddress".to_string(), "garbage".to_string()],
                2,
            ),
            Err(RecoveryError::InvalidHolderAddress)
        ));
    }

    #[test]
    fn threshold_below_two_is_invalid_parameters() {
        let (wallet, holders) = wallet_and_holder_addresses(5);
        assert!(matches!(
            RecoveryPackage::create(wallet, holders, 1),
            Err(RecoveryError::InvalidParameters)
        ));
    }

    #[test]
    fn too_many_holders_is_rejected() {
        let (wallet, holders) = wallet_and_holder_addresses(17);
        assert!(matches!(
            RecoveryPackage::create(wallet, holders, 3),
            Err(RecoveryError::TooManyHolders)
        ));
    }

    #[test]
    fn garbage_payload_is_corrupt() {
        assert!(matches!(
            parse_shard_payload(vec![0xff, 0x00, 0x13]),
            Err(RecoveryError::Corrupt)
        ));
    }
}
