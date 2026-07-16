//! The mobile↔station pairing handshake wire protocol (T1.3.3).
//!
//! Pairing is the one-time, in-person bond that ADR-0008 makes the root of all
//! later trust: it binds two static Ed25519 keys and nothing else. This module
//! owns the *format* of that handshake — the request a mobile POSTs to `/pair`,
//! the reply the station sends back, and exactly which bytes each signature
//! covers. [`Core`](crate::core) owns the *state* (pending requests, the paired
//! list) and does the signing; the pure byte-layout and verification live here
//! so they can be tested without a running station.
//!
//! ## Cross-implementation contract
//!
//! The signed byte layouts below are duplicated in the mobile's `Pairing` seam
//! and must match byte-for-byte, or no signature will ever verify across the
//! two implementations. Each layout is domain-separated by a version tag so a
//! signature made for one purpose can never be valid for another. These are a
//! deliberately simple fixed concatenation rather than the canonical-dCBOR
//! envelope of T1.3.4: pairing is the bootstrap that *establishes* the keys the
//! sealed request channel later relies on, and a fixed three-field layout is
//! easier to get identical on two platforms than a dCBOR encoder.

use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

use crate::core::unhex;

/// Domain tag over a mobile's pairing *request*.
const REQUEST_TAG: &[u8] = b"rrn-pair-req-v1";
/// Domain tag over a station's pairing *response*.
const RESPONSE_TAG: &[u8] = b"rrn-pair-resp-v1";

/// How far a request's `requested_at` may sit from the station's clock, in
/// seconds. Bounds the window in which a captured request can be replayed, and
/// matches the ±5-minute skew the authenticated channel (T1.3.4) will allow.
pub const REQUESTED_AT_SKEW_SECS: i64 = 300;

/// How long the station holds an accepted-but-unconfirmed pairing request before
/// discarding it. Long enough for an operator to walk over and run
/// `station pair-mobile`, short enough that abandoned attempts do not pile up.
pub const PENDING_TTL_SECS: i64 = 300;

/// A pairing request the station has accepted (signature valid, timestamp
/// fresh) and is holding until the operator confirms it or it expires. This is
/// what `station pair-mobile` lists so the operator can read the [`sas`] aloud
/// and compare it with the code on the mobile's screen (T1.3.3).
///
/// [`sas`]: PendingPair::sas
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPair {
    /// The requesting mobile's bech32 identity address.
    pub mobile_address: String,
    /// The 8-hex confirmation code both sides display.
    pub sas: String,
    /// Station-clock Unix seconds when the request was accepted (drives the TTL).
    pub received_at: i64,
}

/// A mobile's pairing request, as it arrives on the wire (JSON body of
/// `POST /pair`). `mobile_address` is bech32; `token` and `signature` are hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    /// The mobile's bech32 identity address (`rrn1…`).
    pub mobile_address: String,
    /// 32 random bytes, hex-encoded — a nonce that makes each request distinct.
    pub token: String,
    /// Unix seconds the mobile stamped the request; the replay bound.
    pub requested_at: i64,
    /// Ed25519 signature over [`request_signed_bytes`], hex-encoded (64 bytes).
    pub signature: String,
}

/// The station's reply to a pairing request. Proves the station holds the key
/// behind `station_address` and binds the reply to the request's `token`, so a
/// captured reply cannot be replayed against a different request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    /// The station's bech32 identity address (`rrn1…`).
    pub station_address: String,
    /// Ed25519 signature over [`response_signed_bytes`], hex-encoded (64 bytes).
    pub signature: String,
}

/// Why a pairing request was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    /// `mobile_address` is not a valid bech32 identity address.
    BadAddress,
    /// `token` is not 32 hex-encoded bytes.
    BadToken,
    /// `signature` is not 64 hex-encoded bytes.
    BadSignature,
    /// The signature did not verify against the mobile's key.
    SignatureMismatch,
    /// `requested_at` is outside [`REQUESTED_AT_SKEW_SECS`] of the station clock.
    StaleTimestamp,
    /// The station could not process the request (its core is shutting down).
    Unavailable,
}

impl PairError {
    /// A short, safe-to-return reason string.
    pub fn as_str(self) -> &'static str {
        match self {
            PairError::BadAddress => "invalid mobile address",
            PairError::BadToken => "invalid token",
            PairError::BadSignature => "malformed signature",
            PairError::SignatureMismatch => "signature does not verify",
            PairError::StaleTimestamp => "requested_at outside allowed clock skew",
            PairError::Unavailable => "station unavailable",
        }
    }
}

/// The exact bytes a mobile signs to prove it holds the key behind
/// `mobile`: `TAG ‖ mobile_pubkey(32) ‖ token(32) ‖ requested_at(8, big-endian)`.
pub fn request_signed_bytes(mobile: &PublicKey, token: &[u8; 32], requested_at: i64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REQUEST_TAG.len() + 32 + 32 + 8);
    msg.extend_from_slice(REQUEST_TAG);
    msg.extend_from_slice(&mobile.to_bytes());
    msg.extend_from_slice(token);
    msg.extend_from_slice(&requested_at.to_be_bytes());
    msg
}

/// The exact bytes a station signs to prove it holds the key behind `station`
/// and to bind its reply to this request's token: `TAG ‖ station_pubkey(32) ‖
/// token(32)`.
pub fn response_signed_bytes(station: &PublicKey, token: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RESPONSE_TAG.len() + 32 + 32);
    msg.extend_from_slice(RESPONSE_TAG);
    msg.extend_from_slice(&station.to_bytes());
    msg.extend_from_slice(token);
    msg
}

/// A pairing request whose signature has been verified against the mobile's own
/// key. Holding one of these is proof the requester controls `mobile_address`.
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    /// The mobile's identity address.
    pub mobile_address: Address,
    /// The mobile's public key (extracted from the address).
    pub mobile_pubkey: PublicKey,
    /// The request nonce.
    pub token: [u8; 32],
    /// When the mobile stamped the request.
    pub requested_at: i64,
}

impl PairRequest {
    /// Parses the wire fields and verifies the signature against the key behind
    /// `mobile_address`. Does **not** check the timestamp — the caller compares
    /// `requested_at` against its own clock (see [`REQUESTED_AT_SKEW_SECS`]),
    /// because only the station knows "now".
    pub fn verify(&self) -> Result<VerifiedRequest, PairError> {
        let mobile_address: Address = self
            .mobile_address
            .parse()
            .map_err(|_| PairError::BadAddress)?;
        let mobile_pubkey = *mobile_address.public_key();

        let token = decode_array::<32>(&self.token).ok_or(PairError::BadToken)?;
        let sig_bytes = decode_array::<64>(&self.signature).ok_or(PairError::BadSignature)?;
        let signature = Signature::from_bytes(sig_bytes).map_err(|_| PairError::BadSignature)?;

        let msg = request_signed_bytes(&mobile_pubkey, &token, self.requested_at);
        mobile_pubkey
            .verify(&msg, &signature)
            .map_err(|_| PairError::SignatureMismatch)?;

        Ok(VerifiedRequest {
            mobile_address,
            mobile_pubkey,
            token,
            requested_at: self.requested_at,
        })
    }
}

/// Decodes exactly `N` bytes of hex, or `None` if the length or alphabet is
/// wrong.
fn decode_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let bytes = unhex(hex)?;
    bytes.as_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::hex;
    use rrn_crypto::keypair::Keypair;

    /// Builds a validly-signed request from a mobile keypair.
    fn signed_request(mobile: &Keypair, requested_at: i64) -> PairRequest {
        let token = [7u8; 32];
        let msg = request_signed_bytes(&mobile.public_key(), &token, requested_at);
        let signature = mobile.sign(&msg);
        PairRequest {
            mobile_address: Address::from_public_key(mobile.public_key()).to_string(),
            token: hex(&token),
            requested_at,
            signature: hex(&signature.to_bytes()),
        }
    }

    #[test]
    fn valid_request_verifies() {
        let mobile = Keypair::generate();
        let req = signed_request(&mobile, 1_000);
        let verified = req.verify().expect("verifies");
        assert_eq!(verified.token, [7u8; 32]);
        assert_eq!(verified.requested_at, 1_000);
        assert_eq!(
            verified.mobile_address.to_string(),
            req.mobile_address,
            "address round-trips"
        );
    }

    #[test]
    fn tampered_timestamp_fails_signature() {
        let mobile = Keypair::generate();
        let mut req = signed_request(&mobile, 1_000);
        req.requested_at = 2_000; // signature was over 1_000
        assert_eq!(req.verify().unwrap_err(), PairError::SignatureMismatch);
    }

    #[test]
    fn signature_from_a_different_key_fails() {
        let mobile = Keypair::generate();
        let attacker = Keypair::generate();
        let mut req = signed_request(&mobile, 1_000);
        // Re-sign with the attacker's key but keep the victim's address.
        let token = [7u8; 32];
        let msg = request_signed_bytes(&mobile.public_key(), &token, 1_000);
        req.signature = hex(&attacker.sign(&msg).to_bytes());
        assert_eq!(req.verify().unwrap_err(), PairError::SignatureMismatch);
    }

    #[test]
    fn malformed_fields_are_rejected() {
        let mobile = Keypair::generate();
        let good = signed_request(&mobile, 1_000);

        let bad_addr = PairRequest {
            mobile_address: "not-an-address".into(),
            ..good.clone()
        };
        assert_eq!(bad_addr.verify().unwrap_err(), PairError::BadAddress);

        let bad_token = PairRequest {
            token: "xyz".into(),
            ..good.clone()
        };
        assert_eq!(bad_token.verify().unwrap_err(), PairError::BadToken);

        let bad_sig = PairRequest {
            signature: "00".into(),
            ..good
        };
        assert_eq!(bad_sig.verify().unwrap_err(), PairError::BadSignature);
    }

    #[test]
    fn response_bytes_bind_station_key_and_token() {
        let station = Keypair::generate();
        let token = [3u8; 32];
        let msg = response_signed_bytes(&station.public_key(), &token);
        let sig = station.sign(&msg);
        assert!(station.public_key().verify(&msg, &sig).is_ok());
        // A different token yields different signed bytes.
        let other = response_signed_bytes(&station.public_key(), &[4u8; 32]);
        assert_ne!(msg, other);
    }
}
