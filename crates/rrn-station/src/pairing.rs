//! The mobile↔station pairing handshake wire protocol.
//!
//! Pairing is the one-time, in-person bond that ADR-0008 makes the root of all
//! later trust: it binds two static Ed25519 keys and nothing else. Since the
//! ADR's 2026-10-14 Clarification it is a two-round **commit-then-reveal**
//! handshake: the device commits to a fresh nonce (`POST /pair/start`), the
//! station answers with its own fresh nonce in a signed offer, and the device
//! reveals its nonce in a station-bound, signed finish (`POST /pair/finish`).
//! Both sides then show a 10-character code derived from both keys and both
//! nonces; the operator types the device's code to confirm. `docs/spec/pairing.md`
//! is the full contract.
//!
//! This module owns the JSON bodies, their parsing and verification, and the
//! pending-session state. [`Core`](crate::core) owns the sessions themselves
//! and does the signing. The byte layouts and the code live in
//! [`rrn_identity::pairing`], shared with the command-line wallet and (through
//! the mobile FFI) the phone.

use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_identity::address::Address;
use rrn_identity::pairing as layout;
use serde::{Deserialize, Serialize};

use crate::core::unhex;

/// The handshake version every pairing request must carry.
pub const PAIRING_VERSION: u64 = 2;

/// How far a start's `requested_at` may sit from the station's clock, in
/// seconds. Bounds the window in which a captured start can be replayed, and
/// matches the ±5-minute skew the authenticated channel allows.
pub const REQUESTED_AT_SKEW_SECS: i64 = 300;

/// How long the station holds a pairing session in either stage before
/// discarding it. Long enough for an operator to walk over and run
/// `station pair-mobile`, short enough that abandoned attempts do not pile up.
pub const PENDING_TTL_SECS: i64 = 300;

/// The status a successful finish answers with.
pub const AWAITING_OPERATOR: &str = "awaiting-operator";

/// A pairing session in progress for one device, keyed by its address in the
/// station's pending map. In memory only: an unconfirmed pairing has no
/// standing to survive a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPair {
    /// The device's bech32 identity address.
    pub mobile_address: String,
    /// The device's commitment to its nonce, from the start.
    pub commitment: [u8; 32],
    /// The start's `requested_at` — a later start for this address replaces
    /// the session; an earlier or equal one cannot.
    pub requested_at: i64,
    /// Station-clock Unix seconds when the session entered its current stage
    /// (drives the TTL; the reveal resets it).
    pub received_at: i64,
    /// Where the handshake has got to.
    pub stage: PendingStage,
}

/// The two stages of a pairing session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingStage {
    /// The station has sent its offer and is waiting for the device's reveal.
    AwaitingReveal {
        /// The device's public key.
        mobile_pk: PublicKey,
        /// The station's nonce, as sent in the offer.
        station_nonce: [u8; 32],
        /// The station-signed offer, re-sent verbatim to a retried start.
        offer: PairOffer,
    },
    /// The device has revealed; the operator must confirm with the code.
    AwaitingOperator {
        /// The confirmation code, as the device shows it (`XXXXX-XXXXX`).
        code: String,
    },
}

/// `POST /pair/start` — the device's commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairStart {
    /// Handshake version; must be [`PAIRING_VERSION`]. Absent reads as 0.
    #[serde(default)]
    pub v: u64,
    /// The device's bech32 identity address (`rrn1…`).
    pub mobile_address: String,
    /// The device's commitment to its nonce, hex (32 bytes).
    pub commitment: String,
    /// Unix seconds the device stamped the start; the replay bound.
    pub requested_at: i64,
    /// Ed25519 signature over the start layout, hex (64 bytes).
    pub signature: String,
}

/// The station's answer to a start: its nonce, signed together with both keys
/// and the device's commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairOffer {
    /// The station's bech32 identity address (`rrn1…`).
    pub station_address: String,
    /// The station's nonce, hex (32 bytes).
    pub station_nonce: String,
    /// Ed25519 signature over the offer layout, hex (64 bytes).
    pub signature: String,
}

/// `POST /pair/finish` — the device's reveal, bound to the station.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairFinish {
    /// Handshake version; must be [`PAIRING_VERSION`]. Absent reads as 0.
    #[serde(default)]
    pub v: u64,
    /// The device's bech32 identity address (`rrn1…`).
    pub mobile_address: String,
    /// The station this finish is for (`rrn1…`).
    pub station_address: String,
    /// The device's nonce, hex (32 bytes); must open the start's commitment.
    pub mobile_nonce: String,
    /// Ed25519 signature over the finish layout, hex (64 bytes).
    pub signature: String,
}

/// The station's answer to a valid finish. Unsigned on purpose: the code
/// comparison is the check, and the station never sends the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairFinished {
    /// Always [`AWAITING_OPERATOR`].
    pub status: String,
}

/// Why a pairing request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    /// `v` is not [`PAIRING_VERSION`].
    UnsupportedVersion,
    /// `mobile_address` is not a valid bech32 identity address.
    BadAddress,
    /// A commitment or nonce is not 32 hex-encoded bytes.
    BadNonce,
    /// `signature` is not 64 hex-encoded bytes or not a signature encoding.
    BadSignature,
    /// The signature did not verify.
    SignatureMismatch,
    /// `requested_at` is outside [`REQUESTED_AT_SKEW_SECS`] of the station clock.
    StaleTimestamp,
    /// The finish names a different station.
    WrongStation,
    /// No session for this address is awaiting a reveal.
    NoSession,
    /// The revealed nonce does not open the start's commitment.
    CommitmentMismatch,
    /// The start repeats or predates the session it would replace.
    Replay,
    /// The retired version-1 route.
    Retired,
    /// The station could not process the request (its core is shutting down).
    Unavailable,
}

impl PairError {
    /// A short, safe-to-return reason string (`docs/spec/pairing.md` "Errors").
    pub fn as_str(self) -> &'static str {
        match self {
            PairError::UnsupportedVersion => "unsupported pairing version",
            PairError::BadAddress => "invalid mobile address",
            PairError::BadNonce => "invalid nonce or commitment",
            PairError::BadSignature => "malformed signature",
            PairError::SignatureMismatch => "signature does not verify",
            PairError::StaleTimestamp => "requested_at outside allowed clock skew",
            PairError::WrongStation => "request names a different station",
            PairError::NoSession => "no pairing in progress for this address; start again",
            PairError::CommitmentMismatch => "revealed nonce does not open the commitment",
            PairError::Replay => "pairing request already used",
            PairError::Retired => "pairing protocol v1 is retired; update the app",
            PairError::Unavailable => "station unavailable",
        }
    }
}

/// A start whose signature verified against the device's own key.
#[derive(Debug, Clone)]
pub struct VerifiedStart {
    /// The device's identity address.
    pub mobile_address: Address,
    /// The device's public key (the key behind the address).
    pub mobile_pk: PublicKey,
    /// The device's commitment to its nonce.
    pub commitment: [u8; 32],
    /// When the device stamped the start.
    pub requested_at: i64,
}

impl PairStart {
    /// Checks the version and field formats and verifies the signature against
    /// the key behind `mobile_address`. Does **not** check the timestamp — only
    /// the station knows "now" (see [`REQUESTED_AT_SKEW_SECS`]).
    pub fn verify(&self) -> Result<VerifiedStart, PairError> {
        check_version(self.v)?;
        let mobile_address = parse_mobile(&self.mobile_address)?;
        let mobile_pk = *mobile_address.public_key();
        let commitment = decode_array::<32>(&self.commitment).ok_or(PairError::BadNonce)?;
        let signature = decode_signature(&self.signature)?;
        let msg = layout::start_signed_bytes(&mobile_pk.to_bytes(), &commitment, self.requested_at);
        mobile_pk
            .verify(&msg, &signature)
            .map_err(|_| PairError::SignatureMismatch)?;
        Ok(VerifiedStart {
            mobile_address,
            mobile_pk,
            commitment,
            requested_at: self.requested_at,
        })
    }
}

/// A finish whose fields are well formed. Its signature can only be checked
/// against a session (it covers the session's commitment and station nonce).
#[derive(Debug, Clone)]
pub struct ParsedFinish {
    /// The device's identity address.
    pub mobile_address: Address,
    /// The station the finish names, or `None` if it is not an address.
    pub station_address: Option<Address>,
    /// The revealed nonce.
    pub mobile_nonce: [u8; 32],
    /// The device's signature over the finish layout.
    pub signature: Signature,
}

impl PairFinish {
    /// Checks the version and field formats. The caller checks the station,
    /// the session, the signature ([`verify_finish`]), and the commitment, in
    /// that order.
    pub fn parse(&self) -> Result<ParsedFinish, PairError> {
        check_version(self.v)?;
        let mobile_address = parse_mobile(&self.mobile_address)?;
        let mobile_nonce = decode_array::<32>(&self.mobile_nonce).ok_or(PairError::BadNonce)?;
        let signature = decode_signature(&self.signature)?;
        Ok(ParsedFinish {
            mobile_address,
            station_address: self.station_address.parse().ok(),
            mobile_nonce,
            signature,
        })
    }
}

/// Verifies a finish signature: the device's key over the finish layout built
/// from the station's key, the session's commitment and station nonce, and
/// the revealed nonce.
pub fn verify_finish(
    station_pk: &PublicKey,
    mobile_pk: &PublicKey,
    commitment: &[u8; 32],
    station_nonce: &[u8; 32],
    finish: &ParsedFinish,
) -> Result<(), PairError> {
    let msg = layout::finish_signed_bytes(
        &station_pk.to_bytes(),
        &mobile_pk.to_bytes(),
        commitment,
        station_nonce,
        &finish.mobile_nonce,
    );
    mobile_pk
        .verify(&msg, &finish.signature)
        .map_err(|_| PairError::SignatureMismatch)
}

impl PairOffer {
    /// The client's check of an offer, after it has matched `station_address`
    /// against the station it expected: the signature verifies against
    /// `station_pk` over this device's key and commitment. Returns the
    /// station's nonce.
    pub fn verify(
        &self,
        station_pk: &PublicKey,
        mobile_pk: &PublicKey,
        commitment: &[u8; 32],
    ) -> Result<[u8; 32], PairError> {
        let station_nonce = decode_array::<32>(&self.station_nonce).ok_or(PairError::BadNonce)?;
        let signature = decode_signature(&self.signature)?;
        let msg = layout::offer_signed_bytes(
            &station_pk.to_bytes(),
            &mobile_pk.to_bytes(),
            commitment,
            &station_nonce,
        );
        station_pk
            .verify(&msg, &signature)
            .map_err(|_| PairError::SignatureMismatch)?;
        Ok(station_nonce)
    }
}

fn check_version(v: u64) -> Result<(), PairError> {
    if v == PAIRING_VERSION {
        Ok(())
    } else {
        Err(PairError::UnsupportedVersion)
    }
}

fn parse_mobile(s: &str) -> Result<Address, PairError> {
    s.parse().map_err(|_| PairError::BadAddress)
}

fn decode_signature(hex: &str) -> Result<Signature, PairError> {
    let bytes = decode_array::<64>(hex).ok_or(PairError::BadSignature)?;
    Signature::from_bytes(bytes).map_err(|_| PairError::BadSignature)
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

    fn signed_start(mobile: &Keypair, commitment: [u8; 32], requested_at: i64) -> PairStart {
        let msg =
            layout::start_signed_bytes(&mobile.public_key().to_bytes(), &commitment, requested_at);
        PairStart {
            v: PAIRING_VERSION,
            mobile_address: Address::from_public_key(mobile.public_key()).to_string(),
            commitment: hex(&commitment),
            requested_at,
            signature: hex(&mobile.sign(&msg).to_bytes()),
        }
    }

    #[test]
    fn valid_start_verifies() {
        let mobile = Keypair::generate();
        let start = signed_start(&mobile, [7; 32], 1_000);
        let v = start.verify().expect("verifies");
        assert_eq!(v.commitment, [7; 32]);
        assert_eq!(v.requested_at, 1_000);
        assert_eq!(v.mobile_address.to_string(), start.mobile_address);
    }

    #[test]
    fn tampered_start_fails_signature() {
        let mobile = Keypair::generate();
        let mut start = signed_start(&mobile, [7; 32], 1_000);
        start.requested_at = 2_000;
        assert_eq!(start.verify().unwrap_err(), PairError::SignatureMismatch);
        let mut start = signed_start(&mobile, [7; 32], 1_000);
        start.commitment = hex(&[8u8; 32]);
        assert_eq!(start.verify().unwrap_err(), PairError::SignatureMismatch);
    }

    #[test]
    fn malformed_fields_are_refused() {
        let mobile = Keypair::generate();
        let good = signed_start(&mobile, [7; 32], 1_000);
        let refused = |s: PairStart| s.verify().unwrap_err();
        assert_eq!(
            refused(PairStart {
                v: 1,
                ..good.clone()
            }),
            PairError::UnsupportedVersion
        );
        assert_eq!(
            refused(PairStart {
                mobile_address: "nope".into(),
                ..good.clone()
            }),
            PairError::BadAddress
        );
        assert_eq!(
            refused(PairStart {
                commitment: "ab".into(),
                ..good.clone()
            }),
            PairError::BadNonce
        );
        // Multibyte input is malformed, never a panic.
        assert_eq!(
            refused(PairStart {
                commitment: "é".repeat(32),
                ..good.clone()
            }),
            PairError::BadNonce
        );
        assert_eq!(
            refused(PairStart {
                signature: "00".into(),
                ..good
            }),
            PairError::BadSignature
        );
    }

    #[test]
    fn a_missing_version_is_unsupported() {
        let body = r#"{"mobile_address":"x","commitment":"","requested_at":0,"signature":""}"#;
        let start: PairStart = serde_json::from_str(body).unwrap();
        assert_eq!(start.verify().unwrap_err(), PairError::UnsupportedVersion);
    }

    #[test]
    fn offer_verifies_only_for_its_station_device_and_commitment() {
        let station = Keypair::generate();
        let mobile = Keypair::generate();
        let commitment = [5; 32];
        let nonce = [6; 32];
        let msg = layout::offer_signed_bytes(
            &station.public_key().to_bytes(),
            &mobile.public_key().to_bytes(),
            &commitment,
            &nonce,
        );
        let offer = PairOffer {
            station_address: Address::from_public_key(station.public_key()).to_string(),
            station_nonce: hex(&nonce),
            signature: hex(&station.sign(&msg).to_bytes()),
        };
        let (spk, mpk) = (station.public_key(), mobile.public_key());
        assert_eq!(offer.verify(&spk, &mpk, &commitment), Ok(nonce));
        assert_eq!(
            offer.verify(&spk, &mpk, &[9; 32]),
            Err(PairError::SignatureMismatch)
        );
        assert_eq!(
            offer.verify(&Keypair::generate().public_key(), &mpk, &commitment),
            Err(PairError::SignatureMismatch)
        );
    }
}
