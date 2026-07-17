//! The authenticated request channel's envelope (T1.3.4, ADR-0008).
//!
//! After pairing (T1.3.3) establishes both static keys, every mobile request
//! travels as a **sealed, signed envelope** over plain HTTP. This module owns
//! the *format* and the pure verification; [`Core`](crate::core) owns the state
//! (the paired list, per-mobile nonces, the station keypair) and the dispatch.
//!
//! ## Construction: sign, then seal
//!
//! A request is built inner-to-outer:
//! 1. a [`RequestEnvelope`] — method, params, and the auth fields — is encoded
//!    to canonical dCBOR (ADR-0002), the same encoder the mobile drives through
//!    the FFI, so the bytes are byte-identical on both sides;
//! 2. the mobile signs those `payload` bytes with its Ed25519 identity key;
//! 3. `payload_len ‖ payload ‖ signature` is framed and **sealed**
//!    ([`crate::sealed`]) to the station's public key.
//!
//! The station opens the seal, verifies the signature over the exact `payload`
//! bytes it received (no re-canonicalization — it authenticates what arrived),
//! then makes the stateful checks. **`recipient` is bound inside the signed
//! payload**: without it a station could peel a signed request out of its
//! envelope and re-seal it to a third party, who would then hold a valid member
//! signature over a request never sent to them.
//!
//! ## params / result as JSON text
//!
//! `params` and `result` ride as JSON strings inside the dCBOR envelope rather
//! than as nested CBOR. The station already speaks `serde_json` for every
//! method's params (see [`crate::rpc`]); carrying them as text lets the channel
//! reuse the existing dispatch unchanged and keeps this module from having to
//! bridge dCBOR values to `serde_json::Value`. The signature covers the whole
//! canonical envelope regardless, so this costs no integrity.

use dcbor::prelude::*;

use rrn_crypto::keypair::{Keypair, PublicKey, Signature};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;

/// The envelope format version, bumped if the wire shape ever changes. Bound
/// inside the signed bytes so a downgrade cannot be forged.
pub const ENVELOPE_VERSION: u64 = 1;

/// How far a request's `timestamp` may sit from the station's clock, in seconds
/// — the replay window. Matches the pairing skew ([`crate::pairing`]).
pub const TIMESTAMP_SKEW_SECS: i64 = 300;

/// Length of the big-endian `u32` payload-length prefix in a framed request.
const LEN_PREFIX: usize = 4;
/// Length of an Ed25519 signature.
const SIG_LEN: usize = 64;

/// Why a request on the authenticated channel was rejected. Each maps to an
/// HTTP status at the edge ([`crate::mobile_server`]); the strings are safe to
/// return to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// The sealed box could not be opened with the station's key.
    Sealed,
    /// The framing or the dCBOR envelope was malformed.
    Malformed,
    /// An unsupported envelope version.
    UnsupportedVersion,
    /// The embedded signature did not decode or did not verify over the payload.
    BadSignature,
    /// The request was addressed (`recipient`) to a different station key.
    WrongRecipient,
    /// The signer is not a paired mobile.
    NotPaired,
    /// `timestamp` is outside [`TIMESTAMP_SKEW_SECS`] of the station clock.
    StaleTimestamp,
    /// The nonce was not strictly greater than the last seen for this signer.
    Replay,
    /// The core is shutting down.
    Unavailable,
}

impl ChannelError {
    /// A short, safe-to-return reason string.
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelError::Sealed => "could not open sealed request",
            ChannelError::Malformed => "malformed request envelope",
            ChannelError::UnsupportedVersion => "unsupported envelope version",
            ChannelError::BadSignature => "signature does not verify",
            ChannelError::WrongRecipient => "request addressed to a different station",
            ChannelError::NotPaired => "signer is not a paired mobile",
            ChannelError::StaleTimestamp => "timestamp outside allowed clock skew",
            ChannelError::Replay => "stale or replayed nonce",
            ChannelError::Unavailable => "station unavailable",
        }
    }
}

/// The inner, signed request. Its canonical dCBOR bytes are what the mobile
/// signs and the station verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    /// The method name, e.g. `"balance"` — routed through the same dispatch the
    /// Unix-socket RPC uses.
    pub method: String,
    /// Method params as a JSON string (parsed with `serde_json` after auth).
    pub params: String,
    /// The requesting mobile's public key. `Address::from_public_key` of this is
    /// the paired-list key the station authorizes against.
    pub signer: PublicKey,
    /// The station's public key this request is for — bound in the signed bytes
    /// so the envelope cannot be re-sealed to another recipient.
    pub recipient: PublicKey,
    /// Per-mobile monotonic request nonce (replay protection).
    pub nonce: u64,
    /// Unix seconds the mobile stamped the request (the replay window bound).
    pub timestamp: i64,
}

impl From<RequestEnvelope> for CBOR {
    fn from(e: RequestEnvelope) -> Self {
        let mut m = Map::new();
        m.insert("v", ENVELOPE_VERSION);
        m.insert("method", e.method);
        m.insert("params", e.params);
        m.insert("signer", CBOR::to_byte_string(e.signer.to_bytes()));
        m.insert("recipient", CBOR::to_byte_string(e.recipient.to_bytes()));
        m.insert("nonce", e.nonce);
        m.insert("timestamp", e.timestamp);
        m.into()
    }
}

impl TryFrom<CBOR> for RequestEnvelope {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, u64>("v")? != ENVELOPE_VERSION {
            return Err(dcbor::Error::WrongType);
        }
        Ok(RequestEnvelope {
            method: map.extract::<&str, String>("method")?,
            params: map.extract::<&str, String>("params")?,
            signer: extract_pubkey(&map, "signer")?,
            recipient: extract_pubkey(&map, "recipient")?,
            nonce: map.extract::<&str, u64>("nonce")?,
            timestamp: map.extract::<&str, i64>("timestamp")?,
        })
    }
}

/// Extracts a 32-byte public key from a byte-string map field.
fn extract_pubkey(map: &dcbor::Map, key: &str) -> Result<PublicKey, dcbor::Error> {
    let bytes: [u8; 32] = map
        .extract::<&str, CBOR>(key)?
        .try_into_byte_string()?
        .as_slice()
        .try_into()
        .map_err(|_| dcbor::Error::WrongType)?;
    PublicKey::from_bytes(bytes).map_err(|_| dcbor::Error::WrongType)
}

/// A method-level error inside a [`ResponseEnvelope`]: a JSON-RPC-style code and
/// a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseError {
    /// One of the `-326xx` codes ([`crate::rpc`]).
    pub code: i32,
    /// Diagnostic text; not meant to be machine-matched.
    pub message: String,
}

/// The station's reply, sealed back to the mobile.
///
/// Serialized as **JSON**, not canonical dCBOR: the response is a single-producer
/// (station), single-consumer (mobile) message, and the mobile verifies the
/// station's signature over the exact bytes it received rather than
/// re-serializing — so canonical determinism buys nothing here, and JSON spares
/// the mobile a dCBOR *decoder* it would otherwise need (it only carries the
/// dCBOR *encoder*, via `canonicalBytes`). The request, which the mobile signs
/// and the station must decode, stays canonical dCBOR.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResponseEnvelope {
    /// The envelope version, mirrored from the request side.
    pub v: u64,
    /// Echo of the request nonce this answers, so the mobile can correlate it.
    pub nonce: u64,
    /// The method result as a JSON string on success; absent on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// The method error on failure; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
}

impl ResponseEnvelope {
    /// A success reply carrying `result` (a JSON string) for `nonce`.
    pub fn ok(nonce: u64, result: String) -> Self {
        ResponseEnvelope {
            v: ENVELOPE_VERSION,
            nonce,
            result: Some(result),
            error: None,
        }
    }

    /// An error reply for `nonce`.
    pub fn err(nonce: u64, code: i32, message: String) -> Self {
        ResponseEnvelope {
            v: ENVELOPE_VERSION,
            nonce,
            result: None,
            error: Some(ResponseError { code, message }),
        }
    }
}

/// The canonical dCBOR bytes of a request envelope — what the mobile signs and
/// the station verifies.
pub fn request_payload_bytes(envelope: &RequestEnvelope) -> Vec<u8> {
    to_canonical_bytes(envelope.clone())
}

/// Frames a signed request: `payload_len(u32 BE) ‖ payload ‖ signature(64)`.
/// The mobile builds this, then seals it to the station.
pub fn frame_signed_request(payload: &[u8], signature: &Signature) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN_PREFIX + payload.len() + SIG_LEN);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&signature.to_bytes());
    out
}

/// Parses an opened request frame, verifies the embedded signature over the
/// exact payload bytes, and returns the decoded envelope. Does **not** make the
/// stateful checks (recipient, paired, skew, nonce) — the caller does, because
/// only the station holds that state.
pub fn parse_signed_request(frame: &[u8]) -> Result<RequestEnvelope, ChannelError> {
    if frame.len() < LEN_PREFIX + SIG_LEN {
        return Err(ChannelError::Malformed);
    }
    let payload_len = u32::from_be_bytes(frame[..LEN_PREFIX].try_into().unwrap()) as usize;
    // payload sits between the length prefix and the trailing signature.
    let payload_end = LEN_PREFIX
        .checked_add(payload_len)
        .ok_or(ChannelError::Malformed)?;
    if frame.len() != payload_end + SIG_LEN {
        return Err(ChannelError::Malformed);
    }
    let payload = &frame[LEN_PREFIX..payload_end];
    let sig_bytes: [u8; SIG_LEN] = frame[payload_end..].try_into().unwrap();

    let envelope: RequestEnvelope =
        from_canonical_bytes(payload).map_err(|_| ChannelError::Malformed)?;
    let signature = Signature::from_bytes(sig_bytes).map_err(|_| ChannelError::BadSignature)?;
    envelope
        .signer
        .verify(payload, &signature)
        .map_err(|_| ChannelError::BadSignature)?;
    Ok(envelope)
}

/// Signs and frames a response: `payload_len ‖ payload ‖ signature`, where the
/// payload is the response's **JSON** bytes and the station signs them. The
/// caller seals the result to the mobile's key. JSON serialization is
/// infallible for this type (only integers and strings), so this cannot fail.
pub fn frame_signed_response(response: &ResponseEnvelope, station: &Keypair) -> Vec<u8> {
    let payload = serde_json::to_vec(response).expect("ResponseEnvelope serializes");
    let signature = station.sign(&payload);
    frame_signed_request(&payload, &signature)
}

/// Length of a public key in the signed-record framing.
const PK_LEN: usize = 32;

/// Frames a mobile-submitted **signed record** (the write path, T1.3.4):
/// `payload_len(u32 BE) ‖ payload(canonical dCBOR) ‖ signer(32) ‖ signature(64)`.
///
/// This is how the mobile hands the station a whole [`SignedPayload`] — a signed
/// proposal or confirmation — over the channel. `SignedPayload` is a serde
/// envelope, not a dCBOR value, so it needs an explicit framing; the mobile
/// builds it from its canonical payload bytes, its public key, and its
/// signature, all of which it already has.
pub fn frame_signed_record(payload: &[u8], signer: &PublicKey, signature: &Signature) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEN_PREFIX + payload.len() + PK_LEN + SIG_LEN);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&signer.to_bytes());
    out.extend_from_slice(&signature.to_bytes());
    out
}

/// Reconstructs a `SignedPayload<T>` from [`frame_signed_record`] framing. The
/// signature is **not** checked here — the ledger engine re-verifies it against
/// the re-canonicalized payload; this only re-assembles the envelope, rejecting
/// malformed framing, a non-canonical payload, or bad key/signature bytes.
pub fn parse_signed_record<T>(bytes: &[u8]) -> Result<SignedPayload<T>, ChannelError>
where
    T: TryFrom<CBOR>,
    <T as TryFrom<CBOR>>::Error: core::fmt::Display,
{
    if bytes.len() < LEN_PREFIX + PK_LEN + SIG_LEN {
        return Err(ChannelError::Malformed);
    }
    let payload_len = u32::from_be_bytes(bytes[..LEN_PREFIX].try_into().unwrap()) as usize;
    let payload_end = LEN_PREFIX
        .checked_add(payload_len)
        .ok_or(ChannelError::Malformed)?;
    if bytes.len() != payload_end + PK_LEN + SIG_LEN {
        return Err(ChannelError::Malformed);
    }
    let payload: T = from_canonical_bytes(&bytes[LEN_PREFIX..payload_end])
        .map_err(|_| ChannelError::Malformed)?;
    let signer_bytes: [u8; PK_LEN] = bytes[payload_end..payload_end + PK_LEN].try_into().unwrap();
    let sig_bytes: [u8; SIG_LEN] = bytes[payload_end + PK_LEN..].try_into().unwrap();
    let signer = PublicKey::from_bytes(signer_bytes).map_err(|_| ChannelError::BadSignature)?;
    let signature = Signature::from_bytes(sig_bytes).map_err(|_| ChannelError::BadSignature)?;
    Ok(SignedPayload {
        payload,
        signer,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    fn sample(mobile: &Keypair, station: &Keypair, nonce: u64, ts: i64) -> RequestEnvelope {
        RequestEnvelope {
            method: "balance".into(),
            params: "{\"address\":\"rrn1abc\"}".into(),
            signer: mobile.public_key(),
            recipient: station.public_key(),
            nonce,
            timestamp: ts,
        }
    }

    /// Builds a validly signed + framed request (the mobile's job), for tests.
    fn signed_frame(mobile: &Keypair, envelope: &RequestEnvelope) -> Vec<u8> {
        let payload = request_payload_bytes(envelope);
        let signature = mobile.sign(&payload);
        frame_signed_request(&payload, &signature)
    }

    #[test]
    fn envelope_cbor_roundtrips() {
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        let env = sample(&mobile, &station, 7, 1_000);
        let bytes = request_payload_bytes(&env);
        let decoded: RequestEnvelope = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, env);
    }

    #[test]
    fn valid_frame_parses_and_verifies() {
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        let env = sample(&mobile, &station, 7, 1_000);
        let frame = signed_frame(&mobile, &env);
        let parsed = parse_signed_request(&frame).expect("parses");
        assert_eq!(parsed, env);
    }

    #[test]
    fn a_signature_from_another_key_is_rejected() {
        let mobile = Keypair::generate();
        let attacker = Keypair::generate();
        let station = Keypair::generate();
        let env = sample(&mobile, &station, 7, 1_000);
        // Sign with the attacker's key but keep the mobile's signer field.
        let payload = request_payload_bytes(&env);
        let frame = frame_signed_request(&payload, &attacker.sign(&payload));
        assert_eq!(
            parse_signed_request(&frame).unwrap_err(),
            ChannelError::BadSignature
        );
    }

    #[test]
    fn a_tampered_payload_fails_verification() {
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        let env = sample(&mobile, &station, 7, 1_000);
        let mut frame = signed_frame(&mobile, &env);
        // Flip a byte inside the payload region (after the 4-byte length prefix).
        frame[LEN_PREFIX + 6] ^= 0x01;
        // Either the CBOR no longer decodes, or the signature no longer matches;
        // both are rejections, never a silently-accepted mutated request.
        assert!(parse_signed_request(&frame).is_err());
    }

    #[test]
    fn truncated_and_misframed_inputs_are_rejected() {
        assert_eq!(
            parse_signed_request(&[0u8; 3]).unwrap_err(),
            ChannelError::Malformed
        );
        // A length prefix that overruns the buffer.
        let mut frame = vec![0u8; LEN_PREFIX + SIG_LEN + 4];
        frame[..LEN_PREFIX].copy_from_slice(&9999u32.to_be_bytes());
        assert_eq!(
            parse_signed_request(&frame).unwrap_err(),
            ChannelError::Malformed
        );
    }

    #[test]
    fn response_frame_is_station_signed_and_json_parses() {
        let station = Keypair::generate();
        let resp = ResponseEnvelope::ok(7, "{\"balance_centi\":2400}".into());
        let frame = frame_signed_response(&resp, &station);
        // The mobile splits the frame like the station splits a request, verifies
        // the station's signature over the received bytes, then JSON-parses them.
        let payload_len = u32::from_be_bytes(frame[..LEN_PREFIX].try_into().unwrap()) as usize;
        let payload = &frame[LEN_PREFIX..LEN_PREFIX + payload_len];
        let sig: [u8; SIG_LEN] = frame[LEN_PREFIX + payload_len..].try_into().unwrap();
        assert!(station
            .public_key()
            .verify(payload, &Signature::from_bytes(sig).unwrap())
            .is_ok());
        let decoded: ResponseEnvelope = serde_json::from_slice(payload).unwrap();
        assert_eq!(decoded.v, ENVELOPE_VERSION);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.result.as_deref(), Some("{\"balance_centi\":2400}"));
        assert!(decoded.error.is_none());
    }
}
