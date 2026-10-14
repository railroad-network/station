//! The authenticated request channel's envelope (ADR-0008).
//!
//! After pairing establishes both static keys, every mobile request
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
//!
//! ## Replies are bound to their request (envelope v2)
//!
//! A version-2 request gets a reply that names the member it is for
//! (`recipient`) and the exact request it answers (`request_hash`, a tagged
//! blake3 of the signed request payload bytes as received), and the station
//! signs `"rrn-channel-resp-v2" ‖ reply JSON`. Without that binding a reply
//! signed for one member's request would verify as the answer to another's
//! request with the same nonce, since anyone can re-seal a signed frame to any
//! key (ADR-0008, Clarification 2026-10-14, Part B). A version-1 request still
//! gets the unbound version-1 reply — the bare JSON, signed untagged — until
//! the clients that send v1 are retired.

use dcbor::prelude::*;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, Signature};
use rrn_crypto::serialize::{checked_from_data, from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;

/// The original envelope version: its reply names neither the member nor the
/// request it answers. Still answered (with an unbound v1 reply) until the
/// clients that send it are retired.
pub const ENVELOPE_V1: u64 = 1;

/// The current envelope version: the request is unchanged from v1, but its
/// reply is bound to the requesting member and the exact request (see
/// [`ReplyBinding`]). The version is bound inside the member's signed bytes, so
/// nobody can downgrade a v2 request to a v1 one.
pub const ENVELOPE_V2: u64 = 2;

/// Domain tag of a v2 request hash: [`request_hash`] is
/// `blake3(REQUEST_HASH_TAG ‖ request payload)`.
pub const REQUEST_HASH_TAG: &[u8] = b"rrn-channel-request-v2";

/// Domain tag the station prefixes to a v2 reply's JSON before signing, so its
/// raw-JSON reply signatures can never be mistaken for any other station
/// signature (or for an untagged v1 reply).
pub const RESPONSE_SIGN_TAG: &[u8] = b"rrn-channel-resp-v2";

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
    /// The envelope version, [`ENVELOPE_V1`] or [`ENVELOPE_V2`]. Inside the
    /// signed bytes, so the reply form it selects cannot be downgraded.
    pub v: u64,
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
        m.insert("v", e.v);
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
        let v = map.extract::<&str, u64>("v")?;
        if !is_supported_version(v) {
            return Err(dcbor::Error::WrongType);
        }
        Ok(RequestEnvelope {
            v,
            method: map.extract::<&str, String>("method")?,
            params: map.extract::<&str, String>("params")?,
            signer: extract_pubkey(&map, "signer")?,
            recipient: extract_pubkey(&map, "recipient")?,
            nonce: map.extract::<&str, u64>("nonce")?,
            timestamp: map.extract::<&str, i64>("timestamp")?,
        })
    }
}

/// Whether `v` is an envelope version this station answers.
fn is_supported_version(v: u64) -> bool {
    v == ENVELOPE_V1 || v == ENVELOPE_V2
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
    /// The envelope version, echoed from the request it answers. It selects the
    /// signed form: a v2 reply is signed under [`RESPONSE_SIGN_TAG`].
    pub v: u64,
    /// Echo of the request nonce this answers, so the mobile can correlate it.
    pub nonce: u64,
    /// v2 only: hex of the requesting member's 32-byte public key — the member
    /// this reply was issued to. Absent (not null) on a v1 reply, so a v1
    /// reply's JSON is byte-identical to before v2 existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// v2 only: hex of the [`request_hash`] of the request this answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    /// The method result as a JSON string on success; absent on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// The method error on failure; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
}

/// Everything a reply must echo to answer one authenticated request — built
/// once, when the request is authenticated, and the only way to construct a
/// [`ResponseEnvelope`], so no reply path can answer from a bare nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyBinding {
    /// The request's envelope version; the reply echoes it.
    pub v: u64,
    /// The request's nonce; the reply echoes it.
    pub nonce: u64,
    /// The requesting member's key: the reply is sealed to it and, for v2,
    /// names it.
    pub recipient: PublicKey,
    /// [`request_hash`] of the request's payload bytes as received.
    pub request_hash: [u8; 32],
}

impl ReplyBinding {
    /// The binding for an authenticated request.
    pub fn for_request(request: &AuthenticatedRequest) -> Self {
        ReplyBinding {
            v: request.envelope.v,
            nonce: request.envelope.nonce,
            recipient: request.envelope.signer,
            request_hash: request.request_hash,
        }
    }

    /// A reply skeleton for this binding: the version and nonce echoed, and for
    /// v2 the recipient and request hash set; neither for v1.
    fn reply(&self, result: Option<String>, error: Option<ResponseError>) -> ResponseEnvelope {
        let bound = self.v == ENVELOPE_V2;
        ResponseEnvelope {
            v: self.v,
            nonce: self.nonce,
            recipient: bound.then(|| crate::core::hex(&self.recipient.to_bytes())),
            request_hash: bound.then(|| crate::core::hex(&self.request_hash)),
            result,
            error,
        }
    }
}

impl ResponseEnvelope {
    /// A success reply carrying `result` (a JSON string), answering `binding`.
    pub fn ok(binding: &ReplyBinding, result: String) -> Self {
        binding.reply(Some(result), None)
    }

    /// An error reply answering `binding`.
    pub fn err(binding: &ReplyBinding, code: i32, message: String) -> Self {
        binding.reply(None, Some(ResponseError { code, message }))
    }
}

/// `blake3(REQUEST_HASH_TAG ‖ payload)` — the hash a v2 reply carries of the
/// request it answers, over the **exact** signed payload bytes (as received on
/// the station, as sent on the client), never a re-encoding.
pub fn request_hash(payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(REQUEST_HASH_TAG.len() + payload.len());
    input.extend_from_slice(REQUEST_HASH_TAG);
    input.extend_from_slice(payload);
    Hash::of(&input).to_bytes()
}

/// The bytes the station signs for a reply of version `v` whose JSON is
/// `json`: `RESPONSE_SIGN_TAG ‖ json` for v2, the bare `json` for v1. The JSON
/// framed on the wire is exactly the bytes that follow the tag.
pub fn response_signed_message(v: u64, json: &[u8]) -> Vec<u8> {
    if v == ENVELOPE_V2 {
        let mut msg = Vec::with_capacity(RESPONSE_SIGN_TAG.len() + json.len());
        msg.extend_from_slice(RESPONSE_SIGN_TAG);
        msg.extend_from_slice(json);
        msg
    } else {
        json.to_vec()
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

/// A request whose signature verified, with the hash of the exact payload bytes
/// it arrived as — what a v2 reply echoes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRequest {
    /// The decoded, signature-verified envelope.
    pub envelope: RequestEnvelope,
    /// [`request_hash`] of the received payload bytes.
    pub request_hash: [u8; 32],
}

/// Parses an opened request frame, verifies the embedded signature over the
/// exact payload bytes, and returns the decoded envelope with the hash of those
/// bytes. Does **not** make the stateful checks (recipient, paired, skew,
/// nonce) — the caller does, because only the station holds that state.
pub fn parse_signed_request(frame: &[u8]) -> Result<AuthenticatedRequest, ChannelError> {
    if frame.len() < LEN_PREFIX + SIG_LEN {
        return Err(ChannelError::Malformed);
    }
    let payload_len = u32::from_be_bytes(frame[..LEN_PREFIX].try_into().unwrap()) as usize;
    // payload sits between the length prefix and the trailing signature.
    let payload_end = LEN_PREFIX
        .checked_add(payload_len)
        .ok_or(ChannelError::Malformed)?;
    let frame_len = payload_end
        .checked_add(SIG_LEN)
        .ok_or(ChannelError::Malformed)?;
    if frame.len() != frame_len {
        return Err(ChannelError::Malformed);
    }
    let payload = &frame[LEN_PREFIX..payload_end];
    let sig_bytes: [u8; SIG_LEN] = frame[payload_end..].try_into().unwrap();

    // Decode once, read the version first so an unknown one is reported as
    // such rather than as a malformed envelope, then decode the fields.
    let cbor = checked_from_data(payload).map_err(|_| ChannelError::Malformed)?;
    if let CBORCase::Map(map) = cbor.as_case() {
        if let Ok(v) = map.extract::<&str, u64>("v") {
            if !is_supported_version(v) {
                return Err(ChannelError::UnsupportedVersion);
            }
        }
    }
    let envelope = RequestEnvelope::try_from(cbor).map_err(|_| ChannelError::Malformed)?;
    // `checked_from_data` accepts only canonical dCBOR, so these are the bytes
    // the member signed; the signature and the hash both cover them as received.
    let signature = Signature::from_bytes(sig_bytes).map_err(|_| ChannelError::BadSignature)?;
    envelope
        .signer
        .verify(payload, &signature)
        .map_err(|_| ChannelError::BadSignature)?;
    Ok(AuthenticatedRequest {
        envelope,
        request_hash: request_hash(payload),
    })
}

/// Signs and frames a response: `payload_len ‖ payload ‖ signature`, where the
/// payload is the response's **JSON** bytes and the station signs
/// [`response_signed_message`] of them — tagged for v2, bare for v1, picked by
/// the response's `v`. The caller seals the result to the mobile's key. JSON
/// serialization is infallible for this type (only integers and strings), so
/// this cannot fail.
pub fn frame_signed_response(response: &ResponseEnvelope, station: &Keypair) -> Vec<u8> {
    let payload = serde_json::to_vec(response).expect("ResponseEnvelope serializes");
    let signature = station.sign(&response_signed_message(response.v, &payload));
    frame_signed_request(&payload, &signature)
}

/// Length of a public key in the signed-record framing.
const PK_LEN: usize = 32;

/// Frames a mobile-submitted **signed record** (the write path):
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
    let frame_len = payload_end
        .checked_add(PK_LEN)
        .and_then(|n| n.checked_add(SIG_LEN))
        .ok_or(ChannelError::Malformed)?;
    if bytes.len() != frame_len {
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
            v: ENVELOPE_V2,
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
        assert_eq!(parsed.envelope, env);
        // The hash covers the exact payload bytes that arrived.
        let payload = request_payload_bytes(&env);
        assert_eq!(parsed.request_hash, request_hash(&payload));
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
    fn frame_length_overflow_is_malformed() {
        // A length prefix of `u32::MAX` must be refused as malformed framing, never
        // overflow the frame-length arithmetic (it would on a 32-bit `usize`).
        let mut frame = u32::MAX.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0u8; PK_LEN + SIG_LEN]);
        assert_eq!(
            parse_signed_request(&frame).unwrap_err(),
            ChannelError::Malformed
        );
        assert_eq!(
            parse_signed_record::<rrn_ledger::transaction::TransactionProposal>(&frame)
                .unwrap_err(),
            ChannelError::Malformed
        );
    }

    /// Splits a response frame into its JSON payload and signature.
    fn split_response(frame: &[u8]) -> (&[u8], Signature) {
        let payload_len = u32::from_be_bytes(frame[..LEN_PREFIX].try_into().unwrap()) as usize;
        let payload = &frame[LEN_PREFIX..LEN_PREFIX + payload_len];
        let sig: [u8; SIG_LEN] = frame[LEN_PREFIX + payload_len..].try_into().unwrap();
        (payload, Signature::from_bytes(sig).unwrap())
    }

    /// The binding the station would build for `env` arriving as a signed frame.
    fn binding_for(mobile: &Keypair, env: &RequestEnvelope) -> ReplyBinding {
        ReplyBinding::for_request(&parse_signed_request(&signed_frame(mobile, env)).unwrap())
    }

    #[test]
    fn v2_reply_signs_the_tagged_json_and_echoes_the_binding() {
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        let env = sample(&mobile, &station, 7, 1_000);
        let binding = binding_for(&mobile, &env);
        assert_eq!(binding.v, ENVELOPE_V2);
        assert_eq!(binding.recipient, mobile.public_key());

        let resp = ResponseEnvelope::ok(&binding, "{\"balance_centi\":2400}".into());
        let frame = frame_signed_response(&resp, &station);
        let (payload, sig) = split_response(&frame);

        // The signature covers the tag followed by exactly the framed JSON bytes,
        // and not the bare JSON.
        let mut tagged = RESPONSE_SIGN_TAG.to_vec();
        tagged.extend_from_slice(payload);
        assert!(station.public_key().verify(&tagged, &sig).is_ok());
        assert!(station.public_key().verify(payload, &sig).is_err());

        let decoded: ResponseEnvelope = serde_json::from_slice(payload).unwrap();
        assert_eq!(decoded.v, ENVELOPE_V2);
        assert_eq!(decoded.nonce, 7);
        let recipient_hex = crate::core::hex(&mobile.public_key().to_bytes());
        assert_eq!(decoded.recipient.as_deref(), Some(recipient_hex.as_str()));
        let hash_hex = crate::core::hex(&request_hash(&request_payload_bytes(&env)));
        assert_eq!(decoded.request_hash.as_deref(), Some(hash_hex.as_str()));
        assert_eq!(decoded.result.as_deref(), Some("{\"balance_centi\":2400}"));
        assert!(decoded.error.is_none());

        // An error reply carries the same binding.
        let err = ResponseEnvelope::err(&binding, -32601, "method not found".into());
        assert_eq!(err.recipient, decoded.recipient);
        assert_eq!(err.request_hash, decoded.request_hash);
    }

    #[test]
    fn v1_request_gets_an_unbound_v1_reply() {
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        let mut env = sample(&mobile, &station, 7, 1_000);
        env.v = ENVELOPE_V1;
        let binding = binding_for(&mobile, &env);
        assert_eq!(binding.v, ENVELOPE_V1);

        let resp = ResponseEnvelope::ok(&binding, "{\"balance_centi\":2400}".into());
        let frame = frame_signed_response(&resp, &station);
        let (payload, sig) = split_response(&frame);
        // Untagged signature over the bare JSON, and the JSON is byte-identical to
        // the reply a station sent before v2 existed: no binding fields at all.
        assert!(station.public_key().verify(payload, &sig).is_ok());
        assert_eq!(
            payload,
            br#"{"v":1,"nonce":7,"result":"{\"balance_centi\":2400}"}"#
        );
        let err = ResponseEnvelope::err(&binding, -32601, "nope".into());
        assert_eq!(
            serde_json::to_vec(&err).unwrap(),
            br#"{"v":1,"nonce":7,"error":{"code":-32601,"message":"nope"}}"#
        );
    }

    #[test]
    fn unknown_request_version_is_unsupported() {
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        for v in [0, 3, u64::MAX] {
            let mut env = sample(&mobile, &station, 7, 1_000);
            env.v = v;
            assert_eq!(
                parse_signed_request(&signed_frame(&mobile, &env)).unwrap_err(),
                ChannelError::UnsupportedVersion,
                "version {v}"
            );
        }
    }

    #[test]
    fn the_request_version_is_inside_the_signature() {
        // Rewriting a signed v2 request as v1 (to get an unbound reply) breaks the
        // member's signature: a v2 client cannot be downgraded.
        let mobile = Keypair::generate();
        let station = Keypair::generate();
        let env = sample(&mobile, &station, 7, 1_000);
        let signature = mobile.sign(&request_payload_bytes(&env));
        let mut downgraded = env.clone();
        downgraded.v = ENVELOPE_V1;
        let frame = frame_signed_request(&request_payload_bytes(&downgraded), &signature);
        assert_eq!(
            parse_signed_request(&frame).unwrap_err(),
            ChannelError::BadSignature
        );
    }
}
