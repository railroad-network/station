//! Client side of the ADR-0008 sealed request channel.
//!
//! The station *serves* the sealed channel ([`crate::mobile_server`],
//! [`crate::rpc_envelope`]); this is the matching *client* — the byte-for-byte
//! counterpart the mobile FFI runs on-device, promoted here so a non-mobile
//! member device (`rrn wallet`, ADR-0028) can pair and call over the same
//! channel. It is the sibling of [`crate::rpc_client`], which speaks the
//! operator's line-delimited JSON over a Unix socket; this speaks the mobile's
//! sealed-and-signed envelope over plain HTTP.
//!
//! # Why raw HTTP, no `reqwest`/TLS
//!
//! The channel is sealed and authenticated at the *application* layer (ADR-0008):
//! every request is signed by the member and sealed to the station's public key,
//! and every reply is signed by the station and sealed back. Transport
//! confidentiality would be redundant, and a TLS/HTTP client stack would be a
//! large new dependency surface for no security gain. So this writes a minimal
//! HTTP/1.1 `POST` with `Connection: close` directly over a
//! [`tokio::net::TcpStream`] and reads the response to EOF — exactly what the
//! station's own acceptance test does.
//!
//! # Construction (mirrors [`crate::rpc_envelope`])
//!
//! `call` builds a version-2 [`RequestEnvelope`] bound to the station as
//! `recipient`, signs its canonical bytes, frames `len ‖ payload ‖ sig`, seals
//! it to the station, and POSTs it, remembering the nonce and the hash of the
//! payload it signed ([`SentRequest`]). [`ChannelClient::verify_reply`] then
//! accepts only a reply that answers *that* request: opened with the member's
//! key, signed by the pinned station under the v2 reply tag, version 2, the
//! same nonce, naming this member, and carrying this request's hash. A reply
//! the station signed for another member, or for this member's request before a
//! re-pair or restore, does not verify (ADR-0008, Clarification 2026-10-14,
//! Part B).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The largest response the client will read, headers included: a sealed reply
/// is at most a bundle-sized payload, so this bounds an unbounded-stream DoS from
/// a wrong or hostile host at a mistyped `--url` before any verification.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

use rrn_crypto::keypair::{Keypair, PublicKey, Signature};
use rrn_identity::address::Address;
use rrn_identity::pairing as layout;
use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};

use crate::core::hex;
use crate::pairing::{PairFinish, PairFinished, PairOffer, PairStart, PAIRING_VERSION};
use crate::rpc_envelope::{
    frame_signed_request, request_hash, request_payload_bytes, response_signed_message,
    RequestEnvelope, ResponseEnvelope, ENVELOPE_V2,
};

/// How long a single request waits for the station's response before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// A completed pairing handshake, awaiting the operator: the station that
/// answered (always the pinned one) and the code to read to its operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairOutcome {
    /// The station's bech32 address.
    pub station_address: String,
    /// The confirmation code (`XXXXX-XXXXX`) the operator types to confirm.
    pub code: String,
}

/// Why a sealed-channel call failed. The transport/crypto variants are the
/// client's own; [`ChannelClientError::Method`] carries a station-returned
/// method error (a sealed `ResponseEnvelope.error`, i.e. the call reached the
/// method and it declined).
#[derive(Debug, thiserror::Error)]
pub enum ChannelClientError {
    /// The TCP connection to the station could not be established or read.
    #[error("could not reach the station at {url}: {source}")]
    Connect {
        /// The `host:port` that could not be reached.
        url: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The station did not answer within [`RESPONSE_TIMEOUT`].
    #[error("the station did not respond within {0:?}")]
    Timeout(Duration),
    /// The signer is not (yet) a paired mobile — HTTP 401 on `/rpc`. For a
    /// freshly paired wallet this means the operator has not confirmed the pair.
    #[error("the station has not confirmed this device is paired")]
    NotPaired,
    /// A non-success HTTP status other than 401.
    #[error("station returned HTTP {status}: {message}")]
    Http {
        /// The HTTP status code.
        status: u16,
        /// The (text) response body, for diagnostics.
        message: String,
    },
    /// The reply could not be opened, or its framing/JSON was malformed.
    #[error("malformed station reply")]
    Malformed,
    /// The station's signature over the reply did not verify against the pin.
    #[error("station reply signature did not verify against the pinned station key")]
    Verify,
    /// The reply echoed a nonce other than the one sent — a mismatched or
    /// reordered response.
    #[error("station reply nonce {got} did not echo the request nonce {expected}")]
    NonceMismatch {
        /// The nonce that was sent.
        expected: u64,
        /// The nonce the reply carried.
        got: u64,
    },
    /// The reply is station-signed but does not answer this request: it names
    /// another member or another request, lacks the binding, or is an unbound
    /// version-1 reply.
    #[error("station reply does not answer this request")]
    RequestMismatch,
    /// The station named a different identity than the one this wallet pinned —
    /// the station at this URL is not the station the member enrolled with.
    #[error("the station at this URL identifies as {got}, not the pinned {pinned}")]
    StationMismatch {
        /// The pinned station address.
        pinned: String,
        /// The address the station at the URL returned.
        got: String,
    },
    /// A method-level error returned by the station (the call reached the method).
    #[error("station refused the request ({code}): {message}")]
    Method {
        /// The `-326xx` method error code.
        code: i32,
        /// The station's error message.
        message: String,
    },
}

/// What a client keeps about a request it sent, to check that a reply answers
/// it: the transport nonce and the hash of the exact payload bytes it signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentRequest {
    /// The request's transport nonce.
    pub nonce: u64,
    /// [`request_hash`] of the signed request payload.
    pub request_hash: [u8; 32],
}

/// A client for one station's sealed request channel, pinned to that station's
/// public key.
pub struct ChannelClient {
    /// `host:port` of the station's mobile listener.
    url: String,
    /// The pinned station public key: reply signatures and the pair response are
    /// checked against this, never against a key the station hands over.
    station: PublicKey,
}

impl ChannelClient {
    /// Builds a client targeting the station at `url` (`host:port`), pinned to
    /// `station`'s public key.
    pub fn new(url: impl Into<String>, station: PublicKey) -> Self {
        Self {
            url: url.into(),
            station,
        }
    }

    /// Runs both rounds of the pairing handshake for `member` and returns the
    /// station's address and the confirmation code to show the operator.
    ///
    /// Commits to a fresh nonce (`POST /pair/start`), then checks the offer in
    /// the order ADR-0028 §3.3 requires: first that the returned
    /// `station_address` equals the pinned station (a
    /// [`ChannelClientError::StationMismatch`] otherwise, naming both), then
    /// that the offer's signature verifies against the pinned key over this
    /// member's key and commitment. Only then does it reveal its nonce in a
    /// finish signed over the pinned station's key (`POST /pair/finish`). The
    /// station never sends the code; both sides compute it.
    pub async fn pair(
        &self,
        member: &Keypair,
        now: i64,
    ) -> Result<PairOutcome, ChannelClientError> {
        let member_pk = member.public_key();
        let member_address = Address::from_public_key(member_pk).to_string();
        let mobile_nonce = layout::fresh_nonce();
        let commitment = layout::commitment(&member_pk.to_bytes(), &mobile_nonce);

        let start_msg = layout::start_signed_bytes(&member_pk.to_bytes(), &commitment, now);
        let start = PairStart {
            v: PAIRING_VERSION,
            mobile_address: member_address.clone(),
            commitment: hex(&commitment),
            requested_at: now,
            signature: hex(&member.sign(&start_msg).to_bytes()),
        };
        let body = serde_json::to_vec(&start).expect("PairStart serializes");
        let offer: PairOffer = self.pair_post("/pair/start", &body).await?;

        // The station names itself: it must be the one this wallet pinned. This
        // is checked before the signature so a wrong station gives the precise
        // "not the station you enrolled with" error rather than a generic
        // verification failure (ADR-0028 §3.3).
        let pinned = Address::from_public_key(self.station).to_string();
        if offer.station_address != pinned {
            return Err(ChannelClientError::StationMismatch {
                pinned,
                got: offer.station_address,
            });
        }
        // Then prove the pin holds the key behind that address and fixed its
        // nonce against this commitment, so a man-in-the-middle echoing the
        // address cannot pass.
        let station_nonce = offer
            .verify(&self.station, &member_pk, &commitment)
            .map_err(|e| match e {
                crate::pairing::PairError::SignatureMismatch => ChannelClientError::Verify,
                _ => ChannelClientError::Malformed,
            })?;

        let finish_msg = layout::finish_signed_bytes(
            &self.station.to_bytes(),
            &member_pk.to_bytes(),
            &commitment,
            &station_nonce,
            &mobile_nonce,
        );
        let finish = PairFinish {
            v: PAIRING_VERSION,
            mobile_address: member_address,
            station_address: pinned.clone(),
            mobile_nonce: hex(&mobile_nonce),
            signature: hex(&member.sign(&finish_msg).to_bytes()),
        };
        let body = serde_json::to_vec(&finish).expect("PairFinish serializes");
        let _: PairFinished = self.pair_post("/pair/finish", &body).await?;

        Ok(PairOutcome {
            station_address: pinned,
            code: layout::code(
                &self.station.to_bytes(),
                &member_pk.to_bytes(),
                &mobile_nonce,
                &station_nonce,
            ),
        })
    }

    /// POSTs one pairing round and parses a `200` JSON answer; any other
    /// status is an [`ChannelClientError::Http`] carrying the station's reason.
    async fn pair_post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<T, ChannelClientError> {
        let (status, resp) = self.http_post(path, "application/json", body).await?;
        if status != 200 {
            return Err(ChannelClientError::Http {
                status,
                message: String::from_utf8_lossy(&resp).into_owned(),
            });
        }
        serde_json::from_slice(&resp).map_err(|_| ChannelClientError::Malformed)
    }

    /// Makes one authenticated `method` call with `params`, using `transport_nonce`
    /// as the per-device request nonce and `now` as the request timestamp.
    ///
    /// Returns the method's result as a `serde_json::Value`, or a typed error: a
    /// [`ChannelClientError::Method`] when the station reached the method and it
    /// declined, [`ChannelClientError::NotPaired`] on a 401, and the transport /
    /// crypto variants otherwise. The caller is responsible for persisting the
    /// transport nonce *before* calling (ADR-0028 §3.1), so a strictly increasing
    /// nonce is used even across a crash.
    pub async fn call(
        &self,
        member: &Keypair,
        method: &str,
        params: &serde_json::Value,
        transport_nonce: u64,
        now: i64,
    ) -> Result<serde_json::Value, ChannelClientError> {
        let (sealed_req, sent) =
            self.seal_request(member, method, &params.to_string(), transport_nonce, now)?;

        let (status, body) = self
            .http_post("/rpc", "application/octet-stream", &sealed_req)
            .await?;
        match status {
            200 => {}
            401 => return Err(ChannelClientError::NotPaired),
            other => {
                return Err(ChannelClientError::Http {
                    status: other,
                    message: String::from_utf8_lossy(&body).into_owned(),
                })
            }
        }

        let reply = self.verify_reply(member, &body, &sent)?;
        if let Some(err) = reply.error {
            return Err(ChannelClientError::Method {
                code: err.code,
                message: err.message,
            });
        }
        let result = reply.result.ok_or(ChannelClientError::Malformed)?;
        serde_json::from_str(&result).map_err(|_| ChannelClientError::Malformed)
    }

    /// Builds one sealed version-2 request — `params` is the method's params as
    /// JSON text — and returns it with the [`SentRequest`] its reply must
    /// answer. The request hash is taken over the exact payload bytes signed.
    pub fn seal_request(
        &self,
        member: &Keypair,
        method: &str,
        params: &str,
        transport_nonce: u64,
        now: i64,
    ) -> Result<(Vec<u8>, SentRequest), ChannelClientError> {
        let envelope = RequestEnvelope {
            v: ENVELOPE_V2,
            method: method.to_string(),
            params: params.to_string(),
            signer: member.public_key(),
            recipient: self.station,
            nonce: transport_nonce,
            timestamp: now,
        };
        let payload = request_payload_bytes(&envelope);
        let signature = member.sign(&payload);
        let frame = frame_signed_request(&payload, &signature);
        let sealed_req = sealed::seal(&self.station, &frame, TRANSPORT_CONTEXT)
            .map_err(|_| ChannelClientError::Malformed)?
            .to_bytes();
        let sent = SentRequest {
            nonce: transport_nonce,
            request_hash: request_hash(&payload),
        };
        Ok((sealed_req, sent))
    }

    /// Accepts a sealed reply only as the answer to `sent`, from the pinned
    /// station, for `member`. In order: the seal opens with the member's key;
    /// the pinned station's signature verifies over the v2 reply tag followed
    /// by the exact JSON bytes received; the reply is version 2; it echoes the
    /// request's nonce; it names this member as recipient; it carries this
    /// request's hash. An unbound v1 reply, a missing binding field, or a
    /// binding to another member or request is a
    /// [`ChannelClientError::RequestMismatch`].
    pub fn verify_reply(
        &self,
        member: &Keypair,
        sealed_reply: &[u8],
        sent: &SentRequest,
    ) -> Result<ResponseEnvelope, ChannelClientError> {
        let sb = SealedBox::from_bytes(sealed_reply).map_err(|_| ChannelClientError::Malformed)?;
        let frame = sealed::open(&sb, member.secret_key(), TRANSPORT_CONTEXT)
            .map_err(|_| ChannelClientError::Malformed)?;
        // Frame is payload_len(4 BE) ‖ payload ‖ signature(64).
        if frame.len() < 4 + 64 {
            return Err(ChannelClientError::Malformed);
        }
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let end = 4usize
            .checked_add(len)
            .ok_or(ChannelClientError::Malformed)?;
        if frame.len() != end + 64 {
            return Err(ChannelClientError::Malformed);
        }
        let payload = &frame[4..end];
        let sig_bytes: [u8; 64] = frame[end..].try_into().unwrap();
        let signature = Signature::from_bytes(sig_bytes).map_err(|_| ChannelClientError::Verify)?;
        // A v2 client verifies only the tagged form: an untagged (v1) signature
        // fails here, whatever the JSON claims its version is.
        self.station
            .verify(&response_signed_message(ENVELOPE_V2, payload), &signature)
            .map_err(|_| ChannelClientError::Verify)?;
        // The response is JSON (the mobile carries no dCBOR decoder); the request
        // was canonical dCBOR (see rpc_envelope for why they differ).
        let reply: ResponseEnvelope =
            serde_json::from_slice(payload).map_err(|_| ChannelClientError::Malformed)?;
        if reply.v != ENVELOPE_V2 {
            return Err(ChannelClientError::RequestMismatch);
        }
        if reply.nonce != sent.nonce {
            return Err(ChannelClientError::NonceMismatch {
                expected: sent.nonce,
                got: reply.nonce,
            });
        }
        if reply.recipient.as_deref() != Some(hex(&member.public_key().to_bytes()).as_str()) {
            return Err(ChannelClientError::RequestMismatch);
        }
        if reply.request_hash.as_deref() != Some(hex(&sent.request_hash).as_str()) {
            return Err(ChannelClientError::RequestMismatch);
        }
        Ok(reply)
    }

    /// POSTs raw `body` to `path` and returns `(status, body_bytes)`. Uses
    /// `Connection: close` so the (possibly binary) response reads cleanly to EOF
    /// without chunk parsing.
    async fn http_post(
        &self,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), ChannelClientError> {
        let connect = TcpStream::connect(&self.url);
        let mut stream = tokio::time::timeout(RESPONSE_TIMEOUT, connect)
            .await
            .map_err(|_| ChannelClientError::Timeout(RESPONSE_TIMEOUT))?
            .map_err(|source| ChannelClientError::Connect {
                url: self.url.clone(),
                source,
            })?;
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\n\
             Content-Length: {len}\r\nConnection: close\r\n\r\n",
            host = self.url,
            len = body.len(),
        );

        let io = async {
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(body).await?;
            stream.flush().await?;
            // Bound the read: a wrong or hostile host at a mistyped `--url` (before
            // any pairing/verification) must not be able to stream unbounded bytes
            // into memory. A sealed reply is at most a bundle-sized response plus
            // HTTP headers, so this ceiling is generous.
            let mut raw = Vec::new();
            let mut limited = (&mut stream).take(MAX_RESPONSE_BYTES);
            limited.read_to_end(&mut raw).await?;
            Ok::<Vec<u8>, std::io::Error>(raw)
        };
        let raw = tokio::time::timeout(RESPONSE_TIMEOUT, io)
            .await
            .map_err(|_| ChannelClientError::Timeout(RESPONSE_TIMEOUT))?
            .map_err(|source| ChannelClientError::Connect {
                url: self.url.clone(),
                source,
            })?;

        // Split the head from the body on the first CRLFCRLF, keeping the body
        // bytes exactly (a sealed reply is binary).
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(ChannelClientError::Malformed)?;
        let head = String::from_utf8_lossy(&raw[..split]).into_owned();
        let resp_body = raw[split + 4..].to_vec();
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or(ChannelClientError::Malformed)?;
        Ok((status, resp_body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_envelope::{
        frame_signed_response, parse_signed_request, ReplyBinding, ENVELOPE_V1, RESPONSE_SIGN_TAG,
    };

    /// What the station does with a sealed request: open it, authenticate it,
    /// and build the binding its reply answers.
    fn station_binding(station: &Keypair, sealed_req: &[u8]) -> ReplyBinding {
        let sb = SealedBox::from_bytes(sealed_req).unwrap();
        let frame = sealed::open(&sb, station.secret_key(), TRANSPORT_CONTEXT).unwrap();
        ReplyBinding::for_request(&parse_signed_request(&frame).unwrap())
    }

    /// A station-signed, framed (unsealed) `ok` reply for `binding`.
    fn station_reply_frame(station: &Keypair, binding: &ReplyBinding) -> Vec<u8> {
        frame_signed_response(
            &ResponseEnvelope::ok(binding, "{\"ok\":true}".into()),
            station,
        )
    }

    fn seal_to(member: &Keypair, frame: &[u8]) -> Vec<u8> {
        sealed::seal(&member.public_key(), frame, TRANSPORT_CONTEXT)
            .unwrap()
            .to_bytes()
    }

    /// Frames `json` with the station's signature over `message`.
    fn frame_with_signature(station: &Keypair, json: &[u8], message: &[u8]) -> Vec<u8> {
        frame_signed_request(json, &station.sign(message))
    }

    #[test]
    fn the_genuine_reply_verifies() {
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let client = ChannelClient::new("", station.public_key());
        let (req, sent) = client
            .seal_request(&alice, "whoami", "null", 1, 1_000)
            .unwrap();
        let binding = station_binding(&station, &req);
        let sealed = seal_to(&alice, &station_reply_frame(&station, &binding));
        let reply = client.verify_reply(&alice, &sealed, &sent).unwrap();
        assert_eq!(reply.result.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn a_reply_for_another_members_request_is_refused() {
        // Alice and Bob each send a request at nonce 1. The station's reply to
        // Alice is opened by Alice (a paired member) and re-sealed to Bob as the
        // answer to Bob's request. The nonce matches and the station's signature
        // is genuine; only the binding gives it away.
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let client = ChannelClient::new("", station.public_key());
        let (alice_req, _) = client
            .seal_request(&alice, "submit_proposal", "{}", 1, 1_000)
            .unwrap();
        let (_bob_req, bob_sent) = client
            .seal_request(&bob, "submit_proposal", "{}", 1, 1_000)
            .unwrap();
        let alice_binding = station_binding(&station, &alice_req);
        let alice_sealed = seal_to(&alice, &station_reply_frame(&station, &alice_binding));

        // Alice opens her reply and re-seals the station-signed frame to Bob.
        let sb = SealedBox::from_bytes(&alice_sealed).unwrap();
        let frame = sealed::open(&sb, alice.secret_key(), TRANSPORT_CONTEXT).unwrap();
        let resealed = seal_to(&bob, &frame);

        assert!(matches!(
            client.verify_reply(&bob, &resealed, &bob_sent),
            Err(ChannelClientError::RequestMismatch)
        ));
    }

    #[test]
    fn a_reply_recorded_before_a_re_pair_is_refused() {
        // The same member's request at the same nonce, before and after a
        // re-pair or restore: a different timestamp, so a different request
        // hash. The recorded reply to the first does not answer the second.
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let client = ChannelClient::new("", station.public_key());
        let (old_req, _) = client
            .seal_request(&alice, "whoami", "null", 1, 1_000)
            .unwrap();
        let (_new_req, new_sent) = client
            .seal_request(&alice, "whoami", "null", 1, 2_000)
            .unwrap();
        let old_binding = station_binding(&station, &old_req);
        let recorded = seal_to(&alice, &station_reply_frame(&station, &old_binding));
        assert!(matches!(
            client.verify_reply(&alice, &recorded, &new_sent),
            Err(ChannelClientError::RequestMismatch)
        ));
    }

    #[test]
    fn a_v1_reply_is_refused_by_a_v2_client() {
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let client = ChannelClient::new("", station.public_key());
        let (req, sent) = client
            .seal_request(&alice, "whoami", "null", 1, 1_000)
            .unwrap();
        let v2 = station_binding(&station, &req);

        // A genuine v1 reply (the station's answer to a v1 request at this
        // nonce): untagged signature, so it never verifies for a v2 client.
        let v1 = ReplyBinding {
            v: ENVELOPE_V1,
            ..v2
        };
        let sealed = seal_to(&alice, &station_reply_frame(&station, &v1));
        assert!(matches!(
            client.verify_reply(&alice, &sealed, &sent),
            Err(ChannelClientError::Verify)
        ));

        // Even under the v2 tag, a reply that says v1 — or that lacks either
        // binding field — does not answer a v2 request.
        let mut json_v1 = ResponseEnvelope::ok(&v2, "{}".into());
        json_v1.v = ENVELOPE_V1;
        let mut no_recipient = ResponseEnvelope::ok(&v2, "{}".into());
        no_recipient.recipient = None;
        let mut no_hash = ResponseEnvelope::ok(&v2, "{}".into());
        no_hash.request_hash = None;
        for reply in [json_v1, no_recipient, no_hash] {
            let json = serde_json::to_vec(&reply).unwrap();
            let mut tagged = RESPONSE_SIGN_TAG.to_vec();
            tagged.extend_from_slice(&json);
            let sealed = seal_to(&alice, &frame_with_signature(&station, &json, &tagged));
            assert!(
                matches!(
                    client.verify_reply(&alice, &sealed, &sent),
                    Err(ChannelClientError::RequestMismatch)
                ),
                "{reply:?}"
            );
        }
    }

    #[test]
    fn a_reply_signed_without_the_tag_is_refused() {
        // A correctly bound v2 reply whose station signature covers the bare
        // JSON (no domain tag) is not a v2 reply signature.
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let client = ChannelClient::new("", station.public_key());
        let (req, sent) = client
            .seal_request(&alice, "whoami", "null", 1, 1_000)
            .unwrap();
        let binding = station_binding(&station, &req);
        let json = serde_json::to_vec(&ResponseEnvelope::ok(&binding, "{}".into())).unwrap();
        let sealed = seal_to(&alice, &frame_with_signature(&station, &json, &json));
        assert!(matches!(
            client.verify_reply(&alice, &sealed, &sent),
            Err(ChannelClientError::Verify)
        ));
    }

    #[test]
    fn a_reply_at_another_nonce_is_a_nonce_mismatch() {
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let client = ChannelClient::new("", station.public_key());
        let (req, _) = client
            .seal_request(&alice, "whoami", "null", 1, 1_000)
            .unwrap();
        let (_, sent2) = client
            .seal_request(&alice, "whoami", "null", 2, 1_000)
            .unwrap();
        let binding = station_binding(&station, &req);
        let sealed = seal_to(&alice, &station_reply_frame(&station, &binding));
        assert!(matches!(
            client.verify_reply(&alice, &sealed, &sent2),
            Err(ChannelClientError::NonceMismatch {
                expected: 2,
                got: 1
            })
        ));
    }
}
