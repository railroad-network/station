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
//! `call` builds a [`RequestEnvelope`] bound to the station as `recipient`,
//! signs its canonical bytes, frames `len ‖ payload ‖ sig`, seals it to the
//! station, and POSTs it. The reply is opened with the member's secret key, the
//! station's signature is verified over the exact bytes received, the echoed
//! nonce is checked, and the method result (or a typed method error) is returned.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The largest response the client will read, headers included: a sealed reply
/// is at most a bundle-sized payload, so this bounds an unbounded-stream DoS from
/// a wrong or hostile host at a mistyped `--url` before any verification.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

use rrn_crypto::keypair::{Keypair, PublicKey, Signature};
use rrn_identity::address::Address;
use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};

use crate::core::hex;
use crate::pairing::{request_signed_bytes, PairRequest, PairResponse};
use crate::rpc_envelope::{
    frame_signed_request, request_payload_bytes, RequestEnvelope, ResponseEnvelope,
};

/// How long a single request waits for the station's response before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

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

    /// Performs the `POST /pair` handshake for `member` and returns the station's
    /// [`PairResponse`].
    ///
    /// Verifies, in the order ADR-0028 §3.3 requires: first that the returned
    /// `station_address` equals the pinned station (a [`ChannelClientError::StationMismatch`]
    /// otherwise, naming both), then that the response signature verifies against
    /// the pinned key over this request's token. The token is a fresh 32-byte
    /// nonce so a captured reply cannot be replayed against a later request.
    pub async fn pair(
        &self,
        member: &Keypair,
        now: i64,
    ) -> Result<PairResponse, ChannelClientError> {
        let token = random_token();
        let msg = request_signed_bytes(&member.public_key(), &token, now);
        let request = PairRequest {
            mobile_address: Address::from_public_key(member.public_key()).to_string(),
            token: hex(&token),
            requested_at: now,
            signature: hex(&member.sign(&msg).to_bytes()),
        };
        let body = serde_json::to_vec(&request).expect("PairRequest serializes");
        let (status, resp) = self.http_post("/pair", "application/json", &body).await?;
        if status != 200 {
            return Err(ChannelClientError::Http {
                status,
                message: String::from_utf8_lossy(&resp).into_owned(),
            });
        }
        let response: PairResponse =
            serde_json::from_slice(&resp).map_err(|_| ChannelClientError::Malformed)?;

        // The station names itself: it must be the one this wallet pinned. This
        // is checked before the signature so a wrong station gives the precise
        // "not the station you enrolled with" error rather than a generic
        // verification failure (ADR-0028 §3.3).
        let pinned = Address::from_public_key(self.station).to_string();
        if response.station_address != pinned {
            return Err(ChannelClientError::StationMismatch {
                pinned,
                got: response.station_address,
            });
        }
        // Then prove the pin holds the key behind that address and bound this
        // token, so a man-in-the-middle echoing the address cannot pass.
        let response_msg = crate::pairing::response_signed_bytes(&self.station, &token);
        let sig_bytes = crate::core::unhex(&response.signature)
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or(ChannelClientError::Malformed)?;
        let signature = Signature::from_bytes(sig_bytes).map_err(|_| ChannelClientError::Verify)?;
        self.station
            .verify(&response_msg, &signature)
            .map_err(|_| ChannelClientError::Verify)?;
        Ok(response)
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
        let envelope = RequestEnvelope {
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

        let reply = self.open_reply(member, &body)?;
        if reply.nonce != transport_nonce {
            return Err(ChannelClientError::NonceMismatch {
                expected: transport_nonce,
                got: reply.nonce,
            });
        }
        if let Some(err) = reply.error {
            return Err(ChannelClientError::Method {
                code: err.code,
                message: err.message,
            });
        }
        let result = reply.result.ok_or(ChannelClientError::Malformed)?;
        serde_json::from_str(&result).map_err(|_| ChannelClientError::Malformed)
    }

    /// Opens a sealed reply, verifies the station's signature over the exact
    /// bytes received (against the pin), and parses the [`ResponseEnvelope`].
    fn open_reply(
        &self,
        member: &Keypair,
        sealed_reply: &[u8],
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
        self.station
            .verify(payload, &signature)
            .map_err(|_| ChannelClientError::Verify)?;
        // The response is JSON (the mobile carries no dCBOR decoder); the request
        // was canonical dCBOR (see rpc_envelope for why they differ).
        serde_json::from_slice(payload).map_err(|_| ChannelClientError::Malformed)
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

/// A fresh 32-byte pairing nonce. Derived from an ephemeral keypair's public key
/// bytes so the channel client needs no direct `rand` dependency (the CSPRNG is
/// `rrn-crypto`'s `Keypair::generate`); the token is a uniqueness/unpredictability
/// nonce, not key material.
fn random_token() -> [u8; 32] {
    Keypair::generate().public_key().to_bytes()
}
