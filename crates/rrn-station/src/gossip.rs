//! The Phase 0 gossip stub: replicate log entries between two communities.
//!
//! This is deliberately the dumbest thing that works for a two-station demo.
//! Every [`gossip_interval`](crate::config::TimersSection) seconds, for each
//! configured peer, a station opens a TCP connection, asks "what's your log
//! tail?", pulls the peer's entries, and appends the ones it doesn't already
//! have — verifying every signature on the way in (peer bytes are never
//! trusted). Connections are one-shot: open, one request, one response, close.
//!
//! It does **not** scale and it does **not** resolve forks — if a peer's chain
//! diverges, [`do_append_entries`](crate::core::Core) simply drops the entries
//! it can't verify and logs a warning. Phase 2 replaces this wholesale. The wire
//! envelope is the same line-delimited JSON as the CLI protocol ([`crate::rpc`]),
//! with its own method set (`peer_handshake`, `log_tail`, `log_range`).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use rrn_storage::log::StoredPayload;

use crate::core::{stored_from_parts, CoreHandle};
use crate::rpc::{self, Request, Response};
use crate::rpc_client::request_response;

/// A log entry as it crosses the peer wire: the three fields of a
/// [`StoredPayload`], each as a JSON byte array. Position in the chain
/// (`prev_hash`, `seq`) is intentionally *not* sent — the receiver re-chains the
/// payload onto its own log, and the content hash (over `bytes`) is what makes
/// the same entry recognizable on both sides.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEntry {
    /// The 32-byte signer public key.
    pub signer: Vec<u8>,
    /// The 64-byte signature over `bytes`.
    pub signature: Vec<u8>,
    /// The canonical CBOR that was signed.
    pub bytes: Vec<u8>,
}

impl WireEntry {
    /// Serializes a stored payload for transmission.
    pub fn from_stored(p: &StoredPayload) -> Self {
        WireEntry {
            signer: p.signer.to_bytes().to_vec(),
            signature: p.signature.to_bytes().to_vec(),
            bytes: p.bytes.clone(),
        }
    }

    /// Reconstructs a stored payload, or `None` if the key/signature lengths are
    /// wrong. (The signature is *verified* later, at append time.)
    pub fn to_stored(&self) -> Option<StoredPayload> {
        stored_from_parts(&self.signer, &self.signature, self.bytes.clone())
    }
}

// --- peer method params / results ------------------------------------------

#[derive(Serialize, Deserialize)]
struct HandshakeParams {
    our_address: String,
}

#[derive(Serialize, Deserialize)]
struct HandshakeResult {
    their_address: String,
    their_log_tail_seq: u64,
}

#[derive(Serialize, Deserialize)]
struct LogTailResult {
    seq: u64,
}

#[derive(Serialize, Deserialize)]
struct LogRangeParams {
    from_seq: u64,
    to_seq: u64,
}

#[derive(Serialize, Deserialize)]
struct LogRangeResult {
    entries: Vec<WireEntry>,
}

// --- server side: handle inbound peer connections ---------------------------

/// Serves the peer protocol on `listener` until `shutdown` resolves, dispatching
/// each request to `core`.
pub async fn serve_peers(
    listener: TcpListener,
    core: CoreHandle,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let core = core.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_peer_conn(stream, core).await {
                                tracing::debug!(error = %e, "peer connection ended");
                            }
                        });
                    }
                    Err(e) => tracing::warn!(error = %e, "peer accept failed"),
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Reads requests line-by-line from one peer connection and answers each.
async fn handle_peer_conn(stream: TcpStream, core: CoreHandle) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(()); // peer closed
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(req) => dispatch_peer(&req, &core).await,
            Err(e) => Response::err("", rpc::INVALID_REQUEST, format!("bad request: {e}")),
        };
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        write_half.write_all(out.as_bytes()).await?;
        write_half.flush().await?;
    }
}

/// Maps one peer request to a core query and builds the response.
async fn dispatch_peer(req: &Request, core: &CoreHandle) -> Response {
    match req.method.as_str() {
        "peer_handshake" => {
            // We log the peer's claimed address but don't act on it in Phase 0.
            let _params: Result<HandshakeParams, _> = serde_json::from_value(req.params.clone());
            let (their_address, their_log_tail_seq) = core.handshake().await.unwrap_or_default();
            reply(
                req,
                &HandshakeResult {
                    their_address,
                    their_log_tail_seq,
                },
            )
        }
        "log_tail" => {
            let seq = core.log_tail().await;
            reply(req, &LogTailResult { seq })
        }
        "log_range" => match serde_json::from_value::<LogRangeParams>(req.params.clone()) {
            Ok(p) => {
                let entries = core.log_range(p.from_seq, p.to_seq).await;
                reply(req, &LogRangeResult { entries })
            }
            Err(e) => Response::err(req.id.clone(), rpc::INVALID_PARAMS, format!("{e}")),
        },
        other => Response::err(
            req.id.clone(),
            rpc::METHOD_NOT_FOUND,
            format!("unknown peer method: {other}"),
        ),
    }
}

fn reply<T: Serialize>(req: &Request, value: &T) -> Response {
    match serde_json::to_value(value) {
        Ok(v) => Response::ok(req.id.clone(), v),
        Err(e) => Response::err(req.id.clone(), rpc::INTERNAL_ERROR, format!("{e}")),
    }
}

// --- client side: the periodic gossip loop ----------------------------------

/// Runs a gossip round against every peer every `interval`, until `shutdown`.
pub async fn gossip_loop(
    interval: Duration,
    peers: Arc<Vec<String>>,
    our_address: String,
    core: CoreHandle,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                for peer in peers.iter() {
                    if let Err(e) = gossip_with_peer(peer, &our_address, &core).await {
                        tracing::debug!(peer = %peer, error = %e, "gossip round failed");
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// One gossip exchange with a single peer: handshake, then pull and apply the
/// peer's entries.
async fn gossip_with_peer(peer: &str, our_address: &str, core: &CoreHandle) -> anyhow::Result<()> {
    // 1. Handshake — learn the peer's log tail.
    let handshake: HandshakeResult = peer_call(
        peer,
        "peer_handshake",
        serde_json::to_value(HandshakeParams {
            our_address: our_address.to_string(),
        })?,
    )
    .await?;

    if handshake.their_log_tail_seq == 0 {
        return Ok(()); // nothing to pull
    }

    // 2. Pull the peer's whole log. Dedup-by-content on our side makes re-pulling
    //    cheap-enough for a two-station Phase 0 demo; a smarter delta sync is a
    //    later concern.
    let range: LogRangeResult = peer_call(
        peer,
        "log_range",
        serde_json::to_value(LogRangeParams {
            from_seq: 1,
            to_seq: handshake.their_log_tail_seq,
        })?,
    )
    .await?;

    // 3. Apply — the core verifies signatures and dedups before appending.
    if !range.entries.is_empty() {
        let n = core.append_entries(range.entries).await;
        if n > 0 {
            tracing::info!(peer = %peer, appended = n, "gossip: pulled new entries");
        }
    }
    Ok(())
}

/// Opens a one-shot TCP connection to `peer`, sends one request, and decodes the
/// typed result. Errors if the peer returns an `error` envelope.
async fn peer_call<T: for<'de> Deserialize<'de>>(
    peer: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<T> {
    let request = Request {
        id: uuid::Uuid::new_v4().to_string(),
        method: method.to_string(),
        params,
    };
    let mut stream = TcpStream::connect(peer).await?;
    let response = request_response(&mut stream, &request).await?;
    if let Some(err) = response.error {
        anyhow::bail!("peer error: {} (code {})", err.message, err.code);
    }
    let value = response.result.unwrap_or(serde_json::Value::Null);
    Ok(serde_json::from_value(value)?)
}
