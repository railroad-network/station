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

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use rrn_storage::log::StoredPayload;

use crate::clock::Clock;
use crate::core::{stored_from_parts, CoreHandle};
use crate::rpc::{self, Request, Response};
use crate::rpc_client::request_response;

/// How long a single peer exchange (TCP connect **and** the one request/response)
/// may take before it is abandoned as unreachable. A station on a loopback-only
/// host must never park a gossip round — or, through it, its own shutdown — on the
/// OS TCP SYN timeout of a routable-but-dead peer (~75s macOS / ~127s Linux). The
/// bound keeps a round proportional to `peers.len()` and shutdown prompt (ADR-0020;
/// T2.4.1).
pub const PEER_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// The health of one peer, as last observed by the gossip loop. Derived, in-memory
/// only (never logged/persisted state) — the `status` connectivity block reads it.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerHealth {
    /// Whether the most recent gossip round with this peer succeeded.
    pub reachable: bool,
    /// Clock time of the last successful round, if any.
    pub last_success_at: Option<i64>,
    /// Clock time this peer was last attempted.
    pub last_attempt_at: Option<i64>,
}

/// Shared, in-memory connectivity snapshot the `status` RPC reports from (T2.4.1).
/// Written by the gossip loop and the startup path; read by the status handler.
/// Purely derived degradation-legibility state — nothing here is signed, logged,
/// or required for correctness.
#[derive(Debug)]
pub struct ConnectivityState {
    /// The configured peer addresses (static, from `[peers] list`).
    pub peers: Vec<String>,
    /// The configured mobile listen address (`[mobile] listen`).
    pub mobile_listen: String,
    /// Whether the station is advertising over mDNS (`[mobile] advertise`).
    pub mobile_advertising: bool,
    /// Whether the mobile HTTP listener actually bound at startup.
    pub mobile_bound: AtomicBool,
    /// Per-peer reachability, keyed by peer address.
    pub peer_health: Mutex<HashMap<String, PeerHealth>>,
}

impl ConnectivityState {
    /// A fresh snapshot for the configured peers/mobile surface; no peer has been
    /// contacted yet.
    pub fn new(peers: Vec<String>, mobile_listen: String, mobile_advertising: bool) -> Self {
        Self {
            peers,
            mobile_listen,
            mobile_advertising,
            mobile_bound: AtomicBool::new(false),
            peer_health: Mutex::new(HashMap::new()),
        }
    }

    /// Records a round's outcome for `peer` and returns the reachability
    /// *transition* (`Some(true)` newly reachable, `Some(false)` newly unreachable,
    /// `None` unchanged) so the caller logs one `info` on a flip, not per round.
    fn record(&self, peer: &str, ok: bool, now: i64) -> Option<bool> {
        let mut map = self.peer_health.lock().expect("peer_health mutex");
        let entry = map.entry(peer.to_string()).or_default();
        let first = entry.last_attempt_at.is_none();
        let was = entry.reachable;
        entry.last_attempt_at = Some(now);
        entry.reachable = ok;
        if ok {
            entry.last_success_at = Some(now);
        }
        // A flip is a transition; so is the very first observation of a reachable
        // peer (worth one line), but not the first observation of an unreachable one
        // (that is the silent, expected offline default).
        if was != ok || (first && ok) {
            Some(ok)
        } else {
            None
        }
    }
}

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
///
/// Each peer exchange is bounded by [`PEER_DIAL_TIMEOUT`], so one unreachable peer
/// cannot stall the round (or shutdown). Outcomes update `connectivity`, and a
/// peer flipping reachable↔unreachable logs one `info`; ordinary offline rounds
/// stay at `debug` so an offline month does not fill the log (T2.4.1).
pub async fn gossip_loop(
    interval: Duration,
    peers: Arc<Vec<String>>,
    our_address: String,
    core: CoreHandle,
    connectivity: Arc<ConnectivityState>,
    clock: Clock,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                for peer in peers.iter() {
                    // Bail out of a slow round the instant shutdown is signalled, so
                    // a long peer list cannot delay a clean stop.
                    if *shutdown.borrow() {
                        break;
                    }
                    // The network work — connect and each request/response — is
                    // bounded *inside* `peer_call` by `PEER_DIAL_TIMEOUT`, which is
                    // what stops a black-holed peer from hanging the round. The local
                    // apply (`append_entries`) is deliberately NOT under that budget:
                    // pulling and verifying a large log is legitimate work, and
                    // timing it out here would falsely report a reachable peer as
                    // unreachable.
                    let outcome = gossip_with_peer(peer, &our_address, &core).await;
                    let ok = outcome.is_ok();
                    if let Err(e) = &outcome {
                        tracing::debug!(peer = %peer, error = %e, "gossip round failed");
                    }
                    match connectivity.record(peer, ok, clock.now()) {
                        Some(true) => tracing::info!(peer = %peer, "peer reachable"),
                        Some(false) => tracing::info!(peer = %peer, "peer unreachable"),
                        None => {}
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
    // Bound the whole exchange — connect and the single request/response — so a
    // black-holed peer cannot hang the round on the OS SYN timeout (T2.4.1). The
    // caller also wraps the round in `PEER_DIAL_TIMEOUT`; this inner bound protects
    // any direct `peer_call` and keeps the failure mode a clean typed error.
    let response = tokio::time::timeout(PEER_DIAL_TIMEOUT, async {
        let mut stream = TcpStream::connect(peer).await?;
        request_response(&mut stream, &request).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("peer {peer} timed out after {PEER_DIAL_TIMEOUT:?}"))??;
    if let Some(err) = response.error {
        anyhow::bail!("peer error: {} (code {})", err.message, err.code);
    }
    let value = response.result.unwrap_or(serde_json::Value::Null);
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ConnectivityState {
        ConnectivityState::new(vec!["10.255.255.1:7411".into()], "127.0.0.1:0".into(), true)
    }

    #[test]
    fn reachability_transitions_log_once_not_per_round() {
        let s = state();
        let peer = "10.255.255.1:7411";

        // First unreachable observation is the silent offline default (no transition).
        assert_eq!(s.record(peer, false, 100), None);
        // Repeated failures stay silent.
        assert_eq!(s.record(peer, false, 101), None);
        // Becoming reachable is a transition.
        assert_eq!(s.record(peer, true, 102), Some(true));
        // Staying reachable is silent.
        assert_eq!(s.record(peer, true, 103), None);
        // Dropping is a transition.
        assert_eq!(s.record(peer, false, 104), Some(false));

        // Health reflects the last observation and the last success time.
        let h = s.peer_health.lock().unwrap()[peer];
        assert!(!h.reachable);
        // Last success is the most recent reachable round (t=103), not the flip.
        assert_eq!(h.last_success_at, Some(103));
        assert_eq!(h.last_attempt_at, Some(104));
    }

    #[test]
    fn first_reachable_observation_is_a_transition() {
        // A peer that is reachable from the very first round is worth one info line.
        let s = state();
        assert_eq!(s.record("127.0.0.1:1", true, 1), Some(true));
    }
}
