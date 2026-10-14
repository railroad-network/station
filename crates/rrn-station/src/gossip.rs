//! The peer port: a writer serves its chain to read-replicas, and a replica
//! pulls it (ADR-0020 §7).
//!
//! Every [`gossip_interval`](crate::config::TimersSection) seconds, for each
//! configured peer, a replica opens a TCP connection per request, asks "what's
//! your log tail?", pulls the entries after its per-peer cursor in bounded pages
//! (`log_range`), and appends the ones it doesn't already have — verifying every
//! signature on the way in (peer bytes are never trusted). Connections are
//! one-shot: open, one request, one response, close.
//!
//! It does **not** resolve forks — if a peer's chain diverges,
//! [`do_append_entries`](crate::core::Core) simply drops the entries it can't
//! verify and logs a warning. The wire envelope is the same line-delimited JSON
//! as the CLI protocol ([`crate::rpc`]), with its own method set
//! (`peer_handshake`, `log_tail`, `log_range`). Both sides bound what they read:
//! request and response lines are capped ([`crate::rpc_client`]), the server
//! caps concurrent connections and idle reads, and one `log_range` reads at
//! most one bounded page of the log.
//!
//! Who may read the chain (ADR-0020 Clarification 2026-10-14): the replica
//! method set is served only to loopback and to the addresses in
//! `[network] replicas` ([`PeerGate`]); every other source is refused with
//! [`rpc::PEER_NOT_ALLOWED`] and served nothing. The gate is per method, so
//! federation methods can carry their own authentication later (ADR-0029 §6).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use rrn_storage::log::StoredPayload;

use crate::clock::Clock;
use crate::core::{stored_from_parts, CoreHandle};
use crate::rpc::{self, Request, Response};
use crate::rpc_client::{
    read_line_bounded, request_response, LineError, MAX_LOG_RANGE_ENTRIES, MAX_PAGES_PER_ROUND,
    MAX_PEER_CONNECTIONS, PEER_IDLE_TIMEOUT, PEER_REQUEST_LINE_LIMIT, PEER_RESPONSE_LINE_LIMIT,
};

/// How long a single peer exchange (TCP connect **and** the one request/response)
/// may take before it is abandoned as unreachable. A station on a loopback-only
/// host must never park a gossip round — or, through it, its own shutdown — on the
/// OS TCP SYN timeout of a routable-but-dead peer (~75s macOS / ~127s Linux). The
/// bound keeps a round proportional to `peers.len()` and shutdown prompt (ADR-0020).
pub const PEER_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// How long one `log_range` page may take to arrive once connected. A full page
/// is about 4 MiB of JSON, which a slow link (a VPN or SSH tunnel to an
/// off-site replica) cannot carry inside [`PEER_DIAL_TIMEOUT`]; the connect
/// itself stays bounded by that, and a pull in flight is abandoned the moment
/// shutdown is signalled.
pub const PEER_PAGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Most distinct refused source addresses remembered so each is warned about
/// once; sources beyond this are logged at `debug` only.
const REFUSED_SOURCES_REMEMBERED: usize = 256;

/// Whether `source` may be served the replica method set: loopback
/// (`127.0.0.0/8`, `::1`, or an IPv4-mapped form) or exactly one of the
/// configured `replicas`. IPv4-mapped IPv6 addresses compare as their IPv4
/// form on both sides, so a dual-stack listener cannot be used to dodge the list.
pub fn peer_allowed(source: IpAddr, replicas: &[IpAddr]) -> bool {
    let source = source.to_canonical();
    source.is_loopback() || replicas.iter().any(|r| r.to_canonical() == source)
}

/// The peer port's replica allowlist, plus the refused-source memory that
/// keeps its log quiet (one `warn` per source per process).
#[derive(Debug, Default)]
pub struct PeerGate {
    replicas: Vec<IpAddr>,
    refused: Mutex<HashSet<IpAddr>>,
}

impl PeerGate {
    /// A gate serving loopback and `replicas` (`[network] replicas`).
    pub fn new(replicas: Vec<IpAddr>) -> Self {
        Self {
            replicas,
            refused: Mutex::new(HashSet::new()),
        }
    }

    /// Whether `source` may be served; logs a refusal.
    fn admit(&self, source: IpAddr, method: &str) -> bool {
        if peer_allowed(source, &self.replicas) {
            return true;
        }
        let source = source.to_canonical();
        let first = {
            let mut refused = self.refused.lock().expect("refused-sources mutex");
            refused.len() < REFUSED_SOURCES_REMEMBERED && refused.insert(source)
        };
        if first {
            tracing::warn!(
                %source,
                method,
                "refusing a peer-port read from an address that is not a configured \
                 replica; add it to [network] replicas if it is yours"
            );
        } else {
            tracing::debug!(%source, method, "refused peer-port read");
        }
        false
    }
}

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

/// Shared, in-memory connectivity snapshot the `status` RPC reports from.
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
    /// The Reticulum sidecar's live posture. Written by the sidecar
    /// supervisor, read by the status handler; `Disabled` until the supervisor
    /// says otherwise (and forever, when `[sidecar] enabled = false`).
    pub sidecar: Mutex<crate::sidecar::SidecarState>,
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
            sidecar: Mutex::new(crate::sidecar::SidecarState::Disabled),
        }
    }

    /// Records the sidecar supervisor's current [`SidecarState`](crate::sidecar::SidecarState).
    pub fn set_sidecar(&self, state: crate::sidecar::SidecarState) {
        *self.sidecar.lock().expect("sidecar mutex") = state;
    }

    /// A clone of the sidecar's current state, for the `status` RPC.
    pub fn sidecar_snapshot(&self) -> crate::sidecar::SidecarState {
        self.sidecar.lock().expect("sidecar mutex").clone()
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

/// `log_range` params. `limit` is required (no serde default): a puller that
/// predates paging is refused with `INVALID_PARAMS` rather than silently
/// stalling at its first page — writer and replicas upgrade together.
#[derive(Serialize, Deserialize)]
struct LogRangeParams {
    from_seq: u64,
    to_seq: u64,
    /// Requested page size; the server clamps it to `1..=MAX_LOG_RANGE_ENTRIES`.
    limit: u32,
}

/// One `log_range` page.
#[derive(Serialize, Deserialize)]
pub(crate) struct LogRangeResult {
    /// The entries served, ascending by the server's seq.
    pub(crate) entries: Vec<WireEntry>,
    /// The seq after the last entry served — where the next page starts
    /// (`from_seq` when the page is empty).
    pub(crate) next_from_seq: u64,
}

// --- server side: handle inbound peer connections ---------------------------

/// Serves the peer protocol on `listener` until `shutdown` resolves, dispatching
/// each request to `core` behind `gate`. At most [`MAX_PEER_CONNECTIONS`]
/// connections are served at once; one accepted beyond that is dropped
/// immediately.
pub async fn serve_peers(
    listener: TcpListener,
    core: CoreHandle,
    gate: Arc<PeerGate>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(MAX_PEER_CONNECTIONS));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        let Ok(permit) = slots.clone().try_acquire_owned() else {
                            tracing::debug!(peer = %addr, "peer port full; dropping connection");
                            drop(stream);
                            continue;
                        };
                        let core = core.clone();
                        let gate = gate.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_peer_conn(stream, addr.ip(), core, &gate).await {
                                tracing::debug!(error = %e, "peer connection ended");
                            }
                            drop(permit);
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
///
/// Each line is capped at [`PEER_REQUEST_LINE_LIMIT`] bytes and must arrive
/// within [`PEER_IDLE_TIMEOUT`]. An oversize line is answered with one
/// `INVALID_REQUEST` and the connection closed (the stream cannot be
/// resynchronized mid-line); an idle connection is closed without a reply, and
/// one that stops reading a reply is closed after [`PEER_PAGE_TIMEOUT`].
async fn handle_peer_conn(
    stream: TcpStream,
    source: IpAddr,
    core: CoreHandle,
    gate: &PeerGate,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = Vec::new();

    loop {
        let read = tokio::time::timeout(
            PEER_IDLE_TIMEOUT,
            read_line_bounded(&mut reader, &mut line, PEER_REQUEST_LINE_LIMIT),
        )
        .await;
        let n = match read {
            Err(_) => return Ok(()), // idle: close without a reply
            Ok(Ok(n)) => n,
            Ok(Err(LineError::TooLong { max })) => {
                let response = Response::err(
                    "",
                    rpc::INVALID_REQUEST,
                    format!("request line exceeds {max} bytes"),
                );
                write_line(&mut write_half, &response).await?;
                return Ok(());
            }
            Ok(Err(LineError::NotUtf8)) => {
                let response = Response::err("", rpc::INVALID_REQUEST, "bad request: not UTF-8");
                write_line(&mut write_half, &response).await?;
                continue;
            }
            Ok(Err(LineError::Io(e))) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(()); // peer closed
        }
        // `read_line_bounded` checked the bytes are UTF-8.
        let trimmed = std::str::from_utf8(&line).unwrap_or_default().trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(req) => dispatch_peer(&req, source, &core, gate).await,
            Err(e) => Response::err("", rpc::INVALID_REQUEST, format!("bad request: {e}")),
        };
        write_line(&mut write_half, &response).await?;
    }
}

/// Writes `response` as one JSON line and flushes it, within
/// [`PEER_PAGE_TIMEOUT`] — the same budget a puller gives a page to arrive, so a
/// full page still reaches a replica on a slow link, while a peer that stops
/// reading cannot hold a connection slot forever.
async fn write_line<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    response: &Response,
) -> anyhow::Result<()> {
    let mut out = serde_json::to_string(response)?;
    out.push('\n');
    tokio::time::timeout(PEER_PAGE_TIMEOUT, async {
        w.write_all(out.as_bytes()).await?;
        w.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("peer stopped reading; closing after {PEER_PAGE_TIMEOUT:?}"))??;
    Ok(())
}

/// Maps one peer request to a core query and builds the response. The replica
/// method set is refused, before any core query, to a `source` the `gate`
/// does not admit.
async fn dispatch_peer(
    req: &Request,
    source: IpAddr,
    core: &CoreHandle,
    gate: &PeerGate,
) -> Response {
    let method = req.method.as_str();
    if matches!(method, "peer_handshake" | "log_tail" | "log_range") && !gate.admit(source, method)
    {
        return Response::err(
            req.id.clone(),
            rpc::PEER_NOT_ALLOWED,
            rpc::PEER_NOT_ALLOWED_MESSAGE,
        );
    }
    match method {
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
            Ok(p) => match core.log_range(p.from_seq, p.to_seq, p.limit).await {
                Some((entries, next_from_seq)) => reply(
                    req,
                    &LogRangeResult {
                        entries,
                        next_from_seq,
                    },
                ),
                // Fail the puller's round visibly rather than serve an empty
                // page it would read as "nothing more".
                None => Response::err(req.id.clone(), rpc::INTERNAL_ERROR, "log read failed"),
            },
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
/// stay at `debug` so an offline month does not fill the log.
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
    // Per-peer pull cursor: the peer's next seq to fetch. In memory only — a
    // restart re-pulls once from 1, and `append_raw` dedups what we hold.
    let mut cursors: HashMap<String, u64> = HashMap::new();
    // Peers that refused us as a replica, so the refusal is warned once.
    let mut refused_by: HashSet<String> = HashSet::new();
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                for peer in peers.iter() {
                    // Bail out of a slow round the instant shutdown is signalled, so
                    // a long peer list cannot delay a clean stop.
                    if *shutdown.borrow() {
                        break;
                    }
                    // The network work is bounded *inside* `peer_call`: every
                    // connect by `PEER_DIAL_TIMEOUT`, which is what stops a
                    // black-holed peer from hanging the round, and each exchange by
                    // `PEER_DIAL_TIMEOUT` (or `PEER_PAGE_TIMEOUT` for a page, which
                    // shutdown interrupts). The local
                    // apply (`append_entries`) is deliberately NOT under that budget:
                    // pulling and verifying a large log is legitimate work, and
                    // timing it out here would falsely report a reachable peer as
                    // unreachable.
                    let cursor = cursors.entry(peer.clone()).or_insert(1);
                    let outcome =
                        gossip_with_peer(peer, &our_address, &core, cursor, &shutdown).await;
                    let ok = outcome.is_ok();
                    if let Err(e) = &outcome {
                        tracing::debug!(peer = %peer, error = %e, "gossip round failed");
                    }
                    // A refusal is a configuration problem on the writer, not an
                    // outage: say so once per peer, where this operator will look.
                    let refused = outcome
                        .as_ref()
                        .err()
                        .is_some_and(|e| e.downcast_ref::<PeerRefused>().is_some());
                    if refused && refused_by.insert(peer.clone()) {
                        tracing::warn!(
                            peer = %peer,
                            "the peer refused this station as a replica — add this \
                             station's address to the writer's [network] replicas"
                        );
                    } else if ok {
                        refused_by.remove(peer);
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
/// peer's entries from `cursor` in bounded pages.
///
/// The round ends when the cursor passes the handshake tail, a page comes back
/// empty, [`MAX_PAGES_PER_ROUND`] pages have been pulled, or shutdown is
/// signalled. The cursor advances past a page only once the core reports it
/// fully applied, so a failed round re-pulls rather than skipping entries.
async fn gossip_with_peer(
    peer: &str,
    our_address: &str,
    core: &CoreHandle,
    cursor: &mut u64,
    shutdown: &tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut shutdown = shutdown.clone();
    // 1. Handshake — learn the peer's log tail.
    let handshake: HandshakeResult = peer_call(
        peer,
        "peer_handshake",
        serde_json::to_value(HandshakeParams {
            our_address: our_address.to_string(),
        })?,
    )
    .await?;
    let tail = handshake.their_log_tail_seq;

    // A tail below what we already pulled means the peer's log shrank (a writer
    // restored from an older backup): start over rather than wait for seqs we
    // already passed. `append_raw` dedups what we hold.
    let pulled_to = *cursor;
    if rewind_if_shrunk(cursor, tail) {
        tracing::warn!(
            peer = %peer,
            tail,
            cursor = pulled_to,
            "peer's log tail is behind what this replica already pulled; re-pulling from the start"
        );
    }

    // 2. Pull pages from the cursor; 3. apply each — the core verifies
    //    signatures and dedups before appending.
    let mut appended = 0usize;
    for _ in 0..MAX_PAGES_PER_ROUND {
        if *cursor > tail || *shutdown.borrow() {
            break;
        }
        let params = serde_json::to_value(LogRangeParams {
            from_seq: *cursor,
            to_seq: tail,
            limit: MAX_LOG_RANGE_ENTRIES,
        })?;
        let page: LogRangeResult = tokio::select! {
            page = peer_call_within(peer, "log_range", params, PEER_PAGE_TIMEOUT) => page?,
            _ = shutdown_signalled(&mut shutdown) => break,
        };
        if page.entries.is_empty() {
            break;
        }
        // An honest page moves forward and never past the tail we asked about.
        if page.next_from_seq <= *cursor || page.next_from_seq > tail.saturating_add(1) {
            anyhow::bail!(
                "peer returned next_from_seq {} for a page from {} to {tail}",
                page.next_from_seq,
                *cursor
            );
        }
        let Some(n) = core.append_entries(page.entries).await else {
            anyhow::bail!(
                "page from seq {} was not fully applied; will retry",
                *cursor
            );
        };
        appended += n;
        *cursor = page.next_from_seq;
    }
    if appended > 0 {
        tracing::info!(peer = %peer, appended, "gossip: pulled new entries");
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
    peer_call_within(peer, method, params, PEER_DIAL_TIMEOUT).await
}

/// [`peer_call`] whose request/response exchange may take up to `exchange`.
/// The TCP connect is always bounded by [`PEER_DIAL_TIMEOUT`], so a
/// black-holed peer cannot hang the round on the OS SYN timeout; a longer
/// `exchange` only lets a reachable peer's large reply arrive over a slow link.
async fn peer_call_within<T: for<'de> Deserialize<'de>>(
    peer: &str,
    method: &str,
    params: serde_json::Value,
    exchange: Duration,
) -> anyhow::Result<T> {
    let request = Request {
        id: uuid::Uuid::new_v4().to_string(),
        method: method.to_string(),
        params,
    };
    let mut stream = tokio::time::timeout(PEER_DIAL_TIMEOUT, TcpStream::connect(peer))
        .await
        .map_err(|_| anyhow::anyhow!("peer {peer} timed out after {PEER_DIAL_TIMEOUT:?}"))??;
    let response = tokio::time::timeout(
        exchange,
        request_response(&mut stream, &request, PEER_RESPONSE_LINE_LIMIT),
    )
    .await
    .map_err(|_| anyhow::anyhow!("peer {peer} timed out after {exchange:?}"))??;
    if let Some(err) = response.error {
        if err.code == rpc::PEER_NOT_ALLOWED {
            return Err(PeerRefused.into());
        }
        anyhow::bail!("peer error: {} (code {})", err.message, err.code);
    }
    let value = response.result.unwrap_or(serde_json::Value::Null);
    Ok(serde_json::from_value(value)?)
}

/// The peer answered [`rpc::PEER_NOT_ALLOWED`]: it does not list this station
/// as a replica.
#[derive(Debug, thiserror::Error)]
#[error(
    "peer refused this station: not a configured replica (code {})",
    rpc::PEER_NOT_ALLOWED
)]
struct PeerRefused;

/// Resolves once `shutdown` reads `true` (never, if its sender is gone).
async fn shutdown_signalled(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Rewinds `cursor` to 1 when the peer's `tail` is below what was already
/// pulled (`cursor - 1`) — a writer restored from an older backup. Returns
/// whether it rewound.
fn rewind_if_shrunk(cursor: &mut u64, tail: u64) -> bool {
    if tail < cursor.saturating_sub(1) {
        *cursor = 1;
        true
    } else {
        false
    }
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
    fn peer_allowed_loopback_and_listed_only() {
        let ip = |a: &str| a.parse::<IpAddr>().unwrap();
        let replicas = vec![ip("192.168.1.20")];
        // Loopback in every form, with or without a list.
        for a in ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"] {
            assert!(peer_allowed(ip(a), &replicas), "{a}");
            assert!(peer_allowed(ip(a), &[]), "{a}");
        }
        // A listed address, also as IPv4-mapped IPv6 (a dual-stack listener).
        assert!(peer_allowed(ip("192.168.1.20"), &replicas));
        assert!(peer_allowed(ip("::ffff:192.168.1.20"), &replicas));
        // A list entry written in mapped form matches the plain address too.
        assert!(peer_allowed(
            ip("192.168.1.20"),
            &[ip("::ffff:192.168.1.20")]
        ));
        // Everything else is refused.
        for a in [
            "192.168.1.21",
            "10.0.0.1",
            "0.0.0.0",
            "::",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!peer_allowed(ip(a), &replicas), "{a}");
        }
        assert!(!peer_allowed(ip("192.168.1.20"), &[]));
    }

    /// A real core (writer, one vouch on its log) behind a handle.
    fn spawn_core() -> CoreHandle {
        use rrn_crypto::keypair::Keypair;
        use rrn_identity::address::Address;
        use rrn_storage::db::Database;
        use rrn_storage::log::AppendLog;
        let db = Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        let kp = Keypair::generate();
        let subject = Address::from_public_key(Keypair::generate().public_key());
        AppendLog::new(&db)
            .append(
                rrn_identity::vouch::create_vouch(&kp, &subject, "c", "hi", 0),
                1_000,
            )
            .unwrap();
        crate::core::Core::new(
            db,
            rrn_identity::wallet::WalletContents::create_new(),
            rrn_ledger::settlement::SettlementConfig::default(),
            rrn_ledger::credit::CreditConfig::default(),
            Clock::manual(1_000),
            crate::paired::PairedMobiles::default(),
            rrn_marketplace::search::SearchIndex::in_memory(),
        )
        .spawn()
    }

    #[tokio::test]
    async fn unlisted_source_gets_peer_not_allowed() {
        let core = spawn_core();
        let gate = PeerGate::new(vec!["192.168.1.20".parse().unwrap()]);
        let requests = [
            ("peer_handshake", serde_json::json!({ "our_address": "x" })),
            ("log_tail", serde_json::Value::Null),
            (
                "log_range",
                serde_json::json!({ "from_seq": 1, "to_seq": 10, "limit": 10 }),
            ),
        ];
        let outsider: IpAddr = "192.168.1.99".parse().unwrap();
        let replica: IpAddr = "::ffff:192.168.1.20".parse().unwrap();
        for (method, params) in requests {
            let req = Request {
                id: format!("id-{method}"),
                method: method.into(),
                params,
            };
            // Refused: the typed code, the constant message, no result.
            let refused = dispatch_peer(&req, outsider, &core, &gate).await;
            assert!(refused.result.is_none(), "{method} served a result");
            let err = refused.error.expect("a refusal");
            assert_eq!(err.code, rpc::PEER_NOT_ALLOWED, "{method}");
            assert_eq!(err.message, rpc::PEER_NOT_ALLOWED_MESSAGE, "{method}");
            assert_eq!(refused.id, req.id);
            // The listed replica (here arriving IPv4-mapped) is served.
            let served = dispatch_peer(&req, replica, &core, &gate).await;
            assert!(served.error.is_none(), "{method}: {:?}", served.error);
            assert!(served.result.is_some(), "{method}");
        }
        // The outsider was remembered once, for one warning.
        assert_eq!(gate.refused.lock().unwrap().len(), 1);
        core.shutdown();
    }

    #[test]
    fn cursor_rewinds_only_when_the_peer_tail_shrinks() {
        // Pulled through 600 (cursor 601): a tail of 600 or more is not a shrink.
        let mut cursor = 601;
        assert!(!rewind_if_shrunk(&mut cursor, 600));
        assert!(!rewind_if_shrunk(&mut cursor, 900));
        assert_eq!(cursor, 601);
        // A tail below what was pulled (writer restored from an older backup).
        assert!(rewind_if_shrunk(&mut cursor, 599));
        assert_eq!(cursor, 1);
        // A fresh cursor never rewinds, even against an empty log.
        assert!(!rewind_if_shrunk(&mut cursor, 0));
        assert_eq!(cursor, 1);
    }

    #[test]
    fn first_reachable_observation_is_a_transition() {
        // A peer that is reachable from the very first round is worth one info line.
        let s = state();
        assert_eq!(s.record("127.0.0.1:1", true, 1), Some(true));
    }
}
