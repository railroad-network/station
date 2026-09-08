//! Delay-tolerant bundle sync over any [`FrameTransport`] (T2.6.2, ADR-0013).
//!
//! This is the engine that moves DTN bundles and delivery receipts station↔station
//! and device↔station over a constrained carrier — the Reticulum sidecar in
//! production ([`crate::reticulum`]), a fault-injecting mock in tests. It is
//! **generic over the carrier**: it holds any `FrameTransport` and drives it,
//! which is exactly the seam T2.10.1's 72-hour outage harness needs (construct it
//! with a mock carrier and drive simulated time).
//!
//! What it composes:
//! - **[`airtime::PacedSender`]** — outbound frames leave inside the LoRa airtime
//!   budget, in strict priority (money first).
//! - **[`framing`]** — a payload too big for one frame is chunked; the receiver
//!   reassembles order-independently.
//! - **a tiny reliability layer** — because a chunked payload over a lossy carrier
//!   loses chunks, the receiver asks for the ones still missing
//!   ([`ControlFrame::RequestMissing`]) and acknowledges a completed payload
//!   ([`ControlFrame::Ack`]); the sender keeps a payload's chunks until acked (or
//!   a TTL elapses) so it can answer.
//!
//! The engine is deliberately **clock-injected and pull-driven**: nothing here
//! reads a clock or spawns a task. [`tick`](DtnSyncer::tick) is called with `now`;
//! it pumps the pacer onto the wire, drains arrivals, and hands the caller the
//! payloads that completed. Ingest (turning a received bundle into a signed
//! receipt) is the caller's job — kept out of the engine so it stays testable
//! without a ledger, and so the daemon can run ingest on its single-writer core
//! thread (ADR-0020).

use std::collections::{HashMap, HashSet};

use rrn_protocol::airtime::{AirtimeBudget, Enqueued, PacedSender, Priority, QueueCaps};
use rrn_protocol::framing::{self, Reassembler, ReassemblerConfig};
use rrn_protocol::transport::{Endpoint, FrameTransport, TransportError};

/// What a reassembled payload is. A one-byte tag prefixes every payload before
/// chunking, so the receiver can route a completed payload without decoding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    /// A carriage [`Bundle`](rrn_protocol::bundle::Bundle) of signed records to
    /// ingest. Tag byte `0x01`.
    Bundle,
    /// A signed [`DeliveryReceipt`](rrn_protocol::receipt::DeliveryReceipt) — proof
    /// the sender's bundle landed. Tag byte `0x02`.
    Receipt,
}

impl PayloadKind {
    fn tag(self) -> u8 {
        match self {
            PayloadKind::Bundle => 0x01,
            PayloadKind::Receipt => 0x02,
        }
    }
    fn from_tag(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(PayloadKind::Bundle),
            0x02 => Some(PayloadKind::Receipt),
            _ => None,
        }
    }
}

/// The engine's control-frame magic — distinct from [`framing::MAGIC`] (`RRNF`),
/// so a receiver tells a data chunk from a control frame by its first four bytes.
pub const CONTROL_MAGIC: [u8; 4] = *b"RRNC";
/// Control-frame format version.
pub const CONTROL_VERSION: u8 = 1;

const CTRL_REQUEST_MISSING: u8 = 0x01;
const CTRL_ACK: u8 = 0x02;

/// A tiny reliability control frame (versioned; documented in
/// `docs/dtn-bundles.md`). Header: `RRNC`(4) · version(1) · type(1) · payload_id(32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlFrame {
    /// "I am still missing these chunk indexes of this payload — resend them."
    RequestMissing {
        /// The payload whose chunks are wanted.
        payload_id: [u8; 32],
        /// The chunk indexes still absent, ascending.
        missing: Vec<u16>,
    },
    /// "I have the whole payload — you may drop it." Lets the sender free its
    /// retransmit cache promptly rather than waiting out the TTL.
    Ack {
        /// The completed payload.
        payload_id: [u8; 32],
    },
}

impl ControlFrame {
    /// Encodes the control frame to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&CONTROL_MAGIC);
        out.push(CONTROL_VERSION);
        match self {
            ControlFrame::RequestMissing {
                payload_id,
                missing,
            } => {
                out.push(CTRL_REQUEST_MISSING);
                out.extend_from_slice(payload_id);
                out.extend_from_slice(&(missing.len() as u16).to_be_bytes());
                for idx in missing {
                    out.extend_from_slice(&idx.to_be_bytes());
                }
            }
            ControlFrame::Ack { payload_id } => {
                out.push(CTRL_ACK);
                out.extend_from_slice(payload_id);
            }
        }
        out
    }

    /// Parses a control frame, or `None` if `bytes` is not a well-formed one (not
    /// the control magic, wrong version, truncated, unknown type).
    pub fn decode(bytes: &[u8]) -> Option<ControlFrame> {
        if bytes.len() < 6 || bytes[0..4] != CONTROL_MAGIC || bytes[4] != CONTROL_VERSION {
            return None;
        }
        let ty = bytes[5];
        let rest = &bytes[6..];
        if rest.len() < 32 {
            return None;
        }
        let mut payload_id = [0u8; 32];
        payload_id.copy_from_slice(&rest[..32]);
        match ty {
            CTRL_ACK => Some(ControlFrame::Ack { payload_id }),
            CTRL_REQUEST_MISSING => {
                let tail = &rest[32..];
                if tail.len() < 2 {
                    return None;
                }
                let count = u16::from_be_bytes([tail[0], tail[1]]) as usize;
                let idx_bytes = &tail[2..];
                if idx_bytes.len() < count * 2 {
                    return None;
                }
                let missing = (0..count)
                    .map(|i| u16::from_be_bytes([idx_bytes[i * 2], idx_bytes[i * 2 + 1]]))
                    .collect();
                Some(ControlFrame::RequestMissing {
                    payload_id,
                    missing,
                })
            }
            _ => None,
        }
    }
}

/// A payload that finished reassembling this tick, for the caller to act on: a
/// [`PayloadKind::Bundle`] to ingest (and reply to with a receipt) or a
/// [`PayloadKind::Receipt`] confirming one of our own sends landed.
#[derive(Clone, Debug)]
pub struct Completed {
    /// The peer the payload arrived from.
    pub source: Endpoint,
    /// What it is.
    pub kind: PayloadKind,
    /// The reassembled payload bytes (the tag byte stripped).
    pub bytes: Vec<u8>,
}

/// Tuning for a [`DtnSyncer`].
#[derive(Clone, Copy, Debug)]
pub struct SyncConfig {
    /// How often (seconds) the receiver re-asks for a payload's still-missing
    /// chunks.
    pub resend_interval_secs: i64,
    /// How long (seconds) the sender keeps a payload's chunks for retransmit
    /// before giving up, if never acked.
    pub cache_ttl_secs: i64,
    /// Reassembler bounds (memory caps, per-payload TTL).
    pub reassembler: ReassemblerConfig,
    /// Airtime queue depth caps.
    pub queue_caps: QueueCaps,
    /// The most inbound in-flight payloads to track at once — a bound so a peer
    /// spraying one chunk each of many distinct payloads cannot grow the
    /// receiver-side map (and its request-missing traffic) without limit.
    pub max_inbound_tracked: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            resend_interval_secs: 30,
            cache_ttl_secs: 24 * 60 * 60,
            reassembler: ReassemblerConfig::default(),
            queue_caps: QueueCaps::default(),
            max_inbound_tracked: 256,
        }
    }
}

/// A cached outbound payload's chunks, kept for retransmit until acked or TTL.
struct CachedSend {
    chunks: Vec<Vec<u8>>,
    priority: Priority,
    /// When the peer was last heard from about this payload (its first send, or a
    /// request-missing) — the anchor for the retransmit TTL, so a payload to a peer
    /// that has gone silent is *eventually* abandoned. Our own pokes do **not**
    /// refresh it (or the cache would live forever — a real bug).
    last_activity_at: i64,
    /// When we last poked (re-sent the first chunk of) this payload — the poke
    /// cadence anchor, distinct from the TTL anchor above.
    last_poke_at: i64,
}

/// Receiver-side state for one inbound in-flight payload: who it came from and
/// when we last asked for its missing chunks.
struct InboundState {
    source: Endpoint,
    last_request_at: i64,
}

/// The delay-tolerant sync engine over one carrier (module docs).
pub struct DtnSyncer<T: FrameTransport> {
    transport: T,
    sender: PacedSender,
    reassembler: Reassembler,
    config: SyncConfig,
    max_frame_bytes: usize,
    /// Send-side retransmit cache, keyed by `(peer, payload_id)`.
    outbound: HashMap<(Endpoint, [u8; 32]), CachedSend>,
    /// Chunks currently queued-but-not-yet-sent, keyed by `(peer, payload_id,
    /// chunk_index)`. A retransmit request only enqueues a chunk absent from this
    /// set, so a receiver re-requesting faster than a slow carrier can drain
    /// cannot pile duplicate resends into the pacer (an unbounded-queue bug).
    pending: HashSet<(Endpoint, [u8; 32], u16)>,
    /// Request-missing control frames currently queued-not-sent, keyed by
    /// `(peer, payload_id)` — so at most one outstanding request per payload sits
    /// in the pacer at a time (control frames, like data chunks, must not pile up
    /// on a slow carrier).
    pending_requests: HashSet<(Endpoint, [u8; 32])>,
    /// Receiver-side tracking, keyed by `payload_id`.
    inbound: HashMap<[u8; 32], InboundState>,
}

impl<T: FrameTransport> DtnSyncer<T> {
    /// Builds a syncer over `transport`, pacing to `budget`. The pacer's clock is
    /// seeded at `now`.
    pub fn new(transport: T, budget: AirtimeBudget, config: SyncConfig, now: i64) -> Self {
        let max_frame_bytes = transport.profile().max_frame_bytes;
        DtnSyncer {
            sender: PacedSender::with_caps(budget, config.queue_caps, now),
            reassembler: Reassembler::new(config.reassembler),
            transport,
            config,
            max_frame_bytes,
            outbound: HashMap::new(),
            pending: HashSet::new(),
            pending_requests: HashSet::new(),
            inbound: HashMap::new(),
        }
    }

    /// Enqueues one data chunk for `to`, skipping it if an identical chunk is
    /// already queued-not-sent (dedup — see [`pending`](Self::pending)). Returns
    /// whether it was newly enqueued.
    /// Best-effort enqueue of one data chunk, deduped against the in-flight set.
    /// Returns whether it was newly queued (`false` if already in flight or the
    /// pacer refused it under backpressure — either way the caller's cache + poke
    /// will retry it, so backpressure is not an error here).
    fn enqueue_chunk(&mut self, priority: Priority, to: &Endpoint, chunk: Vec<u8>) -> bool {
        let key = framing::frame_ids(&chunk).map(|(pid, idx)| (to.clone(), pid, idx));
        if let Some(ref k) = key {
            if self.pending.contains(k) {
                return false; // already in flight; don't double-queue
            }
        }
        match self.sender.enqueue(priority, to.clone(), chunk) {
            Ok(outcome) => {
                // If a bulk enqueue evicted an older frame, forget that frame's
                // in-flight key — else it leaks a phantom "still queued" entry that
                // suppresses its later retransmit forever.
                if let Enqueued::AcceptedDroppedOldest { to: dto, bytes } = outcome {
                    if let Some((pid, idx)) = framing::frame_ids(&bytes) {
                        self.pending.remove(&(dto, pid, idx));
                    }
                }
                if let Some(k) = key {
                    self.pending.insert(k);
                }
                true
            }
            // Backpressured (economic/governance queue full): the cache + poke
            // retry it later. Not queued now.
            Err(_) => false,
        }
    }

    /// Queues a payload for `to`, chunked and paced at `priority`, and **caches it
    /// for retransmit** until the peer acks (or the TTL elapses).
    ///
    /// Returns whether the payload could be framed (`false` only for one too large
    /// to chunk for this carrier — a caller error). Backpressure is *not* a caller
    /// concern here: the cache is inserted **before** enqueuing, so any chunk the
    /// airtime queue refuses right now is simply delivered later by the poke /
    /// request-missing machinery — the payload is durably tracked either way, and
    /// no chunk is ever orphaned without a cache entry.
    pub fn send(
        &mut self,
        to: &Endpoint,
        kind: PayloadKind,
        payload: &[u8],
        priority: Priority,
        now: i64,
    ) -> bool {
        // Tag the payload so the receiver can route it, then chunk.
        let mut tagged = Vec::with_capacity(payload.len() + 1);
        tagged.push(kind.tag());
        tagged.extend_from_slice(payload);
        let chunks = match framing::chunk(&tagged, self.max_frame_bytes) {
            Ok(c) => c,
            Err(_) => return false, // too large to frame for this carrier
        };
        let payload_id = framing::payload_id(&tagged);

        // Cache first, so a chunk the pacer refuses right now is still tracked and
        // retransmitted (never orphaned). Then best-effort enqueue every chunk.
        self.outbound.insert(
            (to.clone(), payload_id),
            CachedSend {
                chunks: chunks.clone(),
                priority,
                last_activity_at: now,
                last_poke_at: now,
            },
        );
        for chunk in chunks {
            let _ = self.enqueue_chunk(priority, to, chunk);
        }
        true
    }

    /// Advances the engine at `now`: pumps paced frames onto the wire, drains and
    /// dispatches arrivals (answering control frames itself), and returns the
    /// payloads that completed this tick for the caller to ingest/record.
    ///
    /// The caller replies to a [`PayloadKind::Bundle`] by ingesting it and calling
    /// [`send`](Self::send) with the resulting receipt.
    pub fn tick(&mut self, now: i64) -> Result<Vec<Completed>, TransportError> {
        // 1. Drain the pacer, then push each cleared frame onto the carrier and
        // clear it from the in-flight set (collect first so `self` is not borrowed
        // by the pump closure and mutably below). A send error is a connectivity
        // event, not fatal — the receiver's request-missing pulls it again later.
        let mut outgoing: Vec<(Endpoint, Vec<u8>)> = Vec::new();
        self.sender
            .pump(now, |to, frame| outgoing.push((to, frame)));
        for (to, frame) in outgoing {
            if let Some((pid, idx)) = framing::frame_ids(&frame) {
                self.pending.remove(&(to.clone(), pid, idx));
            } else if let Some(ControlFrame::RequestMissing { payload_id, .. }) =
                ControlFrame::decode(&frame)
            {
                self.pending_requests.remove(&(to.clone(), payload_id));
            }
            let _ = self.transport.send(&to, frame);
        }

        // 2. Drain arrivals and dispatch.
        let mut completed = Vec::new();
        for (from, frame) in self.transport.poll_recv()? {
            if let Some(ctrl) = ControlFrame::decode(&frame) {
                self.handle_control(&from, ctrl, now);
                continue;
            }
            // Otherwise a data chunk: feed the reassembler.
            match self.reassembler.accept(&frame, now) {
                Ok(Some(tagged)) => {
                    if let Some(done) = self.finish_inbound(&from, &frame, tagged) {
                        completed.push(done);
                    }
                }
                Ok(None) => {
                    // `accept` returns None for BOTH "still incomplete" and
                    // "already completed" (a duplicate chunk of a payload we
                    // finished before). Tell them apart by `missing`: Some →
                    // partial, track its source so we can request the rest; None →
                    // already complete, so **re-ack** (our first ack may have been
                    // lost — without this the sender pokes forever and the receiver
                    // never re-acks).
                    if let Some(pid) = framing::frame_payload_id(&frame) {
                        match self.reassembler.missing(&pid) {
                            Some(_) => {
                                // Bound the receiver-side map: ignore a new partial
                                // once we are already tracking a carrier's worth.
                                if self.inbound.len() < self.config.max_inbound_tracked
                                    || self.inbound.contains_key(&pid)
                                {
                                    self.inbound.entry(pid).or_insert(InboundState {
                                        source: from.clone(),
                                        last_request_at: i64::MIN,
                                    });
                                }
                            }
                            None => self.enqueue_ack(&from, pid),
                        }
                    }
                }
                // A malformed/duplicate/over-cap frame is ignored (the carrier's
                // fault; the reassembler already refused it safely).
                Err(_) => {}
            }
        }

        // 3. Nudge, receiver side: for each inbound in-flight payload past the
        // resend interval, ask its source for the still-missing chunks.
        self.request_missing(now);

        // 4. Poke, sender side: re-send the first chunk of any un-acked payload
        // that has gone quiet. This is what rescues a payload whose *only* (or
        // first) chunk was lost — the receiver never saw it, so it cannot request
        // it; the poke makes the receiver aware, after which it drives the rest.
        self.poke_unacked(now);

        // 5. Housekeeping: prune the reassembler and expire stale send caches.
        self.reassembler.prune(now);
        self.prune_outbound(now);

        Ok(completed)
    }

    /// The transport this syncer drives (for status/inspection).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Consumes the syncer and returns its transport (to shut it down cleanly).
    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Frames still queued in the pacer across all classes.
    pub fn queued(&self) -> usize {
        self.sender.queued()
    }

    /// In-flight inbound payloads not yet reassembled.
    pub fn inbound_inflight(&self) -> usize {
        self.inbound.len()
    }

    /// Outbound payloads still cached for retransmit (un-acked).
    pub fn outbound_cached(&self) -> usize {
        self.outbound.len()
    }

    fn handle_control(&mut self, from: &Endpoint, ctrl: ControlFrame, now: i64) {
        match ctrl {
            ControlFrame::Ack { payload_id } => {
                self.outbound.remove(&(from.clone(), payload_id));
                // Also drop any still-pending chunks of the acked payload.
                self.pending
                    .retain(|(ep, pid, _)| !(ep == from && *pid == payload_id));
            }
            ControlFrame::RequestMissing {
                payload_id,
                missing,
            } => {
                // Clone the requested chunks out first (immutable borrow), then
                // enqueue them deduped (mutable borrow). A request is proof the
                // peer is alive, so it refreshes the TTL anchor.
                let resend: Option<(Priority, Vec<Vec<u8>>)> =
                    self.outbound.get_mut(&(from.clone(), payload_id)).map(|c| {
                        c.last_activity_at = now;
                        (
                            c.priority,
                            missing
                                .iter()
                                .filter_map(|&i| c.chunks.get(i as usize).cloned())
                                .collect(),
                        )
                    });
                if let Some((priority, chunks)) = resend {
                    for chunk in chunks {
                        // Deduped: a chunk still queued from a prior request is not
                        // re-added, so a fast re-requester cannot flood the pacer.
                        let _ = self.enqueue_chunk(priority, from, chunk);
                    }
                }
            }
        }
    }

    /// Enqueues an `Ack` for `payload_id` to `to` (economic-priority; tiny).
    fn enqueue_ack(&mut self, to: &Endpoint, payload_id: [u8; 32]) {
        let _ = self.sender.enqueue(
            Priority::Economic,
            to.clone(),
            ControlFrame::Ack { payload_id }.encode(),
        );
    }

    /// A payload finished reassembling: strip its kind tag, ack the sender, and
    /// return it for the caller. `frame` is any one of its chunks (for the id).
    fn finish_inbound(
        &mut self,
        from: &Endpoint,
        frame: &[u8],
        tagged: Vec<u8>,
    ) -> Option<Completed> {
        if let Some(pid) = framing::frame_payload_id(frame) {
            self.inbound.remove(&pid);
            self.enqueue_ack(from, pid);
        }
        let (tag, body) = tagged.split_first()?;
        let kind = PayloadKind::from_tag(*tag)?;
        Some(Completed {
            source: from.clone(),
            kind,
            bytes: body.to_vec(),
        })
    }

    /// The most chunk indexes that fit one request-missing frame on this carrier —
    /// header is `RRNC`(4)+ver(1)+type(1)+id(32)+count(2) = 40 bytes, then 2 per
    /// index. A request never exceeds the frame budget (or it would be refused and
    /// the payload would stall); the rest are covered by the next interval.
    fn max_missing_per_request(&self) -> usize {
        self.max_frame_bytes.saturating_sub(40) / 2
    }

    fn request_missing(&mut self, now: i64) {
        let cap = self.max_missing_per_request().max(1);
        // Collect the requests first (immutable borrow of the reassembler), then
        // enqueue (mutable borrow of the sender). Also drop inbound entries whose
        // payload the reassembler no longer tracks (completed or evicted).
        let mut requests: Vec<(Endpoint, [u8; 32], Vec<u16>)> = Vec::new();
        let mut done: Vec<[u8; 32]> = Vec::new();
        for (pid, state) in self.inbound.iter_mut() {
            match self.reassembler.missing(pid) {
                None => done.push(*pid), // completed or evicted: stop tracking
                Some(missing) if missing.is_empty() => done.push(*pid),
                Some(_)
                    if now.saturating_sub(state.last_request_at)
                        < self.config.resend_interval_secs => {}
                Some(_)
                    if self
                        .pending_requests
                        .contains(&(state.source.clone(), *pid)) => {}
                Some(mut missing) => {
                    missing.truncate(cap);
                    state.last_request_at = now;
                    requests.push((state.source.clone(), *pid, missing));
                }
            }
        }
        for pid in done {
            self.inbound.remove(&pid);
        }
        for (to, payload_id, missing) in requests {
            let frame = ControlFrame::RequestMissing {
                payload_id,
                missing,
            }
            .encode();
            if self
                .sender
                .enqueue(Priority::Economic, to.clone(), frame)
                .is_ok()
            {
                self.pending_requests.insert((to, payload_id));
            }
        }
    }

    /// Re-sends the first chunk of every un-acked cached payload that has gone
    /// quiet (poke cadence `resend_interval_secs`), *unless* a chunk of that
    /// payload is already queued — this rescues a payload whose only/first chunk
    /// was lost (the receiver never saw it, so cannot request it) without
    /// gratuitously re-sending chunk 0 while the initial transmission is still
    /// draining. The peer's [`ControlFrame::Ack`] drops the cache once it lands.
    fn poke_unacked(&mut self, now: i64) {
        let interval = self.config.resend_interval_secs;
        let due: Vec<(Endpoint, [u8; 32])> = self
            .outbound
            .iter()
            .filter(|(_, c)| now.saturating_sub(c.last_poke_at) >= interval)
            .map(|(k, _)| k.clone())
            .collect();
        for (to, pid) in due {
            // Skip if any chunk of this payload is still queued to send.
            let queued = self.pending.iter().any(|(ep, p, _)| ep == &to && *p == pid);
            let poke = self
                .outbound
                .get(&(to.clone(), pid))
                .and_then(|c| c.chunks.first().cloned().map(|ch| (c.priority, ch)));
            if !queued {
                if let Some((priority, chunk)) = poke {
                    let _ = self.enqueue_chunk(priority, &to, chunk);
                }
            }
            if let Some(c) = self.outbound.get_mut(&(to, pid)) {
                c.last_poke_at = now;
            }
        }
    }

    /// Drops cached payloads whose peer has gone silent past the TTL (measured from
    /// the last peer activity, never from our own pokes) — so a payload to a peer
    /// that will never ack is eventually abandoned, and the cache stays bounded.
    fn prune_outbound(&mut self, now: i64) {
        let ttl = self.config.cache_ttl_secs;
        let stale: Vec<(Endpoint, [u8; 32])> = self
            .outbound
            .iter()
            .filter(|(_, c)| now.saturating_sub(c.last_activity_at) > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for key in stale {
            self.outbound.remove(&key);
            self.pending
                .retain(|(ep, pid, _)| !(ep == &key.0 && *pid == key.1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcbor::CBOR;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::address::Address;
    use rrn_protocol::bundle::{Bundle, EntryEnvelope};
    use rrn_protocol::outbox::OutboxEntry;
    use rrn_protocol::transport::mock::{FaultConfig, FaultTransport, LoopbackNet};

    #[derive(Clone)]
    struct Rec {
        n: u64,
    }
    impl From<Rec> for CBOR {
        fn from(r: Rec) -> Self {
            let mut m = dcbor::Map::new();
            m.insert("kind", "rrn.test.record");
            m.insert("n", r.n);
            m.into()
        }
    }

    /// A real signed bundle of `len` chained entries, tagged distinct by `salt`.
    fn bundle(len: u64, salt: u64) -> Bundle {
        let device = Keypair::generate();
        let author = Address::from_public_key(device.public_key());
        let mut prev = rrn_crypto::hash::Hash::from_bytes([0u8; 32]);
        let mut envs = Vec::new();
        for pos in 0..len {
            let rec = SignedPayload::sign(
                Rec {
                    n: pos + salt * 1000,
                },
                &device,
            );
            let entry = OutboxEntry::wrapping(author, pos, prev, &rec, 1_700_000_000 + pos as i64);
            prev = entry.entry_hash();
            envs.push(EntryEnvelope::from_signed(&SignedPayload::sign(
                entry, &device,
            )));
        }
        Bundle::new(envs, 1_700_000_000 + salt as i64)
    }

    /// Two syncers on one lossy net, and the endpoints addressing each other.
    fn pair(
        max_frame_bytes: usize,
        budget: AirtimeBudget,
        drop_prob: f64,
        now: i64,
    ) -> (
        DtnSyncer<FaultTransport<rrn_protocol::transport::mock::LoopbackTransport>>,
        DtnSyncer<FaultTransport<rrn_protocol::transport::mock::LoopbackTransport>>,
        Endpoint,
        Endpoint,
    ) {
        let net = LoopbackNet::new(max_frame_bytes);
        let fault = FaultConfig {
            drop_prob,
            dup_prob: 0.0,
            corrupt_prob: 0.0,
            reorder_window: 0,
            seed: 0xD7A1_7357,
        };
        let cfg = SyncConfig {
            resend_interval_secs: 20,
            ..SyncConfig::default()
        };
        let a = DtnSyncer::new(
            FaultTransport::new(net.endpoint("a"), fault),
            budget,
            cfg,
            now,
        );
        let b = DtnSyncer::new(
            FaultTransport::new(net.endpoint("b"), fault),
            budget,
            cfg,
            now,
        );
        (a, b, Endpoint::new("a"), Endpoint::new("b"))
    }

    #[test]
    fn signed_bundles_survive_a_lossy_constrained_channel_economic_first() {
        // ~120-byte frames, 2 B/s sustained (the design's punishing LoRa figure),
        // 10% loss. Small bundles so the run converges in simulated minutes.
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 2.0,
            burst_bytes: 300,
        };
        let (mut a, mut b, _ep_a, ep_b) = pair(120, budget, 0.10, 0);

        let econ = bundle(2, 1);
        let bulk = bundle(2, 2);
        let econ_bytes = econ.encode();
        let bulk_bytes = bulk.encode();

        // A sends both; the economic one is paced ahead of the bulk one regardless
        // of the order enqueued (bulk first, to prove priority beats arrival).
        assert!(a.send(&ep_b, PayloadKind::Bundle, &bulk_bytes, Priority::Bulk, 0));
        assert!(a.send(
            &ep_b,
            PayloadKind::Bundle,
            &econ_bytes,
            Priority::Economic,
            0
        ));

        let mut b_completed_order: Vec<Vec<u8>> = Vec::new();
        let mut a_receipts: Vec<Vec<u8>> = Vec::new();

        // Drive simulated time, one tick per second.
        for now in 1..=8000 {
            // A pumps/receives; any receipts it gets are recorded.
            for c in a.tick(now).unwrap() {
                if c.kind == PayloadKind::Receipt {
                    a_receipts.push(c.bytes);
                }
            }
            // B pumps/receives; a completed bundle is "ingested" into a tiny
            // receipt (blake3 of the bundle bytes) and sent back economic-priority.
            for c in b.tick(now).unwrap() {
                if c.kind == PayloadKind::Bundle {
                    b_completed_order.push(c.bytes.clone());
                    let receipt = rrn_crypto::hash::Hash::of(&c.bytes).to_bytes().to_vec();
                    b.send(
                        &c.source,
                        PayloadKind::Receipt,
                        &receipt,
                        Priority::Economic,
                        now,
                    );
                }
            }
            if b_completed_order.len() == 2 && a_receipts.len() == 2 {
                break;
            }
        }

        // Both bundles arrived, byte-identical, and re-decode as the same bundles.
        assert_eq!(
            b_completed_order.len(),
            2,
            "both bundles must complete in time"
        );
        assert!(b_completed_order.contains(&econ_bytes));
        assert!(b_completed_order.contains(&bulk_bytes));
        for got in &b_completed_order {
            Bundle::decode(got).expect("received bytes decode as a Bundle");
        }
        // Economic before bulk, despite bulk being enqueued first.
        assert_eq!(
            b_completed_order[0], econ_bytes,
            "the economic bundle must complete before the bulk one"
        );
        // Both receipts made the return trip.
        assert_eq!(a_receipts.len(), 2, "both delivery receipts must return");
        assert!(a_receipts.contains(&rrn_crypto::hash::Hash::of(&econ_bytes).to_bytes().to_vec()));
        assert!(a_receipts.contains(&rrn_crypto::hash::Hash::of(&bulk_bytes).to_bytes().to_vec()));
    }

    #[test]
    fn converges_and_releases_caches_under_heavy_loss() {
        // 50% loss stresses every reliability path: retransmit, the sender poke
        // (lost first chunk), and re-ack (lost ack). Both sides must complete AND
        // free their caches (a lost ack must not wedge the sender forever).
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 5.0,
            burst_bytes: 400,
        };
        let (mut a, mut b, _ep_a, ep_b) = pair(120, budget, 0.50, 0);
        let payload = bundle(2, 7).encode();
        assert!(a.send(&ep_b, PayloadKind::Bundle, &payload, Priority::Economic, 0));

        let mut got = None;
        let mut a_acked = false;
        for now in 1..=20000 {
            for c in a.tick(now).unwrap() {
                let _ = c;
            }
            for c in b.tick(now).unwrap() {
                if c.kind == PayloadKind::Bundle {
                    got = Some(c.bytes.clone());
                }
            }
            // Success = delivered, and A's cache released by B's ack (even across
            // lost acks, which the re-ack path recovers).
            if got.is_some() && a.outbound_cached() == 0 {
                a_acked = true;
                break;
            }
        }
        assert_eq!(
            got.as_deref(),
            Some(payload.as_slice()),
            "delivered under 50% loss"
        );
        assert!(
            a_acked,
            "sender cache released after ack (re-ack recovers a lost ack)"
        );
        assert_eq!(
            b.inbound_inflight(),
            0,
            "receiver stops tracking a completed payload"
        );
    }

    #[test]
    fn a_cache_to_a_gone_peer_is_abandoned_after_ttl() {
        // A sends to a peer that never responds; the cache must not poke forever —
        // it is pruned once the TTL elapses since the last (nonexistent) activity.
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 100.0,
            burst_bytes: 500,
        };
        let net = LoopbackNet::new(200);
        let cfg = SyncConfig {
            resend_interval_secs: 5,
            cache_ttl_secs: 100,
            ..SyncConfig::default()
        };
        let mut a = DtnSyncer::new(
            FaultTransport::new(net.endpoint("a"), FaultConfig::none(1)),
            budget,
            cfg,
            0,
        );
        assert!(a.send(
            &Endpoint::new("gone"),
            PayloadKind::Bundle,
            b"hello",
            Priority::Bulk,
            0
        ));
        assert_eq!(a.outbound_cached(), 1);
        // Tick well past the TTL; no peer ever acks or requests.
        for now in 1..=200 {
            a.tick(now).unwrap();
        }
        assert_eq!(
            a.outbound_cached(),
            0,
            "cache to a gone peer is abandoned after TTL"
        );
    }

    #[test]
    fn control_frame_roundtrips() {
        let req = ControlFrame::RequestMissing {
            payload_id: [7u8; 32],
            missing: vec![0, 3, 9, 65535],
        };
        assert_eq!(ControlFrame::decode(&req.encode()), Some(req));
        let ack = ControlFrame::Ack {
            payload_id: [9u8; 32],
        };
        assert_eq!(ControlFrame::decode(&ack.encode()), Some(ack));
        // Not a control frame: the framing magic, and junk.
        assert_eq!(ControlFrame::decode(b"RRNF...."), None);
        assert_eq!(ControlFrame::decode(b"x"), None);
    }

    #[test]
    fn payload_kind_tags() {
        for k in [PayloadKind::Bundle, PayloadKind::Receipt] {
            assert_eq!(PayloadKind::from_tag(k.tag()), Some(k));
        }
        assert_eq!(PayloadKind::from_tag(0xFF), None);
    }
}
