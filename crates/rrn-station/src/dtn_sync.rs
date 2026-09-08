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

use rrn_protocol::airtime::{AirtimeBudget, Backpressure, PacedSender, Priority, QueueCaps};
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
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            resend_interval_secs: 30,
            cache_ttl_secs: 24 * 60 * 60,
            reassembler: ReassemblerConfig::default(),
            queue_caps: QueueCaps::default(),
        }
    }
}

/// A cached outbound payload's chunks, kept for retransmit until acked or TTL.
struct CachedSend {
    chunks: Vec<Vec<u8>>,
    priority: Priority,
    last_touched: i64,
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
    fn enqueue_chunk(
        &mut self,
        priority: Priority,
        to: &Endpoint,
        chunk: Vec<u8>,
    ) -> Result<bool, Backpressure> {
        let key = framing::frame_ids(&chunk).map(|(pid, idx)| (to.clone(), pid, idx));
        if let Some(ref k) = key {
            if self.pending.contains(k) {
                return Ok(false); // already in flight; don't double-queue
            }
        }
        self.sender.enqueue(priority, to.clone(), chunk)?;
        if let Some(k) = key {
            self.pending.insert(k);
        }
        Ok(true)
    }

    /// Queues a payload for `to`, chunked and paced at `priority`. The payload's
    /// chunks are cached for retransmit until the peer acks (or the TTL elapses).
    ///
    /// Returns [`Backpressure`] if the airtime queue for `priority` is full and
    /// the frame was refused (economic/governance) — the caller holds and retries.
    /// A bulk overflow silently drops its oldest instead, per the pacer.
    pub fn send(
        &mut self,
        to: &Endpoint,
        kind: PayloadKind,
        payload: &[u8],
        priority: Priority,
        now: i64,
    ) -> Result<(), Backpressure> {
        // Tag the payload so the receiver can route it, then chunk.
        let mut tagged = Vec::with_capacity(payload.len() + 1);
        tagged.push(kind.tag());
        tagged.extend_from_slice(payload);
        let chunks = match framing::chunk(&tagged, self.max_frame_bytes) {
            Ok(c) => c,
            // A payload that cannot be framed (too many chunks for the carrier) is
            // a caller error surfaced as backpressure rather than a panic.
            Err(_) => return Err(Backpressure { priority, depth: 0 }),
        };
        // payload_id is the framing chunk's payload id (same for every chunk).
        let payload_id = framing::payload_id(&tagged);

        // Enqueue every chunk (deduped); on backpressure, drop the cache entry and
        // report so the caller retries the whole payload.
        for chunk in &chunks {
            if let Err(bp) = self.enqueue_chunk(priority, to, chunk.clone()) {
                self.outbound.remove(&(to.clone(), payload_id));
                return Err(bp);
            }
        }
        self.outbound.insert(
            (to.clone(), payload_id),
            CachedSend {
                chunks,
                priority,
                last_touched: now,
            },
        );
        Ok(())
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
                    // Incomplete: remember the source so we can ask for the rest.
                    if let Some(pid) = framing::frame_payload_id(&frame) {
                        self.inbound.entry(pid).or_insert(InboundState {
                            source: from.clone(),
                            last_request_at: i64::MIN,
                        });
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

    /// Frames still queued in the pacer across all classes.
    pub fn queued(&self) -> usize {
        self.sender.queued()
    }

    /// In-flight inbound payloads not yet reassembled.
    pub fn inbound_inflight(&self) -> usize {
        self.inbound.len()
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
                // enqueue them deduped (mutable borrow).
                let resend: Option<(Priority, Vec<Vec<u8>>)> =
                    self.outbound.get_mut(&(from.clone(), payload_id)).map(|c| {
                        c.last_touched = now;
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
            // Ack so the sender can free its cache; economic-priority (tiny).
            let _ = self.sender.enqueue(
                Priority::Economic,
                from.clone(),
                ControlFrame::Ack { payload_id: pid }.encode(),
            );
        }
        let (tag, body) = tagged.split_first()?;
        let kind = PayloadKind::from_tag(*tag)?;
        Some(Completed {
            source: from.clone(),
            kind,
            bytes: body.to_vec(),
        })
    }

    fn request_missing(&mut self, now: i64) {
        // Collect the requests first (immutable borrow of the reassembler), then
        // enqueue (mutable borrow of the sender).
        let mut requests: Vec<(Endpoint, [u8; 32], Vec<u16>)> = Vec::new();
        for (pid, state) in self.inbound.iter_mut() {
            if now.saturating_sub(state.last_request_at) < self.config.resend_interval_secs {
                continue;
            }
            // Skip if a request for this payload is already queued-not-sent.
            if self
                .pending_requests
                .contains(&(state.source.clone(), *pid))
            {
                continue;
            }
            if let Some(missing) = self.reassembler.missing(pid) {
                if !missing.is_empty() {
                    state.last_request_at = now;
                    requests.push((state.source.clone(), *pid, missing));
                }
            }
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

    /// Re-enqueues the first chunk of every un-acked cached payload that has been
    /// quiet for `resend_interval_secs`, deduped. Bounded: at most one chunk per
    /// stuck payload per interval, and the peer's [`ControlFrame::Ack`] drops the
    /// cache the moment the payload lands.
    fn poke_unacked(&mut self, now: i64) {
        let interval = self.config.resend_interval_secs;
        let due: Vec<(Endpoint, [u8; 32])> = self
            .outbound
            .iter()
            .filter(|(_, c)| now.saturating_sub(c.last_touched) >= interval)
            .map(|(k, _)| k.clone())
            .collect();
        for key in due {
            let poke = self
                .outbound
                .get(&key)
                .and_then(|c| c.chunks.first().cloned().map(|ch| (c.priority, ch)));
            if let Some((priority, chunk)) = poke {
                let _ = self.enqueue_chunk(priority, &key.0, chunk);
            }
            if let Some(c) = self.outbound.get_mut(&key) {
                c.last_touched = now;
            }
        }
    }

    fn prune_outbound(&mut self, now: i64) {
        let ttl = self.config.cache_ttl_secs;
        self.outbound
            .retain(|_, c| now.saturating_sub(c.last_touched) <= ttl);
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
        a.send(&ep_b, PayloadKind::Bundle, &bulk_bytes, Priority::Bulk, 0)
            .unwrap();
        a.send(
            &ep_b,
            PayloadKind::Bundle,
            &econ_bytes,
            Priority::Economic,
            0,
        )
        .unwrap();

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
                    )
                    .unwrap();
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
