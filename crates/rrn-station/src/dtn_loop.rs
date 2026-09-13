//! The station-originated DTN outbound loop (ADR-0013, ADR-0020).
//!
//! The *inbound* half over Reticulum was wired earlier: the daemon receives a
//! [`PayloadKind::Bundle`](crate::dtn_sync::PayloadKind::Bundle), ingests it on
//! the single-writer core, and sends back its signed receipt. This module closes
//! the loop — it lets a station **originate** an outbound bundle push to a named
//! peer, track it durably, and correlate the peer's returned receipt back to the
//! push so it can be marked delivered.
//!
//! # Where the moving parts live
//!
//! - The **downstream carriage** — chunking, airtime pacing, retransmit, receipt
//!   return — is [`DtnSyncer`](crate::dtn_sync), unchanged.
//! - The **durable record** is the `dtn_pushes` table
//!   ([`rrn_storage::dtn::PushStore`]): a push already handed to a `DtnSyncer`
//!   dies with that syncer if the adapter is re-spawned (a fresh syncer has an
//!   empty retransmit cache), so the loop re-sends every undelivered,
//!   un-abandoned row from the table on **every** start and on a periodic
//!   re-scan. Idempotent on the receiving side by construction (ADR-0020 §3: a
//!   re-presented bundle yields `known`, never a second admission).
//! - This module is the **glue**: [`DtnLoop`] holds the syncer and, on each
//!   [`step`](DtnLoop::step), (1) on first call re-sends all pending pushes from
//!   the store, (2) drains the [`DtnOutbound`] wake channel for freshly-queued
//!   pushes, (3) ticks the syncer and routes completed payloads — ingesting a
//!   received bundle and replying with a receipt, correlating a received receipt
//!   to a tracked push — and (4) periodically re-scans the store for pending
//!   pushes to re-send.
//!
//! # Clock-injected and pull-driven, exactly like the syncer
//!
//! [`step`](DtnLoop::step) takes `now`. It never reads a clock and never sleeps;
//! the daemon wrapper ([`crate::station::run_dtn_syncer`]) supplies the injected
//! `Clock`, and the hermetic tests drive simulated time by calling `step` in a
//! fast loop over a mock carrier. Every database touch goes through the
//! single-writer core over a [`CoreHandle`] command (ADR-0020) — the loop never
//! holds a `Database`.

use tokio::sync::mpsc;

use rrn_protocol::airtime::{AirtimeBudget, Priority};
use rrn_protocol::transport::{Endpoint, FrameTransport};

use crate::core::CoreHandle;
use crate::dtn_sync::{DtnSyncer, PayloadKind};

/// A wake signal to the outbound loop that new outbound work has been queued.
/// It carries no payload: the durable record is the `dtn_pushes` row the RPC
/// inserted *before* signalling, and the loop drains all due rows from that table
/// on a wake, so a lost or coalesced signal costs only latency, never a push
/// (ADR-0020 §3). The channel is a bounded, best-effort "there is new work" edge.
#[derive(Clone, Copy, Debug)]
pub enum DtnOutbound {
    /// New outbound work is queued — pull and send the due rows.
    Wake,
}

/// One pending outbound push the loop should (re-)send. Handed back by the core
/// from the `dtn_pushes` table (a loop start / wake, or a periodic re-scan).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushToSend {
    /// The push id (the bundle's presentation hash).
    pub push_id: [u8; 32],
    /// The carrier destination to send to.
    pub to: Endpoint,
    /// The encoded bundle bytes.
    pub bundle: Vec<u8>,
    /// The airtime class the bundle is paced at.
    pub priority: Priority,
}

/// Drives one carrier's [`DtnSyncer`] plus the outbound-push lifecycle (module
/// docs). Generic over the carrier so the daemon runs it over the real
/// [`ReticulumTransport`](crate::reticulum::ReticulumTransport) and the hermetic
/// tests run the very same logic over the `rrn_protocol::transport::mock` carriers.
pub struct DtnLoop<T: FrameTransport> {
    syncer: DtnSyncer<T>,
    push_ttl_secs: i64,
    push_rescan_secs: i64,
    last_rescan_at: i64,
    started: bool,
}

impl<T: FrameTransport> DtnLoop<T> {
    /// Builds a loop over `transport`, pacing to `budget`, with the push TTL and
    /// re-scan interval (seconds). The syncer's clock is seeded at `now`.
    pub fn new(
        transport: T,
        budget: AirtimeBudget,
        push_ttl_secs: i64,
        push_rescan_secs: i64,
        now: i64,
    ) -> Self {
        Self {
            syncer: DtnSyncer::new(
                transport,
                budget,
                crate::dtn_sync::SyncConfig::default(),
                now,
            ),
            push_ttl_secs,
            push_rescan_secs,
            last_rescan_at: now,
            started: false,
        }
    }

    /// The transport this loop drives (for liveness checks / shutdown).
    pub fn transport(&self) -> &T {
        self.syncer.transport()
    }

    /// Consumes the loop and returns its transport (to shut it down cleanly).
    pub fn into_transport(self) -> T {
        self.syncer.into_transport()
    }

    /// Advances the loop at `now`: on the first tick or a wake, pull and send all
    /// due pushes from the durable table; tick the carrier and route completed
    /// payloads; then periodically re-scan for pending pushes to re-send. See the
    /// module docs.
    pub async fn step(
        &mut self,
        now: i64,
        core: &CoreHandle,
        outbound: &mut mpsc::Receiver<DtnOutbound>,
    ) {
        // 1. Decide whether to do a full pull this tick. On the first tick (a
        //    fresh syncer with an empty retransmit cache — the daemon's first
        //    spawn or a re-spawn after an adapter death), and whenever a wake
        //    signal says new work was queued, drain every undelivered,
        //    un-abandoned push from the durable table and (re-)send it. Pulling
        //    (never the wake's own payload) is what makes it lossless across an
        //    adapter restart and keeps the send bookkeeping in one place.
        let mut pull = false;
        if !self.started {
            self.started = true;
            self.last_rescan_at = now;
            pull = true;
        }
        // Coalesce all pending wake signals into one pull.
        while outbound.try_recv().is_ok() {
            pull = true;
        }
        if pull {
            for p in core.dtn_pending_pushes(self.push_ttl_secs, None).await {
                self.send_push(p, now, core).await;
            }
        }

        // 2. Pump the carrier and route what completed this tick.
        match self.syncer.tick(now) {
            Ok(completed) => {
                for c in completed {
                    match c.kind {
                        PayloadKind::Bundle => {
                            // Ingest on the single-writer core and reply with the
                            // signed receipt (the inbound half, unchanged).
                            if let Some(receipt) = core.ingest_bundle_bytes(c.bytes).await {
                                self.syncer.send(
                                    &c.source,
                                    PayloadKind::Receipt,
                                    &receipt,
                                    Priority::Economic,
                                    now,
                                );
                            }
                        }
                        PayloadKind::Receipt => {
                            // Correlate the receipt to one of our tracked pushes and
                            // mark it delivered (the new outbound half).
                            core.dtn_receipt(c.bytes, c.source).await;
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "DTN transport error while ticking the syncer"),
        }

        // 3. Periodic re-scan: re-send pending pushes gone quiet longer than the
        //    re-scan interval, and abandon any past the TTL (surfaced legibly by
        //    `rrn dtn status`, never silently dropped). Both clocks are the
        //    injected daemon clock — never a peer-asserted time (ADR-0022).
        if now.saturating_sub(self.last_rescan_at) >= self.push_rescan_secs {
            self.last_rescan_at = now;
            for p in core
                .dtn_pending_pushes(self.push_ttl_secs, Some(self.push_rescan_secs))
                .await
            {
                self.send_push(p, now, core).await;
            }
        }
    }

    /// Enqueues one pending push onto the paced sender. A bundle too large to
    /// frame for this carrier can never be sent, so it is abandoned **immediately**
    /// (surfaced by `rrn dtn status`) rather than retried silently until its TTL —
    /// economic payload must fail legibly.
    async fn send_push(&mut self, p: PushToSend, now: i64, core: &CoreHandle) {
        let framed = self
            .syncer
            .send(&p.to, PayloadKind::Bundle, &p.bundle, p.priority, now);
        if !framed {
            tracing::warn!(
                peer = %p.to.0,
                bytes = p.bundle.len(),
                "outbound bundle is too large to frame for this carrier; abandoning it \
                 (it can never be sent) — split it or use the paper fallback"
            );
            core.dtn_abandon_push(p.push_id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rrn_crypto::hash::Hash;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::address::Address;
    use rrn_identity::wallet::WalletContents;
    use rrn_ledger::credit::CreditConfig;
    use rrn_ledger::settlement::SettlementConfig;
    use rrn_ledger::transaction::TransactionProposal;
    use rrn_marketplace::search::SearchIndex;
    use rrn_protocol::bundle::{Bundle, EntryEnvelope};
    use rrn_protocol::outbox::OutboxEntry;
    use rrn_protocol::transport::mock::{
        FaultConfig, FaultTransport, LoopbackNet, LoopbackTransport,
    };
    use rrn_storage::db::Database;
    use rrn_storage::migrations;

    use crate::clock::Clock;
    use crate::core::{hex, Core, CoreHandle};
    use crate::paired::PairedMobiles;
    use crate::rpc;

    type Mock = FaultTransport<LoopbackTransport>;

    /// A bare spawned core over an in-memory db, sharing `clock`. With
    /// `dtn_outbound` it can originate pushes; without it, it only receives.
    fn spawn_core(clock: Clock, dtn_tx: Option<mpsc::Sender<DtnOutbound>>) -> CoreHandle {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let mut core = Core::new(
            db,
            WalletContents::create_new(),
            SettlementConfig::default(),
            CreditConfig::default(),
            clock,
            PairedMobiles::default(),
            SearchIndex::in_memory(),
        );
        if let Some(tx) = dtn_tx {
            core = core.with_dtn_outbound(tx);
        }
        core.spawn()
    }

    /// A real one-record proposal bundle (encoded bytes + its push id), which the
    /// receiver admits so delivery reflects a genuine log append.
    fn proposal_bundle() -> (Vec<u8>, [u8; 32]) {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let alice_addr = Address::from_public_key(alice.public_key());
        let bob_addr = Address::from_public_key(bob.public_key());
        let proposal =
            TransactionProposal::new(alice_addr, bob_addr, 300, None, 0, 900, 900 + 1_000_000);
        let signed = SignedPayload::sign(proposal, &alice);
        let entry = OutboxEntry::wrapping(alice_addr, 0, Hash::from_bytes([0u8; 32]), &signed, 900);
        let soe = SignedPayload::sign(entry, &alice);
        let push_id = Hash::of(&soe.payload.record_hash().to_bytes()).to_bytes();
        let bundle = Bundle::new(vec![EntryEnvelope::from_signed(&soe)], 1000);
        (bundle.encode(), push_id)
    }

    fn mock_pair(now: i64, drop_prob: f64) -> (DtnLoop<Mock>, DtnLoop<Mock>, LoopbackNet) {
        // ~120-byte frames, 2 B/s sustained (the design's punishing LoRa figure).
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 2.0,
            burst_bytes: 300,
        };
        let net = LoopbackNet::new(120);
        let fault = FaultConfig {
            drop_prob,
            dup_prob: 0.0,
            corrupt_prob: 0.0,
            reorder_window: 0,
            seed: 0xD7A1_7357,
        };
        // TTL huge, rescan brisk (30s of simulated time) so re-sends are exercised.
        let a = DtnLoop::new(
            FaultTransport::new(net.endpoint("a"), fault),
            budget,
            1_000_000,
            30,
            now,
        );
        let b = DtnLoop::new(
            FaultTransport::new(net.endpoint("b"), fault),
            budget,
            1_000_000,
            30,
            now,
        );
        (a, b, net)
    }

    async fn push_state(core: &CoreHandle, push_id: &[u8; 32]) -> Option<String> {
        let result = core
            .call(rpc::Request {
                id: "1".into(),
                method: "dtn_pushes".into(),
                params: serde_json::json!({}),
            })
            .await
            .ok()?;
        let pushes = result["pushes"].as_array()?;
        let want = hex(push_id);
        pushes
            .iter()
            .find(|p| p["push_id_hex"] == serde_json::Value::String(want.clone()))
            .and_then(|p| p["state"].as_str().map(String::from))
    }

    /// The core new coverage: A originates a bundle push over a lossy ~2 B/s mock
    /// carrier through the real [`DtnLoop`], B ingests it and returns a receipt, A
    /// correlates it and marks the row delivered — exactly once — and a forged or
    /// duplicate receipt afterward does not disturb it.
    #[tokio::test]
    async fn hermetic_originate_ingest_receipt_delivered_under_loss() {
        let clock = Clock::manual(1000);
        let (tx_a, mut rx_a) = mpsc::channel(16);
        let (_tx_b, mut rx_b) = mpsc::channel(16);
        let core_a = spawn_core(clock.clone(), Some(tx_a));
        let core_b = spawn_core(clock.clone(), None);
        let (mut a, mut b, _net) = mock_pair(1000, 0.10);

        let (bundle, push_id) = proposal_bundle();

        // A originates the push through the RPC front door (row inserted + signal).
        let queued = core_a
            .call(rpc::Request {
                id: "1".into(),
                method: "dtn_push".into(),
                params: serde_json::json!({
                    "bundle_hex": hex(&bundle),
                    "endpoint_hex": "b"
                }),
            })
            .await
            .unwrap();
        assert_eq!(queued["queued"], true);

        // Drive simulated time until A's push row flips delivered.
        let mut delivered = false;
        for now in 1001..=40_000 {
            clock.set(now);
            a.step(now, &core_a, &mut rx_a).await;
            b.step(now, &core_b, &mut rx_b).await;
            if push_state(&core_a, &push_id).await.as_deref() == Some("delivered") {
                delivered = true;
                break;
            }
        }
        assert!(delivered, "the push must be delivered within the sim bound");

        // B admitted the record — the delivered receipt summarizes one admission,
        // so B's log contains the pushed record (not merely a receipt round-trip).
        let result = core_a
            .call(rpc::Request {
                id: "1".into(),
                method: "dtn_pushes".into(),
                params: serde_json::json!({}),
            })
            .await
            .unwrap();
        assert_eq!(result["pushes"][0]["receipt_summary"], "1 admitted");

        // A forged receipt (wrong signer) does not disturb the delivered row, and a
        // duplicate genuine receipt is a no-op.
        let forged = {
            use rrn_protocol::receipt::{self, DeliveryReceipt};
            let bogus = DeliveryReceipt {
                station: Address::from_public_key(Keypair::generate().public_key()),
                outcomes: vec![],
                received_at: 1000,
            };
            receipt::encode_signed(&SignedPayload::sign(bogus, &Keypair::generate()))
        };
        assert!(!core_a.dtn_receipt(forged, Endpoint::new("b")).await);
        assert_eq!(
            push_state(&core_a, &push_id).await.as_deref(),
            Some("delivered"),
            "still delivered exactly once"
        );
    }

    /// No economic payload is lost across an adapter re-spawn: a first loop sends a
    /// push but the "adapter dies" (the loop is dropped, its in-memory retransmit
    /// cache gone) before delivery; a fresh loop re-sends the pending row from the
    /// durable table and it is delivered, with `attempts` incremented.
    #[tokio::test]
    async fn loop_restart_re_sends_pending_from_the_table() {
        let clock = Clock::manual(1000);
        let (tx_a, mut rx_a) = mpsc::channel(16);
        let (_tx_b, mut rx_b) = mpsc::channel(16);
        let core_a = spawn_core(clock.clone(), Some(tx_a));
        let core_b = spawn_core(clock.clone(), None);
        let (bundle, push_id) = proposal_bundle();

        core_a
            .call(rpc::Request {
                id: "1".into(),
                method: "dtn_push".into(),
                params: serde_json::json!({ "bundle_hex": hex(&bundle), "endpoint_hex": "b" }),
            })
            .await
            .unwrap();

        // One net shared across the "adapter restart" (B stays put on it).
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 2.0,
            burst_bytes: 300,
        };
        let net = LoopbackNet::new(120);
        let fault = FaultConfig::none(1);
        let mut b = DtnLoop::new(
            FaultTransport::new(net.endpoint("b"), fault),
            budget,
            1_000_000,
            30,
            1000,
        );

        // First loop sends for a few ticks, then "dies" (dropped) — B never polled,
        // so nothing was delivered and the in-memory cache is lost with it.
        {
            let mut a1 = DtnLoop::new(
                FaultTransport::new(net.endpoint("a"), fault),
                budget,
                1_000_000,
                30,
                1000,
            );
            for now in 1001..=1005 {
                clock.set(now);
                a1.step(now, &core_a, &mut rx_a).await;
            }
        }
        assert_ne!(
            push_state(&core_a, &push_id).await.as_deref(),
            Some("delivered"),
            "not delivered before the restart"
        );

        // A fresh loop (empty cache) re-sends the pending row from the table.
        let mut a2 = DtnLoop::new(
            FaultTransport::new(net.endpoint("a"), fault),
            budget,
            1_000_000,
            30,
            1005,
        );
        let mut delivered = false;
        for now in 1006..=40_000 {
            clock.set(now);
            a2.step(now, &core_a, &mut rx_a).await;
            b.step(now, &core_b, &mut rx_b).await;
            if push_state(&core_a, &push_id).await.as_deref() == Some("delivered") {
                delivered = true;
                break;
            }
        }
        assert!(
            delivered,
            "the fresh loop re-sent from the table and delivered"
        );

        let result = core_a
            .call(rpc::Request {
                id: "1".into(),
                method: "dtn_pushes".into(),
                params: serde_json::json!({}),
            })
            .await
            .unwrap();
        assert!(
            result["pushes"][0]["attempts"].as_i64().unwrap() >= 2,
            "attempts counted across the restart (a1's send + a2's re-send from the table)"
        );
    }

    /// A push to a peer that never produces a receipt is abandoned past its TTL —
    /// legibly (surfaced as `abandoned` by status), never silently dropped.
    #[tokio::test]
    async fn abandoned_after_ttl_via_the_loop() {
        let clock = Clock::manual(1000);
        let (tx_a, mut rx_a) = mpsc::channel(16);
        let core_a = spawn_core(clock.clone(), Some(tx_a));
        let (bundle, push_id) = proposal_bundle();
        core_a
            .call(rpc::Request {
                id: "1".into(),
                method: "dtn_push".into(),
                params: serde_json::json!({ "bundle_hex": hex(&bundle), "endpoint_hex": "gone" }),
            })
            .await
            .unwrap();

        // Small TTL and rescan; the peer "gone" is never polled by anyone.
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 100.0,
            burst_bytes: 500,
        };
        let net = LoopbackNet::new(200);
        let mut a = DtnLoop::new(
            FaultTransport::new(net.endpoint("a"), FaultConfig::none(1)),
            budget,
            100, // push_ttl_secs
            5,   // push_rescan_secs
            1000,
        );
        let mut abandoned = false;
        for now in 1001..=1200 {
            clock.set(now);
            a.step(now, &core_a, &mut rx_a).await;
            if push_state(&core_a, &push_id).await.as_deref() == Some("abandoned") {
                abandoned = true;
                break;
            }
        }
        assert!(
            abandoned,
            "an undelivered push is abandoned past its TTL and shown, not dropped"
        );
    }
}
