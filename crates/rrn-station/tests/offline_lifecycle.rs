//! The T2.4.1 offline exit test: a single `station` daemon, bound to loopback
//! only, with a configured but **unreachable** black-hole peer, drives a full
//! economic lifecycle — a plain payment and a cert-backed *offline* spend
//! delivered by DTN — with zero reachable connectivity, and shuts down cleanly.
//!
//! Member model (see the T2.4.1 PR): the station **operator** is member A and the
//! sole certificate holder (issuance is a live operator round-trip — a DTN cert
//! request is refused `UnroutableKind`). A second test keypair is member **B**,
//! whose confirmations reach the station **only** through `bundle_submit` — the
//! real courier path (ADR-0020 §3). The cert-backed offline spend is the
//! operator's own, signed in-test with the station keypair recovered from the
//! wallet file, and delivered in a bundle alongside B's confirmation.
//!
//! The whole body runs under a 55s timeout: bounded-timeout gossip against the
//! black hole (T2.4.1's `PEER_DIAL_TIMEOUT`) is exactly what keeps this — and the
//! daemon's own shutdown — from parking on the OS TCP SYN timeout.

use std::path::Path;
use std::time::Duration;

use rrn_station::core::{hex, unhex};
use rrn_station::rpc::{
    BalanceResult, CertListResult, CertRequestResult, ProposeResult, StatusResult, WhoamiResult,
};
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams, DB_FILE, WALLET_FILE};
use rrn_station::Clock;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::escrow::CertId;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};
use rrn_protocol::receipt::{self, Disposition, SignedReceipt};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

const PASSPHRASE: &str = "offline-passphrase";
const START: i64 = 1_000_000;
const WINDOW: u64 = 5;
/// RFC 5737-adjacent address the host routes to its default gateway and never
/// answers — a true black hole (a bounded connect timeout, not the OS SYN
/// timeout, is what keeps the round and shutdown prompt).
const BLACK_HOLE: &str = "10.255.255.1:7411";

/// Writes a config with an unreachable peer, mDNS advertising ON (per the ticket),
/// loopback-only binds on ephemeral ports, and fast windows/timers.
fn write_config(dir: &Path) {
    let text = format!(
        "[peers]\n\
         list = [\"{BLACK_HOLE}\"]\n\n\
         [network]\n\
         listen = \"127.0.0.1:0\"\n\n\
         [mobile]\n\
         advertise = true\n\
         listen = \"127.0.0.1:0\"\n\n\
         [settlement]\n\
         window_seconds = {WINDOW}\n\n\
         [timers]\n\
         sweep_interval_secs = 1\n\
         gossip_interval_secs = 1\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

fn addr(k: &Keypair) -> Address {
    Address::from_public_key(k.public_key())
}

async fn balance(client: &UnixClient, address: &str) -> i64 {
    let v = client
        .call("balance", serde_json::json!({ "address": address }))
        .await
        .unwrap();
    serde_json::from_value::<BalanceResult>(v)
        .unwrap()
        .balance_centi
}

/// Wraps an already-signed record as a signed outbox entry authored by `device`.
fn outbox_entry<T: Clone + Into<dcbor::CBOR>>(
    device: &Keypair,
    position: u64,
    prev: Hash,
    record: &SignedPayload<T>,
    authored_at: i64,
) -> SignedOutboxEntry {
    let entry = OutboxEntry::wrapping(addr(device), position, prev, record, authored_at);
    SignedPayload::sign(entry, device)
}

/// Submits a DTN bundle through the operator `bundle_submit` RPC and returns the
/// decoded, signature-verified station receipt.
async fn submit_bundle(
    client: &UnixClient,
    entries: &[SignedOutboxEntry],
    assembled_at: i64,
) -> SignedReceipt {
    let envs: Vec<EntryEnvelope> = entries.iter().map(EntryEnvelope::from_signed).collect();
    let bundle_hex = hex(&Bundle::new(envs, assembled_at).encode());
    let v = client
        .call(
            "bundle_submit",
            serde_json::json!({ "bundle_hex": bundle_hex }),
        )
        .await
        .unwrap();
    let receipt_hex = v["receipt_hex"].as_str().unwrap();
    let signed = receipt::decode_signed(&unhex(receipt_hex).unwrap()).unwrap();
    assert!(signed.verify().is_ok(), "station receipt must verify");
    signed
}

fn verify_chain(db_path: &Path) -> u64 {
    let db = Database::open(db_path).unwrap();
    AppendLog::new(&db).verify_chain().unwrap()
}

/// Polls `check` every 100ms until it is true or `timeout` elapses.
async fn poll_until<F, Fut>(timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "poll_until timed out"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_full_lifecycle_with_black_hole_peer() {
    tokio::time::timeout(Duration::from_secs(55), run())
        .await
        .expect("offline lifecycle must finish well under the OS SYN timeout");
}

async fn run() {
    let dir = tempfile::tempdir().unwrap();
    let a = Station::init(dir.path(), PASSPHRASE).unwrap().to_string();
    write_config(dir.path());

    let clock = Clock::manual(START);
    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let client = UnixClient::new(station.socket_path());

    // Recover the operator keypair from the wallet file — the offline cert-backed
    // spend is signed with it in-test (there is no external-signing RPC).
    let wallet = WalletContents::load_from_file(&dir.path().join(WALLET_FILE), PASSPHRASE).unwrap();
    let operator = Keypair::from_secret(wallet.secret_key.clone());
    let a_addr = addr(&operator);
    let b = Keypair::generate();
    let b_addr = addr(&b);

    // Ready despite the unreachable peer: whoami answers immediately.
    let who: WhoamiResult =
        serde_json::from_value(client.call("whoami", serde_json::json!({})).await.unwrap())
            .unwrap();
    assert_eq!(who.address, a);

    // status reports the black-hole peer, the bound mobile listener, and empty DTN
    // queues — degradation is legible.
    let st: StatusResult =
        serde_json::from_value(client.call("status", serde_json::json!({})).await.unwrap())
            .unwrap();
    assert_eq!(st.connectivity.peers.len(), 1);
    assert_eq!(st.connectivity.peers[0].address, BLACK_HOLE);
    assert!(!st.connectivity.peers[0].reachable);
    assert!(st.connectivity.mobile_advertising);
    assert!(
        st.connectivity.mobile_listener_bound,
        "the mobile listener binds on loopback even with no route out"
    );
    assert_eq!(st.connectivity.pending_outbox, 0);
    assert_eq!(st.connectivity.pending_receipts, 0);

    // A real gossip round against the black hole completes under the dial bound and
    // is recorded — proving the timeout fix end-to-end (not just the default state):
    // `last_attempt_at` becomes set while `reachable` stays false.
    poll_until(Duration::from_secs(10), || async {
        let st: StatusResult =
            serde_json::from_value(client.call("status", serde_json::json!({})).await.unwrap())
                .unwrap();
        st.connectivity.peers[0].last_attempt_at.is_some()
    })
    .await;
    let st: StatusResult =
        serde_json::from_value(client.call("status", serde_json::json!({})).await.unwrap())
            .unwrap();
    assert!(
        !st.connectivity.peers[0].reachable && st.connectivity.peers[0].last_success_at.is_none(),
        "the black-hole peer is attempted but never reachable"
    );

    // --- Phase 1: a plain payment, B's confirmation via DTN -----------------

    // A vouches for B (Phase-1 identity step; not engine-required to transact).
    client
        .call(
            "vouch",
            serde_json::json!({ "subject": b_addr.to_string(), "statement": "known good", "stake_centi": 0 }),
        )
        .await
        .unwrap();

    // A proposes 300 to B over the socket (operator nonce 0).
    let prop: ProposeResult = serde_json::from_value(
        client
            .call(
                "propose",
                serde_json::json!({ "receiver": b_addr.to_string(), "amount_centi": 300 }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let tx1 = TransactionId(Hash::from_hex(&prop.tx_id).unwrap());

    // B confirms it OFFLINE; the confirmation reaches the station only via DTN.
    let conf1 = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: tx1,
            confirmer: b_addr,
            confirmed_at: clock.now(),
        },
        &b,
    );
    let r = submit_bundle(
        &client,
        &[outbox_entry(
            &b,
            0,
            Hash::from_bytes([0u8; 32]),
            &conf1,
            clock.now(),
        )],
        clock.now(),
    )
    .await;
    assert!(matches!(
        r.payload.outcomes[0].disposition,
        Disposition::Admitted { .. }
    ));

    // The courier fetches B's-authored delivery receipt (no ack on the courier path).
    let fetched = client
        .call(
            "receipts_fetch",
            serde_json::json!({ "authors": [b_addr.to_string()] }),
        )
        .await
        .unwrap();
    assert_eq!(fetched["receipts_hex"].as_array().unwrap().len(), 1);
    assert_eq!(fetched["truncated"], false);

    // Settle after the window, measured from admission.
    clock.advance(WINDOW as i64 + 1);
    // Drop the count assertion: the 1s background sweep timer shares this clock
    // and may settle first (returning 0). The balance assertions below are the
    // deterministic proof (the explicit sweep guarantees settlement by return).
    station.sweep().await;
    assert_eq!(balance(&client, &a).await, -300);
    assert_eq!(balance(&client, &b_addr.to_string()).await, 300);

    // --- Phase 2: an offline cert-backed spend by the operator --------------

    // A issues itself a 500-cap certificate (operator nonce 1).
    let cert: CertRequestResult = serde_json::from_value(
        client
            .call("cert_request", serde_json::json!({ "cap_centi": 500 }))
            .await
            .unwrap(),
    )
    .unwrap();
    let cert_id = CertId(Hash::from_hex(&cert.cert_id).unwrap());

    // A signs a cert-backed 300 spend to B OFFLINE (operator nonce 2 — cert
    // requests share the proposal nonce sequence). `expires_at >= cert.expires_at`
    // per ADR-0021 §4.
    let spend = SignedProposal::sign(
        TransactionProposal::new(a_addr, b_addr, 300, None, 2, clock.now(), cert.expires_at)
            .with_certificate(cert_id),
        &operator,
    );
    let conf2 = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: spend.payload.id,
            confirmer: b_addr,
            confirmed_at: clock.now(),
        },
        &b,
    );
    // One bundle: the operator's spend (its own outbox pos 0) then B's confirmation
    // (its outbox pos 1, chained onto conf1).
    let entries = [
        outbox_entry(
            &operator,
            0,
            Hash::from_bytes([0u8; 32]),
            &spend,
            clock.now(),
        ),
        outbox_entry(
            &b,
            1,
            {
                // chain B's second entry onto its first
                let first = outbox_entry(&b, 0, Hash::from_bytes([0u8; 32]), &conf1, START);
                first.payload.entry_hash()
            },
            &conf2,
            clock.now(),
        ),
    ];
    let r = submit_bundle(&client, &entries, clock.now()).await;
    assert!(matches!(
        r.payload.outcomes[0].disposition,
        Disposition::Admitted { .. }
    ));
    assert!(matches!(
        r.payload.outcomes[1].disposition,
        Disposition::Admitted { .. }
    ));

    // The operator acks its own spend's delivery receipt (author path); idempotent.
    let spend_hash = hex(r.payload.outcomes[0].record_hash.to_bytes().as_slice());
    let acked = client
        .call(
            "receipts_ack",
            serde_json::json!({ "record_hashes": [spend_hash.clone()] }),
        )
        .await
        .unwrap();
    assert_eq!(acked["acked"], 1);
    let again = client
        .call(
            "receipts_ack",
            serde_json::json!({ "record_hashes": [spend_hash] }),
        )
        .await
        .unwrap();
    assert_eq!(again["acked"], 0);

    // The cert now shows 300 consumed / 200 remaining.
    let certs: CertListResult = serde_json::from_value(
        client
            .call("cert_list", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(certs.certificates.len(), 1);
    assert_eq!(certs.certificates[0].consumed_centi, 300);
    assert_eq!(certs.certificates[0].remaining_centi, 200);

    // The DTN activity moved the queue-depth counters off zero: B's confirmation
    // deliveries are still unconfirmed (a courier fetch never acks), so status now
    // reports pending receipts — the COUNT(*) helper reads real rows.
    let st: StatusResult =
        serde_json::from_value(client.call("status", serde_json::json!({})).await.unwrap())
            .unwrap();
    assert!(
        st.connectivity.pending_receipts >= 1,
        "unconfirmed courier receipts should be visible in status"
    );

    // Settle the spend.
    clock.advance(WINDOW as i64 + 1);
    station.sweep().await;
    assert_eq!(balance(&client, &a).await, -600);
    assert_eq!(balance(&client, &b_addr.to_string()).await, 600);

    // --- The chain is whole, and the daemon stops cleanly -------------------
    let db_path = dir.path().join(DB_FILE);
    assert!(
        verify_chain(&db_path) >= 9,
        "expected >=9 log entries (vouch, proposal, confirmation, settlement, cert request, \
         certificate, spend, confirmation, settlement)"
    );

    let socket = station.socket_path().to_path_buf();
    station.shutdown().await;
    assert!(
        !socket.exists(),
        "the Unix socket must be removed on clean shutdown"
    );
}
