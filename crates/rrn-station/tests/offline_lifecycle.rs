//! The offline exit tests, in two parts (split under the single-writer model,
//! ADR-0020 §7: a writer never pulls, so a writer no longer carries a peer):
//!
//! 1. [`offline_full_lifecycle_on_a_peerless_writer`] — a single **writer**
//!    `station` daemon, bound to loopback only, with **no peers at all** (fully
//!    offline), drives a full economic lifecycle — a plain payment and a
//!    cert-backed *offline* spend delivered by DTN — and shuts down cleanly.
//! 2. [`a_replica_against_an_unreachable_writer_reports_it_and_shuts_down`] — a
//!    **replica** pointed at an unreachable **black-hole** writer proves the
//!    bounded-dial timeout fix: a real pull round completes under
//!    `PEER_DIAL_TIMEOUT` (`last_attempt_at` set, `reachable` false), the replica
//!    admits nothing, and the daemon stops promptly rather than parking on the OS
//!    SYN timeout. This is where the bounded-dial evidence lives now, because only
//!    a replica dials.
//!
//! Member model: the writer **operator** is member A and the
//! sole certificate holder (issuance is a live operator round-trip — a DTN cert
//! request is refused `UnroutableKind`). A second test keypair is member **B**,
//! whose confirmations reach the station **only** through `bundle_submit` — the
//! real courier path (ADR-0020 §3). The cert-backed offline spend is the
//! operator's own, signed in-test with the station keypair recovered from the
//! wallet file, and delivered in a bundle alongside B's confirmation.

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

/// Writes a **writer** config with no peers (a writer never pulls, ADR-0020 §1),
/// mDNS advertising ON (per the offline-hardening design), loopback-only binds on ephemeral
/// ports, and fast windows/timers.
fn write_config(dir: &Path) {
    let text = format!(
        "[network]\n\
         listen = \"127.0.0.1:0\"\n\
         role = \"writer\"\n\n\
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

/// Writes a **replica** config pointed at `peer` (the unreachable black-hole
/// writer), with a fast gossip loop so the bounded dial round runs promptly.
fn write_replica_config(dir: &Path, peer: &str) {
    let text = format!(
        "[peers]\n\
         list = [\"{peer}\"]\n\n\
         [network]\n\
         listen = \"127.0.0.1:0\"\n\
         role = \"replica\"\n\n\
         [mobile]\n\
         advertise = false\n\
         listen = \"127.0.0.1:0\"\n\n\
         [timers]\n\
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
async fn offline_full_lifecycle_on_a_peerless_writer() {
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

    // status reports a writer with no peers, the bound mobile listener, and empty
    // DTN queues — degradation is legible even fully offline. (The bounded-dial
    // evidence against an unreachable peer now lives in the replica test below,
    // because a writer never dials.)
    let st: StatusResult =
        serde_json::from_value(client.call("status", serde_json::json!({})).await.unwrap())
            .unwrap();
    assert_eq!(st.connectivity.role, "writer");
    assert!(
        st.connectivity.peers.is_empty(),
        "a writer never pulls, so it has no peers (ADR-0020 §1)"
    );
    assert!(st.connectivity.mobile_advertising);
    assert!(
        st.connectivity.mobile_listener_bound,
        "the mobile listener binds on loopback even with no route out"
    );
    assert_eq!(st.connectivity.pending_outbox, 0);
    assert_eq!(st.connectivity.pending_receipts, 0);

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

/// A read-replica pointed at an unreachable (black-hole) writer: the bounded-dial
/// reachability evidence now lives here, because only a replica pulls
/// (ADR-0020 §7). The replica attempts the writer, is bounded by
/// `PEER_DIAL_TIMEOUT` (never the OS SYN timeout), reports the peer as attempted
/// but never reachable, admits nothing, and shuts down promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replica_against_an_unreachable_writer_reports_it_and_shuts_down() {
    tokio::time::timeout(Duration::from_secs(40), replica_run())
        .await
        .expect("a replica against a black hole must finish under the OS SYN timeout");
}

async fn replica_run() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_replica_config(dir.path(), BLACK_HOLE);

    let clock = Clock::manual(START);
    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock,
    })
    .await
    .unwrap();
    let client = UnixClient::new(station.socket_path());

    // status reports the replica role and the single (unreachable) peer.
    let st: StatusResult =
        serde_json::from_value(client.call("status", serde_json::json!({})).await.unwrap())
            .unwrap();
    assert_eq!(st.connectivity.role, "replica");
    assert_eq!(st.connectivity.peers.len(), 1);
    assert_eq!(st.connectivity.peers[0].address, BLACK_HOLE);

    // A real pull round against the black hole completes under the dial bound and
    // is recorded: `last_attempt_at` set, `reachable` false — the bounded-dial
    // timeout fix, proven on the path that actually dials.
    poll_until(Duration::from_secs(15), || async {
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
        "the black-hole writer is attempted but never reachable"
    );

    // The replica admits nothing: an operator write is refused with the typed
    // read-replica error, and its log stays empty (it pulled nothing).
    let err = client
        .call(
            "propose",
            serde_json::json!({ "receiver": addr(&Keypair::generate()).to_string(), "amount_centi": 100 }),
        )
        .await
        .expect_err("a replica must refuse a write");
    let msg = err.to_string();
    assert!(msg.contains("read-replica"), "unexpected error: {msg}");
    assert!(msg.contains("-32010"), "expected READ_REPLICA code: {msg}");
    assert_eq!(
        verify_chain(&dir.path().join(DB_FILE)),
        0,
        "a replica with an unreachable writer admits nothing"
    );

    // The transport half of "a replica never admits": a DTN bundle handed to the
    // core directly (the code path both the Reticulum and SMS inbound loops use)
    // is dropped — no receipt, nothing appended. Even a well-formed bundle whose
    // records would pass a writer's front door is refused before ingest.
    let sender = Keypair::generate();
    let receiver = Keypair::generate();
    let proposal = SignedProposal::sign(
        TransactionProposal::new(
            addr(&sender),
            addr(&receiver),
            100,
            None,
            0,
            START,
            START + 100_000,
        ),
        &sender,
    );
    let entry = outbox_entry(&sender, 0, Hash::from_bytes([0u8; 32]), &proposal, START);
    let bundle = Bundle::new(vec![EntryEnvelope::from_signed(&entry)], START).encode();
    let receipt = station.core().ingest_bundle_bytes(bundle).await;
    assert!(
        receipt.is_none(),
        "a replica returns no receipt for a DTN bundle"
    );
    assert_eq!(
        verify_chain(&dir.path().join(DB_FILE)),
        0,
        "a replica ingests nothing over a DTN transport"
    );

    // And it stops cleanly and promptly (bounded by PEER_DIAL_TIMEOUT).
    let socket = station.socket_path().to_path_buf();
    station.shutdown().await;
    assert!(
        !socket.exists(),
        "the socket must be removed on clean shutdown"
    );
}

/// A writer refuses to start with a peer list (ADR-0020 §1): the single-writer
/// discipline holds at startup, not only in the config validator's unit test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_with_peers_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    // Default role is writer; give it a peer — a misconfiguration.
    let text = format!(
        "[peers]\n\
         list = [\"{BLACK_HOLE}\"]\n\n\
         [network]\n\
         listen = \"127.0.0.1:0\"\n\n\
         [mobile]\n\
         advertise = false\n\
         listen = \"127.0.0.1:0\"\n"
    );
    std::fs::write(dir.path().join("config.toml"), text).unwrap();

    let result = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::manual(START),
    })
    .await;
    // `Station` is not `Debug`, so match rather than `expect_err`.
    let err = match result {
        Ok(_) => panic!("a writer with a peer list must refuse to start"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("writer never pulls"),
        "unexpected error: {msg}"
    );
}
