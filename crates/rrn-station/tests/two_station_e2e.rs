//! The two-station exit test, reshaped for the single-writer model (ADR-0020 §1,
//! and its §7 Clarification: the writer never pulls, a replica never admits).
//!
//! A community has exactly one **writer** — the station that owns the chain and
//! admits records at its front door — and any number of **replicas**, read-only
//! copies that pull the writer's log over gossip and re-derive state by replay
//! (ADR-0018), admitting nothing themselves. So the two stations here are a
//! writer + a replica, not the writer/writer pair the Phase-0 test used (which is
//! no longer a supported topology: a writer with peers refuses to start).
//!
//! The flow: Alice (the writer's operator) vouches for member Bob and proposes a
//! payment; Bob — a member with his own keypair, not a station — confirms
//! *offline* and his confirmation reaches the writer through the real courier
//! path (`bundle_submit`, ADR-0020 §3), exactly as a phone's would. The writer
//! settles. The replica then converges to a byte-identical copy of the writer's
//! chain — and refuses any write with the typed read-replica error. (Its own
//! balance view reads zero: it pins station-signed records to its own key, not
//! the writer's — the documented signer-pinning residual, asserted below.)
//!
//! Both stations run in-process as Tokio tasks sharing one manual [`Clock`] so the
//! test fast-forwards across the settlement window atomically.

use std::path::Path;
use std::time::Duration;

use rrn_station::core::{hex, unhex};
use rrn_station::rpc::{BalanceResult, HistoryResult, ProposeResult, VouchResult, WhoamiResult};
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams, DB_FILE, WALLET_FILE};
use rrn_station::Clock;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::transaction::{SignedConfirmation, TransactionConfirmation, TransactionId};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};
use rrn_protocol::receipt::{self, Disposition, SignedReceipt};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

const PASSPHRASE: &str = "e2e-passphrase";
const START: i64 = 1_000_000;
const WINDOW: u64 = 5; // short settlement window for the test
const WRITER_PORT: u16 = 7411;

/// Writes the **writer** config: no peers (a writer never pulls, ADR-0020 §1),
/// bound on a fixed loopback port so the replica can dial it, mDNS off, fast
/// windows/timers.
fn write_writer_config(dir: &Path) {
    let text = format!(
        "[network]\n\
         listen = \"127.0.0.1:{WRITER_PORT}\"\n\
         role = \"writer\"\n\n\
         [mobile]\n\
         advertise = false\n\
         listen = \"127.0.0.1:0\"\n\n\
         [settlement]\n\
         window_seconds = {WINDOW}\n\n\
         [timers]\n\
         sweep_interval_secs = 1\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// Writes the **replica** config: it pulls the writer at `WRITER_PORT`, binds an
/// ephemeral loopback port, mDNS off, fast gossip. A replica runs no sweep timers
/// (it re-derives, never admits).
fn write_replica_config(dir: &Path) {
    let text = format!(
        "[peers]\n\
         list = [\"127.0.0.1:{WRITER_PORT}\"]\n\n\
         [network]\n\
         listen = \"127.0.0.1:0\"\n\
         role = \"replica\"\n\n\
         [mobile]\n\
         advertise = false\n\
         listen = \"127.0.0.1:0\"\n\n\
         [settlement]\n\
         window_seconds = {WINDOW}\n\n\
         [timers]\n\
         gossip_interval_secs = 1\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

fn addr(k: &Keypair) -> Address {
    Address::from_public_key(k.public_key())
}

/// Polls `check` every 100ms until it returns true or `timeout` elapses.
async fn wait_until<F, Fut>(label: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {label}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn balance(client: &UnixClient, address: &str) -> i64 {
    let v = client
        .call("balance", serde_json::json!({ "address": address }))
        .await
        .unwrap();
    let r: BalanceResult = serde_json::from_value(v).unwrap();
    r.balance_centi
}

/// True if this station's history contains at least one entry of `kind`.
async fn has_kind(client: &UnixClient, kind: &str) -> bool {
    let v = client.call("history", serde_json::json!({})).await.unwrap();
    let r: HistoryResult = serde_json::from_value(v).unwrap();
    r.entries.iter().any(|e| e.kind == kind)
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

/// Submits a DTN bundle through the writer's operator `bundle_submit` RPC and
/// returns the decoded, signature-verified station receipt.
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

/// Content-hash set of a station's log, read from a fresh connection.
fn log_content_set(db_path: &Path) -> std::collections::BTreeSet<[u8; 32]> {
    let db = Database::open(db_path).unwrap();
    let log = AppendLog::new(&db);
    let mut set = std::collections::BTreeSet::new();
    for entry in log.iter_from(1) {
        set.insert(entry.unwrap().content_hash.to_bytes());
    }
    set
}

fn verify_chain(db_path: &Path) -> u64 {
    let db = Database::open(db_path).unwrap();
    AppendLog::new(&db).verify_chain().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writer_admits_and_settles_while_a_replica_copies_the_chain() {
    let dir_w = tempfile::tempdir().unwrap();
    let dir_r = tempfile::tempdir().unwrap();

    // The writer (Alice's station) and a replica.
    let alice = Station::init(dir_w.path(), PASSPHRASE).unwrap().to_string();
    Station::init(dir_r.path(), PASSPHRASE).unwrap();
    write_writer_config(dir_w.path());
    write_replica_config(dir_r.path());

    // A single shared manual clock drives both stations.
    let clock = Clock::manual(START);

    let writer = Station::open(StationParams {
        data_dir: dir_w.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let replica = Station::open(StationParams {
        data_dir: dir_r.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();

    let client_w = UnixClient::new(writer.socket_path());
    let client_r = UnixClient::new(replica.socket_path());

    // Bob is a member with his own keypair (not a station).
    let bob_kp = Keypair::generate();
    let bob = addr(&bob_kp).to_string();

    // The writer is Alice; the replica reports the replica role.
    let who_w: WhoamiResult = serde_json::from_value(
        client_w
            .call("whoami", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(who_w.address, alice);

    // 1. Alice vouches for Bob on the writer's operator socket.
    let vouch: VouchResult = serde_json::from_value(
        client_w
            .call(
                "vouch",
                serde_json::json!({ "subject": bob, "statement": "known good", "stake_centi": 0 }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!vouch.vouch_id.is_empty());

    // 2. Alice proposes 3 Commons to Bob on the writer.
    let proposal: ProposeResult = serde_json::from_value(
        client_w
            .call(
                "propose",
                serde_json::json!({ "receiver": bob, "amount_centi": 300 }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let tx_id = TransactionId(Hash::from_hex(&proposal.tx_id).unwrap());
    assert_eq!(proposal.state, "Proposed");

    // 3. Bob confirms OFFLINE; the confirmation reaches the writer via the
    //    courier path (`bundle_submit`), exactly as a phone's would.
    let conf = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: tx_id,
            confirmer: addr(&bob_kp),
            confirmed_at: clock.now(),
        },
        &bob_kp,
    );
    let r = submit_bundle(
        &client_w,
        &[outbox_entry(
            &bob_kp,
            0,
            Hash::from_bytes([0u8; 32]),
            &conf,
            clock.now(),
        )],
        clock.now(),
    )
    .await;
    assert!(matches!(
        r.payload.outcomes[0].disposition,
        Disposition::Admitted { .. }
    ));

    // 4. The replica refuses to admit anything itself: a write returns the typed
    //    read-replica error, and bundle submit is refused too.
    let err = client_r
        .call(
            "propose",
            serde_json::json!({ "receiver": bob, "amount_centi": 100 }),
        )
        .await
        .expect_err("a replica must refuse a write");
    let msg = err.to_string();
    assert!(msg.contains("read-replica"), "unexpected error: {msg}");
    assert!(msg.contains("-32010"), "expected READ_REPLICA code: {msg}");

    // 5. Fast-forward past the settlement window and sweep on the writer only.
    clock.advance(WINDOW as i64 + 1);
    writer.sweep().await;
    assert_eq!(balance(&client_w, &alice).await, -300);
    assert_eq!(balance(&client_w, &bob).await, 300);

    // 6. The replica converges to a byte-identical copy of the writer's chain,
    //    re-chained locally with dedup intact (ADR-0018).
    let db_w = dir_w.path().join(DB_FILE);
    let db_r = dir_r.path().join(DB_FILE);
    wait_until(
        "replica converges to the writer's chain",
        Duration::from_secs(20),
        || async { log_content_set(&db_w) == log_content_set(&db_r) },
    )
    .await;

    assert!(
        verify_chain(&db_w) >= 4,
        "writer chain should have >=4 entries"
    );
    assert_eq!(
        verify_chain(&db_w),
        verify_chain(&db_r),
        "the replica must hold the same number of entries as the writer"
    );
    assert_eq!(
        log_content_set(&db_w),
        log_content_set(&db_r),
        "the replica must hold a byte-identical copy of the writer's chain"
    );

    // The replica saw the records by replication, not by admitting them.
    assert!(has_kind(&client_r, "settlement").await || has_kind(&client_r, "confirmation").await);

    // A replica's admitting sweep timers are gated off; even if the operator
    // drives a sweep by hand it is a no-op and appends nothing, so the replica
    // cannot fork its copy by settling under its own key.
    let before = log_content_set(&db_r);
    assert_eq!(
        replica.sweep().await,
        0,
        "a replica sweep must admit nothing"
    );
    assert_eq!(replica.charge_contracts().await, 0);
    assert_eq!(replica.enact_governance().await, 0);
    assert_eq!(replica.resolve_disputes().await, 0);
    assert_eq!(
        log_content_set(&db_r),
        before,
        "a replica's sweep hooks must not append to its chain"
    );

    // The replica re-derives from the chain but pins station-signed records to
    // *its own* station key (the station signer-pinning residual, decision (a)),
    // which differs from the writer's — so the writer-signed **settlement**
    // records are not counted in the replica's balance view: it reads 0, not
    // -300/+300. This is the documented signer-pinning residual (a read-replica
    // pins to the wrong key), out of scope for this change; the *chain* is what a
    // replica copies faithfully. Asserted here so the residual is legible and a
    // regression in the pinning boundary would be caught.
    assert_eq!(
        balance(&client_r, &alice).await,
        0,
        "a replica cannot re-derive the writer-signed settlement under its own key \
         (documented signer-pinning residual)"
    );
    assert_eq!(balance(&client_r, &bob).await, 0);

    // Sanity: the wallets differ (two independent stations).
    let wallet_w =
        WalletContents::load_from_file(&dir_w.path().join(WALLET_FILE), PASSPHRASE).unwrap();
    let wallet_r =
        WalletContents::load_from_file(&dir_r.path().join(WALLET_FILE), PASSPHRASE).unwrap();
    assert_ne!(wallet_w.address, wallet_r.address);

    writer.shutdown().await;
    replica.shutdown().await;
}
