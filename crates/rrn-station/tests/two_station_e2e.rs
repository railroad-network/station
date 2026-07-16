//! The Phase 0 exit test: two stations, a vouch, a payment, settlement.
//!
//! Both stations run in-process as Tokio tasks (no separate binaries), sharing a
//! single manual [`Clock`] so the test can fast-forward across the settlement
//! window atomically. User-facing operations go through the real RPC path (a
//! [`UnixClient`] over each station's socket); time control and settlement are
//! driven in-process for determinism. If this test fails, M0.6 — and Phase 0 —
//! is not done.

use std::path::Path;
use std::time::Duration;

use rrn_station::rpc::{BalanceResult, HistoryResult, ProposeResult, VouchResult, WhoamiResult};
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams, DB_FILE};
use rrn_station::Clock;

use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

const PASSPHRASE: &str = "e2e-passphrase";
const START: i64 = 1_000_000;
const WINDOW: u64 = 5; // short settlement window for the test

/// Writes a `config.toml` with the given listen port, peer port, and fast loops.
///
/// mDNS is off: `[mobile] advertise` defaults to `true`, and a test has no
/// business publishing services onto whatever network the developer or the CI
/// runner happens to be on. This test is about the peer/gossip surface, which
/// is unrelated.
fn write_config(dir: &Path, listen_port: u16, peer_port: u16) {
    let text = format!(
        "[peers]\n\
         list = [\"127.0.0.1:{peer_port}\"]\n\n\
         [network]\n\
         listen = \"127.0.0.1:{listen_port}\"\n\n\
         [mobile]\n\
         advertise = false\n\
         listen = \"127.0.0.1:0\"\n\n\
         [settlement]\n\
         window_seconds = {WINDOW}\n\n\
         [timers]\n\
         sweep_interval_secs = 1\n\
         gossip_interval_secs = 1\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
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
async fn two_station_vouch_pay_confirm_settle() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    // 1–2. Initialize both stations and pin their ports/peer-lists.
    let alice = Station::init(dir_a.path(), PASSPHRASE).unwrap().to_string();
    let bob = Station::init(dir_b.path(), PASSPHRASE).unwrap().to_string();
    write_config(dir_a.path(), 7411, 7412);
    write_config(dir_b.path(), 7412, 7411);

    // A single shared manual clock drives both stations.
    let clock = Clock::manual(START);

    let station_a = Station::open(StationParams {
        data_dir: dir_a.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let station_b = Station::open(StationParams {
        data_dir: dir_b.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();

    let client_a = UnixClient::new(station_a.socket_path());
    let client_b = UnixClient::new(station_b.socket_path());

    // 3. Both ready: whoami returns the expected identities.
    let who_a: WhoamiResult = serde_json::from_value(
        client_a
            .call("whoami", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    let who_b: WhoamiResult = serde_json::from_value(
        client_b
            .call("whoami", serde_json::json!({}))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(who_a.address, alice);
    assert_eq!(who_b.address, bob);

    // 4. Alice vouches for Bob (RPC → station A).
    let vouch: VouchResult = serde_json::from_value(
        client_a
            .call(
                "vouch",
                serde_json::json!({ "subject": bob, "statement": "known good", "stake_centi": 0 }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!vouch.vouch_id.is_empty());

    // 5. The vouch reaches station B by gossip.
    wait_until("vouch on B", Duration::from_secs(15), || {
        has_kind(&client_b, "vouch")
    })
    .await;

    // 6. Alice proposes 3 Commons to Bob (RPC → station A).
    let proposal: ProposeResult = serde_json::from_value(
        client_a
            .call(
                "propose",
                serde_json::json!({ "receiver": bob, "amount_centi": 300 }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let tx_id = proposal.tx_id;
    assert_eq!(proposal.state, "Proposed");

    // 7. The proposal reaches B (B needs it locally to confirm).
    wait_until("proposal on B", Duration::from_secs(15), || {
        has_kind(&client_b, "proposal")
    })
    .await;

    // 8. Bob confirms (RPC → station B).
    let confirm = client_b
        .call("confirm", serde_json::json!({ "tx_id": tx_id }))
        .await
        .unwrap();
    assert_eq!(confirm["state"], "Confirmed");

    // 9. The confirmation reaches A.
    wait_until("confirmation on A", Duration::from_secs(15), || {
        has_kind(&client_a, "confirmation")
    })
    .await;

    // 10. Fast-forward both stations past the settlement window (shared clock).
    clock.advance(WINDOW as i64 + 1);

    // 11. Both stations sweep settlement.
    station_a.sweep().await;
    station_b.sweep().await;

    // 12–13. Balances settle to ±300 on *both* stations (settlement records
    // gossip both ways; the derivation dedups per transaction).
    wait_until(
        "balances settle on both",
        Duration::from_secs(15),
        || async {
            balance(&client_a, &alice).await == -300
                && balance(&client_a, &bob).await == 300
                && balance(&client_b, &alice).await == -300
                && balance(&client_b, &bob).await == 300
        },
    )
    .await;

    assert_eq!(balance(&client_a, &alice).await, -300);
    assert_eq!(balance(&client_a, &bob).await, 300);
    assert_eq!(balance(&client_b, &alice).await, -300);
    assert_eq!(balance(&client_b, &bob).await, 300);

    // 14. Both chains verify, and the two stations hold the same set of entries.
    let db_a = dir_a.path().join(DB_FILE);
    let db_b = dir_b.path().join(DB_FILE);

    // Let any in-flight gossip carry the last settlement record across so the
    // two logs converge to the identical set.
    wait_until("logs converge", Duration::from_secs(15), || async {
        log_content_set(&db_a) == log_content_set(&db_b)
    })
    .await;

    assert!(verify_chain(&db_a) >= 4, "A chain should have ≥4 entries");
    assert!(verify_chain(&db_b) >= 4, "B chain should have ≥4 entries");
    assert_eq!(
        log_content_set(&db_a),
        log_content_set(&db_b),
        "both stations must hold the same set of log entries"
    );

    station_a.shutdown().await;
    station_b.shutdown().await;
}
