//! End-to-end tests for `rrn wallet` (ADR-0028): the real `rrn` binary drives a
//! live in-process station over its Unix socket (operator side) and its mobile
//! sealed channel (member side). Everything that touches the binary runs off the
//! reactor via `spawn_blocking`.
//!
//! The station clock is set to real time so the wallet's system-clock request
//! timestamps stay inside the channel skew window; settlement (which needs a
//! long window) is proven in the ledger/station suites, so these tests assert
//! admission, receipts, chain integrity, and the pin — the wallet's own logic.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use std::collections::BTreeMap;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::{self, RecoveryRequest};
use rrn_identity::recovery::flow::RecoveryPackage;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::transaction::{SignedProposal, TransactionProposal};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::OutboxEntry;
use rrn_protocol::receipt::{self, DeliveryReceipt, Disposition, Outcome};
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;
use rrn_storage::db::Database;
use rrn_storage::outbox::OutboxStore;

const RRN: &str = env!("CARGO_BIN_EXE_rrn");
const PASS: &str = "wallet-e2e-pass";
const STATION_PASS: &str = "station-e2e-pass";

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A free localhost TCP port for the mobile listener (small bind-then-drop race,
/// acceptable in tests).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_config(dir: &Path, mobile_port: u16, replica: bool) {
    let role = if replica {
        "\n[network]\nlisten = \"127.0.0.1:0\"\nrole = \"replica\"\n"
    } else {
        "\n[network]\nlisten = \"127.0.0.1:0\"\n"
    };
    let text = format!(
        "[peers]\nlist = []\n{role}\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:{mobile_port}\"\nsubscribe_hold_secs = 2\n\n\
         [settlement]\nwindow_seconds = 1\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// A running station and the handles a test drives it through.
struct Harness {
    station: Station,
    socket: PathBuf,
    station_addr: String,
    url: String,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(replica: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Station::init(dir.path(), STATION_PASS).unwrap();
        let port = free_port();
        write_config(dir.path(), port, replica);
        let station = Station::open(StationParams {
            data_dir: dir.path().to_path_buf(),
            passphrase: STATION_PASS.into(),
            clock: Clock::manual(now_secs()),
        })
        .await
        .unwrap();
        let socket = station.socket_path().to_path_buf();
        let station_addr = station.address().to_string();
        Self {
            station,
            socket,
            station_addr,
            url: format!("127.0.0.1:{port}"),
            _dir: dir,
        }
    }

    fn client(&self) -> UnixClient {
        UnixClient::new(&self.socket)
    }

    async fn shutdown(self) {
        self.station.shutdown().await;
    }
}

/// Runs `rrn --format json wallet --home H <args>` with the wallet passphrase in
/// the environment, off the reactor. Returns `(success, stdout, stderr)`.
fn run_wallet(home: &Path, pass: Option<&str>, args: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(RRN);
    cmd.arg("--format")
        .arg("json")
        .arg("wallet")
        .arg("--home")
        .arg(home)
        .args(args)
        .stdin(Stdio::null());
    match pass {
        Some(p) => {
            cmd.env("RRN_WALLET_PASSPHRASE", p);
        }
        None => {
            cmd.env_remove("RRN_WALLET_PASSPHRASE");
        }
    }
    let out = cmd.output().expect("spawn rrn wallet");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A wallet command expected to succeed; returns parsed JSON stdout.
async fn wjson(home: &Path, args: &[&str]) -> serde_json::Value {
    let home = home.to_path_buf();
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (ok, stdout, stderr) = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        run_wallet(&home, Some(PASS), &refs)
    })
    .await
    .unwrap();
    assert!(ok, "wallet {args:?} failed: {stderr}");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("wallet {args:?} stdout not JSON ({e}): {stdout:?}"))
}

/// A wallet command expected to fail; returns stderr.
async fn wfail(home: &Path, pass: Option<&str>, args: &[&str]) -> String {
    let home = home.to_path_buf();
    let pass = pass.map(str::to_string);
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (ok, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        run_wallet(&home, pass.as_deref(), &refs)
    })
    .await
    .unwrap();
    assert!(!ok, "wallet {args:?} unexpectedly succeeded");
    stderr
}

/// One line-delimited operator RPC over the socket.
async fn socket_call(
    client: &UnixClient,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    client.call(method, params).await.unwrap()
}

/// Inits a fresh wallet home pinned to `station`; returns `(home, member_addr)`.
async fn init_wallet(dir: &Path, name: &str, station: &str) -> (PathBuf, String) {
    let home = dir.join(name);
    let v = wjson(&home, &["init", "--station", station]).await;
    let addr = v["address"].as_str().unwrap().to_string();
    (home, addr)
}

/// Pairs `home` to the harness and confirms it over the operator socket with
/// the code `rrn wallet pair` printed, as the operator would type it.
async fn pair_and_confirm(h: &Harness, home: &Path, member_addr: &str) {
    let paired = wjson(home, &["pair", "--url", &h.url]).await;
    let code = paired["code"].as_str().expect("pair prints a code");
    assert_eq!(code.len(), 11, "XXXXX-XXXXX: {code}");
    assert_eq!(code.as_bytes()[5], b'-');
    assert!(paired.get("sas").is_none());
    let confirmed = socket_call(
        &h.client(),
        "pair_confirm",
        serde_json::json!({ "address": member_addr, "code": code }),
    )
    .await;
    assert_eq!(confirmed["address"], member_addr, "{confirmed}");
}

/// The number of pending outbox rows for `member_addr` in the wallet's own db.
fn pending_rows(home: &Path, member_addr: &str) -> usize {
    let db = Database::open(&home.join("wallet.db")).unwrap();
    let author = member_addr
        .parse::<Address>()
        .unwrap()
        .public_key()
        .to_bytes();
    OutboxStore::new(&db).pending(&author, None).unwrap().len()
}

// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn station_dir_refused() {
    // A --home pointing at a station's data dir is refused before any prompt —
    // even with no passphrase in the environment and stdin closed.
    let h = Harness::start(false).await;
    let stderr = wfail(&h.station_data_dir(), None, &["status"]).await;
    assert!(
        stderr.contains("station data directory"),
        "expected a station-dir refusal, got: {stderr}"
    );
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_station_at_pair_refused() {
    // A wallet pinned to station A that pairs at station B's URL is refused, and
    // its stored URL is left unchanged.
    let a = Harness::start(false).await;
    let b = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &a.station_addr).await;

    let stderr = wfail(&home, Some(PASS), &["pair", "--url", &b.url]).await;
    assert!(
        stderr.contains("not the pinned") || stderr.contains("identifies as"),
        "expected a station-mismatch refusal, got: {stderr}"
    );
    // The failed pair must not have stored station B's URL.
    let after_fail = wjson(&home, &["status"]).await;
    assert_ne!(
        after_fail["url"].as_str().unwrap(),
        b.url,
        "a refused pair must not persist the wrong URL"
    );

    // Pairing to the right station still works afterward.
    pair_and_confirm(&a, &home, &member).await;
    let status = wjson(&home, &["status"]).await;
    assert_eq!(status["url"].as_str().unwrap(), a.url);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_against_station_with_no_record_stays_unknown() {
    // The no-self-fork guard (ADR-0028 §7): a restored wallet whose key the
    // station has no record of — e.g. synced against a read replica (which never
    // sees carried bundles) or the wrong station — must NOT conclude "fresh" and
    // sign position 0. It stays `unknown` and keeps refusing to sign.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();

    // A known key with NO history at this station, written into a backup file.
    let m = Keypair::generate();
    let m_addr = Address::from_public_key(m.public_key());
    let mut metadata = BTreeMap::new();
    metadata.insert("role".to_string(), "member".to_string());
    metadata.insert("schema".to_string(), "1".to_string());
    let contents = WalletContents {
        secret_key: m.secret_key().clone(),
        address: m_addr,
        created_at: now_secs(),
        metadata,
    };
    let backup = dir.path().join("backup.rrnwallet");
    contents.save_to_file(&backup, PASS).unwrap();

    let home = dir.path().join("w");
    wjson(
        &home,
        &[
            "init",
            "--station",
            &h.station_addr,
            "--restore",
            backup.to_str().unwrap(),
        ],
    )
    .await;
    pair_and_confirm(&h, &home, &m_addr.to_string()).await;

    // Sync finds no station record → the chain stays `unknown`, not `fresh`.
    let synced = wjson(&home, &["sync"]).await;
    assert_eq!(
        synced["chain_state"], "unknown",
        "a restored key the station has never seen must not become fresh"
    );
    assert!(
        synced["blocked"].is_string(),
        "sync surfaces why it is blocked"
    );

    // Signing is still refused (no silent fork of position 0).
    let stderr = wfail(&home, Some(PASS), &["pay", &h.station_addr, "1"]).await;
    assert!(stderr.contains("re-anchor"), "got: {stderr}");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_receipt_is_rejected() {
    // A receipt signed by a random key, and one signed correctly but naming a
    // different station, are both rejected; pending rows stay pending.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    // Author one pending record so there is something an apply could touch.
    wjson(&home, &["pay", &h.station_addr, "1"]).await;
    assert_eq!(pending_rows(&home, &member), 1);

    let record_hash = Hash::from_bytes([7u8; 32]);
    // (a) signed by a random key.
    let imposter = Keypair::generate();
    let forged = SignedPayload::sign(
        DeliveryReceipt {
            station: Address::from_public_key(imposter.public_key()),
            outcomes: vec![Outcome {
                record_hash,
                disposition: Disposition::Admitted { seq: 9 },
            }],
            received_at: now_secs(),
        },
        &imposter,
    );
    let forged_path = home.join("forged.txt");
    std::fs::write(&forged_path, hex(&receipt::encode_signed(&forged))).unwrap();
    let stderr = wfail(
        &home,
        Some(PASS),
        &["receipts", "apply", "--in", forged_path.to_str().unwrap()],
    )
    .await;
    assert!(
        stderr.contains("pinned station"),
        "expected a pin refusal, got: {stderr}"
    );
    assert_eq!(pending_rows(&home, &member), 1, "rows stay pending");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_paper_round_trip() {
    // Author offline, export QR, ingest via the operator socket, carry receipts
    // back, apply them — idempotently — and confirm the row is acked.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    // A fresh chain (position 0 legitimate) needs no re-anchor to sign.
    wjson(&home, &["pay", &h.station_addr, "3.00", "--memo", "eggs"]).await;
    assert_eq!(pending_rows(&home, &member), 1);

    let out = home.join("out");
    wjson(&home, &["export", "qr", "--out", out.to_str().unwrap()]).await;
    let payload = out.join("bundle.txt");
    assert!(payload.exists());

    // Operator ingests the exported bundle from the file (existing paper tool).
    let carry = home.join("carry");
    let socket = h.socket.to_str().unwrap().to_string();
    let payload_s = payload.to_str().unwrap().to_string();
    let carry_s = carry.to_str().unwrap().to_string();
    let member_s = member.clone();
    tokio::task::spawn_blocking(move || {
        run_paper(&socket, &["ingest", "--in", &payload_s, "--out", &carry_s]);
        run_paper(
            &socket,
            &["export-receipts", "--author", &member_s, "--out", &carry_s],
        );
    })
    .await
    .unwrap();

    // Apply the carried-back receipts: the row is acked, and re-applying is a
    // no-op (idempotent).
    let receipts = carry.join("receipts.txt");
    let applied = wjson(
        &home,
        &["receipts", "apply", "--in", receipts.to_str().unwrap()],
    )
    .await;
    assert_eq!(applied["applied"].as_u64().unwrap(), 1);
    assert_eq!(pending_rows(&home, &member), 0, "row acked and pruned");

    let again = wjson(
        &home,
        &["receipts", "apply", "--in", receipts.to_str().unwrap()],
    )
    .await;
    assert_eq!(again["applied"].as_u64().unwrap(), 0, "idempotent re-apply");

    // With nothing pending, export refuses cleanly.
    // (Bundle export of an empty set is still valid CBOR; submit is the guard.)
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn online_round_trip_admits_and_advances_cursor() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    pair_and_confirm(&h, &home, &member).await;

    // Sync a fresh, never-seen chain: cursor 0, head null.
    let synced = wjson(&home, &["sync"]).await;
    assert_eq!(synced["chain_state"], "fresh");
    assert_eq!(synced["nonce_cursor"].as_u64().unwrap(), 0);

    // Pay the station 2 Commons, submit online, and confirm the receipt admitted.
    wjson(&home, &["pay", &h.station_addr, "2.00"]).await;
    let submitted = wjson(&home, &["submit"]).await;
    assert_eq!(submitted["applied"].as_u64().unwrap(), 1);
    assert_eq!(pending_rows(&home, &member), 0, "acked and pruned");

    // The cursor advanced to 1, and the station saw the chain.
    let status = wjson(&home, &["status"]).await;
    assert_eq!(status["nonce_cursor"].as_u64().unwrap(), 1);

    // A second sync now reports the chain anchored (the station has seen it).
    let synced2 = wjson(&home, &["sync"]).await;
    assert_eq!(synced2["chain_state"], "anchored");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_reanchors_and_never_forks() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    pair_and_confirm(&h, &home, &member).await;
    wjson(&home, &["sync"]).await;
    wjson(&home, &["pay", &h.station_addr, "1.00"]).await;
    wjson(&home, &["submit"]).await;

    // Back up the wallet file, then restore into a brand-new home.
    let backup = dir.path().join("backup.rrnwallet");
    std::fs::copy(home.join("member.rrnwallet"), &backup).unwrap();
    let home2 = dir.path().join("w2");
    wjson(
        &home2,
        &[
            "init",
            "--station",
            &h.station_addr,
            "--restore",
            backup.to_str().unwrap(),
        ],
    )
    .await;

    // Signing is refused until a sync re-anchors the unknown chain.
    let stderr = wfail(&home2, Some(PASS), &["pay", &h.station_addr, "1"]).await;
    assert!(stderr.contains("re-anchor"), "got: {stderr}");

    pair_and_confirm(&h, &home2, &member).await;
    let synced = wjson(&home2, &["sync"]).await;
    assert_eq!(synced["chain_state"], "anchored");
    assert!(synced["reanchored"].as_bool().unwrap());

    // A pay after re-anchor admits, and the station records NO fork.
    wjson(&home2, &["pay", &h.station_addr, "1.00"]).await;
    let submitted = wjson(&home2, &["submit"]).await;
    assert_eq!(submitted["applied"].as_u64().unwrap(), 1);
    assert!(
        !station_recorded_fork(&h.station_data_dir(), &member),
        "no outbox fork must be recorded"
    );
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replica_keeps_records_pending() {
    let h = Harness::start(true).await; // replica
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    pair_and_confirm(&h, &home, &member).await;
    // A replica still serves reads, so sync works; outbox_head reads empty.
    wjson(&home, &["sync"]).await;
    wjson(&home, &["pay", &h.station_addr, "1.00"]).await;

    let stderr = wfail(&home, Some(PASS), &["submit"]).await;
    assert!(stderr.contains("read replica"), "got: {stderr}");
    assert_eq!(pending_rows(&home, &member), 1, "rows stay pending");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vouch_is_online_only() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    let subject = Address::from_public_key(Keypair::generate().public_key()).to_string();

    // Offline: refused, and no outbox row is written.
    let stderr = wfail(
        &home,
        Some(PASS),
        &[
            "vouch",
            &subject,
            "--statement",
            "I know them",
            "--stake",
            "0.50",
        ],
    )
    .await;
    assert!(stderr.contains("reachable"), "got: {stderr}");
    assert_eq!(
        pending_rows(&home, &member),
        0,
        "vouch never touches the outbox"
    );

    // Online: returns a vouch id.
    pair_and_confirm(&h, &home, &member).await;
    wjson(&home, &["sync"]).await;
    let voucher = wjson(
        &home,
        &[
            "vouch",
            &subject,
            "--statement",
            "I know them",
            "--stake",
            "0.50",
        ],
    )
    .await;
    assert_eq!(voucher["vouch_id"].as_str().unwrap().len(), 64);
    assert_eq!(pending_rows(&home, &member), 0, "still no outbox row");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cert_backed_spend_and_return() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    pair_and_confirm(&h, &home, &member).await;
    wjson(&home, &["sync"]).await;

    // Request a 5-Common certificate over the channel.
    let issued = wjson(&home, &["cert", "request", "5"]).await;
    let cert_id = issued["cert_id"].as_str().unwrap().to_string();
    let list = wjson(&home, &["cert", "list"]).await;
    assert_eq!(list["certificates"].as_array().unwrap().len(), 1);

    // A within-cap cert-backed spend is accepted locally and chains.
    wjson(&home, &["pay", &h.station_addr, "2.00", "--cert", &cert_id]).await;
    assert_eq!(pending_rows(&home, &member), 1);

    // Over the remaining cap is refused locally (5 − 2 = 3 remaining).
    let stderr = wfail(
        &home,
        Some(PASS),
        &["pay", &h.station_addr, "4.00", "--cert", &cert_id],
    )
    .await;
    assert!(stderr.contains("remaining allowance"), "got: {stderr}");

    // Return the certificate: a chained record.
    wjson(&home, &["cert", "return", &cert_id]).await;
    assert_eq!(pending_rows(&home, &member), 2, "spend + return pending");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bundle_export_matches_ingest() {
    // A `export bundle` file, submitted over the operator socket, yields the
    // same admitted receipt shape an online submit would.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    // This wallet never pairs, so the operator enrolls it (ADR-0038) before it
    // may spend from zero.
    socket_call(
        &h.client(),
        "enroll",
        serde_json::json!({ "address": member }),
    )
    .await;
    wjson(&home, &["pay", &h.station_addr, "1.50"]).await;
    let out = home.join("out");
    wjson(&home, &["export", "bundle", "--out", out.to_str().unwrap()]).await;
    let bundle = std::fs::read(out.join("payload.bundle")).unwrap();

    let res = socket_call(
        &h.client(),
        "bundle_submit",
        serde_json::json!({ "bundle_hex": hex(&bundle) }),
    )
    .await;
    let receipt_hex = res["receipt_hex"].as_str().unwrap();
    let signed = receipt::decode_signed(&rrn_station::core::unhex(receipt_hex).unwrap()).unwrap();
    assert!(matches!(
        signed.payload.outcomes[0].disposition,
        Disposition::Admitted { .. }
    ));
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_refusal_resets_cursor() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    pair_and_confirm(&h, &home, &member).await;
    wjson(&home, &["sync"]).await;

    // Two offline pays: the first already expired (--expires-in in the past),
    // the second normal — so on submit the first is `expired` and the second
    // `nonce-gap` (its nonce 1 never follows an admitted 0). Cursor is now 2.
    wjson(&home, &["pay", &h.station_addr, "1", "--expires-in=-5"]).await;
    wjson(&home, &["pay", &h.station_addr, "1"]).await;
    assert_eq!(wjson(&home, &["status"]).await["nonce_cursor"], 2);

    // Submit: both refused, nothing admitted.
    wjson(&home, &["submit"]).await;
    assert_eq!(pending_rows(&home, &member), 0, "both acked (refused)");

    // Sync with nothing pending resets the cursor to the station's next (0).
    let synced = wjson(&home, &["sync"]).await;
    assert_eq!(synced["nonce_cursor"], 0, "cursor reset after refusals");

    // A third pay at the reset nonce now admits.
    wjson(&home, &["pay", &h.station_addr, "1"]).await;
    let submitted = wjson(&home, &["submit"]).await;
    assert_eq!(submitted["applied"].as_u64().unwrap(), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_refusal_of_a_confirmation_stays_pending_and_retries() {
    // B confirms A's offline payment and submits before A does: the station
    // answers `not-proposed`, a refusal that can change, so B's confirmation
    // stays pending. Once A's proposal lands, B's next submit carries the same
    // entry again and it is admitted (ADR-0020 Clarification).
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_b, b) = init_wallet(dir.path(), "b", &h.station_addr).await;
    pair_and_confirm(&h, &home_a, &a).await;
    pair_and_confirm(&h, &home_b, &b).await;
    wjson(&home_a, &["sync"]).await;
    wjson(&home_b, &["sync"]).await;

    let paid = wjson(&home_a, &["pay", &b, "1.00"]).await;
    let tx_id = paid["tx_id"].as_str().unwrap().to_string();
    // B confirms from A's carried bundle: the station has not seen it yet.
    let carried = dir.path().join("carried");
    wjson(
        &home_a,
        &["export", "bundle", "--out", carried.to_str().unwrap()],
    )
    .await;
    let bundle = carried.join("payload.bundle");
    wjson(
        &home_b,
        &["confirm", &tx_id, "--from", bundle.to_str().unwrap()],
    )
    .await;

    let first_b = {
        let home_b = home_b.clone();
        tokio::task::spawn_blocking(move || run_wallet(&home_b, Some(PASS), &["submit"]))
            .await
            .unwrap()
    };
    assert!(first_b.0, "submit failed: {}", first_b.2);
    assert!(
        first_b.2.contains("refused for now (not-proposed)"),
        "expected the retry notice, got: {}",
        first_b.2
    );
    assert_eq!(
        pending_rows(&home_b, &b),
        1,
        "the confirmation stays pending"
    );

    let submitted_a = wjson(&home_a, &["submit"]).await;
    assert_eq!(submitted_a["applied"].as_u64().unwrap(), 1);

    let submitted_b = wjson(&home_b, &["submit"]).await;
    assert_eq!(submitted_b["applied"].as_u64().unwrap(), 1);
    assert_eq!(pending_rows(&home_b, &b), 0, "admitted on retry");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_confirmation_of_a_paid_transaction_is_refused_for_good() {
    // B confirms A's payment twice (two different confirmations of one id).
    // The first is admitted; the transaction is then no longer open, so the
    // second is refused `tx-closed` — a final answer the wallet acks at once
    // instead of carrying it forever.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_b, b) = init_wallet(dir.path(), "b", &h.station_addr).await;
    pair_and_confirm(&h, &home_a, &a).await;
    pair_and_confirm(&h, &home_b, &b).await;
    wjson(&home_a, &["sync"]).await;
    wjson(&home_b, &["sync"]).await;

    let paid = wjson(&home_a, &["pay", &b, "1.00"]).await;
    let tx_id = paid["tx_id"].as_str().unwrap().to_string();
    wjson(&home_a, &["submit"]).await;
    wjson(&home_b, &["confirm", &tx_id]).await;
    // A confirmation's bytes carry a seconds timestamp; wait so the second one
    // is a different record.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    wjson(&home_b, &["confirm", &tx_id]).await;
    wjson(&home_b, &["submit"]).await;
    assert_eq!(
        pending_rows(&home_b, &b),
        0,
        "the refusal is final, so acked"
    );
    assert_eq!(wjson(&home_b, &["status"]).await["refused_for_now"], 0);
    let shown = wjson(&home_b, &["show", "--all"]).await;
    let rows = shown["rows"].as_array().unwrap();
    assert_eq!(
        rows.last().unwrap()["disposition"],
        "refused (tx-closed)",
        "got: {shown}"
    );
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmation_whose_payment_never_arrives_can_be_abandoned() {
    // A signs a payment to B offline and never submits it (say A's laptop is
    // lost). B confirms the id; the station has never seen the proposal, so it
    // answers `not-proposed` — transient, because the proposal could still
    // arrive. The wallet keeps it pending, says why, and lets B abandon it.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_b, b) = init_wallet(dir.path(), "b", &h.station_addr).await;
    pair_and_confirm(&h, &home_a, &a).await;
    pair_and_confirm(&h, &home_b, &b).await;
    wjson(&home_a, &["sync"]).await;
    wjson(&home_b, &["sync"]).await;

    let paid = wjson(&home_a, &["pay", &b, "1.00"]).await;
    let tx_id = paid["tx_id"].as_str().unwrap().to_string();
    // B confirms from A's carried QR sheet; A never delivers the payment.
    let carried = dir.path().join("carried");
    wjson(
        &home_a,
        &["export", "qr", "--out", carried.to_str().unwrap()],
    )
    .await;
    let sheet = carried.join("bundle.txt");
    wjson(
        &home_b,
        &["confirm", &tx_id, "--from", sheet.to_str().unwrap()],
    )
    .await;
    wjson(&home_b, &["submit"]).await;
    assert_eq!(
        pending_rows(&home_b, &b),
        1,
        "the confirmation stays pending"
    );
    assert_eq!(wjson(&home_b, &["status"]).await["refused_for_now"], 1);

    // `show` says why, and gives the hash to abandon.
    let shown = wjson(&home_b, &["show", "--pending"]).await;
    let row = &shown["rows"][0];
    assert_eq!(row["last_refusal_reason"], "not-proposed");
    assert!(row["last_refused_at"].as_i64().is_some());
    let record_hash = row["record_hash"].as_str().unwrap().to_string();

    // A re-submit carries it again and it is refused again; still pending.
    wjson(&home_b, &["submit"]).await;
    assert_eq!(pending_rows(&home_b, &b), 1);

    // A prefix in any case resolves to the row.
    let prefix = record_hash[..12].to_ascii_uppercase();
    let abandoned = wjson(&home_b, &["abandon", &prefix]).await;
    assert_eq!(abandoned["abandoned"], record_hash.as_str());
    assert_eq!(abandoned["last_refusal"], "not-proposed");
    assert_eq!(pending_rows(&home_b, &b), 0, "no longer carried");
    assert_eq!(wjson(&home_b, &["status"]).await["refused_for_now"], 0);
    let stderr = wfail(&home_b, Some(PASS), &["submit"]).await;
    assert!(stderr.contains("nothing pending"), "got: {stderr}");
    h.shutdown().await;
}

// --- confirm signs only a verified, displayed proposal ---------------------

/// Submits a proposal hand-signed by the member whose wallet lives in `home`
/// over the sealed channel — as a hostile or buggy client could — and returns
/// its transaction id.
async fn submit_hand_signed(h: &Harness, home: &Path, receiver: &str, amount_centi: i64) -> String {
    let contents = WalletContents::load_from_file(&home.join("member.rrnwallet"), PASS).unwrap();
    let kp = Keypair::from_secret(contents.secret_key.clone());
    let now = now_secs();
    let p = TransactionProposal::new(
        Address::from_public_key(kp.public_key()),
        receiver.parse().unwrap(),
        amount_centi,
        None,
        0,
        now,
        now + 86_400,
    );
    let tx_id = hex(&p.id.to_bytes());
    let signed = SignedProposal::sign(p, &kp);
    let frame = rrn_station::rpc_envelope::frame_signed_record(
        &rrn_crypto::serialize::to_canonical_bytes(signed.payload.clone()),
        &signed.signer,
        &signed.signature,
    );
    let client = rrn_station::channel_client::ChannelClient::new(
        h.url.clone(),
        *h.station_addr.parse::<Address>().unwrap().public_key(),
    );
    let nonce = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64)
        + 1_000;
    client
        .call(
            &kp,
            "submit_proposal",
            &serde_json::json!({ "signed_proposal": hex(&frame) }),
            nonce,
            now,
        )
        .await
        .expect("the station admits the hand-signed proposal");
    tx_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_shows_payment_request_and_requires_accept_debit() {
    // B sends A a −5.00 proposal: a payment *request*, which debits whoever
    // confirms it (ADR-0018). "Confirm this id, I paid you" must not get A to
    // sign a debit unseen.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_b, b) = init_wallet(dir.path(), "b", &h.station_addr).await;
    pair_and_confirm(&h, &home_a, &a).await;
    pair_and_confirm(&h, &home_b, &b).await;
    wjson(&home_a, &["sync"]).await;
    let tx_id = submit_hand_signed(&h, &home_b, &a, -500).await;

    let stderr = wfail(&home_a, Some(PASS), &["confirm", &tx_id]).await;
    assert!(stderr.contains("you would PAY 5.00"), "got: {stderr}");
    assert!(stderr.contains("--accept-debit"), "got: {stderr}");
    assert_eq!(pending_rows(&home_a, &a), 0, "nothing was signed");

    let confirmed = wjson(&home_a, &["confirm", &tx_id, "--accept-debit"]).await;
    assert_eq!(confirmed["direction"], "you-pay");
    assert_eq!(confirmed["proposal_amount_centi"], -500);
    assert_eq!(confirmed["counterparty"], b.as_str());
    assert_eq!(pending_rows(&home_a, &a), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_refuses_a_proposal_not_addressed_to_you() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_c, c) = init_wallet(dir.path(), "c", &h.station_addr).await;
    pair_and_confirm(&h, &home_a, &a).await;
    pair_and_confirm(&h, &home_c, &c).await;
    wjson(&home_a, &["sync"]).await;
    wjson(&home_c, &["sync"]).await;
    // A pays the station; C is shown the id and told to confirm it.
    let paid = wjson(&home_a, &["pay", &h.station_addr, "1.00"]).await;
    let tx_id = paid["tx_id"].as_str().unwrap().to_string();
    wjson(&home_a, &["submit"]).await;

    let stderr = wfail(&home_c, Some(PASS), &["confirm", &tx_id]).await;
    assert!(stderr.contains("not addressed to you"), "got: {stderr}");
    assert_eq!(pending_rows(&home_c, &c), 0);

    // An id the station does not serve is refused, not signed blind.
    let stderr = wfail(&home_c, Some(PASS), &["confirm", &"ab".repeat(32)]).await;
    assert!(stderr.contains("no servable record"), "got: {stderr}");
    assert_eq!(pending_rows(&home_c, &c), 0);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_from_carried_bundle_offline() {
    // B pays A offline and prints the QR sheet; A — never paired — confirms
    // straight from the sheet.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_b, b) = init_wallet(dir.path(), "b", &h.station_addr).await;
    let paid = wjson(&home_b, &["pay", &a, "2.50", "--memo", "eggs"]).await;
    let tx_id = paid["tx_id"].as_str().unwrap().to_string();
    let out = dir.path().join("sheet");
    wjson(&home_b, &["export", "qr", "--out", out.to_str().unwrap()]).await;
    let sheet = out.join("bundle.txt");
    let sheet = sheet.to_str().unwrap();

    // A bundle needs the id; a wrong id is not in it.
    let stderr = wfail(&home_a, Some(PASS), &["confirm", "--from", sheet]).await;
    assert!(stderr.contains("give the transaction id"), "got: {stderr}");
    let stderr = wfail(
        &home_a,
        Some(PASS),
        &["confirm", &"cd".repeat(32), "--from", sheet],
    )
    .await;
    assert!(stderr.contains("has no record"), "got: {stderr}");

    let confirmed = wjson(&home_a, &["confirm", &tx_id, "--from", sheet]).await;
    assert_eq!(confirmed["tx_id"], tx_id.as_str());
    assert_eq!(confirmed["direction"], "you-receive");
    assert_eq!(confirmed["proposal_amount_centi"], 250);
    assert_eq!(confirmed["counterparty"], b.as_str());
    assert_eq!(pending_rows(&home_a, &a), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn confirm_from_voucher_runs_the_receiver_ritual() {
    // B holds a certificate and pays C offline with a voucher. A, handed the
    // voucher, is refused by the receiver's check; C confirms from it.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home_a, a) = init_wallet(dir.path(), "a", &h.station_addr).await;
    let (home_b, b) = init_wallet(dir.path(), "b", &h.station_addr).await;
    let (home_c, c) = init_wallet(dir.path(), "c", &h.station_addr).await;
    pair_and_confirm(&h, &home_b, &b).await;
    wjson(&home_b, &["sync"]).await;
    let issued = wjson(&home_b, &["cert", "request", "5"]).await;
    let cert_id = issued["cert_id"].as_str().unwrap().to_string();
    let voucher = dir.path().join("voucher.txt");
    let paid = wjson(
        &home_b,
        &[
            "pay",
            &c,
            "2.00",
            "--cert",
            &cert_id,
            "--voucher-out",
            voucher.to_str().unwrap(),
        ],
    )
    .await;
    let tx_id = paid["tx_id"].as_str().unwrap().to_string();
    let voucher = voucher.to_str().unwrap();

    let stderr = wfail(&home_a, Some(PASS), &["confirm", "--from", voucher]).await;
    assert!(stderr.contains("wrong-receiver"), "got: {stderr}");
    assert_eq!(pending_rows(&home_a, &a), 0);

    let confirmed = wjson(&home_c, &["confirm", "--from", voucher]).await;
    assert_eq!(confirmed["tx_id"], tx_id.as_str());
    assert_eq!(confirmed["direction"], "you-receive");
    assert_eq!(pending_rows(&home_c, &c), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandon_refuses_a_proposal() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    let (home, member) = init_wallet(dir.path(), "w", &h.station_addr).await;
    pair_and_confirm(&h, &home, &member).await;
    wjson(&home, &["sync"]).await;
    wjson(&home, &["pay", &h.station_addr, "1"]).await;
    let shown = wjson(&home, &["show", "--pending"]).await;
    let record_hash = shown["rows"][0]["record_hash"]
        .as_str()
        .unwrap()
        .to_string();

    let stderr = wfail(&home, Some(PASS), &["abandon", &record_hash]).await;
    assert!(
        stderr.contains("a proposal cannot be abandoned"),
        "got: {stderr}"
    );
    let stderr = wfail(&home, Some(PASS), &["abandon", &record_hash[..6]]).await;
    assert!(stderr.contains("at least 8 hex"), "got: {stderr}");
    let stderr = wfail(&home, Some(PASS), &["abandon", "0123456789abcdef"]).await;
    assert!(stderr.contains("no outbox record matches"), "got: {stderr}");
    assert_eq!(
        pending_rows(&home, &member),
        1,
        "the proposal is still pending"
    );
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_into_gap_still_admits_and_warns() {
    // The station has seen an entry ahead of a gap (position 3, 0..2 absent). A
    // wallet restored onto that key re-anchors at the highest seen, warns about
    // the hole, resumes at position 4, and its next record still admits.
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();

    // A known member key, written into a backup wallet file we can restore.
    let m = Keypair::generate();
    let m_addr = Address::from_public_key(m.public_key());
    let mut metadata = BTreeMap::new();
    metadata.insert("role".to_string(), "member".to_string());
    metadata.insert("schema".to_string(), "1".to_string());
    let contents = WalletContents {
        secret_key: m.secret_key().clone(),
        address: m_addr,
        created_at: now_secs(),
        metadata,
    };
    let backup = dir.path().join("backup.rrnwallet");
    contents.save_to_file(&backup, PASS).unwrap();

    // Seed the station with the member's entry at position 3 (a gap below it).
    let now = now_secs();
    let prop = SignedProposal::sign(
        TransactionProposal::new(
            m_addr,
            h.station_addr.parse().unwrap(),
            100,
            None,
            0,
            now,
            now + 100_000,
        ),
        &m,
    );
    let entry = OutboxEntry::wrapping(m_addr, 3, Hash::from_bytes([9u8; 32]), &prop, now);
    let signed_entry = SignedPayload::sign(entry, &m);
    let bundle = Bundle::new(vec![EntryEnvelope::from_signed(&signed_entry)], now).encode();
    socket_call(
        &h.client(),
        "bundle_submit",
        serde_json::json!({ "bundle_hex": hex(&bundle) }),
    )
    .await;

    // Restore onto that key and sync: re-anchors at the highest seen (3), warns.
    let home = dir.path().join("w");
    wjson(
        &home,
        &[
            "init",
            "--station",
            &h.station_addr,
            "--restore",
            backup.to_str().unwrap(),
        ],
    )
    .await;
    pair_and_confirm(&h, &home, &m_addr.to_string()).await;
    let synced = wjson(&home, &["sync"]).await;
    assert_eq!(synced["chain_state"], "anchored");
    assert!(
        synced["hole"].is_object(),
        "a hole below the head is reported"
    );

    // A pay resumes at position 4 and admits.
    wjson(&home, &["pay", &h.station_addr, "1.00"]).await;
    let submitted = wjson(&home, &["submit"]).await;
    assert_eq!(submitted["applied"].as_u64().unwrap(), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paper_module_stays_keyless() {
    // The paper courier tools hold no key and open no database: the source must
    // not import the wallet module or rrn-storage. This pins the ADR-0028
    // one-directional contract cheaply.
    let src = include_str!("../../src/paper.rs");
    assert!(
        !src.contains("use crate::wallet"),
        "paper.rs must not import the wallet module"
    );
    assert!(
        !src.contains("rrn_storage"),
        "paper.rs must not use rrn-storage"
    );
}

// --- recovery ceremony ------------------------------------------------------

/// Drives `rrn wallet recover` end to end: spawns the process, captures the
/// `rrnrecover-req:` request line it prints (on stderr), asks `responder` for the
/// holder response lines to feed, writes them on stdin, and returns
/// `(success, stdout, stderr)`. `responder` runs on the parsed request so the
/// simulated holders seal to the process's own ephemeral key.
fn run_recover(
    home: &Path,
    pass: &str,
    station: &str,
    address: &str,
    force: bool,
    responder: impl FnOnce(&RecoveryRequest) -> Vec<String>,
) -> (bool, String, String) {
    use std::io::{BufRead, BufReader, Write};

    let mut args = vec![
        "--format",
        "json",
        "wallet",
        "--home",
        home.to_str().unwrap(),
        "recover",
        "--station",
        station,
        "--address",
        address,
    ];
    if force {
        args.push("--force");
    }
    let mut child = Command::new(RRN)
        .args(&args)
        .env("RRN_WALLET_PASSPHRASE", pass)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rrn wallet recover");

    // Drain stdout on its own thread so the child never blocks writing the QR.
    let mut stdout = child.stdout.take().unwrap();
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut buf).ok();
        buf
    });

    // Drain stderr fully on its own thread (so the child never blocks writing
    // guidance), forwarding the first `rrnrecover-req:` line back over a channel.
    let stderr = child.stderr.take().unwrap();
    let (req_tx, req_rx) = std::sync::mpsc::channel::<String>();
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut sent = false;
        for line in BufReader::new(stderr).lines() {
            let line = line.unwrap_or_default();
            if !sent {
                if let Some(idx) = line.find(rrn_station::recovery::REQUEST_QR_PREFIX) {
                    req_tx.send(line[idx..].to_string()).ok();
                    sent = true;
                }
            }
            buf.push_str(&line);
            buf.push('\n');
        }
        buf
    });

    // Wait for the request line (or the channel to close if the process bailed
    // before printing one), then feed the holder responses on stdin.
    let mut stdin = child.stdin.take().unwrap();
    if let Ok(req_line) = req_rx.recv() {
        let bytes = rrn_station::recovery::decode_request_line(&req_line).unwrap();
        let request = RecoveryRequest::from_bytes(&bytes).unwrap();
        for resp in responder(&request) {
            writeln!(stdin, "{resp}").unwrap();
        }
        writeln!(stdin).unwrap(); // blank line ends input
        stdin.flush().ok();
    }
    drop(stdin); // EOF, in case the process never asked for input

    let status = child.wait().expect("wait recover");
    let stderr_buf = stderr_thread.join().unwrap();
    let stdout = stdout_thread.join().unwrap();
    (status.success(), stdout, stderr_buf)
}

/// The last JSON object printed on stdout (the emitted result), if any.
fn last_json_line(stdout: &str) -> Option<serde_json::Value> {
    stdout
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_recover_from_circle() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();

    // The lost identity, split 2-of-3 across three holders (driven through
    // rrn-identity directly — the CLI wallet has no circle command).
    let lost = WalletContents::create_new();
    let lost_kp = Keypair::from_secret(lost.secret_key.clone());
    let lost_addr = lost.address.to_string();

    // Seed the station with one entry for this key (position 0) so a post-recovery
    // sync finds a record to re-anchor onto — the no-self-fork rule keeps a
    // never-seen key `unknown` forever (proven separately), which is not what we
    // are testing here.
    let now = now_secs();
    let prop = SignedProposal::sign(
        TransactionProposal::new(
            lost.address,
            h.station_addr.parse().unwrap(),
            100,
            None,
            0,
            now,
            now + 100_000,
        ),
        &lost_kp,
    );
    let entry = OutboxEntry::wrapping(lost.address, 0, Hash::from_bytes([1u8; 32]), &prop, now);
    let signed_entry = SignedPayload::sign(entry, &lost_kp);
    let bundle = Bundle::new(vec![EntryEnvelope::from_signed(&signed_entry)], now).encode();
    socket_call(
        &h.client(),
        "bundle_submit",
        serde_json::json!({ "bundle_hex": hex(&bundle) }),
    )
    .await;

    let holders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    let holder_pubs: Vec<_> = holders.iter().map(|k| k.public_key()).collect();
    let package = RecoveryPackage::create(&lost, &holder_pubs, 2).unwrap();
    let payloads: Vec<Vec<u8>> = (0..3).map(|i| package.shard_payload(i).unwrap()).collect();

    // Two responses (K=2) rebuild the key. The responder seals to the process's
    // own ephemeral request.
    let holders_for = holders;
    let payloads_for = payloads.clone();
    let home = dir.path().join("recovered");
    let station = h.station_addr.clone();
    let lost_for = lost_addr.clone();
    let (ok, stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_recover(&home, PASS, &station, &lost_for, false, |req| {
            [0usize, 2]
                .iter()
                .map(|&i| {
                    let resp = ceremony::build_response(
                        &payloads_for[i],
                        holders_for[i].secret_key(),
                        req,
                    )
                    .unwrap();
                    rrn_station::recovery::encode_response(&resp)
                })
                .collect()
        })
    })
    .await
    .unwrap();

    assert!(ok, "recover failed: {stderr}");
    let result = last_json_line(&stdout).expect("recover emits a JSON result");
    assert_eq!(result["address"].as_str().unwrap(), lost_addr);
    assert_eq!(result["chain_state"], "unknown");

    // The home now holds the recovered identity, reported as restored/unanchored.
    let home = dir.path().join("recovered");
    let status = wjson(&home, &["status"]).await;
    assert_eq!(status["address"].as_str().unwrap(), lost_addr);
    assert_eq!(status["chain_state"], "unknown");

    // Signing is refused until a sync re-anchors the recovered chain...
    let stderr = wfail(&home, Some(PASS), &["pay", &h.station_addr, "1"]).await;
    assert!(stderr.contains("re-anchor"), "got: {stderr}");

    // ...and after pairing + sync (which re-anchors onto the seeded record), a
    // pay admits at the next position.
    pair_and_confirm(&h, &home, &lost_addr).await;
    let synced = wjson(&home, &["sync"]).await;
    assert_eq!(synced["chain_state"], "anchored");
    assert!(synced["reanchored"].as_bool().unwrap());
    wjson(&home, &["pay", &h.station_addr, "1.00"]).await;
    let submitted = wjson(&home, &["submit"]).await;
    assert_eq!(submitted["applied"].as_u64().unwrap(), 1);
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_recover_below_threshold_writes_nothing() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();

    let lost = WalletContents::create_new();
    let lost_addr = lost.address.to_string();
    let holders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    let holder_pubs: Vec<_> = holders.iter().map(|k| k.public_key()).collect();
    let package = RecoveryPackage::create(&lost, &holder_pubs, 3).unwrap(); // K=3
    let payloads: Vec<Vec<u8>> = (0..3).map(|i| package.shard_payload(i).unwrap()).collect();

    // Only two responses for a 3-of-3 split.
    let home = dir.path().join("recovered");
    let home_check = home.clone();
    let station = h.station_addr.clone();
    let lost_for = lost_addr.clone();
    let holders_for = holders;
    let payloads_for = payloads;
    let (ok, _stdout, _stderr) = tokio::task::spawn_blocking(move || {
        run_recover(&home, PASS, &station, &lost_for, false, |req| {
            [0usize, 1]
                .iter()
                .map(|&i| {
                    let resp = ceremony::build_response(
                        &payloads_for[i],
                        holders_for[i].secret_key(),
                        req,
                    )
                    .unwrap();
                    rrn_station::recovery::encode_response(&resp)
                })
                .collect()
        })
    })
    .await
    .unwrap();

    assert!(!ok, "recover below threshold must fail");
    // No wallet was written.
    assert!(
        !home_check.join("member.rrnwallet").exists(),
        "a failed recover must not write a wallet"
    );
    assert!(
        !home_check.join("wallet.db").exists(),
        "a failed recover must not create the db"
    );
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_recover_refuses_existing_home_without_force() {
    let h = Harness::start(false).await;
    let dir = tempfile::tempdir().unwrap();
    // A fully initialised home already exists.
    let (home, _member) = init_wallet(dir.path(), "existing", &h.station_addr).await;

    let target = Address::from_public_key(Keypair::generate().public_key()).to_string();
    let home_for = home.clone();
    let station = h.station_addr.clone();
    let (ok, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        // No request will ever be printed — the home check bails first — so the
        // responder is never called.
        run_recover(&home_for, PASS, &station, &target, false, |_req| Vec::new())
    })
    .await
    .unwrap();

    assert!(
        !ok,
        "recover into a non-empty home must refuse without --force"
    );
    assert!(stderr.contains("not empty"), "got: {stderr}");
    h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_recover_refuses_a_station_dir_even_with_force() {
    // --force overrides the member-file guard, but NOT the station-data-dir
    // refusal: recovering into a live station's dir must fail before any ceremony.
    let h = Harness::start(false).await;
    let station_dir = h.station_data_dir();
    let target = Address::from_public_key(Keypair::generate().public_key()).to_string();
    let station = h.station_addr.clone();
    let (ok, _stdout, stderr) = tokio::task::spawn_blocking(move || {
        run_recover(&station_dir, PASS, &station, &target, true, |_req| {
            Vec::new()
        })
    })
    .await
    .unwrap();

    assert!(
        !ok,
        "recover into a station data dir must refuse even with --force"
    );
    assert!(stderr.contains("station data directory"), "got: {stderr}");
    h.shutdown().await;
}

// --- helpers that reach into the station's on-disk state --------------------

impl Harness {
    fn station_data_dir(&self) -> PathBuf {
        // The socket lives in the data dir.
        self.socket.parent().unwrap().to_path_buf()
    }
}

/// Whether the station recorded an outbox fork for `member` at any position.
fn station_recorded_fork(station_dir: &Path, member: &str) -> bool {
    let db = Database::open(&station_dir.join("station.db")).unwrap();
    let author = member.parse::<Address>().unwrap().public_key().to_bytes();
    let dtn = rrn_storage::dtn::DtnStore::new(&db);
    // A fork, if any, sits at some position below the highest seen; scan a small
    // range (the tests never build long chains).
    (0..16).any(|pos| dtn.fork_at(&author, pos).unwrap().is_some())
}

/// Runs `rrn --socket S --format json paper <args>`.
fn run_paper(socket: &str, args: &[&str]) -> serde_json::Value {
    let out = Command::new(RRN)
        .arg("--socket")
        .arg(socket)
        .arg("--format")
        .arg("json")
        .arg("paper")
        .args(args)
        .output()
        .expect("spawn rrn paper");
    assert!(
        out.status.success(),
        "rrn paper {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    rrn_station::core::hex(bytes)
}
