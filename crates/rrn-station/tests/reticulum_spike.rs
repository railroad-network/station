//! Reticulum integration spike — T2.6.1 (ADR-0013), the Phase-2 spike ADR-0013
//! chartered.
//!
//! This is a **non-hermetic, `#[ignore]`-by-default** lane: it needs a pinned
//! `rnsd` (the Python Reticulum daemon) plus `LXMF` on the machine, so it is
//! excluded from the default `cargo test` gate and run explicitly with
//! `cargo test -- --ignored` in the `reticulum-spike` CI job (which installs the
//! pin). It is not a unit test of station code — the supervisor's own behavior is
//! covered hermetically in `sidecar.rs` against a fake `rnsd`. This proves the
//! *adoption thesis* end to end: a real signed [`Bundle`] crosses two supervised
//! `rnsd` instances over Reticulum/LXMF, byte-identically, **with the receiver
//! started only after the send is already in flight** — path request → later
//! announce → path discovery → direct delivery. That is delay-tolerant delivery
//! to an initially-absent receiver; the payload is held (by the sender helper's
//! own poll loop) until a path appears. Full LXMF-layer store-and-forward through
//! a propagation node — where the message survives with *neither* endpoint
//! online — is a T2.6.2 follow-up (see ADR-0026 §5).
//!
//! ## Running it
//!
//! ```sh
//! python3 -m venv /tmp/rns && /tmp/rns/bin/pip install rns==1.5.2 lxmf==1.1.1
//! RRN_SPIKE_RNSD=/tmp/rns/bin/rnsd RRN_SPIKE_PYTHON=/tmp/rns/bin/python \
//!   cargo test -p rrn-station --test reticulum_spike -- --ignored --nocapture
//! ```
//!
//! `RRN_SPIKE_RNSD` / `RRN_SPIKE_PYTHON` default to `rnsd` / `python3` on `PATH`.
//! Pinned + verified against `rns` 1.5.2 / `lxmf` 1.1.1 (PyPI, 2026-08).
//!
//! ## What it does NOT do
//!
//! No radio (T2.6.3), no `FrameTransport` impl (T2.6.2). The bytes move over a
//! local TCP interface between the two `rnsd`s; Reticulum is exercised as the
//! carrier, exactly as ADR-0013 frames it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use dcbor::CBOR;
use tokio::process::Command;
use tokio::sync::watch;

use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::OutboxEntry;
use rrn_station::gossip::ConnectivityState;
use rrn_station::rpc_client::UnixClient;
use rrn_station::sidecar::{self, SidecarConfig};
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

/// A tiny signed inner record so the spike carries a *real* signed `Bundle`, not
/// an opaque blob — the same shape the DTN path moves in production.
#[derive(Clone)]
struct SpikeRecord {
    n: u64,
}
impl From<SpikeRecord> for CBOR {
    fn from(r: SpikeRecord) -> Self {
        let mut m = dcbor::Map::new();
        m.insert("kind", "rrn.test.spike");
        m.insert("n", r.n);
        m.into()
    }
}

/// Builds a real signed bundle of `len` chained outbox entries for one device.
fn build_bundle(len: u64) -> Bundle {
    let device = Keypair::generate();
    let author = Address::from_public_key(device.public_key());
    // The "no previous" sentinel for the first entry is the all-zero hash.
    let mut prev = rrn_crypto::hash::Hash::from_bytes([0u8; 32]);
    let mut envelopes = Vec::new();
    for pos in 0..len {
        let record = SignedPayload::sign(SpikeRecord { n: pos }, &device);
        let entry = OutboxEntry::wrapping(author, pos, prev, &record, 1_700_000_000 + pos as i64);
        prev = entry.entry_hash();
        let signed = SignedPayload::sign(entry, &device);
        envelopes.push(EntryEnvelope::from_signed(&signed));
    }
    Bundle::new(envelopes, 1_700_000_900)
}

fn rnsd_bin() -> String {
    std::env::var("RRN_SPIKE_RNSD").unwrap_or_else(|_| "rnsd".to_string())
}
fn python_bin() -> String {
    std::env::var("RRN_SPIKE_PYTHON").unwrap_or_else(|_| "python3".to_string())
}
fn helper_script() -> PathBuf {
    // crates/rrn-station/ -> repo root -> scripts/spike/lxmf_pingpong.py
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/spike/lxmf_pingpong.py")
}

/// Writes a Reticulum config for one spike node. Two `rnsd` share this host, so
/// each needs a distinct shared-instance identity — hence the explicit
/// `instance_name` / `shared_instance_port` (the production template in
/// `sidecar.rs` runs one node per host and keeps the RNS defaults).
fn write_spike_config(dir: &Path, node: &str, iface: &str, shared_port: u16) {
    std::fs::create_dir_all(dir).unwrap();
    let cfg = format!(
        "[reticulum]\n  \
         enable_transport = Yes\n  \
         share_instance = Yes\n  \
         shared_instance_type = tcp\n  \
         shared_instance_port = {shared}\n  \
         instance_control_port = {control}\n  \
         instance_name = rrn-spike-{node}\n\n\
         [logging]\n  loglevel = 4\n\n\
         [interfaces]\n\n{iface}\n",
        shared = shared_port,
        control = shared_port + 1,
    );
    std::fs::write(dir.join(sidecar::RETICULUM_CONFIG_FILE), cfg).unwrap();
}

/// One booted, station-supervised `rnsd`: the shared connectivity state (so the
/// test can assert it actually reached `Running`), its shutdown sender, and the
/// supervisor task.
struct Node {
    state: Arc<ConnectivityState>,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

/// Boots one supervised `rnsd` on a pre-written config dir. Pins to `1.5` with
/// **drift disallowed**, so the CI lane validates the pin parser against real
/// `rnsd --version` output — a mismatch degrades the sidecar, and the test then
/// fails at the `Running` assertion rather than passing vacuously.
fn boot_rnsd(config_dir: PathBuf) -> Node {
    let cfg = SidecarConfig {
        rnsd_path: PathBuf::from(rnsd_bin()),
        config_dir,
        pinned_version: "1.5".to_string(),
        allow_version_drift: false,
        restart_backoff: Duration::from_secs(1),
        tcp_listen: None, // config is pre-written; supervisor must not regenerate
        tcp_peers: vec![],
        shutdown_grace: Duration::from_secs(5),
    };
    let state = Arc::new(ConnectivityState::new(vec![], "127.0.0.1:0".into(), false));
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(sidecar::supervise(cfg, state.clone(), rx));
    Node {
        state,
        shutdown,
        task,
    }
}

/// Blocks until the node's supervisor reports `Running`, failing the test if it
/// degrades or does not come up — so a spike that never actually supervised
/// `rnsd` cannot pass.
async fn await_running(node: &Node, which: &str) {
    let start = std::time::Instant::now();
    loop {
        match node.state.sidecar_snapshot() {
            sidecar::SidecarState::Running { .. } => return,
            sidecar::SidecarState::Degraded { reason } => {
                panic!("node {which} sidecar degraded instead of running: {reason}")
            }
            other => {
                if start.elapsed() > Duration::from_secs(20) {
                    panic!("node {which} sidecar never reached Running (last: {other:?})");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn run_helper(args: &[&str]) -> std::process::Output {
    Command::new(python_bin())
        .arg(helper_script())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn spike helper")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "non-hermetic: needs pinned rnsd + lxmf; run in the reticulum-spike CI lane"]
async fn signed_bundle_survives_reticulum_delivery_to_a_late_receiver() {
    let work = tempfile::tempdir().unwrap();
    let dir = work.path();

    // A real signed bundle, and its canonical bytes as the opaque LXMF payload.
    let bundle = build_bundle(3);
    let payload = bundle.encode();
    let payload_path = dir.join("bundle.cbor");
    std::fs::write(&payload_path, &payload).unwrap();

    // Persisted identities. Compute the receiver's LXMF hash offline, so the
    // sender can be launched *before the receiver exists* and hold the payload
    // (in the helper's own poll loop) until the receiver announces a path.
    let recv_id = dir.join("recv.identity");
    let send_id = dir.join("send.identity");
    let hash_out = run_helper(&["hash", "--identity", recv_id.to_str().unwrap()]).await;
    assert!(
        hash_out.status.success(),
        "hash role failed: {}",
        String::from_utf8_lossy(&hash_out.stderr)
    );
    let recv_hash = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();
    assert_eq!(recv_hash.len(), 32, "expected a 16-byte dest hash hex");

    // Two config dirs: A (sender) runs a TCP server; B (receiver) dials it.
    let dir_a = dir.join("node-a");
    let dir_b = dir.join("node-b");
    let link_port = free_port();
    write_spike_config(
        &dir_a,
        "a",
        &format!(
            "  [[Spike TCP Server]]\n    type = TCPServerInterface\n    \
             interface_enabled = True\n    listen_ip = 127.0.0.1\n    listen_port = {link_port}",
        ),
        37428,
    );
    write_spike_config(
        &dir_b,
        "b",
        &format!(
            "  [[Spike TCP Client]]\n    type = TCPClientInterface\n    \
             interface_enabled = True\n    target_host = 127.0.0.1\n    target_port = {link_port}",
        ),
        37430,
    );

    // Boot both supervised rnsd instances and require each to actually reach
    // Running before the helpers attach — otherwise the helpers would become the
    // RNS instances themselves and the spike would pass without a supervised
    // rnsd (require_shared_instance in the helper is the second guard).
    let node_a = boot_rnsd(dir_a.clone());
    let node_b = boot_rnsd(dir_b.clone());
    await_running(&node_a, "a").await;
    await_running(&node_b, "b").await;
    // Give the TCP link between the two rnsd instances a moment to form.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Sender goes first, addressing a receiver that is not up yet — the helper
    // holds and retries until the receiver announces a path.
    let script = helper_script();
    let py = python_bin();
    let send_dir = dir_a.clone();
    let send = tokio::spawn(async move {
        Command::new(&py)
            .arg(&script)
            .args([
                "send",
                "--config",
                send_dir.to_str().unwrap(),
                "--storage",
                send_dir.join("lxmf").to_str().unwrap(),
                "--identity",
                send_id.to_str().unwrap(),
                "--peer",
                &recv_hash,
                "--payload",
                payload_path.to_str().unwrap(),
                "--timeout",
                "90",
            ])
            .output()
            .await
            .expect("spawn send")
    });

    // Receiver starts *after* the send is already outstanding.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let recv_out = dir.join("received.cbor");
    let recv_dir = dir_b.clone();
    let (py2, script2) = (python_bin(), helper_script());
    let recv_out2 = recv_out.clone();
    let recv_id2 = recv_id.clone();
    let recv = tokio::spawn(async move {
        Command::new(&py2)
            .arg(&script2)
            .args([
                "recv",
                "--config",
                recv_dir.to_str().unwrap(),
                "--storage",
                recv_dir.join("lxmf").to_str().unwrap(),
                "--identity",
                recv_id2.to_str().unwrap(),
                "--out",
                recv_out2.to_str().unwrap(),
                "--timeout",
                "90",
            ])
            .output()
            .await
            .expect("spawn recv")
    });

    let send_res = tokio::time::timeout(Duration::from_secs(120), send)
        .await
        .expect("send did not finish in time")
        .unwrap();
    let recv_res = tokio::time::timeout(Duration::from_secs(120), recv)
        .await
        .expect("recv did not finish in time")
        .unwrap();

    // Tear the sidecars down before asserting, so a failure still cleans up.
    let _ = node_a.shutdown.send(true);
    let _ = node_b.shutdown.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(15), node_a.task).await;
    let _ = tokio::time::timeout(Duration::from_secs(15), node_b.task).await;

    assert!(
        send_res.status.success(),
        "send failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&send_res.stdout),
        String::from_utf8_lossy(&send_res.stderr)
    );
    assert!(
        recv_res.status.success(),
        "recv failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&recv_res.stdout),
        String::from_utf8_lossy(&recv_res.stderr)
    );

    // Byte-identical delivery, and the bytes still decode as the same bundle.
    let received = std::fs::read(&recv_out).expect("receiver wrote the payload");
    assert_eq!(received, payload, "LXMF delivered non-identical bytes");
    let decoded = Bundle::decode(&received).expect("received bytes decode as a Bundle");
    assert_eq!(decoded.bundle_id(), bundle.bundle_id());
}

/// Grabs a free localhost TCP port by binding an ephemeral one and releasing it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The production LXMF adapter the station spawns (`scripts/reticulum/lxmf_adapter.py`).
fn adapter_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/reticulum/lxmf_adapter.py")
}

/// Writes a station `config.toml` that supervises `rnsd` against a **pre-written**
/// Reticulum config dir and runs the DTN transport over the production adapter.
fn write_station_config(data_dir: &Path, reticulum_dir: &Path) {
    let text = format!(
        "[network]\nlisten = \"127.0.0.1:0\"\n\n\
         [mobile]\nlisten = \"127.0.0.1:0\"\nadvertise = false\n\n\
         [sidecar]\n\
         enabled = true\n\
         rnsd_path = \"{rnsd}\"\n\
         config_dir = \"{cfg}\"\n\
         pinned_version = \"1.5\"\n\n\
         [lora]\n\
         adapter_script = \"{adapter}\"\n\
         adapter_python = \"{python}\"\n\
         frame_bytes = 400\n\
         push_rescan_secs = 15\n",
        rnsd = rnsd_bin(),
        cfg = reticulum_dir.display(),
        adapter = adapter_script().display(),
        python = python_bin(),
    );
    std::fs::write(data_dir.join("config.toml"), text).unwrap();
}

/// T2.6.4: originate → ingest → receipt → delivered over two **real** supervised
/// `rnsd` instances on local TCP, through the **production** path (RPC → outbound
/// channel → `run_dtn_syncer` → LXMF adapter). The first end-to-end exercise of a
/// station *originating* an outbound DTN push over a real Reticulum instance
/// (still TCP, not radio — radio is T2.6.3's human-gated field run).
///
/// Run it exactly like the T2.6.1 spike (same pinned venv), with:
/// ```sh
/// RRN_SPIKE_RNSD=/tmp/rns/bin/rnsd RRN_SPIKE_PYTHON=/tmp/rns/bin/python \
///   cargo test -p rrn-station --test reticulum_spike -- --ignored --nocapture \
///   originate_receipt_round_trip_over_two_real_rnsd
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "non-hermetic: needs pinned rnsd + lxmf; run in the reticulum-spike CI lane"]
async fn originate_receipt_round_trip_over_two_real_rnsd() {
    const PASSPHRASE: &str = "spike-passphrase";
    let work = tempfile::tempdir().unwrap();
    let dir = work.path();

    // Two station data dirs; each station's Reticulum config dir sits under it so
    // the adapter identity lands at <data>/reticulum/adapter.identity.
    let data_a = dir.join("station-a");
    let data_b = dir.join("station-b");
    std::fs::create_dir_all(&data_a).unwrap();
    std::fs::create_dir_all(&data_b).unwrap();
    let ret_a = data_a.join("reticulum");
    let ret_b = data_b.join("reticulum");

    // A serves a TCP link; B dials it. Distinct shared-instance ports (two nodes,
    // one host).
    let link_port = free_port();
    write_spike_config(
        &ret_a,
        "a",
        &format!(
            "  [[Spike TCP Server]]\n    type = TCPServerInterface\n    \
             interface_enabled = True\n    listen_ip = 127.0.0.1\n    listen_port = {link_port}",
        ),
        37428,
    );
    write_spike_config(
        &ret_b,
        "b",
        &format!(
            "  [[Spike TCP Client]]\n    type = TCPClientInterface\n    \
             interface_enabled = True\n    target_host = 127.0.0.1\n    target_port = {link_port}",
        ),
        37430,
    );

    // Compute B's adapter destination offline against the identity file B's adapter
    // will load on boot — creating it now, so we can address it before B is up.
    let b_identity = ret_b.join("adapter.identity");
    let hash_out = run_helper(&["hash", "--identity", b_identity.to_str().unwrap()]).await;
    assert!(
        hash_out.status.success(),
        "hash role failed: {}",
        String::from_utf8_lossy(&hash_out.stderr)
    );
    let b_hash = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();
    assert_eq!(b_hash.len(), 32, "expected a 16-byte dest hash hex");

    // Init wallets, then write the station configs (sidecar + adapter).
    Station::init(&data_a, PASSPHRASE).unwrap();
    Station::init(&data_b, PASSPHRASE).unwrap();
    write_station_config(&data_a, &ret_a);
    write_station_config(&data_b, &ret_b);

    // Boot both stations (each spawns its supervised rnsd + adapter + DTN loop).
    let clock = Clock::system();
    let station_a = Station::open(StationParams {
        data_dir: data_a.clone(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let station_b = Station::open(StationParams {
        data_dir: data_b.clone(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    // Give the sidecars + adapters time to come up and the TCP link to form.
    tokio::time::sleep(Duration::from_secs(8)).await;

    let client_a = UnixClient::new(station_a.socket_path());
    let bundle = build_bundle(2);
    let bundle_hex = hex_encode(&bundle.encode());

    // A originates the push to B's destination through the production RPC path.
    let queued = client_a
        .call(
            "dtn_push",
            serde_json::json!({ "bundle_hex": bundle_hex, "endpoint_hex": b_hash }),
        )
        .await
        .expect("dtn_push");
    assert_eq!(queued["queued"], true);
    let push_id = queued["push_id_hex"].as_str().unwrap().to_string();

    // Poll A's push status until the returned receipt flips it to delivered.
    let mut delivered = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(150) {
        let status = client_a
            .call("dtn_pushes", serde_json::json!({}))
            .await
            .unwrap();
        if let Some(rows) = status["pushes"].as_array() {
            if rows.iter().any(|p| {
                p["push_id_hex"] == serde_json::Value::String(push_id.clone())
                    && p["state"] == "delivered"
            }) {
                delivered = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    station_a.shutdown().await;
    station_b.shutdown().await;
    assert!(
        delivered,
        "A's push must flip to delivered once B's receipt returns over Reticulum"
    );
}

/// Lowercase hex of a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
