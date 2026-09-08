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
//! `rnsd` instances over Reticulum/LXMF, byte-identically, **including when the
//! receiver starts after the send** — the store-and-forward property the whole
//! Reticulum adoption is for (ADR-0013 §Consequences).
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
use rrn_station::sidecar::{self, SidecarConfig};

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

/// Boots one supervised `rnsd` on a pre-written config dir and returns its
/// shutdown sender + supervisor task.
fn boot_rnsd(config_dir: PathBuf) -> (watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let cfg = SidecarConfig {
        rnsd_path: PathBuf::from(rnsd_bin()),
        config_dir,
        pinned_version: "1.5".to_string(),
        allow_version_drift: true, // any 1.x rnsd is fine for the spike
        restart_backoff: Duration::from_secs(1),
        tcp_listen: None, // config is pre-written; supervisor must not regenerate
        tcp_peers: vec![],
    };
    let state = Arc::new(ConnectivityState::new(vec![], "127.0.0.1:0".into(), false));
    let (tx, rx) = watch::channel(false);
    let handle = tokio::spawn(sidecar::supervise(cfg, state, rx));
    (tx, handle)
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
async fn signed_bundle_survives_reticulum_lxmf_store_and_forward() {
    let work = tempfile::tempdir().unwrap();
    let dir = work.path();

    // A real signed bundle, and its canonical bytes as the opaque LXMF payload.
    let bundle = build_bundle(3);
    let payload = bundle.encode();
    let payload_path = dir.join("bundle.cbor");
    std::fs::write(&payload_path, &payload).unwrap();

    // Persisted identities. Compute the receiver's LXMF hash offline, so the
    // sender can address it *before it starts* (the store-and-forward case).
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

    // Boot both supervised rnsd instances; give the TCP link a moment to form.
    let (tx_a, task_a) = boot_rnsd(dir_a.clone());
    let (tx_b, task_b) = boot_rnsd(dir_b.clone());
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Sender goes first, addressing a receiver that is not up yet — LXMF holds
    // and retries the message.
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
    let _ = tx_a.send(true);
    let _ = tx_b.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(15), task_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(15), task_b).await;

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
