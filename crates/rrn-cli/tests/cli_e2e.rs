//! CLI acceptance (T0.6.4): the real `rrn` binary against a live daemon.
//!
//! The daemon runs in-process (an `rrn_station::Station`); the CLI is the
//! actually-built `rrn` binary, invoked over the station's socket. Each
//! subcommand is exercised, and every command is checked to emit valid one-line
//! JSON under `--format json`.

use std::path::Path;
use std::process::Command;

use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

const PASSPHRASE: &str = "cli-e2e";
const RRN: &str = env!("CARGO_BIN_EXE_rrn");

fn write_config(dir: &Path, port: u16) {
    let text = format!(
        "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{port}\"\n\n\
         [settlement]\nwindow_seconds = 1\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// Runs `rrn --socket <socket> [extra args...]` and returns trimmed stdout,
/// asserting success.
fn rrn(socket: &Path, args: &[&str]) -> String {
    let output = Command::new(RRN)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("spawn rrn");
    assert!(
        output.status.success(),
        "rrn {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .trim_end()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_drives_daemon() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_config(dir.path(), 7457);

    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::manual(1_000),
    })
    .await
    .unwrap();
    let socket = station.socket_path().to_path_buf();

    // Run blocking CLI invocations off the reactor.
    let result = tokio::task::spawn_blocking(move || {
        // whoami (text) → an rrn1 address.
        let me = rrn(&socket, &["whoami"]);
        assert!(me.starts_with("rrn1"), "whoami: {me}");

        // whoami (json) → valid JSON with the same address.
        let j = rrn(&socket, &["--format", "json", "whoami"]);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["address"], me);

        // balance (text) → "0.00 Commons" initially.
        assert_eq!(rrn(&socket, &["balance"]), "0.00 Commons");
        // balance (json) parses.
        let j = rrn(&socket, &["--format", "json", "balance"]);
        let _: serde_json::Value = serde_json::from_str(&j).expect("valid json");

        // pay to self (sender == receiver nets to zero), then confirm.
        let tx = rrn(&socket, &["pay", &me, "1.50"]);
        assert_eq!(tx.len(), 64, "tx id should be 32-byte hex: {tx}");
        assert_eq!(rrn(&socket, &["confirm", &tx]), "Confirmed");

        // history (text) has rows; (json) is a valid array of entries.
        let h = rrn(&socket, &["history"]);
        assert!(h.contains("proposal"), "history text: {h}");
        let j = rrn(&socket, &["--format", "json", "history"]);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert!(v["entries"].is_array());

        // vouch (json) returns a vouch_id.
        let j = rrn(
            &socket,
            &["--format", "json", "vouch", &me, "--statement", "self"],
        );
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert!(v["vouch_id"].as_str().unwrap().len() == 64);

        // init prints guidance and exits 0 (no daemon contact).
        let out = Command::new(RRN).arg("init").output().unwrap();
        assert!(out.status.success());
    })
    .await;

    station.shutdown().await;
    result.unwrap();
}
