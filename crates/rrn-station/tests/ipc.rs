//! Daemon IPC acceptance (T0.6.3): a real station, raw socket lines.
//!
//! Connects to a running station's Unix socket and speaks the line-delimited
//! JSON protocol by hand to check the envelope contract: a known method
//! answers, an unknown method returns `-32601`, and a malformed line returns an
//! error *without* killing the daemon (a following valid request still works).

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

const PASSPHRASE: &str = "ipc-test";

/// Writes a config with a unique listen port and no peers.
fn write_config(dir: &Path, port: u16) {
    let text = format!(
        "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{port}\"\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// Sends one raw line and returns the one-line response.
async fn round_trip(socket: &Path, line: &str) -> String {
    let stream = UnixStream::connect(socket).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut msg = line.to_string();
    msg.push('\n');
    write_half.write_all(msg.as_bytes()).await.unwrap();
    write_half.flush().await.unwrap();

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut buf))
        .await
        .expect("response in time")
        .unwrap();
    buf.trim_end().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipc_envelope_contract() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_config(dir.path(), 7455);

    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap();
    let socket = station.socket_path().to_path_buf();

    // A valid `whoami` round-trips with the same id and an address result.
    let resp = round_trip(&socket, r#"{"id":"abc","method":"whoami","params":{}}"#).await;
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], "abc");
    assert!(v["result"]["address"].as_str().unwrap().starts_with("rrn1"));
    assert!(v["error"].is_null());

    // An unknown method → -32601.
    let resp = round_trip(&socket, r#"{"id":"x","method":"frobnicate","params":{}}"#).await;
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["error"]["code"], -32601);

    // A malformed line → error response, and the daemon stays up: a subsequent
    // valid request on a fresh connection still succeeds.
    let resp = round_trip(&socket, "this is not json").await;
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert!(
        v["error"]["code"].is_i64(),
        "expected an error envelope: {resp}"
    );

    let resp = round_trip(&socket, r#"{"id":"after","method":"whoami","params":{}}"#).await;
    let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["id"], "after");
    assert!(v["result"]["address"].as_str().unwrap().starts_with("rrn1"));

    station.shutdown().await;
}
