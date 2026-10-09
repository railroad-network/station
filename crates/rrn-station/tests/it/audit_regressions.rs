//! Regression tests for findings of the October 2026 internal security audit
//! (`docs/security/audit-2026-10.md`), each driven against a real station over
//! its real network surfaces.
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

const PASSPHRASE: &str = "audit-regressions";

async fn http_post_json(addr: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, body.to_string())
}

async fn rpc(socket: &Path, method: &str, params: serde_json::Value) -> String {
    let line = serde_json::json!({ "id": "t", "method": method, "params": params }).to_string();
    let stream = UnixStream::connect(socket).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(line.as_bytes()).await.unwrap();
    write_half.write_all(b"\n").await.unwrap();
    write_half.flush().await.unwrap();
    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut buf)).await;
    buf
}

/// The unauthenticated `/pair` multibyte-hex halt: an unpaired client's `/pair` request whose hex `token` holds a
/// multi-byte character at an odd byte offset. Before the fix, the hex decoder
/// sliced the `&str` mid-character and panicked on the core thread, leaving the
/// daemon up with a dead command loop ("core stopped"). Now it is a clean `400`
/// and the core keeps answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_pair_request_with_multibyte_hex() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    let text = "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:7592\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:7591\"\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n";
    std::fs::write(dir.path().join("config.toml"), text).unwrap();
    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap();
    let socket = station.socket_path().to_path_buf();

    let before = rpc(&socket, "whoami", serde_json::json!({})).await;
    assert!(before.contains("address"), "whoami before: {before}");

    let outsider = Keypair::generate();
    let addr = Address::from_public_key(outsider.public_key()).to_string();
    // Even byte length (1 + 2 + 1), with a two-byte character at byte offset 1.
    let body = serde_json::json!({
        "mobile_address": addr,
        "token": "a\u{e9}b",
        "requested_at": 0,
        "signature": "00",
    })
    .to_string();
    let (status, resp) = http_post_json("127.0.0.1:7591", "/pair", &body).await;
    assert_eq!(status, 400, "malformed /pair -> {status} {resp:?}");

    // The core is alive: the operator socket still answers, and a repeat of the
    // same malformed request is refused the same way.
    let after = rpc(&socket, "whoami", serde_json::json!({})).await;
    assert!(after.contains("\"result\""), "whoami after: {after}");
    assert!(after.contains("address"), "whoami after: {after}");
    let (status2, resp2) = http_post_json("127.0.0.1:7591", "/pair", &body).await;
    assert_eq!(status2, 400, "second /pair -> {status2} {resp2:?}");

    station.shutdown().await;
}
