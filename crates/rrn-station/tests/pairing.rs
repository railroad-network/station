//! Pairing acceptance (T1.3.3): a real station, the real HTTP `/pair` endpoint,
//! and the real operator Unix-socket commands.
//!
//! Drives the whole happy path end-to-end — a mobile POSTs a signed request, the
//! station returns a signed response, the operator lists the pending request,
//! compares the confirmation code, and confirms it — plus the rejection paths a
//! station must get right: a bad signature is refused, and unpairing removes the
//! mobile. Persistence is checked against the on-disk list the daemon reloads at
//! startup.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use rrn_crypto::keypair::{Keypair, Signature};
use rrn_identity::address::Address;
use rrn_station::core::{hex, unhex};
use rrn_station::paired::{confirmation_code, PairedMobiles};
use rrn_station::pairing::{
    request_signed_bytes, response_signed_bytes, PairRequest, PairResponse,
};
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

const PASSPHRASE: &str = "pairing-test";
/// Fixed loopback port for this test's mobile HTTP surface (needs to be known so
/// the test can POST to it). Distinct from other tests' ports.
const MOBILE_PORT: u16 = 7523;
const PEER_PORT: u16 = 7524;

fn write_config(dir: &Path) {
    let text = format!(
        "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{PEER_PORT}\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:{MOBILE_PORT}\"\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// POSTs a JSON body over a fresh connection and returns `(status, body)`. Uses
/// `Connection: close` so the response can be read to EOF without parsing
/// chunked framing.
async fn http_post_json(path: &str, body: &str) -> (u16, String) {
    let addr = format!("127.0.0.1:{MOBILE_PORT}");
    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("response in time")
        .unwrap();

    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("headers/body split");
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, body.to_string())
}

/// Sends one line-delimited JSON RPC over the Unix socket and returns the parsed
/// response value.
async fn rpc(socket: &Path, method: &str, params: serde_json::Value) -> serde_json::Value {
    let line = serde_json::json!({ "id": "t", "method": method, "params": params }).to_string();
    let stream = UnixStream::connect(socket).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(line.as_bytes()).await.unwrap();
    write_half.write_all(b"\n").await.unwrap();
    write_half.flush().await.unwrap();

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut buf))
        .await
        .expect("response in time")
        .unwrap();
    serde_json::from_str(buf.trim_end()).unwrap()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Builds a validly-signed pairing request from `mobile`, stamped `now`.
fn signed_request(mobile: &Keypair, token: [u8; 32], requested_at: i64) -> PairRequest {
    let msg = request_signed_bytes(&mobile.public_key(), &token, requested_at);
    PairRequest {
        mobile_address: Address::from_public_key(mobile.public_key()).to_string(),
        token: hex(&token),
        requested_at,
        signature: hex(&mobile.sign(&msg).to_bytes()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_happy_path_and_revocation() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_config(dir.path());

    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap();
    let socket = station.socket_path().to_path_buf();
    let station_addr = station.address().to_string();
    let station_pk = *station_addr.parse::<Address>().unwrap().public_key();

    // The mobile POSTs a signed pairing request.
    let mobile = Keypair::generate();
    let mobile_addr = Address::from_public_key(mobile.public_key()).to_string();
    let token = [0x11u8; 32];
    let request = signed_request(&mobile, token, now_secs());
    let (status, body) = http_post_json("/pair", &serde_json::to_string(&request).unwrap()).await;
    assert_eq!(status, 200, "pair request accepted; body: {body}");

    // The station's response proves its identity and binds to our token.
    let response: PairResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(response.station_address, station_addr);
    let sig_bytes: [u8; 64] = unhex(&response.signature).unwrap().try_into().unwrap();
    let signature = Signature::from_bytes(sig_bytes).unwrap();
    station_pk
        .verify(&response_signed_bytes(&station_pk, &token), &signature)
        .expect("station response signature verifies");

    // Both sides derive the same confirmation code.
    let expected_sas = confirmation_code(&station_pk, &mobile.public_key());

    // The operator sees the pending request, with the code to compare.
    let listed = rpc(&socket, "pair_list_pending", serde_json::json!({})).await;
    let pending = listed["result"]["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["address"], mobile_addr);
    assert_eq!(pending[0]["sas"], expected_sas);

    // Not paired until the operator confirms.
    assert!(!PairedMobiles::load(dir.path())
        .unwrap()
        .contains(&mobile_addr));

    // Operator confirms; the mobile is now paired and persisted.
    let confirmed = rpc(
        &socket,
        "pair_confirm",
        serde_json::json!({ "address": mobile_addr }),
    )
    .await;
    assert_eq!(confirmed["result"]["address"], mobile_addr);
    assert!(
        PairedMobiles::load(dir.path())
            .unwrap()
            .contains(&mobile_addr),
        "pairing survives on disk for the next daemon start"
    );

    let mobiles = rpc(&socket, "list_mobiles", serde_json::json!({})).await;
    assert_eq!(mobiles["result"]["mobiles"][0]["address"], mobile_addr);

    // Unpair revokes and persists the revocation.
    let removed = rpc(
        &socket,
        "unpair",
        serde_json::json!({ "address": mobile_addr }),
    )
    .await;
    assert_eq!(removed["result"]["removed"], true);
    assert!(!PairedMobiles::load(dir.path())
        .unwrap()
        .contains(&mobile_addr));

    station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_signature_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    // A second station in the same test binary would collide on MOBILE_PORT, so
    // give this one its own ports.
    let text = "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:7526\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:7525\"\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n";
    std::fs::write(dir.path().join("config.toml"), text).unwrap();

    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap();

    // A request whose signature is the right shape but does not verify.
    let mobile = Keypair::generate();
    let mut request = signed_request(&mobile, [0x22u8; 32], now_secs());
    request.signature = hex(&[0u8; 64]);
    let body = serde_json::to_string(&request).unwrap();

    let addr = "127.0.0.1:7525";
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let http = format!(
        "POST /pair HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(http.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    let status: u16 = text
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(status, 400, "bad signature rejected; response: {text}");

    station.shutdown().await;
}
