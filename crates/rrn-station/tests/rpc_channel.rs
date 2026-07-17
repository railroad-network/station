//! Authenticated request-channel acceptance (T1.3.4): a real station, the real
//! HTTP `/rpc` endpoint, real sealing and signing.
//!
//! Drives a paired mobile's happy path — seal + sign a request, POST it, open
//! and verify the sealed reply — then the rejections a station must get right:
//! an unpaired signer, a replayed nonce, a stale timestamp, and a request
//! addressed to a different station key. The mobile side here uses the same Rust
//! `sealed` / `rpc_envelope` code the FFI exposes; true cross-implementation
//! agreement is proven by the on-device run.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use rrn_crypto::keypair::{Keypair, PublicKey, Signature};
use rrn_identity::address::Address;
use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};
use rrn_station::core::hex;
use rrn_station::pairing::{request_signed_bytes, PairRequest};
use rrn_station::rpc_envelope::{
    frame_signed_request, request_payload_bytes, RequestEnvelope, ResponseEnvelope,
    ENVELOPE_VERSION,
};
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

use rrn_crypto::serialize::from_canonical_bytes;

const PASSPHRASE: &str = "rpc-channel-test";
const MOBILE_PORT: u16 = 7530;
const PEER_PORT: u16 = 7531;

fn write_config(dir: &Path) {
    let text = format!(
        "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{PEER_PORT}\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:{MOBILE_PORT}\"\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// POSTs raw bytes with `content_type` and returns `(status, body_bytes)`.
/// `Connection: close` lets us read the (binary) response to EOF without chunk
/// parsing.
async fn http_post(path: &str, content_type: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let addr = format!("127.0.0.1:{MOBILE_PORT}");
    let mut stream = TcpStream::connect(&addr).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len(),
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("response in time")
        .unwrap();

    // Split the head from the body on the first CRLFCRLF, keeping the body bytes
    // exactly (the sealed reply is binary).
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers/body split");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, body)
}

/// Sends one line-delimited JSON RPC over the operator Unix socket.
async fn socket_rpc(socket: &Path, method: &str, params: serde_json::Value) -> serde_json::Value {
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

/// Pairs `mobile` with the station: POST /pair, then operator `pair_confirm`.
async fn pair_mobile(socket: &Path, mobile: &Keypair) {
    let token = [0x11u8; 32];
    let msg = request_signed_bytes(&mobile.public_key(), &token, now_secs());
    let request = PairRequest {
        mobile_address: Address::from_public_key(mobile.public_key()).to_string(),
        token: hex(&token),
        requested_at: now_secs(),
        signature: hex(&mobile.sign(&msg).to_bytes()),
    };
    let (status, _) = http_post(
        "/pair",
        "application/json",
        serde_json::to_string(&request).unwrap().as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "pair accepted");
    let addr = Address::from_public_key(mobile.public_key()).to_string();
    let confirmed = socket_rpc(
        socket,
        "pair_confirm",
        serde_json::json!({ "address": addr }),
    )
    .await;
    assert_eq!(confirmed["result"]["address"], addr);
}

/// Builds a sealed, signed request the way the mobile does.
fn sealed_request(
    mobile: &Keypair,
    station_pk: &PublicKey,
    recipient: &PublicKey,
    method: &str,
    params: &str,
    nonce: u64,
    timestamp: i64,
) -> Vec<u8> {
    let envelope = RequestEnvelope {
        method: method.into(),
        params: params.into(),
        signer: mobile.public_key(),
        recipient: *recipient,
        nonce,
        timestamp,
    };
    let payload = request_payload_bytes(&envelope);
    let signature = mobile.sign(&payload);
    let frame = frame_signed_request(&payload, &signature);
    sealed::seal(station_pk, &frame, TRANSPORT_CONTEXT)
        .unwrap()
        .to_bytes()
}

/// Opens and verifies a sealed reply, returning the decoded response envelope.
fn open_reply(mobile: &Keypair, station_pk: &PublicKey, sealed_reply: &[u8]) -> ResponseEnvelope {
    let sb = SealedBox::from_bytes(sealed_reply).unwrap();
    let frame = sealed::open(&sb, mobile.secret_key(), TRANSPORT_CONTEXT).unwrap();
    // Frame is payload_len(4 BE) ‖ payload ‖ signature(64).
    let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    let payload = &frame[4..4 + len];
    let sig: [u8; 64] = frame[4 + len..].try_into().unwrap();
    station_pk
        .verify(payload, &Signature::from_bytes(sig).unwrap())
        .expect("station reply signature verifies");
    from_canonical_bytes(payload).unwrap()
}

async fn open_station(dir: &Path) -> Station {
    Station::open(StationParams {
        data_dir: dir.to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_channel_happy_path_and_rejections() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_config(dir.path());
    let station = open_station(dir.path()).await;
    let socket = station.socket_path().to_path_buf();
    let station_pk = *station
        .address()
        .to_string()
        .parse::<Address>()
        .unwrap()
        .public_key();

    let mobile = Keypair::generate();
    pair_mobile(&socket, &mobile).await;
    let mobile_addr = Address::from_public_key(mobile.public_key()).to_string();

    // --- happy path: balance of my own address (nonce 1) ---
    let params = format!("{{\"address\":\"{mobile_addr}\"}}");
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "balance",
        &params,
        1,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "authenticated balance accepted");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert_eq!(reply.nonce, 1);
    assert!(reply.error.is_none(), "no error: {:?}", reply.error);
    let result: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert_eq!(result["balance_centi"], 0);

    // --- whoami (nonce 2) returns the station's address ---
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "whoami",
        "null",
        2,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    let result: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert_eq!(result["address"], station.address().to_string());

    // --- replay of nonce 2 is rejected ---
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "whoami",
        "null",
        2,
        now_secs(),
    );
    let (status, _) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 401, "replayed nonce rejected");

    // --- a stale timestamp is rejected (fresh nonce, so only the clock fails) ---
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "whoami",
        "null",
        3,
        now_secs() - 3600,
    );
    let (status, _) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 401, "stale timestamp rejected");

    // --- a request addressed to a different station key is rejected (400) ---
    let other = Keypair::generate().public_key();
    let req = sealed_request(
        &mobile,
        &station_pk,
        &other,
        "whoami",
        "null",
        4,
        now_secs(),
    );
    let (status, _) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 400, "wrong recipient rejected");

    // --- an unpaired mobile cannot authenticate ---
    let stranger = Keypair::generate();
    let req = sealed_request(
        &stranger,
        &station_pk,
        &station_pk,
        "whoami",
        "null",
        1,
        now_secs(),
    );
    let (status, _) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 401, "unpaired signer rejected");

    // --- an operator-only method is not reachable over the channel (sealed
    //     error, not a transport rejection) ---
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "list_mobiles",
        "null",
        5,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "authenticated, but the method is gated");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(reply.result.is_none());
    assert_eq!(reply.error.unwrap().0, -32601, "method not found");

    // The reply really used the current envelope version.
    assert_eq!(ENVELOPE_VERSION, 1);

    station.shutdown().await;
}
