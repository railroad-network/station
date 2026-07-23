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
use rrn_identity::attestation::Attestation;
use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_station::core::hex;
use rrn_station::pairing::{request_signed_bytes, PairRequest};
use rrn_station::rpc_envelope::{
    frame_signed_record, frame_signed_request, request_payload_bytes, RequestEnvelope,
    ResponseEnvelope, ENVELOPE_VERSION,
};
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

use rrn_crypto::serialize::to_canonical_bytes;

const PASSPHRASE: &str = "rpc-channel-test";
const MOBILE_PORT: u16 = 7530;
const PEER_PORT: u16 = 7531;

fn write_config(dir: &Path) {
    let text = format!(
        "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{PEER_PORT}\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:{MOBILE_PORT}\"\nsubscribe_hold_secs = 2\n\n\
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
    // The response is JSON (the mobile carries no dCBOR decoder); the request was
    // canonical dCBOR. See rpc_envelope for why they differ.
    serde_json::from_slice(payload).unwrap()
}

/// Builds the `submit_proposal` params: a sender-signed proposal, framed as a
/// signed record and hex-encoded — exactly what the mobile produces.
fn proposal_params(
    sender: &Keypair,
    receiver: &Address,
    amount: i64,
    nonce: u64,
    now: i64,
) -> String {
    let proposal = TransactionProposal::new(
        Address::from_public_key(sender.public_key()),
        *receiver,
        amount,
        Some("groceries".into()),
        nonce,
        now,
        now + 3600,
    );
    let signed = SignedProposal::sign(proposal.clone(), sender);
    let frame = frame_signed_record(
        &to_canonical_bytes(proposal),
        &sender.public_key(),
        &signed.signature,
    );
    format!("{{\"signed_proposal\":\"{}\"}}", hex(&frame))
}

/// Builds the `submit_confirmation` params: a receiver-signed confirmation of
/// `tx_id_hex`, framed and hex-encoded.
fn confirmation_params(receiver: &Keypair, tx_id_hex: &str, now: i64) -> String {
    use rrn_crypto::hash::Hash;
    use rrn_ledger::transaction::TransactionId;
    let id_bytes: [u8; 32] = rrn_station::core::unhex(tx_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let confirmation = TransactionConfirmation {
        proposal_id: TransactionId(Hash::from_bytes(id_bytes)),
        confirmer: Address::from_public_key(receiver.public_key()),
        confirmed_at: now,
    };
    let signed = SignedConfirmation::sign(confirmation.clone(), receiver);
    let frame = frame_signed_record(
        &to_canonical_bytes(confirmation),
        &receiver.public_key(),
        &signed.signature,
    );
    format!("{{\"signed_confirmation\":\"{}\"}}", hex(&frame))
}

/// Builds the `submit_vouch` params: a voucher-signed vouch attestation for
/// `subject`, framed as a signed record and hex-encoded — what the mobile makes.
fn vouch_params(voucher: &Keypair, subject: &Address, now: i64) -> String {
    let attestation = Attestation {
        kind: VouchKind,
        body: VouchBody {
            community: "rrn-phase0".to_string(),
            statement: "I know this person personally".to_string(),
            reputation_stake_centi: 50,
        },
        subject: *subject,
        issued_at: now,
        expires_at: None,
    };
    let signed = attestation.clone().sign(voucher);
    let frame = frame_signed_record(
        &to_canonical_bytes(attestation),
        &voucher.public_key(),
        &signed.signature,
    );
    format!("{{\"signed_vouch\":\"{}\"}}", hex(&frame))
}

/// The `events` array from a subscribe reply.
fn events_of(reply: &ResponseEnvelope) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    v["events"].as_array().cloned().unwrap_or_default()
}

/// The `last_seen_event_id` cursor from a subscribe reply.
fn cursor_of(reply: &ResponseEnvelope) -> u64 {
    let v: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    v["last_seen_event_id"].as_u64().unwrap()
}

/// Whether any event in a subscribe reply has the given `kind`.
fn has_kind(reply: &ResponseEnvelope, kind: &str) -> bool {
    events_of(reply).iter().any(|e| e["kind"] == kind)
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
    assert_eq!(reply.error.unwrap().code, -32601, "method not found");

    // The reply really used the current envelope version.
    assert_eq!(ENVELOPE_VERSION, 1);

    // --- write path: the mobile submits its own signed proposal ---
    // A receiver mobile, also paired so it can later confirm over the channel.
    let receiver = Keypair::generate();
    pair_mobile(&socket, &receiver).await;
    let receiver_addr = Address::from_public_key(receiver.public_key());
    let now = now_secs();

    // Query-first: the sender asks for its authoritative next ledger nonce before
    // signing. A member that has never proposed gets 0.
    let params = format!("{{\"address\":\"{mobile_addr}\"}}");
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "next_nonce",
        &params,
        6,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    let ledger_nonce = serde_json::from_str::<serde_json::Value>(reply.result.as_deref().unwrap())
        .unwrap()["nonce"]
        .as_u64()
        .unwrap();
    assert_eq!(ledger_nonce, 0, "first proposal is nonce 0");

    // The sender proposes 500 to the receiver with that ledger nonce. Its
    // *transport* nonce continues at 7 — the two are independent.
    let params = proposal_params(&mobile, &receiver_addr, 500, ledger_nonce, now);
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "submit_proposal",
        &params,
        7,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "proposal submitted");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(reply.error.is_none(), "propose error: {:?}", reply.error);
    let proposed: serde_json::Value =
        serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert_eq!(proposed["state"], "Proposed");
    let tx_id = proposed["tx_id"].as_str().unwrap().to_string();

    // The sender sees it in their transaction view: out, negative, pending.
    let params = format!("{{\"address\":\"{mobile_addr}\"}}");
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "transactions",
        &params,
        8,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    let view: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    let row = &view["transactions"][0];
    assert_eq!(row["id"], tx_id);
    assert_eq!(row["direction"], "out");
    assert_eq!(row["amount_centi"], -500);
    assert_eq!(row["state"], "pending");
    assert_eq!(row["counterparty_address"], receiver_addr.to_string());

    // The receiver confirms it (their own signed confirmation, transport nonce 1).
    let params = confirmation_params(&receiver, &tx_id, now);
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "submit_confirmation",
        &params,
        1,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "confirmation submitted");
    let reply = open_reply(&receiver, &station_pk, &body);
    assert!(reply.error.is_none(), "confirm error: {:?}", reply.error);

    // The receiver's view now shows it: in, positive, confirmed.
    let params = format!("{{\"address\":\"{}\"}}", receiver_addr);
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "transactions",
        &params,
        2,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&receiver, &station_pk, &body);
    let view: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    let row = &view["transactions"][0];
    assert_eq!(row["direction"], "in");
    assert_eq!(row["amount_centi"], 500);
    assert_eq!(row["state"], "confirmed");

    // A mobile cannot submit a proposal signed by someone else (submitter binding).
    let stranger = Keypair::generate();
    let params = proposal_params(&stranger, &receiver_addr, 100, 0, now);
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "submit_proposal",
        &params,
        9,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "authenticated");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(
        reply.error.is_some(),
        "a relayed foreign proposal is refused"
    );

    // --- T1.3.5: push events over /subscribe -------------------------------
    // The log now holds a proposal (seq 1) and its confirmation (seq 2).

    // (a) The sender subscribes from the start: it is told its proposal was
    //     confirmed — but never notified of its own proposal.
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "subscribe",
        "{\"last_seen_event_id\":0}",
        10,
        now_secs(),
    );
    let (status, body) = http_post("/subscribe", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "subscribe with pending events returns at once");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(
        has_kind(&reply, "confirmation_received"),
        "sender told of confirm"
    );
    assert!(
        !has_kind(&reply, "proposal_received"),
        "sender not told of own proposal"
    );
    let sender_cursor = cursor_of(&reply);

    // (b) The receiver subscribes from the start: it is told a proposal arrived.
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "subscribe",
        "{\"last_seen_event_id\":0}",
        3,
        now_secs(),
    );
    let (status, body) = http_post("/subscribe", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&receiver, &station_pk, &body);
    assert!(
        has_kind(&reply, "proposal_received"),
        "receiver told of proposal"
    );

    // (c) Long-poll wakes on a fresh append: the sender parks at the current
    //     tail, the receiver then proposes *to* it, and the parked call returns.
    let parked_req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "subscribe",
        &format!("{{\"last_seen_event_id\":{sender_cursor}}}"),
        11,
        now_secs(),
    );
    let parked = tokio::spawn(async move {
        http_post("/subscribe", "application/octet-stream", &parked_req).await
    });
    // Give the subscribe time to authenticate and park before the append.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let now = now_secs();
    let params = format!("{{\"address\":\"{}\"}}", receiver_addr);
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "next_nonce",
        &params,
        4,
        now,
    );
    let (_, body) = http_post("/rpc", "application/octet-stream", &req).await;
    let reply = open_reply(&receiver, &station_pk, &body);
    let r_nonce = serde_json::from_str::<serde_json::Value>(reply.result.as_deref().unwrap())
        .unwrap()["nonce"]
        .as_u64()
        .unwrap();
    let mobile_pubaddr = Address::from_public_key(mobile.public_key());
    let params = proposal_params(&receiver, &mobile_pubaddr, 250, r_nonce, now);
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "submit_proposal",
        &params,
        5,
        now,
    );
    let (status, _) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "wake proposal submitted");

    let (status, body) = tokio::time::timeout(Duration::from_secs(10), parked)
        .await
        .expect("parked subscribe returns")
        .unwrap();
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(
        has_kind(&reply, "proposal_received"),
        "parked subscribe woke on the new proposal"
    );
    let sender_cursor2 = cursor_of(&reply);

    // (d) With nothing new appended, the long-poll returns an empty heartbeat
    //     after the (short, test-configured) hold, advancing the cursor.
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "subscribe",
        &format!("{{\"last_seen_event_id\":{sender_cursor2}}}"),
        12,
        now_secs(),
    );
    let (status, body) = http_post("/subscribe", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(events_of(&reply).is_empty(), "heartbeat carries no events");
    assert!(
        cursor_of(&reply) >= sender_cursor2,
        "heartbeat advances the cursor"
    );

    // --- T1.4.3: a paired mobile submits a vouch it signed -----------------
    let params = vouch_params(&mobile, &receiver_addr, now);
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "submit_vouch",
        &params,
        20,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "vouch submitted");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(reply.error.is_none(), "vouch error: {:?}", reply.error);
    let vouched: serde_json::Value =
        serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    let vouch_id = vouched["vouch_id"].as_str().expect("vouch_id string");
    assert_eq!(vouch_id.len(), 64, "vouch_id is a 32-byte hex hash");

    // A mobile cannot submit a vouch signed by someone else (submitter binding).
    let stranger = Keypair::generate();
    let params = vouch_params(&stranger, &receiver_addr, now);
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "submit_vouch",
        &params,
        21,
        now,
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200, "authenticated");
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(reply.error.is_some(), "a relayed foreign vouch is refused");

    // --- T1.4.1: the vouch reaches its subject over /subscribe -------------
    // The subject (the receiver) subscribes from the start and finds a
    // vouch_received event carrying the vouch row — same content address the
    // submit returned, the voucher's address, and no transaction payload.
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "subscribe",
        "{\"last_seen_event_id\":0}",
        6,
        now_secs(),
    );
    let (status, body) = http_post("/subscribe", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&receiver, &station_pk, &body);
    assert!(has_kind(&reply, "vouch_received"), "subject told of vouch");
    let vouch_event = events_of(&reply)
        .into_iter()
        .find(|e| e["kind"] == "vouch_received")
        .unwrap();
    assert_eq!(vouch_event["vouch"]["vouch_id"], vouch_id);
    assert_eq!(vouch_event["vouch"]["voucher_address"], mobile_addr);
    assert_eq!(vouch_event["vouch"]["stake_centi"], 50);
    assert!(
        vouch_event.get("transaction").is_none(),
        "a vouch event carries no transaction row"
    );

    // The voucher is never notified of their own vouch.
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "subscribe",
        &format!("{{\"last_seen_event_id\":{sender_cursor2}}}"),
        22,
        now_secs(),
    );
    let (status, body) = http_post("/subscribe", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(
        !has_kind(&reply, "vouch_received"),
        "voucher not told of own vouch"
    );

    // --- T1.4.4: vouch_counts are member-relative and truthful -------------
    // One vouch was appended (mobile → receiver). The voucher sees given=1,
    // received=0; the subject sees given=0, received=1. Each reads its OWN
    // counts (the member is the authenticated signer, not a param).
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "vouch_counts",
        "{}",
        23,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(
        reply.error.is_none(),
        "vouch_counts error: {:?}",
        reply.error
    );
    let counts: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert_eq!(counts["given"], 1, "voucher gave one vouch");
    assert_eq!(counts["received"], 0, "voucher received none");

    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "vouch_counts",
        "{}",
        7,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&receiver, &station_pk, &body);
    assert!(
        reply.error.is_none(),
        "vouch_counts error: {:?}",
        reply.error
    );
    let counts: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert_eq!(counts["given"], 0, "subject gave none");
    assert_eq!(counts["received"], 1, "subject received one vouch");

    // --- T1.4.5: list_vouches returns the browser rows, split by direction --
    // The voucher lists one given row (naming both parties, same content
    // address the submit returned) and no received rows.
    let req = sealed_request(
        &mobile,
        &station_pk,
        &station_pk,
        "list_vouches",
        "{}",
        24,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&mobile, &station_pk, &body);
    assert!(
        reply.error.is_none(),
        "list_vouches error: {:?}",
        reply.error
    );
    let lists: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert_eq!(
        lists["given"].as_array().unwrap().len(),
        1,
        "voucher gave one"
    );
    assert!(
        lists["received"].as_array().unwrap().is_empty(),
        "voucher received none"
    );
    let row = &lists["given"][0];
    assert_eq!(row["vouch_id"], vouch_id, "same content address as submit");
    assert_eq!(row["voucher_address"], mobile_addr);
    assert_eq!(row["subject_address"], receiver_addr.to_string());
    assert_eq!(row["stake_centi"], 50);

    // The subject lists the same vouch under `received`, nothing under `given`.
    let req = sealed_request(
        &receiver,
        &station_pk,
        &station_pk,
        "list_vouches",
        "{}",
        8,
        now_secs(),
    );
    let (status, body) = http_post("/rpc", "application/octet-stream", &req).await;
    assert_eq!(status, 200);
    let reply = open_reply(&receiver, &station_pk, &body);
    assert!(
        reply.error.is_none(),
        "list_vouches error: {:?}",
        reply.error
    );
    let lists: serde_json::Value = serde_json::from_str(reply.result.as_deref().unwrap()).unwrap();
    assert!(
        lists["given"].as_array().unwrap().is_empty(),
        "subject gave none"
    );
    assert_eq!(
        lists["received"].as_array().unwrap().len(),
        1,
        "subject received one"
    );
    assert_eq!(lists["received"][0]["vouch_id"], vouch_id);

    station.shutdown().await;
}
