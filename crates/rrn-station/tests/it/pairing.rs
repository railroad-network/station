//! Pairing acceptance: a real station, the real HTTP pairing routes, and the
//! real operator Unix-socket commands.
//!
//! Drives the commit-then-reveal handshake (ADR-0008, Clarification
//! 2026-10-14; `docs/spec/pairing.md`) end to end — a device commits, the
//! station offers its nonce, the device reveals in a station-bound finish, and
//! the operator confirms by typing the code the device shows — plus every
//! refusal the station must get right. Each test runs its own station on its
//! own ports with a manual clock, so expiry can be tested without waiting.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_identity::address::Address;
use rrn_identity::pairing as layout;
use rrn_station::core::hex;
use rrn_station::paired::PairedMobiles;
use rrn_station::pairing::{PairFinish, PairOffer, PairStart, PAIRING_VERSION, PENDING_TTL_SECS};
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

const PASSPHRASE: &str = "pairing-test";

/// A running station for one test: its data dir, mobile port, operator
/// socket, key, and the manual clock it reads.
struct Harness {
    dir: tempfile::TempDir,
    station: Station,
    mobile_port: u16,
    socket: std::path::PathBuf,
    station_pk: PublicKey,
    clock: Clock,
}

impl Harness {
    /// Starts a station whose mobile surface listens on `mobile_port` (and its
    /// peer port on `mobile_port + 1`), on a manual clock set to now.
    async fn start(mobile_port: u16) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        Station::init(dir.path(), PASSPHRASE).unwrap();
        let peer_port = mobile_port + 1;
        let text = format!(
            "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{peer_port}\"\n\n\
             [mobile]\nadvertise = false\nlisten = \"127.0.0.1:{mobile_port}\"\n\n\
             [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
        );
        std::fs::write(dir.path().join("config.toml"), text).unwrap();
        let clock = Clock::manual(now_secs());
        let station = Station::open(StationParams {
            data_dir: dir.path().to_path_buf(),
            passphrase: PASSPHRASE.into(),
            clock: clock.clone(),
        })
        .await
        .unwrap();
        let socket = station.socket_path().to_path_buf();
        let station_pk = *station
            .address()
            .to_string()
            .parse::<Address>()
            .unwrap()
            .public_key();
        Harness {
            dir,
            station,
            mobile_port,
            socket,
            station_pk,
            clock,
        }
    }

    async fn post(&self, path: &str, body: &str) -> (u16, String) {
        http_post_json(self.mobile_port, path, body).await
    }

    async fn rpc(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        rpc(&self.socket, method, params).await
    }

    /// The operator's pending list.
    async fn pending(&self) -> Vec<serde_json::Value> {
        let listed = self.rpc("pair_list_pending", serde_json::json!({})).await;
        listed["result"]["pending"].as_array().unwrap().clone()
    }

    fn is_paired(&self, address: &str) -> bool {
        PairedMobiles::load(self.dir.path())
            .unwrap()
            .contains(address)
    }
}

/// One device's side of a handshake: its key, nonce, and commitment.
struct Device {
    kp: Keypair,
    nonce: [u8; 32],
    commitment: [u8; 32],
}

impl Device {
    fn new() -> Device {
        Device::from_parts(Keypair::generate(), layout::fresh_nonce())
    }

    /// A session for `kp` committing to `nonce`.
    fn from_parts(kp: Keypair, nonce: [u8; 32]) -> Device {
        let commitment = layout::commitment(&kp.public_key().to_bytes(), &nonce);
        Device {
            kp,
            nonce,
            commitment,
        }
    }

    /// The same device's key, starting a new session with `nonce`.
    fn session(seed: [u8; 32], nonce: [u8; 32]) -> Device {
        Device::from_parts(Keypair::from_secret(SecretKey::from_bytes(seed)), nonce)
    }

    fn pk(&self) -> [u8; 32] {
        self.kp.public_key().to_bytes()
    }

    fn address(&self) -> String {
        Address::from_public_key(self.kp.public_key()).to_string()
    }

    fn start(&self, requested_at: i64) -> String {
        let msg = layout::start_signed_bytes(&self.pk(), &self.commitment, requested_at);
        serde_json::to_string(&PairStart {
            v: PAIRING_VERSION,
            mobile_address: self.address(),
            commitment: hex(&self.commitment),
            requested_at,
            signature: hex(&self.kp.sign(&msg).to_bytes()),
        })
        .unwrap()
    }

    /// A finish naming `named`, signed over `signed_for`'s key, revealing
    /// `nonce` (honest: all three are the real station and the device's nonce).
    fn finish_with(
        &self,
        named: &PublicKey,
        signed_for: &PublicKey,
        station_nonce: &[u8; 32],
        nonce: &[u8; 32],
    ) -> String {
        let msg = layout::finish_signed_bytes(
            &signed_for.to_bytes(),
            &self.pk(),
            &self.commitment,
            station_nonce,
            nonce,
        );
        serde_json::to_string(&PairFinish {
            v: PAIRING_VERSION,
            mobile_address: self.address(),
            station_address: Address::from_public_key(*named).to_string(),
            mobile_nonce: hex(nonce),
            signature: hex(&self.kp.sign(&msg).to_bytes()),
        })
        .unwrap()
    }

    fn finish(&self, station: &PublicKey, station_nonce: &[u8; 32]) -> String {
        self.finish_with(station, station, station_nonce, &self.nonce)
    }

    fn code(&self, station: &PublicKey, station_nonce: &[u8; 32]) -> String {
        layout::code(&station.to_bytes(), &self.pk(), &self.nonce, station_nonce)
    }

    /// Posts a start at `requested_at`, checks the offer as a client would,
    /// and returns the station's nonce.
    async fn start_ok(&self, h: &Harness, requested_at: i64) -> [u8; 32] {
        let (status, body) = h.post("/pair/start", &self.start(requested_at)).await;
        assert_eq!(status, 200, "start accepted; body: {body}");
        let offer: PairOffer = serde_json::from_str(&body).unwrap();
        assert_eq!(
            offer.station_address,
            Address::from_public_key(h.station_pk).to_string()
        );
        offer
            .verify(&h.station_pk, &self.kp.public_key(), &self.commitment)
            .expect("offer verifies over this device's commitment")
    }

    /// Runs both rounds and returns the code the device shows.
    async fn handshake(&self, h: &Harness) -> String {
        let sn = self.start_ok(h, h.clock.now()).await;
        let (status, body) = h
            .post("/pair/finish", &self.finish(&h.station_pk, &sn))
            .await;
        assert_eq!(status, 200, "finish accepted; body: {body}");
        assert_eq!(body, r#"{"status":"awaiting-operator"}"#);
        self.code(&h.station_pk, &sn)
    }
}

/// POSTs a JSON body over a fresh connection and returns `(status, body)`. Uses
/// `Connection: close` so the response can be read to EOF without parsing
/// chunked framing.
async fn http_post_json(port: u16, path: &str, body: &str) -> (u16, String) {
    let addr = format!("127.0.0.1:{port}");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_pairing_happy_path_confirm_by_code_and_revocation() {
    let h = Harness::start(7523).await;
    let device = Device::new();
    let address = device.address();

    // After the start alone the session has no code, so the operator sees
    // nothing to confirm yet.
    let sn = device.start_ok(&h, h.clock.now()).await;
    assert!(h.pending().await.is_empty());

    let (status, body) = h
        .post("/pair/finish", &device.finish(&h.station_pk, &sn))
        .await;
    assert_eq!(status, 200, "finish accepted; body: {body}");
    // The station never sends the code: the answer is only a status.
    assert_eq!(body, r#"{"status":"awaiting-operator"}"#);
    let code = device.code(&h.station_pk, &sn);
    assert!(!body.contains(&code));

    // The operator's list carries the same code the device computed.
    let pending = h.pending().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["address"], address);
    assert_eq!(pending[0]["code"], code);
    assert!(pending[0].get("sas").is_none());
    assert!(
        !h.is_paired(&address),
        "not paired until the operator confirms"
    );

    // An address alone no longer confirms.
    let bare = h
        .rpc("pair_confirm", serde_json::json!({ "address": address }))
        .await;
    assert!(bare["error"].is_object(), "confirm without a code: {bare}");
    assert!(!h.is_paired(&address));

    // The operator types the code as read aloud: lowercase, no hyphen.
    let typed = code.replace('-', "").to_lowercase();
    let confirmed = h
        .rpc(
            "pair_confirm",
            serde_json::json!({ "address": address, "code": typed }),
        )
        .await;
    assert_eq!(confirmed["result"]["address"], address, "{confirmed}");
    assert!(h.is_paired(&address), "pairing survives on disk");
    assert!(h.pending().await.is_empty());

    let mobiles = h.rpc("list_mobiles", serde_json::json!({})).await;
    assert_eq!(mobiles["result"]["mobiles"][0]["address"], address);

    // Unpair revokes and persists the revocation.
    let removed = h
        .rpc("unpair", serde_json::json!({ "address": address }))
        .await;
    assert_eq!(removed["result"]["removed"], true);
    assert!(!h.is_paired(&address));

    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_pair_route_is_retired() {
    let h = Harness::start(7525).await;
    // Any body, including a well-formed version-1 request, is gone.
    let v1 = serde_json::json!({
        "mobile_address": Device::new().address(),
        "token": hex(&[0x11; 32]),
        "requested_at": h.clock.now(),
        "signature": hex(&[0; 64]),
    })
    .to_string();
    for body in [v1.as_str(), "{}"] {
        let (status, text) = h.post("/pair", body).await;
        assert_eq!(status, 410, "{text}");
        assert_eq!(text, "pairing protocol v1 is retired; update the app");
    }
    // A start that says it is version 1 is refused too.
    let device = Device::new();
    let mut start: serde_json::Value = serde_json::from_str(&device.start(h.clock.now())).unwrap();
    start["v"] = 1.into();
    let (status, text) = h.post("/pair/start", &start.to_string()).await;
    assert_eq!(
        (status, text.as_str()),
        (400, "unsupported pairing version")
    );
    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finish_that_does_not_open_the_commitment_is_refused() {
    let h = Harness::start(7540).await;
    let device = Device::new();
    let now = h.clock.now();
    let sn = device.start_ok(&h, now).await;

    // A retried start (same commitment) re-sends the same offer.
    let (_, first) = h.post("/pair/start", &device.start(now)).await;
    let (_, again) = h.post("/pair/start", &device.start(now)).await;
    assert_eq!(first, again, "a retried start is idempotent");

    // A properly signed finish revealing a different nonce: the commitment
    // does not open, so the device could not have chosen its nonce late.
    let other = layout::fresh_nonce();
    let lying = device.finish_with(&h.station_pk, &h.station_pk, &sn, &other);
    let (status, text) = h.post("/pair/finish", &lying).await;
    assert_eq!(
        (status, text.as_str()),
        (400, "revealed nonce does not open the commitment")
    );
    assert!(h.pending().await.is_empty(), "no code for a failed reveal");

    // A finish whose signature does not verify is refused the same way.
    let mut forged: serde_json::Value =
        serde_json::from_str(&device.finish(&h.station_pk, &sn)).unwrap();
    forged["signature"] = hex(&Keypair::generate().sign(b"x").to_bytes()).into();
    let (status, text) = h.post("/pair/finish", &forged.to_string()).await;
    assert_eq!((status, text.as_str()), (400, "signature does not verify"));

    // The session survives both: the honest reveal still completes.
    let (status, _) = h
        .post("/pair/finish", &device.finish(&h.station_pk, &sn))
        .await;
    assert_eq!(status, 200);
    assert_eq!(h.pending().await.len(), 1);
    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finish_signed_for_another_station_is_refused() {
    let h = Harness::start(7542).await;
    let device = Device::new();
    let sn = device.start_ok(&h, h.clock.now()).await;
    let elsewhere = Keypair::generate().public_key();

    // A finish naming another station.
    let named_elsewhere = device.finish_with(&elsewhere, &elsewhere, &sn, &device.nonce);
    let (status, text) = h.post("/pair/finish", &named_elsewhere).await;
    assert_eq!(
        (status, text.as_str()),
        (400, "request names a different station")
    );

    // A finish naming this station but signed over another station's key
    // (one relayed from a session with a different station) does not verify.
    let signed_elsewhere = device.finish_with(&h.station_pk, &elsewhere, &sn, &device.nonce);
    let (status, text) = h.post("/pair/finish", &signed_elsewhere).await;
    assert_eq!((status, text.as_str()), (400, "signature does not verify"));

    assert!(h.pending().await.is_empty());
    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finish_without_a_start_is_refused() {
    let h = Harness::start(7544).await;
    let device = Device::new();
    let (status, text) = h
        .post("/pair/finish", &device.finish(&h.station_pk, &[3; 32]))
        .await;
    assert_eq!(
        (status, text.as_str()),
        (400, "no pairing in progress for this address; start again")
    );

    // A second reveal of an already-revealed session is refused the same way.
    let code = device.handshake(&h).await;
    let (status, text) = h
        .post("/pair/finish", &device.finish(&h.station_pk, &[3; 32]))
        .await;
    assert_eq!(
        (status, text.as_str()),
        (400, "no pairing in progress for this address; start again")
    );
    assert_eq!(h.pending().await[0]["code"], code, "the row is unchanged");
    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_start_does_not_replace_a_revealed_session() {
    let h = Harness::start(7546).await;
    let now = h.clock.now();

    // Two starts from one device: an older one (captured) and the current one.
    let older = Device::session([9; 32], [1; 32]);
    let current = Device::session([9; 32], [2; 32]);
    let older_start = older.start(now - 10);

    let sn = current.start_ok(&h, now).await;
    // While the reveal is awaited, the older start cannot evict the session.
    let (status, text) = h.post("/pair/start", &older_start).await;
    assert_eq!(
        (status, text.as_str()),
        (400, "pairing request already used")
    );

    let (status, _) = h
        .post("/pair/finish", &current.finish(&h.station_pk, &sn))
        .await;
    assert_eq!(status, 200);
    let code = current.code(&h.station_pk, &sn);

    // Once revealed: replaying the same start is refused, and so is the older one.
    for replay in [current.start(now), older_start] {
        let (status, text) = h.post("/pair/start", &replay).await;
        assert_eq!(
            (status, text.as_str()),
            (400, "pairing request already used")
        );
    }
    let pending = h.pending().await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["code"], code, "the revealed row survives");

    // A genuinely newer start (the device starting over) does replace it.
    let newer = Device::session([9; 32], [3; 32]);
    newer.start_ok(&h, now + 1).await;
    assert!(h.pending().await.is_empty(), "back to awaiting the reveal");
    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_confirm_with_the_wrong_code_is_refused_and_keeps_the_row() {
    let h = Harness::start(7548).await;
    let device = Device::new();
    let address = device.address();
    let code = device.handshake(&h).await;

    // A row planted by someone else under another address cannot borrow this
    // device's code either: the code is checked against that row's own.
    let planted = Device::new();
    planted.handshake(&h).await;
    let refused = h
        .rpc(
            "pair_confirm",
            serde_json::json!({ "address": planted.address(), "code": code }),
        )
        .await;
    assert!(refused["error"].is_object(), "{refused}");

    let wrong = if code.starts_with('0') {
        "11111-11111"
    } else {
        "00000-00000"
    };
    let refused = h
        .rpc(
            "pair_confirm",
            serde_json::json!({ "address": address, "code": wrong }),
        )
        .await;
    assert_eq!(
        refused["error"]["message"],
        format!("the code does not match the pending request from {address}; compare again")
    );
    assert!(!h.is_paired(&address));
    assert_eq!(h.pending().await.len(), 2, "both rows are kept");

    let confirmed = h
        .rpc(
            "pair_confirm",
            serde_json::json!({ "address": address, "code": code }),
        )
        .await;
    assert_eq!(confirmed["result"]["address"], address, "{confirmed}");
    assert!(h.is_paired(&address));
    assert!(!h.is_paired(&planted.address()));
    h.station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_expires_in_either_stage() {
    let h = Harness::start(7550).await;

    // Awaiting the reveal: past the TTL, the finish finds no session.
    let device = Device::new();
    let sn = device.start_ok(&h, h.clock.now()).await;
    h.clock.advance(PENDING_TTL_SECS + 1);
    let (status, text) = h
        .post("/pair/finish", &device.finish(&h.station_pk, &sn))
        .await;
    assert_eq!(
        (status, text.as_str()),
        (400, "no pairing in progress for this address; start again")
    );

    // Awaiting the operator: the reveal restarts the clock, and past the TTL
    // the row is gone and cannot be confirmed.
    let device = Device::new();
    let code = device.handshake(&h).await;
    h.clock.advance(PENDING_TTL_SECS);
    assert_eq!(h.pending().await.len(), 1, "still inside the TTL");
    h.clock.advance(1);
    assert!(h.pending().await.is_empty());
    let refused = h
        .rpc(
            "pair_confirm",
            serde_json::json!({ "address": device.address(), "code": code }),
        )
        .await;
    assert!(refused["error"].is_object(), "{refused}");

    // A start stamped outside the clock skew is refused.
    let late = Device::new();
    let (status, text) = h
        .post("/pair/start", &late.start(h.clock.now() - 301))
        .await;
    assert_eq!(
        (status, text.as_str()),
        (400, "requested_at outside allowed clock skew")
    );
    h.station.shutdown().await;
}
