//! The peer port and the operator socket bound what they read:
//! an oversize request line is refused with one `INVALID_REQUEST` and the
//! connection closed, and a replica pulls a log longer than one `log_range`
//! page in bounded pages from a cursor (ADR-0020 §7).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_identity::vouch::create_vouch;
use rrn_station::rpc;
use rrn_station::rpc_client::{
    UnixClient, LOCAL_REQUEST_LINE_LIMIT, MAX_LOG_RANGE_ENTRIES, PEER_REQUEST_LINE_LIMIT,
};
use rrn_station::station::{Station, StationParams, DB_FILE};
use rrn_station::Clock;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

const PASSPHRASE: &str = "peer-port";

/// A writer config on `peer_port`, mDNS off, an ephemeral mobile port.
fn write_writer_config(dir: &Path, peer_port: u16) {
    let text = format!(
        "[network]\nlisten = \"127.0.0.1:{peer_port}\"\nrole = \"writer\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:0\"\n\n\
         [timers]\nsweep_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// A replica config pulling the writer at `writer_port` every second.
fn write_replica_config(dir: &Path, writer_port: u16) {
    let text = format!(
        "[peers]\nlist = [\"127.0.0.1:{writer_port}\"]\n\n\
         [network]\nlisten = \"127.0.0.1:0\"\nrole = \"replica\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:0\"\n\n\
         [timers]\ngossip_interval_secs = 1\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

async fn open(dir: &Path) -> Station {
    Station::open(StationParams {
        data_dir: dir.to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap()
}

/// Writes `bytes` (no newline) to `stream`, then expects, within 5 s, exactly
/// one `INVALID_REQUEST` line naming the cap followed by EOF.
async fn expect_refused_and_closed<S>(stream: S, bytes: &[u8], cap: usize)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    write_half.write_all(bytes).await.unwrap();
    write_half.flush().await.unwrap();

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("a refusal line within 5 s")
        .unwrap();
    let response: rpc::Response = serde_json::from_str(line.trim_end()).unwrap();
    let err = response.error.expect("an error response");
    assert_eq!(err.code, rpc::INVALID_REQUEST);
    assert_eq!(err.message, format!("request line exceeds {cap} bytes"));

    let mut rest = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read_to_end(&mut rest))
        .await
        .expect("the connection closes within 5 s")
        .unwrap();
    assert_eq!(n, 0, "nothing after the refusal: {rest:?}");
}

/// Content-hash set of a station's log.
fn log_content_set(db_path: &Path) -> BTreeSet<[u8; 32]> {
    let db = Database::open(db_path).unwrap();
    let log = AppendLog::new(&db);
    log.iter_from(1)
        .map(|e| e.unwrap().content_hash.to_bytes())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_request_line_is_refused_and_closed() {
    const PEER_PORT: u16 = 7603;
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_writer_config(dir.path(), PEER_PORT);
    let station = open(dir.path()).await;

    let stream = TcpStream::connect(("127.0.0.1", PEER_PORT)).await.unwrap();
    let flood = vec![b'a'; PEER_REQUEST_LINE_LIMIT + 1];
    expect_refused_and_closed(stream, &flood, PEER_REQUEST_LINE_LIMIT).await;

    // The station is unharmed: the operator socket still answers, and so does
    // a well-formed peer request.
    let client = UnixClient::new(station.socket_path());
    let who = client.call("whoami", serde_json::json!({})).await.unwrap();
    assert!(who["address"].is_string(), "whoami: {who}");
    let mut stream = TcpStream::connect(("127.0.0.1", PEER_PORT)).await.unwrap();
    stream
        .write_all(b"{\"id\":\"t\",\"method\":\"log_tail\"}\n")
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(&mut stream).read_line(&mut line),
    )
    .await
    .expect("log_tail answers")
    .unwrap();
    assert!(line.contains("\"result\""), "log_tail: {line}");

    // A puller that predates paging (no `limit`) is refused, not served a
    // page it cannot resume from.
    let mut stream = TcpStream::connect(("127.0.0.1", PEER_PORT)).await.unwrap();
    stream
        .write_all(
            b"{\"id\":\"old\",\"method\":\"log_range\",\"params\":{\"from_seq\":1,\"to_seq\":10}}\n",
        )
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        BufReader::new(&mut stream).read_line(&mut line),
    )
    .await
    .expect("log_range answers")
    .unwrap();
    let response: rpc::Response = serde_json::from_str(line.trim_end()).unwrap();
    let err = response.error.expect("an old-style log_range is refused");
    assert_eq!(err.code, rpc::INVALID_PARAMS);
    assert!(err.message.contains("limit"), "{}", err.message);

    station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unix_socket_oversize_line_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_writer_config(dir.path(), 7604);
    let station = open(dir.path()).await;

    let stream = UnixStream::connect(station.socket_path()).await.unwrap();
    let flood = vec![b'a'; LOCAL_REQUEST_LINE_LIMIT + 1];
    expect_refused_and_closed(stream, &flood, LOCAL_REQUEST_LINE_LIMIT).await;

    // A fresh connection still works.
    let client = UnixClient::new(station.socket_path());
    let who = client.call("whoami", serde_json::json!({})).await.unwrap();
    assert!(who["address"].is_string(), "whoami: {who}");

    station.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replica_converges_on_a_log_longer_than_one_page() {
    const WRITER_PORT: u16 = 7601;
    const SEEDED: u32 = 600;
    // At least three pages at the server's page size.
    const _: () = assert!(SEEDED > 2 * MAX_LOG_RANGE_ENTRIES);

    let dir_w = tempfile::tempdir().unwrap();
    let dir_r = tempfile::tempdir().unwrap();
    Station::init(dir_w.path(), PASSPHRASE).unwrap();
    Station::init(dir_r.path(), PASSPHRASE).unwrap();
    write_writer_config(dir_w.path(), WRITER_PORT);
    write_replica_config(dir_r.path(), WRITER_PORT);

    // Seed the writer's log before it starts.
    {
        let db = Database::open(&dir_w.path().join(DB_FILE)).unwrap();
        let mut log = AppendLog::new(&db);
        for i in 0..SEEDED {
            let voucher = Keypair::generate();
            let subject = Address::from_public_key(Keypair::generate().public_key());
            log.append(
                create_vouch(&voucher, &subject, "c", &format!("seed {i}"), 0),
                1_000,
            )
            .unwrap();
        }
    }

    let writer = open(dir_w.path()).await;
    let replica = open(dir_r.path()).await;

    let writer_db = dir_w.path().join(DB_FILE);
    let replica_db = dir_r.path().join(DB_FILE);
    let want = log_content_set(&writer_db);
    assert!(want.len() >= SEEDED as usize);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let got = log_content_set(&replica_db);
        if got == want {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "replica holds {} of the writer's {} entries",
            want.intersection(&got).count(),
            want.len()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    replica.shutdown().await;
    writer.shutdown().await;
}
