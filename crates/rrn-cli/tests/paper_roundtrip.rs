//! T2.5.2 paper end-to-end, without images: the real `rrn` binary drives a live
//! daemon over its socket. A bundle authored offline (member B's confirmation of
//! an operator proposal) is encoded to QR *text* with the shared codec, ingested
//! from a file, and the station's delivery receipt is exported and shown back —
//! the "carry / ingest / receipt / carry-back" legs the CLI can actually drive.
//! The "sign offline" leg is member B here, whose records travel only by bundle
//! (ADR-0020 §3), mirroring `rrn-station`'s `offline_lifecycle.rs`.

use std::path::Path;
use std::process::Command;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::transaction::{SignedConfirmation, TransactionConfirmation, TransactionId};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};
use rrn_protocol::paper::{encode_chunks, PaperKind};
use rrn_station::rpc::{ProposeResult, WhoamiResult};
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams, WALLET_FILE};
use rrn_station::Clock;

const PASSPHRASE: &str = "paper-e2e";
const RRN: &str = env!("CARGO_BIN_EXE_rrn");
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../rrn-protocol/tests/fixtures/paper"
);

fn write_config(dir: &Path) {
    let text = "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:0\"\n\n\
                [settlement]\nwindow_seconds = 1\n\n\
                [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n";
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// Runs `rrn --socket <s> --format json <args>` and returns parsed stdout.
fn rrn_json(socket: &Path, args: &[&str]) -> serde_json::Value {
    let out = Command::new(RRN)
        .arg("--socket")
        .arg(socket)
        .arg("--format")
        .arg("json")
        .args(args)
        .output()
        .expect("spawn rrn");
    assert!(
        out.status.success(),
        "rrn {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rrn {args:?} stdout not JSON ({e}): {:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Runs `rrn --socket <s> <args>` (text) and returns trimmed stdout.
fn rrn_text(socket: &Path, args: &[&str]) -> String {
    let out = Command::new(RRN)
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("spawn rrn");
    assert!(
        out.status.success(),
        "rrn {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .trim_end()
        .to_string()
}

fn outbox_entry(
    device: &Keypair,
    position: u64,
    prev: Hash,
    record: &SignedConfirmation,
    authored_at: i64,
) -> SignedOutboxEntry {
    let entry = OutboxEntry::wrapping(
        Address::from_public_key(device.public_key()),
        position,
        prev,
        record,
        authored_at,
    );
    SignedPayload::sign(entry, device)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paper_export_ingest_receipts_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    Station::init(dir.path(), PASSPHRASE).unwrap();
    write_config(dir.path());
    let clock = Clock::manual(1_000_000);
    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: clock.clone(),
    })
    .await
    .unwrap();
    let socket = station.socket_path().to_path_buf();
    let client = UnixClient::new(&socket);

    // Member B (the offline signer) and the operator address.
    let b = Keypair::generate();
    let b_addr = Address::from_public_key(b.public_key());
    let who: WhoamiResult =
        serde_json::from_value(client.call("whoami", serde_json::json!({})).await.unwrap())
            .unwrap();

    // Operator proposes 300 to B over the socket; B confirms OFFLINE.
    let prop: ProposeResult = serde_json::from_value(
        client
            .call(
                "propose",
                serde_json::json!({ "receiver": b_addr.to_string(), "amount_centi": 300 }),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let tx1 = TransactionId(Hash::from_hex(&prop.tx_id).unwrap());
    let conf = SignedConfirmation::sign(
        TransactionConfirmation {
            proposal_id: tx1,
            confirmer: b_addr,
            confirmed_at: clock.now(),
        },
        &b,
    );
    let entry = outbox_entry(&b, 0, Hash::from_bytes([0u8; 32]), &conf, clock.now());
    let bundle = Bundle::new(vec![EntryEnvelope::from_signed(&entry)], clock.now());
    let chunks = encode_chunks(PaperKind::Bundle, &bundle.encode()).unwrap();

    let work = dir.path();
    let payload_txt = work.join("payload.txt");
    std::fs::write(&payload_txt, format!("{}\n", chunks.join("\n"))).unwrap();

    // Everything that touches the binary runs off the reactor.
    let socket2 = socket.clone();
    let b_str = b_addr.to_string();
    let work = work.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let socket = socket2.as_path();
        let payload = work.join("payload.txt");
        let payload = payload.to_str().unwrap();
        let carry = work.join("carryback");

        // show (offline): classifies the bundle and verifies B's entry signature.
        let shown = rrn_json(socket, &["paper", "show", "--in", payload]);
        assert_eq!(shown["payloads"][0]["kind"], "bundle");
        assert_eq!(shown["payloads"][0]["records"][0]["verified"], true);

        // ingest → the confirmation is admitted, and a verified receipt is written
        // to the carry-back dir.
        let res = rrn_json(
            socket,
            &[
                "paper",
                "ingest",
                "--in",
                payload,
                "--out",
                carry.to_str().unwrap(),
            ],
        );
        assert_eq!(res["results"][0]["ingested"], true);
        assert_eq!(res["results"][0]["receipt_verified"], true);
        assert_eq!(
            res["results"][0]["outcomes"][0]["disposition"],
            "admitted (seq 2)"
        );
        assert!(
            carry.join("receipts.txt").exists(),
            "carry-back receipts written"
        );
        assert!(
            carry.join("sheet.pdf").exists(),
            "carry-back sheet rendered"
        );

        // Idempotent re-ingest: an identical bundle has the same presentation
        // hash, so the station returns its stored receipt verbatim — the same
        // outcome, never a second admission (ADR-0020 §3).
        let again = rrn_json(socket, &["paper", "ingest", "--in", payload]);
        assert_eq!(
            again["results"][0]["outcomes"][0]["disposition"],
            "admitted (seq 2)"
        );
        assert_eq!(again["results"][0]["receipt_verified"], true);

        // export-receipts for B → a receipts.txt the courier carries back.
        let exp = work.join("receipts");
        let r = rrn_json(
            socket,
            &[
                "paper",
                "export-receipts",
                "--out",
                exp.to_str().unwrap(),
                "--author",
                &b_str,
            ],
        );
        assert_eq!(r["receipts"], 1);
        let receipts_txt = exp.join("receipts.txt");
        assert!(receipts_txt.exists());

        // show the carried-back receipt: it verifies as the station's signature.
        let shown = rrn_json(
            socket,
            &["paper", "show", "--in", receipts_txt.to_str().unwrap()],
        );
        assert_eq!(shown["payloads"][0]["kind"], "receipt");
        assert_eq!(shown["payloads"][0]["verified"], true);

        // A certificate wallet card round-trips: request → export → show verifies.
        let cards = work.join("cards");
        rrn_text(
            socket,
            &[
                "paper",
                "cert",
                "--request",
                "5",
                "--out",
                cards.to_str().unwrap(),
            ],
        );
        let cert_txt = cards.join("certificate.txt");
        assert!(cert_txt.exists() && cards.join("certificate.pdf").exists());
        let shown = rrn_json(
            socket,
            &["paper", "show", "--in", cert_txt.to_str().unwrap()],
        );
        assert_eq!(shown["payloads"][0]["kind"], "certificate");
        assert_eq!(shown["payloads"][0]["verified"], true);

        // A member credential card is the bare address QR.
        rrn_text(
            socket,
            &[
                "paper",
                "credential",
                "--address",
                &b_str,
                "--out",
                cards.to_str().unwrap(),
            ],
        );
        let cred_txt = cards.join("credential.txt");
        assert!(cred_txt.exists());
        assert_eq!(std::fs::read_to_string(&cred_txt).unwrap().trim(), b_str);

        // show classifies every T2.5.1 fixture by kind.
        for (file, kind) in [
            ("multipart_bundle.txt", "bundle"),
            ("certificate.txt", "certificate"),
            ("spend_voucher.txt", "spend-voucher"),
            ("voucher_multipart.txt", "spend-voucher"),
        ] {
            let path = format!("{FIXTURES}/{file}");
            let shown = rrn_json(socket, &["paper", "show", "--in", &path]);
            assert_eq!(shown["payloads"][0]["kind"], kind, "classify {file}");
        }
    })
    .await
    .unwrap();

    // The operator wallet loads (sanity that the fixtures path and wallet file are
    // where the offline flow expects them, for the demo script).
    let _ = WalletContents::load_from_file(&dir.path().join(WALLET_FILE), PASSPHRASE).unwrap();
    let _ = who;

    station.shutdown().await;
}
