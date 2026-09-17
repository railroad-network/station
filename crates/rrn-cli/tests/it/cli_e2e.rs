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

        // --- marketplace (T1.7.3) ---------------------------------------
        //
        // The whole operator loop against a live daemon: publish, browse, read
        // one in full, state a need, see it matched, then withdraw the offer.

        // Nothing on offer yet, and that reads as a sentence rather than as
        // empty stdout.
        assert_eq!(rrn(&socket, &["browse"]), "no listings");

        // list → a content address on stdout.
        let listing_id = rrn(
            &socket,
            &[
                "list",
                "goods",
                "Winter squash, by the crate",
                "--price",
                "2.50",
                "--category",
                "food",
                "--capacity",
                "12",
                "--description",
                "Picked this week.",
            ],
        );
        assert_eq!(
            listing_id.len(),
            64,
            "listing id should be hex: {listing_id}"
        );

        // browse (text) finds it, with the price and band on the row.
        let browsed = rrn(&socket, &["browse"]);
        assert!(browsed.contains("Winter squash"), "browse: {browsed}");
        assert!(browsed.contains("2.50 Commons"), "browse: {browsed}");
        assert!(browsed.contains("goods"), "browse: {browsed}");
        // The row leads with the id's first 12 chars, which is what gets retyped.
        assert!(
            browsed.contains(&listing_id[..12]),
            "browse should carry the short id: {browsed}"
        );

        // browse (json) is one line of valid JSON with the full id.
        let j = rrn(&socket, &["--format", "json", "browse"]);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["listings"][0]["listing_id"], listing_id);
        assert_eq!(v["listings"][0]["amount_centi"], 250);

        // Filters narrow it, and a filter that excludes it returns nothing.
        let hit = rrn(
            &socket,
            &["browse", "--category", "food", "--text", "squash"],
        );
        assert!(hit.contains("Winter squash"), "filtered browse: {hit}");
        assert_eq!(
            rrn(&socket, &["browse", "--surface", "services"]),
            "no listings"
        );
        assert_eq!(
            rrn(&socket, &["browse", "--max-price", "1.00"]),
            "no listings"
        );

        // An unknown surface is an error, not a silently dropped filter. Caught
        // by the arg parser here, and independently by the station (see the
        // `marketplace_search` tests in `core`) for clients that are not this one.
        let out = Command::new(RRN)
            .arg("--socket")
            .arg(&socket)
            .args(["browse", "--surface", "livestock"])
            .output()
            .unwrap();
        assert!(!out.status.success(), "an unknown surface should fail");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("goods"),
            "the error should name the surfaces that do exist"
        );

        // show-listing renders labelled fields, greppable by name.
        let detail = rrn(&socket, &["show-listing", &listing_id]);
        assert!(detail.contains("Picked this week."), "detail: {detail}");
        assert!(detail.contains("oracle_tier"), "detail: {detail}");
        assert!(detail.contains("active"), "detail: {detail}");
        let j = rrn(&socket, &["--format", "json", "show-listing", &listing_id]);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["state"], "active");
        assert_eq!(v["community_member_only"], false);

        // my-listings carries the lifecycle state alongside the row.
        let mine = rrn(&socket, &["my-listings"]);
        assert!(mine.contains("active"), "my-listings: {mine}");
        assert!(mine.contains("Winter squash"), "my-listings: {mine}");

        // need → a log seq, and matches finds the listing that answers it.
        let seq = rrn(
            &socket,
            &[
                "need",
                "food",
                "6",
                "--max-price",
                "3.00",
                "--valid-until",
                "+30d",
            ],
        );
        assert!(seq.parse::<u64>().is_ok(), "need should print a seq: {seq}");

        let matched = rrn(&socket, &["matches"]);
        assert!(matched.contains("need "), "matches: {matched}");
        assert!(matched.contains("Winter squash"), "matches: {matched}");
        let j = rrn(&socket, &["--format", "json", "matches", &seq]);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["needs"][0]["seq"].to_string(), seq);
        assert_eq!(v["needs"][0]["expired"], false);
        assert_eq!(v["needs"][0]["listings"][0]["listing_id"], listing_id);

        // --color always adds escape codes; the default does not.
        let plain = rrn(&socket, &["browse"]);
        let painted = rrn(&socket, &["--color", "always", "browse"]);
        assert!(!plain.contains('\x1b'), "default output must be plain");
        assert!(painted.contains('\x1b'), "--color always should colorize");

        // close-listing takes it off browse but keeps it in my-listings.
        assert_eq!(
            rrn(&socket, &["close-listing", &listing_id]),
            "provider_closed"
        );
        assert_eq!(rrn(&socket, &["browse"]), "no listings");
        let mine = rrn(&socket, &["my-listings"]);
        assert!(mine.contains("closed"), "my-listings after close: {mine}");

        // And the need now matches nothing, since nothing is on offer.
        let matched = rrn(&socket, &["matches"]);
        assert!(matched.contains("no matches"), "matches: {matched}");
    })
    .await;

    station.shutdown().await;
    result.unwrap();
}
