//! Social-recovery round-trip over RPC (exercises `backup_export` +
//! `recover_import`).
//!
//! A station exports a 2-of-3 recovery package sealed to three holder keys; we
//! then play the role each holder would in real life — decrypt our own shard —
//! write the decrypted raw shards to files, and ask the station to reconstruct.
//! The reconstructed address must equal the station's own identity.

use std::path::Path;

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_identity::recovery::encryption::decrypt_shard;
use rrn_identity::recovery::flow::RecoveryPackage;

use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams};
use rrn_station::Clock;

const PASSPHRASE: &str = "recovery-test";

fn write_config(dir: &Path, port: u16) {
    let text = format!(
        "[peers]\nlist = []\n\n[network]\nlisten = \"127.0.0.1:{port}\"\n\n\
         [timers]\nsweep_interval_secs = 60\ngossip_interval_secs = 60\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_then_recover_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let me = Station::init(dir.path(), PASSPHRASE).unwrap().to_string();
    write_config(dir.path(), 7459);

    let station = Station::open(StationParams {
        data_dir: dir.path().to_path_buf(),
        passphrase: PASSPHRASE.into(),
        clock: Clock::system(),
    })
    .await
    .unwrap();
    let client = UnixClient::new(station.socket_path());

    // Three holders; a 2-of-3 split.
    let holders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
    let holder_addrs: Vec<String> = holders
        .iter()
        .map(|k| Address::from_public_key(k.public_key()).to_string())
        .collect();

    let pkg_path = dir.path().join("backup.rrnrecovery");
    let v = client
        .call(
            "backup_export",
            serde_json::json!({
                "holders": holder_addrs,
                "threshold": 2,
                "output": pkg_path.to_string_lossy(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(v["recovery_path"], pkg_path.to_string_lossy().to_string());
    assert!(pkg_path.exists());

    // Each of two holders decrypts their own shard and writes it out as the
    // 33-byte (index ‖ data) raw-shard file the recover RPC expects.
    let package = RecoveryPackage::load_from_file(&pkg_path).unwrap();
    let mut shard_files = Vec::new();
    for (i, holder) in holders.iter().enumerate().take(2) {
        let sealed = &package.shards[i];
        let raw = decrypt_shard(sealed, holder.secret_key()).unwrap();
        let mut bytes = Vec::with_capacity(33);
        bytes.push(raw.index.0);
        bytes.extend_from_slice(&raw.data);
        let path = dir.path().join(format!("shard{i}.bin"));
        std::fs::write(&path, &bytes).unwrap();
        shard_files.push(path.to_string_lossy().into_owned());
    }

    let v = client
        .call(
            "recover_import",
            serde_json::json!({
                "recovery_path": pkg_path.to_string_lossy(),
                "shards": shard_files,
            }),
        )
        .await
        .unwrap();
    assert_eq!(v["restored_address"], me);

    station.shutdown().await;
}
