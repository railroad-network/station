//! Encrypted-at-rest integration tests (ADR-0024) — **Linux, dm-crypt, root**.
//!
//! These exercise the real kernel block-encryption path: provisioning a
//! keyslot-less LUKS2 container, the brick property on raw bytes, the boot ceremony
//! reconstructing the volume key, ledger durability across an unmount/remount cycle,
//! and the `Station::open` mount guard. None of this can run on the macOS dev host, so the
//! whole file is `#![cfg(target_os = "linux")]` and every test is `#[ignore]`d:
//! `--ignored` is the opt-in. There is no "skip if unavailable" fallback —
//! [`require_dmcrypt`] **panics** with a clear message if the prerequisites
//! (cryptsetup, loop devices, passwordless sudo, the `dm_crypt` module) are missing,
//! so a run that was asked for cannot silently pass by doing nothing.
//!
//! Run them (on a Linux host / the `at-rest-dmcrypt` CI lane):
//!
//! ```sh
//! sudo modprobe dm_crypt
//! cargo test -p rrn-station --test at_rest_dmcrypt -- --ignored --nocapture
//! ```
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use dcbor::prelude::*;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::{self, RecoveryRequest};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use rrn_station::recovery::{HolderShard, REQUEST_QR_PREFIX, RESPONSE_PREFIX, SHARD_QR_PREFIX};
use rrn_station::storage::vmk::{self, Vmk};
use rrn_station::storage::volume::{self, DmCryptVolume, MountHelper, SudoCryptsetupHelper};

/// A minimal signed value for populating a real hash-chained log.
#[derive(Clone)]
struct Note(u64);
impl From<Note> for CBOR {
    fn from(n: Note) -> Self {
        n.0.into()
    }
}

/// Panics unless the host can actually run dm-crypt. Asked-for runs must fail loudly
/// on a misconfigured host, never silently skip.
fn require_dmcrypt() {
    fn ok(cmd: &str, args: &[&str]) -> bool {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    assert!(ok("cryptsetup", &["--version"]), "cryptsetup not installed");
    assert!(
        ok("losetup", &["-f"]),
        "no free loop device (losetup -f failed)"
    );
    assert!(ok("sudo", &["-n", "true"]), "passwordless sudo required");
    // Ensure the dm_crypt module is available (load it; ignore already-loaded).
    let _ = Command::new("sudo")
        .args(["-n", "modprobe", "dm_crypt"])
        .output();
}

/// Owns a provisioned container and tears it down (umount, close, detach) on drop,
/// so a failing assertion never leaves a dangling mapping or loop device.
struct TestVolume {
    _work: tempfile::TempDir,
    boot_dir: PathBuf,
    container: PathBuf,
    state_dir: PathBuf,
    mapping: String,
}

impl TestVolume {
    /// Provisions a fresh keyslot-less container with `vmk`, mounted at `state_dir`.
    ///
    /// The dm-crypt mapping name is derived from the (unique per-test) boot dir with
    /// the same formula `Layout::mapping_name` uses, so (a) concurrently-running tests
    /// never collide on a mapping name, and (b) `Station::open`'s strict crypt-mount
    /// guard, which recomputes the name from the boot dir, matches this mount.
    fn provision(vmk: &Vmk) -> Self {
        let work = tempfile::tempdir().unwrap();
        let boot_dir = work.path().to_path_buf();
        let container = boot_dir.join("state.img");
        let state_dir = boot_dir.join("state");
        // Canonicalize the boot dir before hashing, exactly as `Layout::mapping_name`
        // does, so this mount's mapping equals the one `Station::open`'s strict guard
        // recomputes even when TMPDIR resolves through a symlink.
        let canonical = std::fs::canonicalize(&boot_dir).unwrap_or_else(|_| boot_dir.clone());
        let mapping = format!(
            "rrnstate-{}",
            &Hash::of(canonical.to_string_lossy().as_bytes()).to_hex()[..12]
        );
        let helper = SudoCryptsetupHelper;
        helper
            .provision(
                &container,
                64 * 1024 * 1024,
                &vmk.key_bytes(),
                &mapping,
                &state_dir,
            )
            .expect("provision container");
        TestVolume {
            _work: work,
            boot_dir,
            container,
            state_dir,
            mapping,
        }
    }

    fn close(&self) {
        let _ = Command::new("sudo")
            .args(["-n", "umount"])
            .arg(&self.state_dir)
            .output();
        let _ = Command::new("sudo")
            .args(["-n", "cryptsetup", "close", &self.mapping])
            .output();
        for d in loop_devices(&self.container) {
            let _ = Command::new("sudo")
                .args(["-n", "losetup", "-d", &d])
                .output();
        }
    }
}

impl Drop for TestVolume {
    fn drop(&mut self) {
        self.close();
    }
}

fn loop_devices(container: &Path) -> Vec<String> {
    let out = Command::new("losetup").arg("-j").arg(container).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| l.split(':').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn holder_set(n: usize) -> (Vec<Keypair>, Vec<String>) {
    let kps: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
    let addrs = kps
        .iter()
        .map(|k| Address::from_public_key(k.public_key()).to_string())
        .collect();
    (kps, addrs)
}

fn responses_for(
    request_qr: &str,
    shards: &[HolderShard],
    who: &[(usize, &Keypair)],
) -> Vec<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let req = RecoveryRequest::from_bytes(
        &b64.decode(request_qr.strip_prefix(REQUEST_QR_PREFIX).unwrap())
            .unwrap(),
    )
    .unwrap();
    who.iter()
        .map(|(i, kp)| {
            let stored = b64
                .decode(shards[*i].qr_payload.strip_prefix(SHARD_QR_PREFIX).unwrap())
                .unwrap();
            let resp = ceremony::build_response(&stored, kp.secret_key(), &req).unwrap();
            format!("{RESPONSE_PREFIX}{}", b64.encode(resp))
        })
        .collect()
}

/// Writes N chained, signed log entries into a station.db under `dir`.
fn seed_log(dir: &Path, n: u64) {
    let db = Database::open(&dir.join("station.db")).unwrap();
    rrn_storage::migrations::run(&db).unwrap();
    let kp = Keypair::generate();
    let mut log = AppendLog::new(&db);
    for i in 0..n {
        log.append(SignedPayload::sign(Note(i), &kp), 1_000 + i as i64)
            .unwrap();
    }
}

fn verify_log(dir: &Path) -> u64 {
    let db = Database::open(&dir.join("station.db")).unwrap();
    let log = AppendLog::new(&db);
    log.verify_chain().expect("hash chain verifies")
}

// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn brick_property_no_plaintext_at_rest_with_positive_control() {
    require_dmcrypt();
    let marker = format!("MEMBER-MEMO-{}", std::process::id());

    let vmk = Vmk::generate();
    let vol = TestVolume::provision(&vmk);
    // Plant known plaintext inside the mounted (decrypted) volume.
    let marker_file = vol.state_dir.join("memo.txt");
    std::fs::write(&marker_file, marker.as_bytes()).unwrap();
    // Sanity: it is readable while mounted.
    assert!(std::fs::read_to_string(&marker_file)
        .unwrap()
        .contains(&marker));

    // Power off: unmount + close the mapping, leaving only the container brick.
    vol.close();
    assert!(
        !volume::state_dir_is_live_mount(&vol.state_dir).unwrap(),
        "state dir must be unmounted after close"
    );

    // Sweep the raw container bytes and the whole boot dir: the marker must be gone.
    let container_bytes = std::fs::read(&vol.container).unwrap();
    assert!(
        !contains(&container_bytes, marker.as_bytes()),
        "plaintext marker LEAKED into the container bytes — not a brick"
    );
    assert!(
        container_bytes.len() > 1024,
        "container should be a non-trivial LUKS image"
    );
    assert!(
        !dir_contains_marker(&vol.boot_dir, &marker, Some(&vol.container)),
        "plaintext marker LEAKED onto the unencrypted boot dir"
    );

    // Positive control: the identical sweep DOES find the marker in a plaintext dir,
    // proving the sweep can detect plaintext at all.
    let control = tempfile::tempdir().unwrap();
    std::fs::write(control.path().join("memo.txt"), marker.as_bytes()).unwrap();
    assert!(
        dir_contains_marker(control.path(), &marker, None),
        "positive control failed — the sweep cannot detect plaintext"
    );
}

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn provisioning_leaves_zero_keyslots() {
    require_dmcrypt();
    let vmk = Vmk::generate();
    let vol = TestVolume::provision(&vmk);
    let helper = SudoCryptsetupHelper;
    let slots = MountHelper::keyslot_count(&helper, &vol.container).unwrap();
    assert_eq!(
        slots, 0,
        "a real brick has zero keyslots (no wrapped key on disk)"
    );
}

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn boot_ceremony_reconstructs_the_key_and_opens_the_volume() {
    require_dmcrypt();
    let vmk = Vmk::generate();
    let vol = TestVolume::provision(&vmk);
    // Plant content, then power off.
    std::fs::write(vol.state_dir.join("marker"), b"hello").unwrap();
    vol.close();

    // Arm the VMK among 3 holders (2-of-3) and run the wallet-free ceremony.
    let (kps, addrs) = holder_set(3);
    let (_pkg, descriptor, shards) = vmk::arm(&vmk, &addrs, 2).unwrap();
    let (session, req_qr, _fp) = vmk::begin_unlock(&descriptor);
    let responses = responses_for(&req_qr, &shards, &[(0, &kps[0]), (2, &kps[2])]);
    let recovered = vmk::finish_unlock(&session, &responses).unwrap();

    // The reconstructed key opens the container and the planted content is back.
    let dmv = DmCryptVolume::new(
        vol.container.clone(),
        vol.mapping.clone(),
        vol.state_dir.clone(),
    );
    dmv.open(&recovered.key_bytes())
        .expect("reconstructed VMK opens the volume");
    assert!(volume::state_dir_is_live_mount(&vol.state_dir).unwrap());
    assert_eq!(
        std::fs::read_to_string(vol.state_dir.join("marker")).unwrap(),
        "hello"
    );
}

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn remount_cycle_preserves_and_verifies_the_chain() {
    require_dmcrypt();
    // Loop a few seeds: write a hash-chained log inside the container, unmount and
    // close the dm-crypt mapping, then re-open with the same VMK and confirm the
    // chain still verifies with every entry. This proves the ledger survives the
    // full close/re-attach cycle (a daemon restart while the host stays up) with no
    // corruption or lost entries. It is a *clean* unmount, not a kill-9 during
    // writes: SQLite checkpoints its WAL when `seed_log` drops the connection, so
    // there is no open WAL at unmount. True power-loss-mid-write consistency rests on
    // ext4 ordered journaling under dm-crypt plus SQLite WAL recovery, exercised by
    // the manual field procedure in the runbook rather than in-process (an open DB
    // handle would make the `umount` fail with "target is busy").
    for seed in 0..3u64 {
        let vmk = Vmk::generate();
        let vol = TestVolume::provision(&vmk);
        let n = 8 + seed;
        seed_log(&vol.state_dir, n);
        assert_eq!(
            verify_log(&vol.state_dir),
            n,
            "seed {seed}: chain before unmount"
        );

        // Unmount + close the mapping (a daemon stop / host-up restart).
        vol.close();

        // Re-open the same container with the same VMK and verify the chain survived
        // intact — no corruption, no lost entries.
        let dmv = DmCryptVolume::new(
            vol.container.clone(),
            vol.mapping.clone(),
            vol.state_dir.clone(),
        );
        dmv.open(&vmk.key_bytes()).expect("re-open after remount");
        assert_eq!(
            verify_log(&vol.state_dir),
            n,
            "seed {seed}: chain after remount"
        );
    }
}

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn station_open_refuses_an_unmounted_state_dir_and_writes_nothing() {
    require_dmcrypt();
    // Mis-ordered restart: encrypted profile, but the state volume is NOT mounted.
    // Station::open must refuse *before touching any file* — no plaintext station.db
    // may appear on the (unencrypted) state dir.
    let work = tempfile::tempdir().unwrap();
    let boot = work.path();
    let state = boot.join("state");
    std::fs::create_dir_all(&state).unwrap(); // a plain directory, not a mount
    let cfg = format!(
        "[network]\nlisten = \"127.0.0.1:7411\"\n[storage]\nat_rest = \"encrypted\"\n\
         [storage.encrypted]\nstate_dir = \"{}\"\nthreshold = 3\n",
        state.display()
    );
    std::fs::write(boot.join("config.toml"), cfg).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        rrn_station::Station::open(rrn_station::StationParams {
            data_dir: boot.to_path_buf(),
            passphrase: "pw".into(),
            clock: rrn_station::Clock::system(),
        })
        .await
    });
    assert!(
        res.is_err(),
        "Station::open must refuse an unmounted encrypted volume"
    );
    assert!(
        !state.join("station.db").exists(),
        "no plaintext station.db may be created on an unmounted state dir"
    );
    assert!(!state.join("wallet.rrnwallet").exists());
}

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn station_runs_on_the_encrypted_volume_and_leaves_no_plaintext_at_rest() {
    require_dmcrypt();
    // Invariant 1 as specified: run a station under the encrypted profile, stop it,
    // then sweep every byte at rest for a planted member memo — it must be absent.
    let marker = format!("MEMBER-MEMO-RUN-{}", std::process::id());

    let vmk = Vmk::generate();
    let vol = TestVolume::provision(&vmk);

    // Seed a real station INSIDE the mounted container: wallet, migrated DB with a
    // log entry whose bytes carry the marker (via a memo-ish note is not enough, so
    // also drop a paired-list file carrying the marker, which Station::open loads).
    rrn_identity::wallet::WalletContents::create_new()
        .save_to_file(&vol.state_dir.join("wallet.rrnwallet"), "pw")
        .unwrap();
    seed_log(&vol.state_dir, 5);
    std::fs::write(
        vol.state_dir.join("paired_mobiles.json"),
        format!("{{\"mobiles\":[],\"note\":\"{marker}\"}}").as_bytes(),
    )
    .unwrap();

    // Config on the (unencrypted) boot dir selects the encrypted profile at this
    // container/state dir. A random loopback port avoids collisions on the CI host.
    let cfg = format!(
        "[network]\nlisten = \"127.0.0.1:0\"\n[mobile]\nlisten = \"127.0.0.1:0\"\nadvertise = false\n\
         [storage]\nat_rest = \"encrypted\"\n[storage.encrypted]\nstate_dir = \"{}\"\ncontainer_path = \"{}\"\n",
        vol.state_dir.display(),
        vol.container.display()
    );
    std::fs::write(vol.boot_dir.join("config.toml"), cfg).unwrap();

    // Station::open must succeed against the live mount, and its socket lands on the
    // boot dir while the index is built inside the container.
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let station = rrn_station::Station::open(rrn_station::StationParams {
            data_dir: vol.boot_dir.clone(),
            passphrase: "pw".into(),
            clock: rrn_station::Clock::system(),
        })
        .await
        .expect("station opens on the mounted encrypted volume");
        assert!(
            vol.boot_dir.join("station.sock").exists(),
            "socket on boot dir"
        );
        assert!(
            vol.state_dir.join("marketplace_index").exists(),
            "index built inside the container"
        );
        station.shutdown().await;
    });

    // Power off and sweep: the marker must be nowhere at rest.
    vol.close();
    let container_bytes = std::fs::read(&vol.container).unwrap();
    assert!(
        !contains(&container_bytes, marker.as_bytes()),
        "planted memo LEAKED into the container bytes"
    );
    assert!(
        !dir_contains_marker(&vol.boot_dir, &marker, Some(&vol.container)),
        "planted memo LEAKED onto the unencrypted boot dir (incl. any WAL/SHM leftovers)"
    );
}

#[test]
#[ignore = "needs dm-crypt + loop + passwordless sudo; run in the at-rest-dmcrypt CI lane"]
fn strict_guard_matches_only_this_containers_mapping() {
    require_dmcrypt();
    // A live dm-crypt mount is present at the state dir. The loose guard accepts it,
    // and the strict guard accepts it *only* under this container's own mapping name —
    // a different mapping (e.g. another station's, or a plaintext dm-linear volume
    // that happened to mount here) must be rejected, or `Station::open` could serve
    // the wrong volume.
    let vmk = Vmk::generate();
    let vol = TestVolume::provision(&vmk);

    assert!(
        volume::state_dir_is_live_mount(&vol.state_dir).unwrap(),
        "loose guard sees the live mount"
    );
    assert!(
        volume::state_dir_is_crypt_mount(&vol.state_dir, &vol.mapping).unwrap(),
        "strict guard accepts this container's own mapping"
    );
    assert!(
        !volume::state_dir_is_crypt_mount(&vol.state_dir, "rrnstate-000000000000").unwrap(),
        "strict guard rejects a different mapping name at the same mount point"
    );
}

// ---------------------------------------------------------------------------

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether any file under `dir` (except `skip`) contains `marker` in its bytes.
fn dir_contains_marker(dir: &Path, marker: &str, skip: Option<&Path>) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if skip == Some(path.as_path()) {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                if contains(&bytes, marker.as_bytes()) {
                    return true;
                }
            }
        }
    }
    false
}
