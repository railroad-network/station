//! Operator orchestration for the encrypted at-rest profile (ADR-0024): the
//! `station status`, `encrypt-in-place`, `unlock`, and `vmk refresh` flows.
//!
//! The cross-platform ceremony logic lives in [`vmk`]; the root-privileged block
//! operations live in [`volume`] behind the [`MountHelper`](volume::MountHelper)
//! seam and are Linux-only. Every encrypted-profile entry point here refuses cleanly
//! on a non-Linux host via [`volume::ensure_platform_supported`], so nothing here
//! silently degrades to plaintext.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::config::{AtRestProfile, EncryptedSection, StationConfig, StorageSection};
use crate::recovery::HolderShard;
use crate::station::CONFIG_FILE;
use crate::storage::layout::{Layout, STATE_DIR_NAME};
use crate::storage::vmk::{self, UnlockSession, VmkDescriptor};
use crate::storage::volume;

/// Reads `config.toml` from `data_dir` **without creating it** — so read-only
/// operations like `status` never write a config into an empty directory. A missing
/// file yields the default (plaintext) config.
fn load_config(data_dir: &Path) -> Result<StationConfig> {
    let path = data_dir.join(CONFIG_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(StationConfig::parse(&text, &path)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StationConfig::default_config()),
        Err(e) => Err(anyhow::Error::from(e).context(format!("read {}", path.display()))),
    }
}

/// A `station status` report (offline — reads on-disk config and the boot-dir
/// descriptor; needs no running daemon and no unlock).
pub struct StatusReport {
    /// `"plaintext"` or `"encrypted"`.
    pub profile: &'static str,
    /// Encrypted-profile detail, when `profile == "encrypted"`.
    pub encrypted: Option<EncryptedStatus>,
}

/// The encrypted-profile portion of a [`StatusReport`].
pub struct EncryptedStatus {
    /// The VMK's derived `rrn1…` address (from the boot-dir descriptor), if armed.
    pub vmk_address: Option<String>,
    /// `K`/`N` from the descriptor, if armed.
    pub threshold: Option<u8>,
    /// `N` from the descriptor, if armed.
    pub total: Option<u8>,
    /// The configured state-dir (mount point).
    pub state_dir: String,
    /// Whether the state volume is a live `dm-crypt` mount right now.
    pub mounted: bool,
}

/// Resolves the configured (or default) state dir for the encrypted profile without
/// the platform guard, so `status` can report on any host.
fn encrypted_state_dir(data_dir: &Path, config: &StationConfig) -> std::path::PathBuf {
    config
        .storage
        .encrypted
        .as_ref()
        .and_then(|e| e.state_dir.clone())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| data_dir.join(STATE_DIR_NAME))
}

/// Reports the at-rest profile and, under the encrypted profile, whether the volume
/// is mounted and the VMK descriptor's parameters. Works on any platform.
pub fn status(data_dir: &Path) -> Result<StatusReport> {
    let config = load_config(data_dir)?;
    match config.storage.at_rest {
        AtRestProfile::Plaintext => Ok(StatusReport {
            profile: "plaintext",
            encrypted: None,
        }),
        AtRestProfile::Encrypted => {
            let state_dir = encrypted_state_dir(data_dir, &config);
            let descriptor = VmkDescriptor::load_from_file(
                &data_dir.join(crate::storage::layout::VMK_DESCRIPTOR_FILE),
            )
            .ok();
            let mounted = volume::state_dir_is_live_mount(&state_dir)?;
            Ok(StatusReport {
                profile: "encrypted",
                encrypted: Some(EncryptedStatus {
                    vmk_address: descriptor.as_ref().map(|d| d.vmk_address.to_string()),
                    threshold: descriptor.as_ref().map(|d| d.threshold),
                    total: descriptor.as_ref().map(|d| d.total),
                    state_dir: state_dir.display().to_string(),
                    mounted,
                }),
            })
        }
    }
}

/// The current VMK holder set, read from the package inside the (mounted) container.
/// Errors if the volume is not mounted or the station is not encrypted.
pub fn vmk_holders(data_dir: &Path) -> Result<Vec<String>> {
    let config = load_config(data_dir)?;
    if config.storage.at_rest != AtRestProfile::Encrypted {
        bail!("this station is not running the encrypted profile");
    }
    let state_dir = encrypted_state_dir(data_dir, &config);
    if !volume::state_dir_is_live_mount(&state_dir)? {
        bail!("the state volume is not mounted");
    }
    let pkg_path = state_dir.join(crate::storage::layout::VMK_PACKAGE_FILE);
    let package = rrn_identity::recovery::flow::RecoveryPackage::load_from_file(&pkg_path)
        .context("read the VMK package from inside the container")?;
    Ok(package
        .shards
        .iter()
        .map(|s| s.holder.to_string())
        .collect())
}

/// The configured VMK threshold `K` for `data_dir`: the `[storage.encrypted]
/// threshold` when set, else the default (3). Used as the default when the operator
/// omits `--threshold`, so the config value is authoritative rather than write-only.
pub fn configured_vmk_threshold(data_dir: &Path) -> u8 {
    load_config(data_dir)
        .ok()
        .and_then(|c| c.storage.encrypted.map(|e| e.threshold))
        .unwrap_or_else(|| EncryptedSection::default().threshold)
}

/// Container size for a fresh migration: room for the ledger to grow well past its
/// current size, floored at 512 MiB. A sparse file, so the nominal size is a ceiling
/// on growth, not disk actually consumed up front.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn container_size_bytes(db_bytes: u64) -> u64 {
    const FLOOR: u64 = 512 * 1024 * 1024;
    (db_bytes.saturating_mul(4).saturating_add(256 * 1024 * 1024)).max(FLOOR)
}

/// `station encrypt-in-place` — migrate a plaintext station to the encrypted profile
/// (ADR-0024 "Migration"): provision a keyslot-less container, move the wallet and a
/// consistent DB snapshot inside (never onto the plaintext root), arm the VMK split
/// among `holders`, write the boot-dir descriptor, flip the config to the encrypted
/// profile, and securely erase the plaintext originals. Returns the per-holder shard
/// QR payloads to distribute.
///
/// Linux only. The volume is left **mounted** on success so the operator can start
/// the daemon immediately; a later reboot needs a `station unlock` ceremony.
pub fn encrypt_in_place(
    data_dir: &Path,
    passphrase: &str,
    holders: &[String],
    threshold: u8,
) -> Result<Vec<HolderShard>> {
    volume::ensure_platform_supported()?;
    #[cfg(target_os = "linux")]
    {
        linux::encrypt_in_place(data_dir, passphrase, holders, threshold)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (data_dir, passphrase, holders, threshold);
        unreachable!("guarded by ensure_platform_supported")
    }
}

/// Begins a boot ceremony for `station unlock` / `vmk refresh`: loads the boot-dir
/// descriptor and returns the session, the `rrnrecover-req:` request QR string, and
/// the console fingerprint to read aloud. Cross-platform (the ceremony is pure key
/// material); mounting happens later in [`finish_unlock_and_mount`].
pub fn begin_unlock(data_dir: &Path) -> Result<(UnlockSession, String, String, VmkDescriptor)> {
    let descriptor =
        VmkDescriptor::load_from_file(&data_dir.join(crate::storage::layout::VMK_DESCRIPTOR_FILE))
            .context("read the VMK descriptor (is this an encrypted-profile station?)")?;
    let (session, qr, fingerprint) = vmk::begin_unlock(&descriptor);
    Ok((session, qr, fingerprint, descriptor))
}

/// Finishes `station unlock`: reconstructs the VMK from the gathered holder
/// responses and opens+mounts the container. The VMK is zeroized as this returns —
/// from then on the volume key lives only in the kernel.
pub fn finish_unlock_and_mount(
    data_dir: &Path,
    session: &UnlockSession,
    responses: &[String],
) -> Result<()> {
    volume::ensure_platform_supported()?;
    let vmk = vmk::finish_unlock(session, responses)?;
    #[cfg(target_os = "linux")]
    {
        linux::open_and_mount(data_dir, &vmk)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (data_dir, &vmk);
        unreachable!("guarded by ensure_platform_supported")
    }
}

/// Finishes `vmk refresh`: reconstructs the VMK from holder responses and re-splits
/// it to `new_holders` at `new_threshold`, revoking the old shards. Requires the
/// volume to be **mounted** (the full package lives inside it). Returns the new
/// per-holder shard QR payloads. Cross-platform (no block operations — only the
/// package and the boot-dir descriptor are rewritten).
pub fn finish_refresh(
    data_dir: &Path,
    session: &UnlockSession,
    responses: &[String],
    new_holders: &[String],
    new_threshold: u8,
) -> Result<Vec<HolderShard>> {
    let mut config = load_config(data_dir)?;
    if config.storage.at_rest != AtRestProfile::Encrypted {
        bail!("this station is not running the encrypted profile");
    }
    let state_dir = encrypted_state_dir(data_dir, &config);
    if !volume::state_dir_is_live_mount(&state_dir)? {
        bail!("the state volume is not mounted — run `station unlock` before `vmk refresh`");
    }
    let vmk = vmk::finish_unlock(session, responses)?;
    let pkg_path = state_dir.join(crate::storage::layout::VMK_PACKAGE_FILE);
    let package = rrn_identity::recovery::flow::RecoveryPackage::load_from_file(&pkg_path)
        .context("read the current VMK package from inside the container")?;
    let (refreshed, descriptor, shards) = vmk::refresh(&vmk, &package, new_holders, new_threshold)?;
    refreshed
        .save_to_file(&pkg_path)
        .context("persist the refreshed VMK package")?;
    descriptor
        .save_to_file(&data_dir.join(crate::storage::layout::VMK_DESCRIPTOR_FILE))
        .context("write the updated VMK descriptor")?;
    // Keep `config.toml`'s recorded threshold in step with the new descriptor, so the
    // config value never drifts from the K the ceremony now enforces.
    if let Some(enc) = config.storage.encrypted.as_mut() {
        if enc.threshold != new_threshold {
            enc.threshold = new_threshold;
            config
                .save(&data_dir.join(CONFIG_FILE))
                .context("update the recorded threshold in config.toml after refresh")?;
        }
    }
    Ok(shards)
}

/// Writes the encrypted-profile config to `config.toml` after a successful
/// migration: `at_rest = "encrypted"` plus the `[storage.encrypted]` block.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_encrypted_config(
    data_dir: &Path,
    mut config: StationConfig,
    layout: &Layout,
    threshold: u8,
) -> Result<()> {
    // Note: the holder set is deliberately NOT written here — it lives only in the
    // VMK package inside the container, never on the unencrypted boot dir (ADR-0024).
    config.storage = StorageSection {
        at_rest: AtRestProfile::Encrypted,
        encrypted: Some(EncryptedSection {
            container_path: Some(layout.container_path().display().to_string()),
            state_dir: Some(layout.state_dir().display().to_string()),
            threshold,
        }),
    };
    config
        .save(&data_dir.join(CONFIG_FILE))
        .context("write encrypted-profile config")?;
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::station::DB_FILE;
    use crate::storage::layout::RETICULUM_DIR;
    use crate::storage::vmk::Vmk;
    use crate::storage::volume::{MountHelper, SudoCryptsetupHelper};
    use zeroize::Zeroizing;

    /// The migration proper (see [`super::encrypt_in_place`]).
    pub fn encrypt_in_place(
        data_dir: &Path,
        passphrase: &str,
        holders: &[String],
        threshold: u8,
    ) -> Result<Vec<HolderShard>> {
        let config = load_config(data_dir)?;
        if config.storage.at_rest == AtRestProfile::Encrypted {
            bail!("this station is already running the encrypted profile");
        }

        // Refuse to migrate under a live daemon: it would keep appending to the
        // plaintext DB after the snapshot, and those records would be lost (and the
        // erase below would pull the file out from under it).
        let sock = data_dir.join(crate::station::SOCKET_FILE);
        if sock.exists() && std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            bail!(
                "a station daemon appears to be running (its socket {} accepts connections) — \
                 stop it before `encrypt-in-place`",
                sock.display()
            );
        }

        // Source (plaintext) and destination (encrypted) layouts.
        let plain = Layout::plaintext(data_dir);
        let state_dir = data_dir.join(STATE_DIR_NAME);
        let container = data_dir.join(crate::storage::layout::CONTAINER_FILE);
        let enc = Layout::encrypted(data_dir, &state_dir, &container);

        // Validate the source is a plaintext station and the destination is clear.
        if !plain.wallet_path().exists() || !plain.db_path().exists() {
            bail!(
                "{} is not a plaintext station data dir (no wallet/database to migrate)",
                data_dir.display()
            );
        }
        if container.exists() || state_dir.exists() {
            bail!(
                "an encrypted container ({}) or state dir ({}) already exists; refusing to \
                 overwrite",
                container.display(),
                state_dir.display()
            );
        }

        // Verify the passphrase up front by opening the wallet (and prove it is a
        // real station wallet) before doing anything destructive.
        rrn_identity::wallet::WalletContents::load_from_file(&plain.wallet_path(), passphrase)
            .context("open wallet (wrong passphrase, or not a station data dir)")?;

        // Validate the holder set/threshold BEFORE any block operation: a bad
        // `--holder`/`--threshold` must fail here, not after `provision` has mounted a
        // container under a VMK that then leaves memory forever (an unrecoverable
        // orphan). This is the same check `vmk::arm` runs below.
        vmk::validate_holders(holders, threshold)?;

        // Provision the keyslot-less container with a fresh VMK, then mount it.
        let vmk = Vmk::generate();
        let helper = SudoCryptsetupHelper;
        let db_bytes = std::fs::metadata(plain.db_path())
            .map(|m| m.len())
            .unwrap_or(0);
        {
            let key = vmk.key_bytes();
            helper
                .provision(
                    &container,
                    container_size_bytes(db_bytes),
                    &key,
                    &enc.mapping_name(),
                    &state_dir,
                )
                .context("provision the encrypted container")?;
            // key (Zeroizing) drops here.
        }

        // Everything past `provision` has mounted a container and attached a loop
        // device; a failure here would otherwise leave that orphan behind and the
        // "already exists" guard would refuse the retry. Run the rest under a guard
        // that tears the orphan down on error.
        let outcome =
            migrate_after_provision(data_dir, &plain, &enc, config, holders, threshold, &vmk);
        if outcome.is_err() {
            cleanup_orphan_container(&enc);
        }
        outcome
    }

    /// The migration steps that run *after* the container is provisioned and mounted:
    /// move state inside, arm the VMK, verify the migrated ledger, flip the config,
    /// then securely erase the plaintext originals. Split out so [`encrypt_in_place`]
    /// can tear down the mounted orphan if any of it fails.
    fn migrate_after_provision(
        data_dir: &Path,
        plain: &Layout,
        enc: &Layout,
        config: StationConfig,
        holders: &[String],
        threshold: u8,
        vmk: &Vmk,
    ) -> Result<Vec<HolderShard>> {
        // Move state INSIDE the container — never onto the plaintext root.
        // 1. A consistent DB snapshot straight into the container (VACUUM INTO).
        rrn_storage::db::snapshot_to(&plain.db_path(), &enc.db_path())
            .context("snapshot the ledger into the encrypted container")?;
        // 2. The wallet verbatim (already passphrase-encrypted; moved for brick
        //    protection so the boot ceremony needs no station passphrase on the
        //    plaintext medium).
        std::fs::copy(plain.wallet_path(), enc.wallet_path()).context("move wallet inside")?;
        // 3. Optional companions.
        if plain.paired_path().exists() {
            std::fs::copy(plain.paired_path(), enc.paired_path()).context("move paired list")?;
        }
        if plain.recovery_path().exists() {
            std::fs::copy(plain.recovery_path(), enc.recovery_path())
                .context("move station recovery package")?;
        }
        let plain_reticulum = data_dir.join(RETICULUM_DIR);
        if plain_reticulum.exists() {
            copy_dir_recursive(&plain_reticulum, &enc.reticulum_dir())
                .context("move Reticulum directory inside")?;
        }

        // Arm the VMK split; the full package lives inside the container, the
        // descriptor on the boot dir.
        let (package, descriptor, shards) = vmk::arm(vmk, holders, threshold)?;
        package
            .save_to_file(&enc.vmk_package_path())
            .context("persist the VMK package inside the container")?;
        descriptor
            .save_to_file(&enc.vmk_descriptor_path())
            .context("write the VMK descriptor to the boot dir")?;

        // VERIFY the migrated ledger against the source BEFORE flipping the config or
        // erasing the only other copy: the container's hash chain must verify and hold
        // exactly as many entries as the plaintext original (ADR-0024 "…VACUUM INTO
        // across, verify, then securely erase"). If this fails the config is still
        // plaintext and the originals are intact, so the guard's teardown leaves a
        // clean plaintext station.
        {
            let src = rrn_storage::db::Database::open(&plain.db_path())?;
            let src_n = rrn_storage::log::AppendLog::new(&src)
                .verify_chain()
                .context("verify the source ledger before erase")?;
            drop(src);
            let dst = rrn_storage::db::Database::open(&enc.db_path())?;
            let dst_n = rrn_storage::log::AppendLog::new(&dst)
                .verify_chain()
                .context("verify the migrated ledger before erase")?;
            drop(dst);
            if src_n != dst_n {
                bail!(
                    "migrated ledger has {dst_n} entries but the source has {src_n}; refusing to \
                     erase the plaintext original (the container is mounted at {} — investigate)",
                    enc.state_dir().display()
                );
            }
        }

        // Only now — the migrated copy is verified good — flip the config to the
        // encrypted profile (holder set NOT persisted here). After this point a crash
        // leaves a verified, mounted encrypted station with (harmless) plaintext
        // leftovers the operator can shred manually; `station run` uses the container.
        write_encrypted_config(data_dir, config, enc, threshold)?;

        // Securely erase the plaintext originals. Note the caller must warn that
        // secure erase is unreliable on wear-levelled flash/SD.
        secure_erase(&plain.wallet_path());
        secure_erase(&plain.db_path());
        secure_erase(&data_dir.join(format!("{DB_FILE}-wal")));
        secure_erase(&data_dir.join(format!("{DB_FILE}-shm")));
        if plain.paired_path().exists() {
            secure_erase(&plain.paired_path());
        }
        // The station recovery package names every station-key trustee — the same
        // "coercion-target map" ADR-0024 keeps off the boot dir — so shred it, not
        // just unlink it, once its copy is safe inside the container.
        if plain.recovery_path().exists() {
            secure_erase(&plain.recovery_path());
        }
        // The Reticulum directory holds the adapter's identity secret key; shred its
        // files rather than a plain remove.
        secure_erase_dir(&plain_reticulum);
        // The marketplace index is non-secret (rebuilt inside the container on next
        // run), so a plain remove is fine.
        let _ = std::fs::remove_dir_all(data_dir.join(crate::station::LISTING_INDEX_DIR));

        Ok(shards)
    }

    /// Best-effort teardown of a half-migrated container: unmount, close the crypt
    /// mapping, detach the loop device, and remove the container file and state dir so
    /// a re-run of `encrypt-in-place` is not refused by the "already exists" guard.
    fn cleanup_orphan_container(enc: &Layout) {
        let helper = SudoCryptsetupHelper;
        let _ = helper.close(&enc.mapping_name(), enc.container_path(), enc.state_dir());
        let _ = std::fs::remove_file(enc.container_path());
        let _ = std::fs::remove_dir_all(enc.state_dir());
    }

    /// Opens and mounts the already-provisioned container with a reconstructed VMK
    /// (the `station unlock` completion), enforcing the zero-keyslot precondition and
    /// the live-mount check via [`volume::DmCryptVolume`].
    pub fn open_and_mount(data_dir: &Path, vmk: &Vmk) -> Result<()> {
        let config = load_config(data_dir)?;
        let layout = Layout::resolve(data_dir, &config)?;
        if !layout.is_encrypted() {
            bail!("this station is not running the encrypted profile");
        }
        if volume::state_dir_is_live_mount(layout.state_dir())? {
            // Already unlocked (e.g. a concurrent unlock) — nothing to do.
            return Ok(());
        }
        let vol = volume::DmCryptVolume::new(
            layout.container_path().to_path_buf(),
            layout.mapping_name(),
            layout.state_dir().to_path_buf(),
        );
        let key: Zeroizing<[u8; 32]> = vmk.key_bytes();
        vol.open(&key)
            .context("open and mount the encrypted volume")
    }

    /// Best-effort secure erase of a plaintext file: `shred -u` then remove.
    fn secure_erase(path: &Path) {
        if !path.exists() {
            return;
        }
        let _ = std::process::Command::new("shred")
            .args(["-u", "-z"])
            .arg(path)
            .output();
        let _ = std::fs::remove_file(path);
    }

    /// Best-effort secure erase of a directory tree: [`secure_erase`] every file
    /// (depth-first) before removing the directories, so secret files (e.g. the
    /// Reticulum adapter identity key) are shredded rather than merely unlinked.
    fn secure_erase_dir(dir: &Path) {
        if !dir.exists() {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                match entry.file_type() {
                    Ok(ty) if ty.is_dir() => secure_erase_dir(&path),
                    _ => secure_erase(&path),
                }
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A minimal recursive directory copy (used to move the Reticulum dir inside).
    fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let to = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir_recursive(&entry.path(), &to)?;
            } else {
                std::fs::copy(entry.path(), &to)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reports_plaintext_for_a_default_station() {
        let dir = tempfile::tempdir().unwrap();
        // A default config (plaintext profile).
        StationConfig::default_config()
            .save(&dir.path().join(CONFIG_FILE))
            .unwrap();
        let report = status(dir.path()).unwrap();
        assert_eq!(report.profile, "plaintext");
        assert!(report.encrypted.is_none());
    }

    #[test]
    fn status_reports_encrypted_and_unmounted_when_configured() {
        let dir = tempfile::tempdir().unwrap();
        let text = "[network]\nlisten = \"127.0.0.1:7411\"\n[storage]\nat_rest = \"encrypted\"\n\
                    [storage.encrypted]\nthreshold = 3\n";
        std::fs::write(dir.path().join(CONFIG_FILE), text).unwrap();
        let report = status(dir.path()).unwrap();
        assert_eq!(report.profile, "encrypted");
        let enc = report.encrypted.expect("encrypted status");
        // No descriptor written yet, and nothing is mounted.
        assert!(enc.vmk_address.is_none());
        assert!(!enc.mounted);
        assert!(enc.state_dir.ends_with("state"));
    }

    #[test]
    fn container_size_has_a_floor_and_grows_with_db() {
        assert_eq!(container_size_bytes(0), 512 * 1024 * 1024);
        // A big DB pushes the size above the floor.
        let big = 400 * 1024 * 1024;
        assert!(container_size_bytes(big) > 512 * 1024 * 1024);
    }
}
