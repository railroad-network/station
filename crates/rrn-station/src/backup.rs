//! Encrypted station backup and restore (ADR-0016 / T1.11.3).
//!
//! A backup is a single encrypted archive of the irreplaceable contents of a
//! station's data directory:
//!
//! - `station.db` — captured as a **consistent live snapshot** via
//!   [`rrn_storage::db::snapshot_to`] (`VACUUM INTO`). Because the database is
//!   in WAL mode this needs no exclusive lock, so a running station can be
//!   backed up without downtime.
//! - `wallet.rrnwallet` — copied verbatim (it is already passphrase-encrypted).
//! - `paired_mobiles.json` and `config.toml` — if present.
//!
//! The derived `marketplace_index/` is deliberately excluded; a restored
//! station rebuilds it from the log on first run.
//!
//! The whole bundle is sealed in a [`DualWrapEnvelope`]: encrypted under a fresh
//! random data-encryption key whose key is wrapped both under the passphrase and
//! to the station's own public key. The passphrase path is used by
//! [`restore_backup`] here; the public-key path is what the (T1.11.3 slice D)
//! recovery ceremony uses to open a backup after a lost passphrase. See
//! [ADR-0016](../../../docs/adr/0016-station-backup-and-key-recovery.md).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dcbor::prelude::*;

use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_identity::address::Address;
use rrn_identity::envelope::DualWrapEnvelope;
use rrn_identity::wallet::WalletContents;

use crate::station::{CONFIG_FILE, DB_FILE, PAIRED_FILE, WALLET_FILE};

/// File extension for a written backup archive.
pub const BACKUP_EXTENSION: &str = "rrnbak";

/// Bundle format version, bumped if the set of archived files or their framing
/// changes.
const BUNDLE_VERSION: u32 = 1;

/// The plaintext bundle carried inside the encrypted envelope: a versioned map
/// from data-dir-relative filename to raw bytes.
struct BackupBundle {
    version: u32,
    files: BTreeMap<String, Vec<u8>>,
}

impl From<BackupBundle> for CBOR {
    fn from(b: BackupBundle) -> Self {
        let mut files = Map::new();
        for (name, bytes) in b.files {
            files.insert(name, CBOR::to_byte_string(bytes));
        }
        let mut m = Map::new();
        m.insert("v", b.version);
        m.insert("files", CBOR::from(files));
        m.into()
    }
}

impl TryFrom<CBOR> for BackupBundle {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> core::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let version = map.extract::<&str, u32>("v")?;
        let files_map = match map.extract::<&str, CBOR>("files")?.into_case() {
            CBORCase::Map(m) => m,
            _ => return Err(dcbor::Error::WrongType),
        };
        let mut files = BTreeMap::new();
        for (k, v) in files_map.iter() {
            let name: String = k.clone().try_into()?;
            let bytes = v.clone().try_into_byte_string()?.as_slice().to_vec();
            files.insert(name, bytes);
        }
        Ok(Self { version, files })
    }
}

/// Writes an encrypted backup of the station at `data_dir` to `out_path`.
///
/// `passphrase` must be the station wallet's passphrase: it is verified by
/// opening the wallet (a wrong passphrase fails here, before anything is
/// written), and it protects the archive. Returns the path written.
pub fn create_backup(data_dir: &Path, passphrase: &str, out_path: &Path) -> Result<PathBuf> {
    // Open the wallet first: this both validates the passphrase up front and
    // gives us the station's public key for the envelope's recovery wrap.
    let wallet = WalletContents::load_from_file(&data_dir.join(WALLET_FILE), passphrase)
        .context("open wallet (wrong passphrase, or not a station data dir)")?;
    let station_pub = Keypair::from_secret(wallet.secret_key.clone()).public_key();

    let db_path = data_dir.join(DB_FILE);
    if !db_path.exists() {
        bail!(
            "no database at {} — not a station data dir",
            db_path.display()
        );
    }

    let mut files = BTreeMap::new();

    // Consistent live snapshot of the ledger into a throwaway temp dir, read
    // into the bundle, then dropped.
    let snap_dir = tempfile::tempdir().context("create temp dir for db snapshot")?;
    let snap_path = snap_dir.path().join("snapshot.db");
    rrn_storage::db::snapshot_to(&db_path, &snap_path).context("snapshot database")?;
    let db_bytes = std::fs::read(&snap_path).context("read database snapshot")?;
    files.insert(DB_FILE.to_string(), db_bytes);

    // Wallet verbatim (already encrypted).
    let wallet_bytes = std::fs::read(data_dir.join(WALLET_FILE)).context("read wallet file")?;
    files.insert(WALLET_FILE.to_string(), wallet_bytes);

    // Optional smaller files.
    for name in [PAIRED_FILE, CONFIG_FILE] {
        let path = data_dir.join(name);
        if path.exists() {
            let bytes = std::fs::read(&path).with_context(|| format!("read {name}"))?;
            files.insert(name.to_string(), bytes);
        }
    }

    let bundle = BackupBundle {
        version: BUNDLE_VERSION,
        files,
    };
    let plaintext = to_canonical_bytes(bundle);

    let envelope = DualWrapEnvelope::seal(&plaintext, passphrase, &station_pub)
        .context("seal backup archive")?;
    let archive_bytes = to_canonical_bytes(envelope);

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::write(out_path, archive_bytes)
        .with_context(|| format!("write backup to {}", out_path.display()))?;

    Ok(out_path.to_path_buf())
}

/// Restores an encrypted backup archive into `dest_dir`.
///
/// Refuses to write into a directory that already holds a wallet or database
/// unless `force` is set, so a restore cannot silently clobber a live station.
/// Returns the restored station's address.
pub fn restore_backup(
    archive_path: &Path,
    dest_dir: &Path,
    passphrase: &str,
    force: bool,
) -> Result<Address> {
    let archive_bytes = std::fs::read(archive_path)
        .with_context(|| format!("read archive {}", archive_path.display()))?;
    let envelope: DualWrapEnvelope =
        from_canonical_bytes(&archive_bytes).context("parse backup archive")?;

    let plaintext = envelope
        .open_with_passphrase(passphrase)
        .context("decrypt backup (wrong passphrase, or corrupt archive)")?;
    let bundle: BackupBundle =
        from_canonical_bytes(&plaintext).context("parse decrypted backup bundle")?;
    if bundle.version != BUNDLE_VERSION {
        bail!(
            "unsupported backup bundle version {} (this build supports {BUNDLE_VERSION})",
            bundle.version
        );
    }

    write_bundle(&bundle, dest_dir, force, false)?;
    envelope_address(&envelope)
}

/// Restores an archive using the station's **secret key** rather than the
/// passphrase — the recovery path (T1.11.3 slice D) taken after a lost
/// passphrase, once the key has been reconstructed from a threshold of holders.
///
/// Writes the ledger and the paired/config files, but **skips the stored wallet
/// file**: it was encrypted under the lost passphrase and is useless. The caller
/// writes a fresh wallet from the reconstructed key under a new passphrase.
/// Returns the restored station's address.
pub fn restore_with_secret(
    archive_path: &Path,
    dest_dir: &Path,
    secret: &SecretKey,
    force: bool,
) -> Result<Address> {
    let archive_bytes = std::fs::read(archive_path)
        .with_context(|| format!("read archive {}", archive_path.display()))?;
    let envelope: DualWrapEnvelope =
        from_canonical_bytes(&archive_bytes).context("parse backup archive")?;

    let plaintext = envelope
        .open_with_secret_key(secret)
        .context("open backup with the recovered key")?;
    let bundle: BackupBundle =
        from_canonical_bytes(&plaintext).context("parse decrypted backup bundle")?;
    if bundle.version != BUNDLE_VERSION {
        bail!(
            "unsupported backup bundle version {} (this build supports {BUNDLE_VERSION})",
            bundle.version
        );
    }

    write_bundle(&bundle, dest_dir, force, true)?;
    envelope_address(&envelope)
}

/// Writes a decrypted bundle's files into `dest_dir`, with the clobber guard and
/// a path-traversal check. When `skip_wallet` is set the stored wallet file is
/// not written (the caller supplies a freshly-keyed one).
fn write_bundle(
    bundle: &BackupBundle,
    dest_dir: &Path,
    force: bool,
    skip_wallet: bool,
) -> Result<()> {
    let occupied = dest_dir.join(WALLET_FILE).exists() || dest_dir.join(DB_FILE).exists();
    if occupied && !force {
        bail!(
            "{} already contains a station (wallet or database present); \
             pass --force to overwrite",
            dest_dir.display()
        );
    }

    std::fs::create_dir_all(dest_dir).with_context(|| format!("create {}", dest_dir.display()))?;
    for (name, bytes) in &bundle.files {
        if skip_wallet && name == WALLET_FILE {
            continue;
        }
        // Defend against a tampered bundle steering a write outside dest_dir.
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            bail!("refusing to restore suspicious filename {name:?}");
        }
        let path = dest_dir.join(name);
        std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

/// The station address recorded (in the clear) in an archive's envelope.
fn envelope_address(envelope: &DualWrapEnvelope) -> Result<Address> {
    let public = PublicKey::from_bytes(envelope.recipient_public_key())
        .map_err(|e| anyhow::anyhow!("archive carried an invalid station key: {e}"))?;
    Ok(Address::from_public_key(public))
}

/// Reads which station an archive belongs to without decrypting it — the
/// envelope records the station's public key in the clear. Used by recovery to
/// learn the target address before the key has been reconstructed.
pub fn archive_address(archive_path: &Path) -> Result<Address> {
    let archive_bytes = std::fs::read(archive_path)
        .with_context(|| format!("read archive {}", archive_path.display()))?;
    let envelope: DualWrapEnvelope =
        from_canonical_bytes(&archive_bytes).context("parse backup archive")?;
    envelope_address(&envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_storage::db::Database;

    /// Builds a minimal but realistic station data dir: an encrypted wallet, a
    /// WAL database with a row, a paired list, and a config file.
    fn seed_data_dir(dir: &Path, passphrase: &str) -> Address {
        let wallet = WalletContents::create_new();
        let address = wallet.address;
        wallet
            .save_to_file(&dir.join(WALLET_FILE), passphrase)
            .unwrap();

        // A real WAL database. Content preservation through the snapshot is
        // covered by rrn_storage's own tests; here we only need a valid,
        // live-opened database file to back up and restore.
        let db = Database::open(&dir.join(DB_FILE)).unwrap();
        drop(db);

        std::fs::write(dir.join(PAIRED_FILE), b"{\"mobiles\":[]}").unwrap();
        std::fs::write(dir.join(CONFIG_FILE), b"# config\n").unwrap();
        address
    }

    #[test]
    fn backup_then_restore_round_trips() {
        let src = tempfile::tempdir().unwrap();
        let addr = seed_data_dir(src.path(), "pw123");

        let archive = src.path().join("out.rrnbak");
        create_backup(src.path(), "pw123", &archive).unwrap();
        assert!(archive.exists());

        let dest = tempfile::tempdir().unwrap();
        let restored = restore_backup(&archive, dest.path(), "pw123", false).unwrap();
        assert_eq!(restored, addr, "restored address matches the original");

        // All four files came back.
        for name in [WALLET_FILE, DB_FILE, PAIRED_FILE, CONFIG_FILE] {
            assert!(dest.path().join(name).exists(), "{name} restored");
        }
        // The restored wallet still opens under the same passphrase.
        let w = WalletContents::load_from_file(&dest.path().join(WALLET_FILE), "pw123").unwrap();
        assert_eq!(w.address, addr);
        // The restored database is a valid, openable SQLite file.
        assert!(Database::open(&dest.path().join(DB_FILE)).is_ok());
    }

    #[test]
    fn wrong_passphrase_cannot_create_or_restore() {
        let src = tempfile::tempdir().unwrap();
        seed_data_dir(src.path(), "right");
        let archive = src.path().join("out.rrnbak");

        // Wrong passphrase is caught up front, before writing.
        assert!(create_backup(src.path(), "wrong", &archive).is_err());

        create_backup(src.path(), "right", &archive).unwrap();
        let dest = tempfile::tempdir().unwrap();
        assert!(restore_backup(&archive, dest.path(), "wrong", false).is_err());
        // And a failed restore left nothing behind.
        assert!(!dest.path().join(WALLET_FILE).exists());
    }

    #[test]
    fn restore_refuses_to_clobber_without_force() {
        let src = tempfile::tempdir().unwrap();
        seed_data_dir(src.path(), "pw");
        let archive = src.path().join("out.rrnbak");
        create_backup(src.path(), "pw", &archive).unwrap();

        // Destination already holds a station.
        let dest = tempfile::tempdir().unwrap();
        seed_data_dir(dest.path(), "pw");
        assert!(
            restore_backup(&archive, dest.path(), "pw", false).is_err(),
            "must refuse without --force"
        );
        assert!(
            restore_backup(&archive, dest.path(), "pw", true).is_ok(),
            "--force overwrites"
        );
    }
}
