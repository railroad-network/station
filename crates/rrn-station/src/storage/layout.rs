//! The two-root data layout (ADR-0024).
//!
//! Every path a station reads or writes resolves through a [`Layout`], which knows
//! which of two roots a file belongs to:
//!
//! - the unencrypted **boot dir** — `config.toml`, the CLI socket, the LUKS
//!   container file, and the VMK unlock descriptor: the minimum a locked node needs
//!   to configure itself and *begin* a ceremony;
//! - the encrypted **state dir** — the wallet, the ledger database (and its
//!   `-wal`/`-shm` sidecars), paired mobiles, the marketplace index, the recovery
//!   package, and the Reticulum directory: everything sensitive.
//!
//! Under the **plaintext** profile the two roots are the same directory, so the
//! layout collapses to today's flat data dir and existing call sites are unchanged.
//! Under the **encrypted** profile they differ, and the state dir is a `dm-crypt`
//! mount point that is empty until a ceremony unlocks it.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::config::{AtRestProfile, StationConfig};
use crate::station::{
    CONFIG_FILE, DB_FILE, LISTING_INDEX_DIR, PAIRED_FILE, SOCKET_FILE, WALLET_FILE,
};

/// The LUKS2 container file within the boot dir (encrypted profile).
pub const CONTAINER_FILE: &str = "state.img";
/// The default mount point (state dir) within the boot dir (encrypted profile).
pub const STATE_DIR_NAME: &str = "state";
/// The VMK unlock descriptor within the boot dir (encrypted profile). Holds only
/// the VMK's derived address and `K`/`N` — never the holder set.
pub const VMK_DESCRIPTOR_FILE: &str = "vmk.descriptor";
/// The recovery package filename within the state dir (mirrors
/// [`crate::recovery::RECOVERY_FILE`]).
pub const RECOVERY_FILE: &str = "recovery.rrnrecovery";
/// The VMK recovery package filename within the state dir — the full package with
/// holder identities, kept inside the container for post-unlock status/refresh
/// (ADR-0024). Distinct from the station-identity [`RECOVERY_FILE`].
pub const VMK_PACKAGE_FILE: &str = "vmk.rrnrecovery";
/// The Reticulum config/adapter directory within the state dir.
pub const RETICULUM_DIR: &str = "reticulum";

/// Where a station's files live, split across the (possibly identical) boot and
/// state roots.
///
/// Construct with [`Layout::plaintext`] (both roots the flat data dir) or
/// [`Layout::encrypted`] (an unencrypted boot dir and a separate encrypted state
/// dir). The accessors below are the single source of truth for every path the
/// daemon and CLI touch, so the two-root split lives in exactly one place.
#[derive(Clone, Debug)]
pub struct Layout {
    boot_dir: PathBuf,
    state_dir: PathBuf,
    container_path: PathBuf,
    encrypted: bool,
}

impl Layout {
    /// The plaintext profile: one flat directory holding everything (today's
    /// behavior). Both roots are `data_dir`.
    pub fn plaintext(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let container_path = data_dir.join(CONTAINER_FILE);
        Self {
            boot_dir: data_dir.clone(),
            state_dir: data_dir,
            container_path,
            encrypted: false,
        }
    }

    /// The encrypted profile: an unencrypted `boot_dir`, a separate `state_dir`
    /// (the container's mount point), and the LUKS container file.
    pub fn encrypted(
        boot_dir: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        container_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            boot_dir: boot_dir.into(),
            state_dir: state_dir.into(),
            container_path: container_path.into(),
            encrypted: true,
        }
    }

    /// Resolves the layout for `boot_dir` from a station config: the flat plaintext
    /// layout, or the two-root encrypted layout with `state_dir`/`container_path`
    /// taken from `[storage.encrypted]` (defaulting under `boot_dir`). The encrypted
    /// profile is refused on non-Linux hosts here, so a mis-set config fails at
    /// bring-up rather than silently serving plaintext.
    pub fn resolve(boot_dir: impl Into<PathBuf>, config: &StationConfig) -> Result<Self> {
        let boot_dir = boot_dir.into();
        match config.storage.at_rest {
            AtRestProfile::Plaintext => Ok(Self::plaintext(boot_dir)),
            AtRestProfile::Encrypted => {
                crate::storage::volume::ensure_platform_supported()?;
                let enc = config.storage.encrypted.as_ref();
                let state_dir = enc
                    .and_then(|e| e.state_dir.clone())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| boot_dir.join(STATE_DIR_NAME));
                let container_path = enc
                    .and_then(|e| e.container_path.clone())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| boot_dir.join(CONTAINER_FILE));
                if state_dir == boot_dir {
                    bail!(
                        "[storage.encrypted] state_dir must differ from the boot dir; the state \
                         dir is the encrypted container's mount point, not the plaintext root"
                    );
                }
                Ok(Self::encrypted(boot_dir, state_dir, container_path))
            }
        }
    }

    /// The unencrypted boot dir (config, socket, container, descriptor).
    pub fn boot_dir(&self) -> &Path {
        &self.boot_dir
    }

    /// The encrypted state dir (everything sensitive). Equal to the boot dir under
    /// the plaintext profile.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Whether this is an encrypted-profile layout (two distinct roots).
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// A stable device-mapper name for this station's `dm-crypt` mapping, derived
    /// from the boot dir so two stations on one host do not collide.
    pub fn mapping_name(&self) -> String {
        let digest = rrn_crypto::hash::Hash::of(self.boot_dir.to_string_lossy().as_bytes());
        format!("rrnstate-{}", &digest.to_hex()[..12])
    }

    // --- boot dir (unencrypted) ---------------------------------------------

    /// `config.toml` — always in the boot dir, readable while locked.
    pub fn config_path(&self) -> PathBuf {
        self.boot_dir.join(CONFIG_FILE)
    }

    /// The CLI Unix socket — in the boot dir, so the operator can reach a locked
    /// (pre-unlock) daemon.
    pub fn socket_path(&self) -> PathBuf {
        self.boot_dir.join(SOCKET_FILE)
    }

    /// The LUKS container file (encrypted profile). Meaningful only when
    /// [`is_encrypted`](Layout::is_encrypted); under the plaintext profile there is
    /// none.
    pub fn container_path(&self) -> &Path {
        &self.container_path
    }

    /// The VMK unlock descriptor (encrypted profile) — in the boot dir.
    pub fn vmk_descriptor_path(&self) -> PathBuf {
        self.boot_dir.join(VMK_DESCRIPTOR_FILE)
    }

    // --- state dir (encrypted) ----------------------------------------------

    /// `wallet.rrnwallet` — inside the container.
    pub fn wallet_path(&self) -> PathBuf {
        self.state_dir.join(WALLET_FILE)
    }

    /// `station.db` (its `-wal`/`-shm` follow it automatically) — inside the
    /// container.
    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join(DB_FILE)
    }

    /// `paired_mobiles.json` — inside the container.
    pub fn paired_path(&self) -> PathBuf {
        self.state_dir.join(PAIRED_FILE)
    }

    /// The marketplace search index directory — inside the container (its text
    /// would otherwise leak).
    pub fn index_dir(&self) -> PathBuf {
        self.state_dir.join(LISTING_INDEX_DIR)
    }

    /// The recovery package (`recovery.rrnrecovery`) — inside the container.
    pub fn recovery_path(&self) -> PathBuf {
        self.state_dir.join(RECOVERY_FILE)
    }

    /// The VMK recovery package (`vmk.rrnrecovery`) — inside the container.
    pub fn vmk_package_path(&self) -> PathBuf {
        self.state_dir.join(VMK_PACKAGE_FILE)
    }

    /// The Reticulum config/adapter directory — inside the container (ADR-0026 §7:
    /// the adapter identity is at-rest scope).
    pub fn reticulum_dir(&self) -> PathBuf {
        self.state_dir.join(RETICULUM_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_collapses_to_one_root() {
        let l = Layout::plaintext("/data");
        assert!(!l.is_encrypted());
        assert_eq!(l.config_path(), Path::new("/data/config.toml"));
        assert_eq!(l.socket_path(), Path::new("/data/station.sock"));
        assert_eq!(l.wallet_path(), Path::new("/data/wallet.rrnwallet"));
        assert_eq!(l.db_path(), Path::new("/data/station.db"));
        assert_eq!(l.index_dir(), Path::new("/data/marketplace_index"));
        // Every file resolves under the single root.
        for p in [
            l.wallet_path(),
            l.db_path(),
            l.paired_path(),
            l.recovery_path(),
            l.reticulum_dir(),
            l.config_path(),
            l.socket_path(),
        ] {
            assert!(p.starts_with("/data"));
        }
    }

    #[test]
    fn encrypted_splits_boot_from_state() {
        let l = Layout::encrypted("/boot", "/run/state", "/boot/state.img");
        assert!(l.is_encrypted());
        // Config, socket, container, descriptor stay on the (unencrypted) boot dir.
        assert_eq!(l.config_path(), Path::new("/boot/config.toml"));
        assert_eq!(l.socket_path(), Path::new("/boot/station.sock"));
        assert_eq!(l.container_path(), Path::new("/boot/state.img"));
        assert_eq!(l.vmk_descriptor_path(), Path::new("/boot/vmk.descriptor"));
        // Everything sensitive lands under the (encrypted) state dir.
        assert_eq!(l.wallet_path(), Path::new("/run/state/wallet.rrnwallet"));
        assert_eq!(l.db_path(), Path::new("/run/state/station.db"));
        assert_eq!(l.paired_path(), Path::new("/run/state/paired_mobiles.json"));
        assert_eq!(
            l.recovery_path(),
            Path::new("/run/state/recovery.rrnrecovery")
        );
        assert_eq!(l.reticulum_dir(), Path::new("/run/state/reticulum"));
        for sensitive in [
            l.wallet_path(),
            l.db_path(),
            l.paired_path(),
            l.index_dir(),
            l.recovery_path(),
            l.reticulum_dir(),
        ] {
            assert!(
                sensitive.starts_with("/run/state"),
                "{sensitive:?} must be inside the encrypted state dir"
            );
            assert!(
                !sensitive.starts_with("/boot"),
                "{sensitive:?} must NOT be on the unencrypted boot dir"
            );
        }
    }

    #[test]
    fn resolve_plaintext_is_flat() {
        let cfg = StationConfig::parse(
            "[network]\nlisten = \"127.0.0.1:7411\"\n",
            Path::new("config.toml"),
        )
        .unwrap();
        let l = Layout::resolve("/data", &cfg).unwrap();
        assert!(!l.is_encrypted());
        assert_eq!(l.wallet_path(), Path::new("/data/wallet.rrnwallet"));
    }

    #[test]
    fn resolve_encrypted_is_linux_only() {
        let cfg = StationConfig::parse(
            "[network]\nlisten = \"127.0.0.1:7411\"\n[storage]\nat_rest = \"encrypted\"\n\
             [storage.encrypted]\nholders = [\"a\",\"b\",\"c\"]\n",
            Path::new("config.toml"),
        )
        .unwrap();
        let res = Layout::resolve("/boot", &cfg);
        if cfg!(target_os = "linux") {
            let l = res.expect("encrypted layout resolves on Linux");
            assert!(l.is_encrypted());
            assert_eq!(l.state_dir(), Path::new("/boot/state"));
            assert_eq!(l.container_path(), Path::new("/boot/state.img"));
        } else {
            assert!(res.is_err(), "encrypted profile refused off Linux");
        }
    }
}
