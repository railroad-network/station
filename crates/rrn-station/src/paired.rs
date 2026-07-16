//! Persistent record of which mobiles have paired with this station (T1.3.3).
//!
//! Pairing binds static public keys and nothing else (see
//! [ADR-0008](../../../docs/adr/0008-mobile-station-transport.md)): there is no
//! certificate to pin, expire, or rotate. A paired mobile is remembered by its
//! bech32 identity address plus the moment it paired, and that list is the
//! entire authorization story for the mobile-facing HTTP surface — an unpaired
//! key's requests are rejected (T1.3.4). Either side may revoke: the operator
//! via `station unpair <address>`, the mobile from its own Settings.
//!
//! The list is persisted to `<data_dir>/paired_mobiles.json` so it survives a
//! station restart, mirroring the mobile, which persists the station's key
//! across its own restarts. Together that is what makes a pairing outlast both
//! processes, per the M1.3 exit criterion.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rrn_crypto::hash::Hasher;
use rrn_crypto::keypair::PublicKey;
use serde::{Deserialize, Serialize};

/// File under the station data dir that holds the paired list.
const FILE: &str = "paired_mobiles.json";

/// One paired mobile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedMobile {
    /// The mobile's bech32 identity address (`rrn1…`) — the same string the
    /// mobile signs its requests under, and what `unpair` takes.
    pub address: String,
    /// Station-clock Unix seconds when this pairing was confirmed.
    pub paired_at: i64,
}

/// The station's set of paired mobiles, backed by a JSON file.
///
/// Keyed by address so a repeat pair of the same mobile updates rather than
/// duplicates, and so the list has a stable order for display.
#[derive(Debug, Default)]
pub struct PairedMobiles {
    mobiles: BTreeMap<String, PairedMobile>,
    /// Where [`save`](Self::save) writes. Not serialized — it *is* the location.
    path: PathBuf,
}

/// The on-disk shape. Separated from [`PairedMobiles`] so the file never carries
/// the path it lives at.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    mobiles: Vec<PairedMobile>,
}

impl PairedMobiles {
    /// Loads the paired list from `<data_dir>/paired_mobiles.json`, or returns an
    /// empty list (bound to that path) if the file does not exist yet.
    pub fn load(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join(FILE);
        if !path.exists() {
            return Ok(Self {
                mobiles: BTreeMap::new(),
                path,
            });
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        let stored: Stored = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parse {}: {e}", path.display()))?;
        let mobiles = stored
            .mobiles
            .into_iter()
            .map(|m| (m.address.clone(), m))
            .collect();
        Ok(Self { mobiles, path })
    }

    /// Writes the list back to disk, atomically (temp file + rename) so a crash
    /// mid-write cannot leave a truncated list that would silently unpair
    /// everyone.
    pub fn save(&self) -> anyhow::Result<()> {
        let stored = Stored {
            mobiles: self.mobiles.values().cloned().collect(),
        };
        let json = serde_json::to_string_pretty(&stored)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| anyhow::anyhow!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| anyhow::anyhow!("rename into {}: {e}", self.path.display()))?;
        Ok(())
    }

    /// Records a mobile as paired at `now` (Unix seconds), replacing any prior
    /// entry for the same address. Does **not** persist — call [`save`](Self::save).
    pub fn add(&mut self, address: String, now: i64) {
        self.mobiles.insert(
            address.clone(),
            PairedMobile {
                address,
                paired_at: now,
            },
        );
    }

    /// Removes a mobile by address. Returns whether it was present. Does not
    /// persist — call [`save`](Self::save).
    pub fn remove(&mut self, address: &str) -> bool {
        self.mobiles.remove(address).is_some()
    }

    /// Whether `address` is currently paired — the authorization check the
    /// request channel (T1.3.4) will gate on.
    pub fn contains(&self, address: &str) -> bool {
        self.mobiles.contains_key(address)
    }

    /// All paired mobiles, in stable address order.
    pub fn list(&self) -> Vec<&PairedMobile> {
        self.mobiles.values().collect()
    }
}

/// Domain-separation tag for the pairing SAS, so this hash can never collide
/// with any other blake3 use in the system.
const SAS_TAG: &[u8] = b"rrn-pair-sas-v1";

/// The 8-hex-char short authenticated string both sides display so a human can
/// confirm the pair in person (ADR-0008).
///
/// Derived from **both** static public keys, so it authenticates the pair rather
/// than a rotatable credential: a network man-in-the-middle would have to
/// present its own key and could not reproduce this code. The input order is
/// fixed — station key first, then mobile key — so the station and the mobile
/// compute an identical value; this ordering is the cross-implementation
/// contract the mobile's `Pairing` seam must match exactly.
pub fn confirmation_code(station: &PublicKey, mobile: &PublicKey) -> String {
    let mut hasher = Hasher::new();
    hasher.update(SAS_TAG);
    hasher.update(&station.to_bytes());
    hasher.update(&mobile.to_bytes());
    let hex = hasher.finalize().to_hex();
    hex[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    fn tmp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn missing_file_loads_empty() {
        let dir = tmp_dir();
        let paired = PairedMobiles::load(dir.path()).unwrap();
        assert!(paired.list().is_empty());
        assert!(!paired.contains("rrn1anything"));
    }

    #[test]
    fn add_persists_and_survives_reload() {
        let dir = tmp_dir();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 1_000);
        paired.add("rrn1bob".to_string(), 2_000);
        paired.save().unwrap();

        let reloaded = PairedMobiles::load(dir.path()).unwrap();
        assert!(reloaded.contains("rrn1alice"));
        assert!(reloaded.contains("rrn1bob"));
        assert_eq!(reloaded.list().len(), 2);
    }

    #[test]
    fn add_same_address_updates_not_duplicates() {
        let dir = tmp_dir();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 1_000);
        paired.add("rrn1alice".to_string(), 5_000);
        assert_eq!(paired.list().len(), 1);
        assert_eq!(paired.list()[0].paired_at, 5_000);
    }

    #[test]
    fn remove_reports_presence_and_persists() {
        let dir = tmp_dir();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 1_000);
        assert!(paired.remove("rrn1alice"));
        assert!(!paired.remove("rrn1alice"));
        paired.save().unwrap();

        let reloaded = PairedMobiles::load(dir.path()).unwrap();
        assert!(!reloaded.contains("rrn1alice"));
    }

    #[test]
    fn confirmation_code_is_stable_and_order_fixed() {
        let station = Keypair::generate().public_key();
        let mobile = Keypair::generate().public_key();

        let code = confirmation_code(&station, &mobile);
        assert_eq!(code.len(), 8);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic for the same pair.
        assert_eq!(code, confirmation_code(&station, &mobile));
        // Order is load-bearing: swapping the keys is a different pair.
        assert_ne!(code, confirmation_code(&mobile, &station));
    }

    #[test]
    fn confirmation_code_differs_per_pair() {
        let station = Keypair::generate().public_key();
        let m1 = Keypair::generate().public_key();
        let m2 = Keypair::generate().public_key();
        assert_ne!(
            confirmation_code(&station, &m1),
            confirmation_code(&station, &m2)
        );
    }
}
