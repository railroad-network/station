//! Persistent record of which mobiles have paired with this station.
//!
//! Pairing binds static public keys and nothing else (see
//! [ADR-0008](../../../docs/adr/0008-mobile-station-transport.md)): there is no
//! certificate to pin, expire, or rotate. A paired mobile is remembered by its
//! bech32 identity address plus the moment it paired, and that list is the
//! entire authorization story for the mobile-facing HTTP surface — an unpaired
//! key's requests are rejected. Either side may revoke: the operator
//! via `station unpair <address>`, the mobile from its own Settings.
//!
//! The list is persisted to `<data_dir>/paired_mobiles.json` so it survives a
//! station restart, mirroring the mobile, which persists the station's key
//! across its own restarts. Together that is what makes a pairing outlast both
//! processes, per the mobile-transport exit criterion.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File under the station data dir that holds the paired list.
use crate::station::PAIRED_FILE as FILE;

/// One paired mobile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedMobile {
    /// The mobile's bech32 identity address (`rrn1…`) — the same string the
    /// mobile signs its requests under, and what `unpair` takes.
    pub address: String,
    /// Station-clock Unix seconds when this pairing was confirmed.
    pub paired_at: i64,
    /// The highest request nonce seen from this mobile on the authenticated
    /// channel. Monotonic per mobile: a request must carry a strictly
    /// greater nonce or it is rejected as a replay. Starts at 0 for an address
    /// never seen before, and **never decreases** — not on a re-pair, and not
    /// on an unpair followed by a new pairing (the mark is kept in the retired
    /// list meanwhile), so a request recorded under an earlier pairing can never
    /// be replayed (ADR-0008, Clarification 2026-10-14, Part B).
    /// `#[serde(default)]` so a `paired_mobiles.json` written before this field
    /// parses as 0.
    #[serde(default)]
    pub last_nonce: u64,
}

/// The station's set of paired mobiles, backed by a JSON file.
///
/// Keyed by address so a repeat pair of the same mobile updates rather than
/// duplicates, and so the list has a stable order for display.
#[derive(Debug, Default)]
pub struct PairedMobiles {
    mobiles: BTreeMap<String, PairedMobile>,
    /// The nonce high-water marks of unpaired mobiles, by address, restored by
    /// [`add`](Self::add) if the address pairs again. Grows only by an operator
    /// unpair, so it is left uncapped.
    retired: BTreeMap<String, u64>,
    /// Where [`save`](Self::save) writes. Not serialized — it *is* the location.
    path: PathBuf,
}

/// The on-disk shape. Separated from [`PairedMobiles`] so the file never carries
/// the path it lives at.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    mobiles: Vec<PairedMobile>,
    /// `#[serde(default)]` so a file written before nonce retention parses.
    #[serde(default)]
    retired_nonces: Vec<RetiredNonce>,
}

/// The nonce high-water mark of a mobile that has been unpaired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RetiredNonce {
    /// The unpaired mobile's bech32 address.
    address: String,
    /// Its highest accepted request nonce when it was unpaired.
    last_nonce: u64,
}

impl PairedMobiles {
    /// Loads the paired list from `<data_dir>/paired_mobiles.json`, or returns an
    /// empty list (bound to that path) if the file does not exist yet.
    pub fn load(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join(FILE);
        if !path.exists() {
            return Ok(Self {
                mobiles: BTreeMap::new(),
                retired: BTreeMap::new(),
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
        let retired = stored
            .retired_nonces
            .into_iter()
            .map(|r| (r.address, r.last_nonce))
            .collect();
        Ok(Self {
            mobiles,
            retired,
            path,
        })
    }

    /// Writes the list back to disk, atomically (temp file + rename) so a crash
    /// mid-write cannot leave a truncated list that would silently unpair
    /// everyone.
    pub fn save(&self) -> anyhow::Result<()> {
        let stored = Stored {
            mobiles: self.mobiles.values().cloned().collect(),
            retired_nonces: self
                .retired
                .iter()
                .map(|(address, &last_nonce)| RetiredNonce {
                    address: address.clone(),
                    last_nonce,
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&stored)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| anyhow::anyhow!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| anyhow::anyhow!("rename into {}: {e}", self.path.display()))?;
        Ok(())
    }

    /// Records a mobile as paired at `now` (Unix seconds), replacing any prior
    /// entry for the same address. The nonce high-water mark carries over — the
    /// higher of the current entry's and a retired one's — and is never reset,
    /// so a re-pair, a re-confirm, or an unpair followed by a new pairing cannot
    /// reopen nonces the station already accepted. Clients send
    /// `max(last + 1, unix milliseconds)`, so a device that lost its counter
    /// still lands above the mark. Does **not** persist — call
    /// [`save`](Self::save).
    pub fn add(&mut self, address: String, now: i64) {
        let current = self.mobiles.get(&address).map_or(0, |m| m.last_nonce);
        let retired = self.retired.remove(&address).unwrap_or(0);
        self.mobiles.insert(
            address.clone(),
            PairedMobile {
                address,
                paired_at: now,
                last_nonce: current.max(retired),
            },
        );
    }

    /// Accepts request nonce `nonce` from `address` if it is strictly greater
    /// than the highest previously seen — the monotonic replay check for the
    /// authenticated channel. On success updates the stored high-water
    /// mark and returns `true`; returns `false` for an unpaired address or a
    /// stale/replayed nonce. Does **not** persist — call [`save`](Self::save)
    /// after a successful accept so the bump survives a restart.
    pub fn accept_nonce(&mut self, address: &str, nonce: u64) -> bool {
        match self.mobiles.get_mut(address) {
            Some(m) if nonce > m.last_nonce => {
                m.last_nonce = nonce;
                true
            }
            _ => false,
        }
    }

    /// Removes a mobile by address, keeping its nonce high-water mark in the
    /// retired list for a later [`add`](Self::add). Returns whether it was
    /// present. Does not persist — call [`save`](Self::save).
    pub fn remove(&mut self, address: &str) -> bool {
        match self.mobiles.remove(address) {
            Some(m) => {
                let mark = self.retired.entry(m.address).or_insert(0);
                *mark = (*mark).max(m.last_nonce);
                true
            }
            None => false,
        }
    }

    /// Whether `address` is currently paired — the authorization check the
    /// request channel will gate on.
    pub fn contains(&self, address: &str) -> bool {
        self.mobiles.contains_key(address)
    }

    /// All paired mobiles, in stable address order.
    pub fn list(&self) -> Vec<&PairedMobile> {
        self.mobiles.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn nonce_must_strictly_increase_and_persists() {
        let dir = tmp_dir();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 1_000);

        // First request (nonce 1) accepted; the same or lower rejected.
        assert!(paired.accept_nonce("rrn1alice", 1));
        assert!(!paired.accept_nonce("rrn1alice", 1), "replay of same nonce");
        assert!(!paired.accept_nonce("rrn1alice", 0), "lower nonce");
        // A jump forward is fine (the mobile may skip nonces).
        assert!(paired.accept_nonce("rrn1alice", 5));
        assert!(
            !paired.accept_nonce("rrn1alice", 4),
            "below high-water mark"
        );
        // Unpaired address never accepts.
        assert!(!paired.accept_nonce("rrn1bob", 1));

        paired.save().unwrap();
        let reloaded = PairedMobiles::load(dir.path()).unwrap();
        // The high-water mark survived the restart, so old nonces stay rejected.
        assert!(!reloaded.list()[0].last_nonce.eq(&0));
        let mut reloaded = reloaded;
        assert!(!reloaded.accept_nonce("rrn1alice", 5));
        assert!(reloaded.accept_nonce("rrn1alice", 6));
    }

    #[test]
    fn repairing_keeps_the_nonce_window() {
        let dir = tmp_dir();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 1_000);
        assert!(paired.accept_nonce("rrn1alice", 9));
        // Re-pairing (or re-confirming) the same address keeps the mark: a
        // request recorded under the earlier pairing stays a replay.
        paired.add("rrn1alice".to_string(), 2_000);
        assert_eq!(paired.list()[0].paired_at, 2_000);
        assert!(!paired.accept_nonce("rrn1alice", 1));
        assert!(!paired.accept_nonce("rrn1alice", 9));
        assert!(paired.accept_nonce("rrn1alice", 10));
    }

    #[test]
    fn unpair_then_pair_keeps_the_retired_mark() {
        let dir = tmp_dir();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 1_000);
        assert!(paired.accept_nonce("rrn1alice", 9));
        assert!(paired.remove("rrn1alice"));
        assert!(!paired.contains("rrn1alice"));
        // The retired mark survives a restart while unpaired.
        paired.save().unwrap();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        paired.add("rrn1alice".to_string(), 2_000);
        assert_eq!(paired.list()[0].last_nonce, 9);
        assert!(!paired.accept_nonce("rrn1alice", 9));
        assert!(paired.accept_nonce("rrn1alice", 10));
        // Consumed back into the live entry: a second unpair retires the new mark.
        assert!(paired.remove("rrn1alice"));
        paired.add("rrn1alice".to_string(), 3_000);
        assert_eq!(paired.list()[0].last_nonce, 10);
        // Other addresses start from zero.
        paired.add("rrn1bob".to_string(), 3_000);
        assert!(paired.accept_nonce("rrn1bob", 1));
    }

    #[test]
    fn old_file_without_retired_nonces_parses() {
        let dir = tmp_dir();
        std::fs::write(
            dir.path().join(FILE),
            r#"{"mobiles":[{"address":"rrn1alice","paired_at":1000,"last_nonce":4}]}"#,
        )
        .unwrap();
        let mut paired = PairedMobiles::load(dir.path()).unwrap();
        assert!(paired.contains("rrn1alice"));
        assert!(!paired.accept_nonce("rrn1alice", 4));
        assert!(paired.remove("rrn1alice"));
        paired.save().unwrap();
        let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(text.contains("retired_nonces"), "{text}");
    }
}
