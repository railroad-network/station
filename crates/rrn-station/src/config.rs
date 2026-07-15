//! On-disk station configuration: `<data_dir>/config.toml`.
//!
//! *Peer* discovery is a static list — no mDNS, no DHT. The file names the
//! peers this station gossips with and the TCP address it listens on for
//! incoming peer connections (distinct from the Unix socket, which is local-only
//! CLI IPC). Three optional sections — [`MobileConfig`], [`SettlementSection`],
//! and [`TimersSection`] — cover the mobile-facing surface and let the demo
//! shorten the settlement window and speed up the sweep/gossip loops; all
//! default to production-ish values when omitted, so the minimal file in the
//! [module example](#example) is valid on its own.
//!
//! Note that *mobile* discovery is mDNS ([`crate::mdns`], T1.3.2) — that is a
//! separate surface from peer gossip, and the two are not to be confused.
//!
//! # Example
//!
//! ```toml
//! [peers]
//! list = ["127.0.0.1:7411", "127.0.0.1:7412"]
//!
//! [network]
//! listen = "127.0.0.1:7411"
//! ```

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use rrn_ledger::settlement::DEFAULT_WINDOW_SECONDS;

/// The parsed `config.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StationConfig {
    /// Static peer list.
    #[serde(default)]
    pub peers: PeersConfig,
    /// Inbound peer-network binding.
    pub network: NetworkConfig,
    /// The mobile-facing surface (optional; defaults to advertising on all
    /// interfaces).
    #[serde(default)]
    pub mobile: MobileConfig,
    /// Settlement tuning (optional; defaults to the 48h production window).
    #[serde(default)]
    pub settlement: SettlementSection,
    /// Background-loop intervals (optional; defaults to the daemon cadence).
    #[serde(default)]
    pub timers: TimersSection,
}

/// `[peers]` — who to gossip with.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeersConfig {
    /// `host:port` of each peer's gossip listener.
    #[serde(default)]
    pub list: Vec<String>,
}

/// `[network]` — where to accept incoming peer connections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// `host:port` this station binds for inbound gossip.
    pub listen: String,
}

/// `[mobile]` — how paired mobile clients reach this station.
///
/// Distinct from [`NetworkConfig`], which is the *peer* gossip surface: a phone
/// and a peer station speak different protocols on different ports.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MobileConfig {
    /// `host:port` the mobile↔station listener binds. Unlike the peer listener
    /// this must be reachable from the LAN, so it defaults to all interfaces
    /// rather than loopback.
    ///
    /// T1.3.2 only *advertises* this port over mDNS; T1.3.4 binds it.
    #[serde(default = "default_mobile_listen")]
    pub listen: String,
    /// Overrides the name advertised over mDNS. When omitted — the normal case
    /// — the name is derived deterministically from the station's own address
    /// (see [`crate::mdns::station_name`]), so it is stable across restarts and
    /// distinct between stations without anything being persisted here.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether to advertise on the local network at all. Set `false` to run
    /// dark: mobiles must then be pointed at this station by hand.
    #[serde(default = "default_advertise")]
    pub advertise: bool,
}

fn default_mobile_listen() -> String {
    "0.0.0.0:7500".to_string()
}
fn default_advertise() -> bool {
    true
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            listen: default_mobile_listen(),
            name: None,
            advertise: default_advertise(),
        }
    }
}

/// `[settlement]` — the dispute/settlement window.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementSection {
    /// Seconds a confirmed transaction waits before it settles. The demo sets
    /// this to a handful of seconds; production is [`DEFAULT_WINDOW_SECONDS`].
    #[serde(default = "default_window_seconds")]
    pub window_seconds: u64,
}

/// `[timers]` — how often the background loops fire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimersSection {
    /// Settlement-sweep interval in seconds (spec default: 30).
    #[serde(default = "default_sweep_interval")]
    pub sweep_interval_secs: u64,
    /// Gossip-round interval in seconds (spec default: 5).
    #[serde(default = "default_gossip_interval")]
    pub gossip_interval_secs: u64,
}

fn default_window_seconds() -> u64 {
    DEFAULT_WINDOW_SECONDS
}
fn default_sweep_interval() -> u64 {
    30
}
fn default_gossip_interval() -> u64 {
    5
}

impl Default for SettlementSection {
    fn default() -> Self {
        Self {
            window_seconds: default_window_seconds(),
        }
    }
}

impl Default for TimersSection {
    fn default() -> Self {
        Self {
            sweep_interval_secs: default_sweep_interval(),
            gossip_interval_secs: default_gossip_interval(),
        }
    }
}

/// Errors loading or creating the config.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    /// The file could not be read or written.
    #[error("config i/o at {path}: {source}")]
    Io {
        /// The path involved.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file was present but not valid TOML / did not match the schema. The
    /// message carries the line/column from the `toml` parser.
    #[error("malformed config at {path}: {message}")]
    Parse {
        /// The path involved.
        path: String,
        /// The parser's message, including a line number where available.
        message: String,
    },
}

impl StationConfig {
    /// Loads the config at `path`, or creates a default and writes it there if
    /// the file is missing.
    ///
    /// A default config has an empty peer list and binds to a pseudo-randomly
    /// chosen port in `7400..=7499` on loopback. A *malformed* file is an error
    /// (with a line number) — it is not silently overwritten.
    pub fn load_or_create(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Self::default_config();
                cfg.save(path)?;
                Ok(cfg)
            }
            Err(e) => Err(ConfigError::Io {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    /// Parses `text` as a `config.toml`, attributing errors to `path`.
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Writes the config to `path` as TOML.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = toml::to_string_pretty(self).expect("config serializes");
        std::fs::write(path, text).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// A fresh default: no peers, a random loopback port, production timers.
    pub fn default_config() -> Self {
        StationConfig {
            peers: PeersConfig::default(),
            network: NetworkConfig {
                listen: format!("127.0.0.1:{}", random_port()),
            },
            mobile: MobileConfig::default(),
            settlement: SettlementSection::default(),
            timers: TimersSection::default(),
        }
    }
}

/// A pseudo-random port in `7400..=7499`, seeded from the system clock. Good
/// enough to avoid collisions between two freshly-initialized local stations;
/// not security-sensitive.
fn random_port() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    7400 + (nanos % 100) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p() -> PathBuf {
        PathBuf::from("config.toml")
    }

    #[test]
    fn minimal_file_parses_with_defaults() {
        let text = r#"
            [peers]
            list = ["127.0.0.1:7412"]

            [network]
            listen = "127.0.0.1:7411"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.peers.list, vec!["127.0.0.1:7412"]);
        assert_eq!(cfg.network.listen, "127.0.0.1:7411");
        // Optional sections fall back to defaults.
        assert_eq!(cfg.settlement.window_seconds, DEFAULT_WINDOW_SECONDS);
        assert_eq!(cfg.timers.sweep_interval_secs, 30);
        assert_eq!(cfg.timers.gossip_interval_secs, 5);
        // A config written before [mobile] existed still parses, and advertises
        // on all interfaces with a derived name.
        assert_eq!(cfg.mobile.listen, "0.0.0.0:7500");
        assert!(cfg.mobile.advertise);
        assert_eq!(cfg.mobile.name, None);
    }

    #[test]
    fn mobile_section_overrides_defaults() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [mobile]
            listen = "192.168.1.9:9000"
            name = "Railroad Station — Blue Ridge"
            advertise = false
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.mobile.listen, "192.168.1.9:9000");
        assert_eq!(
            cfg.mobile.name.as_deref(),
            Some("Railroad Station — Blue Ridge")
        );
        assert!(!cfg.mobile.advertise);
    }

    #[test]
    fn missing_file_creates_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let cfg = StationConfig::load_or_create(&path).unwrap();
        assert!(path.exists());
        assert!(cfg.peers.list.is_empty());
        let port: u16 = cfg
            .network
            .listen
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!((7400..=7499).contains(&port));
        // Re-loading reads back the written file (no overwrite).
        let again = StationConfig::load_or_create(&path).unwrap();
        assert_eq!(again.network.listen, cfg.network.listen);
    }

    #[test]
    fn malformed_file_errors_with_location() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is = = not valid toml\n[network\n").unwrap();
        let err = StationConfig::load_or_create(&path).unwrap_err();
        match err {
            ConfigError::Parse { message, .. } => {
                // `toml` reports a line/column; assert it mentions a line.
                assert!(message.contains("line"), "message was: {message}");
            }
            other => panic!("expected parse error, got {other:?}"),
        }
    }
}
