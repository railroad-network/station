//! mDNS advertisement: how a mobile finds this station without typing an IP.
//!
//! The station publishes a DNS-SD service — [`SERVICE_TYPE`] — on the port the
//! mobile↔station listener binds ([`crate::config::MobileConfig::listen`]). A
//! phone on the same broadcast domain browses for that type and gets back a
//! host, a port, and two TXT records:
//!
//! - `address` — this station's `rrn1…` address (its identity public key)
//! - `version` — the station version, so a mobile can flag a mismatch
//!
//! # Discovery is not trust
//!
//! Per ADR-0008 the advertisement is **unauthenticated**. Anything on the LAN
//! can publish this service type, and every TXT record is attacker-controlled:
//! the `address` here is a *claim*, not a proof. A discovered station is an
//! untrusted `(host, port, claimed address)` tuple until pairing (T1.3.3) binds
//! its static public key out-of-band, and thereafter every exchange is
//! authenticated by the sealed envelope rather than by anything learned here.
//! Nothing in this module is a security boundary, which is exactly why it is
//! safe to lean on the platform's mDNS stack on the mobile side.
//!
//! There is deliberately **no certificate fingerprint** in the TXT records. The
//! M1.3 task spec originally called for a `cert_fp`, but ADR-0008 chose sealed
//! envelopes over TLS, so there is no certificate to fingerprint.
//!
//! # Scope
//!
//! mDNS reaches one broadcast domain — the same WiFi or Ethernet segment. That
//! is the intended scope: this finds the station at your community center, not
//! a station across the internet (federation is Phase 2).

use std::net::SocketAddr;

use mdns_sd::{ServiceDaemon, ServiceInfo};
use tokio::sync::watch;

/// The DNS-SD service type mobiles browse for.
///
/// This exact string is duplicated on the mobile side (in `NSBonjourServices`
/// on iOS, which must declare it, and in the discovery seam). Changing it here
/// is a breaking change for every paired mobile.
///
/// # Why not `_railroad-station`
///
/// The M1.3 task spec asked for `_railroad-station._tcp`, which is **illegal**:
/// RFC 6763 §7 caps a Service Name at 15 characters and `railroad-station` is
/// 16. mdns-sd rejects it — but only on its own daemon thread, *after*
/// `register` has returned `Ok`, so the station would have logged that it was
/// advertising while publishing nothing at all. `rrn-station` is 11 characters
/// and matches the `rrn` prefix used throughout the project. See
/// [`service_name_is_rfc6763_legal`](tests::service_name_is_rfc6763_legal),
/// which holds the line so this cannot regress silently.
pub const SERVICE_TYPE: &str = "_rrn-station._tcp.local.";

/// Adjectives for the derived station name. Kept deliberately plain and
/// place-like: the name exists so a human can tell two stations apart in a list,
/// not to be clever.
const ADJECTIVES: &[&str] = &[
    "Quiet",
    "Amber",
    "Copper",
    "Hidden",
    "Distant",
    "Northern",
    "Silver",
    "Golden",
    "Iron",
    "Steady",
    "Winter",
    "Morning",
    "Evening",
    "Wandering",
    "Open",
    "Still",
    "Bright",
    "Deep",
    "Elder",
    "Free",
];

/// Nouns for the derived station name — railroad and landscape words, matching
/// the project's voice.
const NOUNS: &[&str] = &[
    "Forest",
    "River",
    "Junction",
    "Meadow",
    "Harbor",
    "Summit",
    "Crossing",
    "Signal",
    "Lantern",
    "Depot",
    "Valley",
    "Bridge",
    "Prairie",
    "Hollow",
    "Trestle",
    "Siding",
    "Ridge",
    "Ferry",
    "Landing",
    "Switchback",
];

/// Errors setting up the advertisement.
#[derive(thiserror::Error, Debug)]
pub enum MdnsError {
    /// The configured mobile listen address is not a `host:port`.
    #[error("mobile listen address {listen:?} is not a host:port: {source}")]
    BadListen {
        /// The offending value from `[mobile] listen`.
        listen: String,
        /// The parse failure.
        source: std::net::AddrParseError,
    },
    /// The mDNS daemon could not start, or the service could not be registered.
    #[error("mdns: {0}")]
    Daemon(String),
}

/// A live registration. Dropping this does **not** withdraw the service — pass
/// it to [`serve`], which withdraws on shutdown.
pub struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    /// The registered instance's fully-qualified DNS-SD name.
    pub fn fullname(&self) -> &str {
        &self.fullname
    }
}

/// Derives this station's human-recognizable name from its address.
///
/// Deterministic on purpose: the same station keeps the same name across
/// restarts and reinstalls without persisting anything, and two stations on one
/// network almost always differ. The task spec called for a *random* name; a
/// derived one meets the same goal (humans get something to recognize) and is
/// strictly better behaved, since a random name would either drift on every
/// restart or need to be migrated into existing configs.
///
/// Collisions are possible — 400 combinations — and harmless: the name is a
/// display label, never an identifier. Pairing verifies the address.
pub fn station_name(address: &str) -> String {
    // FNV-1a over the address. A bech32 address is already uniformly random, so
    // this only needs to spread it across two small lists; it is a cosmetic
    // picker and is not security-sensitive.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in address.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let adjective = ADJECTIVES[(hash % ADJECTIVES.len() as u64) as usize];
    let noun = NOUNS[((hash / ADJECTIVES.len() as u64) % NOUNS.len() as u64) as usize];
    format!("Railroad Station — {adjective} {noun}")
}

/// Turns a display name into a DNS-safe host label.
///
/// Instance names may be free-form UTF-8 ("Railroad Station — Quiet Forest"),
/// but the host record may not, so the pretty name is slugged down to ASCII.
fn hostname_for(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "railroad-station.local.".to_string()
    } else {
        format!("{slug}.local.")
    }
}

/// Registers this station's service on the local network.
///
/// `listen` is the mobile listener's `host:port` (only the port is advertised;
/// the addresses are discovered from the live interfaces). `name` is the display
/// name, and `address` is this station's `rrn1…` address.
pub fn advertise(listen: &str, name: &str, address: &str) -> Result<Advertisement, MdnsError> {
    let port = listen
        .parse::<SocketAddr>()
        .map_err(|source| MdnsError::BadListen {
            listen: listen.to_string(),
            source,
        })?
        .port();

    let daemon = ServiceDaemon::new().map_err(|e| MdnsError::Daemon(e.to_string()))?;

    let properties = [("address", address), ("version", env!("CARGO_PKG_VERSION"))];

    // An empty IP list plus `enable_addr_auto` lets the daemon publish whatever
    // interfaces the host actually has, and keep them current as the network
    // changes — a station on WiFi that gets a new DHCP lease stays findable.
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        name,
        &hostname_for(name),
        "",
        port,
        &properties[..],
    )
    .map_err(|e| MdnsError::Daemon(e.to_string()))?
    .enable_addr_auto();

    let fullname = info.get_fullname().to_string();
    daemon
        .register(info)
        .map_err(|e| MdnsError::Daemon(e.to_string()))?;

    Ok(Advertisement { daemon, fullname })
}

/// Holds the registration until shutdown, then withdraws it.
///
/// There is nothing to poll: the mDNS daemon runs on its own thread. This task
/// exists so the service is withdrawn *actively* on shutdown — browsers see the
/// goodbye packet and drop the station immediately, rather than showing a dead
/// entry until the record ages out.
pub async fn serve(ad: Advertisement, mut shutdown: watch::Receiver<bool>) {
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            break;
        }
    }

    match ad.daemon.unregister(&ad.fullname) {
        Ok(rx) => {
            // Give the goodbye a moment to go out, but never hang shutdown on it.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::task::spawn_blocking(move || rx.recv()).await
            })
            .await;
        }
        Err(e) => tracing::warn!(error = %e, "mdns unregister failed"),
    }
    let _ = ad.daemon.shutdown();
    tracing::info!("Stopped advertising on the local network");
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR_A: &str = "rrn1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    const ADDR_B: &str = "rrn1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

    /// RFC 6763 §7 caps the Service Name at 15 characters. mdns-sd only
    /// enforces this on its daemon thread *after* `register` returns `Ok`, so a
    /// violation is invisible except as a log line and the station silently
    /// advertises nothing. This test is the only thing standing between us and
    /// that failure mode — it is why the spec's `_railroad-station` (16) became
    /// `_rrn-station` (11).
    #[test]
    fn service_name_is_rfc6763_legal() {
        let labels: Vec<&str> = SERVICE_TYPE.split('.').collect();
        assert_eq!(
            labels.as_slice(),
            ["_rrn-station", "_tcp", "local", ""],
            "service type must be <name>._tcp.local. — was {SERVICE_TYPE:?}"
        );
        let name = labels[0].strip_prefix('_').expect("leading underscore");
        assert!(
            name.len() <= 15,
            "RFC 6763 caps the service name at 15 bytes; {name:?} is {}",
            name.len()
        );
        // RFC 6335: letters, digits and hyphens only, and not hyphen-edged.
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !name.starts_with('-')
                && !name.ends_with('-'),
            "illegal characters in service name {name:?}"
        );
    }

    #[test]
    fn station_name_is_stable_for_an_address() {
        assert_eq!(station_name(ADDR_A), station_name(ADDR_A));
    }

    #[test]
    fn station_name_differs_between_addresses() {
        assert_ne!(station_name(ADDR_A), station_name(ADDR_B));
    }

    #[test]
    fn station_name_is_well_formed() {
        let name = station_name(ADDR_A);
        assert!(name.starts_with("Railroad Station — "), "was: {name}");
        let tail: Vec<&str> = name
            .trim_start_matches("Railroad Station — ")
            .split(' ')
            .collect();
        assert_eq!(tail.len(), 2, "expected adjective + noun, was: {name}");
        assert!(ADJECTIVES.contains(&tail[0]));
        assert!(NOUNS.contains(&tail[1]));
    }

    #[test]
    fn hostname_is_dns_safe() {
        assert_eq!(
            hostname_for("Railroad Station — Quiet Forest"),
            "railroad-station-quiet-forest.local."
        );
        // Non-ASCII and punctuation collapse to single separators rather than
        // leaking through — ugly but legal, and only reachable via an operator's
        // custom name (the derived default is already ASCII).
        assert_eq!(hostname_for("Estación — Ñuñoa!!"), "estaci-n-u-oa.local.");
        // A run of junk collapses to one separator, and edges are trimmed.
        assert_eq!(hostname_for("  --Depot!!  "), "depot.local.");
        // A name with nothing usable still yields a legal host.
        assert_eq!(hostname_for("—"), "railroad-station.local.");
    }

    #[test]
    fn bad_listen_address_is_rejected() {
        // Rejected while parsing, before any daemon starts — so this test does
        // not touch the network.
        match advertise("not-a-socket-addr", "Test", ADDR_A) {
            Err(MdnsError::BadListen { listen, .. }) => assert_eq!(listen, "not-a-socket-addr"),
            Err(other) => panic!("expected BadListen, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }
}
