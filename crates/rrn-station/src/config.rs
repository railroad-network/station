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
//! A community's log has exactly one writer (ADR-0020 §1). The default
//! `[network] role` is `writer`, and a writer never pulls — so a writer's
//! `[peers] list` must be empty (a non-empty one refuses to start). Peers are
//! configured on a **replica**, the read-only second copy of the writer's chain
//! (ADR-0020 §7); see [`StationRole`].
//!
//! # Example
//!
//! A writer (the normal case — owns the chain, no peers):
//!
//! ```toml
//! [network]
//! listen = "127.0.0.1:7411"
//! # role = "writer"   # the default
//! ```
//!
//! A read-replica that copies the writer above:
//!
//! ```toml
//! [peers]
//! list = ["127.0.0.1:7411"]
//!
//! [network]
//! listen = "127.0.0.1:7412"
//! role = "replica"
//! ```

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use rrn_ledger::credit::{
    DEFAULT_CERT_DELIVERY_GRACE_SECS, DEFAULT_CERT_MAX_CAP_CENTI, DEFAULT_CERT_MAX_OUTSTANDING,
    DEFAULT_CERT_VALIDITY_SECS, DEFAULT_DEBT_FLOOR_CENTI,
};
use rrn_ledger::settlement::{DEFAULT_TIER1_WINDOW_SECONDS, DEFAULT_TIER2_WINDOW_SECONDS};

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
    /// Settlement tuning (optional; defaults to the per-tier windows —
    /// Tier 1 = 24h, Tier 2 = 48h, T1.8.4).
    #[serde(default)]
    pub settlement: SettlementSection,
    /// Credit tuning (optional; defaults to the protocol debt floor of
    /// −20 Commons, ADR-0018).
    #[serde(default)]
    pub credit: CreditSection,
    /// Background-loop intervals (optional; defaults to the daemon cadence).
    #[serde(default)]
    pub timers: TimersSection,
    /// Delay-tolerant-networking tuning (optional; defaults to the protocol
    /// receipt-retention window, ADR-0020 §3).
    #[serde(default)]
    pub dtn: DtnSection,
    /// The supervised Reticulum daemon (`rnsd`) sidecar (optional; disabled by
    /// default, ADR-0013).
    #[serde(default)]
    pub sidecar: SidecarSection,
    /// LoRa airtime budget for the Reticulum transport (optional; defaults to the
    /// design's ~250 B/s raw at 1% duty, T2.6.2).
    #[serde(default)]
    pub lora: LoraSection,
    /// SMS carrier (optional; disabled by default, T2.7.1). A member's paired phone
    /// texts its outbox to the station's number; the station decodes, ingests, and
    /// texts receipts back.
    #[serde(default)]
    pub sms: SmsSection,
    /// At-rest encryption profile (optional; defaults to the `plaintext` profile —
    /// today's behavior). The `encrypted` profile wraps the station's mutable state
    /// in a member-keyed LUKS container unlocked by a boot ceremony (ADR-0024).
    #[serde(default)]
    pub storage: StorageSection,
}

/// `[storage]` — the at-rest encryption profile (ADR-0024).
///
/// Two profiles, chosen at provisioning and not a runtime toggle:
///
/// - **`plaintext`** (default) — today's behavior: the data directory is a flat,
///   unencrypted tree. Correct for communities that do not face a physical-seizure
///   threat, and the only supported profile on non-Linux hosts.
/// - **`encrypted`** — the seizure-resistance profile: the station's mutable and
///   secret state lives inside a member-keyed LUKS2 container (`dm-crypt`), unlocked
///   at boot by a Shamir quorum of member holders (the Volume Master Key is never
///   written to disk). Powered off, the container is an encrypted brick. This
///   profile is **Linux-only** — block encryption is the kernel's `dm-crypt`, driven
///   by `cryptsetup`/`losetup`; a station started with `at_rest = "encrypted"` on a
///   non-Linux host refuses rather than silently serving plaintext.
///
/// See ADR-0024 for the full design and the availability trade (every power loss
/// costs a ceremony — a UPS is strongly recommended).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageSection {
    /// Which at-rest profile this station runs. Defaults to
    /// [`AtRestProfile::Plaintext`].
    #[serde(default)]
    pub at_rest: AtRestProfile,
    /// The encrypted-profile parameters. Required (and validated) when
    /// `at_rest = "encrypted"`; ignored under the plaintext profile.
    #[serde(default)]
    pub encrypted: Option<EncryptedSection>,
}

/// The at-rest storage profile (`[storage] at_rest`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AtRestProfile {
    /// Flat, unencrypted data directory — today's behavior (default).
    #[default]
    Plaintext,
    /// Member-keyed LUKS container unlocked by a boot ceremony (ADR-0024, Linux).
    Encrypted,
}

/// `[storage.encrypted]` — the member-keyed encrypted-volume parameters (ADR-0024).
///
/// The `boot_dir` (the unencrypted `--data-dir`) holds only `config.toml`, the CLI
/// socket, the LUKS container file, and a tiny VMK unlock descriptor; everything
/// sensitive — the wallet, the ledger database, paired mobiles, the search index,
/// the recovery package, and the Reticulum adapter identity — lives inside the
/// container, mounted at [`state_dir`](EncryptedSection::state_dir). The VMK is
/// Shamir-split at threshold [`threshold`](EncryptedSection::threshold) among the
/// holders named on the `station encrypt-in-place` / `vmk refresh` command line,
/// reusing ADR-0016's machinery.
///
/// **The holder set is deliberately not stored here.** Persisting holder addresses
/// on the unencrypted boot dir would hand a seizer who imaged the card a
/// coercion-target map (ADR-0024) — exactly what the boot-dir VMK descriptor is
/// designed to avoid. The authoritative record of who holds a shard is the VMK
/// package *inside* the encrypted container (readable only once unlocked, via
/// `station vmk status`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSection {
    /// Path to the LUKS2 container file (`state.img`). When omitted, defaults to
    /// `<boot_dir>/state.img` (resolved at [`Station::open`](crate::station::Station::open)
    /// time, since the boot dir is not known here).
    #[serde(default)]
    pub container_path: Option<String>,
    /// The mount point the decrypted container is mapped at — the `state_dir`. When
    /// omitted, defaults to `<boot_dir>/state`.
    #[serde(default)]
    pub state_dir: Option<String>,
    /// `K` — how many holders must cooperate at the boot ceremony to reconstruct the
    /// VMK. Defaults to 3; provisioning refuses `K < 2` (matching ADR-0016
    /// `recovery::setup`), and `K` may not exceed the number of holders.
    #[serde(default = "default_vmk_threshold")]
    pub threshold: u8,
}

fn default_vmk_threshold() -> u8 {
    3
}

impl Default for EncryptedSection {
    fn default() -> Self {
        Self {
            container_path: None,
            state_dir: None,
            threshold: default_vmk_threshold(),
        }
    }
}

/// `[sms]` — SMS as a DTN carrier (T2.7.1, Overview §10.3 "No internet — SMS").
///
/// SMS is a *carrier for signed payloads*, never custody: a paired phone encodes
/// its outbox into GSM-7-safe text chunks and texts them to `station_msisdn`; the
/// station reassembles, ingests through the same DTN front door the online path
/// uses (ADR-0020 §3), and texts the signed receipt back. Off by default; and even
/// when enabled, T2.7.1 ships no modem backend — the real gateway that this config
/// drives is T2.7.2, so an enabled `[sms]` without that backend is supervised-but-
/// idle (mirroring `[sidecar]` without `[lora] adapter_script`). See
/// `docs/spec/sms-carrier.md`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmsSection {
    /// Whether the SMS carrier is enabled at all. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// The station's own phone number (E.164), the number members text. Required
    /// when the modem backend runs (T2.7.2); optional here.
    #[serde(default)]
    pub station_msisdn: Option<String>,
    /// The most concatenated GSM-7 parts one SMS message (one chunk) may span.
    /// Defaults to 4 (→ a 442-byte chunk budget; see
    /// [`rrn_protocol::paper::sms_chunk_budget_bytes`]). Must be ≥ 1.
    #[serde(default = "default_sms_max_parts")]
    pub max_parts_per_message: usize,
    /// Which inbound senders to process: `"paired"` (default — only numbers a
    /// `rrn.net.sms_binding` record names) or `"open"` (any number; still
    /// signature-gated at ingest).
    #[serde(default)]
    pub allowed_senders: crate::sms::AllowedSenders,
    /// The most inbound texts one sender may send per fixed 1-hour window before the rest
    /// are dropped (with a throttled log). Defaults to 60.
    #[serde(default = "default_sms_max_inbound_per_hour")]
    pub max_inbound_per_hour: u32,
}

fn default_sms_max_parts() -> usize {
    4
}
fn default_sms_max_inbound_per_hour() -> u32 {
    60
}

impl Default for SmsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            station_msisdn: None,
            max_parts_per_message: default_sms_max_parts(),
            allowed_senders: crate::sms::AllowedSenders::default(),
            max_inbound_per_hour: default_sms_max_inbound_per_hour(),
        }
    }
}

impl SmsSection {
    /// The [`SmsRelayConfig`](crate::sms::SmsRelayConfig) this section describes:
    /// the chunk budget derived from `max_parts_per_message`, the registry mode, and
    /// the inbound rate cap. Outbound pacing takes its default.
    pub fn relay_config(&self) -> crate::sms::SmsRelayConfig {
        crate::sms::SmsRelayConfig {
            chunk_budget_bytes: rrn_protocol::paper::sms_chunk_budget_bytes(
                self.max_parts_per_message,
            ),
            allowed_senders: self.allowed_senders,
            max_inbound_per_hour: self.max_inbound_per_hour,
            message_budget: crate::sms::MessageBudget::default(),
        }
    }
}

/// `[lora]` — the airtime budget the Reticulum transport paces to (T2.6.2).
///
/// LoRa's honest ceiling is ~250 raw bytes/second, and regional duty-cycle rules
/// cut *sustained* throughput far lower (design overview §10.3). The station paces
/// to `sustained = raw_bytes_per_sec × duty_cycle_percent / 100`, prioritizing
/// money over governance over bulk (`rrn_protocol::airtime`). Code takes numbers;
/// the per-geography duty-cycle table is the T2.6.3 operator runbook's job.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoraSection {
    /// Raw carrier throughput in bytes/second before the duty cycle. Defaults to
    /// 250 (the design's LoRa figure).
    #[serde(default = "default_raw_bytes_per_sec")]
    pub raw_bytes_per_sec: f64,
    /// Duty-cycle **percentage** (`1.0` = 1%). Defaults to 1.0 — the conservative
    /// EU-868-style ceiling; a laxer region raises it.
    #[serde(default = "default_duty_cycle_percent")]
    pub duty_cycle_percent: f64,
    /// Token-bucket burst ceiling in bytes — the largest catch-up burst after an
    /// idle period, and the largest single frame the budget can ever pass. Must be
    /// ≥ the carrier's frame size. Defaults to 500.
    #[serde(default = "default_burst_bytes")]
    pub burst_bytes: u32,
    /// The largest carrier frame in bytes (chunk size the framing layer targets).
    /// Defaults to 480 — under a typical LoRa/Reticulum MTU, and ≤ `burst_bytes`.
    #[serde(default = "default_lora_frame_bytes")]
    pub frame_bytes: usize,
    /// Path to the Reticulum LXMF adapter script
    /// (`scripts/reticulum/lxmf_adapter.py`). When set **and** `[sidecar]` is
    /// enabled, the station runs the DTN transport over Reticulum (T2.6.2);
    /// omitted → the sidecar is supervised but no DTN traffic flows over it yet.
    #[serde(default)]
    pub adapter_script: Option<String>,
    /// The Python interpreter that has `rns` + `lxmf` for the adapter. Defaults to
    /// `"python3"` on `PATH`.
    #[serde(default = "default_adapter_python")]
    pub adapter_python: String,
    /// How often (seconds) the outbound loop re-scans the `dtn_pushes` table for
    /// undelivered pushes gone quiet, re-sending them. Defaults to 1 hour.
    #[serde(default = "default_push_rescan_secs")]
    pub push_rescan_secs: i64,
    /// How long (seconds) an undelivered outbound push is retried before it is
    /// marked **abandoned** — never silently dropped; shown by `rrn dtn status`.
    /// Defaults to 7 days.
    #[serde(default = "default_push_ttl_secs")]
    pub push_ttl_secs: i64,
    /// The physical RNode radio interface (`[lora.rnode]`), templated into the
    /// generated Reticulum config (ADR-0013). Absent → no radio interface is
    /// templated: the generated config carries a commented example and a docs
    /// pointer instead, so a station never transmits on a frequency or power that
    /// nobody deliberately chose.
    #[serde(default)]
    pub rnode: Option<RNodeSection>,
}

/// `[lora.rnode]` — the physical RNode LoRa radio interface.
///
/// This templates an `RNodeInterface` stanza into the station's generated
/// Reticulum config, so putting a station on radio is a *configuration* change,
/// not a code one (ADR-0013: Reticulum is a carrier only). `frequency_hz` and
/// `tx_power_dbm` have **no defaults**: a radio is enabled only by a deliberate,
/// region-aware choice. Spectrum compliance (frequency, duty cycle, EIRP) is the
/// operator's responsibility per geography — see the regional compliance table in
/// `docs/lora-radio-bringup.md`. Every node on one LoRa network must share the
/// same frequency, bandwidth, and spreading factor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RNodeSection {
    /// Serial port of the radio, e.g. `/dev/ttyACM0` (nRF52 boards) or
    /// `/dev/ttyUSB0` (many ESP32 boards). Run `ls /dev/tty*` before and after
    /// plugging the radio in to find it.
    pub port: String,
    /// Centre frequency in Hz — **no default**. Must be legal for your region
    /// (e.g. EU-868: 867200000; US-915: 915000000) and identical on every node.
    pub frequency_hz: u64,
    /// Transmit power in dBm — **no default**. Start low and stay within your
    /// region's EIRP cap (antenna gain counts toward it).
    pub tx_power_dbm: i32,
    /// Channel bandwidth in Hz. Defaults to 125000 (125 kHz — the robust default).
    #[serde(default = "default_lora_bandwidth_hz")]
    pub bandwidth_hz: u64,
    /// Spreading factor, 7..=12 (higher = more range, less throughput). Defaults
    /// to 8.
    #[serde(default = "default_lora_spreading_factor")]
    pub spreading_factor: u8,
    /// Coding-rate denominator (the `x` in 4/x); RNS accepts 5..=8. Defaults to 5
    /// (a 4/5 coding rate).
    #[serde(default = "default_lora_coding_rate")]
    pub coding_rate: u8,
}

fn default_lora_bandwidth_hz() -> u64 {
    125_000
}
fn default_lora_spreading_factor() -> u8 {
    8
}
fn default_lora_coding_rate() -> u8 {
    5
}

fn default_adapter_python() -> String {
    "python3".to_string()
}

fn default_push_rescan_secs() -> i64 {
    60 * 60
}
fn default_push_ttl_secs() -> i64 {
    7 * 24 * 60 * 60
}

fn default_raw_bytes_per_sec() -> f64 {
    250.0
}
fn default_duty_cycle_percent() -> f64 {
    1.0
}
fn default_burst_bytes() -> u32 {
    500
}
fn default_lora_frame_bytes() -> usize {
    480
}

impl Default for LoraSection {
    fn default() -> Self {
        Self {
            raw_bytes_per_sec: default_raw_bytes_per_sec(),
            duty_cycle_percent: default_duty_cycle_percent(),
            burst_bytes: default_burst_bytes(),
            frame_bytes: default_lora_frame_bytes(),
            adapter_script: None,
            adapter_python: default_adapter_python(),
            push_rescan_secs: default_push_rescan_secs(),
            push_ttl_secs: default_push_ttl_secs(),
            rnode: None,
        }
    }
}

impl LoraSection {
    /// The [`AirtimeBudget`](rrn_protocol::airtime::AirtimeBudget) this section
    /// describes.
    pub fn budget(&self) -> rrn_protocol::airtime::AirtimeBudget {
        rrn_protocol::airtime::AirtimeBudget::from_duty_cycle(
            self.raw_bytes_per_sec,
            self.duty_cycle_percent,
            self.burst_bytes,
        )
    }
}

/// `[peers]` — who to gossip with.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeersConfig {
    /// `host:port` of each peer's gossip listener.
    #[serde(default)]
    pub list: Vec<String>,
}

/// `[network]` — where to accept incoming peer connections, and this station's
/// role in the community's single-writer chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// `host:port` this station binds for inbound gossip.
    pub listen: String,
    /// This station's role in the community (ADR-0020 §1/§7 Clarification).
    /// Serde-defaulted to [`StationRole::Writer`], so a config written before
    /// this field existed is a writer — today's behavior.
    #[serde(default)]
    pub role: StationRole,
}

/// `[network] role` — the station's place in the single-writer chain
/// (ADR-0020 §1 "one chain, one writer"; §7 "read-replica gossip retired in
/// place", and its 2026-09-14 Clarification: *the writer never pulls; a replica
/// never admits*).
///
/// - **`writer`** (default) owns the community's log: it admits records only at
///   its own front door and **never pulls** from a peer. A writer configured
///   with a non-empty `[peers] list` refuses to start — a writer that pulled
///   would let a record couriered to a hostile peer land on the chain ungated,
///   defeating the single-writer property (ADR-0020 §1). A writer still *serves*
///   its peer port so replicas can copy the chain from it.
/// - **`replica`** is a read-only copy of the writer's chain (ADR-0020 §7): it
///   pulls the writer's log over gossip and re-derives state by replay
///   (ADR-0018 "replicas re-derive, never re-enforce"), but **never admits** a
///   record itself. Every write surface on a replica — operator socket, mobile
///   channel, and DTN ingest — refuses with a "this station is a read-replica"
///   error. A replica is a warm second copy for audit/backup; it is **not** a
///   failover standby (ADR-0020 Consequences: writer succession is Phase 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StationRole {
    /// Owns the chain; admits at its front door; never pulls (default).
    #[default]
    Writer,
    /// A read-only copy of the writer's chain; pulls, never admits.
    Replica,
}

impl StationRole {
    /// Whether this station pulls the log from its peers. Only a replica does.
    pub fn pulls(self) -> bool {
        matches!(self, StationRole::Replica)
    }

    /// Whether this station admits records (front door, timers, DTN ingest).
    /// Only a writer does; a replica is a read-only copy.
    pub fn admits(self) -> bool {
        matches!(self, StationRole::Writer)
    }

    /// The lowercase wire spelling (`"writer"` / `"replica"`), for the `status`
    /// RPC and logs. Matches the serde `rename_all = "lowercase"` above.
    pub fn as_str(self) -> &'static str {
        match self {
            StationRole::Writer => "writer",
            StationRole::Replica => "replica",
        }
    }
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
    /// How long a `/subscribe` long-poll is held open before returning an empty
    /// heartbeat (T1.3.5). The default matches the task's 30s; tests set it small
    /// so the timeout path is fast.
    #[serde(default = "default_subscribe_hold_secs")]
    pub subscribe_hold_secs: u64,
}

fn default_mobile_listen() -> String {
    "0.0.0.0:7500".to_string()
}
fn default_advertise() -> bool {
    true
}
fn default_subscribe_hold_secs() -> u64 {
    30
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            listen: default_mobile_listen(),
            name: None,
            advertise: default_advertise(),
            subscribe_hold_secs: default_subscribe_hold_secs(),
        }
    }
}

/// `[settlement]` — the dispute/settlement window, per oracle tier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementSection {
    /// A uniform override applied to *every* tier — the demo/test knob. When set
    /// (a handful of seconds), it wins over the per-tier keys so settlement fires
    /// promptly; leave it unset in production to use the per-tier windows below.
    #[serde(default)]
    pub window_seconds: Option<u64>,
    /// Seconds a confirmed **Tier-1** transaction waits before settling. Defaults
    /// to [`DEFAULT_TIER1_WINDOW_SECONDS`] (24h).
    #[serde(default = "default_tier1_window_seconds")]
    pub tier1_window_seconds: u64,
    /// Seconds a confirmed **Tier-2** transaction waits before settling. Defaults
    /// to [`DEFAULT_TIER2_WINDOW_SECONDS`] (48h).
    #[serde(default = "default_tier2_window_seconds")]
    pub tier2_window_seconds: u64,
}

/// `[credit]` — how far into debt a member may sign themselves (ADR-0018) and
/// the offline-certificate parameters that reserve headroom ahead of a partition
/// (ADR-0021).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreditSection {
    /// The lowest projected balance, in centicommons, a member may commit
    /// themselves down to. Must be ≤ 0. Defaults to
    /// [`DEFAULT_DEBT_FLOOR_CENTI`] (−2,000 = −20 Commons); per-community
    /// tuning through governance is a later milestone — until then this is the
    /// operator's knob, and lowering it is a community-level decision, not a
    /// personal one.
    #[serde(default = "default_debt_floor_centi")]
    pub debt_floor_centi: i64,
    /// How long a newly issued headroom certificate stays valid, in seconds.
    /// Defaults to [`DEFAULT_CERT_VALIDITY_SECS`] (7 days). Must be > 0.
    #[serde(default = "default_cert_validity_seconds")]
    pub cert_validity_seconds: i64,
    /// The largest cap, in centicommons, one certificate may reserve. Defaults to
    /// [`DEFAULT_CERT_MAX_CAP_CENTI`] (1,000 = 10 Commons). Must be > 0 and, per
    /// ADR-0021 §1, no larger than the Tier-2 single-transaction ceiling
    /// ([`rrn_ledger::tier::TIER_3_FLOOR_CENTI`]); the station also warns if it
    /// exceeds the debt-floor magnitude (unreachable at zero balance).
    #[serde(default = "default_cert_max_cap_centi")]
    pub cert_max_cap_centi: i64,
    /// The DTN delivery grace beyond expiry, in seconds, within which a
    /// cert-backed spend is still admissible (ADR-0021 §4). Defaults to
    /// [`DEFAULT_CERT_DELIVERY_GRACE_SECS`] (14 days). Must be ≥ 0.
    #[serde(default = "default_cert_delivery_grace_seconds")]
    pub cert_delivery_grace_seconds: i64,
    /// The maximum number of simultaneously outstanding certificates one member
    /// may hold. Defaults to [`DEFAULT_CERT_MAX_OUTSTANDING`] (4).
    #[serde(default = "default_cert_max_outstanding")]
    pub cert_max_outstanding: u32,
}

fn default_debt_floor_centi() -> i64 {
    DEFAULT_DEBT_FLOOR_CENTI
}
fn default_cert_validity_seconds() -> i64 {
    DEFAULT_CERT_VALIDITY_SECS
}
fn default_cert_max_cap_centi() -> i64 {
    DEFAULT_CERT_MAX_CAP_CENTI
}
fn default_cert_delivery_grace_seconds() -> i64 {
    DEFAULT_CERT_DELIVERY_GRACE_SECS
}
fn default_cert_max_outstanding() -> u32 {
    DEFAULT_CERT_MAX_OUTSTANDING
}

impl Default for CreditSection {
    fn default() -> Self {
        Self {
            debt_floor_centi: default_debt_floor_centi(),
            cert_validity_seconds: default_cert_validity_seconds(),
            cert_max_cap_centi: default_cert_max_cap_centi(),
            cert_delivery_grace_seconds: default_cert_delivery_grace_seconds(),
            cert_max_outstanding: default_cert_max_outstanding(),
        }
    }
}

/// `[dtn]` — delay-tolerant-networking retention (ADR-0020 §3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnSection {
    /// How long a *confirmed* delivery receipt is retained before the prune sweep
    /// removes it, in seconds. Defaults to 30 days. An unconfirmed receipt — one
    /// no author has picked up — is kept far longer (four times this), since a
    /// courier may take weeks to carry it home
    /// (`rrn_storage::dtn::RETENTION_UNCONFIRMED_MULTIPLIER`).
    #[serde(default = "default_receipt_retention_secs")]
    pub receipt_retention_secs: u64,
}

fn default_receipt_retention_secs() -> u64 {
    30 * 24 * 60 * 60
}

impl Default for DtnSection {
    fn default() -> Self {
        Self {
            receipt_retention_secs: default_receipt_retention_secs(),
        }
    }
}

/// `[sidecar]` — the supervised Reticulum daemon (`rnsd`), ADR-0013.
///
/// Reticulum is a *carrier only*: the sidecar moves opaque, already-signed
/// bundles and never becomes the identity, integrity, or encryption boundary
/// (ADR-0013's non-goals). It is off by default — a station carries traffic over
/// Reticulum only where an operator opts in — and, when on, is run as an
/// appliance-style managed child (version-pinned, restarted with backoff, killed
/// cleanly on shutdown). Its loss is a connectivity event, never a reason the
/// daemon exits (T2.4.1 posture).
///
/// The generated Reticulum config (in [`config_dir`](SidecarSection::config_dir))
/// is templated from [`tcp_listen`](SidecarSection::tcp_listen) and
/// [`tcp_peers`](SidecarSection::tcp_peers) only; the RNode/LoRa interface
/// template lands in T2.6.3, and the `FrameTransport` impl over the sidecar in
/// T2.6.2. This ticket (T2.6.1) delivers the supervisor and the integration
/// spike, not the transport wiring.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidecarSection {
    /// Whether to run the sidecar at all. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Path to (or name of) the `rnsd` binary. Defaults to `"rnsd"`, found on
    /// `PATH`.
    #[serde(default = "default_rnsd_path")]
    pub rnsd_path: String,
    /// Directory the generated Reticulum config lives in. When omitted, defaults
    /// to `<data_dir>/reticulum` (resolved at [`Station::open`](crate::station::Station::open)
    /// time, since the data dir is not known here).
    #[serde(default)]
    pub config_dir: Option<String>,
    /// The pinned `rnsd` version this station is validated against, as a
    /// dotted-prefix match: `"1.5"` accepts any `1.5.x`, `"1.5.2"` only that
    /// point release, and a trailing `x`/`*` component (`"1.5.x"`) is an explicit
    /// wildcard. The supervisor refuses to run a mismatched `rnsd` (running
    /// degraded *without* the sidecar) unless
    /// [`allow_version_drift`](SidecarSection::allow_version_drift) is set —
    /// appliance discipline, never a silently-unpinned carrier. Defaults to
    /// [`DEFAULT_PINNED_RNSD_VERSION`](crate::sidecar::DEFAULT_PINNED_RNSD_VERSION).
    #[serde(default = "default_pinned_rnsd_version")]
    pub pinned_version: String,
    /// Development escape hatch: run against an `rnsd` whose version does not
    /// match [`pinned_version`](SidecarSection::pinned_version) anyway (warns
    /// loudly). Off by default.
    #[serde(default)]
    pub allow_version_drift: bool,
    /// Base restart backoff in seconds after the sidecar exits. Doubles on each
    /// consecutive failure, capped at 300 (five minutes); resets once the child
    /// has stayed up past the healthy threshold. Defaults to 5.
    #[serde(default = "default_restart_backoff_secs")]
    pub restart_backoff_secs: u64,
    /// A TCP *server* interface for the generated Reticulum config: the
    /// `host:port` `rnsd` listens on for inbound Reticulum links. Omitted → no
    /// server stanza is templated.
    #[serde(default)]
    pub tcp_listen: Option<String>,
    /// TCP *client* interfaces for the generated Reticulum config: `host:port`
    /// targets `rnsd` dials out to. Each becomes one `TCPClientInterface` stanza.
    #[serde(default)]
    pub tcp_peers: Vec<String>,
}

fn default_rnsd_path() -> String {
    "rnsd".to_string()
}
fn default_pinned_rnsd_version() -> String {
    crate::sidecar::DEFAULT_PINNED_RNSD_VERSION.to_string()
}
fn default_restart_backoff_secs() -> u64 {
    5
}

impl Default for SidecarSection {
    fn default() -> Self {
        Self {
            enabled: false,
            rnsd_path: default_rnsd_path(),
            config_dir: None,
            pinned_version: default_pinned_rnsd_version(),
            allow_version_drift: false,
            restart_backoff_secs: default_restart_backoff_secs(),
            tcp_listen: None,
            tcp_peers: Vec::new(),
        }
    }
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
    /// Reputation-snapshot refresh interval in seconds (spec default: 3600 —
    /// hourly). The floor under ad-hoc refreshes; recomputes every known
    /// identity's cached profile from the log.
    #[serde(default = "default_reputation_refresh_interval")]
    pub reputation_refresh_interval_secs: u64,
    /// Listing-expiry sweep interval in seconds (default: 300 — five minutes).
    ///
    /// Longer than the settlement sweep on purpose. Settlement latency delays
    /// money a member is waiting for, whereas an expired listing is already
    /// unbuyable to every reader the moment its expiry passes (ADR-0010); this
    /// sweep only writes that down, so it is housekeeping rather than a deadline.
    #[serde(default = "default_listing_expiry_interval")]
    pub listing_expiry_interval_secs: u64,
    /// Inquiry-expiry sweep interval in seconds (default: 3600 — hourly).
    ///
    /// Coarser than the listing sweep: an inquiry expires after seven days of no
    /// activity (T1.7.4), so a few minutes of latency on writing that close down
    /// changes nothing a party would notice.
    #[serde(default = "default_inquiry_expiry_interval")]
    pub inquiry_expiry_interval_secs: u64,
    /// Service-contract charge sweep interval in seconds (default: 300 — five
    /// minutes).
    ///
    /// Each tick bills every period a live contract has due (T1.7.7). Latency here
    /// only delays *writing down* a charge the contract already authorized, and a
    /// re-swept period folds to nothing (the `(contract, period)` idempotency key),
    /// so a coarse cadence is safe; a test drives it directly through
    /// [`charge_contracts`](crate::core::CoreHandle::charge_contracts).
    #[serde(default = "default_contract_charge_interval")]
    pub contract_charge_interval_secs: u64,
    /// Governance-enactment sweep interval in seconds (default: 3600 — hourly).
    ///
    /// Puts every passed proposal whose implementation delay has run into force
    /// (T1.9.7). Coarse on purpose: the delay is measured in days, so an hour of
    /// latency writing the enactment down changes nothing a member would notice,
    /// and the sweep catches up every proposal due since the last tick.
    #[serde(default = "default_governance_implementation_interval")]
    pub governance_implementation_interval_secs: u64,
    /// Dispute-resolution sweep interval in seconds (default: 3600 — hourly).
    ///
    /// Enacts a dispute whose jury has reached a majority, and lapses one whose
    /// window has closed unresolved (T1.10.5). Coarse on purpose: the freeze window
    /// is measured in days, so an hour of latency writing the outcome down changes
    /// nothing a party would notice, and the sweep catches up every dispute due
    /// since the last tick. A test drives it directly through
    /// [`resolve_disputes`](crate::core::CoreHandle::resolve_disputes).
    #[serde(default = "default_dispute_resolution_interval")]
    pub dispute_resolution_interval_secs: u64,
    /// DTN receipt-delivery prune interval in seconds (default: 3600 — hourly).
    ///
    /// Each tick removes delivery-tracking rows past their retention (ADR-0020 §3,
    /// T2.2.4): confirmed receipts older than `[dtn] receipt_retention_secs`, and
    /// unconfirmed ones older than four times that. Pure housekeeping on a queue,
    /// with days-to-weeks-long retentions, so a coarse cadence is ample; a test
    /// drives it directly through
    /// [`prune_receipts`](crate::core::CoreHandle::prune_receipts).
    #[serde(default = "default_dtn_prune_interval")]
    pub dtn_prune_interval_secs: u64,
}

fn default_tier1_window_seconds() -> u64 {
    DEFAULT_TIER1_WINDOW_SECONDS
}
fn default_tier2_window_seconds() -> u64 {
    DEFAULT_TIER2_WINDOW_SECONDS
}
fn default_sweep_interval() -> u64 {
    30
}
fn default_gossip_interval() -> u64 {
    5
}
fn default_reputation_refresh_interval() -> u64 {
    3600
}
fn default_listing_expiry_interval() -> u64 {
    300
}
fn default_inquiry_expiry_interval() -> u64 {
    3600
}
fn default_contract_charge_interval() -> u64 {
    300
}
fn default_governance_implementation_interval() -> u64 {
    3600
}
fn default_dispute_resolution_interval() -> u64 {
    3600
}
fn default_dtn_prune_interval() -> u64 {
    3600
}

impl Default for SettlementSection {
    fn default() -> Self {
        Self {
            window_seconds: None,
            tier1_window_seconds: default_tier1_window_seconds(),
            tier2_window_seconds: default_tier2_window_seconds(),
        }
    }
}

impl Default for TimersSection {
    fn default() -> Self {
        Self {
            sweep_interval_secs: default_sweep_interval(),
            gossip_interval_secs: default_gossip_interval(),
            reputation_refresh_interval_secs: default_reputation_refresh_interval(),
            listing_expiry_interval_secs: default_listing_expiry_interval(),
            inquiry_expiry_interval_secs: default_inquiry_expiry_interval(),
            contract_charge_interval_secs: default_contract_charge_interval(),
            governance_implementation_interval_secs: default_governance_implementation_interval(),
            dispute_resolution_interval_secs: default_dispute_resolution_interval(),
            dtn_prune_interval_secs: default_dtn_prune_interval(),
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

    /// Validates the network role against the peer list (ADR-0020 §1/§7): a
    /// writer never pulls, so a `writer` (the default) with a non-empty
    /// `[peers] list` is a misconfiguration — a pulled record would bypass the
    /// front door and defeat the single-writer property. Returns an error whose
    /// message names the fix. A replica with an empty peer list is valid (it
    /// simply never receives anything); the daemon warns about that at startup.
    pub fn check_role_peers(&self) -> Result<(), String> {
        if self.network.role == StationRole::Writer && !self.peers.list.is_empty() {
            let n = self.peers.list.len();
            return Err(format!(
                "[network] role is \"writer\" but [peers] list has {n} \
                 entr{} — a writer never pulls (ADR-0020 §1). Remove the \
                 [peers] list, or set [network] role = \"replica\" to run this \
                 station as a read-only copy of the writer's chain.",
                if n == 1 { "y" } else { "ies" },
            ));
        }
        Ok(())
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
                role: StationRole::Writer,
            },
            mobile: MobileConfig::default(),
            settlement: SettlementSection::default(),
            credit: CreditSection::default(),
            timers: TimersSection::default(),
            dtn: DtnSection::default(),
            sidecar: SidecarSection::default(),
            lora: LoraSection::default(),
            sms: SmsSection::default(),
            storage: StorageSection::default(),
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
        // A config written before [network] role existed is a writer (ADR-0020 §7).
        assert_eq!(cfg.network.role, StationRole::Writer);
        // Optional sections fall back to defaults.
        assert_eq!(cfg.settlement.window_seconds, None);
        assert_eq!(
            cfg.settlement.tier1_window_seconds,
            DEFAULT_TIER1_WINDOW_SECONDS
        );
        assert_eq!(
            cfg.settlement.tier2_window_seconds,
            DEFAULT_TIER2_WINDOW_SECONDS
        );
        assert_eq!(cfg.timers.sweep_interval_secs, 30);
        assert_eq!(cfg.timers.gossip_interval_secs, 5);
        // DTN retention/prune fall back to their protocol defaults.
        assert_eq!(cfg.timers.dtn_prune_interval_secs, 3600);
        assert_eq!(cfg.dtn.receipt_retention_secs, 30 * 24 * 60 * 60);
        // Credit/certificate parameters fall back to the protocol defaults.
        assert_eq!(cfg.credit.debt_floor_centi, DEFAULT_DEBT_FLOOR_CENTI);
        assert_eq!(cfg.credit.cert_validity_seconds, DEFAULT_CERT_VALIDITY_SECS);
        assert_eq!(cfg.credit.cert_max_cap_centi, DEFAULT_CERT_MAX_CAP_CENTI);
        assert_eq!(
            cfg.credit.cert_delivery_grace_seconds,
            DEFAULT_CERT_DELIVERY_GRACE_SECS
        );
        assert_eq!(
            cfg.credit.cert_max_outstanding,
            DEFAULT_CERT_MAX_OUTSTANDING
        );
        // A config written before [mobile] existed still parses, and advertises
        // on all interfaces with a derived name.
        assert_eq!(cfg.mobile.listen, "0.0.0.0:7500");
        assert!(cfg.mobile.advertise);
        assert_eq!(cfg.mobile.name, None);
    }

    #[test]
    fn role_replica_parses_and_role_peers_validation() {
        // A replica config parses the role and keeps its peers.
        let replica = StationConfig::parse(
            r#"
                [peers]
                list = ["127.0.0.1:7411"]

                [network]
                listen = "127.0.0.1:7412"
                role = "replica"
            "#,
            &p(),
        )
        .unwrap();
        assert_eq!(replica.network.role, StationRole::Replica);
        assert_eq!(replica.peers.list, vec!["127.0.0.1:7411"]);
        // A replica may name peers (that is the whole point).
        assert!(replica.check_role_peers().is_ok());

        // A writer with peers is refused, and the message names the fix.
        let writer_with_peers = StationConfig::parse(
            r#"
                [peers]
                list = ["127.0.0.1:7411"]

                [network]
                listen = "127.0.0.1:7412"
            "#,
            &p(),
        )
        .unwrap();
        assert_eq!(writer_with_peers.network.role, StationRole::Writer);
        let err = writer_with_peers.check_role_peers().unwrap_err();
        assert!(err.contains("writer never pulls"), "message: {err}");
        assert!(err.contains("role = \"replica\""), "message: {err}");

        // A writer with no peers is the normal case and is valid.
        let writer = StationConfig::parse(
            r#"
                [network]
                listen = "127.0.0.1:7411"
            "#,
            &p(),
        )
        .unwrap();
        assert!(writer.check_role_peers().is_ok());

        // The generated default is a valid (peerless) writer.
        assert!(StationConfig::default_config().check_role_peers().is_ok());
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
    fn credit_section_overrides_certificate_defaults() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [credit]
            debt_floor_centi = -3000
            cert_validity_seconds = 86400
            cert_max_cap_centi = 2500
            cert_delivery_grace_seconds = 172800
            cert_max_outstanding = 2
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.credit.debt_floor_centi, -3000);
        assert_eq!(cfg.credit.cert_validity_seconds, 86400);
        assert_eq!(cfg.credit.cert_max_cap_centi, 2500);
        assert_eq!(cfg.credit.cert_delivery_grace_seconds, 172800);
        assert_eq!(cfg.credit.cert_max_outstanding, 2);
    }

    #[test]
    fn credit_section_partial_override_keeps_other_cert_defaults() {
        // A file written before the certificate keys existed (only debt_floor)
        // still parses, and the certificate keys take their protocol defaults.
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [credit]
            debt_floor_centi = -1000
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.credit.debt_floor_centi, -1000);
        assert_eq!(cfg.credit.cert_max_cap_centi, DEFAULT_CERT_MAX_CAP_CENTI);
        assert_eq!(
            cfg.credit.cert_max_outstanding,
            DEFAULT_CERT_MAX_OUTSTANDING
        );
    }

    #[test]
    fn dtn_section_overrides_defaults() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [dtn]
            receipt_retention_secs = 120

            [timers]
            dtn_prune_interval_secs = 15
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.dtn.receipt_retention_secs, 120);
        assert_eq!(cfg.timers.dtn_prune_interval_secs, 15);
    }

    #[test]
    fn sidecar_defaults_to_disabled() {
        // A config written before [sidecar] existed still parses, and the
        // sidecar is off with the pinned defaults.
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert!(!cfg.sidecar.enabled);
        assert_eq!(cfg.sidecar.rnsd_path, "rnsd");
        assert_eq!(cfg.sidecar.config_dir, None);
        assert_eq!(
            cfg.sidecar.pinned_version,
            crate::sidecar::DEFAULT_PINNED_RNSD_VERSION
        );
        assert!(!cfg.sidecar.allow_version_drift);
        assert_eq!(cfg.sidecar.restart_backoff_secs, 5);
        assert_eq!(cfg.sidecar.tcp_listen, None);
        assert!(cfg.sidecar.tcp_peers.is_empty());
    }

    #[test]
    fn sidecar_section_overrides_defaults() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [sidecar]
            enabled = true
            rnsd_path = "/opt/reticulum/bin/rnsd"
            config_dir = "/var/lib/rrn/reticulum"
            pinned_version = "0.9.6"
            allow_version_drift = true
            restart_backoff_secs = 10
            tcp_listen = "0.0.0.0:4242"
            tcp_peers = ["203.0.113.7:4242", "198.51.100.9:4242"]
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert!(cfg.sidecar.enabled);
        assert_eq!(cfg.sidecar.rnsd_path, "/opt/reticulum/bin/rnsd");
        assert_eq!(
            cfg.sidecar.config_dir.as_deref(),
            Some("/var/lib/rrn/reticulum")
        );
        assert_eq!(cfg.sidecar.pinned_version, "0.9.6");
        assert!(cfg.sidecar.allow_version_drift);
        assert_eq!(cfg.sidecar.restart_backoff_secs, 10);
        assert_eq!(cfg.sidecar.tcp_listen.as_deref(), Some("0.0.0.0:4242"));
        assert_eq!(
            cfg.sidecar.tcp_peers,
            vec!["203.0.113.7:4242", "198.51.100.9:4242"]
        );
    }

    #[test]
    fn lora_defaults_and_budget() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.lora.raw_bytes_per_sec, 250.0);
        assert_eq!(cfg.lora.duty_cycle_percent, 1.0);
        assert_eq!(cfg.lora.burst_bytes, 500);
        assert_eq!(cfg.lora.frame_bytes, 480);
        // 250 raw × 1% = 2.5 sustained B/s.
        assert_eq!(cfg.lora.budget().sustained_bytes_per_sec, 2.5);

        let overridden = StationConfig::parse(
            "[network]\nlisten = \"127.0.0.1:7411\"\n[lora]\nduty_cycle_percent = 10.0\nraw_bytes_per_sec = 300.0\n",
            &p(),
        )
        .unwrap();
        assert_eq!(overridden.lora.budget().sustained_bytes_per_sec, 30.0);
    }

    #[test]
    fn rnode_absent_by_default() {
        // A config with no [lora.rnode] leaves the radio interface unconfigured —
        // the generated Reticulum config carries a commented example instead.
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert!(cfg.lora.rnode.is_none());
    }

    #[test]
    fn rnode_parses_with_required_fields_and_radio_defaults() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"
            [lora.rnode]
            port = "/dev/ttyUSB0"
            frequency_hz = 915000000
            tx_power_dbm = 5
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        let r = cfg.lora.rnode.expect("rnode configured");
        assert_eq!(r.port, "/dev/ttyUSB0");
        assert_eq!(r.frequency_hz, 915_000_000);
        assert_eq!(r.tx_power_dbm, 5);
        // Radio defaults fill in when omitted.
        assert_eq!(r.bandwidth_hz, 125_000);
        assert_eq!(r.spreading_factor, 8);
        assert_eq!(r.coding_rate, 5);
    }

    #[test]
    fn rnode_without_frequency_or_power_is_a_loud_error() {
        // frequency_hz and tx_power_dbm have no defaults: a half-specified radio
        // is a config error, never a silently-disabled or silently-defaulted one.
        let missing_freq = r#"
            [network]
            listen = "127.0.0.1:7411"
            [lora.rnode]
            port = "/dev/ttyUSB0"
            tx_power_dbm = 5
        "#;
        assert!(StationConfig::parse(missing_freq, &p()).is_err());

        let missing_power = r#"
            [network]
            listen = "127.0.0.1:7411"
            [lora.rnode]
            port = "/dev/ttyUSB0"
            frequency_hz = 915000000
        "#;
        assert!(StationConfig::parse(missing_power, &p()).is_err());
    }

    #[test]
    fn sms_defaults_to_disabled() {
        // A config written before [sms] existed still parses, and the carrier is
        // off with the protocol defaults.
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert!(!cfg.sms.enabled);
        assert_eq!(cfg.sms.station_msisdn, None);
        assert_eq!(cfg.sms.max_parts_per_message, 4);
        assert_eq!(cfg.sms.allowed_senders, crate::sms::AllowedSenders::Paired);
        assert_eq!(cfg.sms.max_inbound_per_hour, 60);
        // The derived relay config sizes the chunk budget from max_parts (442 @ 4).
        assert_eq!(cfg.sms.relay_config().chunk_budget_bytes, 442);
    }

    #[test]
    fn sms_section_overrides_defaults() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [sms]
            enabled = true
            station_msisdn = "+15550001111"
            max_parts_per_message = 6
            allowed_senders = "open"
            max_inbound_per_hour = 120
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert!(cfg.sms.enabled);
        assert_eq!(cfg.sms.station_msisdn.as_deref(), Some("+15550001111"));
        assert_eq!(cfg.sms.max_parts_per_message, 6);
        assert_eq!(cfg.sms.allowed_senders, crate::sms::AllowedSenders::Open);
        assert_eq!(cfg.sms.max_inbound_per_hour, 120);
        // 153×6 = 918 chars − 22 header = 896 data chars → floor(896×3/4) = 672.
        assert_eq!(cfg.sms.relay_config().chunk_budget_bytes, 672);
    }

    #[test]
    fn storage_defaults_to_plaintext_profile() {
        // A config written before [storage] existed still parses, and the station
        // runs the plaintext (today's) profile with no encrypted parameters.
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.storage.at_rest, AtRestProfile::Plaintext);
        assert!(cfg.storage.encrypted.is_none());
    }

    #[test]
    fn storage_encrypted_profile_parses() {
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [storage]
            at_rest = "encrypted"

            [storage.encrypted]
            container_path = "/var/lib/rrn/state.img"
            state_dir = "/run/rrn/state"
            threshold = 3
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        assert_eq!(cfg.storage.at_rest, AtRestProfile::Encrypted);
        let enc = cfg.storage.encrypted.expect("encrypted section present");
        assert_eq!(
            enc.container_path.as_deref(),
            Some("/var/lib/rrn/state.img")
        );
        assert_eq!(enc.state_dir.as_deref(), Some("/run/rrn/state"));
        assert_eq!(enc.threshold, 3);
    }

    #[test]
    fn storage_encrypted_config_never_persists_holders() {
        // The serialized encrypted config must not carry the holder set — persisting
        // it on the unencrypted boot dir would leak a coercion-target map (ADR-0024).
        let cfg = StationConfig::parse(
            "[network]\nlisten = \"127.0.0.1:7411\"\n[storage]\nat_rest = \"encrypted\"\n\
             [storage.encrypted]\nthreshold = 2\n",
            &p(),
        )
        .unwrap();
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        assert!(
            !serialized.contains("holders"),
            "config must not serialize a holders field: {serialized}"
        );
    }

    #[test]
    fn storage_encrypted_threshold_defaults_to_three() {
        // [storage.encrypted] with no explicit threshold takes the default of 3.
        let text = r#"
            [network]
            listen = "127.0.0.1:7411"

            [storage]
            at_rest = "encrypted"

            [storage.encrypted]
            state_dir = "/run/rrn/state"
        "#;
        let cfg = StationConfig::parse(text, &p()).unwrap();
        let enc = cfg.storage.encrypted.expect("encrypted section present");
        assert_eq!(enc.threshold, 3);
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
