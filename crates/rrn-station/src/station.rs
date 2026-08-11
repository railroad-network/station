//! Wiring: turn a data directory + passphrase into a running station.
//!
//! [`Station::open`] is the one place that assembles the pieces — load the
//! config, open the database, decrypt the wallet, spawn the [`core`](crate::core)
//! thread, bind the Unix socket and the peer TCP listener, and start the three
//! background loops (CLI server, peer gossip server, gossip client, settlement
//! timer). The `station` binary calls it; so does the in-process e2e test, which
//! is why `Station` hands back a [`CoreHandle`] and the injected [`Clock`] for
//! direct, deterministic control.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::settlement::SettlementConfig;
use rrn_marketplace::search::SearchIndex;
use rrn_storage::db::Database;
use rrn_storage::migrations;

use crate::clock::Clock;
use crate::config::StationConfig;
use crate::core::{Core, CoreHandle};
use crate::{gossip, mdns, mobile_server, paired, server};

/// Wallet file name within the data dir.
pub const WALLET_FILE: &str = "wallet.rrnwallet";
/// SQLite database file name within the data dir.
pub const DB_FILE: &str = "station.db";
/// Unix socket file name within the data dir.
pub const SOCKET_FILE: &str = "station.sock";
/// Config file name within the data dir.
pub const CONFIG_FILE: &str = "config.toml";
/// Marketplace full-text index directory within the data dir (T1.6.6).
///
/// A derived cache, not data: per ADR-0010 deleting this directory is a
/// supported repair, and the core rebuilds it from the log at startup.
pub const LISTING_INDEX_DIR: &str = "marketplace_index";

/// Inputs needed to bring a station up.
pub struct StationParams {
    /// The station's data directory (wallet, db, socket, config live here).
    pub data_dir: PathBuf,
    /// Passphrase that decrypts the wallet.
    pub passphrase: String,
    /// The clock the station (and its settlement timer) reads. Use
    /// [`Clock::system`] in production, [`Clock::manual`] in tests.
    pub clock: Clock,
}

/// A running station and the handles needed to drive or stop it.
pub struct Station {
    core: CoreHandle,
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    socket_path: PathBuf,
    address: String,
    clock: Clock,
    config: StationConfig,
}

impl Station {
    /// Bootstraps a fresh data directory: generates an identity, writes the
    /// encrypted wallet, initializes the database, and writes a default config.
    /// Returns the new identity's address. Errors if a wallet already exists.
    pub fn init(data_dir: &Path, passphrase: &str) -> Result<Address> {
        std::fs::create_dir_all(data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;

        let wallet_path = data_dir.join(WALLET_FILE);
        if wallet_path.exists() {
            anyhow::bail!("a wallet already exists at {}", wallet_path.display());
        }

        let wallet = WalletContents::create_new();
        let address = wallet.address;
        wallet
            .save_to_file(&wallet_path, passphrase)
            .context("write wallet")?;

        // Create + migrate the database file.
        let db = Database::open(&data_dir.join(DB_FILE)).context("open database")?;
        migrations::run(&db).context("run migrations")?;

        // Write a default config if none exists yet.
        StationConfig::load_or_create(&data_dir.join(CONFIG_FILE)).context("write config")?;

        Ok(address)
    }

    /// Opens an already-initialized data directory and starts all background
    /// tasks on the current Tokio runtime.
    pub async fn open(params: StationParams) -> Result<Station> {
        let data_dir = params.data_dir;
        let config =
            StationConfig::load_or_create(&data_dir.join(CONFIG_FILE)).context("load config")?;

        let db = Database::open(&data_dir.join(DB_FILE)).context("open database")?;
        migrations::run(&db).context("run migrations")?;

        let wallet =
            WalletContents::load_from_file(&data_dir.join(WALLET_FILE), &params.passphrase)
                .context("open wallet (wrong passphrase, or run `station init` first)")?;
        let address = wallet.address.to_string();

        // A `window_seconds` override collapses every tier to one window (the
        // demo/test knob); otherwise each tier keeps its own configured window.
        let settlement = match config.settlement.window_seconds {
            Some(window) => SettlementConfig::uniform(window),
            None => SettlementConfig {
                tier1_window_seconds: config.settlement.tier1_window_seconds,
                tier2_window_seconds: config.settlement.tier2_window_seconds,
            },
        };
        let paired = paired::PairedMobiles::load(&data_dir).context("load paired mobiles")?;

        // The marketplace index (T1.6.6). Failing to open it must not keep the
        // station down — it is a cache the core rebuilds from the log anyway — so
        // fall back to an in-memory index, which costs this run's browse nothing
        // and simply does not survive a restart.
        let index_dir = data_dir.join(LISTING_INDEX_DIR);
        let listings = match SearchIndex::open(&index_dir) {
            Ok(index) => index,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    dir = %index_dir.display(),
                    "could not open the marketplace index; using an in-memory one for this run"
                );
                SearchIndex::in_memory()
            }
        };

        let core = Core::new(
            db,
            wallet,
            settlement,
            params.clock.clone(),
            paired,
            listings,
        )
        .spawn();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = Vec::new();

        // CLI Unix-socket server.
        let socket_path = data_dir.join(SOCKET_FILE);
        let unix = server::bind(&socket_path).context("bind unix socket")?;
        tracing::info!(socket = %socket_path.display(), "Listening on Unix socket");
        tasks.push(tokio::spawn(server::serve(
            unix,
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Peer TCP listener + gossip client.
        let tcp = TcpListener::bind(&config.network.listen)
            .await
            .with_context(|| format!("bind peer listener on {}", config.network.listen))?;
        tracing::info!(listen = %config.network.listen, "Listening for peers");
        tasks.push(tokio::spawn(gossip::serve_peers(
            tcp,
            core.clone(),
            shutdown_rx.clone(),
        )));

        let peers = Arc::new(config.peers.list.clone());
        tasks.push(tokio::spawn(gossip::gossip_loop(
            Duration::from_secs(config.timers.gossip_interval_secs.max(1)),
            peers,
            address.clone(),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Mobile-facing HTTP surface (ADR-0008 / T1.3.3+), on the port mDNS
        // advertises. Best-effort, matching the advertisement below: if the port
        // cannot be bound — most often another station already holds it on this
        // host — the station still serves peers and the CLI, and the warning
        // explains why mobiles cannot reach it. A dark station (advertise =
        // false) still serves here: `advertise` governs discoverability, not
        // reachability, since a hand-added mobile must still connect.
        match TcpListener::bind(&config.mobile.listen).await {
            Ok(mobile_listener) => {
                tracing::info!(listen = %config.mobile.listen, "Listening for mobiles");
                tasks.push(tokio::spawn(mobile_server::serve(
                    mobile_listener,
                    core.clone(),
                    std::time::Duration::from_secs(config.mobile.subscribe_hold_secs),
                    shutdown_rx.clone(),
                )));
            }
            Err(e) => tracing::warn!(
                error = %e,
                listen = %config.mobile.listen,
                "mobile HTTP listener not bound; mobiles cannot reach this station"
            ),
        }

        // Local-network advertisement, so a mobile can find this station
        // without being told an IP address (T1.3.2).
        //
        // Best-effort by design: a station that cannot advertise — no
        // multicast-capable interface, a locked-down network, another daemon
        // holding the mDNS port — is still perfectly usable by a mobile that is
        // pointed at it by hand, which is why the mobile keeps a manual-add
        // path. So a failure here warns and carries on rather than refusing to
        // bring the station up.
        if config.mobile.advertise {
            let name = config
                .mobile
                .name
                .clone()
                .unwrap_or_else(|| mdns::station_name(&address));
            match mdns::advertise(&config.mobile.listen, &name, &address) {
                Ok(ad) => {
                    tracing::info!(
                        name = %name,
                        listen = %config.mobile.listen,
                        "Advertising on the local network"
                    );
                    tasks.push(tokio::spawn(mdns::serve(ad, shutdown_rx.clone())));
                }
                Err(e) => tracing::warn!(error = %e, "not advertising on the local network"),
            }
        }

        // Settlement sweep timer.
        tasks.push(tokio::spawn(sweep_timer(
            Duration::from_secs(config.timers.sweep_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Reputation snapshot refresh timer.
        tasks.push(tokio::spawn(reputation_refresh_timer(
            Duration::from_secs(config.timers.reputation_refresh_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Listing expiry sweep timer (T1.7.0).
        tasks.push(tokio::spawn(listing_expiry_timer(
            Duration::from_secs(config.timers.listing_expiry_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Inquiry expiry sweep timer (T1.7.4).
        tasks.push(tokio::spawn(inquiry_expiry_timer(
            Duration::from_secs(config.timers.inquiry_expiry_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Service-contract charge sweep timer (T1.7.7).
        tasks.push(tokio::spawn(contract_charge_timer(
            Duration::from_secs(config.timers.contract_charge_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Governance-enactment sweep timer (T1.9.7).
        tasks.push(tokio::spawn(governance_implementation_timer(
            Duration::from_secs(config.timers.governance_implementation_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        // Dispute-resolution sweep timer (T1.10.5).
        tasks.push(tokio::spawn(dispute_resolution_timer(
            Duration::from_secs(config.timers.dispute_resolution_interval_secs.max(1)),
            core.clone(),
            shutdown_rx.clone(),
        )));

        Ok(Station {
            core,
            shutdown_tx,
            tasks,
            socket_path,
            address,
            clock: params.clock,
            config,
        })
    }

    /// A handle to the core, for in-process drivers (the e2e test).
    pub fn core(&self) -> CoreHandle {
        self.core.clone()
    }

    /// The path to this station's CLI Unix socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// This station's own `rrn1…` address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The clock this station reads (clone to advance it in tests).
    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    /// The loaded config.
    pub fn config(&self) -> &StationConfig {
        &self.config
    }

    /// Forces an immediate settlement sweep; returns the number settled. Used by
    /// the e2e test for deterministic settlement without waiting on the timer.
    pub async fn sweep(&self) -> usize {
        self.core.sweep().await
    }

    /// Forces an immediate reputation-snapshot refresh; returns the number of
    /// identities refreshed. Lets a driver refresh deterministically without
    /// waiting on the hourly timer.
    pub async fn refresh_reputation(&self) -> usize {
        self.core.refresh_reputation().await
    }

    /// Forces an immediate listing-expiry sweep; returns the number closed. Lets
    /// a driver advance the clock past an expiry and see the close record
    /// written without waiting on the timer.
    pub async fn expire_listings(&self) -> usize {
        self.core.expire_listings().await
    }

    /// Forces an immediate service-contract charge sweep; returns the number of
    /// charge records appended. Lets a driver advance the clock past a period and
    /// see the direct debit taken without waiting on the timer.
    pub async fn charge_contracts(&self) -> usize {
        self.core.charge_contracts().await
    }

    /// Forces an immediate governance-enactment sweep; returns the number of
    /// proposals put into force. Lets a driver advance the clock past an
    /// implementation delay and see the enactment recorded without waiting on the
    /// hourly timer.
    pub async fn enact_governance(&self) -> usize {
        self.core.enact_governance().await
    }

    /// Forces an immediate dispute-resolution sweep; returns the number of
    /// disputes given a terminal outcome. Lets a driver advance the clock past a
    /// jury's majority (or a window's close) and see the outcome enacted without
    /// waiting on the hourly timer.
    pub async fn resolve_disputes(&self) -> usize {
        self.core.resolve_disputes().await
    }

    /// Signals all tasks to stop, stops the core thread, awaits the tasks, and
    /// removes the socket file. Idempotent-ish: safe to call once.
    pub async fn shutdown(mut self) {
        tracing::info!("Shutting down");
        let _ = self.shutdown_tx.send(true);
        self.core.shutdown();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Periodically asks the core to sweep settlement at the current clock time.
async fn sweep_timer(interval: Duration, core: CoreHandle, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately; skip it so startup doesn't sweep an
    // empty log (harmless, but noisy).
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.sweep().await;
                if n > 0 {
                    tracing::info!(settled = n, "settlement sweep");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Periodically asks the core to close listings whose expiry has passed
/// (T1.7.0).
///
/// Latency here is not a correctness problem — every reader already treats a
/// past-expiry listing as off the market (ADR-0010), so this converts a
/// derivation into a signed record rather than deciding anything.
async fn listing_expiry_timer(
    interval: Duration,
    core: CoreHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick, as the other timers do.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.expire_listings().await;
                if n > 0 {
                    tracing::info!(closed = n, "listing expiry sweep");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Periodically asks the core to close inquiries gone quiet past the TTL
/// (T1.7.4).
///
/// Like the listing sweep, this converts a derivation into a signed record
/// rather than deciding anything: a party already treats a long-dormant thread
/// as done, and this writes that down.
async fn inquiry_expiry_timer(
    interval: Duration,
    core: CoreHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick, as the other timers do.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.expire_inquiries().await;
                if n > 0 {
                    tracing::info!(closed = n, "inquiry expiry sweep");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Periodically asks the core to bill every service contract's due periods
/// (T1.7.7).
///
/// Unlike the settlement sweep, a charge here has no window to close and no party
/// to confirm it — the buyer's contract signature pre-authorized it — so this is
/// the only thing that turns an owed period into a balance move. A missed or
/// coalesced tick is caught up on the next one: the sweep bills every period due,
/// not just the newest, and a re-charge is idempotent.
async fn contract_charge_timer(
    interval: Duration,
    core: CoreHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick, as the other timers do.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.charge_contracts().await;
                if n > 0 {
                    tracing::info!(charged = n, "contract charge sweep");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Periodically asks the core to refresh reputation snapshots at the current
/// clock time.
async fn reputation_refresh_timer(
    interval: Duration,
    core: CoreHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick so startup doesn't refresh an empty log.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.refresh_reputation().await;
                if n > 0 {
                    tracing::info!(refreshed = n, "reputation snapshot refresh");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Periodically asks the core to enact passed proposals whose implementation delay
/// has run (T1.9.7).
///
/// Like the contract charge sweep, this is the only thing that turns a decided
/// proposal into a recorded fact — the community's vote authorized it, and the
/// delay only defers *writing it down*. A missed tick is caught up on the next:
/// the sweep enacts every proposal now due, not just the newest, and an already-
/// enacted proposal is skipped.
async fn governance_implementation_timer(
    interval: Duration,
    core: CoreHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick, as the other timers do.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.enact_governance().await;
                if n > 0 {
                    tracing::info!(enacted = n, "governance enactment sweep");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Periodically asks the core to resolve disputes: enact the outcome of any whose
/// jury has reached a majority, and lapse (settle as confirmed) any whose window
/// has closed unresolved (T1.10.5).
///
/// Like the governance-enactment sweep, this is what turns a decided dispute into
/// a recorded fact. A missed tick is caught up on the next — the sweep resolves
/// every dispute now terminal, not just the newest — and a dispute already moved
/// out of `Disputed` is skipped.
async fn dispute_resolution_timer(
    interval: Duration,
    core: CoreHandle,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick, as the other timers do.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let n = core.resolve_disputes().await;
                if n > 0 {
                    tracing::info!(resolved = n, "dispute resolution sweep");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}
