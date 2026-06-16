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
use rrn_storage::db::Database;
use rrn_storage::migrations;

use crate::clock::Clock;
use crate::config::StationConfig;
use crate::core::{Core, CoreHandle};
use crate::{gossip, server};

/// Wallet file name within the data dir.
pub const WALLET_FILE: &str = "wallet.rrnwallet";
/// SQLite database file name within the data dir.
pub const DB_FILE: &str = "station.db";
/// Unix socket file name within the data dir.
pub const SOCKET_FILE: &str = "station.sock";
/// Config file name within the data dir.
pub const CONFIG_FILE: &str = "config.toml";

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

        let settlement = SettlementConfig {
            window_seconds: config.settlement.window_seconds,
        };
        let core = Core::new(db, wallet, settlement, params.clock.clone()).spawn();

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

        // Settlement sweep timer.
        tasks.push(tokio::spawn(sweep_timer(
            Duration::from_secs(config.timers.sweep_interval_secs.max(1)),
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
