//! The `station` daemon binary: a thin clap shell over the `rrn_station`
//! library. Subcommands:
//!
//! - `init` — bootstrap a data directory (wallet + database + config).
//! - `run` (default) — open the data directory and run the daemon until
//!   Ctrl-C / SIGTERM.
//! - `peers list` — print the configured peer list and exit.
//!
//! The passphrase is read without echo (via `rpassword`), or from the
//! `RRN_PASSPHRASE` environment variable when set — the latter is how CI and the
//! demo script drive `init`/`run` non-interactively.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use rrn_station::config::StationConfig;
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams, CONFIG_FILE, SOCKET_FILE};
use rrn_station::Clock;
use serde_json::json;

/// The Railroad Network station daemon.
#[derive(Parser)]
#[command(name = "station", version, about)]
struct Cli {
    /// Data directory (wallet, database, socket, config).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Bootstrap a new station: generate an identity and initialize storage.
    Init,
    /// Run the daemon (default).
    Run,
    /// Inspect the static peer configuration.
    Peers {
        #[command(subcommand)]
        cmd: PeersCmd,
    },
    /// Confirm a mobile's pairing request (T1.3.3). With no address, lists the
    /// pending requests and their confirmation codes; pass an address to
    /// confirm it after comparing the code with the mobile's screen in person.
    PairMobile {
        /// The bech32 address of the pending mobile to confirm.
        address: Option<String>,
    },
    /// List the mobiles currently paired with this station.
    ListMobiles,
    /// Revoke a mobile's pairing by its bech32 address.
    Unpair {
        /// The mobile's bech32 address.
        address: String,
    },
}

#[derive(Subcommand)]
enum PeersCmd {
    /// Print the configured peers.
    List,
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone().unwrap_or_else(default_data_dir);

    match cli.command.unwrap_or(Command::Run) {
        Command::Init => cmd_init(&data_dir),
        Command::Run => cmd_run(&data_dir),
        Command::Peers { cmd } => match cmd {
            PeersCmd::List => cmd_peers_list(&data_dir),
        },
        Command::PairMobile { address } => cmd_pair_mobile(&data_dir, address),
        Command::ListMobiles => cmd_list_mobiles(&data_dir),
        Command::Unpair { address } => cmd_unpair(&data_dir, address),
    }
}

/// `station init` — prompt for a passphrase (twice) and bootstrap the dir.
fn cmd_init(data_dir: &std::path::Path) -> Result<()> {
    let passphrase = match std::env::var("RRN_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => {
            let first =
                rpassword::prompt_password("New wallet passphrase: ").context("read passphrase")?;
            let second =
                rpassword::prompt_password("Confirm passphrase: ").context("read passphrase")?;
            if first != second {
                anyhow::bail!("passphrases did not match");
            }
            first
        }
    };

    let address = Station::init(data_dir, &passphrase)?;
    println!("{address}");
    eprintln!("Initialized station at {}", data_dir.display());
    Ok(())
}

/// `station run` — open the dir and serve until a shutdown signal.
fn cmd_run(data_dir: &std::path::Path) -> Result<()> {
    let passphrase = read_run_passphrase()?;
    let runtime = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    runtime.block_on(async move {
        let station = Station::open(StationParams {
            data_dir: data_dir.to_path_buf(),
            passphrase,
            clock: Clock::system(),
        })
        .await?;

        wait_for_shutdown().await;
        station.shutdown().await;
        Ok::<(), anyhow::Error>(())
    })
}

/// `station peers list` — print configured peers (read-only).
fn cmd_peers_list(data_dir: &std::path::Path) -> Result<()> {
    let config = StationConfig::load_or_create(&data_dir.join(CONFIG_FILE))?;
    if config.peers.list.is_empty() {
        eprintln!("(no peers configured)");
    } else {
        for peer in &config.peers.list {
            println!("{peer}");
        }
    }
    Ok(())
}

/// Runs a single Unix-socket RPC against the live daemon and returns its result.
///
/// These operator commands are separate processes from `station run`; they reach
/// the daemon's in-memory pairing state the same way the `rrn` CLI does — over
/// the owner-only Unix socket.
fn socket_call(
    data_dir: &std::path::Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let client = UnixClient::new(data_dir.join(SOCKET_FILE));
    let runtime = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    runtime
        .block_on(client.call(method, params))
        .with_context(|| format!("call `{method}` (is the station running?)"))
}

/// `station pair-mobile [address]` — list pending pairing requests, or confirm
/// one after the operator has compared its code with the mobile's screen.
fn cmd_pair_mobile(data_dir: &std::path::Path, address: Option<String>) -> Result<()> {
    match address {
        None => {
            let result = socket_call(data_dir, "pair_list_pending", json!({}))?;
            let pending = result["pending"].as_array().cloned().unwrap_or_default();
            if pending.is_empty() {
                eprintln!("(no pending pairing requests)");
                return Ok(());
            }
            eprintln!("Pending pairing requests — compare the code with the mobile, then");
            eprintln!("run `station pair-mobile <address>` to confirm:\n");
            for entry in &pending {
                let addr = entry["address"].as_str().unwrap_or("?");
                let sas = entry["sas"].as_str().unwrap_or("?");
                let age = entry["age_secs"].as_i64().unwrap_or(0);
                println!("  {sas}   {addr}   ({age}s ago)");
            }
        }
        Some(addr) => {
            let result = socket_call(data_dir, "pair_confirm", json!({ "address": addr }))?;
            let confirmed = result["address"].as_str().unwrap_or(&addr);
            println!("{confirmed}");
            eprintln!("Paired.");
        }
    }
    Ok(())
}

/// `station list-mobiles` — the mobiles currently paired with this station.
fn cmd_list_mobiles(data_dir: &std::path::Path) -> Result<()> {
    let result = socket_call(data_dir, "list_mobiles", json!({}))?;
    let mobiles = result["mobiles"].as_array().cloned().unwrap_or_default();
    if mobiles.is_empty() {
        eprintln!("(no paired mobiles)");
        return Ok(());
    }
    for entry in &mobiles {
        let addr = entry["address"].as_str().unwrap_or("?");
        let paired_at = entry["paired_at"].as_i64().unwrap_or(0);
        println!("{addr}   (paired at {paired_at})");
    }
    Ok(())
}

/// `station unpair <address>` — revoke a mobile's pairing.
fn cmd_unpair(data_dir: &std::path::Path, address: String) -> Result<()> {
    let result = socket_call(data_dir, "unpair", json!({ "address": address }))?;
    if result["removed"].as_bool().unwrap_or(false) {
        eprintln!("Unpaired {address}.");
    } else {
        eprintln!("{address} was not paired.");
    }
    Ok(())
}

fn read_run_passphrase() -> Result<String> {
    match std::env::var("RRN_PASSPHRASE") {
        Ok(p) => Ok(p),
        Err(_) => rpassword::prompt_password("Wallet passphrase: ").context("read passphrase"),
    }
}

/// Resolves once Ctrl-C or SIGTERM arrives.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn default_data_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".railroad").join("station")
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_env("RRN_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
