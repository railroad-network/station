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
    /// Write an encrypted backup of this station (wallet + ledger + config).
    ///
    /// Safe to run while the station is running: the ledger is captured as a
    /// consistent live snapshot. Prompts for the wallet passphrase, which both
    /// protects the archive and is verified before anything is written.
    Backup {
        /// Where to write the archive. Defaults to a timestamped file
        /// `station-backup-<unix>.rrnbak` in the current directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Restore a station from an encrypted backup archive into the data dir.
    ///
    /// Refuses to overwrite a data dir that already holds a station unless
    /// `--force` is given. Restore into a stopped station (or a fresh dir).
    Restore {
        /// The backup archive to restore.
        archive: PathBuf,
        /// Overwrite even if the data dir already holds a wallet or database.
        #[arg(long)]
        force: bool,
    },
    /// Manage key recovery: split the station key across trusted holders so a
    /// threshold of them can restore it after a lost passphrase (ADR-0016).
    Recovery {
        #[command(subcommand)]
        cmd: RecoveryCmd,
    },
}

#[derive(Subcommand)]
enum RecoveryCmd {
    /// Arm recovery: split the station key across holders and print a shard QR
    /// for each. Prompts for the wallet passphrase. Re-running re-splits and
    /// invalidates shards handed out before.
    Setup {
        /// A holder's `rrn1…` address. Repeat once per holder (N total).
        #[arg(long = "holder", required = true, value_name = "ADDRESS")]
        holders: Vec<String>,
        /// K — how many holders must cooperate to recover (2 ≤ K ≤ N).
        #[arg(long)]
        threshold: u8,
    },
    /// Show the current recovery configuration.
    Status,
    /// Re-display one holder's shard QR (for redelivery).
    ShowShard {
        /// The holder's `rrn1…` address.
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
        Command::Backup { out } => cmd_backup(&data_dir, out),
        Command::Restore { archive, force } => cmd_restore(&data_dir, &archive, force),
        Command::Recovery { cmd } => match cmd {
            RecoveryCmd::Setup { holders, threshold } => {
                cmd_recovery_setup(&data_dir, &holders, threshold)
            }
            RecoveryCmd::Status => cmd_recovery_status(&data_dir),
            RecoveryCmd::ShowShard { address } => cmd_recovery_show_shard(&data_dir, &address),
        },
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

/// `station backup [--out FILE]` — write an encrypted backup archive.
fn cmd_backup(data_dir: &std::path::Path, out: Option<PathBuf>) -> Result<()> {
    let out_path = out.unwrap_or_else(default_backup_path);
    let passphrase = read_run_passphrase()?;
    let written = rrn_station::backup::create_backup(data_dir, &passphrase, &out_path)?;
    println!("{}", written.display());
    eprintln!("Backed up station to {}", written.display());
    eprintln!("Keep this file safe: it holds the ledger and the (encrypted) wallet.");
    Ok(())
}

/// `station restore <archive> [--force]` — restore a station into the data dir.
fn cmd_restore(data_dir: &std::path::Path, archive: &std::path::Path, force: bool) -> Result<()> {
    let passphrase = read_run_passphrase()?;
    let address = rrn_station::backup::restore_backup(archive, data_dir, &passphrase, force)?;
    println!("{address}");
    eprintln!("Restored station {address} into {}", data_dir.display());
    eprintln!("Start it with `station run` (the search index rebuilds on first run).");
    Ok(())
}

/// `station recovery setup` — split the key across holders and print shard QRs.
fn cmd_recovery_setup(data_dir: &std::path::Path, holders: &[String], threshold: u8) -> Result<()> {
    let passphrase = read_run_passphrase()?;
    let shards = rrn_station::recovery::setup(data_dir, &passphrase, holders, threshold)?;
    eprintln!(
        "Recovery armed: {}-of-{} holders. Show each holder their QR to scan into their wallet.\n",
        threshold,
        shards.len()
    );
    for (i, shard) in shards.iter().enumerate() {
        eprintln!(
            "── Holder {} of {} — {}",
            i + 1,
            shards.len(),
            shard.address
        );
        println!("{}", rrn_station::recovery::render_qr(&shard.qr_payload));
        eprintln!("(or paste this if scanning fails: {})\n", shard.qr_payload);
    }
    eprintln!(
        "Keep at least {threshold} holders reachable — any {threshold} of them can restore the \
         station key even if the passphrase is lost."
    );
    Ok(())
}

/// `station recovery status` — print the current recovery configuration.
fn cmd_recovery_status(data_dir: &std::path::Path) -> Result<()> {
    let st = rrn_station::recovery::status(data_dir)?;
    println!("{}-of-{} recovery", st.threshold, st.total);
    eprintln!("Holders:");
    for h in &st.holders {
        println!("  {h}");
    }
    eprintln!("Armed at (unix): {}", st.created_at);
    Ok(())
}

/// `station recovery show-shard <address>` — re-print one holder's shard QR.
fn cmd_recovery_show_shard(data_dir: &std::path::Path, address: &str) -> Result<()> {
    let shard = rrn_station::recovery::shard_for(data_dir, address)?;
    eprintln!("Shard for {} — have them scan this:", shard.address);
    println!("{}", rrn_station::recovery::render_qr(&shard.qr_payload));
    eprintln!("(or paste: {})", shard.qr_payload);
    Ok(())
}

/// Default archive path for `station backup`: a timestamped file in the cwd.
fn default_backup_path() -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(format!(
        "station-backup-{secs}.{}",
        rrn_station::backup::BACKUP_EXTENSION
    ))
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

/// The default log filter: our own crates at `info`, and tantivy quieted to
/// `warn`.
///
/// tantivy narrates every commit at `info` — "Preparing commit", "save metas",
/// "Running garbage collection" — and the marketplace index commits once per
/// listing change, so at `info` its bookkeeping would drown out the station's own
/// events. `RRN_LOG=tantivy=info` brings it back when the index itself is what
/// you are debugging.
const DEFAULT_LOG_FILTER: &str = "info,tantivy=warn";

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter =
        EnvFilter::try_from_env("RRN_LOG").unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
