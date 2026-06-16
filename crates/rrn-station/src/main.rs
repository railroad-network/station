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
use rrn_station::station::{Station, StationParams, CONFIG_FILE};
use rrn_station::Clock;

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
