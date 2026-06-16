//! `rrn` — the Railroad Network command-line client.
//!
//! Each subcommand maps to exactly one daemon RPC method: parse args, build the
//! request, send it over the station's Unix socket, format the reply. Output is
//! deliberately terse and machine-friendly — greppable in `text` mode,
//! one-line-JSON in `json` mode (pipe to `jq` if you want it pretty). Results go
//! to stdout, errors to stderr, and any failure exits non-zero.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use rrn_station::history::fmt_commons;
use rrn_station::rpc::{
    BackupExportResult, BalanceResult, ConfirmResult, HistoryResult, ProposeResult,
    RecoverImportResult, VouchResult, WhoamiResult,
};
use rrn_station::rpc_client::UnixClient;

/// Output format for command results.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Terse, human/grep-friendly lines.
    Text,
    /// One-line JSON for piping.
    Json,
}

/// The Railroad Network CLI.
#[derive(Parser)]
#[command(name = "rrn", version, about)]
struct Cli {
    /// Path to the station's Unix socket.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = Format::Text)]
    format: Format,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Explain how to bootstrap a station (init runs in the daemon, not here).
    Init,
    /// Print this station's own address.
    Whoami,
    /// Show a balance (defaults to your own).
    Balance {
        /// The `rrn1…` address to query; omitted means your own.
        address: Option<String>,
    },
    /// Propose a payment to another identity.
    Pay {
        /// The receiver's `rrn1…` address.
        receiver: String,
        /// Amount in Commons, e.g. `3`, `3.5`, or `3.50`.
        amount: String,
        /// Optional memo recorded in the signed proposal.
        #[arg(long)]
        memo: Option<String>,
    },
    /// Confirm a proposed payment addressed to you.
    Confirm {
        /// The hex transaction id.
        tx_id: String,
    },
    /// Print recent log history.
    History {
        /// Maximum number of (most-recent-first) entries.
        #[arg(long)]
        limit: Option<u64>,
    },
    /// Vouch for another identity.
    Vouch {
        /// The `rrn1…` address being vouched for.
        subject: String,
        /// A free-text statement.
        #[arg(long)]
        statement: Option<String>,
        /// Reputation to stake, in points, e.g. `1.50`.
        #[arg(long)]
        stake: Option<String>,
    },
    /// Export a social-recovery package sealed to a set of holders.
    Backup {
        /// Holder `rrn1…` addresses (two or more).
        #[arg(required = true)]
        holders: Vec<String>,
        /// `K` — how many shards are required to reconstruct.
        #[arg(long)]
        threshold: u8,
        /// Where to write the recovery package.
        #[arg(long)]
        output: PathBuf,
    },
    /// Reconstruct an identity from a recovery package and decrypted shards.
    Recover {
        /// Path to a `.rrnrecovery` package.
        #[arg(long)]
        package: PathBuf,
        /// Comma-separated decrypted raw-shard files.
        #[arg(long, value_delimiter = ',')]
        shards: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    // `init` needs no daemon connection.
    if let Command::Init = cli.command {
        return cmd_init();
    }

    let socket = cli.socket.clone().unwrap_or_else(default_socket);
    let client = UnixClient::new(&socket);
    let fmt = cli.format;

    match cli.command {
        Command::Init => unreachable!("handled above"),
        Command::Whoami => {
            let v = client.call("whoami", json!({})).await?;
            emit(fmt, &v, || {
                let r: WhoamiResult = parse(&v)?;
                Ok(r.address)
            })
        }
        Command::Balance { address } => {
            let params = match address {
                Some(a) => json!({ "address": a }),
                None => json!({}),
            };
            let v = client.call("balance", params).await?;
            emit(fmt, &v, || {
                let r: BalanceResult = parse(&v)?;
                Ok(fmt_commons(r.balance_centi))
            })
        }
        Command::Pay {
            receiver,
            amount,
            memo,
        } => {
            let amount_centi = parse_amount(&amount)?;
            let mut params = json!({ "receiver": receiver, "amount_centi": amount_centi });
            if let Some(memo) = memo {
                params["memo"] = json!(memo);
            }
            let v = client.call("propose", params).await?;
            emit(fmt, &v, || {
                let r: ProposeResult = parse(&v)?;
                Ok(r.tx_id)
            })
        }
        Command::Confirm { tx_id } => {
            let v = client.call("confirm", json!({ "tx_id": tx_id })).await?;
            emit(fmt, &v, || {
                let r: ConfirmResult = parse(&v)?;
                Ok(r.state)
            })
        }
        Command::History { limit } => {
            let mut params = json!({});
            if let Some(limit) = limit {
                params["limit"] = json!(limit);
            }
            let v = client.call("history", params).await?;
            emit(fmt, &v, || {
                let r: HistoryResult = parse(&v)?;
                let mut out = String::new();
                for e in &r.entries {
                    out.push_str(&format!("{:>4}  {:<12}  {}\n", e.seq, e.kind, e.summary));
                }
                Ok(out.trim_end().to_string())
            })
        }
        Command::Vouch {
            subject,
            statement,
            stake,
        } => {
            let stake_centi = match stake {
                Some(s) => parse_amount(&s)?,
                None => 0,
            };
            let params = json!({
                "subject": subject,
                "statement": statement.unwrap_or_default(),
                "stake_centi": stake_centi as u64,
            });
            let v = client.call("vouch", params).await?;
            emit(fmt, &v, || {
                let r: VouchResult = parse(&v)?;
                Ok(r.vouch_id)
            })
        }
        Command::Backup {
            holders,
            threshold,
            output,
        } => {
            let params = json!({
                "holders": holders,
                "threshold": threshold,
                "output": output.to_string_lossy(),
            });
            let v = client.call("backup_export", params).await?;
            emit(fmt, &v, || {
                let r: BackupExportResult = parse(&v)?;
                Ok(r.recovery_path)
            })
        }
        Command::Recover { package, shards } => {
            let shard_paths: Vec<String> = shards
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            let params = json!({
                "recovery_path": package.to_string_lossy(),
                "shards": shard_paths,
            });
            let v = client.call("recover_import", params).await?;
            emit(fmt, &v, || {
                let r: RecoverImportResult = parse(&v)?;
                Ok(r.restored_address)
            })
        }
    }
}

fn cmd_init() -> Result<()> {
    eprintln!(
        "`rrn init` does not run here: initialization creates the wallet the\n\
         daemon opens, so run it against the daemon's data dir directly:\n\n\
         \tstation init --data-dir <dir>\n\n\
         then start the daemon with `station run --data-dir <dir>`."
    );
    Ok(())
}

/// Prints either the raw JSON result (json mode) or the text rendering.
fn emit(fmt: Format, raw: &serde_json::Value, text: impl FnOnce() -> Result<String>) -> Result<()> {
    match fmt {
        Format::Json => {
            println!("{}", serde_json::to_string(raw).context("encode result")?);
            Ok(())
        }
        Format::Text => {
            println!("{}", text()?);
            Ok(())
        }
    }
}

fn parse<T: serde::de::DeserializeOwned>(v: &serde_json::Value) -> Result<T> {
    serde_json::from_value(v.clone()).context("decode daemon result")
}

/// Parses a Commons amount (`<int>` or `<int>.<1-2 digits>`) into centicommons.
///
/// Accepts `3`, `3.5`, `3.50`, `0.01`. Rejects empty input, more than two
/// fractional digits (`3.001`), trailing junk (`3.5x`), and negatives.
fn parse_amount(s: &str) -> Result<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty amount"));
    }
    let (whole, frac) = match s.split_once('.') {
        // A decimal point with no digits after it (`3.`) is malformed.
        Some((_, "")) => return Err(anyhow!("invalid amount {s:?}: digits required after '.'")),
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("invalid amount {s:?}: whole part must be digits"));
    }
    if frac.len() > 2 || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!(
            "invalid amount {s:?}: at most two digits after the decimal point"
        ));
    }
    let commons: i64 = whole.parse().context("amount too large")?;
    // Pad the fractional part to exactly two digits: "5" → 50, "" → 0.
    let centi: i64 = match frac.len() {
        0 => 0,
        1 => frac.parse::<i64>().unwrap() * 10,
        _ => frac.parse::<i64>().unwrap(),
    };
    commons
        .checked_mul(100)
        .and_then(|c| c.checked_add(centi))
        .ok_or_else(|| anyhow!("amount too large"))
}

fn default_socket() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".railroad").join("station").join("station.sock")
}

#[cfg(test)]
mod tests {
    use super::parse_amount;

    #[test]
    fn parses_valid_amounts() {
        assert_eq!(parse_amount("3").unwrap(), 300);
        assert_eq!(parse_amount("3.5").unwrap(), 350);
        assert_eq!(parse_amount("3.50").unwrap(), 350);
        assert_eq!(parse_amount("0.01").unwrap(), 1);
        assert_eq!(parse_amount("0").unwrap(), 0);
        assert_eq!(parse_amount("12.00").unwrap(), 1200);
    }

    #[test]
    fn rejects_invalid_amounts() {
        for bad in ["3.5x", "3.001", "", ".", "-3", "3.", "abc", "3.5.5"] {
            assert!(parse_amount(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
