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
use clap::builder::PossibleValuesParser;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;

use rrn_station::history::fmt_commons;
use rrn_station::marketplace_view::CATEGORIES;
use rrn_station::rpc::{
    AnnounceNeedResult, BackupExportResult, BalanceResult, CloseListingResult, ConfirmResult,
    ContractStateResult, CreateListingResult, EditListingResult, HistoryResult, InquireResult,
    InquiryStateResult, ProposeResult, RecoverImportResult, TransactionRow, TransactionsResult,
    VouchResult, WhoamiResult,
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

/// The marketplace surfaces, as `clap` accepted values.
///
/// The station refuses an unknown surface rather than ignoring the filter, so
/// naming them here only moves that refusal earlier — a typo fails before the
/// round trip and prints the three options. Unlike [`CATEGORIES`] this list is not
/// shared from the marketplace crate: `Surface` is an enum of exactly three
/// variants, and a fourth would be a code change here either way.
const SURFACES: [&str; 3] = ["goods", "services", "commons"];

/// Whether to colorize text output.
///
/// Off by default, and deliberately not an `auto` that sniffs the terminal: this
/// output is meant to be piped, and a mode that changes what the bytes are
/// depending on where they are going makes `rrn browse | grep` behave one way in
/// a shell and another in a script.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ColorMode {
    /// No escape codes, ever.
    Never,
    /// Colorize, whatever stdout is attached to.
    Always,
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

    /// Colorize text output. Off unless asked for.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Never)]
    color: ColorMode,

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
    /// Show settled and pending transactions, naming the listing each
    /// marketplace payment settled.
    Transactions {
        /// The `rrn1…` address to view; omitted means your own.
        address: Option<String>,
        /// Maximum number of (most-recent-first) rows.
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
    /// Publish a listing offering something to the marketplace.
    List {
        /// The surface to publish on.
        #[arg(value_parser = PossibleValuesParser::new(SURFACES))]
        surface: String,
        /// Short name for the offer.
        title: String,
        /// Price in Commons, e.g. `3`, `3.5`, or `3.50`. Only a `commons`
        /// listing may be negative (a subsidy), written as `-3.50`.
        ///
        // `allow_hyphen_values` so a subsidy can be written `--price -3.50` and
        // not only `--price=-3.50`. Without it clap reads the leading `-` as the
        // start of another flag, which makes the one case the negative sign
        // exists for the one case that needs escaping.
        #[arg(long, allow_hyphen_values = true)]
        price: String,
        /// Category from the controlled vocabulary.
        #[arg(long, value_parser = PossibleValuesParser::new(CATEGORIES))]
        category: String,
        /// Invite offers on the price.
        #[arg(long)]
        negotiable: bool,
        /// Longer prose describing the offer.
        #[arg(long)]
        description: Option<String>,
        /// Units available (`goods` only).
        #[arg(long)]
        capacity: Option<u32>,
        /// Next open slot, as a date or unix seconds (`services` only).
        #[arg(long)]
        next_slot: Option<String>,
        /// Minimum reputation an inquirer must hold, in points e.g. `1.50`.
        #[arg(long)]
        min_reputation: Option<String>,
        /// Deal only with members of your own community.
        #[arg(long)]
        community_only: bool,
        /// Oracle tier to claim; defaults to the price-based suggestion.
        #[arg(long)]
        oracle_tier: Option<u8>,
        /// Take the listing off offer after this date (or unix seconds).
        #[arg(long)]
        expires: Option<String>,
        /// Make this a recurring service: how often a period falls due
        /// (`services` only).
        #[arg(long, value_parser = PossibleValuesParser::new(["daily", "weekly", "monthly"]))]
        every: Option<String>,
        /// How many periods a recurring commitment runs for (required with
        /// `--every`).
        #[arg(long)]
        periods: Option<u32>,
        /// Days of notice to end a recurring contract early.
        #[arg(long)]
        notice: Option<u32>,
        /// Early-termination penalty in Commons, charged to whoever ends a
        /// recurring contract before its natural end.
        #[arg(long)]
        penalty: Option<String>,
    },
    /// Browse what is on offer.
    Browse {
        /// Free-text query over titles and descriptions.
        #[arg(long)]
        text: Option<String>,
        /// Only this surface.
        #[arg(long, value_parser = PossibleValuesParser::new(SURFACES))]
        surface: Option<String>,
        /// Only this category.
        #[arg(long, value_parser = PossibleValuesParser::new(CATEGORIES))]
        category: Option<String>,
        /// Only listings at or below this price, in Commons. May be negative, to
        /// look only at Commons-surface subsidies.
        #[arg(long, allow_hyphen_values = true)]
        max_price: Option<String>,
        /// Only providers at or above this reputation, in points.
        #[arg(long)]
        min_reputation: Option<String>,
        /// Page size.
        #[arg(long)]
        limit: Option<usize>,
        /// Ranked hits to skip.
        #[arg(long)]
        offset: Option<usize>,
    },
    /// Show one listing in full.
    ShowListing {
        /// The hex listing id.
        listing_id: String,
    },
    /// Show the listings you have published, in any state.
    MyListings,
    /// Edit one of your own listings. Only price, description, availability, and
    /// expiry can change; surface, category, title, and requirements are fixed at
    /// publication. Each field left off is kept as it was.
    EditListing {
        /// The hex listing id.
        listing_id: String,
        /// New price in Commons, e.g. `3`, `3.5`, or `-3.50` (Commons subsidy).
        #[arg(long, allow_hyphen_values = true)]
        price: Option<String>,
        /// Invite offers (`--negotiable true`) or fix the price
        /// (`--negotiable false`). Omitted leaves the pricing model.
        #[arg(long)]
        negotiable: Option<bool>,
        /// New description.
        #[arg(long)]
        description: Option<String>,
        /// New units available (`goods` only).
        #[arg(long)]
        capacity: Option<u32>,
        /// New next open slot, as a date or unix seconds (`services` only).
        #[arg(long)]
        next_slot: Option<String>,
        /// New expiry, as a date or unix seconds.
        #[arg(long)]
        expires: Option<String>,
        /// Remove the expiry so the listing stands until closed. Wins over
        /// `--expires` if both are given.
        #[arg(long)]
        clear_expiry: bool,
    },
    /// Take one of your own listings off offer.
    CloseListing {
        /// The hex listing id.
        listing_id: String,
    },
    /// Announce something you are looking for.
    Need {
        /// Category from the controlled vocabulary.
        #[arg(value_parser = PossibleValuesParser::new(CATEGORIES))]
        category: String,
        /// How many units you want.
        quantity: u32,
        /// The most you will pay, in Commons. May be negative, to seek only
        /// Commons-surface work that pays.
        #[arg(long, allow_hyphen_values = true)]
        max_price: Option<String>,
        /// Valid through this date (`YYYY-MM-DD`), a `+<N>d` offset, or unix
        /// seconds.
        #[arg(long)]
        valid_until: String,
    },
    /// Show the listings answering your needs.
    Matches {
        /// The log seq of one need (from `rrn need`); omitted means all of them.
        seq: Option<u64>,
    },
    /// Open an inquiry against a listing.
    Inquire {
        /// The hex listing id.
        listing_id: String,
        /// Your opening offer, in Commons; omitted accepts the listed price.
        #[arg(long, allow_hyphen_values = true)]
        offer: Option<String>,
        /// An opening message.
        #[arg(long)]
        message: Option<String>,
    },
    /// Show one inquiry thread in full.
    ShowInquiry {
        /// The hex inquiry id.
        inquiry_id: String,
    },
    /// Show the inquiries you are a party to.
    Inquiries,
    /// Reply in an inquiry, optionally with a counter-offer.
    InquiryReply {
        /// The hex inquiry id.
        inquiry_id: String,
        /// A counter-offer, in Commons.
        #[arg(long, allow_hyphen_values = true)]
        offer: Option<String>,
        /// The message body.
        #[arg(long)]
        message: Option<String>,
    },
    /// Close an inquiry: agree on a price, or decline.
    InquiryClose {
        /// The hex inquiry id.
        inquiry_id: String,
        /// How it ends.
        #[arg(long, value_parser = PossibleValuesParser::new(["agreed", "declined"]))]
        outcome: String,
        /// The agreed price, in Commons (for `--outcome agreed`); omitted takes
        /// the listed price.
        #[arg(long, allow_hyphen_values = true)]
        price: Option<String>,
    },
    /// Pay for an inquiry the provider has agreed. Signs a listing-linked payment
    /// at the agreed price, which the provider then confirms with `rrn confirm`.
    /// Only the inquiry's buyer may settle it; a second run returns the existing
    /// payment rather than paying twice.
    SettleInquiry {
        /// The hex id of the agreed inquiry.
        inquiry_id: String,
    },
    /// Sign up to a recurring service, from an inquiry the provider has agreed.
    Contract {
        /// The hex id of the agreed inquiry.
        inquiry_id: String,
        /// A free-form note to record on the contract, as `key=value`;
        /// repeatable. No logic reads these; they are not part of the terms.
        #[arg(long = "metric", value_parser = parse_kv)]
        metrics: Vec<(String, String)>,
    },
    /// Show the service contracts you are a party to.
    Contracts,
    /// Show one service contract in full.
    ShowContract {
        /// The hex contract id.
        contract_id: String,
    },
    /// End one of your service contracts early.
    TerminateContract {
        /// The hex contract id.
        contract_id: String,
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
    let color = cli.color;

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
        Command::Transactions { address, limit } => {
            // `transactions` is expressed relative to a member; default to this
            // station's own address, as `balance` does.
            let address = match address {
                Some(a) => a,
                None => {
                    let v = client.call("whoami", json!({})).await?;
                    parse::<WhoamiResult>(&v)?.address
                }
            };
            let mut params = json!({ "address": address });
            if let Some(limit) = limit {
                params["limit"] = json!(limit);
            }
            let v = client.call("transactions", params).await?;
            emit(fmt, &v, || {
                let r: TransactionsResult = parse(&v)?;
                Ok(render_transactions(&r.transactions, color))
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
        Command::List {
            surface,
            title,
            price,
            category,
            negotiable,
            description,
            capacity,
            next_slot,
            min_reputation,
            community_only,
            oracle_tier,
            expires,
            every,
            periods,
            notice,
            penalty,
        } => {
            let mut params = json!({
                "surface": surface,
                "category": category,
                "title": title,
                "amount_centi": parse_signed_amount(&price)?,
                "negotiable": negotiable,
                "community_member_only": community_only,
            });
            if let Some(d) = description {
                params["description"] = json!(d);
            }
            if let Some(c) = capacity {
                params["capacity"] = json!(c);
            }
            if let Some(s) = next_slot {
                params["next_slot"] = json!(parse_when(&s)?);
            }
            if let Some(r) = min_reputation {
                params["min_reputation"] = json!(parse_points(&r)?);
            }
            if let Some(t) = oracle_tier {
                params["oracle_tier"] = json!(t);
            }
            if let Some(e) = expires {
                params["expires_at"] = json!(parse_when(&e)?);
            }
            if let Some(e) = every {
                params["every"] = json!(e);
            }
            if let Some(p) = periods {
                params["periods"] = json!(p);
            }
            if let Some(n) = notice {
                params["notice_days"] = json!(n);
            }
            if let Some(p) = penalty {
                params["penalty_centi"] = json!(parse_signed_amount(&p)?);
            }
            let v = client.call("marketplace_create_listing", params).await?;
            emit(fmt, &v, || {
                let r: CreateListingResult = parse(&v)?;
                Ok(r.listing_id)
            })
        }
        Command::Browse {
            text,
            surface,
            category,
            max_price,
            min_reputation,
            limit,
            offset,
        } => {
            let mut params = json!({});
            if let Some(t) = text {
                params["text"] = json!(t);
            }
            if let Some(s) = surface {
                params["surface"] = json!(s);
            }
            if let Some(c) = category {
                params["category"] = json!(c);
            }
            if let Some(p) = max_price {
                params["max_price_centi"] = json!(parse_signed_amount(&p)?);
            }
            if let Some(r) = min_reputation {
                params["min_provider_reputation"] = json!(parse_points(&r)?);
            }
            if let Some(l) = limit {
                params["limit"] = json!(l);
            }
            if let Some(o) = offset {
                params["offset"] = json!(o);
            }
            let v = client.call("marketplace_search", params).await?;
            emit(fmt, &v, || Ok(render_cards(&v["listings"], color)))
        }
        Command::ShowListing { listing_id } => {
            let v = client
                .call("marketplace_listing", json!({ "listing_id": listing_id }))
                .await?;
            emit(fmt, &v, || Ok(render_detail(&v, color)))
        }
        Command::MyListings => {
            let v = client.call("marketplace_my_listings", json!({})).await?;
            emit(fmt, &v, || Ok(render_my_listings(&v["listings"], color)))
        }
        Command::EditListing {
            listing_id,
            price,
            negotiable,
            description,
            capacity,
            next_slot,
            expires,
            clear_expiry,
        } => {
            let mut params = json!({ "listing_id": listing_id });
            if let Some(p) = price {
                params["amount_centi"] = json!(parse_signed_amount(&p)?);
            }
            if let Some(n) = negotiable {
                params["negotiable"] = json!(n);
            }
            if let Some(d) = description {
                params["description"] = json!(d);
            }
            if let Some(c) = capacity {
                params["capacity"] = json!(c);
            }
            if let Some(s) = next_slot {
                params["next_slot"] = json!(parse_when(&s)?);
            }
            if let Some(e) = expires {
                params["expires_at"] = json!(parse_when(&e)?);
            }
            if clear_expiry {
                params["clear_expiry"] = json!(true);
            }
            let v = client.call("marketplace_edit_listing", params).await?;
            emit(fmt, &v, || {
                let r: EditListingResult = parse(&v)?;
                Ok(r.listing_id)
            })
        }
        Command::CloseListing { listing_id } => {
            let v = client
                .call(
                    "marketplace_close_listing",
                    json!({ "listing_id": listing_id }),
                )
                .await?;
            emit(fmt, &v, || {
                let r: CloseListingResult = parse(&v)?;
                Ok(r.reason)
            })
        }
        Command::Need {
            category,
            quantity,
            max_price,
            valid_until,
        } => {
            let mut params = json!({
                "category": category,
                "quantity_needed": quantity,
                "valid_until": parse_when(&valid_until)?,
            });
            if let Some(p) = max_price {
                params["max_price_centi"] = json!(parse_signed_amount(&p)?);
            }
            let v = client.call("marketplace_announce_need", params).await?;
            emit(fmt, &v, || {
                let r: AnnounceNeedResult = parse(&v)?;
                Ok(r.seq.to_string())
            })
        }
        Command::Matches { seq } => {
            let params = match seq {
                Some(seq) => json!({ "seq": seq }),
                None => json!({}),
            };
            let v = client.call("marketplace_matches", params).await?;
            emit(fmt, &v, || Ok(render_matches(&v["needs"], color)))
        }
        Command::Inquire {
            listing_id,
            offer,
            message,
        } => {
            let mut params = json!({ "listing_id": listing_id });
            if let Some(m) = message {
                params["message"] = json!(m);
            }
            if let Some(o) = offer {
                params["offer_centi"] = json!(parse_signed_amount(&o)?);
            }
            let v = client.call("marketplace_inquire", params).await?;
            emit(fmt, &v, || {
                let r: InquireResult = parse(&v)?;
                Ok(r.inquiry_id)
            })
        }
        Command::ShowInquiry { inquiry_id } => {
            let v = client
                .call(
                    "marketplace_inquiry_thread",
                    json!({ "inquiry_id": inquiry_id }),
                )
                .await?;
            emit(fmt, &v, || Ok(render_thread(&v, color)))
        }
        Command::Inquiries => {
            let v = client.call("marketplace_my_inquiries", json!({})).await?;
            emit(fmt, &v, || Ok(render_inquiries(&v["inquiries"], color)))
        }
        Command::InquiryReply {
            inquiry_id,
            offer,
            message,
        } => {
            let mut params = json!({ "inquiry_id": inquiry_id });
            if let Some(m) = message {
                params["message"] = json!(m);
            }
            if let Some(o) = offer {
                params["counter_offer_centi"] = json!(parse_signed_amount(&o)?);
            }
            let v = client.call("marketplace_inquiry_message", params).await?;
            emit(fmt, &v, || {
                let r: InquireResult = parse(&v)?;
                Ok(r.inquiry_id)
            })
        }
        Command::InquiryClose {
            inquiry_id,
            outcome,
            price,
        } => {
            let mut params = json!({ "inquiry_id": inquiry_id, "outcome": outcome });
            if let Some(p) = price {
                params["final_price_centi"] = json!(parse_signed_amount(&p)?);
            }
            let v = client.call("marketplace_inquiry_close", params).await?;
            emit(fmt, &v, || {
                let r: InquiryStateResult = parse(&v)?;
                Ok(r.state)
            })
        }
        Command::SettleInquiry { inquiry_id } => {
            let v = client
                .call(
                    "marketplace_settle_inquiry",
                    json!({ "inquiry_id": inquiry_id }),
                )
                .await?;
            emit(fmt, &v, || {
                let r: ProposeResult = parse(&v)?;
                Ok(r.tx_id)
            })
        }
        Command::Contract {
            inquiry_id,
            metrics,
        } => {
            let metrics: std::collections::BTreeMap<String, String> = metrics.into_iter().collect();
            let params = json!({ "inquiry_id": inquiry_id, "metrics": metrics });
            let v = client.call("marketplace_contract", params).await?;
            emit(fmt, &v, || {
                let r: ContractStateResult = parse(&v)?;
                Ok(r.contract_id)
            })
        }
        Command::Contracts => {
            let v = client.call("marketplace_contracts", json!({})).await?;
            emit(fmt, &v, || Ok(render_contracts(&v["contracts"], color)))
        }
        Command::ShowContract { contract_id } => {
            let v = client
                .call(
                    "marketplace_contract_show",
                    json!({ "contract_id": contract_id }),
                )
                .await?;
            emit(fmt, &v, || Ok(render_contract(&v, color)))
        }
        Command::TerminateContract { contract_id } => {
            let v = client
                .call(
                    "marketplace_contract_terminate",
                    json!({ "contract_id": contract_id }),
                )
                .await?;
            emit(fmt, &v, || {
                let r: ContractStateResult = parse(&v)?;
                Ok(r.state)
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

// --- marketplace text rendering ---------------------------------------------
//
// One row per listing, columns aligned, no headers and no box drawing: the point
// is that `rrn browse | grep food | cut -f1` works. The listing id comes first on
// every row because it is the argument every other marketplace command takes.
//
// These read the daemon's JSON directly rather than deserializing into a struct.
// The view types on the station side carry `&'static str` tags and are
// `Serialize`-only, so there is no type to decode back into — see the note in
// `rrn_station::rpc`.

/// ANSI dim, for the identifiers and secondary columns.
const DIM: &str = "\x1b[2m";
/// ANSI bold, for a listing's title.
const BOLD: &str = "\x1b[1m";
/// ANSI reset.
const RESET: &str = "\x1b[0m";

/// Wraps `text` in an escape code, or returns it untouched when color is off.
fn paint(color: ColorMode, code: &str, text: &str) -> String {
    match color {
        ColorMode::Never => text.to_string(),
        ColorMode::Always => format!("{code}{text}{RESET}"),
    }
}

/// A JSON string field, or `""` when absent.
fn s(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

/// A JSON integer field, or `None` when absent or null.
fn i(v: &serde_json::Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_i64())
}

/// One browse row: id, price, surface, category, band, title.
fn card_line(card: &serde_json::Value, color: ColorMode) -> String {
    let id = s(card, "listing_id");
    // The first 12 hex chars are what a person retypes; the full id is in
    // `--format json` for anything that needs to be exact.
    let short = id.chars().take(12).collect::<String>();
    // Wide enough that `fmt_commons` right-aligns rather than pushing the row:
    // "-3.00 Commons" is 13 characters, and a subsidy is the widest common case.
    // Anything larger overflows the column and shifts its own row only.
    format!(
        "{}  {:>14}  {:<9}  {:<14}  {:<9}  {}",
        paint(color, DIM, &short),
        fmt_commons(i(card, "amount_centi").unwrap_or(0)),
        s(card, "surface"),
        s(card, "category"),
        s(card, "provider_band"),
        paint(color, BOLD, &s(card, "title")),
    )
}

/// Renders a `listings` array as browse rows, or a single explanatory line when
/// nothing matched — an empty stdout reads as a failure.
fn render_cards(listings: &serde_json::Value, color: ColorMode) -> String {
    let Some(rows) = listings.as_array() else {
        return "no listings".to_string();
    };
    if rows.is_empty() {
        return "no listings".to_string();
    }
    rows.iter()
        .map(|card| card_line(card, color))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders `my-listings` rows, which are browse rows plus the lifecycle state.
fn render_my_listings(listings: &serde_json::Value, color: ColorMode) -> String {
    let Some(rows) = listings.as_array() else {
        return "no listings".to_string();
    };
    if rows.is_empty() {
        return "no listings".to_string();
    }
    rows.iter()
        .map(|row| {
            format!(
                "{:<8}  {}",
                s(row, "state"),
                card_line(row, color).trim_end()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders `transactions` rows: id, state, the amount signed relative to the
/// viewer, the counterparty, and — for a marketplace payment — the listing it
/// settled (falling back to the memo). One greppable line each.
fn render_transactions(rows: &[TransactionRow], color: ColorMode) -> String {
    if rows.is_empty() {
        return "no transactions".to_string();
    }
    rows.iter()
        .map(|r| {
            let short = r.id.chars().take(12).collect::<String>();
            let party = r.counterparty_address.chars().take(12).collect::<String>();
            // What the payment was for: the resolved listing title on a
            // marketplace payment, else the memo, else nothing.
            let for_ = r
                .listing_title
                .clone()
                .or_else(|| r.memo.clone())
                .unwrap_or_default();
            format!(
                "{}  {:<9} {:>14}  {}  {}",
                paint(color, DIM, &short),
                r.state,
                fmt_commons(r.amount_centi),
                paint(color, DIM, &party),
                paint(color, BOLD, &for_),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders one listing in full as `key: value` lines — greppable by field name,
/// which is what a detail view is actually used for from a shell.
fn render_detail(v: &serde_json::Value, color: ColorMode) -> String {
    let mut out = Vec::new();
    out.push(format!(
        "{:<24}{}",
        "title",
        paint(color, BOLD, &s(v, "title"))
    ));
    out.push(format!("{:<24}{}", "listing_id", s(v, "listing_id")));
    out.push(format!("{:<24}{}", "state", s(v, "state")));
    if let Some(reason) = v.get("close_reason").and_then(|x| x.as_str()) {
        out.push(format!("{:<24}{}", "close_reason", reason));
    }
    out.push(format!("{:<24}{}", "surface", s(v, "surface")));
    out.push(format!("{:<24}{}", "category", s(v, "category")));
    out.push(format!(
        "{:<24}{} ({})",
        "price",
        fmt_commons(i(v, "amount_centi").unwrap_or(0)),
        s(v, "pricing_model")
    ));
    out.push(format!(
        "{:<24}{}",
        "negotiable",
        v.get("negotiable")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
    ));
    let availability = &v["availability"];
    out.push(format!(
        "{:<24}{}",
        "availability",
        s(availability, "status")
    ));
    if let Some(c) = i(availability, "capacity") {
        out.push(format!("{:<24}{}", "capacity", c));
    }
    if let Some(t) = i(availability, "next_slot") {
        out.push(format!("{:<24}{}", "next_slot", t));
    }
    out.push(format!("{:<24}{}", "provider", s(v, "provider")));
    out.push(format!(
        "{:<24}{} ({:.2})",
        "provider_band",
        s(v, "provider_band"),
        v.get("provider_composite")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0)
    ));
    out.push(format!(
        "{:<24}{}",
        "provider_vouches",
        i(v, "provider_vouches_received").unwrap_or(0)
    ));
    out.push(format!("{:<24}{}", "community", s(v, "community")));
    out.push(format!(
        "{:<24}{}",
        "oracle_tier",
        i(v, "oracle_tier").unwrap_or(0)
    ));
    out.push(format!(
        "{:<24}{:.2}",
        "min_reputation",
        v.get("min_reputation")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0)
    ));
    out.push(format!(
        "{:<24}{}",
        "community_member_only",
        v.get("community_member_only")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
    ));
    out.push(format!(
        "{:<24}{}",
        "created_at",
        i(v, "created_at").unwrap_or(0)
    ));
    if let Some(t) = i(v, "expires_at") {
        out.push(format!("{:<24}{}", "expires_at", t));
    }
    let description = s(v, "description");
    if !description.is_empty() {
        out.push(format!("{:<24}{}", "description", description));
    }
    out.join("\n")
}

/// Renders `matches` as one need header followed by its indented matches, so a
/// call with no argument (every need at once) stays readable.
fn render_matches(needs: &serde_json::Value, color: ColorMode) -> String {
    let Some(rows) = needs.as_array() else {
        return "no needs announced".to_string();
    };
    if rows.is_empty() {
        return "no needs announced".to_string();
    }
    let mut out = Vec::new();
    for need in rows {
        let ceiling = match i(need, "max_price_centi") {
            Some(c) => format!(" under {}", fmt_commons(c)),
            None => String::new(),
        };
        let expired = need
            .get("expired")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        out.push(format!(
            "need {} {} x{}{}{}",
            i(need, "seq").unwrap_or(0),
            s(need, "category"),
            i(need, "quantity_needed").unwrap_or(0),
            ceiling,
            if expired { "  (expired)" } else { "" },
        ));
        let listings = need["listings"]
            .as_array()
            .map(|a| a.as_slice())
            .unwrap_or(&[]);
        if listings.is_empty() {
            out.push("    no matches".to_string());
        } else {
            for card in listings {
                out.push(format!("    {}", card_line(card, color)));
            }
        }
    }
    out.join("\n")
}

/// Renders `inquiries` rows: state, the caller's role, the price on the table,
/// the counterparty, and the listing title — one greppable line each.
fn render_inquiries(inquiries: &serde_json::Value, color: ColorMode) -> String {
    let Some(rows) = inquiries.as_array() else {
        return "no inquiries".to_string();
    };
    if rows.is_empty() {
        return "no inquiries".to_string();
    }
    rows.iter()
        .map(|row| {
            let offer = i(row, "latest_offer_centi")
                .map(fmt_commons)
                .unwrap_or_else(|| "—".to_string());
            format!(
                "{}  {:<8} {:<9} {:>12}  {}  {}",
                s(row, "inquiry_id"),
                s(row, "state"),
                s(row, "role"),
                offer,
                s(row, "counterparty"),
                paint(color, BOLD, &s(row, "listing_title")),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders one inquiry thread: a header of who and where it stands, then the
/// messages in order, each tagged with the side that sent it and any offer.
fn render_thread(v: &serde_json::Value, color: ColorMode) -> String {
    let buyer = s(v, "buyer");
    let mut out = vec![
        format!("{:<14}{}", "inquiry_id", s(v, "inquiry_id")),
        format!(
            "{:<14}{}",
            "listing",
            paint(color, BOLD, &s(v, "listing_title"))
        ),
        format!(
            "{:<14}{} ({})",
            "listed_price",
            fmt_commons(i(v, "listed_amount_centi").unwrap_or(0)),
            if v.get("negotiable")
                .and_then(|x| x.as_bool())
                .unwrap_or(false)
            {
                "negotiable"
            } else {
                "fixed price"
            }
        ),
        format!("{:<14}{}", "buyer", buyer),
        format!("{:<14}{}", "provider", s(v, "provider")),
        format!("{:<14}{}", "state", s(v, "state")),
    ];
    if let Some(outcome) = v.get("outcome").and_then(|x| x.as_str()) {
        out.push(format!("{:<14}{}", "outcome", outcome));
    }
    if let Some(p) = i(v, "final_price_centi") {
        out.push(format!("{:<14}{}", "final_price", fmt_commons(p)));
    }
    out.push(String::new());

    // The opening is the buyer's, by definition.
    out.push(format!(
        "[buyer]    {}",
        message_line(&s(v, "initial_message"), i(v, "initial_offer_centi"))
    ));
    if let Some(msgs) = v.get("messages").and_then(|x| x.as_array()) {
        for m in msgs {
            let who = if s(m, "sender") == buyer {
                "buyer"
            } else {
                "provider"
            };
            out.push(format!(
                "[{:<8}] {}",
                who,
                message_line(&s(m, "body"), i(m, "counter_offer_centi"))
            ));
        }
    }
    out.join("\n")
}

/// A message body prefixed with its offer, when it carried one.
fn message_line(body: &str, offer_centi: Option<i64>) -> String {
    match offer_centi {
        Some(o) => {
            let offer = format!("(offer {})", fmt_commons(o));
            if body.trim().is_empty() {
                offer
            } else {
                format!("{offer} {body}")
            }
        }
        None => body.to_string(),
    }
}

/// Renders `contracts` rows: state, the caller's role, the per-period price, how
/// many periods have been charged, the counterparty, and the listing title.
fn render_contracts(contracts: &serde_json::Value, color: ColorMode) -> String {
    let Some(rows) = contracts.as_array() else {
        return "no contracts".to_string();
    };
    if rows.is_empty() {
        return "no contracts".to_string();
    }
    rows.iter()
        .map(|row| {
            let charged = i(row, "periods_charged").unwrap_or(0);
            let total = charged + i(row, "periods_remaining").unwrap_or(0);
            format!(
                "{}  {:<11} {:<9} {:>10}/period  {}/{} charged  {}  {}",
                s(row, "contract_id"),
                s(row, "state"),
                s(row, "role"),
                fmt_commons(i(row, "commons_per_period_centi").unwrap_or(0)),
                charged,
                total,
                s(row, "counterparty"),
                paint(color, BOLD, &s(row, "listing_title")),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders one contract in full: the terms, where it stands, and any free-form
/// notes the buyer recorded. Timestamps are raw unix seconds, as elsewhere.
fn render_contract(v: &serde_json::Value, color: ColorMode) -> String {
    let mut out = vec![
        format!(
            "{:<24}{}",
            "listing",
            paint(color, BOLD, &s(v, "listing_title"))
        ),
        format!("{:<24}{}", "contract_id", s(v, "contract_id")),
        format!("{:<24}{}", "inquiry_id", s(v, "inquiry_id")),
        format!("{:<24}{}", "state", s(v, "state")),
        format!("{:<24}{}", "buyer", s(v, "buyer")),
        format!("{:<24}{}", "provider", s(v, "provider")),
        format!(
            "{:<24}{} (every {}s)",
            "cadence",
            s(v, "frequency"),
            i(v, "period_secs").unwrap_or(0)
        ),
        format!(
            "{:<24}{}/period",
            "price",
            fmt_commons(i(v, "commons_per_period_centi").unwrap_or(0))
        ),
        format!(
            "{:<24}{} charged, {} left of {}",
            "periods",
            i(v, "periods_charged").unwrap_or(0),
            i(v, "periods_remaining").unwrap_or(0),
            i(v, "duration_periods").unwrap_or(0)
        ),
        format!(
            "{:<24}{} days",
            "notice",
            i(v, "notice_period_days").unwrap_or(0)
        ),
        format!(
            "{:<24}{}",
            "penalty",
            fmt_commons(i(v, "early_termination_penalty_centi").unwrap_or(0))
        ),
        format!("{:<24}{}", "started_at", i(v, "started_at").unwrap_or(0)),
    ];
    if let Some(t) = i(v, "next_charge_due") {
        out.push(format!("{:<24}{}", "next_charge_due", t));
    }
    if let Some(t) = i(v, "terminating_effective_at") {
        out.push(format!("{:<24}{}", "terminating_at", t));
    }
    if let Some(r) = v.get("ended_reason").and_then(|x| x.as_str()) {
        out.push(format!("{:<24}{}", "ended_reason", r));
    }
    if let Some(b) = v.get("terminated_by").and_then(|x| x.as_str()) {
        out.push(format!("{:<24}{}", "terminated_by", b));
    }
    if let Some(e) = v.get("ended_early").and_then(|x| x.as_bool()) {
        out.push(format!("{:<24}{}", "ended_early", e));
    }
    if let Some(t) = i(v, "ended_at") {
        out.push(format!("{:<24}{}", "ended_at", t));
    }
    if let Some(metrics) = v.get("performance_metrics").and_then(|x| x.as_object()) {
        if !metrics.is_empty() {
            out.push(String::new());
            out.push("metrics".to_string());
            for (k, val) in metrics {
                out.push(format!("  {:<22}{}", k, val.as_str().unwrap_or("")));
            }
        }
    }
    out.join("\n")
}

/// Parses a `key=value` metric pair for `rrn contract --metric`. The key may not
/// be empty; the value may (a bare `note=` records an empty note).
fn parse_kv(s: &str) -> std::result::Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => Err(format!("expected key=value, got {s:?}")),
    }
}

/// Parses a point value (a reputation composite, e.g. `1.5`) from the same
/// two-decimal grammar amounts use, so `1.5` and `1.50` both mean 1.5 points.
fn parse_points(s: &str) -> Result<f32> {
    Ok(parse_signed_amount(s)? as f32 / 100.0)
}

/// Parses a moment: `YYYY-MM-DD`, a `+<N>d` offset from now, or raw unix seconds.
///
/// A bare date means the **end** of that day in UTC, because that is what a
/// person means by "valid until the 30th" — a listing or need that stopped
/// mattering at midnight as the day began would surprise everyone.
fn parse_when(s: &str) -> Result<i64> {
    let s = s.trim();
    if let Some(days) = s.strip_prefix('+').and_then(|d| d.strip_suffix('d')) {
        let days: i64 = days
            .parse()
            .with_context(|| format!("invalid day offset {s:?}"))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        return Ok(now + days * 86_400);
    }
    if let Some((y, rest)) = s.split_once('-') {
        let (m, d) = rest
            .split_once('-')
            .ok_or_else(|| anyhow!("invalid date {s:?}: expected YYYY-MM-DD"))?;
        let year: i64 = y
            .parse()
            .with_context(|| format!("invalid year in {s:?}"))?;
        let month: i64 = m
            .parse()
            .with_context(|| format!("invalid month in {s:?}"))?;
        let day: i64 = d.parse().with_context(|| format!("invalid day in {s:?}"))?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(anyhow!("invalid date {s:?}"));
        }
        // End of that day: the last second it is still that date in UTC.
        return Ok(days_from_civil(year, month, day) * 86_400 + 86_399);
    }
    s.parse::<i64>()
        .with_context(|| format!("invalid date or unix seconds {s:?}"))
}

/// Days since the Unix epoch for a civil (proleptic Gregorian) date.
///
/// Howard Hinnant's `days_from_civil`, which is exact for every date the network
/// will see and needs no date library — the workspace has none, and one date
/// conversion is not the reason to add one.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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

/// Parses a Commons amount that may be negative, for the marketplace.
///
/// A leading `-` is accepted here and refused by [`parse_amount`] because the two
/// answer different questions: a payment's direction is which way it is
/// addressed, never a negative number, while a `commons`-surface listing at a
/// negative price is a subsidy — the community paying a member to take a
/// responsibility on. The station still refuses a negative price on the other two
/// surfaces (ADR-0010); this only declines to make that judgment in the client.
fn parse_signed_amount(s: &str) -> Result<i64> {
    match s.trim().strip_prefix('-') {
        Some(rest) => Ok(-parse_amount(rest)?),
        None => parse_amount(s),
    }
}

fn default_socket() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".railroad").join("station").join("station.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn signed_amounts_allow_the_commons_subsidy_case() {
        assert_eq!(parse_signed_amount("2.50").unwrap(), 250);
        assert_eq!(parse_signed_amount("-2.50").unwrap(), -250);
        assert_eq!(parse_signed_amount("-0.01").unwrap(), -1);
        // The grammar is otherwise the same, so the same junk is refused.
        for bad in ["-3.001", "-", "-abc", "--3"] {
            assert!(
                parse_signed_amount(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn points_come_from_the_same_two_decimal_grammar() {
        assert_eq!(parse_points("1.5").unwrap(), 1.5);
        assert_eq!(parse_points("1.50").unwrap(), 1.5);
        assert_eq!(parse_points("0").unwrap(), 0.0);
        assert_eq!(parse_points("3.50").unwrap(), 3.5);
    }

    #[test]
    fn civil_dates_convert_to_the_right_epoch_day() {
        // Anchors: the epoch itself, a leap day, and a century non-leap year.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2024, 2, 29), 19_782);
    }

    #[test]
    fn a_bare_date_means_the_end_of_that_day() {
        // 2026-07-29 23:59:59 UTC. A need "valid until the 29th" that expired as
        // the 29th began would surprise everyone.
        let end_of_day = parse_when("2026-07-29").unwrap();
        assert_eq!(end_of_day % 86_400, 86_399);
        assert_eq!(end_of_day, days_from_civil(2026, 7, 29) * 86_400 + 86_399);
    }

    #[test]
    fn a_moment_can_also_be_an_offset_or_raw_seconds() {
        // Raw unix seconds pass through untouched.
        assert_eq!(parse_when("1800000000").unwrap(), 1_800_000_000);

        // `+Nd` is relative to now, so assert the span rather than the value.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let in_30_days = parse_when("+30d").unwrap();
        assert!((in_30_days - (now + 30 * 86_400)).abs() <= 2);
    }

    #[test]
    fn rejects_moments_that_are_not_dates() {
        for bad in [
            "2026-13-01",
            "2026-07-32",
            "2026-07",
            "not-a-date",
            "+xd",
            "",
        ] {
            assert!(parse_when(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn browse_rows_are_plain_unless_color_is_asked_for() {
        let card = serde_json::json!({
            "listing_id": "abcdef0123456789",
            "amount_centi": 250,
            "surface": "goods",
            "category": "food",
            "provider_band": "New",
            "title": "Winter squash",
        });
        let plain = card_line(&card, ColorMode::Never);
        assert!(plain.contains("Winter squash"));
        assert!(plain.contains("2.50 Commons"));
        // The short id is what a person retypes; the full one is in JSON mode.
        assert!(plain.contains("abcdef012345"));
        assert!(!plain.contains('\x1b'), "default output must be plain");
        assert!(card_line(&card, ColorMode::Always).contains('\x1b'));
    }

    #[test]
    fn an_empty_result_says_so_rather_than_printing_nothing() {
        // Empty stdout reads as a failure; these commands succeed with nothing
        // to show, which is a different thing and has to look different.
        assert_eq!(
            render_cards(&serde_json::json!([]), ColorMode::Never),
            "no listings"
        );
        assert_eq!(
            render_my_listings(&serde_json::json!([]), ColorMode::Never),
            "no listings"
        );
        assert_eq!(
            render_matches(&serde_json::json!([]), ColorMode::Never),
            "no needs announced"
        );
        assert_eq!(
            render_transactions(&[], ColorMode::Never),
            "no transactions"
        );
    }

    #[test]
    fn a_transaction_row_leads_with_its_listing_then_falls_back_to_memo() {
        let base = TransactionRow {
            id: "abcdef0123456789".into(),
            counterparty_address: "rrn1counterparty000".into(),
            direction: "out".into(),
            amount_centi: -400,
            memo: Some("Fresh eggs · #a63d8d06".into()),
            listing_id: Some("3c3738c4".into()),
            listing_title: Some("Fresh eggs".into()),
            state: "settled".into(),
            oracle_tier: 1,
            timestamp: 1_000,
            expires_at: None,
            confirmed_at: None,
            settle_by: None,
            settled_at: Some(1_010),
            nonce: 0,
        };
        // The resolved listing title wins over the memo.
        let with_title = render_transactions(std::slice::from_ref(&base), ColorMode::Never);
        assert!(with_title.contains("Fresh eggs"), "{with_title}");
        assert!(with_title.contains("-4.00 Commons"), "{with_title}");
        assert!(with_title.contains("abcdef012345"), "{with_title}");

        // A direct pay with no listing shows the memo instead.
        let direct = TransactionRow {
            listing_id: None,
            listing_title: None,
            memo: Some("lunch".into()),
            ..base
        };
        let out = render_transactions(&[direct], ColorMode::Never);
        assert!(out.contains("lunch"), "{out}");
    }

    #[test]
    fn a_need_with_no_matches_says_that_under_its_own_header() {
        let needs = serde_json::json!([{
            "seq": 7,
            "category": "food",
            "quantity_needed": 6,
            "max_price_centi": 300,
            "valid_until": 1_800_000_000i64,
            "expired": true,
            "listings": [],
        }]);
        let out = render_matches(&needs, ColorMode::Never);
        assert!(out.contains("need 7 food x6"), "{out}");
        assert!(out.contains("under 3.00 Commons"), "{out}");
        assert!(out.contains("(expired)"), "{out}");
        assert!(out.contains("no matches"), "{out}");
    }
}
