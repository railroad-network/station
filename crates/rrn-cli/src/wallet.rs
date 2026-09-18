//! `rrn wallet` — the self-custody CLI member wallet (ADR-0028).
//!
//! The member device that is a *laptop, not a phone*: it holds its own Ed25519
//! key (in an `EncryptedWallet` `member.rrnwallet`, exactly the mobile format),
//! signs payments/confirmations/votes/disputes offline into a durable,
//! hash-chained outbox (`rrn-storage`'s `OutboxStore` over its own `wallet.db`),
//! carries them to the station on paper or a DTN bundle, and — online — pairs
//! and syncs over the ADR-0008 sealed channel like a phone
//! ([`rrn_station::channel_client`]).
//!
//! This is the one CLI role that holds a key and opens a database; the operator
//! console (the rest of `rrn`) holds neither, and the `paper` module stays a
//! verify-only courier tool. The arrow between the two is one-directional: this
//! module *calls* `paper`'s render helpers; `paper` never calls this one.
//!
//! # Trust anchor: the station pin
//!
//! `init --station rrn1…` pins the station's identity. Every station-signed
//! artifact the wallet accepts — receipts, certificates, the pairing response —
//! is checked against that pin, not merely self-verified: a receipt must be
//! signed by the pin *and* name it, mirroring the mobile FFI's `receipt_parse`.
//!
//! # No self-forking
//!
//! The outbox is a single hash chain. A restored wallet (`init --restore`)
//! refuses every signing verb until one `sync` re-anchors it on the station's
//! highest-*seen* position (ADR-0028 §7); the nonce cursor advances at signing
//! time and is reset from the station only when nothing is pending. There is no
//! manual position/hash override — that is the self-fork footgun.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use dcbor::prelude::*;
use serde_json::json;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_governance::proposal::ProposalId;
use rrn_governance::vote::{Vote, VoteChoice};
use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::RecoverySession;
use rrn_identity::vouch::create_vouch;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::dispute::DisputeRecord;
use rrn_ledger::escrow::{
    self, CertId, CertificateRequest, CertificateReturn, SignedCertificateRequest,
};
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
};
use rrn_protocol::bundle::{Bundle, EntryEnvelope, MAX_BUNDLE_ENTRIES};
use rrn_protocol::outbox::OutboxEntry;
use rrn_protocol::paper::{
    self, classify, PaperKind, PaperPayloadKind, PaperReassembler, SpendVoucher,
};
use rrn_protocol::receipt::{self, Disposition};
use rrn_station::channel_client::{ChannelClient, ChannelClientError};
use rrn_station::history::fmt_commons;
use rrn_station::station::{CONFIG_FILE, DB_FILE, SOCKET_FILE, WALLET_FILE};
use rrn_storage::db::Database;
use rrn_storage::migrations;
use rrn_storage::outbox::{AckOutcome, NewOutboxEntry, OutboxRow, OutboxStore};
use rrn_storage::wallet_meta::WalletMeta;

use crate::{ColorMode, Format};

/// The wallet's on-disk metadata schema version.
const SCHEMA: &str = "1";
/// The community stamped on vouches (mirrors the station's placeholder).
const VOUCH_COMMUNITY: &str = "rrn-phase0";
/// Default proposal validity, matching the station's `PROPOSAL_TTL_SECS`.
const PROPOSAL_TTL_SECS: i64 = 24 * 3600;
/// The wallet file name — deliberately *not* the station's `wallet.rrnwallet`.
const MEMBER_WALLET_FILE: &str = "member.rrnwallet";

// --- meta keys (documented in `wallet_meta.rs`) -----------------------------
const K_ROLE: &str = "role";
const K_SCHEMA: &str = "schema";
const K_ADDRESS: &str = "address";
const K_STATION_ADDRESS: &str = "station_address";
const K_STATION_URL: &str = "station_url";
const K_PAIRED: &str = "paired";
const K_TRANSPORT_NONCE: &str = "transport_nonce";
const K_NONCE_CURSOR: &str = "nonce_cursor";
const K_CHAIN_STATE: &str = "chain_state";
const K_LAST_SYNC_AT: &str = "last_sync_at";

/// The DTN carrier a signed record is bound for — it only sets the default
/// expiry, wide enough for a slow carrier to deliver in time.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Carrier {
    /// Online submit or a same-day courier: the normal 24h proposal TTL.
    Fast,
    /// Paper / LoRa / SMS: a two-week window so the record survives delivery.
    Slow,
}

/// The output form of `wallet export`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Printable QR sheets (`rrnp:` chunks + PNG + PDF), for `rrn paper ingest`.
    Qr,
    /// A single `payload.bundle` of raw bytes, for `rrn dtn push --bundle`.
    Bundle,
}

/// A ballot choice on the command line.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum VoteChoiceArg {
    Yes,
    No,
    Abstain,
}

impl From<VoteChoiceArg> for VoteChoice {
    fn from(c: VoteChoiceArg) -> Self {
        match c {
            VoteChoiceArg::Yes => VoteChoice::Yes,
            VoteChoiceArg::No => VoteChoice::No,
            VoteChoiceArg::Abstain => VoteChoice::Abstain,
        }
    }
}

/// The `rrn wallet …` command family.
#[derive(Subcommand)]
pub enum WalletCmd {
    /// Create a new member wallet (or restore a backed-up one) pinned to a station.
    Init {
        /// The station's `rrn1…` address to pin (learned from the operator, in
        /// person — the pin is the security boundary).
        #[arg(long)]
        station: String,
        /// Restore from a backed-up `member.rrnwallet` instead of a fresh key.
        /// The restored wallet refuses signing until one `sync` re-anchors it.
        #[arg(long)]
        restore: Option<PathBuf>,
    },
    /// Rebuild a lost key from your recovery circle, into a fresh wallet home.
    ///
    /// Runs the reconstruction ceremony on *this* device: prints a request QR and
    /// a fingerprint for your holders to confirm, gathers their responses, and
    /// rebuilds your key locally — nothing touches the station (ADR-0006). The
    /// recovered wallet is treated as restored: it refuses signing until one
    /// `sync` re-anchors it (ADR-0028).
    Recover {
        /// The station's `rrn1…` address to pin (as for `init`).
        #[arg(long)]
        station: String,
        /// The `rrn1…` address being recovered. Prompted for if omitted (read it
        /// off your old credential card or a friend's contact list).
        #[arg(long)]
        address: Option<String>,
        /// Overwrite an existing wallet home.
        #[arg(long)]
        force: bool,
    },
    /// Pair with the station over the sealed channel; prints the SAS for the
    /// operator to confirm.
    Pair {
        /// The station's mobile listener, `host:port`.
        #[arg(long)]
        url: String,
    },
    /// Re-anchor and sync: nonce, outbox head, balance, and delivery receipts.
    Sync {
        /// Skip fetching and applying delivery receipts.
        #[arg(long)]
        no_receipts: bool,
    },
    /// Show local wallet state — never unlocks the key.
    Status,
    /// Sign a payment: chained into the outbox, pending until submitted/carried.
    Pay {
        /// The receiver's `rrn1…` address.
        receiver: String,
        /// Amount in Commons, e.g. `3`, `3.5`, or `3.50`.
        amount: String,
        /// Optional memo recorded in the signed proposal.
        #[arg(long)]
        memo: Option<String>,
        /// Spend against a held headroom certificate (id hex or prefix).
        #[arg(long)]
        cert: Option<String>,
        /// Override the proposal's validity window, in seconds.
        #[arg(long)]
        expires_in: Option<i64>,
        /// The carrier this spend is bound for (sets the default expiry).
        #[arg(long, value_enum, default_value_t = Carrier::Fast)]
        carrier: Carrier,
        /// Also write `rrnspend:` voucher lines for offline verification.
        #[arg(long)]
        voucher_out: Option<PathBuf>,
    },
    /// Confirm a proposed payment addressed to you.
    Confirm {
        /// The hex transaction id.
        tx_id: String,
    },
    /// Cast a governance ballot.
    Vote {
        /// The proposal id, hex.
        proposal_id: String,
        /// yes | no | abstain.
        #[arg(value_enum)]
        choice: VoteChoiceArg,
    },
    /// Contest a confirmed payment.
    Dispute {
        /// The hex transaction id.
        tx_id: String,
        /// A bounded free-text statement of the grievance.
        #[arg(long)]
        reason: String,
        /// Optional content hash of out-of-band evidence (hex).
        #[arg(long)]
        evidence_hash: Option<String>,
    },
    /// Vouch for another member (online only — needs the station reachable).
    Vouch {
        /// The `rrn1…` address to vouch for.
        address: String,
        /// The attestation statement.
        #[arg(long)]
        statement: String,
        /// The reputation stake, in Commons.
        #[arg(long)]
        stake: String,
    },
    /// Headroom certificates (ADR-0021): request, import, list, return.
    Cert {
        #[command(subcommand)]
        cmd: WalletCertCmd,
    },
    /// Export pending outbox entries as QR sheets or a raw bundle (offline path).
    ///
    /// The encoding is a positional argument (`qr` or `bundle`): the global
    /// `--format json|text` already owns `--format`, so this cannot reuse it.
    Export {
        /// `qr` (printable sheets) or `bundle` (raw `payload.bundle`).
        #[arg(value_enum)]
        encoding: ExportFormat,
        /// The output directory.
        #[arg(long)]
        out: PathBuf,
        /// Cap the number of pending entries carried.
        #[arg(long)]
        max_entries: Option<usize>,
    },
    /// Submit pending entries online: bundle → channel → apply receipts.
    Submit {
        /// Cap the number of pending entries submitted in one bundle.
        #[arg(long)]
        max_entries: Option<usize>,
    },
    /// Delivery receipts.
    Receipts {
        #[command(subcommand)]
        cmd: WalletReceiptsCmd,
    },
    /// Show local outbox rows and their dispositions.
    Show {
        /// Only still-pending rows.
        #[arg(long)]
        pending: bool,
        /// Every row, acked and pending (the default shows pending + recent).
        #[arg(long)]
        all: bool,
    },
    /// Your transactions, read live from the station over the channel.
    Transactions,
}

/// `rrn wallet cert …`.
#[derive(Subcommand)]
pub enum WalletCertCmd {
    /// Request a headroom certificate (online round-trip).
    Request {
        /// The cap, in Commons.
        cap: String,
    },
    /// Import a certificate from an `rrncert:` line or raw envelope file.
    Import {
        /// The file to read.
        #[arg(long = "in")]
        input: PathBuf,
    },
    /// List certificates the wallet holds.
    List,
    /// Return an outstanding certificate early (chained record).
    Return {
        /// The certificate id, hex or prefix.
        id: String,
    },
}

/// `rrn wallet receipts …`.
#[derive(Subcommand)]
pub enum WalletReceiptsCmd {
    /// Apply station-signed receipts from scanned QR text or raw bytes.
    Apply {
        /// One or more files of receipt lines.
        #[arg(long = "in", required = true, num_args = 1..)]
        input: Vec<PathBuf>,
    },
}

/// Dispatch entry point for the whole `wallet` family.
pub async fn cmd_wallet(
    fmt: Format,
    color: ColorMode,
    home: Option<PathBuf>,
    cmd: WalletCmd,
) -> Result<()> {
    let home = resolve_home(home);

    // `init` is the only verb allowed to run against an empty (or brand-new)
    // home; every other verb requires an already-initialized member wallet.
    if let WalletCmd::Init { station, restore } = &cmd {
        return cmd_init(fmt, &home, station, restore.as_deref());
    }
    // `recover` likewise runs against a fresh home and never opens an existing
    // wallet — it *creates* one from the recovery ceremony.
    if let WalletCmd::Recover {
        station,
        address,
        force,
    } = &cmd
    {
        return cmd_recover(fmt, &home, station, address.as_deref(), *force);
    }

    // Pre-unlock guard: refuse a station's data dir or a non-member wallet home
    // before any passphrase is read (ADR-0028 §3.1).
    guard_home(&home)?;
    let _lock = HomeLock::acquire(&home)?;
    let wallet = Wallet::open(home)?;

    match cmd {
        WalletCmd::Init { .. } => unreachable!("handled above"),
        WalletCmd::Recover { .. } => unreachable!("handled above"),
        WalletCmd::Pair { url } => wallet.cmd_pair(fmt, &url).await,
        WalletCmd::Sync { no_receipts } => wallet.cmd_sync(fmt, no_receipts).await,
        WalletCmd::Status => wallet.cmd_status(fmt),
        WalletCmd::Pay {
            receiver,
            amount,
            memo,
            cert,
            expires_in,
            carrier,
            voucher_out,
        } => wallet.cmd_pay(
            fmt,
            &receiver,
            &amount,
            memo,
            cert.as_deref(),
            expires_in,
            carrier,
            voucher_out.as_deref(),
        ),
        WalletCmd::Confirm { tx_id } => wallet.cmd_confirm(fmt, &tx_id),
        WalletCmd::Vote {
            proposal_id,
            choice,
        } => wallet.cmd_vote(fmt, &proposal_id, choice.into()),
        WalletCmd::Dispute {
            tx_id,
            reason,
            evidence_hash,
        } => wallet.cmd_dispute(fmt, &tx_id, &reason, evidence_hash.as_deref()),
        WalletCmd::Vouch {
            address,
            statement,
            stake,
        } => wallet.cmd_vouch(fmt, &address, &statement, &stake).await,
        WalletCmd::Cert { cmd } => wallet.cmd_cert(fmt, cmd).await,
        WalletCmd::Export {
            encoding,
            out,
            max_entries,
        } => wallet.cmd_export(fmt, &out, encoding, max_entries),
        WalletCmd::Submit { max_entries } => wallet.cmd_submit(fmt, max_entries).await,
        WalletCmd::Receipts { cmd } => match cmd {
            WalletReceiptsCmd::Apply { input } => wallet.cmd_receipts_apply(fmt, &input),
        },
        WalletCmd::Show { pending, all } => wallet.cmd_show(fmt, color, pending, all),
        WalletCmd::Transactions => wallet.cmd_transactions(fmt, color).await,
    }
}

// ---------------------------------------------------------------------------
// Home resolution, guard, and a single-writer lock
// ---------------------------------------------------------------------------

/// Resolves the wallet home: `--home` > `RRN_WALLET_HOME` > `$HOME/.railroad/wallet`.
fn resolve_home(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir;
    }
    if let Some(dir) = std::env::var_os("RRN_WALLET_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".railroad").join("wallet")
}

/// Refuses a home that is actually a station's data dir, or is not a member
/// wallet. Runs before any passphrase is read (ADR-0028 §3.1).
fn guard_home(home: &Path) -> Result<()> {
    for forbidden in [DB_FILE, CONFIG_FILE, WALLET_FILE, SOCKET_FILE] {
        if home.join(forbidden).exists() {
            bail!(
                "{} looks like a station data directory (found {forbidden}); \
                 the member wallet home must be its own directory",
                home.display()
            );
        }
    }
    // The wallet database must exist and be a member wallet.
    let db_path = home.join("wallet.db");
    if !db_path.exists() {
        bail!(
            "no member wallet at {} — run `rrn wallet init --station rrn1…` first",
            home.display()
        );
    }
    let db = Database::open(&db_path).context("open wallet.db")?;
    migrations::run(&db).context("apply wallet migrations")?;
    match WalletMeta::new(&db).get(K_ROLE)? {
        Some(role) if role == "member" => Ok(()),
        _ => bail!(
            "{} is not a member wallet (its role marker is missing or wrong)",
            home.display()
        ),
    }
}

/// A best-effort single-writer lock over `<home>/wallet.lock`, held for the
/// lifetime of one verb. Concurrent use is "belt and braces", not a security
/// boundary (ADR-0028 Consequences): a stale lock left by a killed process must
/// be removed by hand.
struct HomeLock {
    path: PathBuf,
}

impl HomeLock {
    fn acquire(home: &Path) -> Result<Self> {
        let path = home.join("wallet.lock");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => Ok(Self { path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => bail!(
                "another `rrn wallet` command is using {} (or a stale {} remains — \
                 remove it by hand if no wallet command is running)",
                home.display(),
                path.display()
            ),
            Err(e) => Err(e).context("create wallet lock"),
        }
    }
}

impl Drop for HomeLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// `init`
// ---------------------------------------------------------------------------

fn cmd_init(fmt: Format, home: &Path, station: &str, restore: Option<&Path>) -> Result<()> {
    // The pin must be a valid station address.
    let station_addr: Address = station
        .parse()
        .map_err(|_| anyhow!("invalid station address {station:?} (expected rrn1…)"))?;

    // Refuse a non-empty home (any of our files present, or a station's).
    for name in [
        MEMBER_WALLET_FILE,
        "wallet.db",
        DB_FILE,
        CONFIG_FILE,
        WALLET_FILE,
        SOCKET_FILE,
    ] {
        if home.join(name).exists() {
            bail!(
                "{} is not empty (found {name}); choose a fresh --home",
                home.display()
            );
        }
    }
    std::fs::create_dir_all(home).context("create wallet home")?;
    set_dir_private(home);

    let passphrase = read_passphrase(true)?;

    // Fresh key, or restore a backed-up wallet file.
    let (contents, chain_state) = match restore {
        None => {
            let mut c = WalletContents::create_new();
            c.metadata.insert(K_ROLE.into(), "member".into());
            c.metadata.insert(K_SCHEMA.into(), SCHEMA.into());
            (c, "fresh")
        }
        Some(src) => {
            let bytes = std::fs::read(src).with_context(|| format!("read {}", src.display()))?;
            // Load with the *new* passphrase — a restore keeps the file's own
            // passphrase, so the operator supplies that here.
            let c = WalletContents::load_from_file(src, &passphrase)
                .map_err(|e| anyhow!("could not open the backup wallet: {e}"))?;
            let _ = bytes; // read only to fail early on a missing file
            (c, "unknown")
        }
    };

    let address = contents.address.to_string();
    let wallet_path = home.join(MEMBER_WALLET_FILE);
    contents
        .save_to_file(&wallet_path, &passphrase)
        .context("write member.rrnwallet")?;

    // The local metadata database, co-located with the outbox.
    let db = Database::open(&home.join("wallet.db")).context("create wallet.db")?;
    migrations::run(&db).context("apply wallet migrations")?;
    write_initial_meta(&db, &address, &station_addr, chain_state)?;

    crate::emit(
        fmt,
        &json!({ "address": address, "chain_state": chain_state }),
        || Ok(address.clone()),
    )
}

/// Writes the initial local metadata for a freshly created (or recovered) member
/// wallet: a fresh, unpaired, un-synced chain pinned to `station_addr`. Shared by
/// `init` and `recover` so the two cannot drift.
fn write_initial_meta(
    db: &Database,
    address: &str,
    station_addr: &Address,
    chain_state: &str,
) -> Result<()> {
    let mut m = WalletMeta::new(db);
    m.set(K_ROLE, "member")?;
    m.set(K_SCHEMA, SCHEMA)?;
    m.set(K_ADDRESS, address)?;
    m.set(K_STATION_ADDRESS, &station_addr.to_string())?;
    m.set(K_PAIRED, "no")?;
    m.set(K_TRANSPORT_NONCE, "0")?;
    m.set(K_NONCE_CURSOR, "0")?;
    m.set(K_CHAIN_STATE, chain_state)?;
    Ok(())
}

/// `rrn wallet recover` — rebuild a lost key from the member's recovery circle.
///
/// The reconstruction ceremony (ADR-0016) runs entirely on this device: an
/// ephemeral recovery keypair is minted here, the request QR and fingerprint are
/// shown here, holders' responses are opened here, and the key is interpolated
/// and immediately sealed under a new passphrase here. The station is never
/// involved and learns nothing (ADR-0006). A recovered wallet is a restored
/// wallet: chain state `unknown`, signing refused until one `sync` (ADR-0028 §7).
fn cmd_recover(
    fmt: Format,
    home: &Path,
    station: &str,
    address: Option<&str>,
    force: bool,
) -> Result<()> {
    let station_addr: Address = station
        .parse()
        .map_err(|_| anyhow!("invalid station address {station:?} (expected rrn1…)"))?;

    // The identity being recovered: from --address, else prompted (read off the
    // old credential card). Validated as a well-formed rrn1… address.
    let target: Address = match address {
        Some(a) => a
            .parse()
            .map_err(|_| anyhow!("invalid address {a:?} (expected rrn1…)"))?,
        None => {
            let entered =
                rpassword::prompt_password("address to recover (rrn1…): ").or_else(|_| {
                    // Not secret; fall back to a visible prompt if no tty for rpassword.
                    use std::io::Write;
                    print!("address to recover (rrn1…): ");
                    std::io::stdout().flush().ok();
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s).map(|_| s)
                })?;
            entered
                .trim()
                .parse()
                .map_err(|_| anyhow!("that is not a valid rrn1… address"))?
        }
    };

    // Refuse a non-empty home unless --force (mirrors `init`, which never
    // overwrites; recover adds the escape hatch for a half-set-up device).
    if !force {
        for name in [
            MEMBER_WALLET_FILE,
            "wallet.db",
            DB_FILE,
            CONFIG_FILE,
            WALLET_FILE,
            SOCKET_FILE,
        ] {
            if home.join(name).exists() {
                bail!(
                    "{} is not empty (found {name}); choose a fresh --home or pass --force",
                    home.display()
                );
            }
        }
    }

    // Run the ceremony: publish the request, show the fingerprint, gather
    // responses from stdin. Nothing is written to disk until the key rebuilds.
    let mut session = RecoverySession::begin(target);
    let request_line = rrn_station::recovery::encode_request(&session.request());
    // All human guidance goes to stderr; stdout carries only the final result
    // (the JSON/text object), so `rrn --format json wallet recover` stays
    // machine-parseable.
    eprintln!("Recovering {target}");
    eprintln!("\nHave each holder scan this request in their wallet's \"help recover\" flow:\n");
    eprintln!("{}", rrn_station::recovery::render_qr(&request_line));
    eprintln!("or paste this line to each holder:");
    eprintln!("{request_line}\n");
    eprintln!("Ceremony fingerprint: {}", session.fingerprint());
    eprintln!("Every holder must see this exact code on their screen before responding.\n");
    eprintln!(
        "Paste each holder's response line below as it comes in. Press Enter on an empty line \
         when you have enough:"
    );

    {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let line = line.context("read response")?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if !trimmed.starts_with(rrn_station::recovery::RESPONSE_PREFIX) {
                eprintln!(
                    "  (ignored — not an {} line)",
                    rrn_station::recovery::RESPONSE_PREFIX
                );
                continue;
            }
            let bytes = match rrn_station::recovery::decode_response_line(trimmed) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("  (ignored — {e})");
                    continue;
                }
            };
            match session.add_response(&bytes) {
                Ok(n) => eprintln!("  collected {n} response(s)"),
                Err(e) => eprintln!("  (ignored — {e})"),
            }
        }
    }

    // Try to rebuild. Below the threshold (or with wrong shares) this reports
    // NeedMoreResponses and writes nothing.
    let mut contents = match session.reconstruct(now()) {
        Ok(c) => c,
        Err(e) => bail!(
            "could not rebuild the key ({e}); gather responses from more holders and try again"
        ),
    };
    if contents.address != target {
        // Defensive: reconstruct already verifies this, but never write a wallet
        // whose address is not the one we set out to recover.
        bail!("reconstructed a different identity — aborting");
    }
    contents.metadata.insert(K_ROLE.into(), "member".into());
    contents.metadata.insert(K_SCHEMA.into(), SCHEMA.into());

    // Now persist: prompt for a NEW passphrase and write the wallet home.
    std::fs::create_dir_all(home).context("create wallet home")?;
    set_dir_private(home);
    let passphrase = read_passphrase(true)?;
    let address = contents.address.to_string();
    contents
        .save_to_file(&home.join(MEMBER_WALLET_FILE), &passphrase)
        .context("write member.rrnwallet")?;
    let db = Database::open(&home.join("wallet.db")).context("create wallet.db")?;
    migrations::run(&db).context("apply wallet migrations")?;
    write_initial_meta(&db, &address, &station_addr, "unknown")?;

    eprintln!("Recovered {address}. Run `rrn wallet sync` before signing.");
    crate::emit(
        fmt,
        &json!({ "address": address, "chain_state": "unknown" }),
        || Ok(address.clone()),
    )
}

// ---------------------------------------------------------------------------
// The opened wallet
// ---------------------------------------------------------------------------

struct Wallet {
    home: PathBuf,
    db: Database,
}

impl Wallet {
    fn open(home: PathBuf) -> Result<Self> {
        let db = Database::open(&home.join("wallet.db")).context("open wallet.db")?;
        migrations::run(&db).context("apply wallet migrations")?;
        Ok(Self { home, db })
    }

    fn wallet_path(&self) -> PathBuf {
        self.home.join(MEMBER_WALLET_FILE)
    }

    fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(WalletMeta::new(&self.db).get(key)?)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        WalletMeta::new(&self.db).set(key, value)?;
        Ok(())
    }

    fn meta_u64(&self, key: &str) -> Result<u64> {
        Ok(self
            .meta(key)?
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0))
    }

    /// The wallet's own address (plaintext meta — no unlock).
    fn address(&self) -> Result<Address> {
        let s = self
            .meta(K_ADDRESS)?
            .ok_or_else(|| anyhow!("wallet metadata missing its address"))?;
        s.parse()
            .map_err(|_| anyhow!("stored wallet address is not a valid rrn1… address"))
    }

    /// The wallet's own author key bytes (the outbox chain owner).
    fn author(&self) -> Result<[u8; 32]> {
        Ok(self.address()?.public_key().to_bytes())
    }

    /// The pinned station address (bech32).
    fn pin_address(&self) -> Result<Address> {
        let s = self
            .meta(K_STATION_ADDRESS)?
            .ok_or_else(|| anyhow!("wallet has no pinned station"))?;
        s.parse()
            .map_err(|_| anyhow!("stored station pin is not a valid rrn1… address"))
    }

    /// Unlocks the wallet key. Only signing verbs call this.
    fn unlock(&self) -> Result<Keypair> {
        let passphrase = read_passphrase(false)?;
        let contents = WalletContents::load_from_file(&self.wallet_path(), &passphrase)
            .map_err(|e| anyhow!("could not open the wallet: {e}"))?;
        // After unlock, confirm the sealed metadata agrees this is a member
        // wallet at the expected schema (ADR-0028 §3.1).
        if contents.metadata.get(K_ROLE).map(String::as_str) != Some("member") {
            bail!("this wallet file is not a member wallet");
        }
        if contents.metadata.get(K_SCHEMA).map(String::as_str) != Some(SCHEMA) {
            bail!("this wallet file has an unsupported schema version");
        }
        Ok(Keypair::from_secret(contents.secret_key.clone()))
    }

    /// The pinned-station channel client, if a URL has been set by `pair`.
    fn client(&self) -> Result<ChannelClient> {
        let url = self.meta(K_STATION_URL)?.ok_or_else(offline_error)?;
        Ok(ChannelClient::new(url, *self.pin_address()?.public_key()))
    }

    /// Persists the *next* transport nonce before it is used, so a crash never
    /// reuses one (ADR-0028 §3.1). Returns the nonce to send.
    fn next_transport_nonce(&self) -> Result<u64> {
        let next = self.meta_u64(K_TRANSPORT_NONCE)?.saturating_add(1);
        self.set_meta(K_TRANSPORT_NONCE, &next.to_string())?;
        Ok(next)
    }

    fn chain_state(&self) -> Result<String> {
        Ok(self
            .meta(K_CHAIN_STATE)?
            .unwrap_or_else(|| "unknown".into()))
    }

    /// Requires a signable chain (fresh or anchored); a restored `unknown` chain
    /// must `sync` first (ADR-0028 §7).
    fn require_signable(&self) -> Result<()> {
        match self.chain_state()?.as_str() {
            "fresh" | "anchored" => Ok(()),
            _ => bail!(
                "this wallet was restored and has not re-anchored yet; run \
                 `rrn wallet sync` on the station's LAN once before signing"
            ),
        }
    }

    // --- chained signing --------------------------------------------------

    /// Wraps a freshly-signed record into the next outbox entry and appends it.
    /// Signing the record and appending the entry are one unit: on append
    /// failure nothing is kept and the caller does not advance the cursor.
    fn append_record<T: Clone + Into<CBOR>>(
        &self,
        keypair: &Keypair,
        signed_record: &SignedPayload<T>,
        now: i64,
    ) -> Result<()> {
        // Both the chain owner and the entry's author come from the unlocked
        // keypair, never the plaintext meta `address` — a tampered meta row must
        // not be able to store rows under one key while they are signed by
        // another (finding: store/entry author must agree).
        let address = Address::from_public_key(keypair.public_key());
        let author = address.public_key().to_bytes();
        let mut store = OutboxStore::new(&self.db);
        let (position, prev_hash) = match store.head(&author)? {
            Some(h) => (h.position + 1, Hash::from_bytes(h.entry_hash)),
            None => (0, Hash::from_bytes([0u8; 32])),
        };
        let entry = OutboxEntry::wrapping(address, position, prev_hash, signed_record, now);
        let signed_entry = SignedPayload::sign(entry, keypair);
        let kind = signed_entry
            .payload
            .record_kind()
            .ok_or_else(|| anyhow!("signed record has no kind discriminator"))?;
        let envelope = to_canonical_bytes(EntryEnvelope::from_signed(&signed_entry));
        store
            .append(NewOutboxEntry {
                author,
                position,
                entry_hash: signed_entry.payload.entry_hash().to_bytes(),
                prev_hash: prev_hash.to_bytes(),
                record_hash: signed_entry.payload.record_hash().to_bytes(),
                record_kind: &kind,
                envelope: &envelope,
                authored_at: now,
            })
            .context("append to outbox")?;
        Ok(())
    }

    // --- commands ---------------------------------------------------------

    async fn cmd_pair(&self, fmt: Format, url: &str) -> Result<()> {
        let pin = self.pin_address()?;
        let keypair = self.unlock()?;
        let client = ChannelClient::new(url.to_string(), *pin.public_key());
        let response = client
            .pair(&keypair, now())
            .await
            .map_err(map_channel_error)?;
        // The pair succeeded and verified against the pin; record the URL and
        // that we are awaiting the operator's confirmation.
        self.set_meta(K_STATION_URL, url)?;
        self.set_meta(K_PAIRED, "pending")?;

        let sas = rrn_station::paired::confirmation_code(pin.public_key(), &keypair.public_key());
        let my_addr = Address::from_public_key(keypair.public_key()).to_string();
        let text = format!(
            "paired with {} (pending operator confirmation)\n\
             SAS: {sas}\n\
             have the operator run: station pair-mobile {my_addr}",
            response.station_address
        );
        crate::emit(
            fmt,
            &json!({ "station_address": response.station_address, "sas": sas, "member_address": my_addr, "paired": "pending" }),
            || Ok(text),
        )
    }

    async fn cmd_sync(&self, fmt: Format, no_receipts: bool) -> Result<()> {
        let keypair = self.unlock()?;
        let client = self.client()?;
        let author = self.author()?;
        let address = self.address()?;

        // 1. Re-anchor / learn the station's view of our outbox chain.
        let head = self
            .call(&client, &keypair, "outbox_head", &json!({}))
            .await?;
        let seen_position = head.get("position").and_then(|v| v.as_u64());
        let contiguous = head.get("contiguous_position").and_then(|v| v.as_u64());
        let entry_hash_hex = head.get("entry_hash").and_then(|v| v.as_str());

        let local_head = OutboxStore::new(&self.db).head(&author)?;
        let seen_hash: Option<[u8; 32]> = entry_hash_hex
            .and_then(rrn_station::core::unhex)
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        let was_unknown = self.chain_state()? == "unknown";
        let mut reanchored = false;
        // A message that means "do not sign": set when the station's view and the
        // local chain cannot be reconciled without a self-fork (ADR-0028 §7).
        let mut blocked: Option<String> = None;

        match (local_head.as_ref(), seen_position) {
            // No local chain, and the station has history for this key: anchor
            // onto its highest-seen position so the next record chains forward
            // (a restore, or a fresh key a paper submit already reached the
            // writer with).
            (None, Some(pos)) => {
                let bytes =
                    seen_hash.ok_or_else(|| anyhow!("station returned a position with no hash"))?;
                OutboxStore::new(&self.db).anchor(&author, pos, &bytes, now())?;
                reanchored = true;
                self.set_meta(K_CHAIN_STATE, "anchored")?;
            }
            // No local chain and the station has no record of this key.
            (None, None) => {
                if was_unknown {
                    // A *restored* wallet almost certainly transacted before, so a
                    // null answer does not mean the key is fresh — it means we
                    // reached a read replica (which never sees carried bundles) or
                    // the wrong station. Concluding "fresh" and signing position 0
                    // would fork against the writer, which re-anchoring exists to
                    // prevent (ADR-0028 §7). Stay unknown and refuse. (This departs
                    // from the ticket's "null → fresh" sketch: the ADR's
                    // no-self-fork guarantee wins against observed replica
                    // behavior.)
                    blocked = Some(
                        "the station has no record of this key. You may have synced against a \
                         read replica (which never sees carried bundles) or the wrong station — \
                         reach the writer once before signing. If this key truly never \
                         transacted, start over with `rrn wallet init` (without --restore)."
                            .into(),
                    );
                }
                // A non-restored fresh key with no history stays `fresh` (position
                // 0 is legitimately ours to write) — leave the state unchanged.
            }
            // A local chain and the station has seen this author.
            (Some(h), Some(pos)) => {
                if pos > h.position || (pos == h.position && seen_hash != Some(h.entry_hash)) {
                    // The station holds outbox positions this device does not (a
                    // rollback or a stale whole-home restore), or its head
                    // disagrees with ours at the same position: signing the next
                    // record would fork. Refuse and block signing until it is
                    // resolved.
                    blocked = Some(format!(
                        "your local outbox ends at position {}, but the station has seen up to \
                         {pos} — this device's chain is behind the station (a rollback or stale \
                         backup). Signing now would fork; do not sign. Restore the current \
                         wallet home, or reach the writer.",
                        h.position
                    ));
                    self.set_meta(K_CHAIN_STATE, "unknown")?;
                } else {
                    // The station is at or behind our head with matching hashes:
                    // we are level with it or ahead with pending, unsubmitted
                    // entries. Anchored to real history.
                    self.set_meta(K_CHAIN_STATE, "anchored")?;
                }
            }
            // A local chain the station has not seen at all.
            (Some(_), None) => {
                if was_unknown {
                    bail!(
                        "this store already has a chain but the station has no record of it; \
                         do not restore over an existing chain"
                    );
                }
                // Otherwise all our entries are pending, never submitted — nothing
                // to anchor onto; keep the current state.
            }
        }

        // 2. Nonce cursor: reconcile with the station's next nonce for us.
        let nn = self
            .call(
                &client,
                &keypair,
                "next_nonce",
                &json!({ "address": address.to_string() }),
            )
            .await?;
        let station_next = nn.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
        let cursor = self.meta_u64(K_NONCE_CURSOR)?;
        let has_pending_proposals = self.pending_proposal_count()? > 0;
        let new_cursor = if has_pending_proposals {
            station_next.max(cursor)
        } else {
            station_next
        };
        self.set_meta(K_NONCE_CURSOR, &new_cursor.to_string())?;

        // 3. Balance.
        let bal = self
            .call(
                &client,
                &keypair,
                "balance",
                &json!({ "address": address.to_string() }),
            )
            .await?;
        let balance_centi = bal
            .get("balance_centi")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        // 4. Receipts (fetch + apply) unless suppressed.
        let mut applied = 0usize;
        if !no_receipts {
            applied = self.fetch_and_apply_receipts(&client, &keypair).await?;
        }

        self.set_meta(K_PAIRED, "yes")?;
        self.set_meta(K_LAST_SYNC_AT, &now().to_string())?;

        // Hole-below-head warning (ADR-0028 §7).
        let hole = match (seen_position, contiguous) {
            (Some(seen), Some(cont)) if cont < seen => Some((cont + 1, seen)),
            (Some(seen), None) => Some((0, seen)),
            _ => None,
        };

        let mut text = format!(
            "synced with {}\n\
             chain: {}{}\n\
             nonce cursor: {new_cursor}\n\
             balance: {}\n\
             receipts applied: {applied}",
            self.pin_address()?,
            self.chain_state()?,
            if reanchored { " (re-anchored)" } else { "" },
            fmt_commons(balance_centi),
        );
        if let Some((from, to)) = hole {
            text.push_str(&format!(
                "\nWARNING: the station is missing part of your outbox chain below the head at \
                 position {to} (positions {from}..{to} are not all present — an in-flight record \
                 this device cannot reproduce); your chain will never be contiguous again — do \
                 not attempt to fill it. New records still admit."
            ));
        }
        if let Some(msg) = &blocked {
            text.push_str(&format!("\nWARNING: {msg}"));
        }
        crate::emit(
            fmt,
            &json!({
                "station_address": self.pin_address()?.to_string(),
                "chain_state": self.chain_state()?,
                "reanchored": reanchored,
                "nonce_cursor": new_cursor,
                "balance_centi": balance_centi,
                "receipts_applied": applied,
                "hole": hole.map(|(f, t)| json!({ "from": f, "to": t })),
                "blocked": blocked,
            }),
            || Ok(text),
        )
    }

    fn cmd_status(&self, fmt: Format) -> Result<()> {
        let address = self.meta(K_ADDRESS)?.unwrap_or_default();
        let pin = self.meta(K_STATION_ADDRESS)?.unwrap_or_default();
        let url = self
            .meta(K_STATION_URL)?
            .unwrap_or_else(|| "(unset)".into());
        let paired = self.meta(K_PAIRED)?.unwrap_or_else(|| "no".into());
        let chain_state = self.chain_state()?;
        let cursor = self.meta_u64(K_NONCE_CURSOR)?;
        let last_sync = self.meta(K_LAST_SYNC_AT)?.unwrap_or_else(|| "never".into());
        let author = self.author()?;
        let store = OutboxStore::new(&self.db);
        let head_pos = store.head(&author)?.map(|h| h.position);
        let pending = store.pending(&author, None)?.len();
        let certs = self.held_cert_ids()?.len();

        let text = format!(
            "address: {address}\n\
             pinned station: {pin}\n\
             url: {url}\n\
             paired: {paired}\n\
             chain: {chain_state}\n\
             head position: {}\n\
             pending: {pending}\n\
             nonce cursor: {cursor}\n\
             certificates held: {certs}\n\
             last sync: {last_sync}",
            head_pos
                .map(|p| p.to_string())
                .unwrap_or_else(|| "(none)".into()),
        );
        crate::emit(
            fmt,
            &json!({
                "address": address,
                "pinned_station": pin,
                "url": url,
                "paired": paired,
                "chain_state": chain_state,
                "head_position": head_pos,
                "pending": pending,
                "nonce_cursor": cursor,
                "certificates_held": certs,
                "last_sync_at": last_sync,
            }),
            || Ok(text),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn cmd_pay(
        &self,
        fmt: Format,
        receiver: &str,
        amount: &str,
        memo: Option<String>,
        cert: Option<&str>,
        expires_in: Option<i64>,
        carrier: Carrier,
        voucher_out: Option<&Path>,
    ) -> Result<()> {
        self.require_signable()?;
        let keypair = self.unlock()?;
        let sender = Address::from_public_key(keypair.public_key());
        let receiver_addr: Address = receiver
            .parse()
            .map_err(|_| anyhow!("invalid receiver address {receiver:?}"))?;
        let amount_centi = crate::parse_amount(amount)?;
        let now = now();
        let nonce = self.meta_u64(K_NONCE_CURSOR)?;

        // Resolve a certificate first, since it constrains the expiry and cap.
        let cert_state = match cert {
            Some(prefix) => Some(self.load_held_cert(prefix)?),
            None => None,
        };

        let expires_at = resolve_expiry(
            now,
            carrier,
            expires_in,
            cert_state.as_ref().map(|c| c.payload.expires_at),
        );

        let mut proposal = TransactionProposal::new(
            sender,
            receiver_addr,
            amount_centi,
            memo,
            nonce,
            now,
            expires_at,
        );

        if let Some(c) = &cert_state {
            // Local guards mirroring the engine, so an obviously-doomed spend
            // fails here rather than at admission.
            if now > c.payload.expires_at {
                bail!(
                    "certificate {} has expired",
                    short_hex(&c.payload.cert_id.0.to_bytes())
                );
            }
            if c.payload.member != sender {
                bail!("certificate is for another member, not this wallet");
            }
            let spent = self.cert_history_spent(&c.payload.cert_id)?;
            if amount_centi > c.payload.cap_centi.saturating_sub(spent) {
                bail!(
                    "spend {} exceeds the certificate's remaining allowance {}",
                    fmt_commons(amount_centi),
                    fmt_commons(c.payload.cap_centi.saturating_sub(spent))
                );
            }
            proposal = proposal.with_certificate(c.payload.cert_id);
        }

        let signed = SignedProposal::sign(proposal.clone(), &keypair);
        self.append_record(&keypair, &signed, now)?;
        // Only after a successful append does the cursor advance (ADR-0028 §3.4).
        self.set_meta(K_NONCE_CURSOR, &nonce.saturating_add(1).to_string())?;

        // Record the spend against the certificate's history, and optionally
        // emit an offline spend voucher for the receiver.
        if let Some(c) = &cert_state {
            let prop_env = signed_record_envelope(&signed);
            self.push_cert_history(&c.payload.cert_id, &prop_env)?;
            if let Some(path) = voucher_out {
                self.write_spend_voucher(path, &c.payload.cert_id, &prop_env)?;
            }
        }

        let tx_id = hex(&proposal.id.0.to_bytes());
        crate::emit(
            fmt,
            &json!({ "tx_id": tx_id, "state": "pending", "nonce": nonce }),
            || Ok(tx_id.clone()),
        )
    }

    fn cmd_confirm(&self, fmt: Format, tx_id: &str) -> Result<()> {
        self.require_signable()?;
        let keypair = self.unlock()?;
        let id = TransactionId(Hash::from_bytes(parse_hash(tx_id)?));
        let now = now();
        let confirmation = TransactionConfirmation {
            proposal_id: id,
            confirmer: Address::from_public_key(keypair.public_key()),
            confirmed_at: now,
        };
        let signed = SignedConfirmation::sign(confirmation, &keypair);
        self.append_record(&keypair, &signed, now)?;
        crate::emit(fmt, &json!({ "tx_id": tx_id, "state": "pending" }), || {
            Ok(format!("confirmed {tx_id} (pending)"))
        })
    }

    fn cmd_vote(&self, fmt: Format, proposal_id: &str, choice: VoteChoice) -> Result<()> {
        self.require_signable()?;
        let keypair = self.unlock()?;
        let now = now();
        let vote = Vote {
            proposal_id: ProposalId(Hash::from_bytes(parse_hash(proposal_id)?)),
            voter: Address::from_public_key(keypair.public_key()),
            choice,
            cast_at: now,
        };
        let signed = SignedPayload::sign(vote, &keypair);
        self.append_record(&keypair, &signed, now)?;
        crate::emit(
            fmt,
            &json!({ "proposal_id": proposal_id, "state": "pending" }),
            || Ok(format!("voted on {proposal_id} (pending)")),
        )
    }

    fn cmd_dispute(
        &self,
        fmt: Format,
        tx_id: &str,
        reason: &str,
        evidence_hash: Option<&str>,
    ) -> Result<()> {
        self.require_signable()?;
        let keypair = self.unlock()?;
        let now = now();
        let evidence = match evidence_hash {
            Some(h) => Some(Hash::from_bytes(parse_hash(h)?)),
            None => None,
        };
        let record = DisputeRecord {
            proposal_id: TransactionId(Hash::from_bytes(parse_hash(tx_id)?)),
            raiser: Address::from_public_key(keypair.public_key()),
            reason: reason.to_string(),
            evidence_hash: evidence,
            opened_at: now,
        };
        let signed = SignedPayload::sign(record, &keypair);
        self.append_record(&keypair, &signed, now)?;
        crate::emit(fmt, &json!({ "tx_id": tx_id, "state": "pending" }), || {
            Ok(format!("dispute raised on {tx_id} (pending)"))
        })
    }

    async fn cmd_vouch(
        &self,
        fmt: Format,
        address: &str,
        statement: &str,
        stake: &str,
    ) -> Result<()> {
        // Vouches are online-only and never chained into the outbox (ADR-0028):
        // a vouch is not nonce-tracked, and making it DTN-routable is a
        // reputation/sybil change out of scope here.
        let subject: Address = address
            .parse()
            .map_err(|_| anyhow!("invalid address {address:?}"))?;
        let stake_centi = u64::try_from(crate::parse_amount(stake)?)
            .map_err(|_| anyhow!("stake must be non-negative"))?;
        let keypair = self.unlock()?;
        let signed = create_vouch(&keypair, &subject, VOUCH_COMMUNITY, statement, stake_centi);
        let frame = channel_frame(&signed);
        // Submit directly; refuse cleanly when offline.
        let client = self
            .client()
            .context("vouching needs the station reachable — there is no offline vouch")?;
        let result = self
            .call(
                &client,
                &keypair,
                "submit_vouch",
                &json!({ "signed_vouch": hex(&frame) }),
            )
            .await?;
        let vouch_id = result
            .get("vouch_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        crate::emit(fmt, &json!({ "vouch_id": vouch_id }), || {
            Ok(vouch_id.clone())
        })
    }

    async fn cmd_cert(&self, fmt: Format, cmd: WalletCertCmd) -> Result<()> {
        match cmd {
            WalletCertCmd::Request { cap } => self.cert_request(fmt, &cap).await,
            WalletCertCmd::Import { input } => self.cert_import(fmt, &input),
            WalletCertCmd::List => self.cert_list(fmt),
            WalletCertCmd::Return { id } => self.cert_return(fmt, &id),
        }
    }

    async fn cert_request(&self, fmt: Format, cap: &str) -> Result<()> {
        // A certificate request consumes a nonce, so it is a signing verb: a
        // restored chain must re-anchor first (ADR-0028 §7).
        self.require_signable()?;
        let keypair = self.unlock()?;
        let cap_centi = crate::parse_amount(cap)?;
        let now = now();
        let nonce = self.meta_u64(K_NONCE_CURSOR)?;
        let request = CertificateRequest::new(
            Address::from_public_key(keypair.public_key()),
            cap_centi,
            nonce,
            now,
        );
        let signed: SignedCertificateRequest = SignedPayload::sign(request, &keypair);
        let frame = channel_frame(&signed);
        let client = self.client()?;
        let result = self
            .call(
                &client,
                &keypair,
                "cert_request",
                &json!({ "signed_request": hex(&frame) }),
            )
            .await?;
        // A cert request is a live round-trip, never an outbox record; only the
        // cursor advances.
        self.set_meta(K_NONCE_CURSOR, &nonce.saturating_add(1).to_string())?;

        let cert_hex = result
            .get("certificate_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("station reply had no certificate"))?;
        let cert = self.verify_and_store_cert(cert_hex)?;
        let id = hex(&cert.payload.cert_id.0.to_bytes());
        crate::emit(
            fmt,
            &json!({ "cert_id": id, "cap_centi": cert.payload.cap_centi }),
            || {
                Ok(format!(
                    "certificate {id} for {} issued",
                    fmt_commons(cert.payload.cap_centi)
                ))
            },
        )
    }

    fn cert_import(&self, fmt: Format, input: &Path) -> Result<()> {
        let text =
            std::fs::read_to_string(input).with_context(|| format!("read {}", input.display()))?;
        // Accept an `rrncert:` line, or raw envelope bytes as hex, on any line.
        let mut cert_hex = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if classify(line) == PaperPayloadKind::Certificate {
                let bytes = paper::decode_certificate(line)
                    .map_err(|e| anyhow!("bad rrncert: line: {e}"))?;
                cert_hex = Some(hex(&bytes));
                break;
            }
            if let Some(bytes) = rrn_station::core::unhex(line) {
                if escrow::decode_certificate_envelope(&bytes).is_some() {
                    cert_hex = Some(hex(&bytes));
                    break;
                }
            }
        }
        let cert_hex =
            cert_hex.ok_or_else(|| anyhow!("no certificate found in {}", input.display()))?;
        let cert = self.verify_and_store_cert(&cert_hex)?;
        let id = hex(&cert.payload.cert_id.0.to_bytes());
        crate::emit(fmt, &json!({ "cert_id": id }), || {
            Ok(format!("imported certificate {id}"))
        })
    }

    fn cert_list(&self, fmt: Format) -> Result<()> {
        let mut rows = Vec::new();
        let mut lines = Vec::new();
        for id in self.held_cert_ids()? {
            if let Some(cert) = self.load_cert_by_id(&id)? {
                let spent = self.cert_history_spent(&cert.payload.cert_id)?;
                let remaining = cert.payload.cap_centi.saturating_sub(spent);
                lines.push(format!(
                    "{}\tcap {}\tremaining {}\texpires {}",
                    id,
                    fmt_commons(cert.payload.cap_centi),
                    fmt_commons(remaining),
                    cert.payload.expires_at
                ));
                rows.push(json!({
                    "cert_id": id,
                    "cap_centi": cert.payload.cap_centi,
                    "remaining_centi": remaining,
                    "expires_at": cert.payload.expires_at,
                }));
            }
        }
        crate::emit(fmt, &json!({ "certificates": rows }), || {
            Ok(lines.join("\n"))
        })
    }

    fn cert_return(&self, fmt: Format, id: &str) -> Result<()> {
        self.require_signable()?;
        let keypair = self.unlock()?;
        let cert = self.load_held_cert(id)?;
        let now = now();
        let record = CertificateReturn {
            member: Address::from_public_key(keypair.public_key()),
            cert_id: cert.payload.cert_id,
            returned_at: now,
        };
        let signed = SignedPayload::sign(record, &keypair);
        self.append_record(&keypair, &signed, now)?;
        let id = hex(&cert.payload.cert_id.0.to_bytes());
        crate::emit(fmt, &json!({ "cert_id": id, "state": "pending" }), || {
            Ok(format!("certificate {id} return signed (pending)"))
        })
    }

    fn cmd_export(
        &self,
        fmt: Format,
        out: &Path,
        format: ExportFormat,
        max_entries: Option<usize>,
    ) -> Result<()> {
        let (bundle_bytes, count) = self.pending_bundle(max_entries)?;
        if count == 0 {
            bail!("nothing pending to export");
        }
        std::fs::create_dir_all(out).context("create export directory")?;
        match format {
            ExportFormat::Bundle => {
                let path = out.join("payload.bundle");
                std::fs::write(&path, &bundle_bytes).context("write payload.bundle")?;
                crate::emit(
                    fmt,
                    &json!({ "entries": count, "path": path.to_string_lossy() }),
                    || {
                        Ok(format!(
                            "exported {count} entr(y/ies) to {}",
                            path.display()
                        ))
                    },
                )
            }
            ExportFormat::Qr => {
                let lines = paper::encode_chunks(PaperKind::Bundle, &bundle_bytes)
                    .map_err(|e| anyhow!("chunk bundle: {e}"))?;
                crate::paper::write_lines_and_render(out, "bundle", &lines)?;
                crate::emit(
                    fmt,
                    &json!({ "entries": count, "chunks": lines.len(), "out": out.to_string_lossy() }),
                    || {
                        Ok(format!(
                            "exported {count} entr(y/ies) as {} QR chunk(s) to {}",
                            lines.len(),
                            out.display()
                        ))
                    },
                )
            }
        }
    }

    async fn cmd_submit(&self, fmt: Format, max_entries: Option<usize>) -> Result<()> {
        let keypair = self.unlock()?;
        let (bundle_bytes, count) = self.pending_bundle(max_entries)?;
        if count == 0 {
            bail!("nothing pending to submit");
        }
        let client = self.client()?;
        // Call the raw client here (not the anyhow-mapping helper) so the typed
        // READ_REPLICA method error can be recognized and re-couriered.
        let nonce = self.next_transport_nonce()?;
        let result = client
            .call(
                &keypair,
                "bundle_submit",
                &json!({ "bundle_hex": hex(&bundle_bytes) }),
                nonce,
                now(),
            )
            .await;
        let result = match result {
            Ok(v) => v,
            Err(ChannelClientError::Method { code, .. })
                if code == rrn_station::rpc::READ_REPLICA =>
            {
                bail!(
                    "the paired station is a read replica and cannot admit records; \
                     export and courier to the writer, or pair with the writer"
                );
            }
            Err(e) => return Err(map_channel_error(e)),
        };
        let receipt_hex = result
            .get("receipt_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("station reply had no receipt"))?;
        let applied = self.apply_receipt_bytes(
            &rrn_station::core::unhex(receipt_hex)
                .ok_or_else(|| anyhow!("station returned a non-hex receipt"))?,
        )?;
        crate::emit(
            fmt,
            &json!({ "submitted": count, "applied": applied }),
            || {
                Ok(format!(
                    "submitted {count} entr(y/ies); {applied} receipt outcome(s) applied"
                ))
            },
        )
    }

    fn cmd_receipts_apply(&self, fmt: Format, files: &[PathBuf]) -> Result<()> {
        let mut applied = 0usize;
        for bytes in self.read_receipt_payloads(files)? {
            applied += self.apply_receipt_bytes(&bytes)?;
        }
        crate::emit(fmt, &json!({ "applied": applied }), || {
            Ok(format!("{applied} receipt outcome(s) applied"))
        })
    }

    fn cmd_show(&self, fmt: Format, _color: ColorMode, pending: bool, all: bool) -> Result<()> {
        let author = self.author()?;
        let store = OutboxStore::new(&self.db);
        // `--pending` narrows to unacked rows; `--all` (or no flag) shows every
        // row, so `--all` still forces the full view alongside `--pending`.
        let rows: Vec<OutboxRow> = if pending && !all {
            store.pending(&author, None)?
        } else {
            store.all_rows(&author)?
        };
        let mut lines = Vec::new();
        let mut json_rows = Vec::new();
        for r in &rows {
            let disposition = match (&r.acked_outcome, &r.refusal_reason) {
                (None, _) => "pending".to_string(),
                (Some(AckOutcome::Admitted), _) => "admitted".to_string(),
                (Some(AckOutcome::Known), _) => "known".to_string(),
                (Some(AckOutcome::Refused), Some(why)) => format!("refused ({why})"),
                (Some(AckOutcome::Refused), None) => "refused".to_string(),
            };
            lines.push(format!(
                "{}\t{}\t{}",
                r.position, r.record_kind, disposition
            ));
            json_rows.push(json!({
                "position": r.position,
                "record_kind": r.record_kind,
                "disposition": disposition,
                "record_hash": hex(&r.record_hash),
            }));
        }
        crate::emit(fmt, &json!({ "rows": json_rows }), || Ok(lines.join("\n")))
    }

    async fn cmd_transactions(&self, fmt: Format, color: ColorMode) -> Result<()> {
        let keypair = self.unlock()?;
        let client = self.client()?;
        let address = self.address()?;
        let v = self
            .call(
                &client,
                &keypair,
                "transactions",
                &json!({ "address": address.to_string() }),
            )
            .await?;
        crate::emit(fmt, &v, || {
            let rows: Vec<rrn_station::rpc::TransactionRow> =
                serde_json::from_value(v["transactions"].clone()).context("decode transactions")?;
            Ok(crate::render_transactions(&rows, color))
        })
    }

    // --- channel + receipt helpers ---------------------------------------

    /// One authenticated channel call, persisting the transport nonce first.
    async fn call(
        &self,
        client: &ChannelClient,
        keypair: &Keypair,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let nonce = self.next_transport_nonce()?;
        client
            .call(keypair, method, params, nonce, now())
            .await
            .map_err(map_channel_error)
    }

    async fn fetch_and_apply_receipts(
        &self,
        client: &ChannelClient,
        keypair: &Keypair,
    ) -> Result<usize> {
        let v = self
            .call(client, keypair, "receipts_fetch", &json!({}))
            .await?;
        let mut applied = 0usize;
        if let Some(arr) = v.get("receipts_hex").and_then(|r| r.as_array()) {
            for item in arr {
                if let Some(h) = item.as_str() {
                    if let Some(bytes) = rrn_station::core::unhex(h) {
                        applied += self.apply_receipt_bytes(&bytes)?;
                    }
                }
            }
        }
        Ok(applied)
    }

    /// Verifies a station receipt against the pin and applies each outcome to the
    /// outbox. Mirrors the mobile FFI's `receipt_parse` pin check exactly.
    fn apply_receipt_bytes(&self, bytes: &[u8]) -> Result<usize> {
        let pin = self.pin_address()?;
        let signed =
            receipt::decode_signed(bytes).map_err(|_| anyhow!("malformed delivery receipt"))?;
        if &signed.signer != pin.public_key()
            || signed.payload.station.public_key() != &signed.signer
            || signed.verify().is_err()
        {
            bail!("receipt is not signed by the pinned station");
        }
        let author = self.author()?;
        let mut store = OutboxStore::new(&self.db);
        // Which rows are still pending *before* this receipt, so a re-applied
        // (idempotent) receipt reports zero newly-applied outcomes.
        let pending_before: std::collections::HashSet<[u8; 32]> = store
            .all_rows(&author)?
            .into_iter()
            .filter(|r| r.acked_outcome.is_none())
            .map(|r| r.record_hash)
            .collect();
        let mut applied = 0usize;
        let mut nonce_gap = false;
        for outcome in &signed.payload.outcomes {
            let (ack, seq, reason) = match &outcome.disposition {
                Disposition::Admitted { seq } => (AckOutcome::Admitted, Some(*seq), None),
                Disposition::Known { seq } => (AckOutcome::Known, Some(*seq), None),
                Disposition::Refused { reason } => (
                    AckOutcome::Refused,
                    None,
                    Some(reason.as_slug().to_string()),
                ),
            };
            if matches!(reason.as_deref(), Some(slug) if slug.contains("nonce")) {
                nonce_gap = true;
            }
            let record_hash = outcome.record_hash.to_bytes();
            // A `receipts_fetch` marks its whole page delivered on the station
            // *before* replying (ADR-0020 §3), so one bad outcome must not abort
            // the rest. A `ConflictingAck` here is a row already terminally acked
            // with a different-but-final outcome (e.g. an inline `known` from a
            // re-submit, then a queued `admitted` for the same record) — the row
            // is settled either way, so skip it rather than losing the page.
            match store.apply_ack(&author, &record_hash, ack, seq, reason.as_deref()) {
                Ok(matched) => {
                    if matched && pending_before.contains(&record_hash) {
                        applied += 1;
                    }
                }
                Err(rrn_storage::Error::ConflictingAck) => {
                    eprintln!(
                        "warning: receipt outcome for {} conflicts with an already-recorded \
                         final outcome; skipping it",
                        short_hex(&record_hash)
                    );
                }
                Err(e) => return Err(e.into()),
            }
        }
        // Reclaim the acked prefix, keeping the chain contiguous.
        store.prune_acked(&author)?;
        if nonce_gap {
            eprintln!(
                "warning: a proposal was refused for a nonce gap. Any proposals you signed \
                 after it will be refused too — run `rrn wallet sync` and re-pay them."
            );
        }
        Ok(applied)
    }

    /// Reassembles receipt payloads from scanned QR text or raw hex/bytes.
    fn read_receipt_payloads(&self, files: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut reass = PaperReassembler::new();
        for file in files {
            let text = std::fs::read_to_string(file)
                .with_context(|| format!("read {}", file.display()))?;
            for raw in text.lines() {
                let line = raw.trim();
                if line.is_empty() {
                    continue;
                }
                match classify(line) {
                    PaperPayloadKind::Multipart => {
                        if let Ok(Some((kind, bytes))) = reass.accept(line) {
                            if kind == PaperKind::Receipt {
                                out.push(bytes);
                            }
                        }
                    }
                    _ => {
                        // A bare hex line of raw `encode_signed` receipt bytes.
                        if let Some(bytes) = rrn_station::core::unhex(line) {
                            if receipt::decode_signed(&bytes).is_ok() {
                                out.push(bytes);
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    // --- outbox / bundle helpers -----------------------------------------

    fn pending_proposal_count(&self) -> Result<usize> {
        let author = self.author()?;
        let store = OutboxStore::new(&self.db);
        Ok(store
            .pending(&author, None)?
            .into_iter()
            .filter(|r| r.record_kind == "rrn.tx.proposal")
            .count())
    }

    /// Builds a bundle from the pending outbox entries, capped at
    /// `max_entries` (and always the wire caps). Round-trips through
    /// `Bundle::decode` so an over-size export never diverges from an online
    /// submit. Returns the encoded bytes and the entry count.
    fn pending_bundle(&self, max_entries: Option<usize>) -> Result<(Vec<u8>, usize)> {
        let author = self.author()?;
        let cap = max_entries
            .unwrap_or(MAX_BUNDLE_ENTRIES)
            .min(MAX_BUNDLE_ENTRIES);
        let store = OutboxStore::new(&self.db);
        let rows = store.pending(&author, Some(cap))?;
        let mut entries = Vec::with_capacity(rows.len());
        for r in &rows {
            let env: EntryEnvelope = rrn_crypto::serialize::from_canonical_bytes(&r.envelope)
                .map_err(|_| anyhow!("corrupt outbox envelope at position {}", r.position))?;
            entries.push(env);
        }
        let count = entries.len();
        let encoded = Bundle::new(entries, now()).encode();
        // Prove the station will structurally accept it (same bound both paths).
        Bundle::decode(&encoded).map_err(|e| anyhow!("bundle would be rejected: {e}"))?;
        Ok((encoded, count))
    }

    // --- certificate storage helpers -------------------------------------

    fn cert_meta_key(id: &CertId) -> String {
        format!("cert:{}", hex(&id.0.to_bytes()))
    }

    fn cert_history_key(id: &CertId) -> String {
        format!("cert_history:{}", hex(&id.0.to_bytes()))
    }

    fn held_cert_ids(&self) -> Result<Vec<String>> {
        Ok(WalletMeta::new(&self.db)
            .all()?
            .into_iter()
            .filter_map(|(k, _)| k.strip_prefix("cert:").map(str::to_string))
            .collect())
    }

    fn verify_and_store_cert(&self, cert_hex: &str) -> Result<escrow::SignedHeadroomCertificate> {
        let bytes =
            rrn_station::core::unhex(cert_hex).ok_or_else(|| anyhow!("certificate is not hex"))?;
        let cert = escrow::decode_certificate_envelope(&bytes)
            .ok_or_else(|| anyhow!("certificate envelope is malformed"))?;
        let pin = self.pin_address()?;
        if &cert.signer != pin.public_key() || cert.verify().is_err() {
            bail!("certificate is not signed by the pinned station");
        }
        self.set_meta(&Self::cert_meta_key(&cert.payload.cert_id), &hex(&bytes))?;
        Ok(cert)
    }

    fn load_cert_by_id(&self, id_hex: &str) -> Result<Option<escrow::SignedHeadroomCertificate>> {
        match self.meta(&format!("cert:{id_hex}"))? {
            Some(h) => {
                let bytes = rrn_station::core::unhex(&h)
                    .ok_or_else(|| anyhow!("stored certificate is not hex"))?;
                Ok(escrow::decode_certificate_envelope(&bytes))
            }
            None => Ok(None),
        }
    }

    /// Resolves a certificate id hex or unique prefix to the held certificate.
    fn load_held_cert(&self, prefix: &str) -> Result<escrow::SignedHeadroomCertificate> {
        let matches: Vec<String> = self
            .held_cert_ids()?
            .into_iter()
            .filter(|id| id.starts_with(&prefix.to_lowercase()))
            .collect();
        match matches.as_slice() {
            [] => bail!("no held certificate matches {prefix:?}"),
            [id] => self
                .load_cert_by_id(id)?
                .ok_or_else(|| anyhow!("certificate {id} is stored but unreadable")),
            _ => bail!("{prefix:?} matches more than one held certificate; use the full id"),
        }
    }

    fn cert_history_spent(&self, id: &CertId) -> Result<i64> {
        let mut total = 0i64;
        for env_hex in self.cert_history(id)? {
            if let Some(bytes) = rrn_station::core::unhex(&env_hex) {
                if let Some((_, _, body)) = decode_envelope(&bytes) {
                    if let Ok(p) =
                        rrn_crypto::serialize::from_canonical_bytes::<TransactionProposal>(&body)
                    {
                        total = total.saturating_add(p.amount_centi);
                    }
                }
            }
        }
        Ok(total)
    }

    fn cert_history(&self, id: &CertId) -> Result<Vec<String>> {
        match self.meta(&Self::cert_history_key(id))? {
            Some(s) => Ok(serde_json::from_str(&s).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    fn push_cert_history(&self, id: &CertId, proposal_envelope: &[u8]) -> Result<()> {
        let mut history = self.cert_history(id)?;
        history.push(hex(proposal_envelope));
        self.set_meta(
            &Self::cert_history_key(id),
            &serde_json::to_string(&history).context("encode cert history")?,
        )
    }

    /// Writes `rrnspend:` voucher lines for a cert-backed spend so a receiver can
    /// verify it offline with `rrn paper show`.
    fn write_spend_voucher(
        &self,
        path: &Path,
        id: &CertId,
        proposal_envelope: &[u8],
    ) -> Result<()> {
        let cert = self
            .load_cert_by_id(&hex(&id.0.to_bytes()))?
            .ok_or_else(|| anyhow!("certificate not held"))?;
        let cert_env = escrow::encode_certificate_envelope(&cert);
        // History = prior spends against this cert (excludes the one just made,
        // which is `proposal`).
        let history: Vec<Vec<u8>> = self
            .cert_history(id)?
            .into_iter()
            .filter_map(|h| rrn_station::core::unhex(&h))
            .collect();
        let voucher = SpendVoucher {
            proposal: proposal_envelope.to_vec(),
            cert: cert_env,
            history,
        };
        let lines = paper::encode_chunks(PaperKind::SpendVoucher, &voucher.encode())
            .map_err(|e| anyhow!("chunk voucher: {e}"))?;
        std::fs::write(path, lines.join("\n") + "\n")
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// The current Unix time in seconds — read only at the CLI edge.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reads the wallet passphrase: `RRN_WALLET_PASSPHRASE` (never `RRN_PASSPHRASE`)
/// else a hidden prompt. Never taken on argv, never logged.
fn read_passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("RRN_WALLET_PASSPHRASE") {
        return Ok(p);
    }
    let p = rpassword::prompt_password("wallet passphrase: ").context("read passphrase")?;
    if confirm {
        let again =
            rpassword::prompt_password("confirm passphrase: ").context("read passphrase")?;
        if again != p {
            bail!("passphrases did not match");
        }
    }
    Ok(p)
}

/// The one-line refusal for a verb that needs the channel but has no URL.
fn offline_error() -> anyhow::Error {
    anyhow!(
        "the station is not reachable (no paired URL); sign offline and carry with \
         `rrn wallet export`, or run `rrn wallet pair --url host:port` first"
    )
}

/// Maps a channel-client error to an anyhow error, with a friendlier line for
/// the pairing-not-confirmed case.
fn map_channel_error(e: ChannelClientError) -> anyhow::Error {
    match e {
        ChannelClientError::NotPaired => anyhow!(
            "the station has not confirmed this device is paired yet — ask the operator to \
             run `station pair-mobile <your rrn1…>`, then retry"
        ),
        other => anyhow!(other.to_string()),
    }
}

/// Frames a signed record for a channel `submit_*` / `cert_request` param, the
/// way the mobile FFI does: `len ‖ canonical-payload ‖ signer ‖ sig`. This is
/// distinct from [`signed_record_envelope`], the `{signer,sig,body}` CBOR map
/// used for outbox entries and spend vouchers.
fn channel_frame<T: Clone + Into<CBOR>>(signed: &SignedPayload<T>) -> Vec<u8> {
    rrn_station::rpc_envelope::frame_signed_record(
        &to_canonical_bytes(signed.payload.clone()),
        &signed.signer,
        &signed.signature,
    )
}

/// Encodes a signed record as the repo's portable `{signer, sig, body}` envelope.
fn signed_record_envelope<T: Clone + Into<CBOR>>(signed: &SignedPayload<T>) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("signer", CBOR::to_byte_string(signed.signer.to_bytes()));
    m.insert("sig", CBOR::to_byte_string(signed.signature.to_bytes()));
    m.insert(
        "body",
        CBOR::to_byte_string(to_canonical_bytes(signed.payload.clone())),
    );
    CBOR::from(m).to_cbor_data()
}

/// Decodes the repo's `{signer, sig, body}` envelope (signer, sig, body bytes).
fn decode_envelope(
    bytes: &[u8],
) -> Option<(
    rrn_crypto::keypair::PublicKey,
    rrn_crypto::keypair::Signature,
    Vec<u8>,
)> {
    use rrn_crypto::serialize::checked_from_data;
    let cbor = checked_from_data(bytes).ok()?;
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return None,
    };
    let signer: [u8; 32] = map
        .extract::<&str, CBOR>("signer")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let sig: [u8; 64] = map
        .extract::<&str, CBOR>("sig")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let body = map
        .extract::<&str, CBOR>("body")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .to_vec();
    Some((
        rrn_crypto::keypair::PublicKey::from_bytes(signer).ok()?,
        rrn_crypto::keypair::Signature::from_bytes(sig).ok()?,
        body,
    ))
}

/// Parses a 32-byte hex hash (transaction/proposal/cert/evidence id).
fn parse_hash(s: &str) -> Result<[u8; 32]> {
    rrn_station::core::unhex(s.trim())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| anyhow!("{s:?} is not a 32-byte hex hash"))
}

/// Hex of bytes (shared with the daemon's encoder so the two cannot drift).
fn hex(bytes: &[u8]) -> String {
    rrn_station::core::hex(bytes)
}

/// A short hex prefix for messages.
fn short_hex(bytes: &[u8]) -> String {
    let full = rrn_station::core::hex(bytes);
    full.chars().take(12).collect()
}

/// Sets `0o700` on the wallet home (best effort; unsupported off-unix).
fn set_dir_private(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The `expires_at` a signed proposal should carry: the carrier's default TTL,
/// overridden by an explicit `--expires-in`, and then — for a cert-backed spend —
/// floored at the certificate's own expiry so the spend never expires before the
/// certificate it draws against (ADR-0028; the engine does not enforce this).
/// The cert floor is applied *last* so an override cannot undercut it.
fn resolve_expiry(
    now: i64,
    carrier: Carrier,
    expires_in: Option<i64>,
    cert_expires_at: Option<i64>,
) -> i64 {
    let mut expires_at = match carrier {
        Carrier::Fast => now.saturating_add(PROPOSAL_TTL_SECS),
        Carrier::Slow => now.saturating_add(rrn_ledger::credit::DEFAULT_CERT_DELIVERY_GRACE_SECS),
    };
    if let Some(secs) = expires_in {
        expires_at = now.saturating_add(secs);
    }
    if let Some(cert) = cert_expires_at {
        expires_at = expires_at.max(cert);
    }
    expires_at
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_carrier_defaults() {
        let now = 1_000_000;
        assert_eq!(
            resolve_expiry(now, Carrier::Fast, None, None),
            now + PROPOSAL_TTL_SECS
        );
        assert_eq!(
            resolve_expiry(now, Carrier::Slow, None, None),
            now + rrn_ledger::credit::DEFAULT_CERT_DELIVERY_GRACE_SECS
        );
    }

    #[test]
    fn explicit_override_replaces_the_carrier_default() {
        let now = 1_000_000;
        assert_eq!(resolve_expiry(now, Carrier::Fast, Some(60), None), now + 60);
        // …but the cert floor still wins over a too-short override, so a
        // cert-backed spend never expires before its certificate.
        let cert_exp = now + 500_000;
        assert_eq!(
            resolve_expiry(now, Carrier::Fast, Some(60), Some(cert_exp)),
            cert_exp,
            "the cert floor must not be undercut by --expires-in"
        );
    }

    #[test]
    fn cert_floor_only_raises_never_lowers() {
        let now = 1_000_000;
        // A generous carrier default already past the cert expiry stays as-is.
        let cert_exp = now + 10;
        assert_eq!(
            resolve_expiry(now, Carrier::Slow, None, Some(cert_exp)),
            now + rrn_ledger::credit::DEFAULT_CERT_DELIVERY_GRACE_SECS
        );
    }

    #[test]
    fn guard_rejects_a_station_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        // A directory carrying any station-layout file is refused.
        std::fs::write(dir.path().join(DB_FILE), b"x").unwrap();
        let err = guard_home(dir.path()).unwrap_err().to_string();
        assert!(err.contains("station data directory"), "{err}");
    }

    #[test]
    fn guard_rejects_an_uninitialized_home() {
        let dir = tempfile::tempdir().unwrap();
        let err = guard_home(dir.path()).unwrap_err().to_string();
        assert!(err.contains("no member wallet"), "{err}");
    }
}
