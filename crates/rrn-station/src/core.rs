//! The station core: the one place that touches the database.
//!
//! [`rrn_storage::db::Database`] is `!Sync` — a single-writer model — so rather
//! than wrap it in locks we give it a single owner thread and funnel every
//! operation to it as a [`Command`]. The Unix-socket server, the gossip tasks,
//! and the settlement timer are all *clients* of the core: they build a command,
//! hand it a [`oneshot`] reply channel, and `await` the answer. This both
//! satisfies the storage contract and serializes all log appends through one
//! place, which is exactly what an append-only log wants.
//!
//! The core runs on a dedicated OS thread (the DB calls are blocking SQLite),
//! receiving commands over a [`std::sync::mpsc`] channel and replying over Tokio
//! oneshots — which can be fulfilled from any thread.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc;

use tokio::sync::oneshot;

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_identity::recovery::flow::{reconstruct_wallet, RecoveryPackage};
use rrn_identity::recovery::shamir::{RawShard, ShardIndex};
use rrn_identity::vouch::{append_vouch, create_vouch};
use rrn_identity::wallet::WalletContents;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{SettlementConfig, Settler};
use rrn_ledger::state::TransactionState;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, StoredPayload};

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};

use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};

use crate::clock::Clock;
use crate::gossip::WireEntry;
use crate::ledger_view;
use crate::paired::{self, PairedMobiles};
use crate::pairing::{self, PairError, PairRequest, PairResponse, PendingPair};
use crate::rpc_envelope::{self, ChannelError, RequestEnvelope, ResponseEnvelope};
use crate::{history, rpc};

/// Methods a paired mobile may invoke over the authenticated channel (T1.3.4).
/// The operator-only methods (`pair_confirm`, `unpair`, `list_mobiles`,
/// `pair_list_pending`) and the local-only recovery methods are deliberately
/// absent — a mobile reaches only its own read surface. The write methods
/// (`propose`, `confirm`) join this list with the mobile-signed submit path.
const MOBILE_METHODS: &[&str] = &["whoami", "balance", "history"];

/// Community identifier stamped on Phase 0 vouches (a placeholder until real
/// community ids arrive in Phase 1).
const VOUCH_COMMUNITY: &str = "rrn-phase0";

/// How long a proposal stays valid before it auto-expires, in seconds.
const PROPOSAL_TTL_SECS: i64 = 24 * 3600;

/// Bytes of secret data in a raw Shamir shard (the ed25519 seed length). The
/// shamir crate keeps its `SECRET_LEN` private; this mirrors it for the
/// file-format check in [`read_raw_shard`].
const SHARD_DATA_LEN: usize = 32;

/// A unit of work for the core thread. Each carries its own typed reply channel.
pub enum Command {
    /// A public RPC call (the methods the `rrn` CLI invokes).
    Call {
        /// The decoded request envelope.
        request: rpc::Request,
        /// Where to send the `result`-or-`error` payload.
        reply: oneshot::Sender<Result<serde_json::Value, rpc::RpcError>>,
    },
    /// Run a settlement sweep at the core's current clock time; reply with the
    /// number of transactions settled.
    Sweep {
        /// Count of settled transactions.
        reply: oneshot::Sender<usize>,
    },
    /// Report this station's own address and current log tail seq (for the peer
    /// handshake).
    Handshake {
        /// `(our_address, log_tail_seq)`.
        reply: oneshot::Sender<(String, u64)>,
    },
    /// The current log tail sequence number.
    LogTail {
        /// Tail seq (0 if empty).
        reply: oneshot::Sender<u64>,
    },
    /// The log entries with `from_seq <= seq <= to_seq`, as wire entries.
    LogRange {
        /// Inclusive lower bound.
        from_seq: u64,
        /// Inclusive upper bound.
        to_seq: u64,
        /// The matching entries.
        reply: oneshot::Sender<Vec<WireEntry>>,
    },
    /// Append replicated entries from a peer; reply with how many were new.
    AppendEntries {
        /// Entries received from a peer, in the peer's log order.
        entries: Vec<WireEntry>,
        /// How many were newly appended (not already held).
        reply: oneshot::Sender<usize>,
    },
    /// A mobile's pairing request (T1.3.3), from the mobile HTTP surface. The
    /// core verifies it, records it as pending for the operator to confirm, and
    /// replies with the station's signed response.
    PairRequest {
        /// The request as it arrived on the wire.
        request: PairRequest,
        /// The station's signed response, or why it was rejected.
        reply: oneshot::Sender<Result<PairResponse, PairError>>,
    },
    /// A paired mobile's authenticated request (T1.3.4), from the mobile HTTP
    /// surface. The bytes are the sealed envelope; the reply is the sealed
    /// response bytes, or the rejection reason for the edge to turn into a status.
    RpcRequest {
        /// The sealed request envelope as it arrived on the wire.
        sealed: Vec<u8>,
        /// The sealed response bytes, or why the request was rejected.
        reply: oneshot::Sender<Result<Vec<u8>, ChannelError>>,
    },
    /// Stop the core loop (graceful shutdown).
    Shutdown,
}

/// A cloneable handle the async tasks use to talk to the core.
#[derive(Clone)]
pub struct CoreHandle {
    tx: mpsc::Sender<Command>,
}

impl CoreHandle {
    /// Sends a public RPC request and awaits the result/error payload.
    pub async fn call(&self, request: rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::Call { request, reply }).is_err() {
            return Err(rpc::RpcError {
                code: rpc::INTERNAL_ERROR,
                message: "core stopped".into(),
            });
        }
        rx.await.unwrap_or_else(|_| {
            Err(rpc::RpcError {
                code: rpc::INTERNAL_ERROR,
                message: "core dropped reply".into(),
            })
        })
    }

    /// Triggers a settlement sweep; returns the number settled.
    pub async fn sweep(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::Sweep { reply }).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Returns `(our_address, log_tail_seq)`.
    pub async fn handshake(&self) -> Option<(String, u64)> {
        let (reply, rx) = oneshot::channel();
        self.tx.send(Command::Handshake { reply }).ok()?;
        rx.await.ok()
    }

    /// The current log tail seq.
    pub async fn log_tail(&self) -> u64 {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::LogTail { reply }).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Fetches the wire entries in `[from_seq, to_seq]`.
    pub async fn log_range(&self, from_seq: u64, to_seq: u64) -> Vec<WireEntry> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(Command::LogRange {
                from_seq,
                to_seq,
                reply,
            })
            .is_err()
        {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Appends replicated entries; returns the count newly appended.
    pub async fn append_entries(&self, entries: Vec<WireEntry>) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(Command::AppendEntries { entries, reply })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Submits a mobile's pairing request; returns the station's signed response
    /// or the rejection reason. [`PairError::Unavailable`] means the core is gone.
    pub async fn pair_request(&self, request: PairRequest) -> Result<PairResponse, PairError> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(Command::PairRequest { request, reply })
            .is_err()
        {
            return Err(PairError::Unavailable);
        }
        rx.await.unwrap_or(Err(PairError::Unavailable))
    }

    /// Submits a paired mobile's sealed request (T1.3.4); returns the sealed
    /// response bytes, or the rejection reason. [`ChannelError::Unavailable`]
    /// means the core is gone.
    pub async fn rpc_request(&self, sealed: Vec<u8>) -> Result<Vec<u8>, ChannelError> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::RpcRequest { sealed, reply }).is_err() {
            return Err(ChannelError::Unavailable);
        }
        rx.await.unwrap_or(Err(ChannelError::Unavailable))
    }

    /// Asks the core to shut down.
    pub fn shutdown(&self) {
        let _ = self.tx.send(Command::Shutdown);
    }
}

/// The owned state of the station: the database, the wallet, and the knobs the
/// core needs. Lives on its own thread.
pub struct Core {
    db: Database,
    wallet: WalletContents,
    settlement: SettlementConfig,
    clock: Clock,
    /// Mobiles that have completed pairing — the authorization list for the
    /// mobile HTTP surface (T1.3.3). Persisted across restarts.
    paired: PairedMobiles,
    /// Pairing requests accepted but not yet confirmed by the operator, keyed by
    /// mobile address. In-memory only: an unconfirmed request has no standing to
    /// survive a restart, and each entry expires after [`pairing::PENDING_TTL_SECS`].
    pending: BTreeMap<String, PendingPair>,
}

impl Core {
    /// Builds a core over an opened `db`, decrypted `wallet`, and the persisted
    /// paired-mobile list.
    pub fn new(
        db: Database,
        wallet: WalletContents,
        settlement: SettlementConfig,
        clock: Clock,
        paired: PairedMobiles,
    ) -> Self {
        Core {
            db,
            wallet,
            settlement,
            clock,
            paired,
            pending: BTreeMap::new(),
        }
    }

    /// Spawns the core on a dedicated thread and returns a handle to it.
    pub fn spawn(self) -> CoreHandle {
        let (tx, rx) = mpsc::channel::<Command>();
        std::thread::Builder::new()
            .name("rrn-core".into())
            .spawn(move || self.run(rx))
            .expect("spawn core thread");
        CoreHandle { tx }
    }

    /// The blocking command loop. Returns when a [`Command::Shutdown`] arrives or
    /// all handles are dropped.
    fn run(mut self, rx: mpsc::Receiver<Command>) {
        while let Ok(cmd) = rx.recv() {
            match cmd {
                Command::Call { request, reply } => {
                    let _ = reply.send(self.handle_call(&request));
                }
                Command::Sweep { reply } => {
                    let n = self.do_sweep();
                    let _ = reply.send(n);
                }
                Command::Handshake { reply } => {
                    let tail = self.tail_seq();
                    let _ = reply.send((self.wallet.address.to_string(), tail));
                }
                Command::LogTail { reply } => {
                    let _ = reply.send(self.tail_seq());
                }
                Command::LogRange {
                    from_seq,
                    to_seq,
                    reply,
                } => {
                    let _ = reply.send(self.do_log_range(from_seq, to_seq));
                }
                Command::AppendEntries { entries, reply } => {
                    let _ = reply.send(self.do_append_entries(entries));
                }
                Command::PairRequest { request, reply } => {
                    let _ = reply.send(self.do_pair_request(request));
                }
                Command::RpcRequest { sealed, reply } => {
                    let _ = reply.send(self.do_rpc_request(sealed));
                }
                Command::Shutdown => {
                    tracing::info!("core shutting down");
                    break;
                }
            }
        }
    }

    // --- public RPC dispatch ------------------------------------------------

    fn handle_call(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        match req.method.as_str() {
            "whoami" => self.m_whoami(),
            "balance" => self.m_balance(req),
            "propose" => self.m_propose(req),
            "confirm" => self.m_confirm(req),
            "history" => self.m_history(req),
            "vouch" => self.m_vouch(req),
            "backup_export" => self.m_backup_export(req),
            "recover_import" => self.m_recover_import(req),
            // Operator-facing pairing management (T1.3.3), invoked by the
            // `station` binary over this same Unix socket.
            "pair_list_pending" => self.m_pair_list_pending(),
            "pair_confirm" => self.m_pair_confirm(req),
            "list_mobiles" => self.m_list_mobiles(),
            "unpair" => self.m_unpair(req),
            other => Err(rpc::RpcError {
                code: rpc::METHOD_NOT_FOUND,
                message: format!("unknown method: {other}"),
            }),
        }
    }

    fn m_whoami(&self) -> Result<serde_json::Value, rpc::RpcError> {
        ok(&rpc::WhoamiResult {
            address: self.wallet.address.to_string(),
        })
    }

    fn m_balance(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::BalanceParams = parse_params(req)?;
        let who = match params.address {
            Some(s) => parse_addr(&s)?,
            None => self.wallet.address,
        };
        let balance_centi = ledger_view::balance_of(&self.db, &who).map_err(internal)?;
        ok(&rpc::BalanceResult { balance_centi })
    }

    fn m_propose(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::ProposeParams = parse_params(req)?;
        let receiver = parse_addr(&params.receiver)?;
        let now = self.clock.now();
        let station = self.station_keypair();

        // The next nonce for *this* identity, derived from the log.
        let snapshot = rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&self.db))
            .map_err(internal)?;
        let nonce = snapshot.next_nonce(&self.wallet.address.public_key().to_bytes());

        let proposal = TransactionProposal::new(
            self.wallet.address,
            receiver,
            params.amount_centi,
            params.memo,
            nonce,
            now,
            now + PROPOSAL_TTL_SECS,
        );
        let tx_id = proposal.id;
        let signed: SignedProposal = SignedProposal::sign(proposal, &station);

        let mut engine = Engine::new(&self.db, station);
        engine.submit_proposal(signed, now).map_err(ledger_err)?;

        ok(&rpc::ProposeResult {
            tx_id: hex(&tx_id.to_bytes()),
            state: "Proposed".into(),
        })
    }

    fn m_confirm(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::ConfirmParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        let now = self.clock.now();
        let station = self.station_keypair();

        let confirmation = TransactionConfirmation {
            proposal_id: tx_id,
            confirmer: self.wallet.address,
            confirmed_at: now,
        };
        let signed: SignedConfirmation = SignedConfirmation::sign(confirmation, &station);

        let mut engine = Engine::new(&self.db, station);
        engine
            .submit_confirmation(signed, now)
            .map_err(ledger_err)?;

        ok(&rpc::ConfirmResult {
            state: "Confirmed".into(),
        })
    }

    fn m_history(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::HistoryParams = parse_params(req)?;
        let entries = history::history(&self.db, params.limit, params.offset).map_err(internal)?;
        ok(&rpc::HistoryResult { entries })
    }

    fn m_vouch(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::VouchParams = parse_params(req)?;
        let subject = parse_addr(&params.subject)?;
        let station = self.station_keypair();

        let vouch = create_vouch(
            &station,
            &subject,
            VOUCH_COMMUNITY,
            &params.statement,
            params.stake_centi,
        );
        let vouch_id = hex(&vouch.payload_hash().to_bytes());
        let mut log = AppendLog::new(&self.db);
        append_vouch(&mut log, vouch).map_err(internal)?;

        ok(&rpc::VouchResult { vouch_id })
    }

    fn m_backup_export(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::BackupExportParams = parse_params(req)?;
        let mut holders = Vec::with_capacity(params.holders.len());
        for h in &params.holders {
            holders.push(*parse_addr(h)?.public_key());
        }
        let package = RecoveryPackage::create(&self.wallet, &holders, params.threshold)
            .map_err(|e| invalid_params(format!("recovery: {e}")))?;
        let path = PathBuf::from(&params.output);
        package
            .save_to_file(&path)
            .map_err(|e| internal(format!("save recovery package: {e}")))?;

        ok(&rpc::BackupExportResult {
            recovery_path: params.output,
        })
    }

    fn m_recover_import(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::RecoverImportParams = parse_params(req)?;
        let package = RecoveryPackage::load_from_file(std::path::Path::new(&params.recovery_path))
            .map_err(|e| invalid_params(format!("load recovery package: {e}")))?;

        let mut shards = Vec::with_capacity(params.shards.len());
        for path in &params.shards {
            shards.push(read_raw_shard(path)?);
        }
        let wallet = reconstruct_wallet(&package, &shards)
            .map_err(|e| invalid_params(format!("reconstruct: {e}")))?;

        ok(&rpc::RecoverImportResult {
            restored_address: wallet.address.to_string(),
        })
    }

    // --- internal operations ------------------------------------------------

    fn do_sweep(&mut self) -> usize {
        let now = self.clock.now();
        let station = self.station_keypair();
        let mut settler = Settler::new(&self.db, station, self.settlement);
        match settler.sweep(now) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "settlement sweep failed");
                0
            }
        }
    }

    fn tail_seq(&self) -> u64 {
        AppendLog::new(&self.db)
            .tail()
            .ok()
            .flatten()
            .map(|e| e.seq)
            .unwrap_or(0)
    }

    fn do_log_range(&self, from_seq: u64, to_seq: u64) -> Vec<WireEntry> {
        let log = AppendLog::new(&self.db);
        let mut out = Vec::new();
        for entry in log.iter_from(from_seq) {
            match entry {
                Ok(e) if e.seq <= to_seq => out.push(WireEntry::from_stored(&e.payload)),
                Ok(_) => break, // past the upper bound (iter is ascending)
                Err(e) => {
                    tracing::warn!(error = %e, "log_range read error");
                    break;
                }
            }
        }
        out
    }

    fn do_append_entries(&mut self, entries: Vec<WireEntry>) -> usize {
        let mut appended = 0;
        let mut log = AppendLog::new(&self.db);
        for w in entries {
            let stored = match w.to_stored() {
                Some(s) => s,
                None => {
                    tracing::warn!("dropping malformed peer entry");
                    continue;
                }
            };
            match log.append_raw(stored) {
                Ok(Some(_)) => appended += 1,
                Ok(None) => {} // already held — dedup
                Err(e) => {
                    // A peer's entry that fails signature verification (or any
                    // other error) is skipped — never trust a peer's bytes.
                    tracing::warn!(error = %e, "rejecting peer log entry");
                }
            }
        }
        appended
    }

    fn station_keypair(&self) -> Keypair {
        Keypair::from_secret(self.wallet.secret_key.clone())
    }

    // --- pairing (T1.3.3) ---------------------------------------------------

    /// Verifies a mobile's pairing request, records it as pending for the
    /// operator to confirm, and returns the station's signed response.
    ///
    /// Accepting a request does **not** pair the mobile: it proves the mobile
    /// holds its key and lets both sides display the same confirmation code. The
    /// mobile is added to [`paired`](Self::paired) only when the operator runs
    /// `station pair-mobile` after comparing that code in person (T1.3.3).
    fn do_pair_request(&mut self, request: PairRequest) -> Result<PairResponse, PairError> {
        let verified = request.verify()?;

        let now = self.clock.now();
        if (now - verified.requested_at).abs() > pairing::REQUESTED_AT_SKEW_SECS {
            return Err(PairError::StaleTimestamp);
        }

        let station = self.station_keypair();
        let station_pubkey = station.public_key();
        let sas = paired::confirmation_code(&station_pubkey, &verified.mobile_pubkey);

        // Drop anything that has aged out before recording this one, so a stream
        // of abandoned attempts cannot grow the map without bound.
        self.prune_pending(now);
        let address = verified.mobile_address.to_string();
        self.pending.insert(
            address.clone(),
            PendingPair {
                mobile_address: address,
                sas,
                received_at: now,
            },
        );

        // Sign a response bound to this request's token, proving the station's
        // identity and preventing a captured response from being reused.
        let msg = pairing::response_signed_bytes(&station_pubkey, &verified.token);
        let signature = station.sign(&msg);
        Ok(PairResponse {
            station_address: self.wallet.address.to_string(),
            signature: hex(&signature.to_bytes()),
        })
    }

    // --- authenticated request channel (T1.3.4) -----------------------------

    /// Opens, authenticates, and dispatches a paired mobile's sealed request,
    /// returning the sealed response bytes.
    ///
    /// The order is deliberate: cheap, stateless checks (open, signature, format)
    /// run before the stateful ones (recipient, paired, skew, nonce), and the
    /// nonce is consumed **before** dispatch so a request cannot be replayed even
    /// if the method itself fails. Auth failures return a [`ChannelError`] with
    /// no sealed body — the edge turns them into a 4xx; an authenticated request
    /// whose *method* fails still gets a sealed error response.
    fn do_rpc_request(&mut self, sealed_bytes: Vec<u8>) -> Result<Vec<u8>, ChannelError> {
        // 1. Open the seal with the station's secret key.
        let sealed = SealedBox::from_bytes(&sealed_bytes).map_err(|_| ChannelError::Sealed)?;
        let frame = sealed::open(&sealed, &self.wallet.secret_key, TRANSPORT_CONTEXT)
            .map_err(|_| ChannelError::Sealed)?;

        // 2. Parse the frame and verify the signature over the exact payload.
        let envelope = rpc_envelope::parse_signed_request(&frame)?;

        // 3. Stateful authorization.
        let station = self.station_keypair();
        if envelope.recipient.to_bytes() != station.public_key().to_bytes() {
            return Err(ChannelError::WrongRecipient);
        }
        let signer = Address::from_public_key(envelope.signer).to_string();
        if !self.paired.contains(&signer) {
            return Err(ChannelError::NotPaired);
        }
        let now = self.clock.now();
        if (now - envelope.timestamp).abs() > rpc_envelope::TIMESTAMP_SKEW_SECS {
            return Err(ChannelError::StaleTimestamp);
        }
        if !self.paired.accept_nonce(&signer, envelope.nonce) {
            return Err(ChannelError::Replay);
        }
        // Persist the nonce high-water mark so the replay bound survives a
        // restart. If this fails, do not consume the request against a nonce we
        // could not record — surface it as unavailable so the mobile retries.
        if let Err(e) = self.paired.save() {
            tracing::error!(error = %e, "failed to persist mobile request nonce");
            return Err(ChannelError::Unavailable);
        }

        // 4. Dispatch through the mobile-permitted method surface.
        let mobile_pubkey = envelope.signer;
        let response = self.dispatch_channel_call(&envelope);

        // 5. Sign the reply as the station and seal it back to the mobile.
        let reply_frame = rpc_envelope::frame_signed_response(response, &station);
        let sealed_reply = sealed::seal(&mobile_pubkey, &reply_frame, TRANSPORT_CONTEXT)
            .map_err(|_| ChannelError::Sealed)?;
        Ok(sealed_reply.to_bytes())
    }

    /// Routes an authenticated envelope to the existing method dispatch, gated to
    /// the [`MOBILE_METHODS`] surface, and wraps the outcome as a response
    /// envelope (a method-level failure becomes a sealed error, not a rejection).
    fn dispatch_channel_call(&mut self, envelope: &RequestEnvelope) -> ResponseEnvelope {
        if !MOBILE_METHODS.contains(&envelope.method.as_str()) {
            return ResponseEnvelope {
                nonce: envelope.nonce,
                result: None,
                error: Some((
                    rpc::METHOD_NOT_FOUND,
                    format!("method not available to mobiles: {}", envelope.method),
                )),
            };
        }
        let params: serde_json::Value = match serde_json::from_str(&envelope.params) {
            Ok(v) => v,
            Err(e) => {
                return ResponseEnvelope {
                    nonce: envelope.nonce,
                    result: None,
                    error: Some((rpc::INVALID_PARAMS, format!("params not valid JSON: {e}"))),
                }
            }
        };
        let req = rpc::Request {
            id: envelope.nonce.to_string(),
            method: envelope.method.clone(),
            params,
        };
        match self.handle_call(&req) {
            Ok(result) => ResponseEnvelope {
                nonce: envelope.nonce,
                result: Some(result.to_string()),
                error: None,
            },
            Err(e) => ResponseEnvelope {
                nonce: envelope.nonce,
                result: None,
                error: Some((e.code, e.message)),
            },
        }
    }

    /// Removes pending requests older than [`pairing::PENDING_TTL_SECS`].
    fn prune_pending(&mut self, now: i64) {
        self.pending
            .retain(|_, p| now - p.received_at <= pairing::PENDING_TTL_SECS);
    }

    /// `pair_list_pending` — the accepted-but-unconfirmed requests, each with the
    /// confirmation code the operator reads aloud to compare with the mobile.
    fn m_pair_list_pending(&mut self) -> Result<serde_json::Value, rpc::RpcError> {
        let now = self.clock.now();
        self.prune_pending(now);
        let pending: Vec<_> = self
            .pending
            .values()
            .map(|p| {
                serde_json::json!({
                    "address": p.mobile_address,
                    "sas": p.sas,
                    "age_secs": now - p.received_at,
                })
            })
            .collect();
        ok(&serde_json::json!({ "pending": pending }))
    }

    /// `pair_confirm` — the operator has compared the code in person and vouches
    /// for the pair. Moves the mobile from pending to the persisted paired list.
    fn m_pair_confirm(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        #[derive(serde::Deserialize)]
        struct Params {
            address: String,
        }
        let params: Params = parse_params(req)?;

        let now = self.clock.now();
        self.prune_pending(now);
        let pending = self.pending.remove(&params.address).ok_or_else(|| {
            invalid_params(format!(
                "no pending pairing request from {} (it may have expired)",
                params.address
            ))
        })?;

        self.paired.add(pending.mobile_address.clone(), now);
        self.paired.save().map_err(internal)?;
        ok(&serde_json::json!({
            "address": pending.mobile_address,
            "paired_at": now,
        }))
    }

    /// `list_mobiles` — the mobiles currently paired with this station.
    fn m_list_mobiles(&self) -> Result<serde_json::Value, rpc::RpcError> {
        let mobiles: Vec<_> = self
            .paired
            .list()
            .iter()
            .map(|m| {
                serde_json::json!({
                    "address": m.address,
                    "paired_at": m.paired_at,
                })
            })
            .collect();
        ok(&serde_json::json!({ "mobiles": mobiles }))
    }

    /// `unpair` — revoke a mobile's pairing. Its next request will be rejected
    /// (T1.3.4). Reports whether the address was actually paired.
    fn m_unpair(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        #[derive(serde::Deserialize)]
        struct Params {
            address: String,
        }
        let params: Params = parse_params(req)?;

        let removed = self.paired.remove(&params.address);
        if removed {
            self.paired.save().map_err(internal)?;
        }
        ok(&serde_json::json!({ "removed": removed }))
    }
}

// --- helpers ----------------------------------------------------------------

fn ok<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, rpc::RpcError> {
    serde_json::to_value(value).map_err(|e| internal(format!("serialize result: {e}")))
}

fn parse_params<T: serde::de::DeserializeOwned>(req: &rpc::Request) -> Result<T, rpc::RpcError> {
    serde_json::from_value(req.params.clone())
        .map_err(|e| invalid_params(format!("invalid params: {e}")))
}

fn parse_addr(s: &str) -> Result<Address, rpc::RpcError> {
    s.parse::<Address>()
        .map_err(|e| invalid_params(format!("invalid address {s:?}: {e}")))
}

fn parse_tx_id(s: &str) -> Result<TransactionId, rpc::RpcError> {
    let bytes = unhex(s).ok_or_else(|| invalid_params(format!("invalid tx id {s:?}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_params("tx id must be 32 bytes"))?;
    Ok(TransactionId(Hash::from_bytes(arr)))
}

fn read_raw_shard(path: &str) -> Result<RawShard, rpc::RpcError> {
    let bytes =
        std::fs::read(path).map_err(|e| invalid_params(format!("read shard {path:?}: {e}")))?;
    if bytes.len() != 1 + SHARD_DATA_LEN {
        return Err(invalid_params(format!(
            "shard {path:?} is {} bytes, expected {}",
            bytes.len(),
            1 + SHARD_DATA_LEN
        )));
    }
    let data: [u8; SHARD_DATA_LEN] = bytes[1..].try_into().expect("checked length");
    Ok(RawShard {
        index: ShardIndex(bytes[0]),
        data,
    })
}

fn invalid_params(message: impl Into<String>) -> rpc::RpcError {
    rpc::RpcError {
        code: rpc::INVALID_PARAMS,
        message: message.into(),
    }
}

fn internal(e: impl std::fmt::Display) -> rpc::RpcError {
    rpc::RpcError {
        code: rpc::INTERNAL_ERROR,
        message: e.to_string(),
    }
}

/// Maps a ledger error to an RPC error, distinguishing caller mistakes
/// (bad/duplicate/expired inputs → invalid params) from internal failures.
fn ledger_err(e: rrn_ledger::Error) -> rpc::RpcError {
    use rrn_ledger::Error::*;
    match e {
        Storage(_) | Invalid(_) => internal(e),
        _ => invalid_params(e.to_string()),
    }
}

/// Lowercase hex of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decodes lowercase/uppercase hex, or `None` if it is not valid hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Reconstructs a [`StoredPayload`] from its three byte fields (used by the
/// gossip wire codec).
pub(crate) fn stored_from_parts(
    signer: &[u8],
    signature: &[u8],
    bytes: Vec<u8>,
) -> Option<StoredPayload> {
    let signer = PublicKey::from_bytes(signer.try_into().ok()?).ok()?;
    let signature = Signature::from_bytes(signature.try_into().ok()?).ok()?;
    Some(StoredPayload {
        bytes,
        signer,
        signature,
    })
}

/// A transaction's state as a short string, for the few callers that need it
/// (currently only tests; the RPC handlers return fixed post-op states).
pub fn state_name(state: &TransactionState) -> &'static str {
    match state {
        TransactionState::Proposed { .. } => "Proposed",
        TransactionState::Confirmed { .. } => "Confirmed",
        TransactionState::Settled { .. } => "Settled",
        TransactionState::Cancelled { .. } => "Cancelled",
        TransactionState::DisputedStub => "Disputed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::to_canonical_bytes;
    use rrn_identity::vouch::create_vouch;
    use rrn_storage::migrations;

    fn test_core() -> Core {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        Core::new(
            db,
            WalletContents::create_new(),
            SettlementConfig::default(),
            Clock::manual(1_000),
            PairedMobiles::default(),
        )
    }

    /// Builds a wire entry from a freshly-signed vouch, optionally corrupting the
    /// signature so it should be rejected.
    fn wire_vouch(corrupt: bool) -> WireEntry {
        let kp = Keypair::generate();
        let subject = Address::from_public_key(Keypair::generate().public_key());
        let vouch = create_vouch(&kp, &subject, "c", "hi", 0);
        let mut signature = vouch.signature.to_bytes().to_vec();
        if corrupt {
            signature[0] ^= 0xff; // break the signature
        }
        WireEntry {
            signer: vouch.signer.to_bytes().to_vec(),
            signature,
            bytes: to_canonical_bytes(vouch.payload.clone()),
        }
    }

    #[test]
    fn gossip_apply_accepts_valid_and_ignores_bad_signatures() {
        let mut core = test_core();
        let good = wire_vouch(false);
        let bad = wire_vouch(true);

        // One good, one tampered: only the good one is appended, and the bad one
        // does not abort the batch or crash.
        let appended = core.do_append_entries(vec![good.clone(), bad]);
        assert_eq!(appended, 1);
        assert_eq!(core.tail_seq(), 1);

        // Replaying the same good entry is deduped (idempotent).
        assert_eq!(core.do_append_entries(vec![good]), 0);
        assert_eq!(core.tail_seq(), 1);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let mut core = test_core();
        let req = rpc::Request {
            id: "1".into(),
            method: "nope".into(),
            params: serde_json::Value::Null,
        };
        let err = core.handle_call(&req).unwrap_err();
        assert_eq!(err.code, rpc::METHOD_NOT_FOUND);
    }

    #[test]
    fn balance_of_unknown_address_is_zero() {
        let mut core = test_core();
        let other = Address::from_public_key(Keypair::generate().public_key()).to_string();
        let req = rpc::Request {
            id: "1".into(),
            method: "balance".into(),
            params: serde_json::json!({ "address": other }),
        };
        let v = core.handle_call(&req).unwrap();
        assert_eq!(v["balance_centi"], 0);
    }
}
