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

use tokio::sync::{oneshot, watch};

use rrn_crypto::keypair::Keypair;
use rrn_identity::address::Address;
use rrn_identity::recovery::flow::{reconstruct_wallet, RecoveryPackage};
use rrn_identity::recovery::shamir::{RawShard, ShardIndex};
use rrn_identity::vouch::{append_vouch, create_vouch, SignedVouch};
use rrn_identity::wallet::WalletContents;
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{SettlementConfig, Settler};
use rrn_ledger::state::TransactionState;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
};
use rrn_marketplace::lifecycle::{
    append_listing_closed, touched_listing, CloseReason, ListingClosed, ListingState,
};
use rrn_marketplace::listing::{ListingId, Surface};
use rrn_marketplace::search::{SearchIndex, SearchQuery};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, StoredPayload};

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};

use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};

use crate::clock::Clock;
use crate::events::{self, Event};
use crate::gossip::WireEntry;
use crate::ledger_view;
use crate::marketplace_view;
use crate::paired::{self, PairedMobiles};
use crate::pairing::{self, PairError, PairRequest, PairResponse, PendingPair};
use crate::reputation_view;
use crate::rpc_envelope::{self, ChannelError, RequestEnvelope, ResponseEnvelope};
use crate::transaction_view;
use crate::vouch_view;
use crate::{history, rpc};

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
    /// Refresh every known identity's reputation snapshot at the core's current
    /// clock time; reply with the number of identities refreshed.
    RefreshReputation {
        /// Count of identities refreshed.
        reply: oneshot::Sender<usize>,
    },
    /// Close every listing whose `expires_at` has passed with a station-signed
    /// [`ListingClosed`]; reply with the number closed (T1.7.0).
    ExpireListings {
        /// Count of listings closed.
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
    /// A paired mobile's `/subscribe` request (T1.3.5): authenticate, then return
    /// pending events sealed, or the context to long-poll on.
    Subscribe {
        /// The sealed subscribe envelope as it arrived on the wire.
        sealed: Vec<u8>,
        /// Pending events (sealed), or the long-poll context, or a rejection.
        reply: oneshot::Sender<Result<SubscribeOutcome, ChannelError>>,
    },
    /// Re-poll events for an already-authenticated long-polling subscriber
    /// (T1.3.5). `force` returns a sealed empty heartbeat when still empty.
    CollectEvents {
        /// The subscriber's address.
        member: Address,
        /// The subscriber's public key (to seal the reply to).
        member_pk: PublicKey,
        /// The cursor the subscriber is polling from.
        last_seen: u64,
        /// The subscribe request's nonce, echoed in the sealed reply.
        nonce: u64,
        /// Return a sealed empty batch even with no events (the timeout path).
        force: bool,
        /// The sealed response, or `None` when there is still nothing.
        reply: oneshot::Sender<Option<Vec<u8>>>,
    },
    /// Stop the core loop (graceful shutdown).
    Shutdown,
}

/// The outcome of an authenticated `/subscribe` request (T1.3.5): either events
/// were already pending (sealed, return immediately) or the edge should park on
/// the log-tail signal and re-poll with the carried context — no re-auth.
pub enum SubscribeOutcome {
    /// A sealed response carrying at least one event.
    Ready(Vec<u8>),
    /// No events yet; long-poll using this (already-authenticated) context.
    Waiting {
        /// The subscriber's address.
        member: Address,
        /// The subscriber's public key (to seal the reply to).
        member_pk: PublicKey,
        /// The cursor to poll from.
        last_seen: u64,
        /// The request nonce to echo in the eventual reply.
        nonce: u64,
    },
}

/// A cloneable handle the async tasks use to talk to the core.
#[derive(Clone)]
pub struct CoreHandle {
    tx: mpsc::Sender<Command>,
    /// Fires whenever the log tail advances — the wake signal a `/subscribe`
    /// long-poll parks on (T1.3.5). Carries the current tail seq, but callers
    /// only use it as an edge trigger to re-poll for events.
    log_tail: watch::Receiver<u64>,
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

    /// Triggers a reputation-snapshot refresh; returns the number of identities
    /// refreshed.
    pub async fn refresh_reputation(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::RefreshReputation { reply }).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Triggers the listing-expiry sweep; returns the number closed.
    pub async fn expire_listings(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::ExpireListings { reply }).is_err() {
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

    /// Authenticates a paired mobile's `/subscribe` request (T1.3.5); returns
    /// pending events (sealed) or the long-poll context. [`ChannelError::Unavailable`]
    /// means the core is gone.
    pub async fn subscribe(&self, sealed: Vec<u8>) -> Result<SubscribeOutcome, ChannelError> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::Subscribe { sealed, reply }).is_err() {
            return Err(ChannelError::Unavailable);
        }
        rx.await.unwrap_or(Err(ChannelError::Unavailable))
    }

    /// Re-polls events for a parked subscriber. `Some` is a sealed response to
    /// return (events, or an empty heartbeat when `force`); `None` means there is
    /// still nothing and the caller should keep waiting.
    pub async fn poll_events(
        &self,
        member: Address,
        member_pk: PublicKey,
        last_seen: u64,
        nonce: u64,
        force: bool,
    ) -> Option<Vec<u8>> {
        let (reply, rx) = oneshot::channel();
        if self
            .tx
            .send(Command::CollectEvents {
                member,
                member_pk,
                last_seen,
                nonce,
                force,
                reply,
            })
            .is_err()
        {
            return None;
        }
        rx.await.unwrap_or(None)
    }

    /// A receiver that fires whenever the log tail advances — the wake signal a
    /// `/subscribe` long-poll parks on (T1.3.5).
    pub fn log_tail_watch(&self) -> watch::Receiver<u64> {
        self.log_tail.clone()
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
    /// Publishes the log tail after every append so a parked `/subscribe`
    /// long-poll wakes and re-polls for events (T1.3.5).
    tail_tx: watch::Sender<u64>,
    /// The marketplace's full-text index (T1.6.6), kept in step with the log as
    /// listing records are appended or replicated.
    ///
    /// A cache and nothing more: it is rebuilt from the log at startup and can
    /// be deleted at any time (ADR-0010), so a station whose index is corrupt or
    /// absent loses browse until the next boot and loses no marketplace *data*
    /// ever.
    listings: SearchIndex,
}

impl Core {
    /// Builds a core over an opened `db`, decrypted `wallet`, the persisted
    /// paired-mobile list, and the marketplace search index.
    pub fn new(
        db: Database,
        wallet: WalletContents,
        settlement: SettlementConfig,
        clock: Clock,
        paired: PairedMobiles,
        listings: SearchIndex,
    ) -> Self {
        let (tail_tx, _) = watch::channel(0u64);
        Core {
            db,
            wallet,
            settlement,
            clock,
            paired,
            pending: BTreeMap::new(),
            tail_tx,
            listings,
        }
    }

    /// Spawns the core on a dedicated thread and returns a handle to it.
    pub fn spawn(self) -> CoreHandle {
        let (tx, rx) = mpsc::channel::<Command>();
        let log_tail = self.tail_tx.subscribe();
        std::thread::Builder::new()
            .name("rrn-core".into())
            .spawn(move || self.run(rx))
            .expect("spawn core thread");
        CoreHandle { tx, log_tail }
    }

    /// The blocking command loop. Returns when a [`Command::Shutdown`] arrives or
    /// all handles are dropped.
    fn run(mut self, rx: mpsc::Receiver<Command>) {
        self.rebuild_listing_index();
        while let Ok(cmd) = rx.recv() {
            match cmd {
                Command::Call { request, reply } => {
                    let _ = reply.send(self.handle_call(&request));
                }
                Command::Sweep { reply } => {
                    let n = self.do_sweep();
                    let _ = reply.send(n);
                }
                Command::RefreshReputation { reply } => {
                    let n = self.do_refresh_reputation();
                    let _ = reply.send(n);
                }
                Command::ExpireListings { reply } => {
                    let n = self.do_expire_listings();
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
                Command::Subscribe { sealed, reply } => {
                    let _ = reply.send(self.do_subscribe(sealed));
                }
                Command::CollectEvents {
                    member,
                    member_pk,
                    last_seen,
                    nonce,
                    force,
                    reply,
                } => {
                    let _ = reply
                        .send(self.do_collect_events(member, member_pk, last_seen, nonce, force));
                }
                Command::Shutdown => {
                    tracing::info!("core shutting down");
                    break;
                }
            }
            // After any command that may have appended to the log (a mobile or
            // operator write, a settlement sweep, a gossip apply), wake parked
            // long-polls if the tail advanced. A no-op for read-only commands.
            self.publish_tail();
        }
    }

    /// Publishes the current log tail to `/subscribe` waiters, but only when it
    /// actually advanced — so a read-only command does not spuriously wake them.
    fn publish_tail(&self) {
        let tail = self.tail_seq();
        self.tail_tx.send_if_modified(|current| {
            if *current == tail {
                false
            } else {
                *current = tail;
                true
            }
        });
    }

    // --- public RPC dispatch ------------------------------------------------

    fn handle_call(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        match req.method.as_str() {
            "whoami" => self.m_whoami(),
            "balance" => self.m_balance(req),
            "propose" => self.m_propose(req),
            "confirm" => self.m_confirm(req),
            "history" => self.m_history(req),
            "transactions" => self.m_transactions(req),
            "next_nonce" => self.m_next_nonce(req),
            "vouch" => self.m_vouch(req),
            "backup_export" => self.m_backup_export(req),
            "recover_import" => self.m_recover_import(req),
            // Operator-facing marketplace (T1.7.3). The reads answer with the
            // same views the mobile channel serves; the writes are signed by
            // this station's own wallet, as `propose` and `vouch` are.
            "marketplace_search" => self.m_marketplace_search(req),
            "marketplace_listing" => self.m_marketplace_listing(req),
            "marketplace_create_listing" => self.m_marketplace_create_listing(req),
            "marketplace_close_listing" => self.m_marketplace_close_listing(req),
            "marketplace_my_listings" => self.m_marketplace_my_listings(),
            "marketplace_announce_need" => self.m_marketplace_announce_need(req),
            "marketplace_matches" => self.m_marketplace_matches(req),
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
            community: VOUCH_COMMUNITY.to_string(),
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

    /// `transactions` — the member-relative, structured transaction view the
    /// mobile wallet renders (T1.3.4). Correlates the log's events into one row
    /// per transaction from the querying member's vantage point.
    fn m_transactions(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::TransactionsParams = parse_params(req)?;
        let member = parse_addr(&params.address)?;
        let snapshot = rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&self.db))
            .map_err(internal)?;
        let transactions = transaction_view::member_transactions(&snapshot, &member, params.limit);
        ok(&rpc::TransactionsResult { transactions })
    }

    /// `next_nonce` — the nonce a member's next proposal must carry (T1.3.4). The
    /// mobile reads this before it signs a proposal, since the nonce is signed
    /// and the ledger requires it to be exactly the next in sequence.
    fn m_next_nonce(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::NextNonceParams = parse_params(req)?;
        let who = match params.address {
            Some(s) => parse_addr(&s)?,
            None => self.wallet.address,
        };
        let snapshot = rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&self.db))
            .map_err(internal)?;
        let nonce = snapshot.next_nonce(&who.public_key().to_bytes());
        ok(&rpc::NextNonceResult { nonce })
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

    // --- operator marketplace (T1.7.3) --------------------------------------

    /// `marketplace_search` — browse, for the CLI. The same read the mobile gets.
    fn m_marketplace_search(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        // `null` params (an absent `params` key) is a valid "everything" browse.
        let params: rpc::SearchParams = if req.params.is_null() {
            rpc::SearchParams::default()
        } else {
            parse_params(req)?
        };
        self.run_marketplace_search(params)
    }

    /// `marketplace_listing` — one listing in full, for the CLI.
    fn m_marketplace_listing(
        &self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::ListingParams = parse_params(req)?;
        self.run_marketplace_listing(&params.listing_id)
    }

    /// `marketplace_create_listing` — publish a station-signed listing.
    ///
    /// The station's wallet is the provider, which on the operator's socket is
    /// the operator themselves; a member publishing from a phone signs their own
    /// listing instead (T1.7.2). `community` comes from this station rather than
    /// the caller for the same reason `provider` does — both are facts about who
    /// is publishing, not choices the request gets to make.
    fn m_marketplace_create_listing(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::CreateListingParams = parse_params(req)?;
        let surface = Surface::from_tag(&params.surface).ok_or_else(|| {
            invalid_params(format!(
                "unknown surface: {} (goods, services, or commons)",
                params.surface
            ))
        })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let oracle_tier = params
            .oracle_tier
            .unwrap_or_else(|| suggest_oracle_tier(params.amount_centi));

        let listing = rrn_marketplace::listing::Listing::new(
            self.wallet.address,
            VOUCH_COMMUNITY.to_string(),
            surface,
            params.category,
            params.title,
            params.description,
            rrn_marketplace::listing::Pricing {
                amount_centi: params.amount_centi,
                // A listing that invites offers must say so in both places, or
                // `validate` rejects it as contradictory pricing.
                model: if params.negotiable {
                    rrn_marketplace::listing::PricingModel::Negotiable
                } else {
                    rrn_marketplace::listing::PricingModel::Fixed
                },
                negotiable: params.negotiable,
            },
            availability_for(surface, params.capacity, params.next_slot),
            rrn_marketplace::listing::Requirements {
                min_reputation: params.min_reputation,
                community_member_only: params.community_member_only,
                federation_only: false,
            },
            oracle_tier,
            false,
            now,
            params.expires_at,
        )
        .map_err(|e| invalid_params(e.to_string()))?;

        let listing_id = listing.id;
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::lifecycle::append_listing_created(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(listing, &station),
        )
        .map_err(marketplace_err)?;
        // Bring browse in step in the same call that published, so a listing is
        // findable the moment the command returns rather than at the next boot.
        self.reindex_listing(&listing_id);

        ok(&rpc::CreateListingResult {
            listing_id: hex(&listing_id.to_bytes()),
            oracle_tier,
        })
    }

    /// `marketplace_close_listing` — withdraw one of the station's own listings.
    ///
    /// Always `ProviderClosed`: this path signs as the provider, and the two
    /// station-signable reasons belong to the sweep and to housekeeping, not to a
    /// person asking for their offer to come down.
    fn m_marketplace_close_listing(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::CloseListingParams = parse_params(req)?;
        let listing_id = parse_listing_id(&params.listing_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();

        let record = ListingClosed {
            listing_id,
            reason: CloseReason::ProviderClosed,
            closed_at: now,
        };
        let mut log = AppendLog::new(&self.db);
        append_listing_closed(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(record, &station),
            &station_pk,
        )
        .map_err(marketplace_err)?;
        self.reindex_listing(&listing_id);

        ok(&rpc::CloseListingResult {
            listing_id: params.listing_id,
            reason: "provider_closed".into(),
        })
    }

    /// `marketplace_my_listings` — every listing this station has published, in
    /// whatever state, newest first.
    fn m_marketplace_my_listings(&self) -> Result<serde_json::Value, rpc::RpcError> {
        let now = self.clock.now();
        let station = self.wallet.address.public_key();
        let listings = marketplace_view::my_listings(&self.db, &self.wallet.address, station, now)
            .map_err(internal)?;
        ok(&serde_json::json!({ "listings": listings }))
    }

    /// `marketplace_announce_need` — state what this station is looking for.
    ///
    /// Returns the log seq, which is how a need is named: needs are not
    /// content-addressed (see [`rrn_marketplace::need::AnnouncedNeed`]).
    fn m_marketplace_announce_need(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::AnnounceNeedParams = parse_params(req)?;
        let station = self.station_keypair();
        let need = rrn_marketplace::need::Need::new(
            self.wallet.address,
            params.category,
            params.quantity_needed,
            params.max_price_centi,
            params.valid_until,
        )
        .map_err(|e| invalid_params(e.to_string()))?;

        let mut log = AppendLog::new(&self.db);
        let entry = rrn_marketplace::need::append_need_announced(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(need, &station),
        )
        .map_err(marketplace_err)?;

        ok(&rpc::AnnounceNeedResult { seq: entry.seq })
    }

    /// `marketplace_matches` — the listings answering this station's needs, one
    /// group per need. With no `seq`, every need it has announced; with one, just
    /// that need.
    fn m_marketplace_matches(
        &self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::MatchesParams = if req.params.is_null() {
            rpc::MatchesParams::default()
        } else {
            parse_params(req)?
        };
        let now = self.clock.now();
        let log = AppendLog::new(&self.db);
        let mut announced =
            rrn_marketplace::need::announced_needs(&log, &self.wallet.address).map_err(internal)?;
        if let Some(seq) = params.seq {
            announced.retain(|a| a.seq == seq);
            if announced.is_empty() {
                return Err(invalid_params(format!(
                    "no need announced by this station at log seq {seq}"
                )));
            }
        }

        let mut needs = Vec::with_capacity(announced.len());
        for entry in announced {
            // An expired need matches nothing, and `find_matches` says so by
            // returning empty. The row carries `expired` so the difference
            // between "stale" and "nothing on offer" is visible.
            let listings = marketplace_view::matches(&self.listings, &self.db, &entry.need, now)
                .map_err(internal)?;
            let expired = entry.need.has_expired(now);
            needs.push(marketplace_view::NeedMatchRow {
                seq: entry.seq,
                category: entry.need.category,
                quantity_needed: entry.need.quantity_needed,
                max_price_centi: entry.need.max_price_centi,
                valid_until: entry.need.valid_until,
                expired,
                listings,
            });
        }
        ok(&serde_json::json!({ "needs": needs }))
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

    fn do_refresh_reputation(&mut self) -> usize {
        let now = self.clock.now();
        match rrn_reputation::snapshot::refresh_all_snapshots(&self.db, now) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "reputation snapshot refresh failed");
                0
            }
        }
    }

    // --- marketplace index maintenance (T1.7.0) -----------------------------

    /// Rebuilds the listing index from a full log replay.
    ///
    /// Run once at startup, unconditionally. Nothing appends to the log while the
    /// station is down, so the index a previous run left behind is *usually*
    /// still correct — but "usually" is the wrong standard for a derived view
    /// with no transaction binding it to the log (ADR-0010 accepted exactly this
    /// drift when it chose tantivy over FTS5), and the log is the only thing that
    /// can settle it. One replay per boot buys the guarantee that browse never
    /// serves a listing state the log disagrees with.
    ///
    /// A failure here is logged and tolerated: browse degrades to empty, and
    /// every other thing the station does is unaffected. The index is
    /// authoritative over nothing, so it must never be able to keep a station
    /// from starting.
    fn rebuild_listing_index(&mut self) {
        let now = self.clock.now();
        let station = self.wallet.address.public_key();
        let log = AppendLog::new(&self.db);
        match self.listings.rebuild(&self.db, &log, station, now) {
            Ok(0) => {}
            Ok(n) => tracing::info!(listings = n, "rebuilt the marketplace index"),
            Err(e) => tracing::warn!(
                error = %e,
                "marketplace index rebuild failed; browse will be empty until the next restart"
            ),
        }
    }

    /// Brings one listing's index entry back in step with the log.
    ///
    /// Called after anything that could have changed a listing — a local append,
    /// a replicated entry — with the id that record named. The state comes from
    /// the log via `compute_state`, so an entry written by someone not entitled
    /// to write it changes nothing here either: this re-derives rather than
    /// applying the record it was told about.
    ///
    /// A listing no longer on offer is *removed* from the index rather than
    /// updated, because the index exists to answer "what can I buy".
    fn reindex_listing(&self, listing_id: &ListingId) {
        let now = self.clock.now();
        let station = self.wallet.address.public_key();
        let log = AppendLog::new(&self.db);
        let state = match rrn_marketplace::lifecycle::compute_state(&log, listing_id, station, now)
        {
            Ok(Some(state)) => state,
            // Nothing valid on the log for this id — an impostor's record, or a
            // record about a listing this station never saw created.
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "could not compute listing state for reindex");
                return;
            }
        };

        let result = match (&state, state.listing()) {
            (ListingState::Active(_), Some(listing)) => {
                self.listings.upsert(&self.db, listing, &state)
            }
            _ => self.listings.remove(&self.db, listing_id),
        };
        if let Err(e) = result {
            tracing::warn!(error = %e, "could not update the marketplace index");
        }
    }

    /// Closes every listing whose expiry has passed, with a station-signed
    /// [`ListingClosed`] (T1.6.5, ADR-0005's station-as-signer pattern).
    ///
    /// `Expired` is a *derived* state, not a record: readers already treat it as
    /// off the market, so this sweep is not what makes an expired listing
    /// unbuyable — it is what turns a derivation everyone recomputes into a fact
    /// on the log, which is what a peer replicating this log later needs. The
    /// station may sign this reason and never `ProviderClosed` (a station must
    /// not be able to claim a provider withdrew an offer).
    fn do_expire_listings(&mut self) -> usize {
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();

        let log = AppendLog::new(&self.db);
        let expired: Vec<ListingId> =
            match rrn_marketplace::lifecycle::compute_all(&log, &station_pk, now) {
                Ok(states) => states
                    .into_iter()
                    .filter(|(_, state)| matches!(state, ListingState::Expired { .. }))
                    .map(|(id, _)| id)
                    .collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "listing expiry sweep could not read the log");
                    return 0;
                }
            };
        if expired.is_empty() {
            return 0;
        }

        let mut closed = 0;
        for listing_id in expired {
            let record = ListingClosed {
                listing_id,
                reason: CloseReason::ExpirationReached,
                closed_at: now,
            };
            let mut log = AppendLog::new(&self.db);
            match append_listing_closed(
                &mut log,
                rrn_crypto::signed::SignedPayload::sign(record, &station),
                &station_pk,
            ) {
                Ok(_) => closed += 1,
                // Most likely a race with a provider's own close landing first,
                // which is a fine outcome — the listing is closed either way.
                Err(e) => tracing::warn!(error = %e, "could not close an expired listing"),
            }
            // Drop it from browse whether or not the append succeeded: it is
            // past its expiry either way, and an expired listing has no business
            // in the index. Only the listings this sweep found are touched —
            // re-deriving the whole corpus here would cost one index writer per
            // listing on the station's single thread, to change the few that
            // moved.
            if let Err(e) = self.listings.remove(&self.db, &listing_id) {
                tracing::warn!(error = %e, "could not drop an expired listing from the index");
            }
        }
        closed
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
        // Listings a replicated entry claims to be about, so the browse index
        // can be brought back in step below. Collected rather than reindexed
        // inline because each reindex replays the log, and a gossip round can
        // carry many records for one listing.
        let mut touched: Vec<ListingId> = Vec::new();
        let mut log = AppendLog::new(&self.db);
        for w in entries {
            let stored = match w.to_stored() {
                Some(s) => s,
                None => {
                    tracing::warn!("dropping malformed peer entry");
                    continue;
                }
            };
            let listing = touched_listing(&stored.bytes);
            match log.append_raw(stored) {
                Ok(Some(_)) => {
                    appended += 1;
                    if let Some(id) = listing {
                        if !touched.contains(&id) {
                            touched.push(id);
                        }
                    }
                }
                Ok(None) => {} // already held — dedup
                Err(e) => {
                    // A peer's entry that fails signature verification (or any
                    // other error) is skipped — never trust a peer's bytes.
                    tracing::warn!(error = %e, "rejecting peer log entry");
                }
            }
        }
        for listing_id in &touched {
            self.reindex_listing(listing_id);
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
        // Authenticate (open, verify, authorize, consume the nonce), then
        // dispatch through the mobile-permitted method surface and seal the reply
        // back to the mobile. A method-level failure still gets a sealed error
        // response; only auth failures return no sealed body (a 4xx at the edge).
        let envelope = self.authenticate_envelope(&sealed_bytes)?;
        let mobile_pubkey = envelope.signer;
        let response = self.dispatch_channel_call(&envelope);
        let station = self.station_keypair();
        let reply_frame = rpc_envelope::frame_signed_response(&response, &station);
        let sealed_reply = sealed::seal(&mobile_pubkey, &reply_frame, TRANSPORT_CONTEXT)
            .map_err(|_| ChannelError::Sealed)?;
        Ok(sealed_reply.to_bytes())
    }

    /// Opens, verifies, and authorizes a sealed request envelope — the auth
    /// preamble shared by `/rpc` and `/subscribe` (T1.3.4/T1.3.5). On success the
    /// request's transport nonce is consumed and persisted, so a replay is
    /// rejected even if the caller never dispatches. Auth failures return a
    /// [`ChannelError`] the edge turns into a 4xx.
    fn authenticate_envelope(
        &mut self,
        sealed_bytes: &[u8],
    ) -> Result<RequestEnvelope, ChannelError> {
        // 1. Open the seal with the station's secret key.
        let sealed = SealedBox::from_bytes(sealed_bytes).map_err(|_| ChannelError::Sealed)?;
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
        Ok(envelope)
    }

    /// Authenticates a `/subscribe` request and either returns pending events
    /// (sealed, ready) or the context to long-poll on (T1.3.5). The 30s wait
    /// itself lives in the async edge, not here — the core must not block.
    fn do_subscribe(&mut self, sealed_bytes: Vec<u8>) -> Result<SubscribeOutcome, ChannelError> {
        let envelope = self.authenticate_envelope(&sealed_bytes)?;
        if envelope.method != "subscribe" {
            return Err(ChannelError::Malformed);
        }
        let last_seen = parse_subscribe_cursor(&envelope.params);
        let member = Address::from_public_key(envelope.signer);
        let member_pk = envelope.signer;
        let nonce = envelope.nonce;
        let tail = self.tail_seq();
        let events = events::events_since(&self.db, &member, last_seen, tail);
        if events.is_empty() {
            Ok(SubscribeOutcome::Waiting {
                member,
                member_pk,
                last_seen,
                nonce,
            })
        } else {
            let sealed = self
                .seal_subscribe_reply(&member_pk, nonce, tail, events)
                .ok_or(ChannelError::Sealed)?;
            Ok(SubscribeOutcome::Ready(sealed))
        }
    }

    /// Re-polls for a parked subscriber (already authenticated by [`Self::do_subscribe`]).
    /// Returns `Some(sealed)` when there are events, or when `force` (the timeout
    /// heartbeat — a sealed empty batch advancing the cursor to the tail); `None`
    /// when there is still nothing and the caller should keep waiting.
    fn do_collect_events(
        &self,
        member: Address,
        member_pk: PublicKey,
        last_seen: u64,
        nonce: u64,
        force: bool,
    ) -> Option<Vec<u8>> {
        let tail = self.tail_seq();
        let events = events::events_since(&self.db, &member, last_seen, tail);
        if events.is_empty() && !force {
            return None;
        }
        self.seal_subscribe_reply(&member_pk, nonce, tail, events)
    }

    /// Builds the subscribe response (`{last_seen_event_id, events}` as the
    /// `ResponseEnvelope.result` JSON), signs it as the station, and seals it to
    /// the member — mirroring the `/rpc` reply path.
    fn seal_subscribe_reply(
        &self,
        member_pk: &PublicKey,
        nonce: u64,
        tail: u64,
        events: Vec<Event>,
    ) -> Option<Vec<u8>> {
        let result =
            serde_json::json!({ "last_seen_event_id": tail, "events": events }).to_string();
        let response = ResponseEnvelope::ok(nonce, result);
        let station = self.station_keypair();
        let reply_frame = rpc_envelope::frame_signed_response(&response, &station);
        match sealed::seal(member_pk, &reply_frame, TRANSPORT_CONTEXT) {
            Ok(s) => Some(s.to_bytes()),
            Err(e) => {
                tracing::error!(error = %e, "failed to seal subscribe reply");
                None
            }
        }
    }

    /// Routes an authenticated envelope to the mobile-permitted method surface
    /// and wraps the outcome as a response envelope (a method-level failure
    /// becomes a sealed error, not a transport rejection).
    fn dispatch_channel_call(&mut self, envelope: &RequestEnvelope) -> ResponseEnvelope {
        match self.route_channel_method(envelope) {
            Ok(result) => ResponseEnvelope::ok(envelope.nonce, result.to_string()),
            Err((code, message)) => ResponseEnvelope::err(envelope.nonce, code, message),
        }
    }

    /// The mobile method allowlist, as an explicit match. Read methods route
    /// through the shared dispatch; the write methods (`submit_proposal` /
    /// `submit_confirmation`) need the *authenticated* signer — a mobile submits
    /// only records it itself signed as sender/receiver — so they are handled
    /// here rather than via the signer-less [`Self::handle_call`]. Everything
    /// else (operator, recovery, station-as-sender `propose`/`confirm`) is
    /// unreachable.
    fn route_channel_method(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        match envelope.method.as_str() {
            "submit_proposal" => self.channel_submit_proposal(envelope),
            "submit_confirmation" => self.channel_submit_confirmation(envelope),
            "submit_vouch" => self.channel_submit_vouch(envelope),
            "vouch_counts" => self.channel_vouch_counts(envelope),
            "list_vouches" => self.channel_list_vouches(envelope),
            "reputation" => self.channel_reputation(envelope),
            "reputation_band" => self.channel_reputation_band(envelope),
            "marketplace_search" => self.channel_marketplace_search(envelope),
            "marketplace_listing" => self.channel_marketplace_listing(envelope),
            "submit_listing" => self.channel_submit_listing(envelope),
            "submit_listing_close" => self.channel_submit_listing_close(envelope),
            "marketplace_my_listings" => self.channel_marketplace_my_listings(envelope),
            "whoami" | "balance" | "transactions" | "next_nonce" => {
                let params = serde_json::from_str(&envelope.params)
                    .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
                let req = rpc::Request {
                    id: envelope.nonce.to_string(),
                    method: envelope.method.clone(),
                    params,
                };
                self.handle_call(&req).map_err(|e| (e.code, e.message))
            }
            other => Err((
                rpc::METHOD_NOT_FOUND,
                format!("method not available to mobiles: {other}"),
            )),
        }
    }

    /// `submit_proposal` — accept a mobile-signed [`SignedProposal`] and append
    /// it. The member is the sender and signs it on the phone (ADR-0006); the
    /// station only validates and records. `params` carries the canonical dCBOR
    /// of the signed proposal, hex-encoded.
    fn channel_submit_proposal(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_proposal")?;
        let signed: SignedProposal = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed proposal".into()))?;
        // A mobile submits only its own transactions: the sender must be the
        // authenticated signer. (The engine independently checks the embedded
        // signature is by the sender; this binds it to *this* paired mobile.)
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "proposal sender is not the authenticated mobile".into(),
            ));
        }
        let now = self.clock.now();
        let tx_id = signed.payload.id;
        let mut engine = Engine::new(&self.db, self.station_keypair());
        engine
            .submit_proposal(signed, now)
            .map_err(ledger_err_pair)?;
        Ok(serde_json::json!({ "tx_id": hex(&tx_id.to_bytes()), "state": "Proposed" }))
    }

    /// `submit_confirmation` — accept a mobile-signed [`SignedConfirmation`] of a
    /// proposal the mobile is the receiver of.
    fn channel_submit_confirmation(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_confirmation")?;
        let signed: SignedConfirmation = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed confirmation".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "confirmer is not the authenticated mobile".into(),
            ));
        }
        let now = self.clock.now();
        let mut engine = Engine::new(&self.db, self.station_keypair());
        engine
            .submit_confirmation(signed, now)
            .map_err(ledger_err_pair)?;
        Ok(serde_json::json!({ "state": "Confirmed" }))
    }

    /// `submit_vouch` — accept a mobile-signed [`SignedVouch`] and append it. The
    /// voucher is the signer and signs it on the phone (ADR-0006); the station
    /// only validates and records. `params` carries the canonical dCBOR of the
    /// signed vouch, hex-encoded (as `submit_proposal` does for a proposal).
    fn channel_submit_vouch(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_vouch")?;
        let signed: SignedVouch = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed vouch".into()))?;
        // A mobile submits only vouches it signed: the voucher must be the
        // authenticated signer bound to this paired mobile.
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "voucher is not the authenticated mobile".into(),
            ));
        }
        // Verify the signature over the canonical payload before persisting.
        // Unlike a proposal there is no ledger engine to re-check it, so verify
        // it explicitly here.
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "vouch signature does not verify".into(),
            )
        })?;
        let vouch_id = hex(&signed.payload_hash().to_bytes());
        let mut log = AppendLog::new(&self.db);
        append_vouch(&mut log, signed).map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        Ok(serde_json::json!({ "vouch_id": vouch_id }))
    }

    /// `submit_listing` — accept a mobile-signed [`SignedListing`] and publish it
    /// (T1.7.2). The member is the provider and signs the listing on the phone,
    /// exactly as they sign a vouch; the station verifies the signature, that the
    /// signer is this paired mobile, and that the listing names this station's
    /// community, then leaves signer-is-provider, self-validity, and
    /// no-duplicate-id to [`append_listing_created`] — so the local write path and
    /// replay's `scan` agree by construction. `params` carries the canonical dCBOR
    /// of the signed listing, hex-encoded.
    fn channel_submit_listing(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_listing")?;
        let signed: rrn_marketplace::listing::SignedListing =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed listing".into()))?;
        // A mobile submits only listings it signed: the provider must be the
        // authenticated signer bound to this paired mobile.
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "provider is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "listing signature does not verify".into(),
            )
        })?;
        // A member publishes into the community this station serves, not an
        // arbitrary string they happened to sign — the same reason the operator
        // path stamps the community rather than taking it from the request.
        if signed.payload.community.as_str() != VOUCH_COMMUNITY {
            return Err((
                rpc::INVALID_PARAMS,
                format!(
                    "listing community {:?} is not this station's community",
                    signed.payload.community
                ),
            ));
        }
        let listing_id = signed.payload.id;
        let oracle_tier = signed.payload.oracle_tier;
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::lifecycle::append_listing_created(&mut log, signed)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        // Bring browse in step in the same call that published, as the operator
        // path does, so the listing is findable the moment the reply returns.
        self.reindex_listing(&listing_id);
        Ok(serde_json::json!({
            "listing_id": hex(&listing_id.to_bytes()),
            "oracle_tier": oracle_tier,
        }))
    }

    /// `submit_listing_close` — accept a mobile-signed [`SignedListingClose`] and
    /// take the member's own listing off offer (T1.7.2). A provider may only sign
    /// `ProviderClosed`; entitlement, existence, and not-already-closed are
    /// [`append_listing_closed`]'s to enforce.
    fn channel_submit_listing_close(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_listing_close")?;
        let signed: rrn_marketplace::lifecycle::SignedListingClose =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed close".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "closer is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "close signature does not verify".into(),
            )
        })?;
        let listing_id = signed.payload.listing_id;
        let station_pk = self.station_keypair().public_key();
        let mut log = AppendLog::new(&self.db);
        append_listing_closed(&mut log, signed, &station_pk)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        self.reindex_listing(&listing_id);
        Ok(serde_json::json!({
            "listing_id": hex(&listing_id.to_bytes()),
            "reason": "provider_closed",
        }))
    }

    /// `marketplace_my_listings` — the authenticated mobile's own listings, in
    /// whatever state, newest first (T1.7.2). The member is the signer, not a
    /// param, so a mobile only ever reads its own; the operator's socket keeps its
    /// station-scoped variant ([`Self::m_marketplace_my_listings`]).
    fn channel_marketplace_my_listings(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let address = Address::from_public_key(envelope.signer);
        let now = self.clock.now();
        let station = self.wallet.address.public_key();
        let listings = marketplace_view::my_listings(&self.db, &address, station, now)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        Ok(serde_json::json!({ "listings": listings }))
    }

    /// `vouch_counts` — the authenticated mobile's own vouching tallies (T1.4.4):
    /// how many vouches it has given (signed) and received (is the subject of).
    /// The member is the authenticated signer, not a param, so a mobile only ever
    /// reads its own counts. A live log scan (see [`vouch_view`]).
    fn channel_vouch_counts(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let member = Address::from_public_key(envelope.signer);
        let counts = vouch_view::member_vouch_counts(&self.db, &member)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        Ok(serde_json::json!({ "given": counts.given, "received": counts.received }))
    }

    /// `list_vouches` — the authenticated mobile's own vouches for the vouching
    /// browser (T1.4.5), split into `given` (it signed) and `received` (it is the
    /// subject of), newest first. The member is the authenticated signer, not a
    /// param, so a mobile only ever lists its own vouches. Optional `limit` /
    /// `offset` window each list (client-side search still sees the fetched set;
    /// see [`vouch_view::member_vouches`]). A live log scan.
    fn channel_list_vouches(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let member = Address::from_public_key(envelope.signer);
        // Params are optional: an empty body or `{}` lists everything.
        let params: serde_json::Value = if envelope.params.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&envelope.params)
                .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?
        };
        let limit = params.get("limit").and_then(|v| v.as_u64());
        let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
        let lists = vouch_view::member_vouches(&self.db, &member, limit, offset)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        serde_json::to_value(lists).map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))
    }

    /// `reputation` — the authenticated mobile's own standing (T1.5.9): the five
    /// ADR-0009 dimensions, the composite, the band, and whether an anchoring
    /// vouch has lifted the newcomer cap. The member is the authenticated signer,
    /// not a param, so a mobile only ever reads its own full profile; other
    /// members are visible only as a band (see [`Self::channel_reputation_band`]).
    /// Served from the snapshot cache (see [`reputation_view`]).
    fn channel_reputation(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let member = Address::from_public_key(envelope.signer);
        let now = self.clock.now();
        let view = reputation_view::member_reputation(&self.db, &member, now)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        serde_json::to_value(view).map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))
    }

    /// `reputation_band` — the band for an arbitrary `address` param, which is
    /// what a marketplace listing card shows about its lister (M1.7). Only the
    /// band and composite, never the dimension breakdown: what one member needs
    /// about another is whether to trade with them, not an audit of their
    /// history. An address with no history answers `New` rather than erroring.
    fn channel_reputation_band(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        #[derive(serde::Deserialize)]
        struct Params {
            address: String,
        }
        let params: Params = serde_json::from_str(&envelope.params)
            .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
        let address = parse_addr(&params.address).map_err(|e| (e.code, e.message))?;
        let now = self.clock.now();
        let view = reputation_view::address_band(&self.db, &address, now)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        serde_json::to_value(view).map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))
    }

    /// `marketplace_search` — the browse read (T1.7.1). Every filter is
    /// optional; an empty `{}` returns the most relevant page of everything on
    /// offer. Results are ranked by text relevance times the provider's standing
    /// (T1.6.6) and carry the provider's band inline, so a browse screen renders
    /// a page from one round trip (see [`marketplace_view`]).
    ///
    /// `limit` is clamped, not validated — a client asking for more than
    /// [`marketplace_view::MAX_SEARCH_LIMIT`] gets that many rather than an
    /// error, so no request can turn into an unbounded index read.
    fn channel_marketplace_search(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        // An empty body is a valid "show me everything" search.
        let params: rpc::SearchParams = if envelope.params.trim().is_empty() {
            serde_json::from_str("{}")
        } else {
            serde_json::from_str(&envelope.params)
        }
        .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
        self.run_marketplace_search(params)
            .map_err(|e| (e.code, e.message))
    }

    /// `marketplace_listing` — one listing in full, by hex `listing_id`
    /// (T1.7.1). Read from the log rather than the index, so a detail screen
    /// cannot be the place a stale cache is taken as authoritative.
    fn channel_marketplace_listing(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        #[derive(serde::Deserialize)]
        struct Params {
            listing_id: String,
        }
        let params: Params = serde_json::from_str(&envelope.params)
            .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
        self.run_marketplace_listing(&params.listing_id)
            .map_err(|e| (e.code, e.message))
    }

    /// The browse read itself, shared by the mobile channel and the CLI socket
    /// (T1.7.3). One query with one meaning however it arrived — the transports
    /// differ in who is asking, not in what browse is.
    fn run_marketplace_search(
        &self,
        params: rpc::SearchParams,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        // An unknown surface is refused rather than ignored: silently dropping
        // the filter would answer a question the caller did not ask.
        let surface = match params.surface.as_deref() {
            None => None,
            Some(tag) => Some(Surface::from_tag(tag).ok_or_else(|| {
                invalid_params(format!(
                    "unknown surface: {tag} (goods, services, or commons)"
                ))
            })?),
        };

        let default = SearchQuery::default();
        let query = SearchQuery {
            text: params.text,
            surface,
            category: params.category,
            max_price_centi: params.max_price_centi,
            min_provider_reputation: params.min_provider_reputation,
            limit: params.limit.unwrap_or(default.limit),
            offset: params.offset.unwrap_or(default.offset),
        };
        let now = self.clock.now();
        let listings =
            marketplace_view::search(&self.listings, &self.db, query, now).map_err(internal)?;
        ok(&serde_json::json!({ "listings": listings }))
    }

    /// The detail read itself, shared by both transports as
    /// [`Self::run_marketplace_search`] is.
    fn run_marketplace_listing(
        &self,
        listing_id: &str,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let listing_id = parse_listing_id(listing_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.wallet.address.public_key();
        match marketplace_view::detail(&self.db, &listing_id, station, now).map_err(internal)? {
            Some(view) => ok(&view),
            None => Err(invalid_params("no such listing on this station")),
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

/// Reads `last_seen_event_id` from a subscribe request's JSON `params`. A missing
/// or malformed cursor means "from the start" (0) — the station simply returns
/// everything the member has not acked, so a fresh subscriber sees its backlog.
fn parse_subscribe_cursor(params: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(params)
        .ok()
        .and_then(|v| v.get("last_seen_event_id").and_then(|n| n.as_u64()))
        .unwrap_or(0)
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

/// The oracle tier a listing at this price defaults to — the bottom of the M1.8
/// ladder for small trades, the next rung above it for the rest.
///
/// Phase 1 supports tiers 1 and 2 only
/// ([`ORACLE_TIER_MAX`](rrn_marketplace::listing::ORACLE_TIER_MAX)), so the
/// ladder's higher rungs cannot be suggested yet however large the amount: a
/// 500-Commons listing gets tier 2 and an explicit `--oracle-tier` is refused
/// above the range by `validate`. Commons-surface subsidies can be negative,
/// which the absolute value folds in with small trades where they belong.
fn suggest_oracle_tier(amount_centi: i64) -> u8 {
    // 5 Commons, the boundary the M1.8.2 ladder puts between tier 1 and tier 2.
    const TIER_2_FROM_CENTI: i64 = 500;
    if amount_centi.saturating_abs() < TIER_2_FROM_CENTI {
        1
    } else {
        2
    }
}

/// The availability a new listing records, given what the caller supplied.
///
/// The three surfaces mean different things by "available": Goods have a count,
/// Services have a next slot, and Commons have neither. Each surface keeps only
/// the field that means something to it, so a `--capacity` passed to a Services
/// listing is dropped rather than recorded as a number nothing will read.
/// `capacity: Some(0)` is honored as sold out, since that is a thing a provider
/// may legitimately say.
fn availability_for(
    surface: Surface,
    capacity: Option<u32>,
    next_slot: Option<i64>,
) -> rrn_marketplace::listing::Availability {
    use rrn_marketplace::listing::{Availability, AvailabilityStatus};
    let (capacity, next_slot) = match surface {
        Surface::Goods => (capacity, None),
        Surface::Services => (None, next_slot),
        Surface::Commons => (None, None),
    };
    let status = match capacity {
        Some(0) => AvailabilityStatus::Unavailable,
        _ => AvailabilityStatus::Available,
    };
    Availability {
        status,
        capacity,
        next_slot,
    }
}

/// Maps a marketplace error to an RPC error. A rule the caller's own request
/// broke — an unknown category, a listing that is not theirs to close, one
/// already closed — is their mistake to fix; only storage and index trouble is
/// ours.
fn marketplace_err(e: rrn_marketplace::Error) -> rpc::RpcError {
    use rrn_marketplace::Error::*;
    match e {
        Storage(_) | Tantivy(_) | Index(_) => internal(e),
        Listing(_) | Lifecycle(_) | Need(_) => invalid_params(e.to_string()),
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

/// The channel's `(code, message)` form of a ledger error — the same mapping as
/// [`ledger_err`], for the write-path handlers that build a response envelope.
fn ledger_err_pair(e: rrn_ledger::Error) -> (i32, String) {
    let r = ledger_err(e);
    (r.code, r.message)
}

/// Pulls a hex-string field out of a JSON `params` object and decodes it to
/// bytes, for the write-path handlers that carry a canonical-dCBOR record.
fn hex_param(params: &str, field: &str) -> Result<Vec<u8>, (i32, String)> {
    let value: serde_json::Value = serde_json::from_str(params)
        .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
    let hex_str = value.get(field).and_then(|v| v.as_str()).ok_or_else(|| {
        (
            rpc::INVALID_PARAMS,
            format!("missing string field: {field}"),
        )
    })?;
    unhex(hex_str).ok_or_else(|| (rpc::INVALID_PARAMS, format!("{field} is not hex")))
}

/// Parses a hex [`ListingId`] as it appears in a marketplace view, in the
/// `(code, message)` form the channel handlers build a response envelope from.
fn parse_listing_id(s: &str) -> Result<ListingId, (i32, String)> {
    let bytes =
        unhex(s).ok_or_else(|| (rpc::INVALID_PARAMS, "listing_id is not hex".to_string()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        (
            rpc::INVALID_PARAMS,
            "listing_id is not 32 bytes".to_string(),
        )
    })?;
    Ok(ListingId(Hash::from_bytes(bytes)))
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
            SearchIndex::in_memory(),
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

    // --- marketplace wiring (T1.7.0) ----------------------------------------

    use rrn_marketplace::lifecycle::append_listing_created;
    use rrn_marketplace::listing::{
        Availability, AvailabilityStatus, Listing, Pricing, PricingModel, Requirements,
    };

    /// The core's manual clock is at 1_000, so a listing created "now" with an
    /// expiry beyond it is on offer and one below it has expired.
    const NOW: i64 = 1_000;

    fn test_listing(provider: &Keypair, title: &str, expires_at: Option<i64>) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            "blue_ridge_collective".into(),
            Surface::Goods,
            "food".into(),
            title.into(),
            "Picked this week.".into(),
            Pricing {
                amount_centi: 250,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: Some(12),
                next_slot: None,
            },
            Requirements {
                min_reputation: 0.0,
                community_member_only: false,
                federation_only: false,
            },
            1,
            false,
            NOW - 100,
            expires_at,
        )
        .unwrap()
    }

    /// Publishes a listing straight onto the core's log, as a provider would, and
    /// brings the index up to date the way an append path will.
    fn publish(core: &mut Core, provider: &Keypair, listing: &Listing) {
        append_to_log(core, provider, listing);
        core.reindex_listing(&listing.id);
    }

    /// Appends a provider's signed listing and nothing else — no reindex. Scoped
    /// so the log's borrow of the core ends before the caller reads back.
    fn append_to_log(core: &Core, provider: &Keypair, listing: &Listing) {
        let mut log = AppendLog::new(&core.db);
        append_listing_created(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(listing.clone(), provider),
        )
        .unwrap();
    }

    /// A channel envelope for `method` with `params`, signed by `signer`. The
    /// marketplace read methods authorize on nothing but being a paired mobile,
    /// so the envelope's other fields do not matter to them.
    fn envelope(signer: &Keypair, method: &str, params: serde_json::Value) -> RequestEnvelope {
        RequestEnvelope {
            method: method.into(),
            params: params.to_string(),
            signer: signer.public_key(),
            recipient: signer.public_key(),
            nonce: 1,
            timestamp: NOW,
        }
    }

    #[test]
    fn marketplace_search_finds_a_published_listing_with_its_providers_band() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Winter squash, by the crate", None);
        publish(&mut core, &provider, &listing);

        let env = envelope(&provider, "marketplace_search", serde_json::json!({}));
        let result = core.route_channel_method(&env).unwrap();
        let listings = result["listings"].as_array().unwrap();

        assert_eq!(listings.len(), 1);
        assert_eq!(listings[0]["title"], "Winter squash, by the crate");
        assert_eq!(listings[0]["surface"], "goods");
        assert_eq!(listings[0]["amount_centi"], 250);
        // The card carries the band inline so a browse page is one round trip. An
        // unscored provider reads as `New`, which is what they are.
        assert_eq!(listings[0]["provider_band"], "New");
    }

    #[test]
    fn marketplace_search_filters_by_surface_and_refuses_an_unknown_one() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Winter squash", None);
        publish(&mut core, &provider, &listing);

        // The listing is Goods, so a Services tab must not show it.
        let env = envelope(
            &provider,
            "marketplace_search",
            serde_json::json!({ "surface": "services" }),
        );
        let result = core.route_channel_method(&env).unwrap();
        assert!(result["listings"].as_array().unwrap().is_empty());

        // An unknown surface is an error, not a silently-dropped filter: the
        // caller would otherwise get an answer to a question they did not ask.
        let env = envelope(
            &provider,
            "marketplace_search",
            serde_json::json!({ "surface": "livestock" }),
        );
        let (code, message) = core.route_channel_method(&env).unwrap_err();
        assert_eq!(code, rpc::INVALID_PARAMS);
        assert!(message.contains("livestock"), "{message}");
    }

    #[test]
    fn marketplace_search_clamps_an_oversized_limit() {
        let mut core = test_core();
        let provider = Keypair::generate();
        // One more listing than the clamp allows through, so the clamp is what
        // decides the page size rather than the corpus.
        for i in 0..(marketplace_view::MAX_SEARCH_LIMIT + 1) {
            let listing = test_listing(&provider, &format!("Crate {i} of squash"), None);
            publish(&mut core, &provider, &listing);
        }

        let env = envelope(
            &provider,
            "marketplace_search",
            serde_json::json!({ "limit": 100_000 }),
        );
        let result = core.route_channel_method(&env).unwrap();
        assert_eq!(
            result["listings"].as_array().unwrap().len(),
            marketplace_view::MAX_SEARCH_LIMIT
        );
    }

    #[test]
    fn marketplace_listing_reads_one_in_full_and_rejects_an_unknown_id() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Winter squash", None);
        publish(&mut core, &provider, &listing);

        let env = envelope(
            &provider,
            "marketplace_listing",
            serde_json::json!({ "listing_id": hex(&listing.id.to_bytes()) }),
        );
        let result = core.route_channel_method(&env).unwrap();
        assert_eq!(result["title"], "Winter squash");
        assert_eq!(result["description"], "Picked this week.");
        assert_eq!(result["community"], "blue_ridge_collective");
        assert_eq!(result["state"], "active");
        assert_eq!(result["oracle_tier"], 1);

        let env = envelope(
            &provider,
            "marketplace_listing",
            serde_json::json!({ "listing_id": hex(&[0u8; 32]) }),
        );
        let (code, _) = core.route_channel_method(&env).unwrap_err();
        assert_eq!(code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn expiry_sweep_closes_a_past_expiry_listing_and_drops_it_from_browse() {
        let mut core = test_core();
        let provider = Keypair::generate();
        // Expired at the core's clock: on the log, past its expiry, no close
        // record yet — the `Expired` state the sweep exists to convert.
        let listing = test_listing(&provider, "Last week's squash", Some(NOW - 10));
        append_to_log(&core, &provider, &listing);

        assert_eq!(core.do_expire_listings(), 1);

        // The close is on the log, station-signed, and says why.
        let station = core.wallet.address.public_key();
        let state = rrn_marketplace::lifecycle::compute_state(
            &AppendLog::new(&core.db),
            &listing.id,
            station,
            NOW,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            state,
            ListingState::Closed {
                reason: CloseReason::ExpirationReached,
                ..
            }
        ));

        // And browse no longer offers it.
        let env = envelope(&provider, "marketplace_search", serde_json::json!({}));
        let result = core.route_channel_method(&env).unwrap();
        assert!(result["listings"].as_array().unwrap().is_empty());

        // Nothing left to close: the sweep is idempotent.
        assert_eq!(core.do_expire_listings(), 0);
    }

    #[test]
    fn expiry_sweep_leaves_a_listing_that_is_still_on_offer() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Next week's squash", Some(NOW + 10_000));
        publish(&mut core, &provider, &listing);

        assert_eq!(core.do_expire_listings(), 0);
        let env = envelope(&provider, "marketplace_search", serde_json::json!({}));
        let result = core.route_channel_method(&env).unwrap();
        assert_eq!(result["listings"].as_array().unwrap().len(), 1);
    }

    // --- operator marketplace (T1.7.3) --------------------------------------

    /// A CLI-style call: the operator's socket, no envelope and no signer, since
    /// the station's own wallet is the identity every write here is signed by.
    fn call(core: &mut Core, method: &str, params: serde_json::Value) -> serde_json::Value {
        let req = rpc::Request {
            id: "1".into(),
            method: method.into(),
            params,
        };
        core.handle_call(&req).unwrap()
    }

    fn call_err(core: &mut Core, method: &str, params: serde_json::Value) -> rpc::RpcError {
        let req = rpc::Request {
            id: "1".into(),
            method: method.into(),
            params,
        };
        core.handle_call(&req).unwrap_err()
    }

    /// The params a `rrn list` invocation sends for a plain Goods listing.
    fn create_params(title: &str) -> serde_json::Value {
        serde_json::json!({
            "surface": "goods",
            "category": "food",
            "title": title,
            "description": "Picked this week.",
            "amount_centi": 250,
            "capacity": 12,
        })
    }

    #[test]
    fn cli_creates_a_listing_that_browse_finds_immediately() {
        let mut core = test_core();
        let created = call(
            &mut core,
            "marketplace_create_listing",
            create_params("Squash"),
        );
        let listing_id = created["listing_id"].as_str().unwrap().to_string();
        assert_eq!(listing_id.len(), 64, "a content address in hex");

        // Findable in the same process, without waiting for the boot rebuild —
        // the create path reindexes rather than leaving that to the next start.
        let browsed = call(&mut core, "marketplace_search", serde_json::Value::Null);
        let rows = browsed["listings"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["title"], "Squash");
        assert_eq!(rows[0]["listing_id"], listing_id);
        // The station is the provider on this path: an operator's listing is
        // published under the station's own identity.
        assert_eq!(rows[0]["provider"], core.wallet.address.to_string());

        // And the detail read agrees with the card.
        let detail = call(
            &mut core,
            "marketplace_listing",
            serde_json::json!({ "listing_id": listing_id }),
        );
        assert_eq!(detail["state"], "active");
        assert_eq!(detail["description"], "Picked this week.");
        assert_eq!(detail["availability"]["capacity"], 12);
    }

    #[test]
    fn a_created_listings_oracle_tier_follows_the_price_unless_it_is_given() {
        let mut core = test_core();
        // Under 5 Commons → tier 1; at or above → tier 2 (the M1.8.2 ladder).
        let mut params = create_params("Cheap squash");
        params["amount_centi"] = serde_json::json!(499);
        assert_eq!(
            call(&mut core, "marketplace_create_listing", params)["oracle_tier"],
            1
        );

        let mut params = create_params("Dear squash");
        params["amount_centi"] = serde_json::json!(500);
        assert_eq!(
            call(&mut core, "marketplace_create_listing", params)["oracle_tier"],
            2
        );

        // An explicit tier overrides the suggestion.
        let mut params = create_params("Squash, tier by hand");
        params["amount_centi"] = serde_json::json!(100);
        params["oracle_tier"] = serde_json::json!(2);
        assert_eq!(
            call(&mut core, "marketplace_create_listing", params)["oracle_tier"],
            2
        );

        // And one outside the Phase-1 range is the caller's mistake.
        let mut params = create_params("Squash, tier 9");
        params["oracle_tier"] = serde_json::json!(9);
        assert_eq!(
            call_err(&mut core, "marketplace_create_listing", params).code,
            rpc::INVALID_PARAMS
        );
    }

    #[test]
    fn creating_a_listing_refuses_a_bad_surface_category_and_price() {
        let mut core = test_core();

        let mut params = create_params("Squash");
        params["surface"] = serde_json::json!("livestock");
        let err = call_err(&mut core, "marketplace_create_listing", params);
        assert_eq!(err.code, rpc::INVALID_PARAMS);
        assert!(err.message.contains("livestock"), "{}", err.message);

        let mut params = create_params("Squash");
        params["category"] = serde_json::json!("cryptocurrency");
        let err = call_err(&mut core, "marketplace_create_listing", params);
        assert_eq!(err.code, rpc::INVALID_PARAMS);
        assert!(err.message.contains("cryptocurrency"), "{}", err.message);

        // A negative price is a subsidy, legal only on the Commons surface.
        let mut params = create_params("Squash, but we pay you");
        params["amount_centi"] = serde_json::json!(-250);
        assert_eq!(
            call_err(&mut core, "marketplace_create_listing", params).code,
            rpc::INVALID_PARAMS
        );

        let mut params = create_params("Watch the grain store");
        params["surface"] = serde_json::json!("commons");
        params["amount_centi"] = serde_json::json!(-250);
        call(&mut core, "marketplace_create_listing", params);
    }

    #[test]
    fn availability_keeps_only_what_the_surface_means_by_it() {
        let mut core = test_core();
        // A Services listing's capacity is dropped and its slot kept; the Goods
        // case is covered by the create test above.
        let mut params = create_params("Cart repair, by appointment");
        params["surface"] = serde_json::json!("services");
        params["category"] = serde_json::json!("tools");
        params["next_slot"] = serde_json::json!(NOW + 3_600);
        let created = call(&mut core, "marketplace_create_listing", params);

        let detail = call(
            &mut core,
            "marketplace_listing",
            serde_json::json!({ "listing_id": created["listing_id"] }),
        );
        assert!(detail["availability"]["capacity"].is_null());
        assert_eq!(detail["availability"]["next_slot"], NOW + 3_600);

        // Zero units is a provider saying "sold out", not an error.
        let mut params = create_params("Squash, all gone");
        params["capacity"] = serde_json::json!(0);
        let created = call(&mut core, "marketplace_create_listing", params);
        let detail = call(
            &mut core,
            "marketplace_listing",
            serde_json::json!({ "listing_id": created["listing_id"] }),
        );
        assert_eq!(detail["availability"]["status"], "unavailable");
    }

    #[test]
    fn closing_a_listing_takes_it_off_browse_and_keeps_it_in_my_listings() {
        let mut core = test_core();
        let created = call(
            &mut core,
            "marketplace_create_listing",
            create_params("Squash"),
        );
        let listing_id = created["listing_id"].as_str().unwrap().to_string();

        let closed = call(
            &mut core,
            "marketplace_close_listing",
            serde_json::json!({ "listing_id": listing_id }),
        );
        // Never `expiration_reached`: a station may not claim a provider
        // withdrew, and this path is the provider withdrawing.
        assert_eq!(closed["reason"], "provider_closed");

        let browsed = call(&mut core, "marketplace_search", serde_json::Value::Null);
        assert!(browsed["listings"].as_array().unwrap().is_empty());

        // Off offer but not gone: a closed listing that vanished would read as
        // deleted to the provider who closed it.
        let mine = call(
            &mut core,
            "marketplace_my_listings",
            serde_json::Value::Null,
        );
        let rows = mine["listings"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["state"], "closed");
        assert_eq!(rows[0]["close_reason"], "provider_closed");

        // Closing it twice is the caller's mistake, reported as such.
        let err = call_err(
            &mut core,
            "marketplace_close_listing",
            serde_json::json!({ "listing_id": listing_id }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn closing_someone_elses_listing_is_refused() {
        let mut core = test_core();
        // Published by another member, so the station is not its provider.
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Not yours to withdraw", None);
        publish(&mut core, &provider, &listing);

        let err = call_err(
            &mut core,
            "marketplace_close_listing",
            serde_json::json!({ "listing_id": hex(&listing.id.to_bytes()) }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
        // Still on offer.
        let browsed = call(&mut core, "marketplace_search", serde_json::Value::Null);
        assert_eq!(browsed["listings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn my_listings_shows_only_the_stations_own_newest_first() {
        let mut core = test_core();
        let other = Keypair::generate();
        let theirs = test_listing(&other, "Someone else's squash", None);
        publish(&mut core, &other, &theirs);

        // The core's clock does not move, so both of these are created at NOW and
        // the tie-break on listing id is what orders them deterministically.
        call(
            &mut core,
            "marketplace_create_listing",
            create_params("Mine A"),
        );
        call(
            &mut core,
            "marketplace_create_listing",
            create_params("Mine B"),
        );

        let mine = call(
            &mut core,
            "marketplace_my_listings",
            serde_json::Value::Null,
        );
        let rows = mine["listings"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "another member's listing is not mine");
        let titles: Vec<&str> = rows.iter().map(|r| r["title"].as_str().unwrap()).collect();
        assert!(titles.contains(&"Mine A") && titles.contains(&"Mine B"));
        for row in rows {
            assert_eq!(row["provider"], core.wallet.address.to_string());
            assert_eq!(row["state"], "active");
        }
    }

    #[test]
    fn a_need_matches_the_listing_that_answers_it() {
        let mut core = test_core();
        // Someone else is offering food; the station announces it wants food.
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Winter squash, by the crate", None);
        publish(&mut core, &provider, &listing);

        let announced = call(
            &mut core,
            "marketplace_announce_need",
            serde_json::json!({
                "category": "food",
                "quantity_needed": 6,
                "max_price_centi": 300,
                "valid_until": NOW + 10_000,
            }),
        );
        let seq = announced["seq"].as_u64().unwrap();
        assert!(seq > 0, "a need is named by its log seq");

        let matched = call(&mut core, "marketplace_matches", serde_json::Value::Null);
        let needs = matched["needs"].as_array().unwrap();
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0]["seq"], seq);
        assert_eq!(needs[0]["expired"], false);
        let listings = needs[0]["listings"].as_array().unwrap();
        assert_eq!(listings.len(), 1);
        assert_eq!(listings[0]["title"], "Winter squash, by the crate");

        // Asking for that one need by seq is the same answer.
        let one = call(
            &mut core,
            "marketplace_matches",
            serde_json::json!({ "seq": seq }),
        );
        assert_eq!(one["needs"].as_array().unwrap().len(), 1);

        // A seq that is not one of ours is a caller mistake, not an empty list.
        let err = call_err(
            &mut core,
            "marketplace_matches",
            serde_json::json!({ "seq": 9_999 }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn a_needs_price_ceiling_and_expiry_both_bound_its_matches() {
        let mut core = test_core();
        let provider = Keypair::generate();
        // Priced at 250 by `test_listing`.
        let listing = test_listing(&provider, "Winter squash", None);
        publish(&mut core, &provider, &listing);

        // A ceiling under the asking price matches nothing.
        call(
            &mut core,
            "marketplace_announce_need",
            serde_json::json!({
                "category": "food",
                "quantity_needed": 1,
                "max_price_centi": 100,
                "valid_until": NOW + 10_000,
            }),
        );
        // An expired need matches nothing whatever is on offer, and says why.
        call(
            &mut core,
            "marketplace_announce_need",
            serde_json::json!({
                "category": "food",
                "quantity_needed": 1,
                "valid_until": NOW - 1,
            }),
        );

        let matched = call(&mut core, "marketplace_matches", serde_json::Value::Null);
        let needs = matched["needs"].as_array().unwrap();
        assert_eq!(needs.len(), 2);
        assert_eq!(needs[0]["expired"], false);
        assert!(needs[0]["listings"].as_array().unwrap().is_empty());
        assert_eq!(needs[1]["expired"], true);
        assert!(needs[1]["listings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn announcing_a_need_refuses_an_unknown_category_and_a_zero_quantity() {
        let mut core = test_core();
        let err = call_err(
            &mut core,
            "marketplace_announce_need",
            serde_json::json!({
                "category": "cryptocurrency",
                "quantity_needed": 1,
                "valid_until": NOW + 10_000,
            }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);

        let err = call_err(
            &mut core,
            "marketplace_announce_need",
            serde_json::json!({
                "category": "food",
                "quantity_needed": 0,
                "valid_until": NOW + 10_000,
            }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn the_cli_and_the_mobile_read_the_same_browse() {
        let mut core = test_core();
        call(
            &mut core,
            "marketplace_create_listing",
            create_params("Squash"),
        );

        // Same query, two transports, one answer — the point of routing both
        // through `run_marketplace_search`.
        let over_socket = call(&mut core, "marketplace_search", serde_json::json!({}));
        let mobile = Keypair::generate();
        let env = envelope(&mobile, "marketplace_search", serde_json::json!({}));
        let over_channel = core.route_channel_method(&env).unwrap();
        assert_eq!(over_socket, over_channel);
    }

    #[test]
    fn browse_over_the_socket_clamps_an_oversized_limit_too() {
        let mut core = test_core();
        let provider = Keypair::generate();
        for i in 0..(marketplace_view::MAX_SEARCH_LIMIT + 1) {
            let listing = test_listing(&provider, &format!("Crate {i} of squash"), None);
            publish(&mut core, &provider, &listing);
        }
        let browsed = call(
            &mut core,
            "marketplace_search",
            serde_json::json!({ "limit": 100_000 }),
        );
        assert_eq!(
            browsed["listings"].as_array().unwrap().len(),
            marketplace_view::MAX_SEARCH_LIMIT
        );
    }

    #[test]
    fn a_replicated_listing_reaches_browse_but_an_impostors_does_not() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Winter squash", None);

        // Arriving by gossip rather than by a local append — the path that
        // bypasses every append guard.
        let signed = rrn_crypto::signed::SignedPayload::sign(listing.clone(), &provider);
        let entry = WireEntry {
            signer: signed.signer.to_bytes().to_vec(),
            signature: signed.signature.to_bytes().to_vec(),
            bytes: to_canonical_bytes(listing.clone()),
        };
        assert_eq!(core.do_append_entries(vec![entry]), 1);

        let env = envelope(&provider, "marketplace_search", serde_json::json!({}));
        let result = core.route_channel_method(&env).unwrap();
        assert_eq!(result["listings"].as_array().unwrap().len(), 1);

        // A listing someone else signed in the provider's name is validly
        // *signed* — so gossip accepts the entry — and is still not a listing,
        // because replay refuses a creation record whose signer is not the
        // provider. It must not reach browse.
        let impostor = Keypair::generate();
        let forged = test_listing(&provider, "Squash that is not on offer", None);
        let signed = rrn_crypto::signed::SignedPayload::sign(forged.clone(), &impostor);
        let entry = WireEntry {
            signer: signed.signer.to_bytes().to_vec(),
            signature: signed.signature.to_bytes().to_vec(),
            bytes: to_canonical_bytes(forged),
        };
        assert_eq!(core.do_append_entries(vec![entry]), 1);

        let result = core.route_channel_method(&env).unwrap();
        let listings = result["listings"].as_array().unwrap();
        assert_eq!(listings.len(), 1);
        assert_eq!(listings[0]["title"], "Winter squash");
    }

    #[test]
    fn the_index_is_rebuilt_from_the_log_at_startup() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let listing = test_listing(&provider, "Winter squash", None);

        // Appended with no reindex — the state a station is in when its index
        // directory was deleted, or written by a version that did not maintain
        // one. Browse is empty until the rebuild runs.
        append_to_log(&core, &provider, &listing);

        let env = envelope(&provider, "marketplace_search", serde_json::json!({}));
        let before = core.route_channel_method(&env).unwrap();
        assert!(before["listings"].as_array().unwrap().is_empty());

        core.rebuild_listing_index();

        let after = core.route_channel_method(&env).unwrap();
        assert_eq!(after["listings"].as_array().unwrap().len(), 1);
    }
}
