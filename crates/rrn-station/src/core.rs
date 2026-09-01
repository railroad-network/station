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

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::mpsc;

use tokio::sync::{oneshot, watch};

use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_dispute::escalation::{
    EscalationBallot, EscalationReason, EscalationRecord, SignedEscalation, SignedEscalationBallot,
};
use rrn_dispute::resolution::{
    append_escalation_ballot, append_verdict, find_disputed, open_escalation, resolve, Resolution,
};
use rrn_dispute::verdict::{JurorVerdict, SignedVerdict};
use rrn_dispute::DisputeParams;
use rrn_governance::charter::{
    create_charter, latest_charter, store_charter, store_pending_charter, CharterParams,
    SignedCharter,
};
use rrn_governance::proposal::{
    append_cosign, append_proposal, Proposal, ProposalCosign, ProposalId, ProposalKind,
};
use rrn_governance::tally::effective_charter;
use rrn_governance::vote::{append_vote, Vote, VoteChoice};
use rrn_identity::address::Address;
use rrn_identity::recovery::flow::{reconstruct_wallet, RecoveryPackage};
use rrn_identity::recovery::shamir::{RawShard, ShardIndex};
use rrn_identity::vouch::{append_vouch, create_vouch, SignedVouch};
use rrn_identity::wallet::WalletContents;
use rrn_ledger::contract::{ContractCharge, ContractRef};
use rrn_ledger::dispute::{DisputeRecord, DisputeResponse, SignedDispute, SignedDisputeResponse};
use rrn_ledger::engine::Engine;
use rrn_ledger::settlement::{SettlementConfig, Settler};
use rrn_ledger::state::TransactionState;
use rrn_ledger::transaction::{
    ListingRef, SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId,
    TransactionProposal,
};
use rrn_marketplace::contract::{
    all_contract_records, append_service_contract, ContractId, ContractState, ContractTermination,
    ContractTerms, EndReason, ServiceContract, TerminatedBy,
};
use rrn_marketplace::lifecycle::{
    append_listing_closed, append_stock_consumed, touched_listing, CloseReason, ListingClosed,
    ListingState, StockConsumed,
};
use rrn_marketplace::listing::{Listing, ListingId, Surface};
use rrn_marketplace::search::{SearchIndex, SearchQuery};
use rrn_storage::db::Database;
use rrn_storage::dtn::{DtnStore, NoteOutcome};
use rrn_storage::log::{AppendLog, StoredPayload};

use rrn_protocol::bundle::Bundle;
use rrn_protocol::outbox;
use rrn_protocol::receipt::{
    self, DeliveryReceipt, Disposition, Outcome, RefusalReason, SignedReceipt,
};

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::signed::SignedPayload;

use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};

use crate::clock::Clock;
use crate::contract_view;
use crate::dispute_view;
use crate::events::{self, Event};
use crate::gossip::WireEntry;
use crate::governance_view;
use crate::inquiry_view;
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
    /// Close every inquiry gone quiet past [`INQUIRY_TTL_SECS`](rrn_marketplace::inquiry::INQUIRY_TTL_SECS)
    /// with a station-signed `InquiryClosed { Expired }`; reply with the number
    /// closed (T1.7.4).
    ExpireInquiries {
        /// Count of inquiries closed.
        reply: oneshot::Sender<usize>,
    },
    /// Charge every service contract's periods that have fallen due with a
    /// station-signed [`ContractCharge`], plus the early-termination penalty of a
    /// contract whose notice window has closed; reply with the number of charge
    /// records appended (T1.7.7).
    ChargeContracts {
        /// Count of charge records appended.
        reply: oneshot::Sender<usize>,
    },
    /// Put every passed proposal whose implementation delay has run into force with
    /// a station-signed `ProposalImplemented`; reply with the number enacted (T1.9.7).
    EnactGovernance {
        /// Count of proposals enacted.
        reply: oneshot::Sender<usize>,
    },
    /// Resolve every disputed transaction whose jury has reached a majority, and
    /// lapse (settle as confirmed) any whose window has closed unresolved; reply
    /// with the number of disputes given a terminal outcome (T1.10.5).
    ResolveDisputes {
        /// Count of disputes resolved (upheld, rejected, or lapsed) this pass.
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

    /// Triggers the inquiry-expiry sweep; returns the number closed.
    pub async fn expire_inquiries(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::ExpireInquiries { reply }).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Triggers the service-contract charge sweep; returns the number of charge
    /// records appended.
    pub async fn charge_contracts(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::ChargeContracts { reply }).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Triggers the governance-enactment sweep; returns the number of proposals
    /// put into force.
    pub async fn enact_governance(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::EnactGovernance { reply }).is_err() {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Triggers the dispute-resolution sweep; returns the number of disputes given
    /// a terminal outcome (upheld, rejected, or lapsed).
    pub async fn resolve_disputes(&self) -> usize {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(Command::ResolveDisputes { reply }).is_err() {
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
    /// The debt floor the transaction engine enforces (ADR-0018).
    credit: rrn_ledger::credit::CreditConfig,
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
        credit: rrn_ledger::credit::CreditConfig,
        clock: Clock,
        paired: PairedMobiles,
        listings: SearchIndex,
    ) -> Self {
        let (tail_tx, _) = watch::channel(0u64);
        Core {
            db,
            wallet,
            settlement,
            credit,
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
                Command::ExpireInquiries { reply } => {
                    let n = self.do_expire_inquiries();
                    let _ = reply.send(n);
                }
                Command::ChargeContracts { reply } => {
                    let n = self.do_charge_contracts();
                    let _ = reply.send(n);
                }
                Command::EnactGovernance { reply } => {
                    let n = self.do_enact_governance();
                    let _ = reply.send(n);
                }
                Command::ResolveDisputes { reply } => {
                    let n = self.do_resolve_disputes();
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
            "marketplace_edit_listing" => self.m_marketplace_edit_listing(req),
            "marketplace_close_listing" => self.m_marketplace_close_listing(req),
            "marketplace_my_listings" => self.m_marketplace_my_listings(),
            "marketplace_announce_need" => self.m_marketplace_announce_need(req),
            "marketplace_matches" => self.m_marketplace_matches(req),
            "marketplace_inquire" => self.m_marketplace_inquire(req),
            "marketplace_inquiry_message" => self.m_marketplace_inquiry_message(req),
            "marketplace_inquiry_close" => self.m_marketplace_inquiry_close(req),
            "marketplace_inquiry_thread" => self.m_marketplace_inquiry_thread(req),
            "marketplace_my_inquiries" => self.m_marketplace_my_inquiries(),
            "marketplace_settle_inquiry" => self.m_marketplace_settle_inquiry(req),
            "marketplace_contract" => self.m_marketplace_contract(req),
            "marketplace_contracts" => self.m_marketplace_contracts(),
            "marketplace_contract_show" => self.m_marketplace_contract_show(req),
            "marketplace_contract_terminate" => self.m_marketplace_contract_terminate(req),
            // Operator-facing governance (T1.9.7b). Reads answer with the same
            // views the mobile channel serves; the writes are signed by this
            // station's own wallet, as `propose` and `vouch` are.
            "governance_charter" => self.m_governance_charter(),
            "governance_proposals" => self.m_governance_proposals(),
            "governance_proposal" => self.m_governance_proposal(req),
            "governance_statutes" => self.m_governance_statutes(),
            "governance_init_charter" => self.m_governance_init_charter(req),
            "governance_charter_begin" => self.m_governance_charter_begin(req),
            "governance_pending_charter" => self.m_governance_pending_charter(),
            "governance_add_charter_signature" => self.m_governance_add_charter_signature(req),
            "governance_charter_sign" => self.m_governance_charter_sign(req),
            "governance_propose" => self.m_governance_propose(req),
            "governance_cosign" => self.m_governance_cosign(req),
            "governance_vote" => self.m_governance_vote(req),
            // Operator-facing disputes (T1.10.5). Reads answer with the same
            // views the mobile channel serves; the writes are signed by this
            // station's own wallet, as `propose` and `vouch` are.
            "disputes" => self.m_disputes(),
            "dispute" => self.m_dispute(req),
            "dispute_raise" => self.m_dispute_raise(req),
            "dispute_respond" => self.m_dispute_respond(req),
            "dispute_rule" => self.m_dispute_rule(req),
            "dispute_resolve" => self.m_dispute_resolve(req),
            "dispute_escalate" => self.m_dispute_escalate(req),
            "dispute_escalation_vote" => self.m_dispute_escalation_vote(req),
            // Operator-facing pairing management (T1.3.3), invoked by the
            // `station` binary over this same Unix socket.
            "pair_list_pending" => self.m_pair_list_pending(),
            "pair_confirm" => self.m_pair_confirm(req),
            "list_mobiles" => self.m_list_mobiles(),
            "unpair" => self.m_unpair(req),
            // DTN bundle ingest (T2.2.3, ADR-0020): the operator/courier hands the
            // station a bundle over the Unix socket; the station admits each
            // carried record through the same engine front doors the live path
            // uses and answers with one signed delivery receipt.
            "bundle_submit" => self.m_bundle_submit(req),
            other => Err(rpc::RpcError {
                code: rpc::METHOD_NOT_FOUND,
                message: format!("unknown method: {other}"),
            }),
        }
    }

    fn m_whoami(&self) -> Result<serde_json::Value, rpc::RpcError> {
        // Bootstrap-grace status (T1.8.6, widened in T1.11.2/ADR-0015): while fewer
        // than the threshold of members are established, the community runs under
        // grace across all three subsystems at once — any member may confirm a
        // Tier-2 payment, and the genesis founders stand in as the electorate for
        // governance and dispute juries. `bootstrap_in_grace` is exactly the shared
        // `in_grace` predicate; the count is derived from the log, so it always
        // reflects current standing and the phone can render its grace banner
        // without recomputing it.
        let established =
            rrn_reputation::staking::established_member_count(&self.db, self.clock.now())
                .map_err(internal)?;
        let threshold = rrn_reputation::staking::BOOTSTRAP_GRACE_THRESHOLD;
        ok(&rpc::WhoamiResult {
            address: self.wallet.address.to_string(),
            community: VOUCH_COMMUNITY.to_string(),
            bootstrap_in_grace: established < threshold,
            established_members: established as u64,
            grace_threshold: threshold as u64,
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

        let mut proposal = TransactionProposal::new(
            self.wallet.address,
            receiver,
            params.amount_centi,
            params.memo,
            nonce,
            now,
            now + PROPOSAL_TTL_SECS,
        );
        // Honor a sender's opt-up to a higher oracle tier (T1.8.1). `with_tier`
        // drops a request that is not a genuine lift, so a plain pay stays at its
        // amount-derived floor and its bytes are unchanged from before this field.
        if let Some(tier) = params.oracle_tier {
            proposal = proposal.with_tier(tier);
        }
        let tx_id = proposal.id;
        let signed: SignedProposal = SignedProposal::sign(proposal, &station);

        let mut engine = Engine::new(&self.db, station).with_credit_config(self.credit);
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

        // A Tier-2 transaction is confirmed by staking reputation on it (T1.8.2):
        // the confirmer must be an established member, or the community must still
        // be inside its bootstrap grace. Shared with the mobile and DTN paths via
        // `tier2_confirmation_gate`.
        if let Some((composite, established)) = self
            .tier2_confirmation_gate(&tx_id, &self.wallet.address, now)
            .map_err(internal)?
        {
            let member_floor = rrn_reputation::model::BAND_MEMBER_MIN;
            return Err(invalid_params(format!(
                "cannot confirm a Tier-2 payment: your standing is {composite:.2}, \
                 below the Member band ({member_floor:.1}) the community now \
                 requires ({established} members are established, so the bootstrap \
                 grace has ended)"
            )));
        }

        let confirmation = TransactionConfirmation {
            proposal_id: tx_id,
            confirmer: self.wallet.address,
            confirmed_at: now,
        };
        let signed: SignedConfirmation = SignedConfirmation::sign(confirmation, &station);

        let mut engine = Engine::new(&self.db, station).with_credit_config(self.credit);
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
        let log = AppendLog::new(&self.db);
        let snapshot = rrn_ledger::state::LedgerSnapshot::derive(&log).map_err(internal)?;
        let station_pk = self.station_keypair().public_key();
        let transactions = transaction_view::member_transactions(
            &snapshot,
            &member,
            params.limit,
            &log,
            &station_pk,
            &self.settlement,
        );
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
        let now = self.clock.now();
        let mut log = AppendLog::new(&self.db);
        append_vouch(&mut log, vouch, now).map_err(internal)?;

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
        // The operator socket is anonymous for eligibility — whoever holds the
        // key is not a marketplace member with a standing to weigh.
        self.run_marketplace_listing(&params.listing_id, None)
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

        // A recurring service carries the standing terms a later contract
        // snapshots. `with_recurring` re-derives the id but does not re-validate,
        // so check the whole listing again — this is where "recurring only on a
        // service" and the duration/penalty rules are enforced at the boundary.
        let listing = match params.every {
            Some(ref every) => {
                let terms = recurring_terms_from(
                    every,
                    params.periods,
                    params.notice_days,
                    params.penalty_centi,
                )?;
                let listing = listing.with_recurring(terms);
                listing
                    .validate()
                    .map_err(|e| invalid_params(e.to_string()))?;
                listing
            }
            None => listing,
        };

        let listing_id = listing.id;
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::lifecycle::append_listing_created(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(listing, &station),
            now,
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
            now,
        )
        .map_err(marketplace_err)?;
        self.reindex_listing(&listing_id);

        ok(&rpc::CloseListingResult {
            listing_id: params.listing_id,
            reason: "provider_closed".into(),
        })
    }

    /// `marketplace_edit_listing` — apply a provider patch to one of the station's
    /// own listings (T1.7.2 Phase B). The listing's content id is fixed at
    /// publication; an update references it and changes only what a
    /// [`ListingPatch`](rrn_marketplace::lifecycle::ListingPatch) permits —
    /// pricing, description, availability, expiry. The current listing is read
    /// back so a partial edit (say, only `--price`) keeps every field the caller
    /// did not mention. `append_listing_updated` re-runs signer-is-provider,
    /// not-closed, non-empty-patch, and the patched listing's own validity.
    fn m_marketplace_edit_listing(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        use rrn_marketplace::lifecycle::{ExpiryPatch, ListingPatch, ListingUpdated};
        use rrn_marketplace::listing::{Pricing, PricingModel};
        let params: rpc::EditListingParams = parse_params(req)?;
        let listing_id = parse_listing_id(&params.listing_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let station = self.station_keypair();
        let station_pk = station.public_key();

        let mut log = AppendLog::new(&self.db);
        let records = rrn_marketplace::lifecycle::listing_records(&log, &listing_id, &station_pk)
            .map_err(marketplace_err)?;
        let current = records
            .current()
            .ok_or_else(|| invalid_params(format!("no such listing: {}", params.listing_id)))?;

        // Pricing: patch only when a price or model override was given, carrying
        // the untouched half from the current listing so `--price` alone keeps the
        // model (and a model flip alone keeps the amount).
        let pricing = if params.amount_centi.is_some() || params.negotiable.is_some() {
            let negotiable = params.negotiable.unwrap_or(current.pricing.negotiable);
            Some(Pricing {
                amount_centi: params.amount_centi.unwrap_or(current.pricing.amount_centi),
                model: if negotiable {
                    PricingModel::Negotiable
                } else {
                    PricingModel::Fixed
                },
                negotiable,
            })
        } else {
            None
        };

        // Availability: rebuild from the current values with the given override,
        // clamped to what the surface allows (goods=capacity, services=next_slot).
        let availability = if params.capacity.is_some() || params.next_slot.is_some() {
            let capacity = params.capacity.or(current.availability.capacity);
            let next_slot = params.next_slot.or(current.availability.next_slot);
            Some(availability_for(current.surface, capacity, next_slot))
        } else {
            None
        };

        let expires_at = if params.clear_expiry.unwrap_or(false) {
            ExpiryPatch::Clear
        } else if let Some(t) = params.expires_at {
            ExpiryPatch::Set(t)
        } else {
            ExpiryPatch::Unchanged
        };

        let patch = ListingPatch {
            pricing,
            description: params.description,
            availability,
            expires_at,
        };
        let update = ListingUpdated {
            listing_id,
            patch,
            signed_by: self.wallet.address,
        };
        let now = self.clock.now();
        rrn_marketplace::lifecycle::append_listing_updated(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(update, &station),
            &station_pk,
            now,
        )
        .map_err(marketplace_err)?;
        self.reindex_listing(&listing_id);

        ok(&rpc::EditListingResult {
            listing_id: params.listing_id,
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
        let now = self.clock.now();
        let entry = rrn_marketplace::need::append_need_announced(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(need, &station),
            now,
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

    /// `marketplace_inquire` — open a station-signed inquiry against a listing.
    ///
    /// The station wallet is the buyer, which on the operator's socket is the
    /// operator themselves (a member inquires from a phone with their own key,
    /// T1.7.4). The listing's requirements are checked against the operator's own
    /// standing, so an operator below a listing's floor is refused just as a
    /// member would be.
    fn m_marketplace_inquire(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::InquireParams = parse_params(req)?;
        let listing_id = parse_listing_id(&params.listing_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let listing = self
            .active_listing_for_inquiry(&listing_id, now)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let station = self.station_keypair();
        let opened = rrn_marketplace::inquiry::InquiryOpened::new(
            listing_id,
            self.wallet.address,
            params.message,
            params.offer_centi,
            now,
        )
        .map_err(|e| invalid_params(e.to_string()))?;
        let composite = marketplace_view::capped_composite(&self.db, &self.wallet.address, now);
        let in_community = listing.community == VOUCH_COMMUNITY;
        let inquiry_id = opened.inquiry_id;

        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::inquiry::append_inquiry_opened(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(opened, &station),
            &listing,
            composite,
            in_community,
            now,
        )
        .map_err(marketplace_err)?;
        ok(&rpc::InquireResult {
            inquiry_id: hex(&inquiry_id.to_bytes()),
        })
    }

    /// `marketplace_inquiry_message` — send a station-signed message (optionally a
    /// counter-offer) in an inquiry the station is a party to.
    fn m_marketplace_inquiry_message(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::InquiryMessageParams = parse_params(req)?;
        let inquiry_id = parse_inquiry_id(&params.inquiry_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let message = rrn_marketplace::inquiry::InquiryMessage {
            inquiry_id,
            sender: self.wallet.address,
            body: params.message,
            counter_offer_centi: params.counter_offer_centi,
            sent_at: now,
        };
        let admits = self.inquiry_admits(now);
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::inquiry::append_inquiry_message(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(message, &station),
            &station_pk,
            &admits,
            now,
        )
        .map_err(marketplace_err)?;
        ok(&rpc::InquireResult {
            inquiry_id: params.inquiry_id,
        })
    }

    /// `marketplace_inquiry_close` — end an inquiry the station is a party to:
    /// agree on a price, or decline the station's own side. `expired` is not
    /// available here — that outcome belongs to the sweep alone.
    fn m_marketplace_inquiry_close(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::InquiryCloseParams = parse_params(req)?;
        let inquiry_id = parse_inquiry_id(&params.inquiry_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let admits = self.inquiry_admits(now);

        // Resolve the inquiry to learn the station's role (which decline) and the
        // listed price (the fallback for an `agreed` with no explicit price).
        let records = {
            let log = AppendLog::new(&self.db);
            rrn_marketplace::inquiry::inquiry_records(&log, &inquiry_id, &station_pk, &admits)
                .map_err(internal)?
                .ok_or_else(|| invalid_params("no such inquiry on this station"))?
        };
        let me = self.wallet.address;
        let outcome = match params.outcome.as_str() {
            "agreed" => rrn_marketplace::inquiry::InquiryOutcome::Agreed {
                final_price_centi: params
                    .final_price_centi
                    .unwrap_or(records.listing.pricing.amount_centi),
            },
            "declined" if records.buyer() == me => {
                rrn_marketplace::inquiry::InquiryOutcome::DeclinedByBuyer
            }
            "declined" if records.provider() == me => {
                rrn_marketplace::inquiry::InquiryOutcome::DeclinedBySeller
            }
            "declined" => return Err(invalid_params("not a party to this inquiry")),
            other => {
                return Err(invalid_params(format!(
                    "unknown outcome {other:?} (agreed or declined)"
                )))
            }
        };

        let record = rrn_marketplace::inquiry::InquiryClosed {
            inquiry_id,
            outcome,
            closed_at: now,
        };
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::inquiry::append_inquiry_closed(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(record, &station),
            &station_pk,
            &admits,
            now,
        )
        .map_err(marketplace_err)?;
        ok(&rpc::InquiryStateResult {
            inquiry_id: params.inquiry_id,
            state: "closed".into(),
        })
    }

    /// `marketplace_inquiry_thread` — one inquiry the station is a party to.
    fn m_marketplace_inquiry_thread(
        &self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::InquiryThreadParams = parse_params(req)?;
        self.run_inquiry_thread(&params.inquiry_id, self.wallet.address)
    }

    /// `marketplace_my_inquiries` — every inquiry the station is a party to.
    fn m_marketplace_my_inquiries(&self) -> Result<serde_json::Value, rpc::RpcError> {
        self.run_my_inquiries(self.wallet.address)
    }

    /// `marketplace_contract` — sign up to a recurring service, born from an
    /// agreed inquiry (T1.7.7).
    ///
    /// The station wallet is the buyer, which on the operator's socket is the
    /// operator themselves (a member signs their own contract from a phone in
    /// Stage 2). The terms are snapshotted from the agreed inquiry — the listing's
    /// standing cadence and the price the two parties settled on — so the request
    /// chooses nothing but the free-form notes: everything binding was already
    /// agreed. [`append_service_contract`] re-checks all of it against the log.
    /// `marketplace_settle_inquiry` — pay for an agreed inquiry (T1.7.6), the CLI
    /// counterpart of the mobile "Send payment" step. The station wallet must be
    /// the inquiry's buyer; the payment is a station-signed, listing-linked
    /// proposal at the granted price, which the provider then confirms through the
    /// ordinary M0.5 flow. Idempotent: a payment already on the log for this
    /// agreement is returned rather than duplicated.
    fn m_marketplace_settle_inquiry(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::SettleInquiryParams = parse_params(req)?;
        let inquiry_id = parse_inquiry_id(&params.inquiry_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let admits = self.inquiry_admits(now);
        let me = self.wallet.address;

        // Resolve the agreed inquiry: only its buyer pays, only the price the
        // provider granted, to the provider, linked to the listing.
        let inquiry = {
            let log = AppendLog::new(&self.db);
            rrn_marketplace::inquiry::inquiry_records(&log, &inquiry_id, &station_pk, &admits)
                .map_err(internal)?
                .ok_or_else(|| invalid_params("no such inquiry on this station"))?
        };
        if inquiry.buyer() != me {
            return Err(invalid_params("only the inquiry's buyer can settle it"));
        }
        let final_price_centi = match inquiry.closed.as_ref().map(|c| c.outcome) {
            Some(rrn_marketplace::inquiry::InquiryOutcome::Agreed { final_price_centi }) => {
                final_price_centi
            }
            _ => return Err(invalid_params("that inquiry is not agreed")),
        };
        let provider = inquiry.provider();
        let listing_ref = ListingRef(inquiry.listing.id.to_bytes());
        // Mirror the mobile memo so the two paths read alike in history and share
        // one double-pay key: the listing title, then a short slice of the id.
        let memo = format!(
            "{} · #{}",
            inquiry.listing.title,
            &hex(&inquiry_id.to_bytes())[..8]
        );

        let snapshot = rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&self.db))
            .map_err(internal)?;

        // Idempotency: if a payment for this agreement is already on the log, return
        // it instead of signing a second one — the station-side of the guard the
        // mobile thread applies before offering the button. The memo is the key on
        // both sides, so a re-run (or a mobile that already paid) can't double-pay.
        if let Some((tx_id, state)) = snapshot.iter().find_map(|(id, state)| {
            let p = proposal_of(state)?;
            (p.memo.as_deref() == Some(memo.as_str()))
                .then(|| (hex(&id.to_bytes()), state_name(state).to_string()))
        }) {
            return ok(&rpc::ProposeResult { tx_id, state });
        }

        let nonce = snapshot.next_nonce(&me.public_key().to_bytes());
        let proposal = TransactionProposal::new(
            me,
            provider,
            final_price_centi,
            Some(memo),
            nonce,
            now,
            now + PROPOSAL_TTL_SECS,
        )
        .with_listing(listing_ref)
        // Carry the listing's declared oracle tier onto the payment as an opt-up
        // (T1.8.1): a Tier-2 listing (e.g. a low-value medical consult) lifts an
        // otherwise Tier-1 amount up to Tier 2. `with_tier` drops the request when
        // it is not a genuine lift, so a Tier-1 listing or an amount already at
        // the listing's tier leaves the proposal at its amount-derived floor.
        .with_tier(inquiry.listing.oracle_tier);
        let tx_id = proposal.id;
        let signed: SignedProposal = SignedProposal::sign(proposal, &station);

        let mut engine = Engine::new(&self.db, station).with_credit_config(self.credit);
        engine.submit_proposal(signed, now).map_err(ledger_err)?;

        ok(&rpc::ProposeResult {
            tx_id: hex(&tx_id.to_bytes()),
            state: "Proposed".into(),
        })
    }

    fn m_marketplace_contract(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::ContractParams = parse_params(req)?;
        let inquiry_id = parse_inquiry_id(&params.inquiry_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let admits = self.inquiry_admits(now);

        // Resolve the agreed inquiry to snapshot the terms the contract commits to:
        // the listing's standing cadence and the price the grant settled on.
        let inquiry = {
            let log = AppendLog::new(&self.db);
            rrn_marketplace::inquiry::inquiry_records(&log, &inquiry_id, &station_pk, &admits)
                .map_err(internal)?
                .ok_or_else(|| invalid_params("no such inquiry on this station"))?
        };
        let recurring = inquiry
            .listing
            .recurring
            .ok_or_else(|| invalid_params("that inquiry's listing is not a recurring service"))?;
        let final_price_centi = match inquiry.closed.as_ref().map(|c| c.outcome) {
            Some(rrn_marketplace::inquiry::InquiryOutcome::Agreed { final_price_centi }) => {
                final_price_centi
            }
            _ => return Err(invalid_params("that inquiry is not agreed")),
        };

        let terms = ContractTerms {
            frequency: recurring.frequency,
            duration_periods: recurring.duration_periods,
            commons_per_period_centi: final_price_centi,
            performance_metrics: params.metrics,
            notice_period_days: recurring.notice_period_days,
            early_termination_penalty_centi: recurring.early_termination_penalty_centi,
        };
        let contract = ServiceContract::new(
            inquiry_id,
            inquiry.listing.id,
            self.wallet.address,
            inquiry.provider(),
            terms,
            now,
        )
        .map_err(|e| invalid_params(e.to_string()))?;
        let contract_id = contract.contract_id;

        let mut log = AppendLog::new(&self.db);
        append_service_contract(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(contract, &station),
            &station_pk,
            &admits,
            now,
        )
        .map_err(marketplace_err)?;

        // A fresh contract has charged nothing, so it stands `active` at `now`.
        ok(&rpc::ContractStateResult {
            contract_id: hex(&contract_id.to_bytes()),
            state: "active".into(),
        })
    }

    /// `marketplace_contracts` — every contract the station is a party to.
    fn m_marketplace_contracts(&self) -> Result<serde_json::Value, rpc::RpcError> {
        self.run_my_contracts(self.wallet.address)
    }

    /// `marketplace_contract_show` — one contract the station is a party to.
    fn m_marketplace_contract_show(
        &self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::ContractShowParams = parse_params(req)?;
        self.run_contract_detail(&params.contract_id, self.wallet.address)
    }

    /// `marketplace_contract_terminate` — end a contract the station is a party
    /// to. Either party may; the notice window (and any penalty) is the charge
    /// sweep's to apply.
    fn m_marketplace_contract_terminate(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::ContractTerminateParams = parse_params(req)?;
        let contract_id = parse_contract_id(&params.contract_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let admits = self.inquiry_admits(now);

        // Resolve the contract to learn which side the station is on — the record
        // must claim the party that actually signed it.
        let records = {
            let log = AppendLog::new(&self.db);
            rrn_marketplace::contract::contract_records(&log, &contract_id, &station_pk, &admits)
                .map_err(internal)?
                .ok_or_else(|| invalid_params("no such contract on this station"))?
        };
        let me = self.wallet.address;
        let terminated_by = if records.buyer() == me {
            TerminatedBy::Buyer
        } else if records.provider() == me {
            TerminatedBy::Provider
        } else {
            return Err(invalid_params("not a party to this contract"));
        };

        let record = ContractTermination {
            contract_id,
            terminated_by,
            requested_at: now,
        };
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::contract::append_contract_termination(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(record, &station),
            &station_pk,
            &admits,
            now,
        )
        .map_err(marketplace_err)?;

        // Report where it now stands — within its notice window (`terminating`) or
        // already past it (`ended`) — by re-reading the contract with the
        // termination on the log.
        let state = {
            let log = AppendLog::new(&self.db);
            let records = rrn_marketplace::contract::contract_records(
                &log,
                &contract_id,
                &station_pk,
                &admits,
            )
            .map_err(internal)?
            .ok_or_else(|| internal("contract vanished after termination"))?;
            let charged = charged_periods_by_contract(&log);
            let periods_charged =
                periods_charged_of(&charged, &contract_id, records.total_periods());
            records.state(now, periods_charged).tag()
        };
        ok(&rpc::ContractStateResult {
            contract_id: params.contract_id,
            state: state.into(),
        })
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

    /// Settles every transaction whose window has closed, and — for a settled
    /// marketplace payment — attests the sale against its listing (T1.7.6 Stage
    /// B): one settled, listing-linked payment consumes one unit of stock.
    fn do_sweep(&mut self) -> usize {
        let now = self.clock.now();

        // Which transactions are due, and the listing each marketplace one pays
        // for — captured from the snapshot *before* settling, since settling
        // changes it. A direct pay carries no link and settles as it always has.
        let due: Vec<(TransactionId, Option<ListingId>)> = {
            let log = AppendLog::new(&self.db);
            let snapshot = match rrn_ledger::state::LedgerSnapshot::derive(&log) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "settlement sweep could not read the log");
                    return 0;
                }
            };
            let settler = Settler::new(&self.db, self.station_keypair(), self.settlement);
            match settler.find_eligible(now) {
                Ok(ids) => ids
                    .into_iter()
                    .map(|id| (id, snapshot.get(&id).and_then(linked_listing)))
                    .collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "settlement sweep: find_eligible failed");
                    return 0;
                }
            }
        };

        let mut settled = 0;
        for (tx_id, listing_id) in due {
            let mut settler = Settler::new(&self.db, self.station_keypair(), self.settlement);
            if let Err(e) = settler.settle(&tx_id, now) {
                tracing::warn!(error = %e, tx = ?tx_id, "could not settle a transaction");
                continue;
            }
            settled += 1;
            if let Some(listing_id) = listing_id {
                self.attest_sale(listing_id, tx_id, now);
            }
        }
        settled
    }

    /// Appends a station-signed [`StockConsumed`] for a settled marketplace
    /// payment, and refreshes the listing in browse. Only a listing still on
    /// offer that *tracks* stock is decremented — a service slot, a commons
    /// offer, or an already-closed listing has no unit to take, so nothing is
    /// written for it. A duplicate would be inert anyway (state counts distinct
    /// transactions), so a race here costs at most a redundant record.
    fn attest_sale(&mut self, listing_id: ListingId, tx_id: TransactionId, now: i64) {
        let station = self.station_keypair();
        let station_pk = station.public_key();

        let log = AppendLog::new(&self.db);
        let tracks_stock = matches!(
            rrn_marketplace::lifecycle::compute_state(&log, &listing_id, &station_pk, now),
            Ok(Some(ListingState::Active(ref l))) if l.availability.capacity.is_some()
        );
        if !tracks_stock {
            return;
        }

        let record = StockConsumed {
            listing_id,
            tx_id,
            consumed_at: now,
        };
        let mut log = AppendLog::new(&self.db);
        match append_stock_consumed(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(record, &station),
            &station_pk,
            now,
        ) {
            Ok(_) => self.reindex_listing(&listing_id),
            Err(e) => tracing::warn!(error = %e, "could not attest a sale"),
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
                now,
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

    /// Closes every inquiry gone quiet past the TTL with a station-signed
    /// `InquiryClosed { Expired }` (T1.7.4), mirroring [`Self::do_expire_listings`].
    ///
    /// Inquiries are not indexed, so there is nothing to drop from a cache here —
    /// this only writes the terminal record a stale thread already reads as. A
    /// close that races a party's own decline is a fine outcome: the inquiry is
    /// closed either way, and the loser's append is refused as already-closed.
    fn do_expire_inquiries(&mut self) -> usize {
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let admits = self.inquiry_admits(now);

        let stale: Vec<rrn_marketplace::inquiry::InquiryId> = {
            let log = AppendLog::new(&self.db);
            match rrn_marketplace::inquiry::all_inquiry_records(&log, &station_pk, &admits) {
                Ok(all) => all
                    .into_iter()
                    .filter(|(_, records)| records.is_stale(now))
                    .map(|(id, _)| id)
                    .collect(),
                Err(e) => {
                    tracing::warn!(error = %e, "inquiry expiry sweep could not read the log");
                    return 0;
                }
            }
        };
        if stale.is_empty() {
            return 0;
        }

        let mut closed = 0;
        for inquiry_id in stale {
            let record = rrn_marketplace::inquiry::InquiryClosed {
                inquiry_id,
                outcome: rrn_marketplace::inquiry::InquiryOutcome::Expired,
                closed_at: now,
            };
            let mut log = AppendLog::new(&self.db);
            match rrn_marketplace::inquiry::append_inquiry_closed(
                &mut log,
                rrn_crypto::signed::SignedPayload::sign(record, &station),
                &station_pk,
                &admits,
                now,
            ) {
                Ok(_) => closed += 1,
                Err(e) => tracing::warn!(error = %e, "could not close an expired inquiry"),
            }
        }
        closed
    }

    /// Executes every service contract's due periods as direct debits, and levies
    /// the early-termination penalty on a terminated contract once its notice
    /// window has closed (T1.7.7 Part D).
    ///
    /// The buyer's one `ServiceContract` signature pre-authorized every period, so
    /// no party is present to sign the individual charges: the station appends a
    /// station-signed [`ContractCharge`] per due period, exactly as it signs a
    /// settlement no transacting party is present for. `periods_charged` — the
    /// count this crate treats as an input — is read back from the ledger's own
    /// charge records, not held anywhere, so a boot-time re-sweep replays the same
    /// verdict and the `(contract_ref, period_index)` idempotency key in the
    /// balance fold makes a re-charge inert.
    ///
    /// A charge that races a duplicate (a gossiped record, an overlapping sweep)
    /// costs at most a redundant log entry that folds to nothing.
    fn do_charge_contracts(&mut self) -> usize {
        let now = self.clock.now();
        let station = self.station_keypair();
        let station_pk = station.public_key();
        let admits = self.inquiry_admits(now);

        // Every contract on the log, and — per contract — the period indices the
        // ledger has already charged, captured in one pass before we append.
        let (contracts, charged) = {
            let log = AppendLog::new(&self.db);
            let contracts = match all_contract_records(&log, &station_pk, &admits) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "contract charge sweep could not read the log");
                    return 0;
                }
            };
            (contracts, charged_periods_by_contract(&log))
        };

        let mut appended = 0;
        for (id, records) in contracts {
            let contract_ref = ContractRef(id.to_bytes());
            let already = charged.get(&contract_ref).cloned().unwrap_or_default();

            // A real period's index is `< total_periods`; the penalty rides a
            // sentinel index so it never counts as a period nor collides with one.
            let total = records.total_periods();
            let mut periods_charged = already.iter().filter(|&&p| p < total).count() as u32;

            // Catch up every period due since the last sweep — after downtime a
            // contract can owe several at once.
            while let Some(index) = records.next_due_charge(now, periods_charged) {
                let charge = ContractCharge {
                    contract_ref,
                    buyer: records.buyer(),
                    provider: records.provider(),
                    amount_centi: records.contract.terms.commons_per_period_centi,
                    period_index: index,
                    charged_at: now,
                };
                if !self.append_contract_charge(charge, &station, now) {
                    break;
                }
                appended += 1;
                periods_charged += 1;
            }

            // Once, after the notice window closes on an early termination, levy
            // the penalty on whoever ended it: the buyer pays the provider (the
            // usual direction), or the provider pays the buyer (the reversed sign
            // the balance fold reads as provider→buyer). A contract that ran its
            // full course reads `Completed`, never `Terminated`, so it never pays.
            let penalty = records.contract.terms.early_termination_penalty_centi;
            let penalty_due = penalty > 0 && !already.contains(&PENALTY_PERIOD_INDEX);
            if penalty_due {
                if let ContractState::Ended {
                    reason: EndReason::Terminated { by, early: true },
                    ..
                } = records.state(now, periods_charged)
                {
                    let amount_centi = match by {
                        TerminatedBy::Buyer => penalty,
                        TerminatedBy::Provider => -penalty,
                    };
                    let charge = ContractCharge {
                        contract_ref,
                        buyer: records.buyer(),
                        provider: records.provider(),
                        amount_centi,
                        period_index: PENALTY_PERIOD_INDEX,
                        charged_at: now,
                    };
                    if self.append_contract_charge(charge, &station, now) {
                        appended += 1;
                    }
                }
            }
        }
        appended
    }

    /// Appends one station-signed [`ContractCharge`], returning whether it landed.
    /// The station is the only party that can produce a valid one, so — like a
    /// settlement record — it needs no append-time entitlement guard beyond the
    /// signature; the balance fold's per-period dedup absorbs any duplicate.
    fn append_contract_charge(&self, charge: ContractCharge, station: &Keypair, now: i64) -> bool {
        match AppendLog::new(&self.db).append(
            rrn_crypto::signed::SignedPayload::sign(charge, station),
            now,
        ) {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!(error = %e, "could not append a contract charge");
                false
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
        // Listings a replicated entry claims to be about, so the browse index
        // can be brought back in step below. Collected rather than reindexed
        // inline because each reindex replays the log, and a gossip round can
        // carry many records for one listing.
        let mut touched: Vec<ListingId> = Vec::new();
        // Replicas re-stamp admission time from their own clock (ADR-0022 §1);
        // one reading for the whole gossip round is fine — the log's monotone
        // clamp keeps them non-decreasing in receipt order.
        let now = self.clock.now();
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
            match log.append_raw(stored, now) {
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

    // --- governance (T1.9.7b) ----------------------------------------------

    fn m_governance_charter(&self) -> Result<serde_json::Value, rpc::RpcError> {
        ok(&governance_view::charter_view(&self.db).map_err(internal)?)
    }

    fn m_governance_proposals(&self) -> Result<serde_json::Value, rpc::RpcError> {
        let proposals =
            governance_view::proposals_view(&self.db, self.clock.now()).map_err(internal)?;
        Ok(serde_json::json!({ "proposals": proposals }))
    }

    fn m_governance_proposal(
        &self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovProposalParams = parse_params(req)?;
        let id = parse_proposal_id(&params.proposal_id)?;
        match governance_view::proposal_view(&self.db, &id, self.clock.now()).map_err(internal)? {
            Some(detail) => ok(&detail),
            None => Err(invalid_params(format!(
                "no proposal {}",
                params.proposal_id
            ))),
        }
    }

    fn m_governance_statutes(&self) -> Result<serde_json::Value, rpc::RpcError> {
        let statutes = governance_view::statutes_view(&self.db).map_err(internal)?;
        Ok(serde_json::json!({ "statutes": statutes }))
    }

    /// `governance_init_charter` — create and publish the genesis Charter. With no
    /// founder keys the station wallet is the sole founder (the solo bootstrap);
    /// otherwise the supplied secret keys are the founding set (T1.9.7b).
    fn m_governance_init_charter(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovInitCharterParams = parse_params(req)?;
        let station = self.station_keypair();
        let now = self.clock.now();

        let founders: Vec<Keypair> = if params.founder_secrets_hex.is_empty() {
            vec![station.clone()]
        } else {
            let mut keys = Vec::with_capacity(params.founder_secrets_hex.len());
            for h in &params.founder_secrets_hex {
                keys.push(parse_secret_keypair(h)?);
            }
            keys
        };

        let charter_params = CharterParams {
            version: 1,
            community_id: params.community_id,
            founding_principles: params.founding_principles,
            rights_floor: params.rights_floor,
            governance_structure: rrn_governance::charter::GovernanceStructure::default(),
            amendment_rules: rrn_governance::charter::AmendmentRules::default(),
            founders: founders
                .iter()
                .map(|k| Address::from_public_key(k.public_key()))
                .collect(),
            created_at: now,
            previous_hash: None,
        };
        let signed =
            create_charter(charter_params, &founders).map_err(|e| invalid_params(e.to_string()))?;
        let charter_hash = signed.charter_hash().to_string();
        let version = signed.charter().version;

        let mut log = AppendLog::new(&self.db);
        store_charter(&mut log, &station, signed, now)
            .map_err(|e| invalid_params(e.to_string()))?;
        ok(&rpc::GovCharterResult {
            charter_hash,
            version,
        })
    }

    /// `governance_charter_begin` — open a distributed founding ceremony. The
    /// operator declares the founders **by address** (not by secret key), so
    /// founders who hold their keys on a phone can take part: the coordinator
    /// station fixes the Charter body (including a single `created_at`), adds its
    /// own signature if it is itself a founder, and appends it as a *pending*
    /// Charter. Each remaining founder then signs the same body on their own
    /// device and submits the signature (`governance_submit_charter_signature`
    /// over the channel, or `governance_add_charter_signature` locally); the
    /// Charter publishes automatically once the founder threshold is met.
    fn m_governance_charter_begin(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovCharterBeginParams = parse_params(req)?;
        if latest_charter(&self.db).map_err(internal)?.is_some() {
            return Err(invalid_params(
                "a charter already exists for this community (pending or published)",
            ));
        }
        let station = self.station_keypair();
        let now = self.clock.now();

        let mut founders = Vec::with_capacity(params.founders.len());
        for a in &params.founders {
            founders.push(parse_addr(a)?);
        }

        let charter_params = CharterParams {
            version: 1,
            community_id: params.community_id,
            founding_principles: params.founding_principles,
            rights_floor: params.rights_floor,
            governance_structure: rrn_governance::charter::GovernanceStructure::default(),
            amendment_rules: rrn_governance::charter::AmendmentRules::default(),
            founders,
            created_at: now,
            previous_hash: None,
        };
        // The coordinator co-signs at once only if it is itself a declared founder.
        let self_signer: Vec<Keypair> = if charter_params.founders.contains(&self.wallet.address) {
            vec![station.clone()]
        } else {
            vec![]
        };
        let signed = create_charter(charter_params, &self_signer)
            .map_err(|e| invalid_params(e.to_string()))?;

        let mut log = AppendLog::new(&self.db);
        store_pending_charter(&mut log, &station, signed.clone(), now)
            .map_err(|e| invalid_params(e.to_string()))?;
        ok(&self.pending_charter_view(&signed))
    }

    /// `governance_pending_charter` — the state of the founding ceremony: the
    /// Charter body being signed, which founders have signed, the threshold, and
    /// whether it has published. `None` before any `charter-begin`.
    fn m_governance_pending_charter(&self) -> Result<serde_json::Value, rpc::RpcError> {
        match latest_charter(&self.db).map_err(internal)? {
            Some(signed) => ok(&self.pending_charter_view(&signed)),
            None => ok(&serde_json::json!({ "exists": false })),
        }
    }

    /// `governance_add_charter_signature` — ingest a founder signature collected
    /// out of band (e.g. another station founder ran `governance charter-sign`).
    /// The channel path (`channel_governance_submit_charter_signature`) is the
    /// same logic keyed off the authenticated mobile instead.
    fn m_governance_add_charter_signature(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovAddCharterSignatureParams = parse_params(req)?;
        let signer = parse_pubkey_hex(&params.signer_pubkey_hex)?;
        let signature = parse_signature_hex(&params.signature_hex)?;
        let signed = self
            .ingest_charter_signature(signer, signature)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        ok(&self.pending_charter_view(&signed))
    }

    /// `governance_charter_sign` — sign a Charter body's canonical bytes with this
    /// station's own wallet, returning the `(signer, signature)` pair. A founder
    /// station runs this on the body the coordinator shares (its `body_hex`) and
    /// hands the signature back — the CLI counterpart of a phone signing over the
    /// channel. It signs the supplied bytes and does not itself touch the log.
    fn m_governance_charter_sign(
        &self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovCharterSignParams = parse_params(req)?;
        let body = unhex(params.charter_body_hex.trim())
            .ok_or_else(|| invalid_params("charter_body_hex is not valid hex"))?;
        // Round-trips the body so a mistyped blob is caught, not silently signed.
        from_canonical_bytes::<rrn_governance::charter::Charter>(&body)
            .map_err(|_| invalid_params("charter_body_hex is not a valid Charter body"))?;
        let station = self.station_keypair();
        let signature = station.sign(&body);
        ok(&rpc::GovCharterSignResult {
            signer_pubkey_hex: hex(&station.public_key().to_bytes()),
            signature_hex: hex(&signature.to_bytes()),
        })
    }

    /// Adds one founder's remote signature to the pending Charter and re-appends
    /// it, publishing (a threshold-clearing append) once enough founders have
    /// signed. Shared by the local and channel entry points; returns the updated
    /// Charter.
    fn ingest_charter_signature(
        &mut self,
        signer: PublicKey,
        signature: Signature,
    ) -> Result<SignedCharter, (i32, String)> {
        let mut signed = latest_charter(&self.db)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?
            .ok_or_else(|| {
                (
                    rpc::INVALID_PARAMS,
                    "no founding charter in progress; run governance charter-begin".to_string(),
                )
            })?;
        if signed.verify_founders().is_ok() {
            return Err((
                rpc::INVALID_PARAMS,
                "the charter has already published; no more signatures are needed".to_string(),
            ));
        }
        signed
            .add_remote_signature(signer, signature)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        let station = self.station_keypair();
        let now = self.clock.now();
        let mut log = AppendLog::new(&self.db);
        // Threshold-clearing appends publish (verify_founders holds); short of it,
        // the Charter stays pending — both are the same append, gated on reads.
        store_pending_charter(&mut log, &station, signed.clone(), now)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        Ok(signed)
    }

    /// Renders a Charter (pending or published) as the ceremony view.
    fn pending_charter_view(&self, signed: &SignedCharter) -> rpc::GovPendingCharterResult {
        let charter = signed.charter();
        let founders: Vec<String> = charter.founders.iter().map(|a| a.to_string()).collect();
        let signed_founders: Vec<String> = signed
            .signed_founders()
            .iter()
            .map(|a| a.to_string())
            .collect();
        rpc::GovPendingCharterResult {
            exists: true,
            published: signed.verify_founders().is_ok(),
            charter_hash: signed.charter_hash().to_string(),
            community_id: charter.community_id.clone(),
            founding_principles: charter.founding_principles.clone(),
            rights_floor: charter.rights_floor.clone(),
            founders,
            signed_founders,
            threshold: rrn_governance::charter::founder_threshold(charter.founders.len()),
            created_at: charter.created_at,
            version: charter.version,
            body_hex: hex(&to_canonical_bytes(charter.clone())),
        }
    }

    /// `governance_propose` — author a proposal signed by the station wallet. The
    /// author must be an established member, as the governance guard enforces.
    fn m_governance_propose(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovProposeParams = parse_params(req)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let charter = effective_charter(&self.db)
            .map_err(internal)?
            .ok_or_else(|| invalid_params("no charter published; run governance charter-init"))?;
        let kind = parse_proposal_kind(&params)?;
        let proposal = Proposal::new(
            self.wallet.address,
            params.title,
            params.body,
            kind,
            now,
            &charter,
        )
        .map_err(|e| invalid_params(e.to_string()))?;
        let proposal_id = proposal.proposal_id.to_string();

        let mut log = AppendLog::new(&self.db);
        append_proposal(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(proposal, &station),
            &self.db,
            now,
        )
        .map_err(|e| invalid_params(e.to_string()))?;
        ok(&rpc::GovProposeResult { proposal_id })
    }

    /// `governance_cosign` — endorse a proposal, signed by the station wallet.
    fn m_governance_cosign(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovCosignParams = parse_params(req)?;
        let id = parse_proposal_id(&params.proposal_id)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let cosign = ProposalCosign {
            proposal_id: id,
            cosigner: self.wallet.address,
            cosigned_at: now,
        };
        let mut log = AppendLog::new(&self.db);
        append_cosign(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(cosign, &station),
            &self.db,
            now,
        )
        .map_err(|e| invalid_params(e.to_string()))?;
        let records =
            rrn_governance::proposal::proposal_records(&AppendLog::new(&self.db), &id, &self.db)
                .map_err(internal)?;
        ok(&rpc::GovCosignResult {
            cosigner_count: records.cosigner_count(),
        })
    }

    /// `governance_vote` — cast a ballot, signed by the station wallet.
    fn m_governance_vote(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::GovVoteParams = parse_params(req)?;
        let id = parse_proposal_id(&params.proposal_id)?;
        let choice = parse_vote_choice(&params.choice)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let vote = Vote {
            proposal_id: id,
            voter: self.wallet.address,
            choice,
            cast_at: now,
        };
        let mut log = AppendLog::new(&self.db);
        append_vote(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(vote, &station),
            &self.db,
            now,
        )
        .map_err(|e| invalid_params(e.to_string()))?;
        Ok(serde_json::json!({ "ok": true }))
    }

    // --- disputes (T1.10.5) ------------------------------------------------

    /// The dispute-resolution parameters this station runs: the freeze window, a
    /// juror's response deadline, and the panel size. Fixed at the Phase-1 defaults
    /// (ADR-0014 says these are not governance-tunable yet); every dispute call
    /// reads them from here so the draw, the seating, and the resolution all agree.
    fn dispute_params(&self) -> DisputeParams {
        DisputeParams::default()
    }

    /// The community value mixed into a dispute's sortition seed. In Phase 1 —
    /// single community, no federation — an empty anchor is correct (ADR-0014 §2);
    /// a stable per-community anchor drops in here when federation arrives, and
    /// every dispute call routes through this one helper so they never disagree.
    fn dispute_anchor(&self) -> Vec<u8> {
        Vec::new()
    }

    /// The genesis founders of the effective Charter, or an empty set if none is
    /// published. Threaded into every dispute call so the jury pool and escalation
    /// electorate seat founders while the community is in bootstrap grace
    /// (ADR-0015); once three members establish, the set is ignored.
    fn dispute_founders(&self) -> Result<Vec<Address>, rpc::RpcError> {
        Ok(effective_charter(&self.db)
            .map_err(internal)?
            .map(|c| c.founders)
            .unwrap_or_default())
    }

    /// [`dispute_founders`] for the channel write path, whose errors are the
    /// `(code, message)` pair the mobile handlers return.
    fn dispute_founders_pair(&self) -> Result<Vec<Address>, (i32, String)> {
        Ok(effective_charter(&self.db)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?
            .map(|c| c.founders)
            .unwrap_or_default())
    }

    fn m_disputes(&self) -> Result<serde_json::Value, rpc::RpcError> {
        let disputes = dispute_view::disputes_view(
            &self.db,
            &self.dispute_founders()?,
            &self.dispute_params(),
            &self.dispute_anchor(),
            self.clock.now(),
        )
        .map_err(dispute_err)?;
        Ok(serde_json::json!({ "disputes": disputes }))
    }

    fn m_dispute(&self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeShowParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        match dispute_view::dispute_view(
            &self.db,
            &self.dispute_founders()?,
            &tx_id,
            &self.dispute_params(),
            &self.dispute_anchor(),
            self.clock.now(),
        )
        .map_err(dispute_err)?
        {
            Some(detail) => ok(&detail),
            None => Err(invalid_params(format!(
                "no live dispute for transaction {}",
                params.tx_id
            ))),
        }
    }

    /// `dispute_raise` — contest a `Confirmed` transaction, signed by the station
    /// wallet. Freezes settlement across the `Confirmed → Disputed` edge.
    fn m_dispute_raise(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeRaiseParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        let evidence_hash = parse_evidence_hash(&params.evidence_hash)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let record = DisputeRecord {
            proposal_id: tx_id,
            raiser: self.wallet.address,
            reason: params.reason,
            evidence_hash,
            opened_at: now,
        };
        let signed = SignedDispute::sign(record, &station);
        let mut engine = Engine::new(&self.db, station);
        engine
            .raise_dispute(signed, &self.settlement, now)
            .map_err(ledger_err)?;
        ok(&rpc::DisputeRaiseResult {
            tx_id: params.tx_id,
            state: "Disputed".into(),
        })
    }

    /// `dispute_respond` — file the station wallet's side of a live dispute.
    fn m_dispute_respond(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeRespondParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        let evidence_hash = parse_evidence_hash(&params.evidence_hash)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let record = DisputeResponse {
            proposal_id: tx_id,
            responder: self.wallet.address,
            statement: params.statement,
            evidence_hash,
            responded_at: now,
        };
        let signed = SignedDisputeResponse::sign(record, &station);
        let mut engine = Engine::new(&self.db, station);
        engine.respond_to_dispute(signed, now).map_err(ledger_err)?;
        ok(&rpc::DisputeRespondResult {
            tx_id: params.tx_id,
        })
    }

    /// `dispute_rule` — cast the station wallet's juror verdict on a dispute. The
    /// wallet must hold a live seat on the derived panel, which
    /// [`append_verdict`] enforces.
    fn m_dispute_rule(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeRuleParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let verdict = JurorVerdict {
            proposal_id: tx_id,
            juror: self.wallet.address,
            uphold: params.uphold,
            cast_at: now,
        };
        let signed = SignedVerdict::sign(verdict, &station);
        append_verdict(
            &self.db,
            &self.dispute_founders()?,
            &self.dispute_params(),
            &self.dispute_anchor(),
            signed,
            now,
        )
        .map_err(dispute_err)?;
        ok(&rpc::DisputeRuleResult {
            tx_id: params.tx_id,
            uphold: params.uphold,
        })
    }

    /// `dispute_resolve` — enact a terminal outcome, or lapse a dispute whose
    /// window has closed. With a `tx_id`, resolves just that one; without,
    /// sweeps every disputed transaction (the same work the resolution timer does).
    fn m_dispute_resolve(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeResolveParams = parse_params(req)?;
        // A targeted single-tx request surfaces its error to the caller; the
        // unfiltered sweep skips-and-warns per dispute, exactly like the background
        // resolution timer (`do_resolve_disputes`), so one un-resolvable dispute
        // (e.g. a corrupt record yielding `MissingAdmission`) cannot block resolving
        // every other one.
        let targeted = params.tx_id.is_some();
        let ids = match &params.tx_id {
            Some(hex) => vec![parse_tx_id(hex)?],
            None => find_disputed(&self.db).map_err(dispute_err)?,
        };
        let now = self.clock.now();
        let station = self.station_keypair();
        let disp_params = self.dispute_params();
        let anchor = self.dispute_anchor();
        let founders = self.dispute_founders()?;
        let mut resolved = Vec::with_capacity(ids.len());
        for id in ids {
            match resolve(
                &self.db,
                &founders,
                &station,
                &id,
                &disp_params,
                &anchor,
                now,
            ) {
                Ok(outcome) => resolved.push(rpc::DisputeResolvedRow {
                    tx_id: id.0.to_string(),
                    resolution: resolution_name(outcome).to_string(),
                }),
                Err(e) if targeted => return Err(dispute_err(e)),
                Err(e) => {
                    tracing::warn!(tx = ?id, error = %e, "dispute_resolve sweep: skipping failed dispute");
                }
            }
        }
        ok(&rpc::DisputeResolveResult { resolved })
    }

    /// `dispute_escalate` — open an escalation to the established-member electorate,
    /// signed by the station wallet (which must be a party). Used when the jury
    /// cannot seat a panel, or to appeal its ruling (ADR-0014 §5).
    fn m_dispute_escalate(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeEscalateParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        let reason = parse_escalation_reason(&params.reason)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let record = EscalationRecord {
            proposal_id: tx_id,
            initiator: self.wallet.address,
            reason,
            opened_at: now,
        };
        let signed = SignedEscalation::sign(record, &station);
        open_escalation(
            &self.db,
            &self.dispute_founders()?,
            &self.dispute_params(),
            &self.dispute_anchor(),
            signed,
            now,
        )
        .map_err(dispute_err)?;
        ok(&rpc::DisputeEscalateResult {
            tx_id: params.tx_id,
            reason: params.reason,
        })
    }

    /// `dispute_escalation_vote` — cast the station wallet's ballot in an open
    /// escalation. The wallet must be an eligible, non-party established member,
    /// which [`append_escalation_ballot`] enforces.
    fn m_dispute_escalation_vote(
        &mut self,
        req: &rpc::Request,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::DisputeEscalationVoteParams = parse_params(req)?;
        let tx_id = parse_tx_id(&params.tx_id)?;
        let now = self.clock.now();
        let station = self.station_keypair();
        let ballot = EscalationBallot {
            proposal_id: tx_id,
            voter: self.wallet.address,
            uphold: params.uphold,
            cast_at: now,
        };
        let signed = SignedEscalationBallot::sign(ballot, &station);
        append_escalation_ballot(
            &self.db,
            &self.dispute_founders()?,
            &self.dispute_params(),
            signed,
            now,
        )
        .map_err(dispute_err)?;
        ok(&rpc::DisputeEscalationVoteResult {
            tx_id: params.tx_id,
            uphold: params.uphold,
        })
    }

    // --- governance mobile writes (T1.9.7b) --------------------------------

    /// `governance_submit_proposal` — accept a mobile-signed governance
    /// [`Proposal`] and append it. The author signs it on the phone; the station
    /// only validates and records. `params` carries the canonical dCBOR of the
    /// signed proposal, hex-encoded.
    fn channel_governance_submit_proposal(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_proposal")?;
        let signed: rrn_governance::proposal::SignedProposal =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed proposal".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "proposal author is not the authenticated mobile".into(),
            ));
        }
        let proposal_id = signed.payload.proposal_id.to_string();
        let now = self.clock.now();
        let mut log = AppendLog::new(&self.db);
        append_proposal(&mut log, signed, &self.db, now)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        Ok(serde_json::json!({ "proposal_id": proposal_id }))
    }

    /// `governance_submit_cosign` — accept a mobile-signed [`ProposalCosign`].
    fn channel_governance_submit_cosign(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_cosign")?;
        let signed: rrn_governance::proposal::SignedCosign =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed cosign".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "co-signer is not the authenticated mobile".into(),
            ));
        }
        let id = signed.payload.proposal_id;
        let now = self.clock.now();
        let mut log = AppendLog::new(&self.db);
        append_cosign(&mut log, signed, &self.db, now)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        let records =
            rrn_governance::proposal::proposal_records(&AppendLog::new(&self.db), &id, &self.db)
                .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        Ok(serde_json::json!({ "cosigner_count": records.cosigner_count() }))
    }

    /// `governance_submit_charter_signature` — a founder's phone signs the genesis
    /// Charter body on-device and submits its signature (the distributed founding
    /// ceremony). The founder is the authenticated mobile, so the signature is
    /// attributed to `envelope.signer`; the payload carries only the 64-byte
    /// signature over the Charter body's canonical bytes. Publishes the Charter
    /// once the founder threshold is met.
    fn channel_governance_submit_charter_signature(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let sig_bytes = hex_param(&envelope.params, "charter_signature")?;
        let arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| (rpc::INVALID_PARAMS, "signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(arr)
            .map_err(|_| (rpc::INVALID_PARAMS, "signature is malformed".into()))?;
        let signed = self.ingest_charter_signature(envelope.signer, signature)?;
        Ok(serde_json::to_value(self.pending_charter_view(&signed)).unwrap_or_default())
    }

    /// `governance_submit_vote` — accept a mobile-signed [`Vote`].
    fn channel_governance_submit_vote(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_vote")?;
        let signed: rrn_governance::vote::SignedVote = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed vote".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "voter is not the authenticated mobile".into(),
            ));
        }
        let now = self.clock.now();
        let mut log = AppendLog::new(&self.db);
        append_vote(&mut log, signed, &self.db, now)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        Ok(serde_json::json!({ "ok": true }))
    }

    // --- dispute mobile writes (T1.10.5) -----------------------------------

    /// `submit_dispute` — accept a mobile-signed [`SignedDispute`] and raise it.
    /// The party signs it on the phone; the station validates and records, freezing
    /// the contested transaction. `params` carries the canonical dCBOR of the
    /// signed dispute, hex-encoded.
    fn channel_submit_dispute(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_dispute")?;
        let signed: SignedDispute = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed dispute".into()))?;
        // A mobile raises only its own dispute: the raiser must be the
        // authenticated signer. (The engine independently checks the raiser is a
        // party; this binds it to *this* paired mobile.)
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "dispute raiser is not the authenticated mobile".into(),
            ));
        }
        let tx_id = signed.payload.proposal_id.0.to_string();
        let now = self.clock.now();
        let station = self.station_keypair();
        let mut engine = Engine::new(&self.db, station);
        engine
            .raise_dispute(signed, &self.settlement, now)
            .map_err(ledger_err_pair)?;
        Ok(serde_json::json!({ "tx_id": tx_id, "state": "Disputed" }))
    }

    /// `submit_dispute_response` — accept a mobile-signed [`SignedDisputeResponse`].
    fn channel_submit_dispute_response(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_response")?;
        let signed: SignedDisputeResponse = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed response".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "responder is not the authenticated mobile".into(),
            ));
        }
        let tx_id = signed.payload.proposal_id.0.to_string();
        let now = self.clock.now();
        let station = self.station_keypair();
        let mut engine = Engine::new(&self.db, station);
        engine
            .respond_to_dispute(signed, now)
            .map_err(ledger_err_pair)?;
        Ok(serde_json::json!({ "tx_id": tx_id }))
    }

    /// `submit_verdict` — accept a mobile-signed [`SignedVerdict`] from a seated
    /// juror. The signer must be the authenticated mobile, and hold a live seat on
    /// the derived panel (which [`append_verdict`] enforces).
    fn channel_submit_verdict(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_verdict")?;
        let signed: SignedVerdict = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed verdict".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "juror is not the authenticated mobile".into(),
            ));
        }
        let (tx_id, uphold) = (
            signed.payload.proposal_id.0.to_string(),
            signed.payload.uphold,
        );
        let now = self.clock.now();
        append_verdict(
            &self.db,
            &self.dispute_founders_pair()?,
            &self.dispute_params(),
            &self.dispute_anchor(),
            signed,
            now,
        )
        .map_err(dispute_err_pair)?;
        Ok(serde_json::json!({ "tx_id": tx_id, "uphold": uphold }))
    }

    /// `submit_escalation` — accept a mobile-signed [`SignedEscalation`] and open
    /// it. The party signs it on the phone; the station validates the reason against
    /// the dispute's state and records it (ADR-0014 §5).
    fn channel_submit_escalation(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_escalation")?;
        let signed: SignedEscalation = rpc_envelope::parse_signed_record(&bytes)
            .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed escalation".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "escalation initiator is not the authenticated mobile".into(),
            ));
        }
        let tx_id = signed.payload.proposal_id.0.to_string();
        let reason = match signed.payload.reason {
            EscalationReason::Appeal => "appeal",
            EscalationReason::CannotSeat => "cannot_seat",
        }
        .to_string();
        let now = self.clock.now();
        open_escalation(
            &self.db,
            &self.dispute_founders_pair()?,
            &self.dispute_params(),
            &self.dispute_anchor(),
            signed,
            now,
        )
        .map_err(dispute_err_pair)?;
        Ok(serde_json::json!({ "tx_id": tx_id, "reason": reason }))
    }

    /// `submit_escalation_ballot` — accept a mobile-signed [`SignedEscalationBallot`]
    /// from an eligible voter. The signer must be the authenticated mobile, and an
    /// eligible non-party established member ([`append_escalation_ballot`] enforces).
    fn channel_submit_escalation_ballot(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_ballot")?;
        let signed: SignedEscalationBallot =
            rpc_envelope::parse_signed_record(&bytes).map_err(|_| {
                (
                    rpc::INVALID_PARAMS,
                    "malformed signed escalation ballot".into(),
                )
            })?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "voter is not the authenticated mobile".into(),
            ));
        }
        let (tx_id, uphold) = (
            signed.payload.proposal_id.0.to_string(),
            signed.payload.uphold,
        );
        let now = self.clock.now();
        append_escalation_ballot(
            &self.db,
            &self.dispute_founders_pair()?,
            &self.dispute_params(),
            signed,
            now,
        )
        .map_err(dispute_err_pair)?;
        Ok(serde_json::json!({ "tx_id": tx_id, "uphold": uphold }))
    }

    /// Puts every passed proposal whose implementation delay has run into force,
    /// appending a station-signed enactment record for each (T1.9.7). Returns the
    /// number enacted. Emergencies, whose delay is zero, are enacted the first
    /// sweep after their vote closes.
    fn do_enact_governance(&mut self) -> usize {
        let now = self.clock.now();
        let station = self.station_keypair();
        match rrn_governance::lifecycle::enact_due(&self.db, &station, now) {
            Ok(enacted) => enacted.len(),
            Err(e) => {
                tracing::warn!(error = %e, "governance enactment sweep failed");
                0
            }
        }
    }

    /// Resolves every disputed transaction whose jury has reached a majority, and
    /// lapses (settles as confirmed) any whose window has closed with no ruling
    /// (T1.10.5). Returns the number given a terminal outcome. A dispute still
    /// inside its window with no majority is left `Pending` and untouched; a failing
    /// resolution is logged and skipped so one bad dispute cannot stall the sweep.
    fn do_resolve_disputes(&mut self) -> usize {
        let now = self.clock.now();
        let station = self.station_keypair();
        let params = self.dispute_params();
        let anchor = self.dispute_anchor();
        // Founders seat the grace electorate; if the charter cannot be read the
        // sweep still runs on the established set alone rather than stalling.
        let founders = match effective_charter(&self.db) {
            Ok(charter) => charter.map(|c| c.founders).unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error = %e, "dispute resolution sweep: reading founders failed");
                Vec::new()
            }
        };
        let ids = match find_disputed(&self.db) {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(error = %e, "dispute resolution sweep: listing disputes failed");
                return 0;
            }
        };
        let mut resolved = 0;
        for id in ids {
            match resolve(&self.db, &founders, &station, &id, &params, &anchor, now) {
                Ok(Resolution::Pending) => {}
                Ok(_) => resolved += 1,
                Err(e) => {
                    tracing::warn!(tx = ?id, error = %e, "dispute resolution failed");
                }
            }
        }
        resolved
    }

    /// `bundle_submit` (operator / Unix socket): ingest a DTN bundle handed over
    /// by a courier and answer with the hex of the signed delivery receipt.
    fn m_bundle_submit(&mut self, req: &rpc::Request) -> Result<serde_json::Value, rpc::RpcError> {
        let params: rpc::BundleSubmitParams = parse_params(req)?;
        let bundle_bytes = unhex(&params.bundle_hex).ok_or_else(|| rpc::RpcError {
            code: rpc::INVALID_PARAMS,
            message: "bundle_hex is not hex".into(),
        })?;
        let now = self.clock.now();
        let receipt = self
            .ingest_bundle(&bundle_bytes, now)
            .map_err(|e| e.rpc_error())?;
        ok(&rpc::BundleSubmitResult {
            receipt_hex: hex(&receipt),
        })
    }

    /// `bundle_submit` (paired mobile / sealed channel): the authenticated mobile
    /// is a **courier** here, not the author — the carried records may be signed
    /// by other members, so this does not bind the record signer to the mobile.
    /// The pairing gate (already cleared before dispatch) is the DoS boundary;
    /// per-entry signatures are the integrity boundary (ADR-0020 §3).
    fn channel_bundle_submit(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bundle_bytes = hex_param(&envelope.params, "bundle_hex")?;
        let now = self.clock.now();
        let receipt = self
            .ingest_bundle(&bundle_bytes, now)
            .map_err(|e| e.pair_error())?;
        Ok(serde_json::json!({ "receipt_hex": hex(&receipt) }))
    }

    /// Ingests a DTN bundle (ADR-0020 §3-§4): decode it, then for each carried
    /// outbox entry in bundle order — validate signatures, track the author's
    /// chain (detecting forks and gaps), and route the embedded record through
    /// the **same** engine front door the live path uses — and answer with one
    /// station-signed [`SignedReceipt`], returned as its portable envelope bytes.
    ///
    /// Idempotent: a byte-identical *presentation* (the same ordered record
    /// hashes) returns the stored receipt verbatim; a different bundle
    /// re-carrying already-admitted records yields `known` outcomes via the log's
    /// own dedup. Neither path re-admits a record.
    ///
    /// The whole operation reads and writes only through `&self.db` (SQLite
    /// interior mutability), so it takes `&self`; the caller supplies `now` from
    /// the daemon clock.
    fn ingest_bundle(&self, bundle_bytes: &[u8], now: i64) -> Result<Vec<u8>, BundleIngestError> {
        let bundle = Bundle::decode(bundle_bytes)
            .map_err(|e| BundleIngestError::Malformed(e.to_string()))?;

        // Decode each carried entry once, up front, and capture the envelope
        // bytes (for fork evidence) and the record hash (for the presentation
        // hash, dedup, and the receipt outcome).
        struct Prepared {
            signed: rrn_protocol::outbox::SignedOutboxEntry,
            envelope_bytes: Vec<u8>,
            record_hash: Hash,
        }
        let mut entries = Vec::with_capacity(bundle.entries.len());
        for env in &bundle.entries {
            let signed = env
                .to_signed()
                .map_err(|e| BundleIngestError::Malformed(e.to_string()))?;
            let record_hash = signed.payload.record_hash();
            entries.push(Prepared {
                signed,
                envelope_bytes: to_canonical_bytes(env),
                record_hash,
            });
        }

        // Presentation hash: Blake3 over the ordered record-hash list — the
        // idempotency key. Independent of how the records were bundled.
        let mut pres = Vec::with_capacity(entries.len() * 32);
        for pe in &entries {
            pres.extend_from_slice(&pe.record_hash.to_bytes());
        }
        let presentation_hash = Hash::of(&pres);

        // Idempotent replay: if this exact presentation was already answered,
        // return that receipt's bytes verbatim (byte-identical guarantee).
        if let Some(stored) = DtnStore::new(&self.db)
            .receipt_for(&presentation_hash.to_bytes())
            .map_err(|e| BundleIngestError::Internal(e.to_string()))?
        {
            return Ok(stored);
        }

        let mut outcomes = Vec::with_capacity(entries.len());
        for pe in &entries {
            let entry = &pe.signed.payload;
            let record_hash = pe.record_hash;

            // (a) Signature validation (outer entry sig, author == signer, inner
            // record sig). A failure is a refusal, never a bundle abort.
            if outbox::validate(&pe.signed).is_err() {
                outcomes.push(refused(record_hash, RefusalReason::BadSignature));
                continue;
            }

            // (b) Chain tracking: record the entry against the author's seen
            // positions, detecting an outbox fork (same position, different
            // content) or a benign duplicate. A gap does not refuse (couriers
            // carry partial chains, ADR-0020 §2) — the store simply does not
            // advance the contiguous head past it.
            let author = entry.author.public_key().to_bytes();
            let entry_hash = entry.entry_hash().to_bytes();
            {
                let mut dtn = DtnStore::new(&self.db);
                match dtn
                    .note_entry(
                        &author,
                        entry.position,
                        &entry_hash,
                        &pe.envelope_bytes,
                        now,
                    )
                    .map_err(|e| BundleIngestError::Internal(e.to_string()))?
                {
                    NoteOutcome::Fresh => {
                        // A gap: this entry sits ahead of the contiguous head
                        // (`Some(head)` with `head.position < position`), or there
                        // is no head at all yet (`None` — a *leading* gap, the
                        // author's position 0 has not been seen). Either way the
                        // head did not advance to this entry; log the hole so a
                        // suppressed run is visible (ADR-0020 §2).
                        let head = dtn
                            .head(&author)
                            .map_err(|e| BundleIngestError::Internal(e.to_string()))?;
                        let at_head = head.map(|h| h.position) == Some(entry.position);
                        if !at_head {
                            tracing::info!(
                                author = %entry.author,
                                position = entry.position,
                                contiguous_head = head.map(|h| h.position as i64).unwrap_or(-1),
                                "outbox gap: entry recorded ahead of the contiguous head"
                            );
                        }
                    }
                    NoteOutcome::Duplicate => {}
                    NoteOutcome::Fork {
                        stored_entry_hash,
                        stored_envelope,
                    } => {
                        dtn.record_fork(
                            &author,
                            entry.position,
                            &stored_entry_hash,
                            &stored_envelope,
                            &entry_hash,
                            &pe.envelope_bytes,
                            now,
                        )
                        .map_err(|e| BundleIngestError::Internal(e.to_string()))?;
                        tracing::warn!(
                            author = %entry.author,
                            position = entry.position,
                            "outbox fork detected; refusing the conflicting entry (ADR-0021)"
                        );
                        outcomes.push(refused(record_hash, RefusalReason::OutboxFork));
                        continue;
                    }
                }
            }

            // (c) Dedup against the log: a record already admitted answers
            // `known` with its sequence — never re-admitted.
            if let Some((seq, _)) = AppendLog::new(&self.db)
                .admission_of(&record_hash)
                .map_err(|e| BundleIngestError::Internal(e.to_string()))?
            {
                outcomes.push(Outcome {
                    record_hash,
                    disposition: Disposition::Known { seq },
                });
                continue;
            }

            // (d) Route through the engine front door for the record's kind.
            let disposition = self.route_dtn_record(&pe.signed, now)?;
            outcomes.push(Outcome {
                record_hash,
                disposition,
            });
        }

        // Build, sign, persist (keyed by presentation hash), and return the
        // receipt as portable envelope bytes.
        let receipt = DeliveryReceipt {
            station: self.wallet.address,
            outcomes,
            received_at: now,
        };
        let signed = SignedReceipt::sign(receipt, &self.station_keypair());
        let receipt_bytes = receipt::encode_signed(&signed);
        DtnStore::new(&self.db)
            .put_receipt(&presentation_hash.to_bytes(), &receipt_bytes, now)
            .map_err(|e| BundleIngestError::Internal(e.to_string()))?;
        Ok(receipt_bytes)
    }

    /// Routes one validated, not-yet-admitted outbox entry to the matching engine
    /// front door and returns its [`Disposition`]. The engine re-verifies every
    /// signature and enforces every admission rule; this adds no admission logic
    /// of its own, only kind dispatch and error → refusal-slug mapping.
    fn route_dtn_record(
        &self,
        signed: &rrn_protocol::outbox::SignedOutboxEntry,
        now: i64,
    ) -> Result<Disposition, BundleIngestError> {
        let entry = &signed.payload;
        let signer = entry.record_signer;
        let signature = entry.record_sig;
        let bytes = &entry.record_bytes;
        let mut engine =
            Engine::new(&self.db, self.station_keypair()).with_credit_config(self.credit);

        // Decode the record's payload to its typed form (the `kind` inside the
        // canonical bytes selects the branch), rebuild the signed envelope from
        // the entry's carried signer/signature, and hand it to the engine. A
        // decode failure on a matched kind is a malformed record → `rejected`.
        let result = match dtn_record_kind(bytes).as_deref() {
            Some(KIND_PROPOSAL) => match from_canonical_bytes::<TransactionProposal>(bytes) {
                Ok(payload) => engine.submit_proposal(
                    SignedPayload {
                        payload,
                        signer,
                        signature,
                    },
                    now,
                ),
                Err(_) => return Ok(refused_disposition(RefusalReason::Rejected)),
            },
            Some(KIND_CONFIRMATION) => {
                match from_canonical_bytes::<TransactionConfirmation>(bytes) {
                    Ok(payload) => {
                        // Enforce the same Tier-2 staking gate the live paths do
                        // (T1.8.2) — a confirmation must clear it however it is
                        // carried, so DTN is not a bypass. Keyed on the record's
                        // own confirmer.
                        if self
                            .tier2_confirmation_gate(&payload.proposal_id, &payload.confirmer, now)
                            .map_err(|e| BundleIngestError::Internal(e.to_string()))?
                            .is_some()
                        {
                            return Ok(refused_disposition(RefusalReason::Tier2Stake));
                        }
                        engine.submit_confirmation(
                            SignedPayload {
                                payload,
                                signer,
                                signature,
                            },
                            now,
                        )
                    }
                    Err(_) => return Ok(refused_disposition(RefusalReason::Rejected)),
                }
            }
            Some(KIND_DISPUTE) => match from_canonical_bytes::<DisputeRecord>(bytes) {
                Ok(payload) => engine.raise_dispute(
                    SignedPayload {
                        payload,
                        signer,
                        signature,
                    },
                    &self.settlement,
                    now,
                ),
                Err(_) => return Ok(refused_disposition(RefusalReason::Rejected)),
            },
            Some(KIND_DISPUTE_RESPONSE) => match from_canonical_bytes::<DisputeResponse>(bytes) {
                Ok(payload) => engine.respond_to_dispute(
                    SignedPayload {
                        payload,
                        signer,
                        signature,
                    },
                    now,
                ),
                Err(_) => return Ok(refused_disposition(RefusalReason::Rejected)),
            },
            _ => return Ok(refused_disposition(RefusalReason::UnroutableKind)),
        };

        match result {
            Ok(()) => match AppendLog::new(&self.db)
                .admission_of(&entry.record_hash())
                .map_err(|e| BundleIngestError::Internal(e.to_string()))?
            {
                Some((seq, _)) => Ok(Disposition::Admitted { seq }),
                // The engine reported success but the record is not in the log:
                // an invariant violation, not a member-visible refusal.
                None => Err(BundleIngestError::Internal(
                    "engine admitted a record absent from the log".into(),
                )),
            },
            // A storage fault is an internal failure, not a refusal — abort the
            // bundle rather than issue a receipt that misrepresents it.
            Err(rrn_ledger::Error::Storage(e)) => Err(BundleIngestError::Internal(e.to_string())),
            Err(e) => Ok(refused_disposition(map_refusal(&e))),
        }
    }

    /// The Tier-2 confirmation staking gate (T1.8.2), shared by every path that
    /// admits a confirmation — the operator CLI (`m_confirm`), the mobile channel
    /// (`channel_submit_confirmation`), and DTN ingest (`route_dtn_record`) — so
    /// a Tier-2 confirmation clears the same reputation bar however it is carried
    /// (no bypass; ADR-0020 §4 admission parity).
    ///
    /// A confirmation of a Tier-2 proposal requires `confirmer` to clear the
    /// Member band, unless the community is still in bootstrap grace (ADR-0015).
    /// Returns `Ok(None)` when the confirmation may proceed (the proposal is
    /// Tier 1, or Tier 2 and the confirmer is eligible) and `Ok(Some((composite,
    /// established)))` when the gate refuses — the confirmer's composite standing
    /// and how many members are established, for the caller's message.
    fn tier2_confirmation_gate(
        &self,
        proposal_id: &TransactionId,
        confirmer: &Address,
        now: i64,
    ) -> anyhow::Result<Option<(f32, usize)>> {
        let snapshot = rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&self.db))?;
        let tier = snapshot
            .get(proposal_id)
            .and_then(proposal_of)
            // An unknown proposal falls through as Tier 1; the engine is what
            // rejects it authoritatively (UnknownTransaction).
            .map(|p| p.effective_tier())
            .unwrap_or(rrn_ledger::tier::MIN_TIER);
        if tier < 2 {
            return Ok(None);
        }
        use rrn_reputation::staking::Tier2Eligibility;
        match rrn_reputation::staking::evaluate_tier2_confirmation(&self.db, confirmer, now)? {
            Tier2Eligibility::Allowed {
                stake_centi,
                via_grace,
            } => {
                tracing::info!(
                    tx = %hex(&proposal_id.to_bytes()),
                    stake_centi,
                    via_grace,
                    "tier-2 confirmation: reputation staked"
                );
                Ok(None)
            }
            Tier2Eligibility::Refused {
                composite,
                established,
            } => Ok(Some((composite, established))),
        }
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
            "submit_listing_update" => self.channel_submit_listing_update(envelope),
            "submit_listing_close" => self.channel_submit_listing_close(envelope),
            "marketplace_my_listings" => self.channel_marketplace_my_listings(envelope),
            "submit_inquiry" => self.channel_submit_inquiry(envelope),
            "submit_inquiry_message" => self.channel_submit_inquiry_message(envelope),
            "submit_inquiry_close" => self.channel_submit_inquiry_close(envelope),
            "inquiry_thread" => self.channel_inquiry_thread(envelope),
            "my_inquiries" => self.channel_my_inquiries(envelope),
            "submit_contract" => self.channel_submit_contract(envelope),
            "submit_contract_termination" => self.channel_submit_contract_termination(envelope),
            "marketplace_contracts" => self.channel_marketplace_contracts(envelope),
            "marketplace_contract_show" => self.channel_marketplace_contract_show(envelope),
            // Governance writes (T1.9.7b): each carries a mobile-signed record, and
            // the signer must be the authenticated mobile. Reads fall through to the
            // shared, signer-less dispatch below.
            "governance_submit_proposal" => self.channel_governance_submit_proposal(envelope),
            "governance_submit_cosign" => self.channel_governance_submit_cosign(envelope),
            "governance_submit_vote" => self.channel_governance_submit_vote(envelope),
            "governance_submit_charter_signature" => {
                self.channel_governance_submit_charter_signature(envelope)
            }
            // Dispute writes (T1.10.5): each carries a mobile-signed record whose
            // signer must be the authenticated mobile. Reads fall through to the
            // shared, signer-less dispatch below.
            // DTN bundle ingest (T2.2.3, ADR-0020). Unlike the other channel
            // writes, the paired mobile here is a **courier**, not the author:
            // the carried records may be signed by *other* members, so this
            // deliberately does NOT bind the record signer to the authenticated
            // mobile. The pairing gate is the DoS/accountability boundary; per-
            // entry signatures are the integrity boundary (ADR-0020 §3).
            "bundle_submit" => self.channel_bundle_submit(envelope),
            "submit_dispute" => self.channel_submit_dispute(envelope),
            "submit_dispute_response" => self.channel_submit_dispute_response(envelope),
            "submit_verdict" => self.channel_submit_verdict(envelope),
            "submit_escalation" => self.channel_submit_escalation(envelope),
            "submit_escalation_ballot" => self.channel_submit_escalation_ballot(envelope),
            "whoami"
            | "balance"
            | "transactions"
            | "next_nonce"
            | "governance_charter"
            | "governance_pending_charter"
            | "governance_proposals"
            | "governance_proposal"
            | "governance_statutes"
            | "disputes"
            | "dispute" => {
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
        let mut engine =
            Engine::new(&self.db, self.station_keypair()).with_credit_config(self.credit);
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

        // A Tier-2 confirmation stakes reputation (T1.8.2): gate it on the
        // **authenticated mobile** (`signed.signer`) — the confirmer must clear
        // the Member band, or the community must still be in bootstrap grace.
        // Shared with the operator and DTN paths via `tier2_confirmation_gate`.
        let confirmer = Address::from_public_key(signed.signer);
        if let Some((composite, established)) = self
            .tier2_confirmation_gate(&signed.payload.proposal_id, &confirmer, now)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?
        {
            let member_floor = rrn_reputation::model::BAND_MEMBER_MIN;
            return Err((
                rpc::INVALID_PARAMS,
                format!(
                    "cannot confirm a Tier-2 payment: your standing is {composite:.2}, \
                     below the Member band ({member_floor:.1}) the community now \
                     requires ({established} members are established, so the bootstrap \
                     grace has ended)"
                ),
            ));
        }

        let mut engine =
            Engine::new(&self.db, self.station_keypair()).with_credit_config(self.credit);
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
        let now = self.clock.now();
        let mut log = AppendLog::new(&self.db);
        append_vouch(&mut log, signed, now).map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
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
        let now = self.clock.now();
        rrn_marketplace::lifecycle::append_listing_created(&mut log, signed, now)
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
        let now = self.clock.now();
        append_listing_closed(&mut log, signed, &station_pk, now)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        self.reindex_listing(&listing_id);
        Ok(serde_json::json!({
            "listing_id": hex(&listing_id.to_bytes()),
            "reason": "provider_closed",
        }))
    }

    /// `submit_listing_update` — accept a mobile-signed [`SignedListingUpdate`]
    /// and apply the provider's patch to their own listing (T1.7.2 Phase B). The
    /// provider signs a [`ListingPatch`](rrn_marketplace::lifecycle::ListingPatch)
    /// on the phone; the station verifies the signature and that the signer is
    /// this paired mobile, then leaves signer-is-provider, listing-exists,
    /// not-already-closed, non-empty-patch, and the patched listing's own validity
    /// to [`append_listing_updated`] — so the write path and replay's `scan` agree
    /// by construction. The listing's content id is fixed at publication and a
    /// patch never changes it.
    fn channel_submit_listing_update(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_listing_update")?;
        let signed: rrn_marketplace::lifecycle::SignedListingUpdate =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed update".into()))?;
        // A mobile submits only updates it signed: the provider must be the
        // authenticated signer bound to this paired mobile.
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "editor is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "update signature does not verify".into(),
            )
        })?;
        let listing_id = signed.payload.listing_id;
        let station_pk = self.station_keypair().public_key();
        let mut log = AppendLog::new(&self.db);
        let now = self.clock.now();
        rrn_marketplace::lifecycle::append_listing_updated(&mut log, signed, &station_pk, now)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        self.reindex_listing(&listing_id);
        Ok(serde_json::json!({
            "listing_id": hex(&listing_id.to_bytes()),
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

    /// `submit_inquiry` — open a mobile-signed inquiry against a listing (T1.7.4).
    ///
    /// The buyer signs the [`InquiryOpened`](rrn_marketplace::inquiry::InquiryOpened)
    /// on the phone, as they sign a listing or a vouch. The station verifies the
    /// signature and that the signer is this paired mobile, resolves the listing
    /// (which must be on offer), reads the buyer's capped composite from the
    /// snapshot cache, and lets [`append_inquiry_opened`](rrn_marketplace::inquiry::append_inquiry_opened)
    /// apply the listing's requirements — the first place a listing's `min_reputation`
    /// / `community_member_only` becomes a check against a specific buyer. A
    /// refusal comes back as `INVALID_PARAMS` naming the unmet requirement.
    fn channel_submit_inquiry(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_inquiry")?;
        let signed: rrn_marketplace::inquiry::SignedInquiryOpened =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed inquiry".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "buyer is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "inquiry signature does not verify".into(),
            )
        })?;

        let now = self.clock.now();
        let listing = self.active_listing_for_inquiry(&signed.payload.listing_id, now)?;
        let composite = marketplace_view::capped_composite(&self.db, &signed.payload.buyer, now);
        // Phase 1: any paired member is in this station's single community.
        let in_community = listing.community == VOUCH_COMMUNITY;
        let inquiry_id = signed.payload.inquiry_id;

        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::inquiry::append_inquiry_opened(
            &mut log,
            signed,
            &listing,
            composite,
            in_community,
            now,
        )
        .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        Ok(serde_json::json!({ "inquiry_id": hex(&inquiry_id.to_bytes()) }))
    }

    /// Resolves the listing an inquiry names, requiring it to be on offer right
    /// now — an inquiry against a closed or expired listing is refused, as is one
    /// against a listing this station has never seen. Shared by the mobile and
    /// operator open paths so both refuse the same way.
    fn active_listing_for_inquiry(
        &self,
        listing_id: &ListingId,
        now: i64,
    ) -> Result<Listing, (i32, String)> {
        let station_pk = self.wallet.address.public_key();
        let log = AppendLog::new(&self.db);
        let state = rrn_marketplace::lifecycle::compute_state(&log, listing_id, station_pk, now)
            .map_err(|e| (rpc::INTERNAL_ERROR, e.to_string()))?;
        match state {
            Some(ListingState::Active(listing)) => Ok(listing),
            Some(_) => Err((rpc::INVALID_PARAMS, "listing is not on offer".into())),
            None => Err((
                rpc::INVALID_PARAMS,
                "no such listing on this station".into(),
            )),
        }
    }

    /// `submit_inquiry_message` — a mobile-signed message in an open inquiry the
    /// member is a party to (T1.7.4).
    fn channel_submit_inquiry_message(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_message")?;
        let signed: rrn_marketplace::inquiry::SignedInquiryMessage =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed message".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "sender is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "message signature does not verify".into(),
            )
        })?;

        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let inquiry_id = signed.payload.inquiry_id;
        let admits = self.inquiry_admits(now);
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::inquiry::append_inquiry_message(
            &mut log, signed, station_pk, &admits, now,
        )
        .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        Ok(serde_json::json!({ "inquiry_id": hex(&inquiry_id.to_bytes()) }))
    }

    /// `submit_inquiry_close` — a mobile-signed close of an inquiry the member is
    /// a party to: agreeing on a price, or declining their side (T1.7.4).
    fn channel_submit_inquiry_close(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_close")?;
        let signed: rrn_marketplace::inquiry::SignedInquiryClosed =
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

        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let inquiry_id = signed.payload.inquiry_id;
        let admits = self.inquiry_admits(now);
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::inquiry::append_inquiry_closed(&mut log, signed, station_pk, &admits, now)
            .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        Ok(serde_json::json!({ "inquiry_id": hex(&inquiry_id.to_bytes()) }))
    }

    /// `inquiry_thread` — one inquiry's full thread, for the authenticated mobile
    /// (T1.7.4). Only a party to the inquiry may read it.
    fn channel_inquiry_thread(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        #[derive(serde::Deserialize)]
        struct Params {
            inquiry_id: String,
        }
        let params: Params = serde_json::from_str(&envelope.params)
            .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
        let viewer = Address::from_public_key(envelope.signer);
        self.run_inquiry_thread(&params.inquiry_id, viewer)
            .map_err(|e| (e.code, e.message))
    }

    /// `my_inquiries` — the authenticated mobile's own inquiries (as buyer or
    /// provider), newest activity first (T1.7.4).
    fn channel_my_inquiries(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let viewer = Address::from_public_key(envelope.signer);
        self.run_my_inquiries(viewer)
            .map_err(|e| (e.code, e.message))
    }

    /// `submit_contract` — a mobile-signed [`SignedServiceContract`](rrn_marketplace::contract::SignedServiceContract),
    /// the buyer's recurring mandate born from an agreed inquiry (T1.7.7 Stage 2).
    ///
    /// The phone snapshots the terms from the agreed inquiry thread and signs; the
    /// append re-checks every one of them — that the contract is born from an
    /// inquiry closed as agreed for exactly these parties and listing, and that the
    /// terms match the listing's standing cadence and the agreed price — so a phone
    /// cannot forge terms. The operator path signs the same record with the station
    /// wallet; this one is buyer-signed, which is the only difference.
    fn channel_submit_contract(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_contract")?;
        let signed: rrn_marketplace::contract::SignedServiceContract =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed contract".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "buyer is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "contract signature does not verify".into(),
            )
        })?;

        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let contract_id = signed.payload.contract_id;
        let admits = self.inquiry_admits(now);
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::contract::append_service_contract(
            &mut log, signed, station_pk, &admits, now,
        )
        .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        // A fresh contract has charged nothing, so it stands `active` at `now`.
        Ok(serde_json::json!({
            "contract_id": hex(&contract_id.to_bytes()),
            "state": "active",
        }))
    }

    /// `submit_contract_termination` — a mobile-signed
    /// [`SignedContractTermination`](rrn_marketplace::contract::SignedContractTermination)
    /// ending a contract the member is a party to (T1.7.7 Stage 2). Either party
    /// may; the notice window and any penalty are the charge sweep's to apply.
    fn channel_submit_contract_termination(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let bytes = hex_param(&envelope.params, "signed_termination")?;
        let signed: rrn_marketplace::contract::SignedContractTermination =
            rpc_envelope::parse_signed_record(&bytes)
                .map_err(|_| (rpc::INVALID_PARAMS, "malformed signed termination".into()))?;
        if signed.signer.to_bytes() != envelope.signer.to_bytes() {
            return Err((
                rpc::INVALID_PARAMS,
                "terminator is not the authenticated mobile".into(),
            ));
        }
        signed.verify().map_err(|_| {
            (
                rpc::INVALID_PARAMS,
                "termination signature does not verify".into(),
            )
        })?;

        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let contract_id = signed.payload.contract_id;
        let admits = self.inquiry_admits(now);
        let mut log = AppendLog::new(&self.db);
        rrn_marketplace::contract::append_contract_termination(
            &mut log, signed, station_pk, &admits, now,
        )
        .map_err(|e| (rpc::INVALID_PARAMS, e.to_string()))?;
        Ok(serde_json::json!({ "contract_id": hex(&contract_id.to_bytes()) }))
    }

    /// `marketplace_contracts` — the authenticated mobile's own contracts (as
    /// buyer or provider), newest first (T1.7.7 Stage 2).
    fn channel_marketplace_contracts(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        let viewer = Address::from_public_key(envelope.signer);
        self.run_my_contracts(viewer)
            .map_err(|e| (e.code, e.message))
    }

    /// `marketplace_contract_show` — one contract the authenticated mobile is a
    /// party to (T1.7.7 Stage 2). Only a party may read it.
    fn channel_marketplace_contract_show(
        &mut self,
        envelope: &RequestEnvelope,
    ) -> Result<serde_json::Value, (i32, String)> {
        #[derive(serde::Deserialize)]
        struct Params {
            contract_id: String,
        }
        let params: Params = serde_json::from_str(&envelope.params)
            .map_err(|e| (rpc::INVALID_PARAMS, format!("params not valid JSON: {e}")))?;
        let viewer = Address::from_public_key(envelope.signer);
        self.run_contract_detail(&params.contract_id, viewer)
            .map_err(|e| (e.code, e.message))
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
        // The authenticated mobile is the viewer, so the detail carries whether
        // *they* may inquire.
        let viewer = Address::from_public_key(envelope.signer);
        self.run_marketplace_listing(&params.listing_id, Some(viewer))
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
        viewer: Option<Address>,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let listing_id = parse_listing_id(listing_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station = self.wallet.address.public_key();
        match marketplace_view::detail(&self.db, &listing_id, station, now).map_err(internal)? {
            Some(mut view) => {
                // Fill in whether *this* caller qualifies to inquire, so the
                // client can disable the CTA with the reason. An anonymous read
                // (the operator socket) leaves it out.
                if let Some(viewer) = viewer {
                    view.viewer_eligible = Some(self.viewer_eligibility(&view, &viewer, now));
                }
                ok(&view)
            }
            None => Err(invalid_params("no such listing on this station")),
        }
    }

    /// Whether `viewer` meets a listing detail's requirements, reusing the same
    /// [`check_requirements`](rrn_marketplace::inquiry::check_requirements) the
    /// inquiry write path enforces — so the courtesy the client shows and the
    /// refusal the server would return cannot disagree.
    fn viewer_eligibility(
        &self,
        view: &marketplace_view::ListingDetailView,
        viewer: &Address,
        now: i64,
    ) -> marketplace_view::ViewerEligibility {
        let composite = marketplace_view::capped_composite(&self.db, viewer, now);
        let reqs = rrn_marketplace::listing::Requirements {
            min_reputation: view.min_reputation,
            community_member_only: view.community_member_only,
            federation_only: false,
        };
        // Phase 1: any paired member is in this station's single community.
        let in_community = view.community == VOUCH_COMMUNITY;
        marketplace_view::ViewerEligibility::from_check(
            rrn_marketplace::inquiry::check_requirements(
                &reqs,
                &view.community,
                composite,
                in_community,
            ),
        )
    }

    /// The inquiry requirements gate for both reads and writes: reads the buyer's
    /// capped composite from the snapshot cache and treats any member as
    /// belonging to this station's single community (Phase 1). Built per call so
    /// it carries the current clock; borrows `&self.db`.
    fn inquiry_admits(&self, now: i64) -> impl Fn(&Listing, &Address) -> bool + '_ {
        move |listing: &Listing, buyer: &Address| {
            let composite = marketplace_view::capped_composite(&self.db, buyer, now);
            let in_community = listing.community == VOUCH_COMMUNITY;
            rrn_marketplace::inquiry::check_requirements(
                &listing.requirements,
                &listing.community,
                composite,
                in_community,
            )
            .is_ok()
        }
    }

    /// The inquiry-thread read, shared by the mobile channel and the CLI socket.
    /// `viewer` must be the inquiry's buyer or provider — a thread is private to
    /// its two parties, so a non-party gets the same "no such inquiry" a missing
    /// one would, rather than a confirmation the inquiry exists.
    fn run_inquiry_thread(
        &self,
        inquiry_id: &str,
        viewer: Address,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let inquiry_id = parse_inquiry_id(inquiry_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let admits = self.inquiry_admits(now);
        let log = AppendLog::new(&self.db);
        match rrn_marketplace::inquiry::inquiry_records(&log, &inquiry_id, station_pk, &admits)
            .map_err(internal)?
        {
            Some(records) if records.buyer() == viewer || records.provider() == viewer => {
                ok(&inquiry_view::thread(&records, now))
            }
            _ => Err(invalid_params("no such inquiry for this member")),
        }
    }

    /// The my-inquiries read, shared by both transports. Returns the inquiries
    /// `viewer` is a party to, newest activity first.
    fn run_my_inquiries(&self, viewer: Address) -> Result<serde_json::Value, rpc::RpcError> {
        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let admits = self.inquiry_admits(now);
        let log = AppendLog::new(&self.db);
        let all = rrn_marketplace::inquiry::all_inquiry_records(&log, station_pk, &admits)
            .map_err(internal)?;
        let rows = inquiry_view::my_inquiries(all.into_values(), &viewer, now);
        ok(&serde_json::json!({ "inquiries": rows }))
    }

    /// The contract-detail read (T1.7.7). `viewer` must be the contract's buyer or
    /// provider — a contract is private to its two parties, so a non-party gets
    /// the same "no such contract" a missing one would.
    fn run_contract_detail(
        &self,
        contract_id: &str,
        viewer: Address,
    ) -> Result<serde_json::Value, rpc::RpcError> {
        let contract_id = parse_contract_id(contract_id)
            .map_err(|(code, message)| rpc::RpcError { code, message })?;
        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let admits = self.inquiry_admits(now);
        let log = AppendLog::new(&self.db);
        match rrn_marketplace::contract::contract_records(&log, &contract_id, station_pk, &admits)
            .map_err(internal)?
        {
            Some(records) if records.buyer() == viewer || records.provider() == viewer => {
                let charged = charged_periods_by_contract(&log);
                let periods_charged =
                    periods_charged_of(&charged, &contract_id, records.total_periods());
                ok(&contract_view::detail(&records, periods_charged, now))
            }
            _ => Err(invalid_params("no such contract for this member")),
        }
    }

    /// The my-contracts read (T1.7.7). Returns the contracts `viewer` is a party
    /// to, newest first, each with the count of periods the ledger has charged so
    /// the state and next-due date are current.
    fn run_my_contracts(&self, viewer: Address) -> Result<serde_json::Value, rpc::RpcError> {
        let now = self.clock.now();
        let station_pk = self.wallet.address.public_key();
        let admits = self.inquiry_admits(now);
        let log = AppendLog::new(&self.db);
        let all = rrn_marketplace::contract::all_contract_records(&log, station_pk, &admits)
            .map_err(internal)?;
        let charged = charged_periods_by_contract(&log);
        let paired = all.into_iter().map(|(id, records)| {
            let periods_charged = periods_charged_of(&charged, &id, records.total_periods());
            (records, periods_charged)
        });
        let rows = contract_view::my_contracts(paired, &viewer, now);
        ok(&serde_json::json!({ "contracts": rows }))
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

// --- DTN bundle ingest helpers (T2.2.3) -------------------------------------

/// Wire discriminators of the record kinds the station routes over DTN. These
/// mirror the `pub(crate)` `*_KIND` constants in `rrn-ledger`
/// (`transaction.rs` / `dispute.rs`); they are wire-stable and not exported, so
/// they are restated here as the routing table's keys.
const KIND_PROPOSAL: &str = "rrn.tx.proposal";
const KIND_CONFIRMATION: &str = "rrn.tx.confirmation";
const KIND_DISPUTE: &str = "rrn.tx.dispute";
const KIND_DISPUTE_RESPONSE: &str = "rrn.tx.dispute.response";

/// Why an ingest could not produce a receipt at all (as opposed to a per-record
/// refusal, which *is* part of a receipt). A malformed bundle is the caller's
/// fault (`invalid-params`); a storage fault is the station's (`internal`).
enum BundleIngestError {
    /// The bundle bytes did not decode as a valid [`Bundle`].
    Malformed(String),
    /// A storage failure occurred mid-ingest; no trustworthy receipt is possible.
    Internal(String),
}

impl BundleIngestError {
    /// Maps to the Unix-socket RPC error form.
    fn rpc_error(self) -> rpc::RpcError {
        match self {
            BundleIngestError::Malformed(m) => rpc::RpcError {
                code: rpc::INVALID_PARAMS,
                message: format!("malformed bundle: {m}"),
            },
            BundleIngestError::Internal(m) => rpc::RpcError {
                code: rpc::INTERNAL_ERROR,
                message: m,
            },
        }
    }

    /// Maps to the sealed-channel `(code, message)` error form.
    fn pair_error(self) -> (i32, String) {
        let e = self.rpc_error();
        (e.code, e.message)
    }
}

/// Reads a DTN-carried record's `kind` discriminator from its canonical bytes,
/// or `None` if the bytes are not a canonical CBOR map with a text `kind`.
fn dtn_record_kind(bytes: &[u8]) -> Option<String> {
    use dcbor::prelude::*;
    let cbor = CBOR::try_from_data(bytes).ok()?;
    match cbor.into_case() {
        CBORCase::Map(map) => map.extract::<&str, String>("kind").ok(),
        _ => None,
    }
}

/// Maps a ledger admission error to the machine-stable refusal slug carried back
/// in the receipt. `Storage` is handled by the caller (it is internal, not a
/// refusal) and never reaches here.
fn map_refusal(e: &rrn_ledger::Error) -> RefusalReason {
    use rrn_ledger::Error as LE;
    match e {
        // A signature that did not verify.
        LE::BadSignature => RefusalReason::BadSignature,
        // A *valid* signature by the wrong party — an authorization fault, not a
        // verification failure, so it is not `bad-signature` (which would tell
        // the member their signature is broken). No dedicated slug; the catch-all
        // carries it.
        LE::SenderMismatch | LE::ConfirmerMismatch => RefusalReason::Rejected,
        LE::DuplicateProposal => RefusalReason::Duplicate,
        LE::BadNonce { .. } => RefusalReason::NonceGap,
        LE::Expired => RefusalReason::Expired,
        LE::TierNotSupported { .. } => RefusalReason::TierUnsupported,
        LE::DebtFloorExceeded { .. } => RefusalReason::DebtFloor,
        // The referenced transaction is absent or not in the state the record
        // needs — most commonly a confirmation whose proposal has not yet been
        // admitted (couriers must keep outbox order, ADR-0020 §4).
        LE::UnknownTransaction | LE::NotProposed => RefusalReason::NotProposed,
        // Everything else (future-dated/inconsistent testimony, wrong dispute
        // state, not-a-party, closed window, over-long reason, already-responded,
        // invalid state) has no more specific slug.
        _ => RefusalReason::Rejected,
    }
}

/// A refused [`Outcome`] for `record_hash` with `reason`.
fn refused(record_hash: Hash, reason: RefusalReason) -> Outcome {
    Outcome {
        record_hash,
        disposition: refused_disposition(reason),
    }
}

/// A refused [`Disposition`] with `reason`.
fn refused_disposition(reason: RefusalReason) -> Disposition {
    Disposition::Refused { reason }
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

/// Decodes an optional hex evidence hash from a dispute raise/response. An absent
/// field means "no evidence attached"; a present one must be a valid 32-byte hash.
fn parse_evidence_hash(s: &Option<String>) -> Result<Option<Hash>, rpc::RpcError> {
    let Some(s) = s else { return Ok(None) };
    Ok(Some(Hash::from_hex(s).map_err(|e| {
        invalid_params(format!("invalid evidence hash: {e}"))
    })?))
}

fn parse_proposal_id(s: &str) -> Result<ProposalId, rpc::RpcError> {
    let bytes = unhex(s).ok_or_else(|| invalid_params(format!("invalid proposal id {s:?}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_params("proposal id must be 32 bytes"))?;
    Ok(ProposalId(Hash::from_bytes(arr)))
}

fn parse_secret_keypair(hex_secret: &str) -> Result<Keypair, rpc::RpcError> {
    let bytes = unhex(hex_secret).ok_or_else(|| invalid_params("founder key is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_params("founder key must be 32 bytes"))?;
    Ok(Keypair::from_secret(
        rrn_crypto::keypair::SecretKey::from_bytes(arr),
    ))
}

/// Parses a hex-encoded 32-byte public key (a founder's identity).
fn parse_pubkey_hex(s: &str) -> Result<PublicKey, rpc::RpcError> {
    let bytes = unhex(s.trim()).ok_or_else(|| invalid_params("signer key is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_params("signer key must be 32 bytes"))?;
    PublicKey::from_bytes(arr).map_err(|_| invalid_params("signer key is not a valid public key"))
}

/// Parses a hex-encoded 64-byte Ed25519 signature.
fn parse_signature_hex(s: &str) -> Result<Signature, rpc::RpcError> {
    let bytes = unhex(s.trim()).ok_or_else(|| invalid_params("signature is not valid hex"))?;
    let arr: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_params("signature must be 64 bytes"))?;
    Signature::from_bytes(arr).map_err(|_| invalid_params("signature is malformed"))
}

fn parse_proposal_kind(p: &rpc::GovProposeParams) -> Result<ProposalKind, rpc::RpcError> {
    match p.kind.as_str() {
        "statute" => Ok(ProposalKind::Statute),
        "administrative_rule" | "admin_rule" | "admin-rule" => {
            let scope = p
                .scope
                .clone()
                .ok_or_else(|| invalid_params("an administrative_rule proposal needs a --scope"))?;
            Ok(ProposalKind::AdministrativeRule { scope })
        }
        "emergency" => {
            let expires_at = p
                .expires_at
                .ok_or_else(|| invalid_params("an emergency proposal needs --expires-at"))?;
            Ok(ProposalKind::Emergency { expires_at })
        }
        other => Err(invalid_params(format!(
            "unknown proposal kind {other:?} (statute, administrative_rule, emergency)"
        ))),
    }
}

fn parse_vote_choice(s: &str) -> Result<VoteChoice, rpc::RpcError> {
    match s {
        "yes" => Ok(VoteChoice::Yes),
        "no" => Ok(VoteChoice::No),
        "abstain" => Ok(VoteChoice::Abstain),
        other => Err(invalid_params(format!(
            "vote choice must be yes, no, or abstain, got {other:?}"
        ))),
    }
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

/// Builds a listing's [`RecurringTerms`](rrn_marketplace::listing::RecurringTerms)
/// from the `every`/`periods`/`notice`/`penalty` a create request carried. The
/// CLI offers only the three named cadences; a `Custom` interval exists in the
/// model but has no operator surface. `notice` and `penalty` default to zero (no
/// notice, no penalty). The listing's own `validate` enforces the rest — that
/// the surface is a service and the duration is at least one period.
fn recurring_terms_from(
    every: &str,
    periods: Option<u32>,
    notice_days: Option<u32>,
    penalty_centi: Option<i64>,
) -> Result<rrn_marketplace::listing::RecurringTerms, rpc::RpcError> {
    use rrn_marketplace::listing::Frequency;
    let frequency = match every {
        "daily" => Frequency::Daily,
        "weekly" => Frequency::Weekly,
        "monthly" => Frequency::Monthly,
        other => {
            return Err(invalid_params(format!(
                "unknown cadence {other:?} (daily, weekly, or monthly)"
            )))
        }
    };
    let duration_periods =
        periods.ok_or_else(|| invalid_params("a recurring listing needs --periods"))?;
    Ok(rrn_marketplace::listing::RecurringTerms {
        frequency,
        duration_periods,
        notice_period_days: notice_days.unwrap_or(0),
        early_termination_penalty_centi: penalty_centi.unwrap_or(0),
    })
}

/// Maps a marketplace error to an RPC error. A rule the caller's own request
/// broke — an unknown category, a listing that is not theirs to close, one
/// already closed — is their mistake to fix; only storage and index trouble is
/// ours.
fn marketplace_err(e: rrn_marketplace::Error) -> rpc::RpcError {
    use rrn_marketplace::Error::*;
    match e {
        Storage(_) | Tantivy(_) | Index(_) => internal(e),
        Listing(_) | Lifecycle(_) | Need(_) | Inquiry(_) | Contract(_) => {
            invalid_params(e.to_string())
        }
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

/// Maps a dispute-layer error to an RPC error, distinguishing caller mistakes
/// (an unseated juror, a duplicate verdict, a transaction that is not disputed)
/// from internal failures (storage, reputation). A nested ledger error routes
/// through [`ledger_err`] so its own caller-vs-infra split is preserved.
fn dispute_err(e: rrn_dispute::Error) -> rpc::RpcError {
    use rrn_dispute::Error::*;
    match e {
        Storage(_) | Reputation(_) | MissingAdmission => internal(e),
        Ledger(l) => ledger_err(l),
        NotDisputed | BadVerdict | NotSeated | AlreadyVoted | BadEscalation | BadBallot
        | NotEscalatable | AlreadyEscalated | NotEligible | NotEscalated => {
            invalid_params(e.to_string())
        }
    }
}

/// The channel's `(code, message)` form of a dispute error, for the mobile
/// write-path handlers that build a response envelope.
fn dispute_err_pair(e: rrn_dispute::Error) -> (i32, String) {
    let r = dispute_err(e);
    (r.code, r.message)
}

/// The wire name for a resolution outcome — a stable string owned here, not a
/// serde derive on the dispute layer's enum.
fn resolution_name(r: Resolution) -> &'static str {
    match r {
        Resolution::Pending => "pending",
        Resolution::AwaitingAppeal => "awaiting_appeal",
        Resolution::Upheld => "upheld",
        Resolution::Rejected => "rejected",
        Resolution::Lapsed => "lapsed",
        Resolution::EscalationPending => "escalation_pending",
        Resolution::EscalationUpheld => "escalation_upheld",
        Resolution::EscalationRejected => "escalation_rejected",
        Resolution::EscalationLapsed => "escalation_lapsed",
    }
}

/// Parses the wire reason string for a `dispute_escalate` call into the typed
/// [`EscalationReason`].
fn parse_escalation_reason(s: &str) -> Result<EscalationReason, rpc::RpcError> {
    match s {
        "appeal" => Ok(EscalationReason::Appeal),
        "cannot_seat" => Ok(EscalationReason::CannotSeat),
        other => Err(invalid_params(format!(
            "unknown escalation reason: {other}"
        ))),
    }
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

fn parse_inquiry_id(s: &str) -> Result<rrn_marketplace::inquiry::InquiryId, (i32, String)> {
    let bytes =
        unhex(s).ok_or_else(|| (rpc::INVALID_PARAMS, "inquiry_id is not hex".to_string()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        (
            rpc::INVALID_PARAMS,
            "inquiry_id is not 32 bytes".to_string(),
        )
    })?;
    Ok(rrn_marketplace::inquiry::InquiryId(Hash::from_bytes(bytes)))
}

fn parse_contract_id(s: &str) -> Result<ContractId, (i32, String)> {
    let bytes =
        unhex(s).ok_or_else(|| (rpc::INVALID_PARAMS, "contract_id is not hex".to_string()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        (
            rpc::INVALID_PARAMS,
            "contract_id is not 32 bytes".to_string(),
        )
    })?;
    Ok(ContractId(Hash::from_bytes(bytes)))
}

/// The `period_index` a contract's early-termination penalty rides on. Chosen
/// past any real period so it neither counts toward `periods_charged` nor
/// collides with a period's own idempotency key — a contract's duration is a
/// handful of periods, never near `u32::MAX`.
const PENALTY_PERIOD_INDEX: u32 = u32::MAX;

/// The set of period indices already charged for each contract, in one log pass.
///
/// This is where the station reads back `periods_charged` — the count the
/// contract crate takes as an input rather than deriving — so the charge sweep
/// and every state read agree on what the ledger has actually billed.
fn charged_periods_by_contract(log: &AppendLog) -> BTreeMap<ContractRef, BTreeSet<u32>> {
    let mut map: BTreeMap<ContractRef, BTreeSet<u32>> = BTreeMap::new();
    for entry in log.iter_from(1) {
        let Ok(entry) = entry else { continue };
        if let Ok(charge) = from_canonical_bytes::<ContractCharge>(&entry.payload.bytes) {
            map.entry(charge.contract_ref)
                .or_default()
                .insert(charge.period_index);
        }
    }
    map
}

/// How many real periods a contract has been charged, from a
/// [`charged_periods_by_contract`] map. The penalty's sentinel index is excluded
/// so it never counts as a period, matching what the charge sweep counts.
fn periods_charged_of(
    charged: &BTreeMap<ContractRef, BTreeSet<u32>>,
    id: &ContractId,
    total: u32,
) -> u32 {
    charged
        .get(&ContractRef(id.to_bytes()))
        .map(|periods| periods.iter().filter(|&&p| p < total).count() as u32)
        .unwrap_or(0)
}

/// The proposal a transaction carries, whatever state it has reached. Every
/// lifecycle state carries the proposal, so this is always `Some`.
fn proposal_of(state: &TransactionState) -> Option<&TransactionProposal> {
    match state {
        TransactionState::Proposed { proposal }
        | TransactionState::Confirmed { proposal, .. }
        | TransactionState::Settled { proposal, .. }
        | TransactionState::Cancelled { proposal, .. }
        | TransactionState::Disputed { proposal, .. } => Some(&proposal.payload),
    }
}

/// The listing a transaction pays for, if it is a marketplace payment (T1.7.6):
/// the `listing_id` the buyer signed into the proposal, named as a marketplace
/// [`ListingId`]. `None` for a direct pay.
fn linked_listing(state: &TransactionState) -> Option<ListingId> {
    proposal_of(state)?
        .listing_id
        .map(|ListingRef(bytes)| ListingId(Hash::from_bytes(bytes)))
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
        TransactionState::Disputed { .. } => "Disputed",
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
            rrn_ledger::credit::CreditConfig::default(),
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

    // --- disputes (T1.10.5) -------------------------------------------------

    /// Drives the operator dispute surface end to end without a jury: raise a
    /// dispute over a confirmed transaction, read it back, respond, and let it
    /// lapse to settled once its window closes (the fail-open default). A full
    /// rule→resolve with a seated jury is covered in `rrn-dispute`'s tests, which
    /// need the reputation seeding this unit core lacks.
    #[test]
    fn dispute_lifecycle_over_rpc_raise_read_respond_and_lapse() {
        let mut core = test_core();
        let station_addr = core.wallet.address.to_string();
        let station = core.station_keypair();
        let bob = Keypair::generate();
        let bob_addr = Address::from_public_key(bob.public_key());

        // Station proposes a small (Tier-1) payment to bob; bob confirms it. Bob's
        // confirmation is signed directly — the RPC `confirm` is station-as-receiver
        // only, and here the station is the sender.
        let proposed = call(
            &mut core,
            "propose",
            serde_json::json!({ "receiver": bob_addr.to_string(), "amount_centi": 100 }),
        );
        let tx_id = proposed["tx_id"].as_str().unwrap().to_string();
        let now = core.clock.now();
        let confirmation = TransactionConfirmation {
            proposal_id: parse_tx_id(&tx_id).unwrap(),
            confirmer: bob_addr,
            confirmed_at: now,
        };
        Engine::new(&core.db, station.clone())
            .submit_confirmation(SignedConfirmation::sign(confirmation, &bob), now)
            .unwrap();

        // Raise a dispute over RPC (station-signed; the station is the sender, a party).
        let raised = call(
            &mut core,
            "dispute_raise",
            serde_json::json!({ "tx_id": tx_id, "reason": "never delivered" }),
        );
        assert_eq!(raised["state"], "Disputed");

        // It shows in the browse list and the detail read, pending (no jury seated).
        let list = call(&mut core, "disputes", serde_json::json!({}));
        assert_eq!(list["disputes"].as_array().unwrap().len(), 1);
        let detail = call(&mut core, "dispute", serde_json::json!({ "tx_id": tx_id }));
        assert_eq!(detail["resolution"], "pending");
        assert_eq!(detail["raiser"], station_addr);

        // The station files a response; it appears on the dispute.
        call(
            &mut core,
            "dispute_respond",
            serde_json::json!({ "tx_id": tx_id, "statement": "it was delivered on time" }),
        );
        let detail = call(&mut core, "dispute", serde_json::json!({ "tx_id": tx_id }));
        assert_eq!(detail["responses"].as_array().unwrap().len(), 1);

        // Advance past the freeze window; a resolve sweep lapses it to settled.
        core.clock
            .advance(rrn_dispute::DEFAULT_DISPUTE_WINDOW_SECONDS + 1);
        let resolved = call(&mut core, "dispute_resolve", serde_json::json!({}));
        assert_eq!(resolved["resolved"][0]["resolution"], "lapsed");

        // No longer disputed; it is settled and off the disputes list.
        assert!(
            call(&mut core, "disputes", serde_json::json!({}))["disputes"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            Engine::new(&core.db, station)
                .get_state(&parse_tx_id(&tx_id).unwrap())
                .unwrap(),
            Some(TransactionState::Settled { .. })
        ));
    }

    #[test]
    fn raising_a_dispute_on_an_unknown_transaction_is_rejected() {
        let mut core = test_core();
        let err = call_err(
            &mut core,
            "dispute_raise",
            serde_json::json!({ "tx_id": "00".repeat(32), "reason": "x" }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn reading_a_dispute_that_does_not_exist_is_rejected() {
        let mut core = test_core();
        let err = call_err(
            &mut core,
            "dispute",
            serde_json::json!({ "tx_id": "00".repeat(32) }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    /// Drives the escalation surface (T1.10.4b) over RPC. This bare core seats no
    /// jury (no established members), so a raised dispute is a genuine cannot-seat
    /// case: the station (a party) escalates it to the electorate, and with no
    /// electorate to reach quorum it fails open — the transaction settles. The
    /// electorate-vote paths need reputation seeding and are covered in
    /// `rrn-dispute`'s tests.
    #[test]
    fn escalation_lifecycle_over_rpc_cannot_seat_then_lapses() {
        let mut core = test_core();
        let station = core.station_keypair();
        let bob = Keypair::generate();
        let bob_addr = Address::from_public_key(bob.public_key());

        // Station→bob payment, confirmed, then disputed by the station.
        let proposed = call(
            &mut core,
            "propose",
            serde_json::json!({ "receiver": bob_addr.to_string(), "amount_centi": 100 }),
        );
        let tx_id = proposed["tx_id"].as_str().unwrap().to_string();
        let now = core.clock.now();
        let confirmation = TransactionConfirmation {
            proposal_id: parse_tx_id(&tx_id).unwrap(),
            confirmer: bob_addr,
            confirmed_at: now,
        };
        Engine::new(&core.db, station.clone())
            .submit_confirmation(SignedConfirmation::sign(confirmation, &bob), now)
            .unwrap();
        call(
            &mut core,
            "dispute_raise",
            serde_json::json!({ "tx_id": tx_id, "reason": "never delivered" }),
        );

        // Appealing a ruling that does not exist is refused.
        let err = call_err(
            &mut core,
            "dispute_escalate",
            serde_json::json!({ "tx_id": tx_id, "reason": "appeal" }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);

        // With no eligible jurors, a cannot-seat escalation is valid.
        let escalated = call(
            &mut core,
            "dispute_escalate",
            serde_json::json!({ "tx_id": tx_id, "reason": "cannot_seat" }),
        );
        assert_eq!(escalated["reason"], "cannot_seat");

        // The dispute now reads as an open escalation.
        let detail = call(&mut core, "dispute", serde_json::json!({ "tx_id": tx_id }));
        assert_eq!(detail["resolution"], "escalation_pending");
        assert_eq!(detail["escalation"]["reason"], "cannot_seat");

        // A second escalation on the same dispute is refused.
        let err = call_err(
            &mut core,
            "dispute_escalate",
            serde_json::json!({ "tx_id": tx_id, "reason": "cannot_seat" }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);

        // Nobody votes; past the sub-window it fails open and settles.
        core.clock
            .advance(rrn_dispute::DEFAULT_ESCALATION_WINDOW_SECONDS + 1);
        let resolved = call(&mut core, "dispute_resolve", serde_json::json!({}));
        assert_eq!(resolved["resolved"][0]["resolution"], "escalation_lapsed");
        assert!(matches!(
            Engine::new(&core.db, station)
                .get_state(&parse_tx_id(&tx_id).unwrap())
                .unwrap(),
            Some(TransactionState::Settled { .. })
        ));
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
            NOW,
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
    fn whoami_reports_bootstrap_grace_for_a_fresh_community() {
        let mut core = test_core();
        let who = call(&mut core, "whoami", serde_json::json!({}));
        // A brand-new station has no established members, so the community is in
        // bootstrap grace and the phone will show its "new community" banner.
        assert_eq!(who["bootstrap_in_grace"], true);
        assert_eq!(who["established_members"], 0);
        assert_eq!(
            who["grace_threshold"],
            rrn_reputation::staking::BOOTSTRAP_GRACE_THRESHOLD as u64
        );
    }

    #[test]
    fn a_mobile_confirming_a_tier2_payment_runs_the_stake_gate_and_grace_allows_it() {
        let mut core = test_core();
        let sender = Keypair::generate();
        let receiver = Keypair::generate(); // the confirming mobile
        let receiver_addr = Address::from_public_key(receiver.public_key());

        // A Tier-2 proposal — 15 Commons = 1500 centi, above the 5-Common Tier-2
        // floor but within the sender's −20 Commons debt floor (ADR-0018) —
        // submitted over the channel by its sender.
        let proposal = TransactionProposal::new(
            Address::from_public_key(sender.public_key()),
            receiver_addr,
            1500,
            Some("t2".into()),
            0,
            NOW,
            NOW + 86_400,
        );
        let tx_id = proposal.id;
        let env = envelope(
            &sender,
            "submit_proposal",
            serde_json::json!({ "signed_proposal": record_hex(proposal, &sender) }),
        );
        core.route_channel_method(&env).expect("proposal accepted");

        // The receiver confirms over the channel — the path the gate must cover
        // (the operator `m_confirm` gate does not run here). A brand-new station
        // has no established members, so bootstrap grace lets any member confirm a
        // Tier-2 payment: the gate runs and allows rather than being bypassed.
        let confirmation = TransactionConfirmation {
            proposal_id: tx_id,
            confirmer: receiver_addr,
            confirmed_at: NOW + 10,
        };
        let env = envelope(
            &receiver,
            "submit_confirmation",
            serde_json::json!({ "signed_confirmation": record_hex(confirmation, &receiver) }),
        );
        let result = core
            .route_channel_method(&env)
            .expect("tier-2 confirm allowed in grace");
        assert_eq!(result["state"], "Confirmed");
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

    // --- DTN bundle ingest (T2.2.3, ADR-0020) -------------------------------

    use rrn_protocol::bundle::{Bundle, EntryEnvelope};
    use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};

    fn zero() -> Hash {
        Hash::from_bytes([0u8; 32])
    }

    /// Wraps an already-signed application record as a signed outbox entry for
    /// `device` (author == outer signer, as `outbox::validate` requires).
    fn outbox_entry<T: Clone + Into<dcbor::CBOR>>(
        device: &Keypair,
        position: u64,
        prev: Hash,
        record: &SignedPayload<T>,
        authored_at: i64,
    ) -> SignedOutboxEntry {
        let entry = OutboxEntry::wrapping(
            Address::from_public_key(device.public_key()),
            position,
            prev,
            record,
            authored_at,
        );
        SignedPayload::sign(entry, device)
    }

    fn encode_bundle(entries: &[SignedOutboxEntry], assembled_at: i64) -> String {
        let envs: Vec<EntryEnvelope> = entries.iter().map(EntryEnvelope::from_signed).collect();
        hex(&Bundle::new(envs, assembled_at).encode())
    }

    /// Submits a bundle through the operator `bundle_submit` RPC and returns the
    /// decoded, signature-verified receipt.
    fn submit_bundle(
        core: &mut Core,
        entries: &[SignedOutboxEntry],
        assembled_at: i64,
    ) -> SignedReceipt {
        let result = call(
            core,
            "bundle_submit",
            serde_json::json!({ "bundle_hex": encode_bundle(entries, assembled_at) }),
        );
        let receipt_hex = result["receipt_hex"].as_str().unwrap();
        let signed = receipt::decode_signed(&unhex(receipt_hex).unwrap()).unwrap();
        assert!(signed.verify().is_ok(), "the station receipt must verify");
        signed
    }

    fn member_proposal(
        sender: &Keypair,
        receiver: &Keypair,
        amount: i64,
        nonce: u64,
        proposed_at: i64,
        expires_at: i64,
    ) -> SignedProposal {
        let p = TransactionProposal::new(
            Address::from_public_key(sender.public_key()),
            Address::from_public_key(receiver.public_key()),
            amount,
            None,
            nonce,
            proposed_at,
            expires_at,
        );
        SignedProposal::sign(p, sender)
    }

    fn member_confirmation(
        receiver: &Keypair,
        proposal: &SignedProposal,
        confirmed_at: i64,
    ) -> SignedConfirmation {
        let c = TransactionConfirmation {
            proposal_id: proposal.payload.id,
            confirmer: Address::from_public_key(receiver.public_key()),
            confirmed_at,
        };
        SignedConfirmation::sign(c, receiver)
    }

    fn tx_state(core: &Core, id: &TransactionId) -> Option<TransactionState> {
        rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&core.db))
            .unwrap()
            .get(id)
            .cloned()
    }

    /// End-to-end via DTN only: two members sign a proposal and confirmation
    /// offline, the station admits both from a single ingested bundle, and the
    /// transaction settles a full window after **ingest** — never after the
    /// (earlier) claimed `confirmed_at`. Proves the T2.1.2 admission-clock
    /// integration: no live submission RPC is used.
    #[test]
    fn dtn_happy_path_admits_and_settles_from_admission() {
        let mut core = test_core(); // clock = 1000
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        // Signed offline: proposed/confirmed well before ingest (testimony only).
        let proposal = member_proposal(&alice, &bob, 300, 0, 900, 900 + 1_000_000);
        let confirmation = member_confirmation(&bob, &proposal, 950);
        let entries = [
            outbox_entry(&alice, 0, zero(), &proposal, 900),
            outbox_entry(&bob, 0, zero(), &confirmation, 950),
        ];

        let receipt = submit_bundle(&mut core, &entries, 1000);
        assert!(matches!(
            receipt.payload.outcomes[0].disposition,
            Disposition::Admitted { .. }
        ));
        assert!(matches!(
            receipt.payload.outcomes[1].disposition,
            Disposition::Admitted { .. }
        ));
        assert_eq!(receipt.payload.received_at, 1000);

        // The transaction is Confirmed purely from the DTN path.
        assert!(matches!(
            tx_state(&core, &proposal.payload.id),
            Some(TransactionState::Confirmed { .. })
        ));

        // Window (Tier 1: 86_400s) runs from admission (1000), NOT from the
        // claimed confirmed_at (950). Past confirmed_at+window but before
        // admission+window, it must still be unsettled.
        core.clock.advance(950 + 86_400 + 10 - 1000); // clock = 87_360
        core.do_sweep();
        assert!(
            matches!(
                tx_state(&core, &proposal.payload.id),
                Some(TransactionState::Confirmed { .. })
            ),
            "settling from confirmed_at would be premature — window anchors on admission"
        );

        // Past admission+window: it settles and the balances move.
        core.clock.advance(1000 + 86_400 + 10 - 87_360); // clock = 87_410
        core.do_sweep();
        assert!(matches!(
            tx_state(&core, &proposal.payload.id),
            Some(TransactionState::Settled { .. })
        ));
        let alice_addr = Address::from_public_key(alice.public_key());
        let bob_addr = Address::from_public_key(bob.public_key());
        assert_eq!(
            ledger_view::balance_of(&core.db, &alice_addr).unwrap(),
            -300
        );
        assert_eq!(ledger_view::balance_of(&core.db, &bob_addr).unwrap(), 300);
    }

    /// A bundle mixing a good record, a bad signature, an already-admitted
    /// duplicate, and an unroutable kind — each answered independently, the good
    /// record unaffected.
    #[test]
    fn dtn_mixed_bundle_reports_per_record_outcomes() {
        let mut core = test_core();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let charlie = Keypair::generate();
        let dave = Keypair::generate();

        // Pre-admit charlie's proposal so the mixed bundle can re-carry it as a
        // known duplicate.
        let dup = member_proposal(&charlie, &bob, 100, 0, 900, 900 + 1_000_000);
        let dup_entry = outbox_entry(&charlie, 0, zero(), &dup, 900);
        submit_bundle(&mut core, std::slice::from_ref(&dup_entry), 1000);

        // The four mixed entries (distinct authors, so bundle order is trivially
        // valid).
        let good = member_proposal(&alice, &bob, 200, 0, 900, 900 + 1_000_000);
        let good_entry = outbox_entry(&alice, 0, zero(), &good, 900);

        let mut bad_entry = outbox_entry(
            &bob,
            0,
            zero(),
            &member_proposal(&bob, &alice, 50, 0, 900, 900 + 1_000_000),
            900,
        );
        bad_entry.signature = bob.sign(b"not the entry body"); // outer sig no longer verifies

        let vouch = create_vouch(
            &dave,
            &Address::from_public_key(bob.public_key()),
            "c",
            "hi",
            0,
        );
        let unroutable_entry = outbox_entry(&dave, 0, zero(), &vouch, 900);

        let receipt = submit_bundle(
            &mut core,
            &[good_entry, bad_entry, dup_entry, unroutable_entry],
            2000,
        );
        let d: Vec<_> = receipt
            .payload
            .outcomes
            .iter()
            .map(|o| o.disposition)
            .collect();
        assert!(
            matches!(d[0], Disposition::Admitted { .. }),
            "good admitted"
        );
        assert!(
            matches!(
                d[1],
                Disposition::Refused {
                    reason: RefusalReason::BadSignature
                }
            ),
            "bad signature refused"
        );
        assert!(matches!(d[2], Disposition::Known { .. }), "duplicate known");
        assert!(
            matches!(
                d[3],
                Disposition::Refused {
                    reason: RefusalReason::UnroutableKind
                }
            ),
            "unroutable kind refused"
        );

        // The good record really did land.
        assert!(tx_state(&core, &good.payload.id).is_some());
    }

    /// Re-ingesting a byte-identical presentation returns the stored receipt
    /// verbatim and admits nothing new.
    #[test]
    fn dtn_ingest_is_idempotent() {
        let mut core = test_core();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let proposal = member_proposal(&alice, &bob, 300, 0, 900, 900 + 1_000_000);
        let entries = [outbox_entry(&alice, 0, zero(), &proposal, 900)];
        let bundle_hex = encode_bundle(&entries, 1000);

        let first = call(
            &mut core,
            "bundle_submit",
            serde_json::json!({ "bundle_hex": bundle_hex }),
        );
        let len_after_first = core.tail_seq();

        let second = call(
            &mut core,
            "bundle_submit",
            serde_json::json!({ "bundle_hex": bundle_hex }),
        );
        assert_eq!(
            first["receipt_hex"], second["receipt_hex"],
            "an identical presentation returns a byte-identical receipt"
        );
        assert_eq!(
            core.tail_seq(),
            len_after_first,
            "no record is re-admitted on re-ingest"
        );
    }

    /// Two validly-signed entries from one author at the same position with
    /// different content: the second is refused `outbox-fork` and both envelopes
    /// are persisted as evidence.
    #[test]
    fn dtn_fork_is_refused_and_evidence_persisted() {
        let mut core = test_core();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        // Two DIFFERENT proposals equivocating at nonce 0 / outbox position 0.
        let a = member_proposal(&alice, &bob, 300, 0, 900, 900 + 1_000_000);
        let b = member_proposal(&alice, &bob, 700, 0, 900, 900 + 1_000_000);
        let entry_a = outbox_entry(&alice, 0, zero(), &a, 900);
        let entry_b = outbox_entry(&alice, 0, zero(), &b, 900);
        assert_ne!(
            entry_a.payload.entry_hash(),
            entry_b.payload.entry_hash(),
            "a genuine fork"
        );

        let receipt = submit_bundle(&mut core, &[entry_a.clone(), entry_b.clone()], 1000);
        assert!(matches!(
            receipt.payload.outcomes[0].disposition,
            Disposition::Admitted { .. }
        ));
        assert!(matches!(
            receipt.payload.outcomes[1].disposition,
            Disposition::Refused {
                reason: RefusalReason::OutboxFork
            }
        ));

        // Evidence: both envelopes, verbatim.
        let author = alice.public_key().to_bytes();
        let fork = DtnStore::new(&core.db)
            .fork_at(&author, 0)
            .unwrap()
            .expect("fork evidence persisted");
        assert_eq!(fork.entry_hash_a, entry_a.payload.entry_hash().to_bytes());
        assert_eq!(fork.entry_hash_b, entry_b.payload.entry_hash().to_bytes());
        assert_eq!(
            fork.envelope_a,
            to_canonical_bytes(EntryEnvelope::from_signed(&entry_a))
        );
        assert_eq!(
            fork.envelope_b,
            to_canonical_bytes(EntryEnvelope::from_signed(&entry_b))
        );
    }

    /// A gap in an author's carried positions does not refuse the entry; the
    /// contiguous head simply does not advance past the gap, and a later ingest
    /// that fills the gap advances it across every position already seen.
    #[test]
    fn dtn_gap_holds_head_then_fills() {
        let mut core = test_core();
        let alice = Keypair::generate();
        // A 3-entry chain wrapping unroutable records (vouches): this test is
        // about outbox positions, not admission. Correctly linked so each entry
        // validates.
        let subj = Address::from_public_key(Keypair::generate().public_key());
        let v0 = create_vouch(&alice, &subj, "c", "a", 0);
        let e0 = outbox_entry(&alice, 0, zero(), &v0, 900);
        let v1 = create_vouch(&alice, &subj, "c", "b", 1);
        let e1 = outbox_entry(&alice, 1, e0.payload.entry_hash(), &v1, 901);
        let v2 = create_vouch(&alice, &subj, "c", "d", 2);
        let e2 = outbox_entry(&alice, 2, e1.payload.entry_hash(), &v2, 902);

        let author = alice.public_key().to_bytes();

        // Carry positions 0 and 2 (gap at 1): both processed, head stays at 0.
        submit_bundle(&mut core, &[e0.clone(), e2.clone()], 1000);
        assert_eq!(
            DtnStore::new(&core.db)
                .head(&author)
                .unwrap()
                .unwrap()
                .position,
            0
        );

        // Position 1 arrives later → the head jumps across the now-contiguous run
        // to 2.
        submit_bundle(&mut core, std::slice::from_ref(&e1), 1100);
        assert_eq!(
            DtnStore::new(&core.db)
                .head(&author)
                .unwrap()
                .unwrap()
                .position,
            2
        );
    }

    /// Within a bundle, a confirmation admitted after its proposal admits both;
    /// the reversed order refuses the confirmation `not-proposed` (couriers must
    /// keep outbox order — the proposal has not been admitted first).
    #[test]
    fn dtn_confirmation_needs_its_proposal_admitted_first() {
        let mut core = test_core();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let proposal = member_proposal(&alice, &bob, 300, 0, 900, 900 + 1_000_000);
        let confirmation = member_confirmation(&bob, &proposal, 950);
        let p_entry = outbox_entry(&alice, 0, zero(), &proposal, 900);
        let c_entry = outbox_entry(&bob, 0, zero(), &confirmation, 950);

        // Reversed: confirmation before proposal in the same bundle.
        let receipt = submit_bundle(&mut core, &[c_entry, p_entry], 1000);
        assert!(
            matches!(
                receipt.payload.outcomes[0].disposition,
                Disposition::Refused {
                    reason: RefusalReason::NotProposed
                }
            ),
            "a confirmation whose proposal is not yet admitted is refused not-proposed"
        );
        assert!(
            matches!(
                receipt.payload.outcomes[1].disposition,
                Disposition::Admitted { .. }
            ),
            "the proposal still admits"
        );
        // The transaction is Proposed (not Confirmed) — the confirmation did not
        // land. A courier that keeps outbox order (proposal first) would settle
        // it; that forward path is the happy-path test.
        assert!(matches!(
            tx_state(&core, &proposal.payload.id),
            Some(TransactionState::Proposed { .. })
        ));
    }

    /// A Tier-2 confirmation carried over DTN is held to the **same** reputation-
    /// staking bar the live paths enforce (T1.8.2): once bootstrap grace has
    /// ended, a confirmer below the Member band is refused `tier2-stake` — the
    /// DTN path is not a way around the gate. Pins the shared
    /// `tier2_confirmation_gate`.
    #[test]
    fn dtn_tier2_confirmation_is_held_to_the_staking_bar() {
        let mut core = established_core(); // clock = TEN_MONTHS
        let now = core.clock.now();
        // End bootstrap grace: three established members exist.
        gov_established_members(&core.db, 3, now);

        let sender = Keypair::generate();
        let alice = Keypair::generate(); // fresh — below the Member band; the confirmer
                                         // A Tier-2 payment (10 Commons ≥ 5) to alice, signed offline.
        let proposal = member_proposal(&sender, &alice, 1000, 0, now - 1000, now + 1_000_000);
        assert_eq!(proposal.payload.effective_tier(), 2, "a Tier-2 amount");
        let confirmation = member_confirmation(&alice, &proposal, now - 500);
        let entries = [
            outbox_entry(&sender, 0, zero(), &proposal, now - 1000),
            outbox_entry(&alice, 0, zero(), &confirmation, now - 500),
        ];

        let receipt = submit_bundle(&mut core, &entries, now);
        assert!(
            matches!(
                receipt.payload.outcomes[0].disposition,
                Disposition::Admitted { .. }
            ),
            "the proposal admits"
        );
        assert!(
            matches!(
                receipt.payload.outcomes[1].disposition,
                Disposition::Refused {
                    reason: RefusalReason::Tier2Stake
                }
            ),
            "the confirmation is gated by the Tier-2 staking bar, not bypassed"
        );
        // The confirmation did not land — the transaction stays Proposed.
        assert!(matches!(
            tx_state(&core, &proposal.payload.id),
            Some(TransactionState::Proposed { .. })
        ));
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
    fn cli_edits_a_listing_and_the_id_holds_while_the_fields_change() {
        let mut core = test_core();
        let created = call(
            &mut core,
            "marketplace_create_listing",
            create_params("Squash"),
        );
        let listing_id = created["listing_id"].as_str().unwrap().to_string();

        // Patch price and description; leave capacity and everything else alone.
        let edited = call(
            &mut core,
            "marketplace_edit_listing",
            serde_json::json!({
                "listing_id": listing_id,
                "amount_centi": 999,
                "description": "Now half price.",
            }),
        );
        // A listing's content address is its identity — an edit never moves it.
        assert_eq!(edited["listing_id"], listing_id);

        let detail = call(
            &mut core,
            "marketplace_listing",
            serde_json::json!({ "listing_id": listing_id }),
        );
        assert_eq!(detail["amount_centi"], 999);
        assert_eq!(detail["description"], "Now half price.");
        // A field the patch did not name is carried from the current listing.
        assert_eq!(detail["availability"]["capacity"], 12);
        assert_eq!(detail["state"], "active");

        // An empty patch is refused rather than written as a no-op.
        let err = call_err(
            &mut core,
            "marketplace_edit_listing",
            serde_json::json!({ "listing_id": listing_id }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);

        // So is editing a listing that does not exist.
        let err = call_err(
            &mut core,
            "marketplace_edit_listing",
            serde_json::json!({ "listing_id": "00".repeat(32), "amount_centi": 100 }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn editing_a_price_alone_keeps_the_pricing_model() {
        let mut core = test_core();
        // A negotiable listing, edited with only a new price, stays negotiable —
        // the untouched half of pricing is carried from the current listing.
        let mut params = create_params("Firewood, make an offer");
        params["negotiable"] = serde_json::json!(true);
        let listing_id = call(&mut core, "marketplace_create_listing", params)["listing_id"]
            .as_str()
            .unwrap()
            .to_string();

        call(
            &mut core,
            "marketplace_edit_listing",
            serde_json::json!({ "listing_id": listing_id, "amount_centi": 250 }),
        );
        let detail = call(
            &mut core,
            "marketplace_listing",
            serde_json::json!({ "listing_id": listing_id }),
        );
        assert_eq!(detail["amount_centi"], 250);
        assert_eq!(detail["pricing_model"], "negotiable");
        assert_eq!(detail["negotiable"], true);
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

    // --- service contract charge sweep (T1.7.7 Part D) ----------------------

    use rrn_marketplace::contract::{
        append_contract_termination, append_service_contract, ContractId, ContractTermination,
        ContractTerms, ServiceContract, TerminatedBy,
    };
    use rrn_marketplace::inquiry::{
        append_inquiry_closed, append_inquiry_opened, InquiryClosed, InquiryOpened, InquiryOutcome,
    };
    use rrn_marketplace::listing::{Frequency, RecurringTerms};

    const CONTRACT_PRICE: i64 = 500;
    const CONTRACT_PERIODS: u32 = 4;
    const CONTRACT_NOTICE_DAYS: u32 = 7;
    const CONTRACT_PENALTY: i64 = 300;
    const WEEK_SECS: i64 = 7 * 86_400;

    /// A recurring weekly services listing in the station's own community, so the
    /// sweep's real requirements gate admits a fresh buyer (min reputation 0).
    fn recurring_listing(provider: &Keypair) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            VOUCH_COMMUNITY.into(),
            Surface::Services,
            "education".into(),
            "Weekly house clean".into(),
            "Every Tuesday.".into(),
            Pricing {
                amount_centi: CONTRACT_PRICE,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: None,
                next_slot: Some(NOW + WEEK_SECS),
            },
            Requirements {
                min_reputation: 0.0,
                community_member_only: false,
                federation_only: false,
            },
            2,
            false,
            NOW,
            None,
        )
        .unwrap()
        .with_recurring(RecurringTerms {
            frequency: Frequency::Weekly,
            duration_periods: CONTRACT_PERIODS,
            notice_period_days: CONTRACT_NOTICE_DAYS,
            early_termination_penalty_centi: CONTRACT_PENALTY,
        })
    }

    /// Stands up a whole valid contract on the core's log — recurring listing,
    /// buyer's inquiry, provider's grant at the listed price, buyer's signed
    /// contract starting at `NOW` — and returns the contract's id and parties.
    /// Seeds the chain a contract is born from — a recurring listing, the buyer's
    /// inquiry, and the provider's agreed close — and returns the listing and the
    /// inquiry's id. Both [`seed_contract`] and the channel test build a contract
    /// on top of this, one appending it directly and one routing a buyer-signed
    /// one through the mobile channel.
    fn seed_agreed_inquiry(
        core: &Core,
        provider: &Keypair,
        buyer: &Keypair,
    ) -> (Listing, rrn_marketplace::inquiry::InquiryId) {
        let station_pk = core.station_keypair().public_key();
        let admit_all = |_: &Listing, _: &Address| true;
        let listing = recurring_listing(provider);
        let buyer_addr = Address::from_public_key(buyer.public_key());

        let mut log = AppendLog::new(&core.db);
        append_listing_created(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(listing.clone(), provider),
            NOW,
        )
        .unwrap();

        let opened =
            InquiryOpened::new(listing.id, buyer_addr, "Sign me up.".into(), None, NOW).unwrap();
        let inquiry_id = opened.inquiry_id;
        append_inquiry_opened(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(opened, buyer),
            &listing,
            0.0,
            true,
            NOW,
        )
        .unwrap();
        append_inquiry_closed(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(
                InquiryClosed {
                    inquiry_id,
                    outcome: InquiryOutcome::Agreed {
                        final_price_centi: CONTRACT_PRICE,
                    },
                    closed_at: NOW,
                },
                provider,
            ),
            &station_pk,
            &admit_all,
            NOW,
        )
        .unwrap();
        (listing, inquiry_id)
    }

    /// The terms every seeded contract commits to, matching [`recurring_listing`]'s
    /// cadence and the agreed price.
    fn seed_contract_terms() -> ContractTerms {
        ContractTerms {
            frequency: Frequency::Weekly,
            duration_periods: CONTRACT_PERIODS,
            commons_per_period_centi: CONTRACT_PRICE,
            performance_metrics: std::collections::BTreeMap::new(),
            notice_period_days: CONTRACT_NOTICE_DAYS,
            early_termination_penalty_centi: CONTRACT_PENALTY,
        }
    }

    fn seed_contract(core: &Core, provider: &Keypair, buyer: &Keypair) -> ContractId {
        let (listing, inquiry_id) = seed_agreed_inquiry(core, provider, buyer);
        let buyer_addr = Address::from_public_key(buyer.public_key());
        let provider_addr = Address::from_public_key(provider.public_key());
        let contract = ServiceContract::new(
            inquiry_id,
            listing.id,
            buyer_addr,
            provider_addr,
            seed_contract_terms(),
            NOW,
        )
        .unwrap();
        let contract_id = contract.contract_id;
        let mut log = AppendLog::new(&core.db);
        append_service_contract(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(contract, buyer),
            &core.station_keypair().public_key(),
            &|_: &Listing, _: &Address| true,
            NOW,
        )
        .unwrap();
        contract_id
    }

    /// Seeds a one-off goods inquiry the *station wallet* opened — the buyer the
    /// `marketplace_settle_inquiry` path settles as. `agreed` closes it at that
    /// price (provider-granted); `None` leaves it open. Returns the listing and id.
    fn seed_station_inquiry(
        core: &Core,
        provider: &Keypair,
        agreed: Option<i64>,
    ) -> (Listing, rrn_marketplace::inquiry::InquiryId) {
        let station = core.station_keypair();
        let station_pk = station.public_key();
        let admit_all = |_: &Listing, _: &Address| true;
        // Negotiable so the grant can settle on a price above the listed one,
        // which lets the test prove the payment carries the *agreed* price.
        let listing = Listing::new(
            Address::from_public_key(provider.public_key()),
            "blue_ridge_collective".into(),
            Surface::Goods,
            "food".into(),
            "Seed potatoes".into(),
            "Picked this week.".into(),
            Pricing {
                amount_centi: 250,
                model: PricingModel::Negotiable,
                negotiable: true,
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
            Some(NOW + 10_000),
        )
        .unwrap();

        let mut log = AppendLog::new(&core.db);
        append_listing_created(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(listing.clone(), provider),
            NOW,
        )
        .unwrap();

        // The buyer's opening offer is the price the grant settles on — the
        // provider may only agree at the buyer's standing offer.
        let opened = InquiryOpened::new(
            listing.id,
            core.wallet.address,
            "I'll take it.".into(),
            agreed,
            NOW,
        )
        .unwrap();
        let inquiry_id = opened.inquiry_id;
        append_inquiry_opened(
            &mut log,
            rrn_crypto::signed::SignedPayload::sign(opened, &station),
            &listing,
            0.0,
            true,
            NOW,
        )
        .unwrap();
        if let Some(final_price_centi) = agreed {
            append_inquiry_closed(
                &mut log,
                rrn_crypto::signed::SignedPayload::sign(
                    InquiryClosed {
                        inquiry_id,
                        outcome: InquiryOutcome::Agreed { final_price_centi },
                        closed_at: NOW,
                    },
                    provider,
                ),
                &station_pk,
                &admit_all,
                NOW,
            )
            .unwrap();
        }
        (listing, inquiry_id)
    }

    fn settle_req(inquiry_id: &rrn_marketplace::inquiry::InquiryId) -> rpc::Request {
        rpc::Request {
            id: "1".into(),
            method: "marketplace_settle_inquiry".into(),
            params: serde_json::json!({ "inquiry_id": hex(&inquiry_id.to_bytes()) }),
        }
    }

    #[test]
    fn settling_an_agreed_inquiry_pays_the_provider_at_the_agreed_price() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let (listing, inquiry_id) = seed_station_inquiry(&core, &provider, Some(400));
        let provider_addr = Address::from_public_key(provider.public_key());

        let v = core.handle_call(&settle_req(&inquiry_id)).unwrap();
        assert_eq!(v["state"], "Proposed");
        let tx_id = v["tx_id"].as_str().unwrap().to_string();

        // The proposal stands on the log: from the station, to the provider, at the
        // granted price, and linked to the listing so settlement can attest the sale.
        let snapshot =
            rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&core.db)).unwrap();
        let state = snapshot.get(&parse_tx_id(&tx_id).unwrap()).unwrap();
        let proposal = proposal_of(state).unwrap();
        assert_eq!(proposal.sender, core.wallet.address);
        assert_eq!(proposal.receiver, provider_addr);
        assert_eq!(proposal.amount_centi, 400);
        assert_eq!(linked_listing(state), Some(listing.id));
        assert!(proposal
            .memo
            .as_deref()
            .unwrap()
            .starts_with("Seed potatoes · #"));
    }

    #[test]
    fn settling_the_same_agreement_twice_returns_the_one_payment() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let (_listing, inquiry_id) = seed_station_inquiry(&core, &provider, Some(400));

        let first = core.handle_call(&settle_req(&inquiry_id)).unwrap();
        let second = core.handle_call(&settle_req(&inquiry_id)).unwrap();
        assert_eq!(first["tx_id"], second["tx_id"]);

        // Only one proposal was ever appended — the second call found the first.
        let count = rrn_ledger::state::LedgerSnapshot::derive(&AppendLog::new(&core.db))
            .unwrap()
            .iter()
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn an_inquiry_that_is_not_agreed_cannot_be_settled() {
        let mut core = test_core();
        let provider = Keypair::generate();
        let (_listing, inquiry_id) = seed_station_inquiry(&core, &provider, None);

        let err = core.handle_call(&settle_req(&inquiry_id)).unwrap_err();
        assert!(err.message.contains("not agreed"), "{}", err.message);
    }

    #[test]
    fn only_the_inquirys_buyer_may_settle_it() {
        let mut core = test_core();
        // Here the buyer is a third party, not the station wallet.
        let (provider, buyer) = (Keypair::generate(), Keypair::generate());
        let (_listing, inquiry_id) = seed_agreed_inquiry(&core, &provider, &buyer);

        let err = core.handle_call(&settle_req(&inquiry_id)).unwrap_err();
        assert!(err.message.contains("buyer"), "{}", err.message);
    }

    #[test]
    fn the_charge_sweep_bills_due_periods_once_and_catches_up() {
        let mut core = test_core();
        let (provider, buyer) = (Keypair::generate(), Keypair::generate());
        seed_contract(&core, &provider, &buyer);
        let buyer_addr = Address::from_public_key(buyer.public_key());
        let provider_addr = Address::from_public_key(provider.public_key());

        // At NOW only period 0 is due: one charge, buyer debited, provider paid.
        assert_eq!(core.do_charge_contracts(), 1);
        assert_eq!(
            ledger_view::balance_of(&core.db, &buyer_addr).unwrap(),
            -500
        );
        assert_eq!(
            ledger_view::balance_of(&core.db, &provider_addr).unwrap(),
            500
        );

        // Re-running the sweep at the same instant charges nothing more — the
        // per-period idempotency key in the balance fold is the backstop.
        assert_eq!(core.do_charge_contracts(), 0);
        assert_eq!(
            ledger_view::balance_of(&core.db, &buyer_addr).unwrap(),
            -500
        );

        // Jump past the final period: the sweep catches up every period still
        // owed in one pass (1, 2, 3), then stops — a completed contract owes
        // nothing further.
        core.clock.set(NOW + 3 * WEEK_SECS);
        assert_eq!(core.do_charge_contracts(), 3);
        assert_eq!(core.do_charge_contracts(), 0);
        assert_eq!(
            ledger_view::balance_of(&core.db, &buyer_addr).unwrap(),
            -2000
        );
        assert_eq!(
            ledger_view::balance_of(&core.db, &provider_addr).unwrap(),
            2000
        );
    }

    #[test]
    fn an_early_termination_bills_through_notice_then_the_penalty_once() {
        let mut core = test_core();
        let (provider, buyer) = (Keypair::generate(), Keypair::generate());
        let contract_id = seed_contract(&core, &provider, &buyer);
        let buyer_addr = Address::from_public_key(buyer.public_key());
        let provider_addr = Address::from_public_key(provider.public_key());

        // Period 0 charges up front.
        assert_eq!(core.do_charge_contracts(), 1);

        // The buyer terminates at NOW; the notice window closes one week later.
        {
            let mut log = AppendLog::new(&core.db);
            append_contract_termination(
                &mut log,
                rrn_crypto::signed::SignedPayload::sign(
                    ContractTermination {
                        contract_id,
                        terminated_by: TerminatedBy::Buyer,
                        requested_at: NOW,
                    },
                    &buyer,
                ),
                &core.station_keypair().public_key(),
                &|_: &Listing, _: &Address| true,
                NOW,
            )
            .unwrap();
        }

        // At the moment the notice window closes: period 1 falls due on that same
        // instant (charged through the window, inclusive), and the early-exit
        // penalty is levied once on the buyer who ended it. Periods 2 and 3 never
        // charge — they fall past the effective date.
        core.clock.set(NOW + WEEK_SECS);
        assert_eq!(core.do_charge_contracts(), 2); // period 1 + the penalty
        assert_eq!(
            ledger_view::balance_of(&core.db, &buyer_addr).unwrap(),
            -(2 * CONTRACT_PRICE) - CONTRACT_PENALTY
        );
        assert_eq!(
            ledger_view::balance_of(&core.db, &provider_addr).unwrap(),
            2 * CONTRACT_PRICE + CONTRACT_PENALTY
        );

        // The sweep is terminal now: no further period, and the penalty is never
        // charged twice.
        core.clock.set(NOW + 10 * WEEK_SECS);
        assert_eq!(core.do_charge_contracts(), 0);
        assert_eq!(
            ledger_view::balance_of(&core.db, &buyer_addr).unwrap(),
            -(2 * CONTRACT_PRICE) - CONTRACT_PENALTY
        );
    }

    #[test]
    fn contract_reads_shape_detail_and_list_and_scope_to_a_party() {
        let mut core = test_core();
        let (provider, buyer) = (Keypair::generate(), Keypair::generate());
        let contract_id = seed_contract(&core, &provider, &buyer);
        let buyer_addr = Address::from_public_key(buyer.public_key());
        let cid = hex(&contract_id.to_bytes());

        // Detail, before any charge: active, four periods to run, next due now.
        let detail = core.run_contract_detail(&cid, buyer_addr).unwrap();
        assert_eq!(detail["contract_id"], cid);
        assert_eq!(detail["state"], "active");
        assert_eq!(detail["frequency"], "weekly");
        assert_eq!(detail["commons_per_period_centi"], CONTRACT_PRICE);
        assert_eq!(detail["periods_charged"], 0);
        assert_eq!(detail["periods_remaining"], CONTRACT_PERIODS);
        assert_eq!(detail["next_charge_due"], NOW);

        // The list shows the one contract, with the viewer's role on it.
        let rows = core.run_my_contracts(buyer_addr).unwrap();
        let rows = rows["contracts"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["role"], "buyer");
        assert_eq!(rows[0]["periods_charged"], 0);

        // After the sweep bills period 0, the read reflects the ledger's count —
        // one charged, three left, next due a week out.
        assert_eq!(core.do_charge_contracts(), 1);
        let detail = core.run_contract_detail(&cid, buyer_addr).unwrap();
        assert_eq!(detail["periods_charged"], 1);
        assert_eq!(detail["periods_remaining"], CONTRACT_PERIODS - 1);
        assert_eq!(detail["next_charge_due"], NOW + WEEK_SECS);

        // A contract is private to its two parties: a stranger sees neither the
        // detail nor a row for it.
        let stranger = Address::from_public_key(Keypair::generate().public_key());
        assert!(core.run_contract_detail(&cid, stranger).is_err());
        assert!(core.run_my_contracts(stranger).unwrap()["contracts"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    /// Frames a signed record into the hex a channel `submit_*` param carries —
    /// the way a phone hands the station a whole `SignedPayload` (T1.3.4 framing).
    fn record_hex<T>(payload: T, signer: &Keypair) -> String
    where
        T: Clone + Into<dcbor::prelude::CBOR>,
    {
        let bytes = to_canonical_bytes(payload);
        let signature = signer.sign(&bytes);
        hex(&rpc_envelope::frame_signed_record(
            &bytes,
            &signer.public_key(),
            &signature,
        ))
    }

    #[test]
    fn a_paired_mobile_signs_reads_and_terminates_a_contract_over_the_channel() {
        let mut core = test_core();
        let (provider, buyer) = (Keypair::generate(), Keypair::generate());
        let (listing, inquiry_id) = seed_agreed_inquiry(&core, &provider, &buyer);
        let buyer_addr = Address::from_public_key(buyer.public_key());
        let provider_addr = Address::from_public_key(provider.public_key());

        // The buyer builds the mandate on-device from the agreed inquiry's terms
        // and signs it; content-addressing makes the id independent of who relays.
        let contract = ServiceContract::new(
            inquiry_id,
            listing.id,
            buyer_addr,
            provider_addr,
            seed_contract_terms(),
            NOW,
        )
        .unwrap();
        let contract_id = contract.contract_id;
        let cid = hex(&contract_id.to_bytes());

        // A record whose signer is not the authenticated mobile is refused before
        // it reaches the append: the station binds a submission to the pair.
        let forged = envelope(
            &provider,
            "submit_contract",
            serde_json::json!({ "signed_contract": record_hex(contract.clone(), &buyer) }),
        );
        let (code, message) = core.route_channel_method(&forged).unwrap_err();
        assert_eq!(code, rpc::INVALID_PARAMS);
        assert!(message.contains("authenticated mobile"), "{message}");

        // The buyer submits their own signed contract: accepted, active.
        let env = envelope(
            &buyer,
            "submit_contract",
            serde_json::json!({ "signed_contract": record_hex(contract, &buyer) }),
        );
        let result = core.route_channel_method(&env).unwrap();
        assert_eq!(result["contract_id"], cid);
        assert_eq!(result["state"], "active");

        // Both parties read it over the channel, each with their own role.
        let rows = core
            .route_channel_method(&envelope(
                &provider,
                "marketplace_contracts",
                serde_json::json!({}),
            ))
            .unwrap();
        let rows = rows["contracts"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["role"], "provider");

        let detail = core
            .route_channel_method(&envelope(
                &buyer,
                "marketplace_contract_show",
                serde_json::json!({ "contract_id": cid }),
            ))
            .unwrap();
        assert_eq!(detail["state"], "active");
        assert_eq!(detail["frequency"], "weekly");

        // A stranger to the contract cannot read it over the channel.
        let stranger = Keypair::generate();
        assert!(core
            .route_channel_method(&envelope(
                &stranger,
                "marketplace_contract_show",
                serde_json::json!({ "contract_id": cid }),
            ))
            .is_err());

        // The provider ends it over the channel — either party may — and the read
        // no longer reports it active.
        let termination = ContractTermination {
            contract_id,
            terminated_by: TerminatedBy::Provider,
            requested_at: NOW,
        };
        let env = envelope(
            &provider,
            "submit_contract_termination",
            serde_json::json!({ "signed_termination": record_hex(termination, &provider) }),
        );
        assert_eq!(core.route_channel_method(&env).unwrap()["contract_id"], cid);
        let detail = core.run_contract_detail(&cid, buyer_addr).unwrap();
        assert_ne!(detail["state"], "active");
    }

    // --- governance wiring (T1.9.7b) ----------------------------------------

    const TEN_MONTHS: i64 = 10 * 30 * 86_400;

    fn gaddr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// Appends a full proposal → confirmation → settlement chain, mirroring the
    /// reputation crate's own fixture, so the parties earn trade standing.
    fn gov_settled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        settler: &Keypair,
        nonce: u64,
        at: i64,
    ) {
        let mut log = AppendLog::new(db);
        let proposal = TransactionProposal::new(
            gaddr(sender),
            gaddr(receiver),
            300,
            None,
            nonce,
            1,
            i64::MAX / 2,
        );
        let pid = proposal.id;
        log.append(rrn_crypto::signed::SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        log.append(
            rrn_crypto::signed::SignedPayload::sign(
                TransactionConfirmation {
                    proposal_id: pid,
                    confirmer: gaddr(receiver),
                    confirmed_at: at,
                },
                receiver,
            ),
            0,
        )
        .unwrap();
        log.append(
            rrn_crypto::signed::SignedPayload::sign(
                rrn_ledger::settlement::SettlementRecord {
                    proposal_id: pid,
                    sender: gaddr(sender),
                    receiver: gaddr(receiver),
                    amount_centi: 300,
                    settled_at: at,
                },
                settler,
            ),
            0,
        )
        .unwrap();
    }

    /// Appends a vouch, mirroring the reputation crate's fixture (raw
    /// [`Attestation`] with a zero stake) so the issuer earns attestation standing.
    fn gov_vouch(db: &Database, voucher: &Keypair, subject: &Address, at: i64) {
        use rrn_identity::attestation::Attestation;
        use rrn_identity::vouch::{VouchBody, VouchKind};
        let vouch = Attestation {
            kind: VouchKind,
            body: VouchBody {
                community: "commons".into(),
                statement: "trustworthy".into(),
                reputation_stake_centi: 0,
            },
            subject: *subject,
            issued_at: at,
            expires_at: None,
        };
        AppendLog::new(db).append(vouch.sign(voucher), 0).unwrap();
    }

    /// Builds `n` established members anchored in a ring — the electorate the
    /// governance guards require.
    fn gov_established_members(db: &Database, n: usize, at: i64) -> Vec<Keypair> {
        let settler = Keypair::generate();
        let members: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        for m in &members {
            for nonce in 0..10 {
                gov_settled(db, m, &Keypair::generate(), &settler, nonce, at);
            }
            for _ in 0..10 {
                gov_vouch(db, m, &gaddr(&Keypair::generate()), at);
            }
        }
        for i in 0..n {
            gov_vouch(db, &members[(i + 1) % n], &gaddr(&members[i]), at);
        }
        members
    }

    /// A core whose clock sits at a realistic time, so seeded reputation scores as
    /// it would in production.
    fn established_core() -> Core {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        Core::new(
            db,
            WalletContents::create_new(),
            SettlementConfig::default(),
            rrn_ledger::credit::CreditConfig::default(),
            Clock::manual(TEN_MONTHS),
            PairedMobiles::default(),
            SearchIndex::in_memory(),
        )
    }

    #[test]
    fn governance_charter_is_unpublished_before_init() {
        let mut core = test_core();
        let v = call(&mut core, "governance_charter", serde_json::json!({}));
        assert_eq!(v["published"], false);
    }

    #[test]
    fn governance_charter_init_solo_publishes_and_reads_back() {
        let mut core = test_core();
        let r = call(
            &mut core,
            "governance_init_charter",
            serde_json::json!({ "community_id": "commons" }),
        );
        assert_eq!(r["version"], 1);
        assert_eq!(r["charter_hash"].as_str().unwrap().len(), 64);

        let c = call(&mut core, "governance_charter", serde_json::json!({}));
        assert_eq!(c["published"], true);
        assert_eq!(c["version"], 1);
        assert_eq!(c["community_id"], "commons");
        assert_eq!(c["statute_quorum_pct"], 30);
        assert_eq!(c["cosign_threshold"], 3);
        // The station wallet is the sole founder of a solo bootstrap.
        assert_eq!(c["founders"].as_array().unwrap().len(), 1);
        assert_eq!(c["founders"][0], core.wallet.address.to_string());
    }

    #[test]
    fn governance_charter_init_accepts_a_multi_founder_set() {
        let mut core = test_core();
        let founders: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        let secrets: Vec<String> = founders
            .iter()
            .map(|k| hex(&k.secret_key().to_bytes()))
            .collect();
        let r = call(
            &mut core,
            "governance_init_charter",
            serde_json::json!({ "community_id": "commons", "founder_secrets_hex": secrets }),
        );
        assert_eq!(r["version"], 1);
        let c = call(&mut core, "governance_charter", serde_json::json!({}));
        assert_eq!(c["founders"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn governance_charter_ceremony_collects_remote_signatures_and_publishes() {
        let mut core = test_core();
        // Founders = the station coordinator + 3 external (phone-held) founders,
        // so the threshold is ceil(4 × 0.75) = 3.
        let externals: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();
        let mut founders: Vec<String> = vec![core.wallet.address.to_string()];
        founders.extend(
            externals
                .iter()
                .map(|k| Address::from_public_key(k.public_key()).to_string()),
        );

        let begun = call(
            &mut core,
            "governance_charter_begin",
            serde_json::json!({ "community_id": "pilot", "founders": founders }),
        );
        assert_eq!(begun["exists"], true);
        // The coordinator's own signature only — 1 of 4, short of the bar.
        assert_eq!(begun["published"], false);
        assert_eq!(begun["threshold"], 3);
        assert_eq!(begun["signed_founders"].as_array().unwrap().len(), 1);
        // Not yet the community's genesis charter.
        assert_eq!(
            call(&mut core, "governance_charter", serde_json::json!({}))["published"],
            false
        );

        // The body each founder signs, shared to them by the coordinator.
        let body = unhex(begun["body_hex"].as_str().unwrap()).unwrap();

        // Two external founders sign remotely and submit; the third stays absent.
        for f in &externals[..2] {
            let sig = f.sign(&body);
            call(
                &mut core,
                "governance_add_charter_signature",
                serde_json::json!({
                    "signer_pubkey_hex": hex(&f.public_key().to_bytes()),
                    "signature_hex": hex(&sig.to_bytes()),
                }),
            );
        }

        // 3 of 4 have now signed → the charter publishes automatically.
        let pending = call(
            &mut core,
            "governance_pending_charter",
            serde_json::json!({}),
        );
        assert_eq!(pending["published"], true);
        assert_eq!(pending["signed_founders"].as_array().unwrap().len(), 3);
        let c = call(&mut core, "governance_charter", serde_json::json!({}));
        assert_eq!(c["published"], true);
        assert_eq!(c["founders"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn governance_charter_begin_refuses_a_second_ceremony() {
        let mut core = test_core();
        let founders = vec![core.wallet.address.to_string()];
        call(
            &mut core,
            "governance_charter_begin",
            serde_json::json!({ "community_id": "pilot", "founders": founders.clone() }),
        );
        let err = call_err(
            &mut core,
            "governance_charter_begin",
            serde_json::json!({ "community_id": "pilot", "founders": founders }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn governance_propose_without_a_charter_is_refused() {
        let mut core = test_core();
        let err = call_err(
            &mut core,
            "governance_propose",
            serde_json::json!({ "title": "t", "body": "b" }),
        );
        assert_eq!(err.code, rpc::INVALID_PARAMS);
    }

    #[test]
    fn governance_channel_lifecycle_publishes_and_counts_votes() {
        let mut core = established_core();
        let members = gov_established_members(&core.db, 4, TEN_MONTHS);

        // The station publishes the genesis charter (sole founder).
        call(
            &mut core,
            "governance_init_charter",
            serde_json::json!({ "community_id": "commons" }),
        );
        let charter = effective_charter(&core.db).unwrap().unwrap();

        // member[0] authors a statute over the mobile channel.
        let proposal = Proposal::new(
            gaddr(&members[0]),
            "Quiet hours".into(),
            "No power tools after 9pm.".into(),
            ProposalKind::Statute,
            TEN_MONTHS,
            &charter,
        )
        .unwrap();
        let pid = proposal.proposal_id.to_string();
        let env = envelope(
            &members[0],
            "governance_submit_proposal",
            serde_json::json!({ "signed_proposal": record_hex(proposal.clone(), &members[0]) }),
        );
        assert_eq!(core.route_channel_method(&env).unwrap()["proposal_id"], pid);

        // Three others co-sign, carrying it over the threshold.
        for m in &members[1..4] {
            let cosign = ProposalCosign {
                proposal_id: proposal.proposal_id,
                cosigner: gaddr(m),
                cosigned_at: TEN_MONTHS,
            };
            let env = envelope(
                m,
                "governance_submit_cosign",
                serde_json::json!({ "signed_cosign": record_hex(cosign, m) }),
            );
            core.route_channel_method(&env).unwrap();
        }

        // All four vote yes.
        for m in &members {
            let vote = Vote {
                proposal_id: proposal.proposal_id,
                voter: gaddr(m),
                choice: VoteChoice::Yes,
                cast_at: TEN_MONTHS,
            };
            let env = envelope(
                m,
                "governance_submit_vote",
                serde_json::json!({ "signed_vote": record_hex(vote, m) }),
            );
            core.route_channel_method(&env).unwrap();
        }

        // The detail read shows it published, in voting, with four yes ballots.
        let detail = call(
            &mut core,
            "governance_proposal",
            serde_json::json!({ "proposal_id": pid }),
        );
        assert_eq!(detail["phase"], "voting");
        assert_eq!(detail["published"], true);
        assert_eq!(detail["cosigner_count"], 3);
        assert_eq!(detail["tally"]["yes"], 4);
        assert_eq!(detail["tally"]["eligible_voters"], 4);
        assert_eq!(detail["tally"]["quorum_met"], true);
        assert_eq!(detail["tally"]["approval_met"], true);
        assert_eq!(detail["body"], "No power tools after 9pm.");
    }
}
