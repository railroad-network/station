//! The CLI ↔ daemon wire protocol: line-delimited JSON over a Unix socket.
//!
//! One request per line in, one response per line out, UTF-8. The envelope
//! borrows JSON-RPC's vocabulary (`id` / `method` / `params` / `result` /
//! `error`) and its error-code conventions, but not the full 2.0 spec — that is
//! more than a local socket between two programs we ship together needs.
//!
//! These types are deliberately plain `serde` structs (not canonical CBOR):
//! this is operational plumbing, not a signed payload. The canonical, signed
//! records still travel as their own CBOR inside method results where needed
//! (e.g. the raw log entries the gossip layer moves — see [`crate::gossip`]).
//!
//! Both [`crate::server`] (daemon side) and [`crate::rpc_client`] (CLI side)
//! depend on this module, which is why it lives in the `rrn-station` *library*
//! and `rrn-cli` takes a dependency on it rather than redefining the wire types.

use serde::{Deserialize, Serialize};

/// The request was not a well-formed envelope. (JSON-RPC convention.)
pub const INVALID_REQUEST: i32 = -32600;
/// No method with the requested name exists.
pub const METHOD_NOT_FOUND: i32 = -32601;
/// The method exists but its `params` were missing or ill-typed.
pub const INVALID_PARAMS: i32 = -32602;
/// The method failed while executing (a ledger/storage error, etc.).
pub const INTERNAL_ERROR: i32 = -32603;

/// A request line: an opaque `id` echoed back in the response, a `method` name,
/// and free-form `params` interpreted per method.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    /// Caller-chosen correlation id (a UUID, conventionally), echoed verbatim.
    pub id: String,
    /// The method name, e.g. `"balance"`.
    pub method: String,
    /// Method-specific parameters. Absent params decode as JSON `null`.
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A response line: the request's `id`, and exactly one of `result` or `error`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    /// The id from the request this answers.
    pub id: String,
    /// Present on success; the method's result object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Present on failure; mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// A success response carrying `result` for request `id`.
    pub fn ok(id: impl Into<String>, result: serde_json::Value) -> Self {
        Response {
            id: id.into(),
            result: Some(result),
            error: None,
        }
    }

    /// An error response for request `id`.
    pub fn err(id: impl Into<String>, code: i32, message: impl Into<String>) -> Self {
        Response {
            id: id.into(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// A structured error: a numeric `code` (see the constants above) and a
/// human-readable `message`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcError {
    /// One of the `-326xx` codes.
    pub code: i32,
    /// Diagnostic text; not meant to be machine-matched.
    pub message: String,
}

// --- Typed params / results -------------------------------------------------
//
// Each method's params and result get a named struct so the daemon and the CLI
// agree on field names without a hand-maintained JSON schema. They (de)serialize
// to the `params`/`result` JSON values inside the envelope above.

/// `balance` params. An absent/empty `address` means "my own".
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BalanceParams {
    /// The `rrn1…` address to query, or `None` for the station's own identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// `balance` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceResult {
    /// The balance in centicommons (may be negative — members can hold debt).
    pub balance_centi: i64,
}

/// `propose` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeParams {
    /// The receiver's `rrn1…` address.
    pub receiver: String,
    /// Amount in centicommons; positive = the station (sender) pays the receiver.
    pub amount_centi: i64,
    /// Optional human-readable memo, part of the signed proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// Optional oracle-tier **opt-up** (T1.8.1): the sender asking this payment
    /// be held to a higher tier than its amount alone requires. `None` — the
    /// common case — takes the amount's floor. Ignored unless it is a genuine
    /// lift (see `TransactionProposal::with_tier`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_tier: Option<u8>,
}

/// `bundle_submit` params (T2.2.3): a DTN [`Bundle`](rrn_protocol::bundle::Bundle)'s
/// canonical bytes, hex-encoded — matching the repo convention for byte-carrying
/// RPC params (see the `_hex` fields on the charter methods).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleSubmitParams {
    /// The bundle's encoded bytes, hex-encoded.
    pub bundle_hex: String,
}

/// `bundle_submit` result: the station-signed delivery receipt as its portable
/// envelope bytes ([`rrn_protocol::receipt::encode_signed`]), hex-encoded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleSubmitResult {
    /// The signed-receipt envelope bytes, hex-encoded.
    pub receipt_hex: String,
}

/// `receipts_fetch` params (T2.2.4, ADR-0020 §3): pick up pending delivery
/// receipts to carry back. Over the operator/Unix-socket surface this is a
/// **courier** fetch — it bumps each receipt's fetched count but never confirms
/// delivery (a courier is not the author).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReceiptsFetchParams {
    /// The `rrn1…` addresses whose pending receipts to fetch. Empty = *all*
    /// pending receipts (a bulk courier syncing the whole queue).
    #[serde(default)]
    pub authors: Vec<String>,
    /// Only receipts first issued strictly after this admission-clock reading — a
    /// cursor to page past receipts already carried. `None` = from the beginning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
}

/// `receipts_fetch` result: the pending receipts, each as its portable
/// signed-receipt envelope bytes ([`rrn_protocol::receipt::encode_signed`]),
/// hex-encoded, oldest first and capped. `truncated` is `true` when more pending
/// receipts remain than were returned — fetch again (optionally with `since`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptsFetchResult {
    /// The signed-receipt envelope bytes, hex-encoded, oldest first.
    pub receipts_hex: Vec<String>,
    /// Whether pending receipts beyond this page remain.
    pub truncated: bool,
}

/// `receipts_ack` params (T2.2.4): the operator, acting as the **author** of
/// records on this station's own wallet, confirms it has received the delivery
/// receipts for the named records — so the retention sweep may reclaim them. The
/// courier `receipts_fetch` never confirms; this is the operator's author-path
/// counterpart to the mobile author fetch (which confirms implicitly).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptsAckParams {
    /// The record hashes (hex, Blake3 of each record's canonical bytes) to
    /// confirm as delivered.
    pub record_hashes: Vec<String>,
}

/// `receipts_ack` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptsAckResult {
    /// How many delivery rows were newly confirmed (already-confirmed or unknown
    /// record hashes do not count).
    pub acked: u64,
}

/// `propose` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeResult {
    /// The content-addressed transaction id, hex-encoded.
    pub tx_id: String,
    /// The transaction's state after proposing (`"Proposed"`).
    pub state: String,
}

/// `confirm` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmParams {
    /// The hex transaction id to confirm.
    pub tx_id: String,
}

/// `confirm` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmResult {
    /// The transaction's state after confirming (`"Confirmed"`).
    pub state: String,
}

/// `history` params.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HistoryParams {
    /// Max number of (most-recent-first) entries to return; `None` = all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// How many of the most-recent entries to skip before collecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// One decoded, human-readable log entry in a `history` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// The entry's sequence number in this station's log.
    pub seq: u64,
    /// A short kind tag: `proposal`, `confirmation`, `settlement`,
    /// `cancellation`, `vouch`, or `unknown`.
    pub kind: String,
    /// A one-line human summary of the entry.
    pub summary: String,
    /// Unix seconds when the entry was appended locally.
    pub created_at: i64,
}

/// `history` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryResult {
    /// Decoded entries, most recent first.
    pub entries: Vec<HistoryEntry>,
}

/// `vouch` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VouchParams {
    /// The `rrn1…` address being vouched for.
    pub subject: String,
    /// The voucher's free-text statement.
    #[serde(default)]
    pub statement: String,
    /// Reputation staked, in centipoints.
    #[serde(default)]
    pub stake_centi: u64,
}

/// `vouch` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VouchResult {
    /// The vouch's content hash, hex-encoded.
    pub vouch_id: String,
}

/// `backup_export` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupExportParams {
    /// Holder `rrn1…` addresses, one sealed shard each.
    pub holders: Vec<String>,
    /// `K` — how many shards are required to reconstruct.
    pub threshold: u8,
    /// Where to write the `.rrnrecovery` package.
    pub output: String,
}

/// `backup_export` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupExportResult {
    /// The path the recovery package was written to.
    pub recovery_path: String,
}

/// `recover_import` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverImportParams {
    /// Path to a `.rrnrecovery` package.
    pub recovery_path: String,
    /// Paths to `K` decrypted raw-shard files (33 bytes each: index ‖ data).
    pub shards: Vec<String>,
}

/// `recover_import` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverImportResult {
    /// The `rrn1…` address of the reconstructed identity.
    pub restored_address: String,
}

/// `status` result — a live, entirely *derived* snapshot for degradation
/// legibility (T2.4.1): who this station is, and a `connectivity` block. Nothing
/// here is cached authoritative state; each field is recomputed at call time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusResult {
    /// The station's own `rrn1…` address.
    pub address: String,
    /// The community identifier (as in [`WhoamiResult::community`]).
    #[serde(default)]
    pub community: String,
    /// Whether the community is still in bootstrap grace (as in [`WhoamiResult`]).
    #[serde(default)]
    pub bootstrap_in_grace: bool,
    /// How many members are currently established.
    #[serde(default)]
    pub established_members: u64,
    /// The active emergency, if one holds (ADR-0023 §6). The mobile shows a
    /// persistent banner naming it, its reason, and its expiry while set, so a
    /// member is never told a compressed-window vote was an ordinary one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency: Option<EmergencyStatus>,
    /// The connectivity / offline-posture snapshot.
    pub connectivity: ConnectivityBlock,
}

/// The connectivity portion of a [`StatusResult`]: peer reachability, the
/// mobile-listener state, and pending DTN queue depths — everything an operator
/// needs to read "am I isolated, and is anything stuck?" at a glance (T2.4.1).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectivityBlock {
    /// One row per configured peer, with its last-observed reachability. Empty
    /// when no peers are configured, or all rows `reachable=false, last_success_at
    /// absent` before the first gossip round (or in a bare test core).
    #[serde(default)]
    pub peers: Vec<PeerStatus>,
    /// The configured mobile listen address (`[mobile] listen`).
    #[serde(default)]
    pub mobile_listen: String,
    /// Whether this station advertises over mDNS (`[mobile] advertise`).
    #[serde(default)]
    pub mobile_advertising: bool,
    /// Whether the mobile HTTP listener actually bound at startup (a `false` here
    /// with `mobile_advertising=true` is the "advertised but unreachable" case).
    #[serde(default)]
    pub mobile_listener_bound: bool,
    /// Outbox entries still awaiting a delivery outcome. This is the *device*
    /// outbox (a wallet's own send queue) — populated by the CLI-wallet path
    /// (T2.5.2) and the mobile wallet (T2.4.2), not by the daemon itself, so on a
    /// station with no local wallet outbox it reads `0`. Included now so the metric
    /// is live the moment those paths land.
    #[serde(default)]
    pub pending_outbox: u64,
    /// Delivery receipts the station is still holding for a courier / an author's
    /// ack.
    #[serde(default)]
    pub pending_receipts: u64,
    /// The supervised Reticulum sidecar's posture (T2.6.1, ADR-0013). Defaults to
    /// `disabled` on a station with no sidecar configured (or a bare test core).
    #[serde(default)]
    pub sidecar: SidecarStatus,
}

/// The Reticulum sidecar's state in a [`ConnectivityBlock`] (T2.6.1). Purely
/// derived degradation-legibility state — the sidecar is a dumb carrier
/// (ADR-0013), so nothing here is signed or authoritative.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SidecarStatus {
    /// One of `disabled`, `running`, `degraded`, `restarting`.
    pub state: String,
    /// The managed `rnsd` version, present only while `running`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Why the sidecar is not carrying traffic (degraded reason, or the restart
    /// backoff); present only when `degraded` or `restarting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for SidecarStatus {
    fn default() -> Self {
        SidecarStatus {
            state: "disabled".to_string(),
            version: None,
            reason: None,
        }
    }
}

/// One peer's last-observed reachability in a [`ConnectivityBlock`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    /// The peer's configured `host:port`.
    pub address: String,
    /// Whether the most recent gossip round with this peer succeeded.
    pub reachable: bool,
    /// Clock time (Unix seconds) of the last successful round, omitted if never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<i64>,
    /// Clock time (Unix seconds) this peer was last attempted, omitted if never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<i64>,
}

/// `whoami` result (takes no params).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WhoamiResult {
    /// The station's own `rrn1…` address.
    pub address: String,
    /// The community identifier a member stamps into a vouch (Phase 0:
    /// `"rrn-phase0"`; real community identity arrives in Phase 1). The mobile
    /// reads this rather than hardcoding the string so it cannot drift.
    #[serde(default)]
    pub community: String,
    /// Whether the community is still in Tier-2 **bootstrap grace** (T1.8.6):
    /// fewer than [`grace_threshold`](Self::grace_threshold) members have reached
    /// the Member band, so *any* member may confirm a Tier-2 payment without
    /// meeting the standing floor. The mobile shows a persistent banner while this
    /// is true, so members know the oracle is running under weaker assumptions.
    #[serde(default)]
    pub bootstrap_in_grace: bool,
    /// How many members are currently *established* (effective composite over the
    /// Member band) — the count that decides `bootstrap_in_grace`.
    #[serde(default)]
    pub established_members: u64,
    /// The number of established members at which bootstrap grace ends
    /// (`rrn_reputation::staking::BOOTSTRAP_GRACE_THRESHOLD`).
    #[serde(default)]
    pub grace_threshold: u64,
    /// The active emergency, if one holds (ADR-0023). The mobile banners it while
    /// set — a compressed governance window must never look like an ordinary one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency: Option<EmergencyStatus>,
}

/// `transactions` params — the mobile-facing, member-relative view of the
/// ledger (T1.3.4). Unlike `history` (operator summary strings), this returns
/// structured rows the wallet UI renders directly.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransactionsParams {
    /// The member `rrn1…` address whose transactions to return, and the vantage
    /// point for `direction`/`amount_centi` (in vs out relative to them).
    pub address: String,
    /// Max number of (most-recent-first) rows to return; `None` = all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

/// One transaction, correlated from its log events and expressed relative to the
/// querying member (T1.3.4). The station does the stitching; the wallet renders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRow {
    /// The content-addressed transaction id, hex-encoded.
    pub id: String,
    /// The other party's `rrn1…` address (the member is one side; this is the
    /// other). Display names are resolved locally on the mobile, not here.
    pub counterparty_address: String,
    /// `"in"` when the member receives, `"out"` when the member sends.
    pub direction: String,
    /// Amount in centicommons, **signed relative to the member**: positive when
    /// money comes in, negative when it goes out.
    pub amount_centi: i64,
    /// Optional memo carried on the proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// The marketplace listing this paid for, hex — present on a marketplace
    /// payment, absent on a direct pay (T1.7.6 Stage B).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    /// That listing's title, resolved from the marketplace log so history reads
    /// as what it bought ("Seed potatoes") rather than a memo string. Present
    /// when the listing is one this station has seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_title: Option<String>,
    /// The headroom certificate this spend drew against, hex — present on a
    /// cert-backed offline spend (ADR-0021 §3, T2.3.2), absent on an ordinary
    /// proposal. Lets the wallet mark a payment as backed by escrow and gives
    /// T2.4.2's receiver-side checks a row-level hook.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<String>,
    /// Lifecycle: `pending` | `confirmed` | `settled` | `cancelled`.
    pub state: String,
    /// The oracle tier that governs this transaction (T1.8.1): `1` — settlement
    /// window only — or `2` — reputation stake + dispute window. This is the
    /// *effective* tier (amount floor lifted by any opt-up), what the UI shows
    /// and what Tier-2 machinery keys on, not the proposal's raw opt-up field.
    pub oracle_tier: u8,
    /// Unix seconds the proposal was made (the row's sort key).
    pub timestamp: i64,
    /// Unix seconds an unconfirmed proposal auto-cancels; present while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Unix seconds the receiver *claims* they confirmed — plausibility-bounded
    /// testimony, not a window anchor (ADR-0022). Present once confirmed/settled.
    /// For a confirmation carried offline this can be well before `settle_by`
    /// minus the window; use `settle_by` for countdowns, never `confirmed_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<i64>,
    /// Unix seconds the settlement window closes — the confirmation's *admission*
    /// time plus this tier's window (Tier 1 = 24h, Tier 2 = 48h; ADR-0022 §2,
    /// T1.8.4/T1.8.6), i.e. when the community's ledger learned of the
    /// confirmation, not the receiver-claimed `confirmed_at`. Present once
    /// confirmed, so the wallet can count down to settlement without hardcoding
    /// the window or re-deriving it from the tier. Absent while still pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_by: Option<i64>,
    /// Unix seconds the transaction settled; present once settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<i64>,
    /// The sender's per-sender ledger nonce for this transaction.
    pub nonce: u64,
}

/// `transactions` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionsResult {
    /// The member's transactions, most recent first.
    pub transactions: Vec<TransactionRow>,
}

/// `next_nonce` params — the member whose next proposal nonce to return.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NextNonceParams {
    /// The member `rrn1…` address. Absent/empty means the station's own identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

// --- marketplace (T1.7.3) ---------------------------------------------------
//
// The operator-facing half of the marketplace. The read methods answer with the
// same [`crate::marketplace_view`] shapes the mobile channel serves, so a browse
// row means one thing on the network however it was asked for; the results below
// are typed only where the CLI renders a text mode from them.
//
// Writes here are signed by the **station's own wallet**, which on an operator's
// socket is the operator's identity — the precedent `vouch` and `propose` set.
// A mobile's marketplace writes are a different path (T1.7.2): the phone holds
// the key and the station only records what it already signed.

/// `marketplace_search` params — every filter optional, so `{}` is a valid
/// "show me everything on offer". Shared by the mobile channel and the CLI
/// socket: browse is one query with one meaning, whoever asks it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SearchParams {
    /// Free-text query over title and description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `goods`, `services`, or `commons`. An unknown tag is an error, not an
    /// ignored filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    /// One of the controlled-vocabulary categories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Price ceiling in centicommons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_price_centi: Option<i64>,
    /// Only listings whose provider's capped composite is at least this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_provider_reputation: Option<f32>,
    /// Page size, clamped to [`crate::marketplace_view::MAX_SEARCH_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// How many ranked hits to skip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
}

/// `marketplace_listing` params — one listing in full, by content address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListingParams {
    /// The hex listing id.
    pub listing_id: String,
}

/// `marketplace_create_listing` params. Mirrors [`rrn_marketplace::listing::Listing`]
/// minus what the station fills in for itself: the provider (the station's own
/// address), the community, `created_at`, and the derived content address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateListingParams {
    /// `goods`, `services`, or `commons`.
    pub surface: String,
    /// One of the controlled-vocabulary categories.
    pub category: String,
    /// Short human-readable name for the offer.
    pub title: String,
    /// Longer prose; empty is fine.
    #[serde(default)]
    pub description: String,
    /// Price in centicommons. Negative is legal only on `commons`.
    pub amount_centi: i64,
    /// Whether the provider invites offers. Sets `PricingModel::Negotiable` too,
    /// since a listing that invites offers but is priced `Fixed` is the
    /// contradiction [`rrn_marketplace::listing::Listing::validate`] refuses.
    #[serde(default)]
    pub negotiable: bool,
    /// Units available, for `goods`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u32>,
    /// Unix seconds of the next open slot, for `services`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_slot: Option<i64>,
    /// Minimum capped composite an inquirer must hold; `0.0` asks nothing.
    #[serde(default)]
    pub min_reputation: f32,
    /// Whether the provider will deal only inside their own community.
    #[serde(default)]
    pub community_member_only: bool,
    /// Claimed oracle tier. `None` takes the price-based suggestion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_tier: Option<u8>,
    /// Unix seconds the listing goes off offer; `None` stands until closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// The cadence of a recurring service: `daily`, `weekly`, or `monthly`.
    /// `None` for a one-off listing. Only a `services` listing may recur, and the
    /// remaining `recurring_*` fields are read only when this is set (T1.7.7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every: Option<String>,
    /// How many periods a recurring commitment runs for; required with `every`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub periods: Option<u32>,
    /// Days of notice to end a recurring contract early. `None` defaults to 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_days: Option<u32>,
    /// The early-termination penalty in centicommons on a recurring contract.
    /// `None` defaults to 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub penalty_centi: Option<i64>,
}

/// `marketplace_create_listing` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateListingResult {
    /// The listing's content address, hex-encoded.
    pub listing_id: String,
    /// The oracle tier actually recorded (the suggestion, when none was given).
    pub oracle_tier: u8,
}

/// `marketplace_close_listing` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseListingParams {
    /// The hex listing id to withdraw.
    pub listing_id: String,
}

/// `marketplace_close_listing` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseListingResult {
    /// The listing that was closed, hex-encoded.
    pub listing_id: String,
    /// The reason recorded — always `provider_closed` on this path, since a
    /// station may never claim a provider withdrew an offer (ADR-0005).
    pub reason: String,
}

/// `marketplace_edit_listing` params (T1.7.2 Phase B). Every field but the id is
/// optional: an edit patches only what it names, and the current listing supplies
/// the rest. A listing's identity — surface, category, title, requirements — is
/// fixed at publication (ADR-0010) and has no field here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditListingParams {
    /// The hex listing id to edit.
    pub listing_id: String,
    /// New price in centicommons. `None` leaves the price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_centi: Option<i64>,
    /// New negotiable flag (also flips the pricing model). `None` leaves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiable: Option<bool>,
    /// New description. `None` leaves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// New units available, for `goods`. `None` leaves capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u32>,
    /// New next open slot, for `services`. `None` leaves it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_slot: Option<i64>,
    /// New expiry in Unix seconds. `None` leaves the expiry (see `clear_expiry`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Remove the expiry entirely, so the listing stands until closed. Takes
    /// precedence over `expires_at` when both are given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_expiry: Option<bool>,
}

/// `marketplace_edit_listing` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EditListingResult {
    /// The listing that was edited, hex-encoded. Unchanged by the edit — a
    /// listing's content address is fixed at publication.
    pub listing_id: String,
}

/// `marketplace_announce_need` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceNeedParams {
    /// One of the controlled-vocabulary categories.
    pub category: String,
    /// How many units are wanted; at least one.
    pub quantity_needed: u32,
    /// The most the seeker will pay, or `None` for no ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_price_centi: Option<i64>,
    /// Unix seconds through which the need stands.
    pub valid_until: i64,
}

/// `marketplace_announce_need` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnounceNeedResult {
    /// The log sequence number that identifies the need — needs are not
    /// content-addressed (see [`rrn_marketplace::need::AnnouncedNeed`]).
    pub seq: u64,
}

/// `marketplace_matches` params.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MatchesParams {
    /// The log seq of one of the caller's needs, or `None` for all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// `marketplace_inquire` params (operator socket) — open an inquiry against a
/// listing, signed by the station wallet. The mobile signs its own
/// [`rrn_marketplace::inquiry::InquiryOpened`] and submits it over the channel
/// instead (T1.7.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquireParams {
    /// The hex listing id to inquire about.
    pub listing_id: String,
    /// The opening message; empty is fine.
    #[serde(default)]
    pub message: String,
    /// The opening offer in centicommons, or `None` to accept the listed price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_centi: Option<i64>,
}

/// `marketplace_inquire` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquireResult {
    /// The inquiry's content address, hex-encoded.
    pub inquiry_id: String,
}

/// `marketplace_inquiry_message` params (operator socket) — send a message,
/// optionally with a counter-offer, in an inquiry the station is a party to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquiryMessageParams {
    /// The hex inquiry id.
    pub inquiry_id: String,
    /// The message body; empty is allowed only alongside a `counter_offer_centi`.
    #[serde(default)]
    pub message: String,
    /// A revised price in centicommons, or `None` for a message that only says
    /// something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_offer_centi: Option<i64>,
}

/// `marketplace_inquiry_close` params (operator socket) — end an inquiry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquiryCloseParams {
    /// The hex inquiry id.
    pub inquiry_id: String,
    /// `agreed` or `declined` — how it ended. (`expired` is the station sweep's
    /// alone.)
    pub outcome: String,
    /// The agreed price in centicommons; required for `agreed`, ignored
    /// otherwise. `None` on `agreed` takes the listing's listed price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_price_centi: Option<i64>,
}

/// `marketplace_inquiry_close` / `marketplace_inquire` shared result naming the
/// inquiry and its resulting state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquiryStateResult {
    /// The inquiry's content address, hex-encoded.
    pub inquiry_id: String,
    /// The inquiry's state after the call: `open`, `closed`, or `expired_pending`.
    pub state: String,
}

/// `marketplace_inquiry_thread` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquiryThreadParams {
    /// The hex inquiry id.
    pub inquiry_id: String,
}

/// `marketplace_settle_inquiry` params (operator socket) — pay for an agreed
/// inquiry. The station wallet must be the inquiry's buyer; the payment is a
/// listing-linked [`rrn_ledger::transaction::TransactionProposal`], the CLI
/// counterpart of the mobile "Send payment" step. Reuses [`ProposeResult`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleInquiryParams {
    /// The hex id of the agreed inquiry to pay for.
    pub inquiry_id: String,
}

/// `marketplace_contract` params (operator socket) — sign up to a recurring
/// service, born from an agreed inquiry. The station wallet is the buyer; a mobile
/// signs its own [`rrn_marketplace::contract::ServiceContract`] in Stage 2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractParams {
    /// The hex id of the agreed inquiry this contract commits to.
    pub inquiry_id: String,
    /// Free-form notes to record on the contract (labels the buyer chose). No
    /// logic reads them; they are not part of the terms match.
    #[serde(default)]
    pub metrics: std::collections::BTreeMap<String, String>,
}

/// `marketplace_contract` / `marketplace_contract_terminate` shared result naming
/// the contract and its resulting state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractStateResult {
    /// The contract's content address, hex-encoded.
    pub contract_id: String,
    /// The contract's state after the call: `active`, `terminating`, or `ended`.
    pub state: String,
}

/// `marketplace_contract_show` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractShowParams {
    /// The hex contract id.
    pub contract_id: String,
}

/// `marketplace_contract_terminate` params.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractTerminateParams {
    /// The hex contract id.
    pub contract_id: String,
}

// The inquiry *read* results (thread, my-inquiries) are not typed here, for the
// reason the listing reads are not: they are [`crate::inquiry_view`]'s view
// structs with `&'static str` tags, `Serialize`-only by construction.

// The marketplace *read* results are not typed here. They are
// [`crate::marketplace_view`]'s view structs, which carry `&'static str` tags and
// so are `Serialize`-only by construction — there is no type for a client to
// deserialize back into. Both clients read them as JSON: the mobile already does
// (T1.7.0), and the CLI's text mode renders from the same `serde_json::Value` it
// would otherwise print. A struct here with a `serde_json::Value` hole in it
// would document less than the view does.

/// `next_nonce` result — the nonce a member's next proposal must carry (T1.3.4).
///
/// The ledger requires each sender's proposals to be strictly sequential, and
/// the nonce is part of the *signed* proposal, so the mobile must learn its
/// authoritative next value from the station before it signs (it cannot be
/// assigned after signing). This exposes the `next_nonce` the ledger already
/// derives from the log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NextNonceResult {
    /// The next expected per-sender nonce (0 if the member has never proposed).
    pub nonce: u64,
}

// --- Headroom certificates (T2.3.1, ADR-0021) -------------------------------
//
// The operator-facing half of offline spending certificates. `cert_request` is
// signed by the **station's own wallet**, the precedent `propose`/`vouch` set —
// the operator reserves headroom for the station's own identity ahead of a
// partition. A member signing their own request on a phone is T2.4.2's mobile
// FFI path, deliberately not built here. `cert_list` is a derived read of a
// member's outstanding certificates.

/// `cert_request` params — reserve a headroom certificate for the station wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertRequestParams {
    /// The cap to reserve, in centicommons. Must be `1..=cert_max_cap_centi` and
    /// fit the wallet's current debt-floor headroom.
    pub cap_centi: i64,
}

/// `cert_request` result — the issued certificate's terms.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertRequestResult {
    /// The certificate's content address, hex-encoded.
    pub cert_id: String,
    /// The reserved cap, in centicommons.
    pub cap_centi: i64,
    /// Admission-clock seconds at issuance.
    pub issued_at: i64,
    /// Admission-clock seconds the certificate expires.
    pub expires_at: i64,
}

/// `cert_list` params. An absent/empty `address` means the station's own wallet.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CertListParams {
    /// The `rrn1…` address whose outstanding certificates to list, or `None` for
    /// the station's own identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// One outstanding certificate in a `cert_list` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertRow {
    /// The certificate's content address, hex-encoded.
    pub cert_id: String,
    /// The reserved cap, in centicommons.
    pub cap_centi: i64,
    /// Cumulative admitted cert-backed spend so far, in centicommons (always 0
    /// until T2.3.2 lands cert-backed spends).
    pub consumed_centi: i64,
    /// The still-reservable remainder (`cap_centi − consumed_centi`).
    pub remaining_centi: i64,
    /// Admission-clock seconds at issuance.
    pub issued_at: i64,
    /// Admission-clock seconds the certificate expires.
    pub expires_at: i64,
}

/// `cert_list` result — a member's outstanding certificates, in content-id order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertListResult {
    /// The outstanding certificates.
    pub certificates: Vec<CertRow>,
}

/// `cert_export` params — a certificate to export as portable envelope bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertExportParams {
    /// The certificate's content address, hex-encoded (as returned by
    /// `cert_request`/`cert_list`).
    pub cert_id: String,
}

/// `cert_export` result — the station-signed certificate as a portable
/// `{signer, sig, body}` envelope (see
/// [`rrn_ledger::escrow::encode_certificate_envelope`]), hex-encoded. This is the
/// exact byte form the `rrncert:` QR carries and the mobile FFI's
/// `certificate_parse` verifies, so a certificate reserved online can be printed
/// onto a wallet card for the offline-spend flow (T2.5.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertExportResult {
    /// The certificate envelope bytes, hex-encoded.
    pub envelope_hex: String,
}

// --- Station-originated DTN push (ADR-0013, ADR-0020) ---------------------

/// `dtn_push` params: the bundle to push (`bundle_hex`, the same hex the
/// `bundle_submit` surface uses) and exactly one peer identifier — a bare
/// `endpoint_hex` Reticulum destination (the bench path) or an `rrn_address`
/// resolved through the log-derived binding directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnPushParams {
    /// The bundle's encoded bytes, hex-encoded.
    pub bundle_hex: String,
    /// The peer's Reticulum destination hex (a bare-endpoint push). Mutually
    /// exclusive with `rrn_address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_hex: Option<String>,
    /// The peer's `rrn1…` address, resolved to its destination via the binding
    /// directory (which also pins the returned receipt's signer). Mutually
    /// exclusive with `endpoint_hex`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrn_address: Option<String>,
}

/// `dtn_push` result — an accepted/**queued** acknowledgement, NOT a delivery
/// confirmation (delivery is async and confirmed later by the returned receipt;
/// see `dtn_pushes`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnPushResult {
    /// The push id (the bundle's presentation hash), hex-encoded.
    pub push_id_hex: String,
    /// Whether the push is now awaiting delivery (`true` for a freshly-queued or
    /// still-pending row; `false` when an identical bundle to the same peer was
    /// already delivered or abandoned).
    pub queued: bool,
    /// The tracked row's state: `"pending"`, `"delivered"`, or `"abandoned"` — an
    /// identical re-push returns the existing row's state, not a fresh queue.
    pub state: String,
    /// How many records the pushed bundle carries.
    pub records: usize,
    /// Whether the outbound loop was woken immediately (`false` when the wake
    /// channel was full/closed — the push is still durable and will be re-scanned).
    pub signalled: bool,
}

/// `dtn_bind` params: the station's own Reticulum destination hex, operator-
/// supplied (the adapter does not report its own hash; compute it offline with
/// `scripts/spike/lxmf_pingpong.py hash --identity <data_dir>/reticulum/adapter.identity`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnBindParams {
    /// The Reticulum destination hex this station is reachable at.
    pub destination_hex: String,
}

/// `dtn_bind` result — the signed transport-binding record as a portable
/// `{signer, sig, body}` envelope (see [`rrn_protocol::binding::encode_signed`]),
/// hex-encoded, for the operator to carry to peers out of band.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnBindResult {
    /// The binding envelope bytes, hex-encoded.
    pub binding_hex: String,
}

/// One tracked outbound push, for `rrn dtn status` (`dtn_pushes` result).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnPushRow {
    /// The push id (presentation hash), hex-encoded.
    pub push_id_hex: String,
    /// The carrier destination the push was sent to.
    pub peer: String,
    /// How many records the bundle carries.
    pub records: usize,
    /// `"pending"`, `"delivered"`, or `"abandoned"`.
    pub state: String,
    /// How many times the loop has (re-)sent this push.
    pub attempts: i64,
    /// Admission-clock reading when first queued.
    pub queued_at: i64,
    /// Admission-clock reading when a receipt was correlated, if delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<i64>,
    /// Admission-clock reading when abandoned past its TTL, if abandoned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abandoned_at: Option<i64>,
    /// A one-line summary of the correlated receipt's outcomes, if delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_summary: Option<String>,
}

/// `dtn_pushes` result — every tracked outbound push, newest first.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DtnPushesResult {
    /// The tracked pushes.
    pub pushes: Vec<DtnPushRow>,
}

// --- Governance (T1.9.7b) ---------------------------------------------------

/// `governance_init_charter` params — publish a community's genesis Charter.
///
/// With no `founder_secrets_hex`, the daemon signs it with the station wallet as
/// the sole founder (threshold `ceil(1×0.75) = 1`), the one-command solo bootstrap.
/// Supplying founder secret keys assembles a multi-founder genesis instead: the
/// keys are hex-encoded 32-byte secrets, and travel the local socket to the daemon,
/// which signs the Charter with all of them. (A distributed founder-signing
/// ceremony that never gathers the secrets in one place is Phase 2.)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovInitCharterParams {
    /// A stable identifier for the community.
    pub community_id: String,
    /// The founding principles, free text.
    #[serde(default)]
    pub founding_principles: Vec<String>,
    /// Rights guaranteed above the federation floor.
    #[serde(default)]
    pub rights_floor: Vec<String>,
    /// Hex-encoded 32-byte founder secret keys. Empty means the station wallet is
    /// the sole founder.
    #[serde(default)]
    pub founder_secrets_hex: Vec<String>,
}

/// `governance_init_charter` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovCharterResult {
    /// The published Charter's hash, hex-encoded.
    pub charter_hash: String,
    /// Its version (1 at genesis).
    pub version: u32,
}

/// `governance_charter_begin` params — open a distributed founding ceremony. The
/// founders are named by **address** (not secret key), so a founder holding its
/// key on a phone can take part by signing later over the channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovCharterBeginParams {
    /// A stable identifier for the community.
    pub community_id: String,
    /// The founding principles, free text.
    #[serde(default)]
    pub founding_principles: Vec<String>,
    /// Rights guaranteed above the federation floor.
    #[serde(default)]
    pub rights_floor: Vec<String>,
    /// The founding set, as bech32 `rrn1…` addresses.
    pub founders: Vec<String>,
}

/// `governance_pending_charter` / ceremony result — the founding Charter's state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovPendingCharterResult {
    /// Whether a founding Charter exists at all (a ceremony has begun).
    pub exists: bool,
    /// Whether it has cleared the founder threshold and published.
    pub published: bool,
    /// The Charter body's content hash, hex-encoded.
    pub charter_hash: String,
    /// The community identifier.
    pub community_id: String,
    /// The founding principles.
    pub founding_principles: Vec<String>,
    /// The rights floor.
    pub rights_floor: Vec<String>,
    /// The declared founders, bech32 `rrn1…`.
    pub founders: Vec<String>,
    /// The founders who have signed so far, bech32 `rrn1…`.
    pub signed_founders: Vec<String>,
    /// Signatures needed to publish: `ceil(founders × 0.75)`.
    pub threshold: usize,
    /// The single `created_at` fixed at `charter-begin`, Unix seconds.
    pub created_at: i64,
    /// The Charter version (1 at genesis).
    pub version: u32,
    /// The Charter body's canonical bytes, hex-encoded — what each founder signs.
    /// A station founder signs this with `governance charter-sign`.
    pub body_hex: String,
}

/// `governance_add_charter_signature` params — ingest a founder signature
/// collected out of band (a station founder's `governance charter-sign` output).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovAddCharterSignatureParams {
    /// The founder's public key, hex-encoded (32 bytes).
    pub signer_pubkey_hex: String,
    /// Their signature over the Charter body, hex-encoded (64 bytes).
    pub signature_hex: String,
}

/// `governance_charter_sign` params — sign a Charter body with this station wallet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovCharterSignParams {
    /// The Charter body's canonical bytes, hex-encoded (the coordinator's `body_hex`).
    pub charter_body_hex: String,
}

/// `governance_charter_sign` result — this station's founder signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovCharterSignResult {
    /// This station's public key, hex-encoded.
    pub signer_pubkey_hex: String,
    /// Its signature over the supplied Charter body, hex-encoded.
    pub signature_hex: String,
}

/// `governance_propose` params — author a proposal (daemon-signed by the station
/// wallet). `kind` is `statute` (default), `administrative_rule` (with `scope`),
/// or `emergency` (with `expires_at`). Charter amendments carry a full replacement
/// Charter and are authored on the mobile, not through this convenience method.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposeParams {
    /// The short title (≤200 bytes).
    pub title: String,
    /// The full text, markdown allowed (≤16 KiB).
    pub body: String,
    /// `statute`, `administrative_rule`, or `emergency`.
    #[serde(default = "default_proposal_kind")]
    pub kind: String,
    /// The scope label, required when `kind` is `administrative_rule`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Unix seconds an emergency measure expires, required when `kind` is
    /// `emergency`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

fn default_proposal_kind() -> String {
    "statute".to_string()
}

/// `governance_propose` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposeResult {
    /// The proposal's content address, hex-encoded.
    pub proposal_id: String,
}

/// `governance_proposal` params — one proposal in full, by content address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposalParams {
    /// The hex proposal id.
    pub proposal_id: String,
}

/// `governance_cosign` params — endorse a proposal (daemon-signed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovCosignParams {
    /// The hex proposal id to endorse.
    pub proposal_id: String,
}

/// `governance_cosign` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovCosignResult {
    /// Distinct established co-signers now gathered.
    pub cosigner_count: u32,
}

/// `governance_vote` params — cast a ballot (daemon-signed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovVoteParams {
    /// The hex proposal id being voted on.
    pub proposal_id: String,
    /// `yes`, `no`, or `abstain`.
    pub choice: String,
}

// --- Emergency governance (ADR-0023) --------------------------------

/// `governance_emergency_declare` params — raise an emergency declaration
/// (daemon-signed by the station wallet, whose signature counts toward the
/// supermajority).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovEmergencyDeclareParams {
    /// The crisis, human-readable (testimony/display only).
    pub reason: String,
    /// The declared emergency domain (testimony/display only).
    pub scope: String,
    /// Requested lifetime in seconds; clamped to `[24 h, 7 d]` on activation.
    /// Absent means the 72 h default (ADR-0023 §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<i64>,
    /// The declaration this renews (hex hash), if any — advisory; the effective
    /// renewal count is derived from log proximity (ADR-0023 §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_declaration_hash: Option<String>,
}

/// A `declaration_hash`-addressed emergency action (co-sign or lapse).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovEmergencyTargetParams {
    /// The hex declaration hash (for a lapse co-sign, the lapse's own hash).
    pub declaration_hash: String,
}

/// Result of an emergency declare / co-sign / lapse: the target hash and whether an
/// emergency for it is now active (the crossing may or may not have happened).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovEmergencyActionResult {
    /// The declaration (or lapse) content hash, hex.
    pub declaration_hash: String,
    /// Whether an emergency is active for the declaration after this action.
    pub active: bool,
}

/// One emergency in the derived timeline — the shape the status banner and the
/// post-emergency report both render.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyStatus {
    /// The declaration content hash, hex.
    pub declaration_hash: String,
    /// The crisis, human-readable (testimony).
    pub reason: String,
    /// The declared domain (testimony).
    pub scope: String,
    /// The station-attested activation instant.
    pub activation_instant: i64,
    /// The station-attested scheduled expiry.
    pub scheduled_expiry: i64,
    /// The log-derived renewal count within the proximity chain.
    pub renewal_count: u32,
    /// Whether it is active right now (unlapsed and within its scheduled span).
    pub active: bool,
    /// Whether it was ended early by a lapse.
    pub lapsed: bool,
}

/// `governance_emergency_status` result — the active emergency (if any) and the full
/// derived timeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovEmergencyStatusResult {
    /// The currently-active emergency, if one holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<EmergencyStatus>,
    /// Every emergency that legitimately took force, in log order.
    #[serde(default)]
    pub history: Vec<EmergencyStatus>,
}

/// A measure passed under an emergency, for the post-emergency report (ADR-0023 §6).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyMeasure {
    /// The proposal's content address, hex.
    pub proposal_id: String,
    /// Its title.
    pub title: String,
    /// When the measure itself lapses (its `expires_at`).
    pub expires_at: i64,
}

/// One activation's full accountability record (ADR-0023 §6): the emergency, its
/// co-signers, and every measure passed under it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyReportEntry {
    /// The emergency itself.
    pub emergency: EmergencyStatus,
    /// The addresses that co-signed the declaration into force.
    pub cosigners: Vec<String>,
    /// The Emergency measures admitted under this emergency.
    pub measures: Vec<EmergencyMeasure>,
}

/// A declaration that gathered support but never took force, for the §6 report
/// (ADR-0027 D3): cap-refused (dead) or expired past its TTL.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyInertDeclaration {
    /// The declaration's content address, hex.
    pub declaration_hash: String,
    /// The crisis, for display (testimony).
    pub reason: String,
    /// The declared domain, for display (testimony).
    pub scope: String,
    /// Why it is inert: `"refused"` (a §4 cap bound) or `"expired"` (TTL).
    pub disposition: String,
    /// The addresses that co-signed the declaration.
    pub cosigners: Vec<String>,
}

/// `governance_emergency_report` result — the derived, station-served review surface
/// (ADR-0023 §6, ADR-0027): no new *derivation* logic beyond the log replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovEmergencyReportResult {
    /// One entry per legitimate activation, in log order.
    pub activations: Vec<EmergencyReportEntry>,
    /// Declarations that never took force — cap-refused or expired (ADR-0027 §6).
    #[serde(default)]
    pub inert_declarations: Vec<EmergencyInertDeclaration>,
}

// --- Disputes (T1.10.5) -----------------------------------------------------
//
// The operator-facing half of the dispute layer. The writes (`dispute_raise`,
// `dispute_respond`, `dispute_rule`) are signed by the **station's own wallet**,
// as `propose`/`vouch`/`governance_*` are; a mobile signs its own record and
// submits it over the channel (`submit_dispute` / `submit_dispute_response` /
// `submit_verdict`). `dispute_resolve` is operator-only — it enacts a terminal
// outcome or lets a dispute lapse, the same sweep the resolution timer runs.
// Reads answer with the [`crate::dispute_view`] shapes, so a dispute means one
// thing whoever asks for it.

/// `dispute_raise` params — contest a `Confirmed` transaction (daemon-signed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeRaiseParams {
    /// The hex id of the confirmed transaction to contest.
    pub tx_id: String,
    /// A bounded free-text statement of the grievance.
    pub reason: String,
    /// Optional hex content hash of out-of-band evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
}

/// `dispute_raise` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeRaiseResult {
    /// The disputed transaction's id, hex-encoded.
    pub tx_id: String,
    /// The transaction's state after raising (`"Disputed"`).
    pub state: String,
}

/// `dispute_respond` params — a party's reply to a live dispute (daemon-signed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeRespondParams {
    /// The hex id of the disputed transaction to respond to.
    pub tx_id: String,
    /// A bounded free-text statement of the responder's side.
    pub statement: String,
    /// Optional hex content hash of out-of-band evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
}

/// `dispute_respond` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeRespondResult {
    /// The disputed transaction's id, hex-encoded.
    pub tx_id: String,
}

/// `dispute_rule` params — a seated juror's verdict (daemon-signed).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeRuleParams {
    /// The hex id of the disputed transaction being ruled on.
    pub tx_id: String,
    /// `true` upholds the dispute (voids the transfer), `false` rejects it.
    pub uphold: bool,
}

/// `dispute_rule` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeRuleResult {
    /// The disputed transaction's id, hex-encoded.
    pub tx_id: String,
    /// The ruling recorded: `true` upheld, `false` rejected.
    pub uphold: bool,
}

/// `dispute_resolve` params — enact a terminal outcome or lapse. With no
/// `tx_id`, sweeps every disputed transaction; with one, resolves just that one.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DisputeResolveParams {
    /// The hex id of a single disputed transaction to resolve, or `None` to
    /// sweep them all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
}

/// One transaction's resolution outcome in a `dispute_resolve` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeResolvedRow {
    /// The disputed transaction's id, hex-encoded.
    pub tx_id: String,
    /// The outcome this pass: `pending`, `upheld`, `rejected`, or `lapsed`.
    pub resolution: String,
}

/// `dispute_resolve` result — the outcome of each transaction the pass touched.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeResolveResult {
    /// One row per disputed transaction the sweep resolved (or a single row when
    /// a `tx_id` was given).
    pub resolved: Vec<DisputeResolvedRow>,
}

/// `dispute` params — one dispute in full, by disputed-transaction id.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeShowParams {
    /// The hex id of the disputed transaction.
    pub tx_id: String,
}

/// `dispute_escalate` params — put a dispute to the established-member electorate
/// (daemon-signed). Used when the jury cannot seat a panel (`cannot_seat`) or to
/// appeal its ruling (`appeal`); ADR-0014 §5.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeEscalateParams {
    /// The hex id of the disputed transaction to escalate.
    pub tx_id: String,
    /// Why: `appeal` (of a jury ruling) or `cannot_seat` (jury could not seat).
    pub reason: String,
}

/// `dispute_escalate` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeEscalateResult {
    /// The disputed transaction's id, hex-encoded.
    pub tx_id: String,
    /// The escalation reason recorded.
    pub reason: String,
}

/// `dispute_escalation_vote` params — cast the station wallet's escalation ballot
/// (daemon-signed). The wallet must be an eligible, non-party established member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeEscalationVoteParams {
    /// The hex id of the escalated transaction being voted on.
    pub tx_id: String,
    /// `true` upholds the dispute (voids the transfer), `false` rejects it.
    pub uphold: bool,
}

/// `dispute_escalation_vote` result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisputeEscalationVoteResult {
    /// The escalated transaction's id, hex-encoded.
    pub tx_id: String,
    /// The ballot recorded: `true` upheld, `false` rejected.
    pub uphold: bool,
}
