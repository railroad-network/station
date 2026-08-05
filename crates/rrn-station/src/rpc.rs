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
    /// Unix seconds the receiver confirmed; present once confirmed/settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<i64>,
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
