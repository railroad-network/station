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
}
