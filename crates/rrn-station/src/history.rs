//! Decoding raw log entries into the human-readable [`HistoryEntry`] rows the
//! `rrn history` command shows.
//!
//! A log entry is opaque signed CBOR; to summarize it we try the known Phase 0
//! record types in turn — proposal, confirmation, settlement, cancellation,
//! vouch — and fall back to `unknown` for anything we don't recognize (a
//! forward-compatible record from a newer station, say). This is presentation
//! only; nothing here is authoritative.

use dcbor::prelude::*;

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::vouch::Vouch;
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::CancellationRecord;
use rrn_ledger::transaction::{TransactionConfirmation, TransactionId, TransactionProposal};
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};

use crate::rpc::HistoryEntry;

/// Returns decoded history, most recent first, after skipping `offset` entries
/// and taking at most `limit` (both from the most-recent end).
pub fn history(
    db: &Database,
    limit: Option<u64>,
    offset: Option<u64>,
) -> rrn_storage::Result<Vec<HistoryEntry>> {
    let log = AppendLog::new(db);
    let mut all: Vec<HistoryEntry> = Vec::new();
    for entry in log.iter_from(1) {
        all.push(summarize(&entry?));
    }
    // Most recent first.
    all.reverse();

    let offset = offset.unwrap_or(0) as usize;
    let mut out: Vec<HistoryEntry> = all.into_iter().skip(offset).collect();
    if let Some(limit) = limit {
        out.truncate(limit as usize);
    }
    Ok(out)
}

/// Decodes one entry's payload into a `(kind, summary)` row.
fn summarize(entry: &LogEntry) -> HistoryEntry {
    let bytes = &entry.payload.bytes;
    let (kind, summary) = decode_summary(bytes);
    HistoryEntry {
        seq: entry.seq,
        kind,
        summary,
        created_at: entry.created_at,
    }
}

fn decode_summary(bytes: &[u8]) -> (String, String) {
    if let Ok(p) = from_canonical_bytes::<TransactionProposal>(bytes) {
        return (
            "proposal".into(),
            format!(
                "propose {} from {} to {} (tx {})",
                fmt_commons(p.amount_centi),
                short_addr(&p.sender.to_string()),
                short_addr(&p.receiver.to_string()),
                short_tx(&p.id),
            ),
        );
    }
    if let Ok(c) = from_canonical_bytes::<TransactionConfirmation>(bytes) {
        return (
            "confirmation".into(),
            format!(
                "confirm tx {} by {}",
                short_tx(&c.proposal_id),
                short_addr(&c.confirmer.to_string()),
            ),
        );
    }
    if let Ok(s) = from_canonical_bytes::<SettlementRecord>(bytes) {
        return (
            "settlement".into(),
            format!(
                "settle {} from {} to {} (tx {})",
                fmt_commons(s.amount_centi),
                short_addr(&s.sender.to_string()),
                short_addr(&s.receiver.to_string()),
                short_tx(&s.proposal_id),
            ),
        );
    }
    if let Ok(c) = from_canonical_bytes::<CancellationRecord>(bytes) {
        return (
            "cancellation".into(),
            format!("cancel tx {} ({:?})", short_tx(&c.proposal_id), c.reason),
        );
    }
    if let Ok(v) = from_canonical_bytes::<Vouch>(bytes) {
        return (
            "vouch".into(),
            format!(
                "vouch for {}: {:?}",
                short_addr(&v.subject.to_string()),
                v.body.statement,
            ),
        );
    }
    // Anything without a bespoke summary above — every marketplace and contract
    // record — still names itself from the `kind` tag every record carries,
    // rather than reading "unknown". No concrete type is decoded, so this holds
    // for a forward-compatible record from a newer station too.
    if let Some(kind) = record_kind(bytes) {
        return friendly_kind(&kind);
    }
    ("unknown".into(), format!("{} bytes", bytes.len()))
}

/// The `kind` string every signed record carries at its CBOR map's `"kind"` key,
/// read without decoding the concrete type. `None` if the payload is not a CBOR
/// map or carries no `kind`.
fn record_kind(bytes: &[u8]) -> Option<String> {
    let cbor = CBOR::try_from_data(bytes).ok()?;
    let CBORCase::Map(map) = cbor.into_case() else {
        return None;
    };
    map.extract::<&str, String>("kind").ok()
}

/// Turns a record `kind` tag into a `(kind column, summary)` pair. Drops the
/// `rrn.` prefix and any trailing `.vN` version, names the row by its final
/// segment, and reads the summary as a plain phrase — e.g.
/// `rrn.marketplace.stock_consumed.v1` → (`stock_consumed`, "marketplace stock consumed").
fn friendly_kind(kind: &str) -> (String, String) {
    let trimmed = kind.strip_prefix("rrn.").unwrap_or(kind);
    let mut parts: Vec<&str> = trimmed.split('.').collect();
    if parts.last().is_some_and(|s| is_version(s)) {
        parts.pop();
    }
    let name = parts.last().copied().unwrap_or(kind);
    let summary = parts.join(" ").replace('_', " ");
    (name.to_string(), summary)
}

/// Whether a dotted segment is a version tag like `v1`, `v2`.
fn is_version(s: &str) -> bool {
    s.strip_prefix('v')
        .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Formats centicommons as `<int>.<2-digit> Commons`.
pub fn fmt_commons(centi: i64) -> String {
    let sign = if centi < 0 { "-" } else { "" };
    let abs = centi.unsigned_abs();
    format!("{sign}{}.{:02} Commons", abs / 100, abs % 100)
}

/// Hex of the first 4 bytes of a transaction id, for compact display.
fn short_tx(id: &TransactionId) -> String {
    let b = id.to_bytes();
    format!("{:02x}{:02x}{:02x}{:02x}…", b[0], b[1], b[2], b[3])
}

/// First 12 chars of an `rrn1…` address, for compact display.
fn short_addr(addr: &str) -> String {
    let take: String = addr.chars().take(12).collect();
    format!("{take}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_commons_handles_sign_and_padding() {
        assert_eq!(fmt_commons(350), "3.50 Commons");
        assert_eq!(fmt_commons(1), "0.01 Commons");
        assert_eq!(fmt_commons(0), "0.00 Commons");
        assert_eq!(fmt_commons(-300), "-3.00 Commons");
    }

    #[test]
    fn friendly_kind_names_records_from_their_tag() {
        // A versioned marketplace record: prefix and `.v1` dropped, name is the
        // final segment, summary reads as a plain phrase.
        assert_eq!(
            friendly_kind("rrn.marketplace.stock_consumed.v1"),
            (
                "stock_consumed".to_string(),
                "marketplace stock consumed".to_string()
            )
        );
        // An unversioned ledger record.
        assert_eq!(
            friendly_kind("rrn.tx.contract_charge"),
            (
                "contract_charge".to_string(),
                "tx contract charge".to_string()
            )
        );
        // A tag in no recognized shape still names itself rather than panicking.
        assert_eq!(
            friendly_kind("weird"),
            ("weird".to_string(), "weird".to_string())
        );
    }

    #[test]
    fn only_real_version_segments_are_dropped() {
        assert!(is_version("v1"));
        assert!(is_version("v12"));
        assert!(!is_version("v"));
        assert!(!is_version("valve"));
        assert!(!is_version("1"));
    }
}
