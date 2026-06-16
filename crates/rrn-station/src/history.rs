//! Decoding raw log entries into the human-readable [`HistoryEntry`] rows the
//! `rrn history` command shows.
//!
//! A log entry is opaque signed CBOR; to summarize it we try the known Phase 0
//! record types in turn — proposal, confirmation, settlement, cancellation,
//! vouch — and fall back to `unknown` for anything we don't recognize (a
//! forward-compatible record from a newer station, say). This is presentation
//! only; nothing here is authoritative.

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
        kind: kind.to_string(),
        summary,
        created_at: entry.created_at,
    }
}

fn decode_summary(bytes: &[u8]) -> (&'static str, String) {
    if let Ok(p) = from_canonical_bytes::<TransactionProposal>(bytes) {
        return (
            "proposal",
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
            "confirmation",
            format!(
                "confirm tx {} by {}",
                short_tx(&c.proposal_id),
                short_addr(&c.confirmer.to_string()),
            ),
        );
    }
    if let Ok(s) = from_canonical_bytes::<SettlementRecord>(bytes) {
        return (
            "settlement",
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
            "cancellation",
            format!("cancel tx {} ({:?})", short_tx(&c.proposal_id), c.reason),
        );
    }
    if let Ok(v) = from_canonical_bytes::<Vouch>(bytes) {
        return (
            "vouch",
            format!(
                "vouch for {}: {:?}",
                short_addr(&v.subject.to_string()),
                v.body.statement,
            ),
        );
    }
    ("unknown", format!("{} bytes", bytes.len()))
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
}
