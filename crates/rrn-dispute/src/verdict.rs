//! The one record a dispute writes: a juror's signed verdict.
//!
//! A seated juror casts a signed [`JurorVerdict`] — uphold the dispute or reject
//! it — over the disputed transaction. The panel that juror sits on is *derived*
//! (see [`crate::sortition`]), so a verdict is the only appended artifact; the
//! tally recomputes seating from the log and counts only verdicts whose juror
//! actually holds a seat, so a stray or gossiped verdict from a non-juror is inert.

use dcbor::prelude::*;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::transaction::TransactionId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use std::collections::HashMap;

use crate::Result;

/// Discriminant string carried in a verdict's canonical CBOR.
pub(crate) const VERDICT_KIND: &str = "rrn.dispute.verdict";

/// A juror's signed ruling on a dispute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JurorVerdict {
    /// The disputed transaction this verdict rules on.
    pub proposal_id: TransactionId,
    /// The juror casting the verdict (must hold a live seat on the panel).
    pub juror: Address,
    /// `true` to uphold the dispute (void the transfer), `false` to reject it
    /// (let the transaction settle as confirmed).
    pub uphold: bool,
    /// Unix seconds when the juror says they cast the verdict — testimony only
    /// (ADR-0022 §3). The panel seats and times the verdict by its admission time;
    /// this value is refused only when dated into the future beyond the clock-skew
    /// tolerance.
    pub cast_at: i64,
}

/// A [`JurorVerdict`] signed by the juror who cast it.
pub type SignedVerdict = SignedPayload<JurorVerdict>;

impl From<JurorVerdict> for CBOR {
    fn from(v: JurorVerdict) -> Self {
        let mut m = Map::new();
        m.insert("kind", VERDICT_KIND);
        m.insert("proposal_id", v.proposal_id);
        m.insert("juror", v.juror);
        // A binary ruling as a text discriminant, matching the house style for
        // small enumerations (e.g. governance `VoteChoice`) rather than a bare
        // CBOR bool.
        m.insert("ruling", if v.uphold { "uphold" } else { "reject" });
        m.insert("cast_at", v.cast_at);
        m.into()
    }
}

impl TryFrom<CBOR> for JurorVerdict {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != VERDICT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let uphold = match map.extract::<&str, String>("ruling")?.as_str() {
            "uphold" => true,
            "reject" => false,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(JurorVerdict {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            juror: map.extract::<&str, Address>("juror")?,
            uphold,
            cast_at: map.extract::<&str, i64>("cast_at")?,
        })
    }
}

/// Every juror's verdict on `tx_id`, keyed by juror, as `(uphold, admitted_at)` —
/// the map [`resolve_panel`](crate::panel::resolve_panel) consumes.
///
/// The time is the verdict's **admission** time (its log entry's `created_at`),
/// never the juror-signed [`cast_at`](JurorVerdict::cast_at) (ADR-0022 §1, §5): a
/// party-asserted timestamp must not enter seat-window or ruling-time arithmetic, or
/// a juror past their deadline could date a verdict back inside their lapsed seat.
///
/// Replay derivation: scans the log after `after_seq` (pass the dispute's admission
/// `seq`; a verdict cannot precede the dispute it rules on) for verdicts naming this
/// transaction, from a signer who is the juror they name, keeping the **first**
/// admitted per juror (a verdict is final — a later one from the same juror is
/// ignored). This is a thin read; whether a verdict *counts* is decided by the
/// panel, which only credits a verdict whose juror holds a seat within their
/// response window.
pub fn verdicts(
    db: &Database,
    tx_id: &TransactionId,
    after_seq: u64,
) -> Result<HashMap<Address, (bool, i64)>> {
    let log = AppendLog::new(db);
    let mut out: HashMap<Address, (bool, i64)> = HashMap::new();
    for entry in log.iter_from(after_seq.saturating_add(1)) {
        let entry = entry?;
        let Ok(verdict) = from_canonical_bytes::<JurorVerdict>(&entry.payload.bytes) else {
            continue;
        };
        if verdict.proposal_id != *tx_id {
            continue;
        }
        // The signer must be the named juror (defends a hostile log copy).
        if Address::from_public_key(entry.payload.signer) != verdict.juror {
            continue;
        }
        out.entry(verdict.juror)
            .or_insert((verdict.uphold, entry.created_at));
    }
    Ok(out)
}
