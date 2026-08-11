//! Raising a dispute, and the window a dispute freezes settlement for.
//!
//! A confirmed transaction normally waits out its settlement window and then the
//! [`Settler`](crate::settlement::Settler) moves it to `Settled`. That same
//! window is the Phase-1 **dispute window**: while it runs, either party may
//! contest the confirmation. Raising a dispute appends a signed [`DisputeRecord`]
//! that drives the transaction across the `Confirmed → Disputed` edge and
//! **freezes** it — the sweep skips a `Disputed` transaction so no balance moves
//! while the dispute is adjudicated (ADR-0014).
//!
//! The freeze is *bounded*, not indefinite. Opening a dispute starts a fixed
//! **dispute-resolution window** ([`DisputeConfig`], default 14 days). If that
//! window closes with no terminal ruling the dispute lapses and the transaction
//! settles as originally confirmed — a non-ruling is a rejection. The orchestration
//! that draws a jury, tallies verdicts, and enacts the outcome lives in the
//! `rrn-dispute` crate; this module supplies only the ledger-level record, the
//! window constant, and the frozen state it produces, keeping `rrn-ledger` free of
//! any reputation or governance dependency.

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

use crate::transaction::TransactionId;

/// Discriminant string carried in a dispute record's canonical CBOR.
pub(crate) const DISPUTE_KIND: &str = "rrn.tx.dispute";

/// The default dispute-resolution window: 14 days. A dispute freezes settlement
/// for at most this long; if no ruling lands the freeze lifts and the confirmed
/// transaction settles (ADR-0014 §5).
pub const DEFAULT_DISPUTE_WINDOW_SECONDS: i64 = 14 * 24 * 3600;

/// Maximum length, in bytes, of a dispute's free-text `reason`. The evidence
/// channel is deliberately thin in Phase 1 — a bounded statement plus an optional
/// content hash — with the rich artifact channel deferred to Tier 3 (ADR-0014 §1).
pub const MAX_DISPUTE_REASON_BYTES: usize = 2048;

/// Tunable dispute parameters. Kept alongside the settlement windows so a
/// demo/test can collapse the freeze the same way it collapses settlement.
#[derive(Clone, Copy, Debug)]
pub struct DisputeConfig {
    /// How long opening a dispute freezes settlement before the dispute lapses
    /// and the transaction settles as confirmed. Defaults to
    /// [`DEFAULT_DISPUTE_WINDOW_SECONDS`].
    pub window_seconds: i64,
}

impl Default for DisputeConfig {
    fn default() -> Self {
        Self {
            window_seconds: DEFAULT_DISPUTE_WINDOW_SECONDS,
        }
    }
}

impl DisputeConfig {
    /// Whether a dispute opened at `opened_at` has passed its resolution window as
    /// of `now` — the point at which an unresolved dispute lapses to the confirmed
    /// status quo (ADR-0014 §5).
    pub fn has_lapsed(&self, opened_at: i64, now: i64) -> bool {
        opened_at.saturating_add(self.window_seconds) <= now
    }
}

/// A party's signed record that they contest a confirmed transaction.
///
/// Appended by the sender or receiver while the transaction is `Confirmed` and
/// inside its settlement window; it references the disputed transaction, carries a
/// bounded statement of the grievance, and optionally a content hash for evidence
/// exchanged out of band. Derives serde like [`TransactionProposal`] so it can be
/// embedded, verifiable, in the derived [`Disputed`](crate::state::TransactionState::Disputed)
/// state, and carries manual CBOR for its canonical log bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DisputeRecord {
    /// The confirmed transaction being contested.
    pub proposal_id: TransactionId,
    /// The party raising the dispute (must be the transaction's sender or
    /// receiver).
    pub raiser: Address,
    /// A bounded free-text statement of the grievance
    /// (≤ [`MAX_DISPUTE_REASON_BYTES`]).
    pub reason: String,
    /// Optional content hash of out-of-band evidence. `None` for a
    /// statement-only dispute.
    pub evidence_hash: Option<Hash>,
    /// Unix seconds when the dispute was opened.
    pub opened_at: i64,
}

impl DisputeRecord {
    /// Whether `reason` is within the Phase-1 bound. A dispute with an
    /// over-long reason is rejected at append time (`DisputeReasonTooLong`).
    pub fn reason_within_bound(&self) -> bool {
        self.reason.len() <= MAX_DISPUTE_REASON_BYTES
    }
}

/// A [`DisputeRecord`] signed by the party who raised it.
pub type SignedDispute = SignedPayload<DisputeRecord>;

/// A 32-byte content hash on the wire, mirroring `ListingRef`'s byte-string
/// idiom so an optional hash decodes with the same `map.get` path as the other
/// optional record fields.
struct EvidenceHash(Hash);

impl From<EvidenceHash> for CBOR {
    fn from(h: EvidenceHash) -> Self {
        CBOR::to_byte_string(h.0.to_bytes())
    }
}

impl TryFrom<CBOR> for EvidenceHash {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(EvidenceHash(Hash::from_bytes(bytes)))
    }
}

impl From<DisputeRecord> for CBOR {
    fn from(d: DisputeRecord) -> Self {
        let mut m = Map::new();
        m.insert("kind", DISPUTE_KIND);
        m.insert("proposal_id", d.proposal_id);
        m.insert("raiser", d.raiser);
        m.insert("reason", d.reason);
        // Omit-when-`None`, like `listing_id`: a statement-only dispute carries no
        // `evidence_hash` key at all rather than a null.
        if let Some(hash) = d.evidence_hash {
            m.insert("evidence_hash", EvidenceHash(hash));
        }
        m.insert("opened_at", d.opened_at);
        m.into()
    }
}

impl TryFrom<CBOR> for DisputeRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != DISPUTE_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(DisputeRecord {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            raiser: map.extract::<&str, Address>("raiser")?,
            reason: map.extract::<&str, String>("reason")?,
            // Absent decodes to `None`; a byte string to a `Some` hash.
            evidence_hash: map.get::<&str, EvidenceHash>("evidence_hash").map(|e| e.0),
            opened_at: map.extract::<&str, i64>("opened_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn sample(evidence: Option<Hash>) -> DisputeRecord {
        let raiser = Keypair::generate();
        DisputeRecord {
            proposal_id: TransactionId(Hash::of(b"tx")),
            raiser: Address::from_public_key(raiser.public_key()),
            reason: "goods never arrived".into(),
            evidence_hash: evidence,
            opened_at: 1_700,
        }
    }

    #[test]
    fn roundtrip_without_evidence() {
        let rec = sample(None);
        let bytes = to_canonical_bytes(rec.clone());
        // A statement-only dispute must not carry the evidence key at all.
        assert!(!bytes
            .windows(b"evidence_hash".len())
            .any(|w| w == b"evidence_hash"));
        let decoded: DisputeRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn roundtrip_with_evidence() {
        let rec = sample(Some(Hash::of(b"receipt.pdf")));
        let bytes = to_canonical_bytes(rec.clone());
        let decoded: DisputeRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(rec, decoded);
        assert_eq!(decoded.evidence_hash, Some(Hash::of(b"receipt.pdf")));
    }

    #[test]
    fn signed_dispute_verifies() {
        let raiser = Keypair::generate();
        let mut rec = sample(None);
        rec.raiser = Address::from_public_key(raiser.public_key());
        let signed = SignedDispute::sign(rec, &raiser);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn reason_bound() {
        let mut rec = sample(None);
        rec.reason = "x".repeat(MAX_DISPUTE_REASON_BYTES);
        assert!(rec.reason_within_bound());
        rec.reason = "x".repeat(MAX_DISPUTE_REASON_BYTES + 1);
        assert!(!rec.reason_within_bound());
    }

    #[test]
    fn window_lapses_at_end() {
        let cfg = DisputeConfig {
            window_seconds: 100,
        };
        assert!(!cfg.has_lapsed(1_000, 1_099));
        assert!(cfg.has_lapsed(1_000, 1_100));
    }
}
