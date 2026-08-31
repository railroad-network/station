//! Station delivery receipts (ADR-0020 §3).
//!
//! When the station ingests a bundle it answers with a station-signed
//! [`DeliveryReceipt`] enumerating, per presented record, whether it was
//! **admitted**, was **already known**, or was **refused** (with a machine-stable
//! reason). Receipts travel back to members by the same carriers, so an offline
//! sender learns the fate of a record they handed to a courier days ago.
//!
//! Each outcome keys on the record's [`crate::outbox::OutboxEntry::record_hash`]
//! — the Blake3 of the carried record's canonical bytes, the same identifier the
//! log admits under — never on a bundle id, so a receipt is meaningful no matter
//! how the record was bundled.
//!
//! # A receipt is transport state, not community state
//!
//! A [`DeliveryReceipt`] is **never appended to the community log**. It attests
//! delivery, not a ledger fact; the ledger facts (settlement, cancellation) are
//! their own station-signed records (ADR-0005). T2.2.3 persists receipts in a
//! local, unsigned table for redelivery. `received_at` is the station's
//! admission-clock reading at ingest — evidence of when it answered, testimony
//! only (ADR-0022 §3), never an input to any window.

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

/// Discriminant carried in the `kind` field of a receipt's canonical CBOR.
pub(crate) const RECEIPT_KIND: &str = "rrn.dtn.receipt";

/// Why the station refused to admit a presented record. A closed set of
/// machine-stable slugs, never free text, so a receipt reader on any platform
/// can branch on the reason deterministically.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    /// A signature (record or outbox entry) did not verify.
    BadSignature,
    /// The sender's per-sender nonce was a gap or a duplicate.
    NonceGap,
    /// Admitting the record would commit its signer below the debt floor
    /// (ADR-0018).
    DebtFloor,
    /// The proposal had expired by the admission clock (ADR-0022 §4).
    Expired,
    /// The record's `kind` is not one the station admits over DTN.
    UnroutableKind,
    /// The entry is one side of an outbox fork (ADR-0020 §2 / ADR-0021).
    OutboxFork,
}

impl RefusalReason {
    /// The wire slug for this reason.
    pub fn as_slug(&self) -> &'static str {
        match self {
            RefusalReason::BadSignature => "bad-signature",
            RefusalReason::NonceGap => "nonce-gap",
            RefusalReason::DebtFloor => "debt-floor",
            RefusalReason::Expired => "expired",
            RefusalReason::UnroutableKind => "unroutable-kind",
            RefusalReason::OutboxFork => "outbox-fork",
        }
    }

    /// Parses a wire slug back into a [`RefusalReason`], or `None` for any
    /// unrecognised slug. The set is closed, so this is also the length bound:
    /// every accepted slug is one of the short constants below.
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "bad-signature" => Some(RefusalReason::BadSignature),
            "nonce-gap" => Some(RefusalReason::NonceGap),
            "debt-floor" => Some(RefusalReason::DebtFloor),
            "expired" => Some(RefusalReason::Expired),
            "unroutable-kind" => Some(RefusalReason::UnroutableKind),
            "outbox-fork" => Some(RefusalReason::OutboxFork),
            _ => None,
        }
    }
}

/// What the station did with one presented record.
///
/// `seq` (the admitting log sequence) is present exactly for
/// [`Admitted`](Disposition::Admitted) and [`Known`](Disposition::Known); a
/// `reason` is present exactly for [`Refused`](Disposition::Refused). The
/// encoder omits the absent key entirely (never `null`), matching the additive-
/// field discipline of the rest of the wire layer.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Newly admitted at log sequence `seq`.
    Admitted {
        /// Log sequence at which the record was admitted.
        seq: u64,
    },
    /// Already present at log sequence `seq` (idempotent re-submission).
    Known {
        /// Log sequence at which the record already sits.
        seq: u64,
    },
    /// Refused with a machine-stable reason; nothing was admitted.
    Refused {
        /// Why the record was refused.
        reason: RefusalReason,
    },
}

impl Disposition {
    /// The wire slug for the `outcome` field.
    fn outcome_slug(&self) -> &'static str {
        match self {
            Disposition::Admitted { .. } => "admitted",
            Disposition::Known { .. } => "known",
            Disposition::Refused { .. } => "refused",
        }
    }
}

/// One record's fate in a [`DeliveryReceipt`].
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Blake3 of the presented record's canonical bytes
    /// ([`crate::outbox::OutboxEntry::record_hash`]).
    pub record_hash: Hash,
    /// What the station did with it.
    pub disposition: Disposition,
}

impl From<Outcome> for CBOR {
    fn from(o: Outcome) -> Self {
        let mut m = Map::new();
        m.insert(
            "record_hash",
            CBOR::to_byte_string(o.record_hash.to_bytes()),
        );
        m.insert("outcome", o.disposition.outcome_slug());
        // `seq` present iff admitted/known; `reason` present iff refused —
        // omit-when-absent, never null (ADR-0010 discipline).
        match o.disposition {
            Disposition::Admitted { seq } | Disposition::Known { seq } => {
                m.insert("seq", seq);
            }
            Disposition::Refused { reason } => {
                m.insert("reason", reason.as_slug());
            }
        }
        m.into()
    }
}

impl TryFrom<CBOR> for Outcome {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let record_hash = {
            let bytes: [u8; 32] = map
                .extract::<&str, CBOR>("record_hash")?
                .try_into_byte_string()?
                .as_slice()
                .try_into()
                .map_err(|_| dcbor::Error::WrongType)?;
            Hash::from_bytes(bytes)
        };
        // Enforce the tagged-union invariant on decode, mirroring the encoder's
        // omit-when-absent discipline: `seq` is present exactly for
        // admitted/known, `reason` exactly for refused. A contradictory extra
        // key (a `reason` on an admitted outcome, a `seq` on a refused one) is a
        // malformed outcome, not a silently-ignored one — reject it rather than
        // round-trip it as well-formed.
        let has_seq = map.extract::<&str, CBOR>("seq").is_ok();
        let has_reason = map.extract::<&str, CBOR>("reason").is_ok();
        let disposition = match map.extract::<&str, String>("outcome")?.as_str() {
            "admitted" | "known" if has_reason => return Err(dcbor::Error::WrongType),
            "admitted" => Disposition::Admitted {
                seq: map.extract::<&str, u64>("seq")?,
            },
            "known" => Disposition::Known {
                seq: map.extract::<&str, u64>("seq")?,
            },
            "refused" if has_seq => return Err(dcbor::Error::WrongType),
            "refused" => {
                let slug = map.extract::<&str, String>("reason")?;
                let reason = RefusalReason::from_slug(&slug).ok_or(dcbor::Error::WrongType)?;
                Disposition::Refused { reason }
            }
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(Outcome {
            record_hash,
            disposition,
        })
    }
}

/// A station-signed answer to an ingested bundle: one [`Outcome`] per presented
/// record, in presented order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DeliveryReceipt {
    /// The issuing station's address.
    pub station: Address,
    /// One outcome per record presented, in the order presented.
    pub outcomes: Vec<Outcome>,
    /// The station's admission-clock reading at ingest (testimony, ADR-0022 §3).
    pub received_at: i64,
}

impl From<DeliveryReceipt> for CBOR {
    fn from(r: DeliveryReceipt) -> Self {
        let mut m = Map::new();
        m.insert("kind", RECEIPT_KIND);
        m.insert("station", r.station);
        let outcomes: Vec<CBOR> = r.outcomes.into_iter().map(CBOR::from).collect();
        m.insert("outcomes", outcomes);
        m.insert("received_at", r.received_at);
        m.into()
    }
}

impl TryFrom<CBOR> for DeliveryReceipt {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != RECEIPT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let raw = match map.extract::<&str, CBOR>("outcomes")?.into_case() {
            CBORCase::Array(items) => items,
            _ => return Err(dcbor::Error::WrongType),
        };
        let mut outcomes = Vec::with_capacity(raw.len());
        for item in raw {
            outcomes.push(Outcome::try_from(item)?);
        }
        Ok(DeliveryReceipt {
            station: map.extract::<&str, Address>("station")?,
            outcomes,
            received_at: map.extract::<&str, i64>("received_at")?,
        })
    }
}

/// A [`DeliveryReceipt`] signed by the issuing station.
pub type SignedReceipt = SignedPayload<DeliveryReceipt>;

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn station() -> Address {
        Address::from_public_key(Keypair::generate().public_key())
    }

    fn sample() -> DeliveryReceipt {
        DeliveryReceipt {
            station: station(),
            outcomes: vec![
                Outcome {
                    record_hash: Hash::of(b"a"),
                    disposition: Disposition::Admitted { seq: 42 },
                },
                Outcome {
                    record_hash: Hash::of(b"b"),
                    disposition: Disposition::Known { seq: 7 },
                },
                Outcome {
                    record_hash: Hash::of(b"c"),
                    disposition: Disposition::Refused {
                        reason: RefusalReason::DebtFloor,
                    },
                },
            ],
            received_at: 1_700_000_000,
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn canonical_roundtrip() {
        let receipt = sample();
        let bytes = to_canonical_bytes(receipt.clone());
        let decoded: DeliveryReceipt = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(receipt, decoded);
    }

    #[test]
    fn empty_outcomes_roundtrip() {
        let receipt = DeliveryReceipt {
            station: station(),
            outcomes: vec![],
            received_at: 5,
        };
        let bytes = to_canonical_bytes(receipt.clone());
        assert_eq!(
            from_canonical_bytes::<DeliveryReceipt>(&bytes).unwrap(),
            receipt
        );
    }

    #[test]
    fn seq_and_reason_are_omitted_when_absent() {
        // A refused outcome carries no `seq`; an admitted one carries no `reason`.
        let refused = to_canonical_bytes(Outcome {
            record_hash: Hash::of(b"x"),
            disposition: Disposition::Refused {
                reason: RefusalReason::Expired,
            },
        });
        assert!(!contains(&refused, b"seq"));
        assert!(contains(&refused, b"reason"));

        let admitted = to_canonical_bytes(Outcome {
            record_hash: Hash::of(b"y"),
            disposition: Disposition::Admitted { seq: 1 },
        });
        assert!(contains(&admitted, b"seq"));
        assert!(!contains(&admitted, b"reason"));
    }

    #[test]
    fn every_refusal_reason_round_trips_through_its_slug() {
        for reason in [
            RefusalReason::BadSignature,
            RefusalReason::NonceGap,
            RefusalReason::DebtFloor,
            RefusalReason::Expired,
            RefusalReason::UnroutableKind,
            RefusalReason::OutboxFork,
        ] {
            assert_eq!(RefusalReason::from_slug(reason.as_slug()), Some(reason));
        }
        assert_eq!(RefusalReason::from_slug("not-a-reason"), None);
    }

    #[test]
    fn signs_and_verifies() {
        let kp = Keypair::generate();
        let receipt = DeliveryReceipt {
            station: Address::from_public_key(kp.public_key()),
            ..sample()
        };
        let signed = SignedReceipt::sign(receipt, &kp);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn a_contradictory_extra_key_is_rejected() {
        // An "admitted" outcome carrying a stray `reason`, and a "refused" one
        // carrying a stray `seq`, are malformed — the tagged-union invariant is
        // enforced on decode, not silently ignored.
        let mut admitted_with_reason = Map::new();
        admitted_with_reason.insert(
            "record_hash",
            CBOR::to_byte_string(Hash::of(b"a").to_bytes()),
        );
        admitted_with_reason.insert("outcome", "admitted");
        admitted_with_reason.insert("seq", 1u64);
        admitted_with_reason.insert("reason", "debt-floor");
        assert!(Outcome::try_from(CBOR::from(admitted_with_reason)).is_err());

        let mut refused_with_seq = Map::new();
        refused_with_seq.insert(
            "record_hash",
            CBOR::to_byte_string(Hash::of(b"b").to_bytes()),
        );
        refused_with_seq.insert("outcome", "refused");
        refused_with_seq.insert("reason", "expired");
        refused_with_seq.insert("seq", 9u64);
        assert!(Outcome::try_from(CBOR::from(refused_with_seq)).is_err());
    }

    #[test]
    fn a_refused_outcome_without_a_reason_is_rejected() {
        // Hand-build an outcome map claiming "refused" but omitting `reason`.
        let mut m = Map::new();
        m.insert(
            "record_hash",
            CBOR::to_byte_string(Hash::of(b"z").to_bytes()),
        );
        m.insert("outcome", "refused");
        let cbor: CBOR = m.into();
        assert!(Outcome::try_from(cbor).is_err());
    }

    #[test]
    fn record_kinds_do_not_cross_decode() {
        // A receipt's bytes must not decode as an outbox entry (different kind),
        // and a foreign record kind must not decode as a receipt.
        let receipt_bytes = to_canonical_bytes(sample());
        assert!(from_canonical_bytes::<crate::outbox::OutboxEntry>(&receipt_bytes).is_err());

        // A stand-in "foreign" signed record (kind "rrn.tx.proposal").
        let mut foreign = Map::new();
        foreign.insert("kind", "rrn.tx.proposal");
        foreign.insert("amount_centi", 1i64);
        let foreign_bytes = CBOR::from(foreign).to_cbor_data();
        assert!(from_canonical_bytes::<DeliveryReceipt>(&foreign_bytes).is_err());
    }
}
