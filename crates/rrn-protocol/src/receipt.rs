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
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

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
    /// A record content-identical to one already in the log was re-presented as
    /// a *new* admission (the ledger's own duplicate guard fired). Distinct from
    /// the idempotent `known` outcome, which is the benign re-carriage of an
    /// already-admitted record; this is the engine refusing a second admission.
    Duplicate,
    /// The record's oracle tier is above what this phase admits (ADR-0011): the
    /// amount is too large, and is *blocked*, never clamped.
    TierUnsupported,
    /// The referenced transaction is absent or not in the state the record needs
    /// (e.g. a confirmation whose proposal has not been admitted — couriers must
    /// keep outbox order, ADR-0020 §4).
    NotProposed,
    /// The confirmer of a Tier-2 payment does not clear the Member band and the
    /// community is past bootstrap grace, so the reputation-staking gate (T1.8.2)
    /// refuses the confirmation. An eligibility fault, not a signature or state
    /// fault — a courier's owner can tell "raise your standing" from a generic
    /// rejection.
    Tier2Stake,
    /// The engine refused the record for a reason without a more specific slug
    /// (a state-machine or plausibility fault). A machine-stable catch-all so the
    /// closed set need not grow a variant per ledger error.
    Rejected,
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
            RefusalReason::Duplicate => "duplicate",
            RefusalReason::TierUnsupported => "tier-unsupported",
            RefusalReason::NotProposed => "not-proposed",
            RefusalReason::Tier2Stake => "tier2-stake",
            RefusalReason::Rejected => "rejected",
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
            "duplicate" => Some(RefusalReason::Duplicate),
            "tier-unsupported" => Some(RefusalReason::TierUnsupported),
            "not-proposed" => Some(RefusalReason::NotProposed),
            "tier2-stake" => Some(RefusalReason::Tier2Stake),
            "rejected" => Some(RefusalReason::Rejected),
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

/// Encodes a signed receipt as portable **receipt-envelope bytes**: the
/// `{signer, sig, body}` triple as canonical dCBOR, where `body` is the
/// canonical bytes of the [`DeliveryReceipt`] the station signed. This mirrors
/// [`crate::bundle::EntryEnvelope`] field-for-field — a [`SignedPayload`] is a
/// serde envelope, not a dCBOR value, so it needs an explicit framing to travel
/// as bytes over a carrier (or hex over RPC).
///
/// This is the exact byte format an offline receiver decodes and verifies the
/// station signature over (the mobile FFI's `receipt_parse`, T2.4.2). Because
/// the signature covers only the payload's canonical bytes (ADR-0002), the
/// envelope may be re-framed freely without invalidating it.
pub fn encode_signed(signed: &SignedReceipt) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("signer", CBOR::to_byte_string(signed.signer.to_bytes()));
    m.insert("sig", CBOR::to_byte_string(signed.signature.to_bytes()));
    m.insert(
        "body",
        CBOR::to_byte_string(to_canonical_bytes(signed.payload.clone())),
    );
    CBOR::from(m).to_cbor_data()
}

/// Decodes portable receipt-envelope bytes (see [`encode_signed`]) back into a
/// [`SignedReceipt`].
///
/// This does **not** verify the station signature — call [`SignedPayload::verify`]
/// on the result. It only reconstructs the typed envelope, failing if the bytes
/// are not a canonical `{signer, sig, body}` map whose `body` is a canonical
/// [`DeliveryReceipt`].
pub fn decode_signed(bytes: &[u8]) -> Result<SignedReceipt> {
    let cbor = CBOR::try_from_data(bytes).map_err(|e| Error::Cbor(e.to_string()))?;
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return Err(Error::Cbor("receipt envelope is not a CBOR map".into())),
    };
    let signer_bytes: [u8; 32] = map
        .extract::<&str, CBOR>("signer")
        .map_err(|e| Error::Cbor(e.to_string()))?
        .try_into_byte_string()
        .map_err(|e| Error::Cbor(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Cbor("signer is not 32 bytes".into()))?;
    let sig_bytes: [u8; 64] = map
        .extract::<&str, CBOR>("sig")
        .map_err(|e| Error::Cbor(e.to_string()))?
        .try_into_byte_string()
        .map_err(|e| Error::Cbor(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Cbor("sig is not 64 bytes".into()))?;
    let body = map
        .extract::<&str, CBOR>("body")
        .map_err(|e| Error::Cbor(e.to_string()))?
        .try_into_byte_string()
        .map_err(|e| Error::Cbor(e.to_string()))?;
    let payload: DeliveryReceipt = from_canonical_bytes(body.as_slice())?;
    Ok(SignedPayload {
        payload,
        signer: PublicKey::from_bytes(signer_bytes)
            .map_err(|_| Error::Cbor("bad signer".into()))?,
        signature: Signature::from_bytes(sig_bytes).map_err(|_| Error::Cbor("bad sig".into()))?,
    })
}

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
            RefusalReason::Duplicate,
            RefusalReason::TierUnsupported,
            RefusalReason::NotProposed,
            RefusalReason::Tier2Stake,
            RefusalReason::Rejected,
        ] {
            assert_eq!(RefusalReason::from_slug(reason.as_slug()), Some(reason));
        }
        assert_eq!(RefusalReason::from_slug("not-a-reason"), None);
    }

    #[test]
    fn signed_envelope_roundtrips_and_carries_the_signature() {
        let kp = Keypair::generate();
        let receipt = DeliveryReceipt {
            station: Address::from_public_key(kp.public_key()),
            ..sample()
        };
        let signed = SignedReceipt::sign(receipt, &kp);
        let bytes = encode_signed(&signed);
        let decoded = decode_signed(&bytes).unwrap();
        assert_eq!(decoded, signed);
        // The reconstructed envelope still verifies against the station key.
        assert!(decoded.verify().is_ok());
        // Re-encoding is byte-stable (canonical framing).
        assert_eq!(encode_signed(&decoded), bytes);
    }

    #[test]
    fn decode_signed_rejects_garbage_and_wrong_shapes() {
        assert!(decode_signed(&[0xff, 0x00, 0x13]).is_err());
        // A bare (unframed) receipt body is not a `{signer,sig,body}` envelope.
        let bare = to_canonical_bytes(sample());
        assert!(decode_signed(&bare).is_err());
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
