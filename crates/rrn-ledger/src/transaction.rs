//! The canonical, on-log representation of a transaction.
//!
//! Two records make up the first half of a transaction's life:
//!
//! - a [`TransactionProposal`], signed by the **sender**, which says "I propose
//!   to move `amount_centi` between these two parties"; and
//! - a [`TransactionConfirmation`], signed by the **receiver**, which says "I
//!   accept proposal `proposal_id`".
//!
//! Both are wrapped in [`rrn_crypto::signed::SignedPayload`], so the signature
//! covers the *canonical CBOR* of the record (ADR-0002), never a wire envelope.
//!
//! # Content addressing and the `id` field
//!
//! A [`TransactionId`] is the Blake3 hash of a proposal's canonical bytes, so a
//! proposal names itself: tamper with any field and the id changes. The `id`
//! field is therefore **not part of the hashed/signed content** — it *is* the
//! hash of everything else. [`From<TransactionProposal> for CBOR`] omits `id`;
//! [`TryFrom<CBOR>`] recomputes it after decoding, so a decoded proposal can
//! never carry an id that disagrees with its contents.
//!
//! # Sign convention for `amount_centi`
//!
//! Amounts are signed integer **centicommons** (1 Common = 100 centicommons),
//! never floats. The sign encodes direction:
//!
//! - **positive** `amount_centi` → the sender pays the receiver (the common
//!   case): on settlement the sender's balance falls and the receiver's rises;
//! - **negative** `amount_centi` → the reverse (rare but valid): the receiver
//!   pays the sender.
//!
//! Settlement applies the sign uniformly (see [`crate::settlement`]).

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

/// Discriminant strings carried in the `kind` field of each record's canonical
/// CBOR, so log replay can tell the record types apart unambiguously.
pub(crate) const PROPOSAL_KIND: &str = "rrn.tx.proposal";
pub(crate) const CONFIRMATION_KIND: &str = "rrn.tx.confirmation";

/// The content address of a transaction: the Blake3 hash of its proposal's
/// canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct TransactionId(pub Hash);

impl TransactionId {
    /// The 32 raw hash bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

// A total order over the hash bytes, so a `TransactionId` can key a `BTreeMap`
// during log replay. `Hash` is content, not chronology — this order is
// arbitrary but stable and identical on every replica.
impl Ord for TransactionId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for TransactionId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<TransactionId> for CBOR {
    fn from(id: TransactionId) -> Self {
        CBOR::to_byte_string(id.0.to_bytes())
    }
}

impl TryFrom<CBOR> for TransactionId {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(TransactionId(Hash::from_bytes(bytes)))
    }
}

/// A proposed transaction: the sender's signed offer to move Commons.
///
/// Positive `amount_centi` means the sender pays the receiver; negative means
/// the reverse (see the module docs).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionProposal {
    /// Content address: Blake3 of this proposal's canonical bytes (all fields
    /// below). Derived, not independent — see the module docs.
    pub id: TransactionId,
    /// The party who proposes (and signs) the transaction.
    pub sender: Address,
    /// The party on the other side, who must confirm.
    pub receiver: Address,
    /// Signed integer centicommons; positive = sender pays receiver.
    pub amount_centi: i64,
    /// Optional human-readable note. Part of the signed content.
    pub memo: Option<String>,
    /// Per-sender monotonic nonce; the engine rejects gaps and duplicates.
    pub nonce: u64,
    /// Unix seconds when the proposal was made.
    pub proposed_at: i64,
    /// Unix seconds after which the proposal auto-cancels if unconfirmed.
    pub expires_at: i64,
}

impl TransactionProposal {
    /// Builds a proposal and computes its content-addressed [`id`](Self::id).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: Address,
        receiver: Address,
        amount_centi: i64,
        memo: Option<String>,
        nonce: u64,
        proposed_at: i64,
        expires_at: i64,
    ) -> Self {
        let mut proposal = Self {
            // Placeholder; overwritten immediately by `compute_id`, which hashes
            // every field *except* `id`.
            id: TransactionId(Hash::from_bytes([0u8; 32])),
            sender,
            receiver,
            amount_centi,
            memo,
            nonce,
            proposed_at,
            expires_at,
        };
        proposal.id = proposal.compute_id();
        proposal
    }

    /// Recomputes the content address from the current field values.
    fn compute_id(&self) -> TransactionId {
        use rrn_crypto::serialize::to_canonical_bytes;
        // `Into<CBOR>` (below) omits `id`, so this hashes only the content.
        TransactionId(Hash::of(&to_canonical_bytes(self.clone())))
    }
}

impl From<TransactionProposal> for CBOR {
    fn from(p: TransactionProposal) -> Self {
        let mut m = Map::new();
        // `id` is deliberately omitted — it is the hash of these bytes.
        m.insert("kind", PROPOSAL_KIND);
        m.insert("sender", p.sender);
        m.insert("receiver", p.receiver);
        m.insert("amount_centi", p.amount_centi);
        // `Option<String>` has no dCBOR mapping; encode text-or-null explicitly.
        match p.memo {
            Some(text) => m.insert("memo", text),
            None => m.insert("memo", CBOR::null()),
        }
        m.insert("nonce", p.nonce);
        m.insert("proposed_at", p.proposed_at);
        m.insert("expires_at", p.expires_at);
        m.into()
    }
}

impl TryFrom<CBOR> for TransactionProposal {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != PROPOSAL_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let proposal = TransactionProposal::new(
            map.extract::<&str, Address>("sender")?,
            map.extract::<&str, Address>("receiver")?,
            map.extract::<&str, i64>("amount_centi")?,
            // A null (or absent) memo decodes to `None`, text to `Some`.
            map.get::<&str, String>("memo"),
            map.extract::<&str, u64>("nonce")?,
            map.extract::<&str, i64>("proposed_at")?,
            map.extract::<&str, i64>("expires_at")?,
        );
        Ok(proposal)
    }
}

/// A [`TransactionProposal`] signed by its sender.
pub type SignedProposal = SignedPayload<TransactionProposal>;

/// The receiver's signed acceptance of a [`TransactionProposal`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TransactionConfirmation {
    /// The proposal being confirmed.
    pub proposal_id: TransactionId,
    /// Who is confirming — must equal the proposal's `receiver`.
    pub confirmer: Address,
    /// Unix seconds when the confirmation was made.
    pub confirmed_at: i64,
}

impl From<TransactionConfirmation> for CBOR {
    fn from(c: TransactionConfirmation) -> Self {
        let mut m = Map::new();
        m.insert("kind", CONFIRMATION_KIND);
        m.insert("proposal_id", c.proposal_id);
        m.insert("confirmer", c.confirmer);
        m.insert("confirmed_at", c.confirmed_at);
        m.into()
    }
}

impl TryFrom<CBOR> for TransactionConfirmation {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CONFIRMATION_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(TransactionConfirmation {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            confirmer: map.extract::<&str, Address>("confirmer")?,
            confirmed_at: map.extract::<&str, i64>("confirmed_at")?,
        })
    }
}

/// A [`TransactionConfirmation`] signed by its confirmer (the receiver).
pub type SignedConfirmation = SignedPayload<TransactionConfirmation>;

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn addr() -> Address {
        Address::from_public_key(Keypair::generate().public_key())
    }

    fn sample_proposal() -> TransactionProposal {
        TransactionProposal::new(
            addr(),
            addr(),
            300,
            Some("lunch".into()),
            0,
            1_700_000_000,
            1_700_086_400,
        )
    }

    #[test]
    fn proposal_canonical_roundtrip() {
        for memo in [Some("note".to_string()), None] {
            let mut p = sample_proposal();
            p.memo = memo;
            p.id = p.compute_id();
            let bytes = to_canonical_bytes(p.clone());
            let decoded: TransactionProposal = from_canonical_bytes(&bytes).unwrap();
            assert_eq!(p, decoded);
        }
    }

    #[test]
    fn id_is_deterministic_and_content_addressed() {
        let p = sample_proposal();
        // Recomputing from the same content gives the same id (stable across
        // runs — purely a function of the canonical bytes).
        assert_eq!(p.id, p.compute_id());

        // A decoded proposal recomputes the same id.
        let bytes = to_canonical_bytes(p.clone());
        let decoded: TransactionProposal = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.id, p.id);

        // Changing any content field changes the id.
        let mut q = p.clone();
        q.amount_centi += 1;
        q.id = q.compute_id();
        assert_ne!(q.id, p.id);
    }

    #[test]
    fn signing_a_proposal_verifies_and_id_matches_payload_hash() {
        let kp = Keypair::generate();
        let p = sample_proposal();
        let signed = SignedProposal::sign(p.clone(), &kp);
        assert!(signed.verify().is_ok());
        // The proposal id is exactly the hash of the signed canonical bytes.
        assert_eq!(signed.payload_hash(), p.id.0);
    }

    #[test]
    fn confirmation_canonical_roundtrip_and_signs() {
        let kp = Keypair::generate();
        let confirmation = TransactionConfirmation {
            proposal_id: sample_proposal().id,
            confirmer: addr(),
            confirmed_at: 1_700_000_100,
        };
        let bytes = to_canonical_bytes(confirmation.clone());
        let decoded: TransactionConfirmation = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(confirmation, decoded);

        let signed = SignedConfirmation::sign(confirmation, &kp);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn record_kinds_do_not_cross_decode() {
        // A confirmation's bytes must not decode as a proposal, and vice versa —
        // the `kind` discriminant keeps log replay unambiguous.
        let proposal_bytes = to_canonical_bytes(sample_proposal());
        assert!(from_canonical_bytes::<TransactionConfirmation>(&proposal_bytes).is_err());

        let confirmation = TransactionConfirmation {
            proposal_id: sample_proposal().id,
            confirmer: addr(),
            confirmed_at: 1,
        };
        let confirmation_bytes = to_canonical_bytes(confirmation);
        assert!(from_canonical_bytes::<TransactionProposal>(&confirmation_bytes).is_err());
    }
}
