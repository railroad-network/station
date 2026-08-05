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

/// A reference to the marketplace listing a proposal settles (T1.7.6).
///
/// The ledger holds it as **opaque 32 bytes** — a marketplace `ListingId` in raw
/// form — so `rrn-ledger` stays free of a dependency on `rrn-marketplace`, which
/// already depends on it (the reverse would cycle). Marketplace and mobile code
/// convert via `ListingId::to_bytes()` / `hexToBytes`. Encoded as a CBOR byte
/// string, exactly as a listing or inquiry id is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListingRef(pub [u8; 32]);

impl From<ListingRef> for CBOR {
    fn from(r: ListingRef) -> Self {
        CBOR::to_byte_string(r.0)
    }
}

impl TryFrom<CBOR> for ListingRef {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(ListingRef(bytes))
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
    /// The marketplace listing this proposal settles, when it came from an agreed
    /// inquiry (T1.7.6); `None` for a direct pay. **Additive to a content-addressed
    /// record**, so it is OMITTED from the CBOR when `None` (never `null`) — see
    /// the `From`/`TryFrom` impls below and ADR-0010.
    pub listing_id: Option<ListingRef>,
    /// An **opt-up** on the oracle tier (Overview §4.3): a request that this
    /// transaction be held to a higher tier than its amount alone requires, e.g.
    /// a small-value medical consult a listing marks Tier 2. `None` — the common
    /// case — means the transaction takes its amount's [`tier_floor`], so like
    /// [`listing_id`](Self::listing_id) it is **OMITTED from the CBOR when
    /// `None`** to keep every plain proposal byte-identical to before this field
    /// existed (ADR-0010's additive-field rule). When present it must be a
    /// genuine lift ([`tier::is_valid_opt_up`]); the tier that governs settlement
    /// is [`tier::effective_tier`], never this raw value.
    ///
    /// [`tier_floor`]: crate::tier::tier_floor
    /// [`tier::is_valid_opt_up`]: crate::tier::is_valid_opt_up
    /// [`tier::effective_tier`]: crate::tier::effective_tier
    pub oracle_tier: Option<u8>,
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
            // A direct pay carries no listing link; the marketplace path adds one
            // with `with_listing`. Absent-when-`None` keeps direct sends
            // byte-identical to before this field existed.
            listing_id: None,
            // No opt-up by default: the transaction takes its amount's tier
            // floor. `with_tier` records a genuine lift. Absent-when-`None`, same
            // additive-field discipline as `listing_id`.
            oracle_tier: None,
            nonce,
            proposed_at,
            expires_at,
        };
        proposal.id = proposal.compute_id();
        proposal
    }

    /// Links this proposal to the marketplace listing it settles (T1.7.6),
    /// recomputing its content [`id`](Self::id) with the link included. Used when
    /// an agreed inquiry produces a payment; a direct send never calls this.
    pub fn with_listing(mut self, listing: ListingRef) -> Self {
        self.listing_id = Some(listing);
        self.id = self.compute_id();
        self
    }

    /// Opts this transaction *up* the oracle ladder to `tier`, recomputing its
    /// content [`id`](Self::id) with the opt-up included (T1.8.1).
    ///
    /// `tier` must be a genuine lift for this amount ([`crate::tier::is_valid_opt_up`]):
    /// strictly above the amount's own floor and no higher than
    /// [`crate::tier::MAX_PHASE1_TIER`]. A `tier` that is not a valid opt-up is
    /// ignored (the proposal keeps its amount-derived floor), so a redundant or
    /// out-of-range request can never produce a second encoding of the same
    /// effective tier.
    pub fn with_tier(mut self, tier: u8) -> Self {
        if crate::tier::is_valid_opt_up(self.amount_centi, tier) {
            self.oracle_tier = Some(tier);
            self.id = self.compute_id();
        }
        self
    }

    /// The oracle tier that governs this transaction — the higher of its amount
    /// floor and any recorded opt-up. This is what settlement, staking, and
    /// disputes read; never the raw [`oracle_tier`](Self::oracle_tier) field. It
    /// is *not* capped at the Phase-1 ceiling: a Tier-3 amount reports `3`, which
    /// the engine rejects on submit ([`crate::Error::TierNotSupported`]) rather
    /// than lowering.
    pub fn effective_tier(&self) -> u8 {
        crate::tier::effective_tier(self.amount_centi, self.oracle_tier)
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
        // ⚠️ Unlike `memo` above, `listing_id` is OMITTED when `None` — never
        // `null`. It was added to an already content-addressed record (ADR-0010):
        // a key present in *every* proposal's map would change the recomputed id
        // of every proposal already on the log, breaking the confirmations and
        // settlements that reference them. Absent-when-unset keeps old proposals
        // byte-identical; only a linked proposal carries the key.
        if let Some(listing) = p.listing_id {
            m.insert("listing_id", listing);
        }
        // Same omit-when-`None` discipline as `listing_id` above: a plain
        // proposal (no opt-up) carries no `oracle_tier` key, so it stays
        // byte-identical to before this field existed. Only a genuine opt-up
        // writes the key. Encoded as an unsigned integer (tier is 1..=2).
        if let Some(tier) = p.oracle_tier {
            m.insert("oracle_tier", tier);
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
        // Absent listing_id decodes to `None` (a direct pay); a byte string to a
        // link — the omit-when-`None` counterpart of the encoder above. Applied
        // after construction so the recomputed id matches the sender's.
        let proposal = match map.get::<&str, ListingRef>("listing_id") {
            Some(listing) => proposal.with_listing(listing),
            None => proposal,
        };
        // Absent oracle_tier decodes to `None` (the amount's own floor governs);
        // a present integer to an opt-up. `with_tier` re-validates it, so a
        // forged or out-of-range tier in the bytes is dropped rather than
        // trusted — the recomputed id then simply won't match a tampered record.
        let proposal = match map.get::<&str, u8>("oracle_tier") {
            Some(tier) => proposal.with_tier(tier),
            None => proposal,
        };
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

    /// True if `needle` appears anywhere in `haystack`. Used to assert a key is
    /// (or is not) present in canonical CBOR bytes.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn listing_link_is_absent_when_unlinked_and_leaves_the_id_stable() {
        let unlinked = sample_proposal(); // listing_id: None
        let bytes = to_canonical_bytes(unlinked.clone());
        // Absent, never null: the key must not appear at all, so a proposal
        // written before this field existed hashes — and so is id'd — identically.
        // This is the ADR-0010 guard against corrupting the log on upgrade.
        assert!(!contains(&bytes, b"listing_id"));

        // Linking is additive content, so the key appears and the id changes.
        let linked = unlinked.clone().with_listing(ListingRef([7u8; 32]));
        assert!(contains(&to_canonical_bytes(linked.clone()), b"listing_id"));
        assert_ne!(linked.id, unlinked.id);
    }

    #[test]
    fn a_listing_linked_proposal_round_trips() {
        let linked = sample_proposal().with_listing(ListingRef([9u8; 32]));
        let bytes = to_canonical_bytes(linked.clone());
        let decoded: TransactionProposal = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, linked);
        assert_eq!(decoded.listing_id, Some(ListingRef([9u8; 32])));
        // The recomputed id agrees with the link included.
        assert_eq!(decoded.id, linked.id);
    }

    #[test]
    fn tier_opt_up_is_absent_by_default_and_leaves_the_id_stable() {
        let plain = sample_proposal(); // amount 300 → Tier 1 floor, no opt-up
        assert_eq!(plain.oracle_tier, None);
        assert_eq!(plain.effective_tier(), 1);
        let bytes = to_canonical_bytes(plain.clone());
        // Absent, never null — same ADR-0010 guard as listing_id: a proposal
        // written before this field existed hashes identically.
        assert!(!contains(&bytes, b"oracle_tier"));

        // Opting a Tier-1 amount up to Tier 2 is additive content: the key
        // appears, the id changes, and the effective tier follows.
        let lifted = plain.clone().with_tier(2);
        assert_eq!(lifted.oracle_tier, Some(2));
        assert_eq!(lifted.effective_tier(), 2);
        assert!(contains(
            &to_canonical_bytes(lifted.clone()),
            b"oracle_tier"
        ));
        assert_ne!(lifted.id, plain.id);
    }

    #[test]
    fn a_tier_lifted_proposal_round_trips() {
        let lifted = sample_proposal().with_tier(2);
        let bytes = to_canonical_bytes(lifted.clone());
        let decoded: TransactionProposal = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, lifted);
        assert_eq!(decoded.oracle_tier, Some(2));
        assert_eq!(decoded.id, lifted.id);
    }

    #[test]
    fn a_redundant_or_out_of_range_opt_up_is_ignored() {
        // Opting to the floor (Tier 1) is redundant: dropped, so there is one
        // canonical encoding and the id is unchanged from plain.
        let plain = sample_proposal();
        let redundant = plain.clone().with_tier(1);
        assert_eq!(redundant.oracle_tier, None);
        assert_eq!(redundant.id, plain.id);

        // Opting above the Phase-1 ceiling is dropped too.
        let too_high = plain.clone().with_tier(3);
        assert_eq!(too_high.oracle_tier, None);
        assert_eq!(too_high.id, plain.id);
    }

    #[test]
    fn effective_tier_follows_the_amount_floor_without_an_opt_up() {
        // A 5-Common (500 centi) amount is Tier 2 from its floor alone.
        let big =
            TransactionProposal::new(addr(), addr(), 500, None, 0, 1_700_000_000, 1_700_086_400);
        assert_eq!(big.oracle_tier, None);
        assert_eq!(big.effective_tier(), 2);
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
