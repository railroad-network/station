//! Per-device outbox chains (ADR-0020 §2).
//!
//! Every signing device maintains its own append-only, hash-chained **outbox**.
//! Each [`OutboxEntry`] wraps exactly one already-signed application record and
//! is itself signed by the device (member) key that authored that record — one
//! chain per signing key. Entries chain by [`OutboxEntry::entry_hash`], so a
//! carried run is tamper-evident and a courier that drops an entry leaves a
//! detectable gap.
//!
//! # The embedded record
//!
//! The wrapped record travels as three fields — [`record_signer`], [`record_sig`],
//! and [`record_bytes`] — the signer, signature, and *canonical signed bytes* of
//! the carried record, mirroring [`rrn_storage::log::StoredPayload`]
//! field-for-field but as explicit CBOR map entries rather than a packed blob.
//! The signer and signature are copied **verbatim** and never regenerated;
//! `record_bytes` reproduces the payload's canonical dCBOR, which — because that
//! encoding is deterministic (ADR-0002) — is byte-identical to what the author
//! signed, and is thereafter carried and hashed verbatim. So
//! [`record_hash`](OutboxEntry::record_hash) is the Blake3 of `record_bytes`, the
//! same content hash the log admits under, and receipts, dedup, and admission all
//! speak one identifier.
//!
//! [`record_signer`]: OutboxEntry::record_signer
//! [`record_sig`]: OutboxEntry::record_sig
//! [`record_bytes`]: OutboxEntry::record_bytes

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use serde::{Deserialize, Serialize};

use crate::{zero_hash, Error, Result};

/// Discriminant carried in the `kind` field of an outbox entry's canonical CBOR.
pub(crate) const OUTBOX_KIND: &str = "rrn.dtn.outbox";

/// One entry in a per-device outbox chain: a carriage wrapper around one
/// already-signed application record, itself signed by the authoring device key
/// as a [`SignedPayload<OutboxEntry>`].
///
/// The three `record_*` fields carry the wrapped record verbatim (see the module
/// docs). `authored_at` is testimony (ADR-0022 §3): kept for display and
/// evidence, never used in any window or ordering decision.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OutboxEntry {
    /// The chain owner. MUST equal the key that signs the enclosing
    /// [`SignedPayload<OutboxEntry>`] — enforced by [`validate`].
    pub author: Address,
    /// 0-based, strictly sequential position of this entry in the author's
    /// chain.
    pub position: u64,
    /// Blake3 [`entry_hash`](OutboxEntry::entry_hash) of the previous entry, or
    /// the all-zero hash at [`position`](OutboxEntry::position) `0`.
    pub prev_hash: Hash,
    /// Ed25519 public key of the carried record's signer.
    pub record_signer: PublicKey,
    /// Signature by [`record_signer`](OutboxEntry::record_signer) over
    /// [`record_bytes`](OutboxEntry::record_bytes).
    pub record_sig: Signature,
    /// The carried record's canonical dCBOR — the exact bytes its author signed.
    pub record_bytes: Vec<u8>,
    /// Testimony timestamp (ADR-0022 §3): when the device says it authored the
    /// entry. Never load-bearing for windows or ordering.
    pub authored_at: i64,
}

impl OutboxEntry {
    /// Wraps an already-signed application record as the next entry in an
    /// author's chain.
    ///
    /// `record` is embedded verbatim — its canonical payload bytes, signer, and
    /// signature — so the carried signature stays valid exactly as its author
    /// produced it. Call [`SignedPayload::sign`] on the returned value with the
    /// author's device key to seal the entry into the chain.
    pub fn wrapping<T: Clone + Into<CBOR>>(
        author: Address,
        position: u64,
        prev_hash: Hash,
        record: &SignedPayload<T>,
        authored_at: i64,
    ) -> Self {
        Self {
            author,
            position,
            prev_hash,
            record_signer: record.signer,
            record_sig: record.signature,
            record_bytes: to_canonical_bytes(record.payload.clone()),
            authored_at,
        }
    }

    /// Blake3 of this entry's canonical bytes — the identifier the *next* entry
    /// chains to via its `prev_hash`, and what [`is_fork`] compares.
    pub fn entry_hash(&self) -> Hash {
        Hash::of(&to_canonical_bytes(self.clone()))
    }

    /// Blake3 of the carried record's bytes — the same content hash the log
    /// admits under, and what a [`crate::receipt::DeliveryReceipt`] keys on.
    pub fn record_hash(&self) -> Hash {
        Hash::of(&self.record_bytes)
    }

    /// Verifies the *embedded* record's signature: that
    /// [`record_sig`](OutboxEntry::record_sig) is a valid signature by
    /// [`record_signer`](OutboxEntry::record_signer) over
    /// [`record_bytes`](OutboxEntry::record_bytes).
    ///
    /// This is only the inner half; the outer entry signature and the
    /// author/signer identity are checked by [`validate`], which needs the
    /// enclosing [`SignedPayload`] in hand.
    pub fn verify_embedded(&self) -> Result<()> {
        self.record_signer
            .verify(&self.record_bytes, &self.record_sig)
            .map_err(|_| Error::BadEmbeddedSignature)
    }
}

impl From<OutboxEntry> for CBOR {
    fn from(e: OutboxEntry) -> Self {
        let mut m = Map::new();
        m.insert("kind", OUTBOX_KIND);
        m.insert("author", e.author);
        m.insert("position", e.position);
        m.insert("prev_hash", CBOR::to_byte_string(e.prev_hash.to_bytes()));
        m.insert(
            "record_signer",
            CBOR::to_byte_string(e.record_signer.to_bytes()),
        );
        m.insert("record_sig", CBOR::to_byte_string(e.record_sig.to_bytes()));
        m.insert("record_bytes", CBOR::to_byte_string(e.record_bytes));
        m.insert("authored_at", e.authored_at);
        m.into()
    }
}

impl TryFrom<CBOR> for OutboxEntry {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != OUTBOX_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(OutboxEntry {
            author: map.extract::<&str, Address>("author")?,
            position: map.extract::<&str, u64>("position")?,
            prev_hash: extract_hash(&map, "prev_hash")?,
            record_signer: extract_public_key(&map, "record_signer")?,
            record_sig: extract_signature(&map, "record_sig")?,
            record_bytes: map
                .extract::<&str, CBOR>("record_bytes")?
                .try_into_byte_string()?
                .as_slice()
                .to_vec(),
            authored_at: map.extract::<&str, i64>("authored_at")?,
        })
    }
}

/// A [`OutboxEntry`] signed by its author's device key.
pub type SignedOutboxEntry = SignedPayload<OutboxEntry>;

/// Fully validates a signed outbox entry: the outer signature verifies, the
/// declared [`author`](OutboxEntry::author) is the outer signer, and the
/// embedded record signature verifies.
///
/// The author/signer identity can only be checked where the enclosing
/// [`SignedPayload`] is in hand — the outer signer is not part of the entry body
/// — so this takes the signed envelope rather than a bare [`OutboxEntry`].
pub fn validate(signed: &SignedOutboxEntry) -> Result<()> {
    signed.verify().map_err(|_| Error::BadOuterSignature)?;
    if signed.payload.author.public_key() != &signed.signer {
        return Err(Error::AuthorSignerMismatch);
    }
    signed.payload.verify_embedded()
}

/// True iff `a` and `b` are an **outbox fork**: two valid entries by the same
/// author claiming the same [`position`](OutboxEntry::position) with different
/// content ([`entry_hash`](OutboxEntry::entry_hash)).
///
/// This is the device-owner equivocation primitive ADR-0021/T2.3.3 builds on.
/// Two entries with the same position *and* the same hash are a duplicate (the
/// same entry carried twice), **not** a fork. Both entries must independently
/// [`validate`]; an entry that does not verify is not evidence of anything.
pub fn is_fork(a: &SignedOutboxEntry, b: &SignedOutboxEntry) -> bool {
    validate(a).is_ok()
        && validate(b).is_ok()
        && a.payload.author == b.payload.author
        && a.payload.position == b.payload.position
        && a.payload_hash() != b.payload_hash()
}

/// Validates a whole outbox chain from one author: each entry [`validate`]s,
/// positions run `0, 1, 2, …`, and each `prev_hash` links to the previous
/// entry's [`entry_hash`](OutboxEntry::entry_hash) (all-zero at position 0).
///
/// An empty slice is a valid (empty) chain. A *gap* — a chain that does not
/// start at 0 or skips a position — is rejected here as a linkage/sequence
/// fault; partial carriage is a property of a [`crate::bundle::Bundle`], not of
/// a chain presented as complete.
pub fn validate_chain(entries: &[SignedOutboxEntry]) -> Result<()> {
    let mut prev_hash = zero_hash();
    for (i, signed) in entries.iter().enumerate() {
        validate(signed)?;
        let expected = i as u64;
        if signed.payload.position != expected {
            return Err(Error::PositionOutOfSequence {
                expected,
                found: signed.payload.position,
            });
        }
        if signed.payload.prev_hash != prev_hash {
            return Err(Error::ChainBroken {
                position: signed.payload.position,
            });
        }
        prev_hash = signed.payload.entry_hash();
    }
    Ok(())
}

// --- CBOR byte-string field helpers ----------------------------------------
//
// dcbor has no native mapping for our fixed-width crypto types, so a byte-string
// field is extracted then length-checked into the target type. A wrong length or
// a non-byte-string value is a `WrongType` shape fault, matching the house style.

fn extract_hash(map: &Map, key: &str) -> std::result::Result<Hash, dcbor::Error> {
    let bytes: [u8; 32] = map
        .extract::<&str, CBOR>(key)?
        .try_into_byte_string()?
        .as_slice()
        .try_into()
        .map_err(|_| dcbor::Error::WrongType)?;
    Ok(Hash::from_bytes(bytes))
}

fn extract_public_key(map: &Map, key: &str) -> std::result::Result<PublicKey, dcbor::Error> {
    let bytes: [u8; 32] = map
        .extract::<&str, CBOR>(key)?
        .try_into_byte_string()?
        .as_slice()
        .try_into()
        .map_err(|_| dcbor::Error::WrongType)?;
    PublicKey::from_bytes(bytes).map_err(|_| dcbor::Error::WrongType)
}

fn extract_signature(map: &Map, key: &str) -> std::result::Result<Signature, dcbor::Error> {
    let bytes: [u8; 64] = map
        .extract::<&str, CBOR>(key)?
        .try_into_byte_string()?
        .as_slice()
        .try_into()
        .map_err(|_| dcbor::Error::WrongType)?;
    Signature::from_bytes(bytes).map_err(|_| dcbor::Error::WrongType)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    /// A stand-in for a carried application record (a proposal, vote, …), so the
    /// outbox layer can be exercised without depending on a ledger record type.
    #[derive(Clone, Debug, PartialEq)]
    struct Record {
        kind: &'static str,
        n: u64,
    }

    impl From<Record> for CBOR {
        fn from(r: Record) -> Self {
            let mut m = Map::new();
            m.insert("kind", r.kind);
            m.insert("n", r.n);
            m.into()
        }
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    fn record(n: u64) -> SignedPayload<Record> {
        let author = Keypair::generate();
        SignedPayload::sign(
            Record {
                kind: "rrn.test.record",
                n,
            },
            &author,
        )
    }

    /// Builds a signed chain of `len` entries for one device, each wrapping a
    /// fresh record, correctly linked.
    fn chain(device: &Keypair, len: u64) -> Vec<SignedOutboxEntry> {
        let mut out = Vec::new();
        let mut prev = zero_hash();
        for pos in 0..len {
            let entry = OutboxEntry::wrapping(
                addr(device),
                pos,
                prev,
                &record(pos),
                1_700_000_000 + pos as i64,
            );
            prev = entry.entry_hash();
            out.push(SignedPayload::sign(entry, device));
        }
        out
    }

    #[test]
    fn canonical_roundtrip() {
        let device = Keypair::generate();
        let entry = OutboxEntry::wrapping(addr(&device), 0, zero_hash(), &record(7), 1_700_000_000);
        let bytes = to_canonical_bytes(entry.clone());
        let decoded: OutboxEntry = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn record_hash_is_blake3_of_record_bytes() {
        let device = Keypair::generate();
        let carried = record(3);
        let entry = OutboxEntry::wrapping(addr(&device), 0, zero_hash(), &carried, 1);
        assert_eq!(entry.record_hash(), carried.payload_hash());
    }

    #[test]
    fn valid_entry_validates() {
        let device = Keypair::generate();
        let signed = &chain(&device, 1)[0];
        assert!(validate(signed).is_ok());
    }

    #[test]
    fn wrong_outer_signer_is_rejected() {
        let device = Keypair::generate();
        let entry = OutboxEntry::wrapping(addr(&device), 0, zero_hash(), &record(1), 1);
        // Signed by a different key than the declared author.
        let signed = SignedPayload::sign(entry, &Keypair::generate());
        assert_eq!(validate(&signed), Err(Error::AuthorSignerMismatch));
    }

    #[test]
    fn tampered_record_bytes_fails_validation() {
        let device = Keypair::generate();
        let mut signed = chain(&device, 1).pop().unwrap();
        // Flip a byte of the carried record; the outer signature (over the body,
        // which includes record_bytes) no longer verifies.
        signed.payload.record_bytes[0] ^= 0x01;
        assert_eq!(validate(&signed), Err(Error::BadOuterSignature));
    }

    #[test]
    fn bad_embedded_signature_fails_validation() {
        let device = Keypair::generate();
        let mut entry = OutboxEntry::wrapping(addr(&device), 0, zero_hash(), &record(1), 1);
        // Replace the embedded signature with one over unrelated bytes, then
        // re-sign the entry so only the *inner* check can catch it.
        entry.record_sig = Keypair::generate().sign(b"unrelated");
        let signed = SignedPayload::sign(entry, &device);
        assert_eq!(validate(&signed), Err(Error::BadEmbeddedSignature));
    }

    #[test]
    fn fork_detection_positive_and_negative() {
        let device = Keypair::generate();
        // Two different entries at the same position 0 → a fork.
        let a = SignedPayload::sign(
            OutboxEntry::wrapping(addr(&device), 0, zero_hash(), &record(1), 1),
            &device,
        );
        let b = SignedPayload::sign(
            OutboxEntry::wrapping(addr(&device), 0, zero_hash(), &record(2), 1),
            &device,
        );
        assert!(is_fork(&a, &b));

        // The same entry carried twice: same position, same hash → duplicate,
        // not a fork.
        assert!(!is_fork(&a, &a.clone()));

        // Different positions are not a fork.
        let c = SignedPayload::sign(
            OutboxEntry::wrapping(addr(&device), 1, a.payload.entry_hash(), &record(3), 1),
            &device,
        );
        assert!(!is_fork(&a, &c));

        // Same position by two *different* authors is not one device's fork.
        let other = Keypair::generate();
        let d = SignedPayload::sign(
            OutboxEntry::wrapping(addr(&other), 0, zero_hash(), &record(1), 1),
            &other,
        );
        assert!(!is_fork(&a, &d));
    }

    #[test]
    fn a_valid_chain_validates() {
        let device = Keypair::generate();
        assert!(validate_chain(&chain(&device, 5)).is_ok());
        // An empty chain is a valid empty chain.
        assert!(validate_chain(&[]).is_ok());
    }

    #[test]
    fn a_broken_link_is_rejected() {
        let device = Keypair::generate();
        let mut entries = chain(&device, 3);
        // Corrupt the second entry's prev_hash and re-sign so the outer
        // signature still passes — only the chain linkage should catch it.
        entries[1].payload.prev_hash = zero_hash();
        entries[1] = SignedPayload::sign(entries[1].payload.clone(), &device);
        assert_eq!(
            validate_chain(&entries),
            Err(Error::ChainBroken { position: 1 })
        );
    }

    #[test]
    fn an_out_of_sequence_position_is_rejected() {
        let device = Keypair::generate();
        // A chain that starts at position 1 (a gap at the front) is rejected.
        let entry = OutboxEntry::wrapping(addr(&device), 1, zero_hash(), &record(1), 1);
        let signed = SignedPayload::sign(entry, &device);
        assert_eq!(
            validate_chain(&[signed]),
            Err(Error::PositionOutOfSequence {
                expected: 0,
                found: 1,
            })
        );
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_chains_validate_and_mutation_is_local(len in 0u64..40, victim in 0usize..40) {
            let device = Keypair::generate();
            let entries = chain(&device, len);
            // Every entry in a freshly built chain validates.
            for signed in &entries {
                proptest::prop_assert!(validate(signed).is_ok());
            }
            proptest::prop_assert!(validate_chain(&entries).is_ok());

            if !entries.is_empty() {
                let idx = victim % entries.len();
                let mut mutated = entries.clone();
                // Flip one byte of one entry's carried record bytes.
                mutated[idx].payload.record_bytes[0] ^= 0x01;
                for (i, signed) in mutated.iter().enumerate() {
                    if i == idx {
                        proptest::prop_assert!(validate(signed).is_err());
                    } else {
                        // Every other entry is untouched and still validates.
                        proptest::prop_assert!(validate(signed).is_ok());
                    }
                }
            }
        }
    }
}
