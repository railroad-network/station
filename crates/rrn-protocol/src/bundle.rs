//! Carriage bundles (ADR-0020 §3).
//!
//! A [`Bundle`] is an **unsigned** envelope carrying a run of signed outbox
//! entries from one or more devices. It is a dumb-carrier structure
//! (ADR-0008/0013): integrity and authenticity live on each entry's signatures,
//! never on the bundle, so any device or peer may carry any bundle and a
//! tampered bundle can at worst corrupt entries (which then fail
//! [`crate::outbox::validate`]) — it can never forge one.
//!
//! # Entry framing
//!
//! Each carried entry is an [`EntryEnvelope`] — the `{signer, sig, body}` triple
//! of a signed outbox entry, mirroring [`rrn_storage::log::StoredPayload`] — and
//! rides in the bundle as the **canonical bytes** of that triple (a CBOR byte
//! string). Carrying entries as opaque byte strings keeps a courier from having
//! to understand them and makes [`Bundle::bundle_id`] a stable function of the
//! concatenated carriage.
//!
//! # `bundle_id` is a carriage identifier, not a content identifier
//!
//! [`Bundle::bundle_id`] identifies a *carriage unit* (for chunking in T2.2.5).
//! It is deliberately **not** stable under re-bundling: the same record carried
//! in two different bundles has two different `bundle_id`s. Receipts therefore
//! key on each record's [`crate::outbox::OutboxEntry::record_hash`], never on
//! `bundle_id`.

use std::collections::HashMap;

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;

use crate::outbox::OutboxEntry;
use crate::{Error, Result};

/// Bundle format version carried in the `v` field.
pub const BUNDLE_VERSION: u64 = 1;

/// Maximum number of entries a bundle may carry. A decode of a larger bundle is
/// refused — a documented DoS bound.
pub const MAX_BUNDLE_ENTRIES: usize = 512;

/// Maximum encoded size of a bundle in bytes (4 MiB). A decode of a larger
/// input is refused before the CBOR is walked — a documented DoS bound.
pub const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

/// The wire framing of one signed outbox entry as carried in a bundle: the
/// signer, signature, and canonical `body` bytes of the entry. Mirrors
/// [`rrn_storage::log::StoredPayload`], but as explicit CBOR map entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryEnvelope {
    /// The device key that signed the entry `body`.
    pub signer: PublicKey,
    /// Signature by [`signer`](EntryEnvelope::signer) over
    /// [`body`](EntryEnvelope::body).
    pub sig: Signature,
    /// The [`OutboxEntry`]'s canonical dCBOR — the exact bytes that were signed.
    pub body: Vec<u8>,
}

impl EntryEnvelope {
    /// Frames a signed outbox entry for carriage, capturing its canonical body
    /// bytes, signer, and signature verbatim.
    pub fn from_signed(signed: &SignedPayload<OutboxEntry>) -> Self {
        Self {
            signer: signed.signer,
            sig: signed.signature,
            body: to_canonical_bytes(signed.payload.clone()),
        }
    }

    /// Reconstructs the signed outbox entry from its framing, decoding the
    /// `body` bytes back into an [`OutboxEntry`].
    ///
    /// This does **not** verify the signature — that is
    /// [`crate::outbox::validate`]'s job at ingest. It only rebuilds the typed
    /// envelope, failing if `body` is not a canonical outbox entry.
    pub fn to_signed(&self) -> Result<SignedPayload<OutboxEntry>> {
        let payload: OutboxEntry = from_canonical_bytes(&self.body)?;
        Ok(SignedPayload {
            payload,
            signer: self.signer,
            signature: self.sig,
        })
    }
}

impl From<EntryEnvelope> for CBOR {
    fn from(e: EntryEnvelope) -> Self {
        let mut m = Map::new();
        m.insert("signer", CBOR::to_byte_string(e.signer.to_bytes()));
        m.insert("sig", CBOR::to_byte_string(e.sig.to_bytes()));
        m.insert("body", CBOR::to_byte_string(e.body));
        m.into()
    }
}

impl TryFrom<CBOR> for EntryEnvelope {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let signer_bytes: [u8; 32] = map
            .extract::<&str, CBOR>("signer")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        let sig_bytes: [u8; 64] = map
            .extract::<&str, CBOR>("sig")?
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(EntryEnvelope {
            signer: PublicKey::from_bytes(signer_bytes).map_err(|_| dcbor::Error::WrongType)?,
            sig: Signature::from_bytes(sig_bytes).map_err(|_| dcbor::Error::WrongType)?,
            body: map
                .extract::<&str, CBOR>("body")?
                .try_into_byte_string()?
                .as_slice()
                .to_vec(),
        })
    }
}

/// An unsigned carriage envelope: a versioned run of signed outbox entries.
///
/// `assembled_at` is testimony (ADR-0022 §3) — display and evidence only, never
/// arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// The signed outbox entries carried, in carriage order.
    pub entries: Vec<EntryEnvelope>,
    /// Testimony timestamp: when the assembling device says it built the bundle.
    pub assembled_at: i64,
}

impl Bundle {
    /// Assembles a bundle from a set of signed outbox entries.
    pub fn new(entries: Vec<EntryEnvelope>, assembled_at: i64) -> Self {
        Self {
            entries,
            assembled_at,
        }
    }

    /// Encodes the bundle to canonical dCBOR bytes for carriage.
    pub fn encode(&self) -> Vec<u8> {
        to_canonical_bytes(self.clone())
    }

    /// Blake3 of the bundle's encoded bytes — a carriage identifier (see the
    /// module docs; not stable under re-bundling).
    pub fn bundle_id(&self) -> Hash {
        Hash::of(&self.encode())
    }

    /// Decodes and structurally validates a bundle from its encoded bytes.
    ///
    /// Refuses, in order: an input over [`MAX_BUNDLE_BYTES`]; non-canonical or
    /// mis-shaped CBOR; a wrong `v`; more than [`MAX_BUNDLE_ENTRIES`] entries; a
    /// garbage (non-decodable) entry; and a bundle whose *same-author* entries
    /// are out of position order. A gap in one author's positions is **legal**
    /// (partial carriage) — only disorder (a repeated or decreasing position for
    /// one author) is refused. Signatures are **not** checked here; that is
    /// ingest's job (T2.2.3).
    ///
    /// This hand-parses rather than going through a blanket `TryFrom<CBOR>` so
    /// the count cap is enforced *before* the per-entry envelopes are decoded:
    /// the byte cap bounds the parsed CBOR tree, and the entry cap then bounds
    /// the envelope-decoding work — not just the final `Vec`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(Error::BundleTooLarge {
                found: bytes.len(),
                max: MAX_BUNDLE_BYTES,
            });
        }
        // `try_from_data` validates canonical form (rejects non-canonical CBOR);
        // the resulting tree is bounded by the byte cap checked above.
        let cbor = CBOR::try_from_data(bytes).map_err(|e| Error::Cbor(e.to_string()))?;
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(Error::Cbor("bundle is not a CBOR map".into())),
        };
        if map
            .extract::<&str, u64>("v")
            .map_err(|e| Error::Cbor(e.to_string()))?
            != BUNDLE_VERSION
        {
            return Err(Error::Cbor("unsupported bundle version".into()));
        }
        let raw_entries = match map
            .extract::<&str, CBOR>("entries")
            .map_err(|e| Error::Cbor(e.to_string()))?
            .into_case()
        {
            CBORCase::Array(items) => items,
            _ => return Err(Error::Cbor("bundle entries is not an array".into())),
        };
        // Count cap first, so a bundle stuffed with tens of thousands of tiny
        // envelopes is refused before any of them is decoded.
        if raw_entries.len() > MAX_BUNDLE_ENTRIES {
            return Err(Error::TooManyEntries {
                found: raw_entries.len(),
                max: MAX_BUNDLE_ENTRIES,
            });
        }
        let mut entries = Vec::with_capacity(raw_entries.len());
        for item in raw_entries {
            // Each element is a byte string wrapping the envelope's canonical
            // bytes; decode the blob, then the envelope. A garbage element fails
            // here.
            let env_bytes = item
                .try_into_byte_string()
                .map_err(|e| Error::Cbor(e.to_string()))?;
            let env: EntryEnvelope = from_canonical_bytes(env_bytes.as_slice())?;
            entries.push(env);
        }
        let assembled_at = map
            .extract::<&str, i64>("assembled_at")
            .map_err(|e| Error::Cbor(e.to_string()))?;
        let bundle = Bundle {
            entries,
            assembled_at,
        };
        bundle.check_same_author_order()?;
        Ok(bundle)
    }

    /// Enforces that, for each author, the subsequence of that author's entries
    /// (in carriage order) has strictly increasing positions. Gaps are allowed;
    /// a repeated or decreasing position is [`Error::EntriesOutOfOrder`].
    fn check_same_author_order(&self) -> Result<()> {
        let mut last: HashMap<[u8; 32], u64> = HashMap::new();
        for env in &self.entries {
            // Decoding here rejects a garbage entry as well as reading the
            // author/position needed for the order check.
            let entry = env.to_signed()?;
            let author = entry.payload.author.public_key().to_bytes();
            let position = entry.payload.position;
            if let Some(prev) = last.insert(author, position) {
                if position <= prev {
                    return Err(Error::EntriesOutOfOrder);
                }
            }
        }
        Ok(())
    }
}

impl From<Bundle> for CBOR {
    fn from(b: Bundle) -> Self {
        let mut m = Map::new();
        m.insert("v", BUNDLE_VERSION);
        // Each entry rides as the canonical bytes of its `{signer, sig, body}`
        // envelope — an opaque carriage blob (see the module docs).
        let entries: Vec<CBOR> = b
            .entries
            .into_iter()
            .map(|e| CBOR::to_byte_string(to_canonical_bytes(e)))
            .collect();
        m.insert("entries", entries);
        m.insert("assembled_at", b.assembled_at);
        m.into()
    }
}

// A `Bundle` deliberately has **no** `TryFrom<CBOR>`: decoding goes through
// [`Bundle::decode`], which enforces the size/count caps and same-author order.
// A blanket `TryFrom<CBOR>` would be a decode path that silently skips those
// structural checks. Encoding is [`From<Bundle> for CBOR`] above.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::SignedOutboxEntry;
    use crate::zero_hash;
    use rrn_crypto::keypair::Keypair;
    use rrn_identity::address::Address;

    #[derive(Clone, Debug, PartialEq)]
    struct Record {
        n: u64,
    }
    impl From<Record> for CBOR {
        fn from(r: Record) -> Self {
            let mut m = Map::new();
            m.insert("kind", "rrn.test.record");
            m.insert("n", r.n);
            m.into()
        }
    }

    fn signed_record(n: u64) -> SignedPayload<Record> {
        SignedPayload::sign(Record { n }, &Keypair::generate())
    }

    /// One signed outbox entry at `position` for `device`, chained on `prev`.
    fn entry(device: &Keypair, position: u64, prev: Hash) -> SignedOutboxEntry {
        let author = Address::from_public_key(device.public_key());
        let e = OutboxEntry::wrapping(
            author,
            position,
            prev,
            &signed_record(position),
            1_700_000_000,
        );
        SignedPayload::sign(e, device)
    }

    /// A correctly linked chain of `len` entries for one device.
    fn chain(device: &Keypair, len: u64) -> Vec<SignedOutboxEntry> {
        let mut out = Vec::new();
        let mut prev = zero_hash();
        for pos in 0..len {
            let e = entry(device, pos, prev);
            prev = e.payload.entry_hash();
            out.push(e);
        }
        out
    }

    fn envelopes(entries: &[SignedOutboxEntry]) -> Vec<EntryEnvelope> {
        entries.iter().map(EntryEnvelope::from_signed).collect()
    }

    #[test]
    fn canonical_roundtrip_and_reconstruction() {
        let device = Keypair::generate();
        let entries = chain(&device, 3);
        let bundle = Bundle::new(envelopes(&entries), 1_700_000_500);
        let decoded = Bundle::decode(&bundle.encode()).unwrap();
        assert_eq!(decoded, bundle);
        // Each carried envelope reconstructs the original signed entry.
        for (env, original) in decoded.entries.iter().zip(&entries) {
            let back = env.to_signed().unwrap();
            assert_eq!(&back, original);
        }
    }

    #[test]
    fn bundle_id_changes_under_rebundling() {
        let device = Keypair::generate();
        let entries = chain(&device, 2);
        let one = Bundle::new(envelopes(&entries), 10);
        let two = Bundle::new(envelopes(&entries), 20); // same records, different assembly
        assert_ne!(one.bundle_id(), two.bundle_id());
    }

    #[test]
    fn multiple_authors_may_share_a_bundle() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let mut envs = envelopes(&chain(&a, 2));
        envs.extend(envelopes(&chain(&b, 2)));
        let bundle = Bundle::new(envs, 1);
        assert!(Bundle::decode(&bundle.encode()).is_ok());
    }

    #[test]
    fn a_gap_in_one_authors_positions_is_legal() {
        let device = Keypair::generate();
        let full = chain(&device, 4);
        // Carry positions 0 and 2 only (1 and 3 dropped): a legal partial
        // carriage — increasing, just gapped.
        let envs = vec![
            EntryEnvelope::from_signed(&full[0]),
            EntryEnvelope::from_signed(&full[2]),
        ];
        let bundle = Bundle::new(envs, 1);
        assert!(Bundle::decode(&bundle.encode()).is_ok());
    }

    #[test]
    fn same_author_disorder_is_refused() {
        let device = Keypair::generate();
        let full = chain(&device, 3);
        // Positions 2 then 1 for one author: disorder.
        let envs = vec![
            EntryEnvelope::from_signed(&full[2]),
            EntryEnvelope::from_signed(&full[1]),
        ];
        let bundle = Bundle::new(envs, 1);
        assert_eq!(
            Bundle::decode(&bundle.encode()),
            Err(Error::EntriesOutOfOrder)
        );
    }

    #[test]
    fn a_repeated_position_for_one_author_is_refused() {
        let device = Keypair::generate();
        // Two distinct entries at position 0 (an outbox fork) carried together:
        // not strictly increasing, so refused as disorder.
        let a = entry(&device, 0, zero_hash());
        let b = SignedPayload::sign(
            OutboxEntry::wrapping(
                Address::from_public_key(device.public_key()),
                0,
                zero_hash(),
                &signed_record(99),
                1,
            ),
            &device,
        );
        let bundle = Bundle::new(
            vec![
                EntryEnvelope::from_signed(&a),
                EntryEnvelope::from_signed(&b),
            ],
            1,
        );
        assert_eq!(
            Bundle::decode(&bundle.encode()),
            Err(Error::EntriesOutOfOrder)
        );
    }

    #[test]
    fn oversize_entry_count_is_refused() {
        // Build a bundle whose entry list exceeds the cap by reusing one
        // author's single entry many times would trip the order check first, so
        // use distinct authors (each at position 0) — order check passes,
        // count check fires.
        let mut envs = Vec::new();
        for _ in 0..(MAX_BUNDLE_ENTRIES + 1) {
            let device = Keypair::generate();
            envs.push(EntryEnvelope::from_signed(&entry(&device, 0, zero_hash())));
        }
        let bundle = Bundle::new(envs, 1);
        assert_eq!(
            Bundle::decode(&bundle.encode()),
            Err(Error::TooManyEntries {
                found: MAX_BUNDLE_ENTRIES + 1,
                max: MAX_BUNDLE_ENTRIES,
            })
        );
    }

    #[test]
    fn oversize_bytes_are_refused_before_decoding() {
        let too_big = vec![0u8; MAX_BUNDLE_BYTES + 1];
        assert_eq!(
            Bundle::decode(&too_big),
            Err(Error::BundleTooLarge {
                found: MAX_BUNDLE_BYTES + 1,
                max: MAX_BUNDLE_BYTES,
            })
        );
    }

    #[test]
    fn a_garbage_entry_is_refused() {
        let device = Keypair::generate();
        let good = EntryEnvelope::from_signed(&entry(&device, 0, zero_hash()));
        // An envelope whose body is not a canonical outbox entry.
        let garbage = EntryEnvelope {
            signer: device.public_key(),
            sig: device.sign(b"x"),
            body: vec![0xff, 0x00, 0x13],
        };
        let bundle = Bundle::new(vec![good, garbage], 1);
        // The order check decodes each entry and rejects the undecodable one.
        assert!(matches!(
            Bundle::decode(&bundle.encode()),
            Err(Error::Cbor(_))
        ));
    }
}
