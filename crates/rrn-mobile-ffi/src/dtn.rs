//! Delay-tolerant submission for the mobile client (T2.4.2, ADR-0020).
//!
//! Thin marshalling over `rrn-protocol` so the React Native app can build and
//! carry its own outbox chain, assemble and inspect bundles, and read the
//! station's delivery receipts — with no cryptographic logic of its own. Every
//! signed record crosses this boundary as the portable `{signer, sig, body}`
//! envelope ([`crate::envelope`]); an outbox entry envelope produced by
//! [`outbox_next_entry`] is exactly what [`bundle_assemble`] consumes and what a
//! later [`outbox_next_entry`] call takes as its `prev_entry`, so the chain
//! composes without the app ever parsing an entry itself.
//!
//! # What does not cross the boundary
//!
//! The signing secret stays in Rust: [`outbox_next_entry`] takes an opaque
//! [`Keypair`](crate::Keypair) handle, never raw secret bytes (ADR-0006). The
//! app owns durable storage of the chain — it persists the returned envelope
//! bytes (in the OS keychain / its own store) and feeds the last one back as
//! `prev_entry`; this crate keeps no state and opens no database (ADR-0007), so
//! the outbox is exposed as pure functions over caller-held bytes rather than a
//! second copy of T2.2.2's on-station `OutboxStore`.

use std::sync::Arc;

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{self, OutboxEntry};
use rrn_protocol::receipt;

use crate::envelope;
use crate::Keypair;

/// Error surfaced across the FFI boundary for the DTN operations.
///
/// Flat and coarse by design, like the other FFI error enums: the mobile UI does
/// not branch on the crate-local detail. Structural decode faults, signature
/// faults, and the bundle DoS bounds are surfaced as distinct variants so a
/// courier or sender UI can tell "this carriage is malformed" from "this record
/// is forged" from "this bundle is too big".
#[derive(Debug, thiserror::Error)]
pub enum DtnError {
    /// A `{signer, sig, body}` envelope, a wrapped record body, or a bundle was
    /// not well-formed canonical dCBOR of the expected shape.
    #[error("malformed envelope or record")]
    MalformedEnvelope,
    /// The signature over a carried record's bytes did not verify against its
    /// signer.
    #[error("carried record signature does not verify")]
    RecordSignatureInvalid,
    /// The `prev_entry` did not validate, or its author is not this signer — a
    /// new entry cannot chain onto it.
    #[error("outbox chain linkage is invalid")]
    InvalidChain,
    /// A bundle's encoded form exceeded the wire size cap.
    #[error("bundle is too large")]
    BundleTooLarge,
    /// A bundle carried more than the entry cap allows.
    #[error("bundle carries too many entries")]
    TooManyEntries,
    /// A bundle has same-author entries out of position order.
    #[error("bundle entries are out of order")]
    EntriesOutOfOrder,
    /// A receipt's station signature did not verify, or was not by the expected
    /// station key.
    #[error("station signature does not verify")]
    StationSignatureInvalid,
    /// A supplied public key was not 32 valid bytes.
    #[error("invalid public key")]
    InvalidKey,
}

impl From<rrn_protocol::Error> for DtnError {
    fn from(e: rrn_protocol::Error) -> Self {
        use rrn_protocol::Error::*;
        match e {
            TooManyEntries { .. } => DtnError::TooManyEntries,
            BundleTooLarge { .. } => DtnError::BundleTooLarge,
            EntriesOutOfOrder => DtnError::EntriesOutOfOrder,
            ChainBroken { .. } | PositionOutOfSequence { .. } | AuthorSignerMismatch => {
                DtnError::InvalidChain
            }
            BadOuterSignature | BadEmbeddedSignature => DtnError::RecordSignatureInvalid,
            Cbor(_) => DtnError::MalformedEnvelope,
        }
    }
}

/// Builds and signs the next entry in the author's outbox chain, wrapping one
/// already-signed application record.
///
/// `record_envelope` is that record as portable `{signer, sig, body}` envelope
/// bytes (e.g. from [`proposal_sign_with_certificate`](crate::proposal_sign_with_certificate),
/// or a plain record the app built with `canonical_bytes` + `Keypair::sign` and
/// framed). Its signer, signature, and body are carried **verbatim** — never
/// re-signed — so the carried signature stays valid exactly as its author
/// produced it (ADR-0020 §2). `prev_entry` is the envelope returned by the
/// previous call (the last entry the app persisted), or `null` for the first
/// entry: position and `prev_hash` are derived from it, giving position 0 and
/// the all-zero `prev_hash` when absent.
///
/// Returns the new entry as `{signer, sig, body}` envelope bytes — persist it,
/// feed it as the next `prev_entry`, and hand it to [`bundle_assemble`].
///
/// Errors if `record_envelope` is malformed or its embedded signature does not
/// verify ([`RecordSignatureInvalid`](DtnError::RecordSignatureInvalid)), or if
/// `prev_entry` is malformed, does not validate, or was authored by a different
/// key ([`InvalidChain`](DtnError::InvalidChain)).
pub fn outbox_next_entry(
    author: Arc<Keypair>,
    prev_entry: Option<Vec<u8>>,
    record_envelope: Vec<u8>,
    authored_at: i64,
) -> Result<Vec<u8>, DtnError> {
    let author_address = Address::from_public_key(author.core().public_key());

    // The wrapped record is copied verbatim; reject a malformed envelope or a
    // record whose embedded signature does not hold, so no invalid entry is ever
    // built (it would only fail again at the station's ingest).
    let record = envelope::decode(&record_envelope).ok_or(DtnError::MalformedEnvelope)?;
    record
        .signer
        .verify(&record.body, &record.signature)
        .map_err(|_| DtnError::RecordSignatureInvalid)?;

    let (position, prev_hash) = match prev_entry {
        Some(prev_bytes) => {
            // The previous entry rides as the same `{signer, sig, body}` envelope
            // this function returns; decode it, validate it fully, and confirm it
            // belongs to this author's chain before extending it.
            let prev_env: EntryEnvelope =
                from_canonical_bytes(&prev_bytes).map_err(|_| DtnError::MalformedEnvelope)?;
            let prev_signed = prev_env.to_signed().map_err(DtnError::from)?;
            outbox::validate(&prev_signed).map_err(DtnError::from)?;
            if prev_signed.payload.author != author_address {
                return Err(DtnError::InvalidChain);
            }
            // `checked_add` so a maxed-out position (only reachable with a prev
            // this author signed themselves) surfaces as an error rather than a
            // debug panic — an abort across the FFI boundary.
            let position = prev_signed
                .payload
                .position
                .checked_add(1)
                .ok_or(DtnError::InvalidChain)?;
            (position, prev_signed.payload.entry_hash())
        }
        None => (0, Hash::from_bytes([0u8; 32])),
    };

    let entry = OutboxEntry {
        author: author_address,
        position,
        prev_hash,
        record_signer: record.signer,
        record_sig: record.signature,
        record_bytes: record.body,
        authored_at,
    };
    let signed = SignedPayload::sign(entry, author.core());
    Ok(envelope::encode(
        &signed.signer,
        &signed.signature,
        to_canonical_bytes(signed.payload),
    ))
}

/// Assembles a carriage bundle from a set of signed outbox entry envelopes (each
/// the bytes [`outbox_next_entry`] returned), for a courier to move to the
/// station.
///
/// Returns the bundle as canonical dCBOR. The result is round-tripped through the
/// station's own [`Bundle::decode`], so a bundle this returns is one the station
/// will structurally accept: over-cap entry counts / size and same-author
/// disorder are refused here rather than at ingest. Signatures are **not** checked
/// (that is the station's job); a malformed entry envelope is refused.
pub fn bundle_assemble(
    entry_envelopes: Vec<Vec<u8>>,
    assembled_at: i64,
) -> Result<Vec<u8>, DtnError> {
    let mut entries = Vec::with_capacity(entry_envelopes.len());
    for bytes in &entry_envelopes {
        let env: EntryEnvelope =
            from_canonical_bytes(bytes).map_err(|_| DtnError::MalformedEnvelope)?;
        entries.push(env);
    }
    let encoded = Bundle::new(entries, assembled_at).encode();
    // Enforce the same structural bounds the station will (caps + same-author
    // order), so `bundle_assemble` never emits a bundle ingest would reject.
    Bundle::decode(&encoded)?;
    Ok(encoded)
}

/// One entry's display data in a [`BundleInfo`], for a courier screen.
pub struct BundleEntryInfo {
    /// The chain owner's `rrn1…` address.
    pub author: String,
    /// The entry's 0-based chain position.
    pub position: u64,
    /// Blake3 of the carried record's canonical bytes, hex — the identifier the
    /// station admits under and a receipt keys on.
    pub record_hash: String,
    /// The wrapped record's `kind` discriminant (e.g. `rrn.tx.proposal`), or the
    /// empty string if the record is not a `kind`-tagged map.
    pub record_kind: String,
    /// Whether the entry fully validates (outer signature, embedded record
    /// signature, and author == outer signer). A courier is a dumb carrier and
    /// need not care, but a UI can flag a broken entry.
    pub valid: bool,
}

/// Display data for a parsed bundle, for a courier UI (T2.4.2). Carries no
/// secret and performs no admission — inspection only.
pub struct BundleInfo {
    /// Number of entries carried.
    pub entry_count: u32,
    /// The assembler's testimony timestamp (ADR-0022 §3) — display only.
    pub assembled_at: i64,
    /// Per-entry display data, in carriage order.
    pub entries: Vec<BundleEntryInfo>,
}

/// Decodes and structurally validates a bundle, returning per-entry display data
/// for a courier UI.
///
/// Applies the station's own [`Bundle::decode`] bounds (size, entry count,
/// same-author order); a bundle that fails them is refused with the matching
/// error. Each entry's `valid` flag reports whether its signatures check out, but
/// a failing signature does not fail the parse — a courier still displays a
/// bundle carrying a bad entry.
pub fn bundle_parse(bundle_bytes: Vec<u8>) -> Result<BundleInfo, DtnError> {
    let bundle = Bundle::decode(&bundle_bytes)?;
    let mut entries = Vec::with_capacity(bundle.entries.len());
    for env in &bundle.entries {
        let signed = env.to_signed().map_err(DtnError::from)?;
        let entry = &signed.payload;
        entries.push(BundleEntryInfo {
            author: entry.author.to_string(),
            position: entry.position,
            record_hash: entry.record_hash().to_hex(),
            record_kind: record_kind(&entry.record_bytes),
            valid: outbox::validate(&signed).is_ok(),
        });
    }
    Ok(BundleInfo {
        entry_count: entries.len() as u32,
        assembled_at: bundle.assembled_at,
        entries,
    })
}

/// The `kind` discriminant of a canonical record's CBOR map, or the empty string
/// if the bytes are not a map with a text `kind` key. Best-effort display data.
fn record_kind(record_bytes: &[u8]) -> String {
    let Ok(cbor) = CBOR::try_from_data(record_bytes) else {
        return String::new();
    };
    let CBORCase::Map(map) = cbor.into_case() else {
        return String::new();
    };
    map.extract::<&str, String>("kind").unwrap_or_default()
}

/// One record's fate in a parsed delivery receipt.
///
/// `seq` is present exactly for the `admitted`/`known` outcomes; `reason` (a
/// machine-stable refusal slug, e.g. `debt-floor`, `cert-overspent`) exactly for
/// `refused` — mirroring the wire record's tagged-union shape.
pub struct ReceiptOutcome {
    /// Blake3 of the presented record's canonical bytes, hex.
    pub record_hash: String,
    /// `admitted`, `known`, or `refused`.
    pub outcome: String,
    /// The admitting log sequence, for `admitted`/`known`; `None` for `refused`.
    pub seq: Option<u64>,
    /// The refusal reason slug, for `refused`; `None` otherwise.
    pub reason: Option<String>,
}

/// Parses a station delivery receipt, verifying the station signature, and
/// returns one typed outcome per presented record (T2.4.2, ADR-0020 §3).
///
/// `expected_station_pubkey` is the 32-byte Ed25519 key of the member's paired
/// station: the receipt must be signed by it and its `station` address must match
/// that key. A signature that does not verify, or one by any other key, is
/// refused ([`StationSignatureInvalid`](DtnError::StationSignatureInvalid)) — an
/// offline sender only trusts a receipt from the station it submitted to.
pub fn receipt_parse(
    receipt_bytes: Vec<u8>,
    expected_station_pubkey: Vec<u8>,
) -> Result<Vec<ReceiptOutcome>, DtnError> {
    let expected: [u8; 32] = expected_station_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| DtnError::InvalidKey)?;
    let expected_pk = PublicKey::from_bytes(expected).map_err(|_| DtnError::InvalidKey)?;

    let signed = receipt::decode_signed(&receipt_bytes).map_err(|_| DtnError::MalformedEnvelope)?;
    // The signer must be the expected station, its self-signature must verify,
    // and the `station` field it signed must name that same key — a receipt is
    // only meaningful from the station the sender actually submitted to.
    if signed.signer != expected_pk
        || signed.payload.station.public_key() != &signed.signer
        || signed.verify().is_err()
    {
        return Err(DtnError::StationSignatureInvalid);
    }

    Ok(signed
        .payload
        .outcomes
        .iter()
        .map(|o| {
            use rrn_protocol::receipt::Disposition;
            let (outcome, seq, reason) = match o.disposition {
                Disposition::Admitted { seq } => ("admitted", Some(seq), None),
                Disposition::Known { seq } => ("known", Some(seq), None),
                Disposition::Refused { reason } => {
                    ("refused", None, Some(reason.as_slug().to_string()))
                }
            };
            ReceiptOutcome {
                record_hash: o.record_hash.to_hex(),
                outcome: outcome.to_string(),
                seq,
                reason,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair as CoreKeypair;
    use rrn_identity::address::Address;
    use rrn_protocol::receipt::{
        DeliveryReceipt, Disposition, Outcome, RefusalReason, SignedReceipt,
    };

    /// A stand-in application record, canonical and `kind`-tagged.
    #[derive(Clone)]
    struct DemoRecord {
        n: u64,
    }
    impl From<DemoRecord> for CBOR {
        fn from(r: DemoRecord) -> Self {
            let mut m = Map::new();
            m.insert("kind", "rrn.test.record");
            m.insert("n", r.n);
            m.into()
        }
    }

    /// A `{signer, sig, body}` envelope for a demo record signed by `kp`.
    fn record_envelope(kp: &CoreKeypair, n: u64) -> Vec<u8> {
        let signed = SignedPayload::sign(DemoRecord { n }, kp);
        envelope::encode(
            &signed.signer,
            &signed.signature,
            to_canonical_bytes(signed.payload),
        )
    }

    fn ffi_keypair() -> Arc<Keypair> {
        Arc::new(Keypair::generate())
    }

    #[test]
    fn a_three_entry_chain_validates_and_bundles() {
        let author = ffi_keypair();
        let core = author.core().clone();

        let e0 = outbox_next_entry(author.clone(), None, record_envelope(&core, 0), 1_000).unwrap();
        let e1 = outbox_next_entry(
            author.clone(),
            Some(e0.clone()),
            record_envelope(&core, 1),
            1_001,
        )
        .unwrap();
        let e2 = outbox_next_entry(
            author.clone(),
            Some(e1.clone()),
            record_envelope(&core, 2),
            1_002,
        )
        .unwrap();

        // Each envelope reconstructs a valid signed entry, correctly positioned
        // and linked — i.e. `validate_chain` accepts the run.
        let chain: Vec<_> = [&e0, &e1, &e2]
            .iter()
            .map(|b| {
                from_canonical_bytes::<EntryEnvelope>(b)
                    .unwrap()
                    .to_signed()
                    .unwrap()
            })
            .collect();
        assert!(outbox::validate_chain(&chain).is_ok());
        assert_eq!(chain[2].payload.position, 2);

        // They assemble into a bundle the station accepts, whose parse reports
        // three entries with the demo record's kind.
        let bundle = bundle_assemble(vec![e0, e1, e2], 2_000).unwrap();
        let info = bundle_parse(bundle).unwrap();
        assert_eq!(info.entry_count, 3);
        assert_eq!(info.assembled_at, 2_000);
        assert!(info.entries.iter().all(|e| e.valid));
        assert!(info
            .entries
            .iter()
            .all(|e| e.record_kind == "rrn.test.record"));
        assert_eq!(info.entries[0].position, 0);
    }

    #[test]
    fn outbox_rejects_a_malformed_record_envelope() {
        let author = ffi_keypair();
        assert!(matches!(
            outbox_next_entry(author, None, vec![0xff, 0x00, 0x13], 1),
            Err(DtnError::MalformedEnvelope)
        ));
    }

    #[test]
    fn outbox_rejects_a_malformed_prev_entry() {
        let author = ffi_keypair();
        let core = author.core().clone();
        assert!(matches!(
            outbox_next_entry(
                author,
                Some(vec![0xff, 0x00, 0x13]),
                record_envelope(&core, 0),
                1,
            ),
            Err(DtnError::MalformedEnvelope)
        ));
    }

    #[test]
    fn bundle_assemble_rejects_a_malformed_entry_envelope() {
        assert!(matches!(
            bundle_assemble(vec![vec![0xff, 0x00, 0x13]], 1),
            Err(DtnError::MalformedEnvelope)
        ));
    }

    #[test]
    fn bundle_assemble_refuses_same_author_disorder() {
        // Two entries for one author assembled in decreasing position order — the
        // station's decode tripwire, enforced here so `bundle_assemble` never
        // emits a bundle ingest would reject.
        let author = ffi_keypair();
        let core = author.core().clone();
        let e0 = outbox_next_entry(author.clone(), None, record_envelope(&core, 0), 1).unwrap();
        let e1 = outbox_next_entry(author, Some(e0.clone()), record_envelope(&core, 1), 2).unwrap();
        // Present position 1 before position 0.
        assert!(matches!(
            bundle_assemble(vec![e1, e0], 3),
            Err(DtnError::EntriesOutOfOrder)
        ));
    }

    #[test]
    fn outbox_rejects_a_record_with_a_bad_embedded_signature() {
        let author = ffi_keypair();
        let core = author.core().clone();
        // A record envelope whose signature is over unrelated bytes.
        let signed = SignedPayload::sign(DemoRecord { n: 5 }, &core);
        let bad = envelope::encode(
            &signed.signer,
            &CoreKeypair::generate().sign(b"unrelated"),
            to_canonical_bytes(signed.payload),
        );
        assert!(matches!(
            outbox_next_entry(author, None, bad, 1),
            Err(DtnError::RecordSignatureInvalid)
        ));
    }

    #[test]
    fn outbox_rejects_a_prev_entry_from_a_different_author() {
        let a = ffi_keypair();
        let b = ffi_keypair();
        // A first entry authored by `b`.
        let b0 = outbox_next_entry(b.clone(), None, record_envelope(b.core(), 0), 1).unwrap();
        // `a` cannot chain onto `b`'s entry.
        assert!(matches!(
            outbox_next_entry(a, Some(b0), record_envelope(&CoreKeypair::generate(), 1), 2),
            Err(DtnError::InvalidChain)
        ));
    }

    #[test]
    fn receipt_parse_verifies_and_maps_outcomes() {
        let station = CoreKeypair::generate();
        let receipt = DeliveryReceipt {
            station: Address::from_public_key(station.public_key()),
            outcomes: vec![
                Outcome {
                    record_hash: Hash::of(b"a"),
                    disposition: Disposition::Admitted { seq: 42 },
                },
                Outcome {
                    record_hash: Hash::of(b"b"),
                    disposition: Disposition::Refused {
                        reason: RefusalReason::CertOverspent,
                    },
                },
            ],
            received_at: 9,
        };
        let signed = SignedReceipt::sign(receipt, &station);
        let bytes = receipt::encode_signed(&signed);

        let outcomes = receipt_parse(bytes, station.public_key().to_bytes().to_vec()).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].outcome, "admitted");
        assert_eq!(outcomes[0].seq, Some(42));
        assert_eq!(outcomes[0].reason, None);
        assert_eq!(outcomes[1].outcome, "refused");
        assert_eq!(outcomes[1].seq, None);
        assert_eq!(outcomes[1].reason.as_deref(), Some("cert-overspent"));
    }

    #[test]
    fn receipt_parse_refuses_a_receipt_from_another_station() {
        let station = CoreKeypair::generate();
        let receipt = DeliveryReceipt {
            station: Address::from_public_key(station.public_key()),
            outcomes: vec![],
            received_at: 1,
        };
        let signed = SignedReceipt::sign(receipt, &station);
        let bytes = receipt::encode_signed(&signed);
        // Verified against a different expected station key → refused.
        let other = CoreKeypair::generate();
        assert!(matches!(
            receipt_parse(bytes, other.public_key().to_bytes().to_vec()),
            Err(DtnError::StationSignatureInvalid)
        ));
    }

    #[test]
    fn receipt_parse_rejects_a_wrong_length_key() {
        assert!(matches!(
            receipt_parse(vec![], vec![0u8; 31]),
            Err(DtnError::InvalidKey)
        ));
    }
}
