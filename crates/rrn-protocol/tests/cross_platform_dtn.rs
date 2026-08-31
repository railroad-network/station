//! Cross-platform DTN wire fixtures (T2.2.1).
//!
//! One fully-populated, byte-stable vector for each of the three wire records —
//! an outbox entry, a carriage bundle, and a station delivery receipt — so the
//! mobile repo can verify it produces **byte-identical** canonical dCBOR and
//! signatures (ADR-0002/ADR-0020). Deterministic (blake3-derived seeds + RFC
//! 8032 Ed25519), reproducible bit-for-bit.
//!
//! This mirrors the repo's established `cross_platform_*.json` fixture
//! convention (regen + committed-in-sync check) rather than the ticket's loose
//! `.hex`-file sketch, so the mobile side reads one JSON the same way it reads
//! the ledger's `cross_platform_signed_payload.json`. Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-protocol --test cross_platform_dtn
//! then copy `tests/fixtures/cross_platform_dtn.json` into the mobile repo.

use std::path::PathBuf;

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{self, OutboxEntry};
use rrn_protocol::receipt::{DeliveryReceipt, Disposition, Outcome, RefusalReason, SignedReceipt};
use serde::{Deserialize, Serialize};

/// A stand-in application record (a proposal/vote/… would go here in reality),
/// so the fixture is self-contained. The mobile side builds the identical map.
#[derive(Clone, Debug)]
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

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair(label: &str, i: u32) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(derive(label, i)))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OutboxVector {
    device_seed: String,
    author_pubkey: String,
    position: String,
    prev_hash: String,
    record_n: String,
    authored_at: String,
    /// Canonical dCBOR of the `OutboxEntry` body (== `From<OutboxEntry> for CBOR`).
    canonical_hex: String,
    /// The device's Ed25519 signature over `canonical_hex`.
    entry_signature_hex: String,
    entry_hash: String,
    record_hash: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct BundleVector {
    assembled_at: String,
    /// Each entry as the canonical bytes of its `{signer, sig, body}` envelope.
    entry_envelopes_hex: Vec<String>,
    /// Canonical dCBOR of the whole bundle.
    canonical_hex: String,
    bundle_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiptVector {
    station_seed: String,
    station_pubkey: String,
    received_at: String,
    /// Canonical dCBOR of the `DeliveryReceipt` body (== `From<..> for CBOR`).
    canonical_hex: String,
    /// The station's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    outbox_entry: OutboxVector,
    bundle: BundleVector,
    receipt: ReceiptVector,
}

/// A signed outbox entry for `device` at `position`, wrapping a demo record the
/// same device authored (author == record signer == outer signer).
fn signed_entry(device: &Keypair, position: u64, prev: Hash, n: u64) -> SignedPayload<OutboxEntry> {
    let record = SignedPayload::sign(DemoRecord { n }, device);
    let entry = OutboxEntry::wrapping(
        Address::from_public_key(device.public_key()),
        position,
        prev,
        &record,
        1_700_000_000 + position as i64,
    );
    SignedPayload::sign(entry, device)
}

fn build_outbox_vector() -> (OutboxVector, SignedPayload<OutboxEntry>) {
    let device = keypair("rrn-dtn-fixture:v1:outbox-device:", 0);
    // A mid-chain entry (position 3, real prev_hash) so every field is populated.
    let prev = Hash::of(b"rrn-dtn-fixture:v1:outbox:prev");
    let signed = signed_entry(&device, 3, prev, 42);
    // Sanity: the fixture entry validates end to end.
    assert!(outbox::validate(&signed).is_ok());

    let canonical = to_canonical_bytes(signed.payload.clone());
    let v = OutboxVector {
        device_seed: hex::encode(device.secret_key().to_bytes()),
        author_pubkey: hex::encode(device.public_key().to_bytes()),
        position: "3".to_string(),
        prev_hash: prev.to_hex(),
        record_n: "42".to_string(),
        authored_at: (1_700_000_000_i64 + 3).to_string(),
        canonical_hex: hex::encode(&canonical),
        entry_signature_hex: hex::encode(signed.signature.to_bytes()),
        entry_hash: signed.payload.entry_hash().to_hex(),
        record_hash: signed.payload.record_hash().to_hex(),
    };
    (v, signed)
}

fn build_bundle_vector() -> BundleVector {
    // Two authors, correctly ordered, sharing one bundle.
    let a = keypair("rrn-dtn-fixture:v1:bundle-a:", 0);
    let b = keypair("rrn-dtn-fixture:v1:bundle-b:", 0);
    let a0 = signed_entry(&a, 0, Hash::from_bytes([0u8; 32]), 1);
    let a1 = signed_entry(&a, 1, a0.payload.entry_hash(), 2);
    let b0 = signed_entry(&b, 0, Hash::from_bytes([0u8; 32]), 3);
    let envelopes: Vec<EntryEnvelope> = [&a0, &a1, &b0]
        .into_iter()
        .map(EntryEnvelope::from_signed)
        .collect();
    let bundle = Bundle::new(envelopes.clone(), 1_700_000_900);
    // Sanity: the fixture bundle decodes and its structural checks pass.
    assert!(Bundle::decode(&bundle.encode()).is_ok());

    BundleVector {
        assembled_at: "1700000900".to_string(),
        entry_envelopes_hex: envelopes
            .into_iter()
            .map(|e| hex::encode(to_canonical_bytes(e)))
            .collect(),
        canonical_hex: hex::encode(bundle.encode()),
        bundle_id: bundle.bundle_id().to_hex(),
    }
}

fn build_receipt() -> DeliveryReceipt {
    let station = keypair("rrn-dtn-fixture:v1:station:", 0);
    DeliveryReceipt {
        station: Address::from_public_key(station.public_key()),
        outcomes: vec![
            Outcome {
                record_hash: Hash::of(b"rrn-dtn-fixture:v1:admitted"),
                disposition: Disposition::Admitted { seq: 128 },
            },
            Outcome {
                record_hash: Hash::of(b"rrn-dtn-fixture:v1:known"),
                disposition: Disposition::Known { seq: 64 },
            },
            Outcome {
                record_hash: Hash::of(b"rrn-dtn-fixture:v1:refused"),
                disposition: Disposition::Refused {
                    reason: RefusalReason::DebtFloor,
                },
            },
        ],
        received_at: 1_700_001_000,
    }
}

fn build_receipt_vector() -> ReceiptVector {
    let station = keypair("rrn-dtn-fixture:v1:station:", 0);
    let receipt = build_receipt();
    let canonical = to_canonical_bytes(receipt.clone());
    let signed = SignedReceipt::sign(receipt, &station);
    assert!(signed.verify().is_ok());
    ReceiptVector {
        station_seed: hex::encode(station.secret_key().to_bytes()),
        station_pubkey: hex::encode(station.public_key().to_bytes()),
        received_at: "1700001000".to_string(),
        canonical_hex: hex::encode(&canonical),
        signature_hex: hex::encode(signed.signature.to_bytes()),
    }
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform DTN wire fixtures for T2.2.1 (ADR-0020). One fully-populated \
            vector per record: outbox entry, carriage bundle, station delivery receipt. \
            `canonical_hex` is each record's canonical dCBOR (== From<T> for CBOR); signed \
            records also record the Ed25519 signature over those bytes. Deterministic \
            (blake3-derived seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        outbox_entry: build_outbox_vector().0,
        bundle: build_bundle_vector(),
        receipt: build_receipt_vector(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_dtn.json")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn load_committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    serde_json::from_str(&text).expect("committed fixture is not valid JSON")
}

#[test]
fn committed_fixture_is_in_sync() {
    let generated = serialize(&build_fixture());
    if std::env::var("RRN_REGEN").is_ok() {
        std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
        std::fs::write(fixture_path(), &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(fixture_path()).unwrap_or_default();
    assert_eq!(
        committed, generated,
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-protocol \
         --test cross_platform_dtn, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The byte-identity guard: the committed canonical hex must equal what the
/// typed encoders produce today, and the recorded signatures must reproduce and
/// verify. Any change to an encoding or a field order fails this test.
#[test]
fn committed_bytes_match_the_typed_encoders() {
    let fx = load_committed();

    // Outbox entry: rebuild from recorded inputs, re-encode, re-sign.
    let device = Keypair::from_secret(SecretKey::from_bytes(
        hex::decode(&fx.outbox_entry.device_seed)
            .unwrap()
            .try_into()
            .unwrap(),
    ));
    let prev = Hash::from_hex(&fx.outbox_entry.prev_hash).unwrap();
    let signed = signed_entry(
        &device,
        fx.outbox_entry.position.parse().unwrap(),
        prev,
        fx.outbox_entry.record_n.parse().unwrap(),
    );
    assert_eq!(
        hex::encode(to_canonical_bytes(signed.payload.clone())),
        fx.outbox_entry.canonical_hex
    );
    assert_eq!(
        hex::encode(signed.signature.to_bytes()),
        fx.outbox_entry.entry_signature_hex
    );
    assert_eq!(
        signed.payload.entry_hash().to_hex(),
        fx.outbox_entry.entry_hash
    );
    assert_eq!(
        signed.payload.record_hash().to_hex(),
        fx.outbox_entry.record_hash
    );
    assert!(outbox::validate(&signed).is_ok());

    // Bundle: rebuild and compare the whole encoded blob and each envelope.
    let rebuilt_bundle = build_bundle_vector();
    assert_eq!(rebuilt_bundle, fx.bundle);
    // The committed bundle bytes decode and pass the structural checks.
    let bytes = hex::decode(&fx.bundle.canonical_hex).unwrap();
    assert!(Bundle::decode(&bytes).is_ok());

    // Receipt: rebuild, re-encode, re-sign, verify.
    let station = Keypair::from_secret(SecretKey::from_bytes(
        hex::decode(&fx.receipt.station_seed)
            .unwrap()
            .try_into()
            .unwrap(),
    ));
    let receipt = build_receipt();
    assert_eq!(
        hex::encode(to_canonical_bytes(receipt.clone())),
        fx.receipt.canonical_hex
    );
    let signed_receipt = SignedReceipt::sign(receipt, &station);
    assert_eq!(
        hex::encode(signed_receipt.signature.to_bytes()),
        fx.receipt.signature_hex
    );
    assert!(signed_receipt.verify().is_ok());
}
