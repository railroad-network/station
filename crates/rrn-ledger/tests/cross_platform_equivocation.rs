//! Cross-platform equivocation wire fixtures (T2.3.3, ADR-0021 §5).
//!
//! One byte-stable vector per new signed record kind: a station-signed
//! [`EquivocationRecord`] on each basis (cert-overspend and outbox-fork) and a
//! station-signed [`EquivocationVerdictRecord`] (overturn). The mobile repo
//! verifies it produces **byte-identical** canonical dCBOR and signatures
//! (ADR-0002) — including the embedded member-signed evidence envelopes, which
//! travel in full (signer/sig/body triples) rather than by hash.
//!
//! Follows the repo's `cross_platform_*.json` regenerate-and-committed-in-sync
//! convention. Regenerate, then copy the JSON into the mobile repo:
//!
//! ```sh
//! RRN_REGEN=1 cargo test -p rrn-ledger --test cross_platform_equivocation
//! ```

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::escrow::{
    CertId, EquivocationBasis, EquivocationRecord, EquivocationVerdictRecord, EvidenceItem,
    VerdictDecision,
};
use rrn_ledger::transaction::TransactionProposal;
use rrn_protocol::outbox::OutboxEntry;
use serde::{Deserialize, Serialize};

fn keypair(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(Hash::of(label.as_bytes()).to_bytes()))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EvidenceItemVector {
    signer: String,
    sig: String,
    /// Canonical bytes of the embedded member-signed artifact.
    body: String,
}

impl EvidenceItemVector {
    fn of(item: &EvidenceItem) -> Self {
        Self {
            signer: hex::encode(item.signer.to_bytes()),
            sig: hex::encode(item.signature.to_bytes()),
            body: hex::encode(&item.bytes),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EquivocationVector {
    station_pubkey: String,
    member_pubkey: String,
    basis: String,
    /// Present only for the cert-overspend basis (omit-when-`None` in the CBOR).
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_id: Option<String>,
    recorded_at: String,
    evidence: Vec<EvidenceItemVector>,
    /// Canonical dCBOR of the `EquivocationRecord` body (== `From<..> for CBOR`).
    canonical_hex: String,
    /// The station's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
    /// Content address (Blake3 of the canonical bytes), hex.
    equivocation_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct VerdictVector {
    station_pubkey: String,
    equivocation_id: String,
    decision: String,
    decided_at: String,
    canonical_hex: String,
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    cert_overspend: EquivocationVector,
    outbox_fork: EquivocationVector,
    verdict: VerdictVector,
}

const CAP_CENTI: i64 = 500;
const RECORDED_AT: i64 = 1_700_100_000;
const DECIDED_AT: i64 = 1_700_200_000;

/// A member-signed cert-backed spend, as an evidence item.
fn cert_spend(member: &Keypair, receiver: &Address, amount: i64, nonce: u64) -> EvidenceItem {
    let member_addr = Address::from_public_key(member.public_key());
    let p = TransactionProposal::new(member_addr, *receiver, amount, None, nonce, 1, i64::MAX / 2)
        .with_certificate(CertId(Hash::of(b"rrn-equiv-fixture:v1:cert")));
    EvidenceItem::from_signed(&SignedPayload::sign(p, member))
}

/// A member-authored outbox entry at `position` wrapping a plain spend.
fn fork_entry(member: &Keypair, receiver: &Address, amount: i64, position: u64) -> EvidenceItem {
    let member_addr = Address::from_public_key(member.public_key());
    let inner = SignedPayload::sign(
        TransactionProposal::new(member_addr, *receiver, amount, None, 0, 1, i64::MAX / 2),
        member,
    );
    let entry = OutboxEntry::wrapping(
        member_addr,
        position,
        Hash::from_bytes([0u8; 32]),
        &inner,
        position as i64,
    );
    EvidenceItem::from_signed(&SignedPayload::sign(entry, member))
}

fn build_fixture() -> Fixture {
    let member = keypair("rrn-equiv-fixture:v1:member:");
    let station = keypair("rrn-equiv-fixture:v1:station:");
    let receiver = Address::from_public_key(keypair("rrn-equiv-fixture:v1:receiver:").public_key());
    let member_addr = Address::from_public_key(member.public_key());
    let cert = CertId(Hash::of(b"rrn-equiv-fixture:v1:cert"));

    // Cert-overspend: 300 + 300 = 600 > cap 500.
    let overspend_evidence = vec![
        cert_spend(&member, &receiver, 300, 1),
        cert_spend(&member, &receiver, 300, 2),
    ];
    let overspend = EquivocationRecord::new(
        member_addr,
        EquivocationBasis::CertOverspend,
        Some(cert),
        overspend_evidence.clone(),
        RECORDED_AT,
    );
    assert!(
        overspend.verify_evidence(Some(CAP_CENTI)),
        "overspend proof"
    );
    let overspend_id = overspend.equivocation_id;
    let signed_overspend = SignedPayload::sign(overspend.clone(), &station);
    assert!(signed_overspend.verify().is_ok());

    // Outbox-fork: two entries at position 0, different content.
    let fork_evidence = vec![
        fork_entry(&member, &receiver, 100, 0),
        fork_entry(&member, &receiver, 200, 0),
    ];
    let fork = EquivocationRecord::new(
        member_addr,
        EquivocationBasis::OutboxFork,
        None,
        fork_evidence.clone(),
        RECORDED_AT,
    );
    assert!(fork.verify_evidence(None), "fork proof");
    let fork_id = fork.equivocation_id;
    let signed_fork = SignedPayload::sign(fork.clone(), &station);
    assert!(signed_fork.verify().is_ok());

    // An overturn verdict on the cert-overspend record.
    let verdict = EquivocationVerdictRecord {
        equivocation_id: overspend_id,
        decision: VerdictDecision::Overturn,
        decided_at: DECIDED_AT,
    };
    let signed_verdict = SignedPayload::sign(verdict, &station);
    assert!(signed_verdict.verify().is_ok());

    Fixture {
        comment: "Cross-platform equivocation wire fixtures for T2.3.3 (ADR-0021 §5). A \
            station-signed EquivocationRecord on each basis (cert-overspend, with a cert_id; \
            outbox-fork, without) and a station-signed EquivocationVerdictRecord (overturn). \
            Evidence items carry each member-signed artifact in full as a signer/sig/body triple. \
            canonical_hex is each record's canonical dCBOR (== From<T> for CBOR); signature_hex is \
            the station's Ed25519 signature over it; equivocation_id is the Blake3 content address \
            (omitted from the CBOR, recomputed on decode). Deterministic (blake3-derived seeds, \
            RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        cert_overspend: EquivocationVector {
            station_pubkey: hex::encode(station.public_key().to_bytes()),
            member_pubkey: hex::encode(member.public_key().to_bytes()),
            basis: EquivocationBasis::CertOverspend.as_str().to_string(),
            cert_id: Some(cert.0.to_hex()),
            recorded_at: RECORDED_AT.to_string(),
            evidence: overspend_evidence
                .iter()
                .map(EvidenceItemVector::of)
                .collect(),
            canonical_hex: hex::encode(to_canonical_bytes(overspend)),
            signature_hex: hex::encode(signed_overspend.signature.to_bytes()),
            equivocation_id: overspend_id.0.to_hex(),
        },
        outbox_fork: EquivocationVector {
            station_pubkey: hex::encode(station.public_key().to_bytes()),
            member_pubkey: hex::encode(member.public_key().to_bytes()),
            basis: EquivocationBasis::OutboxFork.as_str().to_string(),
            cert_id: None,
            recorded_at: RECORDED_AT.to_string(),
            evidence: fork_evidence.iter().map(EvidenceItemVector::of).collect(),
            canonical_hex: hex::encode(to_canonical_bytes(fork)),
            signature_hex: hex::encode(signed_fork.signature.to_bytes()),
            equivocation_id: fork_id.0.to_hex(),
        },
        verdict: VerdictVector {
            station_pubkey: hex::encode(station.public_key().to_bytes()),
            equivocation_id: overspend_id.0.to_hex(),
            decision: VerdictDecision::Overturn.as_str().to_string(),
            decided_at: DECIDED_AT.to_string(),
            canonical_hex: hex::encode(to_canonical_bytes(verdict)),
            signature_hex: hex::encode(signed_verdict.signature.to_bytes()),
        },
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cross_platform_equivocation.json")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-ledger \
         --test cross_platform_equivocation, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The byte-identity guard: committed canonical bytes decode back to records
/// whose evidence still verifies and whose content ids recompute, and the
/// recorded station signatures reproduce.
#[test]
fn committed_bytes_match_the_typed_encoders() {
    use rrn_crypto::serialize::from_canonical_bytes;

    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    let fx: Fixture = serde_json::from_str(&text).expect("committed fixture is not valid JSON");

    assert_eq!(serialize(&build_fixture()), text);

    // Cert-overspend record decodes, carries its cert_id, verifies against the cap.
    let bytes = hex::decode(&fx.cert_overspend.canonical_hex).unwrap();
    assert!(
        bytes.windows(b"cert_id".len()).any(|w| w == b"cert_id"),
        "cert-overspend record must carry the cert_id key"
    );
    let rec: EquivocationRecord = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(
        rec.equivocation_id.0.to_hex(),
        fx.cert_overspend.equivocation_id
    );
    assert_eq!(rec.basis, EquivocationBasis::CertOverspend);
    assert!(rec.verify_evidence(Some(CAP_CENTI)));

    // Fork record decodes, carries no cert_id, verifies with no cap.
    let bytes = hex::decode(&fx.outbox_fork.canonical_hex).unwrap();
    assert!(
        !bytes.windows(b"cert_id".len()).any(|w| w == b"cert_id"),
        "fork record must omit the cert_id key"
    );
    let rec: EquivocationRecord = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(
        rec.equivocation_id.0.to_hex(),
        fx.outbox_fork.equivocation_id
    );
    assert_eq!(rec.basis, EquivocationBasis::OutboxFork);
    assert!(rec.verify_evidence(None));

    // Verdict decodes and names the cert-overspend record.
    let bytes = hex::decode(&fx.verdict.canonical_hex).unwrap();
    let verdict: EquivocationVerdictRecord = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(verdict.decision, VerdictDecision::Overturn);
    assert_eq!(
        verdict.equivocation_id.0.to_hex(),
        fx.cert_overspend.equivocation_id
    );
}
