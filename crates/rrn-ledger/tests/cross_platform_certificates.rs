//! Cross-platform headroom-certificate wire fixtures (T2.3.1, ADR-0021).
//!
//! One fully-populated, byte-stable vector for each of the three new signed
//! record kinds — a member's certificate request, the station's headroom
//! certificate, and a member's certificate return — so the mobile repo (T2.4.2)
//! can verify it produces **byte-identical** canonical dCBOR and signatures
//! (ADR-0002). Deterministic (blake3-derived seeds + RFC 8032 Ed25519),
//! reproducible bit-for-bit.
//!
//! This follows the repo's established `cross_platform_*.json` convention (a
//! regenerate-and-committed-in-sync check), the same one
//! `tests/cross_platform_signed_payload.rs` and `rrn-protocol`'s
//! `cross_platform_dtn.rs` use. Regenerate, then copy the JSON into the mobile
//! repo alongside the other cross-platform fixtures:
//!
//! ```sh
//! RRN_REGEN=1 cargo test -p rrn-ledger --test cross_platform_certificates
//! ```

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::escrow::{CertificateRequest, CertificateReturn, HeadroomCertificate};
use serde::{Deserialize, Serialize};

fn keypair(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(Hash::of(label.as_bytes()).to_bytes()))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RequestVector {
    member_seed: String,
    member_pubkey: String,
    cap_centi: String,
    nonce: String,
    requested_at: String,
    /// Canonical dCBOR of the `CertificateRequest` body (== `From<..> for CBOR`).
    canonical_hex: String,
    /// The member's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
    /// Content address (Blake3 of the canonical bytes), hex.
    request_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CertificateVector {
    station_seed: String,
    station_pubkey: String,
    member_pubkey: String,
    cap_centi: String,
    request_id: String,
    issued_at: String,
    expires_at: String,
    canonical_hex: String,
    signature_hex: String,
    cert_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReturnVector {
    member_pubkey: String,
    cert_id: String,
    returned_at: String,
    canonical_hex: String,
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    request: RequestVector,
    certificate: CertificateVector,
    certificate_return: ReturnVector,
}

const CAP_CENTI: i64 = 1_000;
const NONCE: u64 = 3;
const REQUESTED_AT: i64 = 1_700_000_000;
const ISSUED_AT: i64 = 1_700_000_100;
const VALIDITY: i64 = 604_800;
const RETURNED_AT: i64 = 1_700_050_000;

fn build_fixture() -> Fixture {
    let member = keypair("rrn-cert-fixture:v1:member:");
    let station = keypair("rrn-cert-fixture:v1:station:");
    let member_addr = Address::from_public_key(member.public_key());

    // Request.
    let request = CertificateRequest::new(member_addr, CAP_CENTI, NONCE, REQUESTED_AT);
    let request_id = request.request_id;
    let signed_request = SignedPayload::sign(request.clone(), &member);
    assert!(signed_request.verify().is_ok());

    // Certificate honoring it.
    let certificate = HeadroomCertificate::new(
        member_addr,
        CAP_CENTI,
        request_id,
        ISSUED_AT,
        ISSUED_AT + VALIDITY,
    );
    let cert_id = certificate.cert_id;
    let signed_cert = SignedPayload::sign(certificate.clone(), &station);
    assert!(signed_cert.verify().is_ok());

    // Return of it.
    let return_record = CertificateReturn {
        member: member_addr,
        cert_id,
        returned_at: RETURNED_AT,
    };
    let signed_return = SignedPayload::sign(return_record.clone(), &member);
    assert!(signed_return.verify().is_ok());

    Fixture {
        comment: "Cross-platform headroom-certificate wire fixtures for T2.3.1 (ADR-0021). One \
            fully-populated vector per signed record kind: member certificate request, station \
            headroom certificate, member certificate return. `canonical_hex` is each record's \
            canonical dCBOR (== From<T> for CBOR); `signature_hex` is the Ed25519 signature over \
            those bytes. request_id/cert_id are the Blake3 content addresses (omitted from the \
            CBOR, recomputed on decode). Deterministic (blake3-derived seeds, RFC 8032); \
            regenerate with RRN_REGEN=1."
            .to_string(),
        request: RequestVector {
            member_seed: hex::encode(member.secret_key().to_bytes()),
            member_pubkey: hex::encode(member.public_key().to_bytes()),
            cap_centi: CAP_CENTI.to_string(),
            nonce: NONCE.to_string(),
            requested_at: REQUESTED_AT.to_string(),
            canonical_hex: hex::encode(to_canonical_bytes(request)),
            signature_hex: hex::encode(signed_request.signature.to_bytes()),
            request_id: request_id.0.to_hex(),
        },
        certificate: CertificateVector {
            station_seed: hex::encode(station.secret_key().to_bytes()),
            station_pubkey: hex::encode(station.public_key().to_bytes()),
            member_pubkey: hex::encode(member.public_key().to_bytes()),
            cap_centi: CAP_CENTI.to_string(),
            request_id: request_id.0.to_hex(),
            issued_at: ISSUED_AT.to_string(),
            expires_at: (ISSUED_AT + VALIDITY).to_string(),
            canonical_hex: hex::encode(to_canonical_bytes(certificate)),
            signature_hex: hex::encode(signed_cert.signature.to_bytes()),
            cert_id: cert_id.0.to_hex(),
        },
        certificate_return: ReturnVector {
            member_pubkey: hex::encode(member.public_key().to_bytes()),
            cert_id: cert_id.0.to_hex(),
            returned_at: RETURNED_AT.to_string(),
            canonical_hex: hex::encode(to_canonical_bytes(return_record)),
            signature_hex: hex::encode(signed_return.signature.to_bytes()),
        },
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cross_platform_certificates.json")
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
         --test cross_platform_certificates, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The byte-identity guard: the committed canonical hex must equal what the typed
/// encoders produce today, the recorded signatures must reproduce and verify, and
/// the committed canonical bytes must decode back to the same records with the
/// same recomputed content ids. Any change to an encoding or field order fails.
#[test]
fn committed_bytes_match_the_typed_encoders() {
    use rrn_crypto::serialize::from_canonical_bytes;

    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    let fx: Fixture = serde_json::from_str(&text).expect("committed fixture is not valid JSON");

    // Everything rebuilds byte-for-byte from the recorded inputs.
    assert_eq!(serialize(&build_fixture()), text);

    // Each committed canonical blob decodes back to a record whose recomputed
    // content id matches the fixture (proves the omit-and-recompute discipline).
    let req_bytes = hex::decode(&fx.request.canonical_hex).unwrap();
    let request: CertificateRequest = from_canonical_bytes(&req_bytes).unwrap();
    assert_eq!(request.request_id.0.to_hex(), fx.request.request_id);

    let cert_bytes = hex::decode(&fx.certificate.canonical_hex).unwrap();
    let certificate: HeadroomCertificate = from_canonical_bytes(&cert_bytes).unwrap();
    assert_eq!(certificate.cert_id.0.to_hex(), fx.certificate.cert_id);
    assert_eq!(certificate.request_id.0.to_hex(), fx.certificate.request_id);

    let ret_bytes = hex::decode(&fx.certificate_return.canonical_hex).unwrap();
    let return_record: CertificateReturn = from_canonical_bytes(&ret_bytes).unwrap();
    assert_eq!(
        return_record.cert_id.0.to_hex(),
        fx.certificate_return.cert_id
    );
}
