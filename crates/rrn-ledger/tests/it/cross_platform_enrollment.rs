//! Enrollment wire fixture (ADR-0038 §1).
//!
//! Three byte-stable vectors for the station-signed `rrn.member.enrollment`
//! kind — a `founder` enroll, a `pairing` enroll and an `operator` revoke — so a
//! change to the record's canonical dCBOR (ADR-0002) fails here. No member
//! device signs or verifies this kind, so unlike the other `cross_platform_*`
//! fixtures there is no copy in the mobile repo. Deterministic (blake3-derived
//! seeds + RFC 8032 Ed25519), reproducible bit-for-bit. Regenerate:
//!
//! ```sh
//! RRN_REGEN=1 cargo test -p rrn-ledger --test it cross_platform_enrollment
//! ```

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_identity::address::Address;
use rrn_ledger::enrollment::{
    sign_enrollment, EnrollmentAction, EnrollmentBasis, EnrollmentRecord,
};
use serde::{Deserialize, Serialize};

fn keypair(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(Hash::of(label.as_bytes()).to_bytes()))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EnrollmentVector {
    member_pubkey: String,
    action: String,
    basis: String,
    recorded_at: String,
    /// Canonical dCBOR of the `EnrollmentRecord` (== `From<..> for CBOR`).
    canonical_hex: String,
    /// The station's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    station_seed: String,
    station_pubkey: String,
    vectors: Vec<EnrollmentVector>,
}

const CASES: [(&str, EnrollmentAction, EnrollmentBasis, i64); 3] = [
    (
        "founder",
        EnrollmentAction::Enroll,
        EnrollmentBasis::Founder,
        1_700_000_000,
    ),
    (
        "paired",
        EnrollmentAction::Enroll,
        EnrollmentBasis::Pairing,
        1_700_000_100,
    ),
    (
        "paired",
        EnrollmentAction::Revoke,
        EnrollmentBasis::Operator,
        1_700_000_200,
    ),
];

fn build_fixture() -> Fixture {
    let station = keypair("rrn-enrollment-fixture:v1:station:");
    let vectors = CASES
        .iter()
        .map(|(label, action, basis, recorded_at)| {
            let member = keypair(&format!("rrn-enrollment-fixture:v1:{label}:"));
            let signed = sign_enrollment(
                &station,
                Address::from_public_key(member.public_key()),
                *action,
                *basis,
                *recorded_at,
            )
            .unwrap();
            assert!(signed.verify().is_ok());
            EnrollmentVector {
                member_pubkey: hex::encode(member.public_key().to_bytes()),
                action: action.as_str().to_string(),
                basis: basis.as_str().to_string(),
                recorded_at: recorded_at.to_string(),
                canonical_hex: hex::encode(to_canonical_bytes(signed.payload.clone())),
                signature_hex: hex::encode(signed.signature.to_bytes()),
            }
        })
        .collect();
    Fixture {
        comment: "Enrollment wire fixture (ADR-0038 §1): the station-signed \
            rrn.member.enrollment kind — a founder enroll, a pairing enroll and an operator \
            revoke. `canonical_hex` is the record's canonical dCBOR (== From<T> for CBOR); \
            `signature_hex` is the station's Ed25519 signature over those bytes. Station-only: \
            no member device signs or verifies this kind, so the mobile repo keeps no copy. \
            Deterministic (blake3-derived seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        station_seed: hex::encode(station.secret_key().to_bytes()),
        station_pubkey: hex::encode(station.public_key().to_bytes()),
        vectors,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_enrollment.json")
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
         --test it cross_platform_enrollment"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The committed canonical bytes decode back to the recorded fields, and the
/// recorded signatures verify under the recorded station key.
#[test]
fn committed_bytes_decode_and_verify() {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    let fx: Fixture = serde_json::from_str(&text).expect("committed fixture is not valid JSON");
    let station = keypair("rrn-enrollment-fixture:v1:station:");
    assert_eq!(
        fx.station_pubkey,
        hex::encode(station.public_key().to_bytes())
    );
    for v in &fx.vectors {
        let bytes = hex::decode(&v.canonical_hex).unwrap();
        let record: EnrollmentRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(
            hex::encode(record.member.public_key().to_bytes()),
            v.member_pubkey
        );
        assert_eq!(record.action.as_str(), v.action);
        assert_eq!(record.basis.as_str(), v.basis);
        assert_eq!(record.recorded_at.to_string(), v.recorded_at);
        let sig: [u8; 64] = hex::decode(&v.signature_hex).unwrap().try_into().unwrap();
        assert!(station
            .public_key()
            .verify(
                &bytes,
                &rrn_crypto::keypair::Signature::from_bytes(sig).unwrap()
            )
            .is_ok());
    }
}
