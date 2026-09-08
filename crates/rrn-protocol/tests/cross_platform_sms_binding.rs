//! Cross-platform SMS-binding wire fixture (T2.7.1).
//!
//! Pins the canonical dCBOR bytes and Ed25519 signature of a `rrn.net.sms_binding`
//! record so the mobile repo verifies a byte-identical encoding (ADR-0002). The
//! key is blake3-derived so the vector is deterministic and self-contained.
//!
//! Regenerate (after an intentional encoding change) with:
//!   RRN_REGEN=1 cargo test -p rrn-protocol --test cross_platform_sms_binding
//! then copy `tests/fixtures/cross_platform_sms_binding.json` into the mobile repo.

use std::path::PathBuf;

use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_protocol::binding::{self, SignedSmsBinding, SmsBinding};
use serde::{Deserialize, Serialize};

fn derive(label: &str) -> [u8; 32] {
    rrn_crypto::hash::Hash::of(format!("rrn-fixture:{label}").as_bytes()).to_bytes()
}

fn keypair(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(derive(label)))
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    _comment: String,
    /// The signer's Ed25519 secret seed (hex) — rebuilds the identical key.
    signer_seed: String,
    /// The bound RRN address (`rrn1…`), == the signer.
    address: String,
    /// The bound phone number (E.164).
    msisdn: String,
    /// Bind time (Unix seconds).
    bound_at: i64,
    /// Canonical dCBOR of the `SmsBinding` payload (== From<T> for CBOR).
    canonical_hex: String,
    /// The signer's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
}

fn build_signed() -> (Keypair, SignedSmsBinding) {
    let kp = keypair("sms-binding");
    let addr = Address::from_public_key(kp.public_key());
    let binding = SmsBinding::new(addr, "+15551234567", 1_700_000_500);
    (kp.clone(), SignedPayload::sign(binding, &kp))
}

fn build_fixture() -> Fixture {
    let (kp, signed) = build_signed();
    let canonical = to_canonical_bytes(signed.payload.clone());
    // Sanity: the fixture must validate as a self-signed SMS binding.
    binding::validate_sms_binding(&signed).expect("fixture sms binding validates");
    Fixture {
        _comment: "Cross-platform SMS-binding fixture (T2.7.1). `canonical_hex` is \
                   the canonical dCBOR of the rrn.net.sms_binding payload; \
                   `signature_hex` is the self-signature over it. Deterministic \
                   (blake3-derived seed); regenerate with RRN_REGEN=1."
            .into(),
        signer_seed: hex::encode(kp.secret_key().to_bytes()),
        address: signed.payload.address.to_string(),
        msisdn: signed.payload.msisdn.clone(),
        bound_at: signed.payload.bound_at,
        canonical_hex: hex::encode(&canonical),
        signature_hex: hex::encode(signed.signature.to_bytes()),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_sms_binding.json")
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-protocol \
         --test cross_platform_sms_binding, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The byte-identity guard: rebuild from the committed seed, re-encode, re-sign,
/// and assert the bytes and signature match — and that the recorded signature
/// verifies.
#[test]
fn committed_bytes_match_the_typed_encoders() {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    let fx: Fixture = serde_json::from_str(&text).expect("fixture is valid JSON");

    let kp = Keypair::from_secret(SecretKey::from_bytes(
        hex::decode(&fx.signer_seed).unwrap().try_into().unwrap(),
    ));
    let addr = Address::from_public_key(kp.public_key());
    let binding = SmsBinding::new(addr, &fx.msisdn, fx.bound_at);
    assert_eq!(
        hex::encode(to_canonical_bytes(binding.clone())),
        fx.canonical_hex
    );

    let signed = SignedPayload::sign(binding, &kp);
    assert_eq!(hex::encode(signed.signature.to_bytes()), fx.signature_hex);
    binding::validate_sms_binding(&signed).expect("recorded binding verifies");
    assert_eq!(signed.payload.address.to_string(), fx.address);
}
