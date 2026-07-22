//! Cross-platform `SignedVouch` vectors (T1.4.3).
//!
//! The vouch write contract's load-bearing claim: a vouch signed on the phone
//! and appended by the station produce **byte-identical** canonical dCBOR and
//! signature, because both sign the same canonical bytes of the same attestation
//! (ADR-0002). The mobile builds the attestation's canonical form in TypeScript
//! (`wallet/vouch.ts`, mirroring `attestation.rs` + `vouch.rs`) rather than
//! through a per-domain FFI call, so the only thing that can drift is that
//! tagged-value tree. This fixture pins it against real Rust output.
//!
//! Like the proposal vector (`rrn-ledger/tests/cross_platform_signed_payload.rs`)
//! it exercises the parts of the tagged model plain JSON cannot carry — a
//! byte-string `subject`, a 64-bit `reputation_stake_centi`, a nested `body`
//! map, and the explicit `expires_at: null`. It also asserts, at generation
//! time, that the recorded `payload` tree canonicalizes (via the real
//! `canonical_bytes` FFI) to the same bytes the typed `From<Attestation> for
//! CBOR` encoder produces — so a mistake in the tree is caught here, not
//! silently baked into the fixture.
//!
//! The mobile side reads the same committed JSON; see
//! `mobile/__tests__/vouchCrossPlatform.test.ts`.
//!
//! Deterministic (blake3 seeds + deterministic Ed25519). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test cross_platform_vouch
//! then copy `tests/fixtures/cross_platform_vouch.json` into the mobile repo at
//! `__tests__/fixtures/cross_platform_vouch.json`. (The first regen run can lose
//! the read-vs-write race with the other tests in this file — run it twice.)

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::attestation::Attestation;
use rrn_identity::vouch::{VouchBody, VouchKind};
use rrn_mobile_ffi::canonical_bytes;
use rrn_station::core::{hex, unhex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The community every Phase-0 vouch carries — mirrors `core.rs::VOUCH_COMMUNITY`
/// (a private const there) and the value `whoami` now returns.
const VOUCH_COMMUNITY: &str = "rrn-phase0";

/// One signed-vouch vector. Numeric fields are decimal **strings** so the full
/// u64/i64 range survives the JSON hop into JavaScript. `payload` is the tagged
/// value model the mobile app builds.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct VouchVector {
    voucher_seed: String,
    voucher_pubkey: String,
    voucher_address: String,
    subject_pubkey: String,
    subject_address: String,
    community: String,
    statement: String,
    reputation_stake_centi: String,
    issued_at: String,
    payload: Value,
    /// Canonical dCBOR of the attestation (== `From<Attestation> for CBOR`).
    canonical_hex: String,
    /// The voucher's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
    /// Blake3 of the canonical bytes — the `vouch_id` the station returns.
    vouch_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    vectors: Vec<VouchVector>,
}

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

/// Varied statements, including unicode, to exercise NFC normalization + text.
fn statement_for(i: u32) -> String {
    match i % 3 {
        0 => "I know this person personally".to_string(),
        1 => format!("neighbour #{i}"),
        _ => format!("café regular ☕ {i}"),
    }
}

/// Varied stakes, including zero (accepted in Phase 0) and a value past 2^53.
fn stake_for(i: u32) -> u64 {
    match i % 3 {
        0 => 50, // the T1.4.1 default minimum
        1 => 0,
        _ => 9_007_199_254_740_993, // past Number.MAX_SAFE_INTEGER
    }
}

fn build_vector(i: u32) -> VouchVector {
    let voucher_seed = derive("rrn-cross-platform-vouch-fixture:v1:voucher:", i);
    let voucher = keypair_from_seed(voucher_seed);
    let subject_kp = keypair_from_seed(derive("rrn-cross-platform-vouch-fixture:v1:subject:", i));
    let voucher_pk = voucher.public_key();
    let subject_pk = subject_kp.public_key();
    let subject = Address::from_public_key(subject_pk);

    let statement = statement_for(i);
    let stake = stake_for(i);
    // A fixed, plausible 2025-era Unix timestamp — deterministic, not `now`, so
    // the vector is stable (why we build the attestation directly rather than
    // via `create_vouch`, whose `now_secs()` would move each run).
    let issued_at: i64 = 1_752_000_000 + i64::from(i);

    let attestation = Attestation {
        kind: VouchKind,
        body: VouchBody {
            community: VOUCH_COMMUNITY.to_string(),
            statement: statement.clone(),
            reputation_stake_centi: stake,
        },
        subject,
        issued_at,
        expires_at: None,
    };

    let canonical = to_canonical_bytes(attestation.clone());
    let signed = attestation.sign(&voucher);

    // The tagged-value payload the mobile app builds. Field order mirrors the
    // struct (and `wallet/vouch.ts`) so `JSON.stringify` matches on the mobile
    // side; dCBOR sorts map keys itself, so it does not affect the bytes.
    let payload = json!({ "map": [
        ["kind", { "text": "vouch" }],
        ["body", { "map": [
            ["community", { "text": VOUCH_COMMUNITY }],
            ["statement", { "text": statement }],
            ["reputation_stake_centi", { "int": stake.to_string() }],
        ]}],
        ["subject", { "bytes": hex(&subject_pk.to_bytes()) }],
        ["issued_at", { "int": issued_at.to_string() }],
        ["expires_at", { "null": null }],
    ]});

    // The heart of the cross-platform contract: the mobile tagged-JSON path must
    // yield the exact bytes the typed encoder produced.
    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "vector {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    VouchVector {
        voucher_seed: hex(&voucher_seed),
        voucher_pubkey: hex(&voucher_pk.to_bytes()),
        voucher_address: Address::from_public_key(voucher_pk).to_string(),
        subject_pubkey: hex(&subject_pk.to_bytes()),
        subject_address: subject.to_string(),
        community: VOUCH_COMMUNITY.to_string(),
        statement: statement_for(i),
        reputation_stake_centi: stake.to_string(),
        issued_at: issued_at.to_string(),
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
        vouch_id: hex(&signed.payload_hash().to_bytes()),
    }
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform SignedVouch vectors for T1.4.3. Generated by \
            rrn-station/tests/cross_platform_vouch.rs. `payload` is the mobile \
            tagged-value model; `canonical_hex` is the vouch attestation's canonical \
            dCBOR (== From<Attestation> for CBOR); `signature_hex` is the voucher's \
            Ed25519 signature over those bytes; `vouch_id` is their blake3 hash (what \
            submit_vouch returns). Mobile builds the same payload via wallet/vouch.ts, \
            canonicalizes it via the canonical_bytes FFI, and signs — producing the \
            identical signature. Deterministic (blake3 seeds, RFC 8032); regenerate \
            with RRN_REGEN=1."
            .to_string(),
        vectors: (0..6).map(build_vector).collect(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_vouch.json")
}

fn load_committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    serde_json::from_str(&text).expect("committed fixture is not valid JSON")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn public_key(hex_pk: &str) -> PublicKey {
    let bytes: [u8; 32] = unhex(hex_pk).unwrap().as_slice().try_into().unwrap();
    PublicKey::from_bytes(bytes).unwrap()
}

/// Rebuilds the attestation from a vector's recorded fields (as the mobile app's
/// inputs would), independent of the stored `payload`/`canonical_hex`.
fn attestation_from(v: &VouchVector) -> Attestation<VouchKind, VouchBody> {
    Attestation {
        kind: VouchKind,
        body: VouchBody {
            community: v.community.clone(),
            statement: v.statement.clone(),
            reputation_stake_centi: v.reputation_stake_centi.parse().unwrap(),
        },
        subject: Address::from_public_key(public_key(&v.subject_pubkey)),
        issued_at: v.issued_at.parse().unwrap(),
        expires_at: None,
    }
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-station \
         --test cross_platform_vouch, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn tagged_json_matches_the_typed_encoder() {
    let fixture = load_committed();
    for v in &fixture.vectors {
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("payload must canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.voucher_pubkey);
        let typed = to_canonical_bytes(attestation_from(v));
        assert_eq!(hex(&typed), v.canonical_hex, "{}", v.voucher_pubkey);
    }
}

#[test]
fn signatures_are_reproducible_and_verify() {
    let fixture = load_committed();
    for v in &fixture.vectors {
        let seed: [u8; 32] = unhex(&v.voucher_seed)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let kp = keypair_from_seed(seed);
        assert_eq!(hex(&kp.public_key().to_bytes()), v.voucher_pubkey);

        // Deterministic Ed25519 reproduces the recorded signature byte-for-byte,
        // and the signature verifies — a mobile-produced signature would too.
        let signed = attestation_from(v).sign(&kp);
        assert_eq!(hex(&signed.signature.to_bytes()), v.signature_hex);
        assert_eq!(hex(&signed.payload_hash().to_bytes()), v.vouch_id);
        assert!(signed.verify().is_ok(), "{}", v.voucher_pubkey);
    }
}
