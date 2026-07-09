//! Cross-platform signing vectors: the contract that mobile and station
//! produce byte-identical Ed25519 signatures for the same (seed, message), and
//! agree on which signatures verify (T1.1.4).
//!
//! `rrn_crypto::keypair` is the single source of truth for signing (ADR-0001);
//! mobile reaches the *same* code through the uniffi FFI (`rrn-mobile-ffi`)
//! rather than reimplementing Ed25519. Ed25519 signing is deterministic
//! (RFC 8032 §5.1.6): a given seed and message always yield the same 64-byte
//! signature, so the fixture is a hard cross-platform equality check, not just
//! a "both verify" check.
//!
//! This test generates a committed fixture — random-but-deterministic keypairs
//! signing messages of varied lengths, locked known-answer vectors, and a set
//! of triples that must NOT verify (tampered sig, tampered message, wrong key)
//! — and verifies every invariant here in Rust. The mobile side reads the same
//! committed JSON; see `mobile/__tests__/sign.test.ts`.
//!
//! The fixture is regenerable but committed, so mobile CI needs no Rust
//! toolchain. Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-crypto --test cross_platform_sign
//! then copy `tests/fixtures/cross_platform_sign.json` into the mobile repo at
//! `__tests__/fixtures/cross_platform_sign.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

/// One signing vector: the seed the keypair was derived from, its public key,
/// the message that was signed, and the resulting signature. All hex-encoded so
/// the fixture is fully reproducible from `seed` + `message` alone.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Vector {
    seed: String,
    pubkey: String,
    message: String,
    signature: String,
}

/// A (pubkey, message, signature) triple that must NOT verify, with why.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Tampered {
    pubkey: String,
    message: String,
    signature: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    /// 100 random-but-deterministic vectors, messages of length 0..=32.
    vectors: Vec<Vector>,
    /// Locked known-answer vectors — if any of these change, the signing
    /// backend changed, which needs an ADR, not a fixture edit.
    known_answer: Vec<Vector>,
    /// Triples the verifier must reject.
    tampered: Vec<Tampered>,
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

fn vector_for(seed: [u8; 32], message: &[u8]) -> Vector {
    let kp = keypair_from_seed(seed);
    let sig = kp.sign(message);
    Vector {
        seed: hex::encode(seed),
        pubkey: hex::encode(kp.public_key().to_bytes()),
        message: hex::encode(message),
        signature: hex::encode(sig.to_bytes()),
    }
}

/// Deterministic 32-byte value from a domain-separated label and index. No RNG,
/// so every run — on any machine — produces byte-identical output.
fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

/// Deterministic message #i: the first `i % 33` bytes of a derived hash, so
/// lengths sweep 0..=32 (vector 0 is the empty message — a real edge case).
fn deterministic_message(i: u32) -> Vec<u8> {
    let len = (i % 33) as usize;
    derive("rrn-cross-platform-sign-fixture:v1:msg:", i)[..len].to_vec()
}

fn build_fixture() -> Fixture {
    let vectors: Vec<Vector> = (0..100)
        .map(|i| {
            let seed = derive("rrn-cross-platform-sign-fixture:v1:seed:", i);
            vector_for(seed, &deterministic_message(i))
        })
        .collect();

    // KATs: the all-zero and all-ones seeds signing a fixed message. Locked in
    // the mobile test too — the two must agree byte-for-byte.
    let kat_msg = b"railroad network";
    let known_answer = vec![
        vector_for([0u8; 32], kat_msg),
        vector_for([0xFFu8; 32], kat_msg),
    ];

    // Triples that must fail verification. Built from the first two vectors.
    let v0 = &vectors[0];
    let v1 = &vectors[1];
    let flip_last_bit = |hex_sig: &str| {
        let mut bytes = hex::decode(hex_sig).unwrap();
        *bytes.last_mut().unwrap() ^= 0x01;
        hex::encode(bytes)
    };
    let tampered = |pubkey: &str, message: &str, signature: String, reason: &str| Tampered {
        pubkey: pubkey.to_string(),
        message: message.to_string(),
        signature,
        reason: reason.to_string(),
    };
    let tampered = vec![
        tampered(
            &v0.pubkey,
            &v0.message,
            flip_last_bit(&v0.signature),
            "signature with one bit flipped",
        ),
        // v0's real signature, but presented over v1's message.
        tampered(
            &v0.pubkey,
            &v1.message,
            v0.signature.clone(),
            "valid signature over a different message",
        ),
        // v0's real signature and message, but checked against v1's key.
        tampered(
            &v1.pubkey,
            &v0.message,
            v0.signature.clone(),
            "valid signature checked against the wrong public key",
        ),
    ];

    Fixture {
        comment: "Cross-platform signing vectors for T1.1.4. Generated by \
            rrn-crypto/tests/cross_platform_sign.rs (rrn_crypto::keypair is the \
            source of truth, ADR-0001). Ed25519 signing is deterministic \
            (RFC 8032), so mobile must produce byte-identical signatures via \
            rrn-mobile-ffi. Seeds and messages are blake3-derived and \
            deterministic; regenerate with RRN_REGEN=1."
            .to_string(),
        vectors,
        known_answer,
        tampered,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_sign.json")
}

fn load_committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    serde_json::from_str(&text).expect("committed fixture is not valid JSON")
}

/// Serialized form: pretty JSON with a trailing newline. Deterministic given
/// deterministic inputs, so re-running produces byte-identical output.
fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn public_key(hex_pk: &str) -> PublicKey {
    PublicKey::from_bytes(hex::decode(hex_pk).unwrap().as_slice().try_into().unwrap()).unwrap()
}

fn signature(hex_sig: &str) -> Signature {
    Signature::from_bytes(hex::decode(hex_sig).unwrap().as_slice().try_into().unwrap()).unwrap()
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-crypto \
         --test cross_platform_sign, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    // The whole cross-platform contract rests on this being reproducible.
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn signing_is_reproducible_from_seed() {
    let fixture = load_committed();
    assert_eq!(fixture.vectors.len(), 100);
    for v in fixture.vectors.iter().chain(fixture.known_answer.iter()) {
        let seed: [u8; 32] = hex::decode(&v.seed).unwrap().as_slice().try_into().unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let kp = keypair_from_seed(seed);
        // Public key derived from the seed matches the recorded key.
        assert_eq!(hex::encode(kp.public_key().to_bytes()), v.pubkey);
        // Signing the same message yields the recorded signature, byte-for-byte.
        assert_eq!(
            hex::encode(kp.sign(&msg).to_bytes()),
            v.signature,
            "{}",
            v.seed
        );
    }
}

#[test]
fn every_vector_verifies() {
    let fixture = load_committed();
    for v in fixture.vectors.iter().chain(fixture.known_answer.iter()) {
        let msg = hex::decode(&v.message).unwrap();
        assert!(
            public_key(&v.pubkey)
                .verify(&msg, &signature(&v.signature))
                .is_ok(),
            "{}",
            v.seed
        );
    }
}

#[test]
fn tampered_triples_are_rejected() {
    let fixture = load_committed();
    assert_eq!(fixture.tampered.len(), 3);
    for t in &fixture.tampered {
        let msg = hex::decode(&t.message).unwrap();
        assert!(
            public_key(&t.pubkey)
                .verify(&msg, &signature(&t.signature))
                .is_err(),
            "expected rejection ({}): {}",
            t.reason,
            t.signature
        );
    }
}

#[test]
fn known_answer_seeds_locked() {
    let fixture = load_committed();
    assert_eq!(fixture.known_answer[0].seed, "0".repeat(64));
    assert_eq!(fixture.known_answer[1].seed, "ff".repeat(32));
    // Both KATs sign the same fixed message.
    let kat_msg = hex::encode(b"railroad network");
    assert_eq!(fixture.known_answer[0].message, kat_msg);
    assert_eq!(fixture.known_answer[1].message, kat_msg);
}
