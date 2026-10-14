//! Cross-platform vectors for the commit-then-reveal pairing handshake
//! (ADR-0008, Clarification 2026-10-14; `docs/spec/pairing.md`).
//!
//! `rrn_identity::pairing` is the single source of truth for the handshake's
//! byte layouts and confirmation code. The phone reaches the same code through
//! the mobile FFI and checks it against a byte-for-byte copy of this fixture;
//! `rrn-mobile-ffi`'s own test checks every FFI function against it too.
//! Seeds and nonces are blake3-derived and Ed25519 signing is deterministic, so
//! the fixture is reproducible bit-for-bit.
//!
//! Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-identity --test it cross_platform_pairing_v2
//! then copy `tests/fixtures/cross_platform_pairing_v2.json` into the mobile
//! repo at `__tests__/fixtures/cross_platform_pairing_v2.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey, Signature};
use rrn_identity::address::Address;
use rrn_identity::pairing;
use serde::{Deserialize, Serialize};

/// One complete handshake. Byte strings are lowercase hex.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Handshake {
    station_seed: String,
    mobile_seed: String,
    station_pk: String,
    mobile_pk: String,
    station_address: String,
    mobile_address: String,
    mobile_nonce: String,
    station_nonce: String,
    commitment: String,
    requested_at: i64,
    start_signed_bytes: String,
    start_signature: String,
    offer_signed_bytes: String,
    offer_signature: String,
    finish_signed_bytes: String,
    finish_signature: String,
    code: String,
}

/// The code for a set of inputs.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CodeVector {
    station_pk: String,
    mobile_pk: String,
    mobile_nonce: String,
    station_nonce: String,
    code: String,
}

/// The start layout at one `requested_at`, including the edge values.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct StartVector {
    mobile_pk: String,
    commitment: String,
    requested_at: i64,
    start_signed_bytes: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    handshake: Handshake,
    code_vectors: Vec<CodeVector>,
    start_vectors: Vec<StartVector>,
}

/// Deterministic 32 bytes from a domain-separated label and index.
fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = b"rrn-cross-platform-pairing-v2-fixture:".to_vec();
    input.extend_from_slice(label.as_bytes());
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair(label: &str, i: u32) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(derive(label, i)))
}

fn pk(kp: &Keypair) -> [u8; 32] {
    kp.public_key().to_bytes()
}

fn build_handshake() -> Handshake {
    let station = keypair("station-seed", 0);
    let mobile = keypair("mobile-seed", 0);
    let (spk, mpk) = (pk(&station), pk(&mobile));
    let mobile_nonce = derive("mobile-nonce", 0);
    let station_nonce = derive("station-nonce", 0);
    let requested_at = 1_760_400_000;

    let commitment = pairing::commitment(&mpk, &mobile_nonce);
    let start = pairing::start_signed_bytes(&mpk, &commitment, requested_at);
    let offer = pairing::offer_signed_bytes(&spk, &mpk, &commitment, &station_nonce);
    let finish =
        pairing::finish_signed_bytes(&spk, &mpk, &commitment, &station_nonce, &mobile_nonce);

    Handshake {
        station_seed: hex::encode(derive("station-seed", 0)),
        mobile_seed: hex::encode(derive("mobile-seed", 0)),
        station_pk: hex::encode(spk),
        mobile_pk: hex::encode(mpk),
        station_address: Address::from_public_key(station.public_key()).to_string(),
        mobile_address: Address::from_public_key(mobile.public_key()).to_string(),
        mobile_nonce: hex::encode(mobile_nonce),
        station_nonce: hex::encode(station_nonce),
        commitment: hex::encode(commitment),
        requested_at,
        start_signature: hex::encode(mobile.sign(&start).to_bytes()),
        start_signed_bytes: hex::encode(start),
        offer_signature: hex::encode(station.sign(&offer).to_bytes()),
        offer_signed_bytes: hex::encode(offer),
        finish_signature: hex::encode(mobile.sign(&finish).to_bytes()),
        finish_signed_bytes: hex::encode(finish),
        code: pairing::code(&spk, &mpk, &mobile_nonce, &station_nonce),
    }
}

fn code_vector(spk: [u8; 32], mpk: [u8; 32], mn: [u8; 32], sn: [u8; 32]) -> CodeVector {
    CodeVector {
        station_pk: hex::encode(spk),
        mobile_pk: hex::encode(mpk),
        mobile_nonce: hex::encode(mn),
        station_nonce: hex::encode(sn),
        code: pairing::code(&spk, &mpk, &mn, &sn),
    }
}

fn build_fixture() -> Fixture {
    let mut code_vectors: Vec<CodeVector> = (0..8)
        .map(|i| {
            code_vector(
                pk(&keypair("code-station", i)),
                pk(&keypair("code-mobile", i)),
                derive("code-mobile-nonce", i),
                derive("code-station-nonce", i),
            )
        })
        .collect();
    // The same inputs with the two keys swapped give a different code: the
    // order (station first) is part of the contract.
    let (s, m) = (
        pk(&keypair("code-station", 0)),
        pk(&keypair("code-mobile", 0)),
    );
    code_vectors.push(code_vector(
        m,
        s,
        derive("code-mobile-nonce", 0),
        derive("code-station-nonce", 0),
    ));

    let mobile = pk(&keypair("start-mobile", 0));
    let commitment = pairing::commitment(&mobile, &derive("start-nonce", 0));
    let start_vectors = [0, 1, -1, (1_i64 << 53) - 1]
        .into_iter()
        .map(|requested_at| StartVector {
            mobile_pk: hex::encode(mobile),
            commitment: hex::encode(commitment),
            requested_at,
            start_signed_bytes: hex::encode(pairing::start_signed_bytes(
                &mobile,
                &commitment,
                requested_at,
            )),
        })
        .collect();

    Fixture {
        comment: "Pairing handshake v2 (ADR-0008 Clarification 2026-10-14; docs/spec/pairing.md). \
            Seeds and nonces are blake3-derived and deterministic; regenerate with RRN_REGEN=1."
            .to_string(),
        handshake: build_handshake(),
        code_vectors,
        start_vectors,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_pairing_v2.json")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[test]
fn cross_platform_pairing_v2_fixture_is_stable() {
    let generated = serialize(&build_fixture());
    if std::env::var("RRN_REGEN").is_ok() {
        std::fs::write(fixture_path(), &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(fixture_path()).unwrap_or_default();
    assert_eq!(
        committed, generated,
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-identity \
         --test it cross_platform_pairing_v2, then copy the JSON into the mobile repo"
    );
}

#[test]
fn committed_handshake_verifies_end_to_end() {
    let text = std::fs::read_to_string(fixture_path()).expect("committed fixture");
    let fixture: Fixture = serde_json::from_str(&text).unwrap();
    let h = &fixture.handshake;

    let spk = PublicKey::from_bytes(arr(&h.station_pk)).unwrap();
    let mpk = PublicKey::from_bytes(arr(&h.mobile_pk)).unwrap();
    assert_eq!(h.station_address, Address::from_public_key(spk).to_string());
    assert_eq!(h.mobile_address, Address::from_public_key(mpk).to_string());

    let commitment: [u8; 32] = arr(&h.commitment);
    assert!(pairing::opens(
        &commitment,
        &mpk.to_bytes(),
        &arr(&h.mobile_nonce)
    ));
    for (bytes, sig, key) in [
        (&h.start_signed_bytes, &h.start_signature, mpk),
        (&h.offer_signed_bytes, &h.offer_signature, spk),
        (&h.finish_signed_bytes, &h.finish_signature, mpk),
    ] {
        let sig = Signature::from_bytes(arr(sig)).unwrap();
        key.verify(&hex::decode(bytes).unwrap(), &sig)
            .expect("signature verifies");
    }

    // The swapped-key vector really is the swap of the first one, and differs.
    let first = &fixture.code_vectors[0];
    let swapped = fixture.code_vectors.last().unwrap();
    assert_eq!(
        (&swapped.station_pk, &swapped.mobile_pk),
        (&first.mobile_pk, &first.station_pk)
    );
    assert_ne!(swapped.code, first.code);
}
