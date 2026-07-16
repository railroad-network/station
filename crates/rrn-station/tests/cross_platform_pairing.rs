//! Cross-platform pairing vectors: the contract that the mobile's `Pairing` seam
//! and the station's `pairing`/`paired` code agree byte-for-byte on the pairing
//! handshake (T1.3.3).
//!
//! The station is the source of truth for the wire layout: `pairing::
//! request_signed_bytes` / `response_signed_bytes` fix which bytes each side
//! signs, and `paired::confirmation_code` fixes the SAS. The mobile reimplements
//! those *layouts* in TypeScript (it reaches the underlying Ed25519 / blake3
//! through the uniffi FFI, not a second implementation), so the only thing that
//! can drift is the layout itself — the tag, the field order, the big-endian
//! encoding of `requested_at`, and the station-key-first SAS order. This fixture
//! pins all of them against real Rust output.
//!
//! What the fixture carries, all hex-encoded and fully reproducible from the
//! seeds:
//!   - `handshake`: one complete round — a mobile's signed request and the
//!     station's signed reply over a fixed (station, mobile, token, timestamp),
//!     so the mobile can prove it emits a station-verifiable request and
//!     verifies a real station reply.
//!   - `sas_vectors`: `confirmation_code` over several key pairs, including the
//!     same pair swapped, so the mobile locks the station-first ordering against
//!     real blake3.
//!   - `request_layout_vectors` / `response_layout_vectors`: the signed byte
//!     strings for varied inputs — notably `requested_at` at 0, 1, -1, and
//!     `Number.MAX_SAFE_INTEGER` — to pin the i64 big-endian encoding, the most
//!     likely cross-language trap.
//!
//! The fixture is regenerable but committed, so mobile CI needs no Rust
//! toolchain. Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test cross_platform_pairing
//! then copy `tests/fixtures/cross_platform_pairing.json` into the mobile repo
//! at `__tests__/fixtures/cross_platform_pairing.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_identity::address::Address;
use rrn_station::core::hex;
use rrn_station::paired::confirmation_code;
use rrn_station::pairing::{request_signed_bytes, response_signed_bytes};
use serde::{Deserialize, Serialize};

/// SAS domain tag — duplicated from `paired.rs` (it is a private const there) so
/// this generator can build the exact input `confirmation_code` hashes and prove
/// it below. If these ever disagree, `sas_matches_confirmation_code` fails.
const SAS_TAG: &[u8] = b"rrn-pair-sas-v1";

/// One complete handshake over a fixed (station, mobile, token, timestamp).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Handshake {
    station_seed: String,
    station_pubkey: String,
    station_address: String,
    mobile_seed: String,
    mobile_pubkey: String,
    mobile_address: String,
    token: String,
    requested_at: i64,
    /// `TAG ‖ mobile_pubkey ‖ token ‖ requested_at.to_be_bytes()`.
    request_signed_bytes: String,
    /// The mobile's Ed25519 signature over `request_signed_bytes`.
    mobile_signature: String,
    /// `TAG ‖ station_pubkey ‖ token`.
    response_signed_bytes: String,
    /// The station's Ed25519 signature over `response_signed_bytes`.
    station_signature: String,
    /// The station-first SAS the operator and the mobile both display.
    sas: String,
}

/// A SAS over an explicit (station, mobile) key pair, with the hashed input and
/// full blake3 digest so the mobile can back its FFI `Hash.of` from the fixture
/// (as `sign.test.ts` backs signing) rather than re-implementing blake3.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SasVector {
    station_pubkey: String,
    mobile_pubkey: String,
    /// `SAS_TAG ‖ station_pubkey ‖ mobile_pubkey` — the exact bytes hashed.
    sas_input: String,
    /// Full blake3 hex of `sas_input`; the SAS is its first 8 chars.
    sas_full_hash: String,
    sas: String,
}

/// A request signed-bytes vector, varying `requested_at` to pin the i64 encoding.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RequestLayout {
    mobile_pubkey: String,
    token: String,
    requested_at: i64,
    signed_bytes: String,
}

/// A response signed-bytes vector.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ResponseLayout {
    station_pubkey: String,
    token: String,
    signed_bytes: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    handshake: Handshake,
    sas_vectors: Vec<SasVector>,
    request_layout_vectors: Vec<RequestLayout>,
    response_layout_vectors: Vec<ResponseLayout>,
}

/// Deterministic 32-byte value from a domain-separated label and index. No RNG,
/// so every run on any machine produces byte-identical output.
fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

fn address_of(pk: &PublicKey) -> String {
    Address::from_public_key(*pk).to_string()
}

/// The bytes `confirmation_code` hashes: `SAS_TAG ‖ station ‖ mobile`.
fn sas_input_bytes(station: &PublicKey, mobile: &PublicKey) -> Vec<u8> {
    let mut input = SAS_TAG.to_vec();
    input.extend_from_slice(&station.to_bytes());
    input.extend_from_slice(&mobile.to_bytes());
    input
}

fn sas_vector(station: &PublicKey, mobile: &PublicKey) -> SasVector {
    let input = sas_input_bytes(station, mobile);
    SasVector {
        station_pubkey: hex(&station.to_bytes()),
        mobile_pubkey: hex(&mobile.to_bytes()),
        sas_input: hex(&input),
        sas_full_hash: Hash::of(&input).to_hex(),
        sas: confirmation_code(station, mobile),
    }
}

fn request_layout(mobile: &PublicKey, token: &[u8; 32], requested_at: i64) -> RequestLayout {
    RequestLayout {
        mobile_pubkey: hex(&mobile.to_bytes()),
        token: hex(token),
        requested_at,
        signed_bytes: hex(&request_signed_bytes(mobile, token, requested_at)),
    }
}

fn response_layout(station: &PublicKey, token: &[u8; 32]) -> ResponseLayout {
    ResponseLayout {
        station_pubkey: hex(&station.to_bytes()),
        token: hex(token),
        signed_bytes: hex(&response_signed_bytes(station, token)),
    }
}

fn build_fixture() -> Fixture {
    let label = "rrn-cross-platform-pairing-fixture:v1:";
    let station = keypair_from_seed(derive(&format!("{label}station-seed:"), 0));
    let mobile = keypair_from_seed(derive(&format!("{label}mobile-seed:"), 0));
    let station2 = keypair_from_seed(derive(&format!("{label}station-seed:"), 1));
    let mobile2 = keypair_from_seed(derive(&format!("{label}mobile-seed:"), 1));
    let token = derive(&format!("{label}token:"), 0);
    let token2 = derive(&format!("{label}token:"), 1);
    // A fixed, plausible 2025-era Unix timestamp — deterministic, not `now`.
    let requested_at: i64 = 1_752_000_000;

    let station_pk = station.public_key();
    let mobile_pk = mobile.public_key();

    let request_bytes = request_signed_bytes(&mobile_pk, &token, requested_at);
    let response_bytes = response_signed_bytes(&station_pk, &token);

    let handshake = Handshake {
        station_seed: hex(&derive(&format!("{label}station-seed:"), 0)),
        station_pubkey: hex(&station_pk.to_bytes()),
        station_address: address_of(&station_pk),
        mobile_seed: hex(&derive(&format!("{label}mobile-seed:"), 0)),
        mobile_pubkey: hex(&mobile_pk.to_bytes()),
        mobile_address: address_of(&mobile_pk),
        token: hex(&token),
        requested_at,
        request_signed_bytes: hex(&request_bytes),
        mobile_signature: hex(&mobile.sign(&request_bytes).to_bytes()),
        response_signed_bytes: hex(&response_bytes),
        station_signature: hex(&station.sign(&response_bytes).to_bytes()),
        sas: confirmation_code(&station_pk, &mobile_pk),
    };

    let sas_vectors = vec![
        // The handshake pair.
        sas_vector(&station_pk, &mobile_pk),
        // The same two keys swapped: a different pair, so a different SAS. Locks
        // the station-first ordering.
        sas_vector(&mobile_pk, &station_pk),
        // An independent pair.
        sas_vector(&station2.public_key(), &mobile2.public_key()),
    ];

    // `requested_at` swept across the values most likely to expose an encoding
    // mismatch: zero, one, negative one (all-0xff two's complement), and
    // JavaScript's Number.MAX_SAFE_INTEGER (2^53 - 1, the largest the mobile can
    // hold exactly).
    let request_layout_vectors = vec![
        request_layout(&mobile_pk, &token, 0),
        request_layout(&mobile_pk, &token, 1),
        request_layout(&mobile_pk, &token, -1),
        request_layout(&mobile_pk, &token, 9_007_199_254_740_991),
        request_layout(&mobile_pk, &token, requested_at),
    ];

    let response_layout_vectors = vec![
        response_layout(&station_pk, &token),
        response_layout(&station_pk, &token2),
    ];

    Fixture {
        comment: "Cross-platform pairing vectors for T1.3.3. Generated by \
            rrn-station/tests/cross_platform_pairing.rs (pairing::/paired:: are \
            the source of truth for the wire layout; ADR-0008). The mobile's \
            Pairing seam must produce byte-identical request/response signed \
            bytes and the same station-first SAS. Seeds, token, and timestamp \
            are blake3-derived and deterministic; regenerate with RRN_REGEN=1."
            .to_string(),
        handshake,
        sas_vectors,
        request_layout_vectors,
        response_layout_vectors,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_pairing.json")
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
    let bytes: [u8; 32] = rrn_station::core::unhex(hex_pk)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    PublicKey::from_bytes(bytes).unwrap()
}

fn token_of(hex_token: &str) -> [u8; 32] {
    rrn_station::core::unhex(hex_token)
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap()
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
         --test cross_platform_pairing, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn request_and_response_bytes_are_reproducible() {
    let fixture = load_committed();

    for v in &fixture.request_layout_vectors {
        let bytes = request_signed_bytes(
            &public_key(&v.mobile_pubkey),
            &token_of(&v.token),
            v.requested_at,
        );
        assert_eq!(
            hex(&bytes),
            v.signed_bytes,
            "requested_at={}",
            v.requested_at
        );
    }
    for v in &fixture.response_layout_vectors {
        let bytes = response_signed_bytes(&public_key(&v.station_pubkey), &token_of(&v.token));
        assert_eq!(hex(&bytes), v.signed_bytes);
    }

    let h = &fixture.handshake;
    assert_eq!(
        hex(&request_signed_bytes(
            &public_key(&h.mobile_pubkey),
            &token_of(&h.token),
            h.requested_at
        )),
        h.request_signed_bytes
    );
    assert_eq!(
        hex(&response_signed_bytes(
            &public_key(&h.station_pubkey),
            &token_of(&h.token)
        )),
        h.response_signed_bytes
    );
}

#[test]
fn sas_matches_confirmation_code() {
    let fixture = load_committed();
    for v in &fixture.sas_vectors {
        let station = public_key(&v.station_pubkey);
        let mobile = public_key(&v.mobile_pubkey);
        // The SAS is confirmation_code, and its input is SAS_TAG ‖ station ‖ mobile.
        assert_eq!(confirmation_code(&station, &mobile), v.sas);
        assert_eq!(hex(&sas_input_bytes(&station, &mobile)), v.sas_input);
        assert_eq!(
            Hash::of(&sas_input_bytes(&station, &mobile)).to_hex(),
            v.sas_full_hash
        );
        assert_eq!(
            &v.sas_full_hash[..8],
            v.sas,
            "SAS is the first 8 hex of the digest"
        );
    }
    // Swapping the keys is a different pair, so a different code (ordering lock).
    assert_ne!(fixture.sas_vectors[0].sas, fixture.sas_vectors[1].sas);
}

#[test]
fn handshake_signatures_verify() {
    let fixture = load_committed();
    let h = &fixture.handshake;

    // The mobile's request signature verifies against the mobile key.
    let mobile_pk = public_key(&h.mobile_pubkey);
    let request_sig = rrn_crypto::keypair::Signature::from_bytes(
        rrn_station::core::unhex(&h.mobile_signature)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert!(mobile_pk
        .verify(
            &rrn_station::core::unhex(&h.request_signed_bytes).unwrap(),
            &request_sig
        )
        .is_ok());

    // The station's response signature verifies against the station key.
    let station_pk = public_key(&h.station_pubkey);
    let response_sig = rrn_crypto::keypair::Signature::from_bytes(
        rrn_station::core::unhex(&h.station_signature)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    assert!(station_pk
        .verify(
            &rrn_station::core::unhex(&h.response_signed_bytes).unwrap(),
            &response_sig
        )
        .is_ok());

    // The address round-trips from the key.
    assert_eq!(address_of(&station_pk), h.station_address);
    assert_eq!(address_of(&mobile_pk), h.mobile_address);
    // The handshake SAS is the station-first vector.
    assert_eq!(h.sas, fixture.sas_vectors[0].sas);
}
