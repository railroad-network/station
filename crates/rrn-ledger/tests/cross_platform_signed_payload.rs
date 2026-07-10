//! Cross-platform `SignedPayload<TransactionProposal>` vectors (T1.1.7).
//!
//! The milestone's load-bearing claim: a transaction proposal signed on mobile
//! and the same proposal signed on the station produce **byte-identical**
//! signatures, because both sign the same canonical dCBOR (ADR-0002). This test
//! proves the two halves that make that true:
//!
//!   1. the mobile tagged-JSON payload, run through the real `canonical_bytes`
//!      FFI, produces the *same* bytes as the station's typed
//!      `From<TransactionProposal> for CBOR` encoder; and
//!   2. Ed25519 signing those bytes (deterministic, RFC 8032) yields the
//!      recorded signature, which `SignedPayload::verify` accepts — i.e. a
//!      mobile-produced signature verifies on the station and vice versa.
//!
//! `TransactionProposal`'s canonical form contains **byte-string** fields
//! (`sender`/`receiver` are `Address::to_byte_string`) and 64-bit integers, so
//! this is the vector that exercises the parts of the tagged model plain JSON
//! could not carry. The generic type-surface vectors live in
//! `rrn-mobile-ffi/tests/cross_platform_canonical.rs`.
//!
//! The mobile side reads the same committed JSON; see
//! `mobile/__tests__/SignedPayload.test.ts`.
//!
//! Deterministic (blake3 seeds + deterministic Ed25519), reproducible
//! bit-for-bit. Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-ledger --test cross_platform_signed_payload
//! then copy `tests/fixtures/cross_platform_signed_payload.json` into the mobile
//! repo at `__tests__/fixtures/cross_platform_signed_payload.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::transaction::TransactionProposal;
use rrn_mobile_ffi::canonical_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The `kind` discriminant the proposal carries in its canonical CBOR. Mirrored
/// here (the crate constant is `pub(crate)`); if it is wrong, the
/// tagged-vs-typed byte-equality assertion below fails loudly.
const PROPOSAL_KIND: &str = "rrn.tx.proposal";

/// How many proposals to generate. Ed25519 is fast (no argon2 here), so this is
/// generous.
const COUNT: u32 = 20;

/// One signed-proposal vector. Numeric fields are decimal **strings** so the
/// full i64/u64 range survives the JSON hop into JavaScript (whose numbers are
/// doubles). `payload` is the tagged-value model the mobile app builds.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ProposalVector {
    seed: String,
    sender_pubkey: String,
    receiver_pubkey: String,
    amount_centi: String,
    memo: Option<String>,
    nonce: String,
    proposed_at: String,
    expires_at: String,
    payload: Value,
    canonical_hex: String,
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    vectors: Vec<ProposalVector>,
}

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

/// Varied but deterministic field values, chosen to exercise edge cases:
/// negative/zero/large amounts, a large u64 nonce past 2^53, and
/// none/ascii/unicode memos.
fn amount_for(i: u32) -> i64 {
    match i % 4 {
        0 => 0,
        1 => 300,
        2 => -1500,
        _ => 9_000_000_000_000, // past 2^32, well within i64
    }
}

fn nonce_for(i: u32) -> u64 {
    match i % 3 {
        0 => u64::from(i),
        1 => 1_000_000 + u64::from(i),
        _ => 18_000_000_000_000_000_000 + u64::from(i), // past 2^53
    }
}

fn memo_for(i: u32) -> Option<String> {
    match i % 3 {
        0 => None,
        1 => Some(format!("lunch #{i}")),
        _ => Some(format!("caffè e brioche ☕ {i}")),
    }
}

fn memo_node(memo: &Option<String>) -> Value {
    match memo {
        Some(text) => json!({ "text": text }),
        None => json!({ "null": null }),
    }
}

fn build_vector(i: u32) -> ProposalVector {
    let sender_seed = derive("rrn-signed-payload-fixture:v1:sender:", i);
    let sender_kp = keypair_from_seed(sender_seed);
    let receiver_kp = keypair_from_seed(derive("rrn-signed-payload-fixture:v1:receiver:", i));
    let sender_pk = sender_kp.public_key();
    let receiver_pk = receiver_kp.public_key();

    let amount = amount_for(i);
    let memo = memo_for(i);
    let nonce = nonce_for(i);
    let proposed_at = 1_700_000_000_i64 + i64::from(i);
    let expires_at = proposed_at + 86_400;

    let proposal = TransactionProposal::new(
        Address::from_public_key(sender_pk),
        Address::from_public_key(receiver_pk),
        amount,
        memo.clone(),
        nonce,
        proposed_at,
        expires_at,
    );

    let canonical = to_canonical_bytes(proposal.clone());
    let signed = SignedPayload::sign(proposal, &sender_kp);

    // The tagged-value payload the mobile app builds for this proposal. Field
    // order is irrelevant — dCBOR sorts map keys — but it mirrors the struct.
    let payload = json!({ "map": [
        ["kind", { "text": PROPOSAL_KIND }],
        ["sender", { "bytes": hex::encode(sender_pk.to_bytes()) }],
        ["receiver", { "bytes": hex::encode(receiver_pk.to_bytes()) }],
        ["amount_centi", { "int": amount.to_string() }],
        ["memo", memo_node(&memo)],
        ["nonce", { "int": nonce.to_string() }],
        ["proposed_at", { "int": proposed_at.to_string() }],
        ["expires_at", { "int": expires_at.to_string() }],
    ]});

    // The heart of the cross-platform contract: the mobile tagged-JSON path must
    // yield the exact bytes the typed encoder produced.
    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "vector {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    ProposalVector {
        seed: hex::encode(sender_seed),
        sender_pubkey: hex::encode(sender_pk.to_bytes()),
        receiver_pubkey: hex::encode(receiver_pk.to_bytes()),
        amount_centi: amount.to_string(),
        memo,
        nonce: nonce.to_string(),
        proposed_at: proposed_at.to_string(),
        expires_at: expires_at.to_string(),
        payload,
        canonical_hex: hex::encode(canonical),
        signature_hex: hex::encode(signed.signature.to_bytes()),
    }
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform SignedPayload<TransactionProposal> vectors for T1.1.7. \
            Generated by rrn-ledger/tests/cross_platform_signed_payload.rs. `payload` is the \
            mobile tagged-value model; `canonical_hex` is the proposal's canonical dCBOR \
            (== From<TransactionProposal> for CBOR); `signature_hex` is the sender's Ed25519 \
            signature over those bytes. Mobile builds the same payload, canonicalizes it via \
            the canonical_bytes FFI, and signs — producing the identical signature, which \
            verifies on the station. Deterministic (blake3 seeds, RFC 8032); regenerate with \
            RRN_REGEN=1."
            .to_string(),
        vectors: (0..COUNT).map(build_vector).collect(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cross_platform_signed_payload.json")
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
    PublicKey::from_bytes(hex::decode(hex_pk).unwrap().as_slice().try_into().unwrap()).unwrap()
}

/// Rebuilds the proposal from a vector's recorded fields (as the mobile app's
/// inputs would), independent of the stored `payload`/`canonical_hex`.
fn proposal_from(v: &ProposalVector) -> TransactionProposal {
    TransactionProposal::new(
        Address::from_public_key(public_key(&v.sender_pubkey)),
        Address::from_public_key(public_key(&v.receiver_pubkey)),
        v.amount_centi.parse().unwrap(),
        v.memo.clone(),
        v.nonce.parse().unwrap(),
        v.proposed_at.parse().unwrap(),
        v.expires_at.parse().unwrap(),
    )
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
         --test cross_platform_signed_payload, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn tagged_json_matches_the_typed_encoder() {
    let fixture = load_committed();
    assert_eq!(fixture.vectors.len(), COUNT as usize);
    for v in &fixture.vectors {
        // The recorded payload canonicalizes (via the real FFI) to the recorded
        // bytes, and the typed encoder produces the same bytes from the fields.
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("payload must canonicalize");
        assert_eq!(
            hex::encode(&via_ffi),
            v.canonical_hex,
            "{}",
            v.sender_pubkey
        );
        let typed = to_canonical_bytes(proposal_from(v));
        assert_eq!(hex::encode(typed), v.canonical_hex, "{}", v.sender_pubkey);
    }
}

#[test]
fn signatures_are_reproducible_and_verify() {
    let fixture = load_committed();
    for v in &fixture.vectors {
        let seed: [u8; 32] = hex::decode(&v.seed).unwrap().as_slice().try_into().unwrap();
        let kp = keypair_from_seed(seed);
        assert_eq!(hex::encode(kp.public_key().to_bytes()), v.sender_pubkey);

        // Re-sign the reconstructed proposal: deterministic Ed25519 reproduces
        // the recorded signature byte-for-byte.
        let signed = SignedPayload::sign(proposal_from(v), &kp);
        assert_eq!(hex::encode(signed.signature.to_bytes()), v.signature_hex);
        // The station verifies the (identical to mobile's) signature.
        assert!(signed.verify().is_ok(), "{}", v.sender_pubkey);
    }
}
