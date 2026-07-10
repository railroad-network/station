//! Consolidated cross-platform FFI invariants (T1.1.6).
//!
//! T1.1.3–T1.1.5 each locked one slice of the mobile/station contract in its
//! own fixture (address parity, signing parity, wallet-file parity). This test
//! rolls the *invariants* those slices rest on into a single suite that both
//! sides run against one committed fixture, and adds the one invariant no prior
//! fixture covered: **Blake3 hash determinism** across the boundary.
//!
//! Every operation here reaches the same Rust core the mobile app reaches
//! through the uniffi FFI (`rrn-mobile-ffi`) — `rrn_crypto` for hashing/signing,
//! `rrn_identity` for addresses/wallets — so there is exactly one implementation
//! of each primitive. The mobile side reads the same committed JSON and asserts
//! the identical invariants; see `mobile/__tests__/ffi_invariants.test.ts`.
//!
//! Invariants covered:
//!   1. Address roundtrip   — pubkey → address → pubkey (bytes identical)
//!   2. Signature roundtrip — sign → verify (succeeds), bytes reproducible
//!   3. Signature tamper    — any bit flip in sig/message, or wrong key, fails
//!   4. Hash determinism    — same input → same Blake3 hash (bytes + hex)
//!   5. Wallet roundtrip    — encrypt → bytes → decrypt → identity matches
//!
//! Deliberately NOT here: generic dcbor canonical-bytes determinism. That needs
//! a `canonical_bytes` FFI surface which does not exist yet — it is a T1.1.7
//! deliverable — and the only dcbor bytes crossing the boundary today
//! (`EncryptedWallet::to_bytes`) are randomized per encrypt, so they cannot back
//! a "same struct → same bytes" check. The dcbor invariant lands in T1.1.7 with
//! its surface.
//!
//! Like the wallet fixture, the `wallet_roundtrip` section is **not**
//! bit-reproducible (fresh salt + nonce per encrypt); every other section is.
//! Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-identity --test ffi_invariants
//! then copy `tests/fixtures/ffi_invariants.json` into the mobile repo at
//! `__tests__/fixtures/ffi_invariants.json`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey, Signature};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_identity::address::Address;
use rrn_identity::wallet::{EncryptedWallet, WalletContents, WalletError};
use serde::{Deserialize, Serialize};

/// Random-but-deterministic cases per reproducible invariant.
const CASE_COUNT: u32 = 100;

/// Wallets are kept small: each encrypt/decrypt runs argon2id at 64 MiB, so a
/// hundred would make the suite slow for no extra coverage — the format is the
/// same for every wallet.
const WALLET_COUNT: u32 = 8;

/// The standard Blake3 hash of the empty input, locked as a backend tripwire: if
/// this changes, the hashing primitive changed, which needs an ADR, not a
/// fixture edit.
const BLAKE3_EMPTY_HEX: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

/// pubkey → address → pubkey.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct AddressVector {
    seed: String,
    pubkey: String,
    address: String,
}

/// (seed, message) → deterministic Ed25519 signature.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SignVector {
    seed: String,
    pubkey: String,
    message: String,
    signature: String,
}

/// A (pubkey, message, signature) triple the verifier must reject.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Tampered {
    pubkey: String,
    message: String,
    signature: String,
    reason: String,
}

/// input → Blake3 hash. `hash` is the hex of the 32 raw bytes, which is exactly
/// what `Hash::to_hex` returns — the mobile side checks both accessors against it.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HashVector {
    input: String,
    hash: String,
}

/// One wallet vector: a deterministic identity plus its randomized sealed bytes.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct WalletVector {
    seed: String,
    passphrase: String,
    created_at: i64,
    metadata: BTreeMap<String, String>,
    address: String,
    pubkey: String,
    encrypted: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    address_roundtrip: Vec<AddressVector>,
    signing: Vec<SignVector>,
    signing_tamper: Vec<Tampered>,
    hashing: Vec<HashVector>,
    hashing_known_answer: Vec<HashVector>,
    /// A passphrase guaranteed to differ from every wallet's — for the
    /// wrong-passphrase rejection check.
    wrong_passphrase: String,
    wallet_roundtrip: Vec<WalletVector>,
}

/// The deterministic (bit-reproducible) half of the fixture — everything except
/// the randomized wallet blobs. Pulled out so drift detection can compare it by
/// value while the wallet section is checked by invariant only.
#[derive(Debug, PartialEq, Eq)]
struct Deterministic {
    address_roundtrip: Vec<AddressVector>,
    signing: Vec<SignVector>,
    signing_tamper: Vec<Tampered>,
    hashing: Vec<HashVector>,
    hashing_known_answer: Vec<HashVector>,
}

/// Deterministic 32-byte value from a domain-separated label and index. No RNG,
/// so every run — on any machine — produces byte-identical output. The labels
/// are distinct from the other fixtures' so this is an independent generation,
/// not a copy of them.
fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

fn address_vector(seed: [u8; 32]) -> AddressVector {
    let pk = keypair_from_seed(seed).public_key();
    AddressVector {
        seed: hex::encode(seed),
        pubkey: hex::encode(pk.to_bytes()),
        address: Address::from_public_key(pk).to_string(),
    }
}

/// Deterministic message #i: the first `i % 33` bytes of a derived hash, so
/// lengths sweep 0..=32 (vector 0 is the empty message — a real edge case).
fn sign_message(i: u32) -> Vec<u8> {
    let len = (i % 33) as usize;
    derive("rrn-ffi-invariants:v1:sign-msg:", i)[..len].to_vec()
}

fn sign_vector(seed: [u8; 32], message: &[u8]) -> SignVector {
    let kp = keypair_from_seed(seed);
    SignVector {
        seed: hex::encode(seed),
        pubkey: hex::encode(kp.public_key().to_bytes()),
        message: hex::encode(message),
        signature: hex::encode(kp.sign(message).to_bytes()),
    }
}

/// A 64-byte deterministic buffer (two domain-separated derives concatenated),
/// so hash inputs can sweep lengths past a single 32-byte hash.
fn derive_wide(label: &str, i: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&derive(label, i));
    out[32..].copy_from_slice(&derive(label, i ^ 0x8000_0000));
    out
}

/// Deterministic hash input #i: the first `i % 65` bytes of a 64-byte derived
/// buffer, so lengths sweep 0..=64 (vector 0 is the empty input).
fn hash_input(i: u32) -> Vec<u8> {
    let len = (i % 65) as usize;
    derive_wide("rrn-ffi-invariants:v1:hash-input:", i)[..len].to_vec()
}

fn hash_vector(input: &[u8]) -> HashVector {
    HashVector {
        input: hex::encode(input),
        hash: Hash::of(input).to_hex(),
    }
}

fn metadata_for(i: u32) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("label".to_string(), format!("wallet-{i}"));
    m.insert("device".to_string(), "phone".to_string());
    m
}

fn wallet_contents(i: u32) -> WalletContents {
    let seed = derive("rrn-ffi-invariants:v1:wallet-seed:", i);
    let keypair = keypair_from_seed(seed);
    let address = Address::from_public_key(keypair.public_key());
    // All WalletContents fields are public, so the fixture pins a chosen
    // deterministic identity rather than the random one `create_new` produces.
    WalletContents {
        secret_key: keypair.secret_key().clone(),
        address,
        created_at: 1_700_000_000 + i64::from(i),
        metadata: metadata_for(i),
    }
}

fn build_deterministic() -> Deterministic {
    let address_roundtrip: Vec<AddressVector> = (0..CASE_COUNT)
        .map(|i| address_vector(derive("rrn-ffi-invariants:v1:addr-seed:", i)))
        .collect();

    let signing: Vec<SignVector> = (0..CASE_COUNT)
        .map(|i| {
            sign_vector(
                derive("rrn-ffi-invariants:v1:sign-seed:", i),
                &sign_message(i),
            )
        })
        .collect();

    // Tamper triples derived from the first two signing vectors — reproducible,
    // so they live in the deterministic half and are drift-checked.
    let v0 = &signing[0];
    let v1 = &signing[1];
    let flip_last_bit = |hex_sig: &str| {
        let mut bytes = hex::decode(hex_sig).unwrap();
        *bytes.last_mut().unwrap() ^= 0x01;
        hex::encode(bytes)
    };
    let signing_tamper = vec![
        Tampered {
            pubkey: v0.pubkey.clone(),
            message: v0.message.clone(),
            signature: flip_last_bit(&v0.signature),
            reason: "signature with one bit flipped".to_string(),
        },
        Tampered {
            pubkey: v0.pubkey.clone(),
            message: v1.message.clone(),
            signature: v0.signature.clone(),
            reason: "valid signature over a different message".to_string(),
        },
        Tampered {
            pubkey: v1.pubkey.clone(),
            message: v0.message.clone(),
            signature: v0.signature.clone(),
            reason: "valid signature checked against the wrong public key".to_string(),
        },
    ];

    let hashing: Vec<HashVector> = (0..CASE_COUNT)
        .map(|i| hash_vector(&hash_input(i)))
        .collect();

    let hashing_known_answer = vec![hash_vector(&[]), hash_vector(b"railroad network")];

    Deterministic {
        address_roundtrip,
        signing,
        signing_tamper,
        hashing,
        hashing_known_answer,
    }
}

fn build_fixture() -> Fixture {
    let det = build_deterministic();

    let wallet_roundtrip = (0..WALLET_COUNT)
        .map(|i| {
            let contents = wallet_contents(i);
            let passphrase = format!("wallet-pass-{i}-🚂");
            let sealed =
                EncryptedWallet::encrypt(&contents, &passphrase).expect("encrypt must succeed");
            WalletVector {
                seed: hex::encode(contents.secret_key.to_bytes()),
                passphrase,
                created_at: contents.created_at,
                metadata: contents.metadata.clone(),
                address: contents.address.to_string(),
                pubkey: hex::encode(
                    Keypair::from_secret(contents.secret_key.clone())
                        .public_key()
                        .to_bytes(),
                ),
                encrypted: hex::encode(to_canonical_bytes(sealed)),
            }
        })
        .collect();

    Fixture {
        comment: "Consolidated cross-platform FFI invariants for T1.1.6. Generated by \
            rrn-identity/tests/ffi_invariants.rs. Rolls the address (ADR-0003), signing \
            (ADR-0001), and wallet-file (M0.3.3) invariants into one suite and adds \
            Blake3 hash determinism; mobile reaches the same Rust core via rrn-mobile-ffi \
            and asserts the identical invariants. The address/signing/hashing sections are \
            blake3-derived and bit-reproducible; the wallet `encrypted` bytes are randomized \
            per encrypt (argon2id + XChaCha20-Poly1305). dcbor canonical-bytes determinism is \
            deferred to T1.1.7 (its FFI surface). Regenerate with RRN_REGEN=1."
            .to_string(),
        address_roundtrip: det.address_roundtrip,
        signing: det.signing,
        signing_tamper: det.signing_tamper,
        hashing: det.hashing,
        hashing_known_answer: det.hashing_known_answer,
        wrong_passphrase: "definitely-not-any-wallet-passphrase".to_string(),
        wallet_roundtrip,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ffi_invariants.json")
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

fn signature(hex_sig: &str) -> Signature {
    Signature::from_bytes(hex::decode(hex_sig).unwrap().as_slice().try_into().unwrap()).unwrap()
}

fn deterministic_of(f: &Fixture) -> Deterministic {
    Deterministic {
        address_roundtrip: f
            .address_roundtrip
            .iter()
            .map(|v| AddressVector {
                seed: v.seed.clone(),
                pubkey: v.pubkey.clone(),
                address: v.address.clone(),
            })
            .collect(),
        signing: f
            .signing
            .iter()
            .map(|v| SignVector {
                seed: v.seed.clone(),
                pubkey: v.pubkey.clone(),
                message: v.message.clone(),
                signature: v.signature.clone(),
            })
            .collect(),
        signing_tamper: f
            .signing_tamper
            .iter()
            .map(|t| Tampered {
                pubkey: t.pubkey.clone(),
                message: t.message.clone(),
                signature: t.signature.clone(),
                reason: t.reason.clone(),
            })
            .collect(),
        hashing: f
            .hashing
            .iter()
            .map(|h| HashVector {
                input: h.input.clone(),
                hash: h.hash.clone(),
            })
            .collect(),
        hashing_known_answer: f
            .hashing_known_answer
            .iter()
            .map(|h| HashVector {
                input: h.input.clone(),
                hash: h.hash.clone(),
            })
            .collect(),
    }
}

#[test]
fn regenerate_fixture_when_requested() {
    if std::env::var("RRN_REGEN").is_ok() {
        std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
        std::fs::write(fixture_path(), serialize(&build_fixture())).unwrap();
    }
    let fixture = load_committed();
    assert_eq!(fixture.address_roundtrip.len(), CASE_COUNT as usize);
    assert_eq!(fixture.signing.len(), CASE_COUNT as usize);
    assert_eq!(fixture.hashing.len(), CASE_COUNT as usize);
    assert_eq!(fixture.wallet_roundtrip.len(), WALLET_COUNT as usize);
    assert!(!fixture.wrong_passphrase.is_empty());
}

#[test]
fn deterministic_sections_match_generator() {
    // Everything but the randomized wallet blobs must equal what the generator
    // produces now — a stale fixture cannot pass CI unnoticed. (The wallet
    // section is checked by invariant instead, below.)
    let committed = deterministic_of(&load_committed());
    assert_eq!(
        committed,
        build_deterministic(),
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-identity \
         --test ffi_invariants, then copy the JSON into the mobile repo"
    );
}

#[test]
fn deterministic_generation_is_stable() {
    // The cross-platform contract for the reproducible sections rests on this.
    assert_eq!(build_deterministic(), build_deterministic());
}

#[test]
fn addresses_roundtrip_to_identical_public_keys() {
    for v in &load_committed().address_roundtrip {
        // address → public key, byte-for-byte equal to the recorded pubkey.
        let parsed: Address = v.address.parse().expect("fixture address must parse");
        assert_eq!(
            hex::encode(parsed.public_key().to_bytes()),
            v.pubkey,
            "{}",
            v.address
        );
        // public key → address, byte-for-byte equal to the recorded address.
        assert_eq!(
            Address::from_public_key(public_key(&v.pubkey)).to_string(),
            v.address
        );
    }
}

#[test]
fn signatures_are_reproducible_and_verify() {
    for v in &load_committed().signing {
        let seed: [u8; 32] = hex::decode(&v.seed).unwrap().as_slice().try_into().unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let kp = keypair_from_seed(seed);
        assert_eq!(hex::encode(kp.public_key().to_bytes()), v.pubkey);
        // Deterministic (RFC 8032): signing the same message reproduces the bytes.
        assert_eq!(
            hex::encode(kp.sign(&msg).to_bytes()),
            v.signature,
            "{}",
            v.seed
        );
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
fn tampered_signatures_are_rejected() {
    let fixture = load_committed();
    assert!(!fixture.signing_tamper.is_empty());
    for t in &fixture.signing_tamper {
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
fn hashes_are_deterministic_and_locked() {
    let fixture = load_committed();
    for h in fixture
        .hashing
        .iter()
        .chain(fixture.hashing_known_answer.iter())
    {
        let input = hex::decode(&h.input).unwrap();
        let hash = Hash::of(&input);
        // Recomputing the hash reproduces the recorded value, and to_bytes and
        // to_hex agree (to_hex is the hex of to_bytes).
        assert_eq!(hash.to_hex(), h.hash, "input {}", h.input);
        assert_eq!(hex::encode(hash.to_bytes()), h.hash, "input {}", h.input);
    }
    // The empty-input Blake3 hash is a well-known constant — lock it as a
    // tripwire against a hashing-backend swap.
    let empty = &fixture.hashing_known_answer[0];
    assert_eq!(empty.input, "");
    assert_eq!(empty.hash, BLAKE3_EMPTY_HEX);
}

#[test]
fn wallets_decrypt_to_recorded_identity() {
    for w in &load_committed().wallet_roundtrip {
        let bytes = hex::decode(&w.encrypted).expect("valid hex");
        let sealed: EncryptedWallet =
            from_canonical_bytes(&bytes).expect("committed wallet must parse");
        let opened = sealed
            .decrypt(&w.passphrase)
            .expect("committed wallet must decrypt");
        assert_eq!(hex::encode(opened.secret_key.to_bytes()), w.seed);
        assert_eq!(opened.address.to_string(), w.address);
        assert_eq!(
            hex::encode(
                Keypair::from_secret(opened.secret_key.clone())
                    .public_key()
                    .to_bytes()
            ),
            w.pubkey
        );
        assert_eq!(opened.created_at, w.created_at);
        assert_eq!(opened.metadata, w.metadata);
    }
}

#[test]
fn wrong_passphrase_and_tampered_wallet_are_rejected() {
    let fixture = load_committed();
    let w = &fixture.wallet_roundtrip[0];

    let sealed: EncryptedWallet =
        from_canonical_bytes(&hex::decode(&w.encrypted).unwrap()).unwrap();
    let err = sealed.decrypt(&fixture.wrong_passphrase).unwrap_err();
    assert!(matches!(err, WalletError::Decrypt), "{err:?}");

    let mut tampered = hex::decode(&w.encrypted).unwrap();
    *tampered.last_mut().unwrap() ^= 0x01;
    // Either the CBOR no longer parses, or the AEAD tag fails — either way, no
    // identity comes out.
    let opened = match from_canonical_bytes::<EncryptedWallet>(&tampered) {
        Ok(sealed) => sealed.decrypt(&w.passphrase).is_ok(),
        Err(_) => false,
    };
    assert!(!opened, "tampered wallet bytes must not yield an identity");
}
