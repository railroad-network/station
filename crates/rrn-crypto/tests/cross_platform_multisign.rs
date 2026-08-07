//! Cross-platform multisig vectors: the contract that mobile and station agree
//! on how a [`MultiSignedPayload`](rrn_crypto::signed::MultiSignedPayload) is
//! verified — which co-signers count, which structural shapes are rejected, and
//! how a threshold is applied on top (T1.9.3, ADR-0012).
//!
//! `SignedPayload`'s single-signer contract is pinned by `cross_platform_sign`.
//! This fixture pins the *composition* layered over it: given canonical payload
//! bytes and a list of `(signer, signature)` pairs, `verify()` returns the set
//! of **distinct valid signers**, rejecting a signer/signature count mismatch or
//! a duplicated signer outright. `message` here is the already-canonical payload
//! bytes (what `to_canonical_bytes(&payload)` produces), so this fixture is
//! independent of any particular payload schema — the Charter's CBOR shape is
//! pinned separately in `rrn-governance`. A signature that simply fails to verify
//! is not an error; it is excluded from the returned set.
//!
//! The fixture is regenerable but committed, so mobile CI needs no Rust
//! toolchain. Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-crypto --test cross_platform_multisign
//! then copy `tests/fixtures/cross_platform_multisign.json` into the mobile repo
//! at `__tests__/fixtures/cross_platform_multisign.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

/// One multisig verification case: canonical payload bytes, the co-signers and
/// their signatures, and the outcome `verify()` must produce — either a
/// structural `error`, or the `valid_signers` set plus whether it clears
/// `threshold`. All keys, signatures, and the message are hex-encoded.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Case {
    description: String,
    message: String,
    signers: Vec<String>,
    signatures: Vec<String>,
    /// `null`, `"count_mismatch"`, or `"duplicate_signer"`.
    error: Option<String>,
    /// Distinct valid signers in signer-list order; empty when `error` is set.
    valid_signers: Vec<String>,
    /// A caller-supplied threshold, to exercise the "caller applies its own
    /// threshold" contract; for the Charter this is `ceil(founders * 0.75)`.
    threshold: u32,
    /// `valid_signers.len() >= threshold`; `false` when `error` is set.
    meets_threshold: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    cases: Vec<Case>,
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

/// Deterministic 32-byte value from a domain-separated label and index. No RNG,
/// so every run — on any machine — produces byte-identical output.
fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

/// Deterministic co-signer #i.
fn signer(i: u32) -> Keypair {
    keypair_from_seed(derive("rrn-cross-platform-multisign:v1:signer:", i))
}

/// `ceil(n * 0.75)` — the Charter's founder threshold (ADR-0012), computed in
/// integer arithmetic so it matches on every platform.
fn founder_threshold(n: u32) -> u32 {
    n.saturating_mul(3).div_ceil(4)
}

/// Builds one case from the signers, the message each one *signs* (a signer who
/// signs a different message than `payload` contributes an invalid signature and
/// is dropped), and a threshold. Computes the expected outcome with raw
/// primitives — independent of `MultiSignedPayload::verify`, which must match.
fn case(
    description: &str,
    payload: &[u8],
    signed_by: &[(&Keypair, &[u8])],
    threshold: u32,
) -> Case {
    let signers: Vec<PublicKey> = signed_by.iter().map(|(kp, _)| kp.public_key()).collect();
    let signatures: Vec<Signature> = signed_by.iter().map(|(kp, msg)| kp.sign(msg)).collect();

    // Independent recomputation of the documented rule.
    let count_mismatch = signers.len() != signatures.len();
    let mut seen = std::collections::HashSet::new();
    let duplicate = signers.iter().any(|s| !seen.insert(s.to_bytes()));
    let error = if count_mismatch {
        Some("count_mismatch")
    } else if duplicate {
        Some("duplicate_signer")
    } else {
        None
    };

    let valid_signers: Vec<String> = if error.is_some() {
        Vec::new()
    } else {
        signers
            .iter()
            .zip(&signatures)
            .filter(|(pk, sig)| pk.verify(payload, sig).is_ok())
            .map(|(pk, _)| hex::encode(pk.to_bytes()))
            .collect()
    };
    let meets_threshold = error.is_none() && valid_signers.len() as u32 >= threshold;

    Case {
        description: description.to_string(),
        message: hex::encode(payload),
        signers: signers.iter().map(|s| hex::encode(s.to_bytes())).collect(),
        signatures: signatures
            .iter()
            .map(|s| hex::encode(s.to_bytes()))
            .collect(),
        error: error.map(str::to_string),
        valid_signers,
        threshold,
        meets_threshold,
    }
}

fn build_fixture() -> Fixture {
    let (a, b, c, d) = (signer(0), signer(1), signer(2), signer(3));
    // The document being co-signed, and a stale draft of it a signer might sign
    // by mistake — a signature over the draft does not verify against `charter`.
    let charter = derive("rrn-cross-platform-multisign:v1:payload:", 1).to_vec();
    let draft = derive("rrn-cross-platform-multisign:v1:payload:", 2).to_vec();

    let cases = vec![
        case(
            "four founders, all sign the charter (75% of 4 = 3, met)",
            &charter,
            &[
                (&a, &charter),
                (&b, &charter),
                (&c, &charter),
                (&d, &charter),
            ],
            founder_threshold(4),
        ),
        case(
            "four founders, one signed a stale draft: three valid, threshold met",
            &charter,
            &[(&a, &charter), (&b, &charter), (&c, &charter), (&d, &draft)],
            founder_threshold(4),
        ),
        case(
            "four founders, only two valid: threshold not met",
            &charter,
            &[(&a, &charter), (&b, &charter), (&c, &draft), (&d, &draft)],
            founder_threshold(4),
        ),
        case(
            "duplicate signer is rejected outright",
            &charter,
            &[(&a, &charter), (&a, &charter), (&b, &charter)],
            founder_threshold(3),
        ),
        // A count mismatch cannot be built through `case` (it pairs each signer
        // with a signature), so it is assembled directly below.
        {
            let mut mismatched = case(
                "signer/signature count mismatch is rejected",
                &charter,
                &[(&a, &charter), (&b, &charter), (&c, &charter)],
                founder_threshold(3),
            );
            mismatched.signatures.pop();
            mismatched.error = Some("count_mismatch".to_string());
            mismatched.valid_signers = Vec::new();
            mismatched.meets_threshold = false;
            mismatched
        },
        case(
            "a single founder signs (75% of 1 = 1, met)",
            &charter,
            &[(&a, &charter)],
            founder_threshold(1),
        ),
        case(
            "no signatures: threshold not met, no error",
            &charter,
            &[],
            founder_threshold(1),
        ),
    ];

    Fixture {
        comment: "Cross-platform multisig verification vectors for T1.9.3 \
            (ADR-0012). Generated by rrn-crypto/tests/cross_platform_multisign.rs. \
            `message` is the canonical payload bytes that each signature covers; \
            verify() returns the distinct valid signers (a bad signature is \
            excluded, not an error), rejects count_mismatch and duplicate_signer, \
            and the caller applies `threshold` (ceil(founders*0.75) for a \
            Charter). Regenerate with RRN_REGEN=1."
            .to_string(),
        cases,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_multisign.json")
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
         --test cross_platform_multisign, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// Re-derive the outcome of every committed case from its raw bytes: the
/// distinct valid signers, the structural rejections, and the threshold verdict
/// must all match what is recorded. This is the invariant mobile reproduces.
#[test]
fn every_case_matches_its_recorded_outcome() {
    let fixture = load_committed();
    for c in &fixture.cases {
        let msg = hex::decode(&c.message).unwrap();

        // Structural checks first, exactly as verify() orders them.
        if c.signers.len() != c.signatures.len() {
            assert_eq!(
                c.error.as_deref(),
                Some("count_mismatch"),
                "{}",
                c.description
            );
            assert!(
                c.valid_signers.is_empty() && !c.meets_threshold,
                "{}",
                c.description
            );
            continue;
        }
        let mut seen = std::collections::HashSet::new();
        let has_dup = c.signers.iter().any(|s| !seen.insert(s.clone()));
        if has_dup {
            assert_eq!(
                c.error.as_deref(),
                Some("duplicate_signer"),
                "{}",
                c.description
            );
            assert!(
                c.valid_signers.is_empty() && !c.meets_threshold,
                "{}",
                c.description
            );
            continue;
        }

        assert_eq!(c.error, None, "{}", c.description);
        let recomputed: Vec<String> = c
            .signers
            .iter()
            .zip(&c.signatures)
            .filter(|(pk, sig)| public_key(pk).verify(&msg, &signature(sig)).is_ok())
            .map(|(pk, _)| pk.clone())
            .collect();
        assert_eq!(recomputed, c.valid_signers, "{}", c.description);
        assert_eq!(
            c.valid_signers.len() as u32 >= c.threshold,
            c.meets_threshold,
            "{}",
            c.description
        );
    }
}

/// Spot-check the shapes we care about are actually present, so a future edit
/// that quietly drops a case is caught.
#[test]
fn covers_the_expected_shapes() {
    let fixture = load_committed();
    let errors: Vec<_> = fixture
        .cases
        .iter()
        .filter_map(|c| c.error.as_deref())
        .collect();
    assert!(errors.contains(&"count_mismatch"));
    assert!(errors.contains(&"duplicate_signer"));
    // A four-of-four met, a three-of-four met, and a two-of-four missed.
    assert!(fixture
        .cases
        .iter()
        .any(|c| c.valid_signers.len() == 4 && c.meets_threshold));
    assert!(fixture
        .cases
        .iter()
        .any(|c| c.valid_signers.len() == 3 && c.threshold == 3 && c.meets_threshold));
    assert!(fixture
        .cases
        .iter()
        .any(|c| c.valid_signers.len() == 2 && c.threshold == 3 && !c.meets_threshold));
}
