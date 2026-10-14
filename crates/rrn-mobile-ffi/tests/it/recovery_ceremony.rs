//! Cross-platform recovery-ceremony FFI fixtures and a full requester round trip.
//!
//! The mobile app rebuilds a lost key on a new device through `RecoverySession`
//! (ADR-0016). Two things must hold cross-platform:
//!
//!  1. the **ceremony fingerprint** the app displays (and every holder confirms)
//!     is byte-identical to what the Rust core computes — a deterministic vector
//!     table (`tests/fixtures/recovery_fingerprint.json`) the mobile repo
//!     asserts its displayed code against;
//!  2. the requester surface reconstructs the original identity from holder
//!     responses, and never returns a wrong key below the threshold.
//!
//! Regenerate the fixture with:
//!   RRN_REGEN=1 cargo test -p rrn-mobile-ffi --test it recovery_ceremony
//! then copy `tests/fixtures/recovery_fingerprint.json` into the mobile repo.

use std::path::PathBuf;
use std::sync::Arc;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_identity::address::Address;
use rrn_identity::recovery::ceremony::{fingerprint, RecoveryRequest};
use rrn_mobile_ffi::{
    parse_recovery_request, respond_to_recovery, RecoveryError, RecoveryPackage, RecoverySession,
    WalletContents,
};
use serde::{Deserialize, Serialize};

// --- deterministic seeding (same idiom as cross_platform_dtn_certs) ---------

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair(label: &str, i: u32) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(derive(label, i)))
}

// --- fixture ----------------------------------------------------------------

/// The construction, stated in the fixture so a reader on either platform sees
/// what the vectors pin (`docs/spec/vmk-boot-ceremony.md`).
const CONSTRUCTION: &str = "blake3(\"rrn.ceremony.fingerprint.v2\" ‖ request canonical bytes), \
                            first 80 bits, Crockford base32, 4×4";

/// The fixture's `vmk-spec-vector` value, also pinned by the spec and by
/// `rrn-station`'s `vmk::tests::fingerprint_pinned_spec_vector`.
const VMK_SPEC_FINGERPRINT: &str = "E26N-ZE0W-1TX8-Z4KF";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct FingerprintVector {
    /// What the vector exercises.
    label: String,
    /// The ephemeral recovery public key, hex.
    recovery_pubkey_hex: String,
    /// The identity the request targets (`rrn1…`).
    target_address: String,
    /// The request's canonical bytes, hex — what the app decodes from the QR,
    /// and what the fingerprint hashes.
    request_hex: String,
    /// The rendered `XXXX-XXXX-XXXX-XXXX` fingerprint.
    fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    construction: String,
    vectors: Vec<FingerprintVector>,
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recovery_fingerprint.json")
}

fn vector(label: &str, recovery: &Keypair, target: Address) -> FingerprintVector {
    let request = RecoveryRequest {
        recovery_pubkey: recovery.public_key(),
        target_address: target,
    };
    FingerprintVector {
        label: label.to_string(),
        recovery_pubkey_hex: hex::encode(recovery.public_key().to_bytes()),
        target_address: target.to_string(),
        request_hex: hex::encode(request.to_bytes()),
        fingerprint: fingerprint(&request),
    }
}

fn address(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

/// Builds the fixture deterministically: three member ceremonies (distinct
/// recovery keys and distinct targets), one that reuses the first recovery key
/// against a different target (its code must differ — the fingerprint binds the
/// target), and the spec's VMK unlock vector.
fn build_fixture() -> Fixture {
    let mut vectors: Vec<FingerprintVector> = (0..3)
        .map(|i| {
            vector(
                &format!("member-{i}"),
                &keypair("recovery-fingerprint", i),
                address(&keypair("recovery-fingerprint-target", i)),
            )
        })
        .collect();
    vectors.push(vector(
        "member-0-other-target",
        &keypair("recovery-fingerprint", 0),
        address(&keypair("recovery-fingerprint-target", 3)),
    ));
    vectors.push(vector(
        "vmk-spec-vector",
        &Keypair::from_secret(SecretKey::from_bytes([1u8; 32])),
        address(&Keypair::from_secret(SecretKey::from_bytes([2u8; 32]))),
    ));
    Fixture {
        construction: CONSTRUCTION.to_string(),
        vectors,
    }
}

fn load_committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    serde_json::from_str(&text).expect("fixture parses")
}

#[test]
fn fingerprint_fixture_is_stable_across_platforms() {
    let generated = build_fixture();
    let json = serde_json::to_string_pretty(&generated).unwrap() + "\n";

    if std::env::var("RRN_REGEN").is_ok() {
        std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
        std::fs::write(fixture_path(), &json).unwrap();
    }

    let committed = load_committed();
    assert_eq!(
        generated, committed,
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-mobile-ffi \
         --test it recovery_ceremony"
    );

    // The FFI's `parse_recovery_request` must surface exactly the committed code
    // and target for each vector's request bytes: this is what a holder's screen
    // shows.
    for v in &committed.vectors {
        let info = parse_recovery_request(hex::decode(&v.request_hex).unwrap()).unwrap();
        assert_eq!(info.fingerprint, v.fingerprint, "{}", v.label);
        assert_eq!(info.target_address, v.target_address, "{}", v.label);
    }

    // Same recovery key, different target: a different ceremony, a different code.
    let by_label = |l: &str| committed.vectors.iter().find(|v| v.label == l).unwrap();
    let (base, other) = (by_label("member-0"), by_label("member-0-other-target"));
    assert_eq!(base.recovery_pubkey_hex, other.recovery_pubkey_hex);
    assert_ne!(base.fingerprint, other.fingerprint);

    // The VMK vector is the value the spec and the station's unlock test pin.
    assert_eq!(
        by_label("vmk-spec-vector").fingerprint,
        VMK_SPEC_FINGERPRINT
    );
}

// --- full requester round trip ---------------------------------------------

/// Split `owner` across `n` holders K-of-N; return the holders and the
/// distributable shard payloads.
fn arm(owner: Arc<WalletContents>, n: usize, k: u8) -> (Vec<Arc<WalletContents>>, Vec<Vec<u8>>) {
    let holders: Vec<Arc<WalletContents>> = (0..n)
        .map(|_| Arc::new(WalletContents::create_new()))
        .collect();
    let addrs: Vec<String> = holders.iter().map(|h| h.address()).collect();
    let package = RecoveryPackage::create(owner, addrs, k).expect("create package");
    let payloads = (0..n)
        .map(|i| package.shard_payload(i as u32).expect("shard payload"))
        .collect();
    (holders, payloads)
}

#[test]
fn ffi_session_reconstructs_the_original_identity() {
    let owner = Arc::new(WalletContents::create_new());
    let owner_address = owner.address();
    let (holders, payloads) = arm(owner, 5, 3);

    let session = RecoverySession::new(owner_address.clone()).unwrap();

    // The confirm-screen fingerprint (parse_recovery_request over the published
    // request) matches the session's own — the code both sides display.
    let info = parse_recovery_request(session.request_payload()).unwrap();
    assert_eq!(info.fingerprint, session.fingerprint());
    assert_eq!(info.target_address, owner_address);

    let request = session.request_payload();

    // Two responses (below K=3) → still needs more, never a wrong key.
    for i in [0usize, 1] {
        let resp =
            respond_to_recovery(holders[i].clone(), payloads[i].clone(), request.clone()).unwrap();
        session.add_response(resp).unwrap();
    }
    assert_eq!(session.responses(), 2);
    assert!(matches!(
        session.reconstruct(),
        Err(RecoveryError::NeedMoreResponses)
    ));

    // A third response crosses the threshold → the original identity is rebuilt.
    let resp =
        respond_to_recovery(holders[4].clone(), payloads[4].clone(), request.clone()).unwrap();
    session.add_response(resp).unwrap();
    let recovered = session.reconstruct().unwrap();
    assert_eq!(recovered.address(), owner_address);
}

#[test]
fn ffi_session_rejects_a_response_from_another_ceremony() {
    let owner = Arc::new(WalletContents::create_new());
    let owner_address = owner.address();
    let (holders, payloads) = arm(owner, 3, 2);

    let session = RecoverySession::new(owner_address.clone()).unwrap();
    let other = RecoverySession::new(owner_address).unwrap();

    // A response built against another ceremony's request cannot be opened here.
    let foreign = respond_to_recovery(
        holders[0].clone(),
        payloads[0].clone(),
        other.request_payload(),
    )
    .unwrap();
    assert!(matches!(
        session.add_response(foreign),
        Err(RecoveryError::Corrupt)
    ));
    assert_eq!(session.responses(), 0);
}

#[test]
fn ffi_session_rejects_a_malformed_target() {
    assert!(matches!(
        RecoverySession::new("not-an-address".to_string()),
        Err(RecoveryError::InvalidHolderAddress)
    ));
}
