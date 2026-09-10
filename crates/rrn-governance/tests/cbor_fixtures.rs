//! Canonical dCBOR fixtures for the governance record kinds (T2.1.3).
//!
//! Each governance signed record has a committed hex of its canonical bytes, so a
//! second implementation (the mobile repo signs co-signatures and ballots; the
//! station signs the window attestation) can prove it produces **byte-identical**
//! encodings (ADR-0002). Covers `rrn.gov.proposal`, `rrn.gov.proposal_cosign`,
//! `rrn.gov.vote`, and the T2.1.3 `rrn.gov.proposal_window` attestation. The
//! proposal fixture also guards the T2.1.3 shape change: the window fields are
//! **not** in the signed content.
//!
//! Deterministic (blake3-seeded keypairs). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-governance --test cbor_fixtures

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_governance::emergency::{
    EmergencyActivated, EmergencyCosign, EmergencyDeclaration, EmergencyDeclarationAdmitted,
    EmergencyLapse, EmergencyRefused,
};
use rrn_governance::proposal::{Proposal, ProposalCosign, ProposalKind};
use rrn_governance::vote::{Vote, VoteChoice};
use rrn_governance::window::ProposalWindow;
use rrn_identity::address::Address;
use std::path::PathBuf;

fn seed(label: &str) -> [u8; 32] {
    Hash::of(label.as_bytes()).to_bytes()
}

fn kp(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed(label)))
}

fn addr(label: &str) -> Address {
    Address::from_public_key(kp(label).public_key())
}

const AT: i64 = 1_700_000_000;

fn sample_proposal() -> Proposal {
    Proposal::new(
        addr("author"),
        "Quiet hours in the workshop".into(),
        "No power tools after 9pm.".into(),
        ProposalKind::Statute,
        AT,
    )
    .unwrap()
}

fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let proposal = sample_proposal();
    let pid = proposal.proposal_id;

    let cosign = ProposalCosign {
        proposal_id: pid,
        cosigner: addr("cosigner"),
        cosigned_at: AT,
    };
    let vote = Vote {
        proposal_id: pid,
        voter: addr("voter"),
        choice: VoteChoice::Yes,
        cast_at: AT,
    };
    let window = ProposalWindow {
        proposal_id: pid,
        admitted_at: AT,
        voting_ends_at: AT + 7 * 86_400,
        implementation_at: AT + 14 * 86_400,
        charter_hash: Hash::of(b"effective-charter"),
    };

    // Emergency-governance record kinds (ADR-0023). An initial declaration
    // (no `previous_declaration_hash`), a co-signature toward it, a lapse against
    // it, and the station-signed activation attestation — all byte-locked for the
    // mobile repo.
    let declaration = EmergencyDeclaration {
        community_id: "commons".into(),
        author: addr("author"),
        reason: "storm surge; grid down".into(),
        scope: "flood-response".into(),
        duration_secs: 72 * 3600,
        stated_renewal_index: 0,
        previous_declaration_hash: None,
        created_at: AT,
    };
    let decl_hash = declaration.hash();
    let em_cosign = EmergencyCosign {
        declaration_hash: decl_hash,
        signer: addr("cosigner"),
    };
    let em_lapse = EmergencyLapse {
        declaration_hash: decl_hash,
        author: addr("author"),
    };
    let activated = EmergencyActivated {
        declaration_hash: decl_hash,
        activation_instant: AT,
        scheduled_expiry: AT + 72 * 3600,
        renewal_count: 0,
    };
    // The two ADR-0027 station-signed kinds: a cap-refusal marker (D1b) and the
    // eager admission anchor (D2) — byte-locked for the mobile repo, which decodes
    // both but never produces them.
    let refused = EmergencyRefused {
        declaration_hash: decl_hash,
        refused_instant: AT,
    };
    let declaration_admitted = EmergencyDeclarationAdmitted {
        declaration_hash: decl_hash,
        admitted_at: AT,
    };

    vec![
        ("rrn.gov.proposal", to_canonical_bytes(proposal)),
        ("rrn.gov.proposal_cosign", to_canonical_bytes(cosign)),
        ("rrn.gov.vote", to_canonical_bytes(vote)),
        ("rrn.gov.proposal_window", to_canonical_bytes(window)),
        (
            "rrn.gov.emergency_declaration",
            to_canonical_bytes(declaration),
        ),
        ("rrn.gov.emergency_cosign", to_canonical_bytes(em_cosign)),
        ("rrn.gov.emergency_lapse", to_canonical_bytes(em_lapse)),
        ("rrn.gov.emergency_activated", to_canonical_bytes(activated)),
        ("rrn.gov.emergency_refused", to_canonical_bytes(refused)),
        (
            "rrn.gov.emergency_declaration_admitted",
            to_canonical_bytes(declaration_admitted),
        ),
    ]
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cbor_fixtures.json")
}

#[test]
fn governance_records_match_committed_cbor_fixtures() {
    let current: Vec<(String, String)> = fixtures()
        .into_iter()
        .map(|(k, b)| (k.to_string(), hex::encode(b)))
        .collect();

    if std::env::var("RRN_REGEN").is_ok() {
        let json = serde_json::to_string_pretty(
            &current
                .iter()
                .map(|(k, h)| serde_json::json!({ "kind": k, "hex": h }))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
        std::fs::write(fixture_path(), json + "\n").unwrap();
        return;
    }

    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_path())
            .expect("missing tests/fixtures/cbor_fixtures.json — regenerate with RRN_REGEN=1"),
    )
    .unwrap();
    let committed = committed.as_array().unwrap();
    assert_eq!(committed.len(), current.len(), "fixture count drifted");
    for (i, (kind, hex)) in current.iter().enumerate() {
        assert_eq!(committed[i]["kind"].as_str().unwrap(), kind);
        assert_eq!(
            committed[i]["hex"].as_str().unwrap(),
            hex,
            "canonical CBOR for {kind} changed — a signed-shape change; regenerate \
             the fixture and hand it to the mobile repo, or revert the change"
        );
    }
}

#[test]
fn the_signed_proposal_excludes_the_window_fields() {
    // The T2.1.3 guard: voting_ends_at/implementation_at are NOT in the signed
    // content, so populating them does not change the canonical bytes (nor, hence,
    // the content-addressed proposal_id).
    let a = sample_proposal();
    let mut b = a.clone();
    b.voting_ends_at = 999;
    b.implementation_at = 999;
    assert_eq!(
        to_canonical_bytes(a),
        to_canonical_bytes(b),
        "the window fields must not be part of the signed proposal"
    );
}
