//! Cross-platform wire fixtures for the equivocation jury record kinds (T2.3.4,
//! ADR-0025).
//!
//! One byte-stable vector per new signed record kind: a juror-signed
//! [`EquivocationBallot`] and an established-member-signed [`EquivocationReseat`].
//! The mobile repo verifies it produces **byte-identical** canonical dCBOR and
//! signatures (ADR-0002). Both kinds live in `rrn-dispute`, distinct from the
//! station's terminal `rrn.credit.equivocation_verdict`
//! ([`EquivocationVerdictRecord`](rrn_ledger::escrow::EquivocationVerdictRecord),
//! whose own fixture is in `rrn-ledger`).
//!
//! Follows the repo's `cross_platform_*.json` regenerate-and-committed-in-sync
//! convention. Regenerate, then copy the JSON into the mobile repo:
//!
//! ```sh
//! RRN_REGEN=1 cargo test -p rrn-dispute --test cross_platform_equivocation_jury
//! ```

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_dispute::equivocation::{EquivocationBallot, EquivocationReseat};
use rrn_identity::address::Address;
use rrn_ledger::escrow::{EquivocationId, VerdictDecision};
use serde::{Deserialize, Serialize};

fn keypair(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(Hash::of(label.as_bytes()).to_bytes()))
}

const CASE_ID_SEED: &[u8] = b"rrn-equiv-jury-fixture:v1:case";
const CAST_AT: i64 = 1_700_300_000;
const REQUESTED_AT: i64 = 1_700_400_000;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct BallotVector {
    juror_pubkey: String,
    equivocation_id: String,
    round: u64,
    decision: String,
    cast_at: String,
    /// Canonical dCBOR of the `EquivocationBallot` body (== `From<..> for CBOR`).
    canonical_hex: String,
    /// The juror's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReseatVector {
    requester_pubkey: String,
    equivocation_id: String,
    round: u64,
    requested_at: String,
    canonical_hex: String,
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    ballot: BallotVector,
    reseat: ReseatVector,
}

fn build_fixture() -> Fixture {
    let juror = keypair("rrn-equiv-jury-fixture:v1:juror:");
    let requester = keypair("rrn-equiv-jury-fixture:v1:requester:");
    let juror_addr = Address::from_public_key(juror.public_key());
    let requester_addr = Address::from_public_key(requester.public_key());
    let case_id = EquivocationId(Hash::of(CASE_ID_SEED));

    // A juror's overturn ballot in round 0.
    let ballot = EquivocationBallot {
        equivocation_id: case_id,
        juror: juror_addr,
        round: 0,
        decision: VerdictDecision::Overturn,
        cast_at: CAST_AT,
    };
    let signed_ballot = SignedPayload::sign(ballot.clone(), &juror);
    assert!(signed_ballot.verify().is_ok());

    // An established member's request to re-seat the (lapsed) case in round 1.
    let reseat = EquivocationReseat {
        equivocation_id: case_id,
        requester: requester_addr,
        round: 1,
        requested_at: REQUESTED_AT,
    };
    let signed_reseat = SignedPayload::sign(reseat.clone(), &requester);
    assert!(signed_reseat.verify().is_ok());

    Fixture {
        comment: "Cross-platform equivocation jury wire fixtures for T2.3.4 (ADR-0025). A \
            juror-signed EquivocationBallot (rrn.dispute.equivocation_ballot, an overturn in \
            round 0) and an established-member-signed EquivocationReseat \
            (rrn.dispute.equivocation_reseat, opening round 1). canonical_hex is each record's \
            canonical dCBOR (== From<T> for CBOR); signature_hex is the signer's Ed25519 \
            signature over it. Deterministic (blake3-derived seeds, RFC 8032); regenerate with \
            RRN_REGEN=1."
            .to_string(),
        ballot: BallotVector {
            juror_pubkey: hex::encode(juror.public_key().to_bytes()),
            equivocation_id: case_id.0.to_hex(),
            round: 0,
            decision: VerdictDecision::Overturn.as_str().to_string(),
            cast_at: CAST_AT.to_string(),
            canonical_hex: hex::encode(to_canonical_bytes(ballot)),
            signature_hex: hex::encode(signed_ballot.signature.to_bytes()),
        },
        reseat: ReseatVector {
            requester_pubkey: hex::encode(requester.public_key().to_bytes()),
            equivocation_id: case_id.0.to_hex(),
            round: 1,
            requested_at: REQUESTED_AT.to_string(),
            canonical_hex: hex::encode(to_canonical_bytes(reseat)),
            signature_hex: hex::encode(signed_reseat.signature.to_bytes()),
        },
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cross_platform_equivocation_jury.json")
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-dispute \
         --test cross_platform_equivocation_jury, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The byte-identity guard: committed canonical bytes decode back to the typed
/// records, their content round-trips, and the recorded signatures reproduce.
#[test]
fn committed_bytes_match_the_typed_encoders() {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    let fx: Fixture = serde_json::from_str(&text).expect("committed fixture is not valid JSON");

    assert_eq!(serialize(&build_fixture()), text);

    let bytes = hex::decode(&fx.ballot.canonical_hex).unwrap();
    let ballot: EquivocationBallot = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(ballot.round, 0);
    assert_eq!(ballot.decision, VerdictDecision::Overturn);
    assert_eq!(ballot.equivocation_id.0.to_hex(), fx.ballot.equivocation_id);

    let bytes = hex::decode(&fx.reseat.canonical_hex).unwrap();
    let reseat: EquivocationReseat = from_canonical_bytes(&bytes).unwrap();
    assert_eq!(reseat.round, 1);
    assert_eq!(reseat.equivocation_id.0.to_hex(), fx.reseat.equivocation_id);
}
