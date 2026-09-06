//! Cross-platform DTN + certificate FFI fixtures (T2.4.2).
//!
//! One deterministic, byte-stable vector for each new envelope the mobile app
//! encodes or decodes through this crate's DTN / escrow surface — an outbox
//! entry envelope and the bundle they assemble into, a station delivery receipt
//! envelope, a certificate request, a station-signed certificate, a cert-backed
//! proposal, and a full offline-spend scenario — so the mobile repo can verify
//! it produces and consumes **byte-identical** canonical dCBOR (ADR-0002 /
//! ADR-0020 / ADR-0021).
//!
//! The envelopes are built here through the same `rrn-protocol` / `rrn-ledger`
//! producers the FFI wraps (with `rrn-crypto` keypairs from fixed seeds, so the
//! bytes are reproducible bit-for-bit), then this test drives the FFI **parse /
//! verify** functions over those exact bytes — proving the FFI decode side is
//! byte-identical to the wire. The FFI *signing* functions' round-trips are
//! covered by the in-crate unit tests (`src/dtn.rs`, `src/cert.rs`); as with the
//! ledger's `cross_platform_signed_payload` fixture, deterministic signing is
//! driven from the core keypair (the FFI `Keypair` intentionally has no
//! from-seed constructor — the secret never crosses the boundary, ADR-0006).
//!
//! Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-mobile-ffi --test cross_platform_dtn_certs
//! then copy `tests/fixtures/cross_platform_dtn_certs.json` into the mobile repo.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::escrow::{CertId, CertificateRequest, HeadroomCertificate, RequestId};
use rrn_ledger::transaction::TransactionProposal;
use rrn_mobile_ffi::{
    bundle_parse, certificate_parse, offline_spend_verify, receipt_parse, OfflineSpendVerdict,
};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::OutboxEntry;
use rrn_protocol::receipt::{
    self, DeliveryReceipt, Disposition, Outcome, RefusalReason, SignedReceipt,
};
use serde::{Deserialize, Serialize};

// --- vectors ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OutboxEntryVector {
    authored_at: String,
    position: String,
    record_kind: String,
    record_hash: String,
    /// The wrapped record as `{signer, sig, body}` envelope bytes — the
    /// `record_envelope` argument to `outbox_next_entry`.
    record_envelope_hex: String,
    /// The signed outbox entry as `{signer, sig, body}` envelope bytes — the
    /// value `outbox_next_entry` returns and `bundle_assemble` consumes.
    entry_envelope_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OutboxChainVector {
    author_seed: String,
    author_pubkey: String,
    author_address: String,
    entries: Vec<OutboxEntryVector>,
    assembled_at: String,
    /// Canonical dCBOR of the assembled bundle (== `bundle_assemble` output).
    bundle_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiptOutcomeVector {
    record_hash: String,
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiptVector {
    station_pubkey: String,
    /// Portable receipt-envelope bytes — the `receipt_parse` argument.
    envelope_hex: String,
    outcomes: Vec<ReceiptOutcomeVector>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CertRequestVector {
    member_pubkey: String,
    cap_centi: String,
    nonce: String,
    requested_at: String,
    /// `{signer, sig, body}` envelope bytes (== `certificate_request_sign`).
    envelope_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CertificateVector {
    station_pubkey: String,
    member_address: String,
    cap_centi: String,
    issued_at: String,
    expires_at: String,
    cert_id: String,
    /// Station-signed certificate as `{signer, sig, body}` envelope bytes — the
    /// `certificate_parse` / `offline_spend_verify` argument.
    envelope_hex: String,
}

/// A tagged verdict, mirroring `OfflineSpendVerdict`. Numbers are decimal
/// strings so the full i64 range survives the JSON hop.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct VerdictVector {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amount_centi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remaining_centi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    available_centi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempted_centi: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OfflineSpendVector {
    name: String,
    station_pubkey: String,
    receiver_address: String,
    now: String,
    cert_envelope_hex: String,
    proposal_envelope_hex: String,
    history_hex: Vec<String>,
    verdict: VerdictVector,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    outbox_chain: OutboxChainVector,
    receipt: ReceiptVector,
    cert_request: CertRequestVector,
    certificate: CertificateVector,
    offline_spend: Vec<OfflineSpendVector>,
}

// --- deterministic builders ------------------------------------------------

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair(label: &str, i: u32) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(derive(label, i)))
}

/// Frames a signed record as the portable `{signer, sig, body}` envelope,
/// byte-identical to the FFI's `envelope::encode` (an `EntryEnvelope` *is* that
/// triple, so this reuses the public protocol codec).
fn envelope_hex<T: Clone + Into<dcbor::CBOR>>(signed: &SignedPayload<T>) -> String {
    let env = EntryEnvelope {
        signer: signed.signer,
        sig: signed.signature,
        body: to_canonical_bytes(signed.payload.clone()),
    };
    hex::encode(to_canonical_bytes(env))
}

/// A plain (non-cert) proposal by `sender` to `receiver`.
fn proposal(
    sender: &Keypair,
    receiver: &Address,
    amount: i64,
    nonce: u64,
) -> SignedPayload<TransactionProposal> {
    let p = TransactionProposal::new(
        Address::from_public_key(sender.public_key()),
        *receiver,
        amount,
        None,
        nonce,
        1_000,
        9_000,
    );
    SignedPayload::sign(p, sender)
}

/// A cert-backed proposal by `sender` against `cert`.
fn cert_spend(
    sender: &Keypair,
    receiver: &Address,
    cert: CertId,
    amount: i64,
    nonce: u64,
) -> SignedPayload<TransactionProposal> {
    let p = TransactionProposal::new(
        Address::from_public_key(sender.public_key()),
        *receiver,
        amount,
        None,
        nonce,
        1_000,
        9_000,
    )
    .with_certificate(cert);
    SignedPayload::sign(p, sender)
}

fn build_outbox_chain() -> OutboxChainVector {
    let author = keypair("rrn-dtn-certs-fixture:v1:outbox-author:", 0);
    let author_addr = Address::from_public_key(author.public_key());
    let receiver =
        Address::from_public_key(keypair("rrn-dtn-certs-fixture:v1:receiver:", 0).public_key());

    let mut entries = Vec::new();
    let mut prev_hash = Hash::from_bytes([0u8; 32]);
    let mut entry_envelopes = Vec::new();
    for pos in 0u64..3 {
        let record = proposal(&author, &receiver, 100 + pos as i64, pos);
        let authored_at = 1_700_000_000 + pos as i64;
        let entry = OutboxEntry::wrapping(author_addr, pos, prev_hash, &record, authored_at);
        let signed = SignedPayload::sign(entry, &author);
        prev_hash = signed.payload.entry_hash();
        entry_envelopes.push(EntryEnvelope::from_signed(&signed));
        entries.push(OutboxEntryVector {
            authored_at: authored_at.to_string(),
            position: pos.to_string(),
            record_kind: "rrn.tx.proposal".to_string(),
            record_hash: signed.payload.record_hash().to_hex(),
            record_envelope_hex: envelope_hex(&record),
            entry_envelope_hex: envelope_hex(&signed),
        });
    }

    let assembled_at = 1_700_001_000;
    let bundle = Bundle::new(entry_envelopes, assembled_at);
    let bundle_bytes = bundle.encode();
    assert!(Bundle::decode(&bundle_bytes).is_ok());

    OutboxChainVector {
        author_seed: hex::encode(author.secret_key().to_bytes()),
        author_pubkey: hex::encode(author.public_key().to_bytes()),
        author_address: author_addr.to_string(),
        entries,
        assembled_at: assembled_at.to_string(),
        bundle_hex: hex::encode(bundle_bytes),
    }
}

fn build_receipt() -> ReceiptVector {
    let station = keypair("rrn-dtn-certs-fixture:v1:station:", 0);
    let receipt = DeliveryReceipt {
        station: Address::from_public_key(station.public_key()),
        outcomes: vec![
            Outcome {
                record_hash: Hash::of(b"rrn-dtn-certs-fixture:admitted"),
                disposition: Disposition::Admitted { seq: 128 },
            },
            Outcome {
                record_hash: Hash::of(b"rrn-dtn-certs-fixture:known"),
                disposition: Disposition::Known { seq: 64 },
            },
            Outcome {
                record_hash: Hash::of(b"rrn-dtn-certs-fixture:refused"),
                disposition: Disposition::Refused {
                    reason: RefusalReason::CertOverspent,
                },
            },
        ],
        received_at: 1_700_002_000,
    };
    let signed = SignedReceipt::sign(receipt, &station);
    let envelope = receipt::encode_signed(&signed);
    let outcomes = signed
        .payload
        .outcomes
        .iter()
        .map(|o| match o.disposition {
            Disposition::Admitted { seq } => ReceiptOutcomeVector {
                record_hash: o.record_hash.to_hex(),
                outcome: "admitted".to_string(),
                seq: Some(seq.to_string()),
                reason: None,
            },
            Disposition::Known { seq } => ReceiptOutcomeVector {
                record_hash: o.record_hash.to_hex(),
                outcome: "known".to_string(),
                seq: Some(seq.to_string()),
                reason: None,
            },
            Disposition::Refused { reason } => ReceiptOutcomeVector {
                record_hash: o.record_hash.to_hex(),
                outcome: "refused".to_string(),
                seq: None,
                reason: Some(reason.as_slug().to_string()),
            },
        })
        .collect();

    ReceiptVector {
        station_pubkey: hex::encode(station.public_key().to_bytes()),
        envelope_hex: hex::encode(envelope),
        outcomes,
    }
}

fn build_cert_request() -> CertRequestVector {
    let member = keypair("rrn-dtn-certs-fixture:v1:cert-req-member:", 0);
    let member_addr = Address::from_public_key(member.public_key());
    let req = CertificateRequest::new(member_addr, 1_500, 3, 1_700_000_000);
    let signed = SignedPayload::sign(req, &member);
    CertRequestVector {
        member_pubkey: hex::encode(member.public_key().to_bytes()),
        cap_centi: "1500".to_string(),
        nonce: "3".to_string(),
        requested_at: "1700000000".to_string(),
        envelope_hex: envelope_hex(&signed),
    }
}

/// The station, member, and certificate shared by the certificate vector and the
/// offline-spend scenarios (so the fixtures are internally consistent).
fn cert_fixture_parts() -> (
    Keypair,
    Keypair,
    HeadroomCertificate,
    SignedPayload<HeadroomCertificate>,
) {
    let station = keypair("rrn-dtn-certs-fixture:v1:cert-station:", 0);
    let member = keypair("rrn-dtn-certs-fixture:v1:cert-member:", 0);
    let member_addr = Address::from_public_key(member.public_key());
    let cert = HeadroomCertificate::new(
        member_addr,
        1_000,
        RequestId(Hash::of(b"rrn-dtn-certs-fixture:req")),
        100,
        5_000,
    );
    let signed = SignedPayload::sign(cert.clone(), &station);
    (station, member, cert, signed)
}

fn build_certificate() -> CertificateVector {
    let (station, _member, cert, signed) = cert_fixture_parts();
    CertificateVector {
        station_pubkey: hex::encode(station.public_key().to_bytes()),
        member_address: cert.member.to_string(),
        cap_centi: cert.cap_centi.to_string(),
        issued_at: cert.issued_at.to_string(),
        expires_at: cert.expires_at.to_string(),
        cert_id: hex::encode(cert.cert_id.to_bytes()),
        envelope_hex: envelope_hex(&signed),
    }
}

fn build_offline_spend() -> Vec<OfflineSpendVector> {
    let (station, member, cert, cert_signed) = cert_fixture_parts();
    let receiver = Address::from_public_key(
        keypair("rrn-dtn-certs-fixture:v1:spend-receiver:", 0).public_key(),
    );
    let station_pk = hex::encode(station.public_key().to_bytes());
    let receiver_addr = receiver.to_string();
    let cert_hex = envelope_hex(&cert_signed);

    // Good spend: 300 history + 200 spend against a 1000 cap → Ok, 500 left.
    let history = cert_spend(&member, &receiver, cert.cert_id, 300, 0);
    let good = cert_spend(&member, &receiver, cert.cert_id, 200, 1);

    // Overspend: 800 history + 300 spend → available 200, attempted 300.
    let over_history = cert_spend(&member, &receiver, cert.cert_id, 800, 0);
    let over = cert_spend(&member, &receiver, cert.cert_id, 300, 1);

    vec![
        OfflineSpendVector {
            name: "good-within-cap".to_string(),
            station_pubkey: station_pk.clone(),
            receiver_address: receiver_addr.clone(),
            now: "1000".to_string(),
            cert_envelope_hex: cert_hex.clone(),
            proposal_envelope_hex: envelope_hex(&good),
            history_hex: vec![envelope_hex(&history)],
            verdict: VerdictVector {
                kind: "ok".to_string(),
                amount_centi: Some("200".to_string()),
                remaining_centi: Some("500".to_string()),
                available_centi: None,
                attempted_centi: None,
            },
        },
        OfflineSpendVector {
            name: "overspends-presented-history".to_string(),
            station_pubkey: station_pk.clone(),
            receiver_address: receiver_addr.clone(),
            now: "1000".to_string(),
            cert_envelope_hex: cert_hex.clone(),
            proposal_envelope_hex: envelope_hex(&over),
            history_hex: vec![envelope_hex(&over_history)],
            verdict: VerdictVector {
                kind: "overspent".to_string(),
                amount_centi: None,
                remaining_centi: None,
                available_centi: Some("200".to_string()),
                attempted_centi: Some("300".to_string()),
            },
        },
        OfflineSpendVector {
            name: "expired-certificate".to_string(),
            station_pubkey: station_pk,
            receiver_address: receiver_addr,
            now: "5001".to_string(), // past cert expires_at (5000), proposal still open
            cert_envelope_hex: cert_hex,
            proposal_envelope_hex: envelope_hex(&good),
            history_hex: vec![],
            verdict: VerdictVector {
                kind: "cert_expired".to_string(),
                amount_centi: None,
                remaining_centi: None,
                available_centi: None,
                attempted_centi: None,
            },
        },
    ]
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform DTN + certificate FFI fixtures for T2.4.2 (ADR-0020/0021). \
            Each `*_envelope_hex` / `bundle_hex` is canonical dCBOR (rrn_crypto::serialize is the \
            source of truth, ADR-0002). This Rust test drives the FFI decode side (bundle_parse, \
            receipt_parse, certificate_parse, offline_spend_verify) over these exact bytes; the \
            producer side (outbox_next_entry, certificate_request_sign, proposal_sign_with_certificate) \
            is covered by the in-crate round-trip tests, and its byte-identity follows because every \
            consumer re-encodes and re-verifies the decoded payload. Envelopes are the portable \
            {signer,sig,body} triple. offline_spend verdicts mirror OfflineSpendVerdict. Deterministic \
            (blake3 seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        outbox_chain: build_outbox_chain(),
        receipt: build_receipt(),
        cert_request: build_cert_request(),
        certificate: build_certificate(),
        offline_spend: build_offline_spend(),
    }
}

// --- fixture I/O (matches the repo convention) -----------------------------

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_dtn_certs.json")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn load_committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    serde_json::from_str(&text).expect("committed fixture is not valid JSON")
}

fn pubkey_bytes(hex_pk: &str) -> Vec<u8> {
    hex::decode(hex_pk).unwrap()
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-mobile-ffi \
         --test cross_platform_dtn_certs, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

/// The FFI `bundle_parse` decodes the recorded bundle to the recorded per-entry
/// display data — decode byte-identity with the wire.
#[test]
fn ffi_bundle_parse_matches_the_fixture() {
    let fx = load_committed();
    let bundle = hex::decode(&fx.outbox_chain.bundle_hex).unwrap();
    let info = bundle_parse(bundle).expect("bundle parses");
    assert_eq!(info.entry_count as usize, fx.outbox_chain.entries.len());
    assert_eq!(info.assembled_at.to_string(), fx.outbox_chain.assembled_at);
    for (got, want) in info.entries.iter().zip(&fx.outbox_chain.entries) {
        assert_eq!(got.author, fx.outbox_chain.author_address);
        assert_eq!(got.position.to_string(), want.position);
        assert_eq!(got.record_hash, want.record_hash);
        assert_eq!(got.record_kind, want.record_kind);
        assert!(got.valid);
    }
}

/// The FFI `receipt_parse` verifies the recorded receipt against the recorded
/// station key and yields the recorded outcomes.
#[test]
fn ffi_receipt_parse_matches_the_fixture() {
    let fx = load_committed();
    let envelope = hex::decode(&fx.receipt.envelope_hex).unwrap();
    let outcomes =
        receipt_parse(envelope, pubkey_bytes(&fx.receipt.station_pubkey)).expect("verifies");
    assert_eq!(outcomes.len(), fx.receipt.outcomes.len());
    for (got, want) in outcomes.iter().zip(&fx.receipt.outcomes) {
        assert_eq!(got.record_hash, want.record_hash);
        assert_eq!(got.outcome, want.outcome);
        assert_eq!(got.seq.map(|s| s.to_string()), want.seq);
        assert_eq!(got.reason, want.reason);
    }
}

/// The FFI `certificate_parse` verifies the recorded certificate and reads its
/// recorded fields.
#[test]
fn ffi_certificate_parse_matches_the_fixture() {
    let fx = load_committed();
    let envelope = hex::decode(&fx.certificate.envelope_hex).unwrap();
    let info = certificate_parse(envelope, pubkey_bytes(&fx.certificate.station_pubkey))
        .expect("verifies");
    assert_eq!(info.member, fx.certificate.member_address);
    assert_eq!(info.cap_centi.to_string(), fx.certificate.cap_centi);
    assert_eq!(info.issued_at.to_string(), fx.certificate.issued_at);
    assert_eq!(info.expires_at.to_string(), fx.certificate.expires_at);
    assert_eq!(info.cert_id, fx.certificate.cert_id);
}

/// The FFI `offline_spend_verify` reaches the recorded verdict for every
/// scenario — the security-critical receiver ritual, byte-identical to the wire.
#[test]
fn ffi_offline_spend_verify_matches_the_fixture() {
    let fx = load_committed();
    for v in &fx.offline_spend {
        let cert = hex::decode(&v.cert_envelope_hex).unwrap();
        let proposal = hex::decode(&v.proposal_envelope_hex).unwrap();
        let history: Vec<Vec<u8>> = v
            .history_hex
            .iter()
            .map(|h| hex::decode(h).unwrap())
            .collect();
        let verdict = offline_spend_verify(
            cert,
            proposal,
            history,
            v.receiver_address.clone(),
            pubkey_bytes(&v.station_pubkey),
            v.now.parse().unwrap(),
        );
        let got = describe(&verdict);
        assert_eq!(got, v.verdict, "scenario {}", v.name);
    }
}

/// Maps an `OfflineSpendVerdict` to the fixture's tagged form for comparison.
fn describe(v: &OfflineSpendVerdict) -> VerdictVector {
    let mut out = VerdictVector {
        kind: String::new(),
        amount_centi: None,
        remaining_centi: None,
        available_centi: None,
        attempted_centi: None,
    };
    match v {
        OfflineSpendVerdict::Ok {
            amount_centi,
            remaining_centi,
        } => {
            out.kind = "ok".to_string();
            out.amount_centi = Some(amount_centi.to_string());
            out.remaining_centi = Some(remaining_centi.to_string());
        }
        OfflineSpendVerdict::Overspent {
            available_centi,
            attempted_centi,
        } => {
            out.kind = "overspent".to_string();
            out.available_centi = Some(available_centi.to_string());
            out.attempted_centi = Some(attempted_centi.to_string());
        }
        OfflineSpendVerdict::CertExpired => out.kind = "cert_expired".to_string(),
        OfflineSpendVerdict::MalformedCertificate => out.kind = "malformed_certificate".to_string(),
        OfflineSpendVerdict::BadCertificateSignature => {
            out.kind = "bad_certificate_signature".to_string()
        }
        OfflineSpendVerdict::MalformedProposal => out.kind = "malformed_proposal".to_string(),
        OfflineSpendVerdict::BadProposalSignature => {
            out.kind = "bad_proposal_signature".to_string()
        }
        OfflineSpendVerdict::CertMemberMismatch => out.kind = "cert_member_mismatch".to_string(),
        OfflineSpendVerdict::CertNotReferenced => out.kind = "cert_not_referenced".to_string(),
        OfflineSpendVerdict::WrongReceiver => out.kind = "wrong_receiver".to_string(),
        OfflineSpendVerdict::NotADebit => out.kind = "not_a_debit".to_string(),
        OfflineSpendVerdict::ProposalExpired => out.kind = "proposal_expired".to_string(),
        OfflineSpendVerdict::ProposalInadmissible => out.kind = "proposal_inadmissible".to_string(),
        OfflineSpendVerdict::MalformedHistory => out.kind = "malformed_history".to_string(),
    }
    out
}
