//! Cross-platform service-contract vectors (T1.7.7).
//!
//! Same load-bearing claim as the inquiry fixture: a [`ServiceContract`] signed
//! on the phone and appended by the station produce **byte-identical** canonical
//! dCBOR and signature, because both sign the same canonical bytes. The mobile
//! builds each record's canonical form in TypeScript (`wallet/contract.ts`,
//! mirroring `contract.rs`, arriving with the Stage-2 mobile work), so the only
//! thing that can drift is that tagged-value tree — pinned here against real Rust
//! output.
//!
//! It covers both contract kinds and the parts plain JSON cannot carry: a
//! content-addressed [`ServiceContract`](rrn_marketplace::contract::ServiceContract)
//! whose `contract_id` is the blake3 of its own bytes, byte-string
//! `inquiry_id` / `listing_id` / `buyer` / `provider`, the nested `terms` map
//! (itself carrying a nested `frequency` map — including the `Custom { secs }`
//! shape — and a nested `performance_metrics` string map dCBOR sorts by key), and
//! the `terminated_by` text tag a
//! [`ContractTermination`](rrn_marketplace::contract::ContractTermination) carries.
//!
//! The mobile side will read the same committed JSON in Stage 2; see (once it
//! lands) `mobile/__tests__/contractCrossPlatform.test.ts`.
//!
//! Deterministic (blake3 seeds + deterministic Ed25519). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test cross_platform_contract
//! then copy `tests/fixtures/cross_platform_contract.json` into the mobile repo at
//! `__tests__/fixtures/cross_platform_contract.json`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_marketplace::contract::{
    ContractId, ContractTermination, ContractTerms, ServiceContract, TerminatedBy,
};
use rrn_marketplace::inquiry::InquiryId;
use rrn_marketplace::listing::{Frequency, ListingId};
use rrn_mobile_ffi::canonical_bytes;
use rrn_station::core::{hex, unhex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const PREFIX: &str = "rrn-cross-platform-contract-fixture:v1";

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = format!("{PREFIX}:{label}:").into_bytes();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

/// A deterministic content address (inquiry/listing) a contract points at.
/// Nothing here decodes it — a contract only references these — so any stable
/// 32 bytes serve, and the mobile side reads the same hex back.
fn stand_in(label: &str, i: u32) -> [u8; 32] {
    derive(label, i)
}

// --- terms tree (mirrors From<ContractTerms> / From<Frequency> for CBOR) ---

/// The nested `frequency` map, mirroring `From<Frequency> for CBOR`.
fn frequency_tree(f: Frequency) -> Value {
    match f {
        Frequency::Daily => json!({ "map": [["unit", { "text": "daily" }]] }),
        Frequency::Weekly => json!({ "map": [["unit", { "text": "weekly" }]] }),
        Frequency::Monthly => json!({ "map": [["unit", { "text": "monthly" }]] }),
        Frequency::Custom(secs) => json!({ "map": [
            ["unit", { "text": "custom" }],
            ["secs", { "int": secs.to_string() }],
        ]}),
    }
}

/// The nested `performance_metrics` string map. dCBOR sorts the keys, so the
/// entry order here is cosmetic — vector 2 deliberately lists them out of order.
fn metrics_tree(metrics: &BTreeMap<String, String>) -> Value {
    let entries: Vec<Value> = metrics
        .iter()
        .map(|(k, v)| json!([k, { "text": v }]))
        .collect();
    json!({ "map": entries })
}

fn terms_tree(t: &ContractTerms) -> Value {
    json!({ "map": [
        ["frequency", frequency_tree(t.frequency)],
        ["duration_periods", { "int": t.duration_periods.to_string() }],
        ["commons_per_period_centi", { "int": t.commons_per_period_centi.to_string() }],
        ["performance_metrics", metrics_tree(&t.performance_metrics)],
        ["notice_period_days", { "int": t.notice_period_days.to_string() }],
        ["early_termination_penalty_centi", { "int": t.early_termination_penalty_centi.to_string() }],
    ]})
}

/// A JSON view of the terms the mobile reconstructs from — numbers as decimal
/// strings so the full i64 range survives the JSON hop into JavaScript.
fn terms_view(t: &ContractTerms) -> Value {
    let mut metrics = serde_json::Map::new();
    for (k, v) in &t.performance_metrics {
        metrics.insert(k.clone(), Value::String(v.clone()));
    }
    json!({
        "frequency": frequency_view(t.frequency),
        "duration_periods": t.duration_periods.to_string(),
        "commons_per_period_centi": t.commons_per_period_centi.to_string(),
        "performance_metrics": Value::Object(metrics),
        "notice_period_days": t.notice_period_days.to_string(),
        "early_termination_penalty_centi": t.early_termination_penalty_centi.to_string(),
    })
}

fn frequency_view(f: Frequency) -> Value {
    match f {
        Frequency::Daily => json!({ "unit": "daily" }),
        Frequency::Weekly => json!({ "unit": "weekly" }),
        Frequency::Monthly => json!({ "unit": "monthly" }),
        Frequency::Custom(secs) => json!({ "unit": "custom", "secs": secs.to_string() }),
    }
}

// --- ServiceContract ------------------------------------------------------

/// One signed-`ServiceContract` vector. Scalar fields are decimal **strings** so
/// the full i64 range survives the JSON hop into JavaScript.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ContractVector {
    buyer_seed: String,
    buyer_pubkey: String,
    buyer_address: String,
    provider_pubkey: String,
    provider_address: String,
    inquiry_id: String,
    listing_id: String,
    terms: Value,
    started_at: String,
    payload: Value,
    canonical_hex: String,
    signature_hex: String,
    contract_id: String,
}

/// The tagged-value payload the mobile builds for a contract. Field order mirrors
/// `From<ServiceContract> for CBOR` (dCBOR sorts keys itself, so order is
/// cosmetic). `contract_id` is omitted — it is the hash of these bytes.
fn contract_payload(
    inquiry_id: &[u8; 32],
    listing_id: &[u8; 32],
    buyer_pk: &[u8; 32],
    provider_pk: &[u8; 32],
    terms: &ContractTerms,
    started_at: i64,
) -> Value {
    json!({ "map": [
        ["kind", { "text": "rrn.marketplace.service_contract.v1" }],
        ["inquiry_id", { "bytes": hex(inquiry_id) }],
        ["listing_id", { "bytes": hex(listing_id) }],
        ["buyer", { "bytes": hex(buyer_pk) }],
        ["provider", { "bytes": hex(provider_pk) }],
        ["terms", terms_tree(terms)],
        ["started_at", { "int": started_at.to_string() }],
    ]})
}

fn terms_of(i: u32) -> ContractTerms {
    // 0: weekly, whole-week notice, no metrics.
    // 1: monthly, several metrics, zero penalty.
    // 2: a bespoke hourly period, metrics listed out of key order (dCBOR sorts).
    let (frequency, duration_periods, price, notice, penalty, metrics): (
        Frequency,
        u32,
        i64,
        u32,
        i64,
        &[(&str, &str)],
    ) = match i {
        0 => (Frequency::Weekly, 4, 500, 7, 500, &[]),
        1 => (
            Frequency::Monthly,
            12,
            2500,
            30,
            0,
            &[("note", "prefers mornings"), ("tier", "gold")],
        ),
        _ => (
            Frequency::Custom(3600),
            6,
            125,
            3,
            250,
            &[("zeta", "last"), ("alpha", "first")],
        ),
    };
    ContractTerms {
        frequency,
        duration_periods,
        commons_per_period_centi: price,
        performance_metrics: metrics
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        notice_period_days: notice,
        early_termination_penalty_centi: penalty,
    }
}

fn build_contract(i: u32) -> ContractVector {
    let buyer = keypair_from_seed(derive("buyer", i));
    let provider = keypair_from_seed(derive("provider", i));
    let buyer_pk = buyer.public_key();
    let provider_pk = provider.public_key();
    let buyer_address = Address::from_public_key(buyer_pk);
    let provider_address = Address::from_public_key(provider_pk);
    let inquiry_ref = stand_in("inquiry-ref", i);
    let listing_ref = stand_in("listing-ref", i);
    let started_at: i64 = 1_753_000_000 + i64::from(i);
    let terms = terms_of(i);

    let contract = ServiceContract::new(
        InquiryId(Hash::from_bytes(inquiry_ref)),
        ListingId(Hash::from_bytes(listing_ref)),
        buyer_address,
        provider_address,
        terms.clone(),
        started_at,
    )
    .expect("fixture contract must be valid");

    let canonical = to_canonical_bytes(contract.clone());
    let signed = SignedPayload::sign(contract.clone(), &buyer);
    let payload = contract_payload(
        &inquiry_ref,
        &listing_ref,
        &buyer_pk.to_bytes(),
        &provider_pk.to_bytes(),
        &terms,
        started_at,
    );

    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "contract {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    ContractVector {
        buyer_seed: hex(&derive("buyer", i)),
        buyer_pubkey: hex(&buyer_pk.to_bytes()),
        buyer_address: buyer_address.to_string(),
        provider_pubkey: hex(&provider_pk.to_bytes()),
        provider_address: provider_address.to_string(),
        inquiry_id: hex(&inquiry_ref),
        listing_id: hex(&listing_ref),
        terms: terms_view(&terms),
        started_at: started_at.to_string(),
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
        contract_id: hex(&contract.contract_id.to_bytes()),
    }
}

// --- ContractTermination --------------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TerminationVector {
    signer_seed: String,
    signer_pubkey: String,
    signer_address: String,
    contract_id: String,
    terminated_by: String,
    requested_at: String,
    payload: Value,
    canonical_hex: String,
    signature_hex: String,
}

fn termination_payload(contract_id: &[u8; 32], terminated_by: &str, requested_at: i64) -> Value {
    json!({ "map": [
        ["kind", { "text": "rrn.marketplace.contract_termination.v1" }],
        ["contract_id", { "bytes": hex(contract_id) }],
        ["terminated_by", { "text": terminated_by }],
        ["requested_at", { "int": requested_at.to_string() }],
    ]})
}

fn build_termination(i: u32) -> TerminationVector {
    let signer = keypair_from_seed(derive("terminator", i));
    let signer_pk = signer.public_key();
    let signer_address = Address::from_public_key(signer_pk);
    let contract_ref = stand_in("contract-ref", i);
    let requested_at: i64 = 1_753_100_000 + i64::from(i);

    // 0: the buyer walks away; 1: the provider ends it.
    let (by, tag) = match i {
        0 => (TerminatedBy::Buyer, "buyer"),
        _ => (TerminatedBy::Provider, "provider"),
    };

    let termination = ContractTermination {
        contract_id: ContractId(Hash::from_bytes(contract_ref)),
        terminated_by: by,
        requested_at,
    };

    let canonical = to_canonical_bytes(termination);
    let signed = SignedPayload::sign(termination, &signer);
    let payload = termination_payload(&contract_ref, tag, requested_at);

    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "termination {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    TerminationVector {
        signer_seed: hex(&derive("terminator", i)),
        signer_pubkey: hex(&signer_pk.to_bytes()),
        signer_address: signer_address.to_string(),
        contract_id: hex(&contract_ref),
        terminated_by: tag.to_string(),
        requested_at: requested_at.to_string(),
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
    }
}

// --- fixture --------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    contracts: Vec<ContractVector>,
    terminations: Vec<TerminationVector>,
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform service-contract vectors for T1.7.7. Generated by \
            rrn-station/tests/cross_platform_contract.rs. Each `payload` is the mobile \
            tagged-value model; `canonical_hex` is the record's canonical dCBOR (== From<T> \
            for CBOR); `signature_hex` is the signer's Ed25519 signature over those bytes. For \
            a contract, `contract_id` is the blake3 of its canonical bytes (content address); a \
            termination references its contract. Mobile builds the same payloads via \
            wallet/contract.ts (Stage 2), canonicalizes, and signs — producing identical bytes. \
            Deterministic (blake3 seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        contracts: (0..3).map(build_contract).collect(),
        terminations: (0..2).map(build_termination).collect(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_contract.json")
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
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-station \
         --test cross_platform_contract, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn signatures_are_reproducible_and_verify() {
    let fixture = build_fixture();
    for v in &fixture.contracts {
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.buyer_pubkey);
        // The contract content-addresses to its contract_id.
        assert_eq!(hex(&Hash::of(&via_ffi).to_bytes()), v.contract_id);
        let seed: [u8; 32] = unhex(&v.buyer_seed).unwrap().as_slice().try_into().unwrap();
        assert_eq!(
            hex(&keypair_from_seed(seed).public_key().to_bytes()),
            v.buyer_pubkey
        );
    }
    for v in &fixture.terminations {
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.signer_pubkey);
    }
}
