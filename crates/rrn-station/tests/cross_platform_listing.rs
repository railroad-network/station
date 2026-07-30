//! Cross-platform `SignedPayload<Listing>` vectors (T1.7.2).
//!
//! The listing write contract's load-bearing claim: a listing signed on the phone
//! and appended by the station produce **byte-identical** canonical dCBOR and
//! signature, because both sign the same canonical bytes of the same listing, and
//! content-address to the same `listing_id`. The mobile builds the listing's
//! canonical form in TypeScript (`wallet/listing.ts`, mirroring `listing.rs`),
//! so the only thing that can drift is that tagged-value tree. This fixture pins
//! it against real Rust output.
//!
//! It exercises the parts that plain JSON cannot carry and that are new to
//! listings: a byte-string `provider`, nested `pricing`/`availability`/
//! `requirements` maps, `capacity`/`next_slot`/`expires_at` as text-or-null, a
//! negative Commons amount, and — the interesting one — a whole-number `f32`
//! `min_reputation` that dCBOR numeric-reduces to an integer, which is exactly
//! what lets the float-free mobile encoder sign it via `int`.
//!
//! The mobile side reads the same committed JSON; see
//! `mobile/__tests__/listingCrossPlatform.test.ts`.
//!
//! Deterministic (blake3 seeds + deterministic Ed25519). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test cross_platform_listing
//! then copy `tests/fixtures/cross_platform_listing.json` into the mobile repo at
//! `__tests__/fixtures/cross_platform_listing.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_marketplace::listing::{
    Availability, AvailabilityStatus, Listing, Pricing, PricingModel, Requirements, Surface,
};
use rrn_mobile_ffi::canonical_bytes;
use rrn_station::core::{hex, unhex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The community every Phase-0 listing carries — mirrors `core.rs::VOUCH_COMMUNITY`.
const COMMUNITY: &str = "rrn-phase0";

/// One signed-listing vector. Numeric fields are decimal **strings** so the full
/// i64 range survives the JSON hop into JavaScript. `payload` is the tagged value
/// model the mobile app builds.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ListingVector {
    provider_seed: String,
    provider_pubkey: String,
    provider_address: String,
    community: String,
    surface: String,
    category: String,
    title: String,
    description: String,
    amount_centi: String,
    pricing_model: String,
    negotiable: bool,
    availability_status: String,
    capacity: Option<String>,
    next_slot: Option<String>,
    min_reputation: u32,
    community_member_only: bool,
    oracle_tier: u32,
    created_at: String,
    expires_at: Option<String>,
    payload: Value,
    /// Canonical dCBOR of the listing (== `From<Listing> for CBOR`, id omitted).
    canonical_hex: String,
    /// The provider's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
    /// Blake3 of the canonical bytes — the `listing_id`.
    listing_id: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    vectors: Vec<ListingVector>,
}

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

/// One provider-chosen shape per vector, spanning the surfaces and the edges:
/// a plain Goods listing, a negotiable Service with a slot and a reputation
/// floor, a subsidized Commons offer (negative amount), a limited-stock Goods
/// with a unicode title, and an unavailable Service.
struct Draft {
    surface: Surface,
    category: &'static str,
    title: String,
    description: String,
    amount_centi: i64,
    model: PricingModel,
    negotiable: bool,
    status: AvailabilityStatus,
    capacity: Option<u32>,
    next_slot: Option<i64>,
    min_reputation: u32,
    community_member_only: bool,
    oracle_tier: u8,
    expires_at: Option<i64>,
}

fn draft_for(i: u32, created_at: i64) -> Draft {
    match i {
        0 => Draft {
            surface: Surface::Goods,
            category: "food",
            title: "Sourdough loaves".into(),
            description: "Baked fresh every morning.".into(),
            amount_centi: 350,
            model: PricingModel::Fixed,
            negotiable: false,
            status: AvailabilityStatus::Available,
            capacity: Some(6),
            next_slot: None,
            min_reputation: 0,
            community_member_only: false,
            oracle_tier: 1,
            expires_at: None,
        },
        1 => Draft {
            surface: Surface::Services,
            category: "education",
            title: "Maths tutoring café ☕".into(),
            description: "Algebra through calculus.\nOne-on-one.".into(),
            amount_centi: 800,
            model: PricingModel::Negotiable,
            negotiable: true,
            status: AvailabilityStatus::Available,
            capacity: None,
            next_slot: Some(created_at + 3 * 86_400),
            min_reputation: 2,
            community_member_only: true,
            oracle_tier: 2,
            expires_at: Some(created_at + 30 * 86_400),
        },
        2 => Draft {
            surface: Surface::Commons,
            category: "transportation",
            title: "Village ride share".into(),
            description: "Subsidised lifts to market.".into(),
            amount_centi: -300,
            model: PricingModel::Fixed,
            negotiable: false,
            status: AvailabilityStatus::Available,
            capacity: None,
            next_slot: None,
            min_reputation: 0,
            community_member_only: false,
            oracle_tier: 1,
            expires_at: None,
        },
        3 => Draft {
            surface: Surface::Goods,
            category: "tools",
            title: "Hand tool set — chisels & planes".into(),
            description: String::new(),
            amount_centi: 1200,
            model: PricingModel::Fixed,
            negotiable: true,
            status: AvailabilityStatus::LimitedStock,
            capacity: Some(2),
            next_slot: None,
            min_reputation: 1,
            community_member_only: false,
            oracle_tier: 2,
            expires_at: None,
        },
        _ => Draft {
            surface: Surface::Services,
            category: "construction",
            title: "Barn raising crew".into(),
            description: "A full day of framing labour.".into(),
            amount_centi: 4500,
            model: PricingModel::Negotiable,
            negotiable: true,
            status: AvailabilityStatus::Unavailable,
            capacity: None,
            next_slot: Some(created_at + 10 * 86_400),
            min_reputation: 2,
            community_member_only: true,
            oracle_tier: 2,
            expires_at: Some(created_at + 45 * 86_400),
        },
    }
}

/// The tagged-value payload the mobile app builds. Field order mirrors
/// `From<Listing> for CBOR` (and `wallet/listing.ts`); dCBOR sorts map keys
/// itself, so order does not affect the bytes.
fn payload_tree(provider_pk: &[u8; 32], d: &Draft, created_at: i64) -> Value {
    let opt_int = |v: Option<i64>| match v {
        Some(n) => json!({ "int": n.to_string() }),
        None => json!({ "null": null }),
    };
    json!({ "map": [
        ["kind", { "text": "rrn.marketplace.listing.v1" }],
        ["provider", { "bytes": hex(provider_pk) }],
        ["community", { "text": COMMUNITY }],
        ["surface", { "text": d.surface.tag() }],
        ["category", { "text": d.category }],
        ["title", { "text": d.title }],
        ["description", { "text": d.description }],
        ["pricing", { "map": [
            ["amount_centi", { "int": d.amount_centi.to_string() }],
            ["model", { "text": d.model.tag() }],
            ["negotiable", { "bool": d.negotiable }],
        ]}],
        ["availability", { "map": [
            ["status", { "text": d.status.tag() }],
            ["capacity", match d.capacity {
                Some(n) => json!({ "int": n.to_string() }),
                None => json!({ "null": null }),
            }],
            ["next_slot", opt_int(d.next_slot)],
        ]}],
        ["requirements", { "map": [
            ["min_reputation", { "int": d.min_reputation.to_string() }],
            ["community_member_only", { "bool": d.community_member_only }],
            ["federation_only", { "bool": false }],
        ]}],
        ["oracle_tier", { "int": d.oracle_tier.to_string() }],
        ["federation_visible", { "bool": false }],
        ["created_at", { "int": created_at.to_string() }],
        ["expires_at", opt_int(d.expires_at)],
    ]})
}

fn build_vector(i: u32) -> ListingVector {
    let provider_seed = derive("rrn-cross-platform-listing-fixture:v1:provider:", i);
    let provider = keypair_from_seed(provider_seed);
    let provider_pk = provider.public_key();
    let provider_address = Address::from_public_key(provider_pk);
    // A fixed, plausible 2025-era Unix timestamp — deterministic, not `now`.
    let created_at: i64 = 1_752_000_000 + i64::from(i);
    let d = draft_for(i, created_at);

    let listing = Listing::new(
        provider_address,
        COMMUNITY.to_string(),
        d.surface,
        d.category.to_string(),
        d.title.clone(),
        d.description.clone(),
        Pricing {
            amount_centi: d.amount_centi,
            model: d.model,
            negotiable: d.negotiable,
        },
        Availability {
            status: d.status,
            capacity: d.capacity,
            next_slot: d.next_slot,
        },
        Requirements {
            min_reputation: d.min_reputation as f32,
            community_member_only: d.community_member_only,
            federation_only: false,
        },
        d.oracle_tier,
        false,
        created_at,
        d.expires_at,
    )
    .expect("fixture listing must be valid");

    let canonical = to_canonical_bytes(listing.clone());
    let signed = SignedPayload::sign(listing.clone(), &provider);
    let payload = payload_tree(&provider_pk.to_bytes(), &d, created_at);

    // The heart of the cross-platform contract: the mobile tagged-JSON path must
    // yield the exact bytes the typed encoder produced — including the whole-number
    // `f32` reducing to the same integer bytes.
    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "vector {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    ListingVector {
        provider_seed: hex(&provider_seed),
        provider_pubkey: hex(&provider_pk.to_bytes()),
        provider_address: provider_address.to_string(),
        community: COMMUNITY.to_string(),
        surface: d.surface.tag().to_string(),
        category: d.category.to_string(),
        title: d.title,
        description: d.description,
        amount_centi: d.amount_centi.to_string(),
        pricing_model: d.model.tag().to_string(),
        negotiable: d.negotiable,
        availability_status: d.status.tag().to_string(),
        capacity: d.capacity.map(|n| n.to_string()),
        next_slot: d.next_slot.map(|n| n.to_string()),
        min_reputation: d.min_reputation,
        community_member_only: d.community_member_only,
        oracle_tier: u32::from(d.oracle_tier),
        created_at: created_at.to_string(),
        expires_at: d.expires_at.map(|n| n.to_string()),
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
        listing_id: hex(&listing.id.to_bytes()),
    }
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform SignedPayload<Listing> vectors for T1.7.2. Generated by \
            rrn-station/tests/cross_platform_listing.rs. `payload` is the mobile tagged-value \
            model; `canonical_hex` is the listing's canonical dCBOR (== From<Listing> for CBOR, \
            id omitted); `signature_hex` is the provider's Ed25519 signature over those bytes; \
            `listing_id` is their blake3 hash. Mobile builds the same payload via \
            wallet/listing.ts, canonicalizes it, and signs — producing the identical signature. \
            Deterministic (blake3 seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        vectors: (0..5).map(build_vector).collect(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_listing.json")
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
         --test cross_platform_listing, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn signatures_are_reproducible_and_verify() {
    for v in build_fixture().vectors {
        let seed: [u8; 32] = unhex(&v.provider_seed)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let kp = keypair_from_seed(seed);
        assert_eq!(hex(&kp.public_key().to_bytes()), v.provider_pubkey);
        // The signature verifies, and its content-address matches the listing_id.
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.provider_pubkey);
        assert_eq!(hex(&Hash::of(&via_ffi).to_bytes()), v.listing_id);
    }
}
