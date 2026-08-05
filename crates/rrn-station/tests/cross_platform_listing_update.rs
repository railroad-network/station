//! Cross-platform `SignedPayload<ListingUpdated>` vectors (T1.7.2 Phase B).
//!
//! Editing a listing signs a [`ListingUpdated`](rrn_marketplace::lifecycle::ListingUpdated):
//! the listing's fixed content `listing_id`, a [`ListingPatch`], and the
//! provider's address. The load-bearing claim is the same as the create path — a
//! patch signed on the phone and one appended by the station produce
//! **byte-identical** canonical dCBOR and signature — but the patch adds two
//! shapes the create vectors do not exercise:
//!
//! * **omit-when-unset** — an unchanged patch field is *absent* from the map, not
//!   `null`. Absence is the meaningful state ("do not touch this"), so a `null`
//!   would say something different (see `From<ListingPatch> for CBOR`).
//! * **the `expires_at` trichotomy** — absent means "leave the expiry", `null`
//!   means "clear it", an integer means "set it". Three states in one optional,
//!   which the mobile encoder has to reproduce exactly.
//!
//! Unlike a listing, a `ListingUpdated` is **not content-addressed** (it has no
//! id) and carries no timestamp, so this fixture pins canonical bytes and the
//! signature only. The mobile side reads the same committed JSON; see
//! `mobile/__tests__/listingUpdateCrossPlatform.test.ts`.
//!
//! Deterministic (blake3 seeds + deterministic Ed25519). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test cross_platform_listing_update
//! then copy `tests/fixtures/cross_platform_listing_update.json` into the mobile
//! repo at `__tests__/fixtures/cross_platform_listing_update.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_marketplace::lifecycle::{ExpiryPatch, ListingPatch, ListingUpdated};
use rrn_marketplace::listing::{
    Availability, AvailabilityStatus, ListingId, Pricing, PricingModel,
};
use rrn_mobile_ffi::canonical_bytes;
use rrn_station::core::{hex, unhex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The `kind` tag every update record carries — mirrors `UPDATED_KIND`.
const UPDATED_KIND: &str = "rrn.marketplace.listing_updated.v1";

/// A pricing patch, as the mobile app carries it in the vector.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PricingJson {
    amount_centi: String,
    model: String,
    negotiable: bool,
}

/// An availability patch, as the mobile app carries it in the vector.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct AvailabilityJson {
    status: String,
    capacity: Option<String>,
    next_slot: Option<String>,
}

/// One signed-update vector. Numeric fields are decimal **strings** so the full
/// i64 range survives the JSON hop into JavaScript. `payload` is the tagged value
/// model the mobile app builds. `patch_expires` is `"unchanged"`, `"clear"`, or a
/// decimal Unix-seconds string — the three cases `ExpiryPatch` names.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct UpdateVector {
    provider_seed: String,
    provider_pubkey: String,
    provider_address: String,
    listing_id: String,
    patch_pricing: Option<PricingJson>,
    patch_description: Option<String>,
    patch_availability: Option<AvailabilityJson>,
    patch_expires: String,
    payload: Value,
    /// Canonical dCBOR of the update (== `From<ListingUpdated> for CBOR`).
    canonical_hex: String,
    /// The provider's Ed25519 signature over `canonical_hex`.
    signature_hex: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    vectors: Vec<UpdateVector>,
}

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

/// One patch shape per vector, spanning the edits and the edges: a price-only
/// change, a description-only change, an availability-only change (new capacity),
/// an expiry set on its own, and a multi-field edit that also *clears* the expiry.
struct Draft {
    pricing: Option<Pricing>,
    description: Option<String>,
    availability: Option<Availability>,
    expires: ExpiryPatch,
}

fn draft_for(i: u32) -> Draft {
    match i {
        // Price only — the commonest edit. The model stays Fixed.
        0 => Draft {
            pricing: Some(Pricing {
                amount_centi: 500,
                model: PricingModel::Fixed,
                negotiable: false,
            }),
            description: None,
            availability: None,
            expires: ExpiryPatch::Unchanged,
        },
        // Description only, with a newline and unicode.
        1 => Draft {
            pricing: None,
            description: Some("Now with free delivery.\nRing the bell ☕".into()),
            availability: None,
            expires: ExpiryPatch::Unchanged,
        },
        // Availability only — restock a Goods listing.
        2 => Draft {
            pricing: None,
            description: None,
            availability: Some(Availability {
                status: AvailabilityStatus::Available,
                capacity: Some(3),
                next_slot: None,
            }),
            expires: ExpiryPatch::Unchanged,
        },
        // Expiry set on its own (the patch is non-empty because expiry changed).
        3 => Draft {
            pricing: None,
            description: None,
            availability: None,
            expires: ExpiryPatch::Set(1_752_600_000),
        },
        // A multi-field edit that flips to negotiable, moves the slot, and *clears*
        // the expiry — exercising the `null` arm of the trichotomy alongside real
        // pricing/availability sub-maps.
        _ => Draft {
            pricing: Some(Pricing {
                amount_centi: 800,
                model: PricingModel::Negotiable,
                negotiable: true,
            }),
            description: Some("Bundle deal for the season.".into()),
            availability: Some(Availability {
                status: AvailabilityStatus::Available,
                capacity: None,
                next_slot: Some(1_752_700_000),
            }),
            expires: ExpiryPatch::Clear,
        },
    }
}

/// The tagged-value patch the mobile app builds. Unset fields are **omitted**;
/// `expires_at` is absent / `null` / an integer. dCBOR sorts map keys itself, so
/// push order does not affect the bytes.
fn patch_tree(d: &Draft) -> Value {
    let mut entries: Vec<Value> = Vec::new();
    if let Some(p) = &d.pricing {
        entries.push(json!(["pricing", { "map": [
            ["amount_centi", { "int": p.amount_centi.to_string() }],
            ["model", { "text": p.model.tag() }],
            ["negotiable", { "bool": p.negotiable }],
        ]}]));
    }
    if let Some(desc) = &d.description {
        entries.push(json!(["description", { "text": desc }]));
    }
    if let Some(a) = &d.availability {
        entries.push(json!(["availability", { "map": [
            ["status", { "text": a.status.tag() }],
            ["capacity", match a.capacity {
                Some(n) => json!({ "int": n.to_string() }),
                None => json!({ "null": null }),
            }],
            ["next_slot", match a.next_slot {
                Some(n) => json!({ "int": n.to_string() }),
                None => json!({ "null": null }),
            }],
        ]}]));
    }
    match d.expires {
        ExpiryPatch::Unchanged => {}
        ExpiryPatch::Clear => entries.push(json!(["expires_at", { "null": null }])),
        ExpiryPatch::Set(t) => entries.push(json!(["expires_at", { "int": t.to_string() }])),
    }
    json!({ "map": entries })
}

/// The full update payload the mobile app builds. Field order mirrors
/// `From<ListingUpdated> for CBOR` (and `wallet/listing.ts`).
fn payload_tree(provider_pk: &[u8; 32], listing_id: &[u8; 32], d: &Draft) -> Value {
    json!({ "map": [
        ["kind", { "text": UPDATED_KIND }],
        ["listing_id", { "bytes": hex(listing_id) }],
        ["patch", patch_tree(d)],
        ["signed_by", { "bytes": hex(provider_pk) }],
    ]})
}

fn build_vector(i: u32) -> UpdateVector {
    let provider_seed = derive("rrn-cross-platform-listing-update-fixture:v1:provider:", i);
    let provider = keypair_from_seed(provider_seed);
    let provider_pk = provider.public_key();
    let provider_address = Address::from_public_key(provider_pk);
    // A deterministic 32-byte listing id — the record only references it; the
    // fixture proves the update's bytes and signature, not that the listing exists.
    let listing_id_bytes = derive("rrn-cross-platform-listing-update-fixture:v1:listing:", i);
    let listing_id = ListingId(Hash::from_bytes(listing_id_bytes));
    let d = draft_for(i);

    let patch = ListingPatch {
        pricing: d.pricing,
        description: d.description.clone(),
        availability: d.availability,
        expires_at: d.expires,
    };
    let update = ListingUpdated {
        listing_id,
        patch,
        signed_by: provider_address,
    };

    let canonical = to_canonical_bytes(update.clone());
    let signed = SignedPayload::sign(update, &provider);
    let payload = payload_tree(&provider_pk.to_bytes(), &listing_id_bytes, &d);

    // The heart of the cross-platform contract: the mobile tagged-JSON path must
    // yield the exact bytes the typed encoder produced — including the omitted
    // fields and the `expires_at` trichotomy.
    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "vector {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    UpdateVector {
        provider_seed: hex(&provider_seed),
        provider_pubkey: hex(&provider_pk.to_bytes()),
        provider_address: provider_address.to_string(),
        listing_id: hex(&listing_id_bytes),
        patch_pricing: d.pricing.as_ref().map(|p| PricingJson {
            amount_centi: p.amount_centi.to_string(),
            model: p.model.tag().to_string(),
            negotiable: p.negotiable,
        }),
        patch_description: d.description.clone(),
        patch_availability: d.availability.as_ref().map(|a| AvailabilityJson {
            status: a.status.tag().to_string(),
            capacity: a.capacity.map(|n| n.to_string()),
            next_slot: a.next_slot.map(|n| n.to_string()),
        }),
        patch_expires: match d.expires {
            ExpiryPatch::Unchanged => "unchanged".to_string(),
            ExpiryPatch::Clear => "clear".to_string(),
            ExpiryPatch::Set(t) => t.to_string(),
        },
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
    }
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform SignedPayload<ListingUpdated> vectors for T1.7.2 Phase B. \
            Generated by rrn-station/tests/cross_platform_listing_update.rs. `payload` is the \
            mobile tagged-value model; `canonical_hex` is the update's canonical dCBOR (== \
            From<ListingUpdated> for CBOR); `signature_hex` is the provider's Ed25519 signature \
            over those bytes. An unset patch field is OMITTED (not null); expires_at is \
            absent/null/int for unchanged/clear/set. Mobile builds the same payload via \
            wallet/listing.ts, canonicalizes it, and signs — producing the identical signature. \
            Deterministic (blake3 seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        vectors: (0..5).map(build_vector).collect(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cross_platform_listing_update.json")
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
         --test cross_platform_listing_update, then copy the JSON into the mobile repo"
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
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.provider_pubkey);
    }
}
