//! Cross-platform inquiry-record vectors (T1.7.4).
//!
//! Same load-bearing claim as the listing fixture: an inquiry record signed on
//! the phone and appended by the station produce **byte-identical** canonical
//! dCBOR and signature, because both sign the same canonical bytes. The mobile
//! builds each record's canonical form in TypeScript (`wallet/inquiry.ts`,
//! mirroring `inquiry.rs`), so the only thing that can drift is that tagged-value
//! tree — pinned here against real Rust output.
//!
//! It covers all three kinds and the parts plain JSON cannot carry: a
//! content-addressed [`InquiryOpened`](rrn_marketplace::inquiry::InquiryOpened)
//! whose `inquiry_id` is the blake3 of its own bytes, a byte-string `buyer` /
//! `sender`, an int-or-null `initial_offer_centi` / `counter_offer_centi`, a
//! unicode message body, and the nested `outcome` map an
//! [`InquiryClosed`](rrn_marketplace::inquiry::InquiryClosed) carries — including
//! `Agreed { final_price_centi }`, the one outcome that carries a number.
//!
//! The mobile side reads the same committed JSON; see
//! `mobile/__tests__/inquiryCrossPlatform.test.ts`.
//!
//! Deterministic (blake3 seeds + deterministic Ed25519). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test cross_platform_inquiry
//! then copy `tests/fixtures/cross_platform_inquiry.json` into the mobile repo at
//! `__tests__/fixtures/cross_platform_inquiry.json`.

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_marketplace::inquiry::{InquiryClosed, InquiryMessage, InquiryOpened, InquiryOutcome};
use rrn_marketplace::listing::ListingId;
use rrn_mobile_ffi::canonical_bytes;
use rrn_station::core::{hex, unhex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A deterministic listing id an inquiry points at. Nothing here decodes it — an
/// inquiry only references a listing; it does not carry one — so any stable
/// 32 bytes serve, and the mobile side reads the same hex back.
fn listing_id(i: u32) -> ListingId {
    let mut input = b"rrn-cross-platform-inquiry-fixture:v1:listing:".to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    ListingId(Hash::of(&input))
}

fn derive(label: &str, i: u32) -> [u8; 32] {
    let mut input = label.as_bytes().to_vec();
    input.extend_from_slice(&i.to_le_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair_from_seed(seed: [u8; 32]) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(seed))
}

fn opt_int(v: Option<i64>) -> Value {
    match v {
        Some(n) => json!({ "int": n.to_string() }),
        None => json!({ "null": null }),
    }
}

// --- InquiryOpened --------------------------------------------------------

/// One signed-`InquiryOpened` vector. Numeric fields are decimal **strings** so
/// the full i64 range survives the JSON hop into JavaScript.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct OpenedVector {
    buyer_seed: String,
    buyer_pubkey: String,
    buyer_address: String,
    listing_id: String,
    initial_message: String,
    initial_offer_centi: Option<String>,
    opened_at: String,
    payload: Value,
    canonical_hex: String,
    signature_hex: String,
    inquiry_id: String,
}

/// The tagged-value payload the mobile builds for an opening. Field order mirrors
/// `From<InquiryOpened> for CBOR` (dCBOR sorts keys itself, so order is cosmetic).
fn opened_payload(
    listing_id: &ListingId,
    buyer_pk: &[u8; 32],
    msg: &str,
    offer: Option<i64>,
    opened_at: i64,
) -> Value {
    json!({ "map": [
        ["kind", { "text": "rrn.marketplace.inquiry_opened.v1" }],
        ["listing_id", { "bytes": hex(&listing_id.to_bytes()) }],
        ["buyer", { "bytes": hex(buyer_pk) }],
        ["initial_message", { "text": msg }],
        ["initial_offer_centi", opt_int(offer)],
        ["opened_at", { "int": opened_at.to_string() }],
    ]})
}

fn build_opened(i: u32) -> OpenedVector {
    let buyer = keypair_from_seed(derive("rrn-cross-platform-inquiry-fixture:v1:buyer:", i));
    let buyer_pk = buyer.public_key();
    let buyer_address = Address::from_public_key(buyer_pk);
    let listing = listing_id(i);
    let opened_at: i64 = 1_752_100_000 + i64::from(i);

    // 0: an offer and a plain message; 1: no offer, empty message (accept listed
    // price with no note); 2: a unicode message and a subsidy-shaped offer.
    let (message, offer): (&str, Option<i64>) = match i {
        0 => ("Is this still available?", Some(250)),
        1 => ("", None),
        _ => ("¿Sigue disponible? ☕", Some(-300)),
    };

    let opened = InquiryOpened::new(
        listing,
        buyer_address,
        message.to_string(),
        offer,
        opened_at,
    )
    .expect("fixture opening must be valid");

    let canonical = to_canonical_bytes(opened.clone());
    let signed = SignedPayload::sign(opened.clone(), &buyer);
    let payload = opened_payload(&listing, &buyer_pk.to_bytes(), message, offer, opened_at);

    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "opened {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    OpenedVector {
        buyer_seed: hex(&derive("rrn-cross-platform-inquiry-fixture:v1:buyer:", i)),
        buyer_pubkey: hex(&buyer_pk.to_bytes()),
        buyer_address: buyer_address.to_string(),
        listing_id: hex(&listing.to_bytes()),
        initial_message: message.to_string(),
        initial_offer_centi: offer.map(|n| n.to_string()),
        opened_at: opened_at.to_string(),
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
        inquiry_id: hex(&opened.inquiry_id.to_bytes()),
    }
}

// --- InquiryMessage -------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct MessageVector {
    sender_seed: String,
    sender_pubkey: String,
    sender_address: String,
    inquiry_id: String,
    body: String,
    counter_offer_centi: Option<String>,
    sent_at: String,
    payload: Value,
    canonical_hex: String,
    signature_hex: String,
}

fn message_payload(
    inquiry_id: &[u8; 32],
    sender_pk: &[u8; 32],
    body: &str,
    counter: Option<i64>,
    sent_at: i64,
) -> Value {
    json!({ "map": [
        ["kind", { "text": "rrn.marketplace.inquiry_message.v1" }],
        ["inquiry_id", { "bytes": hex(inquiry_id) }],
        ["sender", { "bytes": hex(sender_pk) }],
        ["body", { "text": body }],
        ["counter_offer_centi", opt_int(counter)],
        ["sent_at", { "int": sent_at.to_string() }],
    ]})
}

fn build_message(i: u32) -> MessageVector {
    let sender = keypair_from_seed(derive("rrn-cross-platform-inquiry-fixture:v1:sender:", i));
    let sender_pk = sender.public_key();
    let sender_address = Address::from_public_key(sender_pk);
    // A stand-in inquiry id the message references — an inquiry id is 32 bytes
    // like any content address; nothing decodes it here.
    let inquiry_ref = derive("rrn-cross-platform-inquiry-fixture:v1:inquiry-ref:", i);
    let sent_at: i64 = 1_752_200_000 + i64::from(i);

    // 0: a counter-offer with words; 1: words, no offer; 2: a bare zero offer.
    let (body, counter): (&str, Option<i64>) = match i {
        0 => ("I can do 2.75", Some(275)),
        1 => ("Sounds good, thanks", None),
        _ => ("", Some(0)),
    };

    let message = InquiryMessage {
        inquiry_id: rrn_marketplace::inquiry::InquiryId(Hash::from_bytes(inquiry_ref)),
        sender: sender_address,
        body: body.to_string(),
        counter_offer_centi: counter,
        sent_at,
    };

    let canonical = to_canonical_bytes(message.clone());
    let signed = SignedPayload::sign(message.clone(), &sender);
    let payload = message_payload(&inquiry_ref, &sender_pk.to_bytes(), body, counter, sent_at);

    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "message {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    MessageVector {
        sender_seed: hex(&derive("rrn-cross-platform-inquiry-fixture:v1:sender:", i)),
        sender_pubkey: hex(&sender_pk.to_bytes()),
        sender_address: sender_address.to_string(),
        inquiry_id: hex(&inquiry_ref),
        body: body.to_string(),
        counter_offer_centi: counter.map(|n| n.to_string()),
        sent_at: sent_at.to_string(),
        payload,
        canonical_hex: hex(&canonical),
        signature_hex: hex(&signed.signature.to_bytes()),
    }
}

// --- InquiryClosed --------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct ClosedVector {
    signer_seed: String,
    signer_pubkey: String,
    signer_address: String,
    inquiry_id: String,
    outcome: String,
    final_price_centi: Option<String>,
    closed_at: String,
    payload: Value,
    canonical_hex: String,
    signature_hex: String,
}

/// The nested `outcome` map, mirroring `From<InquiryOutcome> for CBOR`.
fn outcome_tree(outcome: InquiryOutcome) -> Value {
    let tag = match outcome {
        InquiryOutcome::Agreed { .. } => "agreed",
        InquiryOutcome::DeclinedByBuyer => "declined_by_buyer",
        InquiryOutcome::DeclinedBySeller => "declined_by_seller",
        InquiryOutcome::Expired => "expired",
    };
    let mut entries = vec![json!(["outcome", { "text": tag }])];
    if let InquiryOutcome::Agreed { final_price_centi } = outcome {
        entries.push(json!(["final_price_centi", { "int": final_price_centi.to_string() }]));
    }
    json!({ "map": entries })
}

fn closed_payload(inquiry_id: &[u8; 32], outcome: InquiryOutcome, closed_at: i64) -> Value {
    json!({ "map": [
        ["kind", { "text": "rrn.marketplace.inquiry_closed.v1" }],
        ["inquiry_id", { "bytes": hex(inquiry_id) }],
        ["outcome", outcome_tree(outcome)],
        ["closed_at", { "int": closed_at.to_string() }],
    ]})
}

fn build_closed(i: u32) -> ClosedVector {
    let signer = keypair_from_seed(derive("rrn-cross-platform-inquiry-fixture:v1:closer:", i));
    let signer_pk = signer.public_key();
    let signer_address = Address::from_public_key(signer_pk);
    let inquiry_ref = derive("rrn-cross-platform-inquiry-fixture:v1:inquiry-ref:", i);
    let closed_at: i64 = 1_752_300_000 + i64::from(i);

    // Every outcome, including the one that carries a price.
    let outcome = match i {
        0 => InquiryOutcome::Agreed {
            final_price_centi: 275,
        },
        1 => InquiryOutcome::DeclinedByBuyer,
        2 => InquiryOutcome::DeclinedBySeller,
        _ => InquiryOutcome::Expired,
    };

    let closed = InquiryClosed {
        inquiry_id: rrn_marketplace::inquiry::InquiryId(Hash::from_bytes(inquiry_ref)),
        outcome,
        closed_at,
    };

    let canonical = to_canonical_bytes(closed);
    let signed = SignedPayload::sign(closed, &signer);
    let payload = closed_payload(&inquiry_ref, outcome, closed_at);

    let via_ffi = canonical_bytes(payload.to_string()).expect("payload must canonicalize");
    assert_eq!(
        via_ffi, canonical,
        "closed {i}: tagged-JSON canonical bytes differ from the typed encoder"
    );

    let (tag, price) = match outcome {
        InquiryOutcome::Agreed { final_price_centi } => ("agreed", Some(final_price_centi)),
        InquiryOutcome::DeclinedByBuyer => ("declined_by_buyer", None),
        InquiryOutcome::DeclinedBySeller => ("declined_by_seller", None),
        InquiryOutcome::Expired => ("expired", None),
    };

    ClosedVector {
        signer_seed: hex(&derive("rrn-cross-platform-inquiry-fixture:v1:closer:", i)),
        signer_pubkey: hex(&signer_pk.to_bytes()),
        signer_address: signer_address.to_string(),
        inquiry_id: hex(&inquiry_ref),
        outcome: tag.to_string(),
        final_price_centi: price.map(|n| n.to_string()),
        closed_at: closed_at.to_string(),
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
    opened: Vec<OpenedVector>,
    messages: Vec<MessageVector>,
    closed: Vec<ClosedVector>,
}

fn build_fixture() -> Fixture {
    Fixture {
        comment: "Cross-platform inquiry-record vectors for T1.7.4. Generated by \
            rrn-station/tests/cross_platform_inquiry.rs. Each `payload` is the mobile \
            tagged-value model; `canonical_hex` is the record's canonical dCBOR (== From<T> \
            for CBOR); `signature_hex` is the signer's Ed25519 signature over those bytes. For \
            an opening, `inquiry_id` is the blake3 of its canonical bytes (content address); \
            for a message/close it is the referenced inquiry. Mobile builds the same payloads \
            via wallet/inquiry.ts, canonicalizes, and signs — producing identical bytes. \
            Deterministic (blake3 seeds, RFC 8032); regenerate with RRN_REGEN=1."
            .to_string(),
        opened: (0..3).map(build_opened).collect(),
        messages: (0..3).map(build_message).collect(),
        closed: (0..4).map(build_closed).collect(),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_inquiry.json")
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
         --test cross_platform_inquiry, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn signatures_are_reproducible_and_verify() {
    let fixture = build_fixture();
    for v in &fixture.opened {
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.buyer_pubkey);
        // The opening content-addresses to its inquiry_id.
        assert_eq!(hex(&Hash::of(&via_ffi).to_bytes()), v.inquiry_id);
        let seed: [u8; 32] = unhex(&v.buyer_seed).unwrap().as_slice().try_into().unwrap();
        assert_eq!(
            hex(&keypair_from_seed(seed).public_key().to_bytes()),
            v.buyer_pubkey
        );
    }
    for v in &fixture.messages {
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.sender_pubkey);
    }
    for v in &fixture.closed {
        let via_ffi = canonical_bytes(v.payload.to_string()).expect("canonicalize");
        assert_eq!(hex(&via_ffi), v.canonical_hex, "{}", v.signer_pubkey);
    }
}
