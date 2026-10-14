//! Cross-platform vectors for the bound channel reply (envelope v2).
//!
//! ADR-0008, Clarification 2026-10-14, Part B: a version-2 channel request gets
//! a reply that names the requesting member (`recipient`) and the exact request
//! it answers (`request_hash = blake3("rrn-channel-request-v2" ‖ request
//! payload)`), and the station signs `"rrn-channel-resp-v2" ‖ reply JSON`. The
//! phone builds the request's canonical dCBOR in TypeScript and checks replies
//! itself, so this fixture pins every byte both sides must agree on:
//!
//! - the member and station seeds and keys;
//! - one v2 request — its fields, canonical payload, member signature, the
//!   framed `len ‖ payload ‖ sig`, and its request hash;
//! - an `ok` and an `err` v2 reply — the JSON bytes, the signed message (tag ‖
//!   JSON), the station signature, and the framed `len ‖ JSON ‖ sig` that is
//!   sealed to the member;
//! - one negative vector: a genuinely station-signed reply bound to a different
//!   request hash, which a client must refuse;
//! - one sealed `ok` reply (sealing is randomized, so this sample is kept from
//!   the committed file rather than regenerated; the test checks it opens to
//!   the recorded frame with the member's key);
//! - the client's check order and nonce rule, as text.
//!
//! Seeds are blake3-derived and Ed25519 signing is deterministic, so every
//! field except the sealed sample is reproducible bit-for-bit. Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-station --test it cross_platform_channel
//! (the first regen run can lose the read-vs-write race with the other test in
//! this file — run it twice), then copy the fixture into the mobile repo:
//!   cp crates/rrn-station/tests/fixtures/cross_platform_channel.json \
//!      ../mobile/__tests__/fixtures/cross_platform_channel.json

use std::path::PathBuf;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey, SecretKey};
use rrn_identity::address::Address;
use rrn_identity::sealed::{self, SealedBox, TRANSPORT_CONTEXT};
use rrn_station::channel_client::{ChannelClient, ChannelClientError, SentRequest};
use rrn_station::core::{hex, unhex};
use rrn_station::rpc_envelope::{
    frame_signed_request, frame_signed_response, parse_signed_request, request_hash,
    request_payload_bytes, response_signed_message, ReplyBinding, RequestEnvelope,
    ResponseEnvelope, ENVELOPE_V2, REQUEST_HASH_TAG, RESPONSE_SIGN_TAG,
};
use serde::{Deserialize, Serialize};

/// The request's fields, as the phone fills them in.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RequestFields {
    v: u64,
    method: String,
    params: String,
    signer: String,
    recipient: String,
    nonce: u64,
    timestamp: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RequestVector {
    fields: RequestFields,
    /// Canonical dCBOR of the envelope — what the member signs.
    payload: String,
    signature: String,
    /// `len(u32 BE) ‖ payload ‖ signature`, the plaintext sealed to the station.
    frame: String,
    /// `blake3(request_hash_tag ‖ payload)`.
    request_hash: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReplyVector {
    /// The reply JSON as text (the same bytes as `json_bytes`).
    json: String,
    json_bytes: String,
    /// `response_sign_tag ‖ json_bytes` — what the station signs.
    signed_message: String,
    signature: String,
    /// `len(u32 BE) ‖ json_bytes ‖ signature`, the plaintext sealed to the member.
    frame: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct NegativeVector {
    why: String,
    expect: String,
    reply: ReplyVector,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    member_seed: String,
    member_pk: String,
    member_address: String,
    station_seed: String,
    station_pk: String,
    station_address: String,
    request_hash_tag: String,
    response_sign_tag: String,
    transport_context: String,
    sealed_layout: String,
    client_check_order: Vec<String>,
    nonce_rule: String,
    request: RequestVector,
    ok_reply: ReplyVector,
    err_reply: ReplyVector,
    negative: NegativeVector,
    /// One `ok_reply.frame` sealed to the member; randomized, kept across regens.
    sealed_ok_reply: String,
}

/// Deterministic 32 bytes from a domain-separated label.
fn derive(label: &str) -> [u8; 32] {
    let mut input = b"rrn-cross-platform-channel-v2-fixture:".to_vec();
    input.extend_from_slice(label.as_bytes());
    Hash::of(&input).to_bytes()
}

fn keypair(label: &str) -> Keypair {
    Keypair::from_secret(SecretKey::from_bytes(derive(label)))
}

/// The request vector: a `balance` call at a time-floored nonce.
fn request_envelope(member: &Keypair, station: &Keypair) -> RequestEnvelope {
    let member_address = Address::from_public_key(member.public_key()).to_string();
    RequestEnvelope {
        v: ENVELOPE_V2,
        method: "balance".into(),
        params: format!("{{\"address\":\"{member_address}\"}}"),
        signer: member.public_key(),
        recipient: station.public_key(),
        nonce: 1_760_400_000_000,
        timestamp: 1_760_400_000,
    }
}

fn reply_vector(station: &Keypair, response: &ResponseEnvelope) -> ReplyVector {
    let json = serde_json::to_vec(response).unwrap();
    let signed_message = response_signed_message(response.v, &json);
    let frame = frame_signed_response(response, station);
    let signature = &frame[frame.len() - 64..];
    ReplyVector {
        json: String::from_utf8(json.clone()).unwrap(),
        json_bytes: hex(&json),
        signed_message: hex(&signed_message),
        signature: hex(signature),
        frame: hex(&frame),
    }
}

fn build_fixture(sealed_ok_reply: String) -> Fixture {
    let member = keypair("member-seed");
    let station = keypair("station-seed");
    let envelope = request_envelope(&member, &station);
    let payload = request_payload_bytes(&envelope);
    let signature = member.sign(&payload);
    let frame = frame_signed_request(&payload, &signature);
    let authenticated = parse_signed_request(&frame).expect("the request authenticates");
    assert_eq!(authenticated.request_hash, request_hash(&payload));
    let binding = ReplyBinding::for_request(&authenticated);

    let ok = ResponseEnvelope::ok(&binding, "{\"balance_centi\":2400}".into());
    let err = ResponseEnvelope::err(&binding, -32601, "method not found".into());
    let other_request = ReplyBinding {
        request_hash: request_hash(b"a different request payload"),
        ..binding
    };
    let negative = ResponseEnvelope::ok(&other_request, "{\"balance_centi\":2400}".into());

    Fixture {
        comment: "Channel envelope v2: replies bound to their request and recipient \
            (ADR-0008 Clarification 2026-10-14, Part B). Byte strings are lowercase hex. \
            Deterministic except sealed_ok_reply; regenerate with RRN_REGEN=1."
            .to_string(),
        member_seed: hex(&derive("member-seed")),
        member_pk: hex(&member.public_key().to_bytes()),
        member_address: Address::from_public_key(member.public_key()).to_string(),
        station_seed: hex(&derive("station-seed")),
        station_pk: hex(&station.public_key().to_bytes()),
        station_address: Address::from_public_key(station.public_key()).to_string(),
        request_hash_tag: String::from_utf8(REQUEST_HASH_TAG.to_vec()).unwrap(),
        response_sign_tag: String::from_utf8(RESPONSE_SIGN_TAG.to_vec()).unwrap(),
        transport_context: TRANSPORT_CONTEXT.to_string(),
        sealed_layout: "ephemeral_x25519_pub(32) ‖ xchacha_nonce(24) ‖ ciphertext(frame) ‖ \
            poly1305_tag(16), sealed to the member's Ed25519 key under transport_context"
            .to_string(),
        client_check_order: [
            "the seal opens with the member's key (else malformed)",
            "the pinned station key verifies the signature over response_sign_tag ‖ json_bytes \
             (else verify; an untagged v1 signature fails here)",
            "v == 2 (else request mismatch)",
            "nonce == the request's nonce (else nonce mismatch)",
            "recipient == hex(member public key) (else request mismatch; absent is a mismatch)",
            "request_hash == hex(blake3(request_hash_tag ‖ the payload bytes signed)) \
             (else request mismatch; absent is a mismatch)",
        ]
        .map(String::from)
        .to_vec(),
        nonce_rule: "next nonce = max(last used + 1, Unix time in milliseconds), persisted \
            before use; the station never lowers a member's high-water mark across \
            re-pairing or unpairing"
            .to_string(),
        request: RequestVector {
            fields: RequestFields {
                v: envelope.v,
                method: envelope.method.clone(),
                params: envelope.params.clone(),
                signer: hex(&envelope.signer.to_bytes()),
                recipient: hex(&envelope.recipient.to_bytes()),
                nonce: envelope.nonce,
                timestamp: envelope.timestamp,
            },
            payload: hex(&payload),
            signature: hex(&signature.to_bytes()),
            frame: hex(&frame),
            request_hash: hex(&authenticated.request_hash),
        },
        ok_reply: reply_vector(&station, &ok),
        err_reply: reply_vector(&station, &err),
        negative: NegativeVector {
            why: "station-signed and addressed to this member at this nonce, but bound to a \
                different request_hash"
                .to_string(),
            expect: "request mismatch".to_string(),
            reply: reply_vector(&station, &negative),
        },
        sealed_ok_reply,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_channel.json")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path()).expect("committed fixture");
    serde_json::from_str(&text).unwrap()
}

fn bytes(h: &str) -> Vec<u8> {
    unhex(h).expect("hex")
}

#[test]
fn cross_platform_channel_fixture_is_stable() {
    if std::env::var("RRN_REGEN").is_ok() {
        let member = keypair("member-seed");
        let ok_frame = bytes(&build_fixture(String::new()).ok_reply.frame);
        let sealed = sealed::seal(&member.public_key(), &ok_frame, TRANSPORT_CONTEXT)
            .unwrap()
            .to_bytes();
        std::fs::write(fixture_path(), serialize(&build_fixture(hex(&sealed)))).unwrap();
        return;
    }
    let committed_text = std::fs::read_to_string(fixture_path()).unwrap_or_default();
    let committed: Fixture = serde_json::from_str(&committed_text).expect("committed fixture");
    let generated = serialize(&build_fixture(committed.sealed_ok_reply.clone()));
    assert_eq!(
        committed_text, generated,
        "fixture drift — regenerate with RRN_REGEN=1 cargo test -p rrn-station \
         --test it cross_platform_channel, then copy the JSON into the mobile repo"
    );
}

#[test]
fn committed_vectors_verify_through_the_client() {
    let f = committed();
    let member = Keypair::from_secret(SecretKey::from_bytes(
        bytes(&f.member_seed).try_into().unwrap(),
    ));
    let station_pk = PublicKey::from_bytes(bytes(&f.station_pk).try_into().unwrap()).unwrap();
    assert_eq!(hex(&member.public_key().to_bytes()), f.member_pk);

    // The station's reading of the request frame gives the recorded hash.
    let request = parse_signed_request(&bytes(&f.request.frame)).unwrap();
    assert_eq!(hex(&request.request_hash), f.request.request_hash);
    let sent = SentRequest {
        nonce: f.request.fields.nonce,
        request_hash: request.request_hash,
    };
    let client = ChannelClient::new("", station_pk);

    // The committed sealed sample opens to the recorded frame and verifies.
    let sb = SealedBox::from_bytes(&bytes(&f.sealed_ok_reply)).unwrap();
    let opened = sealed::open(&sb, member.secret_key(), TRANSPORT_CONTEXT).unwrap();
    assert_eq!(hex(&opened), f.ok_reply.frame);
    let reply = client
        .verify_reply(&member, &bytes(&f.sealed_ok_reply), &sent)
        .expect("the ok reply answers the request");
    assert_eq!(reply.result.as_deref(), Some("{\"balance_centi\":2400}"));

    // Every recorded frame's signed message is the tag followed by its JSON.
    for r in [&f.ok_reply, &f.err_reply, &f.negative.reply] {
        let mut tagged = f.response_sign_tag.as_bytes().to_vec();
        tagged.extend_from_slice(&bytes(&r.json_bytes));
        assert_eq!(hex(&tagged), r.signed_message);
        assert_eq!(r.json.as_bytes(), bytes(&r.json_bytes).as_slice());
    }

    let seal = |frame: &str| {
        sealed::seal(&member.public_key(), &bytes(frame), TRANSPORT_CONTEXT)
            .unwrap()
            .to_bytes()
    };
    let err = client
        .verify_reply(&member, &seal(&f.err_reply.frame), &sent)
        .expect("the err reply answers the request");
    assert_eq!(err.error.unwrap().code, -32601);
    assert!(matches!(
        client.verify_reply(&member, &seal(&f.negative.reply.frame), &sent),
        Err(ChannelClientError::RequestMismatch)
    ));
}
