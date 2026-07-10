//! Cross-platform canonical-CBOR vectors for the tagged-value model (T1.1.7).
//!
//! Proves the mobile `canonical_bytes` FFI turns the tagged-JSON payload model
//! into the same canonical dCBOR the station produces, across the whole dCBOR
//! type surface (text, byte strings, i64/u64 integers, bool, null, arrays,
//! maps) — and that floats and malformed nodes are rejected with clean, named
//! errors. This is the generic half of T1.1.7; the `SignedPayload<TransactionProposal>`
//! end-to-end vector lives in `rrn-ledger/tests/cross_platform_signed_payload.rs`.
//!
//! The mobile side reads the same committed JSON and asserts the identical
//! bytes via its (fake-FFI-backed) wrapper; see `mobile/__tests__/cbor.test.ts`.
//!
//! Reproducible bit-for-bit (no RNG). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-mobile-ffi --test cross_platform_canonical
//! then copy `tests/fixtures/cross_platform_canonical.json` into the mobile repo
//! at `__tests__/fixtures/cross_platform_canonical.json`.

use std::path::PathBuf;

use rrn_mobile_ffi::canonical_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A valid payload and the canonical dCBOR bytes it must produce. `payload` is
/// the tagged-value model embedded directly (not stringified) so the mobile test
/// can read it as a JS object.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Vector {
    name: String,
    payload: Value,
    canonical_hex: String,
}

/// A payload that must be rejected, and the error variant it must raise.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Invalid {
    name: String,
    payload: Value,
    error: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Fixture {
    #[serde(rename = "_comment")]
    comment: String,
    vectors: Vec<Vector>,
    invalid: Vec<Invalid>,
}

fn valid(name: &str, payload: Value) -> Vector {
    let bytes = canonical_bytes(payload.to_string())
        .unwrap_or_else(|e| panic!("case {name} must canonicalize: {e:?}"));
    Vector {
        name: name.to_string(),
        payload,
        canonical_hex: hex::encode(bytes),
    }
}

fn invalid(name: &str, payload: Value, error: &str) -> Invalid {
    Invalid {
        name: name.to_string(),
        payload,
        error: error.to_string(),
    }
}

fn build_fixture() -> Fixture {
    let vectors = vec![
        valid("int-zero", json!({"int": "0"})),
        valid("int-small", json!({"int": "300"})),
        valid("int-negative", json!({"int": "-42"})),
        valid("int-i64-min", json!({"int": "-9223372036854775808"})),
        valid("int-above-i64", json!({"int": "9223372036854775808"})),
        valid("int-u64-max", json!({"int": "18446744073709551615"})),
        valid("text-empty", json!({"text": ""})),
        valid("text-ascii", json!({"text": "railroad network"})),
        // Non-ASCII, already NFC — exercises the UTF-8 / NFC path.
        valid("text-unicode", json!({"text": "café 🚂"})),
        valid("bytes-empty", json!({"bytes": ""})),
        valid("bytes-two", json!({"bytes": "00ff"})),
        // 32 bytes, like an address / hash / key crossing the boundary.
        valid(
            "bytes-32",
            json!({"bytes": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}),
        ),
        valid("bool-true", json!({"bool": true})),
        valid("bool-false", json!({"bool": false})),
        valid("null", json!({"null": null})),
        valid("array-empty", json!({"array": []})),
        valid(
            "array-mixed",
            json!({"array": [{"int": "1"}, {"text": "two"}, {"bool": true}, {"null": null}]}),
        ),
        valid("map-empty", json!({"map": []})),
        // Keys given out of order — canonical output must sort them.
        valid(
            "map-unsorted-keys",
            json!({"map": [["b", {"int": "2"}], ["a", {"int": "1"}], ["c", {"int": "3"}]]}),
        ),
        // A proposal-shaped map (structure only; the real signed vector is in
        // rrn-ledger), exercising a byte-string field alongside ints/text/null.
        valid(
            "map-nested-proposal-like",
            json!({"map": [
                ["kind", {"text": "rrn.demo"}],
                ["who", {"bytes": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}],
                ["amount_centi", {"int": "-1500"}],
                ["memo", {"null": null}],
                ["tags", {"array": [{"text": "a"}, {"text": "b"}]}]
            ]}),
        ),
    ];

    let invalid = vec![
        invalid("float-tag", json!({"float": 2.5}), "FloatForbidden"),
        // A bare JSON number is not a tagged node — floats can't sneak in.
        invalid("raw-number", json!(2.5), "MalformedNode"),
        invalid("raw-string", json!("hi"), "MalformedNode"),
        invalid("int-not-integer", json!({"int": "12.5"}), "InvalidInt"),
        invalid(
            "int-overflow",
            json!({"int": "99999999999999999999999"}),
            "InvalidInt",
        ),
        invalid("int-not-a-string", json!({"int": 5}), "MalformedNode"),
        invalid("bytes-bad-hex", json!({"bytes": "zz"}), "InvalidBytes"),
        invalid("unknown-tag", json!({"blob": 1}), "MalformedNode"),
        invalid(
            "multi-key",
            json!({"text": "a", "extra": "b"}),
            "MalformedNode",
        ),
        invalid(
            "map-entry-wrong-arity",
            json!({"map": [["only-key"]]}),
            "MalformedNode",
        ),
    ];

    Fixture {
        comment: "Cross-platform canonical-CBOR vectors for T1.1.7. Generated by \
            rrn-mobile-ffi/tests/cross_platform_canonical.rs. `payload` is the mobile \
            tagged-value model; `canonical_hex` is the dCBOR the station produces for \
            the equivalent value (rrn_crypto::serialize is the source of truth, ADR-0002). \
            Mobile builds the same tagged values and must canonicalize to identical bytes \
            via the canonical_bytes FFI; floats and malformed nodes must be rejected. \
            Reproducible bit-for-bit; regenerate with RRN_REGEN=1."
            .to_string(),
        vectors,
        invalid,
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cross_platform_canonical.json")
}

fn load_committed() -> Fixture {
    let text = std::fs::read_to_string(fixture_path())
        .expect("committed fixture missing — run with RRN_REGEN=1 to create it");
    serde_json::from_str(&text).expect("committed fixture is not valid JSON")
}

fn serialize(fixture: &Fixture) -> String {
    serde_json::to_string_pretty(fixture).unwrap() + "\n"
}

fn error_variant(err: &rrn_mobile_ffi::PayloadError) -> &'static str {
    use rrn_mobile_ffi::PayloadError::*;
    match err {
        InvalidJson => "InvalidJson",
        MalformedNode => "MalformedNode",
        FloatForbidden => "FloatForbidden",
        InvalidInt => "InvalidInt",
        InvalidBytes => "InvalidBytes",
    }
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
         --test cross_platform_canonical, then copy the JSON into the mobile repo"
    );
}

#[test]
fn regeneration_is_stable() {
    assert_eq!(serialize(&build_fixture()), serialize(&build_fixture()));
}

#[test]
fn every_vector_canonicalizes_to_its_recorded_bytes() {
    let fixture = load_committed();
    assert!(!fixture.vectors.is_empty());
    for v in &fixture.vectors {
        let bytes =
            canonical_bytes(v.payload.to_string()).unwrap_or_else(|e| panic!("{}: {e:?}", v.name));
        assert_eq!(hex::encode(bytes), v.canonical_hex, "{}", v.name);
    }
}

#[test]
fn invalid_payloads_raise_the_recorded_error() {
    let fixture = load_committed();
    assert!(!fixture.invalid.is_empty());
    for bad in &fixture.invalid {
        let err = canonical_bytes(bad.payload.to_string())
            .expect_err(&format!("{} must be rejected", bad.name));
        assert_eq!(error_variant(&err), bad.error, "{}", bad.name);
    }
}
