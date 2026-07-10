//! Canonical CBOR from a tagged-JSON payload value model (T1.1.7).
//!
//! Mobile signs *values*, and the signature must cover the same canonical dCBOR
//! bytes the station would produce for the same logical value (ADR-0002). The
//! app never carries its own CBOR encoder — it builds a small tagged value tree
//! in TypeScript, ships it here as JSON, and this module turns it into
//! `dcbor::CBOR` and hands it to the one canonical encoder. So there is still
//! exactly one canonicalization: the Rust/dcbor one.
//!
//! # Why a tagged value model rather than plain JSON
//!
//! JSON cannot express two things dCBOR needs: **byte strings** (addresses,
//! hashes, keys encode as CBOR byte strings, e.g. `Address` → `to_byte_string`)
//! and **exact 64-bit integers** (JSON numbers are IEEE-754 doubles and lose
//! precision past 2^53). So each node is a single-key tagged object:
//!
//! | Tag        | JSON shape                         | CBOR              |
//! |------------|------------------------------------|-------------------|
//! | `text`     | `{"text": "hello"}`                | text string (NFC) |
//! | `int`      | `{"int": "-300"}` (decimal string) | integer           |
//! | `bytes`    | `{"bytes": "00ff…"}` (hex)         | byte string       |
//! | `bool`     | `{"bool": true}`                   | bool              |
//! | `null`     | `{"null": null}`                   | null              |
//! | `array`    | `{"array": [node, …]}`             | array             |
//! | `map`      | `{"map": [["key", node], …]}`      | map (keys sorted) |
//!
//! Map keys are text; dCBOR emits them in canonical (bytewise-sorted) order, so
//! the TS side never has to sort. Integers travel as decimal strings to keep the
//! full i64/u64 range intact across the JSON hop.
//!
//! # Floats
//!
//! Floats are **forbidden** in signed payloads (project policy; amounts are
//! integer centicommons). There is no float tag, so a float is normally
//! unrepresentable — and the TS builder rejects non-integer numbers before they
//! get here. A literal `{"float": …}` tag is recognized only to return a clean
//! [`PayloadError::FloatForbidden`] rather than a generic "malformed" error, so
//! the rejection is testable by name on both platforms.

use dcbor::prelude::*;
use serde_json::Value;

/// Error from turning a tagged-JSON payload into canonical CBOR.
///
/// Flat and field-less so it maps cleanly onto a uniffi `[Error]` and the
/// idiomatic Swift/Kotlin/TS error types.
#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    /// The payload string was not valid JSON.
    #[error("payload is not valid JSON")]
    InvalidJson,
    /// A node was not a single-key tagged object, or its inner value had the
    /// wrong shape for its tag.
    #[error("payload contains a malformed value node")]
    MalformedNode,
    /// A float was encountered — forbidden in signed payloads.
    #[error("floats are forbidden in signed payloads")]
    FloatForbidden,
    /// An `int` node's string was not a valid signed/unsigned 64-bit integer.
    #[error("integer is not a valid 64-bit integer")]
    InvalidInt,
    /// A `bytes` node's string was not valid hex.
    #[error("byte string is not valid hex")]
    InvalidBytes,
}

/// Serializes a tagged-JSON payload to canonical (deterministic) CBOR bytes.
///
/// The returned bytes are exactly what `rrn_crypto::serialize::to_canonical_bytes`
/// would produce for the equivalent Rust value — this is what makes a mobile
/// signature verify on the station and vice versa.
pub fn canonical_bytes(payload_json: String) -> Result<Vec<u8>, PayloadError> {
    let value: Value =
        serde_json::from_str(&payload_json).map_err(|_| PayloadError::InvalidJson)?;
    Ok(node_to_cbor(&value)?.to_cbor_data())
}

fn node_to_cbor(node: &Value) -> Result<CBOR, PayloadError> {
    let obj = node.as_object().ok_or(PayloadError::MalformedNode)?;
    if obj.len() != 1 {
        return Err(PayloadError::MalformedNode);
    }
    let (tag, inner) = obj.iter().next().expect("len checked to be 1");
    match tag.as_str() {
        "text" => Ok(CBOR::from(str_field(inner)?)),
        "int" => int_to_cbor(str_field(inner)?),
        "bytes" => {
            let bytes = hex::decode(str_field(inner)?).map_err(|_| PayloadError::InvalidBytes)?;
            Ok(CBOR::to_byte_string(bytes))
        }
        "bool" => Ok(CBOR::from(
            inner.as_bool().ok_or(PayloadError::MalformedNode)?,
        )),
        // The inner value is ignored on purpose — `{"null": null}` is idiomatic,
        // but any inner value is accepted as the null marker.
        "null" => Ok(CBOR::null()),
        "array" => {
            let items = inner
                .as_array()
                .ok_or(PayloadError::MalformedNode)?
                .iter()
                .map(node_to_cbor)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CBOR::from(items))
        }
        "map" => map_to_cbor(inner),
        // Recognized only to give floats a clean, named rejection.
        "float" => Err(PayloadError::FloatForbidden),
        _ => Err(PayloadError::MalformedNode),
    }
}

fn map_to_cbor(inner: &Value) -> Result<CBOR, PayloadError> {
    let entries = inner.as_array().ok_or(PayloadError::MalformedNode)?;
    let mut m = Map::new();
    for entry in entries {
        let pair = entry.as_array().ok_or(PayloadError::MalformedNode)?;
        if pair.len() != 2 {
            return Err(PayloadError::MalformedNode);
        }
        let key = pair[0].as_str().ok_or(PayloadError::MalformedNode)?;
        m.insert(key, node_to_cbor(&pair[1])?);
    }
    Ok(m.into())
}

fn str_field(inner: &Value) -> Result<&str, PayloadError> {
    inner.as_str().ok_or(PayloadError::MalformedNode)
}

/// Parses a decimal integer string into canonical CBOR. Tries `i64` first, then
/// `u64` for values above `i64::MAX`; a non-negative value encodes identically
/// either way (CBOR major type 0), so the choice never changes the bytes.
fn int_to_cbor(s: &str) -> Result<CBOR, PayloadError> {
    if let Ok(i) = s.parse::<i64>() {
        Ok(CBOR::from(i))
    } else if let Ok(u) = s.parse::<u64>() {
        Ok(CBOR::from(u))
    } else {
        Err(PayloadError::InvalidInt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::to_canonical_bytes;

    fn canon(json: &str) -> Vec<u8> {
        canonical_bytes(json.to_string()).expect("should canonicalize")
    }

    #[test]
    fn matches_dcbor_documented_vector() {
        // dcbor's own vector: {"key": 123} → a1636b6579187b. Proves the tagged
        // path emits standard canonical dCBOR.
        let bytes = canon(r#"{"map":[["key",{"int":"123"}]]}"#);
        assert_eq!(hex::encode(bytes), "a1636b6579187b");
    }

    #[test]
    fn map_keys_are_canonically_sorted_regardless_of_input_order() {
        // dCBOR sorts map keys bytewise; the two inputs differ only in order.
        let a = canon(r#"{"map":[["a",{"int":"1"}],["b",{"int":"2"}]]}"#);
        let b = canon(r#"{"map":[["b",{"int":"2"}],["a",{"int":"1"}]]}"#);
        assert_eq!(a, b);
    }

    #[test]
    fn bytes_tag_produces_a_cbor_byte_string() {
        // Matches how Address / Hash / keys cross the boundary.
        let bytes = canon(r#"{"bytes":"00ff"}"#);
        // 0x42 = byte string of length 2, then 00 ff.
        assert_eq!(hex::encode(bytes), "4200ff");
    }

    #[test]
    fn full_u64_range_survives_the_json_hop() {
        let bytes = canon(r#"{"int":"18446744073709551615"}"#); // u64::MAX
        assert_eq!(hex::encode(bytes), "1bffffffffffffffff");
    }

    #[test]
    fn agrees_with_to_canonical_bytes_for_the_same_value() {
        // A hand-built dCBOR map and the tagged-JSON path must agree.
        let mut m = Map::new();
        m.insert("amount", 300i64);
        m.insert("memo", "lunch");
        let direct = to_canonical_bytes(m);
        let tagged = canon(r#"{"map":[["amount",{"int":"300"}],["memo",{"text":"lunch"}]]}"#);
        assert_eq!(direct, tagged);
    }

    #[test]
    fn float_tag_is_a_clean_named_error() {
        let err = canonical_bytes(r#"{"float":2.5}"#.to_string()).unwrap_err();
        assert!(matches!(err, PayloadError::FloatForbidden), "{err:?}");
    }

    #[test]
    fn raw_json_number_is_rejected_not_silently_coerced() {
        // A bare number is not a tagged node — floats can never sneak in as JSON.
        let err = canonical_bytes(r#"2.5"#.to_string()).unwrap_err();
        assert!(matches!(err, PayloadError::MalformedNode), "{err:?}");
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert!(matches!(
            canonical_bytes("not json".to_string()).unwrap_err(),
            PayloadError::InvalidJson
        ));
        assert!(matches!(
            canonical_bytes(r#"{"int":"12.5"}"#.to_string()).unwrap_err(),
            PayloadError::InvalidInt
        ));
        assert!(matches!(
            canonical_bytes(r#"{"bytes":"xyz"}"#.to_string()).unwrap_err(),
            PayloadError::InvalidBytes
        ));
        assert!(matches!(
            canonical_bytes(r#"{"unknown":1}"#.to_string()).unwrap_err(),
            PayloadError::MalformedNode
        ));
        assert!(matches!(
            canonical_bytes(r#"{"text":"a","extra":"b"}"#.to_string()).unwrap_err(),
            PayloadError::MalformedNode
        ));
    }
}
