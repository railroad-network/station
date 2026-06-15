//! Canonical (deterministic) CBOR serialization.
//!
//! Anything that gets signed must produce one — and only one — byte sequence,
//! across platforms, library versions, and struct field orderings. Otherwise
//! the same logical value could carry multiple valid signatures, or a peer
//! could craft a value that verifies under one canonicalization but not
//! another.
//!
//! This module wraps [`dcbor`] (Deterministic CBOR, RFC 8949 §4.2.1), which is
//! canonical *by construction*: map keys are emitted in bytewise-sorted order,
//! integers in shortest form, with no indefinite-length items. There is no
//! bespoke sorting/encoding layer here to get wrong — that is the entire reason
//! `dcbor` was chosen over a serde-based encoder. See
//! [ADR-0002](../../../docs/adr/0002-canonical-serialization-dcbor.md).
//!
//! # The type model is native `dcbor`, not serde
//!
//! A value is canonically serializable iff it implements `Into<CBOR>` (encode)
//! and `TryFrom<CBOR>` (decode). This is deliberate: `dcbor` has no serde
//! integration, and bridging serde onto it would reintroduce exactly the
//! audit-critical encoder code ADR-0002 set out to avoid. Each signed type
//! therefore provides a small, explicit `From<T> for CBOR` /
//! `TryFrom<CBOR> for T` mapping. `dcbor`'s stricter-than-serde type model is a
//! feature: if a value doesn't fit it cleanly, it probably should not be in a
//! signed payload.
//!
//! # Floats
//!
//! `dcbor` *can* encode floats deterministically (it canonicalizes NaN and
//! reduces integral floats to integers), so floats are not a canonicalization
//! hazard here. They remain **forbidden in signed monetary/amount payloads** by
//! project policy: amounts are integer centicommons, never floats, to avoid
//! precision ambiguity. That rule is enforced by review and by types simply not
//! exposing a float field — not by this layer.

use dcbor::prelude::*;

/// Serializes a value to canonical (deterministic) CBOR bytes.
///
/// Infallible: conversion to [`CBOR`] is total (`Into<CBOR>`), and canonical
/// encoding of a `CBOR` value cannot fail.
pub fn to_canonical_bytes<T: Into<CBOR>>(value: T) -> Vec<u8> {
    value.into().to_cbor_data()
}

/// Deserializes a value from canonical CBOR bytes.
///
/// Returns [`SerializeError::NotCanonical`] if `bytes` is not valid dCBOR
/// (including non-canonical encodings — e.g. unsorted map keys or non-shortest
/// integers — which are rejected, not silently accepted), and
/// [`SerializeError::WrongShape`] if the decoded CBOR does not match `T`.
pub fn from_canonical_bytes<T>(bytes: &[u8]) -> Result<T, SerializeError>
where
    T: TryFrom<CBOR>,
    <T as TryFrom<CBOR>>::Error: core::fmt::Display,
{
    let cbor =
        CBOR::try_from_data(bytes).map_err(|e| SerializeError::NotCanonical(e.to_string()))?;
    T::try_from(cbor).map_err(|e| SerializeError::WrongShape(e.to_string()))
}

/// An error from canonical (de)serialization.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SerializeError {
    /// The bytes are not valid deterministic CBOR — malformed, or encoded in a
    /// non-canonical form that dCBOR rejects (unsorted keys, non-shortest
    /// integers, indefinite-length items, trailing data, non-NFC strings).
    #[error("not canonical CBOR: {0}")]
    NotCanonical(String),
    /// The bytes decoded as valid CBOR, but the structure did not match the
    /// target type.
    #[error("CBOR did not match the target type: {0}")]
    WrongShape(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Two structs carrying the same logical data, but declaring and inserting
    // their fields in opposite order. Canonical CBOR must encode them to
    // identical bytes — proving determinism does not depend on field order.
    #[derive(Clone, Debug, PartialEq)]
    struct Ab {
        a: u64,
        b: String,
    }
    #[derive(Clone, Debug)]
    struct Ba {
        b: String,
        a: u64,
    }

    impl From<Ab> for CBOR {
        fn from(v: Ab) -> Self {
            let mut m = Map::new();
            m.insert("a", v.a);
            m.insert("b", v.b);
            m.into()
        }
    }
    impl From<Ba> for CBOR {
        fn from(v: Ba) -> Self {
            let mut m = Map::new();
            // Deliberately the opposite insertion order from `Ab`.
            m.insert("b", v.b);
            m.insert("a", v.a);
            m.into()
        }
    }

    impl TryFrom<CBOR> for Ab {
        type Error = dcbor::Error;
        fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
            match cbor.into_case() {
                CBORCase::Map(map) => Ok(Ab {
                    a: map.extract::<&str, u64>("a")?,
                    b: map.extract::<&str, String>("b")?,
                }),
                _ => Err(dcbor::Error::WrongType),
            }
        }
    }

    #[test]
    fn matches_dcbor_canonical_vector() {
        // dcbor's own documented vector: {"key": 123} → a1636b6579187b.
        // Confirms our wrapper emits standard canonical dCBOR, not something
        // bespoke.
        let mut m = Map::new();
        m.insert("key", 123u64);
        assert_eq!(hex::encode(to_canonical_bytes(m)), "a1636b6579187b");
    }

    #[test]
    fn float_encodes_deterministically() {
        // dCBOR has no serde escape hatch; floats reach the encoder only via an
        // explicit `From<f64>`. They ARE deterministic (this is the documented
        // behavior), but project policy keeps them out of signed amounts.
        let once = CBOR::from(2.5_f64).to_cbor_data();
        let twice = CBOR::from(2.5_f64).to_cbor_data();
        assert_eq!(once, twice);
    }

    #[test]
    fn text_is_nfc_normalized() {
        // dCBOR requires text strings in Unicode NFC. A non-NFC string (here a
        // CJK *compatibility* ideograph, U+FA0C, which has a canonical
        // decomposition) is normalized on encode, so it does NOT round-trip to
        // its original codepoint — it becomes its NFC form. This is intended
        // canonicalization: canonically-equivalent strings encode identically,
        // so signed payloads must treat text as NFC.
        let non_nfc = "\u{FA0C}".to_string();
        let normalized: String =
            from_canonical_bytes(&to_canonical_bytes(non_nfc.clone())).expect("string decodes");
        assert_ne!(
            normalized, non_nfc,
            "expected NFC normalization to change the string"
        );

        // Once normalized, it is stable (idempotent under re-encoding).
        let again: String =
            from_canonical_bytes(&to_canonical_bytes(normalized.clone())).expect("string decodes");
        assert_eq!(again, normalized);
    }

    #[test]
    fn rejects_non_canonical_input() {
        // 0x1817 is the integer 23 encoded in a non-shortest form (it fits in
        // the single byte 0x17). dCBOR must reject it rather than accept an
        // alternate encoding of the same value.
        let err = from_canonical_bytes::<u64>(&[0x18, 0x17]).unwrap_err();
        assert!(matches!(err, SerializeError::NotCanonical(_)), "{err:?}");
    }

    proptest! {
        #[test]
        fn encoding_is_deterministic(a in any::<u64>(), b in ".*") {
            let value = Ab { a, b };
            prop_assert_eq!(to_canonical_bytes(value.clone()), to_canonical_bytes(value));
        }

        #[test]
        fn field_order_does_not_change_bytes(a in any::<u64>(), b in ".*") {
            let ab = to_canonical_bytes(Ab { a, b: b.clone() });
            let ba = to_canonical_bytes(Ba { b, a });
            prop_assert_eq!(ab, ba);
        }

        #[test]
        // ASCII is already NFC, so it round-trips byte-identically; non-NFC
        // text is normalized on encode (see `text_is_nfc_normalized`).
        fn roundtrips(a in any::<u64>(), b in "[ -~]*") {
            let original = Ab { a, b };
            let bytes = to_canonical_bytes(original.clone());
            let decoded: Ab = from_canonical_bytes(&bytes).unwrap();
            prop_assert_eq!(original, decoded);
        }
    }
}
