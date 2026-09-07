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

/// Maximum CBOR container-nesting depth accepted by [`checked_from_data`] and
/// [`from_canonical_bytes`].
///
/// `dcbor` decodes recursively — one stack frame per array, map, or tagged
/// level — with no depth limit of its own (verified against dcbor 0.25). So an
/// attacker-supplied chain of nested containers (a few bytes each) can drive the
/// decoder past the thread's stack and **abort the whole process** before any
/// type or signature check runs — empirically tens of thousands of levels deep
/// on a main thread, and far fewer on the smaller stacks of mobile FFI worker
/// threads. No legitimate signed payload in this system nests beyond a handful
/// of levels, so this bound sits an order of magnitude above real depth while
/// keeping the decoder's stack use trivial even on constrained threads. Input
/// deeper than this is **rejected as malformed, never truncated or decoded**.
pub const MAX_CBOR_DEPTH: usize = 128;

/// Decodes bytes to an untyped [`CBOR`] tree, first rejecting input that nests
/// deeper than [`MAX_CBOR_DEPTH`] container levels.
///
/// Prefer this over calling `dcbor`'s [`CBOR::try_from_data`] directly at **any
/// boundary that decodes untrusted bytes**: the depth pre-scan runs first, so a
/// hostile deeply-nested payload is refused with [`SerializeError::TooDeeplyNested`]
/// instead of overflowing the recursive decoder's stack and aborting the
/// process. [`from_canonical_bytes`] already routes through it; call this
/// directly when you need the untyped `CBOR` — e.g. to read a `kind`
/// discriminator from the map before dispatching to a concrete type.
///
/// The pre-scan is iterative (an explicit work stack, never recursion) so it
/// cannot itself overflow, runs in a single O(n) pass, and is deliberately
/// lenient about every *other* canonical-form rule — non-canonical integers,
/// unsorted keys, trailing bytes, truncation are all left for the real decoder
/// that runs immediately after to reject. Its one job is to bound depth.
pub fn checked_from_data(bytes: &[u8]) -> Result<CBOR, SerializeError> {
    ensure_depth_within_limit(bytes)?;
    CBOR::try_from_data(bytes).map_err(|e| SerializeError::NotCanonical(e.to_string()))
}

/// Deserializes a value from canonical CBOR bytes.
///
/// Returns [`SerializeError::TooDeeplyNested`] if `bytes` nests deeper than
/// [`MAX_CBOR_DEPTH`] (checked before decoding, see [`checked_from_data`]),
/// [`SerializeError::NotCanonical`] if `bytes` is not valid dCBOR (including
/// non-canonical encodings — e.g. unsorted map keys or non-shortest integers —
/// which are rejected, not silently accepted), and [`SerializeError::WrongShape`]
/// if the decoded CBOR does not match `T`.
pub fn from_canonical_bytes<T>(bytes: &[u8]) -> Result<T, SerializeError>
where
    T: TryFrom<CBOR>,
    <T as TryFrom<CBOR>>::Error: core::fmt::Display,
{
    let cbor = checked_from_data(bytes)?;
    T::try_from(cbor).map_err(|e| SerializeError::WrongShape(e.to_string()))
}

/// Reads one CBOR item header at `data[pos..]`, returning
/// `(major_type_bits, argument_value, header_len)`, or `None` if the header is
/// truncated or uses an additional-info value the deterministic decoder rejects
/// (28–30 reserved, or 31 indefinite-length). A `None` means "this is not the
/// start of a well-formed dCBOR item"; the caller then stops scanning and lets
/// the real decoder report the precise error — nothing deeper can be reached
/// past a byte the decoder itself refuses. Mirrors `dcbor`'s header parsing for
/// *length*, but skips its canonical-value checks (leniency here is safe: the
/// real decoder re-checks).
fn read_item_header(data: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
    let first = *data.get(pos)?;
    let major = first >> 5;
    let ai = first & 0x1f;
    let (value, arg_len) = match ai {
        0..=23 => (u64::from(ai), 0usize),
        24 => (u64::from(*data.get(pos + 1)?), 1),
        25 => {
            let b = data.get(pos + 1..pos + 3)?;
            ((u64::from(b[0]) << 8) | u64::from(b[1]), 2)
        }
        26 => {
            let b = data.get(pos + 1..pos + 5)?;
            let mut v = 0u64;
            for &x in b {
                v = (v << 8) | u64::from(x);
            }
            (v, 4)
        }
        27 => {
            let b = data.get(pos + 1..pos + 9)?;
            let mut v = 0u64;
            for &x in b {
                v = (v << 8) | u64::from(x);
            }
            (v, 8)
        }
        // 28,29,30 reserved; 31 indefinite-length — dCBOR rejects all of them.
        _ => return None,
    };
    Some((major, value, 1 + arg_len))
}

/// Rejects CBOR whose structural nesting would drive the recursive `dcbor`
/// decoder past [`MAX_CBOR_DEPTH`] frames. See [`checked_from_data`] for why and
/// [`MAX_CBOR_DEPTH`] for the bound. Iterative by construction — it walks the
/// bytes once with an explicit work stack of "items still to read at this
/// level", so the scan itself never recurses and cannot overflow.
fn ensure_depth_within_limit(data: &[u8]) -> Result<(), SerializeError> {
    // Each stack entry is the number of CBOR data items still to be read at that
    // open container level; the stack's length is the current nesting depth. A
    // map of n pairs is flattened to 2n items; a tag is one item at a new level.
    let mut stack: Vec<u64> = Vec::new();
    // A well-formed document is exactly one top-level item.
    let mut top_remaining: u64 = 1;
    let mut pos: usize = 0;

    loop {
        // Close any containers whose items have all been read.
        while stack.last() == Some(&0) {
            stack.pop();
        }
        // Account for consuming one item at the current level (an open
        // container, else the top level). When the top level is spent and every
        // container is closed, the single document item has been fully read.
        match stack.last_mut() {
            Some(remaining) => *remaining -= 1,
            None if top_remaining == 0 => return Ok(()),
            None => top_remaining -= 1,
        }

        let Some((major, value, header_len)) = read_item_header(data, pos) else {
            // Not a well-formed item start: the decoder will error here, and
            // nothing deeper is reachable past it, so depth is already bounded.
            return Ok(());
        };
        pos += header_len;

        match major {
            // Unsigned (0), negative (1), simple/float (7): no nested payload.
            0 | 1 | 7 => {}
            // Byte string (2), text (3): skip `value` opaque content bytes so
            // they are never mistaken for structure.
            2 | 3 => {
                let Ok(len) = usize::try_from(value) else {
                    return Ok(()); // absurd length -> decoder underruns; defer
                };
                match pos.checked_add(len) {
                    Some(end) if end <= data.len() => pos = end,
                    _ => return Ok(()), // underrun -> decoder rejects; defer
                }
            }
            // Array (4), map (5), tag (6): each is a level the decoder recurses
            // into. Opening it puts a frame at depth `stack.len() + 1`.
            4..=6 => {
                if stack.len() >= MAX_CBOR_DEPTH {
                    return Err(SerializeError::TooDeeplyNested {
                        max: MAX_CBOR_DEPTH,
                    });
                }
                let items = match major {
                    4 => value,                   // array: `value` items
                    5 => value.saturating_mul(2), // map: key + value per pair
                    _ => 1,                       // tag: exactly one content item
                };
                if items > 0 {
                    stack.push(items);
                }
            }
            // `major` is `u8 >> 5`, so 0..=7; nothing else is reachable.
            _ => return Ok(()),
        }
    }
}

/// An error from canonical (de)serialization.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SerializeError {
    /// The bytes nest deeper than [`MAX_CBOR_DEPTH`] container levels. Rejected
    /// *before* decoding, because dCBOR decodes recursively with no depth limit
    /// of its own: a deeply nested payload would otherwise overflow the thread
    /// stack and abort the process. Treated as malformed input, never decoded.
    #[error("CBOR nests deeper than the {max}-level limit")]
    TooDeeplyNested {
        /// The limit that was exceeded ([`MAX_CBOR_DEPTH`]).
        max: usize,
    },
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

    /// `depth` nested single-element arrays around an innermost integer `0`.
    /// `0x81` is "array of one item"; the trailing `0x00` is that item at the
    /// bottom. Decoding this recurses `depth + 1` frames in `dcbor`.
    fn nested_arrays(depth: usize) -> Vec<u8> {
        let mut v = vec![0x81u8; depth];
        v.push(0x00);
        v
    }

    /// `depth` nested single-pair maps: each `0xa1` is "map of one pair", `0x00`
    /// its key, and the value is the next map (or the innermost `0x00`).
    fn nested_maps(depth: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(depth * 2 + 1);
        for _ in 0..depth {
            v.push(0xa1); // map(1)
            v.push(0x00); // key: integer 0
        }
        v.push(0x00); // innermost value
        v
    }

    #[test]
    fn accepts_nesting_up_to_the_limit() {
        // Exactly MAX_CBOR_DEPTH nested containers must still decode.
        let bytes = nested_arrays(MAX_CBOR_DEPTH);
        assert!(checked_from_data(&bytes).is_ok(), "arrays at the limit");
        assert!(
            checked_from_data(&nested_maps(MAX_CBOR_DEPTH)).is_ok(),
            "maps at the limit"
        );
    }

    #[test]
    fn rejects_nesting_over_the_limit() {
        for over in [MAX_CBOR_DEPTH + 1, MAX_CBOR_DEPTH + 2] {
            assert_eq!(
                checked_from_data(&nested_arrays(over)).unwrap_err(),
                SerializeError::TooDeeplyNested {
                    max: MAX_CBOR_DEPTH
                },
                "arrays at depth {over}"
            );
            assert_eq!(
                checked_from_data(&nested_maps(over)).unwrap_err(),
                SerializeError::TooDeeplyNested {
                    max: MAX_CBOR_DEPTH
                },
                "maps at depth {over}"
            );
        }
    }

    #[test]
    fn deeply_nested_input_is_refused_not_a_stack_overflow() {
        // The regression this whole change exists for: a payload deep enough to
        // overflow `dcbor`'s recursive decoder (~46k deep aborts the process)
        // must be refused by the iterative pre-scan, which itself cannot
        // overflow. If the guard were absent this test would abort the runner.
        let bytes = nested_arrays(50_000);
        assert_eq!(
            checked_from_data(&bytes).unwrap_err(),
            SerializeError::TooDeeplyNested {
                max: MAX_CBOR_DEPTH
            },
        );
        // Chained tags (major 6) recurse in the decoder too and are counted.
        let deep_tags = {
            let mut v = vec![0xc0u8; 50_000]; // tag(0), repeated
            v.push(0x00);
            v
        };
        assert_eq!(
            checked_from_data(&deep_tags).unwrap_err(),
            SerializeError::TooDeeplyNested {
                max: MAX_CBOR_DEPTH
            },
        );
    }

    #[test]
    fn byte_string_content_is_not_counted_as_nesting() {
        // A byte string whose *content* happens to look like array headers must
        // be skipped as opaque bytes, not walked as structure. `0x58 0x03` is a
        // 3-byte byte string; its content `81 81 81` are three "array of one"
        // header bytes that must NOT add depth.
        let bytes = vec![0x58, 0x03, 0x81, 0x81, 0x81];
        // Depth is 0 open containers here, so the guard passes; whether dcbor
        // then accepts the exact encoding is beside the point — it must not be
        // TooDeeplyNested.
        assert!(!matches!(
            checked_from_data(&bytes),
            Err(SerializeError::TooDeeplyNested { .. })
        ));
    }

    #[test]
    fn shallow_and_empty_values_pass_the_guard() {
        for bytes in [
            vec![0x00],       // integer 0
            vec![0x80],       // empty array
            vec![0xa0],       // empty map
            vec![0x40],       // empty byte string
            vec![0x60],       // empty text string
            nested_arrays(4), // a realistically shallow structure
        ] {
            assert!(
                !matches!(
                    checked_from_data(&bytes),
                    Err(SerializeError::TooDeeplyNested { .. })
                ),
                "unexpected depth rejection for {bytes:02x?}"
            );
        }
    }

    #[test]
    fn typed_decode_also_rejects_deep_nesting() {
        // The typed path (`from_canonical_bytes`) must inherit the guard, not
        // just the untyped `checked_from_data`.
        let err = from_canonical_bytes::<Ab>(&nested_arrays(MAX_CBOR_DEPTH + 1)).unwrap_err();
        assert_eq!(
            err,
            SerializeError::TooDeeplyNested {
                max: MAX_CBOR_DEPTH
            }
        );
    }

    proptest! {
        #[test]
        fn guard_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            // The pre-scan must terminate with Ok/Err on any input, never panic
            // (no index-out-of-bounds, no arithmetic overflow).
            let _ = checked_from_data(&bytes);
        }

        #[test]
        fn nested_arrays_pass_iff_within_limit(depth in 0usize..=(MAX_CBOR_DEPTH + 32)) {
            let res = checked_from_data(&nested_arrays(depth));
            if depth <= MAX_CBOR_DEPTH {
                prop_assert!(res.is_ok(), "depth {} should decode", depth);
            } else {
                prop_assert_eq!(
                    res.unwrap_err(),
                    SerializeError::TooDeeplyNested { max: MAX_CBOR_DEPTH }
                );
            }
        }
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
