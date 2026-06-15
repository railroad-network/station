#![no_main]
//! Fuzz the canonical-CBOR decoder against arbitrary bytes: it must reject
//! malformed or non-canonical input with an error, never panic.
//!
//! The task spec suggested `from_canonical_bytes::<serde_json::Value>`, but
//! under the native-`dcbor` model (ADR-0002) the generic-shape target type is
//! `dcbor::CBOR` itself — `dcbor` has no serde integration. `CBOR` decodes any
//! well-formed dCBOR value, so it is the right "decode anything" probe here.

use dcbor::CBOR;
use libfuzzer_sys::fuzz_target;
use rrn_crypto::serialize::from_canonical_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = from_canonical_bytes::<CBOR>(data);
});
