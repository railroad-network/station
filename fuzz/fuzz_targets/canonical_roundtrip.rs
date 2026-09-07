#![no_main]
//! Fuzz the canonical-CBOR decoder against arbitrary bytes: it must reject
//! malformed or non-canonical input with an error, never panic.
//!
//! The task spec suggested `from_canonical_bytes::<serde_json::Value>`, but
//! under the native-`dcbor` model (ADR-0002) the generic-shape target type is
//! `dcbor::CBOR` itself — `dcbor` has no serde integration. `CBOR` decodes any
//! well-formed dCBOR value, so it is the right "decode anything" probe here.
//!
//! `from_canonical_bytes` routes through `serialize::checked_from_data`, so this
//! target also exercises the CBOR depth guard: a deeply nested input is rejected
//! with `TooDeeplyNested` rather than overflowing the recursive decoder — and
//! were that guard ever removed, a nested-enough input would abort here and the
//! fuzzer would flag the crash.

use dcbor::CBOR;
use libfuzzer_sys::fuzz_target;
use rrn_crypto::serialize::from_canonical_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = from_canonical_bytes::<CBOR>(data);
});
