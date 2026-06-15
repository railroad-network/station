#![no_main]
//! Fuzz hash chaining: fold an arbitrary sequence of byte buffers into a
//! running hash, `Hash::of(prev ‖ next)` — the same shape as the append-only
//! log's entry chaining. Must never panic for any input sizes or count.

use libfuzzer_sys::fuzz_target;
use rrn_crypto::hash::Hash;

fuzz_target!(|chunks: Vec<Vec<u8>>| {
    let mut acc = Hash::of(b"");
    for next in &chunks {
        let mut buf = acc.to_bytes().to_vec();
        buf.extend_from_slice(next);
        acc = Hash::of(&buf);
    }
    // Touch the result so the chain isn't optimized away.
    std::hint::black_box(acc.to_bytes());
});
