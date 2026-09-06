//! Paper / QR text-encoding tests (T2.5.1): a proptest roundtrip over the
//! multi-part chunker/reassembler, and golden fixtures — one exact-string example
//! per scheme prefix, committed under `tests/fixtures/paper/` so the mobile repo
//! can verify its own parser against byte-identical vectors.
//!
//! The fixtures are built from fully-specified deterministic input bytes (a paper
//! payload is opaque bytes to this layer, so no signing is needed to pin the
//! encoding). Regenerate with:
//!   RRN_REGEN=1 cargo test -p rrn-protocol --test paper_qr
//! then copy `tests/fixtures/paper/` into the mobile repo's paper-parser vectors.

use std::path::PathBuf;

use proptest::prelude::*;

use rrn_protocol::paper::{
    classify, decode_certificate, decode_spend_voucher, encode_certificate, encode_chunks,
    encode_spend_voucher, PaperKind, PaperPayloadKind, PaperReassembler, SpendVoucher,
    CHUNK_PAYLOAD_BYTES, MAX_CHUNKS,
};
use rrn_protocol::transport::mock::SplitMix64;

/// The largest payload the multi-part form can carry (64 chunks × 720 bytes).
const MAX_MULTIPART_PAYLOAD: usize = MAX_CHUNKS * CHUNK_PAYLOAD_BYTES;

proptest! {
    /// Chunk a payload of 0..64 KiB, deliver the chunks shuffled and with a random
    /// subset duplicated, and get exactly the original payload back — or, for a
    /// payload past the 64-chunk capacity, a clean `TooManyChunks` refusal at
    /// encode. Mirrors T2.2.5's framing roundtrip proptest.
    #[test]
    fn chunks_reassemble_under_shuffle_and_duplication(
        payload in proptest::collection::vec(any::<u8>(), 0..(64 * 1024)),
        seed in any::<u64>(),
    ) {
        match encode_chunks(PaperKind::Bundle, &payload) {
            Ok(chunks) => {
                // Every emitted string stays within the acceptance bound.
                for c in &chunks {
                    prop_assert!(c.len() <= 1100, "emitted string {} chars", c.len());
                }
                let mut rng = SplitMix64::new(seed);
                // A random permutation of the chunk indexes...
                let mut order: Vec<usize> = (0..chunks.len()).collect();
                for i in (1..order.len()).rev() {
                    let j = rng.below(i + 1);
                    order.swap(i, j);
                }
                // ...with a random subset each delivered twice.
                let mut delivery = Vec::new();
                for idx in order {
                    delivery.push(idx);
                    if rng.next_f64() < 0.3 {
                        delivery.push(idx);
                    }
                }
                let mut r = PaperReassembler::new();
                let mut got = None;
                for idx in delivery {
                    match r.accept(&chunks[idx]) {
                        Ok(Some(out)) => got = Some(out),
                        Ok(None) => {}
                        Err(e) => prop_assert!(false, "unexpected paper error: {e}"),
                    }
                }
                prop_assert_eq!(got, Some((PaperKind::Bundle, payload)));
            }
            Err(rrn_protocol::paper::PaperError::TooManyChunks { .. }) => {
                // Only a payload past capacity may be refused.
                prop_assert!(payload.len() > MAX_MULTIPART_PAYLOAD);
            }
            Err(e) => prop_assert!(false, "unexpected encode error: {e}"),
        }
    }
}

// --- golden fixtures --------------------------------------------------------

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("paper")
        .join(name)
}

/// Reads a fixture, or — under `RRN_REGEN=1` — writes `actual` to it and returns
/// it, so a deliberate wire change regenerates in one run. The file stores one
/// emitted QR string per line.
fn golden(name: &str, actual: &[String]) -> Vec<String> {
    let path = fixture_path(name);
    let joined = actual.join("\n");
    if std::env::var("RRN_REGEN").is_ok() {
        std::fs::write(&path, format!("{joined}\n")).expect("write fixture");
        return actual.to_vec();
    }
    let stored = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read fixture {}: {e} (run with RRN_REGEN=1)",
            path.display()
        )
    });
    stored.lines().map(str::to_string).collect()
}

/// The deterministic bundle payload behind `multipart_bundle.txt`: 1500 bytes of
/// `b[i] = (i * 31 + 7) mod 256`. Documented so the mobile repo reproduces it.
fn fixture_bundle_payload() -> Vec<u8> {
    (0..1500u32)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// The deterministic certificate envelope behind `certificate.txt`: 300 bytes of
/// `b[i] = (i * 17 + 3) mod 256`.
fn fixture_cert_envelope() -> Vec<u8> {
    (0..300u32)
        .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
        .collect()
}

/// The deterministic voucher behind `spend_voucher.txt` (single-QR).
fn fixture_voucher() -> SpendVoucher {
    SpendVoucher {
        proposal: (0..120u32)
            .map(|i| (i.wrapping_mul(5).wrapping_add(1)) as u8)
            .collect(),
        cert: (0..90u32)
            .map(|i| (i.wrapping_mul(9).wrapping_add(2)) as u8)
            .collect(),
        history: vec![(0..80u32).map(|i| (i.wrapping_mul(3)) as u8).collect()],
    }
}

/// The deterministic large voucher behind `voucher_multipart.txt` — a long
/// history pushes it past the single-QR budget so it rides as `rrnp:s/…` chunks,
/// exercising the kind-`s` route end-to-end for the mobile parser.
fn fixture_large_voucher() -> SpendVoucher {
    SpendVoucher {
        proposal: (0..300u32)
            .map(|i| (i.wrapping_mul(5).wrapping_add(1)) as u8)
            .collect(),
        cert: (0..285u32)
            .map(|i| (i.wrapping_mul(9).wrapping_add(2)) as u8)
            .collect(),
        history: (0..6u32)
            .map(|h| {
                (0..300u32)
                    .map(|i| (i.wrapping_mul(7).wrapping_add(h)) as u8)
                    .collect()
            })
            .collect(),
    }
}

#[test]
fn golden_multipart_bundle() {
    let payload = fixture_bundle_payload();
    let chunks = encode_chunks(PaperKind::Bundle, &payload).unwrap();
    let stored = golden("multipart_bundle.txt", &chunks);
    assert_eq!(stored, chunks, "multipart bundle strings drifted");
    // The committed strings classify and reassemble back to the exact payload.
    for c in &stored {
        assert_eq!(classify(c), PaperPayloadKind::Multipart);
    }
    let mut r = PaperReassembler::new();
    let mut got = None;
    for c in &stored {
        if let Some(out) = r.accept(c).unwrap() {
            got = Some(out);
        }
    }
    assert_eq!(got, Some((PaperKind::Bundle, payload)));
}

#[test]
fn golden_certificate() {
    let envelope = fixture_cert_envelope();
    let s = encode_certificate(&envelope);
    let stored = golden("certificate.txt", std::slice::from_ref(&s));
    assert_eq!(stored, vec![s], "certificate string drifted");
    assert_eq!(classify(&stored[0]), PaperPayloadKind::Certificate);
    assert_eq!(decode_certificate(&stored[0]).unwrap(), envelope);
}

#[test]
fn golden_spend_voucher() {
    let voucher = fixture_voucher();
    let strings = encode_spend_voucher(&voucher).unwrap();
    // This voucher is small enough for a single QR.
    assert_eq!(strings.len(), 1);
    let stored = golden("spend_voucher.txt", &strings);
    assert_eq!(stored, strings, "spend voucher string drifted");
    assert_eq!(classify(&stored[0]), PaperPayloadKind::SpendVoucher);
    assert_eq!(decode_spend_voucher(&stored[0]).unwrap(), voucher);
}

#[test]
fn golden_multipart_spend_voucher() {
    let voucher = fixture_large_voucher();
    let strings = encode_spend_voucher(&voucher).unwrap();
    // A long history overflows to `rrnp:s/…` chunks.
    assert!(
        strings.len() > 1,
        "expected multi-part, got {}",
        strings.len()
    );
    let stored = golden("voucher_multipart.txt", &strings);
    assert_eq!(stored, strings, "multipart voucher strings drifted");
    for c in &stored {
        assert!(c.starts_with("rrnp:s/"));
        assert_eq!(classify(c), PaperPayloadKind::Multipart);
    }
    // Reassemble the chunks, then decode the container back to the exact voucher.
    let mut r = PaperReassembler::new();
    let mut got = None;
    for c in &stored {
        if let Some(out) = r.accept(c).unwrap() {
            got = Some(out);
        }
    }
    let (kind, bytes) = got.unwrap();
    assert_eq!(kind, PaperKind::SpendVoucher);
    assert_eq!(SpendVoucher::decode(&bytes).unwrap(), voucher);
}
