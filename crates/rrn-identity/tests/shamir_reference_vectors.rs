//! Cross-validation of our own Shamir implementation against independent,
//! published references — the "did we roll our own correctly?" test (T0.4.5).
//!
//! Three sections, all over GF(256) under the Rijndael polynomial (0x11B,
//! generator `x+1`), the field our [`rrn_identity::recovery`] uses and the one
//! SLIP-0039 / `shamir-mnemonic` use:
//!
//! 1. **Hand-computed vectors** — tiny cases whose expected shards are computed
//!    by hand with GF(256) arithmetic and locked in as literals.
//! 2. **SLIP-0039 reference** — shares produced by Trezor's `shamir-mnemonic`
//!    (the SLIP-0039 reference implementation) `_split_secret`, which pins the
//!    secret at index 255; our reconstruction re-indexes the member shares by
//!    `^255` so the secret lands at `x = 0` and must recover it.
//! 3. **Cross-implementation** — 60+ explicit-coefficient splits whose expected
//!    shards were produced by an independent evaluator certified against
//!    `shamir-mnemonic`'s published `_interpolate`; we reproduce them
//!    byte-for-byte.
//!
//! The fixtures for sections 2 and 3 are committed JSON
//! (`tests/fixtures/shamir_vectors.json`), so the test has no Python dependency.
//! See `tests/fixtures/README.md` for how they were generated and how to
//! regenerate them.

use rrn_identity::recovery::shamir::{
    reconstruct_secret, split_with_coefficients, RawShard, ShardIndex,
};
use serde::Deserialize;

// --- Section 1: hand-computed vectors ---------------------------------------

/// Builds a uniform-byte coefficient set: every one of the 32 positions uses the
/// same byte, so a single position's arithmetic (shown in the comments) is
/// representative of the whole shard and the case is genuinely hand-checkable.
fn uniform_coeffs(bytes: &[u8]) -> Vec<[u8; 32]> {
    bytes.iter().map(|&b| [b; 32]).collect()
}

fn assert_uniform_shards(shards: &[RawShard], expected_bytes: &[u8]) {
    assert_eq!(shards.len(), expected_bytes.len());
    for (i, (shard, &b)) in shards.iter().zip(expected_bytes).enumerate() {
        assert_eq!(shard.index.0 as usize, i + 1, "index mismatch");
        assert_eq!(shard.data, [b; 32], "shard {} data mismatch", i + 1);
    }
}

#[test]
fn hand_vector_k2_n2() {
    // f(x) = 0x53 + 0xCA·x over GF(256).
    //   f(1) = 0x53 ⊕ (0xCA·1) = 0x53 ⊕ 0xCA = 0x99
    //   f(2) = 0x53 ⊕ (0xCA·2); 0xCA·2 = xtime(0xCA) = (0xCA<<1) ⊕ 0x1B
    //          = 0x94 ⊕ 0x1B = 0x8F; so f(2) = 0x53 ⊕ 0x8F = 0xDC
    let secret = [0x53u8; 32];
    let shards = split_with_coefficients(&secret, 2, &uniform_coeffs(&[0xCA])).unwrap();
    assert_uniform_shards(&shards, &[0x99, 0xDC]);
}

#[test]
fn hand_vector_k2_n3() {
    // f(x) = 0x2A + 0x07·x over GF(256).
    //   f(1) = 0x2A ⊕ 0x07         = 0x2D
    //   f(2) = 0x2A ⊕ (0x07·2=0x0E) = 0x24
    //   f(3) = 0x2A ⊕ (0x07·3=0x09) = 0x23
    let secret = [0x2Au8; 32];
    let shards = split_with_coefficients(&secret, 3, &uniform_coeffs(&[0x07])).unwrap();
    assert_uniform_shards(&shards, &[0x2D, 0x24, 0x23]);
}

#[test]
fn hand_vector_k3_n5() {
    // f(x) = 0x11 + 0x80·x + 0x1B·x²  (degree 2, threshold 3).
    // Worked out byte-by-byte with GF(256) arithmetic; expected evaluations at
    // x = 1..=5 are 0x8A, 0x66, 0xFD, 0x8C, 0x17 (see fixtures README / the
    // generator's gmul). A K=3 subset of these must reconstruct 0x11.
    let secret = [0x11u8; 32];
    let shards = split_with_coefficients(&secret, 5, &uniform_coeffs(&[0x80, 0x1B])).unwrap();
    assert_uniform_shards(&shards, &[0x8A, 0x66, 0xFD, 0x8C, 0x17]);

    // And it round-trips from a 3-subset.
    let subset = vec![shards[0].clone(), shards[2].clone(), shards[4].clone()];
    assert_eq!(reconstruct_secret(&subset).unwrap(), secret);
}

// --- Fixture model (sections 2 & 3) -----------------------------------------

#[derive(Deserialize)]
struct Fixtures {
    cross_impl: Vec<CrossImplCase>,
    slip0039: Vec<Slip0039Case>,
}

#[derive(Deserialize)]
struct CrossImplCase {
    threshold: u8,
    total: u8,
    secret: String,
    coefficients: Vec<String>,
    shards: Vec<ShardVec>,
}

#[derive(Deserialize)]
struct ShardVec {
    index: u8,
    data: String,
}

#[derive(Deserialize)]
struct Slip0039Case {
    threshold: u8,
    total: u8,
    secret_index: u8,
    secret: String,
    member_shares: Vec<ShardVec>,
}

fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex");
    bytes.as_slice().try_into().expect("32 bytes")
}

fn load_fixtures() -> Fixtures {
    let raw = include_str!("fixtures/shamir_vectors.json");
    serde_json::from_str(raw).expect("fixtures parse")
}

// --- Section 3: cross-implementation byte-for-byte --------------------------

#[test]
fn cross_impl_split_matches_byte_for_byte() {
    let fixtures = load_fixtures();
    assert!(
        fixtures.cross_impl.len() >= 50,
        "expected 50+ cross-impl vectors, got {}",
        fixtures.cross_impl.len()
    );

    for (n, case) in fixtures.cross_impl.iter().enumerate() {
        let secret = hex32(&case.secret);
        let coeffs: Vec<[u8; 32]> = case.coefficients.iter().map(|c| hex32(c)).collect();
        assert_eq!(
            coeffs.len(),
            case.threshold as usize - 1,
            "case {n}: coefficient count"
        );

        let shards = split_with_coefficients(&secret, case.total, &coeffs)
            .unwrap_or_else(|e| panic!("case {n}: split failed: {e}"));
        assert_eq!(shards.len(), case.shards.len(), "case {n}: shard count");

        for (got, want) in shards.iter().zip(&case.shards) {
            assert_eq!(got.index.0, want.index, "case {n}: shard index");
            assert_eq!(
                hex::encode(got.data),
                want.data,
                "case {n}: shard {} data differs from reference",
                want.index
            );
        }

        // And the reference shards reconstruct to the secret through our
        // interpolation, for a threshold-sized prefix.
        let subset: Vec<RawShard> = shards
            .iter()
            .take(case.threshold as usize)
            .cloned()
            .collect();
        assert_eq!(
            reconstruct_secret(&subset).unwrap(),
            secret,
            "case {n}: reconstruction"
        );
    }
}

// --- Section 2: SLIP-0039 reference reconstruction --------------------------

#[test]
fn slip0039_member_shares_reconstruct_to_secret() {
    let fixtures = load_fixtures();
    assert!(!fixtures.slip0039.is_empty(), "expected SLIP-0039 vectors");

    for (n, case) in fixtures.slip0039.iter().enumerate() {
        let secret = hex32(&case.secret);
        assert_eq!(
            case.secret_index, 255,
            "case {n}: SLIP-0039 secret index is 255"
        );

        // SLIP-0039 pins the secret at x = 255 and interpolates member shares
        // there. Our reconstruct_secret interpolates at x = 0, so re-index each
        // member share by XOR 255 (field addition of the constant 255): the
        // polynomial g(t) = f(t + 255) then has g(0) = f(255) = secret, and our
        // x=0 interpolation recovers it. A threshold-sized subset suffices.
        let reindexed: Vec<RawShard> = case
            .member_shares
            .iter()
            .take(case.threshold as usize)
            .map(|s| RawShard {
                index: ShardIndex(s.index ^ 255),
                data: hex32(&s.data),
            })
            .collect();
        assert_eq!(reindexed.len(), case.threshold as usize);

        let recovered = reconstruct_secret(&reindexed)
            .unwrap_or_else(|e| panic!("case {n} (k={}, n={}): {e}", case.threshold, case.total));
        assert_eq!(
            recovered, secret,
            "case {n}: SLIP-0039 reference shares did not reconstruct the secret"
        );
    }
}
