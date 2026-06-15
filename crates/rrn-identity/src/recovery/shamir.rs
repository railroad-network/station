//! Shamir's Secret Sharing: split a 32-byte secret into `N` shards of which any
//! `K` reconstruct it, and reconstruct it from `K` shards.
//!
//! # The scheme
//!
//! For each of the 32 byte positions independently, we draw a random polynomial
//! over GF(256) (see [`super::gf256`]) of degree `K-1` whose constant term is
//! that secret byte:
//!
//! ```text
//! f_i(x) = secret[i] + a_1·x + a_2·x² + … + a_{K-1}·x^{K-1}
//! ```
//!
//! Shard `s` (for `s in 1..=N`) is the tuple of evaluations
//! `(f_0(s), f_1(s), …, f_31(s))`. Because a degree-`K-1` polynomial is uniquely
//! determined by any `K` points, any `K` shards recover every `f_i`, and reading
//! off the constant terms `f_i(0)` gives the secret back. Fewer than `K` points
//! leave the polynomial — and so the secret — completely undetermined: that is
//! Shamir's information-theoretic security.
//!
//! # Why index 0 is forbidden as a share
//!
//! `f_i(0) = secret[i]` *is* the secret. Handing anyone the evaluation at `x = 0`
//! would hand them the secret outright, so share indices live in `1..=255` and
//! `0` is rejected on both the split and reconstruct paths.
//!
//! # Integrity is not Shamir's job
//!
//! A shard with a corrupted `y` value but a valid index still interpolates to
//! *some* 32-byte output — just not the original secret. Shamir provides no way
//! to tell. Detecting a tampered or wrong shard is the job of the encrypted
//! wrapper ([`super::encryption`]), whose AEAD tag fails on any modification.

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::gf256::Gf256;

/// The number of byte positions in a secret — an Ed25519 secret-key seed is 32
/// bytes, and we share each position independently.
const SECRET_LEN: usize = 32;

/// Phase 0 cap on the number of shards. Revisited only if a real deployment
/// needs more holders than this; see ADR-0004 / the task spec.
pub const MAX_SHARES: u8 = 16;

/// A share index — the `x` coordinate a shard is evaluated at.
///
/// Invariant: `1..=255`. Index `0` is the secret itself (`f_i(0) = secret[i]`)
/// and must never be used as a share; the constructors and reconstruction
/// enforce this.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShardIndex(pub u8);

/// A raw Shamir shard: one `x` index plus the 32 polynomial evaluations at that
/// index, one per secret byte position.
///
/// The `data` is sensitive — `K` of these together *are* the secret — so it is
/// zeroized on drop and redacted from `Debug`. A single shard alone reveals
/// nothing (information-theoretically), but the type takes no chances.
#[derive(Clone, PartialEq, Eq)]
pub struct RawShard {
    /// The share index `s` this shard was evaluated at (`1..=255`).
    pub index: ShardIndex,
    /// `f_i(index)` for each of the 32 byte-position polynomials.
    pub data: [u8; SECRET_LEN],
}

impl core::fmt::Debug for RawShard {
    /// Shows the index but redacts the (sensitive) shard data.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawShard")
            .field("index", &self.index.0)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for RawShard {
    fn zeroize(&mut self) {
        // Only `data` is sensitive; the index is a public coordinate.
        self.data.zeroize();
    }
}

impl Drop for RawShard {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for RawShard {}

/// Error from [`split_secret`].
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum SplitError {
    /// The threshold `K` is out of range: below `2`, or greater than the total
    /// `N` (a threshold you can never reach).
    #[error("invalid threshold: K must satisfy 2 <= K <= N")]
    InvalidThreshold,
    /// The total `N` is out of range: above the [`MAX_SHARES`] cap, or below the
    /// threshold `K`.
    #[error("invalid total: N must satisfy K <= N <= {MAX_SHARES}")]
    InvalidTotal,
}

/// Error from [`reconstruct_secret`].
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ReconstructError {
    /// Fewer than two shards were supplied — too few to interpolate anything.
    #[error("insufficient shards: need at least 2")]
    InsufficientShards,
    /// Two shards share an index, which makes the interpolation singular.
    #[error("duplicate shard index")]
    DuplicateIndex,
    /// A shard carries index `0`, forbidden because `f(0)` is the secret itself.
    #[error("shard has forbidden index 0")]
    ZeroIndex,
}

/// Splits a 32-byte `secret` into `total` shards, any `threshold` of which
/// reconstruct it.
///
/// `threshold` (`K`) must be at least `2` and at most `total`; `total` (`N`) at
/// most [`MAX_SHARES`]. Coefficients are drawn from `rng` (which must be a
/// `CryptoRng` — the secrecy of the scheme rests on them being unpredictable).
///
/// Determinism: for a fixed `secret`, `threshold`, `total`, and RNG state, the
/// output is identical; two different RNG states almost certainly differ.
pub fn split_secret(
    secret: &[u8; SECRET_LEN],
    threshold: u8,
    total: u8,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<RawShard>, SplitError> {
    // Validate K then N. K > N is reported as InvalidThreshold (an unreachable
    // threshold); N > MAX or N < K is InvalidTotal.
    if threshold < 2 || threshold > total {
        return Err(SplitError::InvalidThreshold);
    }
    if total > MAX_SHARES || total < threshold {
        return Err(SplitError::InvalidTotal);
    }

    let k = threshold as usize;

    // The K-1 non-constant coefficients for all 32 polynomials, one [u8; 32] per
    // degree (`coefficients[d]` = a_{d+1}, one byte per position), drawn in a
    // single RNG fill. They are not the secret on their own, but together with
    // the shards they shortcut its recovery, so they are zeroized once the
    // shards are evaluated.
    let mut coefficients = vec![[0u8; SECRET_LEN]; k - 1];
    for coeff in &mut coefficients {
        rng.fill_bytes(coeff);
    }

    let shards = split_with_coefficients(secret, total, &coefficients);

    for coeff in &mut coefficients {
        coeff.zeroize();
    }
    shards
}

/// The deterministic core of [`split_secret`]: evaluates the shards from an
/// explicit set of polynomial coefficients instead of drawing them from an RNG.
///
/// `coefficients[d]` holds the 32 bytes of the degree-`(d+1)` coefficient
/// `a_{d+1}` (one byte per secret position); there are `threshold - 1` of them,
/// so the implied threshold is `coefficients.len() + 1`. The total shard count
/// `total` must satisfy `threshold <= total <= MAX_SHARES`.
///
/// Exposed (rather than kept private) for two reasons: it is the seam the
/// reference-vector tests inject known coefficients through (T0.4.5), and it is a
/// legitimately useful *reproducible* split for callers who derive their own
/// coefficients deterministically. Such callers carry the obligation
/// [`split_secret`] otherwise discharges: the coefficients **must** be
/// unpredictable, or Shamir's secrecy is lost.
pub fn split_with_coefficients(
    secret: &[u8; SECRET_LEN],
    total: u8,
    coefficients: &[[u8; SECRET_LEN]],
) -> Result<Vec<RawShard>, SplitError> {
    // threshold = constant term + the K-1 supplied coefficients.
    let threshold = coefficients.len() + 1;
    if threshold < 2 || threshold > total as usize {
        return Err(SplitError::InvalidThreshold);
    }
    if total > MAX_SHARES {
        return Err(SplitError::InvalidTotal);
    }

    let mut shards = Vec::with_capacity(total as usize);
    for s in 1..=total {
        let x = Gf256::from_u8(s);
        let mut data = [0u8; SECRET_LEN];
        for (i, slot) in data.iter_mut().enumerate() {
            // Horner's method, highest degree down to the constant term:
            //   acc = a_{K-1}; acc = acc·x + a_{K-2}; … ; acc = acc·x + secret[i]
            let mut acc = Gf256::ZERO;
            for coeff in coefficients.iter().rev() {
                acc = acc.mul(x).add(Gf256::from_u8(coeff[i]));
            }
            acc = acc.mul(x).add(Gf256::from_u8(secret[i]));
            *slot = acc.to_u8();
        }
        shards.push(RawShard {
            index: ShardIndex(s),
            data,
        });
    }
    Ok(shards)
}

/// Reconstructs the secret from `shards` via Lagrange interpolation evaluated at
/// `x = 0`.
///
/// Requires at least two shards, all with distinct, nonzero indices. It does
/// **not** know the original threshold `K`: given fewer than `K` shards it
/// returns *a* 32-byte value (just not the original secret); given `K` or more
/// valid shards it returns the secret. Detecting a wrong/short set is out of
/// scope here — that is the encrypted wrapper's integrity check.
///
/// # Constant-time note
///
/// This is constant-time in the *values* of the secret and shard data (the
/// cryptographically relevant property), but **not** in the *number* of shards:
/// a different `K` runs a different number of loop iterations. The shard count
/// is not secret.
pub fn reconstruct_secret(shards: &[RawShard]) -> Result<[u8; SECRET_LEN], ReconstructError> {
    if shards.len() < 2 {
        return Err(ReconstructError::InsufficientShards);
    }

    // Indices must be nonzero and pairwise distinct.
    for (i, s) in shards.iter().enumerate() {
        if s.index.0 == 0 {
            return Err(ReconstructError::ZeroIndex);
        }
        for t in &shards[i + 1..] {
            if s.index.0 == t.index.0 {
                return Err(ReconstructError::DuplicateIndex);
            }
        }
    }

    let k = shards.len();

    // Lagrange basis evaluated at 0:
    //   l_j(0) = ∏_{m≠j} (0 - x_m) / (x_j - x_m)
    // In GF(256), -x = x and a - b = a ⊕ b, so this is
    //   l_j(0) = ∏_{m≠j} x_m / (x_j ⊕ x_m).
    // The basis depends only on the index set, so compute it once and reuse it
    // across all 32 byte positions.
    let mut basis = Vec::with_capacity(k);
    for (j, shard_j) in shards.iter().enumerate() {
        let xj = Gf256::from_u8(shard_j.index.0);
        let mut numerator = Gf256::ONE;
        let mut denominator = Gf256::ONE;
        for (m, shard_m) in shards.iter().enumerate() {
            if m == j {
                continue;
            }
            let xm = Gf256::from_u8(shard_m.index.0);
            numerator = numerator.mul(xm);
            denominator = denominator.mul(xj.add(xm)); // xj - xm
        }
        // The denominator is a product of differences of distinct, nonzero
        // indices, hence nonzero and invertible — guaranteed by the validation
        // above, so the inverse always exists.
        let inv = denominator
            .inv()
            .expect("distinct indices give a nonzero Lagrange denominator");
        basis.push(numerator.mul(inv));
    }

    let mut secret = [0u8; SECRET_LEN];
    for (i, out) in secret.iter_mut().enumerate() {
        let mut acc = Gf256::ZERO;
        for (j, shard) in shards.iter().enumerate() {
            let y = Gf256::from_u8(shard.data[i]);
            acc = acc.add(y.mul(basis[j]));
        }
        *out = acc.to_u8();
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn seeded_rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    // --- T0.4.3: split ------------------------------------------------------

    #[test]
    fn threshold_below_two_is_rejected() {
        let mut rng = seeded_rng(1);
        let err = split_secret(&[0u8; 32], 1, 5, &mut rng).unwrap_err();
        assert_eq!(err, SplitError::InvalidThreshold);
    }

    #[test]
    fn threshold_above_total_is_rejected() {
        let mut rng = seeded_rng(1);
        let err = split_secret(&[0u8; 32], 4, 3, &mut rng).unwrap_err();
        assert_eq!(err, SplitError::InvalidThreshold);
    }

    #[test]
    fn total_above_cap_is_rejected() {
        let mut rng = seeded_rng(1);
        let err = split_secret(&[0u8; 32], 2, 17, &mut rng).unwrap_err();
        assert_eq!(err, SplitError::InvalidTotal);
    }

    #[test]
    fn same_seed_gives_identical_shards() {
        let secret = [7u8; 32];
        let a = split_secret(&secret, 3, 5, &mut seeded_rng(42)).unwrap();
        let b = split_secret(&secret, 3, 5, &mut seeded_rng(42)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_give_different_shards() {
        let secret = [7u8; 32];
        let a = split_secret(&secret, 3, 5, &mut seeded_rng(1)).unwrap();
        let b = split_secret(&secret, 3, 5, &mut seeded_rng(2)).unwrap();
        assert_ne!(a, b);
    }

    proptest! {
        #[test]
        fn split_produces_well_formed_shards(
            secret in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
            // K in 2..=6, N in K..=16
            k in 2u8..=6,
            extra in 0u8..=10,
        ) {
            let n = (k + extra).min(MAX_SHARES);
            prop_assume!(n >= k);
            let mut rng = ChaCha20Rng::from_seed(seed);
            let shards = split_secret(&secret, k, n, &mut rng).unwrap();
            prop_assert_eq!(shards.len(), n as usize);
            for (idx, shard) in shards.iter().enumerate() {
                // Indices are exactly 1..=N, in order, never 0.
                prop_assert_eq!(shard.index.0, (idx + 1) as u8);
                prop_assert!(shard.index.0 >= 1);
                prop_assert_eq!(shard.data.len(), 32);
            }
        }
    }

    // --- T0.4.4: reconstruct ------------------------------------------------

    /// All `k`-element subsets of `0..n` (index combinations), for the
    /// exhaustive subset test.
    fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
        let mut out = Vec::new();
        let mut current = Vec::new();
        fn go(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
            if cur.len() == k {
                out.push(cur.clone());
                return;
            }
            for i in start..n {
                cur.push(i);
                go(i + 1, n, k, cur, out);
                cur.pop();
            }
        }
        go(0, n, k, &mut current, &mut out);
        out
    }

    fn subset(shards: &[RawShard], idxs: &[usize]) -> Vec<RawShard> {
        idxs.iter().map(|&i| shards[i].clone()).collect()
    }

    #[test]
    fn empty_or_single_shard_is_insufficient() {
        assert_eq!(
            reconstruct_secret(&[]).unwrap_err(),
            ReconstructError::InsufficientShards
        );
        let one = split_secret(&[1u8; 32], 2, 3, &mut seeded_rng(5)).unwrap();
        assert_eq!(
            reconstruct_secret(&one[..1]).unwrap_err(),
            ReconstructError::InsufficientShards
        );
    }

    #[test]
    fn duplicate_index_is_rejected() {
        let shards = split_secret(&[1u8; 32], 2, 3, &mut seeded_rng(5)).unwrap();
        let dup = vec![shards[0].clone(), shards[0].clone()];
        assert_eq!(
            reconstruct_secret(&dup).unwrap_err(),
            ReconstructError::DuplicateIndex
        );
    }

    #[test]
    fn zero_index_is_rejected() {
        let mut shards = split_secret(&[1u8; 32], 2, 3, &mut seeded_rng(5)).unwrap();
        shards[0].index = ShardIndex(0);
        assert_eq!(
            reconstruct_secret(&shards).unwrap_err(),
            ReconstructError::ZeroIndex
        );
    }

    #[test]
    fn fewer_than_threshold_does_not_recover_secret() {
        let secret = [0xABu8; 32];
        let shards = split_secret(&secret, 3, 5, &mut seeded_rng(9)).unwrap();
        // Two shards (K-1) interpolate to *something*, but not the secret.
        let got = reconstruct_secret(&subset(&shards, &[0, 1])).unwrap();
        assert_ne!(got, secret, "K-1 shards must not reveal the secret");
    }

    #[test]
    fn all_k_of_n_subsets_recover_the_same_secret() {
        // K=3, N=5: all C(5,3)=10 subsets must reconstruct the original.
        let secret = [0x5Au8; 32];
        let shards = split_secret(&secret, 3, 5, &mut seeded_rng(11)).unwrap();
        let combos = combinations(5, 3);
        assert_eq!(combos.len(), 10);
        for combo in combos {
            let got = reconstruct_secret(&subset(&shards, &combo)).unwrap();
            assert_eq!(got, secret, "subset {combo:?} failed to recover");
        }
    }

    proptest! {
        #[test]
        fn round_trips_from_any_k_subset(
            secret in any::<[u8; 32]>(),
            seed in any::<[u8; 32]>(),
            k in 2u8..=6,
            extra in 0u8..=10,
            rotate in any::<usize>(),
        ) {
            let n = (k + extra).min(MAX_SHARES);
            prop_assume!(n >= k);
            let mut rng = ChaCha20Rng::from_seed(seed);
            let shards = split_secret(&secret, k, n, &mut rng).unwrap();

            // Pick a K-subset (a rotated contiguous window, to vary which
            // indices participate across runs).
            let start = rotate % n as usize;
            let chosen: Vec<usize> =
                (0..k as usize).map(|i| (start + i) % n as usize).collect();
            let recovered = reconstruct_secret(&subset(&shards, &chosen)).unwrap();
            prop_assert_eq!(recovered, secret);

            // K=N (all shards) must also recover the original.
            let all: Vec<usize> = (0..n as usize).collect();
            let recovered_all = reconstruct_secret(&subset(&shards, &all)).unwrap();
            prop_assert_eq!(recovered_all, secret);
        }
    }
}
