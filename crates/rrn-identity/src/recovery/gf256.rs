//! Arithmetic in the finite field GF(256), the foundation of the Shamir split.
//!
//! Shamir's Secret Sharing represents a secret byte as the constant term of a
//! polynomial and hands out evaluations of that polynomial. For the arithmetic
//! to have the right structure — every nonzero element invertible, so Lagrange
//! interpolation works — the coefficients must live in a *field*. The bytes
//! `0..=255` form a field, GF(256), under the **Rijndael (AES) reduction
//! polynomial** `x^8 + x^4 + x^3 + x + 1` (`0x11b`). We use that field (rather
//! than any other GF(256) representation) so our raw Shamir step can be
//! cross-validated byte-for-byte against SLIP-0039 and Trezor's
//! `shamir-mnemonic`, which use the same field. See
//! [ADR-0004](../../../../docs/adr/0004-own-shamir-implementation.md).
//!
//! # How the operations work
//!
//! - **Addition and subtraction are both XOR.** In a field of characteristic 2,
//!   `a + a = 0`, so addition is its own inverse — there is no separate
//!   subtraction, and no "borrow".
//! - **Multiplication uses log/antilog tables.** `3` (i.e. `x + 1`) is a
//!   generator of the 255-element multiplicative group, so every nonzero element
//!   is `3^k` for a unique `k in 0..255`. We precompute `LOG[a] = k` and its
//!   inverse `EXP[k] = 3^k`; then `a * b = EXP[LOG[a] + LOG[b]]`. `EXP` is
//!   carried to length 512 so the index `LOG[a] + LOG[b]` (at most `254 + 254 =
//!   508`) never needs a runtime modulo.
//! - **Inversion** is `a^-1 = 3^(255 - LOG[a])` for `a != 0`; `0` has no inverse.
//!
//! # Constant-time discipline
//!
//! Field elements here are secret-dependent (secret bytes, polynomial
//! coefficients, shard values), so the arithmetic must not branch on their
//! values. [`Gf256::mul`] handles its only data-dependent case — a zero operand
//! — *branchlessly*, via [`subtle`]. [`Gf256::inv`] and [`Gf256::div`] do branch
//! on "is the input zero", but that is an API-level fact (they return
//! [`Option`]) and is only ever exercised on the *public* shard indices during
//! interpolation, never on a secret value.
//!
//! The table lookups themselves are *not* constant-time with respect to the CPU
//! cache: the index is a secret byte, so cache-line access timing leaks
//! information to an attacker who can observe this process's cache. That residual
//! channel is documented and accepted in `docs/threat-model.md`
//! (`rrn-identity::recovery::gf256`) under the local-execution deployment model.

use core::ops;

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// The reduction byte for the Rijndael polynomial: `x^8 ≡ x^4 + x^3 + x + 1`
/// (`0x1b`) when a multiplication overflows out of the byte.
const REDUCTION: u8 = 0x1b;

/// `(LOG, EXP)` tables for GF(256) under the Rijndael polynomial with generator
/// `3`, computed at compile time.
///
/// - `LOG[a] = k` such that `3^k = a`, for `a != 0`. `LOG[0]` is a don't-care
///   (`0`); multiplication masks the zero case so the value is never used.
/// - `EXP[k] = 3^(k mod 255)`, for `k in 0..512`. The extra range past `255`
///   lets `mul` index `LOG[a] + LOG[b]` directly without a modulo.
const fn build_tables() -> ([u8; 256], [u8; 512]) {
    let mut log = [0u8; 256];
    let mut exp = [0u8; 512];

    // Walk the multiplicative group: a = 3^i, starting at 3^0 = 1.
    let mut a: u8 = 1;
    let mut i: usize = 0;
    while i < 255 {
        exp[i] = a;
        log[a as usize] = i as u8;
        // a *= 3, i.e. a*(x+1) = a*x XOR a, with a*x being `xtime`.
        let hi = a >> 7; // 1 if the high bit is set, else 0
        let a_times_x = (a << 1) ^ (REDUCTION.wrapping_mul(hi));
        a = a_times_x ^ a;
        i += 1;
    }
    // 3^255 = 1, so the sequence repeats; mirror it into 255..512.
    let mut k: usize = 255;
    while k < 512 {
        exp[k] = exp[k - 255];
        k += 1;
    }
    (log, exp)
}

const TABLES: ([u8; 256], [u8; 512]) = build_tables();
const LOG: [u8; 256] = TABLES.0;
const EXP: [u8; 512] = TABLES.1;

/// An element of GF(256) under the Rijndael (AES) field polynomial.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gf256(u8);

// The inherent `add`/`sub`/`mul`/`div` methods are the spec'd field API and are
// also surfaced through the `std::ops` traits below (except `div`, which can
// fail). clippy's `should_implement_trait` flags the inherent names regardless;
// allow it here — the trait impls exist where they can, and `div` intentionally
// does not get an operator.
#[allow(clippy::should_implement_trait)]
impl Gf256 {
    /// The additive identity, `0`.
    pub const ZERO: Self = Gf256(0);
    /// The multiplicative identity, `1`.
    pub const ONE: Self = Gf256(1);

    /// Field addition — XOR. In characteristic 2 this is also subtraction.
    #[inline]
    pub fn add(self, other: Self) -> Self {
        Gf256(self.0 ^ other.0)
    }

    /// Field subtraction — identical to addition in characteristic 2 (`a + a =
    /// 0`, so every element is its own additive inverse).
    #[inline]
    pub fn sub(self, other: Self) -> Self {
        Gf256(self.0 ^ other.0)
    }

    /// Field multiplication via the log/antilog tables.
    ///
    /// Branchless: the only data-dependent case is a zero operand, handled with
    /// a constant-time select rather than an `if`, so the operation does not
    /// branch on a secret value. (Table-lookup cache timing is a separate,
    /// accepted residual channel — see the module docs.)
    #[inline]
    pub fn mul(self, other: Self) -> Self {
        let a = self.0;
        let b = other.0;
        // For nonzero a, b: 3^(LOG[a]+LOG[b]). LOG[a]+LOG[b] <= 508 < 512, so no
        // modulo is needed. For a==0 or b==0, LOG[0]=0 makes this read a valid
        // (but meaningless) entry, which the select below discards.
        let product = EXP[LOG[a as usize] as usize + LOG[b as usize] as usize];
        let either_zero = a.ct_eq(&0) | b.ct_eq(&0);
        Gf256(u8::conditional_select(&product, &0, either_zero))
    }

    /// Multiplicative inverse, or `None` for [`Gf256::ZERO`] (which has none).
    ///
    /// Branches on "is this zero" — an API-level fact (the return is `Option`),
    /// only ever evaluated on public shard indices during interpolation, never
    /// on a secret value.
    #[inline]
    pub fn inv(self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        // a^-1 = 3^(255 - LOG[a]). LOG[a] in 0..=254, so the exponent is in
        // 1..=255, a valid EXP index.
        Some(Gf256(EXP[255 - LOG[self.0 as usize] as usize]))
    }

    /// Field division `self / other`, or `None` for division by
    /// [`Gf256::ZERO`].
    ///
    /// Named `div` (not via `std::ops::Div`) deliberately: division can fail, and
    /// a panicking `/` operator would be a foot-gun in interpolation, so callers
    /// are forced to handle the `None`.
    #[inline]
    pub fn div(self, other: Self) -> Option<Self> {
        Some(self.mul(other.inv()?))
    }

    /// Exponentiation by squaring. `pow(_, 0) == ONE` (including `ZERO.pow(0)`,
    /// by the `0^0 = 1` convention); `ZERO.pow(n)` for `n > 0` is `ZERO`.
    ///
    /// The loop is driven by the bits of `exp`; in every intended use `exp` is a
    /// public constant, so no secret value steers control flow.
    pub fn pow(self, exp: u32) -> Self {
        let mut result = Gf256::ONE;
        let mut base = self;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            e >>= 1;
        }
        result
    }

    /// Lifts a raw byte into the field.
    #[inline]
    pub fn from_u8(byte: u8) -> Self {
        Gf256(byte)
    }

    /// Returns the raw byte representation of this element.
    #[inline]
    pub fn to_u8(self) -> u8 {
        self.0
    }
}

impl ops::Add for Gf256 {
    type Output = Gf256;
    #[inline]
    fn add(self, rhs: Gf256) -> Gf256 {
        Gf256::add(self, rhs)
    }
}

impl ops::Sub for Gf256 {
    type Output = Gf256;
    #[inline]
    fn sub(self, rhs: Gf256) -> Gf256 {
        Gf256::sub(self, rhs)
    }
}

impl ops::Mul for Gf256 {
    type Output = Gf256;
    #[inline]
    fn mul(self, rhs: Gf256) -> Gf256 {
        Gf256::mul(self, rhs)
    }
}

// Deliberately no `impl Div`: division can fail (by zero), and a panicking
// operator would be a foot-gun in interpolation. Callers use `div()` and handle
// the `None`. Likewise there is no `Neg`: in characteristic 2 an element is its
// own additive inverse, so `-a == a`.

/// Lets `Gf256` participate in `subtle`'s constant-time selection, used when
/// building shards without branching on secret values.
impl ConditionallySelectable for Gf256 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gf256(u8::conditional_select(&a.0, &b.0, choice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A reference GF(256) multiply, implemented independently of the log/antilog
    /// tables by the carry-less "Russian peasant" shift-and-reduce method. This
    /// is the gold-standard the table-based [`Gf256::mul`] is checked against —
    /// a bug in the tables cannot hide behind a matching bug here, since the two
    /// share no code.
    fn ref_mul(mut a: u8, mut b: u8) -> u8 {
        let mut product: u8 = 0;
        let mut i = 0;
        while i < 8 {
            if b & 1 == 1 {
                product ^= a;
            }
            let high_bit_set = a & 0x80 != 0;
            a <<= 1;
            if high_bit_set {
                a ^= REDUCTION;
            }
            b >>= 1;
            i += 1;
        }
        product
    }

    #[test]
    fn exhaustive_multiplication_table() {
        // The decisive correctness test: verify all 256 × 256 = 65,536 products
        // against the independent reference multiply.
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let got = Gf256(a as u8).mul(Gf256(b as u8)).to_u8();
                let want = ref_mul(a as u8, b as u8);
                assert_eq!(got, want, "mul({a}, {b}) = {got}, expected {want}");
            }
        }
    }

    #[test]
    fn every_nonzero_element_times_its_inverse_is_one() {
        for a in 1u16..=255 {
            let x = Gf256(a as u8);
            let inv = x.inv().expect("nonzero elements are invertible");
            assert_eq!(x.mul(inv), Gf256::ONE, "{a} * inv({a}) != 1");
        }
    }

    #[test]
    fn zero_has_no_inverse() {
        assert_eq!(Gf256::ZERO.inv(), None);
    }

    #[test]
    fn division_by_zero_is_none() {
        assert_eq!(Gf256::ONE.div(Gf256::ZERO), None);
        // Zero divided by a nonzero element is a well-defined zero.
        assert_eq!(Gf256::ZERO.div(Gf256::ONE), Some(Gf256::ZERO));
    }

    #[test]
    fn div_is_inverse_of_mul() {
        for a in 0u16..=255 {
            for b in 1u16..=255 {
                let x = Gf256(a as u8);
                let y = Gf256(b as u8);
                let q = x.div(y).expect("nonzero divisor");
                assert_eq!(q.mul(y), x, "({a}/{b})*{b} != {a}");
            }
        }
    }

    #[test]
    fn generator_has_order_255() {
        // Lagrange's theorem on the multiplicative group: the generator 3 raised
        // to the group order 255 returns to the identity, and no smaller positive
        // power does (it is genuinely a generator, not a lower-order element).
        let g = Gf256::from_u8(3);
        assert_eq!(g.pow(255), Gf256::ONE, "3^255 != 1");
        for k in 1u32..255 {
            assert_ne!(g.pow(k), Gf256::ONE, "3 has unexpected order {k}");
        }
    }

    #[test]
    fn pow_matches_repeated_multiplication() {
        for base in 0u16..=255 {
            let x = Gf256(base as u8);
            let mut acc = Gf256::ONE;
            for e in 0u32..=10 {
                assert_eq!(x.pow(e), acc, "{base}^{e}");
                acc = acc.mul(x);
            }
        }
    }

    #[test]
    fn add_and_sub_are_xor_and_self_inverse() {
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                let x = Gf256(a as u8);
                let y = Gf256(b as u8);
                assert_eq!(x.add(y), Gf256(a as u8 ^ b as u8));
                assert_eq!(x.sub(y), x.add(y));
                // a + b + b = a
                assert_eq!(x.add(y).sub(y), x);
            }
        }
    }

    fn any_gf() -> impl Strategy<Value = Gf256> {
        any::<u8>().prop_map(Gf256)
    }

    proptest! {
        #[test]
        fn addition_is_commutative_and_associative(a in any_gf(), b in any_gf(), c in any_gf()) {
            prop_assert_eq!(a + b, b + a);
            prop_assert_eq!((a + b) + c, a + (b + c));
        }

        #[test]
        fn multiplication_is_commutative_and_associative(a in any_gf(), b in any_gf(), c in any_gf()) {
            prop_assert_eq!(a * b, b * a);
            prop_assert_eq!((a * b) * c, a * (b * c));
        }

        #[test]
        fn multiplication_distributes_over_addition(a in any_gf(), b in any_gf(), c in any_gf()) {
            prop_assert_eq!(a * (b + c), (a * b) + (a * c));
        }

        #[test]
        fn one_and_zero_are_identities(a in any_gf()) {
            prop_assert_eq!(a + Gf256::ZERO, a);
            prop_assert_eq!(a * Gf256::ONE, a);
            prop_assert_eq!(a * Gf256::ZERO, Gf256::ZERO);
        }
    }
}
