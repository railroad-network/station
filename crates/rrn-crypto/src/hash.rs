//! Blake3 content hashing.
//!
//! A single hashing primitive used throughout Railroad Network: append-only
//! log entry chaining, content addressing, and Charter commit hashes. Blake3
//! is chosen over SHA-256 because it is faster on modern CPUs and
//! parallelizable at the same security level, with broad Rust support.
//!
//! The `blake3` types are wrapped, never exposed, so the backend can be
//! swapped behind an ADR without rippling through downstream crates.
//!
//! **Not for passwords.** Password/passphrase hashing is a separate concern
//! handled with `argon2` (argon2id) in `rrn-identity`. Do not use this module
//! to hash secrets that must resist brute force — Blake3 is fast by design,
//! which is the opposite of what password hashing needs.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte Blake3 hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash([u8; 32]);

/// Incremental Blake3 hasher, for hashing data that arrives in pieces.
pub struct Hasher(blake3::Hasher);

/// Error parsing a [`struct@Hash`] from a hex string.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ParseHashError {
    /// The string was not valid hexadecimal.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// The decoded bytes were not exactly 32 bytes long.
    #[error("wrong length: expected 32 bytes, got {0}")]
    WrongLength(usize),
}

impl Hash {
    /// Hashes `data` in one shot.
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Wraps 32 raw bytes as a `Hash` (no hashing performed).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the 32 raw bytes of this hash.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Returns the lowercase hex encoding of this hash (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a hash from its lowercase or uppercase hex encoding.
    pub fn from_hex(s: &str) -> Result<Self, ParseHashError> {
        let bytes = hex::decode(s).map_err(|_| ParseHashError::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ParseHashError::WrongLength(bytes.len()))?;
        Ok(Self(arr))
    }
}

impl Hasher {
    /// Creates a new incremental hasher.
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    /// Feeds more data into the hasher. Returns `&mut Self` for chaining.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    /// Consumes the hasher and returns the final [`struct@Hash`].
    pub fn finalize(self) -> Hash {
        Hash(*self.0.finalize().as_bytes())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Published BLAKE3 test vector for the input `b"abc"`.
    const ABC_VECTOR: &str = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

    #[test]
    fn known_answer_abc() {
        assert_eq!(Hash::of(b"abc").to_hex(), ABC_VECTOR);
    }

    #[test]
    fn display_and_debug_are_hex() {
        let h = Hash::of(b"abc");
        assert_eq!(format!("{h}"), ABC_VECTOR);
        assert_eq!(format!("{h:?}"), format!("Hash({ABC_VECTOR})"));
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(
            Hash::from_hex("zz").unwrap_err(),
            ParseHashError::InvalidHex
        );
        // 31 bytes of hex → wrong length.
        let short = "ab".repeat(31);
        assert_eq!(
            Hash::from_hex(&short).unwrap_err(),
            ParseHashError::WrongLength(31)
        );
    }

    #[test]
    fn serde_roundtrip() {
        let h = Hash::of(b"railroad");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", h.to_hex()));
        assert_eq!(h, serde_json::from_str::<Hash>(&json).unwrap());
    }

    proptest! {
        #[test]
        fn incremental_equals_oneshot(
            a in proptest::collection::vec(any::<u8>(), 0..256),
            b in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut hasher = Hasher::new();
            hasher.update(&a).update(&b);
            let incremental = hasher.finalize();

            let concat: Vec<u8> = a.iter().chain(b.iter()).copied().collect();
            prop_assert_eq!(incremental, Hash::of(&concat));
        }

        #[test]
        fn hex_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let h = Hash::of(&data);
            prop_assert_eq!(Hash::from_hex(&h.to_hex()).unwrap(), h);
        }

        #[test]
        fn byte_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let h = Hash::of(&data);
            prop_assert_eq!(Hash::from_bytes(h.to_bytes()), h);
        }
    }
}
