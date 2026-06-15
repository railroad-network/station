//! Human-readable addresses: bech32m-encoded public keys (`rrn1…`).
//!
//! An [`Address`] is just a wrapper around a [`PublicKey`], but the bech32m
//! encoding gives it three properties raw hex does not: a checksum (so a
//! mistyped address is detected, not silently accepted as a different key), a
//! recognizable human-readable prefix (`rrn`), and case-insensitive,
//! QR-friendly characters. See [ADR-0003](../../../docs/adr/0003-bech32-address-format.md).
//!
//! # Note on the `to_string` / `from_str` API
//!
//! The task spec sketched inherent `to_string`/`from_str` methods. Those are
//! provided here through the standard [`Display`] and [`FromStr`] traits
//! instead — an inherent `to_string` next to a `Display` impl, or an inherent
//! `from_str`, both trip `clippy` lints that CI treats as errors. The ergonomic
//! surface is identical: `addr.to_string()` (via `ToString`) and
//! `"rrn1…".parse::<Address>()` / `Address::from_str("rrn1…")` (with
//! [`FromStr`] in scope) work exactly as the spec intended.

use core::fmt;
use core::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use dcbor::CBOR;
use rrn_crypto::keypair::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The human-readable prefix for Railroad Network addresses. Addresses look
/// like `rrn1…`; the trailing `1` is the bech32 separator, not part of the HRP.
pub const HRP: &str = "rrn";

/// A public key in its human-readable, checksummed address form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(PublicKey);

/// Error parsing an [`Address`] from its string form.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AddressParseError {
    /// The string was not a valid bech32m string (bad characters, mixed case,
    /// bad checksum, or wrong checksum variant).
    #[error("not a valid bech32m address: {0}")]
    Bech32(String),
    /// The string decoded, but under a different human-readable prefix.
    #[error("wrong address prefix: expected {expected:?}, got {actual:?}")]
    WrongHrp {
        /// The HRP this crate expects ([`HRP`]).
        expected: String,
        /// The HRP actually found in the input.
        actual: String,
    },
    /// The payload was the wrong size to be a 32-byte public key.
    #[error("address payload is {0} bytes, expected 32")]
    WrongLength(usize),
    /// The 32 payload bytes are not a valid Ed25519 public key (not a canonical
    /// curve point).
    #[error("address does not decode to a valid public key")]
    MalformedKey,
}

impl Address {
    /// Wraps a public key as an address.
    pub fn from_public_key(pk: PublicKey) -> Self {
        Self(pk)
    }

    /// Returns the underlying public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }
}

impl fmt::Display for Address {
    /// Renders the address as a lowercase bech32m string, e.g. `rrn1…`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Both unwraps are infallible for a fixed valid HRP and a 32-byte
        // payload: `HRP` is a static, valid human-readable part, and bech32m
        // encoding of 32 bytes cannot exceed any length bound.
        let hrp = Hrp::parse(HRP).expect("HRP constant is a valid bech32 HRP");
        let encoded = bech32::encode::<Bech32m>(hrp, &self.0.to_bytes())
            .expect("32-byte payload always encodes");
        f.write_str(&encoded)
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Strictly require the bech32m checksum variant. The crate's top-level
        // `decode` leniently accepts bech32 *or* bech32m; `CheckedHrpstring`
        // with an explicit `Bech32m` does not. Mixed-case input is rejected
        // here too (bech32 forbids it).
        let checked = CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| AddressParseError::Bech32(e.to_string()))?;

        let hrp = checked.hrp();
        if !hrp.as_str().eq_ignore_ascii_case(HRP) {
            return Err(AddressParseError::WrongHrp {
                expected: HRP.to_string(),
                actual: hrp.as_str().to_string(),
            });
        }

        let payload: Vec<u8> = checked.byte_iter().collect();
        let bytes: [u8; 32] = payload
            .as_slice()
            .try_into()
            .map_err(|_| AddressParseError::WrongLength(payload.len()))?;
        let pk = PublicKey::from_bytes(bytes).map_err(|_| AddressParseError::MalformedKey)?;
        Ok(Self(pk))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

// --- serde: the bech32m string form, for wire envelopes / config / logs -----

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// --- canonical CBOR: the raw 32 public-key bytes ----------------------------
//
// Inside a *signed* payload (an attestation's `subject`), an address is the
// 32-byte public key as a CBOR byte string — compact and unambiguous. The
// bech32m text form is a presentation concern, never what gets signed.

impl From<Address> for CBOR {
    fn from(a: Address) -> Self {
        CBOR::to_byte_string(a.0.to_bytes())
    }
}

impl TryFrom<CBOR> for Address {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let bytes = cbor.try_into_byte_string()?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        PublicKey::from_bytes(arr)
            .map(Self)
            .map_err(|_| dcbor::Error::WrongType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rrn_crypto::keypair::{Keypair, SecretKey};

    /// A fixed, reproducible public key: the Ed25519 key for the all-zero seed.
    /// Used to lock a known-answer bech32m vector.
    fn fixed_pubkey() -> PublicKey {
        Keypair::from_secret(SecretKey::from_bytes([0u8; 32])).public_key()
    }

    #[test]
    fn known_answer_vector() {
        let addr = Address::from_public_key(fixed_pubkey());
        // Locked bech32m encoding of the all-zero-seed public key. If this
        // changes, the address format changed — that needs an ADR, not a test
        // edit.
        assert_eq!(
            addr.to_string(),
            "rrn18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5scr4w0n"
        );
    }

    #[test]
    fn starts_with_rrn1_prefix() {
        let addr = Address::from_public_key(Keypair::generate().public_key());
        assert!(addr.to_string().starts_with("rrn1"), "{addr}");
    }

    #[test]
    fn rejects_bad_checksum() {
        let addr = Address::from_public_key(fixed_pubkey()).to_string();
        // Flip a character in the checksum region (last char).
        let mut chars: Vec<char> = addr.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let tampered: String = chars.into_iter().collect();
        let err = tampered.parse::<Address>().unwrap_err();
        assert!(matches!(err, AddressParseError::Bech32(_)), "{err:?}");
    }

    #[test]
    fn rejects_wrong_hrp() {
        // A valid bech32m string under a different HRP (`bc`) must be rejected.
        let hrp = Hrp::parse("bc").unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &fixed_pubkey().to_bytes()).unwrap();
        let err = s.parse::<Address>().unwrap_err();
        assert!(matches!(err, AddressParseError::WrongHrp { .. }), "{err:?}");
    }

    #[test]
    fn rejects_bech32_non_m_variant() {
        // The same payload/HRP encoded with the *bech32* (non-m) checksum must
        // not parse as an address — we strictly require bech32m.
        let hrp = Hrp::parse(HRP).unwrap();
        let s = bech32::encode::<bech32::Bech32>(hrp, &fixed_pubkey().to_bytes()).unwrap();
        assert!(s.parse::<Address>().is_err());
    }

    #[test]
    fn rejects_wrong_length_payload() {
        // A valid bech32m string with our HRP but a 4-byte payload.
        let hrp = Hrp::parse(HRP).unwrap();
        let s = bech32::encode::<Bech32m>(hrp, &[1u8, 2, 3, 4]).unwrap();
        let err = s.parse::<Address>().unwrap_err();
        assert!(matches!(err, AddressParseError::WrongLength(4)), "{err:?}");
    }

    #[test]
    fn cbor_roundtrip() {
        let addr = Address::from_public_key(fixed_pubkey());
        let cbor: CBOR = addr.into();
        let back = Address::try_from(cbor).unwrap();
        assert_eq!(addr, back);
    }

    proptest! {
        #[test]
        fn string_roundtrips(seed in any::<[u8; 32]>()) {
            // Derive a guaranteed-valid public key from a random seed, so the
            // address is always well-formed.
            let pk = Keypair::from_secret(SecretKey::from_bytes(seed)).public_key();
            let addr = Address::from_public_key(pk);
            let parsed: Address = addr.to_string().parse().unwrap();
            prop_assert_eq!(addr, parsed);
        }
    }
}
