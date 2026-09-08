//! Reachability bindings: an RRN identity ↔ a carrier handle.
//!
//! Two live here, one shape: [`TransportBinding`] (RRN identity ↔ Reticulum
//! destination, T2.6.2/ADR-0013) and [`SmsBinding`] (RRN identity ↔ phone number,
//! T2.7.1). Both are **self-signed** statements appended to the log — "you can
//! currently reach me here" — never authorization, reputation, or a key. The rest
//! of these docs describe the Reticulum case; the SMS case is identical bar the
//! handle it names.
//!
//! Reticulum packets carry no source address and a Reticulum destination is a
//! cheap, rotatable hash — so a station or device that wants to be *reachable*
//! over the carrier must tell its community "the RRN identity `rrn1…` is currently
//! reachable at Reticulum destination `<hash>`." A [`TransportBinding`] is that
//! statement, **self-signed by the RRN identity** and appended to the log, so any
//! peer can map an identity to a destination without trusting the carrier to tell
//! it (a hostile carrier could otherwise route a payload to the wrong node).
//!
//! This is ADR-0013's **"bind, do not collapse"** made concrete: the RRN identity
//! (Ed25519 keypair + vouching + recovery) stays the durable root; the Reticulum
//! destination is a disposable reachability handle *under* it. Rotating the
//! destination — after a Reticulum identity change, or just periodically — is a
//! new binding with a later [`issued_at`](TransportBinding::issued_at), which
//! supersedes the old one. The two identities are never merged, even though both
//! happen to use Ed25519.
//!
//! What a binding is **not**: it is not authorization, not reputation, not a key.
//! It says only "you can currently reach me here," signed so it cannot be forged.
//! The integrity of anything *carried* to that destination still rides on the
//! app-layer sealed/signed envelope, never on this binding or on Reticulum.

use dcbor::prelude::*;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;

use crate::{Error, Result};

/// The record kind discriminator for a transport binding.
pub const BINDING_KIND: &str = "rrn.net.binding";

/// A signed statement that an RRN identity is reachable at a Reticulum
/// destination (module docs). Self-signed: the enclosing
/// [`SignedPayload`]'s signer MUST be [`address`](TransportBinding::address)'s key
/// — enforced by [`validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportBinding {
    /// The durable RRN identity this binding is for — the trust root.
    pub address: Address,
    /// The Reticulum destination hash the identity is reachable at, lowercase
    /// hex. Opaque to everything above the transport: a routing handle, never an
    /// identity (ADR-0013).
    pub destination: String,
    /// When the signer issued this binding (Unix seconds). A later binding for the
    /// same address supersedes an earlier one; this is testimony for that
    /// ordering, not a window (ADR-0022 spirit).
    pub issued_at: i64,
}

/// A [`TransportBinding`] signed by its own [`address`](TransportBinding::address).
pub type SignedBinding = SignedPayload<TransportBinding>;

impl TransportBinding {
    /// A new binding of `address` to `destination` at `issued_at`. Sign it with
    /// the address's key to get a [`SignedBinding`].
    pub fn new(address: Address, destination: impl Into<String>, issued_at: i64) -> Self {
        Self {
            address,
            destination: destination.into(),
            issued_at,
        }
    }
}

impl From<TransportBinding> for CBOR {
    fn from(b: TransportBinding) -> Self {
        let mut m = Map::new();
        m.insert("kind", BINDING_KIND);
        m.insert("address", b.address);
        m.insert("destination", b.destination);
        m.insert("issued_at", b.issued_at);
        m.into()
    }
}

impl From<&TransportBinding> for CBOR {
    fn from(b: &TransportBinding) -> Self {
        b.clone().into()
    }
}

impl TryFrom<CBOR> for TransportBinding {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != BINDING_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(TransportBinding {
            address: map.extract::<&str, Address>("address")?,
            destination: map.extract::<&str, String>("destination")?,
            issued_at: map.extract::<&str, i64>("issued_at")?,
        })
    }
}

/// Validates a signed binding: the signature verifies, and the signer is the
/// bound [`address`](TransportBinding::address) itself — a binding may only be
/// issued by the identity it names (self-attested reachability).
pub fn validate(signed: &SignedBinding) -> Result<()> {
    signed
        .verify()
        .map_err(|_| Error::Cbor("transport binding: bad signature".into()))?;
    if signed.signer != *signed.payload.address.public_key() {
        return Err(Error::Cbor(
            "transport binding: signer is not the bound address".into(),
        ));
    }
    Ok(())
}

/// The record kind discriminator for an SMS-reachability binding.
pub const SMS_BINDING_KIND: &str = "rrn.net.sms_binding";

/// A signed statement that an RRN identity is reachable by SMS at a phone number
/// (T2.7.1, Overview §10.3 "No internet — SMS"). Self-signed, appended to the log,
/// same discipline as [`TransportBinding`]: the identity `rrn1…` is the durable
/// root; the [`msisdn`](SmsBinding::msisdn) is a disposable reachability handle
/// *under* it. A later binding for the same address supersedes an earlier one.
///
/// It is the station's **sender registry**: with `[sms] allowed_senders = "paired"`
/// the station processes inbound texts only from numbers a binding names. That is
/// spam control, **not** the security boundary — an MSISDN is forgeable at the
/// carrier, so the real gate is the per-record signature the carried bundle already
/// verifies (ADR-0020). It says only "this number reaches me," signed so the
/// mapping itself cannot be forged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmsBinding {
    /// The durable RRN identity this binding is for — the trust root and the
    /// required signer.
    pub address: Address,
    /// The phone number, E.164 (`+` then 8–15 digits, leading digit non-zero).
    /// Validated by [`valid_msisdn`] at [`validate_sms_binding`]. Cleartext to the
    /// carrier — a metadata residual noted in the threat model.
    pub msisdn: String,
    /// When the signer issued this binding (Unix seconds). A later binding for the
    /// same address supersedes an earlier one; testimony for that ordering, not a
    /// window (ADR-0022 spirit).
    pub bound_at: i64,
}

/// An [`SmsBinding`] signed by its own [`address`](SmsBinding::address).
pub type SignedSmsBinding = SignedPayload<SmsBinding>;

impl SmsBinding {
    /// A new binding of `address` to `msisdn` at `bound_at`. Sign it with the
    /// address's key to get a [`SignedSmsBinding`].
    pub fn new(address: Address, msisdn: impl Into<String>, bound_at: i64) -> Self {
        Self {
            address,
            msisdn: msisdn.into(),
            bound_at,
        }
    }
}

impl From<SmsBinding> for CBOR {
    fn from(b: SmsBinding) -> Self {
        let mut m = Map::new();
        m.insert("kind", SMS_BINDING_KIND);
        m.insert("address", b.address);
        m.insert("msisdn", b.msisdn);
        m.insert("bound_at", b.bound_at);
        m.into()
    }
}

impl From<&SmsBinding> for CBOR {
    fn from(b: &SmsBinding) -> Self {
        b.clone().into()
    }
}

impl TryFrom<CBOR> for SmsBinding {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != SMS_BINDING_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(SmsBinding {
            address: map.extract::<&str, Address>("address")?,
            msisdn: map.extract::<&str, String>("msisdn")?,
            bound_at: map.extract::<&str, i64>("bound_at")?,
        })
    }
}

/// Whether `s` is a well-formed E.164 MSISDN for this codebase: a leading `+`, then
/// 8 to 15 decimal digits, the first of them non-zero (a country code never starts
/// with 0). The single source of truth the log-side binding validator and the
/// station's `Msisdn` type both use, so a number that binds is a number the gateway
/// will accept and vice versa.
pub fn valid_msisdn(s: &str) -> bool {
    let Some(digits) = s.strip_prefix('+') else {
        return false;
    };
    (8..=15).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && !digits.starts_with('0')
}

/// Validates a signed SMS binding: the signature verifies, the signer is the bound
/// [`address`](SmsBinding::address) itself (self-attested, like [`validate`]), and
/// the [`msisdn`](SmsBinding::msisdn) is well-formed E.164 ([`valid_msisdn`]).
pub fn validate_sms_binding(signed: &SignedSmsBinding) -> Result<()> {
    signed
        .verify()
        .map_err(|_| Error::Cbor("sms binding: bad signature".into()))?;
    if signed.signer != *signed.payload.address.public_key() {
        return Err(Error::Cbor(
            "sms binding: signer is not the bound address".into(),
        ));
    }
    if !valid_msisdn(&signed.payload.msisdn) {
        return Err(Error::Cbor("sms binding: msisdn is not valid E.164".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn binding_for(kp: &Keypair, dest: &str, at: i64) -> SignedBinding {
        let addr = Address::from_public_key(kp.public_key());
        SignedPayload::sign(TransportBinding::new(addr, dest, at), kp)
    }

    #[test]
    fn canonical_roundtrip() {
        let kp = Keypair::generate();
        let b = TransportBinding::new(
            Address::from_public_key(kp.public_key()),
            "a1b2c3d4e5f6a7b8",
            1_700_000_000,
        );
        let bytes = to_canonical_bytes(b.clone());
        let back: TransportBinding = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn self_signed_binding_validates() {
        let kp = Keypair::generate();
        let signed = binding_for(&kp, "deadbeef", 1);
        validate(&signed).unwrap();
    }

    #[test]
    fn a_binding_signed_by_another_key_is_refused() {
        // Alice's identity, bound — but signed by Mallory's key.
        let alice = Keypair::generate();
        let mallory = Keypair::generate();
        let addr = Address::from_public_key(alice.public_key());
        let signed = SignedPayload::sign(TransportBinding::new(addr, "x", 1), &mallory);
        assert!(validate(&signed).is_err(), "binding must be self-signed");
    }

    #[test]
    fn wrong_kind_does_not_decode() {
        // A map with the wrong kind is rejected by TryFrom.
        let mut m = Map::new();
        m.insert("kind", "rrn.test.record");
        m.insert(
            "address",
            Address::from_public_key(Keypair::generate().public_key()),
        );
        m.insert("destination", "x");
        m.insert("issued_at", 1i64);
        let cbor: CBOR = m.into();
        assert!(TransportBinding::try_from(cbor).is_err());
    }

    fn sms_binding_for(kp: &Keypair, msisdn: &str, at: i64) -> SignedSmsBinding {
        let addr = Address::from_public_key(kp.public_key());
        SignedPayload::sign(SmsBinding::new(addr, msisdn, at), kp)
    }

    #[test]
    fn sms_binding_canonical_roundtrip() {
        let kp = Keypair::generate();
        let b = SmsBinding::new(
            Address::from_public_key(kp.public_key()),
            "+15551234567",
            1_700_000_000,
        );
        let bytes = to_canonical_bytes(b.clone());
        let back: SmsBinding = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn self_signed_sms_binding_validates() {
        let signed = sms_binding_for(&Keypair::generate(), "+441632960083", 1);
        validate_sms_binding(&signed).unwrap();
    }

    #[test]
    fn sms_binding_signed_by_another_key_is_refused() {
        let alice = Keypair::generate();
        let mallory = Keypair::generate();
        let addr = Address::from_public_key(alice.public_key());
        let signed = SignedPayload::sign(SmsBinding::new(addr, "+15551234567", 1), &mallory);
        assert!(
            validate_sms_binding(&signed).is_err(),
            "sms binding must be self-signed"
        );
    }

    #[test]
    fn sms_binding_with_bad_msisdn_is_refused() {
        let signed = sms_binding_for(&Keypair::generate(), "555-1234", 1);
        assert!(validate_sms_binding(&signed).is_err());
    }

    #[test]
    fn sms_binding_wrong_kind_does_not_decode() {
        let mut m = Map::new();
        m.insert("kind", "rrn.net.binding"); // the *other* binding kind
        m.insert(
            "address",
            Address::from_public_key(Keypair::generate().public_key()),
        );
        m.insert("msisdn", "+15551234567");
        m.insert("bound_at", 1i64);
        let cbor: CBOR = m.into();
        assert!(SmsBinding::try_from(cbor).is_err());
    }

    #[test]
    fn valid_msisdn_accepts_e164_and_rejects_the_rest() {
        assert!(valid_msisdn("+15551234567"));
        assert!(valid_msisdn("+441632960083"));
        assert!(valid_msisdn("+12345678")); // 8 digits, the minimum
        assert!(valid_msisdn("+123456789012345")); // 15 digits, the maximum
        assert!(!valid_msisdn("15551234567")); // no leading +
        assert!(!valid_msisdn("+0123456789")); // leading zero in the country code
        assert!(!valid_msisdn("+1234567")); // 7 digits, too short
        assert!(!valid_msisdn("+1234567890123456")); // 16 digits, too long
        assert!(!valid_msisdn("+1555 123 4567")); // spaces
        assert!(!valid_msisdn("+1555-123-4567")); // dashes
        assert!(!valid_msisdn("")); // empty
        assert!(!valid_msisdn("+")); // just the plus
    }
}
