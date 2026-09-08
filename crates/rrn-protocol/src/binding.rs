//! Transport bindings: RRN identity ↔ Reticulum destination (T2.6.2, ADR-0013).
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
}
