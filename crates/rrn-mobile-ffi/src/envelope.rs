//! The portable `{signer, sig, body}` signed-record envelope (T2.4.2).
//!
//! A [`rrn_crypto::signed::SignedPayload`] is a serde envelope, not a dCBOR
//! value, so a signed record needs an explicit framing to travel as bytes over a
//! carrier or across the FFI. The repo's house framing for that is the canonical
//! dCBOR of a three-key map — `signer` (32-byte Ed25519 public key), `sig`
//! (64-byte signature), `body` (the record's canonical dCBOR, the exact bytes
//! its author signed). It is the same shape as
//! [`rrn_protocol::bundle::EntryEnvelope`],
//! [`rrn_protocol::receipt::encode_signed`], and an
//! `rrn_ledger::escrow::EvidenceItem`, so an envelope produced here is
//! byte-identical to those and re-frameable without invalidating the signature
//! (which covers only `body`, ADR-0002).
//!
//! This module is the single encode/decode point the DTN and certificate FFI
//! functions share, so the mobile app sees one envelope format for every signed
//! record it hands across the boundary — a cert-backed proposal, a certificate
//! request, an outbox entry — regardless of the record inside.

use dcbor::prelude::*;
use rrn_crypto::keypair::{PublicKey, Signature};

/// Encodes a signed record as portable `{signer, sig, body}` envelope bytes.
pub(crate) fn encode(signer: &PublicKey, signature: &Signature, body: Vec<u8>) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("signer", CBOR::to_byte_string(signer.to_bytes()));
    m.insert("sig", CBOR::to_byte_string(signature.to_bytes()));
    m.insert("body", CBOR::to_byte_string(body));
    CBOR::from(m).to_cbor_data()
}

/// The three verbatim parts of a decoded envelope: the signer, the signature,
/// and the record's canonical `body` bytes. The signature is **not** checked
/// here — a caller reconstructs the typed [`SignedPayload`] and calls
/// [`SignedPayload::verify`](rrn_crypto::signed::SignedPayload::verify).
pub(crate) struct DecodedEnvelope {
    pub signer: PublicKey,
    pub signature: Signature,
    pub body: Vec<u8>,
}

/// Decodes portable `{signer, sig, body}` envelope bytes. `None` for any input
/// that is not a canonical three-key map with a 32-byte `signer`, 64-byte `sig`,
/// and a byte-string `body`.
pub(crate) fn decode(bytes: &[u8]) -> Option<DecodedEnvelope> {
    let cbor = CBOR::try_from_data(bytes).ok()?;
    let map = match cbor.into_case() {
        CBORCase::Map(map) => map,
        _ => return None,
    };
    let signer_bytes: [u8; 32] = map
        .extract::<&str, CBOR>("signer")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let sig_bytes: [u8; 64] = map
        .extract::<&str, CBOR>("sig")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .try_into()
        .ok()?;
    let body = map
        .extract::<&str, CBOR>("body")
        .ok()?
        .try_into_byte_string()
        .ok()?
        .as_slice()
        .to_vec();
    Some(DecodedEnvelope {
        signer: PublicKey::from_bytes(signer_bytes).ok()?,
        signature: Signature::from_bytes(sig_bytes).ok()?,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    #[test]
    fn roundtrips_the_three_parts() {
        let kp = Keypair::generate();
        let body = b"canonical record bytes".to_vec();
        let sig = kp.sign(&body);
        let bytes = encode(&kp.public_key(), &sig, body.clone());
        let decoded = decode(&bytes).expect("decodes");
        assert_eq!(decoded.signer, kp.public_key());
        assert_eq!(decoded.signature, sig);
        assert_eq!(decoded.body, body);
    }

    #[test]
    fn matches_the_protocol_receipt_envelope_shape() {
        // Byte-identity with rrn_protocol::receipt::encode_signed proves the FFI
        // envelope is the same house framing, not a parallel one.
        use rrn_crypto::hash::Hash;
        use rrn_identity::address::Address;
        use rrn_protocol::receipt::{
            self, DeliveryReceipt, Disposition, Outcome, RefusalReason, SignedReceipt,
        };

        let kp = Keypair::generate();
        let receipt = DeliveryReceipt {
            station: Address::from_public_key(kp.public_key()),
            outcomes: vec![Outcome {
                record_hash: Hash::of(b"x"),
                disposition: Disposition::Refused {
                    reason: RefusalReason::DebtFloor,
                },
            }],
            received_at: 7,
        };
        let signed = SignedReceipt::sign(receipt, &kp);
        let via_protocol = receipt::encode_signed(&signed);
        let via_ffi = encode(
            &signed.signer,
            &signed.signature,
            rrn_crypto::serialize::to_canonical_bytes(signed.payload.clone()),
        );
        assert_eq!(via_ffi, via_protocol);
    }

    #[test]
    fn rejects_garbage_and_wrong_shapes() {
        assert!(decode(&[0xff, 0x00, 0x13]).is_none());
        // A bare CBOR integer is not the envelope map.
        assert!(decode(&CBOR::from(5).to_cbor_data()).is_none());
    }
}
