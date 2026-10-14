//! The commit-then-reveal pairing handshake (ADR-0008, Clarification
//! 2026-10-14; `docs/spec/pairing.md`).
//!
//! Thin wrappers over `rrn_identity::pairing`, so the phone builds the exact
//! signed byte layouts and renders the exact code the station does, rather
//! than re-implementing either. Signing and verifying use the existing
//! `Keypair` / `PublicKey` handles. Every byte argument has a fixed length (32
//! bytes for keys, nonces, and the commitment); any other length is
//! [`CryptoError::WrongLength`].

use rrn_identity::pairing as layout;

use crate::CryptoError;

fn arr32(bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::WrongLength)
}

/// A fresh 32-byte nonce from the operating system's CSPRNG — the device's
/// pairing nonce, committed to in the start and revealed in the finish.
pub fn pairing_nonce() -> Vec<u8> {
    layout::fresh_nonce().to_vec()
}

/// The device's commitment to `mobile_nonce`.
pub fn pairing_commitment(
    mobile_pk: Vec<u8>,
    mobile_nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    Ok(layout::commitment(&arr32(&mobile_pk)?, &arr32(&mobile_nonce)?).to_vec())
}

/// The bytes the device signs for `POST /pair/start`.
pub fn pairing_start_signed_bytes(
    mobile_pk: Vec<u8>,
    commitment: Vec<u8>,
    requested_at: i64,
) -> Result<Vec<u8>, CryptoError> {
    Ok(layout::start_signed_bytes(
        &arr32(&mobile_pk)?,
        &arr32(&commitment)?,
        requested_at,
    ))
}

/// The bytes the station signed in its offer — what the device verifies the
/// offer's signature over.
pub fn pairing_offer_signed_bytes(
    station_pk: Vec<u8>,
    mobile_pk: Vec<u8>,
    commitment: Vec<u8>,
    station_nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    Ok(layout::offer_signed_bytes(
        &arr32(&station_pk)?,
        &arr32(&mobile_pk)?,
        &arr32(&commitment)?,
        &arr32(&station_nonce)?,
    ))
}

/// The bytes the device signs for `POST /pair/finish`.
pub fn pairing_finish_signed_bytes(
    station_pk: Vec<u8>,
    mobile_pk: Vec<u8>,
    commitment: Vec<u8>,
    station_nonce: Vec<u8>,
    mobile_nonce: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    Ok(layout::finish_signed_bytes(
        &arr32(&station_pk)?,
        &arr32(&mobile_pk)?,
        &arr32(&commitment)?,
        &arr32(&station_nonce)?,
        &arr32(&mobile_nonce)?,
    ))
}

/// The confirmation code the device shows (`XXXXX-XXXXX`).
pub fn pairing_code(
    station_pk: Vec<u8>,
    mobile_pk: Vec<u8>,
    mobile_nonce: Vec<u8>,
    station_nonce: Vec<u8>,
) -> Result<String, CryptoError> {
    Ok(layout::code(
        &arr32(&station_pk)?,
        &arr32(&mobile_pk)?,
        &arr32(&mobile_nonce)?,
        &arr32(&station_nonce)?,
    ))
}
