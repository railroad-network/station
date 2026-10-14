//! The byte layouts of the commit-then-reveal pairing handshake (ADR-0008,
//! Clarification 2026-10-14, Part A).
//!
//! Pairing binds a member device's static Ed25519 key to the station's. The
//! device commits to a fresh nonce, the station answers with its own fresh
//! nonce in a signed offer, and the device then reveals its nonce in a signed
//! finish. The code both sides show is derived from both keys and both nonces;
//! since each side fixed its nonce before seeing the other's, neither can steer
//! the code, and an offline key search cannot target it.
//!
//! Everything here is a pure function of its inputs except [`fresh_nonce`].
//! Keys are the raw 32-byte Ed25519 encodings: these are byte layouts, and
//! whether a key is a valid point is the signature check's concern. The
//! layouts are fixed concatenations rather than canonical dCBOR — pairing
//! establishes the keys the sealed channel relies on, and a fixed layout is
//! the easiest thing to make identical across platforms. The station, the
//! command-line wallet, and the phone (through the mobile FFI) all build them
//! here; `docs/spec/pairing.md` pins them, and
//! `tests/fixtures/cross_platform_pairing_v2.json` locks them.

use rand_core::{OsRng, RngCore};

use crate::human_code;

/// Domain tag of the device's commitment to its nonce.
pub const COMMIT_TAG: &[u8] = b"rrn-pair-commit-v2";
/// Domain tag of the device-signed start.
pub const START_TAG: &[u8] = b"rrn-pair-start-v2";
/// Domain tag of the station-signed offer.
pub const OFFER_TAG: &[u8] = b"rrn-pair-offer-v2";
/// Domain tag of the device-signed finish.
pub const FINISH_TAG: &[u8] = b"rrn-pair-finish-v2";
/// Domain tag of the confirmation-code digest.
pub const CODE_TAG: &[u8] = b"rrn-pair-code-v2";

/// Characters in the confirmation code: 10 × 5 = 50 bits.
pub const CODE_CHARS: usize = 10;
/// Characters per hyphen-separated group of the code (`XXXXX-XXXXX`).
pub const CODE_GROUP: usize = 5;

/// A fresh 32-byte nonce from the operating system's CSPRNG.
pub fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// `blake3(COMMIT_TAG ‖ mobile_pk ‖ mobile_nonce)` — the device's commitment
/// to the nonce it reveals in the finish.
pub fn commitment(mobile_pk: &[u8; 32], mobile_nonce: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(&concat(&[COMMIT_TAG, mobile_pk, mobile_nonce])).as_bytes()
}

/// Whether `mobile_nonce` opens `commitment` for `mobile_pk`.
pub fn opens(commitment_bytes: &[u8; 32], mobile_pk: &[u8; 32], mobile_nonce: &[u8; 32]) -> bool {
    commitment(mobile_pk, mobile_nonce) == *commitment_bytes
}

/// The bytes the device signs to start: `START_TAG ‖ mobile_pk ‖ commitment ‖
/// requested_at` (i64, 8 bytes big-endian). Names no station — a device that
/// reached the station by a typed address does not know its key yet.
pub fn start_signed_bytes(
    mobile_pk: &[u8; 32],
    commitment: &[u8; 32],
    requested_at: i64,
) -> Vec<u8> {
    concat(&[
        START_TAG,
        mobile_pk,
        commitment,
        &requested_at.to_be_bytes(),
    ])
}

/// The bytes the station signs to offer its nonce: `OFFER_TAG ‖ station_pk ‖
/// mobile_pk ‖ commitment ‖ station_nonce`. Covering the commitment fixes the
/// station's nonce against the device's before the device reveals it.
pub fn offer_signed_bytes(
    station_pk: &[u8; 32],
    mobile_pk: &[u8; 32],
    commitment: &[u8; 32],
    station_nonce: &[u8; 32],
) -> Vec<u8> {
    concat(&[OFFER_TAG, station_pk, mobile_pk, commitment, station_nonce])
}

/// The bytes the device signs to finish: `FINISH_TAG ‖ station_pk ‖ mobile_pk
/// ‖ commitment ‖ station_nonce ‖ mobile_nonce`. This is the station-bound
/// request: it cannot be presented to any other station.
pub fn finish_signed_bytes(
    station_pk: &[u8; 32],
    mobile_pk: &[u8; 32],
    commitment: &[u8; 32],
    station_nonce: &[u8; 32],
    mobile_nonce: &[u8; 32],
) -> Vec<u8> {
    concat(&[
        FINISH_TAG,
        station_pk,
        mobile_pk,
        commitment,
        station_nonce,
        mobile_nonce,
    ])
}

/// The confirmation code both sides show: the first 50 bits of
/// `blake3(CODE_TAG ‖ station_pk ‖ mobile_pk ‖ mobile_nonce ‖ station_nonce)`
/// in Crockford base32, as `XXXXX-XXXXX`.
pub fn code(
    station_pk: &[u8; 32],
    mobile_pk: &[u8; 32],
    mobile_nonce: &[u8; 32],
    station_nonce: &[u8; 32],
) -> String {
    let digest = blake3::hash(&concat(&[
        CODE_TAG,
        station_pk,
        mobile_pk,
        mobile_nonce,
        station_nonce,
    ]));
    human_code::render(digest.as_bytes(), CODE_CHARS, CODE_GROUP)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATION: [u8; 32] = [1; 32];
    const MOBILE: [u8; 32] = [2; 32];

    #[test]
    fn the_code_changes_per_session_for_the_same_keys() {
        // With the keys fixed, fresh nonces give a fresh code: a key search
        // made before the session cannot target it. (The retired code was a
        // function of the two keys alone and never changed.)
        let a = code(&STATION, &MOBILE, &fresh_nonce(), &fresh_nonce());
        let b = code(&STATION, &MOBILE, &fresh_nonce(), &fresh_nonce());
        assert_ne!(a, b);
        // Either nonce alone moves it.
        let (mn, sn) = ([3; 32], [4; 32]);
        let base = code(&STATION, &MOBILE, &mn, &sn);
        assert_ne!(base, code(&STATION, &MOBILE, &[5; 32], &sn));
        assert_ne!(base, code(&STATION, &MOBILE, &mn, &[5; 32]));
        // So does either key, and the key order matters.
        assert_ne!(base, code(&MOBILE, &STATION, &mn, &sn));
        assert_ne!(base, code(&[9; 32], &MOBILE, &mn, &sn));
    }

    #[test]
    fn code_is_50_bits_crockford_grouped() {
        let c = code(&STATION, &MOBILE, &[3; 32], &[4; 32]);
        assert_eq!(c.len(), 11);
        let (left, right) = c.split_once('-').expect("one hyphen");
        assert_eq!((left.len(), right.len()), (5, 5));
        assert!(c
            .bytes()
            .filter(|b| *b != b'-')
            .all(|b| human_code::ALPHABET.contains(&b)));
        assert_eq!(human_code::normalize(&c), c.replace('-', ""));
    }

    #[test]
    fn commitment_opens_only_with_its_nonce_and_key() {
        let nonce = [7; 32];
        let c = commitment(&MOBILE, &nonce);
        assert!(opens(&c, &MOBILE, &nonce));
        assert!(!opens(&c, &MOBILE, &[8; 32]));
        assert!(!opens(&c, &STATION, &nonce));
    }

    #[test]
    fn layouts_are_tagged_fixed_concatenations() {
        let c = [6; 32];
        let start = start_signed_bytes(&MOBILE, &c, -1);
        assert_eq!(start.len(), START_TAG.len() + 32 + 32 + 8);
        assert!(start.starts_with(START_TAG));
        assert_eq!(&start[start.len() - 8..], &[0xff; 8]);

        let offer = offer_signed_bytes(&STATION, &MOBILE, &c, &[4; 32]);
        assert_eq!(offer.len(), OFFER_TAG.len() + 4 * 32);
        assert!(offer.starts_with(OFFER_TAG));

        let finish = finish_signed_bytes(&STATION, &MOBILE, &c, &[4; 32], &[3; 32]);
        assert_eq!(finish.len(), FINISH_TAG.len() + 5 * 32);
        assert!(finish.starts_with(FINISH_TAG));
        // The finish carries the station's key, so it differs per station.
        assert_ne!(
            finish,
            finish_signed_bytes(&[9; 32], &MOBILE, &c, &[4; 32], &[3; 32])
        );
    }

    #[test]
    fn fresh_nonces_differ() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }
}
