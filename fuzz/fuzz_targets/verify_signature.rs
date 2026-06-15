#![no_main]
//! Fuzz the signature-verification parsing path: arbitrary
//! `(pubkey_bytes, sig_bytes, message)` triples must never panic. Every error
//! (off-curve key, non-verifying signature) is an expected, handled outcome.

use libfuzzer_sys::fuzz_target;
use rrn_crypto::keypair::{PublicKey, Signature};

fuzz_target!(|data: &[u8]| {
    // Layout: first 32 bytes = public key, next 64 = signature, rest = message.
    if data.len() < 96 {
        return;
    }
    let pk_bytes: [u8; 32] = data[0..32].try_into().unwrap();
    let sig_bytes: [u8; 64] = data[32..96].try_into().unwrap();
    let message = &data[96..];

    if let (Ok(pk), Ok(sig)) = (
        PublicKey::from_bytes(pk_bytes),
        Signature::from_bytes(sig_bytes),
    ) {
        // Result is irrelevant; what matters is that this never panics.
        let _ = pk.verify(message, &sig);
    }
});
