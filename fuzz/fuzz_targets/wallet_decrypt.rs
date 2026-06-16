#![no_main]
//! Fuzz the encrypted-wallet decode + decrypt path: arbitrary bytes are
//! decoded as an `EncryptedWallet` (canonical CBOR) and, if that succeeds,
//! decrypted under an arbitrary passphrase. A wrong passphrase, tampered
//! ciphertext, unsupported version, or malformed CBOR are all expected
//! errors; the parser and AEAD path must never panic.
//!
//! Known caveat: `EncryptedWallet` stores its argon2id parameters in the file,
//! and Phase 0 does not clamp them on decode (see `docs/threat-model.md`,
//! `rrn-identity` DoS residual risk). A coverage-guided run that learns to
//! produce a structurally-valid wallet with a huge `m_cost` can therefore
//! trigger a large allocation rather than a panic — that is the documented
//! residual risk surfacing, not a parser bug. Triage such a finding against
//! the threat model before treating it as a new defect.

use libfuzzer_sys::fuzz_target;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::wallet::EncryptedWallet;

fuzz_target!(|input: (Vec<u8>, String)| {
    let (bytes, passphrase) = input;
    if let Ok(wallet) = from_canonical_bytes::<EncryptedWallet>(&bytes) {
        let _ = wallet.decrypt(&passphrase);
    }
});
