//! Identity layer for Railroad Network — where keys become identities.
//!
//! `rrn-crypto` deals in raw cryptographic primitives (keypairs, signatures,
//! canonical CBOR). This crate gives those primitives a social meaning:
//!
//! - [`address`] — bech32m-encoded, checksummed public keys (`rrn1…`), the
//!   form an identity takes in CLI output, error messages, and QR codes.
//! - [`wallet`] — a single-identity wallet (secret key + metadata) persisted to
//!   disk encrypted under a passphrase (argon2id key derivation +
//!   XChaCha20-Poly1305).
//! - [`attestation`] — the generic "X says Y" signed claim that vouches,
//!   credentials, and transaction confirmations are all specializations of.
//! - [`vouch`] — the first concrete attestation: a signed statement that a key
//!   belongs to a real, known individual.
//!
//! # Where it sits in the stack
//!
//! It depends on `rrn-crypto` for primitives ([`rrn_crypto::keypair`],
//! [`rrn_crypto::signed::SignedPayload`], canonical CBOR) and on `rrn-storage`
//! for the append-only log that attestations are written to. It must not be
//! depended on by `rrn-crypto` — the dependency arrows point up the stack.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod attestation;
pub mod vouch;
pub mod wallet;
