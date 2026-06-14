//! Cryptographic primitives for Railroad Network.
//!
//! Ed25519 signing, Blake3 hashing, and canonical CBOR serialization. This
//! crate is the audit boundary: it must never depend on other `rrn-*` crates.
