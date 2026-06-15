//! Cryptographic primitives for Railroad Network — the foundation crypto layer.
//!
//! This crate provides the four primitives every higher layer builds on:
//!
//! - [`keypair`] — Ed25519 keypair generation, signing, and verification.
//! - [`hash`] — Blake3 content hashing (entry chaining, content addressing).
//! - [`serialize`] — canonical (deterministic) CBOR for anything that gets
//!   signed, so a logical value has exactly one byte representation.
//! - [`signed`] — [`signed::SignedPayload`]: "data plus a signature over its
//!   canonical bytes", used pervasively across the project.
//!
//! # Audit boundary
//!
//! `rrn-crypto` is the project's **audit boundary**. It must never depend on
//! another `rrn-*` crate — the dependency arrows point *into* it, never out.
//! It is also the only crate permitted to contain `unsafe` (a workspace-wide
//! lint forbids it everywhere else); keeping the security-critical surface
//! small and self-contained is the whole point. Anything an external auditor
//! must trust to verify a signature or reproduce a canonical encoding lives
//! here and nowhere else.
//!
//! # What does *not* go through this crate
//!
//! Password/passphrase hashing is a separate concern handled with `argon2`
//! in `rrn-identity` — do not use [`hash`] (Blake3) for that. Symmetric
//! encryption of data at rest likewise lives in `rrn-identity`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod hash;
pub mod keypair;
pub mod serialize;
pub mod signed;
