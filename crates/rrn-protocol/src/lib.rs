//! Delay-tolerant submission wire formats for Railroad Network (ADR-0020).
//!
//! The community log keeps a single writer — the station — and Phase 2 adds
//! *delay-tolerant submission*: signed records travel store-and-forward from
//! member devices to the station over any carrier (LoRa, SMS, paper, another
//! member's phone) and land later, with proof of delivery. This crate is the
//! typed, canonical, fixture-locked wire layer of that mechanism. It is pure
//! data plus validation — no storage (`rrn-storage`, T2.2.2), no ingest or
//! receipt issuance (`rrn-station`, T2.2.3), no networking.
//!
//! Three record shapes make up the layer:
//!
//! - [`outbox::OutboxEntry`] — a per-device, hash-chained, signed carriage
//!   entry wrapping exactly one already-signed application record (a proposal,
//!   confirmation, vote, vouch, …). One chain per signing key. The chain makes
//!   a carried record tamper-evident, makes courier suppression detectable (a
//!   gap in the chain), and makes device-owner double-authorship — two entries
//!   at the same position, an *outbox fork* — provable equivocation, which
//!   ADR-0021 builds on.
//! - [`bundle::Bundle`] — an **unsigned** carriage envelope: a run of signed
//!   outbox entries from one or more devices. Integrity lives on each entry, so
//!   couriers are dumb carriers (ADR-0008/0013) — a bundle is never the
//!   authenticity boundary.
//! - [`receipt::DeliveryReceipt`] — a **station-signed** answer to an ingested
//!   bundle, enumerating per record admitted / already-known / refused-with-
//!   reason. A receipt is transport state, not community state: it is never
//!   appended to the community log.
//!
//! # Time in these records is testimony (ADR-0022 §3)
//!
//! Every timestamp here (`authored_at`, `assembled_at`, `received_at`) is a
//! party- or station-asserted reading kept for display and evidence. None of
//! them drives a window, deadline, ordering, or eligibility decision: admission
//! order is arrival order, and every window runs from the station's admission
//! clock (ADR-0022). `received_at` is the station's own admission-clock reading
//! at ingest — evidence of *when it answered*, not an input to anyone's window
//! arithmetic.
//!
//! # What is signed, and the embedded-record rule
//!
//! Signed records go through [`rrn_crypto::signed::SignedPayload`]: the
//! signature covers the canonical dCBOR of the payload (ADR-0002), never a wire
//! envelope. An outbox entry carries its wrapped record as three fields — the
//! record's signer, its signature, and its *already-signed canonical bytes* —
//! never re-serialized and never re-signed, so the carried signature stays
//! valid exactly as its author produced it and its content hash is the same
//! Blake3 identifier the log admits under.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod outbox;
pub mod receipt;

use rrn_crypto::hash::Hash;

/// An error constructing, decoding, or validating a DTN wire record.
///
/// The `From<T> for CBOR` / `TryFrom<CBOR>` mappings on the record types follow
/// the house style and surface pure shape faults as [`dcbor::Error`]; this
/// richer type is what the *validation* surface returns (signature checks,
/// bundle structural bounds, chain linkage), where a bare `WrongType` would
/// lose the reason a courier-tampered or malformed carriage unit was refused.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes were not valid canonical dCBOR, or did not match the target
    /// record shape.
    #[error("canonical CBOR: {0}")]
    Cbor(String),
    /// An outbox entry's outer signature (by the chain-owning device key) did
    /// not verify against the entry body.
    #[error("outbox entry outer signature does not verify")]
    BadOuterSignature,
    /// The signature over the carried record's bytes did not verify against the
    /// carried record's signer.
    #[error("embedded record signature does not verify")]
    BadEmbeddedSignature,
    /// The entry's declared `author` is not the key that signed the entry. The
    /// chain owner must be the signer (ADR-0020 §2).
    #[error("outbox entry author does not match its outer signer")]
    AuthorSignerMismatch,
    /// A chained entry's `prev_hash` does not equal the previous entry's
    /// [`entry_hash`](outbox::OutboxEntry::entry_hash).
    #[error("outbox chain broken at position {position}: prev_hash does not link")]
    ChainBroken {
        /// Position of the entry whose `prev_hash` failed to link.
        position: u64,
    },
    /// A chain's positions are not the strict sequence `0, 1, 2, …`.
    #[error("outbox chain position out of sequence: expected {expected}, found {found}")]
    PositionOutOfSequence {
        /// The position the sequence required here.
        expected: u64,
        /// The position actually found.
        found: u64,
    },
    /// A bundle carried more than [`bundle::MAX_BUNDLE_ENTRIES`] entries.
    #[error("bundle carries {found} entries, over the {max} cap")]
    TooManyEntries {
        /// Number of entries found.
        found: usize,
        /// The cap ([`bundle::MAX_BUNDLE_ENTRIES`]).
        max: usize,
    },
    /// A bundle's encoded form exceeded [`bundle::MAX_BUNDLE_BYTES`].
    #[error("bundle is {found} bytes, over the {max}-byte cap")]
    BundleTooLarge {
        /// Encoded byte length seen.
        found: usize,
        /// The cap ([`bundle::MAX_BUNDLE_BYTES`]).
        max: usize,
    },
    /// Two entries by the same author appear in a bundle out of position order
    /// (a courier-tamper tripwire — a *gap* is legal, only disorder is refused).
    #[error("bundle has same-author entries out of order for one device")]
    EntriesOutOfOrder,
}

impl From<rrn_crypto::serialize::SerializeError> for Error {
    fn from(e: rrn_crypto::serialize::SerializeError) -> Self {
        Error::Cbor(e.to_string())
    }
}

/// The 32-byte all-zero hash: the `prev_hash` of an outbox chain's first entry.
pub(crate) fn zero_hash() -> Hash {
    Hash::from_bytes([0u8; 32])
}

/// Result alias for this crate's validation surface.
pub type Result<T> = std::result::Result<T, Error>;
