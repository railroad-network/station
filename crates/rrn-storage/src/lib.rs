//! Local storage for Railroad Network.
//!
//! SQLite-backed persistence, CRDTs (PN-Counter, OR-Set, LWW-Register), and
//! the hash-chained append-only signed log. The append-only log is the source
//! of truth; CRDT state is *derived* from replaying it, never the reverse.
//!
//! # Single-writer model
//!
//! A [`db::Database`] owns one [`rusqlite::Connection`]. `Connection` is `!Sync`,
//! so `Database` is too — it is deliberately not shareable across threads
//! without external synchronization. Phase 0 has a single writer; connection
//! pooling and concurrent access are later concerns.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crdt;
pub mod db;
pub mod listings_index;
pub mod log;
pub mod migrations;
pub mod outbox;
pub mod replay;
pub mod reputation_snapshot;

/// Errors from the storage layer.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error surfaced by the underlying SQLite engine.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Stored bytes could not be decoded back into the expected structure —
    /// a corrupt or externally-tampered row.
    #[error("corrupt stored state: {0}")]
    Corrupt(String),
    /// A payload presented for appending did not carry a valid signature.
    #[error("log payload signature failed verification")]
    InvalidSignature,
    /// The hash chain is broken at `seq` — an entry was altered, reordered, or
    /// removed after being written.
    #[error("log chain broken at seq {seq}: {reason}")]
    ChainBroken {
        /// The sequence number where verification failed.
        seq: u64,
        /// What specifically did not line up.
        reason: String,
    },
    /// An outbox append presented a `position` that is not the next in the
    /// author's chain (`head.position + 1`, or `0` for an empty chain).
    #[error("outbox position gap: expected {expected}, got {got}")]
    PositionGap {
        /// The position the next entry must occupy.
        expected: u64,
        /// The position actually presented.
        got: u64,
    },
    /// An outbox append presented a `prev_hash` that does not equal the author's
    /// current head `entry_hash` (all-zero for an empty chain).
    #[error("outbox chain mismatch: prev_hash does not link to head")]
    ChainMismatch,
    /// An outbox append presented a `record_hash` already stored for this author
    /// — the same carried record cannot occupy two positions in one chain.
    #[error("outbox duplicate record for author")]
    DuplicateRecord,
    /// A delivery receipt reported an outcome for a record that conflicts with an
    /// outcome already recorded for it — a station cannot legitimately change its
    /// answer for the same `record_hash`.
    #[error("outbox conflicting ack for record")]
    ConflictingAck,
}

/// Convenience alias for storage results.
pub type Result<T> = std::result::Result<T, Error>;
