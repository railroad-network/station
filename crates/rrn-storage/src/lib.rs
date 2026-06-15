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
pub mod log;
pub mod migrations;
pub mod replay;

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
}

/// Convenience alias for storage results.
pub type Result<T> = std::result::Result<T, Error>;
