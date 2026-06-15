//! SQLite connection management.
//!
//! [`Database`] wraps a single [`rusqlite::Connection`] configured for our
//! access pattern: WAL journaling (concurrent readers alongside one writer,
//! crash-safe) and enforced foreign keys (off by default in SQLite — it must be
//! turned on for every connection).
//!
//! Every operation is traced at `trace` level so a full session can be replayed
//! from logs when debugging.

use std::path::Path;

use rusqlite::Connection;

use crate::Result;

/// A handle to the local SQLite database.
///
/// Owns one connection. `Connection` is `!Sync`, so `Database` inherits that:
/// it must not be shared across threads without external synchronization. This
/// is the intended single-writer model for Phase 0.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Opens (creating if absent) the database file at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        tracing::trace!(path = %path.display(), "opening database");
        let conn = Connection::open(path)?;
        Self::from_conn(conn)
    }

    /// Opens a private, in-memory database — used by tests and ephemeral state.
    ///
    /// Note: SQLite ignores WAL mode for in-memory databases (journaling stays
    /// `memory`); `foreign_keys` is still honored.
    pub fn open_in_memory() -> Result<Self> {
        tracing::trace!("opening in-memory database");
        let conn = Connection::open_in_memory()?;
        Self::from_conn(conn)
    }

    /// Applies the standard PRAGMA configuration to a freshly opened connection.
    fn from_conn(conn: Connection) -> Result<Self> {
        tracing::trace!("configuring connection: journal_mode=WAL, foreign_keys=ON");
        // `foreign_keys` is a connection-level setting and is OFF by default in
        // SQLite — it must be set on every connection, not just at create time.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        Ok(Self { conn })
    }

    /// Borrows the underlying connection for query execution by sibling modules.
    ///
    /// Transactions are taken via [`rusqlite::Connection::unchecked_transaction`]
    /// (which borrows `&self`), so a shared borrow is sufficient throughout —
    /// the single-writer model means there is never a competing transaction.
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Returns the active journal mode (e.g. `"wal"` for file DBs, `"memory"`
    /// for in-memory). Primarily for verifying configuration in tests.
    pub fn journal_mode(&self) -> Result<String> {
        let mode = self
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
        Ok(mode)
    }

    /// Returns whether foreign-key enforcement is enabled on this connection.
    pub fn foreign_keys(&self) -> Result<bool> {
        let on = self
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, bool>(0))?;
        Ok(on)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_succeeds() {
        assert!(Database::open_in_memory().is_ok());
    }

    #[test]
    fn in_memory_enforces_foreign_keys() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.foreign_keys().unwrap(), "foreign_keys must be ON");
        // In-memory databases ignore WAL and report `memory`.
        assert_eq!(db.journal_mode().unwrap(), "memory");
    }

    #[test]
    fn file_db_uses_wal_and_foreign_keys() {
        let dir = std::env::temp_dir().join(format!("rrn-storage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let db = Database::open(&path).unwrap();
        assert_eq!(db.journal_mode().unwrap(), "wal");
        assert!(db.foreign_keys().unwrap());
        drop(db);
        // WAL leaves -wal/-shm sidecar files; clean the whole dir.
        std::fs::remove_dir_all(&dir).ok();
    }
}
