//! Local wallet metadata (ADR-0028).
//!
//! A tiny string-keyed key/value table for the self-custody CLI member wallet's
//! own bookkeeping. Unlike the log and the CRDT-derived caches, this is
//! **unsigned local metadata**: it is never signed, never appended to the
//! community log, never replayed, and a replica re-derives nothing from it. It
//! is co-located with the outbox in the same [`Database`] so that a backup of
//! the wallet home carries the chain and its cursors together (ADR-0028 §3/§7).
//!
//! `rrn-storage` cannot run arbitrary SQL from a higher layer ([`Database::conn`]
//! is crate-private), so the wallet's metadata has to live here rather than in a
//! side file the CLI opens itself. The value column is always TEXT; callers that
//! store a number keep it as a decimal string and parse it back.
//!
//! # The wallet's key set
//!
//! The wallet layer owns the semantics; this module only stores strings. The
//! keys the wallet uses (all documented at the wallet layer):
//!
//! - `role` — `"member"`; the pre-unlock role guard rests on this plaintext row.
//! - `schema` — the wallet's on-disk metadata schema version.
//! - `station_address` — the pinned station `rrn1…` address (bech32).
//! - `station_url` — `host:port` of the paired station.
//! - `paired` — `"pending"` | `"yes"`.
//! - `transport_nonce` — the sealed-channel transport nonce (u64, decimal).
//! - `nonce_cursor` — the nonce the next proposal/cert request will carry (u64).
//! - `chain_state` — `"fresh"` | `"anchored"` | `"unknown"`.
//! - `last_sync_at` — admission/edge-clock reading of the last successful sync.
//! - `cert:<cert_id_hex>` — a held certificate envelope, hex.
//! - `cert_history:<cert_id_hex>` — JSON array of proposal-envelope hex spent
//!   against that certificate.

use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::Result;

/// Read/write access to the wallet's local metadata over a borrowed
/// [`Database`]. Mirrors the borrowing shape of [`crate::outbox::OutboxStore`].
pub struct WalletMeta<'a> {
    db: &'a Database,
}

impl<'a> WalletMeta<'a> {
    /// Wraps a database handle for metadata access.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// The value stored for `key`, or `None` if unset.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT value FROM wallet_meta WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    /// Sets `key` to `value`, overwriting any existing value.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        self.db.conn().execute(
            "INSERT INTO wallet_meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Removes `key` if present (a no-op if it is absent).
    pub fn delete(&mut self, key: &str) -> Result<()> {
        self.db
            .conn()
            .execute("DELETE FROM wallet_meta WHERE key = ?1", [key])?;
        Ok(())
    }

    /// Every `(key, value)` pair, ordered by key — audit/introspection view.
    pub fn all(&self) -> Result<Vec<(String, String)>> {
        let conn = self.db.conn();
        let mut stmt = conn.prepare("SELECT key, value FROM wallet_meta ORDER BY key")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        db
    }

    #[test]
    fn get_set_overwrite_delete() {
        let db = fresh_db();
        let mut meta = WalletMeta::new(&db);

        assert_eq!(meta.get("role").unwrap(), None);
        meta.set("role", "member").unwrap();
        assert_eq!(meta.get("role").unwrap(), Some("member".to_string()));

        // Overwrite.
        meta.set("role", "operator").unwrap();
        assert_eq!(meta.get("role").unwrap(), Some("operator".to_string()));

        // Delete is idempotent.
        meta.delete("role").unwrap();
        assert_eq!(meta.get("role").unwrap(), None);
        meta.delete("role").unwrap();
    }

    #[test]
    fn all_is_ordered_by_key() {
        let db = fresh_db();
        let mut meta = WalletMeta::new(&db);
        meta.set("station_url", "192.168.4.1:7500").unwrap();
        meta.set("nonce_cursor", "3").unwrap();
        meta.set("role", "member").unwrap();

        assert_eq!(
            meta.all().unwrap(),
            vec![
                ("nonce_cursor".to_string(), "3".to_string()),
                ("role".to_string(), "member".to_string()),
                ("station_url".to_string(), "192.168.4.1:7500".to_string()),
            ]
        );
    }
}
