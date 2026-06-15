//! Schema migrations.
//!
//! Migrations are embedded SQL files applied in version order. Each is run once,
//! inside a transaction, and recorded in the `_migrations` table together with a
//! Blake3 checksum of the SQL text. Re-running is a no-op: already-applied
//! versions are skipped. Migrations are immutable once shipped — fixing a
//! mistake means writing a new migration, never editing an old one.

use std::time::{SystemTime, UNIX_EPOCH};

use rrn_crypto::hash::Hash;
use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::Result;

/// One embedded migration: a version number and its SQL text.
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

/// All migrations, in ascending version order. Append new entries; never modify
/// or reorder existing ones.
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial",
    sql: include_str!("../migrations/0001_initial.sql"),
}];

/// Applies every migration that has not yet been recorded, in order.
///
/// Idempotent: a second call with no new migrations does nothing. Each migration
/// runs in its own transaction, so a failure leaves the database at the last
/// fully-applied version rather than half-migrated.
pub fn run(db: &Database) -> Result<()> {
    let conn = db.conn();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
            version    INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            checksum   BLOB NOT NULL
        ) STRICT;",
    )?;

    for m in MIGRATIONS {
        let already: Option<i64> = conn
            .query_row(
                "SELECT version FROM _migrations WHERE version = ?1",
                [m.version],
                |row| row.get(0),
            )
            .optional()?;
        if already.is_some() {
            tracing::trace!(
                version = m.version,
                name = m.name,
                "migration already applied"
            );
            continue;
        }

        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(m.sql)?;
        let checksum = Hash::of(m.sql.as_bytes());
        tx.execute(
            "INSERT INTO _migrations (version, applied_at, checksum) VALUES (?1, ?2, ?3)",
            rusqlite::params![m.version, now(), checksum.to_bytes().as_slice()],
        )?;
        tx.commit()?;
        tracing::info!(version = m.version, name = m.name, "applied migration");
    }
    Ok(())
}

/// Current Unix time in seconds. Migrations are operational (not ledger) code,
/// so reading the system clock here is appropriate; before the epoch is
/// impossible in practice and saturates to 0.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Names of objects created by migration 0001 (excludes the internal
    /// `_migrations` bookkeeping table and SQLite's own `sqlite_*` objects).
    fn schema_objects(db: &Database) -> (BTreeSet<String>, BTreeSet<String>) {
        let conn = db.conn();
        let collect = |kind: &str| -> BTreeSet<String> {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT name FROM sqlite_master WHERE type = '{kind}' \
                     AND name NOT LIKE 'sqlite_%' AND name != '_migrations' ORDER BY name"
                ))
                .unwrap();
            stmt.query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        (collect("table"), collect("index"))
    }

    #[test]
    fn creates_expected_tables_and_indexes() {
        let db = Database::open_in_memory().unwrap();
        run(&db).unwrap();
        let (tables, indexes) = schema_objects(&db);

        let expected_tables: BTreeSet<String> = [
            "attestations",
            "balances",
            "identities",
            "kv",
            "log_entries",
            "transactions",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(tables, expected_tables);

        let expected_indexes: BTreeSet<String> = [
            "idx_attestations_signer",
            "idx_transactions_receiver",
            "idx_transactions_sender",
            "idx_transactions_state",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(indexes, expected_indexes);
    }

    #[test]
    fn rerun_is_a_noop() {
        let db = Database::open_in_memory().unwrap();
        run(&db).unwrap();
        let count_applied = |db: &Database| -> i64 {
            db.conn()
                .query_row("SELECT COUNT(*) FROM _migrations", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count_applied(&db), MIGRATIONS.len() as i64);

        // A second run records nothing new.
        run(&db).unwrap();
        assert_eq!(count_applied(&db), MIGRATIONS.len() as i64);
    }

    #[test]
    fn schema_matches_golden() {
        let db = Database::open_in_memory().unwrap();
        run(&db).unwrap();

        // The CREATE statements SQLite actually stored, each collapsed to a
        // single whitespace-normalized line, one per line, tables before
        // indexes (type DESC) then by name. Compared against a committed golden
        // file so any unintended schema drift trips this test.
        let actual = dump_schema(&db);
        let golden = include_str!("../tests/schema.golden.sql").trim();
        assert_eq!(
            actual.trim(),
            golden,
            "schema drifted from tests/schema.golden.sql; regenerate it from this output"
        );
    }

    /// Regenerates `tests/schema.golden.sql` from the live schema. Run with
    /// `cargo test -p rrn-storage regenerate_golden -- --ignored` after an
    /// intentional schema change, then review the diff.
    #[test]
    #[ignore = "writes a source-tree file; run manually to refresh the golden"]
    fn regenerate_golden() {
        let db = Database::open_in_memory().unwrap();
        run(&db).unwrap();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/schema.golden.sql");
        std::fs::write(path, format!("{}\n", dump_schema(&db))).unwrap();
    }

    /// Renders the live schema as normalized CREATE statements, one per line.
    fn dump_schema(db: &Database) -> String {
        let conn = db.conn();
        let mut stmt = conn
            .prepare(
                "SELECT sql FROM sqlite_master \
                 WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' AND name != '_migrations' \
                 ORDER BY type DESC, name",
            )
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap().split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
