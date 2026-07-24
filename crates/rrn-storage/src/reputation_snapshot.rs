//! Row persistence for the `reputation_snapshots` cache table.
//!
//! This layer knows nothing about what a reputation profile *is* — it stores and
//! returns the opaque canonical-CBOR blob that `rrn-reputation` computes, keyed by
//! a 32-byte address. Keeping the SQL here (next to the schema and the connection)
//! mirrors how `PnCounter` owns the `balances` table: the crate that owns the
//! database owns the statements against it.

use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::Result;

/// A stored snapshot row: the instant it was computed as of, and the profile's
/// canonical CBOR bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSnapshot {
    /// Unix seconds the snapshot was scored as of.
    pub last_computed_at: i64,
    /// Canonical CBOR of the `ReputationProfile`.
    pub profile_cbor: Vec<u8>,
}

/// Writes the snapshot for `address`, last-write-wins on `last_computed_at`.
///
/// A fresh row is always inserted; an existing row is overwritten only when
/// `last_computed_at` is at least as recent as the stored one, so a stale
/// recompute can never clobber a newer snapshot. This is the LWW-Register merge
/// specialized to a value every station derives identically — there is no genuine
/// value conflict to arbitrate, only which computation is fresher. Returns whether
/// a row was written.
pub fn put(
    db: &Database,
    address: &[u8; 32],
    last_computed_at: i64,
    profile_cbor: &[u8],
) -> Result<bool> {
    let changed = db.conn().execute(
        "INSERT INTO reputation_snapshots (address, last_computed_at, profile_cbor) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(address) DO UPDATE SET \
             last_computed_at = excluded.last_computed_at, \
             profile_cbor = excluded.profile_cbor \
         WHERE excluded.last_computed_at >= reputation_snapshots.last_computed_at",
        rusqlite::params![address.as_slice(), last_computed_at, profile_cbor],
    )?;
    Ok(changed > 0)
}

/// Reads the stored snapshot for `address`, if one exists.
pub fn get(db: &Database, address: &[u8; 32]) -> Result<Option<StoredSnapshot>> {
    let row = db
        .conn()
        .query_row(
            "SELECT last_computed_at, profile_cbor FROM reputation_snapshots WHERE address = ?1",
            [address.as_slice()],
            |r| {
                Ok(StoredSnapshot {
                    last_computed_at: r.get(0)?,
                    profile_cbor: r.get(1)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}
