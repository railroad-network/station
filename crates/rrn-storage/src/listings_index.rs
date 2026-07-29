//! Row persistence for the `listings_index` cache table.
//!
//! Like [`reputation_snapshot`](crate::reputation_snapshot), this layer knows
//! nothing about what a listing *is*. It stores flat, already-decided columns
//! plus the listing's opaque canonical CBOR, and answers filter queries over
//! them. What a `surface` may be, which categories exist, and when a listing
//! counts as active are all `rrn-marketplace`'s business — the crate that owns
//! the database owns the statements against it, and nothing more.

use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::Result;

/// The `status` of a listing that is on the log and not closed.
pub const STATUS_ACTIVE: &str = "active";
/// The `status` of a listing with a close record on the log.
pub const STATUS_CLOSED: &str = "closed";

/// One row of the materialized listing index.
#[derive(Clone, Debug, PartialEq)]
pub struct IndexedListing {
    /// Content address of the listing — the primary key.
    pub listing_id: [u8; 32],
    /// The provider's public key bytes.
    pub provider: [u8; 32],
    /// Goods, Services, or Commons, as its wire tag.
    pub surface: String,
    /// The listing's category, from the controlled vocabulary.
    pub category: String,
    /// [`STATUS_ACTIVE`] or [`STATUS_CLOSED`] — what the log says, with expiry
    /// deliberately left out (see the migration).
    pub status: String,
    /// Price in centi-Commons.
    pub price_centi: i64,
    /// The provider's composite reputation at the instant the listing was
    /// created. A historical fact, kept for audit and stable tie-breaking;
    /// ranking uses current standing.
    pub reputation_at_creation: f32,
    /// Unix seconds the listing was created.
    pub created_at: i64,
    /// Unix seconds the listing expires, if it does.
    pub expires_at: Option<i64>,
    /// Canonical CBOR of the listing as it currently reads.
    pub listing_cbor: Vec<u8>,
}

/// Which rows [`active_matching`] should return. Every field is optional and a
/// `None` means "do not narrow on this".
#[derive(Clone, Debug, Default)]
pub struct IndexFilter {
    /// Restrict to one surface tag.
    pub surface: Option<String>,
    /// Restrict to one category.
    pub category: Option<String>,
    /// Cap the price.
    pub max_price_centi: Option<i64>,
}

/// Inserts or replaces the row for a listing.
///
/// A plain upsert with no last-write-wins guard, unlike
/// [`reputation_snapshot::put`](crate::reputation_snapshot::put): a snapshot is
/// a computation whose freshness has to be arbitrated, whereas this row is a
/// projection of log records that the caller has already replayed. The newest
/// replay is simply right.
pub fn put(db: &Database, row: &IndexedListing) -> Result<()> {
    db.conn().execute(
        "INSERT INTO listings_index (\
             listing_id, provider, surface, category, status, price_centi, \
             reputation_at_creation, created_at, expires_at, listing_cbor) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
         ON CONFLICT(listing_id) DO UPDATE SET \
             provider = excluded.provider, \
             surface = excluded.surface, \
             category = excluded.category, \
             status = excluded.status, \
             price_centi = excluded.price_centi, \
             reputation_at_creation = excluded.reputation_at_creation, \
             created_at = excluded.created_at, \
             expires_at = excluded.expires_at, \
             listing_cbor = excluded.listing_cbor",
        rusqlite::params![
            row.listing_id.as_slice(),
            row.provider.as_slice(),
            row.surface,
            row.category,
            row.status,
            row.price_centi,
            row.reputation_at_creation,
            row.created_at,
            row.expires_at,
            row.listing_cbor,
        ],
    )?;
    Ok(())
}

/// Reads one row by listing id.
pub fn get(db: &Database, listing_id: &[u8; 32]) -> Result<Option<IndexedListing>> {
    let row = db
        .conn()
        .query_row(
            "SELECT listing_id, provider, surface, category, status, price_centi, \
                    reputation_at_creation, created_at, expires_at, listing_cbor \
             FROM listings_index WHERE listing_id = ?1",
            [listing_id.as_slice()],
            decode_row,
        )
        .optional()?;
    Ok(row)
}

/// Removes one row. Returns whether there was one to remove.
pub fn remove(db: &Database, listing_id: &[u8; 32]) -> Result<bool> {
    let changed = db.conn().execute(
        "DELETE FROM listings_index WHERE listing_id = ?1",
        [listing_id.as_slice()],
    )?;
    Ok(changed > 0)
}

/// Empties the table — the first half of a rebuild.
pub fn clear(db: &Database) -> Result<()> {
    db.conn().execute("DELETE FROM listings_index", [])?;
    Ok(())
}

/// How many rows the index holds.
pub fn count(db: &Database) -> Result<i64> {
    let n = db
        .conn()
        .query_row("SELECT COUNT(*) FROM listings_index", [], |r| r.get(0))?;
    Ok(n)
}

/// Every active, unexpired row matching `filter`, ordered by listing id.
///
/// "Unexpired at `now`" is `expires_at >= now`: the last second of the window
/// still counts, matching `rrn_marketplace::lifecycle`, which treats a listing
/// as expired only once `now` is strictly past `expires_at`.
///
/// The order is by content address, not by anything chronological, so two
/// stations return the same order regardless of the sequence gossip delivered
/// the entries in. Callers rank the result themselves.
pub fn active_matching(
    db: &Database,
    filter: &IndexFilter,
    now: i64,
) -> Result<Vec<IndexedListing>> {
    let conn = db.conn();
    // One fixed statement with NULL-means-any parameters, rather than SQL built
    // by string concatenation: the plan is stable and there is no place for a
    // caller's value to become syntax.
    let mut stmt = conn.prepare(
        "SELECT listing_id, provider, surface, category, status, price_centi, \
                reputation_at_creation, created_at, expires_at, listing_cbor \
         FROM listings_index \
         WHERE status = ?1 \
           AND (?2 IS NULL OR surface = ?2) \
           AND (?3 IS NULL OR category = ?3) \
           AND (?4 IS NULL OR price_centi <= ?4) \
           AND (expires_at IS NULL OR expires_at >= ?5) \
         ORDER BY listing_id",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![
            STATUS_ACTIVE,
            filter.surface,
            filter.category,
            filter.max_price_centi,
            now,
        ],
        decode_row,
    )?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn decode_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IndexedListing> {
    Ok(IndexedListing {
        listing_id: blob32(r, 0)?,
        provider: blob32(r, 1)?,
        surface: r.get(2)?,
        category: r.get(3)?,
        status: r.get(4)?,
        price_centi: r.get(5)?,
        reputation_at_creation: r.get(6)?,
        created_at: r.get(7)?,
        expires_at: r.get(8)?,
        listing_cbor: r.get(9)?,
    })
}

fn blob32(r: &rusqlite::Row<'_>, idx: usize) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = r.get(idx)?;
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Blob,
            "expected 32 bytes".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations;

    fn open_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn row(id: u8, surface: &str, category: &str, price_centi: i64) -> IndexedListing {
        IndexedListing {
            listing_id: [id; 32],
            provider: [id.wrapping_add(100); 32],
            surface: surface.into(),
            category: category.into(),
            status: STATUS_ACTIVE.into(),
            price_centi,
            reputation_at_creation: 1.5,
            created_at: 1_800_000_000,
            expires_at: Some(1_900_000_000),
            listing_cbor: vec![id, 0xaa, 0xbb],
        }
    }

    #[test]
    fn a_row_survives_a_round_trip() {
        let db = open_db();
        let row = row(1, "goods", "food", 250);

        put(&db, &row).unwrap();

        assert_eq!(get(&db, &row.listing_id).unwrap(), Some(row));
    }

    #[test]
    fn putting_the_same_id_twice_replaces_rather_than_duplicates() {
        let db = open_db();
        let mut row = row(1, "goods", "food", 250);
        put(&db, &row).unwrap();

        row.price_centi = 199;
        row.status = STATUS_CLOSED.into();
        put(&db, &row).unwrap();

        assert_eq!(count(&db).unwrap(), 1);
        assert_eq!(get(&db, &row.listing_id).unwrap().unwrap().price_centi, 199);
    }

    #[test]
    fn filters_narrow_on_surface_category_and_price() {
        let db = open_db();
        put(&db, &row(1, "goods", "food", 250)).unwrap();
        put(&db, &row(2, "services", "food", 100)).unwrap();
        put(&db, &row(3, "goods", "tools", 900)).unwrap();
        let now = 1_850_000_000;

        let all = active_matching(&db, &IndexFilter::default(), now).unwrap();
        assert_eq!(all.len(), 3);
        // Ordered by content address, which for these fixtures is [1;32] < [2;32].
        assert_eq!(all[0].listing_id, [1; 32]);

        let goods = active_matching(
            &db,
            &IndexFilter {
                surface: Some("goods".into()),
                ..IndexFilter::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(goods.len(), 2);

        let food = active_matching(
            &db,
            &IndexFilter {
                category: Some("food".into()),
                ..IndexFilter::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(food.len(), 2);

        let cheap = active_matching(
            &db,
            &IndexFilter {
                max_price_centi: Some(250),
                ..IndexFilter::default()
            },
            now,
        )
        .unwrap();
        assert_eq!(cheap.len(), 2);

        let narrow = active_matching(
            &db,
            &IndexFilter {
                surface: Some("goods".into()),
                category: Some("food".into()),
                max_price_centi: Some(250),
            },
            now,
        )
        .unwrap();
        assert_eq!(narrow.len(), 1);
        assert_eq!(narrow[0].listing_id, [1; 32]);
    }

    #[test]
    fn closed_and_expired_rows_are_left_out() {
        let db = open_db();
        let mut closed = row(1, "goods", "food", 250);
        closed.status = STATUS_CLOSED.into();
        put(&db, &closed).unwrap();
        put(&db, &row(2, "goods", "food", 250)).unwrap();
        let mut evergreen = row(3, "goods", "food", 250);
        evergreen.expires_at = None;
        put(&db, &evergreen).unwrap();

        // Before any expiry: the closed row is out, the other two are in.
        let open_now = active_matching(&db, &IndexFilter::default(), 1_850_000_000).unwrap();
        assert_eq!(open_now.len(), 2);

        // The window's last second still counts; the next one does not.
        assert_eq!(
            active_matching(&db, &IndexFilter::default(), 1_900_000_000)
                .unwrap()
                .len(),
            2
        );
        let after = active_matching(&db, &IndexFilter::default(), 1_900_000_001).unwrap();
        assert_eq!(after.len(), 1);
        // A listing with no expiry never falls out, however late it is asked.
        assert_eq!(after[0].listing_id, [3; 32]);
    }

    #[test]
    fn rows_can_be_removed_and_the_table_cleared() {
        let db = open_db();
        put(&db, &row(1, "goods", "food", 250)).unwrap();
        put(&db, &row(2, "goods", "food", 250)).unwrap();

        assert!(remove(&db, &[1; 32]).unwrap());
        assert!(!remove(&db, &[1; 32]).unwrap());
        assert_eq!(count(&db).unwrap(), 1);

        clear(&db).unwrap();
        assert_eq!(count(&db).unwrap(), 0);
    }
}
