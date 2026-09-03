//! Station-role DTN state: seen remote chains, fork evidence, issued receipts
//! (ADR-0020 §3-§4; T2.2.3).
//!
//! This is the *station's* view of delay-tolerant submission, the counterpart to
//! [`crate::outbox`] (a *device's* own outbox). It persists three things the
//! station needs across restarts:
//!
//! - **Seen remote chains** — for each remote author, every `(position,
//!   entry_hash)` the station has received, and a cache of that author's highest
//!   *contiguously* seen position (its head). A gap does not advance the head;
//!   filling the gap later does (ADR-0020 §2).
//! - **Fork evidence** — when two validly-signed entries from one author claim
//!   the same position with different content (an outbox fork / equivocation,
//!   ADR-0021), both raw envelopes are kept verbatim for T2.3.3.
//! - **Issued receipts** — keyed by a bundle's *presentation hash*, so
//!   re-ingesting a byte-identical presentation returns the same receipt
//!   verbatim (idempotency, ADR-0020 §3).
//!
//! # Layering
//!
//! `rrn-storage` sits below `rrn-protocol`, so this store cannot parse an outbox
//! entry or a receipt. Exactly as [`crate::outbox::OutboxStore`] does, it holds
//! **opaque, already-validated** bytes plus pre-extracted scalar columns; the
//! station layer (which has `rrn-protocol`) validates each entry, decides
//! fresh/duplicate/fork, and supplies the columns. The store enforces only the
//! structural bookkeeping: recording a position once, comparing hashes to detect
//! a fork, and advancing the contiguous head.
//!
//! None of this is community-log state: it is never signed, never replayed, and
//! a replica re-derives nothing from it (ADR-0020 §1).

use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::{Error, Result};

/// An author's highest *contiguously seen* outbox position and that entry's
/// hash — the head of the run received without a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenHead {
    /// The highest contiguous position (0-based).
    pub position: u64,
    /// Blake3 of the entry at that position.
    pub entry_hash: [u8; 32],
}

/// What [`DtnStore::note_entry`] found when recording a seen entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteOutcome {
    /// This `(author, position)` had not been seen before; it was recorded (and
    /// the contiguous head advanced as far as the recorded positions allow).
    Fresh,
    /// This exact `(author, position, entry_hash)` was already recorded — the
    /// same entry carried again. Nothing changed.
    Duplicate,
    /// A *different* entry already sits at this `(author, position)`: an outbox
    /// fork. Carries the stored (earlier-seen) side so the caller can persist
    /// evidence via [`DtnStore::record_fork`]. Nothing was recorded for the
    /// incoming entry — the position stays owned by the stored side.
    Fork {
        /// Blake3 of the stored (earlier) entry.
        stored_entry_hash: [u8; 32],
        /// The stored entry's raw envelope bytes.
        stored_envelope: Vec<u8>,
    },
}

/// How much longer an *unconfirmed* delivery row is kept than a confirmed one:
/// a courier may take weeks to carry a receipt home, so a receipt no author has
/// picked up survives `retention_secs` × this multiplier before it is pruned
/// ([`DtnStore::prune_delivered`]).
pub const RETENTION_UNCONFIRMED_MULTIPLIER: i64 = 4;

/// One queued receipt-delivery row ([`DtnStore::delivery_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRow {
    /// The record's author (32-byte public key).
    pub author: [u8; 32],
    /// The presentation hash of the receipt that reported this record.
    pub receipt_presentation: [u8; 32],
    /// How many times a receipt for this record has been handed out.
    pub fetched_count: i64,
    /// Whether the record's own author has confirmed delivery.
    pub confirmed_delivered: bool,
}

/// A page of pending delivery receipts for one fetch ([`DtnStore::pending_receipts_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReceipts {
    /// The distinct receipt-envelope bytes, oldest first, at most the requested
    /// `limit`. Each is a `SignedReceipt` envelope (`rrn_protocol::receipt`), an
    /// opaque blob to this layer.
    pub receipts: Vec<Vec<u8>>,
    /// The delivery rows this fetch acted on — the record hashes (matching the
    /// author filter) covered by the returned receipts. The caller bumps or
    /// confirms exactly these, so a receipt truncated out by `limit` is untouched.
    pub record_hashes: Vec<[u8; 32]>,
    /// Whether more distinct pending receipts existed than `limit` returned.
    pub truncated: bool,
}

/// One persisted outbox-fork evidence row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkRow {
    /// The equivocating author's 32-byte public key.
    pub author: [u8; 32],
    /// The shared position.
    pub position: u64,
    /// Blake3 of the earlier-seen (stored) entry.
    pub entry_hash_a: [u8; 32],
    /// Blake3 of the later-arriving (refused) entry.
    pub entry_hash_b: [u8; 32],
    /// The earlier entry's envelope bytes.
    pub envelope_a: Vec<u8>,
    /// The later entry's envelope bytes.
    pub envelope_b: Vec<u8>,
    /// Admission-clock reading at detection (testimony).
    pub detected_at: i64,
}

/// Station-role DTN persistence over the `seen_outbox_*`, `outbox_forks`, and
/// `issued_receipts` tables (migration 0006).
pub struct DtnStore<'a> {
    db: &'a Database,
}

impl<'a> DtnStore<'a> {
    /// Opens the store over a database handle.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Records that `entry_hash` was seen at `(author, position)`, returning
    /// whether it was fresh, a duplicate, or one side of a fork.
    ///
    /// On [`NoteOutcome::Fresh`] the entry is persisted and the author's
    /// contiguous head is advanced as far as the recorded positions now allow
    /// (so a previously-gapped position that this call fills lets the head jump
    /// forward). A [`NoteOutcome::Duplicate`] or [`NoteOutcome::Fork`] records
    /// nothing new and leaves the head untouched — the position is already owned.
    pub fn note_entry(
        &mut self,
        author: &[u8; 32],
        position: u64,
        entry_hash: &[u8; 32],
        envelope: &[u8],
        now: i64,
    ) -> Result<NoteOutcome> {
        if let Some((stored_hash, stored_envelope)) = self.entry_at(author, position)? {
            return Ok(if &stored_hash == entry_hash {
                NoteOutcome::Duplicate
            } else {
                NoteOutcome::Fork {
                    stored_entry_hash: stored_hash,
                    stored_envelope,
                }
            });
        }
        // Fresh: record the position, then re-derive the contiguous head.
        self.db.conn().execute(
            "INSERT INTO seen_outbox_entries \
             (author, position, entry_hash, envelope, seen_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                author.as_slice(),
                position as i64,
                entry_hash.as_slice(),
                envelope,
                now
            ],
        )?;
        self.advance_head(author, now)?;
        Ok(NoteOutcome::Fresh)
    }

    /// The author's current contiguous head, if any position has been seen from
    /// position 0 onward.
    pub fn head(&self, author: &[u8; 32]) -> Result<Option<SeenHead>> {
        self.db
            .conn()
            .query_row(
                "SELECT position, entry_hash FROM seen_outbox_heads WHERE author = ?1",
                [author.as_slice()],
                |row| {
                    let position: i64 = row.get(0)?;
                    let entry_hash: Vec<u8> = row.get(1)?;
                    Ok((position, entry_hash))
                },
            )
            .optional()?
            .map(|(position, entry_hash)| {
                Ok(SeenHead {
                    position: position as u64,
                    entry_hash: to_hash("seen_outbox_heads.entry_hash", entry_hash)?,
                })
            })
            .transpose()
    }

    /// Persists outbox-fork evidence for `(author, position)`. Idempotent: a
    /// second detection of the same fork leaves the first row intact.
    #[allow(clippy::too_many_arguments)]
    pub fn record_fork(
        &mut self,
        author: &[u8; 32],
        position: u64,
        entry_hash_a: &[u8; 32],
        envelope_a: &[u8],
        entry_hash_b: &[u8; 32],
        envelope_b: &[u8],
        now: i64,
    ) -> Result<()> {
        self.db.conn().execute(
            "INSERT OR IGNORE INTO outbox_forks \
             (author, position, entry_hash_a, entry_hash_b, envelope_a, envelope_b, detected_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                author.as_slice(),
                position as i64,
                entry_hash_a.as_slice(),
                entry_hash_b.as_slice(),
                envelope_a,
                envelope_b,
                now
            ],
        )?;
        Ok(())
    }

    /// The persisted fork evidence for `(author, position)`, if any.
    pub fn fork_at(&self, author: &[u8; 32], position: u64) -> Result<Option<ForkRow>> {
        self.db
            .conn()
            .query_row(
                "SELECT entry_hash_a, entry_hash_b, envelope_a, envelope_b, detected_at \
                 FROM outbox_forks WHERE author = ?1 AND position = ?2",
                rusqlite::params![author.as_slice(), position as i64],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .map(|(a, b, ea, eb, detected_at)| {
                Ok(ForkRow {
                    author: *author,
                    position,
                    entry_hash_a: to_hash("outbox_forks.entry_hash_a", a)?,
                    entry_hash_b: to_hash("outbox_forks.entry_hash_b", b)?,
                    envelope_a: ea,
                    envelope_b: eb,
                    detected_at,
                })
            })
            .transpose()
    }

    /// The stored receipt-envelope bytes for a bundle's presentation hash, if the
    /// station has already answered that presentation.
    pub fn receipt_for(&self, presentation_hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .conn()
            .query_row(
                "SELECT receipt_envelope FROM issued_receipts WHERE presentation_hash = ?1",
                [presentation_hash.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?)
    }

    /// Persists an issued receipt under its presentation hash. Idempotent: if a
    /// receipt already exists for this presentation it is kept unchanged (the
    /// caller should have returned it via [`receipt_for`](Self::receipt_for)
    /// first).
    pub fn put_receipt(
        &mut self,
        presentation_hash: &[u8; 32],
        receipt_envelope: &[u8],
        now: i64,
    ) -> Result<()> {
        self.db.conn().execute(
            "INSERT OR IGNORE INTO issued_receipts \
             (presentation_hash, receipt_envelope, issued_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![presentation_hash.as_slice(), receipt_envelope, now],
        )?;
        Ok(())
    }

    // --- receipt delivery tracking (ADR-0020 §3; T2.2.4) -------------------
    //
    // The outbound counterpart of the ingest state above: once a receipt is
    // issued (`put_receipt`), one row per reported record is queued here so the
    // receipt can travel back to each record's author by the same dumb carriers.

    /// Queues a delivery row for `record_hash` (authored by `author`), pointing at
    /// the `issued_receipts` row keyed by `presentation_hash`. Idempotent on
    /// `record_hash`: a record re-carried in a *later* bundle (a fresh
    /// presentation) keeps its first delivery row — including any `fetched_count`
    /// and `confirmed_delivered` already accrued — so re-ingest never resets a
    /// record's delivery progress. The referenced `issued_receipts` row must exist
    /// (the caller persists the receipt first; ADR-0020 §3).
    pub fn record_receipt_delivery(
        &mut self,
        record_hash: &[u8; 32],
        author: &[u8; 32],
        presentation_hash: &[u8; 32],
        now: i64,
    ) -> Result<()> {
        self.db.conn().execute(
            "INSERT INTO receipt_deliveries \
             (record_hash, author, receipt_presentation, first_issued_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(record_hash) DO NOTHING",
            rusqlite::params![
                record_hash.as_slice(),
                author.as_slice(),
                presentation_hash.as_slice(),
                now
            ],
        )?;
        Ok(())
    }

    /// The pending (not-yet-confirmed) receipts covering records authored by any
    /// of `authors`, deduplicated by receipt, oldest first, capped at `limit`.
    ///
    /// An empty `authors` slice means *all* authors — the bulk-courier fetch. A
    /// `since` bound (exclusive, on `first_issued_at`) lets a caller page past
    /// receipts it has already carried. Because a single receipt covers a whole
    /// bundle — possibly records from several authors — the returned
    /// [`PendingReceipts::record_hashes`] are exactly the delivery rows this
    /// fetch acted on (matching the author filter and belonging to a returned
    /// receipt); the caller passes them to [`bump_fetched`](Self::bump_fetched)
    /// (courier) or [`mark_confirmed`](Self::mark_confirmed) (the author's own
    /// device). Rows truncated out by `limit` are not among them, so they are
    /// neither counted nor confirmed until a later fetch returns them.
    pub fn pending_receipts_for(
        &self,
        authors: &[[u8; 32]],
        since: Option<i64>,
        limit: usize,
    ) -> Result<PendingReceipts> {
        // Pull the candidate rows in a stable oldest-first order, then group into
        // distinct receipts in Rust — the author filter and the per-receipt cap
        // are simpler to express there than in dynamic SQL, and at pilot scale the
        // pending queue is small (it is swept on the retention timer).
        let conn = self.db.conn();
        let mut stmt = conn.prepare(
            "SELECT record_hash, author, receipt_presentation, first_issued_at \
             FROM receipt_deliveries \
             WHERE confirmed_delivered = 0 AND first_issued_at > ?1 \
             ORDER BY first_issued_at ASC, record_hash ASC",
        )?;
        let rows = stmt.query_map([since.unwrap_or(i64::MIN)], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;

        let wants = |author: &[u8; 32]| authors.is_empty() || authors.contains(author);

        // Distinct receipts in first-seen (oldest) order, and the delivery rows
        // (matching the author filter) that fall under each.
        let mut order: Vec<[u8; 32]> = Vec::new();
        let mut grouped: std::collections::HashMap<[u8; 32], Vec<[u8; 32]>> =
            std::collections::HashMap::new();
        for row in rows {
            let (record_hash, author, presentation) = row?;
            let author = to_hash("receipt_deliveries.author", author)?;
            if !wants(&author) {
                continue;
            }
            let record_hash = to_hash("receipt_deliveries.record_hash", record_hash)?;
            let presentation = to_hash("receipt_deliveries.receipt_presentation", presentation)?;
            if !grouped.contains_key(&presentation) {
                order.push(presentation);
            }
            grouped.entry(presentation).or_default().push(record_hash);
        }

        let truncated = order.len() > limit;
        let mut receipts = Vec::new();
        let mut record_hashes = Vec::new();
        for presentation in order.into_iter().take(limit) {
            let envelope = self.receipt_for(&presentation)?.ok_or_else(|| {
                // A queued delivery row must reference a stored receipt (FK), so a
                // missing envelope is corruption, not an empty result.
                Error::Corrupt(format!(
                    "receipt_deliveries references a missing issued_receipts row {}",
                    hex_short(&presentation)
                ))
            })?;
            receipts.push(envelope);
            if let Some(mut hashes) = grouped.remove(&presentation) {
                record_hashes.append(&mut hashes);
            }
        }
        Ok(PendingReceipts {
            receipts,
            record_hashes,
            truncated,
        })
    }

    /// Bumps `fetched_count` on each named delivery row (a courier picked up a
    /// receipt). Never confirms — a courier is not the author (ADR-0020 §3).
    pub fn bump_fetched(&mut self, record_hashes: &[[u8; 32]], _now: i64) -> Result<()> {
        let conn = self.db.conn();
        let mut stmt = conn.prepare(
            "UPDATE receipt_deliveries SET fetched_count = fetched_count + 1 \
             WHERE record_hash = ?1",
        )?;
        for h in record_hashes {
            stmt.execute([h.as_slice()])?;
        }
        Ok(())
    }

    /// Marks each named delivery row confirmed-delivered (the record's own author
    /// fetched its receipt). Also bumps `fetched_count`, since a confirm is a
    /// fetch. Returns how many rows were newly confirmed. Idempotent: a row
    /// already confirmed is left as-is and not recounted.
    pub fn mark_confirmed(&mut self, record_hashes: &[[u8; 32]], _now: i64) -> Result<usize> {
        let conn = self.db.conn();
        let mut stmt = conn.prepare(
            "UPDATE receipt_deliveries \
             SET confirmed_delivered = 1, fetched_count = fetched_count + 1 \
             WHERE record_hash = ?1 AND confirmed_delivered = 0",
        )?;
        let mut changed = 0;
        for h in record_hashes {
            changed += stmt.execute([h.as_slice()])?;
        }
        Ok(changed)
    }

    /// Prunes delivered-receipt rows the station no longer needs to keep: a
    /// confirmed row older than `retention_secs`, or an *unconfirmed* row older
    /// than `retention_secs` × [`RETENTION_UNCONFIRMED_MULTIPLIER`] (a courier may
    /// take weeks to carry a receipt home, so unconfirmed rows are kept far
    /// longer). Returns the number of rows removed. The `issued_receipts` rows the
    /// deliveries pointed at are left intact — they remain the idempotency cache
    /// for a byte-identical re-ingest (ADR-0020 §3).
    pub fn prune_delivered(&mut self, now: i64, retention_secs: i64) -> Result<usize> {
        let confirmed_cutoff = now.saturating_sub(retention_secs);
        let unconfirmed_cutoff =
            now.saturating_sub(retention_secs.saturating_mul(RETENTION_UNCONFIRMED_MULTIPLIER));
        let removed = self.db.conn().execute(
            "DELETE FROM receipt_deliveries WHERE \
             (confirmed_delivered = 1 AND first_issued_at < ?1) OR \
             (confirmed_delivered = 0 AND first_issued_at < ?2)",
            rusqlite::params![confirmed_cutoff, unconfirmed_cutoff],
        )?;
        Ok(removed)
    }

    /// The queued [`DeliveryRow`] for `record_hash`, if any. Test/introspection
    /// helper.
    pub fn delivery_of(&self, record_hash: &[u8; 32]) -> Result<Option<DeliveryRow>> {
        self.db
            .conn()
            .query_row(
                "SELECT author, receipt_presentation, fetched_count, confirmed_delivered \
                 FROM receipt_deliveries WHERE record_hash = ?1",
                [record_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .map(|(author, presentation, fetched, confirmed)| {
                Ok(DeliveryRow {
                    author: to_hash("receipt_deliveries.author", author)?,
                    receipt_presentation: to_hash(
                        "receipt_deliveries.receipt_presentation",
                        presentation,
                    )?,
                    fetched_count: fetched,
                    confirmed_delivered: confirmed != 0,
                })
            })
            .transpose()
    }

    /// The `(entry_hash, envelope)` recorded at `(author, position)`, if seen.
    fn entry_at(&self, author: &[u8; 32], position: u64) -> Result<Option<([u8; 32], Vec<u8>)>> {
        self.db
            .conn()
            .query_row(
                "SELECT entry_hash, envelope FROM seen_outbox_entries \
                 WHERE author = ?1 AND position = ?2",
                rusqlite::params![author.as_slice(), position as i64],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(hash, envelope)| {
                Ok((to_hash("seen_outbox_entries.entry_hash", hash)?, envelope))
            })
            .transpose()
    }

    /// Re-derives the author's contiguous head from `seen_outbox_entries` and
    /// writes it to `seen_outbox_heads`. Walks upward from the position after the
    /// current head (or 0) while consecutive positions are present, so filling a
    /// gap advances the head across every position already seen beyond it.
    fn advance_head(&mut self, author: &[u8; 32], now: i64) -> Result<()> {
        let mut next = match self.head(author)? {
            Some(head) => head.position + 1,
            None => 0,
        };
        let mut furthest: Option<(u64, [u8; 32])> = None;
        while let Some((hash, _)) = self.entry_at(author, next)? {
            furthest = Some((next, hash));
            next = match next.checked_add(1) {
                Some(n) => n,
                None => break,
            };
        }
        if let Some((position, entry_hash)) = furthest {
            self.db.conn().execute(
                "INSERT INTO seen_outbox_heads (author, position, entry_hash, updated_at) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(author) DO UPDATE SET \
                 position = excluded.position, entry_hash = excluded.entry_hash, \
                 updated_at = excluded.updated_at",
                rusqlite::params![
                    author.as_slice(),
                    position as i64,
                    entry_hash.as_slice(),
                    now
                ],
            )?;
        }
        Ok(())
    }
}

/// Converts a stored BLOB into a 32-byte hash, or [`Error::Corrupt`].
fn to_hash(col: &str, bytes: Vec<u8>) -> Result<[u8; 32]> {
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| Error::Corrupt(format!("{col} is {len} bytes, expected 32")))
}

/// A short hex prefix of a hash, for diagnostic messages only.
fn hex_short(hash: &[u8; 32]) -> String {
    hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations;

    fn store_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn h(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn fresh_then_duplicate_then_fork() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        let author = h(1);

        assert_eq!(
            s.note_entry(&author, 0, &h(10), b"env0", 100).unwrap(),
            NoteOutcome::Fresh
        );
        // The same entry again: a benign duplicate.
        assert_eq!(
            s.note_entry(&author, 0, &h(10), b"env0", 101).unwrap(),
            NoteOutcome::Duplicate
        );
        // A different entry at the same position: a fork carrying the stored side.
        assert_eq!(
            s.note_entry(&author, 0, &h(20), b"env0b", 102).unwrap(),
            NoteOutcome::Fork {
                stored_entry_hash: h(10),
                stored_envelope: b"env0".to_vec(),
            }
        );
    }

    #[test]
    fn head_advances_contiguously_and_jumps_when_a_gap_fills() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        let author = h(2);

        // No head before anything is seen.
        assert_eq!(s.head(&author).unwrap(), None);

        // Position 0 seen → head 0.
        s.note_entry(&author, 0, &h(0), b"e0", 1).unwrap();
        assert_eq!(
            s.head(&author).unwrap(),
            Some(SeenHead {
                position: 0,
                entry_hash: h(0)
            })
        );

        // Position 2 seen (gap at 1) → head stays 0.
        s.note_entry(&author, 2, &h(2), b"e2", 2).unwrap();
        assert_eq!(s.head(&author).unwrap().unwrap().position, 0);

        // Position 1 fills the gap → head jumps to 2.
        s.note_entry(&author, 1, &h(1), b"e1", 3).unwrap();
        assert_eq!(
            s.head(&author).unwrap(),
            Some(SeenHead {
                position: 2,
                entry_hash: h(2)
            })
        );
    }

    #[test]
    fn head_does_not_advance_from_a_leading_gap() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        let author = h(3);
        // First seen position is 5 (no 0): the chain has no contiguous head yet.
        s.note_entry(&author, 5, &h(5), b"e5", 1).unwrap();
        assert_eq!(s.head(&author).unwrap(), None);
    }

    #[test]
    fn fork_evidence_persists_and_is_idempotent() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        let author = h(4);
        s.record_fork(&author, 7, &h(70), b"A", &h(71), b"B", 500)
            .unwrap();
        // A second detection does not overwrite the first.
        s.record_fork(&author, 7, &h(70), b"A", &h(99), b"B2", 600)
            .unwrap();
        let row = s.fork_at(&author, 7).unwrap().unwrap();
        assert_eq!(
            row,
            ForkRow {
                author,
                position: 7,
                entry_hash_a: h(70),
                entry_hash_b: h(71),
                envelope_a: b"A".to_vec(),
                envelope_b: b"B".to_vec(),
                detected_at: 500,
            }
        );
        assert_eq!(s.fork_at(&author, 8).unwrap(), None);
    }

    #[test]
    fn issued_receipts_are_idempotent() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        let ph = h(9);
        assert_eq!(s.receipt_for(&ph).unwrap(), None);
        s.put_receipt(&ph, b"receipt-bytes", 10).unwrap();
        assert_eq!(s.receipt_for(&ph).unwrap(), Some(b"receipt-bytes".to_vec()));
        // A second put for the same presentation keeps the first verbatim.
        s.put_receipt(&ph, b"different", 11).unwrap();
        assert_eq!(s.receipt_for(&ph).unwrap(), Some(b"receipt-bytes".to_vec()));
    }

    // --- receipt delivery tracking (T2.2.4) --------------------------------

    /// Persists a receipt and queues a delivery row for `record_hash` by `author`
    /// against it, in one step (the receipt must exist first for the FK).
    fn queue(
        s: &mut DtnStore,
        presentation: [u8; 32],
        record_hash: [u8; 32],
        author: [u8; 32],
        at: i64,
    ) {
        s.put_receipt(&presentation, &[b"rcpt-", &presentation[..1]].concat(), at)
            .unwrap();
        s.record_receipt_delivery(&record_hash, &author, &presentation, at)
            .unwrap();
    }

    #[test]
    fn delivery_is_queued_and_idempotent_on_record_hash() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        queue(&mut s, h(1), h(10), h(100), 500);
        let row = s.delivery_of(&h(10)).unwrap().unwrap();
        assert_eq!(row.author, h(100));
        assert_eq!(row.receipt_presentation, h(1));
        assert_eq!(row.fetched_count, 0);
        assert!(!row.confirmed_delivered);

        // Re-carrying the same record in a *later* presentation keeps the first
        // delivery row (and any progress on it) — no reset, no second row.
        s.bump_fetched(&[h(10)], 501).unwrap();
        s.put_receipt(&h(2), b"rcpt-2", 600).unwrap();
        s.record_receipt_delivery(&h(10), &h(100), &h(2), 600)
            .unwrap();
        let row = s.delivery_of(&h(10)).unwrap().unwrap();
        assert_eq!(row.receipt_presentation, h(1), "first receipt kept");
        assert_eq!(
            row.fetched_count, 1,
            "fetched_count preserved across re-ingest"
        );
    }

    #[test]
    fn pending_for_author_filters_and_confirm_excludes() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        // Receipt 1 covers records by authors A and B; receipt 2 by C only.
        queue(&mut s, h(1), h(10), h(0xA), 100);
        s.record_receipt_delivery(&h(11), &h(0xB), &h(1), 100)
            .unwrap();
        queue(&mut s, h(2), h(20), h(0xC), 200);

        // A bulk (empty authors) fetch sees both receipts, oldest first.
        let all = s.pending_receipts_for(&[], None, 256).unwrap();
        assert_eq!(all.receipts.len(), 2);
        assert!(!all.truncated);

        // A fetch scoped to author A returns only receipt 1, and only A's row.
        let a = s.pending_receipts_for(&[h(0xA)], None, 256).unwrap();
        assert_eq!(a.receipts.len(), 1);
        assert_eq!(a.record_hashes, vec![h(10)]);

        // An author with no pending receipts gets nothing.
        let none = s.pending_receipts_for(&[h(0xF)], None, 256).unwrap();
        assert!(none.receipts.is_empty());
        assert!(none.record_hashes.is_empty());

        // Confirming A's record leaves B's still pending on the same receipt.
        assert_eq!(s.mark_confirmed(&[h(10)], 300).unwrap(), 1);
        let a_again = s.pending_receipts_for(&[h(0xA)], None, 256).unwrap();
        assert!(a_again.receipts.is_empty(), "A's row now confirmed");
        let b = s.pending_receipts_for(&[h(0xB)], None, 256).unwrap();
        assert_eq!(b.record_hashes, vec![h(11)], "B still pending on receipt 1");
    }

    #[test]
    fn pending_caps_and_reports_truncation_by_receipt() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        // Three distinct receipts, one record each, ascending issue time.
        queue(&mut s, h(1), h(11), h(0xA), 100);
        queue(&mut s, h(2), h(22), h(0xA), 200);
        queue(&mut s, h(3), h(33), h(0xA), 300);

        let page = s.pending_receipts_for(&[], None, 2).unwrap();
        assert_eq!(page.receipts.len(), 2, "capped at the limit");
        assert!(page.truncated, "a third receipt was held back");
        // Oldest first: the two returned rows are the earliest presentations, and
        // the truncated one is not among the acted-on record hashes.
        assert_eq!(page.record_hashes, vec![h(11), h(22)]);

        // `since` pages past the receipts already carried.
        let rest = s.pending_receipts_for(&[], Some(200), 256).unwrap();
        assert_eq!(rest.record_hashes, vec![h(33)]);
        assert!(!rest.truncated);
    }

    #[test]
    fn bump_fetched_counts_without_confirming() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        queue(&mut s, h(1), h(10), h(0xA), 100);
        s.bump_fetched(&[h(10)], 150).unwrap();
        s.bump_fetched(&[h(10)], 160).unwrap();
        let row = s.delivery_of(&h(10)).unwrap().unwrap();
        assert_eq!(row.fetched_count, 2);
        assert!(!row.confirmed_delivered, "a courier fetch never confirms");
        // Still pending after courier fetches.
        assert_eq!(
            s.pending_receipts_for(&[h(0xA)], None, 256)
                .unwrap()
                .receipts
                .len(),
            1
        );
    }

    #[test]
    fn prune_keeps_unconfirmed_far_longer_than_confirmed() {
        let db = store_db();
        let mut s = DtnStore::new(&db);
        let retention = 100;
        // A confirmed row and an unconfirmed row, both issued at t=0.
        queue(&mut s, h(1), h(10), h(0xA), 0);
        queue(&mut s, h(2), h(20), h(0xB), 0);
        s.mark_confirmed(&[h(10)], 0).unwrap();

        // Just past the confirmed retention but well within unconfirmed×4: the
        // confirmed row is pruned, the unconfirmed one kept.
        assert_eq!(s.prune_delivered(retention + 1, retention).unwrap(), 1);
        assert!(s.delivery_of(&h(10)).unwrap().is_none(), "confirmed pruned");
        assert!(s.delivery_of(&h(20)).unwrap().is_some(), "unconfirmed kept");

        // Past retention×4 the unconfirmed row is finally pruned too.
        let past = retention * RETENTION_UNCONFIRMED_MULTIPLIER + 1;
        assert_eq!(s.prune_delivered(past, retention).unwrap(), 1);
        assert!(
            s.delivery_of(&h(20)).unwrap().is_none(),
            "unconfirmed pruned"
        );
    }
}
