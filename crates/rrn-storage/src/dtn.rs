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
}
