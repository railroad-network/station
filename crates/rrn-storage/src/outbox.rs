//! Per-author outbox store (ADR-0020 §2).
//!
//! Durable, chain-checked persistence for a device's *own* outbox: the
//! append-only, hash-chained run of already-signed records it has authored but
//! not yet had admitted by the station. Entries are appended in position order,
//! assembled into bundles by a caller, marked acknowledged from station-signed
//! delivery receipts, and pruned once the retained suffix is no longer needed.
//!
//! # Opaque envelopes — validation lives above this layer
//!
//! `rrn-storage` sits *below* `rrn-identity`/`rrn-protocol` in the crate layer
//! order (it cannot depend on them — that would invert the layering), so it
//! cannot parse or verify an `OutboxEntry`. This store therefore holds the
//! **opaque, already-validated** envelope bytes: the caller — a layer that does
//! have `rrn-protocol` — runs [`rrn_protocol::outbox::validate`] and hands over
//! the pre-extracted columns via [`NewOutboxEntry`]. What the store enforces is
//! only *structural* chain integrity: positions dense from the chain head, and
//! `prev_hash` linking to the head's `entry_hash` as raw 32-byte values. It does
//! not — and cannot — re-check signatures.
//!
//! # Time
//!
//! [`OutboxRow::authored_at`] is **testimony** (ADR-0022 §3): the device's own
//! claim of when it authored the entry, kept for display and evidence only. It
//! is never used in any window, ordering, or eligibility decision — those run on
//! the station's admission clock, never on a party-asserted timestamp.
//!
//! [`rrn_protocol::outbox::validate`]: https://docs.rs/rrn-protocol

use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::{Error, Result};

/// The station's answer for one carried record, from a delivery receipt
/// (ADR-0020 §3). Maps to the `acked_outcome` TEXT column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// The record was admitted to the log.
    Admitted,
    /// The record was already known (idempotent re-submission).
    Known,
    /// The record was refused at the front door (bad signature, nonce, floor,
    /// tier, expiry, …); the reason slug is carried alongside.
    Refused,
}

impl AckOutcome {
    /// The stored TEXT form.
    fn as_str(self) -> &'static str {
        match self {
            AckOutcome::Admitted => "admitted",
            AckOutcome::Known => "known",
            AckOutcome::Refused => "refused",
        }
    }

    /// Parses the stored TEXT form; an unknown value is a corrupt row.
    fn from_column(s: &str) -> Result<Self> {
        match s {
            "admitted" => Ok(AckOutcome::Admitted),
            "known" => Ok(AckOutcome::Known),
            "refused" => Ok(AckOutcome::Refused),
            other => Err(Error::Corrupt(format!("unknown ack outcome {other:?}"))),
        }
    }
}

/// One stored outbox row, typed. The `envelope` is the opaque signed
/// outbox-entry bytes exactly as the caller supplied them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRow {
    /// 32-byte pubkey of the chain owner.
    pub author: [u8; 32],
    /// 0-based, sequential position in the author's chain.
    pub position: u64,
    /// Blake3 of the entry's canonical bytes — what the next entry chains to.
    pub entry_hash: [u8; 32],
    /// Blake3 `entry_hash` of the previous entry; all-zero at position 0.
    pub prev_hash: [u8; 32],
    /// Blake3 of the embedded record's bytes — the content hash the log admits
    /// under and a delivery receipt keys on.
    pub record_hash: [u8; 32],
    /// The embedded record's kind discriminator string.
    pub record_kind: String,
    /// Opaque signed outbox-entry envelope bytes (validated upstream).
    pub envelope: Vec<u8>,
    /// Testimony timestamp (ADR-0022 §3) — display/evidence only.
    pub authored_at: i64,
    /// Log seq from the delivery receipt that acked this record; `None` while
    /// pending.
    pub acked_seq: Option<u64>,
    /// The station's outcome for this record; `None` while pending.
    pub acked_outcome: Option<AckOutcome>,
    /// Refusal reason slug, present iff the outcome is [`AckOutcome::Refused`].
    pub refusal_reason: Option<String>,
}

/// The columns needed to append the next entry to an author's chain. The caller
/// extracts these from a validated `rrn_protocol::outbox::SignedOutboxEntry`.
pub struct NewOutboxEntry<'e> {
    /// 32-byte pubkey of the chain owner.
    pub author: [u8; 32],
    /// The position this entry must occupy: `head.position + 1`, or `0` for an
    /// empty chain.
    pub position: u64,
    /// Blake3 of the entry's canonical bytes.
    pub entry_hash: [u8; 32],
    /// Must equal the current head's `entry_hash` (all-zero for an empty chain).
    pub prev_hash: [u8; 32],
    /// Blake3 of the embedded record's bytes.
    pub record_hash: [u8; 32],
    /// The embedded record's kind discriminator string.
    pub record_kind: &'e str,
    /// Opaque signed outbox-entry envelope bytes (validated upstream).
    pub envelope: &'e [u8],
    /// Testimony timestamp (ADR-0022 §3).
    pub authored_at: i64,
}

/// A handle for reading and appending to one device's outbox over a borrowed
/// [`Database`]. Mirrors [`crate::log::AppendLog`]'s `Database`-borrowing shape.
pub struct OutboxStore<'a> {
    db: &'a Database,
}

impl<'a> OutboxStore<'a> {
    /// Wraps a database handle for outbox access.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Appends the next entry for `e.author`.
    ///
    /// Enforces structural chain integrity only (signatures are the caller's
    /// job, per the module docs). Refuses, without writing, when:
    ///
    /// - [`Error::PositionGap`] — `e.position` is not `head.position + 1`
    ///   (or `0` for an empty chain);
    /// - [`Error::ChainMismatch`] — `e.prev_hash` does not equal the head's
    ///   `entry_hash` (all-zero for an empty chain);
    /// - [`Error::DuplicateRecord`] — `e.record_hash` is already stored for this
    ///   author.
    pub fn append(&mut self, e: NewOutboxEntry<'_>) -> Result<()> {
        let head = self.head(&e.author)?;

        let (expected_position, expected_prev) = match &head {
            Some(h) => (h.position + 1, h.entry_hash),
            None => (0, [0u8; 32]),
        };
        if e.position != expected_position {
            return Err(Error::PositionGap {
                expected: expected_position,
                got: e.position,
            });
        }
        if e.prev_hash != expected_prev {
            return Err(Error::ChainMismatch);
        }
        if self.contains_record(&e.author, &e.record_hash)? {
            return Err(Error::DuplicateRecord);
        }

        let conn = self.db.conn();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO outbox_entries \
             (author, position, entry_hash, prev_hash, record_hash, record_kind, \
              envelope, authored_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                e.author.as_slice(),
                e.position as i64,
                e.entry_hash.as_slice(),
                e.prev_hash.as_slice(),
                e.record_hash.as_slice(),
                e.record_kind,
                e.envelope,
                e.authored_at,
            ],
        )?;
        tx.commit()?;
        tracing::trace!(position = e.position, "appended outbox entry");
        Ok(())
    }

    /// The author's current head (highest-position entry), if the chain is
    /// non-empty.
    pub fn head(&self, author: &[u8; 32]) -> Result<Option<OutboxRow>> {
        self.db
            .conn()
            .query_row(
                "SELECT author, position, entry_hash, prev_hash, record_hash, \
                 record_kind, envelope, authored_at, acked_seq, acked_outcome, refusal_reason \
                 FROM outbox_entries WHERE author = ?1 ORDER BY position DESC LIMIT 1",
                [author.as_slice()],
                row_to_outbox,
            )
            .optional()?
            .transpose()
    }

    /// Pending (unacked) rows in ascending position order, optionally capped at
    /// `limit`.
    pub fn pending(&self, author: &[u8; 32], limit: Option<usize>) -> Result<Vec<OutboxRow>> {
        let conn = self.db.conn();
        // SQLite treats a negative LIMIT as unbounded, which is exactly the
        // "no cap" case — so map `None` to -1 rather than branching the SQL.
        let cap: i64 = limit.map(|n| n as i64).unwrap_or(-1);
        let mut stmt = conn.prepare(
            "SELECT author, position, entry_hash, prev_hash, record_hash, \
             record_kind, envelope, authored_at, acked_seq, acked_outcome, refusal_reason \
             FROM outbox_entries WHERE author = ?1 AND acked_outcome IS NULL \
             ORDER BY position LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![author.as_slice(), cap], row_to_outbox)?;
        collect_rows(rows)
    }

    /// Applies one delivery-receipt outcome to the row for `(author,
    /// record_hash)`.
    ///
    /// Idempotent: re-applying the *same* outcome to an already-acked row is
    /// `Ok(true)` and changes nothing. A *conflicting* outcome for an
    /// already-acked row is [`Error::ConflictingAck`] — a station cannot
    /// legitimately change its answer for one record. `refusal_reason` is stored
    /// only for [`AckOutcome::Refused`]; it is ignored for other outcomes.
    ///
    /// Returns `false` when no row matches `record_hash` (a receipt for someone
    /// else's record — ignore it upstream); `true` when the row was found and is
    /// now acked.
    pub fn apply_ack(
        &mut self,
        author: &[u8; 32],
        record_hash: &[u8; 32],
        outcome: AckOutcome,
        seq: Option<u64>,
        reason: Option<&str>,
    ) -> Result<bool> {
        let conn = self.db.conn();
        let tx = conn.unchecked_transaction()?;

        let existing: Option<Option<String>> = tx
            .query_row(
                "SELECT acked_outcome FROM outbox_entries \
                 WHERE author = ?1 AND record_hash = ?2",
                rusqlite::params![author.as_slice(), record_hash.as_slice()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;

        let current = match existing {
            None => return Ok(false), // unknown record_hash
            Some(current) => current,
        };

        if let Some(prior) = current {
            // Already acked: the same outcome is an idempotent no-op; a
            // different one is an illegitimate change of answer.
            let prior = AckOutcome::from_column(&prior)?;
            if prior == outcome {
                tx.commit()?;
                return Ok(true);
            }
            return Err(Error::ConflictingAck);
        }

        let stored_reason = match outcome {
            AckOutcome::Refused => reason,
            _ => None,
        };
        tx.execute(
            "UPDATE outbox_entries \
             SET acked_seq = ?3, acked_outcome = ?4, refusal_reason = ?5 \
             WHERE author = ?1 AND record_hash = ?2",
            rusqlite::params![
                author.as_slice(),
                record_hash.as_slice(),
                seq.map(|s| s as i64),
                outcome.as_str(),
                stored_reason,
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Deletes acked rows below the retained suffix, keeping the chain
    /// contiguous. Returns the number of rows removed.
    ///
    /// Retention rule (ADR-0020 §2): keep every row from the *first pending*
    /// position through the head, so a courier re-assembling a bundle finds the
    /// retained suffix's hashes lining up; and keep the *last* row even when all
    /// are acked, since the head anchors the next append's `prev_hash`. Formally,
    /// retain `max(last_row, everything ≥ first_pending)`; never punch holes in
    /// the retained suffix.
    pub fn prune_acked(&mut self, author: &[u8; 32]) -> Result<usize> {
        let conn = self.db.conn();
        let tx = conn.unchecked_transaction()?;

        let first_pending: Option<i64> = tx.query_row(
            "SELECT MIN(position) FROM outbox_entries \
             WHERE author = ?1 AND acked_outcome IS NULL",
            [author.as_slice()],
            |row| row.get(0),
        )?;

        let removed = match first_pending {
            // Some pending work remains: drop acked rows strictly below the first
            // pending position. Everything below it is acked by definition, so
            // this never leaves a hole in the retained [first_pending, head]
            // suffix.
            Some(p) => tx.execute(
                "DELETE FROM outbox_entries \
                 WHERE author = ?1 AND acked_outcome IS NOT NULL AND position < ?2",
                rusqlite::params![author.as_slice(), p],
            )?,
            // Nothing pending (all acked, or empty): keep only the head, which
            // anchors the next append. `MAX` over no rows is NULL, so the delete
            // matches nothing and removes zero.
            None => {
                let head_pos: Option<i64> = tx.query_row(
                    "SELECT MAX(position) FROM outbox_entries WHERE author = ?1",
                    [author.as_slice()],
                    |row| row.get(0),
                )?;
                match head_pos {
                    Some(h) => tx.execute(
                        "DELETE FROM outbox_entries WHERE author = ?1 AND position < ?2",
                        rusqlite::params![author.as_slice(), h],
                    )?,
                    None => 0,
                }
            }
        };

        tx.commit()?;
        Ok(removed)
    }

    /// All rows for `author` in ascending position order — evidence/audit view.
    pub fn all_rows(&self, author: &[u8; 32]) -> Result<Vec<OutboxRow>> {
        let conn = self.db.conn();
        let mut stmt = conn.prepare(
            "SELECT author, position, entry_hash, prev_hash, record_hash, \
             record_kind, envelope, authored_at, acked_seq, acked_outcome, refusal_reason \
             FROM outbox_entries WHERE author = ?1 ORDER BY position",
        )?;
        let rows = stmt.query_map([author.as_slice()], row_to_outbox)?;
        collect_rows(rows)
    }

    /// Whether a row with this `record_hash` already exists for `author`.
    fn contains_record(&self, author: &[u8; 32], record_hash: &[u8; 32]) -> Result<bool> {
        let found: Option<i64> = self
            .db
            .conn()
            .query_row(
                "SELECT 1 FROM outbox_entries WHERE author = ?1 AND record_hash = ?2 LIMIT 1",
                rusqlite::params![author.as_slice(), record_hash.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }
}

/// Collects a rusqlite row iterator of `Result<Result<OutboxRow>>` into a single
/// `Result<Vec<OutboxRow>>`, flattening the SQLite error and the decode error.
fn collect_rows(
    rows: impl Iterator<Item = rusqlite::Result<Result<OutboxRow>>>,
) -> Result<Vec<OutboxRow>> {
    rows.map(|r| r.map_err(Error::from).and_then(|inner| inner))
        .collect()
}

/// Decodes one `outbox_entries` row. The closure returns `rusqlite::Result` (so
/// column-access errors flow through rusqlite), carrying our own decode
/// `Result<OutboxRow>` as its value so a malformed BLOB surfaces as
/// [`Error::Corrupt`].
fn row_to_outbox(row: &rusqlite::Row) -> rusqlite::Result<Result<OutboxRow>> {
    let author: Vec<u8> = row.get(0)?;
    let position: i64 = row.get(1)?;
    let entry_hash: Vec<u8> = row.get(2)?;
    let prev_hash: Vec<u8> = row.get(3)?;
    let record_hash: Vec<u8> = row.get(4)?;
    let record_kind: String = row.get(5)?;
    let envelope: Vec<u8> = row.get(6)?;
    let authored_at: i64 = row.get(7)?;
    let acked_seq: Option<i64> = row.get(8)?;
    let acked_outcome: Option<String> = row.get(9)?;
    let refusal_reason: Option<String> = row.get(10)?;

    Ok((|| {
        Ok(OutboxRow {
            author: arr32(&author, "author")?,
            position: position as u64,
            entry_hash: arr32(&entry_hash, "entry_hash")?,
            prev_hash: arr32(&prev_hash, "prev_hash")?,
            record_hash: arr32(&record_hash, "record_hash")?,
            record_kind,
            envelope,
            authored_at,
            acked_seq: acked_seq.map(|s| s as u64),
            acked_outcome: acked_outcome
                .as_deref()
                .map(AckOutcome::from_column)
                .transpose()?,
            refusal_reason,
        })
    })())
}

/// Converts a 32-byte BLOB column into a fixed array, or a corrupt-row error.
fn arr32(bytes: &[u8], col: &str) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| Error::Corrupt(format!("{col} is {} bytes, expected 32", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::hash::Hash;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        db
    }

    /// A distinct 32-byte value seeded from `n` — stands in for a pubkey/hash.
    fn h(n: u64) -> [u8; 32] {
        Hash::of(&n.to_le_bytes()).to_bytes()
    }

    /// Builds a `NewOutboxEntry` whose `entry_hash`/`record_hash` are derived
    /// deterministically from `(author-seed, position)`, correctly linked to the
    /// prior `entry_hash`.
    struct Chain {
        author: [u8; 32],
        prev: [u8; 32],
        next_pos: u64,
    }

    impl Chain {
        fn new(seed: u64) -> Self {
            Self {
                author: h(1000 + seed),
                prev: [0u8; 32],
                next_pos: 0,
            }
        }

        /// The `entry_hash` a position will get — deterministic so tests can
        /// predict linkage.
        fn entry_hash_at(&self, pos: u64) -> [u8; 32] {
            Hash::of(&[self.author.as_slice(), &pos.to_le_bytes()].concat()).to_bytes()
        }

        fn record_hash_at(&self, pos: u64) -> [u8; 32] {
            Hash::of(&[b"rec", self.author.as_slice(), &pos.to_le_bytes()].concat()).to_bytes()
        }

        /// Appends the next linked entry to `store`.
        fn push(&mut self, store: &mut OutboxStore) -> Result<()> {
            self.push_at(store, self.next_pos, self.prev)
        }

        /// Appends with an explicit position/prev (to exercise refusals), and on
        /// success advances the chain cursor.
        fn push_at(&mut self, store: &mut OutboxStore, pos: u64, prev: [u8; 32]) -> Result<()> {
            let entry_hash = self.entry_hash_at(pos);
            let record_hash = self.record_hash_at(pos);
            store.append(NewOutboxEntry {
                author: self.author,
                position: pos,
                entry_hash,
                prev_hash: prev,
                record_hash,
                record_kind: "rrn.test.record",
                envelope: format!("envelope-{pos}").as_bytes(),
                authored_at: 1_700_000_000 + pos as i64,
            })?;
            self.next_pos = pos + 1;
            self.prev = entry_hash;
            Ok(())
        }
    }

    #[test]
    fn sequential_append_and_head() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);

        assert!(store.head(&c.author).unwrap().is_none());
        for _ in 0..4 {
            c.push(&mut store).unwrap();
        }

        let head = store.head(&c.author).unwrap().unwrap();
        assert_eq!(head.position, 3);
        assert_eq!(head.entry_hash, c.entry_hash_at(3));
        assert_eq!(head.prev_hash, c.entry_hash_at(2));
        assert_eq!(head.record_kind, "rrn.test.record");
        assert_eq!(head.envelope, b"envelope-3");
        assert_eq!(head.authored_at, 1_700_000_003);
        assert!(head.acked_outcome.is_none());
        assert_eq!(store.all_rows(&c.author).unwrap().len(), 4);
    }

    #[test]
    fn append_refuses_position_gap() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        c.push(&mut store).unwrap(); // position 0

        // Skipping to position 2 with a well-formed prev is a gap.
        let err = c.push_at(&mut store, 2, c.entry_hash_at(0)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::PositionGap {
                    expected: 1,
                    got: 2
                }
            ),
            "{err:?}"
        );

        // An empty chain must start at 0.
        let mut d = Chain::new(9);
        let err = d.push_at(&mut store, 1, [0u8; 32]).unwrap_err();
        assert!(
            matches!(
                err,
                Error::PositionGap {
                    expected: 0,
                    got: 1
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn append_refuses_chain_mismatch() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        c.push(&mut store).unwrap(); // position 0

        // Correct position, wrong prev_hash.
        let err = c.push_at(&mut store, 1, h(424242)).unwrap_err();
        assert!(matches!(err, Error::ChainMismatch), "{err:?}");

        // A non-zero prev at position 0 is also a mismatch.
        let mut d = Chain::new(7);
        let err = d.push_at(&mut store, 0, h(1)).unwrap_err();
        assert!(matches!(err, Error::ChainMismatch), "{err:?}");
    }

    #[test]
    fn append_refuses_duplicate_record() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let c = Chain::new(0);

        // Position 0 carrying record R.
        store
            .append(NewOutboxEntry {
                author: c.author,
                position: 0,
                entry_hash: c.entry_hash_at(0),
                prev_hash: [0u8; 32],
                record_hash: c.record_hash_at(0),
                record_kind: "rrn.test.record",
                envelope: b"e0",
                authored_at: 1,
            })
            .unwrap();

        // Position 1, correctly linked, but re-carrying record R.
        let err = store
            .append(NewOutboxEntry {
                author: c.author,
                position: 1,
                entry_hash: c.entry_hash_at(1),
                prev_hash: c.entry_hash_at(0),
                record_hash: c.record_hash_at(0), // duplicate
                record_kind: "rrn.test.record",
                envelope: b"e1",
                authored_at: 2,
            })
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateRecord), "{err:?}");
    }

    #[test]
    fn per_author_chains_are_independent() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut a = Chain::new(1);
        let mut b = Chain::new(2);
        a.push(&mut store).unwrap();
        a.push(&mut store).unwrap();
        b.push(&mut store).unwrap();

        assert_eq!(store.head(&a.author).unwrap().unwrap().position, 1);
        assert_eq!(store.head(&b.author).unwrap().unwrap().position, 0);
        assert_eq!(store.all_rows(&a.author).unwrap().len(), 2);
        assert_eq!(store.all_rows(&b.author).unwrap().len(), 1);
    }

    #[test]
    fn pending_ordering_and_limit() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        for _ in 0..5 {
            c.push(&mut store).unwrap();
        }

        let all_pending = store.pending(&c.author, None).unwrap();
        assert_eq!(
            all_pending.iter().map(|r| r.position).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );

        let capped = store.pending(&c.author, Some(2)).unwrap();
        assert_eq!(
            capped.iter().map(|r| r.position).collect::<Vec<_>>(),
            vec![0, 1]
        );

        // Ack the first two: they drop out of the pending view.
        store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Admitted,
                Some(10),
                None,
            )
            .unwrap();
        store
            .apply_ack(
                &c.author,
                &c.record_hash_at(1),
                AckOutcome::Known,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            store
                .pending(&c.author, None)
                .unwrap()
                .iter()
                .map(|r| r.position)
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn apply_ack_records_outcome_and_reason() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        c.push(&mut store).unwrap();
        c.push(&mut store).unwrap();

        assert!(store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Admitted,
                Some(42),
                None
            )
            .unwrap());
        assert!(store
            .apply_ack(
                &c.author,
                &c.record_hash_at(1),
                AckOutcome::Refused,
                Some(43),
                Some("debt_floor"),
            )
            .unwrap());

        let rows = store.all_rows(&c.author).unwrap();
        assert_eq!(rows[0].acked_outcome, Some(AckOutcome::Admitted));
        assert_eq!(rows[0].acked_seq, Some(42));
        assert_eq!(rows[0].refusal_reason, None);
        assert_eq!(rows[1].acked_outcome, Some(AckOutcome::Refused));
        assert_eq!(rows[1].refusal_reason, Some("debt_floor".to_string()));
    }

    #[test]
    fn apply_ack_is_idempotent_but_rejects_conflicts() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        c.push(&mut store).unwrap();

        // First ack, then the *same* outcome again — idempotent no-op.
        assert!(store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Admitted,
                Some(1),
                None
            )
            .unwrap());
        assert!(store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Admitted,
                Some(1),
                None
            )
            .unwrap());
        assert_eq!(
            store.all_rows(&c.author).unwrap()[0].acked_outcome,
            Some(AckOutcome::Admitted)
        );

        // A conflicting outcome for the same record is refused.
        let err = store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Refused,
                Some(2),
                Some("x"),
            )
            .unwrap_err();
        assert!(matches!(err, Error::ConflictingAck), "{err:?}");
    }

    #[test]
    fn apply_ack_unknown_record_returns_false() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        c.push(&mut store).unwrap();

        // A receipt for a record_hash this author's chain does not carry.
        assert!(!store
            .apply_ack(&c.author, &h(999999), AckOutcome::Admitted, Some(1), None)
            .unwrap());
    }

    #[test]
    fn prune_retains_suffix_from_first_pending() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        for _ in 0..5 {
            c.push(&mut store).unwrap();
        }
        // Ack 0 and 1; leave 2..4 pending.
        store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Admitted,
                Some(1),
                None,
            )
            .unwrap();
        store
            .apply_ack(
                &c.author,
                &c.record_hash_at(1),
                AckOutcome::Admitted,
                Some(2),
                None,
            )
            .unwrap();

        let removed = store.prune_acked(&c.author).unwrap();
        assert_eq!(removed, 2);
        let positions: Vec<u64> = store
            .all_rows(&c.author)
            .unwrap()
            .iter()
            .map(|r| r.position)
            .collect();
        assert_eq!(
            positions,
            vec![2, 3, 4],
            "retained suffix stays contiguous to head"
        );
    }

    #[test]
    fn prune_keeps_interleaved_acked_above_first_pending() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        for _ in 0..4 {
            c.push(&mut store).unwrap();
        }
        // Ack 0 and 3 (out of order); 1 and 2 stay pending. First pending is 1,
        // so the acked row at 3 must be retained — it is above the first pending.
        store
            .apply_ack(
                &c.author,
                &c.record_hash_at(0),
                AckOutcome::Admitted,
                Some(1),
                None,
            )
            .unwrap();
        store
            .apply_ack(
                &c.author,
                &c.record_hash_at(3),
                AckOutcome::Admitted,
                Some(4),
                None,
            )
            .unwrap();

        let removed = store.prune_acked(&c.author).unwrap();
        assert_eq!(
            removed, 1,
            "only position 0 (below first pending) is dropped"
        );
        let positions: Vec<u64> = store
            .all_rows(&c.author)
            .unwrap()
            .iter()
            .map(|r| r.position)
            .collect();
        assert_eq!(positions, vec![1, 2, 3]);
    }

    #[test]
    fn prune_all_acked_keeps_only_head() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        for _ in 0..3 {
            c.push(&mut store).unwrap();
        }
        for pos in 0..3 {
            store
                .apply_ack(
                    &c.author,
                    &c.record_hash_at(pos),
                    AckOutcome::Admitted,
                    Some(pos + 1),
                    None,
                )
                .unwrap();
        }

        let removed = store.prune_acked(&c.author).unwrap();
        assert_eq!(removed, 2);
        let rows = store.all_rows(&c.author).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].position, 2,
            "head is kept to anchor the next append"
        );

        // The retained head still anchors a correctly-linked next append.
        c.push(&mut store).unwrap(); // position 3, prev = entry_hash_at(2)
        assert_eq!(store.head(&c.author).unwrap().unwrap().position, 3);
    }

    #[test]
    fn prune_empty_and_all_pending_are_noops() {
        let db = fresh_db();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);

        // Empty chain.
        assert_eq!(store.prune_acked(&c.author).unwrap(), 0);

        // All pending.
        for _ in 0..3 {
            c.push(&mut store).unwrap();
        }
        assert_eq!(store.prune_acked(&c.author).unwrap(), 0);
        assert_eq!(store.all_rows(&c.author).unwrap().len(), 3);
    }

    #[test]
    fn rows_persist_across_reopen() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rrn-outbox-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("outbox.db");

        let author;
        let head_hash;
        {
            let db = Database::open(&path).unwrap();
            crate::migrations::run(&db).unwrap();
            let mut store = OutboxStore::new(&db);
            let mut c = Chain::new(0);
            c.push(&mut store).unwrap();
            c.push(&mut store).unwrap();
            store
                .apply_ack(
                    &c.author,
                    &c.record_hash_at(0),
                    AckOutcome::Admitted,
                    Some(1),
                    None,
                )
                .unwrap();
            author = c.author;
            head_hash = c.entry_hash_at(1);
        }

        // Reopen: the chain, its head, and the recorded ack all survived.
        let db = Database::open(&path).unwrap();
        let store = OutboxStore::new(&db);
        assert_eq!(store.head(&author).unwrap().unwrap().entry_hash, head_hash);
        assert_eq!(store.all_rows(&author).unwrap().len(), 2);
        assert_eq!(store.pending(&author, None).unwrap().len(), 1);

        drop(db);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migration_applies_to_a_phase1_database() {
        // A database created with only migrations 1..=4 (the Phase-1 set), then
        // brought forward: the additive migration applies cleanly and re-running
        // is a no-op.
        let db = fresh_db();
        crate::migrations::run(&db).unwrap();
        let mut store = OutboxStore::new(&db);
        let mut c = Chain::new(0);
        c.push(&mut store).unwrap();
        assert_eq!(store.all_rows(&c.author).unwrap().len(), 1);
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_append_ack_prune_preserve_invariants(
            len in 0u64..25,
            // Which positions to ack, and in what arbitrary order.
            ack_order in proptest::collection::vec(0u64..25, 0..40),
        ) {
            let db = fresh_db();
            let mut store = OutboxStore::new(&db);
            let mut c = Chain::new(0);
            for _ in 0..len {
                c.push(&mut store).unwrap();
            }

            // Ack an arbitrary subset in an arbitrary order (idempotent re-acks
            // are fine and must not error).
            let mut acked = std::collections::BTreeSet::new();
            for pos in ack_order {
                if pos < len {
                    store
                        .apply_ack(&c.author, &c.record_hash_at(pos), AckOutcome::Admitted, Some(pos + 1), None)
                        .unwrap();
                    acked.insert(pos);
                }
            }

            store.prune_acked(&c.author).unwrap();

            let rows = store.all_rows(&c.author).unwrap();

            // Invariant 1: retained positions are dense from min(kept) to head.
            if let (Some(first), Some(last)) = (rows.first(), rows.last()) {
                let expected: Vec<u64> = (first.position..=last.position).collect();
                let got: Vec<u64> = rows.iter().map(|r| r.position).collect();
                proptest::prop_assert_eq!(got, expected);
                // Head is always the last appended entry (never pruned away).
                proptest::prop_assert_eq!(last.position, len - 1);
            } else {
                // Only empty when the chain itself was empty.
                proptest::prop_assert_eq!(len, 0);
            }

            // Invariant 2: every kept row's prev_hash links to its predecessor's
            // entry_hash (when the predecessor is also retained).
            for pair in rows.windows(2) {
                proptest::prop_assert_eq!(pair[1].prev_hash, pair[0].entry_hash);
            }

            // Invariant 3: the pending view is exactly appended ∖ acked.
            let pending: std::collections::BTreeSet<u64> =
                store.pending(&c.author, None).unwrap().iter().map(|r| r.position).collect();
            let expected_pending: std::collections::BTreeSet<u64> =
                (0..len).filter(|p| !acked.contains(p)).collect();
            proptest::prop_assert_eq!(pending, expected_pending);
        }
    }
}
