//! Append-only, hash-chained signed log.
//!
//! The tamper-evident source of truth: every permanent record (attestations,
//! vouches, transactions, governance decisions) is appended here, each entry
//! chained to the Blake3 `content_hash` of the previous one. Altering, dropping,
//! or reordering any entry breaks the chain, which [`AppendLog::verify_chain`]
//! detects. CRDT state is *derived* from this log (see `replay`), never the
//! other way around.
//!
//! # What is stored, and why not `SignedPayload<Vec<u8>>`
//!
//! Each entry is a signed value. A [`rrn_crypto::signed::SignedPayload<T>`]
//! signs the *canonical CBOR of `T`* — so re-wrapping the already-canonical
//! bytes in a `SignedPayload<Vec<u8>>` (as an earlier draft of the spec
//! suggested) would sign `CBOR(CBOR(T))` and fail to verify against the original
//! signature. Instead an entry stores the exact bytes that were signed, the
//! signer, and the signature ([`StoredPayload`]); verification checks the
//! signature against those bytes directly, matching how it was produced.
//!
//! The on-disk `payload` BLOB is `signer(32) ‖ signature(64) ‖ canonical_bytes`,
//! so the single `payload` column carries the whole signed envelope without
//! needing extra schema columns.

use dcbor::CBOR;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rusqlite::OptionalExtension;

use crate::db::Database;
use crate::{Error, Result};

/// Length of the fixed header in a stored payload blob: signer ‖ signature.
const SIGNER_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const HEADER_LEN: usize = SIGNER_LEN + SIGNATURE_LEN;

/// The signed content of a log entry: the exact canonical bytes that were
/// signed, plus the signer and signature over those bytes.
#[derive(Clone, Debug)]
pub struct StoredPayload {
    /// The canonical CBOR bytes of the original signed value.
    pub bytes: Vec<u8>,
    /// The public key that signed [`bytes`](Self::bytes).
    pub signer: PublicKey,
    /// The signature over [`bytes`](Self::bytes).
    pub signature: Signature,
}

impl StoredPayload {
    /// Verifies the signature against the stored bytes.
    pub fn verify(&self) -> std::result::Result<(), rrn_crypto::keypair::VerifyError> {
        self.signer.verify(&self.bytes, &self.signature)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.bytes.len());
        out.extend_from_slice(&self.signer.to_bytes());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    fn decode(blob: &[u8]) -> Result<Self> {
        if blob.len() < HEADER_LEN {
            return Err(Error::Corrupt(format!(
                "log payload {} bytes, shorter than {HEADER_LEN}-byte header",
                blob.len()
            )));
        }
        let signer = PublicKey::from_bytes(blob[..SIGNER_LEN].try_into().expect("32-byte slice"))
            .map_err(|e| Error::Corrupt(format!("log payload signer: {e}")))?;
        let signature = Signature::from_bytes(
            blob[SIGNER_LEN..HEADER_LEN]
                .try_into()
                .expect("64-byte slice"),
        )
        .map_err(|e| Error::Corrupt(format!("log payload signature: {e}")))?;
        Ok(Self {
            bytes: blob[HEADER_LEN..].to_vec(),
            signer,
            signature,
        })
    }
}

/// One entry in the append-only log.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// 1-based sequence number (SQLite rowid).
    pub seq: u64,
    /// `content_hash` of the previous entry, or the all-zero hash for `seq == 1`.
    pub prev_hash: Hash,
    /// Blake3 of the signed canonical bytes.
    pub content_hash: Hash,
    /// The signed content.
    pub payload: StoredPayload,
    /// The admitting station's clock (Unix seconds) at admission — the
    /// *admission time* (ADR-0022 §1). Clamped monotone non-decreasing in log
    /// order (§6). This is station-local, unsigned metadata: it is never part
    /// of signed content and is never replicated as authoritative — a replica
    /// re-stamps it locally on [`AppendLog::append_raw`], so only the admitting
    /// station's reading is load-bearing for that station's window decisions.
    pub created_at: i64,
}

/// A handle for reading and appending to the log over a borrowed [`Database`].
pub struct AppendLog<'a> {
    db: &'a Database,
}

impl<'a> AppendLog<'a> {
    /// Wraps a database handle for log access.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Appends a signed value as the next entry and returns it.
    ///
    /// The signature is verified *before* anything is written — an entry that
    /// does not verify is never persisted. The bound is `Clone + Into<CBOR>`
    /// (not `Serialize`): the signature covers the canonical CBOR of the value,
    /// per ADR-0002, so that is the trait the log needs.
    ///
    /// `now` is the admitting station's injected clock reading (Unix seconds);
    /// library code threads it from its own `now` parameter, the daemon edge
    /// from `clock.rs`. The stored [`created_at`](LogEntry::created_at) is `now`
    /// clamped monotone non-decreasing against the current tail (ADR-0022 §6),
    /// so a backwards clock step cannot reorder admission times against log
    /// order. It is station-local, unsigned metadata — never signed content,
    /// never replicated as authoritative.
    pub fn append<T: Clone + Into<CBOR>>(
        &mut self,
        signed: SignedPayload<T>,
        now: i64,
    ) -> Result<LogEntry> {
        signed.verify().map_err(|_| Error::InvalidSignature)?;

        let bytes = to_canonical_bytes(signed.payload.clone());
        let content_hash = Hash::of(&bytes);
        let (prev_hash, created_at) = match self.tail()? {
            Some(prev) => (prev.content_hash, now.max(prev.created_at)),
            None => (zero_hash(), now),
        };
        let payload = StoredPayload {
            bytes,
            signer: signed.signer,
            signature: signed.signature,
        };

        let conn = self.db.conn();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO log_entries (prev_hash, content_hash, payload, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                prev_hash.to_bytes().as_slice(),
                content_hash.to_bytes().as_slice(),
                payload.encode(),
                created_at,
            ],
        )?;
        let seq = tx.last_insert_rowid() as u64;
        tx.commit()?;

        tracing::trace!(seq, %content_hash, "appended log entry");
        Ok(LogEntry {
            seq,
            prev_hash,
            content_hash,
            payload,
            created_at,
        })
    }

    /// Begins a [`LogBatch`]: a single SQLite transaction into which several
    /// payloads can be appended and then committed atomically (ADR-0027).
    ///
    /// `append` commits one transaction per call; some records must land
    /// **together or not at all** — the crossing declaration/co-sign record and
    /// its station marker, or a declaration and its admission anchor — so that a
    /// crash can never leave a markerless crossing that a later append would
    /// revive. `rusqlite` will not nest `unchecked_transaction`, so this opens
    /// one and hands back a guard the caller appends into.
    ///
    /// While the batch is open, reads on the **same** [`Database`] connection
    /// observe the not-yet-committed entries (SQLite always shows a connection
    /// its own writes), so a writer can append a crossing co-sign and then
    /// evaluate the crossing over a log that already contains it, all before the
    /// single commit. The guard rolls the whole batch back on drop unless
    /// [`commit`](LogBatch::commit) is called; a mid-batch failure therefore
    /// leaves the log exactly as it was.
    ///
    /// The chain invariants are preserved across the batch just as `append`
    /// preserves them per call: monotone `seq`, `prev_hash` chained entry to
    /// entry, and `created_at = now.max(prev.created_at)` clamped against the
    /// running tail (§6).
    pub fn begin_batch(&self) -> Result<LogBatch<'a>> {
        let (prev_hash, prev_created_at) = match self.tail()? {
            Some(prev) => (prev.content_hash, Some(prev.created_at)),
            None => (zero_hash(), None),
        };
        let tx = self.db.conn().unchecked_transaction()?;
        Ok(LogBatch {
            tx,
            prev_hash,
            prev_created_at,
        })
    }

    /// Appends a pre-signed [`StoredPayload`] received from a peer, verbatim.
    ///
    /// Replication (the gossip layer, M0.6) hands over the exact bytes another
    /// replica signed, not a typed `T` — so this path takes a [`StoredPayload`]
    /// and stores its `bytes` unchanged, rather than re-encoding through
    /// `Into<CBOR>` (which would only round-trip for types we can name). The
    /// signature is verified before anything is written.
    ///
    /// A payload's [`content_hash`](LogEntry::content_hash) is the Blake3 of its
    /// `bytes` alone (independent of chain position), so the *same* payload has
    /// the same `content_hash` on every replica. This method is therefore
    /// idempotent across replicas: an entry whose `content_hash` is already in
    /// the log is skipped and `Ok(None)` is returned; a genuinely new entry is
    /// appended (chained to *this* replica's current tail) and returned as
    /// `Ok(Some(entry))`. Two replicas thus converge on the same *set* of
    /// payloads even though their hash chains link them in receipt order.
    ///
    /// `now` is this replica's own injected clock at the moment it admits the
    /// entry (the daemon threads it from `clock.rs`). Replicas re-stamp
    /// [`created_at`](LogEntry::created_at) locally rather than inheriting the
    /// origin's admission time — only the admitting station's reading bears on
    /// its own window decisions (ADR-0022 §1). The same monotone clamp (§6)
    /// applies against this replica's tail.
    pub fn append_raw(&mut self, payload: StoredPayload, now: i64) -> Result<Option<LogEntry>> {
        payload.verify().map_err(|_| Error::InvalidSignature)?;

        let content_hash = Hash::of(&payload.bytes);
        if self.contains(&content_hash)? {
            return Ok(None);
        }
        let (prev_hash, created_at) = match self.tail()? {
            Some(prev) => (prev.content_hash, now.max(prev.created_at)),
            None => (zero_hash(), now),
        };

        let conn = self.db.conn();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO log_entries (prev_hash, content_hash, payload, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                prev_hash.to_bytes().as_slice(),
                content_hash.to_bytes().as_slice(),
                payload.encode(),
                created_at,
            ],
        )?;
        let seq = tx.last_insert_rowid() as u64;
        tx.commit()?;

        tracing::trace!(seq, %content_hash, "appended replicated log entry");
        Ok(Some(LogEntry {
            seq,
            prev_hash,
            content_hash,
            payload,
            created_at,
        }))
    }

    /// Whether an entry with this `content_hash` is already in the log. Used by
    /// [`append_raw`](Self::append_raw) to deduplicate replicated entries.
    pub fn contains(&self, content_hash: &Hash) -> Result<bool> {
        let found: Option<i64> = self
            .db
            .conn()
            .query_row(
                "SELECT 1 FROM log_entries WHERE content_hash = ?1 LIMIT 1",
                [content_hash.to_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// Admission metadata of the entry holding `content_hash`, if present:
    /// `(seq, created_at)`. `created_at` is this station's admission-clock
    /// reading for that entry (ADR-0022). Used by idempotent ingest, receipts,
    /// and window re-anchoring (T2.1.2) to find when an entry was admitted here.
    pub fn admission_of(&self, content_hash: &Hash) -> Result<Option<(u64, i64)>> {
        let row: Option<(i64, i64)> = self
            .db
            .conn()
            .query_row(
                // ORDER BY seq: content_hash is not declared UNIQUE (append_raw's
                // dedup keeps it one in practice, but not by schema constraint),
                // so pin the result to the earliest — the admission that counts —
                // rather than whichever row the planner happens to pick.
                "SELECT seq, created_at FROM log_entries WHERE content_hash = ?1 \
                 ORDER BY seq LIMIT 1",
                [content_hash.to_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(seq, created_at)| (seq as u64, created_at)))
    }

    /// The highest `seq` whose entry was admitted at or before `t` — i.e. the
    /// right boundary of the log prefix admitted by time `t`. `0` when no entry
    /// was admitted that early (an empty prefix; `seq` starts at 1).
    ///
    /// Because admission times are clamped monotone non-decreasing on append
    /// ([`append`](Self::append)/[`append_raw`](Self::append_raw)), the set of
    /// entries with `created_at <= t` is exactly the contiguous prefix
    /// `[1, bound]` — so this seq bound and a `created_at <= t` filter select the
    /// same entries. That equivalence is what lets governance pin an electorate
    /// "as of a window instant" by **log position** (ADR-0022 §5, "ordering is
    /// log order") rather than by wall-clock time, closing the back-dated-evidence
    /// vector (T2.1.3). The query is `MAX(seq) WHERE created_at <= t` so it stays
    /// correct even if monotonicity were ever to regress.
    pub fn last_seq_admitted_by(&self, t: i64) -> Result<u64> {
        let seq: Option<i64> = self.db.conn().query_row(
            "SELECT MAX(seq) FROM log_entries WHERE created_at <= ?1",
            [t],
            |row| row.get(0),
        )?;
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Fetches the entry at `seq`, if present.
    pub fn get(&self, seq: u64) -> Result<Option<LogEntry>> {
        let raw = self
            .db
            .conn()
            .query_row(
                "SELECT seq, prev_hash, content_hash, payload, created_at \
                 FROM log_entries WHERE seq = ?1",
                [seq as i64],
                row_to_raw,
            )
            .optional()?;
        raw.map(decode_entry).transpose()
    }

    /// Fetches the most recent entry, if the log is non-empty.
    pub fn tail(&self) -> Result<Option<LogEntry>> {
        let raw = self
            .db
            .conn()
            .query_row(
                "SELECT seq, prev_hash, content_hash, payload, created_at \
                 FROM log_entries ORDER BY seq DESC LIMIT 1",
                [],
                row_to_raw,
            )
            .optional()?;
        raw.map(decode_entry).transpose()
    }

    /// Iterates entries with `seq >= from_seq`, in ascending order. Entries are
    /// loaded eagerly (Phase 0 logs are small), so the iterator borrows nothing.
    pub fn iter_from(&self, from_seq: u64) -> impl Iterator<Item = Result<LogEntry>> {
        self.collect_from(from_seq).into_iter()
    }

    /// Re-reads the whole log and checks every link: each entry's stored
    /// `content_hash` must equal the Blake3 of its payload bytes, and its
    /// `prev_hash` must equal the previous entry's `content_hash` (zero for the
    /// first). Returns the last verified `seq`, or errors at the first break.
    /// O(N); Phase 0 logs are small.
    pub fn verify_chain(&self) -> Result<u64> {
        let mut expected_prev = zero_hash();
        let mut last_seq = 0u64;
        for entry in self.collect_from(1) {
            let entry = entry?;
            let recomputed = Hash::of(&entry.payload.bytes);
            if recomputed != entry.content_hash {
                return Err(Error::ChainBroken {
                    seq: entry.seq,
                    reason: "content_hash does not match payload".into(),
                });
            }
            if entry.prev_hash != expected_prev {
                return Err(Error::ChainBroken {
                    seq: entry.seq,
                    reason: "prev_hash does not match previous entry".into(),
                });
            }
            expected_prev = entry.content_hash;
            last_seq = entry.seq;
        }
        Ok(last_seq)
    }

    /// Eagerly loads entries `seq >= from_seq` as `Result`s.
    fn collect_from(&self, from_seq: u64) -> Vec<Result<LogEntry>> {
        let conn = self.db.conn();
        let mut stmt = match conn.prepare(
            "SELECT seq, prev_hash, content_hash, payload, created_at \
             FROM log_entries WHERE seq >= ?1 ORDER BY seq",
        ) {
            Ok(stmt) => stmt,
            Err(e) => return vec![Err(e.into())],
        };
        let rows = match stmt.query_map([from_seq as i64], row_to_raw) {
            Ok(rows) => rows,
            Err(e) => return vec![Err(e.into())],
        };
        rows.map(|r| r.map_err(Error::from).and_then(decode_entry))
            .collect()
    }
}

/// A set of appends committed to the log in a single SQLite transaction
/// (ADR-0027). Opened by [`AppendLog::begin_batch`].
///
/// Each [`append`](Self::append) stamps and inserts one entry inside the open
/// transaction, chaining `prev_hash`/`created_at` across the batch exactly as
/// sequential [`AppendLog::append`] calls would. Nothing is durable until
/// [`commit`](Self::commit); dropping the guard without committing rolls the
/// whole batch back, so a failure part-way through leaves no partial write.
pub struct LogBatch<'a> {
    tx: rusqlite::Transaction<'a>,
    prev_hash: Hash,
    /// `created_at` of the running tail (the last entry appended in this batch,
    /// or the log tail at batch start), or `None` if the log was empty and this
    /// batch has appended nothing yet.
    prev_created_at: Option<i64>,
}

impl LogBatch<'_> {
    /// Appends one signed value as the next entry in the open transaction and
    /// returns it. The signature is verified before the row is inserted; an
    /// entry that does not verify errors without inserting (and, since the batch
    /// has not committed, rolls back anything appended before it on drop).
    ///
    /// `now` is clamped monotone non-decreasing against the running tail, so all
    /// entries in one batch share a single admission instant when `now` does not
    /// advance between calls — the same clamp `append` applies (ADR-0022 §6).
    pub fn append<T: Clone + Into<CBOR>>(
        &mut self,
        signed: SignedPayload<T>,
        now: i64,
    ) -> Result<LogEntry> {
        signed.verify().map_err(|_| Error::InvalidSignature)?;
        let bytes = to_canonical_bytes(signed.payload.clone());
        self.insert(bytes, signed.signer, signed.signature, now)
    }

    fn insert(
        &mut self,
        bytes: Vec<u8>,
        signer: PublicKey,
        signature: Signature,
        now: i64,
    ) -> Result<LogEntry> {
        let content_hash = Hash::of(&bytes);
        let prev_hash = self.prev_hash;
        let created_at = match self.prev_created_at {
            Some(prev) => now.max(prev),
            None => now,
        };
        let payload = StoredPayload {
            bytes,
            signer,
            signature,
        };
        self.tx.execute(
            "INSERT INTO log_entries (prev_hash, content_hash, payload, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                prev_hash.to_bytes().as_slice(),
                content_hash.to_bytes().as_slice(),
                payload.encode(),
                created_at,
            ],
        )?;
        let seq = self.tx.last_insert_rowid() as u64;
        self.prev_hash = content_hash;
        self.prev_created_at = Some(created_at);
        tracing::trace!(seq, %content_hash, "appended log entry (batch)");
        Ok(LogEntry {
            seq,
            prev_hash,
            content_hash,
            payload,
            created_at,
        })
    }

    /// Commits the batch, making every appended entry durable in one atomic
    /// transaction. Without this call the guard rolls the batch back on drop.
    pub fn commit(self) -> Result<()> {
        self.tx.commit()?;
        Ok(())
    }
}

/// Raw columns of a `log_entries` row, before decoding into a [`LogEntry`].
type RawEntry = (i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);

fn row_to_raw(row: &rusqlite::Row) -> rusqlite::Result<RawEntry> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn decode_entry((seq, prev, content, payload, created_at): RawEntry) -> Result<LogEntry> {
    Ok(LogEntry {
        seq: seq as u64,
        prev_hash: hash_from_col(&prev, "prev_hash")?,
        content_hash: hash_from_col(&content, "content_hash")?,
        payload: StoredPayload::decode(&payload)?,
        created_at,
    })
}

fn hash_from_col(bytes: &[u8], col: &str) -> Result<Hash> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Corrupt(format!("{col} is {} bytes, expected 32", bytes.len())))?;
    Ok(Hash::from_bytes(arr))
}

/// The all-zero hash used as `prev_hash` of the first entry.
fn zero_hash() -> Hash {
    Hash::from_bytes([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A fixed admission time for tests that do not exercise the clock.
    const NOW: i64 = 1_000;

    /// A minimal signed value: `Into<CBOR>` is all the log requires.
    #[derive(Clone)]
    struct Note(u64);

    impl From<Note> for CBOR {
        fn from(n: Note) -> Self {
            n.0.into()
        }
    }

    fn fresh_log_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        db
    }

    /// Appends a note at the fixed [`NOW`]; used where admission time is
    /// incidental to what the test asserts.
    fn append_note(log: &mut AppendLog, kp: &Keypair, n: u64) -> LogEntry {
        append_note_at(log, kp, n, NOW)
    }

    fn append_note_at(log: &mut AppendLog, kp: &Keypair, n: u64, now: i64) -> LogEntry {
        log.append(SignedPayload::sign(Note(n), kp), now).unwrap()
    }

    #[test]
    fn append_chains_and_verifies() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        let e1 = append_note(&mut log, &kp, 10);
        let e2 = append_note(&mut log, &kp, 20);
        let e3 = append_note(&mut log, &kp, 30);

        assert_eq!((e1.seq, e2.seq, e3.seq), (1, 2, 3));
        assert_eq!(e1.prev_hash, zero_hash());
        assert_eq!(e2.prev_hash, e1.content_hash);
        assert_eq!(e3.prev_hash, e2.content_hash);
        assert_eq!(log.verify_chain().unwrap(), 3);

        // Each stored entry's signature verifies against its bytes.
        assert!(log.get(2).unwrap().unwrap().payload.verify().is_ok());
        assert_eq!(log.tail().unwrap().unwrap().seq, 3);
        assert_eq!(log.iter_from(2).count(), 2);
    }

    #[test]
    fn empty_log_verifies_to_zero() {
        let db = fresh_log_db();
        let log = AppendLog::new(&db);
        assert_eq!(log.verify_chain().unwrap(), 0);
        assert!(log.tail().unwrap().is_none());
        assert!(log.get(1).unwrap().is_none());
    }

    #[test]
    fn log_persists_across_reopen() {
        // A unique temp file so the test can close and reopen the database,
        // simulating a daemon restart.
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rrn-log-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.db");
        let kp = Keypair::generate();

        let want_hash = {
            let db = Database::open(&path).unwrap();
            crate::migrations::run(&db).unwrap();
            let mut log = AppendLog::new(&db);
            append_note(&mut log, &kp, 1);
            append_note(&mut log, &kp, 2).content_hash
            // db dropped here → connection closed.
        };

        // Reopen the same file and confirm the chain survived intact.
        let db = Database::open(&path).unwrap();
        let log = AppendLog::new(&db);
        assert_eq!(log.verify_chain().unwrap(), 2);
        let e2 = log.get(2).unwrap().unwrap();
        assert_eq!(e2.content_hash, want_hash);
        assert!(e2.payload.verify().is_ok());

        drop(db);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampering_with_payload_breaks_chain() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        {
            let mut log = AppendLog::new(&db);
            append_note(&mut log, &kp, 1);
            append_note(&mut log, &kp, 2);
            append_note(&mut log, &kp, 3);
        }
        // Flip the last byte of entry 2's payload (in the signed-bytes region),
        // so its recomputed content_hash no longer matches.
        let mut blob: Vec<u8> = db
            .conn()
            .query_row("SELECT payload FROM log_entries WHERE seq = 2", [], |r| {
                r.get(0)
            })
            .unwrap();
        *blob.last_mut().unwrap() ^= 0x01;
        db.conn()
            .execute(
                "UPDATE log_entries SET payload = ?1 WHERE seq = 2",
                rusqlite::params![blob],
            )
            .unwrap();

        let err = AppendLog::new(&db).verify_chain().unwrap_err();
        assert!(matches!(err, Error::ChainBroken { seq: 2, .. }), "{err:?}");
    }

    #[test]
    fn tampering_with_prev_hash_breaks_chain() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        {
            let mut log = AppendLog::new(&db);
            append_note(&mut log, &kp, 1);
            append_note(&mut log, &kp, 2);
            append_note(&mut log, &kp, 3);
        }
        // Replace entry 2's prev_hash with a different (valid-length) hash.
        db.conn()
            .execute(
                "UPDATE log_entries SET prev_hash = ?1 WHERE seq = 2",
                [Hash::of(b"not the real prev").to_bytes().as_slice()],
            )
            .unwrap();

        let err = AppendLog::new(&db).verify_chain().unwrap_err();
        assert!(matches!(err, Error::ChainBroken { seq: 2, .. }), "{err:?}");
    }

    #[test]
    fn append_rejects_invalid_signature_without_writing() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        let mut signed = SignedPayload::sign(Note(7), &kp);
        signed.payload = Note(8); // mutate after signing → signature no longer valid

        let err = log.append(signed, NOW).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature), "{err:?}");
        // Nothing was written.
        assert!(log.tail().unwrap().is_none());
    }

    #[test]
    fn append_raw_replicates_dedupes_and_rechains() {
        // Source replica writes two entries.
        let src_db = fresh_log_db();
        let kp = Keypair::generate();
        let (s1, s2) = {
            let mut src = AppendLog::new(&src_db);
            (
                append_note(&mut src, &kp, 11).payload,
                append_note(&mut src, &kp, 22).payload,
            )
        };

        // A second replica that already holds an unrelated entry at seq 1.
        let dst_db = fresh_log_db();
        let mut dst = AppendLog::new(&dst_db);
        append_note(&mut dst, &kp, 99);

        // Replicate the source payloads verbatim. They land at seq 2, 3 and are
        // re-chained to *this* replica's tail, not the source's.
        let e2 = dst
            .append_raw(s1.clone(), NOW)
            .unwrap()
            .expect("newly appended");
        let e3 = dst
            .append_raw(s2.clone(), NOW)
            .unwrap()
            .expect("newly appended");
        assert_eq!((e2.seq, e3.seq), (2, 3));
        assert_eq!(e3.prev_hash, e2.content_hash);
        assert_eq!(dst.verify_chain().unwrap(), 3);

        // Re-replicating an already-held payload is a no-op (dedup by content).
        assert!(dst.append_raw(s1, NOW).unwrap().is_none());
        assert!(dst.append_raw(s2, NOW).unwrap().is_none());
        assert_eq!(dst.tail().unwrap().unwrap().seq, 3);
    }

    #[test]
    fn append_raw_rejects_invalid_signature_without_writing() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        // A payload whose signature does not match its bytes.
        let good = SignedPayload::sign(Note(7), &kp);
        let tampered = StoredPayload {
            bytes: to_canonical_bytes(Note(8)),
            signer: good.signer,
            signature: good.signature,
        };
        let err = log.append_raw(tampered, NOW).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature), "{err:?}");
        assert!(log.tail().unwrap().is_none());
    }

    #[test]
    fn append_stamps_injected_time() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        let e = append_note_at(&mut log, &kp, 1, 1_000);
        assert_eq!(e.created_at, 1_000);
        assert_eq!(log.get(1).unwrap().unwrap().created_at, 1_000);
    }

    #[test]
    fn admission_time_is_clamped_monotone() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        // First entry stamps its injected time verbatim.
        assert_eq!(append_note_at(&mut log, &kp, 1, 1_000).created_at, 1_000);
        // A backwards clock step cannot lower the admission time below the tail:
        // it is clamped up to the previous entry's.
        assert_eq!(append_note_at(&mut log, &kp, 2, 900).created_at, 1_000);
        // A forwards step advances normally.
        assert_eq!(append_note_at(&mut log, &kp, 3, 1_100).created_at, 1_100);
    }

    #[test]
    fn last_seq_admitted_by_bounds_the_prefix() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        // Empty log: no prefix, bound is 0.
        assert_eq!(log.last_seq_admitted_by(9_999).unwrap(), 0);

        append_note_at(&mut log, &kp, 1, 1_000); // seq 1 @ 1000
        append_note_at(&mut log, &kp, 2, 1_000); // seq 2 @ 1000 (equal ts)
        append_note_at(&mut log, &kp, 3, 2_000); // seq 3 @ 2000

        // Before the first admission: still empty.
        assert_eq!(log.last_seq_admitted_by(999).unwrap(), 0);
        // At an equal-timestamp boundary: both seq 1 and 2 are included.
        assert_eq!(log.last_seq_admitted_by(1_000).unwrap(), 2);
        // Between the two distinct times: the prefix stops at seq 2.
        assert_eq!(log.last_seq_admitted_by(1_999).unwrap(), 2);
        // At/after the last admission: the whole log.
        assert_eq!(log.last_seq_admitted_by(2_000).unwrap(), 3);
        assert_eq!(log.last_seq_admitted_by(5_000).unwrap(), 3);

        // Equivalence with a created_at filter: the bound is the prefix boundary,
        // so every entry with seq <= bound has created_at <= t and no later one
        // does (relies on the monotone clamp).
        let t = 1_000;
        let bound = log.last_seq_admitted_by(t).unwrap();
        for seq in 1..=3 {
            let admitted = log.get(seq).unwrap().unwrap().created_at;
            assert_eq!(admitted <= t, seq <= bound);
        }
    }

    #[test]
    fn append_raw_clamps_admission_time_monotone() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let src_db = fresh_log_db();
        let payload = {
            let mut src = AppendLog::new(&src_db);
            append_note_at(&mut src, &kp, 7, 500).payload
        };
        let mut dst = AppendLog::new(&db);
        append_note_at(&mut dst, &kp, 1, 2_000);
        // The replica re-stamps at its own clock, clamped to its tail — it does
        // not inherit the origin's admission time (ADR-0022 §1).
        let e = dst.append_raw(payload, 1_500).unwrap().expect("appended");
        assert_eq!(e.created_at, 2_000);
    }

    #[test]
    fn batch_stamping_equals_sequential_stamping() {
        // A batch of three appends must produce byte-identical chain state to
        // three sequential `append`s at the same `now`: same seqs, prev_hashes,
        // content_hashes, and clamped created_at.
        let kp = Keypair::generate();

        let seq_db = fresh_log_db();
        let sequential: Vec<LogEntry> = {
            let mut log = AppendLog::new(&seq_db);
            vec![
                append_note_at(&mut log, &kp, 1, 1_000),
                append_note_at(&mut log, &kp, 2, 1_000),
                append_note_at(&mut log, &kp, 3, 1_000),
            ]
        };

        let batch_db = fresh_log_db();
        let batched: Vec<LogEntry> = {
            let log = AppendLog::new(&batch_db);
            let mut batch = log.begin_batch().unwrap();
            let e1 = batch
                .append(SignedPayload::sign(Note(1), &kp), 1_000)
                .unwrap();
            let e2 = batch
                .append(SignedPayload::sign(Note(2), &kp), 1_000)
                .unwrap();
            let e3 = batch
                .append(SignedPayload::sign(Note(3), &kp), 1_000)
                .unwrap();
            batch.commit().unwrap();
            vec![e1, e2, e3]
        };

        for (s, b) in sequential.iter().zip(&batched) {
            assert_eq!(s.seq, b.seq);
            assert_eq!(s.prev_hash, b.prev_hash);
            assert_eq!(s.content_hash, b.content_hash);
            assert_eq!(s.created_at, b.created_at);
        }
        assert_eq!(AppendLog::new(&batch_db).verify_chain().unwrap(), 3);
    }

    #[test]
    fn batch_chains_onto_a_nonempty_tail_and_clamps() {
        // A batch opened over a non-empty log chains onto its tail, and a
        // backwards `now` is clamped up to the tail's created_at across the batch.
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let tail = {
            let mut log = AppendLog::new(&db);
            append_note_at(&mut log, &kp, 1, 2_000)
        };
        let log = AppendLog::new(&db);
        let mut batch = log.begin_batch().unwrap();
        let e2 = batch
            .append(SignedPayload::sign(Note(2), &kp), 900)
            .unwrap();
        let e3 = batch
            .append(SignedPayload::sign(Note(3), &kp), 900)
            .unwrap();
        batch.commit().unwrap();

        assert_eq!((e2.seq, e3.seq), (2, 3));
        assert_eq!(e2.prev_hash, tail.content_hash);
        assert_eq!(e3.prev_hash, e2.content_hash);
        // Clamped up to the tail's 2_000, not the injected 900.
        assert_eq!((e2.created_at, e3.created_at), (2_000, 2_000));
        assert_eq!(AppendLog::new(&db).verify_chain().unwrap(), 3);
    }

    #[test]
    fn a_mid_batch_failure_rolls_the_whole_batch_back() {
        // Append one good entry into a batch, then an entry whose signature does
        // not verify. The second `append` errors, the batch is dropped without a
        // commit, and nothing — not even the first, already-inserted entry — is
        // persisted.
        let db = fresh_log_db();
        let kp = Keypair::generate();
        {
            let log = AppendLog::new(&db);
            let mut batch = log.begin_batch().unwrap();
            batch
                .append(SignedPayload::sign(Note(1), &kp), NOW)
                .unwrap();

            let mut bad = SignedPayload::sign(Note(7), &kp);
            bad.payload = Note(8); // mutate after signing → signature invalid
            let err = batch.append(bad, NOW).unwrap_err();
            assert!(matches!(err, Error::InvalidSignature), "{err:?}");
            // `batch` dropped here without commit → rollback.
        }
        // The good entry that was inserted mid-batch was rolled back with it.
        assert!(AppendLog::new(&db).tail().unwrap().is_none());
    }

    #[test]
    fn a_dropped_batch_without_commit_persists_nothing() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        {
            let log = AppendLog::new(&db);
            let mut batch = log.begin_batch().unwrap();
            batch
                .append(SignedPayload::sign(Note(1), &kp), NOW)
                .unwrap();
            batch
                .append(SignedPayload::sign(Note(2), &kp), NOW)
                .unwrap();
            // No commit.
        }
        assert!(AppendLog::new(&db).tail().unwrap().is_none());
    }

    #[test]
    fn a_single_element_batch_matches_append() {
        let kp = Keypair::generate();

        let a_db = fresh_log_db();
        let via_append = {
            let mut log = AppendLog::new(&a_db);
            append_note_at(&mut log, &kp, 5, 1_234)
        };

        let b_db = fresh_log_db();
        let via_batch = {
            let log = AppendLog::new(&b_db);
            let mut batch = log.begin_batch().unwrap();
            let e = batch
                .append(SignedPayload::sign(Note(5), &kp), 1_234)
                .unwrap();
            batch.commit().unwrap();
            e
        };

        assert_eq!(via_append.seq, via_batch.seq);
        assert_eq!(via_append.prev_hash, via_batch.prev_hash);
        assert_eq!(via_append.content_hash, via_batch.content_hash);
        assert_eq!(via_append.created_at, via_batch.created_at);
    }

    #[test]
    fn reads_on_the_same_connection_see_uncommitted_batch_entries() {
        // The property the emergency writer relies on: while a batch is open,
        // a read through a separate AppendLog over the same Database observes
        // the entries appended into the batch but not yet committed.
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let log = AppendLog::new(&db);
        let mut batch = log.begin_batch().unwrap();
        let e1 = batch
            .append(SignedPayload::sign(Note(1), &kp), NOW)
            .unwrap();

        // A fresh handle over the same db sees the uncommitted entry.
        let seen = AppendLog::new(&db).tail().unwrap().expect("tail visible");
        assert_eq!(seen.seq, e1.seq);
        assert_eq!(seen.content_hash, e1.content_hash);

        batch.commit().unwrap();
    }

    #[test]
    fn admission_of_finds_entries_and_misses_unknowns() {
        let db = fresh_log_db();
        let kp = Keypair::generate();
        let mut log = AppendLog::new(&db);

        let e1 = append_note_at(&mut log, &kp, 10, 1_000);
        let e2 = append_note_at(&mut log, &kp, 20, 1_200);

        assert_eq!(
            log.admission_of(&e1.content_hash).unwrap(),
            Some((1, 1_000))
        );
        assert_eq!(
            log.admission_of(&e2.content_hash).unwrap(),
            Some((2, 1_200))
        );
        assert_eq!(
            log.admission_of(&Hash::of(b"never appended")).unwrap(),
            None
        );
    }
}
