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
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Unix seconds when the entry was appended.
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
    pub fn append<T: Clone + Into<CBOR>>(&mut self, signed: SignedPayload<T>) -> Result<LogEntry> {
        signed.verify().map_err(|_| Error::InvalidSignature)?;

        let bytes = to_canonical_bytes(signed.payload.clone());
        let content_hash = Hash::of(&bytes);
        let prev_hash = match self.tail()? {
            Some(prev) => prev.content_hash,
            None => zero_hash(),
        };
        let created_at = now_secs();
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
    pub fn append_raw(&mut self, payload: StoredPayload) -> Result<Option<LogEntry>> {
        payload.verify().map_err(|_| Error::InvalidSignature)?;

        let content_hash = Hash::of(&payload.bytes);
        if self.contains(&content_hash)? {
            return Ok(None);
        }
        let prev_hash = match self.tail()? {
            Some(prev) => prev.content_hash,
            None => zero_hash(),
        };
        let created_at = now_secs();

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

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

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

    fn append_note(log: &mut AppendLog, kp: &Keypair, n: u64) -> LogEntry {
        log.append(SignedPayload::sign(Note(n), kp)).unwrap()
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

        let err = log.append(signed).unwrap_err();
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
        let e2 = dst.append_raw(s1.clone()).unwrap().expect("newly appended");
        let e3 = dst.append_raw(s2.clone()).unwrap().expect("newly appended");
        assert_eq!((e2.seq, e3.seq), (2, 3));
        assert_eq!(e3.prev_hash, e2.content_hash);
        assert_eq!(dst.verify_chain().unwrap(), 3);

        // Re-replicating an already-held payload is a no-op (dedup by content).
        assert!(dst.append_raw(s1).unwrap().is_none());
        assert!(dst.append_raw(s2).unwrap().is_none());
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
        let err = log.append_raw(tampered).unwrap_err();
        assert!(matches!(err, Error::InvalidSignature), "{err:?}");
        assert!(log.tail().unwrap().is_none());
    }
}
