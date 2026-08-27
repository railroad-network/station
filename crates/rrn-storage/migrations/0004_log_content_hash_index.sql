-- Index the log by `content_hash`.
--
-- `AppendLog::append_raw` already deduplicates replicated entries by content
-- hash, and `AppendLog::admission_of` (ADR-0022) looks up an entry's admission
-- metadata — `(seq, created_at)` — by content hash. Both did a full table scan
-- without this index; the DTN and certificate paths (Phase 2) make that lookup
-- hot. `content_hash` is Blake3 of the signed bytes and unique per payload, so
-- this is effectively a unique secondary key, though it is not declared UNIQUE
-- (the log tolerates the same payload arriving on two replicas as distinct
-- rows only in principle; in practice append_raw's dedup keeps it one).
CREATE INDEX IF NOT EXISTS idx_log_entries_content_hash
    ON log_entries (content_hash);
