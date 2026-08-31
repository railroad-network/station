-- Per-author outbox store (ADR-0020 §2).
--
-- Durable, chain-checked persistence for a device's *own* outbox: the
-- append-only, hash-chained run of signed records it has authored but not yet
-- had admitted by the station. The CLI wallet (T2.5.2) and, via FFI, the mobile
-- wallet (T2.4.2) write here; the station reuses these shapes in a separate
-- table to track *seen* remote chains (T2.2.3).
--
-- Layering: `rrn-storage` sits below `rrn-identity`/`rrn-protocol`, so it cannot
-- parse an `OutboxEntry`. Rows therefore hold **opaque, already-validated**
-- envelope bytes — the caller (a layer that has `rrn-protocol`) validates the
-- entry and hands over pre-extracted columns. This store enforces only
-- *structural* chain integrity: dense positions and raw prev-hash linkage.
--
-- Columns (kept out of the CREATE statement so the stored schema stays clean;
-- see `outbox.rs` for the typed mirror):
--   author         BLOB    32-byte pubkey of the chain owner
--   position       INTEGER 0-based, sequential per author
--   entry_hash     BLOB    Blake3 of the entry's canonical bytes
--   prev_hash      BLOB    32 bytes; zeros at position 0
--   record_hash    BLOB    Blake3 of the embedded record bytes
--   record_kind    TEXT    the embedded record's kind string
--   envelope       BLOB    signed outbox-entry envelope bytes
--   authored_at    INTEGER testimony (ADR-0022 §3), display only
--   acked_seq      INTEGER log seq from a receipt; NULL = pending
--   acked_outcome  TEXT    'admitted' | 'known' | 'refused'; NULL = pending
--   refusal_reason TEXT    slug, iff refused
CREATE TABLE IF NOT EXISTS outbox_entries (
    author         BLOB NOT NULL,
    position       INTEGER NOT NULL,
    entry_hash     BLOB NOT NULL,
    prev_hash      BLOB NOT NULL,
    record_hash    BLOB NOT NULL,
    record_kind    TEXT NOT NULL,
    envelope       BLOB NOT NULL,
    authored_at    INTEGER NOT NULL,
    acked_seq      INTEGER,
    acked_outcome  TEXT,
    refusal_reason TEXT,
    PRIMARY KEY (author, position)
) STRICT;

-- One outbox entry per carried record, per author: dedup on re-append and the
-- lookup key for applying a delivery receipt's per-record outcome.
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_record
    ON outbox_entries (author, record_hash);

-- Pending (unacked) entries in position order — the hot path for assembling a
-- bundle of what still needs to reach the station.
CREATE INDEX IF NOT EXISTS idx_outbox_pending
    ON outbox_entries (author, position) WHERE acked_outcome IS NULL;
