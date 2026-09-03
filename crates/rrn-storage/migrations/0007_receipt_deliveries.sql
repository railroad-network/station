-- Receipt-delivery tracking (ADR-0020 §3; T2.2.4).
--
-- Closes the DTN loop: a delivery receipt the station issued for an ingested
-- bundle must travel *back* to each record's author by the same dumb carriers
-- (ADR-0020 §3). This table is the station's outbound queue of pending receipts
-- — one row per record whose fate a receipt reported — so a courier can fetch a
-- pending receipt for records authored by *others* and carry it home, and the
-- author's own device can later confirm it delivered.
--
-- Like the rest of `rrn-storage::dtn` (migration 0006) this is station-role
-- local state, NOT community-log state: none of it is signed, none is replayed,
-- and a replica re-derives nothing from it. It is a queue and its bookkeeping;
-- the receipts it points at live in `issued_receipts` (0006), the single place a
-- receipt's bytes are stored.
--
--   record_hash          BLOB    Blake3 of the presented record's canonical bytes
--                                 (the receipt outcome's key). One row per record.
--   author               BLOB    32-byte pubkey of the record's author — indexed
--                                 so "pending receipts for these authors" is a
--                                 direct lookup (the courier/author fetch surface).
--   receipt_presentation BLOB    the presentation hash of the receipt that
--                                 reported this record, into issued_receipts. Many
--                                 records (a whole bundle) share one receipt.
--   first_issued_at      INTEGER admission-clock reading when the receipt was
--                                 first issued (testimony); the retention clock and
--                                 the oldest-first fetch order both key on it.
--   fetched_count        INTEGER how many times a receipt for this record has been
--                                 handed out (courier or author). Diagnostics only.
--   confirmed_delivered  INTEGER 1 once the record's *own author* fetched it over
--                                 the authenticated channel — an anonymous courier
--                                 fetch never sets this. Gates the retention sweep.
CREATE TABLE IF NOT EXISTS receipt_deliveries (
    record_hash          BLOB NOT NULL PRIMARY KEY,
    author               BLOB NOT NULL,
    receipt_presentation BLOB NOT NULL REFERENCES issued_receipts(presentation_hash),
    first_issued_at      INTEGER NOT NULL,
    fetched_count        INTEGER NOT NULL DEFAULT 0,
    confirmed_delivered  INTEGER NOT NULL DEFAULT 0
) STRICT;

-- "Pending receipts for author X" (the fetch surface) filters on author and
-- confirmed_delivered and orders by first_issued_at; index the lookup columns so
-- a courier or author fetch does not scan the whole queue.
CREATE INDEX IF NOT EXISTS receipt_deliveries_author_pending
    ON receipt_deliveries (author, confirmed_delivered, first_issued_at);
