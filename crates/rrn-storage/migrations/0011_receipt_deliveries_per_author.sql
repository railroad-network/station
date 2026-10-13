-- Receipt-delivery rows are per (record, author), and remember whether the
-- answer they point at can still change (ADR-0020 Clarification, receipt
-- idempotency).
--
-- Migration 0007 keyed `receipt_deliveries` on `record_hash` alone, so whoever
-- first presented a record under their own valid entry signature owned its row
-- and the record's real author fetched nothing. A row is now keyed on
-- `(record_hash, author)`, where `author` is the attested outer author of the
-- presenting entry: each presenter's answer travels back to that presenter.
--
--   outcome_final  INTEGER 1 when the receipt this row points at reported an
--                          outcome re-presentation cannot change (admitted,
--                          known, or a final refusal); 0 for a transient
--                          refusal. A re-evaluated presentation re-points a
--                          transient row at its new receipt and re-arms its
--                          delivery; a final row's delivery progress is never
--                          reset.
--
-- Still station-role local state, never community-log state (see 0006/0007).
-- SQLite cannot change a primary key in place, so the table is rebuilt:
-- create, copy (every existing row was written as a final answer's row, so it
-- is copied with outcome_final = 1), drop, rename. The foreign key into
-- issued_receipts and the author-pending index are kept.
CREATE TABLE receipt_deliveries_new (
    record_hash          BLOB NOT NULL,
    author               BLOB NOT NULL,
    receipt_presentation BLOB NOT NULL REFERENCES issued_receipts(presentation_hash),
    first_issued_at      INTEGER NOT NULL,
    fetched_count        INTEGER NOT NULL DEFAULT 0,
    confirmed_delivered  INTEGER NOT NULL DEFAULT 0,
    outcome_final        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (record_hash, author)
) STRICT;

INSERT INTO receipt_deliveries_new
    (record_hash, author, receipt_presentation, first_issued_at,
     fetched_count, confirmed_delivered, outcome_final)
SELECT record_hash, author, receipt_presentation, first_issued_at,
       fetched_count, confirmed_delivered, 1
FROM receipt_deliveries;

DROP INDEX IF EXISTS receipt_deliveries_author_pending;
DROP TABLE receipt_deliveries;
ALTER TABLE receipt_deliveries_new RENAME TO receipt_deliveries;

CREATE INDEX IF NOT EXISTS receipt_deliveries_author_pending
    ON receipt_deliveries (author, confirmed_delivered, first_issued_at);
