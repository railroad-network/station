-- Station-originated DTN push tracking (ADR-0020 §3).
--
-- When a station *originates* an outbound bundle push to a named peer over a
-- dumb carrier (Reticulum/LoRa), it tracks the attempt here until the peer's
-- signed delivery receipt comes back and is correlated. This is the durable
-- record that survives an adapter re-spawn: the in-memory `DtnSyncer` rebuilds a
-- fresh retransmit cache on every (re)start, so a push already handed to a dead
-- syncer would be lost without this table — the outbound loop re-sends every
-- undelivered, un-abandoned row from here on each start and on a periodic
-- re-scan.
--
-- Like the rest of `rrn-storage::dtn` (migrations 0006/0007) this is station-role
-- LOCAL delivery metadata, NOT community-log state: none of it is signed, none
-- is replayed, and a replica re-derives nothing from it (ADR-0020 §1). The log
-- stays the single source of truth; the records a push carries were already
-- signed by their authors, and only the *receiving* station's front door admits
-- them — originating a push appends nothing to the community log.
--
--   push_id          BLOB    the bundle's presentation hash (Blake3 over the
--                             ordered record-hash list) — the same idempotency
--                             key the receiver keys its receipt on, so a
--                             re-push of an identical presentation is one row.
--   peer             TEXT    the carrier destination the push was sent to
--                             (an opaque Reticulum destination hex / Endpoint).
--   expected_station BLOB    32-byte address key the push was addressed to when
--                             resolved from an `rrn.net.binding` (NULL for a
--                             bare-endpoint push) — the returned receipt's signer
--                             must match it before the row is marked delivered.
--   bundle           BLOB    the encoded bundle bytes, re-sent verbatim on
--                             every retransmit.
--   record_hashes    BLOB    the presented record hashes concatenated (32·n, in
--                             presented order) — introspection/diagnostics.
--   priority         INTEGER the airtime class the bundle is paced at (the
--                             highest among its records; Economic=0/Gov=1/Bulk=2).
--   queued_at        INTEGER admission-clock reading when first queued
--                             (testimony); the TTL/abandonment clock keys on it.
--   last_sent_at     INTEGER admission-clock reading when the loop last handed
--                             this row to the syncer, or NULL if never (a fresh
--                             row a rescan has not yet re-sent).
--   attempts         INTEGER how many times the loop has (re-)sent this push.
--   delivered_at     INTEGER admission-clock reading when a matching receipt was
--                             correlated, or NULL while pending.
--   receipt          BLOB    the correlated signed-receipt envelope bytes, or
--                             NULL while pending.
--   abandoned_at     INTEGER admission-clock reading when the row passed
--                             push_ttl_secs with no receipt, or NULL. An
--                             abandoned economic push fails *legibly* (shown by
--                             `rrn dtn status`) — never silently dropped.
CREATE TABLE IF NOT EXISTS dtn_pushes (
    push_id          BLOB NOT NULL PRIMARY KEY,
    peer             TEXT NOT NULL,
    expected_station BLOB,
    bundle           BLOB NOT NULL,
    record_hashes    BLOB NOT NULL,
    priority         INTEGER NOT NULL,
    queued_at        INTEGER NOT NULL,
    last_sent_at     INTEGER,
    attempts         INTEGER NOT NULL DEFAULT 0,
    delivered_at     INTEGER,
    receipt          BLOB,
    abandoned_at     INTEGER
) STRICT;

-- "Pending pushes to (re-)send" (the outbound loop's fetch) filters on
-- delivered_at IS NULL AND abandoned_at IS NULL; index it so a loop start / rescan
-- does not scan delivered and abandoned history.
CREATE INDEX IF NOT EXISTS dtn_pushes_pending
    ON dtn_pushes (delivered_at, abandoned_at);
