-- Station-role DTN state (ADR-0020 §3-§4; T2.2.3).
--
-- These tables are the *station's* record of the delay-tolerant submission
-- machinery — distinct from `outbox_entries` (0005), which is a *device's* own
-- outbox. They are station-role local state, NOT the community log: none of it
-- is signed community state, none is replayed, and a replica re-derives nothing
-- from it. The log stays the single source of truth (ADR-0020 §1); these tables
-- are caches and evidence the station keeps to make ingest idempotent, to track
-- each remote author's chain, and to preserve equivocation evidence.
--
-- Layering note: `rrn-storage` sits below `rrn-protocol`, so it cannot parse an
-- outbox entry or a receipt. As with 0005, rows hold opaque, already-validated
-- bytes and pre-extracted scalar columns; the station layer (which has
-- `rrn-protocol`) validates and supplies the columns.

-- The station's record of each remote author's highest *contiguously seen*
-- outbox position — the head of the run it has received without a gap. A gap
-- (ADR-0020 §2) does not advance the head; filling the gap later does. One row
-- per author. A cache derived from `seen_outbox_entries` below.
--   author      BLOB    32-byte pubkey of the chain owner
--   position    INTEGER highest contiguous position seen (0-based)
--   entry_hash  BLOB    Blake3 of that entry's canonical bytes
--   updated_at  INTEGER admission-clock reading when last advanced (testimony)
CREATE TABLE IF NOT EXISTS seen_outbox_heads (
    author     BLOB NOT NULL PRIMARY KEY,
    position   INTEGER NOT NULL,
    entry_hash BLOB NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Every distinct (author, position) the station has seen, with the winning
-- entry's hash and its raw envelope bytes. This is the per-position memory the
-- head advances across when a gap fills, and the store fork detection compares
-- an incoming entry against: a second entry at an already-seen position with a
-- *different* hash is an outbox fork (recorded below); with the *same* hash it
-- is a benign duplicate. The envelope is kept so fork evidence can cite the
-- earlier side even when it arrived in a prior bundle.
--   author      BLOB    32-byte pubkey of the chain owner
--   position    INTEGER 0-based position in the author's chain
--   entry_hash  BLOB    Blake3 of the entry's canonical bytes
--   envelope    BLOB    the signed outbox-entry envelope bytes (evidence)
--   seen_at     INTEGER admission-clock reading when first seen (testimony)
CREATE TABLE IF NOT EXISTS seen_outbox_entries (
    author     BLOB NOT NULL,
    position   INTEGER NOT NULL,
    entry_hash BLOB NOT NULL,
    envelope   BLOB NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (author, position)
) STRICT;

-- Persisted outbox-fork evidence (ADR-0020 §2 / ADR-0021): two validly-signed
-- entries by one author at the same position with different content. Both raw
-- envelopes are kept verbatim as the equivocation proof T2.3.3 consumes. One
-- row per (author, position) fork — the first conflicting pair detected.
--   author       BLOB    32-byte pubkey of the equivocating author
--   position     INTEGER the shared position
--   entry_hash_a BLOB    Blake3 of the earlier-seen (stored) entry
--   entry_hash_b BLOB    Blake3 of the later-arriving (refused) entry
--   envelope_a   BLOB    the earlier entry's envelope bytes
--   envelope_b   BLOB    the later entry's envelope bytes
--   detected_at  INTEGER admission-clock reading at detection (testimony)
CREATE TABLE IF NOT EXISTS outbox_forks (
    author       BLOB NOT NULL,
    position     INTEGER NOT NULL,
    entry_hash_a BLOB NOT NULL,
    entry_hash_b BLOB NOT NULL,
    envelope_a   BLOB NOT NULL,
    envelope_b   BLOB NOT NULL,
    detected_at  INTEGER NOT NULL,
    PRIMARY KEY (author, position)
) STRICT;

-- Issued delivery receipts, keyed by the bundle's *presentation hash* (Blake3
-- over the ordered record-hash list of the bundle) so re-ingesting a
-- byte-identical presentation returns the stored receipt verbatim — the
-- idempotency guarantee of ADR-0020 §3. A receipt is transport state, never
-- community state (it is never appended to the log).
--   presentation_hash BLOB    Blake3 over the ordered record hashes
--   receipt_envelope  BLOB    the signed-receipt envelope bytes returned
--   issued_at         INTEGER admission-clock reading at issue (testimony)
CREATE TABLE IF NOT EXISTS issued_receipts (
    presentation_hash BLOB NOT NULL PRIMARY KEY,
    receipt_envelope  BLOB NOT NULL,
    issued_at         INTEGER NOT NULL
) STRICT;
