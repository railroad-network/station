-- Local wallet metadata (ADR-0028).
--
-- A tiny string-keyed table for the self-custody CLI member wallet's own
-- bookkeeping: the pinned station address, the paired URL, the transport and
-- nonce cursors, the chain state, held certificates, and so on. It is
-- **unsigned local metadata**: not community-log state, never signed, never
-- replayed, and a replica re-derives nothing from it. It is the wallet's own,
-- co-located with the outbox in the same database so a backup of one directory
-- carries the chain *and* its cursors together.
--
-- The table is created empty in every station database too — harmless and
-- unused there, exactly like the station-only DTN tables a wallet database
-- carries. Only the `rrn wallet` command family reads or writes it.
--
-- Columns (see `wallet_meta.rs` for the typed accessor and the documented key
-- set):
--   key   TEXT the metadata key (e.g. 'role', 'station_address', 'nonce_cursor')
--   value TEXT the value, always stored as text (numbers are decimal strings)
CREATE TABLE IF NOT EXISTS wallet_meta (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
