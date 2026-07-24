-- Materialized reputation profiles: a cache over the log, one row per identity.
-- The log is canonical; a snapshot is only a fast read of what replaying the log
-- would produce (see rrn-reputation::snapshot). `profile_cbor` is the canonical
-- CBOR of a ReputationProfile; `last_computed_at` is the Unix-seconds instant the
-- snapshot was scored as of, and carries last-write-wins semantics — a refresh
-- only overwrites a row when its computation is at least as recent, so an older
-- recompute can never clobber a newer one.
CREATE TABLE reputation_snapshots (
    address          BLOB PRIMARY KEY,
    last_computed_at INTEGER NOT NULL,
    profile_cbor     BLOB NOT NULL
) STRICT;
