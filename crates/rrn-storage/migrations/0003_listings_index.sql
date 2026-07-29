-- Materialized listing index: a cache over the log, one row per listing.
--
-- The log is canonical (ADR-0010). Every row here is derivable by replaying the
-- marketplace records, this table is authoritative over nothing, and dropping it
-- is always a safe repair — `rrn-marketplace::search` rebuilds it from a full
-- replay. It exists so that browsing does not mean replaying: filters answer
-- from an index instead of walking the log once per query.
--
-- `listing_cbor` carries the whole listing so a result set can be returned
-- without going back to the log for each hit, which would put the cost this
-- table removes straight back. ADR-0010 leaves the index schema an
-- implementation detail precisely so it can carry what makes reads cheap.
--
-- `status` holds only what the log *says*: 'active' or 'closed'. Expiry is
-- deliberately NOT baked in, because a listing expires with the passage of time
-- and no new record — a stored 'expired' would silently become wrong as the
-- clock moved, and would need a sweep just to keep the cache honest. Queries
-- apply `expires_at` against the caller's `now` instead, so a row stays correct
-- however long it sits here.
CREATE TABLE listings_index (
    listing_id             BLOB PRIMARY KEY,
    provider               BLOB NOT NULL,
    surface                TEXT NOT NULL,
    category               TEXT NOT NULL,
    status                 TEXT NOT NULL,
    price_centi            INTEGER NOT NULL,
    reputation_at_creation REAL NOT NULL,
    created_at             INTEGER NOT NULL,
    expires_at             INTEGER,
    listing_cbor           BLOB NOT NULL
) STRICT;

-- The browse query: active listings narrowed by surface, category, and price.
CREATE INDEX listings_index_browse
    ON listings_index (status, surface, category, price_centi);

-- Sweeping for listings whose expiry has passed, so the station can close them.
CREATE INDEX listings_index_expiry
    ON listings_index (status, expires_at);

-- Everything one provider offers.
CREATE INDEX listings_index_provider
    ON listings_index (provider);
