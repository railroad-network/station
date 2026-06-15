-- 0001_initial — initial Railroad Network storage schema.
--
-- Conventions:
--   * Public keys, hashes, signatures, transaction/attestation ids: raw BLOBs.
--   * Timestamps: INTEGER, Unix seconds, signed 64-bit (i64).
--   * Monetary amounts: INTEGER centicommons (1 Common = 100 centicommons) —
--     never floats, anywhere.
--
-- Migrations are immutable once shipped. To change the schema, add a new
-- numbered migration; never edit this file.

-- Decentralized identities: one row per known public key.
CREATE TABLE identities (
    pubkey     BLOB PRIMARY KEY,
    created_at INTEGER NOT NULL,
    metadata   BLOB
) STRICT;

-- Signed attestations (vouches and, later, other Attestation kinds). `payload`
-- holds the canonical CBOR bytes that `signature` covers.
CREATE TABLE attestations (
    id         BLOB PRIMARY KEY,
    kind       TEXT NOT NULL,
    payload    BLOB NOT NULL,
    signature  BLOB NOT NULL,
    signer     BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (signer) REFERENCES identities (pubkey)
) STRICT;

-- The append-only, hash-chained signed log — the source of truth. `payload`
-- holds the serialized SignedPayload envelope; `content_hash` is Blake3 over the
-- canonical bytes of the inner signed value; `prev_hash` chains to the previous
-- entry's `content_hash` (all-zero for the first entry).
CREATE TABLE log_entries (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    prev_hash    BLOB NOT NULL,
    content_hash BLOB NOT NULL,
    payload      BLOB NOT NULL,
    created_at   INTEGER NOT NULL
) STRICT;

-- Mutual-credit transactions. `amount_centicommons` is integer centicommons;
-- `state` is the lifecycle stage (proposed/confirmed/settled/...); `settled_at`
-- is NULL until settlement.
CREATE TABLE transactions (
    id                  BLOB PRIMARY KEY,
    sender              BLOB NOT NULL,
    receiver            BLOB NOT NULL,
    amount_centicommons INTEGER NOT NULL,
    state               TEXT NOT NULL,
    nonce               INTEGER NOT NULL,
    proposed_at         INTEGER NOT NULL,
    settled_at          INTEGER
) STRICT;

-- PN-Counter balances, one row per identity. A PN-Counter is per-replica, so
-- each column holds a canonical-CBOR map ReplicaId -> u64 (not a scalar): the
-- positive (increment) and negative (decrement) G-Counters. The materialized
-- balance is sum(positive) - sum(negative), computed on load.
CREATE TABLE balances (
    identity            BLOB PRIMARY KEY,
    positive_increments BLOB NOT NULL,
    negative_increments BLOB NOT NULL
) STRICT;

-- General-purpose key/value store for miscellaneous serialized state
-- (e.g. OR-Set / LWW-Register blobs keyed by name).
CREATE TABLE kv (
    key   TEXT PRIMARY KEY,
    value BLOB
) STRICT;

CREATE INDEX idx_attestations_signer ON attestations (signer);
CREATE INDEX idx_transactions_state ON transactions (state);
CREATE INDEX idx_transactions_sender ON transactions (sender);
CREATE INDEX idx_transactions_receiver ON transactions (receiver);
