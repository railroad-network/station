CREATE TABLE attestations ( id BLOB PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL, signature BLOB NOT NULL, signer BLOB NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY (signer) REFERENCES identities (pubkey) ) STRICT
CREATE TABLE balances ( identity BLOB PRIMARY KEY, positive_increments BLOB NOT NULL, negative_increments BLOB NOT NULL ) STRICT
CREATE TABLE identities ( pubkey BLOB PRIMARY KEY, created_at INTEGER NOT NULL, metadata BLOB ) STRICT
CREATE TABLE issued_receipts ( presentation_hash BLOB NOT NULL PRIMARY KEY, receipt_envelope BLOB NOT NULL, issued_at INTEGER NOT NULL ) STRICT
CREATE TABLE kv ( key TEXT PRIMARY KEY, value BLOB ) STRICT
CREATE TABLE listings_index ( listing_id BLOB PRIMARY KEY, provider BLOB NOT NULL, surface TEXT NOT NULL, category TEXT NOT NULL, status TEXT NOT NULL, price_centi INTEGER NOT NULL, reputation_at_creation REAL NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER, listing_cbor BLOB NOT NULL ) STRICT
CREATE TABLE log_entries ( seq INTEGER PRIMARY KEY AUTOINCREMENT, prev_hash BLOB NOT NULL, content_hash BLOB NOT NULL, payload BLOB NOT NULL, created_at INTEGER NOT NULL ) STRICT
CREATE TABLE outbox_entries ( author BLOB NOT NULL, position INTEGER NOT NULL, entry_hash BLOB NOT NULL, prev_hash BLOB NOT NULL, record_hash BLOB NOT NULL, record_kind TEXT NOT NULL, envelope BLOB NOT NULL, authored_at INTEGER NOT NULL, acked_seq INTEGER, acked_outcome TEXT, refusal_reason TEXT, PRIMARY KEY (author, position) ) STRICT
CREATE TABLE outbox_forks ( author BLOB NOT NULL, position INTEGER NOT NULL, entry_hash_a BLOB NOT NULL, entry_hash_b BLOB NOT NULL, envelope_a BLOB NOT NULL, envelope_b BLOB NOT NULL, detected_at INTEGER NOT NULL, PRIMARY KEY (author, position) ) STRICT
CREATE TABLE receipt_deliveries ( record_hash BLOB NOT NULL PRIMARY KEY, author BLOB NOT NULL, receipt_presentation BLOB NOT NULL REFERENCES issued_receipts(presentation_hash), first_issued_at INTEGER NOT NULL, fetched_count INTEGER NOT NULL DEFAULT 0, confirmed_delivered INTEGER NOT NULL DEFAULT 0 ) STRICT
CREATE TABLE reputation_snapshots ( address BLOB PRIMARY KEY, last_computed_at INTEGER NOT NULL, profile_cbor BLOB NOT NULL ) STRICT
CREATE TABLE seen_outbox_entries ( author BLOB NOT NULL, position INTEGER NOT NULL, entry_hash BLOB NOT NULL, envelope BLOB NOT NULL, seen_at INTEGER NOT NULL, PRIMARY KEY (author, position) ) STRICT
CREATE TABLE seen_outbox_heads ( author BLOB NOT NULL PRIMARY KEY, position INTEGER NOT NULL, entry_hash BLOB NOT NULL, updated_at INTEGER NOT NULL ) STRICT
CREATE TABLE transactions ( id BLOB PRIMARY KEY, sender BLOB NOT NULL, receiver BLOB NOT NULL, amount_centicommons INTEGER NOT NULL, state TEXT NOT NULL, nonce INTEGER NOT NULL, proposed_at INTEGER NOT NULL, settled_at INTEGER ) STRICT
CREATE INDEX idx_attestations_signer ON attestations (signer)
CREATE INDEX idx_log_entries_content_hash ON log_entries (content_hash)
CREATE INDEX idx_outbox_pending ON outbox_entries (author, position) WHERE acked_outcome IS NULL
CREATE UNIQUE INDEX idx_outbox_record ON outbox_entries (author, record_hash)
CREATE INDEX idx_transactions_receiver ON transactions (receiver)
CREATE INDEX idx_transactions_sender ON transactions (sender)
CREATE INDEX idx_transactions_state ON transactions (state)
CREATE INDEX listings_index_browse ON listings_index (status, surface, category, price_centi)
CREATE INDEX listings_index_expiry ON listings_index (status, expires_at)
CREATE INDEX listings_index_provider ON listings_index (provider)
CREATE INDEX receipt_deliveries_author_pending ON receipt_deliveries (author, confirmed_delivered, first_issued_at)
