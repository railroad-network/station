CREATE TABLE attestations ( id BLOB PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL, signature BLOB NOT NULL, signer BLOB NOT NULL, created_at INTEGER NOT NULL, FOREIGN KEY (signer) REFERENCES identities (pubkey) ) STRICT
CREATE TABLE balances ( identity BLOB PRIMARY KEY, positive_increments BLOB NOT NULL, negative_increments BLOB NOT NULL ) STRICT
CREATE TABLE identities ( pubkey BLOB PRIMARY KEY, created_at INTEGER NOT NULL, metadata BLOB ) STRICT
CREATE TABLE kv ( key TEXT PRIMARY KEY, value BLOB ) STRICT
CREATE TABLE log_entries ( seq INTEGER PRIMARY KEY AUTOINCREMENT, prev_hash BLOB NOT NULL, content_hash BLOB NOT NULL, payload BLOB NOT NULL, created_at INTEGER NOT NULL ) STRICT
CREATE TABLE transactions ( id BLOB PRIMARY KEY, sender BLOB NOT NULL, receiver BLOB NOT NULL, amount_centicommons INTEGER NOT NULL, state TEXT NOT NULL, nonce INTEGER NOT NULL, proposed_at INTEGER NOT NULL, settled_at INTEGER ) STRICT
CREATE INDEX idx_attestations_signer ON attestations (signer)
CREATE INDEX idx_transactions_receiver ON transactions (receiver)
CREATE INDEX idx_transactions_sender ON transactions (sender)
CREATE INDEX idx_transactions_state ON transactions (state)
