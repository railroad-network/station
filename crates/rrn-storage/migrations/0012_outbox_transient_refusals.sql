-- A pending outbox row remembers the last transient refusal it received
-- (ADR-0020 Clarification, receipt idempotency).
--
-- A record refused with a slug that can change (not-proposed, debt-floor, …)
-- is not acked: it stays pending and is carried again on the next submit. These
-- two columns let the wallet show the member *why* a row is still pending, so a
-- member can recognise one that will never succeed and abandon it. They are a
-- local display cache — never an input to whether a row is acked, carried, or
-- pruned.
--
--   last_refusal_reason TEXT    the most recent transient refusal slug for this
--                               still-pending row; NULL if none was received
--   last_refused_at     INTEGER the wallet's clock when that receipt was applied
--
-- `acked_outcome` (0005) also gains the value 'abandoned': the member told the
-- wallet to stop carrying the row. It is acked for pruning and bundling, and a
-- later 'admitted' or 'known' answer replaces it. The column has no CHECK
-- constraint, so the new value needs no schema change.
ALTER TABLE outbox_entries ADD COLUMN last_refusal_reason TEXT;
ALTER TABLE outbox_entries ADD COLUMN last_refused_at INTEGER;
