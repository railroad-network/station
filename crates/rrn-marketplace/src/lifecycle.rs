//! Listing lifecycle — `Active`, `Expired`, `Closed`, derived by replaying the
//! log entries that concern one listing.
//!
//! No state is stored: a listing's current state is what its `listing.v1`,
//! `listing_updated.v1` and `listing_closed.v1` entries reduce to, exactly as
//! transaction state reduces from its own records. `Expired` is derived rather
//! than recorded — the log cannot notice time passing on its own — and the
//! station's sweep is what turns it into a real close entry.
//!
//! Implemented in T1.6.5; this is a Phase 1 skeleton placeholder.
