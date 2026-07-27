//! Search — discovery over the set of active listings.
//!
//! Filters run against the materialized index; text relevance comes from
//! tantivy; provider reputation multiplies the relevance score, so standing
//! breaks ties rather than surfacing irrelevant listings. Reputation is read
//! from the M1.5 snapshot cache and never recomputed per result — scoring is
//! O(N) in the log, and a page of results must not become a page of replays.
//!
//! Implemented in T1.6.6 (index and search) and T1.6.7 (matching a stated need
//! against supply); this is a Phase 1 skeleton placeholder.
