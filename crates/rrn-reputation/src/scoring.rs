//! Scoring — replay the log into a `ReputationProfile`.
//!
//! Walks the log entries involving an address and applies each one's
//! contribution to the relevant dimension, then folds in time [`decay`], so the
//! same log and the same `now` always yield the same profile. The log is
//! canonical; the profile is a derived view. Implemented in T1.5.4; this is a
//! Phase 1 scaffold placeholder.
//!
//! [`decay`]: crate::decay
