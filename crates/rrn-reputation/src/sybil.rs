//! Sybil resistance — the velocity cap and identity anchoring that stop fake
//! identities from fast-building reputation.
//!
//! Per ADR-0009: a dimension may gain at most 0.5 per week (excess is flagged
//! for human review, not auto-punished), and a fresh identity is capped at 1.0
//! per dimension until it receives a vouch from an established member.
//! Implemented in T1.5.8; this is a Phase 1 scaffold placeholder.
