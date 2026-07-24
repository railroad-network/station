//! Decay — the time weighting that makes recent evidence count for more than
//! old evidence.
//!
//! Per ADR-0009 (design doc Section 5.5): each dimension drifts down by 0.1 per
//! 30-day month of elapsed time, floored at 0.0, so standing has to be
//! maintained and a dormant identity cannot bank reputation indefinitely.
//! Implemented in T1.5.6; this is a Phase 1 scaffold placeholder.
