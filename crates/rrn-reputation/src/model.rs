//! Model — the multidimensional reputation profile and its external view.
//!
//! Holds the `ReputationProfile` (five dimensions, each `0.0..=5.0`), its
//! `composite()` weighted average, and the `ReputationBand` it maps to. The
//! weights and band thresholds are fixed by ADR-0009 and are not
//! community-tunable. Implemented in T1.5.3; this is a Phase 1 scaffold
//! placeholder.
