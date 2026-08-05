//! The oracle tier ladder (Overview §4.3), realized for Phase 1.
//!
//! A transaction's **oracle tier** sets how much scrutiny moving its Commons
//! requires. Phase 1 implements the first two rungs:
//!
//! - **Tier 1** (under 5 Commons) — bilateral confirmation plus the delayed
//!   settlement window. Low friction; some fraud is tolerated at micro scale.
//! - **Tier 2** (5 to under 50 Commons) — Tier 1 plus a reputation **stake** by
//!   the confirmer, and the settlement window doubles as a **dispute window**.
//!
//! Tiers 3 and 4 (physical artifacts, community witnesses, cross-community
//! validation) arrive in Phase 2 and are out of range here — see
//! [`MAX_PHASE1_TIER`].
//!
//! # The ladder is derived, not stored
//!
//! A transaction's **floor** tier is a pure function of its amount, so the
//! sender and the settling station compute it identically with nothing on the
//! wire ([`tier_floor`]). Only an *opt-up* — a party or listing electing a
//! higher tier than the amount alone requires — needs recording; see
//! [`crate::transaction::TransactionProposal::oracle_tier`]. The tier that
//! actually governs a transaction is [`effective_tier`], the higher of the two.
//!
//! # Phase 1 does not lower the tier — it blocks
//!
//! Tiers 3 and 4 need machinery Phase 1 lacks. Rather than *clamp* a large
//! transaction down to Tier 2 — which would silently weaken the scrutiny its
//! value demands — Phase 1 **rejects** any transaction whose [`effective_tier`]
//! exceeds [`MAX_PHASE1_TIER`] (see [`is_phase1_serviceable`] and
//! [`crate::Error::TierNotSupported`]). Value sets the floor and is never
//! lowered (Overview §4.3).
//!
//! # Sign does not lower the tier
//!
//! The floor is computed on the **absolute** amount, so a large refund or
//! Commons draw (a non-positive `amount_centi`, see the sign convention in
//! [`crate::transaction`]) carries the same tier — and the same stake/dispute
//! protection — as the equivalent payment. A party cannot escape scrutiny by
//! flipping the direction of a transfer.

/// Centicommons at or above which a transaction is at least **Tier 2**
/// (5 Commons). The Tier 1 → Tier 2 boundary is half-open: exactly 5 Commons is
/// Tier 2.
pub const TIER_2_FLOOR_CENTI: i64 = 500;

/// Centicommons at or above which the ladder places a transaction at **Tier 3**
/// (50 Commons). Phase 1 cannot service Tier 3 ([`MAX_PHASE1_TIER`]), so a
/// transaction this large — or larger — is *rejected*, not serviced at a lower
/// tier (see [`is_phase1_serviceable`]).
pub const TIER_3_FLOOR_CENTI: i64 = 5_000;

/// The lowest oracle tier. Every transaction is at least this.
pub const MIN_TIER: u8 = 1;

/// The highest oracle tier Phase 1 realizes. A transaction whose
/// [`effective_tier`] would exceed this is **rejected** ([`is_phase1_serviceable`]),
/// and an opt-up above it is dropped — the machinery those tiers need (artifact
/// evidence, community witnesses, cross-community validation) does not exist
/// until Phase 2.
pub const MAX_PHASE1_TIER: u8 = 2;

/// The oracle tier an amount *requires* on its own, ignoring any opt-up.
///
/// A pure function of the absolute amount, per the half-open bands of
/// Overview §4.3. Returns the true ladder value, which can exceed
/// [`MAX_PHASE1_TIER`] (a Tier-3 amount returns `3`); such a transaction is
/// later rejected by [`is_phase1_serviceable`] rather than serviced at a lower
/// tier.
pub fn tier_floor(amount_centi: i64) -> u8 {
    // Absolute value, so direction never lowers the tier. `saturating_abs`
    // keeps `i64::MIN` from overflowing rather than panicking.
    let magnitude = amount_centi.saturating_abs();
    if magnitude < TIER_2_FLOOR_CENTI {
        1
    } else if magnitude < TIER_3_FLOOR_CENTI {
        2
    } else {
        // 50 Commons and up is Tier 3; Phase 1 blocks it (is_phase1_serviceable).
        3
    }
}

/// The tier that actually governs a transaction: the higher of its amount floor
/// and any recorded opt-up.
///
/// `opt_up` is the proposal's optional [`oracle_tier`](crate::transaction::TransactionProposal::oracle_tier)
/// — `None` for a plain transaction that takes its amount's floor. A transaction
/// may be lifted *up* the ladder (a listing or either party asking for more
/// scrutiny than the amount requires) but never down, which the `max` enforces.
/// The result is **not** capped: a Tier-3 amount yields `3`, which
/// [`is_phase1_serviceable`] then blocks — Phase 1 refuses such a transaction
/// rather than quietly weakening its tier.
pub fn effective_tier(amount_centi: i64, opt_up: Option<u8>) -> u8 {
    tier_floor(amount_centi).max(opt_up.unwrap_or(MIN_TIER))
}

/// Whether Phase 1 can actually service a transaction at `tier`.
///
/// Tiers 3 and 4 need machinery (artifact evidence, community witnesses,
/// cross-community validation) that arrives in Phase 2, so a transaction whose
/// [`effective_tier`] exceeds [`MAX_PHASE1_TIER`] is rejected at the engine's
/// front door ([`crate::Error::TierNotSupported`]) — value sets the floor and is
/// never lowered.
pub fn is_phase1_serviceable(tier: u8) -> bool {
    tier <= MAX_PHASE1_TIER
}

/// Whether `opt_up` is a valid opt-up for a transaction of `amount_centi`.
///
/// A stored opt-up is only meaningful when it lifts the tier: it must be
/// strictly above the amount's own floor (an opt-up equal to or below the floor
/// is redundant and rejected, so there is one canonical encoding), and no higher
/// than [`MAX_PHASE1_TIER`] (Phase 1 cannot service Tier 3+, and an amount whose
/// floor already reaches Tier 3 admits no valid opt-up — it is blocked outright).
/// Returns `true` for a genuine opt-up.
pub fn is_valid_opt_up(amount_centi: i64, opt_up: u8) -> bool {
    opt_up > tier_floor(amount_centi) && opt_up <= MAX_PHASE1_TIER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_bands_are_half_open() {
        assert_eq!(tier_floor(0), 1);
        assert_eq!(tier_floor(499), 1);
        // Exactly 5 Commons is Tier 2 (half-open at the low edge).
        assert_eq!(tier_floor(500), 2);
        assert_eq!(tier_floor(4_999), 2);
        // Exactly 50 Commons is Tier 3 on the raw ladder.
        assert_eq!(tier_floor(5_000), 3);
    }

    #[test]
    fn floor_ignores_sign() {
        assert_eq!(tier_floor(-499), 1);
        assert_eq!(tier_floor(-500), 2);
        assert_eq!(tier_floor(-5_000), 3);
        // The pathological extreme must not panic.
        assert_eq!(tier_floor(i64::MIN), 3);
    }

    #[test]
    fn effective_tier_takes_the_higher_without_clamping() {
        // No opt-up: takes the floor.
        assert_eq!(effective_tier(100, None), 1);
        assert_eq!(effective_tier(500, None), 2);
        // Opt-up lifts a small amount to Tier 2.
        assert_eq!(effective_tier(100, Some(2)), 2);
        // Opt-up below the floor cannot lower it.
        assert_eq!(effective_tier(500, Some(1)), 2);
        // A Tier-3 amount reports its true tier — no clamp; the engine blocks it.
        assert_eq!(effective_tier(5_000, None), 3);
        assert_eq!(effective_tier(50_000, None), 3);
    }

    #[test]
    fn phase1_services_tiers_1_and_2_only() {
        assert!(is_phase1_serviceable(1));
        assert!(is_phase1_serviceable(2));
        assert!(!is_phase1_serviceable(3));
        assert!(!is_phase1_serviceable(4));
        // A Tier-3 amount's effective tier is not serviceable.
        assert!(!is_phase1_serviceable(effective_tier(5_000, None)));
    }

    #[test]
    fn opt_up_validity() {
        // A genuine lift from Tier 1 to Tier 2.
        assert!(is_valid_opt_up(100, 2));
        // Redundant: equal to or below the floor.
        assert!(!is_valid_opt_up(100, 1));
        assert!(!is_valid_opt_up(500, 2));
        // Above the Phase-1 ceiling.
        assert!(!is_valid_opt_up(100, 3));
        // A Tier-3 amount's floor is already 3, so no opt-up (capped at 2) can
        // lift it — it is blocked outright, not opt-upped.
        assert!(!is_valid_opt_up(5_000, 2));
    }
}
