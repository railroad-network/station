//! Model — the multidimensional reputation profile and its external view.
//!
//! A [`ReputationProfile`] holds the five dimensions of ADR-0009, each scored on
//! `0.0..=5.0`, and presents a single [`composite`](ReputationProfile::composite)
//! externally. The composite is a weighted average with the locked weights below
//! and a **full fixed divisor of 1.0** — dimensions that have no Phase-1 input
//! read `0.0` and genuinely pull the composite down, rather than being
//! renormalized away. That is what keeps the same log producing the same score
//! in every phase (ADR-0009, "The composite").
//!
//! The weights and band thresholds here are fixed at the federation-protocol
//! level; there is no config surface for them by design. Computing a profile
//! from the log is a separate concern ([`crate::scoring`], T1.5.4).

use std::collections::BTreeMap;

use rrn_identity::address::Address;

/// Weight of trade reliability in the composite (ADR-0009).
pub const WEIGHT_TRADE_RELIABILITY: f32 = 0.30;
/// Weight of attestation accuracy in the composite (ADR-0009).
pub const WEIGHT_ATTESTATION_ACCURACY: f32 = 0.25;
/// Weight of governance participation in the composite (ADR-0009).
pub const WEIGHT_GOVERNANCE_PARTICIPATION: f32 = 0.15;
/// Weight of community contribution in the composite (ADR-0009).
pub const WEIGHT_COMMUNITY_CONTRIBUTION: f32 = 0.15;
/// Weight of domain competence in the composite (ADR-0009).
pub const WEIGHT_DOMAIN_COMPETENCE: f32 = 0.15;

/// The maximum value any single dimension may reach.
pub const DIMENSION_MAX: f32 = 5.0;

/// Lower bound (inclusive) of the "Member" band (ADR-0009).
pub const BAND_MEMBER_MIN: f32 = 2.0;
/// Lower bound (inclusive) of the "Trusted" band (ADR-0009).
pub const BAND_TRUSTED_MIN: f32 = 3.5;
/// Lower bound (inclusive) of the "Senior" band (ADR-0009).
pub const BAND_SENIOR_MIN: f32 = 4.5;

/// A category label for domain competence, e.g. `"medical"`, `"agriculture"`,
/// `"construction"`.
///
/// The controlled vocabulary these are drawn from is defined by the marketplace
/// (M1.6/M1.7); Phase 1 produces no tags, so the competence map stays empty.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainTag(pub String);

/// A member's reputation across the five dimensions of ADR-0009.
///
/// This is a derived view over the log, not a stored source of truth: the same
/// log and the same clock always reduce to the same profile. Every dimension is
/// on `0.0..=5.0`; `domain_competence` is a per-category map that folds to a
/// single scalar in the [`composite`](Self::composite) (the mean across present
/// tags, or `0.0` when empty).
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationProfile {
    /// The identity this profile scores.
    pub address: Address,
    /// Count and recency of settled transactions (ADR-0009); the bedrock input.
    pub trade_reliability: f32,
    /// Ratio of this member's attestations that were not later proven wrong.
    pub attestation_accuracy: f32,
    /// Votes cast and proposals authored. Reads `0.0` until governance (M1.9).
    pub governance_participation: f32,
    /// Non-economic contribution. **Phase 1: always `0.0`** (no data source).
    pub community_contribution: f32,
    /// Per-category competence. **Phase 1: empty**, fed by the marketplace (M1.7).
    pub domain_competence: BTreeMap<DomainTag, f32>,
    /// Unix seconds the profile is computed as of (decay is relative to this).
    pub last_updated: i64,
}

impl ReputationProfile {
    /// A profile with no evidence yet: every dimension `0.0`, no domain tags,
    /// `last_updated` at the epoch. `composite()` is `0.0` and the band is
    /// [`ReputationBand::New`].
    pub fn empty(address: Address) -> Self {
        Self {
            address,
            trade_reliability: 0.0,
            attestation_accuracy: 0.0,
            governance_participation: 0.0,
            community_contribution: 0.0,
            domain_competence: BTreeMap::new(),
            last_updated: 0,
        }
    }

    /// The composite score: the ADR-0009 weighted average over all five
    /// dimensions, divided by the full fixed weight sum (1.0). Dimensions with
    /// no input read `0.0` and pull the composite down; they are not
    /// renormalized away. In Phase 1 the reachable maximum is 3.50 because
    /// community contribution and domain competence are structurally `0.0`.
    pub fn composite(&self) -> f32 {
        WEIGHT_TRADE_RELIABILITY * self.trade_reliability
            + WEIGHT_ATTESTATION_ACCURACY * self.attestation_accuracy
            + WEIGHT_GOVERNANCE_PARTICIPATION * self.governance_participation
            + WEIGHT_COMMUNITY_CONTRIBUTION * self.community_contribution
            + WEIGHT_DOMAIN_COMPETENCE * self.domain_competence_scalar()
    }

    /// The band the [`composite`](Self::composite) maps to (ADR-0009).
    pub fn band(&self) -> ReputationBand {
        ReputationBand::from_composite(self.composite())
    }

    /// Fold the per-category competence map into a single scalar: the mean over
    /// present tags, or `0.0` when the map is empty.
    fn domain_competence_scalar(&self) -> f32 {
        if self.domain_competence.is_empty() {
            0.0
        } else {
            let sum: f32 = self.domain_competence.values().sum();
            sum / self.domain_competence.len() as f32
        }
    }
}

/// The external presentation band of a composite score.
///
/// Boundaries are half-open (`[low, high)`), so a value exactly on a threshold
/// belongs to the higher band. In Phase 1, with the 3.50 composite ceiling,
/// every member lands in [`New`](Self::New) or [`Member`](Self::Member).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReputationBand {
    /// `[0.0, 2.0)` — a member with little or no demonstrated history.
    New,
    /// `[2.0, 3.5)` — an established member (the Phase-1 ceiling lands here).
    Member,
    /// `[3.5, 4.5)` — reachable only once domain competence has inputs (M1.7+).
    Trusted,
    /// `[4.5, 5.0]` — the top band; unreachable in Phase 1.
    Senior,
}

impl ReputationBand {
    /// Map a raw composite score to its band using the ADR-0009 half-open
    /// thresholds. Values below `0.0` fall in [`New`](Self::New); values at or
    /// above `4.5` fall in [`Senior`](Self::Senior).
    pub fn from_composite(composite: f32) -> Self {
        if composite < BAND_MEMBER_MIN {
            ReputationBand::New
        } else if composite < BAND_TRUSTED_MIN {
            ReputationBand::Member
        } else if composite < BAND_SENIOR_MIN {
            ReputationBand::Trusted
        } else {
            ReputationBand::Senior
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;

    fn test_address() -> Address {
        Address::from_public_key(Keypair::generate().public_key())
    }

    /// A profile whose composite is exactly `v`: because the weights sum to 1.0
    /// and every dimension (including the single domain tag) equals `v`, the
    /// weighted average collapses to `v`. Lets band boundaries be probed exactly.
    fn uniform_profile(v: f32) -> ReputationProfile {
        let mut domain_competence = BTreeMap::new();
        domain_competence.insert(DomainTag("medical".into()), v);
        ReputationProfile {
            address: test_address(),
            trade_reliability: v,
            attestation_accuracy: v,
            governance_participation: v,
            community_contribution: v,
            domain_competence,
            last_updated: 0,
        }
    }

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    #[test]
    fn empty_profile_is_zero_and_new() {
        let p = ReputationProfile::empty(test_address());
        assert!(approx(p.composite(), 0.0));
        assert_eq!(p.band(), ReputationBand::New);
    }

    #[test]
    fn composite_matches_manual_calculation() {
        // 0.30·4 + 0.25·3 + 0.15·2 + 0.15·0 + 0.15·0 = 1.20 + 0.75 + 0.30 = 2.25
        let p = ReputationProfile {
            address: test_address(),
            trade_reliability: 4.0,
            attestation_accuracy: 3.0,
            governance_participation: 2.0,
            community_contribution: 0.0,
            domain_competence: BTreeMap::new(),
            last_updated: 0,
        };
        assert!(approx(p.composite(), 2.25));
        assert_eq!(p.band(), ReputationBand::Member);
    }

    #[test]
    fn domain_competence_folds_to_its_mean() {
        let mut domain_competence = BTreeMap::new();
        domain_competence.insert(DomainTag("medical".into()), 4.0);
        domain_competence.insert(DomainTag("agriculture".into()), 2.0);
        // mean(4.0, 2.0) = 3.0; contribution 0.15·3.0 = 0.45.
        let p = ReputationProfile {
            address: test_address(),
            trade_reliability: 0.0,
            attestation_accuracy: 0.0,
            governance_participation: 0.0,
            community_contribution: 0.0,
            domain_competence,
            last_updated: 0,
        };
        assert!(approx(p.composite(), 0.45));
    }

    #[test]
    fn phase_one_ceiling_is_three_point_five() {
        // All Phase-1-live dimensions maxed; the two dark dimensions stay 0.0.
        // 0.30·5 + 0.25·5 + 0.15·5 = 1.50 + 1.25 + 0.75 = 3.50.
        let p = ReputationProfile {
            address: test_address(),
            trade_reliability: DIMENSION_MAX,
            attestation_accuracy: DIMENSION_MAX,
            governance_participation: DIMENSION_MAX,
            community_contribution: 0.0,
            domain_competence: BTreeMap::new(),
            last_updated: 0,
        };
        assert!(approx(p.composite(), 3.50));
    }

    #[test]
    fn bands_are_half_open_at_their_boundaries() {
        // Boundary values belong to the higher band.
        assert_eq!(ReputationBand::from_composite(0.0), ReputationBand::New);
        assert_eq!(ReputationBand::from_composite(1.999), ReputationBand::New);
        assert_eq!(ReputationBand::from_composite(2.0), ReputationBand::Member);
        assert_eq!(
            ReputationBand::from_composite(3.499),
            ReputationBand::Member
        );
        assert_eq!(ReputationBand::from_composite(3.5), ReputationBand::Trusted);
        assert_eq!(
            ReputationBand::from_composite(4.499),
            ReputationBand::Trusted
        );
        assert_eq!(ReputationBand::from_composite(4.5), ReputationBand::Senior);
        assert_eq!(ReputationBand::from_composite(5.0), ReputationBand::Senior);
    }

    #[test]
    fn band_delegates_to_composite() {
        // The uniform profile makes composite == v exactly, so the profile-level
        // band() agrees with from_composite() at each band's interior.
        assert_eq!(uniform_profile(1.0).band(), ReputationBand::New);
        assert_eq!(uniform_profile(2.5).band(), ReputationBand::Member);
        assert_eq!(uniform_profile(4.0).band(), ReputationBand::Trusted);
        assert_eq!(uniform_profile(5.0).band(), ReputationBand::Senior);
    }
}
