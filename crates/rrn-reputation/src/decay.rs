//! Decay — the time weighting that makes recent evidence count for more than
//! old evidence.
//!
//! Per ADR-0009 (design doc Section 5.5): each dimension drifts down by
//! [`MONTHLY_DECAY`] per 30-day month of elapsed time, floored at `0.0`, so
//! standing has to be maintained and a dormant identity cannot bank reputation
//! indefinitely. Domain competence decays per tag, independently.
//!
//! # Two ways in
//!
//! [`decayed`] is the kernel: one value, aged across one interval. [`crate::scoring`]
//! applies it per dimension, measuring from that dimension's own most recent
//! event, which is what makes a freshly scored profile "as of now".
//!
//! [`apply_decay`] ages a whole [`ReputationProfile`] forward from one instant to
//! another — the projection a cached snapshot needs when it is read later than it
//! was written, without replaying the log. The two agree by construction because
//! both reduce to [`decayed`].
//!
//! Decay is pure arithmetic over signed timestamps, identical on every station,
//! so projecting a profile forward never makes two replicas disagree.

use crate::model::ReputationProfile;

/// Points a dimension loses per 30-day month of elapsed time (ADR-0009 time
/// decay). Protocol-locked: a station that used a different rate would compute a
/// different score from the same log.
pub const MONTHLY_DECAY: f32 = 0.1;

/// Seconds in a 30-day reputation "month" — the decay unit of ADR-0009.
pub const SECONDS_PER_MONTH: f32 = 30.0 * 86_400.0;

/// Ages every dimension of `profile` forward from `from_time` to `to_time`,
/// flooring each at `0.0`, and moves `last_updated` to `to_time`.
///
/// Each entry of `domain_competence` decays on its own, so a member who stays
/// active in one domain still loses standing in the ones they have left.
///
/// Time only runs forward here: if `to_time` is not after `from_time` the profile
/// is left untouched, so a clock that steps backwards cannot inflate a score.
/// Because `last_updated` advances, the usual call is safe to repeat, and decaying
/// in two steps lands on the same values as one step over the whole interval.
/// Read the start instant out first — the borrow checker will not take it from
/// the profile being mutated:
///
/// ```
/// # use rrn_reputation::decay::apply_decay;
/// # use rrn_reputation::model::ReputationProfile;
/// # fn project(profile: &mut ReputationProfile, now: i64) {
/// let computed_at = profile.last_updated;
/// apply_decay(profile, computed_at, now);
/// # }
/// ```
pub fn apply_decay(profile: &mut ReputationProfile, from_time: i64, to_time: i64) {
    if to_time <= from_time {
        return;
    }
    for dimension in [
        &mut profile.trade_reliability,
        &mut profile.attestation_accuracy,
        &mut profile.governance_participation,
        &mut profile.community_contribution,
    ] {
        *dimension = decayed(*dimension, from_time, to_time);
    }
    for competence in profile.domain_competence.values_mut() {
        *competence = decayed(*competence, from_time, to_time);
    }
    profile.last_updated = to_time;
}

/// One dimension's `value`, aged from `from_time` to `to_time` and floored at
/// `0.0`: it loses [`MONTHLY_DECAY`] per elapsed 30-day month, counted
/// fractionally rather than in whole-month steps so the curve has no cliffs.
pub fn decayed(value: f32, from_time: i64, to_time: i64) -> f32 {
    (value - MONTHLY_DECAY * months_elapsed(from_time, to_time)).max(0.0)
}

/// Fractional 30-day months between the two instants, or `0.0` when `to_time` is
/// not after `from_time`.
pub fn months_elapsed(from_time: i64, to_time: i64) -> f32 {
    if to_time <= from_time {
        return 0.0;
    }
    to_time.saturating_sub(from_time) as f32 / SECONDS_PER_MONTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_identity::address::Address;

    use crate::model::DomainTag;

    const MONTH: i64 = 30 * 86_400;

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-6
    }

    /// A profile with every dimension at a known value, computed as of `t`.
    fn profile_at(t: i64) -> ReputationProfile {
        let address = Address::from_public_key(Keypair::generate().public_key());
        let mut profile = ReputationProfile::empty(address);
        profile.trade_reliability = 3.0;
        profile.attestation_accuracy = 2.5;
        profile.governance_participation = 1.0;
        profile.community_contribution = 0.5;
        profile
            .domain_competence
            .insert(DomainTag("medical".into()), 4.0);
        profile
            .domain_competence
            .insert(DomainTag("agriculture".into()), 0.05);
        profile.last_updated = t;
        profile
    }

    #[test]
    fn six_idle_months_cost_every_dimension_zero_point_six() {
        let t = 10 * MONTH;
        let mut profile = profile_at(t);
        apply_decay(&mut profile, t, t + 6 * MONTH);

        assert!(approx(profile.trade_reliability, 2.4));
        assert!(approx(profile.attestation_accuracy, 1.9));
        assert!(approx(profile.governance_participation, 0.4));
        assert!(approx(profile.community_contribution, 0.0)); // 0.5 − 0.6, floored
        assert_eq!(profile.last_updated, t + 6 * MONTH);
    }

    #[test]
    fn dimensions_floor_at_zero_however_long_the_gap() {
        let t = 10 * MONTH;
        let mut profile = profile_at(t);
        // A century of silence: far past what would take any dimension negative.
        apply_decay(&mut profile, t, t + 1200 * MONTH);

        assert!(approx(profile.trade_reliability, 0.0));
        assert!(approx(profile.attestation_accuracy, 0.0));
        assert!(approx(profile.governance_participation, 0.0));
        assert!(approx(profile.community_contribution, 0.0));
        for (tag, value) in &profile.domain_competence {
            assert!(approx(*value, 0.0), "{tag:?} = {value}");
        }
        assert!(approx(profile.composite(), 0.0));
    }

    #[test]
    fn each_domain_tag_decays_on_its_own() {
        let t = 10 * MONTH;
        let mut profile = profile_at(t);
        apply_decay(&mut profile, t, t + 2 * MONTH);

        let medical = profile.domain_competence[&DomainTag("medical".into())];
        let agriculture = profile.domain_competence[&DomainTag("agriculture".into())];
        assert!(approx(medical, 3.8), "medical = {medical}");
        // 0.05 − 0.2 would be negative: this tag floors while the other does not.
        assert!(approx(agriculture, 0.0), "agriculture = {agriculture}");
    }

    #[test]
    fn elapsed_months_are_fractional_not_stepped() {
        let t = 10 * MONTH;
        let mut profile = profile_at(t);
        // Half a month: a tenth of the monthly loss per half-month, no cliff.
        apply_decay(&mut profile, t, t + MONTH / 2);
        assert!(
            approx(profile.trade_reliability, 2.95),
            "trade = {}",
            profile.trade_reliability
        );
    }

    #[test]
    fn time_that_does_not_move_forward_changes_nothing() {
        let t = 10 * MONTH;
        let before = profile_at(t);

        let mut same_instant = before.clone();
        apply_decay(&mut same_instant, t, t);
        assert_eq!(same_instant, before);

        // A backwards clock must not hand out reputation.
        let mut backwards = before.clone();
        apply_decay(&mut backwards, t, t - 5 * MONTH);
        assert_eq!(backwards, before);
    }

    #[test]
    fn decaying_in_two_steps_matches_one_long_step() {
        let t = 10 * MONTH;
        let mut direct = profile_at(t);
        let mut stepwise = direct.clone();

        let from = stepwise.last_updated;
        apply_decay(&mut stepwise, from, t + 3 * MONTH);
        let midpoint = stepwise.last_updated;
        apply_decay(&mut stepwise, midpoint, t + 7 * MONTH);
        apply_decay(&mut direct, t, t + 7 * MONTH);

        // Compared approximately: the two paths round differently in the last
        // bits of an f32, which is not a disagreement about the score.
        assert!(approx(stepwise.trade_reliability, direct.trade_reliability));
        assert!(approx(
            stepwise.attestation_accuracy,
            direct.attestation_accuracy
        ));
        assert!(approx(
            stepwise.governance_participation,
            direct.governance_participation
        ));
        assert!(approx(
            stepwise.community_contribution,
            direct.community_contribution
        ));
        for (tag, value) in &stepwise.domain_competence {
            assert!(approx(*value, direct.domain_competence[tag]), "{tag:?}");
        }
        assert_eq!(stepwise.last_updated, direct.last_updated);
    }
}
