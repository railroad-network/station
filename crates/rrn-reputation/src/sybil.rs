//! Sybil resistance — the velocity cap and identity anchoring that stop fake
//! identities from fast-building reputation.
//!
//! Per ADR-0009, as superseded in part by ADR-0038, Phase 1 leans on local,
//! deterministic defenses rather than the graph analysis a federation could
//! afford:
//!
//! - **The velocity cap** — the scorer credits at most
//!   [`CREDITED_EVENTS_PER_WINDOW`] event per dimension in any trailing
//!   [`VELOCITY_WINDOW_SECS`], which is [`VELOCITY_CAP_PER_WEEK`] of gain
//!   ([`credited_events`], ADR-0038 §10). However many events an identity
//!   generates, its standing grows at the same bounded rate, so establishment
//!   takes at least seven weeks of activity with enrolled counterparties.
//! - **Identity anchoring** — a fresh identity's dimensions are capped at
//!   [`ANCHOR_DIMENSION_CAP`] until it is anchored: reached by a chain of
//!   vouches from the founders, each judged once at the vouch (ADR-0038 §11). A
//!   Sybil cluster cannot bootstrap standing purely among itself; it has to
//!   corrupt an anchored member.
//!
//! # Credit is capped; penalties are never automatic
//!
//! The cap limits *credit*: it only slows the identity whose own activity is
//! being counted, so it cannot be pushed at anyone. ADR-0009's "flag, never
//! punish" still holds for penalties — nothing about a fast rate of activity
//! subtracts standing. [`check_velocity`] remains as an operator signal between
//! consecutive snapshots ([`crate::snapshot`]); with the cap in the scorer it
//! has no positive gain left to catch beyond decay arithmetic, and it never
//! edits a profile.

use rrn_crypto::keypair::PublicKey;
use rrn_identity::address::Address;
use rrn_storage::db::Database;

use crate::context::ScoringContext;
use crate::model::{DomainTag, ReputationProfile};
use crate::Result;

/// Most a single dimension may gain in one week before the gain is flagged
/// (ADR-0009). Protocol-locked.
pub const VELOCITY_CAP_PER_WEEK: f32 = 0.5;

/// Seconds in the velocity cap's week.
const SECONDS_PER_WEEK: f32 = 7.0 * 86_400.0;

/// The velocity cap's trailing window: exactly seven days of 86,400 seconds,
/// never a calendar week (ADR-0038 §10). Protocol-locked.
pub const VELOCITY_WINDOW_SECS: i64 = 7 * 86_400;

/// How many events one dimension credits within any trailing
/// [`VELOCITY_WINDOW_SECS`] — [`VELOCITY_CAP_PER_WEEK`] over the per-event
/// increment (ADR-0038 §10). Protocol-locked.
pub const CREDITED_EVENTS_PER_WINDOW: u32 = 1;

/// The credited subset of a dimension's eligible event times (ADR-0038 §10),
/// ascending. Walking the times in ascending order, an event at `t` is credited
/// only if fewer than [`CREDITED_EVENTS_PER_WINDOW`] credited events already fall
/// in the half-open window `(t − VELOCITY_WINDOW_SECS, t]`.
///
/// A pure function of the multiset of times: the input order does not matter.
pub fn credited_events(times: &[i64]) -> Vec<i64> {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    let mut credited: Vec<i64> = Vec::new();
    // Index of the oldest credited event still inside the current window.
    let mut window_start = 0;
    for t in sorted {
        let floor = t.saturating_sub(VELOCITY_WINDOW_SECS);
        while window_start < credited.len() && credited[window_start] <= floor {
            window_start += 1;
        }
        if credited.len() - window_start < CREDITED_EVENTS_PER_WINDOW as usize {
            credited.push(t);
        }
    }
    credited
}

/// Ceiling on every dimension of an identity nobody established has vouched for
/// (ADR-0009). Protocol-locked.
pub const ANCHOR_DIMENSION_CAP: f32 = 1.0;

/// Composite an existing member needs before their vouch can anchor someone:
/// the floor of the **Member** band (ADR-0009, amended). Protocol-locked.
///
/// Tied to a band boundary rather than given as a bare number so it keeps meaning
/// the same thing — "someone the community recognizes as established" — as later
/// milestones light up the dimensions that are still `0.0`. The original 3.0 was
/// unreachable in Phase 1 (the highest available composite is `0.55 · 5.0 = 2.75`
/// with three of five dimensions structurally zero), which would have held every
/// member, founders included, at [`ANCHOR_DIMENSION_CAP`] permanently.
pub const ANCHOR_VOUCHER_MIN_COMPOSITE: f32 = crate::model::BAND_MEMBER_MIN;

/// A dimension grew faster than [`VELOCITY_CAP_PER_WEEK`] allows.
///
/// Carries what grew and by how much, because the operator reviewing it needs to
/// judge the specific gain — the alert is the beginning of a human decision, not
/// the end of an automatic one.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum VelocityViolation {
    /// One of the five fixed dimensions gained too fast.
    #[error("{dim} gained {gained} against a cap of {cap}")]
    DimensionExceeded {
        /// Field name of the dimension that grew, e.g. `"trade_reliability"`.
        dim: &'static str,
        /// How much it gained over the interval.
        gained: f32,
        /// The most it was allowed to gain over that interval.
        cap: f32,
    },
    /// One domain-competence tag gained too fast. Split from
    /// [`DimensionExceeded`](Self::DimensionExceeded) because a tag is named at
    /// runtime by the marketplace, not by a field of the profile.
    #[error("domain competence in {} gained {gained} against a cap of {cap}", tag.0)]
    DomainExceeded {
        /// The competence tag that grew.
        tag: DomainTag,
        /// How much it gained over the interval.
        gained: f32,
        /// The most it was allowed to gain over that interval.
        cap: f32,
    },
}

/// Checks how much `next` gained over `prev` against the weekly cap, reporting
/// the first dimension that grew too fast.
///
/// The allowance scales with the interval between the two profiles — a month
/// apart permits four weeks' worth — with a floor of one week's allowance, so a
/// station refreshing hourly does not flag a single ordinary transaction. Only
/// growth is examined; decay between snapshots is not a violation.
///
/// # A known undercount
///
/// A true trailing-7-day window needs the snapshot *history*, and the cache keeps
/// only the latest ([`crate::snapshot`]). Comparing consecutive snapshots
/// therefore misses a member who stays just under the floor on each of many
/// sub-weekly refreshes. The gap narrows as the refresh interval lengthens and
/// closes entirely at weekly refresh; a full windowed check waits for retained
/// snapshot history.
pub fn check_velocity(
    prev: &ReputationProfile,
    next: &ReputationProfile,
) -> std::result::Result<(), VelocityViolation> {
    let cap = allowance(prev.last_updated, next.last_updated);

    for (dim, before, after) in [
        (
            "trade_reliability",
            prev.trade_reliability,
            next.trade_reliability,
        ),
        (
            "attestation_accuracy",
            prev.attestation_accuracy,
            next.attestation_accuracy,
        ),
        (
            "governance_participation",
            prev.governance_participation,
            next.governance_participation,
        ),
        (
            "community_contribution",
            prev.community_contribution,
            next.community_contribution,
        ),
    ] {
        let gained = after - before;
        if gained > cap {
            return Err(VelocityViolation::DimensionExceeded { dim, gained, cap });
        }
    }

    for (tag, after) in &next.domain_competence {
        // A tag absent from the previous profile started at zero.
        let before = prev.domain_competence.get(tag).copied().unwrap_or(0.0);
        let gained = after - before;
        if gained > cap {
            return Err(VelocityViolation::DomainExceeded {
                tag: tag.clone(),
                gained,
                cap,
            });
        }
    }

    Ok(())
}

/// How much any one dimension may gain between two instants: the weekly cap
/// scaled by the elapsed weeks, never less than a single week's worth.
fn allowance(from_time: i64, to_time: i64) -> f32 {
    let weeks = (to_time.saturating_sub(from_time)) as f32 / SECONDS_PER_WEEK;
    VELOCITY_CAP_PER_WEEK * weeks.max(1.0)
}

/// Whether `address` is anchored: a founder-basis root, or reached from one by
/// a chain of anchoring edges (ADR-0038 §11).
pub fn is_anchored(
    db: &Database,
    address: &Address,
    at_time: i64,
    station: &PublicKey,
) -> Result<bool> {
    is_anchored_bounded(db, address, at_time, u64::MAX, station)
}

/// Like [`is_anchored`], but only vouches (and voucher evidence) admitted within
/// the log prefix `[1, max_seq]` count — the position-bounded form used so
/// a back-dated anchoring vouch admitted after a window closes cannot retroactively
/// anchor a member into a pinned electorate.
pub fn is_anchored_bounded(
    db: &Database,
    address: &Address,
    at_time: i64,
    max_seq: u64,
    station: &PublicKey,
) -> Result<bool> {
    Ok(ScoringContext::new(db, station, max_seq)?.is_anchored(address, at_time))
}

/// The member whose vouch anchors `address` on its chain to a root, if any.
/// `None` for a root — anchored by definition, with no voucher — and for an
/// unanchored identity, so a yes/no question wants [`is_anchored`].
///
/// # How an anchoring edge is judged
///
/// An eligible vouch forms an edge once, at the vouch: its voucher must have
/// been anchored, and held a **raw** composite of at least
/// [`ANCHOR_VOUCHER_MIN_COMPOSITE`] at the vouch's `issued_at`, over the prefix
/// strictly before the vouch (ADR-0038 §11). The raw composite keeps the rule
/// computable — it does not depend on anchoring — and judging on the shorter
/// prefix makes it well-founded. An edge is never re-judged: decay never
/// unanchors anyone, and a vouch that formed no edge never forms one later. A
/// revocation of either party voids the edge for good. Because a voucher must
/// itself be anchored, a colluding pair of enrolled members cannot anchor each
/// other; see the threat model, "Sybil clusters and manufactured standing".
pub fn anchoring_voucher(
    db: &Database,
    address: &Address,
    at_time: i64,
    station: &PublicKey,
) -> Result<Option<Address>> {
    anchoring_voucher_bounded(db, address, at_time, u64::MAX, station)
}

/// Like [`anchoring_voucher`], but only vouches admitted within the log prefix
/// `[1, max_seq]` are considered, and every voucher is judged from the same
/// bounded prefix. `max_seq == u64::MAX` is the unbounded form.
pub fn anchoring_voucher_bounded(
    db: &Database,
    address: &Address,
    at_time: i64,
    max_seq: u64,
    station: &PublicKey,
) -> Result<Option<Address>> {
    Ok(ScoringContext::new(db, station, max_seq)?.anchoring_voucher(address, at_time))
}

/// `profile` with every dimension held to [`ANCHOR_DIMENSION_CAP`] when
/// `anchored` is false, unchanged when it is true.
///
/// The rest of the algorithm keeps running underneath the cap (ADR-0009): the
/// underlying evidence still accrues and still decays, so an identity that later
/// gets anchored immediately reads at its true value rather than restarting.
///
/// Applied by [`crate::scoring::ReputationScorer::score_at`], which is where it
/// has to sit so that snapshots, exports and remote re-verification all see the
/// same profile.
pub fn anchored_profile(profile: &ReputationProfile, anchored: bool) -> ReputationProfile {
    if anchored {
        return profile.clone();
    }
    let mut capped = profile.clone();
    for dimension in [
        &mut capped.trade_reliability,
        &mut capped.attestation_accuracy,
        &mut capped.governance_participation,
        &mut capped.community_contribution,
    ] {
        *dimension = dimension.min(ANCHOR_DIMENSION_CAP);
    }
    for competence in capped.domain_competence.values_mut() {
        *competence = competence.min(ANCHOR_DIMENSION_CAP);
    }
    capped
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_ledger::enrollment::EnrollmentBasis;
    use rrn_storage::migrations;

    use crate::context::EVENT_INCREMENT;
    use crate::scoring::ReputationScorer;
    use crate::testutil::{enroll, establish_members, vouch, WEEK};

    const MONTH: i64 = 30 * 86_400;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// A profile at `at` with `trade` trade reliability and nothing else.
    fn profile(address: Address, trade: f32, at: i64) -> ReputationProfile {
        let mut p = ReputationProfile::empty(address);
        p.trade_reliability = trade;
        p.last_updated = at;
        p
    }

    #[test]
    fn ordinary_growth_passes() {
        let who = addr(&Keypair::generate());
        let prev = profile(who, 1.0, 0);
        // Half a point over a week is exactly the cap, and the cap is a ceiling.
        let next = profile(who, 1.5, WEEK);
        assert_eq!(check_velocity(&prev, &next), Ok(()));
    }

    #[test]
    fn a_fast_built_identity_is_flagged_with_what_it_gained() {
        let who = addr(&Keypair::generate());
        let prev = profile(who, 0.0, 0);
        // Ten settled transactions inside a day: the whole dimension at once.
        let next = profile(who, 5.0, 86_400);

        let violation = check_velocity(&prev, &next).unwrap_err();
        assert_eq!(
            violation,
            VelocityViolation::DimensionExceeded {
                dim: "trade_reliability",
                gained: 5.0,
                cap: VELOCITY_CAP_PER_WEEK,
            }
        );
        // The message an operator reads names the dimension and the numbers.
        assert!(violation.to_string().contains("trade_reliability"));
    }

    #[test]
    fn the_allowance_scales_with_the_gap_between_snapshots() {
        let who = addr(&Keypair::generate());
        let prev = profile(who, 0.0, 0);
        // Four weeks of steady trading: 2.0 is exactly four weeks' allowance.
        assert_eq!(check_velocity(&prev, &profile(who, 2.0, 4 * WEEK)), Ok(()));
        // A hair more is not.
        assert!(check_velocity(&prev, &profile(who, 2.01, 4 * WEEK)).is_err());
    }

    #[test]
    fn a_sub_weekly_refresh_still_allows_a_full_weeks_gain() {
        let who = addr(&Keypair::generate());
        let prev = profile(who, 1.0, 0);
        // An hourly refresh must not flag one ordinary transaction (+0.5).
        assert_eq!(check_velocity(&prev, &profile(who, 1.5, 3_600)), Ok(()));
    }

    #[test]
    fn decay_between_snapshots_is_not_a_violation() {
        let who = addr(&Keypair::generate());
        let prev = profile(who, 3.0, 0);
        // The profile shrank; only growth is capped.
        assert_eq!(check_velocity(&prev, &profile(who, 2.7, 12 * WEEK)), Ok(()));
    }

    #[test]
    fn a_new_domain_tag_counts_from_zero() {
        let who = addr(&Keypair::generate());
        let prev = profile(who, 0.0, 0);
        let mut next = profile(who, 0.0, WEEK);
        next.domain_competence
            .insert(DomainTag("medical".into()), 4.0);

        assert_eq!(
            check_velocity(&prev, &next).unwrap_err(),
            VelocityViolation::DomainExceeded {
                tag: DomainTag("medical".into()),
                gained: 4.0,
                cap: VELOCITY_CAP_PER_WEEK,
            }
        );
    }

    #[test]
    fn an_unanchored_profile_is_held_at_the_cap() {
        let who = addr(&Keypair::generate());
        let mut full = profile(who, 5.0, MONTH);
        full.attestation_accuracy = 3.0;
        full.governance_participation = 0.4;
        full.domain_competence
            .insert(DomainTag("medical".into()), 2.0);

        let capped = anchored_profile(&full, false);
        assert_eq!(capped.trade_reliability, ANCHOR_DIMENSION_CAP);
        assert_eq!(capped.attestation_accuracy, ANCHOR_DIMENSION_CAP);
        // Already under the cap: untouched, not raised.
        assert_eq!(capped.governance_participation, 0.4);
        assert_eq!(
            capped.domain_competence[&DomainTag("medical".into())],
            ANCHOR_DIMENSION_CAP
        );
        // Anchored, the same profile passes through whole.
        assert_eq!(anchored_profile(&full, true), full);
    }

    #[test]
    fn credited_events_per_window_matches_the_cap() {
        assert_eq!(
            CREDITED_EVENTS_PER_WINDOW as f32 * EVENT_INCREMENT,
            VELOCITY_CAP_PER_WEEK
        );
        assert_eq!(VELOCITY_WINDOW_SECS, 604_800);
    }

    #[test]
    fn the_window_is_trailing_and_half_open() {
        // Exactly a week apart: both credited (the earlier one sits on the
        // window's open end). A second less: only the first.
        assert_eq!(credited_events(&[0, WEEK]), vec![0, WEEK]);
        assert_eq!(credited_events(&[0, WEEK - 1]), vec![0]);
        // Credit is greedy from the earliest: an uncredited event never blocks
        // a later one.
        assert_eq!(credited_events(&[0, WEEK - 1, WEEK]), vec![0, WEEK]);
        // Order-independent, and a burst on one day credits once.
        assert_eq!(credited_events(&[WEEK, 0, 5, 3]), vec![0, WEEK]);
        assert!(credited_events(&[]).is_empty());
    }

    /// An established founder: a root (anchored by definition) with standing
    /// over the Member band, so their vouch forms an anchoring edge.
    fn established_patron(db: &Database, station: &Keypair, at: i64) -> Keypair {
        establish_members(db, station, 2, at).remove(0)
    }

    #[test]
    fn a_vouch_from_an_established_member_anchors() {
        let db = fresh_db();
        let (newcomer, station) = (Keypair::generate(), Keypair::generate());
        let t = 6 * MONTH;
        let patron = established_patron(&db, &station, t);
        enroll(&db, &station, &addr(&newcomer), EnrollmentBasis::Pairing, t);
        vouch(&db, &patron, &addr(&newcomer), t);

        assert!(is_anchored(&db, &addr(&newcomer), t, &station.public_key()).unwrap());
        assert_eq!(
            anchoring_voucher(&db, &addr(&newcomer), t, &station.public_key()).unwrap(),
            Some(addr(&patron))
        );
        // A root is anchored by definition and has no anchoring voucher.
        assert!(is_anchored(&db, &addr(&patron), t, &station.public_key()).unwrap());
        assert_eq!(
            anchoring_voucher(&db, &addr(&patron), t, &station.public_key()).unwrap(),
            None
        );
    }

    #[test]
    fn the_threshold_is_reachable_in_phase_one() {
        let db = fresh_db();
        let station = Keypair::generate();
        let t = 6 * MONTH;
        let patron = established_patron(&db, &station, t);

        // The ceiling with three of five dimensions structurally zero is
        // 0.55·5.0 = 2.75 (scored at the last event, so no decay). The
        // band-relative threshold sits under it, which the original 3.0 did not —
        // the whole reason ADR-0009 was amended.
        let composite = ReputationScorer::new(&db, &station.public_key())
            .score_raw_at(&addr(&patron), t - WEEK)
            .unwrap()
            .composite();
        assert!(
            composite >= ANCHOR_VOUCHER_MIN_COMPOSITE,
            "a maxed-out Phase 1 member reaches only {composite}"
        );
        assert!(composite < 3.0, "and cannot reach the original 3.0");
    }

    #[test]
    fn vouching_for_yourself_anchors_nothing() {
        let db = fresh_db();
        let alice = Keypair::generate();
        let station = Keypair::generate();
        let t = 6 * MONTH;
        enroll(&db, &station, &addr(&alice), EnrollmentBasis::Pairing, t);

        vouch(&db, &alice, &addr(&alice), t);
        assert!(!is_anchored(&db, &addr(&alice), t, &station.public_key()).unwrap());
    }

    #[test]
    fn a_vouch_from_a_nobody_does_not_anchor() {
        let db = fresh_db();
        let (stranger, newcomer) = (Keypair::generate(), Keypair::generate());
        let station = Keypair::generate();
        let t = 6 * MONTH;
        enroll(&db, &station, &addr(&stranger), EnrollmentBasis::Pairing, t);
        enroll(&db, &station, &addr(&newcomer), EnrollmentBasis::Pairing, t);

        // An enrolled identity with no standing vouches: the cheapest Sybil move.
        vouch(&db, &stranger, &addr(&newcomer), t);
        assert!(!is_anchored(&db, &addr(&newcomer), t, &station.public_key()).unwrap());
    }

    #[test]
    fn a_vouch_issued_later_does_not_anchor_yet() {
        let db = fresh_db();
        let (newcomer, station) = (Keypair::generate(), Keypair::generate());
        let t = 6 * MONTH;
        let patron = established_patron(&db, &station, t);
        enroll(&db, &station, &addr(&newcomer), EnrollmentBasis::Pairing, t);

        vouch(&db, &patron, &addr(&newcomer), t);
        assert!(is_anchored(&db, &addr(&newcomer), t, &station.public_key()).unwrap());
        // Asked about a moment before the vouch existed.
        assert!(!is_anchored(&db, &addr(&newcomer), t - 1, &station.public_key()).unwrap());
    }
}
