//! Sybil resistance — the velocity cap and identity anchoring that stop fake
//! identities from fast-building reputation.
//!
//! Per ADR-0009 (design doc Section 5.4), Phase 1 leans on two local,
//! deterministic defenses rather than the graph analysis a federation could
//! afford:
//!
//! - **Velocity limiting** — no dimension may gain more than
//!   [`VELOCITY_CAP_PER_WEEK`] in a week. A fake identity can only manufacture
//!   evidence so fast, so farming shows up as an implausible rate of gain.
//! - **Identity anchoring** — a fresh identity's dimensions are capped at
//!   [`ANCHOR_DIMENSION_CAP`] until an established member vouches for it, so a
//!   Sybil cluster cannot bootstrap standing purely among itself. It has to
//!   corrupt someone real, which is the cost the vouching chain is meant to
//!   impose.
//!
//! # Flag, do not punish
//!
//! [`check_velocity`] *reports*; it never edits a profile. An automatic penalty
//! would be a griefing vector — anyone who can drive transactions at a member
//! could push them over the cap — and the cap's own honest false positives (a
//! member who legitimately trades a lot in one week) are exactly the cases a
//! human should look at. The station logs violations for operator review
//! ([`crate::snapshot`]) and scoring proceeds unchanged.

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::model::{DomainTag, ReputationProfile};
use crate::scoring::ReputationScorer;
use crate::Result;

/// Most a single dimension may gain in one week before the gain is flagged
/// (ADR-0009). Protocol-locked.
pub const VELOCITY_CAP_PER_WEEK: f32 = 0.5;

/// Seconds in the velocity cap's week.
const SECONDS_PER_WEEK: f32 = 7.0 * 86_400.0;

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

/// Whether `address` has been vouched for by a member established enough to
/// anchor it.
pub fn is_anchored(db: &Database, address: &Address, at_time: i64) -> Result<bool> {
    Ok(anchoring_voucher(db, address, at_time)?.is_some())
}

/// The member whose vouch anchors `address`, if any: the first, in log order, to
/// have vouched for it at or before `at_time` while holding a composite of at
/// least [`ANCHOR_VOUCHER_MIN_COMPOSITE`].
///
/// Callers that only need a yes/no want [`is_anchored`]; the address itself is
/// what [`crate::portability`] needs, to ship the evidence a remote verifier must
/// replay in order to reach the same conclusion.
///
/// # Why the voucher is judged uncapped
///
/// The voucher's composite is read from the scorer's internal `score_raw_at` —
/// their score *before* anchoring is applied. This is not a shortcut; it is what
/// makes the rule computable. Judging a voucher by their anchored profile would
/// make two members who vouch for each other mutually undecidable, and no member
/// could ever be the first anchor, since an unanchored member's composite cannot
/// exceed `0.55` — below any usable threshold.
///
/// The cost is that anchoring stops a lone fake identity but not a patient pair:
/// two colluding identities trading with each other raise their *uncapped*
/// composites on real-looking evidence and can then anchor each other. Velocity
/// flagging and human review are what stand against that in Phase 1; see the
/// threat model, "Sybil clusters and manufactured standing".
pub fn anchoring_voucher(
    db: &Database,
    address: &Address,
    at_time: i64,
) -> Result<Option<Address>> {
    let log = AppendLog::new(db);
    let scorer = ReputationScorer::new(db);

    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) else {
            continue;
        };
        if vouch.subject != *address || vouch.issued_at > at_time {
            continue;
        }
        let voucher = Address::from_public_key(entry.payload.signer);
        // A vouch for oneself anchors nothing; self-anchoring is the whole thing
        // the rule exists to prevent.
        if voucher == *address {
            continue;
        }
        if scorer.score_raw_at(&voucher, at_time)?.composite() >= ANCHOR_VOUCHER_MIN_COMPOSITE {
            return Ok(Some(voucher));
        }
    }
    Ok(None)
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
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
    use rrn_storage::migrations;

    const WEEK: i64 = 7 * 86_400;
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

    fn append_settled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        station: &Keypair,
        nonce: u64,
        at: i64,
    ) {
        let mut log = AppendLog::new(db);
        let proposal = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            300,
            None,
            nonce,
            1,
            i64::MAX / 2,
        );
        let pid = proposal.id;
        log.append(SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, receiver), 0)
            .unwrap();
        let settlement = SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        };
        log.append(SignedPayload::sign(settlement, station), 0)
            .unwrap();
    }

    fn append_vouch(db: &Database, voucher: &Keypair, subject: &Address, at: i64) {
        let mut log = AppendLog::new(db);
        let vouch = Attestation {
            kind: VouchKind,
            body: VouchBody {
                community: "commons".into(),
                statement: "trustworthy".into(),
                reputation_stake_centi: 0,
            },
            subject: *subject,
            issued_at: at,
            expires_at: None,
        };
        log.append(vouch.sign(voucher), 0).unwrap();
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

    /// A member with the most history Phase 1 can produce: ten settled trades
    /// (trade reliability 5.0) and ten vouches written (attestation accuracy
    /// 5.0), which is every live dimension at its ceiling.
    fn maxed_out_member(db: &Database, member: &Keypair, station: &Keypair, at: i64) {
        for nonce in 0..10 {
            append_settled(db, member, station, station, nonce, at);
        }
        for _ in 0..10 {
            append_vouch(db, member, &addr(&Keypair::generate()), at);
        }
    }

    #[test]
    fn a_vouch_from_an_established_member_anchors() {
        let db = fresh_db();
        let (patron, newcomer, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 6 * MONTH;
        maxed_out_member(&db, &patron, &station, t);
        append_vouch(&db, &patron, &addr(&newcomer), t);

        assert!(is_anchored(&db, &addr(&newcomer), t).unwrap());
        assert_eq!(
            anchoring_voucher(&db, &addr(&newcomer), t).unwrap(),
            Some(addr(&patron))
        );
    }

    #[test]
    fn the_threshold_is_reachable_in_phase_one() {
        let db = fresh_db();
        let (patron, station) = (Keypair::generate(), Keypair::generate());
        let t = 6 * MONTH;
        maxed_out_member(&db, &patron, &station, t);

        // The ceiling with three of five dimensions structurally zero is
        // 0.55·5.0 = 2.75. The band-relative threshold sits under it, which the
        // original 3.0 did not — the whole reason ADR-0009 was amended.
        let composite = ReputationScorer::new(&db)
            .score_raw_at(&addr(&patron), t)
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
        let t = 6 * MONTH;

        append_vouch(&db, &alice, &addr(&alice), t);
        assert!(!is_anchored(&db, &addr(&alice), t).unwrap());
    }

    #[test]
    fn a_vouch_from_a_nobody_does_not_anchor() {
        let db = fresh_db();
        let (stranger, newcomer) = (Keypair::generate(), Keypair::generate());
        let t = 6 * MONTH;

        // A fresh identity with no history vouches: the cheapest Sybil move.
        append_vouch(&db, &stranger, &addr(&newcomer), t);
        assert!(!is_anchored(&db, &addr(&newcomer), t).unwrap());
    }

    #[test]
    fn a_vouch_issued_later_does_not_anchor_yet() {
        let db = fresh_db();
        let (patron, newcomer) = (Keypair::generate(), Keypair::generate());
        let t = 6 * MONTH;

        append_vouch(&db, &patron, &addr(&newcomer), t);
        // Asked about a moment before the vouch existed.
        assert!(!is_anchored(&db, &addr(&newcomer), t - 1).unwrap());
    }
}
