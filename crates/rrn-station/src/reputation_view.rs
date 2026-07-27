//! Member-facing reputation reads for the mobile (T1.5.9).
//!
//! M1.5 built the scoring engine ([`rrn_reputation`]) but exposed nothing to a
//! member, so a phone could not show anyone their own standing. This module is
//! that read path: it turns a [`ReputationProfile`] into the flat, JSON-shaped
//! view the mobile renders, and answers the band-for-an-address question M1.7's
//! listing cards need.
//!
//! # Reads come from the snapshot cache
//!
//! Scoring replays the whole log — since T1.5.8's anchoring it is O(V·N), one
//! replay per candidate voucher — so a read must never trigger one casually.
//! Both entry points serve [`rrn_reputation::snapshot::get_cached_profile`] and
//! fall back to [`rrn_reputation::snapshot::refresh_snapshot`] only on a miss,
//! and the station's hourly sweep keeps the cache warm. The two tolerances
//! differ on purpose (see [`OWN_PROFILE_MAX_AGE_SECS`] and
//! [`BAND_MAX_AGE_SECS`]).
//!
//! # The view is honest about Phase 1
//!
//! ADR-0009 requires the UI say what is actually reachable. Three of the five
//! dimensions have no data source yet, so they are structurally `0.0` and the
//! composite cannot exceed [`max_composite_now`] (2.75 today, against a nominal
//! scale of 5.0). The station reports both which dimensions are dormant and what
//! ceiling that implies, rather than letting the phone hard-code numbers that
//! would silently go stale when a later milestone lights a dimension up.

use serde::Serialize;

use rrn_identity::address::Address;
use rrn_reputation::model::{
    ReputationBand, ReputationProfile, DIMENSION_MAX, WEIGHT_ATTESTATION_ACCURACY,
    WEIGHT_COMMUNITY_CONTRIBUTION, WEIGHT_DOMAIN_COMPETENCE, WEIGHT_GOVERNANCE_PARTICIPATION,
    WEIGHT_TRADE_RELIABILITY,
};
use rrn_reputation::snapshot::{get_cached_profile, refresh_snapshot};
use rrn_reputation::sybil::{anchoring_voucher, ANCHOR_DIMENSION_CAP};
use rrn_storage::db::Database;

/// How stale the member's *own* profile may be before a read recomputes it.
///
/// Deliberately shorter than the station's hourly sweep: a member who has just
/// been vouched for is watching for their standing to lift, and an hour of lag
/// reads as the app being broken. One member reads their own profile, so the
/// occasional replay this forces is bounded — unlike [`BAND_MAX_AGE_SECS`].
pub const OWN_PROFILE_MAX_AGE_SECS: i64 = 300;

/// How stale *another* address's band may be before a read recomputes it.
///
/// Matches the station's default refresh interval, so a band read normally hits
/// a snapshot the hourly sweep already wrote. M1.7's listing cards ask for one
/// band per row, so this path must not be able to trigger a replay per card.
pub const BAND_MAX_AGE_SECS: i64 = 3600;

/// The dimensions with no data source in Phase 1, with the weight each carries
/// and the milestone that lights it up. They are structurally `0.0`, which is
/// what caps the reachable composite ([`max_composite_now`]).
///
/// ADR-0009 fixes the divisor at the full weight sum precisely so these do *not*
/// get renormalized away — a dormant dimension pulls the composite down, and the
/// UI's job is to say so rather than hide it.
const DORMANT_DIMENSIONS: &[(&str, f32)] = &[
    ("governance_participation", WEIGHT_GOVERNANCE_PARTICIPATION),
    ("community_contribution", WEIGHT_COMMUNITY_CONTRIBUTION),
    ("domain_competence", WEIGHT_DOMAIN_COMPETENCE),
];

/// The highest composite anyone can currently reach: every *live* dimension at
/// [`DIMENSION_MAX`], every dormant one at `0.0`. Today that is
/// `(0.30 + 0.25) × 5.0 = 2.75`, which sits inside the `Member` band — so
/// `Trusted` and `Senior` are unreachable and the mobile must say so.
///
/// Derived from the ADR-0009 weights rather than written down as a literal, so
/// it moves on its own when a milestone removes a dimension from
/// [`DORMANT_DIMENSIONS`].
pub fn max_composite_now() -> f32 {
    let dormant_weight: f32 = DORMANT_DIMENSIONS.iter().map(|(_, w)| w).sum();
    (1.0 - dormant_weight) * DIMENSION_MAX
}

/// A dimension as the mobile lists it: its score, and whether it can carry a
/// score at all yet.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DimensionRow {
    /// Stable machine name (`trade_reliability`, …); the phone owns the wording.
    pub name: &'static str,
    /// The scored value, `0.0..=5.0`.
    pub value: f32,
    /// This dimension's fixed ADR-0009 weight in the composite.
    pub weight: f32,
    /// `false` when the dimension has no data source yet, so its `0.0` means
    /// "not measured", not "measured and poor" — a distinction the UI must draw.
    pub live: bool,
}

/// A member's own standing, flattened for the mobile.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReputationView {
    /// The scored identity's bech32m `rrn1…` address.
    pub address: String,
    /// The ADR-0009 weighted composite, `0.0..=5.0`.
    pub composite: f32,
    /// The band the composite falls in: `New`, `Member`, `Trusted`, `Senior`.
    pub band: &'static str,
    /// All five dimensions in ADR-0009 order, live ones and dormant ones alike.
    pub dimensions: Vec<DimensionRow>,
    /// Per-category domain competence, empty until the marketplace (M1.7) feeds
    /// it. Kept separate from `dimensions`, where domain competence appears as
    /// the single folded scalar that actually enters the composite.
    pub domain_competence: Vec<DomainRow>,
    /// The nominal top of the scale (5.0) — what a dimension is scored against.
    pub scale_max: f32,
    /// The highest composite reachable today ([`max_composite_now`]). Strictly
    /// below `scale_max` while any dimension is dormant.
    pub max_composite_now: f32,
    /// Whether an identity-anchoring vouch has lifted the newcomer cap.
    pub anchored: bool,
    /// The address of the vouch that anchored this member, when anchored. The
    /// member can then recognise *who* vouched for them.
    pub anchoring_voucher_address: Option<String>,
    /// While unanchored, every dimension is held to this ceiling
    /// ([`ANCHOR_DIMENSION_CAP`]) however much history the member has — the
    /// single most confusing thing a new member can hit, so it is explicit.
    pub anchor_dimension_cap: f32,
    /// Unix seconds the profile was computed as of. The phone shows this rather
    /// than implying the number is live to the second.
    pub computed_at: i64,
}

/// One category of domain competence.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DomainRow {
    /// The category label, e.g. `"carpentry"`.
    pub tag: String,
    /// The score in that category, `0.0..=5.0`.
    pub value: f32,
}

/// Just the band for an address, for a listing card (M1.7).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BandView {
    /// The scored identity's bech32m `rrn1…` address.
    pub address: String,
    /// The ADR-0009 weighted composite, `0.0..=5.0`.
    pub composite: f32,
    /// The band name: `New`, `Member`, `Trusted`, `Senior`.
    pub band: &'static str,
    /// Unix seconds the underlying profile was computed as of.
    pub computed_at: i64,
}

/// The authenticated member's own standing, cache-first (see
/// [`OWN_PROFILE_MAX_AGE_SECS`]).
///
/// The anchoring lookup is *not* cached — the snapshot stores the profile, not
/// the reason behind it, and a capped profile is indistinguishable from a
/// genuinely low-scoring one by its numbers alone. It costs one
/// [`anchoring_voucher`] pass, which is why this is the own-profile path only.
pub fn member_reputation(
    db: &Database,
    member: &Address,
    now: i64,
) -> rrn_reputation::Result<ReputationView> {
    let profile = cached_or_fresh(db, member, now, OWN_PROFILE_MAX_AGE_SECS)?;
    let voucher = anchoring_voucher(db, member, now)?;
    Ok(view_of(&profile, voucher))
}

/// The band for any address, cache-first (see [`BAND_MAX_AGE_SECS`]).
///
/// Any paired mobile may ask about any address: a band is what one member shows
/// another to be worth trading with, so it is readable by design (ADR-0009 puts
/// no local policy on who may see a score). An address with no history scores an
/// empty profile — band `New` — rather than erroring, so a listing card for a
/// brand-new member still renders.
pub fn address_band(
    db: &Database,
    address: &Address,
    now: i64,
) -> rrn_reputation::Result<BandView> {
    let profile = cached_or_fresh(db, address, now, BAND_MAX_AGE_SECS)?;
    Ok(BandView {
        address: profile.address.to_string(),
        composite: profile.composite(),
        band: band_name(profile.band()),
        computed_at: profile.last_updated,
    })
}

/// Serves the snapshot cache when it is fresh enough for `max_age`, else
/// recomputes and stores one. The recompute is the expensive path; the hourly
/// station sweep is what keeps it rare.
fn cached_or_fresh(
    db: &Database,
    address: &Address,
    now: i64,
    max_age: i64,
) -> rrn_reputation::Result<ReputationProfile> {
    match get_cached_profile(db, address, max_age)? {
        Some(profile) => Ok(profile),
        None => refresh_snapshot(db, address, now),
    }
}

/// Flattens a profile (plus the anchoring answer) into the wire view.
fn view_of(profile: &ReputationProfile, anchoring_voucher: Option<Address>) -> ReputationView {
    let domain_scalar = mean_or_zero(profile.domain_competence.values().copied());
    ReputationView {
        address: profile.address.to_string(),
        composite: profile.composite(),
        band: band_name(profile.band()),
        dimensions: vec![
            live(
                "trade_reliability",
                profile.trade_reliability,
                WEIGHT_TRADE_RELIABILITY,
            ),
            live(
                "attestation_accuracy",
                profile.attestation_accuracy,
                WEIGHT_ATTESTATION_ACCURACY,
            ),
            dormant(
                "governance_participation",
                profile.governance_participation,
                WEIGHT_GOVERNANCE_PARTICIPATION,
            ),
            dormant(
                "community_contribution",
                profile.community_contribution,
                WEIGHT_COMMUNITY_CONTRIBUTION,
            ),
            dormant("domain_competence", domain_scalar, WEIGHT_DOMAIN_COMPETENCE),
        ],
        domain_competence: profile
            .domain_competence
            .iter()
            .map(|(tag, value)| DomainRow {
                tag: tag.0.clone(),
                value: *value,
            })
            .collect(),
        scale_max: DIMENSION_MAX,
        max_composite_now: max_composite_now(),
        anchored: anchoring_voucher.is_some(),
        anchoring_voucher_address: anchoring_voucher.map(|a| a.to_string()),
        anchor_dimension_cap: ANCHOR_DIMENSION_CAP,
        computed_at: profile.last_updated,
    }
}

/// A dimension that has a data source in Phase 1.
fn live(name: &'static str, value: f32, weight: f32) -> DimensionRow {
    DimensionRow {
        name,
        value,
        weight,
        live: true,
    }
}

/// A dimension whose `0.0` means "no data source yet" (see [`DORMANT_DIMENSIONS`]).
fn dormant(name: &'static str, value: f32, weight: f32) -> DimensionRow {
    debug_assert!(
        DORMANT_DIMENSIONS.iter().any(|(n, _)| *n == name),
        "{name} marked dormant but missing from DORMANT_DIMENSIONS"
    );
    DimensionRow {
        name,
        value,
        weight,
        live: false,
    }
}

/// The band's wire name. A stable string rather than a serde derive on
/// [`ReputationBand`], so the wire shape is owned here and not by the scoring
/// crate's enum spelling.
fn band_name(band: ReputationBand) -> &'static str {
    match band {
        ReputationBand::New => "New",
        ReputationBand::Member => "Member",
        ReputationBand::Trusted => "Trusted",
        ReputationBand::Senior => "Senior",
    }
}

/// Mean-or-zero, mirroring the fold `ReputationProfile::composite` applies to
/// the domain map (whose helper is private to the scoring crate).
fn mean_or_zero(values: impl Iterator<Item = f32>) -> f32 {
    let (sum, count) = values.fold((0.0, 0usize), |(s, c), v| (s + v, c + 1));
    if count == 0 {
        0.0
    } else {
        sum / count as f32
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::vouch::{append_vouch, create_vouch};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
    use rrn_reputation::model::{BAND_MEMBER_MIN, BAND_TRUSTED_MIN};
    use rrn_storage::log::AppendLog;
    use rrn_storage::migrations;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// Snapshot freshness is judged against the *wall* clock inside
    /// `get_cached_profile`, so a test that wants the cache to behave as it does
    /// in production has to score at a realistic timestamp — an arbitrary small
    /// number would read as decades stale on every read.
    fn wall_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Appends a full proposal → confirmation → settlement chain, settling at
    /// `at`. Mirrors the scoring crate's own test fixture.
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
        log.append(SignedPayload::sign(proposal, sender)).unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, receiver))
            .unwrap();
        let settlement = SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        };
        log.append(SignedPayload::sign(settlement, station))
            .unwrap();
    }

    /// Builds an identity that clears the anchoring bar on its raw score: as the
    /// *receiver* of ten settled trades it maxes trade reliability (10 trades)
    /// and attestation accuracy (ten confirmations it signed), for a raw
    /// composite of 2.75 — above `BAND_MEMBER_MIN`. Returns its keypair.
    fn member_who_can_anchor(db: &Database, station: &Keypair, at: i64) -> Keypair {
        let anchor = Keypair::generate();
        for nonce in 0..10 {
            let counterparty = Keypair::generate();
            append_settled(db, &counterparty, &anchor, station, nonce, at);
        }
        anchor
    }

    fn dimension<'a>(view: &'a ReputationView, name: &str) -> &'a DimensionRow {
        view.dimensions.iter().find(|d| d.name == name).unwrap()
    }

    #[test]
    fn an_address_with_no_history_reads_as_new_rather_than_erroring() {
        let db = fresh_db();
        let stranger = addr(&Keypair::generate());

        // A listing card for someone with no history still has to render.
        let view = address_band(&db, &stranger, wall_now()).unwrap();
        assert_eq!(view.band, "New");
        assert_eq!(view.composite, 0.0);
        assert_eq!(view.address, stranger.to_string());
    }

    #[test]
    fn the_view_carries_all_five_dimensions_with_three_marked_dormant() {
        let db = fresh_db();
        let member = addr(&Keypair::generate());

        let view = member_reputation(&db, &member, wall_now()).unwrap();

        assert_eq!(view.dimensions.len(), 5, "all five, dormant ones included");
        assert!(dimension(&view, "trade_reliability").live);
        assert!(dimension(&view, "attestation_accuracy").live);
        // These read 0.0 because nothing feeds them yet, not because the member
        // scored badly — the UI must be able to tell those apart.
        assert!(!dimension(&view, "governance_participation").live);
        assert!(!dimension(&view, "community_contribution").live);
        assert!(!dimension(&view, "domain_competence").live);

        // The weights are ADR-0009's and sum to the full fixed divisor.
        let total: f32 = view.dimensions.iter().map(|d| d.weight).sum();
        assert!(
            (total - 1.0).abs() < 1e-6,
            "weights sum to 1.0, got {total}"
        );
    }

    #[test]
    fn the_reachable_ceiling_is_below_the_nominal_scale_and_lands_in_member() {
        // (0.30 + 0.25) × 5.0 — the two live dimensions maxed, the rest dark.
        assert!((max_composite_now() - 2.75).abs() < 1e-6);
        assert!(
            max_composite_now() < DIMENSION_MAX,
            "the scale is not reachable"
        );

        // ADR-0009's honesty requirement in one assertion: the best possible
        // Phase-1 member is a Member, so Trusted and Senior cannot be earned.
        assert!(max_composite_now() >= BAND_MEMBER_MIN);
        assert!(max_composite_now() < BAND_TRUSTED_MIN);
    }

    #[test]
    fn an_unvouched_member_is_unanchored_and_held_to_the_newcomer_cap() {
        let db = fresh_db();
        let station = Keypair::generate();
        let now = wall_now();
        let member = member_who_can_anchor(&db, &station, now);

        let view = member_reputation(&db, &addr(&member), now).unwrap();

        assert!(!view.anchored, "nobody has vouched for them");
        assert_eq!(view.anchoring_voucher_address, None);
        // Ten settled trades and it still reads 1.0: this is exactly the state
        // that looks like a broken app without the explainer the view enables.
        assert_eq!(
            dimension(&view, "trade_reliability").value,
            ANCHOR_DIMENSION_CAP
        );
        assert_eq!(view.anchor_dimension_cap, ANCHOR_DIMENSION_CAP);
    }

    #[test]
    fn an_anchored_member_names_the_voucher_that_lifted_the_cap() {
        let db = fresh_db();
        let station = Keypair::generate();
        let now = wall_now();
        let anchor = member_who_can_anchor(&db, &station, now);
        let newcomer = Keypair::generate();
        // One settled trade, so there is something for the lifted cap to reveal.
        append_settled(&db, &newcomer, &Keypair::generate(), &station, 0, now);

        let signed = create_vouch(&anchor, &addr(&newcomer), "demo", "I know them", 0);
        append_vouch(&mut AppendLog::new(&db), signed).unwrap();

        let view = member_reputation(&db, &addr(&newcomer), now).unwrap();

        assert!(view.anchored);
        assert_eq!(
            view.anchoring_voucher_address,
            Some(addr(&anchor).to_string()),
            "the member can see who vouched for them"
        );
        // The cap is gone: one trade scores 0.5, which the cap would have hidden
        // only above 1.0 — so assert the anchoring itself rather than a number
        // the cap never bound.
        assert!(dimension(&view, "trade_reliability").value > 0.0);
    }

    #[test]
    fn a_repeat_read_is_served_from_the_snapshot_cache() {
        let db = fresh_db();
        let station = Keypair::generate();
        let now = wall_now();
        let member = addr(&member_who_can_anchor(&db, &station, now));

        let first = member_reputation(&db, &member, now).unwrap();
        // A later read inside the tolerance must not rescore — reads are on the
        // O(V·N) replay path and the whole point of the cache is to stay off it.
        let second = member_reputation(&db, &member, now + OWN_PROFILE_MAX_AGE_SECS / 2).unwrap();

        assert_eq!(
            second.computed_at, first.computed_at,
            "the second read reused the stored snapshot"
        );
        assert_eq!(second.composite, first.composite);
    }
}
