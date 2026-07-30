//! Needs — the demand side of the marketplace.
//!
//! A [`Need`] is a member saying, on the log, what they are looking for. It is
//! the Phase-1 form of the predictive matching in design overview Section 9.4:
//! nothing here predicts anything, it matches a need a buyer stated explicitly
//! against the supply already on offer, when the buyer asks. Proactive
//! surfacing, seasonal prediction, multi-hop chains, and reverse auctions are
//! all later phases.
//!
//! # Matching is a search, not a second ranking
//!
//! [`find_matches`] is a thin query over [`SearchIndex`](crate::search::SearchIndex):
//! a need's category and price ceiling are exactly a [`SearchQuery`] with no
//! text. That is deliberate — a separate matching path would be a second place
//! for "which listings are on offer, and in what order" to be decided, and the
//! two would drift. What matching adds on top is the one thing a text search has
//! no notion of: whether the offer can actually fill the quantity asked for.

use dcbor::prelude::*;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};

use crate::listing::{AvailabilityStatus, Listing, CATEGORIES};
use crate::search::{SearchIndex, SearchQuery, DEFAULT_LIMIT};
use crate::Result;

/// Discriminant carried in the `kind` field of a need's canonical CBOR.
pub(crate) const NEED_KIND: &str = "rrn.marketplace.need_announced.v1";

/// What a member is looking for.
///
/// Unlike a [`Listing`] this is not content-addressed: nothing references a
/// need, so it needs no stable identity, and two identical needs from the same
/// seeker are simply the same request stated twice.
///
/// There is no `announced_at` field. The only time a need reasons about is when
/// it stops being worth answering; when it was said is on the log entry that
/// carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Need {
    /// The member looking. Must equal the signer of the record.
    pub seeker: Address,
    /// One of [`CATEGORIES`] — the same controlled vocabulary listings use,
    /// because a need and an offer have to be about the same thing for either
    /// to find the other.
    pub category: String,
    /// How many units are wanted. Must be at least one.
    pub quantity_needed: u32,
    /// The most the seeker will pay per the listing's own pricing, or `None`
    /// for no ceiling.
    pub max_price_centi: Option<i64>,
    /// Unix seconds after which the need is stale and matches nothing.
    pub valid_until: i64,
}

impl Need {
    /// Builds a need, refusing one that breaks its own rules.
    pub fn new(
        seeker: Address,
        category: String,
        quantity_needed: u32,
        max_price_centi: Option<i64>,
        valid_until: i64,
    ) -> std::result::Result<Self, NeedError> {
        let need = Need {
            seeker,
            category,
            quantity_needed,
            max_price_centi,
            valid_until,
        };
        need.validate()?;
        Ok(need)
    }

    /// Checks the need against its own rules.
    ///
    /// Kept public and separate from decoding for the reason
    /// [`Listing::validate`] is: `TryFrom<CBOR>` can only return a
    /// `dcbor::Error` and would lose which rule broke.
    pub fn validate(&self) -> std::result::Result<(), NeedError> {
        if !CATEGORIES.contains(&self.category.as_str()) {
            return Err(NeedError::UnknownCategory(self.category.clone()));
        }
        if self.quantity_needed == 0 {
            return Err(NeedError::ZeroQuantity);
        }
        Ok(())
    }

    /// Whether the need has passed its `valid_until`.
    ///
    /// Inclusive of the last second, matching how
    /// [`lifecycle`](crate::lifecycle) treats a listing's expiry: valid
    /// *through* `valid_until`, stale the second after.
    pub fn has_expired(&self, now: i64) -> bool {
        now > self.valid_until
    }
}

impl From<Need> for CBOR {
    fn from(n: Need) -> Self {
        let mut m = Map::new();
        m.insert("kind", NEED_KIND);
        m.insert("seeker", n.seeker);
        m.insert("category", n.category);
        m.insert("quantity_needed", n.quantity_needed);
        // Text-or-null rather than omitted: `Need` is a new record type, so the
        // house `memo` style applies. The omit-when-`None` rule is only for a
        // field added to an already content-addressed record (ADR-0010).
        match n.max_price_centi {
            Some(p) => m.insert("max_price_centi", p),
            None => m.insert("max_price_centi", CBOR::null()),
        }
        m.insert("valid_until", n.valid_until);
        m.into()
    }
}

impl TryFrom<CBOR> for Need {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != NEED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(Need {
            seeker: map.extract::<&str, Address>("seeker")?,
            category: map.extract::<&str, String>("category")?,
            quantity_needed: map.extract::<&str, u32>("quantity_needed")?,
            max_price_centi: map.get::<&str, i64>("max_price_centi"),
            valid_until: map.extract::<&str, i64>("valid_until")?,
        })
    }
}

/// A [`Need`] signed by its seeker.
pub type SignedNeed = SignedPayload<Need>;

/// Announces a need on the log.
///
/// Rejects one whose signer is not its seeker, and one that breaks its own
/// rules. A need that has already expired is *not* rejected: `valid_until` is
/// judged when matching, against the caller's clock, and refusing here would
/// mean this station's clock decided whether someone else's record was
/// well-formed.
pub fn append_need_announced(log: &mut AppendLog, signed: SignedNeed) -> Result<LogEntry> {
    let need = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != need.seeker {
        return Err(NeedError::SignerNotSeeker {
            signer,
            seeker: need.seeker,
        }
        .into());
    }
    need.validate()?;
    Ok(log.append(signed)?)
}

/// A need as it sits on the log, with the sequence number that identifies it.
///
/// A [`Need`] is not content-addressed — nothing references one, so it carries no
/// id of its own. But a member with three needs standing has to be able to say
/// *which*, so the log's own sequence number is the handle: it is already unique,
/// already assigned, and already what the entry is filed under. It is local to
/// one station's log and deliberately not a network identifier; a seeker naming a
/// need to their own station is the only case that needs to name one at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncedNeed {
    /// The log sequence number of the entry that announced it.
    pub seq: u64,
    /// The need itself.
    pub need: Need,
}

/// Every need `seeker` has announced on this log, in log order.
///
/// Scoped to one seeker because that is the only question asked of it: a member
/// reviewing what they are still looking for. Skips entries whose signer is not
/// the seeker the need names, exactly as [`append_need_announced`] refuses to
/// write one — so a gossiped need attributed to someone who did not sign it is
/// not visible here either.
///
/// Expired needs are returned rather than filtered: `valid_until` is judged
/// against the reader's clock, and a seeker looking at their own list should see
/// the stale ones too (that is how they know to restate them). Callers that only
/// want live needs filter on [`Need::has_expired`].
pub fn announced_needs(log: &AppendLog, seeker: &Address) -> Result<Vec<AnnouncedNeed>> {
    let mut found = Vec::new();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(need) = from_canonical_bytes::<Need>(&entry.payload.bytes) else {
            continue;
        };
        if need.seeker != *seeker {
            continue;
        }
        if Address::from_public_key(entry.payload.signer) != need.seeker {
            continue;
        }
        found.push(AnnouncedNeed {
            seq: entry.seq,
            need,
        });
    }
    Ok(found)
}

/// How well an offer's stock covers what was asked for: `1.0` when it fills the
/// need outright, the fraction it could cover when it falls short.
///
/// A proportional factor rather than an invented weight — a listing that can
/// supply half of what is wanted ranks at half the strength of one that can
/// supply all of it, and there is nothing to tune. `None` capacity is unlimited
/// and so always fills.
fn fill_fraction(capacity: Option<u32>, quantity_needed: u32) -> f32 {
    match capacity {
        None => 1.0,
        Some(available) => {
            let ratio = available as f32 / quantity_needed.max(1) as f32;
            ratio.min(1.0)
        }
    }
}

/// Whether an offer can be taken up at all, whatever its rank would be.
///
/// Sold out and explicitly unavailable are exclusions, not penalties: a match
/// list is a list of things the seeker can actually go and get, and ranking
/// something unobtainable at the bottom still puts it in front of them.
/// `LimitedStock` stays in — it is available, and `capacity` already carries how
/// much of it there is.
fn is_obtainable(listing: &Listing) -> bool {
    listing.availability.status != AvailabilityStatus::Unavailable
        && listing.availability.capacity != Some(0)
}

/// Active listings that answer `need`, best match first.
///
/// Ranked by the search index's provider-reputation ordering, multiplied by how
/// much of the requested quantity the offer can cover. An expired need matches
/// nothing — not an error, simply no longer a question worth answering.
///
/// Takes the index and the database rather than the database alone (as the task
/// sketch had it), for the same reason the rest of M1.6 does: the tantivy half
/// of the index is not reachable from a `Database` handle.
pub fn find_matches(
    index: &SearchIndex,
    db: &Database,
    need: &Need,
    now: i64,
) -> Result<Vec<Listing>> {
    if need.has_expired(now) {
        return Ok(Vec::new());
    }

    // A need *is* a search: same category filter, same price ceiling, same
    // definition of active, same reputation ranking. No text, so every candidate
    // starts equally relevant and standing orders them.
    let hits = index.search(
        db,
        &SearchQuery {
            category: Some(need.category.clone()),
            max_price_centi: need.max_price_centi,
            // Rank the whole candidate set before truncating: cutting first
            // would drop listings that fill the need better than the ones kept.
            limit: usize::MAX,
            ..SearchQuery::default()
        },
        now,
    )?;

    let mut matched: Vec<(f32, Listing)> = hits
        .into_iter()
        .filter(|hit| is_obtainable(&hit.listing))
        .map(|hit| {
            let fill = fill_fraction(hit.listing.availability.capacity, need.quantity_needed);
            (hit.score * fill, hit.listing)
        })
        .collect();

    matched.sort_by(|(a_score, a), (b_score, b)| {
        b_score
            .partial_cmp(a_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(matched
        .into_iter()
        .map(|(_, listing)| listing)
        .take(DEFAULT_LIMIT)
        .collect())
}

/// A need that breaks one of its own rules, or that nobody was entitled to
/// announce. One variant per check, as elsewhere in this crate.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum NeedError {
    /// The category is not one of [`CATEGORIES`].
    #[error("category {0:?} is not one this marketplace recognizes")]
    UnknownCategory(String),
    /// A need for nothing.
    #[error("a need must be for at least one unit")]
    ZeroQuantity,
    /// The envelope's signer is not the seeker the need names.
    #[error("need signed by {signer}, but names {seeker} as the seeker")]
    SignerNotSeeker {
        /// Who signed.
        signer: Address,
        /// Who the need says is looking.
        seeker: Address,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{append_listing_created, compute_state};
    use crate::listing::{Availability, Pricing, PricingModel, Requirements, Surface};
    use crate::Error;
    use rrn_crypto::keypair::{Keypair, PublicKey};
    use rrn_reputation::model::ReputationProfile;
    use rrn_storage::migrations;

    const CREATED_AT: i64 = 1_800_000_000;
    const EXPIRES_AT: i64 = 1_900_000_000;
    const NOW: i64 = 1_850_000_000;
    const VALID_UNTIL: i64 = 1_860_000_000;

    fn open_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    #[allow(clippy::too_many_arguments)]
    fn listing_of(
        provider: &Keypair,
        category: &str,
        title: &str,
        price_centi: i64,
        status: AvailabilityStatus,
        capacity: Option<u32>,
    ) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            "blue_ridge_collective".into(),
            Surface::Goods,
            category.into(),
            title.into(),
            "Plenty to go around.".into(),
            Pricing {
                amount_centi: price_centi,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status,
                capacity,
                next_slot: None,
            },
            Requirements {
                min_reputation: 0.0,
                community_member_only: false,
                federation_only: false,
            },
            1,
            false,
            CREATED_AT,
            Some(EXPIRES_AT),
        )
        .unwrap()
    }

    fn publish(
        index: &SearchIndex,
        db: &Database,
        log: &mut AppendLog,
        station: &PublicKey,
        provider: &Keypair,
        listing: &Listing,
    ) {
        append_listing_created(log, SignedPayload::sign(listing.clone(), provider)).unwrap();
        let state = compute_state(log, &listing.id, station, NOW)
            .unwrap()
            .unwrap();
        index.upsert(db, listing, &state).unwrap();
    }

    fn give_reputation(db: &Database, provider: &Keypair, composite: f32) {
        let address = Address::from_public_key(provider.public_key());
        let mut profile = ReputationProfile::empty(address);
        profile.trade_reliability = composite / 0.30;
        profile.last_updated = NOW;
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        rrn_storage::reputation_snapshot::put(
            db,
            &address.public_key().to_bytes(),
            wall_now,
            &rrn_crypto::serialize::to_canonical_bytes(profile),
        )
        .unwrap();
    }

    fn need_for(seeker: &Keypair, category: &str, quantity: u32, max_price: Option<i64>) -> Need {
        Need::new(
            Address::from_public_key(seeker.public_key()),
            category.into(),
            quantity,
            max_price,
            VALID_UNTIL,
        )
        .unwrap()
    }

    fn titles(listings: &[Listing]) -> Vec<String> {
        listings.iter().map(|l| l.title.clone()).collect()
    }

    #[test]
    fn a_need_matches_the_listings_that_answer_it() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let growers: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();

        let squash = listing_of(
            &growers[0],
            "food",
            "Squash",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        let honey = listing_of(
            &growers[1],
            "food",
            "Honey",
            900,
            AvailabilityStatus::Available,
            Some(50),
        );
        let hammer = listing_of(
            &growers[2],
            "tools",
            "Hammer",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        publish(&index, &db, &mut log, &station, &growers[0], &squash);
        publish(&index, &db, &mut log, &station, &growers[1], &honey);
        publish(&index, &db, &mut log, &station, &growers[2], &hammer);

        // Everything in the category, when there is no ceiling.
        let need = need_for(&Keypair::generate(), "food", 10, None);
        let mut found = titles(&find_matches(&index, &db, &need, NOW).unwrap());
        found.sort();
        assert_eq!(found, vec!["Honey", "Squash"]);

        // The ceiling excludes the dear one; the other category never appears.
        let need = need_for(&Keypair::generate(), "food", 10, Some(300));
        assert_eq!(
            titles(&find_matches(&index, &db, &need, NOW).unwrap()),
            vec!["Squash"]
        );

        // A category nobody offers in matches nothing.
        let need = need_for(&Keypair::generate(), "medical", 10, None);
        assert!(find_matches(&index, &db, &need, NOW).unwrap().is_empty());
    }

    #[test]
    fn an_expired_need_matches_nothing() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let grower = Keypair::generate();
        let squash = listing_of(
            &grower,
            "food",
            "Squash",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        publish(&index, &db, &mut log, &station, &grower, &squash);
        let need = need_for(&Keypair::generate(), "food", 10, None);

        // Valid through its last second, stale the next — the listing itself is
        // still perfectly on offer either way.
        assert_eq!(
            find_matches(&index, &db, &need, VALID_UNTIL).unwrap().len(),
            1
        );
        assert!(find_matches(&index, &db, &need, VALID_UNTIL + 1)
            .unwrap()
            .is_empty());
        assert!(!need.has_expired(VALID_UNTIL));
        assert!(need.has_expired(VALID_UNTIL + 1));
    }

    #[test]
    fn an_offer_that_cannot_be_taken_up_is_left_out_entirely() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let providers: Vec<Keypair> = (0..3).map(|_| Keypair::generate()).collect();

        let open = listing_of(
            &providers[0],
            "food",
            "Squash",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        let paused = listing_of(
            &providers[1],
            "food",
            "Honey",
            250,
            AvailabilityStatus::Unavailable,
            Some(50),
        );
        let sold_out = listing_of(
            &providers[2],
            "food",
            "Cider",
            250,
            AvailabilityStatus::Available,
            Some(0),
        );
        for (p, l) in providers.iter().zip([&open, &paused, &sold_out]) {
            publish(&index, &db, &mut log, &station, p, l);
        }

        let need = need_for(&Keypair::generate(), "food", 10, None);
        // Ranking them last would still put them in front of the seeker.
        assert_eq!(
            titles(&find_matches(&index, &db, &need, NOW).unwrap()),
            vec!["Squash"]
        );
    }

    #[test]
    fn an_offer_that_fills_the_need_outranks_one_that_only_part_fills_it() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let plenty = Keypair::generate();
        let scarce = Keypair::generate();

        let lots = listing_of(
            &plenty,
            "food",
            "Squash by the crate",
            250,
            AvailabilityStatus::Available,
            Some(100),
        );
        let few = listing_of(
            &scarce,
            "food",
            "Squash, last few",
            250,
            AvailabilityStatus::Available,
            Some(2),
        );
        publish(&index, &db, &mut log, &station, &plenty, &lots);
        publish(&index, &db, &mut log, &station, &scarce, &few);

        let need = need_for(&Keypair::generate(), "food", 20, None);
        let found = find_matches(&index, &db, &need, NOW).unwrap();

        // Still offered — a partial fill is useful — but ranked below the one
        // that can supply the lot.
        assert_eq!(
            titles(&found),
            vec!["Squash by the crate", "Squash, last few"]
        );
        assert_eq!(fill_fraction(Some(100), 20), 1.0);
        assert!((fill_fraction(Some(2), 20) - 0.1).abs() < f32::EPSILON);
        assert_eq!(fill_fraction(None, 20), 1.0);
    }

    #[test]
    fn standing_orders_offers_that_fill_the_need_equally_well() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let humble = Keypair::generate();
        let esteemed = Keypair::generate();

        let theirs = listing_of(
            &humble,
            "food",
            "Squash A",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        let hers = listing_of(
            &esteemed,
            "food",
            "Squash B",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        publish(&index, &db, &mut log, &station, &humble, &theirs);
        publish(&index, &db, &mut log, &station, &esteemed, &hers);
        give_reputation(&db, &esteemed, 2.4);

        let need = need_for(&Keypair::generate(), "food", 10, None);
        assert_eq!(
            titles(&find_matches(&index, &db, &need, NOW).unwrap()),
            vec!["Squash B", "Squash A"]
        );
    }

    #[test]
    fn a_closed_listing_stops_answering_needs() {
        use crate::lifecycle::{append_listing_closed, CloseReason, ListingClosed};

        let db = open_db();
        let mut log = AppendLog::new(&db);
        let station = Keypair::generate().public_key();
        let index = SearchIndex::in_memory();
        let grower = Keypair::generate();
        let squash = listing_of(
            &grower,
            "food",
            "Squash",
            250,
            AvailabilityStatus::Available,
            Some(50),
        );
        publish(&index, &db, &mut log, &station, &grower, &squash);
        let need = need_for(&Keypair::generate(), "food", 10, None);
        assert_eq!(find_matches(&index, &db, &need, NOW).unwrap().len(), 1);

        append_listing_closed(
            &mut log,
            SignedPayload::sign(
                ListingClosed {
                    listing_id: squash.id,
                    reason: CloseReason::ProviderClosed,
                    closed_at: NOW,
                },
                &grower,
            ),
            &station,
        )
        .unwrap();
        let state = compute_state(&log, &squash.id, &station, NOW)
            .unwrap()
            .unwrap();
        index.upsert(&db, &squash, &state).unwrap();

        assert!(find_matches(&index, &db, &need, NOW).unwrap().is_empty());
    }

    #[test]
    fn a_need_must_be_for_something_this_marketplace_trades() {
        let seeker = Address::from_public_key(Keypair::generate().public_key());

        assert_eq!(
            Need::new(seeker, "cryptocurrency".into(), 1, None, VALID_UNTIL),
            Err(NeedError::UnknownCategory("cryptocurrency".into()))
        );
        assert_eq!(
            Need::new(seeker, "food".into(), 0, None, VALID_UNTIL),
            Err(NeedError::ZeroQuantity)
        );
        assert!(Need::new(seeker, "food".into(), 1, None, VALID_UNTIL).is_ok());
    }

    #[test]
    fn only_the_seeker_may_announce_their_own_need() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let seeker = Keypair::generate();
        let impostor = Keypair::generate();
        let need = need_for(&seeker, "food", 10, None);

        let err = append_need_announced(&mut log, SignedPayload::sign(need.clone(), &impostor))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Need(NeedError::SignerNotSeeker { .. })
        ));

        append_need_announced(&mut log, SignedPayload::sign(need, &seeker)).unwrap();
        assert_eq!(log.iter_from(1).count(), 1);
    }

    #[test]
    fn an_invalid_need_never_reaches_the_log() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let seeker = Keypair::generate();
        // Built by hand, bypassing `Need::new`, as a gossiped record could be.
        let need = Need {
            seeker: Address::from_public_key(seeker.public_key()),
            category: "cryptocurrency".into(),
            quantity_needed: 1,
            max_price_centi: None,
            valid_until: VALID_UNTIL,
        };

        let err = append_need_announced(&mut log, SignedPayload::sign(need, &seeker)).unwrap_err();
        assert!(matches!(err, Error::Need(NeedError::UnknownCategory(_))));
        assert_eq!(log.iter_from(1).count(), 0);
    }

    #[test]
    fn an_already_stale_need_may_still_be_announced() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let seeker = Keypair::generate();
        let need = need_for(&seeker, "food", 10, None);

        // Whether it is worth answering is judged when matching, against the
        // reader's clock — not by this station's clock at write time.
        append_need_announced(&mut log, SignedPayload::sign(need.clone(), &seeker)).unwrap();
        assert!(need.has_expired(VALID_UNTIL + 1));
    }

    #[test]
    fn a_need_roundtrips_and_its_wire_tag_is_stable() {
        let seeker = Address::from_public_key(Keypair::generate().public_key());
        for max_price_centi in [Some(250_i64), None] {
            let need = Need {
                seeker,
                category: "food".into(),
                quantity_needed: 12,
                max_price_centi,
                valid_until: VALID_UNTIL,
            };
            let cbor: CBOR = need.clone().into();
            assert_eq!(Need::try_from(cbor).unwrap(), need);
        }

        let cbor: CBOR = Need {
            seeker,
            category: "food".into(),
            quantity_needed: 1,
            max_price_centi: None,
            valid_until: VALID_UNTIL,
        }
        .into();
        let CBORCase::Map(map) = cbor.into_case() else {
            panic!("a need encodes as a map");
        };
        assert_eq!(
            map.extract::<&str, String>("kind").unwrap(),
            "rrn.marketplace.need_announced.v1"
        );
    }

    #[test]
    fn a_need_read_back_off_the_log_is_the_one_that_was_announced() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let seeker = Keypair::generate();
        let need = need_for(&seeker, "food", 12, Some(250));
        append_need_announced(&mut log, SignedPayload::sign(need.clone(), &seeker)).unwrap();

        let entry = log.iter_from(1).next().unwrap().unwrap();
        let decoded =
            rrn_crypto::serialize::from_canonical_bytes::<Need>(&entry.payload.bytes).unwrap();
        assert_eq!(decoded, need);
    }

    #[test]
    fn announced_needs_lists_one_seekers_needs_in_log_order_with_their_seqs() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let seeker = Keypair::generate();
        let other = Keypair::generate();

        let first = need_for(&seeker, "food", 12, Some(250));
        let second = need_for(&seeker, "tools", 1, None);
        let theirs = need_for(&other, "food", 3, None);
        append_need_announced(&mut log, SignedPayload::sign(first.clone(), &seeker)).unwrap();
        append_need_announced(&mut log, SignedPayload::sign(theirs, &other)).unwrap();
        append_need_announced(&mut log, SignedPayload::sign(second.clone(), &seeker)).unwrap();

        let mine = announced_needs(&log, &Address::from_public_key(seeker.public_key())).unwrap();
        assert_eq!(mine.len(), 2, "another seeker's need is not mine");
        assert_eq!(mine[0].need, first);
        assert_eq!(mine[1].need, second);
        // The seq is the log's own, so it skips the entry in between.
        assert_eq!(mine[0].seq, 1);
        assert_eq!(mine[1].seq, 3);
    }

    #[test]
    fn announced_needs_skips_a_need_its_signer_did_not_seek() {
        let db = open_db();
        let seeker = Keypair::generate();
        let impostor = Keypair::generate();
        // A need naming `seeker` but signed by someone else — what a gossiped
        // entry could carry, since replication does not run the append guard.
        let need = need_for(&seeker, "food", 12, None);
        let mut log = AppendLog::new(&db);
        log.append(SignedPayload::sign(need, &impostor)).unwrap();

        let mine = announced_needs(&log, &Address::from_public_key(seeker.public_key())).unwrap();
        assert!(mine.is_empty(), "an unsigned-for need is not evidence");
    }

    #[test]
    fn announced_needs_returns_expired_needs_too() {
        let db = open_db();
        let mut log = AppendLog::new(&db);
        let seeker = Keypair::generate();
        let mut need = need_for(&seeker, "food", 1, None);
        need.valid_until = NOW - 1;
        append_need_announced(&mut log, SignedPayload::sign(need, &seeker)).unwrap();

        // Listing them is not judging them: a seeker reviewing what they asked
        // for needs to see the stale entries to know to restate them.
        let mine = announced_needs(&log, &Address::from_public_key(seeker.public_key())).unwrap();
        assert_eq!(mine.len(), 1);
        assert!(mine[0].need.has_expired(NOW));
    }
}
