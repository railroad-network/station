//! Marketplace reads for the mobile and the CLI (T1.7.0).
//!
//! M1.6 built the marketplace ([`rrn_marketplace`]) but nothing in the workspace
//! depended on it, so no listing was reachable over any network surface. This
//! module is that read path: it turns [`SearchHit`]s and a
//! [`ListingState`] into the flat, JSON-shaped views a browse screen and a
//! listing-detail screen render, and it is the one place the wire shape of a
//! listing lives.
//!
//! # A card carries its provider's band, not a promise to go and ask
//!
//! A browse row shows who is offering and what they are worth trading with, so
//! every [`ListingCard`] carries the provider's band inline. The alternative —
//! the client calling `reputation_band` per row — is a round trip per card on a
//! phone's LAN connection, and 50 of those is the difference between a screen
//! that loads and one that visibly fills in. Ranking already read each
//! provider's composite from the snapshot cache to order the results
//! ([`rrn_marketplace::search`]), so the band is a free byproduct of work that
//! has happened by the time a hit exists.
//!
//! # Search paging is bounded here
//!
//! [`rrn_marketplace::search::SearchQuery`] takes whatever `limit` its caller
//! asks for, which is fine inside the crate and not fine on a network surface —
//! the M1.6 threat model names this as the gap M1.7 has to close. [`search`]
//! clamps to [`MAX_SEARCH_LIMIT`] rather than erroring: a client asking for too
//! much gets a page, not a failure, and no caller can turn one request into an
//! unbounded index read.

use serde::Serialize;

use rrn_identity::address::Address;
use rrn_marketplace::lifecycle::{CloseReason, ListingState};
use rrn_marketplace::listing::{Listing, ListingId, Surface};
use rrn_marketplace::search::{SearchHit, SearchIndex, SearchQuery};
use rrn_reputation::model::ReputationBand;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::reputation_view::band_name;

/// The most listings one search may return, however large a `limit` the caller
/// sends. Generous next to a phone screen (a page is ~20 rows) and small enough
/// that a hostile client cannot make one request expensive.
pub const MAX_SEARCH_LIMIT: usize = 100;

/// What a listing's availability says, flattened. The three fields mean
/// different things per surface — capacity for Goods, next slot for Services,
/// neither for Commons — so the view sends all three and lets the client draw
/// the fulfillment indicator its surface calls for.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AvailabilityRow {
    /// `available`, `limited_stock`, or `unavailable`.
    pub status: &'static str,
    /// Units left, for Goods.
    pub capacity: Option<u32>,
    /// Unix seconds of the next open slot, for Services.
    pub next_slot: Option<i64>,
}

/// One row in the browse list.
///
/// Everything a card draws and nothing more: the detail screen
/// ([`ListingDetailView`]) is where description, requirements, and provider
/// context arrive, on a tap the member chose to make.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ListingCard {
    /// Content address, hex — the id the detail read and an inquiry both take.
    pub listing_id: String,
    /// The provider's bech32m `rrn1…` address.
    pub provider: String,
    /// `goods`, `services`, or `commons`.
    pub surface: &'static str,
    /// The controlled-vocabulary category (also an ADR-0009 domain tag).
    pub category: String,
    /// The listing's title.
    pub title: String,
    /// The price in centi-Commons. Negative is legal on `commons` (a subsidy).
    pub amount_centi: i64,
    /// `fixed` or `negotiable` — what `amount_centi` *is*.
    pub pricing_model: &'static str,
    /// Whether offers are invited (independent of `pricing_model`).
    pub negotiable: bool,
    /// Availability, per surface.
    pub availability: AvailabilityRow,
    /// The provider's current composite, as ranking saw it.
    pub provider_composite: f32,
    /// The band that composite falls in — the chip the card shows.
    pub provider_band: &'static str,
    /// Unix seconds the listing was published.
    pub created_at: i64,
    /// Unix seconds it stops being on offer, if it does.
    pub expires_at: Option<i64>,
}

/// A listing in full, for the detail screen.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ListingDetailView {
    /// The same fields the card carries, so one renderer can draw the header.
    #[serde(flatten)]
    pub card: ListingCard,
    /// The community the listing was published in.
    pub community: String,
    /// The full description (markdown, per T1.7.2).
    pub description: String,
    /// The minimum capped composite an inquirer must have. Recorded provider
    /// intent; T1.7.4 is where it becomes a check against a specific buyer.
    pub min_reputation: f32,
    /// Whether the provider will deal only with members of `community`. Same
    /// standing as `min_reputation`: stated here, enforced in T1.7.4.
    pub community_member_only: bool,
    /// The dispute tier a sale would run under (1 or 2 in Phase 1).
    pub oracle_tier: u8,
    /// `active`, `closed`, or `expired`. A client must treat anything but
    /// `active` as not for sale — including `expired`, which means the station's
    /// sweep has not yet written the close record (ADR-0010).
    pub state: &'static str,
    /// Why it closed, when `state` is `closed`.
    pub close_reason: Option<&'static str>,
    /// Unix seconds it closed, when `state` is `closed`.
    pub closed_at: Option<i64>,
    /// How many members have vouched for the provider — the vouching context a
    /// buyer weighs alongside the band. A live log scan, affordable because it
    /// is one member on one tap (see [`crate::vouch_view`]).
    pub provider_vouches_received: u64,
}

/// Runs a search and shapes the hits into cards, clamping `limit` to
/// [`MAX_SEARCH_LIMIT`].
///
/// `query.limit` is overwritten rather than validated — see the module note on
/// why a too-large page is answered and not refused.
pub fn search(
    index: &SearchIndex,
    db: &Database,
    mut query: SearchQuery,
    now: i64,
) -> rrn_marketplace::Result<Vec<ListingCard>> {
    query.limit = query.limit.clamp(1, MAX_SEARCH_LIMIT);
    Ok(index
        .search(db, &query, now)?
        .into_iter()
        .map(card_of_hit)
        .collect())
}

/// The full view of one listing, or `None` when this log has never seen it
/// created.
///
/// Reads the listing's state from the **log**, not the index: a detail screen is
/// the one place a stale cache would be read as authoritative, and the log is
/// what ADR-0010 says is canonical. The provider's band comes from the snapshot
/// cache as everywhere else.
pub fn detail(
    db: &Database,
    listing_id: &ListingId,
    station: &rrn_crypto::keypair::PublicKey,
    now: i64,
) -> rrn_marketplace::Result<Option<ListingDetailView>> {
    let log = AppendLog::new(db);
    let Some(state) = rrn_marketplace::lifecycle::compute_state(&log, listing_id, station, now)?
    else {
        return Ok(None);
    };
    // `Draft` is the one state carrying no listing, and `compute_state` never
    // returns it (an absent listing is `None` above).
    let Some(listing) = state.listing() else {
        return Ok(None);
    };

    // Both of these are reads of derived caches/scans, and neither is worth
    // failing a detail view over: a provider with an unreadable snapshot still
    // has a listing to show. Fall back to what an unscored, unvouched provider
    // would read as.
    let composite = provider_composite(db, &listing.provider, now);
    let vouches = crate::vouch_view::member_vouch_counts(db, &listing.provider)
        .map(|counts| counts.received)
        .unwrap_or(0);

    Ok(Some(ListingDetailView {
        card: card_of(listing, composite),
        community: listing.community.clone(),
        description: listing.description.clone(),
        min_reputation: listing.requirements.min_reputation,
        community_member_only: listing.requirements.community_member_only,
        oracle_tier: listing.oracle_tier,
        state: state_name(&state),
        close_reason: match &state {
            ListingState::Closed { reason, .. } => Some(close_reason_name(*reason)),
            _ => None,
        },
        closed_at: match &state {
            ListingState::Closed { closed_at, .. } => Some(*closed_at),
            _ => None,
        },
        provider_vouches_received: vouches,
    }))
}

/// The provider's current composite from the snapshot cache, or `0.0` on a miss.
///
/// Never a fresh replay: search ranks from the cache for the reason ADR-0010
/// gives (scoring is O(V·N) since anchoring, and a page of results must not mean
/// a page of replays on the single writer thread), and a detail view must not
/// quietly be the one path that does. An unscored provider reads as `New`, which
/// is what they are.
fn provider_composite(db: &Database, provider: &Address, now: i64) -> f32 {
    rrn_reputation::snapshot::get_cached_profile(
        db,
        provider,
        crate::reputation_view::BAND_MAX_AGE_SECS,
    )
    .ok()
    .flatten()
    .filter(|profile| now - profile.last_updated <= rrn_marketplace::search::MAX_SNAPSHOT_AGE_SECS)
    .map(|profile| profile.composite())
    .unwrap_or(0.0)
}

/// Shapes a ranked hit into a card, reusing the composite ranking already read.
fn card_of_hit(hit: SearchHit) -> ListingCard {
    card_of(&hit.listing, hit.provider_reputation)
}

/// Shapes a listing plus its provider's composite into a card.
fn card_of(listing: &Listing, provider_composite: f32) -> ListingCard {
    ListingCard {
        listing_id: crate::core::hex(&listing.id.to_bytes()),
        provider: listing.provider.to_string(),
        surface: surface_name(listing.surface),
        category: listing.category.clone(),
        title: listing.title.clone(),
        amount_centi: listing.pricing.amount_centi,
        pricing_model: listing.pricing.model.tag(),
        negotiable: listing.pricing.negotiable,
        availability: AvailabilityRow {
            status: listing.availability.status.tag(),
            capacity: listing.availability.capacity,
            next_slot: listing.availability.next_slot,
        },
        provider_composite,
        provider_band: band_name(ReputationBand::from_composite(provider_composite)),
        created_at: listing.created_at,
        expires_at: listing.expires_at,
    }
}

/// The wire name of a surface. Reuses the crate's own tag so the browse tabs
/// filter on exactly the string the log records.
fn surface_name(surface: Surface) -> &'static str {
    surface.tag()
}

/// The wire name of a lifecycle state.
fn state_name(state: &ListingState) -> &'static str {
    match state {
        ListingState::Draft => "draft",
        ListingState::Active(_) => "active",
        ListingState::Closed { .. } => "closed",
        ListingState::Expired { .. } => "expired",
    }
}

/// The wire name of a close reason.
fn close_reason_name(reason: CloseReason) -> &'static str {
    match reason {
        CloseReason::ExpirationReached => "expiration_reached",
        CloseReason::ProviderClosed => "provider_closed",
        CloseReason::StationCleanup => "station_cleanup",
    }
}
