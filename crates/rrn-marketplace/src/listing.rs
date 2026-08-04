//! Listings — a member's signed offer of a good or service, priced in the
//! Common.
//!
//! One schema serves all three surfaces (Goods, Services, Commons) behind the
//! [`Surface`] discriminant, per
//! [ADR-0010](../../../docs/adr/0010-marketplace-data-model.md). The fields mean
//! slightly different things on each surface — capacity is inventory for Goods
//! and pool size for Commons — but search, the index, and the transaction
//! linkage all see one type.
//!
//! # A listing names itself
//!
//! A [`ListingId`] is the Blake3 hash of the listing's canonical bytes, so the
//! `id` field is **not part of the hashed content** — it *is* the hash of
//! everything else. [`From<Listing> for CBOR`] omits it; [`TryFrom<CBOR>`]
//! recomputes it. A decoded listing therefore cannot carry an id that disagrees
//! with its contents, and editing any field yields a different listing rather
//! than a changed one. This mirrors `rrn_ledger::transaction::TransactionId`.
//!
//! # Where validation runs
//!
//! [`Listing::new`] validates and refuses to build an invalid listing: an
//! invalid listing is one that cannot exist, not one that exists and is ignored.
//! Decoding does **not** validate — it is structural, like the ledger's records,
//! because `TryFrom<CBOR>` can only report a `dcbor::Error` and would throw away
//! which rule was broken. Replay revalidates with [`Listing::validate`] (T1.6.4),
//! where a typed [`ListingError`] survives.
//!
//! Two rules are deliberately *not* here, because they need context a listing
//! does not carry: that the signer is the `provider`, and that an update's
//! signer matches the original. Both belong to the append/replay path (T1.6.4).

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_reputation::model::max_composite_now;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Discriminant string carried in a listing's canonical CBOR. Also a schema
/// version marker: a later listing shape takes a new tag rather than silently
/// reinterpreting these bytes.
pub(crate) const LISTING_KIND: &str = "rrn.marketplace.listing.v1";

/// The controlled category vocabulary (ADR-0010).
///
/// Controlled, not free-form, because a marketplace category and a reputation
/// `DomainTag` are the same namespace (ADR-0009: domain competence is keyed by
/// category). Free-form categories would be free-form reputation dimensions — a
/// member could mint a private domain, be its only participant, and hold a
/// perfect score in it. Expanding this list is a protocol change.
pub const CATEGORIES: &[&str] = &[
    "agriculture",
    "construction",
    "education",
    "food",
    "medical",
    "other",
    "tools",
    "transportation",
];

/// Lowest oracle tier a Phase-1 listing may claim (the M1.8 ladder).
pub const ORACLE_TIER_MIN: u8 = 1;
/// Highest oracle tier a Phase-1 listing may claim; tiers 3+ arrive with M1.8.
pub const ORACLE_TIER_MAX: u8 = 2;

/// Longest permitted `title`, in bytes of UTF-8.
///
/// Log entries are permanent and replicated, so the length of a field any
/// paired member can write is a storage cost the whole community carries
/// forever. The bound is generous for a real title and small enough that a
/// listing cannot be used as bulk storage.
pub const MAX_TITLE_BYTES: usize = 200;

/// Longest permitted `description`, in bytes of UTF-8. See [`MAX_TITLE_BYTES`]
/// for why there is a bound at all.
pub const MAX_DESCRIPTION_BYTES: usize = 8 * 1024;

/// The content address of a listing: the Blake3 hash of its canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, std::hash::Hash, Debug, Serialize, Deserialize)]
pub struct ListingId(pub Hash);

impl ListingId {
    /// The 32 raw hash bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Bare hex, the form a listing id takes everywhere a person meets one — a CLI
/// argument, a wire field, an error message. `Debug` stays wrapped
/// (`ListingId(Hash(…))`) for panics and assertions; error text uses this, since
/// `{listing_id:?}` in a message a member reads is a leaked Rust type name.
impl std::fmt::Display for ListingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// A total order over the hash bytes, so a `ListingId` can key a `BTreeMap`
// during replay. Content, not chronology: arbitrary but identical everywhere.
impl Ord for ListingId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for ListingId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<ListingId> for CBOR {
    fn from(id: ListingId) -> Self {
        CBOR::to_byte_string(id.0.to_bytes())
    }
}

impl TryFrom<CBOR> for ListingId {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(ListingId(Hash::from_bytes(bytes)))
    }
}

/// Which marketplace a listing belongs to (design overview Section 9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Surface {
    /// Physical items, inventory-based: `capacity` counts units.
    Goods,
    /// Labour and skills, time-based: `next_slot` is the next bookable time.
    Services,
    /// Community-pooled resources, free or subsidized.
    Commons,
}

impl Surface {
    /// The wire discriminant, as it appears in canonical CBOR.
    ///
    /// Public because it is also what a client filters and displays on: a read
    /// path outside this crate that spelled these strings itself would be a
    /// second copy of the vocabulary, free to drift from the one the log records.
    pub fn tag(self) -> &'static str {
        match self {
            Surface::Goods => "goods",
            Surface::Services => "services",
            Surface::Commons => "commons",
        }
    }

    /// The inverse of [`tag`](Self::tag), for a caller parsing a surface out of
    /// something that is not CBOR — a search filter off the wire, a CLI flag.
    /// Lives here so that the decoder below and every such caller agree on the
    /// vocabulary by construction.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "goods" => Some(Surface::Goods),
            "services" => Some(Surface::Services),
            "commons" => Some(Surface::Commons),
            _ => None,
        }
    }
}

impl From<Surface> for CBOR {
    fn from(s: Surface) -> Self {
        s.tag().into()
    }
}

impl TryFrom<CBOR> for Surface {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        Surface::from_tag(&cbor.try_into_text()?).ok_or(dcbor::Error::WrongType)
    }
}

/// How a listing's `amount_centi` should be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingModel {
    /// The amount is the price.
    Fixed,
    /// The amount is an opening ask; the real price is negotiated.
    Negotiable,
}

impl PricingModel {
    /// The wire discriminant (see [`Surface::tag`] on why it is public).
    pub fn tag(self) -> &'static str {
        match self {
            PricingModel::Fixed => "fixed",
            PricingModel::Negotiable => "negotiable",
        }
    }
}

impl From<PricingModel> for CBOR {
    fn from(m: PricingModel) -> Self {
        m.tag().into()
    }
}

impl TryFrom<CBOR> for PricingModel {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        match cbor.try_into_text()?.as_str() {
            "fixed" => Ok(PricingModel::Fixed),
            "negotiable" => Ok(PricingModel::Negotiable),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// What a listing costs, in the same signed centicommons the ledger uses.
///
/// [`model`](Self::model) and [`negotiable`](Self::negotiable) overlap in the
/// design doc and are given distinct meanings here: `model` says what the amount
/// *is*, `negotiable` says whether the provider invites offers. `Fixed` plus
/// `negotiable` is meaningful ("3 Commons, but make me an offer"); `Negotiable`
/// with `negotiable: false` is a contradiction and is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Pricing {
    /// Signed centicommons (1 Common = 100). May be `<= 0` only on Commons,
    /// where a negative amount is a subsidy paid to whoever takes the work on.
    pub amount_centi: i64,
    /// Whether `amount_centi` is a price or an opening ask.
    pub model: PricingModel,
    /// Whether the provider invites offers.
    pub negotiable: bool,
}

impl From<Pricing> for CBOR {
    fn from(p: Pricing) -> Self {
        let mut m = Map::new();
        m.insert("amount_centi", p.amount_centi);
        m.insert("model", p.model);
        m.insert("negotiable", p.negotiable);
        m.into()
    }
}

impl TryFrom<CBOR> for Pricing {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(Pricing {
            amount_centi: map.extract::<&str, i64>("amount_centi")?,
            model: map.extract::<&str, PricingModel>("model")?,
            negotiable: map.extract::<&str, bool>("negotiable")?,
        })
    }
}

/// Whether a listing can be taken up right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AvailabilityStatus {
    /// Available on the stated terms.
    Available,
    /// Available, but constrained — the provider is signalling scarcity.
    LimitedStock,
    /// Not currently available, without the listing being closed.
    Unavailable,
}

impl AvailabilityStatus {
    /// The wire discriminant (see [`Surface::tag`] on why it is public).
    pub fn tag(self) -> &'static str {
        match self {
            AvailabilityStatus::Available => "available",
            AvailabilityStatus::LimitedStock => "limited_stock",
            AvailabilityStatus::Unavailable => "unavailable",
        }
    }
}

impl From<AvailabilityStatus> for CBOR {
    fn from(s: AvailabilityStatus) -> Self {
        s.tag().into()
    }
}

impl TryFrom<CBOR> for AvailabilityStatus {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        match cbor.try_into_text()?.as_str() {
            "available" => Ok(AvailabilityStatus::Available),
            "limited_stock" => Ok(AvailabilityStatus::LimitedStock),
            "unavailable" => Ok(AvailabilityStatus::Unavailable),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// What is on offer, and when.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Availability {
    /// Whether the listing can be taken up.
    pub status: AvailabilityStatus,
    /// Units available: inventory (Goods), concurrent bookings (Services), pool
    /// size (Commons). `Some(0)` is sold out; `None` is unlimited.
    pub capacity: Option<u32>,
    /// Next bookable time, Unix seconds. Meaningful for Services and pooled
    /// Commons; unused for Goods.
    pub next_slot: Option<i64>,
}

impl From<Availability> for CBOR {
    fn from(a: Availability) -> Self {
        let mut m = Map::new();
        m.insert("status", a.status);
        // These are text-or-null rather than omitted-when-absent: the
        // omit-when-`None` rule ADR-0010 states is about *adding* a field to a
        // record that is already content-addressed, which cannot apply to a
        // field that has been present since the first version of this type.
        match a.capacity {
            Some(n) => m.insert("capacity", n),
            None => m.insert("capacity", CBOR::null()),
        }
        match a.next_slot {
            Some(t) => m.insert("next_slot", t),
            None => m.insert("next_slot", CBOR::null()),
        }
        m.into()
    }
}

impl TryFrom<CBOR> for Availability {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(Availability {
            status: map.extract::<&str, AvailabilityStatus>("status")?,
            capacity: map.get::<&str, u32>("capacity"),
            next_slot: map.get::<&str, i64>("next_slot"),
        })
    }
}

/// What a taker must satisfy before the provider will transact.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Requirements {
    /// Minimum composite reputation, compared against the taker's **capped**
    /// (public) composite — never the raw score, which exists only to make
    /// anchoring computable (ADR-0009). Bounded above by
    /// [`max_composite_now`], so a listing cannot demand standing that no
    /// member of the network can hold.
    pub min_reputation: f32,
    /// Whether the taker must belong to the listing's community.
    pub community_member_only: bool,
    /// Phase 2. Must be `false` in Phase 1.
    pub federation_only: bool,
}

impl From<Requirements> for CBOR {
    fn from(r: Requirements) -> Self {
        let mut m = Map::new();
        m.insert("min_reputation", r.min_reputation);
        m.insert("community_member_only", r.community_member_only);
        m.insert("federation_only", r.federation_only);
        m.into()
    }
}

impl TryFrom<CBOR> for Requirements {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(Requirements {
            min_reputation: map.extract::<&str, f32>("min_reputation")?,
            community_member_only: map.extract::<&str, bool>("community_member_only")?,
            federation_only: map.extract::<&str, bool>("federation_only")?,
        })
    }
}

/// How often a recurring service bills (T1.7.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frequency {
    /// Once a day.
    Daily,
    /// Once a week.
    Weekly,
    /// Once every 30 days (fixed in Phase 1 — no calendar months).
    Monthly,
    /// A bespoke period, in seconds (must be positive).
    Custom(u32),
}

impl Frequency {
    /// The period length in seconds — how far apart charges fall.
    pub fn period_secs(self) -> i64 {
        match self {
            Frequency::Daily => 86_400,
            Frequency::Weekly => 7 * 86_400,
            Frequency::Monthly => 30 * 86_400,
            Frequency::Custom(secs) => i64::from(secs),
        }
    }
}

impl From<Frequency> for CBOR {
    fn from(f: Frequency) -> Self {
        let mut m = Map::new();
        match f {
            Frequency::Daily => m.insert("unit", "daily"),
            Frequency::Weekly => m.insert("unit", "weekly"),
            Frequency::Monthly => m.insert("unit", "monthly"),
            Frequency::Custom(secs) => {
                m.insert("unit", "custom");
                m.insert("secs", secs);
            }
        }
        m.into()
    }
}

impl TryFrom<CBOR> for Frequency {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        match map.extract::<&str, String>("unit")?.as_str() {
            "daily" => Ok(Frequency::Daily),
            "weekly" => Ok(Frequency::Weekly),
            "monthly" => Ok(Frequency::Monthly),
            "custom" => Ok(Frequency::Custom(map.extract::<&str, u32>("secs")?)),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// The recurring cadence a service listing declares (T1.7.7): the provider's
/// standing terms for a subscription, which a [`ServiceContract`](crate::contract::ServiceContract)
/// snapshots when a buyer signs up. The per-period price is the listing's own
/// [`Pricing`]; these are the *other* terms of the commitment.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecurringTerms {
    /// How often a period falls due.
    pub frequency: Frequency,
    /// How many periods the commitment runs for.
    pub duration_periods: u32,
    /// How much notice either side must give to end it early.
    pub notice_period_days: u32,
    /// A charge levied on the party who ends it before its natural end.
    pub early_termination_penalty_centi: i64,
}

impl From<RecurringTerms> for CBOR {
    fn from(t: RecurringTerms) -> Self {
        let mut m = Map::new();
        m.insert("frequency", t.frequency);
        m.insert("duration_periods", t.duration_periods);
        m.insert("notice_period_days", t.notice_period_days);
        m.insert(
            "early_termination_penalty_centi",
            t.early_termination_penalty_centi,
        );
        m.into()
    }
}

impl TryFrom<CBOR> for RecurringTerms {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(RecurringTerms {
            frequency: map.extract::<&str, Frequency>("frequency")?,
            duration_periods: map.extract::<&str, u32>("duration_periods")?,
            notice_period_days: map.extract::<&str, u32>("notice_period_days")?,
            early_termination_penalty_centi: map
                .extract::<&str, i64>("early_termination_penalty_centi")?,
        })
    }
}

/// A standing, signed offer on the log.
///
/// Every field is provider-asserted: nothing here verifies that the grain
/// exists or the slot is real. The guarantee is narrow and exact — *the
/// provider said this, signed, at this time, and cannot deny it*. Oracle tiers
/// (M1.8) and the dispute window are what will bind claims to reality.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Listing {
    /// Content address: Blake3 of every *other* field's canonical bytes.
    /// Derived, not independent — see the module docs.
    pub id: ListingId,
    /// The member making the offer. Must equal the signer of the record.
    pub provider: Address,
    /// The community the listing belongs to. Immutable after creation.
    pub community: String,
    /// Goods, Services, or Commons. Immutable after creation.
    pub surface: Surface,
    /// One of [`CATEGORIES`]. Immutable after creation, because it feeds the
    /// domain-competence dimension of reputation.
    pub category: String,
    /// Short human-readable name for the offer.
    pub title: String,
    /// Longer prose. Markdown is permitted but nothing parses it: Phase 1
    /// renders it as plain text with newlines preserved.
    pub description: String,
    /// What it costs.
    pub pricing: Pricing,
    /// What is on offer, and when.
    pub availability: Availability,
    /// What the provider asks of a taker.
    pub requirements: Requirements,
    /// Claimed oracle tier, `1..=2` in Phase 1 (the M1.8 ladder).
    pub oracle_tier: u8,
    /// Phase 2 federation visibility. Must be `false` in Phase 1.
    pub federation_visible: bool,
    /// Unix seconds the provider created the listing, from signed content.
    pub created_at: i64,
    /// Unix seconds after which the listing is stale and the station's sweep
    /// should close it. `None` means it stands until closed by hand.
    pub expires_at: Option<i64>,
    /// The recurring cadence, when this is a subscription service (T1.7.7);
    /// `None` for a one-off offer. **Additive to a content-addressed record**, so
    /// it is OMITTED from the CBOR when `None` (ADR-0010) — a listing published
    /// before this field existed keeps its id.
    pub recurring: Option<RecurringTerms>,
}

impl Listing {
    /// Builds a validated listing and computes its content-addressed
    /// [`id`](Self::id).
    ///
    /// Returns the first rule broken; there is no partially-valid listing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Address,
        community: String,
        surface: Surface,
        category: String,
        title: String,
        description: String,
        pricing: Pricing,
        availability: Availability,
        requirements: Requirements,
        oracle_tier: u8,
        federation_visible: bool,
        created_at: i64,
        expires_at: Option<i64>,
    ) -> Result<Self, ListingError> {
        let listing = Self::assembled(
            provider,
            community,
            surface,
            category,
            title,
            description,
            pricing,
            availability,
            requirements,
            oracle_tier,
            federation_visible,
            created_at,
            expires_at,
        );
        listing.validate()?;
        Ok(listing)
    }

    /// Assembles a listing and computes its id, *without* validating. Private:
    /// the only unvalidated path is decoding, which is structural by design.
    #[allow(clippy::too_many_arguments)]
    fn assembled(
        provider: Address,
        community: String,
        surface: Surface,
        category: String,
        title: String,
        description: String,
        pricing: Pricing,
        availability: Availability,
        requirements: Requirements,
        oracle_tier: u8,
        federation_visible: bool,
        created_at: i64,
        expires_at: Option<i64>,
    ) -> Self {
        let mut listing = Self {
            // Placeholder; overwritten immediately by `compute_id`, which
            // hashes every field *except* `id`.
            id: ListingId(Hash::from_bytes([0u8; 32])),
            provider,
            community,
            surface,
            category,
            title,
            description,
            pricing,
            availability,
            requirements,
            oracle_tier,
            federation_visible,
            created_at,
            expires_at,
            // A one-off offer carries no cadence; a subscription adds one with
            // `with_recurring`. Absent-when-`None` keeps a plain listing's bytes
            // (and id) as they were before this field existed.
            recurring: None,
        };
        listing.id = listing.compute_id();
        listing
    }

    /// Declares this listing a recurring service on the given terms (T1.7.7),
    /// recomputing its content [`id`](Self::id) with the cadence included. Only a
    /// `Services` listing may carry one — [`validate`](Self::validate) enforces it.
    pub fn with_recurring(mut self, terms: RecurringTerms) -> Self {
        self.recurring = Some(terms);
        self.id = self.compute_id();
        self
    }

    /// Recomputes the content address from the current field values.
    fn compute_id(&self) -> ListingId {
        // `Into<CBOR>` omits `id`, so this hashes only the content.
        ListingId(Hash::of(&to_canonical_bytes(self.clone())))
    }

    /// Checks every rule ADR-0010 places on a listing's own contents.
    ///
    /// Called by [`new`](Self::new), and again by replay on decoded listings —
    /// decoding is structural and does not enforce policy.
    pub fn validate(&self) -> Result<(), ListingError> {
        if self.title.trim().is_empty() {
            return Err(ListingError::EmptyTitle);
        }
        if self.title.len() > MAX_TITLE_BYTES {
            return Err(ListingError::TitleTooLong {
                bytes: self.title.len(),
                max: MAX_TITLE_BYTES,
            });
        }
        if self.description.len() > MAX_DESCRIPTION_BYTES {
            return Err(ListingError::DescriptionTooLong {
                bytes: self.description.len(),
                max: MAX_DESCRIPTION_BYTES,
            });
        }
        if self.community.trim().is_empty() {
            return Err(ListingError::EmptyCommunity);
        }
        if !CATEGORIES.contains(&self.category.as_str()) {
            return Err(ListingError::UnknownCategory(self.category.clone()));
        }
        // Surface-scoped on purpose: Commons is the pooled surface, where zero
        // is normal and a negative amount is a subsidy — the community paying a
        // member to take a responsibility on. The ledger's sign convention
        // already expresses that direction.
        if self.surface != Surface::Commons && self.pricing.amount_centi < 0 {
            return Err(ListingError::NegativeAmount {
                surface: self.surface,
                amount_centi: self.pricing.amount_centi,
            });
        }
        if self.pricing.model == PricingModel::Negotiable && !self.pricing.negotiable {
            return Err(ListingError::ContradictoryPricing);
        }
        if !(ORACLE_TIER_MIN..=ORACLE_TIER_MAX).contains(&self.oracle_tier) {
            return Err(ListingError::OracleTierOutOfRange {
                tier: self.oracle_tier,
                min: ORACLE_TIER_MIN,
                max: ORACLE_TIER_MAX,
            });
        }
        if self.federation_visible {
            return Err(ListingError::FederationVisibleNotYet);
        }
        if self.requirements.federation_only {
            return Err(ListingError::FederationOnlyNotYet);
        }
        let reachable = max_composite_now();
        if self.requirements.min_reputation < 0.0 || self.requirements.min_reputation > reachable {
            return Err(ListingError::MinReputationOutOfRange {
                asked: self.requirements.min_reputation,
                reachable,
            });
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= self.created_at {
                return Err(ListingError::ExpiryNotAfterCreation {
                    created_at: self.created_at,
                    expires_at,
                });
            }
        }
        if let Some(terms) = self.recurring {
            // A subscription is a service commitment; goods and commons don't run
            // on a cadence.
            if self.surface != Surface::Services {
                return Err(ListingError::RecurringNotAService {
                    surface: self.surface,
                });
            }
            if terms.duration_periods == 0 {
                return Err(ListingError::RecurringZeroDuration);
            }
            if matches!(terms.frequency, Frequency::Custom(0)) {
                return Err(ListingError::RecurringZeroPeriod);
            }
            if terms.early_termination_penalty_centi < 0 {
                return Err(ListingError::NegativePenalty {
                    penalty_centi: terms.early_termination_penalty_centi,
                });
            }
        }
        Ok(())
    }
}

/// A rule a listing's own contents broke. One variant per check, so a caller
/// (and a test) can tell *which* rule caught it.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum ListingError {
    /// `title` is empty or only whitespace.
    #[error("listing title is empty")]
    EmptyTitle,
    /// `title` exceeds [`MAX_TITLE_BYTES`].
    #[error("listing title is {bytes} bytes, over the {max}-byte limit")]
    TitleTooLong {
        /// Actual length in bytes.
        bytes: usize,
        /// The limit.
        max: usize,
    },
    /// `description` exceeds [`MAX_DESCRIPTION_BYTES`].
    #[error("listing description is {bytes} bytes, over the {max}-byte limit")]
    DescriptionTooLong {
        /// Actual length in bytes.
        bytes: usize,
        /// The limit.
        max: usize,
    },
    /// `community` is empty or only whitespace.
    #[error("listing community is empty")]
    EmptyCommunity,
    /// `category` is outside [`CATEGORIES`].
    #[error("listing category {0:?} is not in the controlled vocabulary")]
    UnknownCategory(String),
    /// A negative price on a surface that is not Commons.
    #[error("listing on {surface:?} priced at {amount_centi} centicommons; only Commons may be subsidized")]
    NegativeAmount {
        /// The surface that forbids it.
        surface: Surface,
        /// The offending amount.
        amount_centi: i64,
    },
    /// `PricingModel::Negotiable` with `negotiable: false` — an opening ask the
    /// provider will not negotiate.
    #[error("listing is priced as negotiable but does not invite offers")]
    ContradictoryPricing,
    /// `oracle_tier` outside the Phase-1 range.
    #[error("listing claims oracle tier {tier}, outside the supported {min}..={max}")]
    OracleTierOutOfRange {
        /// The claimed tier.
        tier: u8,
        /// Lowest supported tier.
        min: u8,
        /// Highest supported tier.
        max: u8,
    },
    /// `federation_visible` is `true` before federation exists.
    #[error("listing is marked federation-visible, which nothing honors in Phase 1")]
    FederationVisibleNotYet,
    /// `requirements.federation_only` is `true` before federation exists.
    #[error("listing requires federation membership, which nothing honors in Phase 1")]
    FederationOnlyNotYet,
    /// `min_reputation` is negative, or above the composite anyone can reach —
    /// a listing arithmetically closed to every member.
    #[error("listing demands reputation {asked}, outside the reachable 0.0..={reachable}")]
    MinReputationOutOfRange {
        /// What the listing asked for.
        asked: f32,
        /// The highest composite currently reachable ([`max_composite_now`]).
        reachable: f32,
    },
    /// `expires_at` is at or before `created_at` — a listing born expired.
    #[error("listing expires at {expires_at}, not after its creation at {created_at}")]
    ExpiryNotAfterCreation {
        /// When the listing was created.
        created_at: i64,
        /// The offending expiry.
        expires_at: i64,
    },
    /// A recurring cadence on a surface that is not `Services` (T1.7.7).
    #[error("only a Services listing may recur, not {surface:?}")]
    RecurringNotAService {
        /// The surface that forbids it.
        surface: Surface,
    },
    /// A recurring listing that runs for zero periods.
    #[error("a recurring listing must run for at least one period")]
    RecurringZeroDuration,
    /// A `Frequency::Custom(0)` — a period of no length.
    #[error("a custom billing period must be a positive number of seconds")]
    RecurringZeroPeriod,
    /// A negative early-termination penalty.
    #[error("early-termination penalty {penalty_centi} is negative")]
    NegativePenalty {
        /// The offending penalty.
        penalty_centi: i64,
    },
}

impl From<Listing> for CBOR {
    fn from(l: Listing) -> Self {
        let mut m = Map::new();
        // `id` is deliberately omitted — it is the hash of these bytes.
        m.insert("kind", LISTING_KIND);
        m.insert("provider", l.provider);
        m.insert("community", l.community);
        m.insert("surface", l.surface);
        m.insert("category", l.category);
        m.insert("title", l.title);
        m.insert("description", l.description);
        m.insert("pricing", l.pricing);
        m.insert("availability", l.availability);
        m.insert("requirements", l.requirements);
        m.insert("oracle_tier", l.oracle_tier);
        m.insert("federation_visible", l.federation_visible);
        m.insert("created_at", l.created_at);
        match l.expires_at {
            Some(t) => m.insert("expires_at", t),
            None => m.insert("expires_at", CBOR::null()),
        }
        // Unlike the fields above, `recurring` was added to an already
        // content-addressed record, so it is OMITTED when `None` — never `null`
        // — or every existing listing's id would change (ADR-0010).
        if let Some(terms) = l.recurring {
            m.insert("recurring", terms);
        }
        m.into()
    }
}

impl TryFrom<CBOR> for Listing {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != LISTING_KIND {
            return Err(dcbor::Error::WrongType);
        }
        let listing = Self::assembled(
            map.extract::<&str, Address>("provider")?,
            map.extract::<&str, String>("community")?,
            map.extract::<&str, Surface>("surface")?,
            map.extract::<&str, String>("category")?,
            map.extract::<&str, String>("title")?,
            map.extract::<&str, String>("description")?,
            map.extract::<&str, Pricing>("pricing")?,
            map.extract::<&str, Availability>("availability")?,
            map.extract::<&str, Requirements>("requirements")?,
            map.extract::<&str, u8>("oracle_tier")?,
            map.extract::<&str, bool>("federation_visible")?,
            map.extract::<&str, i64>("created_at")?,
            // A null (or absent) expiry decodes to `None`.
            map.get::<&str, i64>("expires_at"),
        );
        // Absent `recurring` decodes to a one-off; present, to a subscription —
        // applied after assembly so the recomputed id matches the signer's.
        Ok(match map.get::<&str, RecurringTerms>("recurring") {
            Some(terms) => listing.with_recurring(terms),
            None => listing,
        })
    }
}

/// A [`Listing`] signed by its provider.
pub type SignedListing = SignedPayload<Listing>;

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::from_canonical_bytes;

    fn test_address() -> Address {
        Address::from_public_key(Keypair::generate().public_key())
    }

    /// A listing that passes every rule, for tests to break one field at a time.
    fn valid_listing() -> Listing {
        Listing::new(
            test_address(),
            "blue_ridge_collective".into(),
            Surface::Services,
            "medical".into(),
            "General Consultation".into(),
            "Thirty minutes, at the clinic or by house call.".into(),
            Pricing {
                amount_centi: 300,
                model: PricingModel::Fixed,
                negotiable: true,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: Some(4),
                next_slot: Some(1_900_000_000),
            },
            Requirements {
                min_reputation: 0.0,
                community_member_only: false,
                federation_only: false,
            },
            2,
            false,
            1_800_000_000,
            Some(1_900_000_000),
        )
        .expect("fixture is valid")
    }

    #[test]
    fn cbor_roundtrip_preserves_every_field() {
        let listing = valid_listing();
        let bytes = to_canonical_bytes(listing.clone());
        let decoded: Listing = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded, listing);
    }

    #[test]
    fn roundtrip_survives_absent_optionals() {
        let mut listing = valid_listing();
        listing.availability.capacity = None;
        listing.availability.next_slot = None;
        listing.expires_at = None;
        let listing = Listing::new(
            listing.provider,
            listing.community,
            listing.surface,
            listing.category,
            listing.title,
            listing.description,
            listing.pricing,
            listing.availability,
            listing.requirements,
            listing.oracle_tier,
            listing.federation_visible,
            listing.created_at,
            listing.expires_at,
        )
        .unwrap();
        let decoded: Listing = from_canonical_bytes(&to_canonical_bytes(listing.clone())).unwrap();
        assert_eq!(decoded, listing);
    }

    #[test]
    fn id_changes_when_any_field_changes() {
        let listing = valid_listing();
        let mut cheaper = listing.clone();
        cheaper.pricing.amount_centi = 299;
        assert_ne!(listing.id, cheaper.compute_id());
    }

    #[test]
    fn id_is_not_part_of_the_signed_content() {
        let listing = valid_listing();
        let honest_bytes = to_canonical_bytes(listing.clone());

        // Someone hands us a listing whose id claims to be something else.
        let mut forged = listing.clone();
        forged.id = ListingId(Hash::of(b"not this listing"));

        // The bytes are unchanged (the id is not in them), so the signature over
        // them still verifies — and decoding recomputes the honest id, which is
        // what makes the lie unrepresentable rather than merely detectable.
        assert_eq!(to_canonical_bytes(forged.clone()), honest_bytes);
        let decoded: Listing = from_canonical_bytes(&to_canonical_bytes(forged)).unwrap();
        assert_eq!(decoded.id, listing.id);
    }

    #[test]
    fn signature_covers_the_content_and_survives_a_roundtrip() {
        let keypair = Keypair::generate();
        let signed = SignedListing::sign(valid_listing(), &keypair);
        assert!(signed.verify().is_ok());

        let decoded: Listing =
            from_canonical_bytes(&to_canonical_bytes(signed.payload.clone())).unwrap();
        let reconstructed = SignedPayload {
            payload: decoded,
            signer: signed.signer,
            signature: signed.signature,
        };
        assert!(reconstructed.verify().is_ok());
    }

    #[test]
    fn empty_or_oversized_title_is_rejected() {
        let mut listing = valid_listing();
        listing.title = "   ".into();
        assert_eq!(listing.validate(), Err(ListingError::EmptyTitle));

        listing.title = "x".repeat(MAX_TITLE_BYTES + 1);
        assert_eq!(
            listing.validate(),
            Err(ListingError::TitleTooLong {
                bytes: MAX_TITLE_BYTES + 1,
                max: MAX_TITLE_BYTES,
            })
        );
    }

    #[test]
    fn oversized_description_is_rejected() {
        let mut listing = valid_listing();
        listing.description = "x".repeat(MAX_DESCRIPTION_BYTES + 1);
        assert_eq!(
            listing.validate(),
            Err(ListingError::DescriptionTooLong {
                bytes: MAX_DESCRIPTION_BYTES + 1,
                max: MAX_DESCRIPTION_BYTES,
            })
        );
    }

    #[test]
    fn category_must_come_from_the_controlled_vocabulary() {
        let mut listing = valid_listing();
        listing.category = "artisanal_widgets".into();
        assert_eq!(
            listing.validate(),
            Err(ListingError::UnknownCategory("artisanal_widgets".into()))
        );

        for category in CATEGORIES {
            let mut listing = valid_listing();
            listing.category = (*category).to_string();
            assert_eq!(listing.validate(), Ok(()), "category {category} rejected");
        }
    }

    #[test]
    fn only_commons_may_be_subsidized() {
        for surface in [Surface::Goods, Surface::Services] {
            let mut listing = valid_listing();
            listing.surface = surface;
            listing.pricing.amount_centi = -100;
            assert_eq!(
                listing.validate(),
                Err(ListingError::NegativeAmount {
                    surface,
                    amount_centi: -100,
                })
            );
        }

        let mut commons = valid_listing();
        commons.surface = Surface::Commons;
        commons.pricing.amount_centi = -100;
        assert_eq!(commons.validate(), Ok(()));
    }

    #[test]
    fn a_negotiable_price_must_invite_offers() {
        let mut listing = valid_listing();
        listing.pricing.model = PricingModel::Negotiable;
        listing.pricing.negotiable = false;
        assert_eq!(listing.validate(), Err(ListingError::ContradictoryPricing));

        // The reverse pairing is meaningful: a set price, offers welcome.
        let mut fixed_but_open = valid_listing();
        fixed_but_open.pricing.model = PricingModel::Fixed;
        fixed_but_open.pricing.negotiable = true;
        assert_eq!(fixed_but_open.validate(), Ok(()));
    }

    #[test]
    fn oracle_tier_must_be_one_the_phase_supports() {
        for tier in [0u8, 3, 255] {
            let mut listing = valid_listing();
            listing.oracle_tier = tier;
            assert_eq!(
                listing.validate(),
                Err(ListingError::OracleTierOutOfRange {
                    tier,
                    min: ORACLE_TIER_MIN,
                    max: ORACLE_TIER_MAX,
                })
            );
        }
        for tier in [ORACLE_TIER_MIN, ORACLE_TIER_MAX] {
            let mut listing = valid_listing();
            listing.oracle_tier = tier;
            assert_eq!(listing.validate(), Ok(()));
        }
    }

    #[test]
    fn federation_flags_must_be_false_in_phase_one() {
        let mut visible = valid_listing();
        visible.federation_visible = true;
        assert_eq!(
            visible.validate(),
            Err(ListingError::FederationVisibleNotYet)
        );

        let mut only = valid_listing();
        only.requirements.federation_only = true;
        assert_eq!(only.validate(), Err(ListingError::FederationOnlyNotYet));
    }

    #[test]
    fn min_reputation_cannot_exceed_what_anyone_can_reach() {
        let reachable = max_composite_now();

        // The number a provider would reasonably type, and the whole problem:
        // three dormant dimensions put 3.0 out of everyone's reach.
        let mut unreachable = valid_listing();
        unreachable.requirements.min_reputation = 3.0;
        assert_eq!(
            unreachable.validate(),
            Err(ListingError::MinReputationOutOfRange {
                asked: 3.0,
                reachable,
            })
        );

        let mut negative = valid_listing();
        negative.requirements.min_reputation = -0.1;
        assert!(matches!(
            negative.validate(),
            Err(ListingError::MinReputationOutOfRange { .. })
        ));

        // The ceiling itself is allowed: exactly reachable, by one member.
        let mut at_ceiling = valid_listing();
        at_ceiling.requirements.min_reputation = reachable;
        assert_eq!(at_ceiling.validate(), Ok(()));
    }

    #[test]
    fn a_listing_cannot_be_born_expired() {
        let mut listing = valid_listing();
        listing.expires_at = Some(listing.created_at);
        assert_eq!(
            listing.validate(),
            Err(ListingError::ExpiryNotAfterCreation {
                created_at: listing.created_at,
                expires_at: listing.created_at,
            })
        );

        let mut earlier = valid_listing();
        earlier.expires_at = Some(earlier.created_at - 1);
        assert!(matches!(
            earlier.validate(),
            Err(ListingError::ExpiryNotAfterCreation { .. })
        ));
    }

    #[test]
    fn new_refuses_to_build_an_invalid_listing() {
        let err = Listing::new(
            test_address(),
            "blue_ridge_collective".into(),
            Surface::Goods,
            "medical".into(),
            String::new(),
            String::new(),
            Pricing {
                amount_centi: 0,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: None,
                next_slot: None,
            },
            Requirements {
                min_reputation: 0.0,
                community_member_only: false,
                federation_only: false,
            },
            1,
            false,
            1_800_000_000,
            None,
        )
        .unwrap_err();
        assert_eq!(err, ListingError::EmptyTitle);
    }

    #[test]
    fn surface_tags_are_stable_on_the_wire() {
        // These strings are on the log forever; a rename is a schema change.
        for (surface, tag) in [
            (Surface::Goods, "goods"),
            (Surface::Services, "services"),
            (Surface::Commons, "commons"),
        ] {
            let cbor: CBOR = surface.into();
            assert_eq!(cbor.clone().try_into_text().unwrap(), tag);
            assert_eq!(Surface::try_from(cbor).unwrap(), surface);
        }
        for (status, tag) in [
            (AvailabilityStatus::Available, "available"),
            (AvailabilityStatus::LimitedStock, "limited_stock"),
            (AvailabilityStatus::Unavailable, "unavailable"),
        ] {
            let cbor: CBOR = status.into();
            assert_eq!(cbor.clone().try_into_text().unwrap(), tag);
            assert_eq!(AvailabilityStatus::try_from(cbor).unwrap(), status);
        }
        for (model, tag) in [
            (PricingModel::Fixed, "fixed"),
            (PricingModel::Negotiable, "negotiable"),
        ] {
            let cbor: CBOR = model.into();
            assert_eq!(cbor.clone().try_into_text().unwrap(), tag);
            assert_eq!(PricingModel::try_from(cbor).unwrap(), model);
        }
    }
}
