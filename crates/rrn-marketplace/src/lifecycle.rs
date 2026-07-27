//! Listing lifecycle — the records that change a listing after it is published,
//! and the append path that refuses the ones nobody was entitled to write.
//!
//! Three record kinds live on the log for one listing:
//!
//! | Kind | Payload | Signer |
//! |---|---|---|
//! | `rrn.marketplace.listing.v1` | [`Listing`] itself | the provider |
//! | `rrn.marketplace.listing_updated.v1` | [`ListingUpdated`] | the provider |
//! | `rrn.marketplace.listing_closed.v1` | [`ListingClosed`] | the provider *or* the station |
//!
//! Creation appends the signed [`Listing`] **directly** — there is no
//! `ListingCreated` wrapper, because a log entry already is a signed payload and
//! wrapping one in another would sign `CBOR(CBOR(Listing))`, the double-encoding
//! `rrn_storage::log` warns against. This follows `rrn_identity::vouch`, whose
//! append helper is likewise a thin function over
//! [`AppendLog::append`](rrn_storage::log::AppendLog::append) rather than a
//! method on the log: `rrn-storage` cannot depend on this crate without
//! inverting the stack.
//!
//! # Patch validity is the listing's own rulebook
//!
//! An update is checked by applying it and running
//! [`Listing::validate`] on the result, so there is exactly one set of rules
//! about what a listing may say, and a patch cannot smuggle in a state that
//! `Listing::new` would have refused.
//!
//! # These checks are not the last line of defence
//!
//! The helpers here guard the *local* write path. A replicated entry arrives
//! through `AppendLog::append_raw` (M0.6 gossip) and never passes through this
//! module, so replay must re-apply the same authorization rules when it computes
//! state (T1.6.5). Enforcing here is what stops this station writing a bad
//! record; enforcing in replay is what stops it believing someone else's.

use dcbor::prelude::*;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};

use crate::listing::{Availability, Listing, ListingId, Pricing, SignedListing};
use crate::Result;

/// Discriminant strings carried in the `kind` field of each record's canonical
/// CBOR, so replay can tell the record types apart unambiguously. The listing
/// record's own tag lives in [`crate::listing`].
pub(crate) const UPDATED_KIND: &str = "rrn.marketplace.listing_updated.v1";
pub(crate) const CLOSED_KIND: &str = "rrn.marketplace.listing_closed.v1";

/// What an update does to `expires_at`.
///
/// A plain `Option<i64>` cannot say the difference between "leave the expiry
/// alone" and "remove the expiry", and a provider extending an offer
/// indefinitely wants the second. On the wire the three cases are the key being
/// absent, null, or an integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpiryPatch {
    /// Leave `expires_at` as it is.
    Unchanged,
    /// Remove the expiry: the listing stands until closed by hand.
    Clear,
    /// Set the expiry to this Unix second.
    Set(i64),
}

/// The subset of a listing its provider may change after publishing.
///
/// Absent from this type, deliberately: `id`, `provider`, `community`,
/// `surface`, and `category`. Those are what other systems key on — the content
/// address, who is accountable, and the reputation domain the listing scores in.
/// A listing that could change category after accumulating transactions would
/// move reputation between domains with no work done (ADR-0010).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListingPatch {
    /// New pricing, or `None` to leave it.
    pub pricing: Option<Pricing>,
    /// New description, or `None` to leave it.
    pub description: Option<String>,
    /// New availability, or `None` to leave it.
    pub availability: Option<Availability>,
    /// What to do with the expiry.
    pub expires_at: ExpiryPatch,
}

impl ListingPatch {
    /// A patch that changes nothing — the starting point for building one.
    pub fn empty() -> Self {
        Self {
            pricing: None,
            description: None,
            availability: None,
            expires_at: ExpiryPatch::Unchanged,
        }
    }

    /// Whether this patch would leave the listing untouched.
    pub fn is_empty(&self) -> bool {
        self.pricing.is_none()
            && self.description.is_none()
            && self.availability.is_none()
            && self.expires_at == ExpiryPatch::Unchanged
    }

    /// Applies the patch, returning the listing as it now reads.
    ///
    /// **The `id` is carried over unchanged and deliberately not re-derived from
    /// the patched content.** A listing's id is its identity, fixed when it was
    /// published: updates reference it, transactions link to it, and an id that
    /// moved when the price changed would detach a listing from its own history.
    /// So the result is the one kind of [`Listing`] whose `id` is not the hash of
    /// its fields, and it must never be re-encoded as a `listing.v1` record —
    /// which nothing does, because an update is a `listing_updated.v1` record.
    pub fn apply_to(&self, listing: &Listing) -> Listing {
        let mut patched = listing.clone();
        if let Some(pricing) = self.pricing {
            patched.pricing = pricing;
        }
        if let Some(description) = &self.description {
            patched.description = description.clone();
        }
        if let Some(availability) = self.availability {
            patched.availability = availability;
        }
        match self.expires_at {
            ExpiryPatch::Unchanged => {}
            ExpiryPatch::Clear => patched.expires_at = None,
            ExpiryPatch::Set(t) => patched.expires_at = Some(t),
        }
        patched
    }
}

impl From<ListingPatch> for CBOR {
    fn from(p: ListingPatch) -> Self {
        let mut m = Map::new();
        // Unset fields are *omitted*, not null: in a patch, absence is the
        // meaningful state ("do not touch this"), which is exactly the case
        // where a null would say something different.
        if let Some(pricing) = p.pricing {
            m.insert("pricing", pricing);
        }
        if let Some(description) = p.description {
            m.insert("description", description);
        }
        if let Some(availability) = p.availability {
            m.insert("availability", availability);
        }
        match p.expires_at {
            ExpiryPatch::Unchanged => {}
            ExpiryPatch::Clear => m.insert("expires_at", CBOR::null()),
            ExpiryPatch::Set(t) => m.insert("expires_at", t),
        }
        m.into()
    }
}

impl TryFrom<CBOR> for ListingPatch {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        // Absent key, null, or an integer — the three cases `ExpiryPatch` names.
        let expires_at = match map.get::<&str, CBOR>("expires_at") {
            None => ExpiryPatch::Unchanged,
            Some(value) if value.is_null() => ExpiryPatch::Clear,
            Some(value) => ExpiryPatch::Set(i64::try_from(value)?),
        };
        Ok(ListingPatch {
            pricing: map.get::<&str, Pricing>("pricing"),
            description: map.get::<&str, String>("description"),
            availability: map.get::<&str, Availability>("availability"),
            expires_at,
        })
    }
}

/// A provider's signed change to a listing they already published.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListingUpdated {
    /// The listing being changed.
    pub listing_id: ListingId,
    /// What changes.
    pub patch: ListingPatch,
    /// Who is making the change. Redundant with the envelope's signer, and kept
    /// so the claim travels *inside* the signed content: replay checks both, and
    /// a record whose content disagrees with its signature is rejected rather
    /// than resolved in favour of either.
    pub signed_by: Address,
}

impl From<ListingUpdated> for CBOR {
    fn from(u: ListingUpdated) -> Self {
        let mut m = Map::new();
        m.insert("kind", UPDATED_KIND);
        m.insert("listing_id", u.listing_id);
        m.insert("patch", u.patch);
        m.insert("signed_by", u.signed_by);
        m.into()
    }
}

impl TryFrom<CBOR> for ListingUpdated {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != UPDATED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ListingUpdated {
            listing_id: map.extract::<&str, ListingId>("listing_id")?,
            patch: map.extract::<&str, ListingPatch>("patch")?,
            signed_by: map.extract::<&str, Address>("signed_by")?,
        })
    }
}

/// Why a listing stopped being on offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    /// `expires_at` passed and the station's sweep closed it.
    ExpirationReached,
    /// The provider withdrew the offer.
    ProviderClosed,
    /// The station closed it for housekeeping.
    StationCleanup,
}

impl CloseReason {
    fn tag(self) -> &'static str {
        match self {
            CloseReason::ExpirationReached => "expiration_reached",
            CloseReason::ProviderClosed => "provider_closed",
            CloseReason::StationCleanup => "station_cleanup",
        }
    }

    /// Whether the station may sign this reason. It may attest to what happened
    /// with no party present (ADR-0005), but it may never claim the provider
    /// withdrew an offer.
    fn station_may_sign(self) -> bool {
        matches!(
            self,
            CloseReason::ExpirationReached | CloseReason::StationCleanup
        )
    }
}

impl From<CloseReason> for CBOR {
    fn from(r: CloseReason) -> Self {
        r.tag().into()
    }
}

impl TryFrom<CBOR> for CloseReason {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        match cbor.try_into_text()?.as_str() {
            "expiration_reached" => Ok(CloseReason::ExpirationReached),
            "provider_closed" => Ok(CloseReason::ProviderClosed),
            "station_cleanup" => Ok(CloseReason::StationCleanup),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// The terminal record for a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingClosed {
    /// The listing being closed.
    pub listing_id: ListingId,
    /// Why.
    pub reason: CloseReason,
    /// Unix seconds the close happened, from the signer's own clock.
    pub closed_at: i64,
}

impl From<ListingClosed> for CBOR {
    fn from(c: ListingClosed) -> Self {
        let mut m = Map::new();
        m.insert("kind", CLOSED_KIND);
        m.insert("listing_id", c.listing_id);
        m.insert("reason", c.reason);
        m.insert("closed_at", c.closed_at);
        m.into()
    }
}

impl TryFrom<CBOR> for ListingClosed {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CLOSED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ListingClosed {
            listing_id: map.extract::<&str, ListingId>("listing_id")?,
            reason: map.extract::<&str, CloseReason>("reason")?,
            closed_at: map.extract::<&str, i64>("closed_at")?,
        })
    }
}

/// A [`ListingUpdated`] signed by the provider.
pub type SignedListingUpdate = SignedPayload<ListingUpdated>;
/// A [`ListingClosed`] signed by the provider or the station.
pub type SignedListingClose = SignedPayload<ListingClosed>;

/// Every record on the log concerning one listing, in log order.
///
/// The single scan behind both the append guards here and the state machine in
/// T1.6.5 — so authorization and replay can never read the log differently.
#[derive(Clone, Debug, Default)]
pub struct ListingRecords {
    /// The creation record, absent if the listing was never published here.
    pub created: Option<Listing>,
    /// Every update, in log order.
    pub updates: Vec<ListingUpdated>,
    /// The close, if it has happened.
    pub closed: Option<ListingClosed>,
}

impl ListingRecords {
    /// The listing as it currently reads: creation with every update applied,
    /// in log order. `None` when the listing was never created here.
    pub fn current(&self) -> Option<Listing> {
        let created = self.created.as_ref()?;
        Some(
            self.updates
                .iter()
                .fold(created.clone(), |listing, update| {
                    update.patch.apply_to(&listing)
                }),
        )
    }
}

/// Collects every record for `listing_id` in one pass over the log.
///
/// A payload that is not one of the three marketplace kinds is skipped, as are
/// records for other listings. Entries whose signer was not entitled to write
/// them are skipped too: an unauthorized record is not evidence of anything, and
/// dropping it here means replay and the append guards agree by construction.
pub fn listing_records(
    log: &AppendLog,
    listing_id: &ListingId,
    station: &PublicKey,
) -> Result<ListingRecords> {
    let mut records = ListingRecords::default();
    for entry in log.iter_from(1) {
        let entry = entry?;
        let signer = Address::from_public_key(entry.payload.signer);

        if let Ok(listing) = from_canonical_bytes::<Listing>(&entry.payload.bytes) {
            if listing.id == *listing_id
                && records.created.is_none()
                && signer == listing.provider
                && listing.validate().is_ok()
            {
                records.created = Some(listing);
            }
            continue;
        }
        // Only records for a listing this station has already seen created can
        // be authorized, so anything before the creation entry is ignored.
        let Some(created) = records.created.as_ref() else {
            continue;
        };
        if let Ok(update) = from_canonical_bytes::<ListingUpdated>(&entry.payload.bytes) {
            if update.listing_id == *listing_id
                && records.closed.is_none()
                && update.signed_by == created.provider
                && signer == update.signed_by
            {
                records.updates.push(update);
            }
            continue;
        }
        if let Ok(close) = from_canonical_bytes::<ListingClosed>(&entry.payload.bytes) {
            if close.listing_id == *listing_id
                && records.closed.is_none()
                && closer_is_entitled(&signer, &created.provider, station, close.reason)
            {
                records.closed = Some(close);
            }
        }
    }
    Ok(records)
}

/// Whether this signer may close the listing for this reason: the provider may
/// withdraw their own offer, and the station may attest to expiry or cleanup.
fn closer_is_entitled(
    signer: &Address,
    provider: &Address,
    station: &PublicKey,
    reason: CloseReason,
) -> bool {
    if signer == provider {
        return reason == CloseReason::ProviderClosed;
    }
    *signer == Address::from_public_key(*station) && reason.station_may_sign()
}

/// Publishes a new listing: appends the provider's signed [`Listing`].
///
/// Rejects a listing whose signer is not its provider, one that breaks its own
/// rules, and one already on this log.
pub fn append_listing_created(log: &mut AppendLog, signed: SignedListing) -> Result<LogEntry> {
    let listing = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != listing.provider {
        return Err(LifecycleError::SignerNotProvider {
            signer,
            provider: listing.provider,
        }
        .into());
    }
    listing.validate()?;
    if find_created(log, &listing.id)?.is_some() {
        return Err(LifecycleError::AlreadyCreated(listing.id).into());
    }
    Ok(log.append(signed)?)
}

/// Records a provider's change to their listing.
///
/// The patch is applied to the current listing and the result validated, so an
/// update cannot produce a listing that could not have been published.
///
/// `station` is needed to read the listing's history, not to authorize the
/// update: whether the listing is already closed depends on whether a
/// station-signed close counts, which only the station's own key can settle.
pub fn append_listing_updated(
    log: &mut AppendLog,
    signed: SignedListingUpdate,
    station: &PublicKey,
) -> Result<LogEntry> {
    let update = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != update.signed_by {
        return Err(LifecycleError::SignerDisagreesWithContent {
            signer,
            claimed: update.signed_by,
        }
        .into());
    }
    if update.patch.is_empty() {
        return Err(LifecycleError::EmptyPatch(update.listing_id).into());
    }

    let records = listing_records(log, &update.listing_id, station)?;
    let Some(current) = records.current() else {
        return Err(LifecycleError::UnknownListing(update.listing_id).into());
    };
    if let Some(closed) = records.closed {
        return Err(LifecycleError::AlreadyClosed {
            listing_id: update.listing_id,
            closed_at: closed.closed_at,
        }
        .into());
    }
    if signer != current.provider {
        return Err(LifecycleError::SignerNotProvider {
            signer,
            provider: current.provider,
        }
        .into());
    }
    update.patch.apply_to(&current).validate()?;

    Ok(log.append(signed)?)
}

/// Closes a listing, signed by the provider or by `station`.
///
/// `station` is passed explicitly because "is this the station" is not something
/// the record can assert about itself — the caller running the station is the
/// only party that knows its key.
pub fn append_listing_closed(
    log: &mut AppendLog,
    signed: SignedListingClose,
    station: &PublicKey,
) -> Result<LogEntry> {
    let close = signed.payload;
    let signer = Address::from_public_key(signed.signer);

    let records = listing_records(log, &close.listing_id, station)?;
    let Some(current) = records.current() else {
        return Err(LifecycleError::UnknownListing(close.listing_id).into());
    };
    if let Some(existing) = records.closed {
        return Err(LifecycleError::AlreadyClosed {
            listing_id: close.listing_id,
            closed_at: existing.closed_at,
        }
        .into());
    }
    if !closer_is_entitled(&signer, &current.provider, station, close.reason) {
        return Err(LifecycleError::CloseNotPermitted {
            signer,
            reason: close.reason,
        }
        .into());
    }

    Ok(log.append(signed)?)
}

/// Finds a listing's creation record without caring about its later history.
fn find_created(log: &AppendLog, listing_id: &ListingId) -> Result<Option<Listing>> {
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(listing) = from_canonical_bytes::<Listing>(&entry.payload.bytes) else {
            continue;
        };
        if listing.id == *listing_id
            && Address::from_public_key(entry.payload.signer) == listing.provider
            && listing.validate().is_ok()
        {
            return Ok(Some(listing));
        }
    }
    Ok(None)
}

/// A lifecycle record the log would not accept. One variant per rule, so a
/// caller can tell which entitlement was missing.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum LifecycleError {
    /// The envelope's signer is not the listing's provider.
    #[error("record signed by {signer}, but the listing's provider is {provider}")]
    SignerNotProvider {
        /// Who signed.
        signer: Address,
        /// Who was entitled to.
        provider: Address,
    },
    /// The record's own `signed_by` disagrees with who actually signed it.
    #[error("record signed by {signer} claims to be from {claimed}")]
    SignerDisagreesWithContent {
        /// Who signed the envelope.
        signer: Address,
        /// Who the content says signed it.
        claimed: Address,
    },
    /// A listing with this id is already on the log.
    #[error("listing {0:?} has already been created")]
    AlreadyCreated(ListingId),
    /// No creation record for this id — nothing to update or close.
    #[error("no listing {0:?} on this log")]
    UnknownListing(ListingId),
    /// The listing is already closed; `Closed` is terminal.
    #[error("listing {listing_id:?} was closed at {closed_at}")]
    AlreadyClosed {
        /// The listing.
        listing_id: ListingId,
        /// When it was closed.
        closed_at: i64,
    },
    /// An update that changes nothing — a permanent log entry for no effect.
    #[error("update to listing {0:?} changes nothing")]
    EmptyPatch(ListingId),
    /// This signer may not close the listing for this reason. In particular the
    /// station may attest to expiry or cleanup but never to a provider's
    /// withdrawal.
    #[error("{signer} may not close a listing as {reason:?}")]
    CloseNotPermitted {
        /// Who tried.
        signer: Address,
        /// The reason they claimed.
        reason: CloseReason,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{AvailabilityStatus, ListingError, PricingModel, Requirements, Surface};
    use crate::Error;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::db::Database;
    use rrn_storage::migrations;

    fn open_log_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn listing_of(provider: &Keypair) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            "blue_ridge_collective".into(),
            Surface::Goods,
            "food".into(),
            "Winter squash, by the crate".into(),
            "Picked this week.".into(),
            Pricing {
                amount_centi: 250,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: Some(12),
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
            Some(1_900_000_000),
        )
        .unwrap()
    }

    fn price_patch(amount_centi: i64) -> ListingPatch {
        ListingPatch {
            pricing: Some(Pricing {
                amount_centi,
                model: PricingModel::Fixed,
                negotiable: false,
            }),
            ..ListingPatch::empty()
        }
    }

    fn update_of(
        provider: &Keypair,
        listing: &Listing,
        patch: ListingPatch,
    ) -> SignedListingUpdate {
        SignedPayload::sign(
            ListingUpdated {
                listing_id: listing.id,
                patch,
                signed_by: Address::from_public_key(provider.public_key()),
            },
            provider,
        )
    }

    fn close_of(signer: &Keypair, listing: &Listing, reason: CloseReason) -> SignedListingClose {
        SignedPayload::sign(
            ListingClosed {
                listing_id: listing.id,
                reason,
                closed_at: 1_850_000_000,
            },
            signer,
        )
    }

    #[test]
    fn creating_puts_one_entry_on_the_log_that_reads_back() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);

        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        assert_eq!(log.iter_from(1).count(), 1);
        let records = listing_records(&log, &listing.id, &station.public_key()).unwrap();
        assert_eq!(records.created, Some(listing.clone()));
        assert_eq!(records.current(), Some(listing));
    }

    #[test]
    fn updating_adds_an_entry_and_the_current_listing_reflects_it() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        append_listing_updated(
            &mut log,
            update_of(&provider, &listing, price_patch(199)),
            &station.public_key(),
        )
        .unwrap();

        assert_eq!(log.iter_from(1).count(), 2);
        let records = listing_records(&log, &listing.id, &station.public_key()).unwrap();
        let current = records.current().unwrap();
        assert_eq!(current.pricing.amount_centi, 199);
        // The creation record is untouched — the log is a history, not a cell.
        assert_eq!(records.created.unwrap().pricing.amount_centi, 250);
    }

    #[test]
    fn an_update_does_not_move_the_listings_identity() {
        let provider = Keypair::generate();
        let listing = listing_of(&provider);
        let patched = price_patch(199).apply_to(&listing);

        assert_eq!(patched.id, listing.id);

        // A patched listing is the one `Listing` whose id is *not* the hash of
        // its own fields: identity is fixed at publication, so that updates
        // reference something stable. Encoding one as a `listing.v1` record
        // would therefore mint a second listing — which is why nothing does,
        // and why an update is its own record kind.
        let recomputed: Listing =
            from_canonical_bytes(&rrn_crypto::serialize::to_canonical_bytes(patched.clone()))
                .unwrap();
        assert_ne!(recomputed.id, patched.id);
    }

    #[test]
    fn closing_adds_a_third_entry_and_is_terminal() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();
        append_listing_updated(
            &mut log,
            update_of(&provider, &listing, price_patch(199)),
            &station.public_key(),
        )
        .unwrap();

        append_listing_closed(
            &mut log,
            close_of(&provider, &listing, CloseReason::ProviderClosed),
            &station.public_key(),
        )
        .unwrap();

        assert_eq!(log.iter_from(1).count(), 3);
        let records = listing_records(&log, &listing.id, &station.public_key()).unwrap();
        assert_eq!(
            records.closed.map(|c| c.reason),
            Some(CloseReason::ProviderClosed)
        );

        // A second close, and any later update, are refused.
        let err = append_listing_closed(
            &mut log,
            close_of(&provider, &listing, CloseReason::ProviderClosed),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::AlreadyClosed { .. })
        ));
        let err = append_listing_updated(
            &mut log,
            update_of(&provider, &listing, price_patch(150)),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::AlreadyClosed { .. })
        ));
        assert_eq!(log.iter_from(1).count(), 3);
    }

    #[test]
    fn only_the_provider_may_publish_their_own_listing() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let impostor = Keypair::generate();

        let err = append_listing_created(
            &mut log,
            SignedPayload::sign(listing_of(&provider), &impostor),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::SignerNotProvider { .. })
        ));
        assert_eq!(log.iter_from(1).count(), 0);
    }

    #[test]
    fn an_invalid_listing_never_reaches_the_log() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let mut listing = listing_of(&provider);
        listing.title = String::new();

        let err =
            append_listing_created(&mut log, SignedPayload::sign(listing, &provider)).unwrap_err();

        assert!(matches!(err, Error::Listing(ListingError::EmptyTitle)));
        assert_eq!(log.iter_from(1).count(), 0);
    }

    #[test]
    fn a_listing_cannot_be_created_twice() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        let err =
            append_listing_created(&mut log, SignedPayload::sign(listing, &provider)).unwrap_err();

        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::AlreadyCreated(_))
        ));
        assert_eq!(log.iter_from(1).count(), 1);
    }

    #[test]
    fn only_the_provider_may_update() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let impostor = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        // Signed by someone else, and honest about it in the content.
        let err = append_listing_updated(
            &mut log,
            update_of(&impostor, &listing, price_patch(1)),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::SignerNotProvider { .. })
        ));

        // Signed by someone else while claiming to be the provider — caught
        // earlier, by the content disagreeing with the signature.
        let lie = SignedPayload::sign(
            ListingUpdated {
                listing_id: listing.id,
                patch: price_patch(1),
                signed_by: listing.provider,
            },
            &impostor,
        );
        let err = append_listing_updated(&mut log, lie, &station.public_key()).unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::SignerDisagreesWithContent { .. })
        ));
        assert_eq!(log.iter_from(1).count(), 1);
    }

    #[test]
    fn a_patch_cannot_produce_a_listing_that_could_not_be_published() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        // Goods may not be subsidized — the same rule `Listing::new` enforces.
        let err = append_listing_updated(
            &mut log,
            update_of(&provider, &listing, price_patch(-1)),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Listing(ListingError::NegativeAmount { .. })
        ));

        // Nor may an update move the expiry to before the listing existed.
        let backdated = ListingPatch {
            expires_at: ExpiryPatch::Set(listing.created_at - 1),
            ..ListingPatch::empty()
        };
        let err = append_listing_updated(
            &mut log,
            update_of(&provider, &listing, backdated),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Listing(ListingError::ExpiryNotAfterCreation { .. })
        ));
        assert_eq!(log.iter_from(1).count(), 1);
    }

    #[test]
    fn an_empty_patch_is_refused() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        let err = append_listing_updated(
            &mut log,
            update_of(&provider, &listing, ListingPatch::empty()),
            &station.public_key(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::EmptyPatch(_))
        ));
    }

    #[test]
    fn an_expiry_can_be_cleared_as_well_as_moved() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        let cleared = ListingPatch {
            expires_at: ExpiryPatch::Clear,
            ..ListingPatch::empty()
        };
        append_listing_updated(
            &mut log,
            update_of(&provider, &listing, cleared),
            &station.public_key(),
        )
        .unwrap();

        let records = listing_records(&log, &listing.id, &station.public_key()).unwrap();
        assert_eq!(records.current().unwrap().expires_at, None);
    }

    #[test]
    fn the_station_may_close_for_expiry_but_never_as_the_provider() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        // The station claiming the provider withdrew is the one thing ADR-0010
        // forbids it: it would be attesting to someone else's decision.
        let err = append_listing_closed(
            &mut log,
            close_of(&station, &listing, CloseReason::ProviderClosed),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::CloseNotPermitted { .. })
        ));

        append_listing_closed(
            &mut log,
            close_of(&station, &listing, CloseReason::ExpirationReached),
            &station.public_key(),
        )
        .unwrap();
        let records = listing_records(&log, &listing.id, &station.public_key()).unwrap();
        assert_eq!(
            records.closed.map(|c| c.reason),
            Some(CloseReason::ExpirationReached)
        );
    }

    #[test]
    fn a_provider_may_not_claim_the_stations_reasons() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        for reason in [CloseReason::ExpirationReached, CloseReason::StationCleanup] {
            let err = append_listing_closed(
                &mut log,
                close_of(&provider, &listing, reason),
                &station.public_key(),
            )
            .unwrap_err();
            assert!(matches!(
                err,
                Error::Lifecycle(LifecycleError::CloseNotPermitted { .. })
            ));
        }
    }

    #[test]
    fn a_stranger_may_not_close_a_listing() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let stranger = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        for reason in [
            CloseReason::ProviderClosed,
            CloseReason::ExpirationReached,
            CloseReason::StationCleanup,
        ] {
            let err = append_listing_closed(
                &mut log,
                close_of(&stranger, &listing, reason),
                &station.public_key(),
            )
            .unwrap_err();
            assert!(matches!(
                err,
                Error::Lifecycle(LifecycleError::CloseNotPermitted { .. })
            ));
        }
    }

    #[test]
    fn updating_or_closing_an_unknown_listing_is_refused() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);

        let err = append_listing_updated(
            &mut log,
            update_of(&provider, &listing, price_patch(1)),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::UnknownListing(_))
        ));

        let err = append_listing_closed(
            &mut log,
            close_of(&provider, &listing, CloseReason::ProviderClosed),
            &station.public_key(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Lifecycle(LifecycleError::UnknownListing(_))
        ));
    }

    #[test]
    fn replay_ignores_records_a_gossiped_entry_could_carry() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let impostor = Keypair::generate();
        let station = Keypair::generate();
        let listing = listing_of(&provider);
        append_listing_created(&mut log, SignedPayload::sign(listing.clone(), &provider)).unwrap();

        // Bypass the append guards exactly as replication does, then check that
        // replay reaches the same verdict the write path would have.
        log.append(update_of(&impostor, &listing, price_patch(1)))
            .unwrap();
        log.append(close_of(&impostor, &listing, CloseReason::ProviderClosed))
            .unwrap();

        let records = listing_records(&log, &listing.id, &station.public_key()).unwrap();
        assert!(records.updates.is_empty());
        assert!(records.closed.is_none());
        assert_eq!(records.current(), Some(listing));
    }

    #[test]
    fn record_roundtrips_and_wire_tags_are_stable() {
        let provider = Keypair::generate();
        let listing = listing_of(&provider);

        let update = ListingUpdated {
            listing_id: listing.id,
            patch: ListingPatch {
                pricing: Some(Pricing {
                    amount_centi: 199,
                    model: PricingModel::Negotiable,
                    negotiable: true,
                }),
                description: Some("Now by the half-crate too.".into()),
                availability: None,
                expires_at: ExpiryPatch::Clear,
            },
            signed_by: listing.provider,
        };
        let cbor: CBOR = update.clone().into();
        assert_eq!(ListingUpdated::try_from(cbor).unwrap(), update);

        // An unchanged expiry must survive as unchanged, not collapse to Clear.
        let untouched = ListingUpdated {
            patch: price_patch(1),
            ..update.clone()
        };
        let cbor: CBOR = untouched.clone().into();
        assert_eq!(ListingUpdated::try_from(cbor).unwrap(), untouched);

        let close = ListingClosed {
            listing_id: listing.id,
            reason: CloseReason::StationCleanup,
            closed_at: 1_850_000_000,
        };
        let cbor: CBOR = close.into();
        assert_eq!(ListingClosed::try_from(cbor).unwrap(), close);

        for (reason, tag) in [
            (CloseReason::ExpirationReached, "expiration_reached"),
            (CloseReason::ProviderClosed, "provider_closed"),
            (CloseReason::StationCleanup, "station_cleanup"),
        ] {
            let cbor: CBOR = reason.into();
            assert_eq!(cbor.clone().try_into_text().unwrap(), tag);
            assert_eq!(CloseReason::try_from(cbor).unwrap(), reason);
        }
    }
}
