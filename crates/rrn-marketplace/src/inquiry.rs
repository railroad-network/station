//! Inquiries — the signed message thread between a buyer and a listing's
//! provider, the step between finding an offer and committing to a transaction.
//!
//! An inquiry is opened by a buyer against an [`Active`](crate::lifecycle::ListingState::Active)
//! listing, carries an opening message and an optional opening offer, and then
//! runs as a thread of signed [`InquiryMessage`]s — each of which may carry a
//! counter-offer — until either party (or the station's expiry sweep) writes the
//! terminal [`InquiryClosed`]. Three record kinds live on the log for one
//! inquiry:
//!
//! | Kind | Payload | Signer |
//! |---|---|---|
//! | `rrn.marketplace.inquiry_opened.v1` | [`InquiryOpened`] | the buyer |
//! | `rrn.marketplace.inquiry_message.v1` | [`InquiryMessage`] | the buyer *or* the provider |
//! | `rrn.marketplace.inquiry_closed.v1` | [`InquiryClosed`] | the buyer, the provider, *or* the station |
//!
//! # An inquiry names itself
//!
//! An [`InquiryId`] is the Blake3 hash of the [`InquiryOpened`]'s canonical
//! bytes — the same content-addressing [`Listing`](crate::listing::Listing) uses:
//! the `inquiry_id` field is not part of the hashed content, it *is* the hash of
//! everything else. Messages and the close reference that id.
//!
//! # Requirements become access control here
//!
//! A listing's [`Requirements`](crate::listing::Requirements) are recorded
//! provider intent up to this point — M1.6 checks they are *reachable* and
//! T1.7.2 lets a provider *set* them, but nothing ever checked them against a
//! buyer. Opening an inquiry is the first moment a specific buyer approaches a
//! specific offer, so it is the one place the check belongs. [`check_requirements`]
//! is a pure comparison; the two facts it needs about the buyer — their capped
//! (public) composite and whether they belong to the listing's community — are
//! *inputs*, supplied by the caller. That keeps this crate free of any reputation
//! lookup and lets the local write path and replay run the identical check.
//!
//! Requirements are evaluated **at open time only** (ADR-0010, and the T1.7.4
//! task note): a buyer whose standing drops mid-negotiation keeps the inquiry
//! they legitimately opened. What a listing may demand — `min_reputation`,
//! `community_member_only` — is immutable after creation (a
//! [`ListingPatch`](crate::lifecycle::ListingPatch) cannot touch `requirements`),
//! so re-deriving the current listing to re-check on replay is stable regardless
//! of any later price or availability edit.
//!
//! # These checks are not the last line of defence
//!
//! As in [`lifecycle`](crate::lifecycle), the append helpers guard the *local*
//! write path, and a replicated entry arrives through `append_raw` (gossip)
//! without passing through them. So [`scan`] re-applies every rule when it
//! derives state — signer entitlement, thread membership, and (for an
//! `InquiryOpened`) the listing's requirements via a caller-supplied `admits`
//! predicate. A gossiped `InquiryOpened` from a buyer who does not qualify never
//! becomes an inquiry this station believes in.

use std::collections::BTreeMap;

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::listing::{Listing, ListingId, Requirements};
use crate::Result;

/// Discriminant strings carried in the `kind` field of each record's canonical
/// CBOR, so replay can tell the record types apart unambiguously.
pub(crate) const OPENED_KIND: &str = "rrn.marketplace.inquiry_opened.v1";
pub(crate) const MESSAGE_KIND: &str = "rrn.marketplace.inquiry_message.v1";
pub(crate) const CLOSED_KIND: &str = "rrn.marketplace.inquiry_closed.v1";

/// How long an inquiry may sit without activity before the station's sweep
/// closes it as [`Expired`](InquiryOutcome::Expired): seven days, per T1.7.4.
/// Measured from the latest of the open and the last message.
pub const INQUIRY_TTL_SECS: i64 = 7 * 24 * 60 * 60;

/// Longest permitted message body (and opening message), in bytes of UTF-8.
/// Log entries are permanent and replicated, so the length of a field any party
/// can write is a cost the whole community carries forever — the same reason a
/// [`listing`](crate::listing) bounds its title and description.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024;

/// The content address of an inquiry: the Blake3 hash of its
/// [`InquiryOpened`]'s canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, std::hash::Hash, Debug, Serialize, Deserialize)]
pub struct InquiryId(pub Hash);

impl InquiryId {
    /// The 32 raw hash bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Bare hex, the form an inquiry id takes everywhere a person meets one — a CLI
/// argument, a wire field, an error message. `Debug` stays wrapped for panics;
/// error text uses this, since a leaked Rust type name is not for a member.
impl std::fmt::Display for InquiryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// A total order over the hash bytes, so an `InquiryId` can key a `BTreeMap`
// during replay. Content, not chronology: arbitrary but identical everywhere.
impl Ord for InquiryId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for InquiryId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<InquiryId> for CBOR {
    fn from(id: InquiryId) -> Self {
        CBOR::to_byte_string(id.0.to_bytes())
    }
}

impl TryFrom<CBOR> for InquiryId {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(InquiryId(Hash::from_bytes(bytes)))
    }
}

/// A buyer's opening of an inquiry against a listing.
///
/// Content-addressed: [`inquiry_id`](Self::inquiry_id) is the hash of every
/// *other* field, so it is omitted from the CBOR and recomputed on decode, and
/// two byte-identical opens are the same inquiry rather than two.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InquiryOpened {
    /// Content address: Blake3 of every *other* field's canonical bytes.
    pub inquiry_id: InquiryId,
    /// The listing being inquired about.
    pub listing_id: ListingId,
    /// The member opening the inquiry. Must equal the signer of the record.
    pub buyer: Address,
    /// The opening message. May be empty — a buyer accepting the listed price
    /// with no note is a real opening.
    pub initial_message: String,
    /// The buyer's opening offer in centicommons, or `None` to accept the
    /// listed price.
    pub initial_offer_centi: Option<i64>,
    /// Unix seconds the buyer opened the inquiry, from their own clock.
    pub opened_at: i64,
}

impl InquiryOpened {
    /// Builds an opening and computes its content-addressed
    /// [`inquiry_id`](Self::inquiry_id), refusing one that breaks its own rules.
    pub fn new(
        listing_id: ListingId,
        buyer: Address,
        initial_message: String,
        initial_offer_centi: Option<i64>,
        opened_at: i64,
    ) -> std::result::Result<Self, InquiryError> {
        let opened = Self::assembled(
            listing_id,
            buyer,
            initial_message,
            initial_offer_centi,
            opened_at,
        );
        opened.validate()?;
        Ok(opened)
    }

    /// Assembles an opening and computes its id *without* validating. Private:
    /// the only unvalidated path is decoding, which is structural by design.
    fn assembled(
        listing_id: ListingId,
        buyer: Address,
        initial_message: String,
        initial_offer_centi: Option<i64>,
        opened_at: i64,
    ) -> Self {
        let mut opened = Self {
            // Placeholder; overwritten immediately by `compute_id`, which hashes
            // every field *except* `inquiry_id`.
            inquiry_id: InquiryId(Hash::from_bytes([0u8; 32])),
            listing_id,
            buyer,
            initial_message,
            initial_offer_centi,
            opened_at,
        };
        opened.inquiry_id = opened.compute_id();
        opened
    }

    /// Recomputes the content address from the current field values.
    fn compute_id(&self) -> InquiryId {
        // `Into<CBOR>` omits `inquiry_id`, so this hashes only the content.
        InquiryId(Hash::of(&to_canonical_bytes(self.clone())))
    }

    /// Checks the opening's own rules — only the message length; qualification
    /// and listing state are the append path's, since they need context an
    /// opening does not carry.
    pub fn validate(&self) -> std::result::Result<(), InquiryError> {
        if self.initial_message.len() > MAX_MESSAGE_BYTES {
            return Err(InquiryError::MessageTooLong {
                bytes: self.initial_message.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        Ok(())
    }
}

impl From<InquiryOpened> for CBOR {
    fn from(o: InquiryOpened) -> Self {
        let mut m = Map::new();
        // `inquiry_id` is deliberately omitted — it is the hash of these bytes.
        m.insert("kind", OPENED_KIND);
        m.insert("listing_id", o.listing_id);
        m.insert("buyer", o.buyer);
        m.insert("initial_message", o.initial_message);
        // Int-or-null rather than omitted: these fields are present since the
        // first version of the record, so the omit-when-`None` rule (which is
        // only for a field *added* to an already content-addressed record) does
        // not apply — the same call `Availability` makes.
        match o.initial_offer_centi {
            Some(offer) => m.insert("initial_offer_centi", offer),
            None => m.insert("initial_offer_centi", CBOR::null()),
        }
        m.insert("opened_at", o.opened_at);
        m.into()
    }
}

impl TryFrom<CBOR> for InquiryOpened {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != OPENED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(Self::assembled(
            map.extract::<&str, ListingId>("listing_id")?,
            map.extract::<&str, Address>("buyer")?,
            map.extract::<&str, String>("initial_message")?,
            map.get::<&str, i64>("initial_offer_centi"),
            map.extract::<&str, i64>("opened_at")?,
        ))
    }
}

/// One signed message in an inquiry thread, optionally carrying a counter-offer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InquiryMessage {
    /// The inquiry this message belongs to.
    pub inquiry_id: InquiryId,
    /// Who sent it. Must equal the signer, and be the buyer or the provider —
    /// no third party may speak in a thread.
    pub sender: Address,
    /// The message body. May be empty only if a `counter_offer_centi` is
    /// present (a bare offer is a real move; a bare empty message is noise on a
    /// permanent log).
    pub body: String,
    /// A revised price in centicommons, or `None` for a message that only says
    /// something.
    pub counter_offer_centi: Option<i64>,
    /// Unix seconds the message was sent, from the sender's own clock.
    pub sent_at: i64,
}

impl InquiryMessage {
    /// Checks the message's own rules — length, and that it says or offers
    /// something.
    pub fn validate(&self) -> std::result::Result<(), InquiryError> {
        if self.body.len() > MAX_MESSAGE_BYTES {
            return Err(InquiryError::MessageTooLong {
                bytes: self.body.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        if self.body.trim().is_empty() && self.counter_offer_centi.is_none() {
            return Err(InquiryError::EmptyMessage);
        }
        Ok(())
    }
}

impl From<InquiryMessage> for CBOR {
    fn from(m: InquiryMessage) -> Self {
        let mut map = Map::new();
        map.insert("kind", MESSAGE_KIND);
        map.insert("inquiry_id", m.inquiry_id);
        map.insert("sender", m.sender);
        map.insert("body", m.body);
        match m.counter_offer_centi {
            Some(offer) => map.insert("counter_offer_centi", offer),
            None => map.insert("counter_offer_centi", CBOR::null()),
        }
        map.insert("sent_at", m.sent_at);
        map.into()
    }
}

impl TryFrom<CBOR> for InquiryMessage {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != MESSAGE_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(InquiryMessage {
            inquiry_id: map.extract::<&str, InquiryId>("inquiry_id")?,
            sender: map.extract::<&str, Address>("sender")?,
            body: map.extract::<&str, String>("body")?,
            counter_offer_centi: map.get::<&str, i64>("counter_offer_centi"),
            sent_at: map.extract::<&str, i64>("sent_at")?,
        })
    }
}

/// How an inquiry ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InquiryOutcome {
    /// Both sides agreed on a price. The value is what a transaction (T1.7.6)
    /// will be proposed for.
    Agreed {
        /// The agreed price in centicommons.
        final_price_centi: i64,
    },
    /// The buyer walked away.
    DeclinedByBuyer,
    /// The provider declined.
    DeclinedBySeller,
    /// The station closed it after [`INQUIRY_TTL_SECS`] of no activity.
    Expired,
}

impl InquiryOutcome {
    /// The wire discriminant carried in the `outcome` field.
    fn tag(self) -> &'static str {
        match self {
            InquiryOutcome::Agreed { .. } => "agreed",
            InquiryOutcome::DeclinedByBuyer => "declined_by_buyer",
            InquiryOutcome::DeclinedBySeller => "declined_by_seller",
            InquiryOutcome::Expired => "expired",
        }
    }

    /// Whether the station may sign this outcome. It may attest that an inquiry
    /// went quiet and expired (ADR-0005: it acts with no party present), but it
    /// may never agree or decline on someone's behalf.
    fn station_may_sign(self) -> bool {
        matches!(self, InquiryOutcome::Expired)
    }
}

impl From<InquiryOutcome> for CBOR {
    fn from(o: InquiryOutcome) -> Self {
        let mut m = Map::new();
        m.insert("outcome", o.tag());
        if let InquiryOutcome::Agreed { final_price_centi } = o {
            m.insert("final_price_centi", final_price_centi);
        }
        m.into()
    }
}

impl TryFrom<CBOR> for InquiryOutcome {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        match map.extract::<&str, String>("outcome")?.as_str() {
            "agreed" => Ok(InquiryOutcome::Agreed {
                final_price_centi: map.extract::<&str, i64>("final_price_centi")?,
            }),
            "declined_by_buyer" => Ok(InquiryOutcome::DeclinedByBuyer),
            "declined_by_seller" => Ok(InquiryOutcome::DeclinedBySeller),
            "expired" => Ok(InquiryOutcome::Expired),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// The terminal record for an inquiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InquiryClosed {
    /// The inquiry being closed.
    pub inquiry_id: InquiryId,
    /// How it ended.
    pub outcome: InquiryOutcome,
    /// Unix seconds the close happened, from the signer's own clock.
    pub closed_at: i64,
}

impl From<InquiryClosed> for CBOR {
    fn from(c: InquiryClosed) -> Self {
        let mut m = Map::new();
        m.insert("kind", CLOSED_KIND);
        m.insert("inquiry_id", c.inquiry_id);
        m.insert("outcome", c.outcome);
        m.insert("closed_at", c.closed_at);
        m.into()
    }
}

impl TryFrom<CBOR> for InquiryClosed {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CLOSED_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(InquiryClosed {
            inquiry_id: map.extract::<&str, InquiryId>("inquiry_id")?,
            outcome: map.extract::<&str, InquiryOutcome>("outcome")?,
            closed_at: map.extract::<&str, i64>("closed_at")?,
        })
    }
}

/// An [`InquiryOpened`] signed by the buyer.
pub type SignedInquiryOpened = SignedPayload<InquiryOpened>;
/// An [`InquiryMessage`] signed by its sender (buyer or provider).
pub type SignedInquiryMessage = SignedPayload<InquiryMessage>;
/// An [`InquiryClosed`] signed by the buyer, the provider, or the station.
pub type SignedInquiryClosed = SignedPayload<InquiryClosed>;

/// A listing-requirements gate: given a listing and a buyer, whether the buyer
/// qualifies to open an inquiry against it. The station backs this with a read
/// of the reputation snapshot cache plus community membership; the crate's tests
/// inject the numbers directly. See [`scan`] on why the fact is an input.
pub type Admits = dyn Fn(&Listing, &Address) -> bool;

/// Whether a listing's requirements admit a particular buyer.
///
/// A pure comparison — the whole point of enforcement living here is that the
/// two facts about the buyer are *inputs*, so this crate performs no reputation
/// lookup and the write path and replay run byte-for-byte the same check.
///
/// - `buyer_capped_composite` is the **capped (public)** composite, never the
///   raw score, which exists only to make anchoring computable (ADR-0009).
/// - `buyer_in_listing_community` answers `community_member_only`; in Phase 1
///   the station treats any paired member as in `rrn-phase0`, which is what
///   every listing is stamped with.
pub fn check_requirements(
    reqs: &Requirements,
    listing_community: &str,
    buyer_capped_composite: f32,
    buyer_in_listing_community: bool,
) -> std::result::Result<(), RequirementUnmet> {
    if buyer_capped_composite < reqs.min_reputation {
        return Err(RequirementUnmet::ReputationTooLow {
            required: reqs.min_reputation,
            have: buyer_capped_composite,
        });
    }
    if reqs.community_member_only && !buyer_in_listing_community {
        return Err(RequirementUnmet::NotInCommunity {
            community: listing_community.to_string(),
        });
    }
    Ok(())
}

/// Every record on the log concerning one inquiry, in log order, together with
/// the listing it is about.
///
/// A key exists in a [`scan`]'s result only once a valid, *admitted*
/// [`InquiryOpened`] has been seen for an existing listing — so "no record
/// before a qualifying open counts" falls out of the structure, exactly as it
/// does for [`ListingRecords`](crate::lifecycle::ListingRecords).
#[derive(Clone, Debug)]
pub struct InquiryRecords {
    /// The opening record.
    pub opened: InquiryOpened,
    /// The listing as it currently reads — carried so message authorization and
    /// the negotiability rule have the provider and price without a second scan.
    pub listing: Listing,
    /// Every message, in log order.
    pub messages: Vec<InquiryMessage>,
    /// The close, if it has happened.
    pub closed: Option<InquiryClosed>,
}

impl InquiryRecords {
    fn new(opened: InquiryOpened, listing: Listing) -> Self {
        Self {
            opened,
            listing,
            messages: Vec::new(),
            closed: None,
        }
    }

    /// The buyer.
    pub fn buyer(&self) -> Address {
        self.opened.buyer
    }

    /// The provider (from the listing).
    pub fn provider(&self) -> Address {
        self.listing.provider
    }

    /// Unix seconds of the latest activity — the open, or the last message.
    pub fn last_activity_at(&self) -> i64 {
        self.messages
            .last()
            .map(|m| m.sent_at)
            .unwrap_or(self.opened.opened_at)
            .max(self.opened.opened_at)
    }

    /// Whether the inquiry has gone quiet past [`INQUIRY_TTL_SECS`] and is not
    /// yet closed — what the station's expiry sweep looks for.
    pub fn is_stale(&self, now: i64) -> bool {
        self.closed.is_none() && now - self.last_activity_at() > INQUIRY_TTL_SECS
    }

    /// Where the inquiry stands at `now`.
    pub fn state(&self, now: i64) -> InquiryState {
        if let Some(closed) = &self.closed {
            return InquiryState::Closed {
                outcome: closed.outcome,
                closed_at: closed.closed_at,
            };
        }
        if self.is_stale(now) {
            return InquiryState::ExpiredPending;
        }
        InquiryState::Open
    }
}

/// Where an inquiry stands, derived by replaying the log.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InquiryState {
    /// Live: either party may message, offer, accept, or decline.
    Open,
    /// Past [`INQUIRY_TTL_SECS`] of no activity, but the station's sweep has not
    /// yet written the close. A real state, not a gap — a reader treats it as
    /// off, and the sweep converts it to a signed [`InquiryClosed`] eventually.
    ExpiredPending,
    /// Closed for good. Terminal.
    Closed {
        /// How it ended.
        outcome: InquiryOutcome,
        /// When, from the closer's clock.
        closed_at: i64,
    },
}

impl InquiryState {
    /// The wire name of the state.
    pub fn tag(&self) -> &'static str {
        match self {
            InquiryState::Open => "open",
            InquiryState::ExpiredPending => "expired_pending",
            InquiryState::Closed { .. } => "closed",
        }
    }

    /// Whether the inquiry still accepts messages and offers.
    pub fn is_open(&self) -> bool {
        matches!(self, InquiryState::Open)
    }
}

/// Which inquiries a scan collects.
enum Scope<'a> {
    /// Just this one.
    One(&'a InquiryId),
    /// Every inquiry on the log.
    All,
}

impl Scope<'_> {
    fn wants(&self, id: &InquiryId) -> bool {
        match self {
            Scope::One(wanted) => *wanted == id,
            Scope::All => true,
        }
    }
}

/// Whether this signer may close the inquiry with this outcome: a party may
/// agree or decline on their own side, and the station may attest to expiry.
fn closer_is_entitled(
    outcome: InquiryOutcome,
    signer: &Address,
    buyer: &Address,
    provider: &Address,
    station: &PublicKey,
) -> bool {
    match outcome {
        // Either party may accept the standing offer (T1.7.5).
        InquiryOutcome::Agreed { .. } => signer == buyer || signer == provider,
        InquiryOutcome::DeclinedByBuyer => signer == buyer,
        InquiryOutcome::DeclinedBySeller => signer == provider,
        InquiryOutcome::Expired => {
            *signer == Address::from_public_key(*station) && outcome.station_may_sign()
        }
    }
}

/// Whether an `Agreed` price is one this listing will accept. A negotiable
/// listing accepts any agreed price; a non-negotiable one only its listed price
/// (T1.7.5). Non-`Agreed` outcomes carry no price and always pass.
fn agreed_price_ok(outcome: InquiryOutcome, listing: &Listing) -> bool {
    match outcome {
        InquiryOutcome::Agreed { final_price_centi } => {
            listing.pricing.negotiable || final_price_centi == listing.pricing.amount_centi
        }
        _ => true,
    }
}

/// Collects the records for every inquiry in `scope` in one pass over the log.
///
/// `admits` is the listing-requirements gate: for each candidate
/// [`InquiryOpened`] whose signer is its buyer and whose listing exists, it
/// decides whether the buyer qualified — the one fact this crate cannot compute
/// itself, since it needs the buyer's reputation. Everything else (signer
/// entitlement, thread membership, the negotiability rule) is settled here, so
/// replay and the append guards reach the same verdict by construction.
///
/// The listing behind each open is resolved through
/// [`lifecycle::listing_records`](crate::lifecycle::listing_records) and
/// memoized, so a market where one listing draws several inquiries pays for that
/// listing's history once.
fn scan(
    log: &AppendLog,
    scope: Scope<'_>,
    station: &PublicKey,
    admits: &Admits,
) -> Result<BTreeMap<InquiryId, InquiryRecords>> {
    use std::collections::btree_map::Entry;

    let mut found: BTreeMap<InquiryId, InquiryRecords> = BTreeMap::new();
    let mut listing_cache: BTreeMap<ListingId, Option<Listing>> = BTreeMap::new();

    for entry in log.iter_from(1) {
        let entry = entry?;
        let signer = Address::from_public_key(entry.payload.signer);

        if let Ok(opened) = from_canonical_bytes::<InquiryOpened>(&entry.payload.bytes) {
            if !scope.wants(&opened.inquiry_id) || signer != opened.buyer {
                continue;
            }
            let listing = match listing_cache.entry(opened.listing_id) {
                Entry::Occupied(e) => e.get().clone(),
                Entry::Vacant(e) => {
                    let resolved =
                        crate::lifecycle::listing_records(log, &opened.listing_id, station)?
                            .current();
                    e.insert(resolved.clone());
                    resolved
                }
            };
            let Some(listing) = listing else {
                continue;
            };
            if admits(&listing, &opened.buyer) {
                // First qualifying open wins; a duplicate id is the same
                // inquiry stated twice, and `append_inquiry_opened` refuses one.
                found
                    .entry(opened.inquiry_id)
                    .or_insert_with(|| InquiryRecords::new(opened, listing));
            }
            continue;
        }
        if let Ok(message) = from_canonical_bytes::<InquiryMessage>(&entry.payload.bytes) {
            let Some(records) = found.get_mut(&message.inquiry_id) else {
                continue;
            };
            if records.closed.is_none()
                && signer == message.sender
                && (message.sender == records.opened.buyer
                    || message.sender == records.listing.provider)
                && message.validate().is_ok()
            {
                records.messages.push(message);
            }
            continue;
        }
        if let Ok(close) = from_canonical_bytes::<InquiryClosed>(&entry.payload.bytes) {
            let Some(records) = found.get_mut(&close.inquiry_id) else {
                continue;
            };
            if records.closed.is_none()
                && closer_is_entitled(
                    close.outcome,
                    &signer,
                    &records.opened.buyer,
                    &records.listing.provider,
                    station,
                )
                && agreed_price_ok(close.outcome, &records.listing)
            {
                records.closed = Some(close);
            }
        }
    }
    Ok(found)
}

/// Collects every record for `inquiry_id` in one pass, or `None` if this log has
/// no qualifying open for it. See [`scan`] for what `admits` decides.
pub fn inquiry_records(
    log: &AppendLog,
    inquiry_id: &InquiryId,
    station: &PublicKey,
    admits: &Admits,
) -> Result<Option<InquiryRecords>> {
    Ok(scan(log, Scope::One(inquiry_id), station, admits)?.remove(inquiry_id))
}

/// Every inquiry this log has seen, keyed by content address. What the station's
/// read views and its expiry sweep replay from.
pub fn all_inquiry_records(
    log: &AppendLog,
    station: &PublicKey,
    admits: &Admits,
) -> Result<BTreeMap<InquiryId, InquiryRecords>> {
    scan(log, Scope::All, station, admits)
}

/// Where one inquiry stands at `now`, or `None` if this log has no qualifying
/// open for it.
pub fn compute_inquiry_state(
    log: &AppendLog,
    inquiry_id: &InquiryId,
    station: &PublicKey,
    now: i64,
    admits: &Admits,
) -> Result<Option<InquiryState>> {
    Ok(inquiry_records(log, inquiry_id, station, admits)?.map(|r| r.state(now)))
}

/// Which inquiry a log payload concerns, or `None` for a payload that is not one
/// of the three inquiry kinds. For a caller maintaining a derived view
/// incrementally; see [`lifecycle::touched_listing`](crate::lifecycle::touched_listing)
/// on why the kind mapping lives in this crate.
pub fn touched_inquiry(payload_bytes: &[u8]) -> Option<InquiryId> {
    if let Ok(opened) = from_canonical_bytes::<InquiryOpened>(payload_bytes) {
        return Some(opened.inquiry_id);
    }
    if let Ok(message) = from_canonical_bytes::<InquiryMessage>(payload_bytes) {
        return Some(message.inquiry_id);
    }
    if let Ok(close) = from_canonical_bytes::<InquiryClosed>(payload_bytes) {
        return Some(close.inquiry_id);
    }
    None
}

/// Whether this buyer already opened this inquiry, for the duplicate check. A
/// content-addressed open is byte-identical to any duplicate, so this needs no
/// `admits`: it only reports whether *this* buyer already opened *this* id.
fn already_opened(log: &AppendLog, inquiry_id: &InquiryId) -> Result<bool> {
    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(opened) = from_canonical_bytes::<InquiryOpened>(&entry.payload.bytes) else {
            continue;
        };
        if opened.inquiry_id == *inquiry_id
            && Address::from_public_key(entry.payload.signer) == opened.buyer
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Opens an inquiry: appends the buyer's signed [`InquiryOpened`] after checking
/// it against the listing's requirements.
///
/// The caller resolves `listing` (which must be the `Active` listing named by
/// the opening) and supplies the two buyer facts [`check_requirements`] needs —
/// so this crate performs no reputation lookup. Rejects an opening whose signer
/// is not its buyer, one about a different listing, one whose buyer does not
/// qualify, one that breaks its own rules, and a duplicate id.
pub fn append_inquiry_opened(
    log: &mut AppendLog,
    signed: SignedInquiryOpened,
    listing: &Listing,
    buyer_capped_composite: f32,
    buyer_in_listing_community: bool,
) -> Result<LogEntry> {
    let opened = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != opened.buyer {
        return Err(InquiryError::SignerNotBuyer {
            signer,
            buyer: opened.buyer,
        }
        .into());
    }
    if opened.listing_id != listing.id {
        return Err(InquiryError::ListingMismatch {
            opened: opened.listing_id,
            listing: listing.id,
        }
        .into());
    }
    opened.validate()?;
    check_requirements(
        &listing.requirements,
        &listing.community,
        buyer_capped_composite,
        buyer_in_listing_community,
    )
    .map_err(InquiryError::from)?;
    if already_opened(log, &opened.inquiry_id)? {
        return Err(InquiryError::AlreadyOpened(opened.inquiry_id).into());
    }
    Ok(log.append(signed)?)
}

/// Records a message from the buyer or the provider in an open inquiry.
pub fn append_inquiry_message(
    log: &mut AppendLog,
    signed: SignedInquiryMessage,
    station: &PublicKey,
    admits: &Admits,
) -> Result<LogEntry> {
    let message = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    if signer != message.sender {
        return Err(InquiryError::SignerDisagreesWithContent {
            signer,
            claimed: message.sender,
        }
        .into());
    }
    message.validate()?;

    let Some(records) = inquiry_records(log, &message.inquiry_id, station, admits)? else {
        return Err(InquiryError::UnknownInquiry(message.inquiry_id).into());
    };
    if let Some(closed) = records.closed {
        return Err(InquiryError::AlreadyClosed {
            inquiry_id: message.inquiry_id,
            closed_at: closed.closed_at,
        }
        .into());
    }
    if signer != records.buyer() && signer != records.provider() {
        return Err(InquiryError::SenderNotParty { sender: signer }.into());
    }

    Ok(log.append(signed)?)
}

/// Closes an inquiry, signed by the buyer, the provider, or the station.
///
/// `station` is passed explicitly because "is this the station" is not something
/// the record can assert about itself. An `Agreed` close must respect the
/// listing's negotiability.
pub fn append_inquiry_closed(
    log: &mut AppendLog,
    signed: SignedInquiryClosed,
    station: &PublicKey,
    admits: &Admits,
) -> Result<LogEntry> {
    let close = signed.payload;
    let signer = Address::from_public_key(signed.signer);

    let Some(records) = inquiry_records(log, &close.inquiry_id, station, admits)? else {
        return Err(InquiryError::UnknownInquiry(close.inquiry_id).into());
    };
    if let Some(existing) = records.closed {
        return Err(InquiryError::AlreadyClosed {
            inquiry_id: close.inquiry_id,
            closed_at: existing.closed_at,
        }
        .into());
    }
    if !closer_is_entitled(
        close.outcome,
        &signer,
        &records.buyer(),
        &records.provider(),
        station,
    ) {
        return Err(InquiryError::CloseNotPermitted {
            signer,
            outcome: close.outcome,
        }
        .into());
    }
    if !agreed_price_ok(close.outcome, &records.listing) {
        return Err(InquiryError::AgreedPriceNotAllowed {
            inquiry_id: close.inquiry_id,
            listed: records.listing.pricing.amount_centi,
        }
        .into());
    }

    Ok(log.append(signed)?)
}

/// A listing requirement a buyer did not meet at open time. One variant per
/// check, so the buyer learns *which* — a silent drop would leave them unable to
/// tell "not for me" from "the station is broken".
#[derive(Clone, Debug, PartialEq, Error)]
pub enum RequirementUnmet {
    /// The buyer's capped composite is below what the listing demands.
    #[error("listing requires reputation {required}, but yours is {have}")]
    ReputationTooLow {
        /// The listing's `min_reputation`.
        required: f32,
        /// The buyer's capped composite.
        have: f32,
    },
    /// The listing deals only with its own community, and the buyer is not in it.
    #[error("listing is limited to members of {community}")]
    NotInCommunity {
        /// The community the listing belongs to.
        community: String,
    },
}

/// An inquiry record the log would not accept. One variant per rule.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum InquiryError {
    /// The envelope's signer is not the inquiry's buyer.
    #[error("inquiry signed by {signer}, but its buyer is {buyer}")]
    SignerNotBuyer {
        /// Who signed.
        signer: Address,
        /// Who was entitled to.
        buyer: Address,
    },
    /// The record's own `sender` disagrees with who actually signed it.
    #[error("message signed by {signer} claims to be from {claimed}")]
    SignerDisagreesWithContent {
        /// Who signed the envelope.
        signer: Address,
        /// Who the content says sent it.
        claimed: Address,
    },
    /// The opening names a listing other than the one it was checked against.
    #[error("inquiry names listing {opened}, but was checked against {listing}")]
    ListingMismatch {
        /// The listing the opening names.
        opened: ListingId,
        /// The listing the caller resolved.
        listing: ListingId,
    },
    /// The buyer did not meet the listing's requirements.
    #[error("{0}")]
    Requirement(#[from] RequirementUnmet),
    /// A message or opening body exceeds [`MAX_MESSAGE_BYTES`].
    #[error("message is {bytes} bytes, over the {max}-byte limit")]
    MessageTooLong {
        /// Actual length in bytes.
        bytes: usize,
        /// The limit.
        max: usize,
    },
    /// A message that neither says nor offers anything.
    #[error("message has no body and no offer")]
    EmptyMessage,
    /// An inquiry with this id is already open on the log.
    #[error("inquiry {0} is already open")]
    AlreadyOpened(InquiryId),
    /// No qualifying open for this id — nothing to message or close.
    #[error("no inquiry {0} on this log")]
    UnknownInquiry(InquiryId),
    /// The inquiry is already closed; `Closed` is terminal.
    #[error("inquiry {inquiry_id} was closed at {closed_at}")]
    AlreadyClosed {
        /// The inquiry.
        inquiry_id: InquiryId,
        /// When it was closed.
        closed_at: i64,
    },
    /// A message from someone who is neither the buyer nor the provider.
    #[error("{sender} is neither the buyer nor the provider of this inquiry")]
    SenderNotParty {
        /// Who tried to speak.
        sender: Address,
    },
    /// This signer may not close the inquiry with this outcome.
    #[error("{signer} may not close an inquiry as {outcome:?}")]
    CloseNotPermitted {
        /// Who tried.
        signer: Address,
        /// The outcome they claimed.
        outcome: InquiryOutcome,
    },
    /// An `Agreed` price a non-negotiable listing will not accept.
    #[error("inquiry {inquiry_id} agreed a price other than the listed {listed}, which the listing does not negotiate")]
    AgreedPriceNotAllowed {
        /// The inquiry.
        inquiry_id: InquiryId,
        /// The listing's listed price.
        listed: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{
        Availability, AvailabilityStatus, Listing, Pricing, PricingModel, Requirements, Surface,
    };
    use crate::Error;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::db::Database;
    use rrn_storage::migrations;

    const OPENED_AT: i64 = 1_800_000_000;
    const COMMUNITY: &str = "blue_ridge_collective";

    fn open_log_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    /// A predicate that admits everyone — the common case in these tests, where
    /// requirements are exercised directly on [`check_requirements`] and the
    /// scan-level gate has its own dedicated test.
    fn admit_all() -> Box<Admits> {
        Box::new(|_, _| true)
    }

    fn listing_of(provider: &Keypair, negotiable: bool) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            COMMUNITY.into(),
            Surface::Services,
            "medical".into(),
            "General consultation".into(),
            "Thirty minutes.".into(),
            Pricing {
                amount_centi: 300,
                model: if negotiable {
                    PricingModel::Negotiable
                } else {
                    PricingModel::Fixed
                },
                negotiable,
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
            1_700_000_000,
            None,
        )
        .unwrap()
    }

    /// Publishes a listing so an inquiry has something real to be about — the
    /// scan resolves the listing from the log.
    fn publish(log: &mut AppendLog, provider: &Keypair, negotiable: bool) -> Listing {
        let listing = listing_of(provider, negotiable);
        crate::lifecycle::append_listing_created(
            log,
            SignedPayload::sign(listing.clone(), provider),
        )
        .unwrap();
        listing
    }

    fn opened_of(buyer: &Keypair, listing: &Listing, offer: Option<i64>) -> SignedInquiryOpened {
        let opened = InquiryOpened::new(
            listing.id,
            Address::from_public_key(buyer.public_key()),
            "Is this still available?".into(),
            offer,
            OPENED_AT,
        )
        .unwrap();
        SignedPayload::sign(opened, buyer)
    }

    fn message_of(
        sender: &Keypair,
        inquiry_id: InquiryId,
        body: &str,
        counter: Option<i64>,
        sent_at: i64,
    ) -> SignedInquiryMessage {
        SignedPayload::sign(
            InquiryMessage {
                inquiry_id,
                sender: Address::from_public_key(sender.public_key()),
                body: body.into(),
                counter_offer_centi: counter,
                sent_at,
            },
            sender,
        )
    }

    fn close_of(
        signer: &Keypair,
        inquiry_id: InquiryId,
        outcome: InquiryOutcome,
        closed_at: i64,
    ) -> SignedInquiryClosed {
        SignedPayload::sign(
            InquiryClosed {
                inquiry_id,
                outcome,
                closed_at,
            },
            signer,
        )
    }

    // --- content addressing + wire ---------------------------------------

    #[test]
    fn opened_names_itself_and_survives_a_roundtrip() {
        let buyer = Keypair::generate();
        let listing_id = ListingId(Hash::of(b"a listing"));
        let opened = InquiryOpened::new(
            listing_id,
            Address::from_public_key(buyer.public_key()),
            "hello".into(),
            Some(250),
            OPENED_AT,
        )
        .unwrap();

        let decoded: InquiryOpened =
            from_canonical_bytes(&to_canonical_bytes(opened.clone())).unwrap();
        assert_eq!(decoded, opened);
        // The id is the hash of the content, so a forged id decodes back to the
        // honest one.
        let mut forged = opened.clone();
        forged.inquiry_id = InquiryId(Hash::of(b"not this inquiry"));
        let decoded: InquiryOpened = from_canonical_bytes(&to_canonical_bytes(forged)).unwrap();
        assert_eq!(decoded.inquiry_id, opened.inquiry_id);
    }

    #[test]
    fn every_record_roundtrips_with_stable_tags() {
        let buyer = Keypair::generate();
        let listing_id = ListingId(Hash::of(b"a listing"));
        let opened = InquiryOpened::new(
            listing_id,
            Address::from_public_key(buyer.public_key()),
            String::new(),
            None,
            OPENED_AT,
        )
        .unwrap();

        let message = InquiryMessage {
            inquiry_id: opened.inquiry_id,
            sender: opened.buyer,
            body: "how about 2.50?".into(),
            counter_offer_centi: Some(250),
            sent_at: OPENED_AT + 10,
        };
        let cbor: CBOR = message.clone().into();
        assert_eq!(InquiryMessage::try_from(cbor).unwrap(), message);

        for outcome in [
            InquiryOutcome::Agreed {
                final_price_centi: 275,
            },
            InquiryOutcome::DeclinedByBuyer,
            InquiryOutcome::DeclinedBySeller,
            InquiryOutcome::Expired,
        ] {
            let close = InquiryClosed {
                inquiry_id: opened.inquiry_id,
                outcome,
                closed_at: OPENED_AT + 100,
            };
            let cbor: CBOR = close.into();
            assert_eq!(InquiryClosed::try_from(cbor).unwrap(), close);
        }
    }

    // --- requirements enforcement ----------------------------------------

    #[test]
    fn requirements_gate_on_reputation_and_community() {
        let reqs = Requirements {
            min_reputation: 2.0,
            community_member_only: true,
            federation_only: false,
        };
        // At or above the floor and in the community: admitted.
        assert!(check_requirements(&reqs, COMMUNITY, 2.0, true).is_ok());
        assert!(check_requirements(&reqs, COMMUNITY, 3.5, true).is_ok());

        // Below the floor: refused, and the error names the numbers.
        assert_eq!(
            check_requirements(&reqs, COMMUNITY, 1.9, true),
            Err(RequirementUnmet::ReputationTooLow {
                required: 2.0,
                have: 1.9,
            })
        );

        // In reach, but the wrong community.
        assert_eq!(
            check_requirements(&reqs, COMMUNITY, 2.0, false),
            Err(RequirementUnmet::NotInCommunity {
                community: COMMUNITY.into(),
            })
        );

        // An open listing admits anyone.
        let open = Requirements {
            min_reputation: 0.0,
            community_member_only: false,
            federation_only: false,
        };
        assert!(check_requirements(&open, COMMUNITY, 0.0, false).is_ok());
    }

    #[test]
    fn opening_is_refused_below_the_reputation_floor() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let mut listing = publish(&mut log, &provider, true);
        listing.requirements.min_reputation = 2.0;

        // The buyer's composite (1.0) is below the listing's floor (2.0).
        let err = append_inquiry_opened(
            &mut log,
            opened_of(&buyer, &listing, None),
            &listing,
            1.0,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::Requirement(
                RequirementUnmet::ReputationTooLow { .. }
            ))
        ));
        assert_eq!(log.iter_from(1).count(), 1); // only the listing

        // At the floor, it goes through.
        append_inquiry_opened(
            &mut log,
            opened_of(&buyer, &listing, None),
            &listing,
            2.0,
            true,
        )
        .unwrap();
        assert_eq!(log.iter_from(1).count(), 2);
    }

    #[test]
    fn opening_is_refused_from_another_community() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let mut listing = publish(&mut log, &provider, true);
        listing.requirements.community_member_only = true;

        let err = append_inquiry_opened(
            &mut log,
            opened_of(&buyer, &listing, None),
            &listing,
            3.0,
            false, // not a member of the listing's community
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::Requirement(
                RequirementUnmet::NotInCommunity { .. }
            ))
        ));
    }

    #[test]
    fn only_the_buyer_may_open_their_own_inquiry() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let impostor = Keypair::generate();
        let listing = publish(&mut log, &provider, true);

        // The opening names `buyer` but is signed by `impostor`.
        let opened = InquiryOpened::new(
            listing.id,
            Address::from_public_key(buyer.public_key()),
            "hi".into(),
            None,
            OPENED_AT,
        )
        .unwrap();
        let err = append_inquiry_opened(
            &mut log,
            SignedPayload::sign(opened, &impostor),
            &listing,
            3.0,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::SignerNotBuyer { .. })
        ));
    }

    #[test]
    fn a_duplicate_open_is_refused() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let listing = publish(&mut log, &provider, true);

        append_inquiry_opened(
            &mut log,
            opened_of(&buyer, &listing, None),
            &listing,
            3.0,
            true,
        )
        .unwrap();
        let err = append_inquiry_opened(
            &mut log,
            opened_of(&buyer, &listing, None),
            &listing,
            3.0,
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::AlreadyOpened(_))
        ));
    }

    // --- thread membership + state machine -------------------------------

    #[test]
    fn buyer_and_provider_may_message_but_no_one_else() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let stranger = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider, true);
        let opened = opened_of(&buyer, &listing, Some(250));
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        // Buyer and provider both land.
        append_inquiry_message(
            &mut log,
            message_of(&buyer, inquiry_id, "still there?", None, OPENED_AT + 5),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();
        append_inquiry_message(
            &mut log,
            message_of(&provider, inquiry_id, "yes", Some(275), OPENED_AT + 6),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();

        // A stranger cannot speak.
        let err = append_inquiry_message(
            &mut log,
            message_of(&stranger, inquiry_id, "me too", None, OPENED_AT + 7),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::SenderNotParty { .. })
        ));

        let records = inquiry_records(&log, &inquiry_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        assert_eq!(records.messages.len(), 2);
        assert!(records.state(OPENED_AT + 10).is_open());
    }

    #[test]
    fn an_empty_message_with_no_offer_is_refused() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider, true);
        let opened = opened_of(&buyer, &listing, None);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        let err = append_inquiry_message(
            &mut log,
            message_of(&buyer, inquiry_id, "   ", None, OPENED_AT + 5),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Inquiry(InquiryError::EmptyMessage)));

        // A bare counter-offer with no words is a real move, and lands.
        append_inquiry_message(
            &mut log,
            message_of(&buyer, inquiry_id, "", Some(250), OPENED_AT + 6),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();
    }

    #[test]
    fn an_inquiry_walks_from_open_through_messages_to_agreed() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let station_key = station.public_key();
        let listing = publish(&mut log, &provider, true);
        let opened = opened_of(&buyer, &listing, Some(250));
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        append_inquiry_message(
            &mut log,
            message_of(
                &provider,
                inquiry_id,
                "I can do 2.75",
                Some(275),
                OPENED_AT + 5,
            ),
            &station_key,
            &admit_all(),
        )
        .unwrap();

        // Buyer accepts the provider's counter.
        append_inquiry_closed(
            &mut log,
            close_of(
                &buyer,
                inquiry_id,
                InquiryOutcome::Agreed {
                    final_price_centi: 275,
                },
                OPENED_AT + 10,
            ),
            &station_key,
            &admit_all(),
        )
        .unwrap();

        let state = compute_inquiry_state(
            &log,
            &inquiry_id,
            &station_key,
            OPENED_AT + 20,
            &admit_all(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            state,
            InquiryState::Closed {
                outcome: InquiryOutcome::Agreed {
                    final_price_centi: 275
                },
                closed_at: OPENED_AT + 10,
            }
        );

        // A message after the terminal close is refused.
        let err = append_inquiry_message(
            &mut log,
            message_of(&buyer, inquiry_id, "actually...", None, OPENED_AT + 30),
            &station_key,
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::AlreadyClosed { .. })
        ));
    }

    #[test]
    fn a_non_negotiable_listing_only_agrees_at_its_listed_price() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let station_key = station.public_key();
        let listing = publish(&mut log, &provider, false); // not negotiable, 300
        let opened = opened_of(&buyer, &listing, None);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        // Agreeing at anything but the listed price is refused.
        let err = append_inquiry_closed(
            &mut log,
            close_of(
                &buyer,
                inquiry_id,
                InquiryOutcome::Agreed {
                    final_price_centi: 250,
                },
                OPENED_AT + 10,
            ),
            &station_key,
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Inquiry(InquiryError::AgreedPriceNotAllowed { .. })
        ));

        // The listed price goes through.
        append_inquiry_closed(
            &mut log,
            close_of(
                &buyer,
                inquiry_id,
                InquiryOutcome::Agreed {
                    final_price_centi: 300,
                },
                OPENED_AT + 11,
            ),
            &station_key,
            &admit_all(),
        )
        .unwrap();
    }

    #[test]
    fn declines_are_scoped_to_their_side_and_expiry_to_the_station() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let station_key = station.public_key();
        let listing = publish(&mut log, &provider, true);
        let opened = opened_of(&buyer, &listing, None);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        // The buyer cannot decline "as the seller", and no party may sign Expired.
        for (signer, outcome) in [
            (&buyer, InquiryOutcome::DeclinedBySeller),
            (&provider, InquiryOutcome::DeclinedByBuyer),
            (&buyer, InquiryOutcome::Expired),
        ] {
            let err = append_inquiry_closed(
                &mut log,
                close_of(signer, inquiry_id, outcome, OPENED_AT + 10),
                &station_key,
                &admit_all(),
            )
            .unwrap_err();
            assert!(matches!(
                err,
                Error::Inquiry(InquiryError::CloseNotPermitted { .. })
            ));
        }

        // The station may sign Expired.
        append_inquiry_closed(
            &mut log,
            close_of(
                &station,
                inquiry_id,
                InquiryOutcome::Expired,
                OPENED_AT + 10,
            ),
            &station_key,
            &admit_all(),
        )
        .unwrap();
    }

    #[test]
    fn an_inquiry_goes_stale_after_the_ttl() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider, true);
        let opened = opened_of(&buyer, &listing, None);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        let records = inquiry_records(&log, &inquiry_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        assert!(records.state(OPENED_AT + INQUIRY_TTL_SECS).is_open());
        assert_eq!(
            records.state(OPENED_AT + INQUIRY_TTL_SECS + 1),
            InquiryState::ExpiredPending
        );
    }

    // --- replay safety ----------------------------------------------------

    #[test]
    fn replay_drops_a_gossiped_open_the_buyer_did_not_qualify_for() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();

        // Publish a listing whose *on-log* requirements carry the floor — the
        // scan resolves the listing from the log, so a floor set only on a local
        // copy would not be what replay reads.
        let mut listing = listing_of(&provider, true);
        listing.requirements.min_reputation = 2.0;
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
        crate::lifecycle::append_listing_created(
            &mut log,
            SignedPayload::sign(listing.clone(), &provider),
        )
        .unwrap();

        // A gossiped open bypasses the append guard entirely.
        let opened = opened_of(&buyer, &listing, None);
        let inquiry_id = opened.payload.inquiry_id;
        log.append(opened).unwrap();

        // A predicate standing in for "read the buyer's reputation": this buyer
        // is below the floor, so replay must not believe the inquiry.
        let below_floor = |listing: &Listing, _buyer: &Address| {
            check_requirements(&listing.requirements, &listing.community, 1.0, true).is_ok()
        };
        assert!(
            inquiry_records(&log, &inquiry_id, &station.public_key(), &below_floor)
                .unwrap()
                .is_none()
        );

        // A buyer who does qualify is admitted from the very same log.
        let at_floor = |listing: &Listing, _buyer: &Address| {
            check_requirements(&listing.requirements, &listing.community, 2.0, true).is_ok()
        };
        assert!(
            inquiry_records(&log, &inquiry_id, &station.public_key(), &at_floor)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn replay_drops_messages_and_closes_no_one_was_entitled_to_write() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let stranger = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider, true);
        let opened = opened_of(&buyer, &listing, None);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        // Gossip a stranger's message and a stranger's decline.
        log.append(message_of(&stranger, inquiry_id, "hi", None, OPENED_AT + 5))
            .unwrap();
        log.append(close_of(
            &stranger,
            inquiry_id,
            InquiryOutcome::DeclinedBySeller,
            OPENED_AT + 6,
        ))
        .unwrap();

        let records = inquiry_records(&log, &inquiry_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        assert!(records.messages.is_empty());
        assert!(records.closed.is_none());
    }

    #[test]
    fn touched_inquiry_names_each_record_kind_and_ignores_others() {
        let buyer = Keypair::generate();
        let listing_id = ListingId(Hash::of(b"a listing"));
        let opened = InquiryOpened::new(
            listing_id,
            Address::from_public_key(buyer.public_key()),
            "hi".into(),
            None,
            OPENED_AT,
        )
        .unwrap();
        let message = InquiryMessage {
            inquiry_id: opened.inquiry_id,
            sender: opened.buyer,
            body: "x".into(),
            counter_offer_centi: None,
            sent_at: OPENED_AT + 1,
        };
        let close = InquiryClosed {
            inquiry_id: opened.inquiry_id,
            outcome: InquiryOutcome::DeclinedByBuyer,
            closed_at: OPENED_AT + 2,
        };

        assert_eq!(
            touched_inquiry(&to_canonical_bytes(opened.clone())),
            Some(opened.inquiry_id)
        );
        assert_eq!(
            touched_inquiry(&to_canonical_bytes(message)),
            Some(opened.inquiry_id)
        );
        assert_eq!(
            touched_inquiry(&to_canonical_bytes(close)),
            Some(opened.inquiry_id)
        );
        assert_eq!(touched_inquiry(b"not cbor at all"), None);
    }
}
