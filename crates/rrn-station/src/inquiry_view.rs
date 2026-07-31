//! Inquiry reads for the mobile and the CLI (T1.7.4).
//!
//! Where [`crate::marketplace_view`] shapes listings, this shapes the inquiry
//! thread a buyer and provider negotiate in: [`thread`] turns one inquiry's
//! records into the chat-and-offers view a message screen renders, and
//! [`my_inquiries`] turns the whole set into the summary rows an inbox lists.
//!
//! Both are pure shaping over [`rrn_marketplace::inquiry::InquiryRecords`],
//! which already carries the listing the inquiry is about — so the negotiability
//! rule and the listing title come along without a second scan, and neither
//! function touches the database.
//!
//! # Only a party sees a thread
//!
//! A thread is private to its buyer and provider; the caller passes the
//! authenticated viewer and these functions never return an inquiry the viewer
//! is not part of. That scoping is the caller's to apply — [`thread`] shapes
//! whatever records it is handed — but [`my_inquiries`] filters to the viewer by
//! construction, since an inbox is the caller's own inquiries by definition.

use serde::Serialize;

use rrn_identity::address::Address;
use rrn_marketplace::inquiry::{InquiryOutcome, InquiryRecords, InquiryState};

/// One message in a thread, flattened for the wire.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InquiryMessageRow {
    /// The sender's bech32m `rrn1…` address. A client aligns the bubble by
    /// comparing this to its own address and to the thread's `buyer`/`provider`.
    pub sender: String,
    /// The message body (may be empty when the move is a bare counter-offer).
    pub body: String,
    /// A revised price in centicommons, if this message carried one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter_offer_centi: Option<i64>,
    /// Unix seconds the message was sent.
    pub sent_at: i64,
}

/// One inquiry in full, for the chat-thread screen.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InquiryThreadView {
    /// The inquiry's content address, hex.
    pub inquiry_id: String,
    /// The listing being negotiated, hex — the id an eventual transaction links.
    pub listing_id: String,
    /// The listing's title, for the screen header.
    pub listing_title: String,
    /// The listing's listed price in centicommons — the reference the offers
    /// move around, and the only acceptable price when `negotiable` is false.
    pub listed_amount_centi: i64,
    /// Whether the listing invites offers. When false, the only close a party
    /// may agree to is at `listed_amount_centi`.
    pub negotiable: bool,
    /// The buyer's `rrn1…` address.
    pub buyer: String,
    /// The provider's `rrn1…` address.
    pub provider: String,
    /// The buyer's opening message (may be empty).
    pub initial_message: String,
    /// The buyer's opening offer, if they made one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_offer_centi: Option<i64>,
    /// Unix seconds the inquiry was opened.
    pub opened_at: i64,
    /// The messages, in log order.
    pub messages: Vec<InquiryMessageRow>,
    /// `open`, `expired_pending`, or `closed`.
    pub state: &'static str,
    /// How it ended, when `state` is `closed`: `agreed`, `declined_by_buyer`,
    /// `declined_by_seller`, or `expired`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    /// The agreed price, when the outcome is `agreed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_price_centi: Option<i64>,
    /// Unix seconds it closed, when `state` is `closed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<i64>,
    /// Unix seconds of the latest activity — for the inbox's ordering and a
    /// "last active" line.
    pub last_activity_at: i64,
}

/// One inquiry as an inbox row: enough to list and route, not the whole thread.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MyInquiryRow {
    /// The inquiry's content address, hex.
    pub inquiry_id: String,
    /// The listing, hex.
    pub listing_id: String,
    /// The listing's title.
    pub listing_title: String,
    /// The viewer's role in this inquiry: `buyer` or `provider`.
    pub role: &'static str,
    /// The other party's `rrn1…` address.
    pub counterparty: String,
    /// `open`, `expired_pending`, or `closed`.
    pub state: &'static str,
    /// How it ended, when `state` is `closed`: `agreed`, `declined_by_buyer`,
    /// `declined_by_seller`, or `expired`. Absent while the inquiry is live, so
    /// the inbox can tell an agreed deal from a declined one at a glance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    /// The most recent offer on the table (opening, last counter, or agreed
    /// price), in centicommons — what the row previews.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_offer_centi: Option<i64>,
    /// Unix seconds of the latest activity — the rows sort by this, newest first.
    pub last_activity_at: i64,
}

/// Shapes one inquiry's records into the thread view at `now`.
///
/// The caller has already checked the viewer is a party; this only shapes.
pub fn thread(records: &InquiryRecords, now: i64) -> InquiryThreadView {
    let state = records.state(now);
    let (outcome, final_price_centi, closed_at) = match state {
        InquiryState::Closed { outcome, closed_at } => {
            let price = match outcome {
                InquiryOutcome::Agreed { final_price_centi } => Some(final_price_centi),
                _ => None,
            };
            (Some(outcome_tag(outcome)), price, Some(closed_at))
        }
        _ => (None, None, None),
    };

    InquiryThreadView {
        inquiry_id: hex(&records.opened.inquiry_id.to_bytes()),
        listing_id: hex(&records.listing.id.to_bytes()),
        listing_title: records.listing.title.clone(),
        listed_amount_centi: records.listing.pricing.amount_centi,
        negotiable: records.listing.pricing.negotiable,
        buyer: records.buyer().to_string(),
        provider: records.provider().to_string(),
        initial_message: records.opened.initial_message.clone(),
        initial_offer_centi: records.opened.initial_offer_centi,
        opened_at: records.opened.opened_at,
        messages: records
            .messages
            .iter()
            .map(|m| InquiryMessageRow {
                sender: m.sender.to_string(),
                body: m.body.clone(),
                counter_offer_centi: m.counter_offer_centi,
                sent_at: m.sent_at,
            })
            .collect(),
        state: state.tag(),
        outcome,
        final_price_centi,
        closed_at,
        last_activity_at: records.last_activity_at(),
    }
}

/// Shapes the inquiries `viewer` is a party to into inbox rows, newest activity
/// first. Inquiries the viewer is neither buyer nor provider of are left out.
pub fn my_inquiries<I>(all: I, viewer: &Address, now: i64) -> Vec<MyInquiryRow>
where
    I: IntoIterator<Item = InquiryRecords>,
{
    let mut rows: Vec<MyInquiryRow> = all
        .into_iter()
        .filter_map(|records| {
            let (role, counterparty) = if records.buyer() == *viewer {
                ("buyer", records.provider())
            } else if records.provider() == *viewer {
                ("provider", records.buyer())
            } else {
                return None;
            };
            let state = records.state(now);
            let outcome = match state {
                InquiryState::Closed { outcome, .. } => Some(outcome_tag(outcome)),
                _ => None,
            };
            Some(MyInquiryRow {
                inquiry_id: hex(&records.opened.inquiry_id.to_bytes()),
                listing_id: hex(&records.listing.id.to_bytes()),
                listing_title: records.listing.title.clone(),
                role,
                counterparty: counterparty.to_string(),
                state: state.tag(),
                outcome,
                latest_offer_centi: latest_offer(&records),
                last_activity_at: records.last_activity_at(),
            })
        })
        .collect();
    // Newest activity first; ties broken by id so the order is deterministic.
    rows.sort_by(|a, b| {
        b.last_activity_at
            .cmp(&a.last_activity_at)
            .then_with(|| a.inquiry_id.cmp(&b.inquiry_id))
    });
    rows
}

/// The most recent offer on the table: the agreed price if closed as agreed, the
/// last counter-offer, or the opening offer — whichever is latest. `None` when
/// no number has been named.
fn latest_offer(records: &InquiryRecords) -> Option<i64> {
    if let Some(closed) = &records.closed {
        if let InquiryOutcome::Agreed { final_price_centi } = closed.outcome {
            return Some(final_price_centi);
        }
    }
    records
        .messages
        .iter()
        .rev()
        .find_map(|m| m.counter_offer_centi)
        .or(records.opened.initial_offer_centi)
}

/// The wire tag of an outcome, matching the `outcome` field the record encodes.
fn outcome_tag(outcome: InquiryOutcome) -> &'static str {
    match outcome {
        InquiryOutcome::Agreed { .. } => "agreed",
        InquiryOutcome::DeclinedByBuyer => "declined_by_buyer",
        InquiryOutcome::DeclinedBySeller => "declined_by_seller",
        InquiryOutcome::Expired => "expired",
    }
}

/// Lowercase hex, the form ids take on the wire. Re-uses the station's own
/// encoder so an inquiry id and a listing id read the same way.
fn hex(bytes: &[u8]) -> String {
    crate::core::hex(bytes)
}
