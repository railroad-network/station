//! Service-contract reads for the CLI (T1.7.7).
//!
//! Where [`crate::inquiry_view`] shapes the negotiation that precedes a deal,
//! this shapes the standing order that follows one: [`detail`] turns one
//! contract's records into the full status view `rrn show-contract` renders, and
//! [`my_contracts`] turns the set into the summary rows `rrn contracts` lists.
//!
//! Both are pure shaping over [`rrn_marketplace::contract::ContractRecords`],
//! which already carries the listing the contract subscribes to — so the title
//! and the parties come along without a second scan. Neither touches the
//! database.
//!
//! # `periods_charged` is an input
//!
//! How many periods the ledger has actually billed lives in the ledger's charge
//! records, not in the contract, so the caller counts it and hands it in — the
//! same shape the contract crate uses, where [`ContractRecords::state`] takes the
//! count rather than deriving it. Everything else about where the contract stands
//! (its next due date, whether it is terminating or ended) follows from that count
//! and the clock.
//!
//! # Only a party sees a contract
//!
//! A contract is private to its buyer and provider. [`my_contracts`] filters to
//! the viewer by construction; [`detail`] shapes whatever records it is handed, so
//! the caller checks the viewer is a party first, exactly as the inquiry thread
//! does.

use std::collections::BTreeMap;

use serde::Serialize;

use rrn_identity::address::Address;
use rrn_marketplace::contract::{ContractRecords, ContractState, EndReason};
use rrn_marketplace::listing::Frequency;

/// One contract in full, for `rrn show-contract`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ContractDetailView {
    /// The contract's content address, hex.
    pub contract_id: String,
    /// The agreed inquiry this contract was born from, hex.
    pub inquiry_id: String,
    /// The listing subscribed to, hex.
    pub listing_id: String,
    /// The listing's title, for the header.
    pub listing_title: String,
    /// The subscriber's `rrn1…` address.
    pub buyer: String,
    /// The provider's `rrn1…` address.
    pub provider: String,
    /// How often a period falls due: `daily`, `weekly`, `monthly`, or `custom`.
    pub frequency: &'static str,
    /// The period length in seconds — the only cadence detail a `custom`
    /// frequency does not otherwise reveal.
    pub period_secs: i64,
    /// How many periods the commitment runs for.
    pub duration_periods: u32,
    /// The per-period charge in centicommons.
    pub commons_per_period_centi: i64,
    /// Days of notice either side must give to end it early.
    pub notice_period_days: u32,
    /// The penalty in centicommons on whoever ends it before its natural end.
    pub early_termination_penalty_centi: i64,
    /// The buyer's free-form notes recorded on the contract.
    pub performance_metrics: BTreeMap<String, String>,
    /// Unix seconds the contract began; period 0 fell due here.
    pub started_at: i64,
    /// `active`, `terminating`, or `ended`.
    pub state: &'static str,
    /// How many periods the ledger has charged.
    pub periods_charged: u32,
    /// How many periods are still to run.
    pub periods_remaining: u32,
    /// When the next unbilled period falls due, while the contract is billing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_charge_due: Option<i64>,
    /// When a pending termination takes effect, while `state` is `terminating`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminating_effective_at: Option<i64>,
    /// Why it ended, when `state` is `ended`: `completed` or `terminated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_reason: Option<&'static str>,
    /// Which party ended it, when it ended by termination: `buyer` or `provider`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminated_by: Option<&'static str>,
    /// Whether it ended before its natural end (so the penalty applied), when
    /// `state` is `ended` by termination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_early: Option<bool>,
    /// Unix seconds it ended, when `state` is `ended`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
}

/// One contract as a list row: enough to list and route, not the full status.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ContractRow {
    /// The contract's content address, hex.
    pub contract_id: String,
    /// The listing's title.
    pub listing_title: String,
    /// The viewer's role: `buyer` or `provider`.
    pub role: &'static str,
    /// The other party's `rrn1…` address.
    pub counterparty: String,
    /// `active`, `terminating`, or `ended`.
    pub state: &'static str,
    /// The per-period charge in centicommons.
    pub commons_per_period_centi: i64,
    /// How many periods have been charged.
    pub periods_charged: u32,
    /// How many are still to run.
    pub periods_remaining: u32,
    /// When the next unbilled period falls due, while billing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_charge_due: Option<i64>,
    /// Unix seconds the contract began — the rows sort by this, newest first.
    pub started_at: i64,
}

/// Shapes one contract's records into the detail view at `now`, given how many
/// periods the ledger has charged. The caller has already checked the viewer is a
/// party; this only shapes.
pub fn detail(records: &ContractRecords, periods_charged: u32, now: i64) -> ContractDetailView {
    let terms = &records.contract.terms;
    let state = records.state(now, periods_charged);
    let mut view = ContractDetailView {
        contract_id: hex(&records.contract.contract_id.to_bytes()),
        inquiry_id: hex(&records.contract.inquiry_id.to_bytes()),
        listing_id: hex(&records.listing.id.to_bytes()),
        listing_title: records.listing.title.clone(),
        buyer: records.buyer().to_string(),
        provider: records.provider().to_string(),
        frequency: frequency_tag(terms.frequency),
        period_secs: terms.frequency.period_secs(),
        duration_periods: terms.duration_periods,
        commons_per_period_centi: terms.commons_per_period_centi,
        notice_period_days: terms.notice_period_days,
        early_termination_penalty_centi: terms.early_termination_penalty_centi,
        performance_metrics: terms.performance_metrics.clone(),
        started_at: records.contract.started_at,
        state: state.tag(),
        periods_charged,
        periods_remaining: records.total_periods().saturating_sub(periods_charged),
        next_charge_due: None,
        terminating_effective_at: None,
        ended_reason: None,
        terminated_by: None,
        ended_early: None,
        ended_at: None,
    };
    match state {
        ContractState::Active {
            next_charge_due,
            periods_remaining,
            ..
        } => {
            view.next_charge_due = Some(next_charge_due);
            view.periods_remaining = periods_remaining;
        }
        ContractState::Terminating { effective_at, .. } => {
            view.terminating_effective_at = Some(effective_at);
        }
        ContractState::Ended { reason, at } => {
            view.ended_at = Some(at);
            view.periods_remaining = 0;
            match reason {
                EndReason::Completed => view.ended_reason = Some("completed"),
                EndReason::Terminated { by, early } => {
                    view.ended_reason = Some("terminated");
                    view.terminated_by = Some(by.tag());
                    view.ended_early = Some(early);
                }
            }
        }
    }
    view
}

/// Shapes the contracts `viewer` is a party to into list rows, newest first.
/// Each record is paired with how many periods the ledger has charged it.
/// Contracts the viewer is neither buyer nor provider of are left out.
pub fn my_contracts<I>(all: I, viewer: &Address, now: i64) -> Vec<ContractRow>
where
    I: IntoIterator<Item = (ContractRecords, u32)>,
{
    let mut rows: Vec<ContractRow> = all
        .into_iter()
        .filter_map(|(records, periods_charged)| {
            let (role, counterparty) = if records.buyer() == *viewer {
                ("buyer", records.provider())
            } else if records.provider() == *viewer {
                ("provider", records.buyer())
            } else {
                return None;
            };
            let state = records.state(now, periods_charged);
            let next_charge_due = match state {
                ContractState::Active {
                    next_charge_due, ..
                } => Some(next_charge_due),
                _ => None,
            };
            Some(ContractRow {
                contract_id: hex(&records.contract.contract_id.to_bytes()),
                listing_title: records.listing.title.clone(),
                role,
                counterparty: counterparty.to_string(),
                state: state.tag(),
                commons_per_period_centi: records.contract.terms.commons_per_period_centi,
                periods_charged,
                periods_remaining: records.total_periods().saturating_sub(periods_charged),
                next_charge_due,
                started_at: records.contract.started_at,
            })
        })
        .collect();
    // Newest first; ties broken by id so the order is deterministic.
    rows.sort_by(|a, b| {
        b.started_at
            .cmp(&a.started_at)
            .then_with(|| a.contract_id.cmp(&b.contract_id))
    });
    rows
}

/// The wire tag of a frequency, matching the `unit` its CBOR encodes.
fn frequency_tag(f: Frequency) -> &'static str {
    match f {
        Frequency::Daily => "daily",
        Frequency::Weekly => "weekly",
        Frequency::Monthly => "monthly",
        Frequency::Custom(_) => "custom",
    }
}

/// Lowercase hex, the form ids take on the wire.
fn hex(bytes: &[u8]) -> String {
    crate::core::hex(bytes)
}
