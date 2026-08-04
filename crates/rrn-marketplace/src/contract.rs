//! Service contracts — the recurring commitment a buyer and a provider enter
//! into when a subscription service (a weekly veg box, a monthly checkup) is
//! agreed, the step that turns a one-off [`inquiry`](crate::inquiry) into a
//! standing order (T1.7.7).
//!
//! A one-off sale settles as a single [`TransactionProposal`](rrn_ledger::transaction::TransactionProposal)
//! the buyer signs. A subscription cannot: the buyer is not present to sign each
//! period's charge. Resolved with a *direct debit* — the buyer's one signature on
//! the [`ServiceContract`] pre-authorizes every identical period, and the station
//! executes each period's balance move directly (the ledger side is
//! [`ContractCharge`](rrn_ledger::contract), T1.7.7 Part C). Two record kinds
//! live on the log for one contract:
//!
//! | Kind | Payload | Signer |
//! |---|---|---|
//! | `rrn.marketplace.service_contract.v1` | [`ServiceContract`] | the buyer |
//! | `rrn.marketplace.contract_termination.v1` | [`ContractTermination`] | the buyer *or* the provider |
//!
//! # A contract names itself
//!
//! A [`ContractId`] is the Blake3 hash of the [`ServiceContract`]'s canonical
//! bytes — the same content-addressing [`Listing`](crate::listing::Listing) and
//! [`InquiryOpened`](crate::inquiry::InquiryOpened) use. The `contract_id` field
//! is not part of the hashed content, it *is* the hash of everything else; the
//! termination references that id.
//!
//! # Born from an agreed inquiry, no provider co-sign
//!
//! The provider *granting* an inquiry (an [`InquiryClosed`](crate::inquiry::InquiryClosed)
//! with an `Agreed` outcome, provider-signed) already is their signed acceptance
//! of the terms. So there is no separate provider signature on the contract: the
//! buyer signs the [`ServiceContract`] *citing that agreed inquiry*, and
//! [`append_service_contract`] refuses one whose cited inquiry is not
//! [`Agreed`](crate::inquiry::InquiryOutcome::Agreed) for exactly this
//! buyer + provider + listing. The cadence (frequency, duration, notice, penalty)
//! is the *listing's* standing terms; the per-period price is the *agreement's*
//! `final_price_centi`; the contract snapshots both as its [`ContractTerms`], so a
//! contract is self-contained on the log even if the listing later changes.
//!
//! # These checks are not the last line of defence
//!
//! As everywhere in this crate, the append helpers guard the *local* write path,
//! and a replicated entry arrives through `append_raw` (gossip) without passing
//! through them. So [`scan`] re-applies every rule when it derives state — the
//! buyer's signature, the agreed-inquiry provenance, the terms match, and the
//! termination entitlement — through the one function the write path also calls,
//! so replay and the guards cannot drift apart.

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

use crate::inquiry::{inquiry_records, InquiryId, InquiryOutcome};
use crate::listing::{Frequency, Listing, ListingId, RecurringTerms};
use crate::Result;

/// Discriminant strings carried in the `kind` field of each record's canonical
/// CBOR, so replay can tell the record types apart unambiguously.
pub(crate) const CONTRACT_KIND: &str = "rrn.marketplace.service_contract.v1";
pub(crate) const TERMINATION_KIND: &str = "rrn.marketplace.contract_termination.v1";

/// Seconds in a day — notice periods are stated in days, applied in seconds.
const SECS_PER_DAY: i64 = 86_400;

/// The content address of a contract: the Blake3 hash of its
/// [`ServiceContract`]'s canonical bytes.
#[derive(Clone, Copy, PartialEq, Eq, std::hash::Hash, Debug, Serialize, Deserialize)]
pub struct ContractId(pub Hash);

impl ContractId {
    /// The 32 raw hash bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Bare hex, the form a contract id takes everywhere a person meets one — a CLI
/// argument, a wire field, an error message. `Debug` stays wrapped for panics.
impl std::fmt::Display for ContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// A total order over the hash bytes, so a `ContractId` can key a `BTreeMap`
// during replay. Content, not chronology: arbitrary but identical everywhere.
impl Ord for ContractId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for ContractId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<ContractId> for CBOR {
    fn from(id: ContractId) -> Self {
        CBOR::to_byte_string(id.0.to_bytes())
    }
}

impl TryFrom<CBOR> for ContractId {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let bytes: [u8; 32] = cbor
            .try_into_byte_string()?
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::WrongType)?;
        Ok(ContractId(Hash::from_bytes(bytes)))
    }
}

/// The terms a contract commits to, snapshotted at signing so the contract is
/// self-contained even if the listing later changes.
///
/// The cadence fields ([`frequency`](Self::frequency),
/// [`duration_periods`](Self::duration_periods),
/// [`notice_period_days`](Self::notice_period_days),
/// [`early_termination_penalty_centi`](Self::early_termination_penalty_centi))
/// come from the listing's [`RecurringTerms`]; the price
/// ([`commons_per_period_centi`](Self::commons_per_period_centi)) is the agreed
/// inquiry's `final_price_centi`. [`performance_metrics`](Self::performance_metrics)
/// is free-form buyer-recorded metadata — a Phase-1 placeholder with no logic
/// behind it, since Phase 1 has no dispute system to weigh performance against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractTerms {
    /// How often a period falls due.
    pub frequency: Frequency,
    /// How many periods the commitment runs for.
    pub duration_periods: u32,
    /// The per-period charge in centicommons — the agreed inquiry's price.
    pub commons_per_period_centi: i64,
    /// Free-form metadata the buyer recorded (labels, notes). No logic reads it.
    pub performance_metrics: BTreeMap<String, String>,
    /// How much notice either side must give to end it early.
    pub notice_period_days: u32,
    /// A charge levied on the party who ends it before its natural end.
    pub early_termination_penalty_centi: i64,
}

impl ContractTerms {
    /// Whether these terms are the ones this listing + agreement dictate: the
    /// cadence must equal the listing's standing [`RecurringTerms`] and the
    /// per-period price the inquiry's agreed price.
    ///
    /// [`performance_metrics`](Self::performance_metrics) is deliberately not
    /// compared — it is the buyer's own free-form note, not a term the provider
    /// or the agreement fixes.
    fn matches(&self, recurring: &RecurringTerms, agreed_price_centi: i64) -> bool {
        self.frequency == recurring.frequency
            && self.duration_periods == recurring.duration_periods
            && self.notice_period_days == recurring.notice_period_days
            && self.early_termination_penalty_centi == recurring.early_termination_penalty_centi
            && self.commons_per_period_centi == agreed_price_centi
    }
}

impl From<ContractTerms> for CBOR {
    fn from(t: ContractTerms) -> Self {
        let mut m = Map::new();
        m.insert("frequency", t.frequency);
        m.insert("duration_periods", t.duration_periods);
        m.insert("commons_per_period_centi", t.commons_per_period_centi);
        // A nested map of the buyer's free-form notes. dcbor canonicalizes the
        // key order, so the same metadata encodes identically everywhere.
        let mut metrics = Map::new();
        for (k, v) in t.performance_metrics {
            metrics.insert(k, v);
        }
        m.insert("performance_metrics", metrics);
        m.insert("notice_period_days", t.notice_period_days);
        m.insert(
            "early_termination_penalty_centi",
            t.early_termination_penalty_centi,
        );
        m.into()
    }
}

impl TryFrom<CBOR> for ContractTerms {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        let mut performance_metrics = BTreeMap::new();
        match map
            .extract::<&str, CBOR>("performance_metrics")?
            .into_case()
        {
            CBORCase::Map(metrics) => {
                for (k, v) in metrics.iter() {
                    performance_metrics
                        .insert(k.clone().try_into_text()?, v.clone().try_into_text()?);
                }
            }
            _ => return Err(dcbor::Error::WrongType),
        }
        Ok(ContractTerms {
            frequency: map.extract::<&str, Frequency>("frequency")?,
            duration_periods: map.extract::<&str, u32>("duration_periods")?,
            commons_per_period_centi: map.extract::<&str, i64>("commons_per_period_centi")?,
            performance_metrics,
            notice_period_days: map.extract::<&str, u32>("notice_period_days")?,
            early_termination_penalty_centi: map
                .extract::<&str, i64>("early_termination_penalty_centi")?,
        })
    }
}

/// A buyer's signed commitment to a recurring service, citing the agreed inquiry
/// that authorizes it.
///
/// Content-addressed: [`contract_id`](Self::contract_id) is the hash of every
/// *other* field, so it is omitted from the CBOR and recomputed on decode, and
/// two byte-identical commitments are the same contract rather than two.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceContract {
    /// Content address: Blake3 of every *other* field's canonical bytes.
    pub contract_id: ContractId,
    /// The agreed inquiry this contract is born from — the provider's grant of it
    /// is their acceptance of the terms.
    pub inquiry_id: InquiryId,
    /// The listing being subscribed to.
    pub listing_id: ListingId,
    /// The member committing. Must equal the signer of the record.
    pub buyer: Address,
    /// The provider on the other side (the listing's provider).
    pub provider: Address,
    /// The terms, snapshotted from the listing + agreement.
    pub terms: ContractTerms,
    /// Unix seconds the contract began, from the buyer's own clock. Period `i`
    /// falls due at `started_at + i * frequency.period_secs()`.
    pub started_at: i64,
}

impl ServiceContract {
    /// Builds a contract and computes its content-addressed
    /// [`contract_id`](Self::contract_id), refusing one that breaks its own rules.
    pub fn new(
        inquiry_id: InquiryId,
        listing_id: ListingId,
        buyer: Address,
        provider: Address,
        terms: ContractTerms,
        started_at: i64,
    ) -> std::result::Result<Self, ContractError> {
        let contract = Self::assembled(inquiry_id, listing_id, buyer, provider, terms, started_at);
        contract.validate()?;
        Ok(contract)
    }

    /// Assembles a contract and computes its id *without* validating. Private:
    /// the only unvalidated path is decoding, which is structural by design.
    fn assembled(
        inquiry_id: InquiryId,
        listing_id: ListingId,
        buyer: Address,
        provider: Address,
        terms: ContractTerms,
        started_at: i64,
    ) -> Self {
        let mut contract = Self {
            // Placeholder; overwritten immediately by `compute_id`, which hashes
            // every field *except* `contract_id`.
            contract_id: ContractId(Hash::from_bytes([0u8; 32])),
            inquiry_id,
            listing_id,
            buyer,
            provider,
            terms,
            started_at,
        };
        contract.contract_id = contract.compute_id();
        contract
    }

    /// Recomputes the content address from the current field values.
    fn compute_id(&self) -> ContractId {
        // `Into<CBOR>` omits `contract_id`, so this hashes only the content.
        ContractId(Hash::of(&to_canonical_bytes(self.clone())))
    }

    /// Checks the contract's own rules — that its terms are internally sane. That
    /// they *match the listing and agreement* is the append path's, since that
    /// needs the log the contract does not carry.
    pub fn validate(&self) -> std::result::Result<(), ContractError> {
        if self.terms.duration_periods == 0 {
            return Err(ContractError::ZeroDuration);
        }
        if matches!(self.terms.frequency, Frequency::Custom(0)) {
            return Err(ContractError::ZeroPeriod);
        }
        if self.terms.early_termination_penalty_centi < 0 {
            return Err(ContractError::NegativePenalty {
                penalty_centi: self.terms.early_termination_penalty_centi,
            });
        }
        Ok(())
    }

    /// The period length in seconds — how far apart charges fall.
    fn period_secs(&self) -> i64 {
        self.terms.frequency.period_secs()
    }
}

impl From<ServiceContract> for CBOR {
    fn from(c: ServiceContract) -> Self {
        let mut m = Map::new();
        // `contract_id` is deliberately omitted — it is the hash of these bytes.
        m.insert("kind", CONTRACT_KIND);
        m.insert("inquiry_id", c.inquiry_id);
        m.insert("listing_id", c.listing_id);
        m.insert("buyer", c.buyer);
        m.insert("provider", c.provider);
        m.insert("terms", c.terms);
        m.insert("started_at", c.started_at);
        m.into()
    }
}

impl TryFrom<CBOR> for ServiceContract {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CONTRACT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(Self::assembled(
            map.extract::<&str, InquiryId>("inquiry_id")?,
            map.extract::<&str, ListingId>("listing_id")?,
            map.extract::<&str, Address>("buyer")?,
            map.extract::<&str, Address>("provider")?,
            map.extract::<&str, ContractTerms>("terms")?,
            map.extract::<&str, i64>("started_at")?,
        ))
    }
}

/// Which party asked to end a contract early.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminatedBy {
    /// The buyer walked away.
    Buyer,
    /// The provider ended it.
    Provider,
}

impl TerminatedBy {
    /// The wire discriminant carried in the `terminated_by` field.
    pub fn tag(self) -> &'static str {
        match self {
            TerminatedBy::Buyer => "buyer",
            TerminatedBy::Provider => "provider",
        }
    }
}

impl From<TerminatedBy> for CBOR {
    fn from(t: TerminatedBy) -> Self {
        t.tag().into()
    }
}

impl TryFrom<CBOR> for TerminatedBy {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        match cbor.try_into_text()?.as_str() {
            "buyer" => Ok(TerminatedBy::Buyer),
            "provider" => Ok(TerminatedBy::Provider),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// Either party's signed request to end a contract before its natural end. Takes
/// effect after the contract's notice period (see [`ContractRecords::state`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractTermination {
    /// The contract being ended.
    pub contract_id: ContractId,
    /// Which party asked. Must equal the signer's role.
    pub terminated_by: TerminatedBy,
    /// Unix seconds the request was made, from the signer's own clock. Notice
    /// runs from here.
    pub requested_at: i64,
}

impl From<ContractTermination> for CBOR {
    fn from(t: ContractTermination) -> Self {
        let mut m = Map::new();
        m.insert("kind", TERMINATION_KIND);
        m.insert("contract_id", t.contract_id);
        m.insert("terminated_by", t.terminated_by);
        m.insert("requested_at", t.requested_at);
        m.into()
    }
}

impl TryFrom<CBOR> for ContractTermination {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != TERMINATION_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ContractTermination {
            contract_id: map.extract::<&str, ContractId>("contract_id")?,
            terminated_by: map.extract::<&str, TerminatedBy>("terminated_by")?,
            requested_at: map.extract::<&str, i64>("requested_at")?,
        })
    }
}

/// A [`ServiceContract`] signed by the buyer.
pub type SignedServiceContract = SignedPayload<ServiceContract>;
/// A [`ContractTermination`] signed by the buyer or the provider.
pub type SignedContractTermination = SignedPayload<ContractTermination>;

/// Every record on the log concerning one contract, in log order, together with
/// the listing it subscribes to.
///
/// A key exists in a [`scan`]'s result only once a valid, agreed-inquiry-backed
/// [`ServiceContract`] has been seen — so "no contract before a valid signing
/// counts" falls out of the structure, exactly as it does for
/// [`InquiryRecords`](crate::inquiry::InquiryRecords).
#[derive(Clone, Debug)]
pub struct ContractRecords {
    /// The signing record.
    pub contract: ServiceContract,
    /// The listing as it read when the contract was validated — carried so the
    /// provider and price are on hand without a second scan.
    pub listing: Listing,
    /// The termination, if one has landed.
    pub terminated: Option<ContractTermination>,
}

impl ContractRecords {
    fn new(contract: ServiceContract, listing: Listing) -> Self {
        Self {
            contract,
            listing,
            terminated: None,
        }
    }

    /// The buyer.
    pub fn buyer(&self) -> Address {
        self.contract.buyer
    }

    /// The provider.
    pub fn provider(&self) -> Address {
        self.contract.provider
    }

    /// The total number of periods the contract runs for.
    pub fn total_periods(&self) -> u32 {
        self.contract.terms.duration_periods
    }

    /// When period `index` (0-based) falls due — `started_at + index * period`.
    /// Period 0 is due at `started_at`, so the first charge is taken up front.
    pub fn period_due_at(&self, index: u32) -> i64 {
        self.contract.started_at + i64::from(index) * self.contract.period_secs()
    }

    /// When the contract would end of its own accord, had no one terminated it —
    /// the moment after the last period.
    fn natural_end_at(&self) -> i64 {
        self.period_due_at(self.total_periods())
    }

    /// When a termination takes effect: the request time plus the notice period.
    /// `None` if no termination has been requested.
    pub fn termination_effective_at(&self) -> Option<i64> {
        self.terminated.map(|t| {
            t.requested_at + i64::from(self.contract.terms.notice_period_days) * SECS_PER_DAY
        })
    }

    /// The next period the station's charge sweep should bill, given how many
    /// have already been charged, or `None` if none is due at `now`.
    ///
    /// The sweep hands in `periods_charged` — the count of periods already
    /// billed, which lives in the ledger, not here (T1.7.7 Part C/D) — so this
    /// crate performs no ledger lookup, exactly as the inquiry gate takes the
    /// buyer's reputation as an input rather than reading it. A period is billable
    /// when it is due, still within the commitment's duration, and (if the
    /// contract is terminating) falls on or before the notice window closes:
    /// charges run *through* the notice window, then stop.
    pub fn next_due_charge(&self, now: i64, periods_charged: u32) -> Option<u32> {
        if periods_charged >= self.total_periods() {
            return None;
        }
        let index = periods_charged;
        let due_at = self.period_due_at(index);
        if now < due_at {
            return None;
        }
        if let Some(effective_at) = self.termination_effective_at() {
            if due_at > effective_at {
                return None;
            }
        }
        Some(index)
    }

    /// Whether a termination ended the contract before its natural end — the
    /// condition under which the [`early_termination_penalty_centi`](ContractTerms::early_termination_penalty_centi)
    /// applies. `false` when no termination has landed.
    pub fn is_early_termination(&self) -> bool {
        self.termination_effective_at()
            .is_some_and(|effective_at| effective_at < self.natural_end_at())
    }

    /// Where the contract stands at `now`, given how many periods the ledger has
    /// charged so far.
    ///
    /// A contract that has been charged its full [`duration`](ContractRecords::total_periods)
    /// reads [`Ended`](ContractState::Ended) with [`Completed`](EndReason::Completed)
    /// even if a stray termination also landed — a commitment that ran its course
    /// is done, and the termination is moot.
    pub fn state(&self, now: i64, periods_charged: u32) -> ContractState {
        if periods_charged >= self.total_periods() {
            return ContractState::Ended {
                reason: EndReason::Completed,
                at: self.natural_end_at(),
            };
        }
        if let (Some(term), Some(effective_at)) = (self.terminated, self.termination_effective_at())
        {
            if now < effective_at {
                return ContractState::Terminating {
                    effective_at,
                    periods_charged,
                };
            }
            return ContractState::Ended {
                reason: EndReason::Terminated {
                    by: term.terminated_by,
                    early: self.is_early_termination(),
                },
                at: effective_at,
            };
        }
        ContractState::Active {
            next_charge_due: self.period_due_at(periods_charged),
            periods_charged,
            periods_remaining: self.total_periods() - periods_charged,
        }
    }
}

/// Why a contract ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// It ran its full duration — every period was charged.
    Completed,
    /// A party terminated it.
    Terminated {
        /// Which party asked.
        by: TerminatedBy,
        /// Whether it ended before its natural end (so the penalty applies).
        early: bool,
    },
}

/// Where a contract stands, derived by replaying the log against the ledger's
/// charge count. A computed view, never stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractState {
    /// Live and billing: the station charges each period as it falls due.
    Active {
        /// When the next unbilled period falls due.
        next_charge_due: i64,
        /// How many periods have been charged.
        periods_charged: u32,
        /// How many periods are still to run.
        periods_remaining: u32,
    },
    /// A termination has landed but its notice window has not closed yet: the
    /// contract keeps billing through the window, then ends.
    Terminating {
        /// When the termination takes effect.
        effective_at: i64,
        /// How many periods have been charged so far.
        periods_charged: u32,
    },
    /// Ended for good. Terminal.
    Ended {
        /// Why it ended.
        reason: EndReason,
        /// When, from the relevant clock.
        at: i64,
    },
}

impl ContractState {
    /// The wire name of the state.
    pub fn tag(&self) -> &'static str {
        match self {
            ContractState::Active { .. } => "active",
            ContractState::Terminating { .. } => "terminating",
            ContractState::Ended { .. } => "ended",
        }
    }

    /// Whether the contract is still live (billing or in its notice window).
    pub fn is_live(&self) -> bool {
        matches!(
            self,
            ContractState::Active { .. } | ContractState::Terminating { .. }
        )
    }
}

/// Which contracts a scan collects.
enum Scope<'a> {
    /// Just this one.
    One(&'a ContractId),
    /// Every contract on the log.
    All,
}

impl Scope<'_> {
    fn wants(&self, id: &ContractId) -> bool {
        match self {
            Scope::One(wanted) => *wanted == id,
            Scope::All => true,
        }
    }
}

/// Whether this signer may terminate the contract with this claim: the buyer may
/// terminate as the buyer, the provider as the provider — and the record's own
/// `terminated_by` must agree with who actually signed.
fn terminator_entitled(
    term: &ContractTermination,
    signer: &Address,
    contract: &ServiceContract,
) -> bool {
    match term.terminated_by {
        TerminatedBy::Buyer => *signer == contract.buyer,
        TerminatedBy::Provider => *signer == contract.provider,
    }
}

/// Checks a signed contract against the log, returning the listing it subscribes
/// to when it holds up: the signer is the buyer, the cited inquiry is `Agreed`
/// for exactly this buyer + provider + listing, the listing is recurring, and the
/// terms match the listing's cadence and the agreement's price.
///
/// The one function the write path and replay both run, so they reach the same
/// verdict by construction. `admits` is the listing-requirements gate the inquiry
/// resolution needs — see [`crate::inquiry::scan`] on why that fact is an input.
/// The duplicate-per-inquiry check is *not* here: [`scan`] handles it by
/// first-write-wins, and [`append_service_contract`] by an explicit log scan.
fn check_contract(
    log: &AppendLog,
    contract: &ServiceContract,
    signer: &Address,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> std::result::Result<Listing, ContractError> {
    if *signer != contract.buyer {
        return Err(ContractError::SignerNotBuyer {
            signer: *signer,
            buyer: contract.buyer,
        });
    }
    contract.validate()?;

    let inquiry = inquiry_records(log, &contract.inquiry_id, station, admits)
        .map_err(|_| ContractError::UnknownInquiry(contract.inquiry_id))?
        .ok_or(ContractError::UnknownInquiry(contract.inquiry_id))?;

    // The provider's grant of the inquiry is their acceptance; without it there
    // is no agreement for the buyer to commit to.
    let Some(closed) = inquiry.closed else {
        return Err(ContractError::InquiryNotAgreed {
            inquiry_id: contract.inquiry_id,
        });
    };
    let InquiryOutcome::Agreed { final_price_centi } = closed.outcome else {
        return Err(ContractError::InquiryNotAgreed {
            inquiry_id: contract.inquiry_id,
        });
    };

    if inquiry.buyer() != contract.buyer || inquiry.provider() != contract.provider {
        return Err(ContractError::PartyMismatch(Box::new(PartyMismatch {
            contract_buyer: contract.buyer,
            contract_provider: contract.provider,
            inquiry_buyer: inquiry.buyer(),
            inquiry_provider: inquiry.provider(),
        })));
    }
    if inquiry.listing.id != contract.listing_id {
        return Err(ContractError::ListingMismatch {
            contract: contract.listing_id,
            inquiry: inquiry.listing.id,
        });
    }

    let Some(recurring) = inquiry.listing.recurring else {
        return Err(ContractError::ListingNotRecurring(contract.listing_id));
    };
    if !contract.terms.matches(&recurring, final_price_centi) {
        return Err(ContractError::TermsMismatch {
            contract_id: contract.contract_id,
        });
    }

    Ok(inquiry.listing)
}

/// Whether a *valid* contract for this inquiry already exists on the log, for the
/// one-contract-per-agreement check. A single agreed inquiry authorizes a single
/// standing order; a second signing over the same inquiry — even with different
/// [`performance_metrics`](ContractTerms::performance_metrics), which would give
/// it a different id — is refused.
///
/// It counts only contracts [`scan`] accepts, so a stranger's self-consistent but
/// bogus contract citing the inquiry (its buyer never agreed it, so [`scan`] drops
/// it) does not spuriously block the real buyer.
fn inquiry_already_contracted(
    log: &AppendLog,
    inquiry_id: &InquiryId,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> Result<bool> {
    Ok(all_contract_records(log, station, admits)?
        .values()
        .any(|records| records.contract.inquiry_id == *inquiry_id))
}

/// Collects the records for every contract in `scope` in one pass over the log.
///
/// `admits` is the listing-requirements gate the inquiry resolution behind each
/// contract needs. Every rule — the buyer's signature, the agreed-inquiry
/// provenance, the terms match, the termination entitlement — is settled here, so
/// replay and the append guards reach the same verdict by construction.
fn scan(
    log: &AppendLog,
    scope: Scope<'_>,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> Result<BTreeMap<ContractId, ContractRecords>> {
    let mut found: BTreeMap<ContractId, ContractRecords> = BTreeMap::new();

    for entry in log.iter_from(1) {
        let entry = entry?;
        let signer = Address::from_public_key(entry.payload.signer);

        if let Ok(contract) = from_canonical_bytes::<ServiceContract>(&entry.payload.bytes) {
            if !scope.wants(&contract.contract_id) {
                continue;
            }
            if let Ok(listing) = check_contract(log, &contract, &signer, station, admits) {
                // First valid signing wins; a duplicate id is the same contract
                // stated twice, and `append_service_contract` refuses one.
                found
                    .entry(contract.contract_id)
                    .or_insert_with(|| ContractRecords::new(contract, listing));
            }
            continue;
        }
        if let Ok(term) = from_canonical_bytes::<ContractTermination>(&entry.payload.bytes) {
            let Some(records) = found.get_mut(&term.contract_id) else {
                continue;
            };
            if records.terminated.is_none()
                && terminator_entitled(&term, &signer, &records.contract)
            {
                records.terminated = Some(term);
            }
        }
    }
    Ok(found)
}

/// Collects every record for `contract_id` in one pass, or `None` if this log has
/// no valid signing for it. See [`scan`] for what `admits` decides.
pub fn contract_records(
    log: &AppendLog,
    contract_id: &ContractId,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> Result<Option<ContractRecords>> {
    Ok(scan(log, Scope::One(contract_id), station, admits)?.remove(contract_id))
}

/// Every contract this log has seen, keyed by content address. What the station's
/// read views and its charge sweep replay from.
pub fn all_contract_records(
    log: &AppendLog,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> Result<BTreeMap<ContractId, ContractRecords>> {
    scan(log, Scope::All, station, admits)
}

/// Which contract a log payload concerns, or `None` for a payload that is not one
/// of the two contract kinds. For a caller maintaining a derived view
/// incrementally; see [`crate::lifecycle::touched_listing`] on why the kind
/// mapping lives in this crate.
pub fn touched_contract(payload_bytes: &[u8]) -> Option<ContractId> {
    if let Ok(contract) = from_canonical_bytes::<ServiceContract>(payload_bytes) {
        return Some(contract.contract_id);
    }
    if let Ok(term) = from_canonical_bytes::<ContractTermination>(payload_bytes) {
        return Some(term.contract_id);
    }
    None
}

/// Signs a buyer up to a recurring service: appends the buyer's signed
/// [`ServiceContract`] after checking it is born from a matching agreed inquiry.
///
/// Rejects a contract whose signer is not its buyer, one that breaks its own
/// rules, one whose cited inquiry is not `Agreed` for this buyer + provider +
/// listing, one whose listing is not recurring, one whose terms do not match the
/// listing and agreement, and a second contract over an inquiry already
/// committed. `admits` is the listing-requirements gate the inquiry resolution
/// needs.
pub fn append_service_contract(
    log: &mut AppendLog,
    signed: SignedServiceContract,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> Result<LogEntry> {
    let contract = &signed.payload;
    let signer = Address::from_public_key(signed.signer);
    check_contract(log, contract, &signer, station, admits)?;
    if inquiry_already_contracted(log, &contract.inquiry_id, station, admits)? {
        return Err(ContractError::AlreadyContracted {
            inquiry_id: contract.inquiry_id,
        }
        .into());
    }
    Ok(log.append(signed)?)
}

/// Ends a contract early, signed by the buyer or the provider. Takes effect after
/// the contract's notice period; the charge sweep bills through the window and
/// applies the penalty if it ended early.
///
/// `station` is passed to read the contract's history (the inquiry behind it is
/// resolved with `admits`), not to authorize the termination — either party may.
pub fn append_contract_termination(
    log: &mut AppendLog,
    signed: SignedContractTermination,
    station: &PublicKey,
    admits: &dyn Fn(&Listing, &Address) -> bool,
) -> Result<LogEntry> {
    let term = signed.payload;
    let signer = Address::from_public_key(signed.signer);

    let Some(records) = contract_records(log, &term.contract_id, station, admits)? else {
        return Err(ContractError::UnknownContract(term.contract_id).into());
    };
    if let Some(existing) = records.terminated {
        return Err(ContractError::AlreadyTerminated {
            contract_id: term.contract_id,
            requested_at: existing.requested_at,
        }
        .into());
    }
    if !terminator_entitled(&term, &signer, &records.contract) {
        return Err(ContractError::TerminationNotPermitted { signer }.into());
    }

    Ok(log.append(signed)?)
}

/// The four parties involved when a contract's buyer/provider disagree with its
/// inquiry's. Carried behind a `Box` in [`ContractError::PartyMismatch`] to keep
/// the error small.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyMismatch {
    /// The buyer the contract names.
    pub contract_buyer: Address,
    /// The provider the contract names.
    pub contract_provider: Address,
    /// The buyer the inquiry names.
    pub inquiry_buyer: Address,
    /// The provider the inquiry names.
    pub inquiry_provider: Address,
}

/// A contract record the log would not accept. One variant per rule, so a caller
/// learns which entitlement or match was missing.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum ContractError {
    /// The envelope's signer is not the contract's buyer.
    #[error("contract signed by {signer}, but its buyer is {buyer}")]
    SignerNotBuyer {
        /// Who signed.
        signer: Address,
        /// Who was entitled to.
        buyer: Address,
    },
    /// A contract that runs for zero periods.
    #[error("a contract must run for at least one period")]
    ZeroDuration,
    /// A `Frequency::Custom(0)` — a period of no length.
    #[error("a custom billing period must be a positive number of seconds")]
    ZeroPeriod,
    /// A negative early-termination penalty.
    #[error("early-termination penalty {penalty_centi} is negative")]
    NegativePenalty {
        /// The offending penalty.
        penalty_centi: i64,
    },
    /// No qualifying inquiry for the cited id — nothing to be born from.
    #[error("no inquiry {0} this contract could be born from")]
    UnknownInquiry(InquiryId),
    /// The cited inquiry is not agreed, so there is no acceptance to commit to.
    #[error("inquiry {inquiry_id} is not an agreed inquiry")]
    InquiryNotAgreed {
        /// The cited inquiry.
        inquiry_id: InquiryId,
    },
    /// The contract's parties disagree with the inquiry's. Boxed so the four
    /// addresses do not bloat every `Result<_, ContractError>` on the write path
    /// (clippy's `result_large_err`).
    #[error("contract parties (buyer {}, provider {}) do not match inquiry (buyer {}, provider {})", .0.contract_buyer, .0.contract_provider, .0.inquiry_buyer, .0.inquiry_provider)]
    PartyMismatch(Box<PartyMismatch>),
    /// The contract names a listing other than the inquiry's.
    #[error("contract names listing {contract}, but its inquiry is about {inquiry}")]
    ListingMismatch {
        /// The listing the contract names.
        contract: ListingId,
        /// The listing the inquiry is about.
        inquiry: ListingId,
    },
    /// The listing is not a recurring service, so it cannot back a contract.
    #[error("listing {0} is not a recurring service")]
    ListingNotRecurring(ListingId),
    /// The contract's terms are not the listing's cadence and the agreement's
    /// price.
    #[error("contract {contract_id} terms do not match the listing and agreement")]
    TermsMismatch {
        /// The contract.
        contract_id: ContractId,
    },
    /// A contract for this inquiry already exists; one agreement, one contract.
    #[error("inquiry {inquiry_id} already has a contract")]
    AlreadyContracted {
        /// The inquiry already committed.
        inquiry_id: InquiryId,
    },
    /// No contract with this id — nothing to terminate.
    #[error("no contract {0} on this log")]
    UnknownContract(ContractId),
    /// The contract is already terminating; a second request is refused.
    #[error("contract {contract_id} was already terminated at {requested_at}")]
    AlreadyTerminated {
        /// The contract.
        contract_id: ContractId,
        /// When the first termination was requested.
        requested_at: i64,
    },
    /// A termination from someone who is neither the buyer nor the provider, or
    /// whose claimed role disagrees with their signature.
    #[error("{signer} may not terminate this contract")]
    TerminationNotPermitted {
        /// Who tried.
        signer: Address,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inquiry::{
        append_inquiry_closed, append_inquiry_opened, Admits, InquiryClosed, InquiryOpened,
        SignedInquiryClosed, SignedInquiryOpened,
    };
    use crate::lifecycle::append_listing_created;
    use crate::listing::{
        Availability, AvailabilityStatus, Pricing, PricingModel, Requirements, Surface,
    };
    use crate::Error;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::db::Database;
    use rrn_storage::migrations;

    const STARTED_AT: i64 = 1_800_000_000;
    const OPENED_AT: i64 = 1_799_000_000;
    const PRICE: i64 = 500;
    const PERIODS: u32 = 4;
    const NOTICE_DAYS: u32 = 7;
    const PENALTY: i64 = 500;
    const COMMUNITY: &str = "blue_ridge_collective";
    const WEEK: i64 = 7 * 86_400;

    fn open_log_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    /// A predicate that admits everyone — requirements enforcement is the
    /// inquiry's concern and has its own tests there.
    fn admit_all() -> Box<Admits> {
        Box::new(|_, _| true)
    }

    fn recurring_terms() -> RecurringTerms {
        RecurringTerms {
            frequency: Frequency::Weekly,
            duration_periods: PERIODS,
            notice_period_days: NOTICE_DAYS,
            early_termination_penalty_centi: PENALTY,
        }
    }

    /// A recurring services listing priced so a buyer accepting the listed price
    /// agrees at [`PRICE`].
    fn recurring_listing(provider: &Keypair) -> Listing {
        Listing::new(
            Address::from_public_key(provider.public_key()),
            COMMUNITY.into(),
            Surface::Services,
            "education".into(),
            "Weekly house clean".into(),
            "Every Tuesday.".into(),
            Pricing {
                amount_centi: PRICE,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: None,
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
        .with_recurring(recurring_terms())
    }

    fn publish(log: &mut AppendLog, provider: &Keypair) -> Listing {
        let listing = recurring_listing(provider);
        append_listing_created(log, SignedPayload::sign(listing.clone(), provider)).unwrap();
        listing
    }

    fn opened_of(buyer: &Keypair, listing: &Listing) -> SignedInquiryOpened {
        // Accept the listed price with no counter-offer: the standing offer is the
        // listed price, which the provider may grant.
        let opened = InquiryOpened::new(
            listing.id,
            Address::from_public_key(buyer.public_key()),
            "Sign me up.".into(),
            None,
            OPENED_AT,
        )
        .unwrap();
        SignedPayload::sign(opened, buyer)
    }

    fn agreed_close(provider: &Keypair, inquiry_id: InquiryId, price: i64) -> SignedInquiryClosed {
        SignedPayload::sign(
            InquiryClosed {
                inquiry_id,
                outcome: InquiryOutcome::Agreed {
                    final_price_centi: price,
                },
                closed_at: OPENED_AT + 10,
            },
            provider,
        )
    }

    /// Opens an inquiry and has the provider grant it at the listed price,
    /// returning the agreed inquiry's id.
    fn agree_inquiry(
        log: &mut AppendLog,
        buyer: &Keypair,
        provider: &Keypair,
        station: &Keypair,
        listing: &Listing,
    ) -> InquiryId {
        let opened = opened_of(buyer, listing);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(log, opened, listing, 3.0, true).unwrap();
        append_inquiry_closed(
            log,
            agreed_close(provider, inquiry_id, listing.pricing.amount_centi),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();
        inquiry_id
    }

    fn terms(price: i64) -> ContractTerms {
        ContractTerms {
            frequency: Frequency::Weekly,
            duration_periods: PERIODS,
            commons_per_period_centi: price,
            performance_metrics: BTreeMap::new(),
            notice_period_days: NOTICE_DAYS,
            early_termination_penalty_centi: PENALTY,
        }
    }

    fn contract_of(
        buyer: &Keypair,
        provider: &Keypair,
        inquiry_id: InquiryId,
        listing: &Listing,
        terms: ContractTerms,
    ) -> SignedServiceContract {
        let contract = ServiceContract::new(
            inquiry_id,
            listing.id,
            Address::from_public_key(buyer.public_key()),
            Address::from_public_key(provider.public_key()),
            terms,
            STARTED_AT,
        )
        .unwrap();
        SignedPayload::sign(contract, buyer)
    }

    fn termination_of(
        signer: &Keypair,
        contract_id: ContractId,
        by: TerminatedBy,
        requested_at: i64,
    ) -> SignedContractTermination {
        SignedPayload::sign(
            ContractTermination {
                contract_id,
                terminated_by: by,
                requested_at,
            },
            signer,
        )
    }

    // --- content addressing + wire ---------------------------------------

    #[test]
    fn contract_names_itself_and_survives_a_roundtrip() {
        let buyer = Keypair::generate();
        let provider = Keypair::generate();
        let mut metrics = BTreeMap::new();
        metrics.insert("note".to_string(), "prefers mornings".to_string());
        metrics.insert("zeta".to_string(), "last".to_string());
        let mut t = terms(PRICE);
        t.performance_metrics = metrics;

        let contract = ServiceContract::new(
            InquiryId(Hash::of(b"an inquiry")),
            ListingId(Hash::of(b"a listing")),
            Address::from_public_key(buyer.public_key()),
            Address::from_public_key(provider.public_key()),
            t,
            STARTED_AT,
        )
        .unwrap();

        let decoded: ServiceContract =
            from_canonical_bytes(&to_canonical_bytes(contract.clone())).unwrap();
        assert_eq!(decoded, contract);
        // The id is the hash of the content, so a forged id decodes back to the
        // honest one.
        let mut forged = contract.clone();
        forged.contract_id = ContractId(Hash::of(b"not this contract"));
        let decoded: ServiceContract = from_canonical_bytes(&to_canonical_bytes(forged)).unwrap();
        assert_eq!(decoded.contract_id, contract.contract_id);

        // The termination roundtrips too, for both parties.
        for by in [TerminatedBy::Buyer, TerminatedBy::Provider] {
            let term = ContractTermination {
                contract_id: contract.contract_id,
                terminated_by: by,
                requested_at: STARTED_AT + WEEK,
            };
            let cbor: CBOR = term.into();
            assert_eq!(ContractTermination::try_from(cbor).unwrap(), term);
        }
    }

    // --- born from an agreed inquiry -------------------------------------

    #[test]
    fn a_contract_is_born_from_an_agreed_inquiry() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);

        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE));
        let contract_id = signed.payload.contract_id;
        append_service_contract(&mut log, signed, &station.public_key(), &admit_all()).unwrap();

        let records = contract_records(&log, &contract_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        assert_eq!(
            records.buyer(),
            Address::from_public_key(buyer.public_key())
        );
        assert_eq!(
            records.provider(),
            Address::from_public_key(provider.public_key())
        );
        assert_eq!(records.total_periods(), PERIODS);
        assert!(records.terminated.is_none());
    }

    #[test]
    fn only_the_buyer_signs_the_contract() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let impostor = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);

        // The contract names `buyer` but is signed by `impostor`.
        let contract = ServiceContract::new(
            inquiry_id,
            listing.id,
            Address::from_public_key(buyer.public_key()),
            Address::from_public_key(provider.public_key()),
            terms(PRICE),
            STARTED_AT,
        )
        .unwrap();
        let err = append_service_contract(
            &mut log,
            SignedPayload::sign(contract, &impostor),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::SignerNotBuyer { .. })
        ));
    }

    #[test]
    fn a_contract_needs_an_agreed_inquiry() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);

        // Open the inquiry but do not have the provider grant it.
        let opened = opened_of(&buyer, &listing);
        let inquiry_id = opened.payload.inquiry_id;
        append_inquiry_opened(&mut log, opened, &listing, 3.0, true).unwrap();

        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE));
        let err = append_service_contract(&mut log, signed, &station.public_key(), &admit_all())
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::InquiryNotAgreed { .. })
        ));
    }

    #[test]
    fn the_listing_must_be_recurring() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();

        // A one-off (non-recurring) services listing at the same price.
        let one_off = Listing::new(
            Address::from_public_key(provider.public_key()),
            COMMUNITY.into(),
            Surface::Services,
            "education".into(),
            "One-time deep clean".into(),
            "Just the once.".into(),
            Pricing {
                amount_centi: PRICE,
                model: PricingModel::Fixed,
                negotiable: false,
            },
            Availability {
                status: AvailabilityStatus::Available,
                capacity: None,
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
        .unwrap();
        append_listing_created(&mut log, SignedPayload::sign(one_off.clone(), &provider)).unwrap();
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &one_off);

        let signed = contract_of(&buyer, &provider, inquiry_id, &one_off, terms(PRICE));
        let err = append_service_contract(&mut log, signed, &station.public_key(), &admit_all())
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::ListingNotRecurring(_))
        ));
    }

    #[test]
    fn terms_must_match_the_listing_and_agreement() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);

        // A price other than the agreed one is refused.
        let wrong_price = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE + 1));
        let err =
            append_service_contract(&mut log, wrong_price, &station.public_key(), &admit_all())
                .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::TermsMismatch { .. })
        ));

        // So is a cadence other than the listing's.
        let mut wrong_cadence = terms(PRICE);
        wrong_cadence.duration_periods = PERIODS + 1;
        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, wrong_cadence);
        let err = append_service_contract(&mut log, signed, &station.public_key(), &admit_all())
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::TermsMismatch { .. })
        ));
    }

    #[test]
    fn one_inquiry_yields_one_contract() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);

        append_service_contract(
            &mut log,
            contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE)),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();

        // A second contract over the same agreement is refused — even one whose
        // differing metrics give it a different id.
        let mut other = terms(PRICE);
        other
            .performance_metrics
            .insert("note".into(), "second try".into());
        let err = append_service_contract(
            &mut log,
            contract_of(&buyer, &provider, inquiry_id, &listing, other),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::AlreadyContracted { .. })
        ));
    }

    // --- termination + state machine -------------------------------------

    #[test]
    fn either_party_may_terminate_but_no_one_else() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let stranger = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);
        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE));
        let contract_id = signed.payload.contract_id;
        append_service_contract(&mut log, signed, &station.public_key(), &admit_all()).unwrap();

        // A stranger cannot terminate.
        let err = append_contract_termination(
            &mut log,
            termination_of(
                &stranger,
                contract_id,
                TerminatedBy::Buyer,
                STARTED_AT + WEEK,
            ),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::TerminationNotPermitted { .. })
        ));

        // Nor may the buyer claim the provider's role.
        let err = append_contract_termination(
            &mut log,
            termination_of(
                &buyer,
                contract_id,
                TerminatedBy::Provider,
                STARTED_AT + WEEK,
            ),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::TerminationNotPermitted { .. })
        ));

        // The provider terminates as the provider: it lands.
        append_contract_termination(
            &mut log,
            termination_of(
                &provider,
                contract_id,
                TerminatedBy::Provider,
                STARTED_AT + WEEK,
            ),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();

        // A second termination is refused.
        let err = append_contract_termination(
            &mut log,
            termination_of(
                &buyer,
                contract_id,
                TerminatedBy::Buyer,
                STARTED_AT + 2 * WEEK,
            ),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::Contract(ContractError::AlreadyTerminated { .. })
        ));
    }

    #[test]
    fn state_walks_from_active_through_terminating_to_ended() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);
        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE));
        let contract_id = signed.payload.contract_id;
        append_service_contract(&mut log, signed, &station.public_key(), &admit_all()).unwrap();

        let records = contract_records(&log, &contract_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();

        // Active up front: the first period is due at the start.
        assert_eq!(
            records.state(STARTED_AT, 0),
            ContractState::Active {
                next_charge_due: STARTED_AT,
                periods_charged: 0,
                periods_remaining: PERIODS,
            }
        );
        // Two periods in.
        assert_eq!(
            records.state(STARTED_AT + 2 * WEEK, 2),
            ContractState::Active {
                next_charge_due: STARTED_AT + 2 * WEEK,
                periods_charged: 2,
                periods_remaining: PERIODS - 2,
            }
        );
        // Fully charged: completed, regardless of `now`.
        assert_eq!(
            records.state(STARTED_AT + 10 * WEEK, PERIODS),
            ContractState::Ended {
                reason: EndReason::Completed,
                at: STARTED_AT + i64::from(PERIODS) * WEEK,
            }
        );

        // Now terminate after the first week and re-derive.
        append_contract_termination(
            &mut log,
            termination_of(&buyer, contract_id, TerminatedBy::Buyer, STARTED_AT + WEEK),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();
        let records = contract_records(&log, &contract_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        let effective_at = STARTED_AT + WEEK + i64::from(NOTICE_DAYS) * 86_400;

        // Inside the notice window: terminating, still billing.
        assert_eq!(
            records.state(STARTED_AT + WEEK + 100, 1),
            ContractState::Terminating {
                effective_at,
                periods_charged: 1,
            }
        );
        // Past the window, short of the duration: ended early (penalty applies).
        assert_eq!(
            records.state(effective_at, 2),
            ContractState::Ended {
                reason: EndReason::Terminated {
                    by: TerminatedBy::Buyer,
                    early: true,
                },
                at: effective_at,
            }
        );
        assert!(records.is_early_termination());
    }

    #[test]
    fn the_charge_sweep_sees_a_due_period_only_when_it_should() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);
        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE));
        let contract_id = signed.payload.contract_id;
        append_service_contract(&mut log, signed, &station.public_key(), &admit_all()).unwrap();

        let records = contract_records(&log, &contract_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();

        // Period 0 is due at the start; before then, nothing is due.
        assert_eq!(records.next_due_charge(STARTED_AT, 0), Some(0));
        assert_eq!(records.next_due_charge(STARTED_AT - 1, 0), None);
        // Period 1 not due until a week in, even long after period 0 was charged.
        assert_eq!(records.next_due_charge(STARTED_AT + 100, 1), None);
        assert_eq!(records.next_due_charge(STARTED_AT + WEEK, 1), Some(1));
        // Fully charged: nothing more, ever.
        assert_eq!(
            records.next_due_charge(STARTED_AT + 100 * WEEK, PERIODS),
            None
        );

        // With a termination, charges stop past the notice window even if a
        // later period would otherwise be due.
        append_contract_termination(
            &mut log,
            termination_of(&buyer, contract_id, TerminatedBy::Buyer, STARTED_AT),
            &station.public_key(),
            &admit_all(),
        )
        .unwrap();
        let records = contract_records(&log, &contract_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        // Notice is 7 days: the window closes exactly when period 1 falls due, so
        // that period still bills — charges run *through* the window, inclusive of
        // its last moment.
        assert_eq!(records.next_due_charge(STARTED_AT + 100 * WEEK, 1), Some(1));
        // But period 2, a further week past the window, does not.
        assert_eq!(records.next_due_charge(STARTED_AT + 100 * WEEK, 2), None);
    }

    #[test]
    fn replay_ignores_records_a_gossiped_entry_could_carry() {
        let db = open_log_db();
        let mut log = AppendLog::new(&db);
        let provider = Keypair::generate();
        let buyer = Keypair::generate();
        let impostor = Keypair::generate();
        let station = Keypair::generate();
        let listing = publish(&mut log, &provider);
        let inquiry_id = agree_inquiry(&mut log, &buyer, &provider, &station, &listing);

        // A contract signed by an impostor (not the buyer), bypassing the append
        // guard exactly as replication would.
        let contract = ServiceContract::new(
            inquiry_id,
            listing.id,
            Address::from_public_key(impostor.public_key()),
            Address::from_public_key(provider.public_key()),
            terms(PRICE),
            STARTED_AT,
        )
        .unwrap();
        log.append(SignedPayload::sign(contract.clone(), &impostor))
            .unwrap();

        // Its buyer never agreed an inquiry, so replay drops it.
        assert!(contract_records(
            &log,
            &contract.contract_id,
            &station.public_key(),
            &admit_all()
        )
        .unwrap()
        .is_none());

        // A real contract, then a stranger's termination bypassing the guard.
        let signed = contract_of(&buyer, &provider, inquiry_id, &listing, terms(PRICE));
        let contract_id = signed.payload.contract_id;
        append_service_contract(&mut log, signed, &station.public_key(), &admit_all()).unwrap();
        log.append(termination_of(
            &impostor,
            contract_id,
            TerminatedBy::Buyer,
            STARTED_AT + WEEK,
        ))
        .unwrap();

        let records = contract_records(&log, &contract_id, &station.public_key(), &admit_all())
            .unwrap()
            .unwrap();
        assert!(records.terminated.is_none());
    }
}
