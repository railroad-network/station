//! The member-relative transaction view the mobile wallet renders (T1.3.4).
//!
//! The log is append-only *events*; [`LedgerSnapshot`] already correlates them
//! into one [`TransactionState`] per transaction (proposed → confirmed →
//! settled / cancelled). This module is the last mapping step: it turns each
//! state into a [`TransactionRow`] expressed from **one member's** vantage
//! point — direction and signed amount relative to them, the counterparty
//! address, and the lifecycle fields the UI needs — and drops transactions the
//! member is not party to. Doing the correlation here, once, keeps the phone a
//! renderer rather than a second implementation of the ledger's lifecycle.

use std::collections::BTreeMap;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::PublicKey;
use rrn_identity::address::Address;
use rrn_ledger::settlement::SettlementConfig;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_ledger::transaction::ListingRef;
use rrn_marketplace::lifecycle::listing_records;
use rrn_marketplace::listing::ListingId;
use rrn_storage::log::AppendLog;

use crate::core::hex;
use crate::rpc::TransactionRow;

/// The member's transactions, most recent first, capped at `limit` if given.
///
/// `log`/`station` are used only to resolve the title of any marketplace payment
/// (T1.7.6 Stage B), so history reads as what it bought. The lookup is memoised
/// by [`ListingId`] and, when a limit is given, runs only on the rows kept — a
/// member with many marketplace payments pays per-listing once, not per-row.
pub fn member_transactions(
    snapshot: &LedgerSnapshot,
    member: &Address,
    limit: Option<u64>,
    log: &AppendLog,
    station: &PublicKey,
    settlement: &SettlementConfig,
) -> Vec<TransactionRow> {
    let mut rows: Vec<TransactionRow> = snapshot
        .iter()
        .filter_map(|(_, state)| row_for(state, member))
        .collect();
    // Newest first; ties broken by id so the order is stable (the mobile groups
    // History by day and relies on a deterministic order).
    rows.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then_with(|| a.id.cmp(&b.id)));
    if let Some(limit) = limit {
        rows.truncate(limit as usize);
    }
    let mut titles: BTreeMap<String, Option<String>> = BTreeMap::new();
    for row in &mut rows {
        if let Some(listing_hex) = &row.listing_id {
            row.listing_title = titles
                .entry(listing_hex.clone())
                .or_insert_with(|| listing_title(log, station, listing_hex))
                .clone();
        }
        // Once confirmed, the settlement window is `confirmed_at` + the tier's
        // window; the phone counts down to this instant. Derived here, not stored,
        // exactly like the tier and the window itself (ADR-0011).
        if let Some(confirmed_at) = row.confirmed_at {
            row.settle_by = Some(confirmed_at + settlement.window_for(row.oracle_tier) as i64);
        }
    }
    rows
}

/// The title of the listing named by `listing_hex`, read from the marketplace
/// log, or `None` if this station has never seen it created. A closed or
/// sold-out listing still has a title — `current()` is the provider's own view,
/// independent of how the listing ended.
pub(crate) fn listing_title(
    log: &AppendLog,
    station: &PublicKey,
    listing_hex: &str,
) -> Option<String> {
    let bytes: [u8; 32] = crate::core::unhex(listing_hex)?.try_into().ok()?;
    let listing_id = ListingId(Hash::from_bytes(bytes));
    listing_records(log, &listing_id, station)
        .ok()?
        .current()
        .map(|listing| listing.title)
}

/// Maps one correlated state to a row for `member`, or `None` if the member is
/// not a party to it (or it is the never-constructed dispute stub). Shared with
/// [`crate::events`], which builds the same member-relative row for a push event.
pub(crate) fn row_for(state: &TransactionState, member: &Address) -> Option<TransactionRow> {
    let proposal = match state {
        TransactionState::Proposed { proposal }
        | TransactionState::Confirmed { proposal, .. }
        | TransactionState::Settled { proposal, .. }
        | TransactionState::Cancelled { proposal, .. } => &proposal.payload,
        TransactionState::DisputedStub => return None,
    };

    // Direction, counterparty, and the sign of the amount are all relative to
    // the member. A positive proposal amount is the sender paying the receiver.
    let (direction, counterparty, amount_centi) = if *member == proposal.receiver {
        ("in", proposal.sender, proposal.amount_centi)
    } else if *member == proposal.sender {
        ("out", proposal.receiver, -proposal.amount_centi)
    } else {
        return None;
    };

    let (state_str, confirmed_at, settled_at) = match state {
        TransactionState::Proposed { .. } => ("pending", None, None),
        TransactionState::Confirmed { confirmation, .. } => {
            ("confirmed", Some(confirmation.payload.confirmed_at), None)
        }
        TransactionState::Settled {
            confirmation,
            settled_at,
            ..
        } => (
            "settled",
            Some(confirmation.payload.confirmed_at),
            Some(*settled_at),
        ),
        TransactionState::Cancelled { .. } => ("cancelled", None, None),
        TransactionState::DisputedStub => unreachable!("filtered above"),
    };

    Some(TransactionRow {
        id: hex(&proposal.id.to_bytes()),
        counterparty_address: counterparty.to_string(),
        direction: direction.to_string(),
        amount_centi,
        memo: proposal.memo.clone(),
        // The listing this paid for; the title is filled in by the caller, which
        // has the log to resolve it (a push event leaves it `None` and the phone
        // falls back to the memo).
        listing_id: proposal.listing_id.map(|ListingRef(b)| hex(&b)),
        listing_title: None,
        state: state_str.to_string(),
        oracle_tier: proposal.effective_tier(),
        timestamp: proposal.proposed_at,
        // Only a still-open proposal has a meaningful expiry.
        expires_at: matches!(state, TransactionState::Proposed { .. })
            .then_some(proposal.expires_at),
        confirmed_at,
        // Filled by `member_transactions`, which has the settlement config; a push
        // event (events.rs) leaves it `None` and the phone's refetch supplies it.
        settle_by: None,
        settled_at,
        nonce: proposal.nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_ledger::transaction::{SignedProposal, TransactionProposal};

    /// A `Proposed` state for a proposal from `sender` to `receiver`.
    fn proposed(sender: &Keypair, receiver: &Address, amount: i64) -> TransactionState {
        let proposal = TransactionProposal::new(
            Address::from_public_key(sender.public_key()),
            *receiver,
            amount,
            Some("lunch".into()),
            1,
            1_000,
            1_000 + 86_400,
        );
        TransactionState::Proposed {
            proposal: SignedProposal::sign(proposal, sender),
        }
    }

    #[test]
    fn a_row_is_out_and_negative_for_the_sender() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let receiver_addr = Address::from_public_key(receiver.public_key());
        let sender_addr = Address::from_public_key(sender.public_key());

        let state = proposed(&sender, &receiver_addr, 300);
        let row = row_for(&state, &sender_addr).expect("sender is a party");
        assert_eq!(row.direction, "out");
        assert_eq!(row.amount_centi, -300);
        assert_eq!(row.counterparty_address, receiver_addr.to_string());
        assert_eq!(row.state, "pending");
        assert_eq!(row.expires_at, Some(1_000 + 86_400));
    }

    #[test]
    fn the_same_transaction_is_in_and_positive_for_the_receiver() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let receiver_addr = Address::from_public_key(receiver.public_key());

        let state = proposed(&sender, &receiver_addr, 300);
        let row = row_for(&state, &receiver_addr).expect("receiver is a party");
        assert_eq!(row.direction, "in");
        assert_eq!(row.amount_centi, 300);
        assert_eq!(
            row.counterparty_address,
            Address::from_public_key(sender.public_key()).to_string()
        );
    }

    #[test]
    fn a_stranger_gets_no_row() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let stranger = Address::from_public_key(Keypair::generate().public_key());
        let state = proposed(
            &sender,
            &Address::from_public_key(receiver.public_key()),
            300,
        );
        assert!(row_for(&state, &stranger).is_none());
    }

    #[test]
    fn a_linked_proposal_carries_its_listing_id_but_leaves_the_title_for_later() {
        use rrn_ledger::transaction::ListingRef;
        let sender = Keypair::generate();
        let sender_addr = Address::from_public_key(sender.public_key());
        let receiver = Address::from_public_key(Keypair::generate().public_key());
        let proposal = TransactionProposal::new(sender_addr, receiver, 500, None, 1, 1_000, 87_400)
            .with_listing(ListingRef([9u8; 32]));
        let state = TransactionState::Proposed {
            proposal: SignedProposal::sign(proposal, &sender),
        };
        let row = row_for(&state, &sender_addr).unwrap();
        assert_eq!(row.listing_id, Some("09".repeat(32)));
        // The title is resolved by `member_transactions`, which has the log — not
        // by `row_for`, which does not.
        assert_eq!(row.listing_title, None);
    }

    #[test]
    fn an_unknown_listing_resolves_to_no_title() {
        let db = rrn_storage::db::Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        let log = AppendLog::new(&db);
        let station_pk = Keypair::generate().public_key();
        assert_eq!(listing_title(&log, &station_pk, &"aa".repeat(32)), None);
    }

    #[test]
    fn a_confirmed_row_carries_its_tier_window_as_settle_by() {
        use rrn_ledger::settlement::{
            SettlementConfig, DEFAULT_TIER1_WINDOW_SECONDS, DEFAULT_TIER2_WINDOW_SECONDS,
        };
        use rrn_ledger::transaction::{SignedConfirmation, TransactionConfirmation};

        let db = rrn_storage::db::Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        let station_pk = Keypair::generate().public_key();
        let config = SettlementConfig::default();

        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let sender_addr = Address::from_public_key(sender.public_key());
        let receiver_addr = Address::from_public_key(receiver.public_key());

        // A sub-5-Common payment is Tier 1 (24h window); a 5.00-Common payment is
        // Tier 2 (48h). Confirm each so it has a settlement window to derive.
        let confirmed_at = 1_100;
        for (nonce, amount) in [300i64, 500].into_iter().enumerate() {
            let proposal = TransactionProposal::new(
                sender_addr,
                receiver_addr,
                amount,
                None,
                nonce as u64,
                1_000,
                1_000 + 86_400,
            );
            let id = proposal.id;
            AppendLog::new(&db)
                .append(SignedProposal::sign(proposal, &sender))
                .unwrap();
            let confirmation = TransactionConfirmation {
                proposal_id: id,
                confirmer: receiver_addr,
                confirmed_at,
            };
            AppendLog::new(&db)
                .append(SignedConfirmation::sign(confirmation, &receiver))
                .unwrap();
        }

        let log = AppendLog::new(&db);
        let snapshot = LedgerSnapshot::derive(&log).unwrap();
        let rows = member_transactions(&snapshot, &receiver_addr, None, &log, &station_pk, &config);

        let tier1 = rows
            .iter()
            .find(|r| r.oracle_tier == 1)
            .expect("a tier-1 row");
        let tier2 = rows
            .iter()
            .find(|r| r.oracle_tier == 2)
            .expect("a tier-2 row");
        assert_eq!(
            tier1.settle_by,
            Some(confirmed_at + DEFAULT_TIER1_WINDOW_SECONDS as i64)
        );
        assert_eq!(
            tier2.settle_by,
            Some(confirmed_at + DEFAULT_TIER2_WINDOW_SECONDS as i64)
        );
    }
}
