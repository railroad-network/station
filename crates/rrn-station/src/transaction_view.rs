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

use rrn_identity::address::Address;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};

use crate::core::hex;
use crate::rpc::TransactionRow;

/// The member's transactions, most recent first, capped at `limit` if given.
pub fn member_transactions(
    snapshot: &LedgerSnapshot,
    member: &Address,
    limit: Option<u64>,
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
    rows
}

/// Maps one correlated state to a row for `member`, or `None` if the member is
/// not a party to it (or it is the never-constructed dispute stub).
fn row_for(state: &TransactionState, member: &Address) -> Option<TransactionRow> {
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
        state: state_str.to_string(),
        timestamp: proposal.proposed_at,
        // Only a still-open proposal has a meaningful expiry.
        expires_at: matches!(state, TransactionState::Proposed { .. })
            .then_some(proposal.expires_at),
        confirmed_at,
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
}
