//! The debt floor: how far into debt a member may *commit* themselves.
//!
//! Mutual credit means balances go negative by design — but without a bound, a
//! member can settle into arbitrary debt and simply leave, with the loss
//! socialized across everyone holding positive balances (threat model, "no debt
//! bound"; ADR-0018). The floor bounds that exposure at the moment a member
//! *signs* a debit against themselves:
//!
//! - a **sender** commits when they sign a proposal with a positive amount, so
//!   [`Engine::submit_proposal`](crate::engine::Engine::submit_proposal) checks
//!   the floor there;
//! - a **receiver** commits to a negative-amount proposal (a payment request
//!   they would pay) only when they sign the confirmation, so
//!   [`Engine::submit_confirmation`](crate::engine::Engine::submit_confirmation)
//!   checks it there.
//!
//! The projected position counts the settled balance *and* every pending debit
//! the member has already signed but which has not yet settled — otherwise a
//! member could stack proposals inside one settlement window, each individually
//! within the floor, that jointly blow through it. Pending *credits* (money
//! owed to the member) do not count: they can still cancel or be disputed, and
//! headroom must never be borrowed against an unsettled inflow.

use rrn_identity::address::Address;

use crate::state::{LedgerSnapshot, TransactionState};

/// The default debt floor: −20 Commons (−2,000 centicommons).
///
/// Sized to a new member's realistic first weeks of consumption at the design
/// overview's reference prices (a 3-Common consultation, an 8-Common grain
/// purchase, a handful of Tier-1 trades) while keeping the worst-case
/// walk-away loss per member small against a young community's trade volume.
/// Deliberately conservative: raising a floor later is painless, but
/// tightening one strands members already below the new line (ADR-0018). A
/// starter value in the ADR-0009 sense — locked as the protocol default,
/// overridable per station via `[credit] debt_floor_centi`, earmarked for
/// governance tuning later.
pub const DEFAULT_DEBT_FLOOR_CENTI: i64 = -2_000;

/// Tunable credit parameters for the engine's front-door checks.
#[derive(Clone, Copy, Debug)]
pub struct CreditConfig {
    /// The lowest projected balance, in centicommons, a member may sign
    /// themselves down to. Always ≤ 0; see [`DEFAULT_DEBT_FLOOR_CENTI`].
    pub debt_floor_centi: i64,
}

impl Default for CreditConfig {
    fn default() -> Self {
        Self {
            debt_floor_centi: DEFAULT_DEBT_FLOOR_CENTI,
        }
    }
}

/// The total pending debit `party` has already **signed for** but not yet
/// settled as of `now`, in centicommons (≥ 0).
///
/// A transaction counts against its debtor once the debtor's own signature is
/// on it: a positive-amount proposal binds its sender from `Proposed` onward,
/// while a negative-amount proposal binds its receiver only from `Confirmed`
/// onward (the receiver's confirmation is their signature on the debit).
/// `Disputed` still counts — a frozen transaction may yet settle as confirmed.
/// `Settled` amounts are already in the balance and `Cancelled` ones never will
/// be, so neither contributes.
///
/// A still-`Proposed` transaction whose `expires_at` has passed (beyond the
/// engine's clock-skew tolerance) no longer counts: the engine refuses a
/// confirmation past that same boundary, so the debit can never land, and
/// holding its headroom forever would let a counterparty who simply ignores a
/// proposal permanently shrink the sender's credit.
pub fn committed_debits_centi(snapshot: &LedgerSnapshot, party: &Address, now: i64) -> i64 {
    let mut total: i64 = 0;
    for (_, state) in snapshot.iter() {
        let (proposal, receiver_committed) = match state {
            TransactionState::Proposed { proposal } => {
                let expiry_cutoff = proposal
                    .payload
                    .expires_at
                    .saturating_add(crate::engine::CLOCK_SKEW_TOLERANCE_SECS);
                if now > expiry_cutoff {
                    // Expired unconfirmed: the engine will never accept its
                    // confirmation, so it can no longer bind its sender.
                    continue;
                }
                (proposal, false)
            }
            TransactionState::Confirmed { proposal, .. }
            | TransactionState::Disputed { proposal, .. } => (proposal, true),
            TransactionState::Settled { .. } | TransactionState::Cancelled { .. } => continue,
        };
        let p = &proposal.payload;
        let debit = if p.amount_centi > 0 && p.sender == *party {
            p.amount_centi
        } else if p.amount_centi < 0 && receiver_committed && p.receiver == *party {
            p.amount_centi.saturating_abs()
        } else {
            0
        };
        total = total.saturating_add(debit);
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::log::AppendLog;
    use rrn_storage::{db::Database, migrations};

    use crate::transaction::{
        SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
    };

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    #[test]
    fn pending_debits_follow_the_debtors_signature() {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        let mut log = AppendLog::new(&db);

        // Alice proposes to pay Bob 300: binds Alice immediately.
        let pay = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 100, 100_000);
        log.append(SignedProposal::sign(pay, &alice)).unwrap();

        // Alice requests 200 from Bob (negative amount): does not bind Bob until
        // he confirms.
        let request =
            TransactionProposal::new(addr(&alice), addr(&bob), -200, None, 1, 100, 100_000);
        let request_id = request.id;
        log.append(SignedProposal::sign(request, &alice)).unwrap();

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert_eq!(committed_debits_centi(&snapshot, &addr(&alice), 150), 300);
        assert_eq!(committed_debits_centi(&snapshot, &addr(&bob), 150), 0);

        // Bob confirms the request: now the 200 binds him.
        let c = TransactionConfirmation {
            proposal_id: request_id,
            confirmer: addr(&bob),
            confirmed_at: 200,
        };
        AppendLog::new(&db)
            .append(SignedConfirmation::sign(c, &bob))
            .unwrap();
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert_eq!(committed_debits_centi(&snapshot, &addr(&bob), 250), 200);
        assert_eq!(committed_debits_centi(&snapshot, &addr(&alice), 250), 300);
    }

    #[test]
    fn an_expired_unconfirmed_proposal_stops_counting() {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        let mut log = AppendLog::new(&db);

        // Alice proposes 300 to Bob, valid from t=100 to t=1_000.
        let pay = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 100, 1_000);
        log.append(SignedProposal::sign(pay, &alice)).unwrap();
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();

        // Within the window (and its skew tolerance) the 300 binds Alice; once
        // the proposal can no longer be confirmed, the headroom is released.
        let skew = crate::engine::CLOCK_SKEW_TOLERANCE_SECS;
        assert_eq!(committed_debits_centi(&snapshot, &addr(&alice), 500), 300);
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 1_000 + skew),
            300
        );
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 1_001 + skew),
            0
        );
    }
}
