//! Deriving balances from the log, the way two replicas can agree on.
//!
//! `rrn-ledger`'s [`Settler`](rrn_ledger::settlement::Settler) maintains a
//! materialized PN-Counter as a side effect of the station that *performs* a
//! settlement. That is fine for a lone station, but in the two-station demo a
//! settlement record can arrive over gossip from the *other* station — and a
//! replicated record never runs through the local settler's balance write, so
//! the materialized counter would miss it. Worse, with independent wall clocks
//! both stations may each author a settlement record for the same transaction
//! (different `settled_at` ⇒ different bytes ⇒ both survive dedup-by-content).
//!
//! So for queries we do the robust thing the design docs call for — *derive
//! balances from the log* — and we key the derivation on `proposal_id`, applying
//! each settled transaction's amount exactly once no matter how many settlement
//! records reference it. The log is the source of truth; this is just a fold over
//! it. Phase 0 logs are small, so a full scan per query is fine.
//!
//! A recurring service contract charges through a second station-signed balance
//! record, [`ContractCharge`] (T1.7.7): a direct debit with no settlement window.
//! It is folded here alongside settlements, keyed on `(contract_ref,
//! period_index)` so each period counts once — the same once-only discipline the
//! settlement fold applies per `proposal_id`, and the backstop that lets the
//! station's charge sweep re-run safely.

use std::collections::BTreeSet;

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_ledger::contract::{ContractCharge, ContractRef};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::transaction::TransactionId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// The balance of `who`, in centicommons, derived from the log's balance records
/// — settlements and contract charges. Positive = net credit; negative = net debt.
pub fn balance_of(db: &Database, who: &Address) -> rrn_storage::Result<i64> {
    let log = AppendLog::new(db);
    let mut settled: BTreeSet<TransactionId> = BTreeSet::new();
    let mut charged: BTreeSet<(ContractRef, u32)> = BTreeSet::new();
    let mut total: i64 = 0;

    for entry in log.iter_from(1) {
        let bytes = &entry?.payload.bytes;

        if let Ok(rec) = from_canonical_bytes::<SettlementRecord>(bytes) {
            // Each transaction settles once; ignore redundant records for it.
            if !settled.insert(rec.proposal_id) {
                continue;
            }
            if &rec.sender == who {
                total = total.saturating_sub(rec.amount_centi);
            }
            if &rec.receiver == who {
                total = total.saturating_add(rec.amount_centi);
            }
            continue;
        }

        if let Ok(charge) = from_canonical_bytes::<ContractCharge>(bytes) {
            // Each contract period charges once; a re-swept, replayed, or gossiped
            // duplicate for the same `(contract, period)` is ignored. The buyer is
            // debited and the provider credited (a contract only ever charges in
            // that direction).
            if !charged.insert((charge.contract_ref, charge.period_index)) {
                continue;
            }
            if &charge.buyer == who {
                total = total.saturating_sub(charge.amount_centi);
            }
            if &charge.provider == who {
                total = total.saturating_add(charge.amount_centi);
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_ledger::transaction::TransactionProposal;
    use rrn_storage::migrations;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// Appends a settlement record (signed by `station`) for a fresh proposal id.
    fn settle(
        db: &Database,
        station: &Keypair,
        sender: &Address,
        receiver: &Address,
        amount: i64,
        settled_at: i64,
    ) -> TransactionId {
        let proposal = TransactionProposal::new(*sender, *receiver, amount, None, 0, 0, 1);
        let rec = SettlementRecord {
            proposal_id: proposal.id,
            sender: *sender,
            receiver: *receiver,
            amount_centi: amount,
            settled_at,
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(rec, station), 0)
            .unwrap();
        proposal.id
    }

    #[test]
    fn balance_nets_credit_and_debt() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (a, b) = (addr(&alice), addr(&bob));
        settle(&db, &station, &a, &b, 300, 100);
        assert_eq!(balance_of(&db, &a).unwrap(), -300);
        assert_eq!(balance_of(&db, &b).unwrap(), 300);
    }

    #[test]
    fn duplicate_settlement_records_apply_once() {
        // Same proposal id settled twice (two records, e.g. one per station with
        // different settled_at) must not double-count.
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (a, b) = (addr(&alice), addr(&bob));

        let proposal = TransactionProposal::new(a, b, 300, None, 0, 0, 1);
        for settled_at in [100, 101] {
            let rec = SettlementRecord {
                proposal_id: proposal.id,
                sender: a,
                receiver: b,
                amount_centi: 300,
                settled_at,
            };
            AppendLog::new(&db)
                .append(SignedPayload::sign(rec, &station), 0)
                .unwrap();
        }
        assert_eq!(balance_of(&db, &b).unwrap(), 300); // not 600
    }

    #[test]
    fn unsettled_log_has_zero_balance() {
        let db = fresh_db();
        let alice = Keypair::generate();
        assert_eq!(balance_of(&db, &addr(&alice)).unwrap(), 0);
    }

    /// Appends a station-signed contract charge to the log.
    fn charge(
        db: &Database,
        station: &Keypair,
        buyer: &Address,
        provider: &Address,
        amount: i64,
        contract_ref: ContractRef,
        period_index: u32,
    ) {
        let rec = ContractCharge {
            contract_ref,
            buyer: *buyer,
            provider: *provider,
            amount_centi: amount,
            period_index,
            charged_at: 1_000 + i64::from(period_index),
        };
        AppendLog::new(db)
            .append(SignedPayload::sign(rec, station), 0)
            .unwrap();
    }

    #[test]
    fn contract_charges_move_the_balance_per_period() {
        let db = fresh_db();
        let (buyer, provider, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (b, p) = (addr(&buyer), addr(&provider));
        let contract = ContractRef([3u8; 32]);

        // Three periods charged at 500 each: buyer -1500, provider +1500.
        for period in 0..3 {
            charge(&db, &station, &b, &p, 500, contract, period);
        }
        assert_eq!(balance_of(&db, &b).unwrap(), -1_500);
        assert_eq!(balance_of(&db, &p).unwrap(), 1_500);
    }

    #[test]
    fn a_duplicate_period_charge_applies_once() {
        // A re-run sweep (or gossip) can append a second charge for the same
        // period with a different `charged_at`; it must not double-charge.
        let db = fresh_db();
        let (buyer, provider, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (b, p) = (addr(&buyer), addr(&provider));
        let contract = ContractRef([4u8; 32]);

        let rec = ContractCharge {
            contract_ref: contract,
            buyer: b,
            provider: p,
            amount_centi: 500,
            period_index: 0,
            charged_at: 1_000,
        };
        for charged_at in [1_000, 1_005] {
            let mut r = rec;
            r.charged_at = charged_at;
            AppendLog::new(&db)
                .append(SignedPayload::sign(r, &station), 0)
                .unwrap();
        }
        assert_eq!(balance_of(&db, &p).unwrap(), 500); // not 1000
    }

    #[test]
    fn settlements_and_contract_charges_both_count() {
        // The same identity can be paid by a one-off settlement and debited by a
        // subscription; the two folds net together.
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (a, b) = (addr(&alice), addr(&bob));

        // Bob pays Alice 300 via settlement (alice +300), then Alice subscribes to
        // Bob at 200/period for 2 periods (alice -400).
        settle(&db, &station, &b, &a, 300, 100);
        charge(&db, &station, &a, &b, 200, ContractRef([5u8; 32]), 0);
        charge(&db, &station, &a, &b, 200, ContractRef([5u8; 32]), 1);

        assert_eq!(balance_of(&db, &a).unwrap(), 300 - 400);
        assert_eq!(balance_of(&db, &b).unwrap(), -300 + 400);
    }
}
