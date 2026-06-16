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

use std::collections::BTreeSet;

use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::transaction::TransactionId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// The balance of `who`, in centicommons, derived from settlement records in the
/// log. Positive = net credit; negative = net debt.
pub fn balance_of(db: &Database, who: &Address) -> rrn_storage::Result<i64> {
    let log = AppendLog::new(db);
    let mut applied: BTreeSet<TransactionId> = BTreeSet::new();
    let mut total: i64 = 0;

    for entry in log.iter_from(1) {
        let entry = entry?;
        let Ok(rec) = from_canonical_bytes::<SettlementRecord>(&entry.payload.bytes) else {
            continue; // not a settlement record
        };
        // Each transaction settles once; ignore redundant records for it.
        if !applied.insert(rec.proposal_id) {
            continue;
        }
        if &rec.sender == who {
            total = total.saturating_sub(rec.amount_centi);
        }
        if &rec.receiver == who {
            total = total.saturating_add(rec.amount_centi);
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
            .append(SignedPayload::sign(rec, station))
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
                .append(SignedPayload::sign(rec, &station))
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
}
