//! Deriving balances from the log, the way two replicas can agree on.
//!
//! A balance is never stored: it is a fold over the log's station-signed balance
//! records, computed by [`LedgerSnapshot`] on replay — the same fold the debt
//! floor reads (ADR-0018), so a member is never shown one number and judged
//! against another. In the two-station demo a settlement record can arrive over
//! gossip from the *other* station, and with independent wall clocks both
//! stations may each author a settlement record for the same transaction
//! (different `settled_at` ⇒ different bytes ⇒ both survive dedup-by-content).
//! So the fold is keyed on `proposal_id`, applying each settled transaction's
//! amount exactly once no matter how many settlement records reference it.
//!
//! A recurring service contract charges through a second station-signed balance
//! record, [`ContractCharge`](rrn_ledger::contract::ContractCharge): a direct
//! debit with no settlement window. It is folded alongside settlements, keyed on
//! `(contract_ref, period_index)` so each period counts once — the same
//! once-only discipline the settlement fold applies per `proposal_id`, and the
//! backstop that lets the station's charge sweep re-run safely.

use rrn_crypto::keypair::PublicKey;
use rrn_identity::address::Address;
use rrn_ledger::state::LedgerSnapshot;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

/// The balance of `who`, in centicommons, derived from the log's balance records
/// — settlements and contract charges. Positive = net credit; negative = net debt.
///
/// Both balance records are station-signed (ADR-0005). Only a record whose
/// envelope signer is the community `station` moves a balance: a forged
/// settlement or contract charge injected via gossip `append_raw` is skipped, so it
/// can never debit or credit an account here. This is the highest-value pin — this
/// function is what a wallet balance is read from.
pub fn balance_of(db: &Database, who: &Address, station: &PublicKey) -> rrn_storage::Result<i64> {
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(db), station).map_err(|e| match e {
        rrn_ledger::Error::Storage(e) => e,
        other => rrn_storage::Error::Corrupt(other.to_string()),
    })?;
    Ok(snapshot.balance_of(who))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_ledger::contract::{ContractCharge, ContractRef};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::TransactionId;
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
        assert_eq!(balance_of(&db, &a, &station.public_key()).unwrap(), -300);
        assert_eq!(balance_of(&db, &b, &station.public_key()).unwrap(), 300);
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
        assert_eq!(balance_of(&db, &b, &station.public_key()).unwrap(), 300); // not 600
    }

    #[test]
    fn unsettled_log_has_zero_balance() {
        let db = fresh_db();
        let alice = Keypair::generate();
        let station = Keypair::generate();
        assert_eq!(
            balance_of(&db, &addr(&alice), &station.public_key()).unwrap(),
            0
        );
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
        assert_eq!(balance_of(&db, &b, &station.public_key()).unwrap(), -1_500);
        assert_eq!(balance_of(&db, &p, &station.public_key()).unwrap(), 1_500);
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
        assert_eq!(balance_of(&db, &p, &station.public_key()).unwrap(), 500); // not 1000
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

        assert_eq!(
            balance_of(&db, &a, &station.public_key()).unwrap(),
            300 - 400
        );
        assert_eq!(
            balance_of(&db, &b, &station.public_key()).unwrap(),
            -300 + 400
        );
    }

    #[test]
    fn a_forged_settlement_or_contract_charge_moves_no_balance() {
        // Both balance records are pinned to the community station key. A
        // settlement or contract charge signed by any other key (a gossip forgery)
        // is skipped, so it can neither debit nor credit an account.
        let db = fresh_db();
        let (alice, bob, station, mallory) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (a, b) = (addr(&alice), addr(&bob));

        // A forged settlement (mallory-signed) crediting bob 300.
        let forged = SettlementRecord {
            proposal_id: TransactionProposal::new(a, b, 300, None, 0, 0, 1).id,
            sender: a,
            receiver: b,
            amount_centi: 300,
            settled_at: 100,
        };
        AppendLog::new(&db)
            .append(SignedPayload::sign(forged, &mallory), 0)
            .unwrap();
        // A forged contract charge (mallory-signed) debiting alice 500.
        let forged_charge = ContractCharge {
            contract_ref: ContractRef([9u8; 32]),
            buyer: a,
            provider: b,
            amount_centi: 500,
            period_index: 0,
            charged_at: 200,
        };
        AppendLog::new(&db)
            .append(SignedPayload::sign(forged_charge, &mallory), 0)
            .unwrap();

        // Under the station key, both forgeries are invisible: everyone is at zero.
        assert_eq!(balance_of(&db, &a, &station.public_key()).unwrap(), 0);
        assert_eq!(balance_of(&db, &b, &station.public_key()).unwrap(), 0);

        // The genuine station-signed settlement then moves the balance.
        settle(&db, &station, &a, &b, 300, 300);
        assert_eq!(balance_of(&db, &a, &station.public_key()).unwrap(), -300);
        assert_eq!(balance_of(&db, &b, &station.public_key()).unwrap(), 300);
    }

    #[test]
    fn a_forged_charge_does_not_dedup_out_the_genuine_one_for_the_same_period() {
        // The signer pin is checked *before* the once-only `(contract, period)`
        // dedup, so a forged charge for a period cannot burn that period's slot and
        // suppress the genuine charge the station later signs for it.
        let db = fresh_db();
        let (alice, bob, station, mallory) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let (a, b) = (addr(&alice), addr(&bob));
        let contract = ContractRef([7u8; 32]);

        // A forged charge for (contract, period 0) debiting alice 500 lands first.
        let forged = ContractCharge {
            contract_ref: contract,
            buyer: a,
            provider: b,
            amount_centi: 500,
            period_index: 0,
            charged_at: 100,
        };
        AppendLog::new(&db)
            .append(SignedPayload::sign(forged, &mallory), 0)
            .unwrap();
        // The genuine station charge for the same period debits alice 200.
        charge(&db, &station, &a, &b, 200, contract, 0);

        // Only the genuine 200 counts — the forged 500 neither applied nor
        // consumed the period's slot.
        assert_eq!(balance_of(&db, &a, &station.public_key()).unwrap(), -200);
        assert_eq!(balance_of(&db, &b, &station.public_key()).unwrap(), 200);
    }
}
