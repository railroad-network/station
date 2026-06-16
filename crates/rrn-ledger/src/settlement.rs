//! The settlement window, and the balance changes that close it.
//!
//! After a transaction is confirmed it sits in the **settlement window** (48h by
//! default; shorter for demos/tests). While it waits, *no balances change* —
//! that delay is the whole point: it is also the dispute window for the Phase 1
//! oracle. When the window elapses the [`Settler`] moves the transaction to
//! [`Settled`](crate::state::TransactionState::Settled) and applies the balance
//! change, exactly once.
//!
//! # Settlement appends a station-signed record
//!
//! Settlement is automatic, so neither the sender nor the receiver is present to
//! sign it. The local station signs a [`SettlementRecord`] with its own key and
//! appends it to the log; that record is the source of truth, and replaying it
//! is what turns the transaction's derived state to `Settled`. The same station
//! key identifies this replica for the per-replica PN-Counter. See ADR-0005 and
//! the crate-level docs.
//!
//! # Idempotence
//!
//! [`Settler::settle`] derives the transaction's current state from the log
//! first. An already-`Settled` transaction is a no-op (returns `Ok` without
//! touching balances); a non-existent one is an error. Because the
//! already-settled check happens *before* any balance write, settling twice can
//! never double-apply a balance change.

use dcbor::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::crdt::pn_counter::PnCounter;
use rrn_storage::crdt::ReplicaId;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::state::{LedgerSnapshot, TransactionState};
use crate::transaction::TransactionId;
use crate::{Error, Result};

/// Discriminant string for a settlement record's canonical CBOR.
pub(crate) const SETTLEMENT_KIND: &str = "rrn.tx.settlement";

/// The default Phase 0 settlement window: 48 hours.
pub const DEFAULT_WINDOW_SECONDS: u64 = 48 * 3600;

/// Tunable settlement parameters.
#[derive(Clone, Copy, Debug)]
pub struct SettlementConfig {
    /// How long after confirmation a transaction must wait before settling.
    /// Defaults to [`DEFAULT_WINDOW_SECONDS`]; demos/tests shorten it.
    pub window_seconds: u64,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self {
            window_seconds: DEFAULT_WINDOW_SECONDS,
        }
    }
}

/// The log record that marks a transaction settled. Signed by the station.
///
/// It restates the parties and amount so that balances are fully re-derivable
/// from the log alone (the materialized `balances` table is just a cache).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementRecord {
    /// The transaction being settled.
    pub proposal_id: TransactionId,
    /// The proposal's sender (debited when `amount_centi` is positive).
    pub sender: Address,
    /// The proposal's receiver (credited when `amount_centi` is positive).
    pub receiver: Address,
    /// Signed integer centicommons; positive = sender pays receiver.
    pub amount_centi: i64,
    /// Unix seconds when settlement occurred.
    pub settled_at: i64,
}

impl From<SettlementRecord> for CBOR {
    fn from(s: SettlementRecord) -> Self {
        let mut m = Map::new();
        m.insert("kind", SETTLEMENT_KIND);
        m.insert("proposal_id", s.proposal_id);
        m.insert("sender", s.sender);
        m.insert("receiver", s.receiver);
        m.insert("amount_centi", s.amount_centi);
        m.insert("settled_at", s.settled_at);
        m.into()
    }
}

impl TryFrom<CBOR> for SettlementRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != SETTLEMENT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(SettlementRecord {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            sender: map.extract::<&str, Address>("sender")?,
            receiver: map.extract::<&str, Address>("receiver")?,
            amount_centi: map.extract::<&str, i64>("amount_centi")?,
            settled_at: map.extract::<&str, i64>("settled_at")?,
        })
    }
}

/// Settles confirmed transactions whose window has elapsed.
///
/// Holds the station keypair (to sign settlement records) and a borrowed
/// [`Database`]. Settlement is invoked explicitly with a `now` argument — there
/// is no timer here; the daemon (M0.6) calls [`Settler::sweep`] periodically.
pub struct Settler<'db> {
    config: SettlementConfig,
    station: Keypair,
    replica: ReplicaId,
    db: &'db Database,
}

impl<'db> Settler<'db> {
    /// Creates a settler over `db`, signing settlement records with `station`.
    ///
    /// The station's public key also identifies this replica in the per-replica
    /// PN-Counter. (The task spec's `new(db, config)` predated the requirement
    /// that settlement append a *signed* log entry — see the module docs.)
    pub fn new(db: &'db Database, station: Keypair, config: SettlementConfig) -> Self {
        let replica = ReplicaId(station.public_key());
        Self {
            config,
            station,
            replica,
            db,
        }
    }

    /// Transaction ids that are confirmed and whose settlement window has now
    /// elapsed (`confirmed_at + window_seconds <= now`).
    pub fn find_eligible(&self, now: i64) -> Result<Vec<TransactionId>> {
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        let window = self.config.window_seconds as i64;
        let mut eligible = Vec::new();
        for (id, state) in snapshot.iter() {
            if let TransactionState::Confirmed { confirmation, .. } = state {
                if confirmation.payload.confirmed_at.saturating_add(window) <= now {
                    eligible.push(*id);
                }
            }
        }
        Ok(eligible)
    }

    /// Settles a single transaction. Idempotent: an already-settled transaction
    /// is a no-op; a non-existent one is an error.
    pub fn settle(&mut self, tx_id: &TransactionId, now: i64) -> Result<()> {
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(self.db))?;
        let state = snapshot.get(tx_id).ok_or(Error::UnknownTransaction)?;

        // The derived state already passed log-time signature verification, but
        // re-check here so settlement never acts on a malformed state.
        state.verify()?;
        let proposal = match state {
            // Already settled — do nothing, do not double-apply balances.
            TransactionState::Settled { .. } => {
                tracing::debug!(tx = ?tx_id, "settle: already settled, no-op");
                return Ok(());
            }
            TransactionState::Confirmed { proposal, .. } => proposal.clone(),
            _ => return Err(Error::NotConfirmed),
        };

        let p = &proposal.payload;
        // 1. Append the settlement record (the source of truth) signed by the
        //    station. 2. Update the materialized balances. The two are not in a
        //    single SQL transaction (the log's append commits its own), but the
        //    log entry is authoritative and balances are re-derivable from it,
        //    so a crash between the two is recoverable by replay.
        let record = SettlementRecord {
            proposal_id: *tx_id,
            sender: p.sender,
            receiver: p.receiver,
            amount_centi: p.amount_centi,
            settled_at: now,
        };
        AppendLog::new(self.db).append(SignedPayload::sign(record, &self.station))?;

        self.apply_balance(&p.sender, &p.receiver, p.amount_centi)?;
        tracing::info!(tx = ?tx_id, amount_centi = p.amount_centi, "settled");
        Ok(())
    }

    /// Settles every eligible transaction. Returns the number settled.
    pub fn sweep(&mut self, now: i64) -> Result<usize> {
        let eligible = self.find_eligible(now)?;
        let count = eligible.len();
        for id in eligible {
            self.settle(&id, now)?;
        }
        Ok(count)
    }

    /// Moves `amount_centi` from sender to receiver in the PN-Counter, applying
    /// the sign convention (positive = sender → receiver).
    fn apply_balance(&self, sender: &Address, receiver: &Address, amount_centi: i64) -> Result<()> {
        let sender_pk = *sender.public_key();
        let receiver_pk = *receiver.public_key();

        // A self-payment nets to zero; applying it via two separate load/save
        // cycles on the same row would lose one side, so short-circuit.
        if sender_pk == receiver_pk {
            return Ok(());
        }

        let mut sender_balance = PnCounter::load(self.db, &sender_pk)?;
        let mut receiver_balance = PnCounter::load(self.db, &receiver_pk)?;

        // The PN-Counter API takes `u64`; split the i64 amount into a magnitude
        // applied to the correct side per the sign convention.
        if amount_centi >= 0 {
            let mag = amount_centi as u64;
            sender_balance.decrement(&self.replica, mag);
            receiver_balance.increment(&self.replica, mag);
        } else {
            let mag = amount_centi.unsigned_abs();
            sender_balance.increment(&self.replica, mag);
            receiver_balance.decrement(&self.replica, mag);
        }

        sender_balance.save(self.db, &sender_pk)?;
        receiver_balance.save(self.db, &receiver_pk)?;
        Ok(())
    }
}

/// Reads materialized balances. The balance of an identity is the value of its
/// PN-Counter, in centicommons (may be negative — members can hold debt).
pub struct BalanceView<'db> {
    db: &'db Database,
}

impl<'db> BalanceView<'db> {
    /// Wraps a database handle for balance queries.
    pub fn new(db: &'db Database) -> Self {
        Self { db }
    }

    /// The current balance of `identity`, in centicommons.
    pub fn balance_of(&self, identity: &Address) -> Result<i64> {
        Ok(PnCounter::load(self.db, identity.public_key())?.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::migrations;

    use crate::transaction::{
        SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
    };

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// Appends a proposal + confirmation directly to the log, leaving the
    /// transaction in the `Confirmed` state. Returns its id.
    fn confirmed_tx(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        amount_centi: i64,
        confirmed_at: i64,
    ) -> TransactionId {
        let proposal = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            amount_centi,
            None,
            0,
            0,
            1_000_000,
        );
        let id = proposal.id;
        let mut log = AppendLog::new(db);
        log.append(SignedProposal::sign(proposal, sender)).unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(receiver),
            confirmed_at,
        };
        log.append(SignedConfirmation::sign(confirmation, receiver))
            .unwrap();
        id
    }

    fn settler<'a>(db: &'a Database, station: &Keypair, window: u64) -> Settler<'a> {
        Settler::new(
            db,
            station.clone(),
            SettlementConfig {
                window_seconds: window,
            },
        )
    }

    #[test]
    fn eligible_exactly_at_window_end() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = confirmed_tx(&db, &alice, &bob, 300, 1_000);
        let s = settler(&db, &station, 100);

        assert_eq!(s.find_eligible(1_100).unwrap(), vec![id]);
        assert!(s.find_eligible(1_099).unwrap().is_empty());
    }

    #[test]
    fn settle_moves_balances_by_amount() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = confirmed_tx(&db, &alice, &bob, 300, 1_000);
        let mut s = settler(&db, &station, 100);

        let balances = BalanceView::new(&db);
        // Before settlement, both balances are zero.
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), 0);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 0);

        s.settle(&id, 1_100).unwrap();
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), -300);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 300);
    }

    #[test]
    fn settle_is_idempotent() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = confirmed_tx(&db, &alice, &bob, 300, 1_000);
        let mut s = settler(&db, &station, 100);

        s.settle(&id, 1_100).unwrap();
        // Settling again must not error and must not double-apply.
        s.settle(&id, 1_200).unwrap();

        let balances = BalanceView::new(&db);
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), -300);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 300);
    }

    #[test]
    fn balances_unchanged_while_confirmed() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        confirmed_tx(&db, &alice, &bob, 300, 1_000);
        // No settle call.
        let _ = settler(&db, &station, 100);
        let balances = BalanceView::new(&db);
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), 0);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 0);
    }

    #[test]
    fn settling_unknown_transaction_errors() {
        let db = fresh_db();
        let station = Keypair::generate();
        let mut s = settler(&db, &station, 100);
        let missing = TransactionId(rrn_crypto::hash::Hash::of(b"nope"));
        assert!(matches!(
            s.settle(&missing, 1_000),
            Err(Error::UnknownTransaction)
        ));
    }

    #[test]
    fn negative_amount_reverses_direction() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        // Negative amount: receiver pays sender.
        let id = confirmed_tx(&db, &alice, &bob, -300, 1_000);
        let mut s = settler(&db, &station, 100);
        s.settle(&id, 1_100).unwrap();

        let balances = BalanceView::new(&db);
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), 300);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), -300);
    }
}
