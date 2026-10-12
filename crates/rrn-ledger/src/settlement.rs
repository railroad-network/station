//! The settlement window, and the balance changes that close it.
//!
//! After a transaction is confirmed it sits in the **settlement window** — 24h
//! for Tier 1, 48h for Tier 2 by default (a demo/test can collapse both to a few
//! seconds; see [`SettlementConfig::uniform`]). The window that governs a given
//! transaction follows its [oracle tier](crate::tier): a lower-value Tier-1
//! transfer clears sooner than the deliberate Tier-2 purchase it stakes
//! reputation on. While it waits, *no balances change* — that delay is the whole
//! point: it is also the dispute window for the Phase 1 oracle. When the window
//! elapses the [`Settler`] appends the station-signed record that moves the
//! transaction to [`Settled`](crate::state::TransactionState::Settled) — and the
//! balance with it, exactly once.
//!
//! # Settlement appends a station-signed record
//!
//! Settlement is automatic, so neither the sender nor the receiver is present to
//! sign it. The local station signs a [`SettlementRecord`] with its own key and
//! appends it to the log; that record is the source of truth, and replaying it
//! is what turns the transaction's derived state to `Settled` and moves the
//! balance. See ADR-0005 and the crate-level docs.
//!
//! # Balances are derived, never stored
//!
//! No balance is written anywhere: [`LedgerSnapshot::balance_of`] folds every
//! station-signed settlement record (once per transaction) and contract charge
//! (once per period) on replay, and [`BalanceView`] and the debt floor read
//! that fold (ADR-0018). So there is no window in which a settlement is on the
//! log but missing from a balance.
//!
//! # Idempotence
//!
//! [`Settler::settle`] derives the transaction's current state from the log
//! first. An already-`Settled` transaction is a no-op (returns `Ok` without
//! appending); a non-existent one is an error. Even a redundant settlement
//! record for the same transaction moves no balance: the fold applies the first
//! one per `proposal_id`.

use dcbor::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;

use crate::state::{LedgerSnapshot, TransactionState};
use crate::transaction::TransactionId;
use crate::{Error, Result};

/// Discriminant string for a settlement record's canonical CBOR.
pub const SETTLEMENT_KIND: &str = "rrn.tx.settlement";

/// The default Tier-1 settlement window: 24 hours. Lower value, shorter scrutiny
/// (ADR-0011).
pub const DEFAULT_TIER1_WINDOW_SECONDS: u64 = 24 * 3600;

/// The default Tier-2 settlement window: 48 hours — the standard dispute window
/// a staked confirmation is exposed to (ADR-0011).
pub const DEFAULT_TIER2_WINDOW_SECONDS: u64 = 48 * 3600;

/// Tunable settlement parameters: the wait a confirmed transaction serves before
/// it settles, per [oracle tier](crate::tier).
#[derive(Clone, Copy, Debug)]
pub struct SettlementConfig {
    /// How long a confirmed **Tier-1** transaction waits before settling.
    /// Defaults to [`DEFAULT_TIER1_WINDOW_SECONDS`].
    pub tier1_window_seconds: u64,
    /// How long a confirmed **Tier-2** transaction waits before settling.
    /// Defaults to [`DEFAULT_TIER2_WINDOW_SECONDS`].
    pub tier2_window_seconds: u64,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self {
            tier1_window_seconds: DEFAULT_TIER1_WINDOW_SECONDS,
            tier2_window_seconds: DEFAULT_TIER2_WINDOW_SECONDS,
        }
    }
}

impl SettlementConfig {
    /// A config that applies the same `window_seconds` to every tier — the
    /// demo/test knob that collapses both windows so settlement fires promptly.
    pub fn uniform(window_seconds: u64) -> Self {
        Self {
            tier1_window_seconds: window_seconds,
            tier2_window_seconds: window_seconds,
        }
    }

    /// The settlement window, in seconds, that governs a transaction of the given
    /// `tier`. Tier 1 gets the shorter window; Tier 2 — and, defensively, any
    /// higher tier that somehow reached settlement — gets the standard one.
    pub fn window_for(&self, tier: u8) -> u64 {
        if tier <= crate::tier::MIN_TIER {
            self.tier1_window_seconds
        } else {
            self.tier2_window_seconds
        }
    }
}

/// The log record that marks a transaction settled. Signed by the station.
///
/// It restates the parties and amount so that balances are fully re-derivable
/// from the log alone ([`LedgerSnapshot::balance_of`] folds it).
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
/// is no timer here; the daemon calls [`Settler::sweep`] periodically.
pub struct Settler<'db> {
    config: SettlementConfig,
    station: Keypair,
    db: &'db Database,
}

impl<'db> Settler<'db> {
    /// Creates a settler over `db`, signing settlement records with `station`.
    pub fn new(db: &'db Database, station: Keypair, config: SettlementConfig) -> Self {
        Self {
            config,
            station,
            db,
        }
    }

    /// Transaction ids that are confirmed and whose settlement window has now
    /// elapsed (`admitted_at(confirmation) + window_seconds <= now`).
    pub fn find_eligible(&self, now: i64) -> Result<Vec<TransactionId>> {
        let snapshot =
            LedgerSnapshot::derive(&AppendLog::new(self.db), &self.station.public_key())?;
        let mut eligible = Vec::new();
        for (id, state) in snapshot.iter() {
            if let TransactionState::Confirmed { proposal, .. } = state {
                // The window is a pure function of the transaction's tier (derived
                // from the immutable signed proposal), measured from when this
                // station *admitted* the confirmation (ADR-0022 §2). The
                // receiver-supplied `confirmed_at` is plausibility-bounded
                // testimony carrying no window weight: a confirmation carried
                // offline for days becomes eligible a full window after it
                // arrives, so late knowledge delays settlement without ever
                // truncating the dispute window that shares this instant.
                let window = self.config.window_for(proposal.payload.effective_tier()) as i64;
                // Every `Confirmed` state carries confirmation admission metadata:
                // replay seeds it on the confirm transition (an invariant), so
                // `None` here is a snapshot-derivation bug, not reachable data. Fail
                // loudly rather than silently skipping a settlement.
                let admitted_at = snapshot
                    .admission(id)
                    .and_then(|a| a.confirmation_admitted_at)
                    .ok_or_else(|| {
                        Error::Invalid(
                            "confirmed transaction missing confirmation admission metadata".into(),
                        )
                    })?;
                if admitted_at.saturating_add(window) <= now {
                    eligible.push(*id);
                }
            }
        }
        Ok(eligible)
    }

    /// Settles a single transaction. Idempotent: an already-settled transaction
    /// is a no-op; a non-existent one is an error.
    pub fn settle(&mut self, tx_id: &TransactionId, now: i64) -> Result<()> {
        let snapshot =
            LedgerSnapshot::derive(&AppendLog::new(self.db), &self.station.public_key())?;
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
            // A dispute that was rejected or lapsed settles as originally
            // confirmed (ADR-0014 §6). The automatic sweep never reaches this arm
            // — `find_eligible` returns only `Confirmed` transactions, so a live
            // dispute stays frozen — but the dispute layer calls `settle`
            // explicitly to enact a rejection.
            TransactionState::Disputed { proposal, .. } => proposal.clone(),
            _ => return Err(Error::NotConfirmed),
        };

        let p = &proposal.payload;
        // Append the station-signed settlement record — the source of truth.
        // The balance move is the fold of this record on replay; nothing else
        // is written.
        let record = SettlementRecord {
            proposal_id: *tx_id,
            sender: p.sender,
            receiver: p.receiver,
            amount_centi: p.amount_centi,
            settled_at: now,
        };
        AppendLog::new(self.db).append(SignedPayload::sign(record, &self.station), now)?;
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
}

/// Reads settled balances, derived from the log (ADR-0018). The balance of an
/// identity is [`LedgerSnapshot::balance_of`] over a fresh replay, in
/// centicommons (may be negative — members can hold debt).
pub struct BalanceView<'db> {
    db: &'db Database,
    station: PublicKey,
}

impl<'db> BalanceView<'db> {
    /// Wraps a database handle for balance queries. `station` is the community
    /// station key the balance records are pinned to (ADR-0005).
    pub fn new(db: &'db Database, station: PublicKey) -> Self {
        Self { db, station }
    }

    /// The current balance of `identity`, in centicommons.
    pub fn balance_of(&self, identity: &Address) -> Result<i64> {
        Ok(LedgerSnapshot::derive(&AppendLog::new(self.db), &self.station)?.balance_of(identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::migrations;

    use crate::dispute::{DisputeRecord, SignedDispute};
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
        log.append(SignedProposal::sign(proposal, sender), confirmed_at)
            .unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(receiver),
            confirmed_at,
        };
        log.append(
            SignedConfirmation::sign(confirmation, receiver),
            confirmed_at,
        )
        .unwrap();
        id
    }

    /// Like [`confirmed_tx`], but admits the confirmation at `admitted_at`
    /// (distinct from the claimed `confirmed_at`) so window arithmetic can be
    /// tested against the admission clock (ADR-0022 §2) specifically.
    fn confirmed_tx_admitted(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        amount_centi: i64,
        confirmed_at: i64,
        admitted_at: i64,
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
        log.append(SignedProposal::sign(proposal, sender), admitted_at)
            .unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: id,
            confirmer: addr(receiver),
            confirmed_at,
        };
        log.append(
            SignedConfirmation::sign(confirmation, receiver),
            admitted_at,
        )
        .unwrap();
        id
    }

    fn settler<'a>(db: &'a Database, station: &Keypair, window: u64) -> Settler<'a> {
        Settler::new(db, station.clone(), SettlementConfig::uniform(window))
    }

    #[test]
    fn settlement_waits_for_admission_plus_window() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        // Backdated `confirmed_at=100`, but admitted at 10_000.
        let id = confirmed_tx_admitted(&db, &alice, &bob, 300, 100, 10_000);
        let w = 5_000i64;
        let s = settler(&db, &station, w as u64);

        // A window past the *claimed* time is not enough — nothing is eligible.
        assert!(s.find_eligible(100 + w).unwrap().is_empty());
        // A window past *admission* is: the tx becomes eligible then.
        assert!(s.find_eligible(10_000 + w - 1).unwrap().is_empty());
        assert_eq!(s.find_eligible(10_000 + w).unwrap(), vec![id]);
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
    fn window_follows_the_transactions_tier() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        // A 3-Common transfer is Tier 1; a 25-Common transfer is Tier 2.
        let low = confirmed_tx(&db, &alice, &bob, 300, 1_000);
        let high = confirmed_tx(&db, &alice, &bob, 2_500, 1_000);
        let s = Settler::new(
            &db,
            station.clone(),
            SettlementConfig {
                tier1_window_seconds: 100,
                tier2_window_seconds: 200,
            },
        );

        // Between the two windows: the Tier-1 transfer is eligible, the Tier-2
        // one still waits.
        let mid = s.find_eligible(1_150).unwrap();
        assert_eq!(mid, vec![low]);

        // Once the Tier-2 window also elapses, both are eligible.
        let done = s.find_eligible(1_200).unwrap();
        assert!(done.contains(&low) && done.contains(&high));
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

        let balances = BalanceView::new(&db, station.public_key());
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

        let balances = BalanceView::new(&db, station.public_key());
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
        let balances = BalanceView::new(&db, station.public_key());
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

    /// Appends proposal + confirmation + a party-raised dispute, leaving the
    /// transaction in the `Disputed` (frozen) state. Returns its id.
    fn disputed_tx(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        amount_centi: i64,
        confirmed_at: i64,
        opened_at: i64,
    ) -> TransactionId {
        let id = confirmed_tx(db, sender, receiver, amount_centi, confirmed_at);
        let dispute = DisputeRecord {
            proposal_id: id,
            raiser: addr(sender),
            reason: "contested".into(),
            evidence_hash: None,
            opened_at,
        };
        AppendLog::new(db)
            .append(SignedDispute::sign(dispute, sender), opened_at)
            .unwrap();
        id
    }

    #[test]
    fn disputed_transaction_is_frozen_from_the_sweep() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = disputed_tx(&db, &alice, &bob, 300, 1_000, 1_050);
        let mut s = settler(&db, &station, 100);

        // The settlement window elapsed long ago, but the dispute freezes it:
        // nothing is eligible and a sweep settles nothing.
        assert!(s.find_eligible(10_000).unwrap().is_empty());
        assert_eq!(s.sweep(10_000).unwrap(), 0);

        let balances = BalanceView::new(&db, station.public_key());
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), 0);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 0);
        let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
        assert!(matches!(
            snap.get(&id),
            Some(TransactionState::Disputed { .. })
        ));
    }

    #[test]
    fn explicit_settle_enacts_a_rejected_dispute() {
        // Rejection/lapse enactment: the dispute layer calls `settle` directly on
        // a frozen transaction, which settles it and moves balances as confirmed.
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = disputed_tx(&db, &alice, &bob, 300, 1_000, 1_050);
        let mut s = settler(&db, &station, 100);

        s.settle(&id, 20_000).unwrap();
        let balances = BalanceView::new(&db, station.public_key());
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), -300);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), 300);
        let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
        assert!(matches!(
            snap.get(&id),
            Some(TransactionState::Settled { .. })
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

        let balances = BalanceView::new(&db, station.public_key());
        assert_eq!(balances.balance_of(&addr(&alice)).unwrap(), 300);
        assert_eq!(balances.balance_of(&addr(&bob)).unwrap(), -300);
    }

    use crate::engine::{Engine, CLOCK_SKEW_TOLERANCE_SECS};
    use proptest::prelude::*;

    /// The proposal's fixed `proposed_at` used by the invariance proptest below.
    const PROPOSED_AT: i64 = 100;

    /// Property-test case budget: `PROPTEST_CASES` if set (the deep lane sets
    /// 1024), else `default_cases`. Unlike `ProptestConfig::with_cases`, this
    /// honors the env var, so the deep lane deepens this property too.
    fn cases(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_cases);
        ProptestConfig {
            cases,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(cases(64))]

        /// The settlement-eligibility instant and the dispute deadline are
        /// functions of the confirmation's *admission* time only (ADR-0022 §2):
        /// across the whole legal range of the party-asserted `confirmed_at`,
        /// both boundaries stay fixed at `confirm_admit + window` (+ skew for the
        /// dispute deadline). If any `confirmed_at` moved either boundary, this
        /// would fail — that is exactly the backdating attack the ADR retires.
        #[test]
        fn windows_are_a_function_of_admission_not_confirmed_at(
            confirm_admit in 1_000i64..500_000,
            window in 1i64..50_000,
            confirmed_pick in 0u32..=1000,
        ) {
            // Sweep `confirmed_at` across its full legal range at admission: no
            // earlier than the proposal (minus skew), no later than admission
            // (plus skew). Every pick must leave both windows unmoved.
            let skew = CLOCK_SKEW_TOLERANCE_SECS;
            let (lo, hi) = (PROPOSED_AT - skew, confirm_admit + skew);
            let confirmed_at = lo + ((hi - lo) * confirmed_pick as i64) / 1000;

            let db = fresh_db();
            let (alice, bob, station) = (
                Keypair::generate(),
                Keypair::generate(),
                Keypair::generate(),
            );
            let mut engine = Engine::new(&db, station.clone());
            // Alice spends from zero, so she must be enrolled (ADR-0038).
            crate::enrollment::append_enrollment(
                &mut AppendLog::new(&db),
                &station,
                addr(&alice),
                crate::enrollment::EnrollmentAction::Enroll,
                crate::enrollment::EnrollmentBasis::Pairing,
                0,
            )
            .unwrap();

            // Propose at PROPOSED_AT; admit the confirmation at `confirm_admit`
            // while it claims the swept-over `confirmed_at`.
            let proposal = TransactionProposal::new(
                addr(&alice),
                addr(&bob),
                300,
                None,
                0,
                PROPOSED_AT,
                1_000_000,
            );
            let id = proposal.id;
            engine
                .submit_proposal(SignedProposal::sign(proposal, &alice), PROPOSED_AT)
                .unwrap();
            let confirmation = TransactionConfirmation {
                proposal_id: id,
                confirmer: addr(&bob),
                confirmed_at,
            };
            engine
                .submit_confirmation(SignedConfirmation::sign(confirmation, &bob), confirm_admit)
                .unwrap();

            // Eligibility instant is admission + window, independent of the claim.
            let s = settler(&db, &station, window as u64);
            prop_assert!(s.find_eligible(confirm_admit + window - 1).unwrap().is_empty());
            prop_assert_eq!(s.find_eligible(confirm_admit + window).unwrap(), vec![id]);

            // Dispute deadline is admission + window + skew, independent too. Test
            // the just-past case first (it does not mutate), then the boundary.
            let cfg = SettlementConfig::uniform(window as u64);
            let deadline = confirm_admit + window + CLOCK_SKEW_TOLERANCE_SECS;
            let dispute = |opened_at: i64| {
                let d = DisputeRecord {
                    proposal_id: id,
                    raiser: addr(&alice),
                    reason: "contested".into(),
                    evidence_hash: None,
                    opened_at,
                };
                SignedDispute::sign(d, &alice)
            };
            prop_assert!(matches!(
                engine.raise_dispute(dispute(deadline + 1), &cfg, deadline + 1),
                Err(Error::DisputeWindowClosed)
            ));
            prop_assert!(engine.raise_dispute(dispute(deadline), &cfg, deadline).is_ok());
        }
    }

    #[test]
    fn a_settlement_record_without_a_cache_write_counts() {
        // The window a cached balance used to open: a station-signed settlement
        // record is on the log, but nothing else was written after it (a crash
        // between the append and a cache write). The debt floor reads the
        // log-derived balance, so the receiver's +300 counts: a 2200 spend
        // projects to -1900, inside the -2000 floor.
        use crate::engine::Engine;
        use crate::enrollment::{append_enrollment, EnrollmentAction, EnrollmentBasis};

        let db = fresh_db();
        let (alice, bob, carol, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let id = confirmed_tx(&db, &alice, &bob, 300, 1_000);
        let record = SettlementRecord {
            proposal_id: id,
            sender: addr(&alice),
            receiver: addr(&bob),
            amount_centi: 300,
            settled_at: 1_100,
        };
        AppendLog::new(&db)
            .append(SignedPayload::sign(record, &station), 1_100)
            .unwrap();
        append_enrollment(
            &mut AppendLog::new(&db),
            &station,
            addr(&bob),
            EnrollmentAction::Enroll,
            EnrollmentBasis::Pairing,
            1_100,
        )
        .unwrap();

        let mut engine = Engine::new(&db, station.clone());
        let spend =
            TransactionProposal::new(addr(&bob), addr(&carol), 2_200, None, 0, 1_200, 9_999);
        engine
            .submit_proposal(SignedProposal::sign(spend, &bob), 1_200)
            .unwrap();
        assert_eq!(
            BalanceView::new(&db, station.public_key())
                .balance_of(&addr(&bob))
                .unwrap(),
            300
        );
    }
}
