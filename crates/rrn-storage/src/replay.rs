//! Snapshot + replay engine.
//!
//! The append-only log is the source of truth; CRDT state is *derived* by
//! replaying it. A fresh station rebuilds its state this way, and recovery
//! re-derives state from the log if the materialized tables are ever lost or
//! suspect — if log and derived state disagree, the log wins.
//!
//! Replay must be deterministic (same log → same state) and tolerant of being
//! run more than once over overlapping ranges. Handlers therefore apply entries
//! via CRDT merge, which is idempotent — re-applying an entry cannot change the
//! result. `from_seq` lets replay resume from a checkpoint, the foundation for
//! future snapshotting (caching derived state at periodic sequence numbers to
//! avoid full replay); snapshot *persistence* itself is deferred.

use dcbor::prelude::*;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::from_canonical_bytes;

use crate::crdt::pn_counter::PnCounter;
use crate::crdt::ReplicaId;
use crate::log::{AppendLog, LogEntry};
use crate::Result;

/// Something that folds log entries into derived CRDT state.
pub trait CrdtHandler {
    /// Applies a single entry. Must be idempotent: applying the same entry
    /// twice yields the same state as applying it once.
    fn handle_entry(&mut self, entry: &LogEntry) -> Result<()>;
}

/// Replays log entries with `seq >= from_seq` into `handler`, in order, and
/// returns the last sequence number applied (0 if the range is empty).
pub fn replay_log(log: &AppendLog, handler: &mut dyn CrdtHandler, from_seq: u64) -> Result<u64> {
    let mut last_seq = 0;
    for entry in log.iter_from(from_seq) {
        let entry = entry?;
        handler.handle_entry(&entry)?;
        last_seq = entry.seq;
    }
    Ok(last_seq)
}

/// A balance-affecting log payload: a replica's *absolute* increment and
/// decrement totals for one identity's PN-Counter.
///
/// Absolute (not delta) totals are what make replay idempotent — applying the
/// entry is a pointwise-max merge, so re-applying it is a no-op. This is a
/// Phase 0 stand-in; M0.5 replaces it with real, type-tagged transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceEntry {
    /// The replica whose G-Counter totals this entry reports.
    pub replica: ReplicaId,
    /// Absolute increment total for `replica`.
    pub positive: u64,
    /// Absolute decrement total for `replica`.
    pub negative: u64,
}

impl From<BalanceEntry> for CBOR {
    fn from(b: BalanceEntry) -> Self {
        let mut m = Map::new();
        m.insert("replica", ByteString::from(b.replica.to_bytes().to_vec()));
        m.insert("positive", b.positive);
        m.insert("negative", b.negative);
        m.into()
    }
}

impl TryFrom<CBOR> for BalanceEntry {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        match cbor.into_case() {
            CBORCase::Map(m) => {
                let replica_bytes: ByteString = m.extract("replica")?;
                let arr: [u8; 32] = replica_bytes
                    .to_vec()
                    .try_into()
                    .map_err(|_| dcbor::Error::WrongType)?;
                let pubkey = PublicKey::from_bytes(arr).map_err(|_| dcbor::Error::WrongType)?;
                Ok(BalanceEntry {
                    replica: ReplicaId(pubkey),
                    positive: m.extract("positive")?,
                    negative: m.extract("negative")?,
                })
            }
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// Reference [`CrdtHandler`] that derives a single PN-Counter from the log.
///
/// Entries whose payload bytes decode as a [`BalanceEntry`] are merged into the
/// counter; all others are ignored. Decoding-as-detection is a Phase 0
/// simplification — M0.5 introduces explicit payload type tags.
#[derive(Default)]
pub struct BalanceHandler {
    counter: PnCounter,
}

impl BalanceHandler {
    /// Creates a handler with an empty counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// The PN-Counter derived so far.
    pub fn counter(&self) -> &PnCounter {
        &self.counter
    }
}

impl CrdtHandler for BalanceHandler {
    fn handle_entry(&mut self, entry: &LogEntry) -> Result<()> {
        if let Ok(be) = from_canonical_bytes::<BalanceEntry>(&entry.payload.bytes) {
            self.counter
                .merge(&PnCounter::single(be.replica, be.positive, be.negative));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;

    use crate::db::Database;
    use crate::log::AppendLog;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        db
    }

    fn replica() -> ReplicaId {
        ReplicaId(Keypair::generate().public_key())
    }

    /// Appends a `BalanceEntry`, signed by `kp`, to the log.
    fn append_balance(log: &mut AppendLog, kp: &Keypair, be: BalanceEntry) {
        log.append(SignedPayload::sign(be, kp)).unwrap();
    }

    #[test]
    fn replay_derives_expected_balance() {
        let db = fresh_db();
        let kp = Keypair::generate();
        let r = replica();
        {
            let mut log = AppendLog::new(&db);
            // Absolute totals: the second entry supersedes the first via max.
            append_balance(
                &mut log,
                &kp,
                BalanceEntry {
                    replica: r,
                    positive: 5,
                    negative: 0,
                },
            );
            append_balance(
                &mut log,
                &kp,
                BalanceEntry {
                    replica: r,
                    positive: 8,
                    negative: 2,
                },
            );
        }

        let log = AppendLog::new(&db);
        let mut handler = BalanceHandler::new();
        let last = replay_log(&log, &mut handler, 1).unwrap();
        assert_eq!(last, 2);
        assert_eq!(handler.counter().value(), 6); // 8 - 2
    }

    #[test]
    fn replay_is_idempotent() {
        let db = fresh_db();
        let kp = Keypair::generate();
        let r = replica();
        {
            let mut log = AppendLog::new(&db);
            append_balance(
                &mut log,
                &kp,
                BalanceEntry {
                    replica: r,
                    positive: 5,
                    negative: 1,
                },
            );
            append_balance(
                &mut log,
                &kp,
                BalanceEntry {
                    replica: r,
                    positive: 9,
                    negative: 1,
                },
            );
        }
        let log = AppendLog::new(&db);

        // Replaying the same range twice into the same handler leaves the state
        // unchanged after the first pass (merge is idempotent).
        let mut handler = BalanceHandler::new();
        replay_log(&log, &mut handler, 1).unwrap();
        let once = handler.counter().value();
        replay_log(&log, &mut handler, 1).unwrap();
        assert_eq!(handler.counter().value(), once);

        // And a fresh handler reaches the identical state (determinism).
        let mut fresh = BalanceHandler::new();
        replay_log(&log, &mut fresh, 1).unwrap();
        assert_eq!(fresh.counter().value(), once);
    }

    #[test]
    fn replay_from_nonzero_seq() {
        let db = fresh_db();
        let kp = Keypair::generate();
        let (r1, r2) = (replica(), replica());
        {
            let mut log = AppendLog::new(&db);
            append_balance(
                &mut log,
                &kp,
                BalanceEntry {
                    replica: r1,
                    positive: 100,
                    negative: 0,
                },
            );
            append_balance(
                &mut log,
                &kp,
                BalanceEntry {
                    replica: r2,
                    positive: 7,
                    negative: 0,
                },
            );
        }

        // Starting at seq 2 skips r1's entry entirely.
        let log = AppendLog::new(&db);
        let mut handler = BalanceHandler::new();
        let last = replay_log(&log, &mut handler, 2).unwrap();
        assert_eq!(last, 2);
        assert_eq!(handler.counter().value(), 7);
    }

    #[test]
    fn empty_range_returns_zero() {
        let db = fresh_db();
        let log = AppendLog::new(&db);
        let mut handler = BalanceHandler::new();
        assert_eq!(replay_log(&log, &mut handler, 1).unwrap(), 0);
        assert_eq!(handler.counter().value(), 0);
    }
}
