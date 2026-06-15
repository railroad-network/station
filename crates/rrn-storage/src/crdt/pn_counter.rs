//! PN-Counter CRDT — per-identity mutual-credit balance.
//!
//! A PN-Counter is a pair of G-Counters: one tracking increments, one tracking
//! decrements, each a map from replica to a monotonically non-decreasing total.
//! The value is `sum(increments) − sum(decrements)`, which may be negative
//! (members can go into debt). Merge takes the pointwise maximum of each
//! replica's entry, which is why per-replica granularity must be preserved —
//! collapsing to scalars would make merge lose updates.
//!
//! Merge is commutative, associative, and idempotent, so replicas that diverge
//! and reconcile in any order converge to the same value.

use std::collections::BTreeMap;

use rrn_crypto::keypair::PublicKey;
use rusqlite::OptionalExtension;

use super::ReplicaId;
use crate::db::Database;
use crate::{Error, Result};

/// Width of one serialized G-Counter entry: 32-byte replica key + 8-byte count.
const ENTRY_LEN: usize = 32 + 8;

/// A per-identity balance counter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PnCounter {
    /// Increments contributed by each replica.
    positive: BTreeMap<ReplicaId, u64>,
    /// Decrements contributed by each replica.
    negative: BTreeMap<ReplicaId, u64>,
}

impl PnCounter {
    /// Creates an empty counter (value `0`).
    pub fn new() -> Self {
        Self::default()
    }

    /// The current value: `sum(increments) − sum(decrements)`.
    ///
    /// Phase 0 bound (documented, not enforced): each side is assumed to stay
    /// below `i64::MAX`; the per-side sums saturate rather than wrap.
    pub fn value(&self) -> i64 {
        let sum =
            |m: &BTreeMap<ReplicaId, u64>| m.values().copied().fold(0u64, u64::saturating_add);
        sum(&self.positive) as i64 - sum(&self.negative) as i64
    }

    /// Builds a counter holding a single replica's absolute increment and
    /// decrement totals. Merging such a counter (pointwise max) applies the
    /// observation idempotently — used by log replay, where the same entry may
    /// be applied more than once.
    pub fn single(replica: ReplicaId, positive: u64, negative: u64) -> Self {
        let mut c = Self::new();
        c.positive.insert(replica, positive);
        c.negative.insert(replica, negative);
        c
    }

    /// Adds `amount` to this replica's increment total.
    pub fn increment(&mut self, replica: &ReplicaId, amount: u64) {
        let entry = self.positive.entry(*replica).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Adds `amount` to this replica's decrement total.
    pub fn decrement(&mut self, replica: &ReplicaId, amount: u64) {
        let entry = self.negative.entry(*replica).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Merges `other` into `self` by taking the pointwise maximum of every
    /// replica's increment and decrement totals. Idempotent, commutative, and
    /// associative.
    pub fn merge(&mut self, other: &Self) {
        merge_gcounter(&mut self.positive, &other.positive);
        merge_gcounter(&mut self.negative, &other.negative);
    }

    /// Persists this counter into the `balances` row for `identity`, replacing
    /// any existing row. The two G-Counters are stored as packed BLOBs.
    pub fn save(&self, db: &Database, identity: &PublicKey) -> Result<()> {
        db.conn().execute(
            "INSERT INTO balances (identity, positive_increments, negative_increments) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(identity) DO UPDATE SET \
                 positive_increments = excluded.positive_increments, \
                 negative_increments = excluded.negative_increments",
            rusqlite::params![
                identity.to_bytes().as_slice(),
                encode_gcounter(&self.positive),
                encode_gcounter(&self.negative),
            ],
        )?;
        Ok(())
    }

    /// Loads the counter for `identity`, or an empty counter if no row exists.
    pub fn load(db: &Database, identity: &PublicKey) -> Result<Self> {
        let row: Option<(Vec<u8>, Vec<u8>)> = db
            .conn()
            .query_row(
                "SELECT positive_increments, negative_increments FROM balances WHERE identity = ?1",
                [identity.to_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((pos, neg)) => Ok(Self {
                positive: decode_gcounter(&pos)?,
                negative: decode_gcounter(&neg)?,
            }),
            None => Ok(Self::new()),
        }
    }
}

/// Pointwise-max merge of one G-Counter map into another.
fn merge_gcounter(into: &mut BTreeMap<ReplicaId, u64>, from: &BTreeMap<ReplicaId, u64>) {
    for (replica, &count) in from {
        let entry = into.entry(*replica).or_insert(0);
        *entry = (*entry).max(count);
    }
}

/// Packs a G-Counter as `[replica(32) ‖ count_be(8)]*`, in replica order
/// (`BTreeMap` already iterates sorted), giving a deterministic encoding.
fn encode_gcounter(map: &BTreeMap<ReplicaId, u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(map.len() * ENTRY_LEN);
    for (replica, &count) in map {
        out.extend_from_slice(&replica.to_bytes());
        out.extend_from_slice(&count.to_be_bytes());
    }
    out
}

/// Inverse of [`encode_gcounter`]. Rejects malformed blobs (bad length or a
/// replica key that is not a valid public key) as [`Error::Corrupt`].
fn decode_gcounter(bytes: &[u8]) -> Result<BTreeMap<ReplicaId, u64>> {
    if !bytes.len().is_multiple_of(ENTRY_LEN) {
        return Err(Error::Corrupt(format!(
            "g-counter blob length {} is not a multiple of {ENTRY_LEN}",
            bytes.len()
        )));
    }
    let mut map = BTreeMap::new();
    for chunk in bytes.chunks_exact(ENTRY_LEN) {
        let key: [u8; 32] = chunk[..32].try_into().expect("32-byte slice");
        let pubkey = PublicKey::from_bytes(key)
            .map_err(|e| Error::Corrupt(format!("invalid replica key: {e}")))?;
        let count = u64::from_be_bytes(chunk[32..ENTRY_LEN].try_into().expect("8-byte slice"));
        map.insert(ReplicaId(pubkey), count);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rrn_crypto::keypair::Keypair;

    fn replicas(n: usize) -> Vec<ReplicaId> {
        (0..n)
            .map(|_| ReplicaId(Keypair::generate().public_key()))
            .collect()
    }

    /// One operation against a fixed replica set: `(replica index, amount,
    /// is_increment)`.
    type Op = (usize, u64, bool);

    fn apply(replicas: &[ReplicaId], ops: &[Op]) -> PnCounter {
        let mut c = PnCounter::new();
        for &(idx, amount, inc) in ops {
            let r = &replicas[idx % replicas.len()];
            if inc {
                c.increment(r, amount);
            } else {
                c.decrement(r, amount);
            }
        }
        c
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<Op>> {
        // Small amounts keep the per-side sums well below the i64 bound.
        prop::collection::vec((0usize..3, 0u64..1_000, any::<bool>()), 0..16)
    }

    #[test]
    fn value_tracks_increments_and_decrements() {
        let r = replicas(2);
        let mut c = PnCounter::new();
        c.increment(&r[0], 5);
        c.increment(&r[1], 3);
        c.decrement(&r[0], 2);
        assert_eq!(c.value(), 6);
    }

    #[test]
    fn value_can_go_negative() {
        let r = replicas(1);
        let mut c = PnCounter::new();
        c.decrement(&r[0], 10);
        assert_eq!(c.value(), -10);
    }

    #[test]
    fn persistence_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        let r = replicas(3);
        let identity = Keypair::generate().public_key();

        let original = apply(
            &r,
            &[(0, 7, true), (1, 4, true), (2, 9, false), (0, 1, false)],
        );
        original.save(&db, &identity).unwrap();
        let loaded = PnCounter::load(&db, &identity).unwrap();
        assert_eq!(loaded, original);
        assert_eq!(loaded.value(), original.value());
    }

    #[test]
    fn load_absent_identity_is_empty() {
        let db = Database::open_in_memory().unwrap();
        crate::migrations::run(&db).unwrap();
        let identity = Keypair::generate().public_key();
        assert_eq!(PnCounter::load(&db, &identity).unwrap(), PnCounter::new());
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert!(matches!(
            decode_gcounter(&[0u8; 39]),
            Err(Error::Corrupt(_))
        ));
    }

    proptest! {
        #[test]
        fn merge_commutative(a in ops_strategy(), b in ops_strategy()) {
            let r = replicas(3);
            let (ca, cb) = (apply(&r, &a), apply(&r, &b));
            let mut ab = ca.clone(); ab.merge(&cb);
            let mut ba = cb.clone(); ba.merge(&ca);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn merge_associative(a in ops_strategy(), b in ops_strategy(), c in ops_strategy()) {
            let r = replicas(3);
            let (ca, cb, cc) = (apply(&r, &a), apply(&r, &b), apply(&r, &c));
            // (a ∪ b) ∪ c
            let mut left = ca.clone(); left.merge(&cb); left.merge(&cc);
            // a ∪ (b ∪ c)
            let mut bc = cb.clone(); bc.merge(&cc);
            let mut right = ca.clone(); right.merge(&bc);
            prop_assert_eq!(left, right);
        }

        #[test]
        fn merge_idempotent(a in ops_strategy()) {
            let r = replicas(3);
            let ca = apply(&r, &a);
            let mut merged = ca.clone(); merged.merge(&ca.clone());
            prop_assert_eq!(merged, ca);
        }
    }
}
