//! LWW-Register (Last-Write-Wins Register) CRDT.
//!
//! A single mutable value where the most recent write wins — used for reputation
//! scores. "Most recent" is decided by a **Hybrid Logical Clock** (HLC), not a
//! raw wall clock: plain timestamps break under clock skew, letting a node with
//! a fast clock always win. An HLC pairs the wall clock with a logical counter
//! and the writer's replica id, giving a total order that stays sensible across
//! skewed clocks and is identical on every replica.
//!
//! The HLC compares by `wall_time_ms`, then `logical`, then `replica` — exactly
//! the field order below, so the derived `Ord` *is* the comparison rule. Because
//! `replica` is part of the key and unique per station, two distinct writes can
//! never share an HLC, so merge is deterministic with no genuine ties.

use std::time::{SystemTime, UNIX_EPOCH};

use super::ReplicaId;

/// A Hybrid Logical Clock timestamp: wall time, a same-millisecond tiebreak
/// counter, and the writing replica.
///
/// Ordering (derived) is lexicographic over the fields in declaration order:
/// `wall_time_ms`, then `logical`, then `replica` (lex order of pubkey bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct HybridLogicalClock {
    /// Milliseconds since the Unix epoch at the time of the write.
    pub wall_time_ms: u64,
    /// Counter that increments when successive writes land on the same
    /// millisecond, preserving local monotonicity.
    pub logical: u32,
    /// The replica that produced this timestamp; the final, total-ordering
    /// tiebreak.
    pub replica: ReplicaId,
}

impl HybridLogicalClock {
    /// A fresh clock reading for `replica` (logical counter reset to 0).
    fn now(replica: &ReplicaId) -> Self {
        Self {
            wall_time_ms: now_ms(),
            logical: 0,
            replica: *replica,
        }
    }

    /// The next clock for `replica` strictly after `self`. Uses
    /// `max(wall_now, self.wall)` so a backwards-stepping system clock cannot
    /// produce a non-increasing timestamp; ties on the same millisecond bump the
    /// logical counter.
    fn tick(&self, replica: &ReplicaId) -> Self {
        let wall = now_ms().max(self.wall_time_ms);
        let logical = if wall == self.wall_time_ms {
            self.logical + 1
        } else {
            0
        };
        Self {
            wall_time_ms: wall,
            logical,
            replica: *replica,
        }
    }
}

/// A last-write-wins register holding a value of type `T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LwwRegister<T: Clone> {
    value: T,
    timestamp: HybridLogicalClock,
}

impl<T: Clone> LwwRegister<T> {
    /// Creates a register with `value`, stamped now by `replica`.
    pub fn new(value: T, replica: &ReplicaId) -> Self {
        Self {
            value,
            timestamp: HybridLogicalClock::now(replica),
        }
    }

    /// Constructs a register from a value and an explicit timestamp — for
    /// reconstructing a register from storage or a remote replica, and for
    /// deterministic tests that need to control the HLC.
    pub fn from_parts(value: T, timestamp: HybridLogicalClock) -> Self {
        Self { value, timestamp }
    }

    /// Overwrites the value, advancing the HLC so this write is strictly later
    /// than the register's previous state on this replica.
    pub fn set(&mut self, value: T, replica: &ReplicaId) {
        self.timestamp = self.timestamp.tick(replica);
        self.value = value;
    }

    /// Borrows the current value.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// The current timestamp (mostly useful for tests and replay ordering).
    pub fn timestamp(&self) -> HybridLogicalClock {
        self.timestamp
    }

    /// Merges `other`: if its HLC is greater, adopt its value and timestamp;
    /// otherwise keep ours. The total order on HLCs makes this commutative,
    /// associative, and idempotent.
    pub fn merge(&mut self, other: &Self) {
        if other.timestamp > self.timestamp {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
        }
    }
}

/// Current wall time in milliseconds since the Unix epoch (saturating at 0
/// before the epoch, which cannot occur in practice).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rrn_crypto::keypair::Keypair;

    fn replicas(n: usize) -> Vec<ReplicaId> {
        let mut rs: Vec<ReplicaId> = (0..n)
            .map(|_| ReplicaId(Keypair::generate().public_key()))
            .collect();
        rs.sort(); // ascending by pubkey bytes, so rs[n-1] is the "highest"
        rs
    }

    /// Builds a register with an explicit HLC — deterministic, no system clock.
    fn reg(value: u8, wall: u64, logical: u32, replica: ReplicaId) -> LwwRegister<u8> {
        LwwRegister {
            value,
            timestamp: HybridLogicalClock {
                wall_time_ms: wall,
                logical,
                replica,
            },
        }
    }

    #[test]
    fn set_advances_clock_and_value() {
        let r = &replicas(1)[0];
        let mut reg = LwwRegister::new(1u8, r);
        let t0 = reg.timestamp();
        reg.set(2, r);
        assert_eq!(*reg.get(), 2);
        assert!(reg.timestamp() > t0, "set must advance the HLC");
    }

    #[test]
    fn later_wall_clock_wins() {
        let r = replicas(2);
        let later = reg(b'A', 200, 0, r[0]);
        let earlier = reg(b'B', 100, 0, r[1]);

        let mut a = later.clone();
        a.merge(&earlier);
        assert_eq!(*a.get(), b'A');

        // Symmetric: the earlier register adopts the later value on merge.
        let mut b = earlier.clone();
        b.merge(&later);
        assert_eq!(*b.get(), b'A');
        assert_eq!(a, b, "both replicas converge");
    }

    #[test]
    fn same_wall_clock_breaks_tie_by_replica() {
        let r = replicas(2);
        let (low, high) = (r[0], r[1]); // r is sorted ascending
        let from_low = reg(b'L', 100, 0, low);
        let from_high = reg(b'H', 100, 0, high);

        let mut a = from_low.clone();
        a.merge(&from_high);
        assert_eq!(*a.get(), b'H', "higher replica id wins the tie");

        let mut b = from_high.clone();
        b.merge(&from_low);
        assert_eq!(*b.get(), b'H');
        assert_eq!(a, b);
    }

    // --- Merge laws --------------------------------------------------------
    //
    // Each register is assigned a distinct replica, so no two share an HLC and
    // the total order is strict — exactly the production invariant.

    fn lww_strategy(replica: ReplicaId) -> impl Strategy<Value = LwwRegister<u8>> {
        (any::<u8>(), 0u64..1000, 0u32..8)
            .prop_map(move |(v, wall, logical)| reg(v, wall, logical, replica))
    }

    proptest! {
        #[test]
        fn merge_commutative(
            (a, b) in {
                let r = replicas(2);
                (lww_strategy(r[0]), lww_strategy(r[1]))
            }
        ) {
            let mut ab = a.clone(); ab.merge(&b);
            let mut ba = b.clone(); ba.merge(&a);
            prop_assert_eq!(ab, ba);
        }

        #[test]
        fn merge_associative(
            (a, b, c) in {
                let r = replicas(3);
                (lww_strategy(r[0]), lww_strategy(r[1]), lww_strategy(r[2]))
            }
        ) {
            let mut left = a.clone(); left.merge(&b); left.merge(&c);
            let mut bc = b.clone(); bc.merge(&c);
            let mut right = a.clone(); right.merge(&bc);
            prop_assert_eq!(left, right);
        }

        #[test]
        fn merge_idempotent(a in lww_strategy(replicas(1)[0])) {
            let mut merged = a.clone(); merged.merge(&a.clone());
            prop_assert_eq!(merged, a);
        }
    }
}
