//! Consolidated property tests for the three CRDTs against the algebraic merge
//! laws, exercised through the public API only.
//!
//! Each CRDT must satisfy, for any states reachable by arbitrary operation
//! sequences:
//!   * **Commutativity:** `a.merge(b)` equals `b.merge(a)`.
//!   * **Associativity:** `(a.merge(b)).merge(c)` equals `a.merge(b.merge(c))`.
//!   * **Idempotence:** `a.merge(a)` equals `a`.
//!
//! These are what guarantee that replicas which diverge and reconcile in any
//! order converge to identical state — the M0.2 exit criterion. Tags (OR-Set)
//! and clocks (LWW-Register) are supplied deterministically so the proptest
//! cases are reproducible from their seed.

use proptest::prelude::*;
use rrn_crypto::keypair::Keypair;

use rrn_storage::crdt::lww_register::{HybridLogicalClock, LwwRegister};
use rrn_storage::crdt::or_set::{OrSet, UniqueTag};
use rrn_storage::crdt::pn_counter::PnCounter;
use rrn_storage::crdt::ReplicaId;

fn replicas(n: usize) -> Vec<ReplicaId> {
    (0..n)
        .map(|_| ReplicaId(Keypair::generate().public_key()))
        .collect()
}

/// Replicas sorted ascending by key bytes, so distinct indices have a known
/// relative order (needed for LWW's replica tiebreak).
fn sorted_replicas(n: usize) -> Vec<ReplicaId> {
    let mut r = replicas(n);
    r.sort();
    r
}

// ---------------------------------------------------------------- PN-Counter

/// `(replica index, amount, is_increment)`.
type PnOp = (usize, u64, bool);

fn pn_apply(replicas: &[ReplicaId], ops: &[PnOp]) -> PnCounter {
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

fn pn_ops() -> impl Strategy<Value = Vec<PnOp>> {
    prop::collection::vec((0usize..3, 0u64..1_000, any::<bool>()), 0..16)
}

proptest! {
    #[test]
    fn pn_counter_commutative(a in pn_ops(), b in pn_ops()) {
        let r = replicas(3);
        let (ca, cb) = (pn_apply(&r, &a), pn_apply(&r, &b));
        let mut ab = ca.clone(); ab.merge(&cb);
        let mut ba = cb.clone(); ba.merge(&ca);
        prop_assert_eq!(ab, ba);
    }

    #[test]
    fn pn_counter_associative(a in pn_ops(), b in pn_ops(), c in pn_ops()) {
        let r = replicas(3);
        let (ca, cb, cc) = (pn_apply(&r, &a), pn_apply(&r, &b), pn_apply(&r, &c));
        let mut left = ca.clone(); left.merge(&cb); left.merge(&cc);
        let mut bc = cb.clone(); bc.merge(&cc);
        let mut right = ca.clone(); right.merge(&bc);
        prop_assert_eq!(left, right);
    }

    #[test]
    fn pn_counter_idempotent(a in pn_ops()) {
        let r = replicas(3);
        let ca = pn_apply(&r, &a);
        let mut merged = ca.clone(); merged.merge(&ca.clone());
        prop_assert_eq!(merged, ca);
    }
}

// -------------------------------------------------------------------- OR-Set

/// `(element, is_add, tag byte)`. Removes target the element; the tag byte
/// distinguishes adds deterministically.
type OrOp = (u8, bool, u8);

fn tag(byte: u8) -> UniqueTag {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    UniqueTag::from_bytes(bytes)
}

fn or_apply(ops: &[OrOp]) -> OrSet<u8> {
    let mut s = OrSet::new();
    for &(element, is_add, t) in ops {
        let element = element % 5;
        if is_add {
            s.add_with_tag(element, tag(t));
        } else {
            s.remove(&element);
        }
    }
    s
}

fn or_ops() -> impl Strategy<Value = Vec<OrOp>> {
    prop::collection::vec((0u8..5, any::<bool>(), any::<u8>()), 0..20)
}

proptest! {
    #[test]
    fn or_set_commutative(a in or_ops(), b in or_ops()) {
        let (sa, sb) = (or_apply(&a), or_apply(&b));
        let mut ab = sa.clone(); ab.merge(&sb);
        let mut ba = sb.clone(); ba.merge(&sa);
        prop_assert_eq!(ab, ba);
    }

    #[test]
    fn or_set_associative(a in or_ops(), b in or_ops(), c in or_ops()) {
        let (sa, sb, sc) = (or_apply(&a), or_apply(&b), or_apply(&c));
        let mut left = sa.clone(); left.merge(&sb); left.merge(&sc);
        let mut bc = sb.clone(); bc.merge(&sc);
        let mut right = sa.clone(); right.merge(&bc);
        prop_assert_eq!(left, right);
    }

    #[test]
    fn or_set_idempotent(a in or_ops()) {
        let sa = or_apply(&a);
        let mut merged = sa.clone(); merged.merge(&sa.clone());
        prop_assert_eq!(merged, sa);
    }
}

// ------------------------------------------------------------- LWW-Register

fn lww(value: u8, wall_ms: u64, logical: u32, replica: ReplicaId) -> LwwRegister<u8> {
    LwwRegister::from_parts(
        value,
        HybridLogicalClock {
            wall_time_ms: wall_ms,
            logical,
            replica,
        },
    )
}

/// A register on a fixed replica with arbitrary value/clock. Distinct replicas
/// across the operands guarantee a strict HLC order (no genuine ties), matching
/// the production invariant.
fn lww_on(replica: ReplicaId) -> impl Strategy<Value = LwwRegister<u8>> {
    (any::<u8>(), 0u64..1_000, 0u32..8).prop_map(move |(v, w, l)| lww(v, w, l, replica))
}

proptest! {
    #[test]
    fn lww_commutative(
        (a, b) in { let r = sorted_replicas(2); (lww_on(r[0]), lww_on(r[1])) }
    ) {
        let mut ab = a.clone(); ab.merge(&b);
        let mut ba = b.clone(); ba.merge(&a);
        prop_assert_eq!(ab, ba);
    }

    #[test]
    fn lww_associative(
        (a, b, c) in { let r = sorted_replicas(3); (lww_on(r[0]), lww_on(r[1]), lww_on(r[2])) }
    ) {
        let mut left = a.clone(); left.merge(&b); left.merge(&c);
        let mut bc = b.clone(); bc.merge(&c);
        let mut right = a.clone(); right.merge(&bc);
        prop_assert_eq!(left, right);
    }

    #[test]
    fn lww_idempotent(a in { let r = sorted_replicas(1); lww_on(r[0]) }) {
        let mut merged = a.clone(); merged.merge(&a.clone());
        prop_assert_eq!(merged, a);
    }
}
