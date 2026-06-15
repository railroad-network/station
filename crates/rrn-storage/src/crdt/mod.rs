//! Conflict-free replicated data types.
//!
//! The three CRDTs Railroad Network derives from the append-only log:
//! [`PnCounter`](pn_counter::PnCounter) for balances, OR-Set for
//! memberships/listings, and LWW-Register for reputation scores. Each provides a
//! `merge` that is commutative, associative, and idempotent, so replicas that
//! diverge and reconcile in any order converge to identical state.
//!
//! Submodules are added by T0.2.3–T0.2.5.

pub mod lww_register;
pub mod or_set;
pub mod pn_counter;

use rrn_crypto::keypair::PublicKey;

/// A stable per-replica identifier: each station's own public key.
///
/// Several CRDTs are keyed or tie-broken by replica (PN-Counter's per-replica
/// G-Counters, LWW-Register's clock), so this type lives in the shared `crdt`
/// module rather than any single CRDT file. Ordering is the lexicographic order
/// of the public key bytes — a total order that is identical on every replica,
/// which is what the CRDTs rely on for deterministic merges.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ReplicaId(pub PublicKey);

impl ReplicaId {
    /// The 32-byte public key identifying this replica.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Ord for ReplicaId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl PartialOrd for ReplicaId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
