//! The transaction lifecycle, and how it is derived from the append-only log.
//!
//! A transaction moves through a strict state machine:
//!
//! ```text
//!                 confirm                 window elapses
//!   Proposed  ─────────────▶  Confirmed  ───────────────▶  Settled
//!      │                          │
//!      │ withdraw / reject /      │ dispute (Phase 1)
//!      │ expire                   ▼
//!      ▼                      DisputedStub
//!   Cancelled
//! ```
//!
//! [`TransactionState::can_transition_to`] encodes exactly these edges; every
//! other transition is rejected as a bug or an attack. The current state of any
//! transaction is not stored as a mutable row — it is *derived* by replaying the
//! log entries for that transaction ([`LedgerSnapshot::derive`]).

use std::collections::BTreeMap;

use dcbor::prelude::*;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_storage::log::{AppendLog, StoredPayload};
use serde::{Deserialize, Serialize};

use crate::settlement::SettlementRecord;
use crate::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId, TransactionProposal,
};
use crate::{Error, Result};

/// Discriminant string for a cancellation record's canonical CBOR.
pub(crate) const CANCELLATION_KIND: &str = "rrn.tx.cancellation";

/// Why a proposal was cancelled before it could settle.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelReason {
    /// The proposal passed its `expires_at` without being confirmed.
    Expired,
    /// The sender withdrew the proposal.
    WithdrawnBySender,
    /// The receiver declined to confirm.
    RejectedByReceiver,
}

impl CancelReason {
    fn tag(self) -> &'static str {
        match self {
            CancelReason::Expired => "expired",
            CancelReason::WithdrawnBySender => "withdrawn_by_sender",
            CancelReason::RejectedByReceiver => "rejected_by_receiver",
        }
    }
}

impl From<CancelReason> for CBOR {
    fn from(r: CancelReason) -> Self {
        r.tag().into()
    }
}

impl TryFrom<CBOR> for CancelReason {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        match cbor.try_into_text()?.as_str() {
            "expired" => Ok(CancelReason::Expired),
            "withdrawn_by_sender" => Ok(CancelReason::WithdrawnBySender),
            "rejected_by_receiver" => Ok(CancelReason::RejectedByReceiver),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// The log record a cancellation appends. Signed by the station (no transacting
/// party is necessarily present to withdraw/reject, and expiry is automatic).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellationRecord {
    /// The proposal being cancelled.
    pub proposal_id: TransactionId,
    /// Why it was cancelled.
    pub reason: CancelReason,
    /// Unix seconds when the cancellation was recorded.
    pub cancelled_at: i64,
}

impl From<CancellationRecord> for CBOR {
    fn from(c: CancellationRecord) -> Self {
        let mut m = Map::new();
        m.insert("kind", CANCELLATION_KIND);
        m.insert("proposal_id", c.proposal_id);
        m.insert("reason", c.reason);
        m.insert("cancelled_at", c.cancelled_at);
        m.into()
    }
}

impl TryFrom<CBOR> for CancellationRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != CANCELLATION_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(CancellationRecord {
            proposal_id: map.extract::<&str, TransactionId>("proposal_id")?,
            reason: map.extract::<&str, CancelReason>("reason")?,
            cancelled_at: map.extract::<&str, i64>("cancelled_at")?,
        })
    }
}

/// The lifecycle state of a single transaction.
///
/// Each non-stub variant carries the *signed* records that justify it, so a
/// state is self-verifying: [`TransactionState::verify`] re-checks every
/// embedded signature.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TransactionState {
    /// The sender has proposed; awaiting the receiver's confirmation.
    Proposed {
        /// The sender-signed proposal.
        proposal: SignedProposal,
    },
    /// The receiver has confirmed; awaiting the settlement window.
    Confirmed {
        /// The sender-signed proposal.
        proposal: SignedProposal,
        /// The receiver-signed confirmation.
        confirmation: SignedConfirmation,
    },
    /// The settlement window has elapsed and balances have moved.
    Settled {
        /// The sender-signed proposal.
        proposal: SignedProposal,
        /// The receiver-signed confirmation.
        confirmation: SignedConfirmation,
        /// Unix seconds when settlement occurred.
        settled_at: i64,
    },
    /// The proposal was cancelled before settling.
    Cancelled {
        /// The sender-signed proposal.
        proposal: SignedProposal,
        /// Unix seconds when it was cancelled.
        cancelled_at: i64,
        /// Why it was cancelled.
        reason: CancelReason,
    },
    /// Placeholder for the Phase 1 dispute path. Never constructed in Phase 0;
    /// the `Confirmed → DisputedStub` edge is accepted but does nothing.
    DisputedStub,
}

/// The coarse lifecycle stage of a state, ignoring the carried records. Used to
/// make the transition table enumerable and `match`-exhaustive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Proposed,
    Confirmed,
    Settled,
    Cancelled,
    Disputed,
}

impl TransactionState {
    /// The transaction this state belongs to.
    ///
    /// [`TransactionState::DisputedStub`] carries no proposal (it is an
    /// unconstructed Phase 0 placeholder) and returns the all-zero id.
    pub fn id(&self) -> TransactionId {
        match self {
            TransactionState::Proposed { proposal }
            | TransactionState::Confirmed { proposal, .. }
            | TransactionState::Settled { proposal, .. }
            | TransactionState::Cancelled { proposal, .. } => proposal.payload.id,
            TransactionState::DisputedStub => {
                TransactionId(rrn_crypto::hash::Hash::from_bytes([0u8; 32]))
            }
        }
    }

    fn stage(&self) -> Stage {
        match self {
            TransactionState::Proposed { .. } => Stage::Proposed,
            TransactionState::Confirmed { .. } => Stage::Confirmed,
            TransactionState::Settled { .. } => Stage::Settled,
            TransactionState::Cancelled { .. } => Stage::Cancelled,
            TransactionState::DisputedStub => Stage::Disputed,
        }
    }

    /// Whether moving from `self` to `target` is a legal lifecycle transition.
    ///
    /// The only legal edges are `Proposed → Confirmed`, `Proposed → Cancelled`,
    /// `Confirmed → Settled`, and `Confirmed → DisputedStub`. Everything else —
    /// including staying in the same state or moving backwards — is illegal.
    pub fn can_transition_to(&self, target: &TransactionState) -> bool {
        matches!(
            (self.stage(), target.stage()),
            (Stage::Proposed, Stage::Confirmed)
                | (Stage::Proposed, Stage::Cancelled)
                | (Stage::Confirmed, Stage::Settled)
                | (Stage::Confirmed, Stage::Disputed)
        )
    }

    /// Re-checks the integrity of this state: every embedded signature must
    /// verify, and a confirmation must come from, and name, the proposal's
    /// receiver over the matching proposal id.
    pub fn verify(&self) -> Result<()> {
        let check_proposal = |proposal: &SignedProposal| -> Result<()> {
            proposal.verify().map_err(|_| Error::BadSignature)?;
            // The signer must be the named sender.
            if &proposal.signer != proposal.payload.sender.public_key() {
                return Err(Error::SenderMismatch);
            }
            Ok(())
        };
        let check_confirmation =
            |proposal: &SignedProposal, confirmation: &SignedConfirmation| -> Result<()> {
                confirmation.verify().map_err(|_| Error::BadSignature)?;
                if confirmation.payload.proposal_id != proposal.payload.id {
                    return Err(Error::Invalid(
                        "confirmation references a different proposal".into(),
                    ));
                }
                // Confirmer must be the receiver, and must have signed it.
                if confirmation.payload.confirmer != proposal.payload.receiver
                    || &confirmation.signer != proposal.payload.receiver.public_key()
                {
                    return Err(Error::ConfirmerMismatch);
                }
                Ok(())
            };

        match self {
            TransactionState::Proposed { proposal }
            | TransactionState::Cancelled { proposal, .. } => check_proposal(proposal),
            TransactionState::Confirmed {
                proposal,
                confirmation,
            }
            | TransactionState::Settled {
                proposal,
                confirmation,
                ..
            } => {
                check_proposal(proposal)?;
                check_confirmation(proposal, confirmation)
            }
            TransactionState::DisputedStub => Ok(()),
        }
    }
}

/// A point-in-time view of every transaction, derived by replaying the log.
///
/// Replay is the only way to learn a transaction's state: the log is the source
/// of truth (CLAUDE.md), so [`Engine`](crate::engine::Engine) and
/// [`Settler`](crate::settlement::Settler) both build a snapshot on demand
/// rather than trusting a mutable cache. Phase 0 logs are small, so a full
/// replay per operation is fine.
#[derive(Debug, Default)]
pub struct LedgerSnapshot {
    states: BTreeMap<TransactionId, TransactionState>,
    /// Highest proposal nonce seen per sender (keyed by raw 32-byte pubkey).
    max_nonce: BTreeMap<[u8; 32], u64>,
}

impl LedgerSnapshot {
    /// Replays the whole log into a snapshot.
    pub fn derive(log: &AppendLog) -> Result<Self> {
        let mut snapshot = LedgerSnapshot::default();
        for entry in log.iter_from(1) {
            snapshot.apply(&entry?.payload);
        }
        Ok(snapshot)
    }

    /// Folds one stored log payload into the snapshot. Unrecognized payloads
    /// (e.g. vouches written by `rrn-identity`) are ignored.
    fn apply(&mut self, stored: &StoredPayload) {
        let bytes = &stored.bytes;

        if let Ok(proposal) = from_canonical_bytes::<TransactionProposal>(bytes) {
            let nonce_key = proposal.sender.public_key().to_bytes();
            let slot = self.max_nonce.entry(nonce_key).or_insert(proposal.nonce);
            *slot = (*slot).max(proposal.nonce);
            let id = proposal.id;
            let signed = SignedProposal {
                payload: proposal,
                signer: stored.signer,
                signature: stored.signature,
            };
            self.states
                .insert(id, TransactionState::Proposed { proposal: signed });
            return;
        }

        if let Ok(confirmation) = from_canonical_bytes::<TransactionConfirmation>(bytes) {
            let signed = SignedConfirmation {
                payload: confirmation.clone(),
                signer: stored.signer,
                signature: stored.signature,
            };
            if let Some(TransactionState::Proposed { proposal }) =
                self.states.get(&confirmation.proposal_id).cloned()
            {
                self.states.insert(
                    confirmation.proposal_id,
                    TransactionState::Confirmed {
                        proposal,
                        confirmation: signed,
                    },
                );
            }
            return;
        }

        if let Ok(settlement) = from_canonical_bytes::<SettlementRecord>(bytes) {
            if let Some(TransactionState::Confirmed {
                proposal,
                confirmation,
            }) = self.states.get(&settlement.proposal_id).cloned()
            {
                self.states.insert(
                    settlement.proposal_id,
                    TransactionState::Settled {
                        proposal,
                        confirmation,
                        settled_at: settlement.settled_at,
                    },
                );
            }
            return;
        }

        if let Ok(cancellation) = from_canonical_bytes::<CancellationRecord>(bytes) {
            if let Some(TransactionState::Proposed { proposal }) =
                self.states.get(&cancellation.proposal_id).cloned()
            {
                self.states.insert(
                    cancellation.proposal_id,
                    TransactionState::Cancelled {
                        proposal,
                        cancelled_at: cancellation.cancelled_at,
                        reason: cancellation.reason,
                    },
                );
            }
        }
    }

    /// The state of one transaction, if it appears in the log.
    pub fn get(&self, id: &TransactionId) -> Option<&TransactionState> {
        self.states.get(id)
    }

    /// The next nonce expected from `sender`: one past the highest seen, or 0 if
    /// the sender has never proposed.
    pub fn next_nonce(&self, sender_pubkey: &[u8; 32]) -> u64 {
        self.max_nonce
            .get(sender_pubkey)
            .map(|n| n.saturating_add(1))
            .unwrap_or(0)
    }

    /// Iterates every transaction's current state.
    pub fn iter(&self) -> impl Iterator<Item = (&TransactionId, &TransactionState)> {
        self.states.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
    use rrn_identity::address::Address;

    fn proposal(sender: &Keypair, receiver: &Keypair) -> SignedProposal {
        let p = TransactionProposal::new(
            Address::from_public_key(sender.public_key()),
            Address::from_public_key(receiver.public_key()),
            300,
            None,
            0,
            1_000,
            2_000,
        );
        SignedProposal::sign(p, sender)
    }

    fn confirmation(proposal: &SignedProposal, receiver: &Keypair) -> SignedConfirmation {
        let c = TransactionConfirmation {
            proposal_id: proposal.payload.id,
            confirmer: proposal.payload.receiver,
            confirmed_at: 1_500,
        };
        SignedConfirmation::sign(c, receiver)
    }

    /// One representative instance of each lifecycle stage.
    fn all_stages() -> Vec<TransactionState> {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let p = proposal(&sender, &receiver);
        let c = confirmation(&p, &receiver);
        vec![
            TransactionState::Proposed {
                proposal: p.clone(),
            },
            TransactionState::Confirmed {
                proposal: p.clone(),
                confirmation: c.clone(),
            },
            TransactionState::Settled {
                proposal: p.clone(),
                confirmation: c,
                settled_at: 9_000,
            },
            TransactionState::Cancelled {
                proposal: p,
                cancelled_at: 9_000,
                reason: CancelReason::Expired,
            },
            TransactionState::DisputedStub,
        ]
    }

    fn expected_edge(from: &TransactionState, to: &TransactionState) -> bool {
        matches!(
            (from.stage(), to.stage()),
            (Stage::Proposed, Stage::Confirmed)
                | (Stage::Proposed, Stage::Cancelled)
                | (Stage::Confirmed, Stage::Settled)
                | (Stage::Confirmed, Stage::Disputed)
        )
    }

    #[test]
    fn transition_table_is_exhaustively_correct() {
        let stages = all_stages();
        for from in &stages {
            for to in &stages {
                assert_eq!(
                    from.can_transition_to(to),
                    expected_edge(from, to),
                    "{:?} -> {:?}",
                    from.stage(),
                    to.stage()
                );
            }
        }
    }

    #[test]
    fn valid_states_verify() {
        for state in all_stages() {
            assert!(state.verify().is_ok(), "{state:?}");
        }
    }

    #[test]
    fn confirmation_with_bad_signature_is_not_a_valid_state() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let p = proposal(&sender, &receiver);
        let mut c = confirmation(&p, &receiver);
        // Tamper with the signed payload after signing: the signature no longer
        // matches, so the Confirmed state must fail verification.
        c.payload.confirmed_at += 1;
        let state = TransactionState::Confirmed {
            proposal: p,
            confirmation: c,
        };
        assert!(matches!(state.verify(), Err(Error::BadSignature)));
    }

    #[test]
    fn confirmation_by_a_stranger_is_not_a_valid_state() {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let stranger = Keypair::generate();
        let p = proposal(&sender, &receiver);
        // A correctly-signed confirmation, but by the wrong key/confirmer.
        let c = confirmation(&p, &stranger);
        let mut c = c;
        c.payload.confirmer = Address::from_public_key(stranger.public_key());
        let c = SignedConfirmation::sign(c.payload, &stranger);
        let state = TransactionState::Confirmed {
            proposal: p,
            confirmation: c,
        };
        assert!(matches!(state.verify(), Err(Error::ConfirmerMismatch)));
    }

    #[test]
    fn cancellation_record_roundtrip() {
        let rec = CancellationRecord {
            proposal_id: TransactionId(rrn_crypto::hash::Hash::of(b"x")),
            reason: CancelReason::WithdrawnBySender,
            cancelled_at: 42,
        };
        let bytes = to_canonical_bytes(rec.clone());
        let decoded: CancellationRecord = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(rec, decoded);
    }
}
