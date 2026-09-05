//! The transaction lifecycle, and how it is derived from the append-only log.
//!
//! A transaction moves through a strict state machine:
//!
//! ```text
//!                 confirm                 window elapses
//!   Proposed  ─────────────▶  Confirmed  ───────────────▶  Settled
//!      │                          │                          ▲
//!      │ withdraw / reject /      │ dispute (ADR-0014)       │ dispute
//!      │ expire                   ▼                          │ rejected /
//!      ▼                      Disputed  ────────────────────┘ lapsed
//!   Cancelled  ◀──────────────────┘  dispute upheld
//! ```
//!
//! [`TransactionState::can_transition_to`] encodes exactly these edges; every
//! other transition is rejected as a bug or an attack. The current state of any
//! transaction is not stored as a mutable row — it is *derived* by replaying the
//! log entries for that transaction ([`LedgerSnapshot::derive`]).

use std::collections::BTreeMap;

use dcbor::prelude::*;
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_identity::address::Address;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};

use crate::credit::CreditConfig;
use crate::dispute::{DisputeRecord, SignedDispute};
use crate::escrow::{
    spend_admissible_until, CertId, CertificateRequest, CertificateReturn, CertificateState,
    CertificateStatus, EquivocationBasis, EquivocationId, EquivocationRecord, HeadroomCertificate,
    RequestId, SignedEquivocationRecord, SignedHeadroomCertificate,
};
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
    /// A dispute was upheld against the confirmation: the pending transfer is
    /// voided (not reversed — the freeze caught it before settlement, so no
    /// balance ever moved). See ADR-0014 §6.
    DisputeUpheld,
}

impl CancelReason {
    fn tag(self) -> &'static str {
        match self {
            CancelReason::Expired => "expired",
            CancelReason::WithdrawnBySender => "withdrawn_by_sender",
            CancelReason::RejectedByReceiver => "rejected_by_receiver",
            CancelReason::DisputeUpheld => "dispute_upheld",
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
            "dispute_upheld" => Ok(CancelReason::DisputeUpheld),
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
    /// A confirmed transaction that a party has contested. Settlement is frozen
    /// (the sweep skips it) until the dispute resolves — rejected/lapsed, moving
    /// on to `Settled`, or upheld, moving to `Cancelled` with
    /// [`CancelReason::DisputeUpheld`]. See ADR-0014.
    Disputed {
        /// The sender-signed proposal.
        proposal: SignedProposal,
        /// The receiver-signed confirmation now under contest.
        confirmation: SignedConfirmation,
        /// The party-signed record that opened the dispute. Boxed so this
        /// variant does not enlarge every `TransactionState` (it carries a third
        /// signed record where the others carry at most two).
        dispute: Box<SignedDispute>,
    },
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
    pub fn id(&self) -> TransactionId {
        match self {
            TransactionState::Proposed { proposal }
            | TransactionState::Confirmed { proposal, .. }
            | TransactionState::Settled { proposal, .. }
            | TransactionState::Cancelled { proposal, .. }
            | TransactionState::Disputed { proposal, .. } => proposal.payload.id,
        }
    }

    /// The sender-signed proposal every state carries, whatever its stage.
    pub fn proposal(&self) -> &SignedProposal {
        match self {
            TransactionState::Proposed { proposal }
            | TransactionState::Confirmed { proposal, .. }
            | TransactionState::Settled { proposal, .. }
            | TransactionState::Cancelled { proposal, .. }
            | TransactionState::Disputed { proposal, .. } => proposal,
        }
    }

    fn stage(&self) -> Stage {
        match self {
            TransactionState::Proposed { .. } => Stage::Proposed,
            TransactionState::Confirmed { .. } => Stage::Confirmed,
            TransactionState::Settled { .. } => Stage::Settled,
            TransactionState::Cancelled { .. } => Stage::Cancelled,
            TransactionState::Disputed { .. } => Stage::Disputed,
        }
    }

    /// Whether moving from `self` to `target` is a legal lifecycle transition.
    ///
    /// The only legal edges are `Proposed → Confirmed`, `Proposed → Cancelled`,
    /// `Confirmed → Settled`, `Confirmed → Disputed`, `Disputed → Settled`
    /// (dispute rejected or lapsed), and `Disputed → Cancelled` (dispute upheld).
    /// Everything else — including staying in the same state or moving backwards —
    /// is illegal.
    pub fn can_transition_to(&self, target: &TransactionState) -> bool {
        matches!(
            (self.stage(), target.stage()),
            (Stage::Proposed, Stage::Confirmed)
                | (Stage::Proposed, Stage::Cancelled)
                | (Stage::Confirmed, Stage::Settled)
                | (Stage::Confirmed, Stage::Disputed)
                | (Stage::Disputed, Stage::Settled)
                | (Stage::Disputed, Stage::Cancelled)
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

        let check_dispute = |proposal: &SignedProposal, dispute: &SignedDispute| -> Result<()> {
            dispute.verify().map_err(|_| Error::BadSignature)?;
            if dispute.payload.proposal_id != proposal.payload.id {
                return Err(Error::Invalid(
                    "dispute references a different proposal".into(),
                ));
            }
            let p = &proposal.payload;
            // Only a party may contest, and they must have signed it.
            let raiser = dispute.payload.raiser;
            if (raiser != p.sender && raiser != p.receiver)
                || &dispute.signer != raiser.public_key()
            {
                return Err(Error::NotAParty);
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
            TransactionState::Disputed {
                proposal,
                confirmation,
                dispute,
            } => {
                check_proposal(proposal)?;
                check_confirmation(proposal, confirmation)?;
                check_dispute(proposal, dispute)
            }
        }
    }
}

/// Station-local admission metadata for one transaction's lifecycle records
/// (ADR-0022): the log positions and admission-clock readings of the entries
/// that produced the current state. Local and unsigned — for display and for
/// window arithmetic on the admitting station only, never signed content (see
/// ADR-0022 §1). T2.1.2 re-anchors settlement and dispute windows onto these.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionTimes {
    /// Log seq of the admitting proposal entry.
    pub proposal_seq: u64,
    /// Admission-clock reading (`created_at`) of the proposal entry.
    pub proposal_admitted_at: i64,
    /// Log seq of the confirmation entry, once confirmed.
    pub confirmation_seq: Option<u64>,
    /// Admission-clock reading of the confirmation entry, once confirmed.
    pub confirmation_admitted_at: Option<i64>,
    /// Log seq of the dispute entry, once disputed.
    pub dispute_seq: Option<u64>,
    /// Admission-clock reading of the dispute entry, once disputed.
    pub dispute_admitted_at: Option<i64>,
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
    /// Certificate requests share this sequence (ADR-0021 §1), so replay bumps it
    /// for them too — one monotonic nonce per key keeps replay protection
    /// single-tracked across proposals and certificate requests.
    max_nonce: BTreeMap<[u8; 32], u64>,
    /// Admission metadata per transaction (ADR-0022), captured during replay
    /// from the admitting log entry of each lifecycle record.
    admissions: BTreeMap<TransactionId, AdmissionTimes>,
    /// Headroom certificates by content address (ADR-0021), each with its live
    /// status and consumed amount.
    certificates: BTreeMap<CertId, CertificateState>,
    /// The member and cap of each admitted certificate *request*, keyed by
    /// request id — so a certificate record can be checked at replay to name a
    /// request that a genuinely earlier entry admitted from the same member
    /// *and for the same cap* (consent is to a specific amount).
    cert_requests: BTreeMap<RequestId, (Address, i64)>,
    /// Station-signed equivocation records by content address (ADR-0021 §5,
    /// T2.3.3). A faithful view of what the log records; scoring re-verifies each
    /// with [`EquivocationRecord::verify_evidence`] before acting on it, so an
    /// unverified record here is not itself a consequence.
    equivocations: BTreeMap<EquivocationId, SignedEquivocationRecord>,
    /// Dedup index: the equivocation already recorded against a certificate
    /// (cert-overspend basis). One record per certificate — repeated overspend
    /// attempts against an already-recorded cert append nothing further (the
    /// spends are still refused). A cert belongs to one member, so the cert id
    /// alone keys the `(member, cert)` dedup.
    equivocation_by_cert: BTreeMap<CertId, EquivocationId>,
    /// Dedup index: the equivocation already recorded against an author's outbox
    /// position (outbox-fork basis), keyed by `(author pubkey, position)`.
    equivocation_by_fork: BTreeMap<([u8; 32], u64), EquivocationId>,
}

impl LedgerSnapshot {
    /// Replays the whole log into a snapshot.
    pub fn derive(log: &AppendLog) -> Result<Self> {
        let mut snapshot = LedgerSnapshot::default();
        for entry in log.iter_from(1) {
            snapshot.apply(&entry?)?;
        }
        Ok(snapshot)
    }

    /// Folds one log entry into the snapshot. Unrecognized payloads (e.g.
    /// vouches written by `rrn-identity`) are ignored. Alongside each applied
    /// lifecycle record, captures the entry's admission metadata — its `seq`
    /// and `created_at` (ADR-0022) — for the transaction it advances.
    ///
    /// Returns `Err` only for a structurally impossible entry in a well-formed
    /// log — currently a headroom certificate whose request is not already on the
    /// log (ADR-0021 §1 requires request-before-certificate, and the station is
    /// the sole writer, so this can only mean a corrupted or tampered log). Every
    /// other precondition miss (a confirmation for an unknown proposal, a return
    /// of an unknown certificate) is tolerated by skipping, as before.
    fn apply(&mut self, entry: &LogEntry) -> Result<()> {
        let stored = &entry.payload;
        let bytes = &stored.bytes;

        if let Ok(proposal) = from_canonical_bytes::<TransactionProposal>(bytes) {
            let nonce_key = proposal.sender.public_key().to_bytes();
            let slot = self.max_nonce.entry(nonce_key).or_insert(proposal.nonce);
            *slot = (*slot).max(proposal.nonce);
            let id = proposal.id;
            // A cert-backed spend consumes from its certificate monotonically
            // (ADR-0021 §5): capture the link, spender, and amount before the
            // payload moves.
            let cert_spend = proposal
                .cert_id
                .map(|cid| (cid, proposal.sender, proposal.amount_centi));
            let signed = SignedProposal {
                payload: proposal,
                signer: stored.signer,
                signature: stored.signature,
            };
            self.states
                .insert(id, TransactionState::Proposed { proposal: signed });
            // A proposal opens a transaction: seed its admission metadata.
            self.admissions.insert(
                id,
                AdmissionTimes {
                    proposal_seq: entry.seq,
                    proposal_admitted_at: entry.created_at,
                    ..AdmissionTimes::default()
                },
            );
            // Consume the spend from its certificate. Monotone: a later
            // cancellation of this proposal does NOT replenish the cap (ADR-0021
            // §5 arrival-order accounting) — nothing here ever subtracts, and the
            // cancellation branch below leaves `consumed_centi` untouched, so the
            // cancelled amount stops counting as a pending debit but stays
            // consumed. Rationale: an offline receiver may already have been shown
            // the spend history; replenishing would let presented history
            // understate the member's true exposure. A cert-backed proposal is
            // only ever admitted by the engine against the signer's own
            // outstanding certificate, so in a well-formed single-writer log the
            // certificate is present, its member is the sender, and the amount is
            // positive. Replay re-checks all three anyway (re-derive, never
            // re-enforce — ADR-0018): a hostile log copy naming an unknown or
            // foreign certificate, or carrying a non-positive amount, counts
            // nothing — so consumption is unconditionally monotone (it can only
            // ever grow). An unknown-cid miss is logged for forensics.
            if let Some((cid, sender, amount_centi)) = cert_spend {
                match self.certificates.get_mut(&cid) {
                    Some(cert_state)
                        if cert_state.certificate.payload.member == sender && amount_centi > 0 =>
                    {
                        cert_state.consumed_centi =
                            cert_state.consumed_centi.saturating_add(amount_centi);
                    }
                    Some(_) => tracing::warn!(
                        cert = ?cid,
                        "cert-backed proposal at replay names a certificate whose member is not \
                         its sender, or carries a non-positive amount; counting no consumption"
                    ),
                    None => tracing::warn!(
                        cert = ?cid,
                        "cert-backed proposal names an unknown certificate at replay; \
                         counting no consumption"
                    ),
                }
            }
            return Ok(());
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
                // Capture confirmation admission only on the real transition,
                // matching the state insert above.
                if let Some(admission) = self.admissions.get_mut(&confirmation.proposal_id) {
                    admission.confirmation_seq = Some(entry.seq);
                    admission.confirmation_admitted_at = Some(entry.created_at);
                }
            }
            return Ok(());
        }

        if let Ok(dispute) = from_canonical_bytes::<DisputeRecord>(bytes) {
            // A dispute freezes a `Confirmed` transaction. Replay re-checks the
            // one structural invariant that matters for the freeze — the raiser
            // is a party — so a stranger's gossiped dispute can never freeze a
            // transaction it has no standing in.
            if let Some(TransactionState::Confirmed {
                proposal,
                confirmation,
            }) = self.states.get(&dispute.proposal_id).cloned()
            {
                let p = &proposal.payload;
                if dispute.raiser == p.sender || dispute.raiser == p.receiver {
                    let signed = SignedDispute {
                        payload: dispute.clone(),
                        signer: stored.signer,
                        signature: stored.signature,
                    };
                    self.states.insert(
                        dispute.proposal_id,
                        TransactionState::Disputed {
                            proposal,
                            confirmation,
                            dispute: Box::new(signed),
                        },
                    );
                    // Capture dispute admission only on the real transition.
                    if let Some(admission) = self.admissions.get_mut(&dispute.proposal_id) {
                        admission.dispute_seq = Some(entry.seq);
                        admission.dispute_admitted_at = Some(entry.created_at);
                    }
                }
            }
            return Ok(());
        }

        if let Ok(settlement) = from_canonical_bytes::<SettlementRecord>(bytes) {
            // A settlement closes either a `Confirmed` transaction (the normal
            // path) or a `Disputed` one whose dispute was rejected or lapsed
            // (ADR-0014 §6) — both carry the proposal and confirmation it needs.
            let prior = match self.states.get(&settlement.proposal_id).cloned() {
                Some(TransactionState::Confirmed {
                    proposal,
                    confirmation,
                })
                | Some(TransactionState::Disputed {
                    proposal,
                    confirmation,
                    ..
                }) => Some((proposal, confirmation)),
                _ => None,
            };
            if let Some((proposal, confirmation)) = prior {
                self.states.insert(
                    settlement.proposal_id,
                    TransactionState::Settled {
                        proposal,
                        confirmation,
                        settled_at: settlement.settled_at,
                    },
                );
            }
            return Ok(());
        }

        if let Ok(cancellation) = from_canonical_bytes::<CancellationRecord>(bytes) {
            // A cancellation retires a `Proposed` transaction (withdraw / reject /
            // expire) or voids a `Disputed` one whose dispute was upheld
            // (`DisputeUpheld` — ADR-0014 §6). The reason and the prior stage must
            // agree, so a stray upheld-cancellation cannot void a mere proposal
            // and an ordinary reason cannot void a dispute.
            let target = self.states.get(&cancellation.proposal_id).cloned();
            let proposal = match (&target, cancellation.reason) {
                // An upheld dispute cannot apply to a still-unconfirmed proposal.
                (Some(TransactionState::Proposed { .. }), CancelReason::DisputeUpheld) => None,
                (Some(TransactionState::Proposed { proposal }), _) => Some(proposal.clone()),
                (
                    Some(TransactionState::Disputed { proposal, .. }),
                    CancelReason::DisputeUpheld,
                ) => Some(proposal.clone()),
                _ => None,
            };
            if let Some(proposal) = proposal {
                self.states.insert(
                    cancellation.proposal_id,
                    TransactionState::Cancelled {
                        proposal,
                        cancelled_at: cancellation.cancelled_at,
                        reason: cancellation.reason,
                    },
                );
            }
            return Ok(());
        }

        // A certificate request records member consent and bumps the member's
        // shared proposal/certificate nonce (ADR-0021 §1). It reserves nothing on
        // its own — only the certificate that honors it does — so a dangling
        // request (the issuance crash window) is harmless at replay.
        if let Ok(request) = from_canonical_bytes::<CertificateRequest>(bytes) {
            let nonce_key = request.member.public_key().to_bytes();
            let slot = self.max_nonce.entry(nonce_key).or_insert(request.nonce);
            *slot = (*slot).max(request.nonce);
            self.cert_requests
                .insert(request.request_id, (request.member, request.cap_centi));
            return Ok(());
        }

        // A headroom certificate opens an Outstanding reservation. It must name a
        // request already admitted from the same member and for the same cap
        // (ADR-0021 §1) — a certificate without its request, or one that inflates
        // the consented cap, cannot exist in a well-formed single-writer log, so
        // it is a hard derive error rather than a silent skip. Signatures are
        // trusted here as everywhere in replay (the log is append-only and
        // station-written; `verify` re-checks on demand).
        if let Ok(certificate) = from_canonical_bytes::<HeadroomCertificate>(bytes) {
            match self.cert_requests.get(&certificate.request_id) {
                Some((member, cap))
                    if *member == certificate.member && *cap == certificate.cap_centi => {}
                _ => {
                    return Err(Error::Invalid(
                        "headroom certificate references an unknown or mismatched request".into(),
                    ))
                }
            }
            let signed: SignedHeadroomCertificate = SignedHeadroomCertificate {
                payload: certificate.clone(),
                signer: stored.signer,
                signature: stored.signature,
            };
            self.certificates.insert(
                certificate.cert_id,
                CertificateState {
                    certificate: signed,
                    status: CertificateStatus::Outstanding,
                    consumed_centi: 0,
                },
            );
            return Ok(());
        }

        // A certificate return retires an Outstanding certificate. Replay
        // re-checks the one structural invariant that matters — the return's
        // member is the certificate's member — so a stranger's gossiped return
        // cannot release someone else's escrow. A duplicate return keeps the
        // first (tolerated at replay; refused at the engine); a return of an
        // unknown certificate is ignored.
        if let Ok(return_record) = from_canonical_bytes::<CertificateReturn>(bytes) {
            if let Some(state) = self.certificates.get_mut(&return_record.cert_id) {
                if return_record.member == state.certificate.payload.member
                    && matches!(state.status, CertificateStatus::Outstanding)
                {
                    state.status = CertificateStatus::Returned { at_seq: entry.seq };
                }
            }
            return Ok(());
        }

        // A station-signed equivocation record (ADR-0021 §5). Replay **re-verifies
        // the evidence** before indexing it (re-derive, never re-enforce — ADR-0018):
        // a record whose embedded member-signed artifacts do not actually prove the
        // conflict is ignored entirely, so a bogus record on a hostile or
        // peer-gossiped log copy cannot reserve the one-record-per-offence dedup slot
        // (which would otherwise suppress the genuine record) nor surface through the
        // counterparty accessor. The cap for a cert-overspend is read from the
        // certificate already folded into this snapshot. The first *verifying* record
        // for a given `(member, cert)` / `(member, fork position)` wins.
        if let Ok(record) = from_canonical_bytes::<EquivocationRecord>(bytes) {
            let cap = match record.basis {
                EquivocationBasis::CertOverspend => record
                    .cert_id
                    .and_then(|c| self.certificates.get(&c))
                    .map(|c| c.certificate.payload.cap_centi),
                EquivocationBasis::OutboxFork => None,
            };
            if !record.verify_evidence(cap) {
                tracing::warn!(
                    member = ?record.member,
                    "equivocation record at replay does not verify; ignoring"
                );
                return Ok(());
            }
            let id = record.equivocation_id;
            match record.basis {
                EquivocationBasis::CertOverspend => {
                    if let Some(cert_id) = record.cert_id {
                        self.equivocation_by_cert.entry(cert_id).or_insert(id);
                    }
                }
                EquivocationBasis::OutboxFork => {
                    if let Some(position) = record.fork_position() {
                        self.equivocation_by_fork
                            .entry((record.member.public_key().to_bytes(), position))
                            .or_insert(id);
                    }
                }
            }
            self.equivocations
                .entry(id)
                .or_insert(SignedEquivocationRecord {
                    payload: record,
                    signer: stored.signer,
                    signature: stored.signature,
                });
            return Ok(());
        }

        Ok(())
    }

    /// The state of one transaction, if it appears in the log.
    pub fn get(&self, id: &TransactionId) -> Option<&TransactionState> {
        self.states.get(id)
    }

    /// The station-local admission metadata for one transaction (ADR-0022), if
    /// it appears in the log. `Some` for every transaction in the snapshot: a
    /// transaction exists only because a proposal admitted it, which seeds this.
    pub fn admission(&self, id: &TransactionId) -> Option<&AdmissionTimes> {
        self.admissions.get(id)
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

    /// The derived state of one headroom certificate, if it appears in the log
    /// (ADR-0021).
    pub fn certificate(&self, id: &CertId) -> Option<&CertificateState> {
        self.certificates.get(id)
    }

    /// Every certificate held by `member` whose status is `Outstanding`
    /// (unreturned), in content-id order, **regardless of expiry**. This is the
    /// structural set; callers that care about time reach for
    /// [`live_certs_of`](Self::live_certs_of) instead.
    pub fn outstanding_certs_of(&self, member: &Address) -> Vec<&CertificateState> {
        self.certificates
            .values()
            .filter(|c| {
                c.certificate.payload.member == *member
                    && matches!(c.status, CertificateStatus::Outstanding)
            })
            .collect()
    }

    /// Every *live* certificate held by `member` as of `now`: outstanding
    /// (unreturned) **and** still within the window in which a spend against it
    /// could be admitted ([`spend_admissible_until`](crate::escrow::spend_admissible_until)).
    ///
    /// This is the set that both reserves headroom
    /// ([`crate::credit::committed_debits_centi`]) and counts toward the issuance
    /// limit (`cert_max_outstanding`): a certificate past its admissibility
    /// boundary reserves nothing, so it must not block new issuance or appear as
    /// usable — exactly as an expired proposal stops counting (ADR-0018 point 2).
    pub fn live_certs_of(
        &self,
        member: &Address,
        now: i64,
        config: &CreditConfig,
    ) -> Vec<&CertificateState> {
        self.outstanding_certs_of(member)
            .into_iter()
            .filter(|c| now <= spend_admissible_until(&c.certificate.payload, config))
            .collect()
    }

    /// Every admitted cert-backed spend against `cert_id`, in transaction-id
    /// order — the admitted half of a cert-overspend equivocation proof. The
    /// station gathers these (plus the refused spend it holds) to build an
    /// [`EquivocationRecord`](crate::escrow::EquivocationRecord); order is
    /// deterministic (content order) so replicas assemble identical evidence.
    ///
    /// Spends in *every* state are returned, including `Cancelled`/`Disputed` — this
    /// is deliberate and matches the engine's **monotone** cert consumption (a
    /// cancellation never replenishes the cap, ADR-0021 §5), so this set equals the
    /// consumed set the overspend was measured against.
    pub fn cert_backed_spends(&self, cert_id: &CertId) -> Vec<SignedProposal> {
        self.states
            .values()
            .map(TransactionState::proposal)
            .filter(|p| p.payload.cert_id == Some(*cert_id))
            .cloned()
            .collect()
    }

    /// Whether an equivocation is already recorded against `cert_id`
    /// (cert-overspend). The station consults this before appending so a repeated
    /// overspend attempt refuses the spend without appending a second record.
    pub fn has_cert_equivocation(&self, cert_id: &CertId) -> bool {
        self.equivocation_by_cert.contains_key(cert_id)
    }

    /// Whether an equivocation is already recorded against `member`'s outbox
    /// `position` (outbox-fork). The station's per-fork dedup guard.
    pub fn has_fork_equivocation(&self, member: &Address, position: u64) -> bool {
        self.equivocation_by_fork
            .contains_key(&(member.public_key().to_bytes(), position))
    }

    /// The equivocation recorded against `cert_id`, if any — the accessor a
    /// stranded receiver uses to see the proof behind their refused cert-backed
    /// spend (the compensation question itself is out of scope; ADR-0021
    /// residual).
    pub fn equivocation_for_cert(&self, cert_id: &CertId) -> Option<&SignedEquivocationRecord> {
        self.equivocation_by_cert
            .get(cert_id)
            .and_then(|id| self.equivocations.get(id))
    }

    /// Every equivocation record on the log, in content-id order.
    pub fn equivocations(&self) -> impl Iterator<Item = &SignedEquivocationRecord> {
        self.equivocations.values()
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

    fn dispute(proposal: &SignedProposal, raiser: &Keypair) -> SignedDispute {
        let d = DisputeRecord {
            proposal_id: proposal.payload.id,
            raiser: Address::from_public_key(raiser.public_key()),
            reason: "contested".into(),
            evidence_hash: None,
            opened_at: 1_600,
        };
        SignedDispute::sign(d, raiser)
    }

    /// One representative instance of each lifecycle stage.
    fn all_stages() -> Vec<TransactionState> {
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let p = proposal(&sender, &receiver);
        let c = confirmation(&p, &receiver);
        // A party (the sender here) raises the dispute in the Disputed instance.
        let d = dispute(&p, &sender);
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
                confirmation: c.clone(),
                settled_at: 9_000,
            },
            TransactionState::Cancelled {
                proposal: p.clone(),
                cancelled_at: 9_000,
                reason: CancelReason::Expired,
            },
            TransactionState::Disputed {
                proposal: p,
                confirmation: c,
                dispute: Box::new(d),
            },
        ]
    }

    fn expected_edge(from: &TransactionState, to: &TransactionState) -> bool {
        matches!(
            (from.stage(), to.stage()),
            (Stage::Proposed, Stage::Confirmed)
                | (Stage::Proposed, Stage::Cancelled)
                | (Stage::Confirmed, Stage::Settled)
                | (Stage::Confirmed, Stage::Disputed)
                | (Stage::Disputed, Stage::Settled)
                | (Stage::Disputed, Stage::Cancelled)
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

    fn fresh_db() -> rrn_storage::db::Database {
        let db = rrn_storage::db::Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        db
    }

    #[test]
    fn snapshot_carries_admission_times() {
        let db = fresh_db();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let p = proposal(&sender, &receiver);
        let id = p.payload.id;
        let c = confirmation(&p, &receiver);

        {
            let mut log = AppendLog::new(&db);
            // Proposal admitted at 100 (seq 1), confirmation at 250 (seq 2).
            log.append(p, 100).unwrap();
            log.append(c, 250).unwrap();
        }

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        let admission = snapshot.admission(&id).expect("admission present");
        assert_eq!(admission.proposal_seq, 1);
        assert_eq!(admission.proposal_admitted_at, 100);
        assert_eq!(admission.confirmation_seq, Some(2));
        assert_eq!(admission.confirmation_admitted_at, Some(250));
        assert_eq!(admission.dispute_seq, None);
        assert_eq!(admission.dispute_admitted_at, None);
    }

    #[test]
    fn admission_times_survive_full_lifecycle() {
        let db = fresh_db();
        let station = Keypair::generate();
        let sender = Keypair::generate();
        let receiver = Keypair::generate();
        let p = proposal(&sender, &receiver);
        let id = p.payload.id;
        let c = confirmation(&p, &receiver);
        let settlement = SettlementRecord {
            proposal_id: id,
            sender: p.payload.sender,
            receiver: p.payload.receiver,
            amount_centi: p.payload.amount_centi,
            settled_at: 9_000,
        };

        {
            let mut log = AppendLog::new(&db);
            log.append(p, 100).unwrap();
            log.append(c, 250).unwrap();
            // Settlement admitted later (seq 3); it captures no admission of its
            // own — its signed `settled_at` carries the reading outward.
            log.append(
                rrn_crypto::signed::SignedPayload::sign(settlement, &station),
                9_000,
            )
            .unwrap();
        }

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert!(matches!(
            snapshot.get(&id),
            Some(TransactionState::Settled { .. })
        ));
        // Confirmation admission metadata is still reported through settlement.
        let admission = snapshot.admission(&id).expect("admission present");
        assert_eq!(admission.proposal_admitted_at, 100);
        assert_eq!(admission.confirmation_seq, Some(2));
        assert_eq!(admission.confirmation_admitted_at, Some(250));
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

    #[test]
    fn certificate_request_cert_return_replays_to_returned() {
        use rrn_crypto::signed::SignedPayload;
        let db = fresh_db();
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let member = Address::from_public_key(alice.public_key());

        let req = CertificateRequest::new(member, 500, 0, 100);
        let request_id = req.request_id;
        let cert = HeadroomCertificate::new(member, 500, request_id, 100, 100 + 604_800);
        let cert_id = cert.cert_id;
        let ret = CertificateReturn {
            member,
            cert_id,
            returned_at: 200,
        };

        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(req, &alice), 100).unwrap();
            log.append(SignedPayload::sign(cert, &station), 100)
                .unwrap();
            log.append(SignedPayload::sign(ret, &alice), 200).unwrap();
        }

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        let state = snapshot.certificate(&cert_id).expect("certificate present");
        assert!(matches!(state.status, CertificateStatus::Returned { .. }));
        // A returned certificate is not counted among the outstanding ones.
        assert!(snapshot.outstanding_certs_of(&member).is_empty());
        // The request also advanced the member's shared nonce sequence.
        assert_eq!(snapshot.next_nonce(&alice.public_key().to_bytes()), 1);
    }

    #[test]
    fn a_certificate_without_its_request_is_a_derive_error() {
        use rrn_crypto::signed::SignedPayload;
        let db = fresh_db();
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let member = Address::from_public_key(alice.public_key());

        // A certificate naming a request that was never appended: impossible in a
        // well-formed single-writer log, so replay must reject it rather than
        // silently reserve headroom against phantom consent.
        let cert = HeadroomCertificate::new(
            member,
            500,
            RequestId(rrn_crypto::hash::Hash::of(b"ghost")),
            100,
            700_000,
        );
        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(cert, &station), 100)
                .unwrap();
        }
        assert!(matches!(
            LedgerSnapshot::derive(&AppendLog::new(&db)),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn a_certificate_with_a_mismatched_cap_is_a_derive_error() {
        use rrn_crypto::signed::SignedPayload;
        let db = fresh_db();
        let (station, alice) = (Keypair::generate(), Keypair::generate());
        let member = Address::from_public_key(alice.public_key());

        // The request consents to 500, but the certificate names 999 for the same
        // request id: consent is to a specific amount, so replay rejects it.
        let req = CertificateRequest::new(member, 500, 0, 100);
        let request_id = req.request_id;
        let cert = HeadroomCertificate::new(member, 999, request_id, 100, 700_000);
        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(req, &alice), 100).unwrap();
            log.append(SignedPayload::sign(cert, &station), 100)
                .unwrap();
        }
        assert!(matches!(
            LedgerSnapshot::derive(&AppendLog::new(&db)),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn a_dangling_request_replays_cleanly_and_reserves_nothing() {
        use rrn_crypto::signed::SignedPayload;
        let db = fresh_db();
        let alice = Keypair::generate();
        let member = Address::from_public_key(alice.public_key());

        // The issuance crash window: a request landed but its certificate did not.
        let req = CertificateRequest::new(member, 500, 0, 100);
        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(req, &alice), 100).unwrap();
        }
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        // No certificate exists, so nothing is reserved…
        assert!(snapshot.outstanding_certs_of(&member).is_empty());
        assert_eq!(
            crate::credit::committed_debits_centi(
                &snapshot,
                &member,
                200,
                &crate::credit::CreditConfig::default()
            ),
            0
        );
        // …but the request still advanced the member's shared nonce sequence.
        assert_eq!(snapshot.next_nonce(&alice.public_key().to_bytes()), 1);
    }

    #[test]
    fn duplicate_and_non_owner_returns_are_tolerated_at_derive() {
        use rrn_crypto::signed::SignedPayload;
        let db = fresh_db();
        let (station, alice, mallory) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let member = Address::from_public_key(alice.public_key());

        let req = CertificateRequest::new(member, 500, 0, 100);
        let request_id = req.request_id;
        let cert = HeadroomCertificate::new(member, 500, request_id, 100, 700_000);
        let cert_id = cert.cert_id;

        // A stranger's return (member = mallory) must not flip the status; the
        // owner's first return (seq 4) wins over a duplicate (seq 5).
        let stranger_return = CertificateReturn {
            member: Address::from_public_key(mallory.public_key()),
            cert_id,
            returned_at: 150,
        };
        let first_return = CertificateReturn {
            member,
            cert_id,
            returned_at: 200,
        };
        let second_return = CertificateReturn {
            member,
            cert_id,
            returned_at: 300,
        };
        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(req, &alice), 100).unwrap(); // seq 1
            log.append(SignedPayload::sign(cert, &station), 100)
                .unwrap(); // seq 2
            log.append(SignedPayload::sign(stranger_return, &mallory), 150)
                .unwrap(); // seq 3, ignored
            log.append(SignedPayload::sign(first_return, &alice), 200)
                .unwrap(); // seq 4, wins
            log.append(SignedPayload::sign(second_return, &alice), 300)
                .unwrap(); // seq 5, ignored (already returned)
        }
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        let state = snapshot.certificate(&cert_id).expect("certificate present");
        assert!(matches!(
            state.status,
            CertificateStatus::Returned { at_seq: 4 }
        ));
    }

    #[test]
    fn replay_ignores_an_unverifiable_equivocation_record() {
        use crate::escrow::{EquivocationBasis, EquivocationRecord, EvidenceItem};
        use rrn_crypto::signed::SignedPayload;

        let db = fresh_db();
        let member = Keypair::generate();
        let station = Keypair::generate();
        let member_addr = Address::from_public_key(member.public_key());
        let cap = 500;

        // A certificate on the log so the cap can be looked up at replay.
        let cert_id = {
            let mut log = AppendLog::new(&db);
            let req = CertificateRequest::new(member_addr, cap, 0, 1_000);
            let rid = req.request_id;
            log.append(SignedPayload::sign(req, &member), 0).unwrap();
            let cert = HeadroomCertificate::new(member_addr, cap, rid, 1_000, 1_000_000);
            let cid = cert.cert_id;
            log.append(SignedPayload::sign(cert, &station), 0).unwrap();
            cid
        };
        let evidence = |amount, nonce| {
            let p =
                TransactionProposal::new(member_addr, member_addr, amount, None, nonce, 1, 9_000)
                    .with_certificate(cert_id);
            EvidenceItem::from_signed(&SignedPayload::sign(p, &member))
        };

        // A bogus record (one embedded signature tampered) is station-signed and
        // lands on the log, but does not verify.
        let mut ev = vec![evidence(300, 1), evidence(300, 2)];
        let last = ev[0].bytes.len() - 1;
        ev[0].bytes[last] ^= 0x01;
        let bogus = EquivocationRecord::new(
            member_addr,
            EquivocationBasis::CertOverspend,
            Some(cert_id),
            ev,
            7_000,
        );
        AppendLog::new(&db)
            .append(SignedPayload::sign(bogus, &station), 0)
            .unwrap();

        // Replay ignores it: it neither reserves the dedup slot nor surfaces.
        let snap = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert!(
            !snap.has_cert_equivocation(&cert_id),
            "bogus record must not reserve the slot"
        );
        assert!(snap.equivocation_for_cert(&cert_id).is_none());
        assert_eq!(snap.equivocations().count(), 0);

        // A genuine record for the same certificate is then indexed normally.
        let genuine = EquivocationRecord::new(
            member_addr,
            EquivocationBasis::CertOverspend,
            Some(cert_id),
            vec![evidence(300, 1), evidence(300, 2)],
            8_000,
        );
        AppendLog::new(&db)
            .append(SignedPayload::sign(genuine, &station), 0)
            .unwrap();
        let snap = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert!(snap.has_cert_equivocation(&cert_id));
        assert_eq!(snap.equivocations().count(), 1);
    }
}
