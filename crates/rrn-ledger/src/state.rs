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
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::{decode_kinded, from_canonical_bytes, KindedCbor};
use rrn_identity::address::Address;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};

use crate::credit::CreditConfig;
use crate::dispute::{DisputeRecord, SignedDispute, DISPUTE_KIND};
use crate::escrow::{
    spend_admissible_until, CertId, CertificateRequest, CertificateReturn, CertificateState,
    CertificateStatus, EquivocationBasis, EquivocationId, EquivocationRecord,
    EquivocationVerdictRecord, HeadroomCertificate, RequestId, SignedEquivocationRecord,
    SignedHeadroomCertificate, VerdictDecision, CERTIFICATE_KIND, CERT_REQUEST_KIND,
    CERT_RETURN_KIND, EQUIVOCATION_KIND, EQUIVOCATION_VERDICT_KIND,
};
use crate::settlement::{SettlementRecord, SETTLEMENT_KIND};
use crate::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionId,
    TransactionProposal, CONFIRMATION_KIND, PROPOSAL_KIND,
};
use crate::{Error, Result};

/// Discriminant string for a cancellation record's canonical CBOR.
pub const CANCELLATION_KIND: &str = "rrn.tx.cancellation";

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
#[derive(Debug, Default, PartialEq)]
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
    /// The terminal jury ruling on each equivocation case, once one is admitted
    /// (ADR-0025 §5–§6). An id lands here only when an
    /// [`EquivocationVerdictRecord`](crate::escrow::EquivocationVerdictRecord) is
    /// admitted whose signer is the **community station key** — so a peer-relayed
    /// member-signed verdict cannot forge a ruling (the same station-signer gate
    /// reputation scoring applies). An
    /// [`Overturn`](crate::escrow::VerdictDecision::Overturn) neutralizes the record
    /// (lifts the penalty and the issuance gate); a
    /// [`Confirm`](crate::escrow::VerdictDecision::Confirm) records finality but
    /// leaves both standing. The first station-signed ruling per id wins.
    equivocation_verdict: BTreeMap<EquivocationId, VerdictDecision>,
}

impl LedgerSnapshot {
    /// Replays the whole log into a snapshot.
    ///
    /// `station` is the community's station public key (ADR-0020: one fixed key per
    /// community). Every station-signed ledger record — settlement, cancellation,
    /// headroom certificate, equivocation, equivocation verdict — is trusted only
    /// when its envelope signer is this key; a record of one of those kinds signed
    /// by any other key is skipped during derivation, so a forged record injected
    /// via gossip `append_raw` is invisible to the ledger state (ADR-0018:
    /// replicas re-derive, and pinning *is* derivation). The caller supplies the
    /// key; a gossip read-replica deriving under its own (different) key sees no
    /// settlements/certificates/equivocations — a loud, diagnosable failure, never
    /// a silent partial (the same loud-failure replica residual the governance signer-pin already accepts, applied to balances too).
    pub fn derive(log: &AppendLog, station: &PublicKey) -> Result<Self> {
        Self::derive_to(log, u64::MAX, station)
    }

    /// Replays the log prefix `[1, max_seq]` into a snapshot — the ledger state as
    /// it stood at that log *position*.
    ///
    /// Used by position-bounded reputation scoring (T2.1.3): pinning an electorate
    /// at a log position means every derived input — settlements, confirmations,
    /// disputes — must also stop at that position, so evidence admitted later
    /// cannot leak into a pinned score however old its self-asserted timestamp is.
    /// Entries arrive in ascending `seq` (`iter_from`), so the scan stops at the
    /// first entry past the bound.
    ///
    /// `station` pins station-signed records to the community key; see
    /// [`derive`](Self::derive).
    pub fn derive_to(log: &AppendLog, max_seq: u64, station: &PublicKey) -> Result<Self> {
        let mut snapshot = LedgerSnapshot::default();
        for entry in log.iter_from(1) {
            let entry = entry?;
            if entry.seq > max_seq {
                break;
            }
            snapshot.apply(&entry, station)?;
        }
        Ok(snapshot)
    }

    /// Like [`derive_to`](Self::derive_to), but folds each entry through the
    /// pre-dispatch trial-decode path ([`apply_reference`](Self::apply_reference)).
    ///
    /// Kept only as the oracle for the `replay_dispatch_equivalence` integration
    /// test, which asserts this reproduces [`derive_to`](Self::derive_to) bit for
    /// bit over generated logs — so kind dispatch is proven to select the same
    /// record (or the same skip) as trial decoding. Not used in production.
    #[doc(hidden)]
    pub fn derive_to_reference(log: &AppendLog, max_seq: u64, station: &PublicKey) -> Result<Self> {
        let mut snapshot = LedgerSnapshot::default();
        for entry in log.iter_from(1) {
            let entry = entry?;
            if entry.seq > max_seq {
                break;
            }
            snapshot.apply_reference(&entry, station)?;
        }
        Ok(snapshot)
    }

    /// Folds one log entry into the snapshot. Unrecognized payloads (e.g.
    /// vouches written by `rrn-identity`) are ignored. Alongside each applied
    /// lifecycle record, captures the entry's admission metadata — its `seq`
    /// and `created_at` (ADR-0022) — for the transaction it advances.
    ///
    /// Returns `Err` only for a structurally impossible entry in a well-formed
    /// log — currently a *station-signed* headroom certificate whose request is not
    /// already on the log (ADR-0021 §1 requires request-before-certificate, and the
    /// station is the sole writer, so this can only mean a corrupted or tampered
    /// log). Every other precondition miss (a confirmation for an unknown proposal,
    /// a return of an unknown certificate) is tolerated by skipping, as before.
    ///
    /// `station` is the community station key. Records whose authority is "the
    /// station said so" — settlements, cancellations, headroom certificates,
    /// equivocations and their verdicts — are applied only when their envelope
    /// signer is `station`; a mismatch is skipped, so a forged station-kind record
    /// is inert (it moves no balance, reserves no headroom, occupies no dedup slot,
    /// and lifts no penalty) and the genuine record still applies.
    fn apply(&mut self, entry: &LogEntry, station: &PublicKey) -> Result<()> {
        // Parse the entry once and dispatch on the `kind` discriminator every
        // signed record carries (CLAUDE.md "Signed payloads"), instead of
        // trial-decoding each record type in turn — each of which would re-run
        // the depth pre-scan and a full dCBOR parse only to fail on its own
        // `kind` check. A malformed entry, or one with no string `kind`, is an
        // "unknown" record and skipped, exactly as trial-decoding every type and
        // matching none did. Each matched `TryFrom` still re-checks the kind, so a
        // wrong-kind payload of a known kind is rejected as before (a wrong-shape
        // payload of a known kind is skipped, not a hard error — the sole
        // hard-error path is a genuine station-signed certificate whose request is
        // absent, preserved in [`apply_certificate`](Self::apply_certificate)).
        let Ok(KindedCbor {
            kind: Some(kind),
            cbor,
        }) = decode_kinded(&entry.payload.bytes)
        else {
            return Ok(());
        };
        match kind.as_str() {
            PROPOSAL_KIND => {
                let Ok(proposal) = TransactionProposal::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_proposal(proposal, entry)
            }
            CONFIRMATION_KIND => {
                let Ok(confirmation) = TransactionConfirmation::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_confirmation(confirmation, entry)
            }
            DISPUTE_KIND => {
                let Ok(dispute) = DisputeRecord::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_dispute(dispute, entry)
            }
            SETTLEMENT_KIND => {
                let Ok(settlement) = SettlementRecord::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_settlement(settlement, entry, station)
            }
            CANCELLATION_KIND => {
                let Ok(cancellation) = CancellationRecord::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_cancellation(cancellation, entry, station)
            }
            CERT_REQUEST_KIND => {
                let Ok(request) = CertificateRequest::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_cert_request(request)
            }
            CERTIFICATE_KIND => {
                let Ok(certificate) = HeadroomCertificate::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_certificate(certificate, entry, station)
            }
            CERT_RETURN_KIND => {
                let Ok(return_record) = CertificateReturn::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_cert_return(return_record, entry)
            }
            EQUIVOCATION_KIND => {
                let Ok(record) = EquivocationRecord::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_equivocation(record, entry, station)
            }
            EQUIVOCATION_VERDICT_KIND => {
                let Ok(verdict) = EquivocationVerdictRecord::try_from(cbor) else {
                    return Ok(());
                };
                self.apply_equivocation_verdict(verdict, entry, station)
            }
            _ => Ok(()),
        }
    }

    /// Folds one log entry using **trial decoding** — the pre-dispatch path,
    /// kept only as the oracle for the `replay_dispatch_equivalence` test.
    ///
    /// It decodes each candidate record type in turn and, on the first that
    /// succeeds, folds it in via the same `apply_*` method the dispatching
    /// [`apply`](Self::apply) uses — so the two share every mutation, and the
    /// equivalence test isolates exactly what changed: whether kind dispatch
    /// selects the same record (or the same skip) as trial decoding, for any
    /// bytes. Never used in production; [`derive_to`](Self::derive_to) calls
    /// [`apply`](Self::apply).
    #[doc(hidden)]
    fn apply_reference(&mut self, entry: &LogEntry, station: &PublicKey) -> Result<()> {
        let bytes = &entry.payload.bytes;
        if let Ok(proposal) = from_canonical_bytes::<TransactionProposal>(bytes) {
            return self.apply_proposal(proposal, entry);
        }
        if let Ok(confirmation) = from_canonical_bytes::<TransactionConfirmation>(bytes) {
            return self.apply_confirmation(confirmation, entry);
        }
        if let Ok(dispute) = from_canonical_bytes::<DisputeRecord>(bytes) {
            return self.apply_dispute(dispute, entry);
        }
        if let Ok(settlement) = from_canonical_bytes::<SettlementRecord>(bytes) {
            return self.apply_settlement(settlement, entry, station);
        }
        if let Ok(cancellation) = from_canonical_bytes::<CancellationRecord>(bytes) {
            return self.apply_cancellation(cancellation, entry, station);
        }
        if let Ok(request) = from_canonical_bytes::<CertificateRequest>(bytes) {
            return self.apply_cert_request(request);
        }
        if let Ok(certificate) = from_canonical_bytes::<HeadroomCertificate>(bytes) {
            return self.apply_certificate(certificate, entry, station);
        }
        if let Ok(return_record) = from_canonical_bytes::<CertificateReturn>(bytes) {
            return self.apply_cert_return(return_record, entry);
        }
        if let Ok(record) = from_canonical_bytes::<EquivocationRecord>(bytes) {
            return self.apply_equivocation(record, entry, station);
        }
        if let Ok(verdict) = from_canonical_bytes::<EquivocationVerdictRecord>(bytes) {
            return self.apply_equivocation_verdict(verdict, entry, station);
        }
        Ok(())
    }

    /// Folds a decoded proposal (`PROPOSAL_KIND`): opens the transaction, seeds
    /// admission metadata, bumps the sender's nonce and consumes any cert-backed
    /// spend from its certificate.
    fn apply_proposal(&mut self, proposal: TransactionProposal, entry: &LogEntry) -> Result<()> {
        let stored = &entry.payload;
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
        Ok(())
    }

    /// Folds a decoded confirmation (`CONFIRMATION_KIND`): advances a `Proposed`
    /// transaction to `Confirmed` and records the confirmation's admission.
    fn apply_confirmation(
        &mut self,
        confirmation: TransactionConfirmation,
        entry: &LogEntry,
    ) -> Result<()> {
        let stored = &entry.payload;
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
        Ok(())
    }

    /// Folds a decoded dispute (`DISPUTE_KIND`): freezes a `Confirmed`
    /// transaction to `Disputed` when the raiser is a party, recording the
    /// dispute's admission.
    fn apply_dispute(&mut self, dispute: DisputeRecord, entry: &LogEntry) -> Result<()> {
        let stored = &entry.payload;
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
        Ok(())
    }

    /// Folds a decoded settlement (`SETTLEMENT_KIND`): closes a `Confirmed` (or a
    /// dispute-cleared `Disputed`) transaction to `Settled`. Station-pinned.
    fn apply_settlement(
        &mut self,
        settlement: SettlementRecord,
        entry: &LogEntry,
        station: &PublicKey,
    ) -> Result<()> {
        let stored = &entry.payload;
        // Only the community station settles (ADR-0005). A settlement record
        // signed by any other key — a forgery injected via gossip `append_raw`
        // — is skipped, so it moves no balance and the transaction stays
        // `Confirmed`, still eligible for the genuine settlement.
        if stored.signer != *station {
            return Ok(());
        }
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
        Ok(())
    }

    /// Folds a decoded cancellation (`CANCELLATION_KIND`): retires a `Proposed`
    /// transaction, or voids an upheld-dispute `Disputed` one, to `Cancelled`.
    /// Station-pinned.
    fn apply_cancellation(
        &mut self,
        cancellation: CancellationRecord,
        entry: &LogEntry,
        station: &PublicKey,
    ) -> Result<()> {
        let stored = &entry.payload;
        // The station signs cancellations (no party need be present to
        // withdraw/reject, and expiry is automatic). A cancellation signed by
        // any other key is a forgery and is skipped, leaving the state
        // unchanged.
        if stored.signer != *station {
            return Ok(());
        }
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
            (Some(TransactionState::Disputed { proposal, .. }), CancelReason::DisputeUpheld) => {
                Some(proposal.clone())
            }
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
        Ok(())
    }

    /// Folds a decoded certificate request (`CERT_REQUEST_KIND`): records member
    /// consent and bumps the member's shared proposal/certificate nonce (ADR-0021
    /// §1). It reserves nothing on its own — only the certificate that honors it
    /// does — so a dangling request (the issuance crash window) is harmless.
    fn apply_cert_request(&mut self, request: CertificateRequest) -> Result<()> {
        let nonce_key = request.member.public_key().to_bytes();
        let slot = self.max_nonce.entry(nonce_key).or_insert(request.nonce);
        *slot = (*slot).max(request.nonce);
        self.cert_requests
            .insert(request.request_id, (request.member, request.cap_centi));
        Ok(())
    }

    /// Folds a decoded headroom certificate (`CERTIFICATE_KIND`): opens an
    /// Outstanding reservation (ADR-0021 §1). Station-pinned.
    fn apply_certificate(
        &mut self,
        certificate: HeadroomCertificate,
        entry: &LogEntry,
        station: &PublicKey,
    ) -> Result<()> {
        let stored = &entry.payload;
        // A headroom certificate opens an Outstanding reservation. The station is
        // the sole issuer (ADR-0021 §1); a certificate signed by any other key is a
        // forgery injected via gossip `append_raw`, and is **skipped** — it
        // reserves nothing, so a cert-backed spend naming it is later refused
        // `UnknownCertificate`. The signer pin is checked *first*, before the
        // request-consistency invariant below: a forged-signer certificate must be
        // inert, never a hard error that would wedge replay on a hostile log copy.
        // Only for a genuine *station-signed* certificate does an unknown or
        // cap-inflating request remain a hard derive error — it must name a request
        // already admitted from the same member and for the same cap (ADR-0021 §1),
        // which cannot happen in a well-formed single-writer log.
        if stored.signer != *station {
            return Ok(());
        }
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
        Ok(())
    }

    /// Folds a decoded certificate return (`CERT_RETURN_KIND`): retires an
    /// Outstanding certificate to `Returned`. Replay re-checks the one structural
    /// invariant that matters — the return's member is the certificate's member —
    /// so a stranger's gossiped return cannot release someone else's escrow. A
    /// duplicate return keeps the first (tolerated at replay; refused at the
    /// engine); a return of an unknown certificate is ignored.
    fn apply_cert_return(
        &mut self,
        return_record: CertificateReturn,
        entry: &LogEntry,
    ) -> Result<()> {
        if let Some(state) = self.certificates.get_mut(&return_record.cert_id) {
            if return_record.member == state.certificate.payload.member
                && matches!(state.status, CertificateStatus::Outstanding)
            {
                state.status = CertificateStatus::Returned { at_seq: entry.seq };
            }
        }
        Ok(())
    }

    /// Folds a decoded equivocation record (`EQUIVOCATION_KIND`, ADR-0021 §5):
    /// indexes a station-signed, evidence-verifying record against its member.
    /// Station-pinned; the first verifying record per `(member, cert)` /
    /// `(member, fork position)` wins.
    fn apply_equivocation(
        &mut self,
        record: EquivocationRecord,
        entry: &LogEntry,
        station: &PublicKey,
    ) -> Result<()> {
        let stored = &entry.payload;
        // A station-signed equivocation record (ADR-0021 §5). The station is the
        // sole author of these records; one signed by any other key — even one
        // wrapping genuine member-signed evidence of that member's own overspend,
        // self-signed to win the first-wins dedup slot — is skipped before it can
        // occupy that slot or levy any penalty, so the station's genuine record
        // still lands and applies. Then replay **re-verifies the evidence** before
        // indexing it (re-derive, never re-enforce — ADR-0018): a genuine
        // station-signed record whose embedded member-signed artifacts do not
        // actually prove the conflict is ignored entirely, so it cannot reserve the
        // dedup slot nor surface through the counterparty accessor. The cap for a
        // cert-overspend is read from the certificate already folded into this
        // snapshot. The first station-signed, *verifying* record for a given
        // `(member, cert)` / `(member, fork position)` wins.
        if stored.signer != *station {
            return Ok(());
        }
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
        Ok(())
    }

    /// Folds a decoded equivocation verdict (`EQUIVOCATION_VERDICT_KIND`,
    /// ADR-0025 §5): records the jury's terminal ruling on a case. Only a ruling
    /// signed by the **community station key** neutralizes the record: the
    /// terminal `EquivocationVerdictRecord` is station-authored, so its signer is
    /// pinned to `station`, not to the equivocation record's own signer. A
    /// juror-cast ballot (kind `rrn.dispute.equivocation_ballot`) is a *different*
    /// record kind and never decodes here; a peer-relayed member-signed verdict —
    /// including one a member signs to overturn their own penalty — does not match
    /// the station key and is skipped, so it lifts nothing (mirrors the gate in
    /// reputation scoring). `Confirm` and a lapse touch nothing: the penalty (and
    /// this gate) simply stand. The equivocation record precedes its verdict in
    /// the single-writer log (ADR-0020), so it is already indexed when the verdict
    /// is folded.
    fn apply_equivocation_verdict(
        &mut self,
        verdict: EquivocationVerdictRecord,
        entry: &LogEntry,
        station: &PublicKey,
    ) -> Result<()> {
        let stored = &entry.payload;
        if stored.signer == *station && self.equivocations.contains_key(&verdict.equivocation_id) {
            // First station-signed ruling per id wins (the sole-writer
            // station appends at most one; dedup defends a hostile copy).
            self.equivocation_verdict
                .entry(verdict.equivocation_id)
                .or_insert(verdict.decision);
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

    /// The station-signed terminal jury ruling on `id`, if one has been admitted
    /// (ADR-0025 §5). `None` means the case is still open or has only lapsed (no
    /// jury ruling); a lapse writes nothing.
    pub fn equivocation_terminal(&self, id: &EquivocationId) -> Option<VerdictDecision> {
        self.equivocation_verdict.get(id).copied()
    }

    /// Whether `id` has been neutralized by a station-signed jury `Overturn`
    /// (ADR-0025 §5–§6). The equivocation then levies no consequence and no longer
    /// blocks issuance.
    pub fn is_equivocation_overturned(&self, id: &EquivocationId) -> bool {
        self.equivocation_terminal(id) == Some(VerdictDecision::Overturn)
    }

    /// Whether `member` currently holds a verified, un-overturned equivocation —
    /// the certificate-issuance disqualification gate (ADR-0025 §7). Every record
    /// in the snapshot already verified at replay (an unverifiable record is never
    /// indexed), so this is exactly "a proven equivocation a jury has not lifted."
    /// A `Confirm` leaves the block standing; only an `Overturn` lifts it.
    pub fn has_active_equivocation(&self, member: &Address) -> bool {
        self.equivocations.values().any(|r| {
            r.payload.member == *member
                && !self.is_equivocation_overturned(&r.payload.equivocation_id)
        })
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

    /// Precondition 1 of the kind-dispatch refactor: a record carrying a known
    /// `kind` string but the *wrong shape* for it must be **skipped** by `apply`,
    /// exactly as trial-decoding would have failed to decode it — never accepted,
    /// and never a hard error. (The one genuine hard-error path — a well-formed
    /// *station-signed* certificate whose request is absent — is a different case,
    /// covered by `a_certificate_without_its_request_is_a_derive_error`.) For each
    /// dispatched kind we append a `{ "kind": <that kind> }` map with none of the
    /// type's fields and assert derivation succeeds with an empty snapshot.
    #[test]
    fn a_known_kind_with_the_wrong_shape_is_skipped_not_accepted_or_a_hard_error() {
        let station = Keypair::generate();
        for kind in [
            PROPOSAL_KIND,
            CONFIRMATION_KIND,
            DISPUTE_KIND,
            SETTLEMENT_KIND,
            CANCELLATION_KIND,
            CERT_REQUEST_KIND,
            CERTIFICATE_KIND,
            CERT_RETURN_KIND,
            EQUIVOCATION_KIND,
            EQUIVOCATION_VERDICT_KIND,
        ] {
            let db = fresh_db();
            // A map with the kind but none of the fields the type needs — signed
            // by the station, so the station-pinned kinds pass their signer gate
            // and still reach (and fail) their `TryFrom`.
            let mut m = Map::new();
            m.insert("kind", kind);
            let bytes = to_canonical_bytes(m);
            let signature = station.sign(&bytes);
            let stored = rrn_storage::log::StoredPayload {
                bytes,
                signer: station.public_key(),
                signature,
            };
            AppendLog::new(&db).append_raw(stored, 0).unwrap();

            let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key())
                .unwrap_or_else(|e| panic!("kind {kind} must be skipped, not a hard error: {e}"));
            assert_eq!(
                snapshot,
                LedgerSnapshot::default(),
                "a wrong-shape {kind} record must leave the snapshot empty"
            );
        }
    }

    /// Precondition 1, the sharp version: a well-formed record of one kind, with
    /// its top-level `kind` **relabelled** to a different kind, must be routed
    /// identically by dispatch and by trial decode. This is the case that would
    /// expose a `TryFrom` that forgot its own `kind` check: trial decode would
    /// reach that lenient type (by field shape) while dispatch routes by the label
    /// — so `derive_to` and `derive_to_reference` would diverge. They must agree
    /// for every ordered (shape, label) pair. Station-signed so the pinned kinds
    /// clear their signer gate and actually reach their `TryFrom`.
    #[test]
    fn a_relabelled_record_is_routed_identically_by_dispatch_and_trial_decode() {
        let station = Keypair::generate();
        let a = Keypair::generate();
        let b = Keypair::generate();
        let pid = proposal(&a, &b).payload.id;

        // A well-formed record for each dispatched kind (semantic validity is
        // irrelevant here — only the field *shape* is, so a relabelled payload can
        // satisfy another type's field extraction if that type skips its kind check).
        let cert = crate::escrow::HeadroomCertificate::new(
            Address::from_public_key(a.public_key()),
            500,
            crate::escrow::CertificateRequest::new(
                Address::from_public_key(a.public_key()),
                500,
                0,
                1,
            )
            .request_id,
            1,
            1_000_000,
        );
        let equiv = crate::escrow::EquivocationRecord::new(
            Address::from_public_key(a.public_key()),
            crate::escrow::EquivocationBasis::OutboxFork,
            None,
            Vec::new(),
            1,
        );
        let well_formed: Vec<(&str, Vec<u8>)> = vec![
            (PROPOSAL_KIND, to_canonical_bytes(proposal(&a, &b).payload)),
            (
                CONFIRMATION_KIND,
                to_canonical_bytes(TransactionConfirmation {
                    proposal_id: pid,
                    confirmer: Address::from_public_key(b.public_key()),
                    confirmed_at: 1,
                }),
            ),
            (
                DISPUTE_KIND,
                to_canonical_bytes(DisputeRecord {
                    proposal_id: pid,
                    raiser: Address::from_public_key(a.public_key()),
                    reason: "x".into(),
                    evidence_hash: None,
                    opened_at: 1,
                }),
            ),
            (
                SETTLEMENT_KIND,
                to_canonical_bytes(SettlementRecord {
                    proposal_id: pid,
                    sender: Address::from_public_key(a.public_key()),
                    receiver: Address::from_public_key(b.public_key()),
                    amount_centi: 300,
                    settled_at: 1,
                }),
            ),
            (
                CANCELLATION_KIND,
                to_canonical_bytes(CancellationRecord {
                    proposal_id: pid,
                    reason: CancelReason::Expired,
                    cancelled_at: 1,
                }),
            ),
            (
                CERT_REQUEST_KIND,
                to_canonical_bytes(crate::escrow::CertificateRequest::new(
                    Address::from_public_key(a.public_key()),
                    500,
                    0,
                    1,
                )),
            ),
            (CERTIFICATE_KIND, to_canonical_bytes(cert.clone())),
            (
                CERT_RETURN_KIND,
                to_canonical_bytes(CertificateReturn {
                    member: Address::from_public_key(a.public_key()),
                    cert_id: cert.cert_id,
                    returned_at: 1,
                }),
            ),
            (EQUIVOCATION_KIND, to_canonical_bytes(equiv.clone())),
            (
                EQUIVOCATION_VERDICT_KIND,
                to_canonical_bytes(EquivocationVerdictRecord {
                    equivocation_id: equiv.equivocation_id,
                    decision: VerdictDecision::Confirm,
                    decided_at: 1,
                }),
            ),
        ];
        let kinds: Vec<&str> = well_formed.iter().map(|(k, _)| *k).collect();

        for (shape_kind, bytes) in &well_formed {
            for target in &kinds {
                // Relabel the well-formed record's `kind` to `target`.
                let cbor = rrn_crypto::serialize::checked_from_data(bytes).unwrap();
                let mut map = match cbor.into_case() {
                    CBORCase::Map(m) => m,
                    _ => unreachable!("records encode as maps"),
                };
                map.insert("kind", *target);
                let relabelled = to_canonical_bytes(map);

                let db = fresh_db();
                let signature = station.sign(&relabelled);
                AppendLog::new(&db)
                    .append_raw(
                        rrn_storage::log::StoredPayload {
                            bytes: relabelled,
                            signer: station.public_key(),
                            signature,
                        },
                        0,
                    )
                    .unwrap();
                let log = AppendLog::new(&db);
                let dispatched = LedgerSnapshot::derive(&log, &station.public_key());
                let reference =
                    LedgerSnapshot::derive_to_reference(&log, u64::MAX, &station.public_key());
                // Both paths must reach the same verdict — the same snapshot, or
                // the same hard error (a genuine station-signed certificate whose
                // request is absent, the one `Err` path, which both share via
                // `apply_certificate`). They must never split Ok vs Err.
                match (dispatched, reference) {
                    (Ok(d), Ok(r)) => assert_eq!(
                        d, r,
                        "dispatch and trial-decode disagree on a {shape_kind}-shaped record labelled {target}"
                    ),
                    (Err(_), Err(_)) => {}
                    (d, r) => panic!(
                        "dispatch and trial-decode split Ok/Err on a {shape_kind}-shaped record labelled {target}: dispatch_ok={} reference_ok={}",
                        d.is_ok(),
                        r.is_ok()
                    ),
                }
            }
        }
    }

    #[test]
    fn snapshot_carries_admission_times() {
        let db = fresh_db();
        let station = Keypair::generate();
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

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
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

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
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

        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
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
            LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()),
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
            LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn a_dangling_request_replays_cleanly_and_reserves_nothing() {
        use rrn_crypto::signed::SignedPayload;
        let db = fresh_db();
        let station = Keypair::generate();
        let alice = Keypair::generate();
        let member = Address::from_public_key(alice.public_key());

        // The issuance crash window: a request landed but its certificate did not.
        let req = CertificateRequest::new(member, 500, 0, 100);
        {
            let mut log = AppendLog::new(&db);
            log.append(SignedPayload::sign(req, &alice), 100).unwrap();
        }
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
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
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
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
        let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
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
        let snap = LedgerSnapshot::derive(&AppendLog::new(&db), &station.public_key()).unwrap();
        assert!(snap.has_cert_equivocation(&cert_id));
        assert_eq!(snap.equivocations().count(), 1);
    }
}
