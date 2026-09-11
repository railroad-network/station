//! The station-signed proposal-window attestation (ADR-0022, T2.1.3).
//!
//! A proposal's deliberation/voting window and its implementation time are
//! functions of *when the station admitted the proposal* plus the effective
//! Charter for its kind — never of the author's self-asserted `created_at`
//! (ADR-0022: party timestamps are testimony, not arithmetic). But admission time
//! is station-local and re-stamped by each replica
//! ([`rrn_storage::log::LogEntry::created_at`]), so a window derived only from
//! local admission would not agree across replicas.
//!
//! So, exactly as the ledger restates its window-bearing decisions in
//! station-signed records (ADR-0005's `SettlementRecord`, and this crate's own
//! [`crate::statute::ProposalImplemented`]), the station **attests the window** in
//! a signed [`ProposalWindow`] record appended immediately after it admits a
//! proposal. Every downstream reader — [`crate::phase`], the tally, enactment, the
//! RPC/CLI views — reads the window from this attestation, so the window is a
//! signed, replicated fact and every replica agrees (ADR-0022 §1).

use dcbor::prelude::*;
use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{Keypair, PublicKey};
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_storage::log::AppendLog;

use crate::charter::Charter;
use crate::proposal::{ProposalId, ProposalKind};

/// Discriminant in the `kind` field of a [`ProposalWindow`]'s canonical CBOR.
pub(crate) const WINDOW_KIND: &str = "rrn.gov.proposal_window";

/// Seconds in a day, for turning the Charter's day-valued windows into the
/// Unix-seconds instants a window attestation carries.
const SECONDS_PER_DAY: i64 = 86_400;

fn days_to_secs(days: u8) -> i64 {
    i64::from(days) * SECONDS_PER_DAY
}

/// The `(voting_ends_at, implementation_at)` a proposal of `kind` runs under when
/// admitted at `admitted_at`, per the effective `charter` (T2.1.3).
///
/// This is the whole of the window arithmetic, in one place, measured from the
/// **admission** clock: a statute/admin rule runs the Charter's
/// `deliberation_window_days` then its `implementation_delay_days`; an amendment
/// its `charter_deliberation_window_days`; an emergency the ordinary deliberation
/// window and takes effect the instant it passes (no delay). The author's
/// `created_at` does not enter.
pub fn window_for(charter: &Charter, kind: &ProposalKind, admitted_at: i64) -> (i64, i64) {
    let gs = &charter.governance_structure;
    let ar = &charter.amendment_rules;
    let (window_days, impl_delay_days, immediate) = match kind {
        ProposalKind::Statute | ProposalKind::AdministrativeRule { .. } => (
            gs.deliberation_window_days,
            gs.implementation_delay_days,
            false,
        ),
        ProposalKind::CharterAmendment { .. } => (
            ar.charter_deliberation_window_days,
            gs.implementation_delay_days,
            false,
        ),
        ProposalKind::Emergency { .. } => (gs.deliberation_window_days, 0, true),
    };
    let voting_ends_at = admitted_at + days_to_secs(window_days);
    let implementation_at = if immediate {
        voting_ends_at
    } else {
        voting_ends_at + days_to_secs(impl_delay_days)
    };
    (voting_ends_at, implementation_at)
}

/// A station's attestation of the window a proposal runs under, anchored on the
/// station's admission of that proposal (ADR-0022).
///
/// Station-signed on append. Its authority **is** the station's signature: the
/// admission instant it carries is station-local and re-stamped per replica
/// ([`rrn_storage::log::LogEntry::created_at`]), so a replica cannot re-derive it
/// from the author's `created_at` — the signed attestation is the only
/// replica-identical statement of the window, and every reader pins its envelope
/// signer to the community station key (T2.1.4) before believing it. Carrying
/// `charter_hash` records *which* Charter's windows were applied, so a later
/// amendment cannot appear to have moved a live proposal's window on replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalWindow {
    /// The proposal this window governs.
    pub proposal_id: ProposalId,
    /// The station's admission-clock reading for the proposal — the instant the
    /// window opens (ADR-0022).
    pub admitted_at: i64,
    /// Unix seconds the deliberation/voting window closes.
    pub voting_ends_at: i64,
    /// Unix seconds a passed proposal takes effect.
    pub implementation_at: i64,
    /// The `charter_hash` of the effective Charter whose windows were applied.
    pub charter_hash: Hash,
}

/// A [`ProposalWindow`] signed by the attesting station.
pub type SignedWindow = SignedPayload<ProposalWindow>;

/// The compressed `(voting_ends_at, implementation_at)` an
/// [`Emergency`](ProposalKind::Emergency) proposal runs under when admitted at
/// `admitted_at` **while an emergency declaration is in force** (ADR-0023 §3a): the
/// window is `emergency_window_secs` from admission and effect is immediate. This is
/// decided once, by the station, at admission, and frozen into the signed
/// [`ProposalWindow`] attestation — replay reads it back, so the compression is a
/// replicated fact, not a per-replica re-derivation (replica determinism).
pub fn compressed_emergency_window(admitted_at: i64, emergency_window_secs: i64) -> (i64, i64) {
    let voting_ends_at = admitted_at + emergency_window_secs;
    (voting_ends_at, voting_ends_at)
}

/// Builds and station-signs the window attestation for a proposal admitted at
/// `admitted_at` under `charter`.
///
/// `emergency_window_secs` is `Some` only for an [`Emergency`](ProposalKind::Emergency)
/// proposal admitted while a declaration is active (ADR-0023 §3a): the window then
/// compresses to that many seconds from admission. For every other case it is
/// `None` and the ordinary [`window_for`] windows apply — so an `Emergency` proposal
/// raised with no active declaration keeps its Phase-1 full window (ADR-0023 §1).
pub fn build_window(
    station: &Keypair,
    proposal_id: ProposalId,
    kind: &ProposalKind,
    charter: &Charter,
    admitted_at: i64,
    emergency_window_secs: Option<i64>,
) -> SignedWindow {
    let (voting_ends_at, implementation_at) = match (kind, emergency_window_secs) {
        (ProposalKind::Emergency { .. }, Some(secs)) => {
            compressed_emergency_window(admitted_at, secs)
        }
        _ => window_for(charter, kind, admitted_at),
    };
    SignedPayload::sign(
        ProposalWindow {
            proposal_id,
            admitted_at,
            voting_ends_at,
            implementation_at,
            charter_hash: charter.hash(),
        },
        station,
    )
}

/// The window attestation for `proposal_id`, if the log carries one, pinned to the
/// community `station` key. Returns the earliest in log order (the station writes
/// exactly one per proposal, on admission).
pub fn window_of(
    log: &AppendLog,
    proposal_id: &ProposalId,
    station: &PublicKey,
) -> Option<ProposalWindow> {
    window_and_seq_of(log, proposal_id, station).map(|(w, _)| w)
}

/// Like [`window_of`], but also returns the log seq of the attestation entry —
/// the proposal's replica-stable **open position** (T2.1.3).
///
/// This is the seq of the *station-signed attestation*, not of the author's
/// proposal entry: the attestation is the station's own record, so a peer that
/// pre-injects the author's proposal bytes early over gossip cannot move the open
/// position (it cannot forge the station's signature). Governance pins the
/// electorate at this seq (ADR-0022 §5, "the attestation's log seq").
///
/// An entry whose envelope signer is not the community `station` key is **skipped**
/// (T2.1.4): a forged window attestation is invisible to derivation exactly as a
/// forged member record is, so it can never open a window or move the electorate
/// pin. The first entry that both decodes *and* passes the station pin wins.
pub fn window_and_seq_of(
    log: &AppendLog,
    proposal_id: &ProposalId,
    station: &PublicKey,
) -> Option<(ProposalWindow, u64)> {
    for entry in log.iter_from(1) {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(record) = from_canonical_bytes::<ProposalWindow>(&entry.payload.bytes) else {
            continue;
        };
        if entry.payload.signer != *station {
            continue;
        }
        if record.proposal_id == *proposal_id {
            return Some((record, entry.seq));
        }
    }
    None
}

// --- Canonical CBOR ---------------------------------------------------------

impl From<ProposalWindow> for CBOR {
    fn from(r: ProposalWindow) -> Self {
        let mut m = Map::new();
        m.insert("kind", WINDOW_KIND);
        m.insert("proposal_id", r.proposal_id);
        m.insert("admitted_at", r.admitted_at);
        m.insert("voting_ends_at", r.voting_ends_at);
        m.insert("implementation_at", r.implementation_at);
        m.insert(
            "charter_hash",
            CBOR::to_byte_string(r.charter_hash.to_bytes()),
        );
        m.into()
    }
}

impl TryFrom<CBOR> for ProposalWindow {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != WINDOW_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(ProposalWindow {
            proposal_id: map.extract::<&str, ProposalId>("proposal_id")?,
            admitted_at: map.extract::<&str, i64>("admitted_at")?,
            voting_ends_at: map.extract::<&str, i64>("voting_ends_at")?,
            implementation_at: map.extract::<&str, i64>("implementation_at")?,
            charter_hash: {
                let bytes: [u8; 32] = map
                    .extract::<&str, CBOR>("charter_hash")?
                    .try_into_byte_string()?
                    .as_slice()
                    .try_into()
                    .map_err(|_| dcbor::Error::WrongType)?;
                Hash::from_bytes(bytes)
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::to_canonical_bytes;

    fn sample() -> ProposalWindow {
        ProposalWindow {
            proposal_id: ProposalId(Hash::from_bytes([7u8; 32])),
            admitted_at: 1_700_000_000,
            voting_ends_at: 1_700_000_000 + 7 * SECONDS_PER_DAY,
            implementation_at: 1_700_000_000 + 14 * SECONDS_PER_DAY,
            charter_hash: Hash::from_bytes([9u8; 32]),
        }
    }

    #[test]
    fn window_cbor_roundtrips() {
        let w = sample();
        let bytes = to_canonical_bytes(w);
        let back: ProposalWindow = from_canonical_bytes(&bytes).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        // A ProposalImplemented-shaped map must not decode as a window.
        let mut m = Map::new();
        m.insert("kind", "rrn.gov.proposal_implemented");
        m.insert("proposal_id", ProposalId(Hash::from_bytes([1u8; 32])));
        m.insert("implemented_at", 1i64);
        let cbor: CBOR = m.into();
        assert!(ProposalWindow::try_from(cbor).is_err());
    }

    #[test]
    fn window_for_measures_from_admission_not_created_at() {
        let charter = Charter {
            version: 1,
            community_id: "commons".into(),
            founding_principles: vec![],
            rights_floor: vec![],
            governance_structure: Default::default(),
            amendment_rules: Default::default(),
            created_at: 0,
            founders: vec![],
            previous_hash: None,
        };
        let admitted_at = 5_000_000;
        // Statute: 7-day window, 7-day implementation delay (defaults).
        let (ve, ia) = window_for(&charter, &ProposalKind::Statute, admitted_at);
        assert_eq!(ve, admitted_at + 7 * SECONDS_PER_DAY);
        assert_eq!(ia, admitted_at + 14 * SECONDS_PER_DAY);
        // Emergency: same window, immediate effect (no delay).
        let (eve, eia) = window_for(
            &charter,
            &ProposalKind::Emergency { expires_at: 0 },
            admitted_at,
        );
        assert_eq!(eve, admitted_at + 7 * SECONDS_PER_DAY);
        assert_eq!(eia, eve);
    }
}
