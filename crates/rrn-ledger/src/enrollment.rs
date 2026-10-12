//! Enrollment: who may go into debt (ADR-0038 Part A).
//!
//! A key may sign itself below zero only once the community has **enrolled** it.
//! Enrollment is a station-signed [`EnrollmentRecord`] on the log, appended by the
//! writer at an in-person ceremony — pairing a device, the operator's
//! `station enroll`, or the founding charter for its founders — and derived on
//! replay like every other station-signed credit record: pinned to the community
//! station key, and skipped (never a halt) when the signer is wrong or the record
//! is malformed (see [`crate::state::LedgerSnapshot`]).
//!
//! The record is **station-only**: no member device signs or verifies it, and it
//! is not a delay-tolerant routable kind, so a carried one is refused at the door
//! and a member-signed one that reaches a log by any other path fails the pin.
//!
//! `recorded_at` is the writer's admission clock when it appended the record —
//! display only. Every derivation reads the entry's log position instead
//! (ADR-0022).

use dcbor::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// The `kind` discriminator of an [`EnrollmentRecord`]'s canonical CBOR.
pub const ENROLLMENT_KIND: &str = "rrn.member.enrollment";

/// Whether a record enrolls or revokes its member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentAction {
    /// The member is enrolled from this record's position on.
    Enroll,
    /// The member's enrollment ends at this record's position.
    Revoke,
}

/// The ceremony behind an enrollment (ADR-0038 §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentBasis {
    /// A founder named by the community's root founder charter — a root of the
    /// anchoring chain of trust (ADR-0038 §11).
    Founder,
    /// The operator compared a pairing code with the member in person.
    Pairing,
    /// The operator enrolled the address directly (`station enroll`), for a
    /// member who never pairs. Every revocation carries this basis too.
    Operator,
}

impl EnrollmentAction {
    /// The CBOR text form.
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollmentAction::Enroll => "enroll",
            EnrollmentAction::Revoke => "revoke",
        }
    }
}

impl EnrollmentBasis {
    /// The CBOR text form (also the operator-socket form).
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollmentBasis::Founder => "founder",
            EnrollmentBasis::Pairing => "pairing",
            EnrollmentBasis::Operator => "operator",
        }
    }
}

impl From<EnrollmentAction> for CBOR {
    fn from(a: EnrollmentAction) -> Self {
        a.as_str().into()
    }
}

impl TryFrom<CBOR> for EnrollmentAction {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        match String::try_from(cbor)?.as_str() {
            "enroll" => Ok(EnrollmentAction::Enroll),
            "revoke" => Ok(EnrollmentAction::Revoke),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

impl From<EnrollmentBasis> for CBOR {
    fn from(b: EnrollmentBasis) -> Self {
        b.as_str().into()
    }
}

impl TryFrom<CBOR> for EnrollmentBasis {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        match String::try_from(cbor)?.as_str() {
            "founder" => Ok(EnrollmentBasis::Founder),
            "pairing" => Ok(EnrollmentBasis::Pairing),
            "operator" => Ok(EnrollmentBasis::Operator),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

/// A station-signed enrollment or revocation of one member (ADR-0038 §1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    /// The enrolled (or revoked) identity.
    pub member: Address,
    /// Enroll or revoke.
    pub action: EnrollmentAction,
    /// The ceremony behind it; a revocation always carries
    /// [`EnrollmentBasis::Operator`].
    pub basis: EnrollmentBasis,
    /// The writer's admission clock when it appended the record — display only;
    /// derivation reads the entry's log position.
    pub recorded_at: i64,
}

impl EnrollmentRecord {
    /// Whether the record is well formed: a revocation must carry the
    /// `operator` basis (only the operator revokes). A malformed record is
    /// refused at append and skipped on replay.
    pub fn validate(&self) -> Result<()> {
        if self.action == EnrollmentAction::Revoke && self.basis != EnrollmentBasis::Operator {
            return Err(Error::Invalid(
                "an enrollment revocation must carry the operator basis".to_string(),
            ));
        }
        Ok(())
    }
}

impl From<EnrollmentRecord> for CBOR {
    fn from(r: EnrollmentRecord) -> Self {
        let mut m = Map::new();
        m.insert("kind", ENROLLMENT_KIND);
        m.insert("member", r.member);
        m.insert("action", r.action);
        m.insert("basis", r.basis);
        m.insert("recorded_at", r.recorded_at);
        m.into()
    }
}

impl TryFrom<CBOR> for EnrollmentRecord {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> std::result::Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        if map.extract::<&str, String>("kind")? != ENROLLMENT_KIND {
            return Err(dcbor::Error::WrongType);
        }
        Ok(EnrollmentRecord {
            member: map.extract::<&str, Address>("member")?,
            action: map.extract::<&str, EnrollmentAction>("action")?,
            basis: map.extract::<&str, EnrollmentBasis>("basis")?,
            recorded_at: map.extract::<&str, i64>("recorded_at")?,
        })
    }
}

/// An [`EnrollmentRecord`] signed by the community station key.
pub type SignedEnrollment = SignedPayload<EnrollmentRecord>;

/// Builds and signs an enrollment record with the station key, refusing a
/// malformed one. For a writer that must land the record inside a
/// [`LogBatch`](rrn_storage::log::LogBatch) alongside another append (the
/// founders of a charter, the startup backfill); otherwise use
/// [`append_enrollment`].
pub fn sign_enrollment(
    station: &Keypair,
    member: Address,
    action: EnrollmentAction,
    basis: EnrollmentBasis,
    now: i64,
) -> Result<SignedEnrollment> {
    let record = EnrollmentRecord {
        member,
        action,
        basis,
        recorded_at: now,
    };
    record.validate()?;
    Ok(SignedPayload::sign(record, station))
}

/// Appends one station-signed enrollment record to the log. Only the writer
/// calls this; whether the record is *effective* (a re-enrollment of an enrolled
/// member is a no-op, for instance) is decided on replay, not here.
pub fn append_enrollment(
    log: &mut AppendLog,
    station: &Keypair,
    member: Address,
    action: EnrollmentAction,
    basis: EnrollmentBasis,
    now: i64,
) -> Result<LogEntry> {
    let signed = sign_enrollment(station, member, action, basis, now)?;
    Ok(log.append(signed, now)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};

    fn addr() -> Address {
        Address::from_public_key(Keypair::generate().public_key())
    }

    #[test]
    fn every_action_and_basis_round_trips() {
        for action in [EnrollmentAction::Enroll, EnrollmentAction::Revoke] {
            for basis in [
                EnrollmentBasis::Founder,
                EnrollmentBasis::Pairing,
                EnrollmentBasis::Operator,
            ] {
                let record = EnrollmentRecord {
                    member: addr(),
                    action,
                    basis,
                    recorded_at: 1_700_000_000,
                };
                let bytes = to_canonical_bytes(record.clone());
                let back: EnrollmentRecord = from_canonical_bytes(&bytes).unwrap();
                assert_eq!(back, record);
            }
        }
    }

    #[test]
    fn a_wrong_kind_does_not_decode() {
        let mut m = Map::new();
        m.insert("kind", "rrn.member.something_else");
        m.insert("member", addr());
        m.insert("action", EnrollmentAction::Enroll);
        m.insert("basis", EnrollmentBasis::Pairing);
        m.insert("recorded_at", 1_i64);
        let bytes = CBOR::from(m).to_cbor_data();
        assert!(from_canonical_bytes::<EnrollmentRecord>(&bytes).is_err());
    }

    #[test]
    fn only_an_operator_basis_revocation_is_well_formed() {
        let station = Keypair::generate();
        for basis in [EnrollmentBasis::Founder, EnrollmentBasis::Pairing] {
            assert!(sign_enrollment(&station, addr(), EnrollmentAction::Revoke, basis, 1).is_err());
        }
        assert!(sign_enrollment(
            &station,
            addr(),
            EnrollmentAction::Revoke,
            EnrollmentBasis::Operator,
            1
        )
        .is_ok());
    }
}
