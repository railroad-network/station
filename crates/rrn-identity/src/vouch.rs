//! The vouch: the first concrete [`Attestation`] type.
//!
//! A vouch is a signed statement that one key belongs to a real, known
//! individual — the social primitive the whole web-of-trust is built from. Per
//! the design doc (§6.2.2) a vouch carries the voucher (the signer), the
//! vouched-for key (the attestation `subject`), a community, a free-text
//! statement, and a reputation stake.
//!
//! # Phase 0 scope
//!
//! `community` is just a string placeholder — community identity is fleshed out
//! in Phase 1. `reputation_stake_centi` is recorded but not *enforced*: there is
//! no reputation system yet, so a stake of 0 is accepted (a UI may warn). And
//! vouches are append-only; revocation is a separate, future attestation kind,
//! not a mutation of an existing vouch.

use dcbor::prelude::*;
use rrn_crypto::keypair::Keypair;
use rrn_storage::log::{AppendLog, LogEntry};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::attestation::{Attestation, SignedAttestation};

/// Type marker identifying the vouch attestation family. Encoded as the text
/// `"vouch"` in canonical CBOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchKind;

/// The discriminant string a [`VouchKind`] encodes to — the top-level `kind` a
/// vouch attestation carries in its canonical CBOR, so a reader replaying the log
/// can dispatch on it (`rrn-reputation`) instead of trial-decoding every type.
pub const VOUCH_KIND_TAG: &str = "vouch";

/// The vouch-specific payload.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VouchBody {
    /// Community identifier (Phase 0: a placeholder string; real values arrive
    /// in Phase 1).
    pub community: String,
    /// The voucher's free-text statement about the vouched-for individual.
    pub statement: String,
    /// Reputation staked on this vouch, in centipoints (1 point = 100
    /// centipoints). Recorded but not enforced in Phase 0.
    pub reputation_stake_centi: u64,
}

/// A vouch attestation: who is vouched for (`subject`), in which community, with
/// what statement and stake.
pub type Vouch = Attestation<VouchKind, VouchBody>;

/// A [`Vouch`] signed by the voucher.
pub type SignedVouch = SignedAttestation<VouchKind, VouchBody>;

impl From<VouchKind> for CBOR {
    fn from(_: VouchKind) -> Self {
        VOUCH_KIND_TAG.into()
    }
}

impl TryFrom<CBOR> for VouchKind {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        match cbor.try_into_text()?.as_str() {
            VOUCH_KIND_TAG => Ok(VouchKind),
            _ => Err(dcbor::Error::WrongType),
        }
    }
}

impl From<VouchBody> for CBOR {
    fn from(b: VouchBody) -> Self {
        let mut m = Map::new();
        m.insert("community", b.community);
        m.insert("statement", b.statement);
        m.insert("reputation_stake_centi", b.reputation_stake_centi);
        m.into()
    }
}

impl TryFrom<CBOR> for VouchBody {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = match cbor.into_case() {
            CBORCase::Map(map) => map,
            _ => return Err(dcbor::Error::WrongType),
        };
        Ok(VouchBody {
            community: map.extract::<&str, String>("community")?,
            statement: map.extract::<&str, String>("statement")?,
            reputation_stake_centi: map.extract::<&str, u64>("reputation_stake_centi")?,
        })
    }
}

/// Why a live vouch door refused a vouch (ADR-0038 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VouchError {
    /// The vouch's `issued_at` is further from the admitting station's clock
    /// than the clock-skew tolerance, in either direction. A vouch is scored at
    /// its `issued_at`, so an unbounded one could spread a farm's credit across
    /// fictitious weeks.
    #[error("the vouch's issued_at ({issued_at}) is not within the clock-skew tolerance of the station clock ({now})")]
    IssuedAtOutOfBounds {
        /// The vouch's signed issue time.
        issued_at: i64,
        /// The admitting station's clock.
        now: i64,
    },
}

/// The live vouch doors' plausibility bound (ADR-0038 §9): a vouch's
/// `issued_at` must be within `tolerance_secs` of the admitting station's
/// clock `now`, on either side. The caller passes the ledger's clock-skew
/// tolerance; vouches are live-only, so the two-sided bound costs offline
/// members nothing.
pub fn check_issued_at(issued_at: i64, now: i64, tolerance_secs: i64) -> Result<(), VouchError> {
    if issued_at.abs_diff(now) > tolerance_secs.unsigned_abs() {
        return Err(VouchError::IssuedAtOutOfBounds { issued_at, now });
    }
    Ok(())
}

/// Creates and signs a vouch from `voucher` for the `vouched` address.
///
/// `issued_at` is the current Unix time; the vouch does not expire
/// (`expires_at = None`). A station stamps with its injected clock through
/// [`create_vouch_at`] instead, so the instant it stamps is the one it checks.
pub fn create_vouch(
    voucher: &Keypair,
    vouched: &Address,
    community: &str,
    statement: &str,
    stake_centi: u64,
) -> SignedVouch {
    create_vouch_at(
        voucher,
        vouched,
        community,
        statement,
        stake_centi,
        now_secs(),
    )
}

/// [`create_vouch`] with the issue time given rather than read from the
/// system clock.
pub fn create_vouch_at(
    voucher: &Keypair,
    vouched: &Address,
    community: &str,
    statement: &str,
    stake_centi: u64,
    issued_at: i64,
) -> SignedVouch {
    let vouch = Attestation {
        kind: VouchKind,
        body: VouchBody {
            community: community.to_string(),
            statement: statement.to_string(),
            reputation_stake_centi: stake_centi,
        },
        subject: *vouched,
        issued_at,
        expires_at: None,
    };
    vouch.sign(voucher)
}

/// Appends a signed vouch to the append-only log as the next entry.
///
/// The signature is verified before the entry is written (by the log layer); an
/// invalid vouch is never persisted. `now` is the admitting station's injected
/// clock (ADR-0022); the daemon threads it from `clock.rs`.
pub fn append_vouch(
    log: &mut AppendLog,
    vouch: SignedVouch,
    now: i64,
) -> rrn_storage::Result<LogEntry> {
    log.append(vouch, now)
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::serialize::from_canonical_bytes;
    use rrn_storage::db::Database;

    #[test]
    fn issued_at_is_bounded_on_both_sides() {
        let now = 1_000_000;
        for at in [now - 300, now, now + 300] {
            assert_eq!(check_issued_at(at, now, 300), Ok(()));
        }
        for at in [now - 301, now + 301, i64::MIN, i64::MAX] {
            assert_eq!(
                check_issued_at(at, now, 300),
                Err(VouchError::IssuedAtOutOfBounds { issued_at: at, now })
            );
        }
    }

    #[test]
    fn create_vouch_at_stamps_the_given_instant() {
        let kp = Keypair::generate();
        let subject = Address::from_public_key(Keypair::generate().public_key());
        let v = create_vouch_at(&kp, &subject, "c", "s", 0, 42);
        assert_eq!(v.payload.issued_at, 42);
    }

    fn fresh_log_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        rrn_storage::migrations::run(&db).unwrap();
        db
    }

    #[test]
    fn create_sign_append_retrieve_verify() {
        let voucher = Keypair::generate();
        let vouched = Address::from_public_key(Keypair::generate().public_key());
        let signed = create_vouch(&voucher, &vouched, "demo", "I know this person", 250);
        assert!(signed.verify().is_ok());

        let db = fresh_log_db();
        let mut log = AppendLog::new(&db);
        let entry = append_vouch(&mut log, signed.clone(), 1_000).unwrap();
        assert_eq!(entry.seq, 1);

        // Retrieve by seq and confirm the stored signature still verifies.
        let fetched = log.get(entry.seq).unwrap().unwrap();
        assert!(fetched.payload.verify().is_ok());

        // The stored bytes decode back to the original vouch.
        let decoded: Vouch = from_canonical_bytes(&fetched.payload.bytes).unwrap();
        assert_eq!(decoded, signed.payload);
        assert_eq!(decoded.subject, vouched);
        assert_eq!(decoded.body.reputation_stake_centi, 250);
    }

    #[test]
    fn tampering_with_stored_body_breaks_verification() {
        let voucher = Keypair::generate();
        let vouched = Address::from_public_key(Keypair::generate().public_key());
        let signed = create_vouch(&voucher, &vouched, "demo", "original", 0);

        let db = fresh_log_db();
        let mut log = AppendLog::new(&db);
        let entry = append_vouch(&mut log, signed, 1_000).unwrap();

        // Flip a byte in the stored payload bytes; the signature must no longer
        // verify against the altered content.
        let mut tampered = log.get(entry.seq).unwrap().unwrap().payload;
        *tampered.bytes.last_mut().unwrap() ^= 0x01;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn zero_stake_is_accepted() {
        let voucher = Keypair::generate();
        let vouched = Address::from_public_key(Keypair::generate().public_key());
        let signed = create_vouch(&voucher, &vouched, "demo", "no stake", 0);
        assert!(signed.verify().is_ok());
    }
}
