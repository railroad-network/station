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

/// The discriminant string a [`VouchKind`] encodes to.
const VOUCH_KIND_TAG: &str = "vouch";

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

/// Creates and signs a vouch from `voucher` for the `vouched` address.
///
/// `issued_at` is the current Unix time; the vouch does not expire
/// (`expires_at = None`).
pub fn create_vouch(
    voucher: &Keypair,
    vouched: &Address,
    community: &str,
    statement: &str,
    stake_centi: u64,
) -> SignedVouch {
    let vouch = Attestation {
        kind: VouchKind,
        body: VouchBody {
            community: community.to_string(),
            statement: statement.to_string(),
            reputation_stake_centi: stake_centi,
        },
        subject: *vouched,
        issued_at: now_secs(),
        expires_at: None,
    };
    vouch.sign(voucher)
}

/// Appends a signed vouch to the append-only log as the next entry.
///
/// The signature is verified before the entry is written (by the log layer); an
/// invalid vouch is never persisted.
pub fn append_vouch(log: &mut AppendLog, vouch: SignedVouch) -> rrn_storage::Result<LogEntry> {
    log.append(vouch)
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
        let entry = append_vouch(&mut log, signed.clone()).unwrap();
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
        let entry = append_vouch(&mut log, signed).unwrap();

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
