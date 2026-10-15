//! Opening a record the station served by content id, before signing over it.
//!
//! The phone confirms, rules on, votes on and co-signs records by their content
//! id. It must not sign over an id on the strength of a station-rendered row:
//! [`signed_record_open`] takes the verbatim parts the station's `signed_record`
//! read returns — the record `kind`, its canonical `body`, the `signer` and the
//! `signature` — and the id the phone is about to sign over, and returns the
//! record's fields only if the body hashes to that id, decodes as that kind,
//! carries a valid signature, and is signed by its own author. The UI renders
//! from the returned fields, never from the station's JSON.
//!
//! No verification logic of its own: a transaction proposal opens through
//! `rrn_ledger::transaction::open_signed_proposal`, the helper `rrn wallet
//! confirm` uses; a governance proposal through the same four checks over
//! `rrn-governance`'s record type.

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::{PublicKey, Signature};
use rrn_governance::proposal::{Proposal, ProposalKind};
use rrn_ledger::transaction::{self, OpenProposalError, TransactionId, PROPOSAL_KIND};

/// The governance proposal kind the station's `signed_record` read serves.
const GOV_PROPOSAL_KIND: &str = "rrn.gov.proposal";

/// Why [`signed_record_open`] refused a served record. Flat, like the other
/// FFI error enums; variants follow the order the checks run.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// `kind` is not one of the two kinds the station serves.
    #[error("unknown record kind")]
    UnknownKind,
    /// The body does not hash to the expected id (or the id is not 32 bytes).
    #[error("the record does not hash to the expected id")]
    IdMismatch,
    /// The body is not a canonical record of the stated kind.
    #[error("malformed record")]
    Malformed,
    /// The signature does not verify over the body (or the key or signature is
    /// not well-formed).
    #[error("the record's signature does not verify")]
    BadSignature,
    /// A transaction proposal not signed by its sender.
    #[error("the proposal is not signed by its sender")]
    SignerNotSender,
    /// A governance proposal not signed by its author.
    #[error("the proposal is not signed by its author")]
    SignerNotAuthor,
}

impl From<OpenProposalError> for RecordError {
    fn from(e: OpenProposalError) -> Self {
        match e {
            OpenProposalError::IdMismatch => RecordError::IdMismatch,
            OpenProposalError::Malformed => RecordError::Malformed,
            OpenProposalError::BadSignature => RecordError::BadSignature,
            OpenProposalError::SignerNotSender => RecordError::SignerNotSender,
        }
    }
}

/// A verified record's display fields. Addresses are `rrn1…` strings, ids and
/// hashes are 64-char lowercase hex, amounts are signed centicommons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedRecord {
    /// A transaction proposal (`rrn.tx.proposal`). A negative `amount_centi`
    /// is a payment request: confirming it debits the receiver (ADR-0018).
    TransactionProposal {
        /// The transaction id (the hash of the body).
        id: String,
        /// The proposer, who signed it.
        sender: String,
        /// The party who must confirm it.
        receiver: String,
        /// Signed centicommons; positive = sender pays receiver.
        amount_centi: i64,
        /// The sender's note, if any.
        memo: Option<String>,
        /// The marketplace listing it settles, as hex, if any.
        listing_id: Option<String>,
        /// The headroom certificate it draws against, as hex, if any.
        cert_id: Option<String>,
        /// The oracle tier that governs it (amount floor or opt-up).
        effective_tier: u8,
        /// The sender's nonce.
        nonce: u64,
        /// The sender's clock at proposal — testimony (ADR-0022).
        proposed_at: i64,
        /// When the proposal stops being confirmable.
        expires_at: i64,
    },
    /// A governance proposal (`rrn.gov.proposal`). Its voting window is not
    /// part of the signed record (it runs from the station's admission,
    /// ADR-0022) and so is not here; read it from the `governance_proposal`
    /// view.
    GovernanceProposal {
        /// The proposal id (the hash of the body).
        id: String,
        /// The member who authored and signed it.
        author: String,
        /// Its title.
        title: String,
        /// Its full text.
        body: String,
        /// `statute`, `administrative_rule`, `charter_amendment` or `emergency`.
        kind: String,
        /// The scope label of an administrative rule.
        scope: Option<String>,
        /// When an emergency measure lapses.
        emergency_expires_at: Option<i64>,
        /// The author's clock at creation — testimony (ADR-0022).
        created_at: i64,
    },
}

/// Opens a record served by the station's `signed_record` read, verifying it
/// against `expected_id` — the id the caller is about to sign over. Checks, in
/// order: the kind is served; the body hashes to `expected_id`; the body is a
/// canonical record of that kind; the signature verifies over the body; the
/// signer is the record's sender (a transaction proposal) or author (a
/// governance proposal).
pub fn signed_record_open(
    kind: String,
    body: Vec<u8>,
    signer: Vec<u8>,
    signature: Vec<u8>,
    expected_id: Vec<u8>,
) -> Result<VerifiedRecord, RecordError> {
    if kind != PROPOSAL_KIND && kind != GOV_PROPOSAL_KIND {
        return Err(RecordError::UnknownKind);
    }
    let expected: [u8; 32] = expected_id
        .as_slice()
        .try_into()
        .map_err(|_| RecordError::IdMismatch)?;
    let expected = Hash::from_bytes(expected);
    if Hash::of(&body) != expected {
        return Err(RecordError::IdMismatch);
    }
    // A key or signature of the wrong shape cannot verify anything.
    let signer = <[u8; 32]>::try_from(signer.as_slice())
        .ok()
        .and_then(|b| PublicKey::from_bytes(b).ok());
    let signature = <[u8; 64]>::try_from(signature.as_slice())
        .ok()
        .and_then(|b| Signature::from_bytes(b).ok());

    if kind == PROPOSAL_KIND {
        // Hash, shape, then signature: a malformed body is reported as such
        // even when the key or signature is malformed too.
        let (Some(signer), Some(signature)) = (signer, signature) else {
            return match rrn_crypto::serialize::from_canonical_bytes_if_kind::<
                rrn_ledger::transaction::TransactionProposal,
            >(&body, PROPOSAL_KIND)
            {
                Ok(Some(p)) if p.id.0 == expected => Err(RecordError::BadSignature),
                _ => Err(RecordError::Malformed),
            };
        };
        let opened = transaction::open_signed_proposal(
            &signer,
            &signature,
            &body,
            &TransactionId(expected),
        )?;
        let p = opened.payload;
        return Ok(VerifiedRecord::TransactionProposal {
            id: hex::encode(p.id.to_bytes()),
            sender: p.sender.to_string(),
            receiver: p.receiver.to_string(),
            amount_centi: p.amount_centi,
            memo: p.memo.clone(),
            listing_id: p.listing_id.map(|l| hex::encode(l.0)),
            cert_id: p.cert_id.map(|c| hex::encode(c.0.to_bytes())),
            effective_tier: p.effective_tier(),
            nonce: p.nonce,
            proposed_at: p.proposed_at,
            expires_at: p.expires_at,
        });
    }

    let proposal: Proposal =
        match rrn_crypto::serialize::from_canonical_bytes_if_kind(&body, GOV_PROPOSAL_KIND) {
            Ok(Some(p)) => p,
            _ => return Err(RecordError::Malformed),
        };
    if proposal.proposal_id.0 != expected {
        return Err(RecordError::Malformed);
    }
    let (Some(signer), Some(signature)) = (signer, signature) else {
        return Err(RecordError::BadSignature);
    };
    if signer.verify(&body, &signature).is_err() {
        return Err(RecordError::BadSignature);
    }
    if &signer != proposal.author.public_key() {
        return Err(RecordError::SignerNotAuthor);
    }
    let (kind, scope, emergency_expires_at) = match &proposal.kind {
        ProposalKind::Statute => ("statute", None, None),
        ProposalKind::AdministrativeRule { scope } => {
            ("administrative_rule", Some(scope.clone()), None)
        }
        ProposalKind::CharterAmendment { .. } => ("charter_amendment", None, None),
        ProposalKind::Emergency { expires_at } => ("emergency", None, Some(*expires_at)),
    };
    Ok(VerifiedRecord::GovernanceProposal {
        id: hex::encode(proposal.proposal_id.0.to_bytes()),
        author: proposal.author.to_string(),
        title: proposal.title,
        body: proposal.body,
        kind: kind.to_string(),
        scope,
        emergency_expires_at,
        created_at: proposal.created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::serialize::to_canonical_bytes;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::address::Address;
    use rrn_ledger::transaction::TransactionProposal;

    /// Parts as the `signed_record` read serves them: (body, signer, sig, id).
    type Served = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    fn served<T: Clone + Into<dcbor::CBOR>>(signed: SignedPayload<T>) -> Served {
        let body = to_canonical_bytes(signed.payload);
        let id = Hash::of(&body).to_bytes().to_vec();
        (
            body,
            signed.signer.to_bytes().to_vec(),
            signed.signature.to_bytes().to_vec(),
            id,
        )
    }

    fn tx(sender: &Keypair, amount: i64) -> Served {
        let p = TransactionProposal::new(
            Address::from_public_key(sender.public_key()),
            Address::from_public_key(Keypair::generate().public_key()),
            amount,
            Some("seedlings".into()),
            7,
            1_000,
            2_000,
        );
        served(SignedPayload::sign(p, sender))
    }

    fn gov(author: &Keypair, kind: ProposalKind) -> Served {
        let p = Proposal::new(
            Address::from_public_key(author.public_key()),
            "Quiet hours".into(),
            "No generators after ten.".into(),
            kind,
            1_000,
        )
        .unwrap();
        served(SignedPayload::sign(p, author))
    }

    fn open(kind: &str, s: Served) -> Result<VerifiedRecord, RecordError> {
        signed_record_open(kind.into(), s.0, s.1, s.2, s.3)
    }

    #[test]
    fn a_transaction_proposal_round_trips() {
        let sender = Keypair::generate();
        let s = tx(&sender, -500);
        let id_hex = hex::encode(&s.3);
        match open("rrn.tx.proposal", s).unwrap() {
            VerifiedRecord::TransactionProposal {
                id,
                sender: from,
                amount_centi,
                memo,
                listing_id,
                cert_id,
                effective_tier,
                nonce,
                expires_at,
                ..
            } => {
                assert_eq!(id, id_hex);
                assert_eq!(
                    from,
                    Address::from_public_key(sender.public_key()).to_string()
                );
                assert_eq!(amount_centi, -500);
                assert_eq!(memo.as_deref(), Some("seedlings"));
                assert_eq!((listing_id, cert_id), (None, None));
                assert_eq!(effective_tier, 2, "5.00 is a Tier-2 amount");
                assert_eq!((nonce, expires_at), (7, 2_000));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn a_governance_proposal_round_trips() {
        let author = Keypair::generate();
        let s = gov(
            &author,
            ProposalKind::AdministrativeRule {
                scope: "tool library".into(),
            },
        );
        let id_hex = hex::encode(&s.3);
        match open("rrn.gov.proposal", s).unwrap() {
            VerifiedRecord::GovernanceProposal {
                id,
                author: by,
                title,
                kind,
                scope,
                emergency_expires_at,
                created_at,
                ..
            } => {
                assert_eq!(id, id_hex);
                assert_eq!(
                    by,
                    Address::from_public_key(author.public_key()).to_string()
                );
                assert_eq!(title, "Quiet hours");
                assert_eq!(kind, "administrative_rule");
                assert_eq!(scope.as_deref(), Some("tool library"));
                assert_eq!(emergency_expires_at, None);
                assert_eq!(created_at, 1_000);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let s = tx(&Keypair::generate(), 100);
        assert!(matches!(
            open("rrn.tx.confirmation", s),
            Err(RecordError::UnknownKind)
        ));
    }

    #[test]
    fn a_body_that_does_not_hash_to_the_id_is_refused() {
        let mut s = tx(&Keypair::generate(), 100);
        s.3 = vec![0x11; 32];
        assert!(matches!(
            open("rrn.tx.proposal", s),
            Err(RecordError::IdMismatch)
        ));
    }

    #[test]
    fn a_record_of_the_other_kind_is_malformed() {
        // A governance proposal's bytes, presented as a transaction proposal.
        let s = gov(&Keypair::generate(), ProposalKind::Statute);
        assert!(matches!(
            open("rrn.tx.proposal", s),
            Err(RecordError::Malformed)
        ));
    }

    #[test]
    fn a_bad_signature_is_refused() {
        let mut s = gov(&Keypair::generate(), ProposalKind::Statute);
        s.2[0] ^= 0x01;
        assert!(matches!(
            open("rrn.gov.proposal", s),
            Err(RecordError::BadSignature)
        ));
    }

    #[test]
    fn a_proposal_signed_by_another_key_is_refused() {
        // Valid signatures over the right bytes, by someone other than the
        // sender / author.
        let impostor = Keypair::generate();
        let mut s = tx(&Keypair::generate(), 100);
        s.1 = impostor.public_key().to_bytes().to_vec();
        s.2 = impostor.sign(&s.0).to_bytes().to_vec();
        assert!(matches!(
            open("rrn.tx.proposal", s),
            Err(RecordError::SignerNotSender)
        ));

        let mut s = gov(&Keypair::generate(), ProposalKind::Statute);
        s.1 = impostor.public_key().to_bytes().to_vec();
        s.2 = impostor.sign(&s.0).to_bytes().to_vec();
        assert!(matches!(
            open("rrn.gov.proposal", s),
            Err(RecordError::SignerNotAuthor)
        ));
    }
}
