//! The receiver's offline verdict on a certificate-backed spend (ADR-0021 §3).
//!
//! One verifier, shared by every receiver surface: the mobile FFI's
//! `offline_spend_verify` decodes its envelopes and calls
//! [`verify_offline_spend`]; `rrn paper show --station … --receiver …` and
//! `rrn wallet confirm --from <voucher>` call it on a scanned `rrnspend:`
//! voucher. A receiver's offline decision therefore cannot silently differ
//! between a phone and a laptop.
//!
//! Decoding is the caller's job: this module takes typed, *unverified*
//! [`SignedPayload`]s and checks every signature itself. A history item the
//! caller could not decode is passed as `None` and is reported at the history
//! step, so a decode failure there never pre-empts an earlier verdict.
//!
//! # The clock is testimony (ADR-0022)
//!
//! Offline, the receiver's own clock is the best `now` available. A receiver
//! whose clock is behind may accept a certificate that has just expired (the
//! station applies a delivery grace beyond `expires_at`), and one whose clock is
//! ahead may decline one still valid at the station. The certificate's expiry
//! and cap bound the exposure either way (ADR-0021 §3, §6).
//!
//! # Hidden history is bounded, not prevented (ADR-0021 §3)
//!
//! A spender can withhold earlier spends from a new receiver, so
//! [`OfflineSpendVerdict::Ok`] is not a guarantee of admission. The station
//! re-checks the cumulative cap over every admitted spend and records an
//! overspend as provable equivocation (ADR-0025).

use std::collections::BTreeSet;

use rrn_crypto::keypair::PublicKey;
use rrn_identity::address::Address;

use crate::escrow::SignedHeadroomCertificate;
use crate::transaction::{SignedProposal, TransactionId};

/// The receiver's verdict on an offline certificate-backed spend.
///
/// Exactly one variant is returned. [`Ok`](Self::Ok) carries the spend amount
/// and the allowance left after it; every other variant is a typed refusal a
/// receiver can act on. [`slug`](Self::slug) names each one in machine output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineSpendVerdict {
    /// The spend verifies. `amount_centi` is what this spend debits;
    /// `remaining_centi` is the allowance left after it against the presented
    /// history (`cap − Σ history − amount`).
    Ok {
        /// The amount this spend debits, in centicommons.
        amount_centi: i64,
        /// Allowance remaining after this spend, in centicommons.
        remaining_centi: i64,
    },
    /// The certificate's signature did not verify, or was not by the station.
    BadCertificateSignature,
    /// The proposal's signature did not verify, or its signer is not its sender.
    BadProposalSignature,
    /// The certificate is for a different member than the proposal's sender.
    CertMemberMismatch,
    /// The proposal does not reference this certificate.
    CertNotReferenced,
    /// The proposal names another receiver: only that receiver can confirm it,
    /// so accepting it delivers against nothing (ADR-0021 §3).
    WrongReceiver,
    /// The spend amount is not a positive debit of the sender.
    NotADebit,
    /// The certificate had expired by the receiver's clock.
    CertExpired,
    /// The proposal itself had expired by the receiver's clock. The station
    /// judges proposal expiry before the certificate carve-out.
    ProposalExpired,
    /// The station would refuse the proposal for a payload reason independent of
    /// the certificate: an inverted window, an over-long memo, or an oracle tier
    /// above what the phase serves.
    ProposalInadmissible,
    /// The spend exceeds the allowance left against the presented history.
    Overspent {
        /// Allowance available before this spend (`cap − Σ history`).
        available_centi: i64,
        /// The amount this spend attempted.
        attempted_centi: i64,
    },
    /// A presented-history entry was undecodable, not signed by the member, did
    /// not reference this certificate, or was not a positive debit.
    MalformedHistory,
}

impl OfflineSpendVerdict {
    /// The stable machine name of this verdict, as `paper show` and
    /// `wallet confirm` print it.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::BadCertificateSignature => "bad-certificate-signature",
            Self::BadProposalSignature => "bad-proposal-signature",
            Self::CertMemberMismatch => "cert-member-mismatch",
            Self::CertNotReferenced => "cert-not-referenced",
            Self::WrongReceiver => "wrong-receiver",
            Self::NotADebit => "not-a-debit",
            Self::CertExpired => "cert-expired",
            Self::ProposalExpired => "proposal-expired",
            Self::ProposalInadmissible => "proposal-inadmissible",
            Self::Overspent { .. } => "overspent",
            Self::MalformedHistory => "malformed-history",
        }
    }
}

/// Whether `cert` verifies and was signed by `station` — the first check of
/// [`verify_offline_spend`], exposed so a caller that must report a decode
/// failure *after* it (the FFI's malformed-proposal case) keeps the same order.
pub fn certificate_signed_by(cert: &SignedHeadroomCertificate, station: &PublicKey) -> bool {
    &cert.signer == station && cert.verify().is_ok()
}

/// Verifies a counterparty's certificate and a cert-backed spend against it,
/// entirely offline — the ADR-0021 §3 receiver ritual.
///
/// Checks, in order: the certificate is signed by `station`; the proposal is
/// signed by its own sender; the certificate is for the sender; the proposal
/// references this certificate; the spend is addressed to `receiver`; the amount
/// is a positive debit; the proposal would not be refused for a payload reason
/// the station judges before the certificate carve-out (window, memo, tier); the
/// proposal and then the certificate are unexpired at `now`; every history entry
/// decoded (`Some`), is signed by the member, references this certificate and is
/// a positive debit; and the amount fits the allowance left (`cap − Σ` distinct
/// history). A copy of the current proposal in the history is not counted
/// against itself.
pub fn verify_offline_spend(
    cert: &SignedHeadroomCertificate,
    proposal: &SignedProposal,
    history: &[Option<SignedProposal>],
    receiver: &Address,
    station: &PublicKey,
    now: i64,
) -> OfflineSpendVerdict {
    use OfflineSpendVerdict::*;

    if !certificate_signed_by(cert, station) {
        return BadCertificateSignature;
    }
    let c = &cert.payload;

    // The proposal must be signed by its own sender — otherwise anyone could
    // author a debit against the certificate holder.
    if &proposal.signer != proposal.payload.sender.public_key() || proposal.verify().is_err() {
        return BadProposalSignature;
    }
    let p = &proposal.payload;

    if c.member != p.sender {
        return CertMemberMismatch;
    }
    if p.cert_id != Some(c.cert_id) {
        return CertNotReferenced;
    }
    // The station requires confirmer == receiver, so a spend naming someone else
    // is worthless to this receiver.
    if &p.receiver != receiver {
        return WrongReceiver;
    }
    if p.amount_centi <= 0 {
        return NotADebit;
    }
    // Mirror the station's payload-only proposal refusals, which it judges
    // *before* the certificate carve-out (`Engine::submit_proposal`): an `Ok`
    // here would have the receiver deliver against a spend the station declines.
    if p.proposed_at > p.expires_at
        || !p.memo_within_bounds()
        || !crate::tier::is_phase1_serviceable(p.effective_tier())
    {
        return ProposalInadmissible;
    }
    if now > p.expires_at {
        return ProposalExpired;
    }
    if now > c.expires_at {
        return CertExpired;
    }

    let mut seen: BTreeSet<TransactionId> = BTreeSet::new();
    seen.insert(p.id);
    let mut spent: i64 = 0;
    for item in history {
        let Some(h) = item else {
            return MalformedHistory;
        };
        if &h.signer != h.payload.sender.public_key() || h.verify().is_err() {
            return MalformedHistory;
        }
        let hp = &h.payload;
        if hp.sender != c.member || hp.cert_id != Some(c.cert_id) || hp.amount_centi <= 0 {
            return MalformedHistory;
        }
        // A repeated presentation of the same spend is not new consumption.
        if seen.insert(hp.id) {
            spent = spent.saturating_add(hp.amount_centi);
        }
    }

    let available = c.cap_centi.saturating_sub(spent);
    if p.amount_centi > available {
        return Overspent {
            available_centi: available,
            attempted_centi: p.amount_centi,
        };
    }
    Ok {
        amount_centi: p.amount_centi,
        remaining_centi: available.saturating_sub(p.amount_centi),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escrow::{CertId, HeadroomCertificate, RequestId};
    use crate::transaction::TransactionProposal;
    use rrn_crypto::hash::Hash;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;

    struct Scene {
        station: Keypair,
        member: Keypair,
        receiver: Address,
        cert: SignedHeadroomCertificate,
    }

    fn scene() -> Scene {
        let station = Keypair::generate();
        let member = Keypair::generate();
        let receiver = Address::from_public_key(Keypair::generate().public_key());
        let cert = HeadroomCertificate::new(
            Address::from_public_key(member.public_key()),
            1_000,
            RequestId(Hash::of(b"req")),
            100,
            5_000,
        );
        let cert = SignedPayload::sign(cert, &station);
        Scene {
            station,
            member,
            receiver,
            cert,
        }
    }

    impl Scene {
        fn spend(&self, amount: i64, nonce: u64) -> SignedProposal {
            self.spend_against(self.cert.payload.cert_id, amount, nonce)
        }

        fn spend_against(&self, cert: CertId, amount: i64, nonce: u64) -> SignedProposal {
            let p = TransactionProposal::new(
                Address::from_public_key(self.member.public_key()),
                self.receiver,
                amount,
                None,
                nonce,
                1_000,
                9_000,
            )
            .with_certificate(cert);
            SignedPayload::sign(p, &self.member)
        }

        fn verify(
            &self,
            p: &SignedProposal,
            history: &[Option<SignedProposal>],
            now: i64,
        ) -> OfflineSpendVerdict {
            verify_offline_spend(
                &self.cert,
                p,
                history,
                &self.receiver,
                &self.station.public_key(),
                now,
            )
        }
    }

    #[test]
    fn ok_reports_amount_and_remaining() {
        let s = scene();
        let v = s.verify(&s.spend(200, 1), &[Some(s.spend(300, 0))], 1_000);
        assert_eq!(
            v,
            OfflineSpendVerdict::Ok {
                amount_centi: 200,
                remaining_centi: 500
            }
        );
        assert_eq!(v.slug(), "ok");
    }

    #[test]
    fn wrong_receiver() {
        let s = scene();
        let stranger = Address::from_public_key(Keypair::generate().public_key());
        let v = verify_offline_spend(
            &s.cert,
            &s.spend(200, 0),
            &[],
            &stranger,
            &s.station.public_key(),
            1_000,
        );
        assert_eq!(v, OfflineSpendVerdict::WrongReceiver);
        assert_eq!(v.slug(), "wrong-receiver");
    }

    #[test]
    fn overspent() {
        let s = scene();
        let v = s.verify(&s.spend(300, 1), &[Some(s.spend(800, 0))], 1_000);
        assert_eq!(
            v,
            OfflineSpendVerdict::Overspent {
                available_centi: 200,
                attempted_centi: 300
            }
        );
        assert_eq!(v.slug(), "overspent");
    }

    #[test]
    fn bad_certificate_signature() {
        let s = scene();
        let attacker = Keypair::generate();
        let v = verify_offline_spend(
            &s.cert,
            &s.spend(200, 0),
            &[],
            &s.receiver,
            &attacker.public_key(),
            1_000,
        );
        assert_eq!(v, OfflineSpendVerdict::BadCertificateSignature);
        assert_eq!(v.slug(), "bad-certificate-signature");
    }

    #[test]
    fn an_undecodable_history_item_does_not_preempt_an_earlier_verdict() {
        // The certificate expires at 5_000; at 6_000 the cert-expiry step comes
        // before the history step, so a `None` item is never reached.
        let s = scene();
        let v = s.verify(&s.spend(200, 1), &[None], 6_000);
        assert_eq!(v, OfflineSpendVerdict::CertExpired);
        assert_eq!(v.slug(), "cert-expired");
    }

    #[test]
    fn an_undecodable_history_item_is_malformed_history() {
        let s = scene();
        let v = s.verify(&s.spend(200, 1), &[Some(s.spend(100, 0)), None], 1_000);
        assert_eq!(v, OfflineSpendVerdict::MalformedHistory);
        assert_eq!(v.slug(), "malformed-history");
    }

    #[test]
    fn slugs_are_distinct() {
        let all = [
            OfflineSpendVerdict::Ok {
                amount_centi: 0,
                remaining_centi: 0,
            },
            OfflineSpendVerdict::BadCertificateSignature,
            OfflineSpendVerdict::BadProposalSignature,
            OfflineSpendVerdict::CertMemberMismatch,
            OfflineSpendVerdict::CertNotReferenced,
            OfflineSpendVerdict::WrongReceiver,
            OfflineSpendVerdict::NotADebit,
            OfflineSpendVerdict::CertExpired,
            OfflineSpendVerdict::ProposalExpired,
            OfflineSpendVerdict::ProposalInadmissible,
            OfflineSpendVerdict::Overspent {
                available_centi: 0,
                attempted_centi: 0,
            },
            OfflineSpendVerdict::MalformedHistory,
        ];
        let slugs: BTreeSet<&str> = all.iter().map(|v| v.slug()).collect();
        assert_eq!(slugs.len(), all.len());
    }
}
