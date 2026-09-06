//! Escrowed offline spending for the mobile client (T2.4.2, ADR-0021).
//!
//! Thin marshalling over `rrn-ledger`'s escrow and transaction types so the app
//! can request a headroom certificate, read a certificate it holds, sign a
//! cert-backed spend, and — the security-critical one — **verify a
//! counterparty's certificate and spend entirely offline** ([`offline_spend_verify`],
//! ADR-0021 §3). No cryptographic logic of its own: every check delegates to the
//! same `rrn-crypto` / `rrn-ledger` code the station runs, so a receiver's
//! offline decision and the station's later admission cannot silently disagree.
//!
//! Signed records cross as the portable `{signer, sig, body}` envelope
//! ([`crate::envelope`]) — the same framing the DTN surface uses — and the
//! signing secret never leaves Rust ([`Keypair`](crate::Keypair) handles only,
//! ADR-0006).

use std::collections::BTreeSet;
use std::sync::Arc;

use rrn_crypto::hash::Hash;
use rrn_crypto::keypair::PublicKey;
use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_ledger::escrow::{CertId, CertificateRequest, HeadroomCertificate};
use rrn_ledger::transaction::{TransactionId, TransactionProposal};

use crate::envelope::{self, DecodedEnvelope};
use crate::Keypair;

/// Error surfaced across the FFI boundary for the fallible certificate
/// operations. Flat and coarse, like the other FFI error enums.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// A receiver address string was not a valid `rrn1…` address.
    #[error("invalid address")]
    InvalidAddress,
    /// A certificate id was not exactly 32 bytes.
    #[error("invalid certificate id")]
    InvalidCertId,
    /// A supplied public key was not 32 valid bytes.
    #[error("invalid public key")]
    InvalidKey,
    /// The certificate envelope was not well-formed canonical dCBOR of a
    /// certificate.
    #[error("malformed certificate")]
    MalformedCertificate,
    /// The certificate's station signature did not verify, or was not by the
    /// expected station key.
    #[error("station signature does not verify")]
    StationSignatureInvalid,
}

/// Signs a member's request for a headroom certificate (ADR-0021 §1), returning
/// it as portable `{signer, sig, body}` envelope bytes.
///
/// `cap_centi` is the reservation the member asks the station to escrow, and
/// `nonce` shares the member's proposal-nonce sequence (the station rejects a gap
/// or duplicate at issuance). The member's address is taken from `member` — the
/// request is signed by, and for, the same key. This only builds the signed
/// request; issuance happens at the station's front door while connected.
pub fn certificate_request_sign(
    member: Arc<Keypair>,
    cap_centi: i64,
    nonce: u64,
    requested_at: i64,
) -> Vec<u8> {
    let member_address = Address::from_public_key(member.core().public_key());
    let request = CertificateRequest::new(member_address, cap_centi, nonce, requested_at);
    let signed = SignedPayload::sign(request, member.core());
    envelope::encode(
        &signed.signer,
        &signed.signature,
        to_canonical_bytes(signed.payload),
    )
}

/// Non-secret description of a headroom certificate, for a cert-wallet UI.
pub struct CertificateInfo {
    /// The `rrn1…` address of the member the certificate is for.
    pub member: String,
    /// The reserved cap, in centicommons.
    pub cap_centi: i64,
    /// The admission-clock reading at issuance (Unix seconds).
    pub issued_at: i64,
    /// When the certificate expires (Unix seconds) — the receiver-side validity
    /// boundary [`offline_spend_verify`] checks.
    pub expires_at: i64,
    /// The certificate's content id, hex — what a cert-backed proposal references.
    pub cert_id: String,
}

/// Parses a station-signed headroom certificate, verifying the station
/// signature, and returns its non-secret fields (T2.4.2, ADR-0021 §1).
///
/// `expected_station_pubkey` is the 32-byte key of the member's paired station:
/// the certificate must be signed by it, else [`StationSignatureInvalid`](CertError::StationSignatureInvalid).
pub fn certificate_parse(
    cert_envelope_bytes: Vec<u8>,
    expected_station_pubkey: Vec<u8>,
) -> Result<CertificateInfo, CertError> {
    let expected = parse_pubkey(&expected_station_pubkey).ok_or(CertError::InvalidKey)?;
    let signed = decode_certificate(&cert_envelope_bytes).ok_or(CertError::MalformedCertificate)?;
    if signed.signer != expected || signed.verify().is_err() {
        return Err(CertError::StationSignatureInvalid);
    }
    let cert = &signed.payload;
    Ok(CertificateInfo {
        member: cert.member.to_string(),
        cap_centi: cert.cap_centi,
        issued_at: cert.issued_at,
        expires_at: cert.expires_at,
        cert_id: hex::encode(cert.cert_id.to_bytes()),
    })
}

/// Signs a cert-backed offline spend against `cert_id` (ADR-0021 §3), returning
/// it as portable `{signer, sig, body}` envelope bytes — the exact bytes a
/// receiver passes to [`offline_spend_verify`] and that
/// [`outbox_next_entry`](crate::outbox_next_entry) later wraps for submission.
///
/// This is the cert-backed sibling of the app's ordinary proposal-signing path
/// (which builds a proposal value with `canonical_bytes` and signs it with
/// `Keypair::sign`); it exists so a cert-backed proposal is byte-identical to the
/// station's `TransactionProposal` encoding without the app hand-assembling the
/// `cert_id` field. `amount_centi` must be a positive debit of the sender for the
/// spend to be admissible — the receiver's [`offline_spend_verify`] and the
/// station both refuse a non-positive cert-backed amount; this signer does not
/// pre-check it.
///
/// **`expires_at` must accommodate DTN delivery** — set it to at least the
/// certificate's own `expires_at` (ADR-0021 §4). The proposal's own window is
/// judged by the admission clock, so a cert-backed spend with a short expiry can
/// be refused as `expired` after courier delay even though the certificate is
/// still valid. This signer takes only `cert_id`, not the certificate, so it
/// cannot enforce the bound; the wallet must pass a suitable `expires_at`.
#[allow(clippy::too_many_arguments)]
pub fn proposal_sign_with_certificate(
    sender: Arc<Keypair>,
    receiver_address: String,
    amount_centi: i64,
    memo: Option<String>,
    cert_id: Vec<u8>,
    nonce: u64,
    proposed_at: i64,
    expires_at: i64,
) -> Result<Vec<u8>, CertError> {
    let receiver: Address = receiver_address
        .parse()
        .map_err(|_| CertError::InvalidAddress)?;
    let cert = parse_cert_id(&cert_id).ok_or(CertError::InvalidCertId)?;
    let sender_address = Address::from_public_key(sender.core().public_key());
    let proposal = TransactionProposal::new(
        sender_address,
        receiver,
        amount_centi,
        memo,
        nonce,
        proposed_at,
        expires_at,
    )
    .with_certificate(cert);
    let signed = SignedPayload::sign(proposal, sender.core());
    Ok(envelope::encode(
        &signed.signer,
        &signed.signature,
        to_canonical_bytes(signed.payload),
    ))
}

/// The receiver's verdict on an offline cert-backed spend ([`offline_spend_verify`]).
///
/// Exactly one variant is returned. [`Ok`](OfflineSpendVerdict::Ok) carries the
/// allowance that would remain *after* this spend
/// (`cap − presented-history − this amount`); every other variant is a typed
/// refusal reason a receiver UI can act on.
pub enum OfflineSpendVerdict {
    /// The spend verifies. `amount_centi` is what this spend debits (what the
    /// receiver is being asked to accept); `remaining_centi` is the allowance
    /// left after it, against the presented history (`cap − Σ history − amount`),
    /// so a receiver can gauge how much more the spender could still commit.
    Ok {
        /// The amount this spend debits, in centicommons — what to display as the
        /// value being accepted (read off the verified proposal, so the app need
        /// not decode it).
        amount_centi: i64,
        /// Allowance remaining after this spend, in centicommons.
        remaining_centi: i64,
    },
    /// The certificate envelope was not well-formed.
    MalformedCertificate,
    /// The certificate's station signature did not verify, or was not by the
    /// supplied station key.
    BadCertificateSignature,
    /// The proposal envelope was not well-formed.
    MalformedProposal,
    /// The proposal's signature did not verify, or its signer is not its sender.
    BadProposalSignature,
    /// The certificate is for a different member than the proposal's sender.
    CertMemberMismatch,
    /// The proposal does not reference this certificate.
    CertNotReferenced,
    /// The proposal's receiver is not the verifying receiver: this spend is
    /// addressed to someone else and is worthless to accept — only the named
    /// receiver can confirm it (ADR-0021 §3).
    WrongReceiver,
    /// The spend amount is not a positive debit of the sender.
    NotADebit,
    /// The certificate had expired by the receiver's clock (`now`).
    CertExpired,
    /// The proposal itself has expired by the receiver's clock (`now >
    /// proposal.expires_at`): the station judges proposal expiry before the
    /// certificate carve-out, so it would refuse this spend regardless of the cap.
    ProposalExpired,
    /// The proposal would be refused at the station for a payload reason
    /// independent of the certificate: an inverted window
    /// (`proposed_at > expires_at`), an over-long memo, or an oracle tier above
    /// what the phase serves. The cap does not rescue it.
    ProposalInadmissible,
    /// The spend exceeds the allowance left against the presented history.
    Overspent {
        /// Allowance available before this spend (`cap − Σ history`).
        available_centi: i64,
        /// The amount this spend attempted.
        attempted_centi: i64,
    },
    /// A presented-history entry was malformed, unsigned by the member, did not
    /// reference this certificate, or was not a positive debit.
    MalformedHistory,
}

/// Verifies a counterparty's certificate and a cert-backed spend against it,
/// entirely offline — the ADR-0021 §3 receiver ritual, in one call.
///
/// Given the counterparty's certificate (`cert_envelope`), the spend they are
/// asking the receiver to accept (`proposal_envelope`), the spends they present
/// as their history against this certificate (`presented_history`, each a
/// cert-backed proposal envelope), the verifying `receiver_address` (the
/// receiver's own `rrn1…` address), the paired `station_pubkey`, and the
/// receiver's current time `now`, this checks, in order: the station signature on
/// the certificate; the proposal's signature and that its signer is its sender;
/// that the certificate is for the sender; that the proposal references this
/// certificate; that the spend is addressed to *this* receiver; that the amount
/// is a positive debit; that the proposal would not be refused for a payload
/// reason the station judges before the certificate carve-out (window, memo,
/// tier); that the proposal and the certificate are both unexpired at `now`; that
/// every history entry verifies, is the member's, and references this
/// certificate; and that the amount fits the allowance left (`cap − Σ history`).
/// On success it returns the spend amount and the allowance remaining after it.
///
/// # The clock is testimony (ADR-0022)
///
/// Offline, the receiver's own device clock is the best `now` available; there is
/// no station to consult. The residual is a clock-skew window: a receiver whose
/// clock is behind the true time may accept a certificate that has in fact just
/// expired (the station applies a delivery grace beyond `expires_at`, so such a
/// spend can still be admitted), and one whose clock is ahead may decline a
/// certificate still valid at the station. This is inherent to offline
/// verification; the certificate's expiry and the cap bound the exposure either
/// way (§3, §6).
///
/// # Hidden history is bounded, not prevented (ADR-0021 §3)
///
/// A dishonest spender can withhold earlier cert spends from a new receiver, so a
/// verdict of `Ok` is *not* a guarantee the spend will be admitted — the spender
/// may have committed the same headroom elsewhere. The cap still bounds the
/// community's loss and the overspend is provable equivocation the station will
/// refuse and record (T2.3.2/T2.3.3): the station-side admission re-checks the
/// cumulative cap over *all* admitted spends, not just the presented ones, and
/// refuses the excess (see `rrn-ledger`'s `check_cert_backed` and the
/// `cert_backed_spends` admission tests). Receivers who need more assurance can
/// demand the spender's outbox-chain segment since issuance, where a gap is
/// visible.
pub fn offline_spend_verify(
    cert_envelope: Vec<u8>,
    proposal_envelope: Vec<u8>,
    presented_history: Vec<Vec<u8>>,
    receiver_address: String,
    station_pubkey: Vec<u8>,
    now: i64,
) -> OfflineSpendVerdict {
    use OfflineSpendVerdict::*;

    // The station key that must have signed the certificate. A malformed key
    // cannot establish the station identity, so the certificate cannot be
    // trusted — treat it as an unverifiable signature.
    let Some(station) = parse_pubkey(&station_pubkey) else {
        return BadCertificateSignature;
    };

    let Some(cert_signed) = decode_certificate(&cert_envelope) else {
        return MalformedCertificate;
    };
    if cert_signed.signer != station || cert_signed.verify().is_err() {
        return BadCertificateSignature;
    }
    let cert = &cert_signed.payload;

    let Some(proposal) = decode_proposal(&proposal_envelope) else {
        return MalformedProposal;
    };
    // The proposal must be signed by its own sender — otherwise anyone could
    // author a debit against the certificate holder.
    if &proposal.signer != proposal.payload.sender.public_key() || proposal.verify().is_err() {
        return BadProposalSignature;
    }
    let p = &proposal.payload;

    if cert.member != p.sender {
        return CertMemberMismatch;
    }
    if p.cert_id != Some(cert.cert_id) {
        return CertNotReferenced;
    }
    // The spend must be addressed to *this* receiver: a proposal naming someone
    // else can only be confirmed by that someone else (the station requires
    // confirmer == receiver), so accepting it delivers goods against nothing. A
    // malformed self-address cannot be matched, so it is treated as a mismatch.
    match receiver_address.parse::<Address>() {
        Ok(receiver) if receiver == p.receiver => {}
        _ => return WrongReceiver,
    }
    if p.amount_centi <= 0 {
        return NotADebit;
    }
    // Mirror the station's payload-only proposal refusals, which it judges
    // *before* the certificate carve-out (see `Engine::submit_proposal`): an
    // inverted or elapsed window, an over-long memo, or a tier above what the
    // phase serves would all be refused regardless of the cap, so an `Ok` here
    // would mislead the receiver into delivering against a spend the station
    // declines. All are checkable with only the payload and the receiver's clock.
    if p.proposed_at > p.expires_at
        || !p.memo_within_bounds()
        || !rrn_ledger::tier::is_phase1_serviceable(p.effective_tier())
    {
        return ProposalInadmissible;
    }
    if now > p.expires_at {
        return ProposalExpired;
    }
    // Unexpired at the receiver's clock (ADR-0021 §3 "unexpired at signing").
    if now > cert.expires_at {
        return CertExpired;
    }

    // Sum the presented history's distinct spends against this certificate. The
    // current proposal's id is pre-seeded, so a copy of it in the history is not
    // double-counted against itself.
    let mut seen: BTreeSet<TransactionId> = BTreeSet::new();
    seen.insert(p.id);
    let mut spent: i64 = 0;
    for item in &presented_history {
        let Some(h) = decode_proposal(item) else {
            return MalformedHistory;
        };
        if &h.signer != h.payload.sender.public_key() || h.verify().is_err() {
            return MalformedHistory;
        }
        let hp = &h.payload;
        if hp.sender != cert.member || hp.cert_id != Some(cert.cert_id) || hp.amount_centi <= 0 {
            return MalformedHistory;
        }
        // A repeated presentation of the same spend is not new consumption.
        if seen.insert(hp.id) {
            spent = spent.saturating_add(hp.amount_centi);
        }
    }

    let available = cert.cap_centi.saturating_sub(spent);
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

/// Parses a 32-byte Ed25519 public key, or `None` for the wrong length or a
/// non-canonical curve point.
fn parse_pubkey(bytes: &[u8]) -> Option<PublicKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    PublicKey::from_bytes(arr).ok()
}

/// Parses a 32-byte certificate id, or `None` for the wrong length.
fn parse_cert_id(bytes: &[u8]) -> Option<CertId> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(CertId(Hash::from_bytes(arr)))
}

/// Reconstructs a `SignedPayload<HeadroomCertificate>` from envelope bytes,
/// without checking the signature (the caller does). `None` on a malformed
/// envelope or a body that is not a canonical certificate.
fn decode_certificate(bytes: &[u8]) -> Option<SignedPayload<HeadroomCertificate>> {
    let DecodedEnvelope {
        signer,
        signature,
        body,
    } = envelope::decode(bytes)?;
    let payload: HeadroomCertificate = from_canonical_bytes(&body).ok()?;
    Some(SignedPayload {
        payload,
        signer,
        signature,
    })
}

/// Reconstructs a `SignedPayload<TransactionProposal>` from envelope bytes,
/// without checking the signature (the caller does). `None` on a malformed
/// envelope or a body that is not a canonical proposal.
fn decode_proposal(bytes: &[u8]) -> Option<SignedPayload<TransactionProposal>> {
    let DecodedEnvelope {
        signer,
        signature,
        body,
    } = envelope::decode(bytes)?;
    let payload: TransactionProposal = from_canonical_bytes(&body).ok()?;
    Some(SignedPayload {
        payload,
        signer,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair as CoreKeypair;
    use rrn_ledger::escrow::RequestId;

    /// A station-signed certificate for `member` with `cap`, and its envelope.
    fn issue_cert(
        station: &CoreKeypair,
        member: &Address,
        cap: i64,
        issued_at: i64,
        expires_at: i64,
    ) -> (HeadroomCertificate, Vec<u8>) {
        let cert = HeadroomCertificate::new(
            *member,
            cap,
            RequestId(Hash::of(b"req")),
            issued_at,
            expires_at,
        );
        let signed = SignedPayload::sign(cert.clone(), station);
        let bytes = envelope::encode(
            &signed.signer,
            &signed.signature,
            to_canonical_bytes(signed.payload),
        );
        (cert, bytes)
    }

    /// A `member`-signed cert-backed spend of `amount` against `cert`, as an
    /// envelope, via the FFI signer under test.
    fn spend(
        member: &Arc<Keypair>,
        receiver: &Address,
        cert: &CertId,
        amount: i64,
        nonce: u64,
    ) -> Vec<u8> {
        proposal_sign_with_certificate(
            member.clone(),
            receiver.to_string(),
            amount,
            None,
            cert.to_bytes().to_vec(),
            nonce,
            1_000,
            9_000,
        )
        .expect("sign cert-backed spend")
    }

    fn member_and_addr() -> (Arc<Keypair>, Address) {
        let kp = Arc::new(Keypair::generate());
        let addr = Address::from_public_key(kp.core().public_key());
        (kp, addr)
    }

    #[test]
    fn certificate_parse_reads_a_valid_certificate() {
        let station = CoreKeypair::generate();
        let (_, member_addr) = member_and_addr();
        let (cert, bytes) = issue_cert(&station, &member_addr, 1_000, 100, 5_000);
        let info = certificate_parse(bytes, station.public_key().to_bytes().to_vec()).unwrap();
        assert_eq!(info.member, member_addr.to_string());
        assert_eq!(info.cap_centi, 1_000);
        assert_eq!(info.expires_at, 5_000);
        assert_eq!(info.cert_id, hex::encode(cert.cert_id.to_bytes()));
    }

    #[test]
    fn certificate_parse_refuses_a_forged_station_signature() {
        let station = CoreKeypair::generate();
        let (_, member_addr) = member_and_addr();
        let (_, bytes) = issue_cert(&station, &member_addr, 1_000, 100, 5_000);
        let attacker = CoreKeypair::generate();
        assert!(matches!(
            certificate_parse(bytes, attacker.public_key().to_bytes().to_vec()),
            Err(CertError::StationSignatureInvalid)
        ));
    }

    #[test]
    fn certificate_request_sign_round_trips_through_the_wire_type() {
        let (member, member_addr) = member_and_addr();
        let bytes = certificate_request_sign(member, 1_500, 3, 1_700_000_000);
        let dec = envelope::decode(&bytes).unwrap();
        let req: CertificateRequest = from_canonical_bytes(&dec.body).unwrap();
        assert_eq!(req.member, member_addr);
        assert_eq!(req.cap_centi, 1_500);
        assert_eq!(req.nonce, 3);
        // Signed by the member; the signature verifies over the request bytes.
        let signed = SignedPayload {
            payload: req,
            signer: dec.signer,
            signature: dec.signature,
        };
        assert!(signed.verify().is_ok());
        assert_eq!(&signed.signer, member_addr.public_key());
    }

    // --- offline_spend_verify: the ADR-0021 §3 receiver ritual ---------------

    /// The station key, member, receiver, and certificate shared by the
    /// offline-spend tests. Cap 1000, valid [100, 5000].
    struct Scene {
        station: CoreKeypair,
        member: Arc<Keypair>,
        receiver: Address,
        cert: HeadroomCertificate,
        cert_bytes: Vec<u8>,
    }

    fn scene() -> Scene {
        let station = CoreKeypair::generate();
        let (member, member_addr) = member_and_addr();
        let receiver = Address::from_public_key(CoreKeypair::generate().public_key());
        let (cert, cert_bytes) = issue_cert(&station, &member_addr, 1_000, 100, 5_000);
        Scene {
            station,
            member,
            receiver,
            cert,
            cert_bytes,
        }
    }

    impl Scene {
        fn station_pk(&self) -> Vec<u8> {
            self.station.public_key().to_bytes().to_vec()
        }
    }

    #[test]
    fn a_good_spend_within_the_cap_verifies() {
        let s = scene();
        // History: 300 already spent; this spend is 200; cap 1000.
        let history = vec![spend(&s.member, &s.receiver, &s.cert.cert_id, 300, 0)];
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 1);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            history,
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(
            verdict,
            OfflineSpendVerdict::Ok {
                amount_centi: 200,
                remaining_centi: 500
            }
        ));
    }

    #[test]
    fn a_spend_exactly_at_the_available_boundary_verifies() {
        let s = scene();
        // 800 presented + a 200 spend = 1000 == cap → the last admissible spend.
        let history = vec![spend(&s.member, &s.receiver, &s.cert.cert_id, 800, 0)];
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 1);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            history,
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(
            verdict,
            OfflineSpendVerdict::Ok {
                amount_centi: 200,
                remaining_centi: 0
            }
        ));
    }

    #[test]
    fn a_duplicated_history_entry_is_not_counted_twice() {
        let s = scene();
        // The same 800-spend presented twice must consume 800, not 1600, so a
        // 200 spend still fits (remaining 0) rather than overspending.
        let one = spend(&s.member, &s.receiver, &s.cert.cert_id, 800, 0);
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 1);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![one.clone(), one],
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(
            verdict,
            OfflineSpendVerdict::Ok {
                amount_centi: 200,
                remaining_centi: 0
            }
        ));
    }

    #[test]
    fn a_spend_overspending_the_presented_history_is_refused() {
        let s = scene();
        // 800 presented + a 300 spend = 1100 > cap 1000.
        let history = vec![spend(&s.member, &s.receiver, &s.cert.cert_id, 800, 0)];
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 300, 1);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            history,
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(
            verdict,
            OfflineSpendVerdict::Overspent {
                available_centi: 200,
                attempted_centi: 300,
            }
        ));
    }

    #[test]
    fn hidden_history_verifies_but_the_station_cap_still_bounds_it() {
        // A spender hides an earlier 900 spend from a new receiver and presents an
        // empty history for a 300 spend against a 1000 cap: the offline check
        // passes (the receiver cannot see what was withheld). This is the ADR-0021
        // §3 residual — the cap still bounds the damage and the station refuses the
        // overspend. `rrn-ledger/tests/cert_backed_spends.rs`
        // (`overspend_past_cap_is_refused`) proves the excess spend is refused with
        // `CertificateOverspent`; the station's appending of an `EquivocationRecord`
        // for it is proven in `rrn-ledger/src/engine.rs`'s equivocation tests.
        let s = scene();
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 300, 5);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![], // history withheld
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(
            verdict,
            OfflineSpendVerdict::Ok {
                amount_centi: 300,
                remaining_centi: 700
            }
        ));
    }

    #[test]
    fn a_spend_to_a_different_receiver_is_refused() {
        let s = scene();
        // The proposal names `s.receiver`, but a stranger runs the check: it is
        // not their spend to accept.
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 0);
        let stranger = Address::from_public_key(CoreKeypair::generate().public_key());
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![],
            stranger.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::WrongReceiver));
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let s = scene();
        // A proposal whose own window comfortably outlasts the certificate, so it
        // is the *certificate* expiry that fires at now = 5001 (> cert 5000).
        let proposal = proposal_sign_with_certificate(
            s.member.clone(),
            s.receiver.to_string(),
            200,
            None,
            s.cert.cert_id.to_bytes().to_vec(),
            0,
            1_000,
            10_000,
        )
        .unwrap();
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![],
            s.receiver.to_string(),
            s.station_pk(),
            5_001,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::CertExpired));
    }

    #[test]
    fn a_proposal_past_its_own_expiry_is_refused() {
        let s = scene();
        // The default `spend` helper sets expires_at = 9000; at now = 9001 the
        // proposal itself has elapsed even though the certificate is still valid,
        // so the station would refuse it — reported distinctly from CertExpired.
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 0);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![],
            s.receiver.to_string(),
            s.station_pk(),
            9_001,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::ProposalExpired));
    }

    #[test]
    fn a_non_positive_amount_is_not_a_debit() {
        let s = scene();
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 0, 0);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![],
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::NotADebit));
    }

    #[test]
    fn a_proposal_signed_by_a_non_sender_is_refused() {
        let s = scene();
        // Take a valid proposal and re-frame it with a *different* signer/sig, so
        // the signer is no longer the sender named inside.
        let valid = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 0);
        let dec = envelope::decode(&valid).unwrap();
        let impostor = CoreKeypair::generate();
        let forged = envelope::encode(&impostor.public_key(), &impostor.sign(&dec.body), dec.body);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            forged,
            vec![],
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::BadProposalSignature));
    }

    #[test]
    fn a_malformed_certificate_or_proposal_is_reported() {
        let s = scene();
        let good_proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 0);
        // Garbage certificate bytes.
        assert!(matches!(
            offline_spend_verify(
                vec![0xff, 0x00, 0x13],
                good_proposal.clone(),
                vec![],
                s.receiver.to_string(),
                s.station_pk(),
                1_000,
            ),
            OfflineSpendVerdict::MalformedCertificate
        ));
        // Garbage proposal bytes.
        assert!(matches!(
            offline_spend_verify(
                s.cert_bytes.clone(),
                vec![0xff, 0x00, 0x13],
                vec![],
                s.receiver.to_string(),
                s.station_pk(),
                1_000,
            ),
            OfflineSpendVerdict::MalformedProposal
        ));
    }

    #[test]
    fn a_forged_station_signature_is_refused() {
        let s = scene();
        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 0);
        // Verified against an attacker's station key.
        let attacker = CoreKeypair::generate();
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![],
            s.receiver.to_string(),
            attacker.public_key().to_bytes().to_vec(),
            1_000,
        );
        assert!(matches!(
            verdict,
            OfflineSpendVerdict::BadCertificateSignature
        ));
    }

    #[test]
    fn a_certificate_for_a_different_member_is_refused() {
        let station = CoreKeypair::generate();
        let (member, _member_addr) = member_and_addr();
        let (_other, other_addr) = member_and_addr();
        let receiver = Address::from_public_key(CoreKeypair::generate().public_key());
        // Certificate is issued to `other`, but the spend is signed by `member`.
        let (cert, cert_bytes) = issue_cert(&station, &other_addr, 1_000, 100, 5_000);
        let proposal = spend(&member, &receiver, &cert.cert_id, 200, 0);
        let verdict = offline_spend_verify(
            cert_bytes,
            proposal,
            vec![],
            receiver.to_string(),
            station.public_key().to_bytes().to_vec(),
            1_000,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::CertMemberMismatch));
    }

    #[test]
    fn a_tampered_history_entry_is_refused() {
        let s = scene();
        // A history entry whose body byte is flipped: its signature no longer
        // verifies, so the whole verification refuses rather than trusting it.
        let mut tampered = spend(&s.member, &s.receiver, &s.cert.cert_id, 300, 0);
        let dec = envelope::decode(&tampered).unwrap();
        let mut body = dec.body.clone();
        let last = body.len() - 1;
        body[last] ^= 0x01;
        tampered = envelope::encode(&dec.signer, &dec.signature, body);

        let proposal = spend(&s.member, &s.receiver, &s.cert.cert_id, 200, 1);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![tampered],
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::MalformedHistory));
    }

    #[test]
    fn a_proposal_not_referencing_the_certificate_is_refused() {
        let s = scene();
        // A spend against a *different* certificate id.
        let wrong_cert = CertId(Hash::of(b"some-other-cert"));
        let proposal = spend(&s.member, &s.receiver, &wrong_cert, 200, 0);
        let verdict = offline_spend_verify(
            s.cert_bytes.clone(),
            proposal,
            vec![],
            s.receiver.to_string(),
            s.station_pk(),
            1_000,
        );
        assert!(matches!(verdict, OfflineSpendVerdict::CertNotReferenced));
    }
}
