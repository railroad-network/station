//! The debt floor: how far into debt a member may *commit* themselves.
//!
//! Mutual credit means balances go negative by design — but without a bound, a
//! member can settle into arbitrary debt and simply leave, with the loss
//! socialized across everyone holding positive balances (threat model, "no debt
//! bound"; ADR-0018). The floor bounds that exposure at the moment a member
//! *signs* a debit against themselves:
//!
//! - a **sender** commits when they sign a proposal with a positive amount, so
//!   [`Engine::submit_proposal`](crate::engine::Engine::submit_proposal) checks
//!   the floor there;
//! - a **receiver** commits to a negative-amount proposal (a payment request
//!   they would pay) only when they sign the confirmation, so
//!   [`Engine::submit_confirmation`](crate::engine::Engine::submit_confirmation)
//!   checks it there.
//!
//! The projected position counts the settled balance *and* every pending debit
//! the member has already signed but which has not yet settled — otherwise a
//! member could stack proposals inside one settlement window, each individually
//! within the floor, that jointly blow through it. Pending *credits* (money
//! owed to the member) do not count: they can still cancel or be disputed, and
//! headroom must never be borrowed against an unsettled inflow.

use rrn_identity::address::Address;

use crate::state::{LedgerSnapshot, TransactionState};

/// The default debt floor: −20 Commons (−2,000 centicommons).
///
/// Sized to a new member's realistic first weeks of consumption at the design
/// overview's reference prices (a 3-Common consultation, an 8-Common grain
/// purchase, a handful of Tier-1 trades) while keeping the worst-case
/// walk-away loss per member small against a young community's trade volume.
/// Deliberately conservative: raising a floor later is painless, but
/// tightening one strands members already below the new line (ADR-0018). A
/// starter value in the ADR-0009 sense — locked as the protocol default,
/// overridable per station via `[credit] debt_floor_centi`, earmarked for
/// governance tuning later.
pub const DEFAULT_DEBT_FLOOR_CENTI: i64 = -2_000;

/// The default validity of a headroom certificate: 7 days (ADR-0021 §1).
///
/// A partition long enough to matter is measured in days; a week covers a market
/// day, a storm, or a drill with room to spare, while keeping reserved (idle)
/// headroom from lingering. Overridable per station via
/// `[credit] cert_validity_seconds`.
pub const DEFAULT_CERT_VALIDITY_SECS: i64 = 7 * 24 * 60 * 60;

/// The default maximum cap of a single headroom certificate: 10 Commons
/// (1,000 centicommons).
///
/// ADR-0021 §1 caps offline certificates at "the Tier-2 single-transaction
/// ceiling … offline trade is Tier-1/2 commerce, not exceptional transfers", and
/// §6/Consequences calibrate the honest-receiver worst-case incident exposure at
/// **10 Commons** ("nobody rational [equivocates] for ≤ 10 Commons"). That
/// calibration is the binding number: 10 Commons sits inside the Tier-2 band
/// ([`crate::tier::TIER_2_FLOOR_CENTI`] = 500 .. [`crate::tier::TIER_3_FLOOR_CENTI`]
/// = 5,000), and a member at zero balance can hold one full certificate and still
/// keep 10 Commons of online headroom under the default floor. It is a
/// **free-standing** default, deliberately *not* aliased to a tier boundary: a
/// certificate cap is a multi-spend budget, not a single-transaction magnitude,
/// and coupling a fraud-exposure parameter to the tier table would let a future
/// tier retune silently change the community's offline worst case. Overridable
/// per station via `[credit] cert_max_cap_centi`; the station rejects a
/// configured cap above the Tier-2 ceiling (ADR-0021 §1) and warns on one above
/// the floor magnitude (unreachable at zero balance).
pub const DEFAULT_CERT_MAX_CAP_CENTI: i64 = 1_000;

/// The default DTN delivery grace beyond a certificate's expiry within which a
/// cert-backed spend is still admitted: 14 days (ADR-0021 §4).
///
/// A spend signed just before expiry may take days to reach the station over a
/// slow transport; the grace keeps such a spend admissible (judged by the
/// admission clock, ADR-0022) rather than stranding the receiver who accepted it.
/// The reservation therefore releases only at `expires_at + this + skew` — see
/// [`crate::escrow::spend_admissible_until`]. Overridable via
/// `[credit] cert_delivery_grace_seconds`.
pub const DEFAULT_CERT_DELIVERY_GRACE_SECS: i64 = 14 * 24 * 60 * 60;

/// The default cap on the number of simultaneously outstanding certificates one
/// member may hold: 4 (ADR-0021 §1).
///
/// Bounds per-member idle-escrow sprawl and the receipt-verification effort an
/// offline receiver faces when checking a spender's presented history.
/// Overridable via `[credit] cert_max_outstanding`.
pub const DEFAULT_CERT_MAX_OUTSTANDING: u32 = 4;

/// Tunable credit parameters for the engine's front-door checks.
#[derive(Clone, Copy, Debug)]
pub struct CreditConfig {
    /// The lowest projected balance, in centicommons, a member may sign
    /// themselves down to. Always ≤ 0; see [`DEFAULT_DEBT_FLOOR_CENTI`].
    pub debt_floor_centi: i64,
    /// How long a newly issued headroom certificate stays valid, in seconds. See
    /// [`DEFAULT_CERT_VALIDITY_SECS`].
    pub cert_validity_seconds: i64,
    /// The largest cap, in centicommons, a single certificate may reserve. See
    /// [`DEFAULT_CERT_MAX_CAP_CENTI`].
    pub cert_max_cap_centi: i64,
    /// The DTN delivery grace beyond expiry, in seconds, within which a
    /// cert-backed spend is still admissible — and thus for which the reservation
    /// is still held. See [`DEFAULT_CERT_DELIVERY_GRACE_SECS`] and
    /// [`crate::escrow::spend_admissible_until`].
    pub cert_delivery_grace_seconds: i64,
    /// The maximum number of simultaneously outstanding certificates one member
    /// may hold. See [`DEFAULT_CERT_MAX_OUTSTANDING`].
    pub cert_max_outstanding: u32,
}

impl Default for CreditConfig {
    fn default() -> Self {
        Self {
            debt_floor_centi: DEFAULT_DEBT_FLOOR_CENTI,
            cert_validity_seconds: DEFAULT_CERT_VALIDITY_SECS,
            cert_max_cap_centi: DEFAULT_CERT_MAX_CAP_CENTI,
            cert_delivery_grace_seconds: DEFAULT_CERT_DELIVERY_GRACE_SECS,
            cert_max_outstanding: DEFAULT_CERT_MAX_OUTSTANDING,
        }
    }
}

/// The total pending debit `party` has already **signed for** but not yet
/// settled as of `now`, in centicommons (≥ 0).
///
/// A transaction counts against its debtor once the debtor's own signature is
/// on it: a positive-amount proposal binds its sender from `Proposed` onward,
/// while a negative-amount proposal binds its receiver only from `Confirmed`
/// onward (the receiver's confirmation is their signature on the debit).
/// `Disputed` still counts — a frozen transaction may yet settle as confirmed.
/// `Settled` amounts are already in the balance and `Cancelled` ones never will
/// be, so neither contributes.
///
/// A still-`Proposed` transaction whose `expires_at` has passed (beyond the
/// engine's clock-skew tolerance) no longer counts: the engine refuses a
/// confirmation past that same boundary, so the debit can never land, and
/// holding its headroom forever would let a counterparty who simply ignores a
/// proposal permanently shrink the sender's credit.
///
/// # Outstanding certificate reservations (ADR-0021 §2)
///
/// Each of `party`'s outstanding [headroom certificates](crate::escrow) reserves
/// its *remaining* cap (`cap_centi − consumed_centi`, floored at 0) here, exactly
/// as a pending signed debit does: issuing a certificate paid for that headroom
/// up front so a later cert-backed spend can be admitted without a fresh floor
/// check. The reservation releases when a spend against the certificate can no
/// longer be admitted — past [`escrow::spend_admissible_until`](crate::escrow::spend_admissible_until),
/// the *single shared boundary* T2.3.2's admission bound also uses — mirroring
/// the proposal-expiry release discipline (ADR-0018 point 2). `config` supplies
/// that boundary's grace and skew.
pub fn committed_debits_centi(
    snapshot: &LedgerSnapshot,
    party: &Address,
    now: i64,
    config: &CreditConfig,
) -> i64 {
    let mut total: i64 = 0;
    for (_, state) in snapshot.iter() {
        let (proposal, receiver_committed) = match state {
            TransactionState::Proposed { proposal } => {
                let expiry_cutoff = proposal
                    .payload
                    .expires_at
                    .saturating_add(crate::engine::CLOCK_SKEW_TOLERANCE_SECS);
                if now > expiry_cutoff {
                    // Expired unconfirmed: the engine will never accept its
                    // confirmation, so it can no longer bind its sender.
                    continue;
                }
                (proposal, false)
            }
            TransactionState::Confirmed { proposal, .. }
            | TransactionState::Disputed { proposal, .. } => (proposal, true),
            TransactionState::Settled { .. } | TransactionState::Cancelled { .. } => continue,
        };
        let p = &proposal.payload;
        let debit = if p.amount_centi > 0 && p.sender == *party {
            p.amount_centi
        } else if p.amount_centi < 0 && receiver_committed && p.receiver == *party {
            p.amount_centi.saturating_abs()
        } else {
            0
        };
        total = total.saturating_add(debit);
    }
    // Outstanding certificate reservations: the remaining cap of each of the
    // member's *live* certificates (unreturned and still admissible — the shared
    // escrow boundary). Past that boundary a certificate reserves nothing, so it
    // is excluded by `live_certs_of`, exactly T2.3.2's admission bound and the
    // proposal-expiry release discipline (ADR-0021 §2, ADR-0018 point 2).
    for cert_state in snapshot.live_certs_of(party, now, config) {
        let cert = &cert_state.certificate.payload;
        let remaining = cert.cap_centi.saturating_sub(cert_state.consumed_centi);
        total = total.saturating_add(remaining.max(0));
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_storage::log::AppendLog;
    use rrn_storage::{db::Database, migrations};

    use crate::transaction::{
        SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
    };

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    #[test]
    fn pending_debits_follow_the_debtors_signature() {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        let mut log = AppendLog::new(&db);

        // Alice proposes to pay Bob 300: binds Alice immediately.
        let pay = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 100, 100_000);
        log.append(SignedProposal::sign(pay, &alice), 100).unwrap();

        // Alice requests 200 from Bob (negative amount): does not bind Bob until
        // he confirms.
        let request =
            TransactionProposal::new(addr(&alice), addr(&bob), -200, None, 1, 100, 100_000);
        let request_id = request.id;
        log.append(SignedProposal::sign(request, &alice), 100)
            .unwrap();

        let cfg = CreditConfig::default();
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 150, &cfg),
            300
        );
        assert_eq!(committed_debits_centi(&snapshot, &addr(&bob), 150, &cfg), 0);

        // Bob confirms the request: now the 200 binds him.
        let c = TransactionConfirmation {
            proposal_id: request_id,
            confirmer: addr(&bob),
            confirmed_at: 200,
        };
        AppendLog::new(&db)
            .append(SignedConfirmation::sign(c, &bob), 200)
            .unwrap();
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&bob), 250, &cfg),
            200
        );
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 250, &cfg),
            300
        );
    }

    #[test]
    fn an_expired_unconfirmed_proposal_stops_counting() {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let (alice, bob) = (Keypair::generate(), Keypair::generate());
        let mut log = AppendLog::new(&db);

        // Alice proposes 300 to Bob, valid from t=100 to t=1_000.
        let pay = TransactionProposal::new(addr(&alice), addr(&bob), 300, None, 0, 100, 1_000);
        log.append(SignedProposal::sign(pay, &alice), 100).unwrap();
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();

        // Within the window (and its skew tolerance) the 300 binds Alice; once
        // the proposal can no longer be confirmed, the headroom is released.
        let cfg = CreditConfig::default();
        let skew = crate::engine::CLOCK_SKEW_TOLERANCE_SECS;
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 500, &cfg),
            300
        );
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 1_000 + skew, &cfg),
            300
        );
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 1_001 + skew, &cfg),
            0
        );
    }

    /// Appends a member-signed request and the station-signed certificate that
    /// honors it (request first, both at `now`), mirroring the engine's issuance
    /// path so the reservation arithmetic can be tested from the snapshot alone.
    fn issue_cert(
        db: &Database,
        station: &Keypair,
        member: &Keypair,
        cap_centi: i64,
        nonce: u64,
        now: i64,
        validity: i64,
    ) -> crate::escrow::CertId {
        use crate::escrow::{CertificateRequest, HeadroomCertificate};
        use rrn_crypto::signed::SignedPayload;
        let req = CertificateRequest::new(addr(member), cap_centi, nonce, now);
        let request_id = req.request_id;
        let mut log = AppendLog::new(db);
        log.append(SignedPayload::sign(req, member), now).unwrap();
        let cert =
            HeadroomCertificate::new(addr(member), cap_centi, request_id, now, now + validity);
        let cert_id = cert.cert_id;
        log.append(SignedPayload::sign(cert, station), now).unwrap();
        cert_id
    }

    #[test]
    fn an_outstanding_certificate_reserves_its_cap() {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let (station, alice) = (Keypair::generate(), Keypair::generate());
        let cfg = CreditConfig::default();

        issue_cert(
            &db,
            &station,
            &alice,
            1_000,
            0,
            1_000,
            cfg.cert_validity_seconds,
        );
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
        // The full cap is reserved against the member's committed position, like
        // a pending debit — and nobody else's.
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), 1_000, &cfg),
            1_000
        );
        let bob = Keypair::generate();
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&bob), 1_000, &cfg),
            0
        );
    }

    #[test]
    fn a_certificates_reservation_releases_at_the_shared_escrow_boundary() {
        // The coupled-boundary invariant (ADR-0021 §2, acceptance): the release
        // condition in `committed_debits_centi` fires at exactly
        // `escrow::spend_admissible_until`, the same instant T2.3.2's admission
        // bound will use. Boundary-tested one second either side.
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let (station, alice) = (Keypair::generate(), Keypair::generate());
        let cfg = CreditConfig::default();

        let issued_at = 1_000;
        let validity = cfg.cert_validity_seconds;
        issue_cert(&db, &station, &alice, 1_000, 0, issued_at, validity);
        let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();

        let cert = snapshot.outstanding_certs_of(&addr(&alice))[0]
            .certificate
            .payload
            .clone();
        let boundary = crate::escrow::spend_admissible_until(&cert, &cfg);
        // At and just before the boundary the cap is still reserved.
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), boundary - 1, &cfg),
            1_000
        );
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), boundary, &cfg),
            1_000
        );
        // One second past it, the reservation releases without any return record.
        assert_eq!(
            committed_debits_centi(&snapshot, &addr(&alice), boundary + 1, &cfg),
            0
        );
    }
}
