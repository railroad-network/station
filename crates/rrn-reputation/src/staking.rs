//! Tier-2 reputation staking and the bootstrap grace (T1.8.2).
//!
//! A Tier-2 transaction (Overview §4.3) is confirmed by the receiver *staking
//! their reputation* on it being real: §4.2.2's reputation staking. This module
//! decides whether a would-be confirmer is allowed to make that stake, and what
//! the stake is worth.
//!
//! # What a confirmer stakes
//!
//! The stake is the confirmer's **raw (uncapped) composite** as of the moment of
//! confirmation — [`ReputationScorer::score_raw_at`], the same uncapped score
//! [`crate::sybil::anchoring_voucher`] judges a voucher on. High-standing
//! attestors therefore carry more weight (§4.2.2), and the value is fully
//! replayable from the log at any later time (the score is a pure function of
//! evidence dated at or before `at_time`), so a dispute can recompute exactly
//! what was at risk — nothing needs to be frozen onto the signed confirmation.
//!
//! # Who may confirm — the bootstrap grace
//!
//! Steady state: only an **established** member — effective composite at or above
//! the Member band ([`BAND_MEMBER_MIN`]) — may confirm a Tier-2 transaction, so
//! there is real reputation behind the attestation.
//!
//! But a brand-new community has no established members yet: anchoring caps every
//! unanchored identity's composite far below the Member band, so a strict floor
//! would make Tier-2 impossible until reputation somehow bootstrapped — the same
//! deadlock [`crate::sybil::anchoring_voucher`] documents for the *first* anchor.
//! The escape hatch is a **grace period**: while fewer than
//! [`BOOTSTRAP_GRACE_THRESHOLD`] members have reached the Member band, *any*
//! member may confirm a Tier-2 transaction (staking whatever raw composite they
//! have). Once the community has that many established members, the grace ends on
//! its own and the floor applies to everyone thereafter.
//!
//! The condition is evaluated from the log (the established-member count is a
//! function of everyone's replayable score), so it is not tied to this station's
//! snapshot cache.

use rrn_identity::address::Address;
use rrn_storage::db::Database;

use crate::model::{BAND_MEMBER_MIN, DIMENSION_MAX};
use crate::scoring::ReputationScorer;
use crate::snapshot::known_addresses;
use crate::Result;

/// Members at the Member band the community needs before the Tier-2 bootstrap
/// grace ends (T1.8.2). Below this, any member may confirm a Tier-2 transaction;
/// at or above it, the [`BAND_MEMBER_MIN`] floor applies to everyone.
///
/// A Phase-1 default (revisited in the M1.8 oracle ADR): small enough that a
/// fresh ~20-person community leaves bootstrap quickly once a trusted core
/// forms, large enough that grace does not end on a single member's standing.
pub const BOOTSTRAP_GRACE_THRESHOLD: usize = 3;

/// A composite (0.0..=5.0) expressed as centi-points (0..=500), the integer unit
/// the ledger and vouch stakes already use. Clamped to the dimension range and
/// rounded, so a stake is always a clean non-negative integer.
pub fn composite_to_centi(composite: f32) -> u64 {
    let clamped = composite.clamp(0.0, DIMENSION_MAX);
    (clamped * 100.0).round() as u64
}

/// The reputation `address` would stake on a Tier-2 confirmation made at
/// `at_time`: their raw composite in centi-points. Replayable, so a later dispute
/// can recompute the exact stake that was at risk.
pub fn tier2_stake_centi(db: &Database, address: &Address, at_time: i64) -> Result<u64> {
    let raw = ReputationScorer::new(db)
        .score_raw_at(address, at_time)?
        .composite();
    Ok(composite_to_centi(raw))
}

/// Every known member holding an **effective** (anchored) composite at or above
/// the Member band as of `at_time` — the community's established-member set. This
/// is the same electorate governance ballots on ([ADR-0012]) and the pool a
/// dispute jury is drawn from (ADR-0014).
///
/// Scores every identity that appears on the log; `O(members)` full scorings, so
/// it is called off hot paths (grace checks, governance tallies, dispute draws),
/// not per transaction. The *set* is derived from the canonical log and so is
/// identical on every replica, but the returned **order is not** deterministic (it
/// follows a hash-set iteration): a caller that needs a stable order — a dispute
/// draw, say — must sort the result itself.
pub fn established_members(db: &Database, at_time: i64) -> Result<Vec<Address>> {
    let scorer = ReputationScorer::new(db);
    let mut members = Vec::new();
    for address in known_addresses(db)? {
        if scorer.score(&address, at_time)?.composite() >= BAND_MEMBER_MIN {
            members.push(address);
        }
    }
    Ok(members)
}

/// How many known members hold an **effective** (anchored) composite at or above
/// the Member band as of `at_time` — the count the bootstrap grace turns on.
pub fn established_member_count(db: &Database, at_time: i64) -> Result<usize> {
    Ok(established_members(db, at_time)?.len())
}

/// Whether the community is still in **bootstrap grace** as of `at_time`: fewer
/// than [`BOOTSTRAP_GRACE_THRESHOLD`] members hold an effective composite at or
/// above the Member band (ADR-0015).
///
/// This is the single shared predicate the oracle ladder (T1.8), governance
/// (ADR-0012), and disputes (ADR-0014) all key their bootstrap relaxations off,
/// so a community is either bootstrapping or it is not — uniformly across all
/// three. Like [`established_member_count`] it is a pure function of the log.
pub fn in_grace(db: &Database, at_time: i64) -> Result<bool> {
    Ok(established_member_count(db, at_time)? < BOOTSTRAP_GRACE_THRESHOLD)
}

/// The community's governing electorate as of `at_time` (ADR-0015): the body that
/// may co-sign proposals, vote, be counted toward a quorum, and be drawn for a
/// dispute jury.
///
/// In steady state this is exactly [`established_members`]. **While the community
/// is [`in_grace`]** it is the union of the established set with the genesis
/// `founders` — the one pre-vetted body — so a young community can govern and
/// adjudicate before anyone has earned their standing. The instant a
/// [`BOOTSTRAP_GRACE_THRESHOLD`]-th member establishes, grace ends and the union
/// collapses back to the established set on its own; nothing is stored. Founders
/// count during grace regardless of their own standing or anchoring, because
/// their eligibility is their genesis membership, not a score.
///
/// Founders are supplied by the caller: they live in the effective Charter, which
/// this crate deliberately does not depend on. As with [`established_members`] the
/// returned order is **not** deterministic; a caller needing a stable order (a
/// dispute draw, say) must sort it.
pub fn grace_electorate(db: &Database, founders: &[Address], at_time: i64) -> Result<Vec<Address>> {
    // `established_members().len()` is the grace predicate, so reuse the set we
    // just computed rather than scoring the community a second time.
    let mut electorate = established_members(db, at_time)?;
    if electorate.len() < BOOTSTRAP_GRACE_THRESHOLD {
        for founder in founders {
            if !electorate.contains(founder) {
                electorate.push(*founder);
            }
        }
    }
    Ok(electorate)
}

/// The outcome of checking whether `confirmer` may confirm a Tier-2 transaction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tier2Eligibility {
    /// The confirmation is allowed; `stake_centi` is the raw composite put at
    /// risk. `via_grace` is `true` when the confirmer is below the Member band
    /// and is permitted only because the community is still bootstrapping — worth
    /// distinguishing in logs and, later, in dispute weighting.
    Allowed {
        /// Raw composite staked, in centi-points.
        stake_centi: u64,
        /// Whether the allowance came from the bootstrap grace rather than the
        /// confirmer meeting the Member-band floor.
        via_grace: bool,
    },
    /// The confirmer is below the Member band and the grace has ended — refused.
    Refused {
        /// The confirmer's effective composite (below [`BAND_MEMBER_MIN`]).
        composite: f32,
        /// How many members are established — at or above the grace threshold,
        /// which is why grace no longer applies.
        established: usize,
    },
}

/// The pure eligibility rule, given the confirmer's effective composite, the
/// stake they would put up, and how many members are established. Split out from
/// the scoring so the branching — the actual policy (T1.8.2) — is tested on its
/// own, without manufacturing reputation in the log.
fn decide(effective_composite: f32, stake_centi: u64, established: usize) -> Tier2Eligibility {
    if effective_composite >= BAND_MEMBER_MIN {
        // An established member always may — the steady-state rule.
        Tier2Eligibility::Allowed {
            stake_centi,
            via_grace: false,
        }
    } else if established < BOOTSTRAP_GRACE_THRESHOLD {
        // Below the floor, but the community is still bootstrapping.
        Tier2Eligibility::Allowed {
            stake_centi,
            via_grace: true,
        }
    } else {
        // Below the floor and grace has ended.
        Tier2Eligibility::Refused {
            composite: effective_composite,
            established,
        }
    }
}

/// Decides whether `confirmer` may confirm a Tier-2 transaction at `at_time`, and
/// what they stake (T1.8.2). See the module docs for the rule.
///
/// The established-member count is only computed when the confirmer is below the
/// floor (an established confirmer short-circuits), so the steady-state path stays
/// a single scoring.
pub fn evaluate_tier2_confirmation(
    db: &Database,
    confirmer: &Address,
    at_time: i64,
) -> Result<Tier2Eligibility> {
    let scorer = ReputationScorer::new(db);
    let effective = scorer.score(confirmer, at_time)?.composite();
    let stake_centi = composite_to_centi(scorer.score_raw_at(confirmer, at_time)?.composite());

    // Short-circuit the established path so we do not score the whole community
    // on every ordinary Tier-2 confirmation.
    if effective >= BAND_MEMBER_MIN {
        return Ok(Tier2Eligibility::Allowed {
            stake_centi,
            via_grace: false,
        });
    }
    // Below the floor: the count decides grace vs. refusal.
    let established = established_member_count(db, at_time)?;
    Ok(decide(effective, stake_centi, established))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_identity::attestation::Attestation;
    use rrn_identity::vouch::{VouchBody, VouchKind};
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
    use rrn_storage::log::AppendLog;
    use rrn_storage::migrations;

    const MONTH: i64 = 30 * 86_400;

    fn fresh_db() -> Database {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        db
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(kp.public_key())
    }

    /// Appends a proposal → confirmation → settlement chain, so `sender` and
    /// `receiver` both accrue trade reliability and `receiver` an attestation.
    fn append_settled(
        db: &Database,
        sender: &Keypair,
        receiver: &Keypair,
        station: &Keypair,
        nonce: u64,
        at: i64,
    ) {
        let mut log = AppendLog::new(db);
        let proposal = TransactionProposal::new(
            addr(sender),
            addr(receiver),
            300,
            None,
            nonce,
            1,
            i64::MAX / 2,
        );
        let pid = proposal.id;
        log.append(SignedPayload::sign(proposal, sender), 0)
            .unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, receiver), 0)
            .unwrap();
        let settlement = SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        };
        log.append(SignedPayload::sign(settlement, station), 0)
            .unwrap();
    }

    fn append_vouch(db: &Database, voucher: &Keypair, subject: &Address, at: i64) {
        let mut log = AppendLog::new(db);
        let vouch = Attestation {
            kind: VouchKind,
            body: VouchBody {
                community: "commons".into(),
                statement: "trustworthy".into(),
                reputation_stake_centi: 0,
            },
            subject: *subject,
            issued_at: at,
            expires_at: None,
        };
        log.append(vouch.sign(voucher), 0).unwrap();
    }

    /// Raises `who`'s **raw** composite over the Member band — ten settled trades
    /// plus ten vouches written, the recipe `scoring`'s own tests use to mint a
    /// member established enough to anchor others.
    fn earn_raw_standing(db: &Database, who: &Keypair, station: &Keypair, at: i64) {
        for nonce in 0..10 {
            append_settled(db, who, station, station, nonce, at);
        }
        for _ in 0..10 {
            append_vouch(db, who, &addr(&Keypair::generate()), at);
        }
    }

    #[test]
    fn composite_to_centi_clamps_and_rounds() {
        assert_eq!(composite_to_centi(0.0), 0);
        assert_eq!(composite_to_centi(2.5), 250);
        assert_eq!(composite_to_centi(5.0), 500);
        // Rounds to the nearest centi.
        assert_eq!(composite_to_centi(2.005), 201);
        // Out-of-range values are clamped, never negative or over 500.
        assert_eq!(composite_to_centi(-1.0), 0);
        assert_eq!(composite_to_centi(9.9), 500);
    }

    #[test]
    fn decide_established_is_allowed_without_grace_regardless_of_count() {
        // At or above the floor, allowed and not via grace — even with zero
        // established members counted.
        assert_eq!(
            decide(BAND_MEMBER_MIN, 250, 0),
            Tier2Eligibility::Allowed {
                stake_centi: 250,
                via_grace: false
            }
        );
    }

    #[test]
    fn decide_below_floor_grants_grace_then_refuses_at_threshold() {
        let below = BAND_MEMBER_MIN - 0.01;
        // Fewer than the threshold established → grace.
        assert_eq!(
            decide(below, 40, BOOTSTRAP_GRACE_THRESHOLD - 1),
            Tier2Eligibility::Allowed {
                stake_centi: 40,
                via_grace: true
            }
        );
        // Exactly the threshold established → grace has ended, refused.
        assert_eq!(
            decide(below, 40, BOOTSTRAP_GRACE_THRESHOLD),
            Tier2Eligibility::Refused {
                composite: below,
                established: BOOTSTRAP_GRACE_THRESHOLD
            }
        );
    }

    #[test]
    fn grace_lets_a_new_member_confirm_in_a_fresh_community() {
        let db = fresh_db();
        let (buyer, newcomer, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        // The newcomer receives (and confirms) a couple of trades: some raw
        // standing, but nowhere near the Member band, and nobody has anchored them.
        append_settled(&db, &buyer, &newcomer, &station, 0, t);
        append_settled(&db, &buyer, &newcomer, &station, 1, t);

        // No member is established, so the bootstrap grace is open.
        assert_eq!(established_member_count(&db, t).unwrap(), 0);

        let decision = evaluate_tier2_confirmation(&db, &addr(&newcomer), t).unwrap();
        match decision {
            Tier2Eligibility::Allowed {
                stake_centi,
                via_grace,
            } => {
                assert!(
                    via_grace,
                    "a below-floor newcomer is allowed only via grace"
                );
                // The stake is their raw composite, and they have some.
                assert!(stake_centi > 0);
                assert_eq!(
                    stake_centi,
                    tier2_stake_centi(&db, &addr(&newcomer), t).unwrap()
                );
            }
            other => panic!("expected grace allowance, got {other:?}"),
        }
    }

    #[test]
    fn established_member_count_counts_anchored_members_over_the_band() {
        let db = fresh_db();
        let (patron_a, patron_b, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;

        // Two members earn raw standing over the band, then anchor each other, so
        // each reads at its true (uncapped) composite rather than the anchor cap.
        earn_raw_standing(&db, &patron_a, &station, t);
        earn_raw_standing(&db, &patron_b, &station, t);
        // Before anchoring, neither is *effectively* established (both capped).
        assert_eq!(established_member_count(&db, t).unwrap(), 0);

        append_vouch(&db, &patron_a, &addr(&patron_b), t);
        append_vouch(&db, &patron_b, &addr(&patron_a), t);

        // Now both clear the Member band on their effective (anchored) composite;
        // the many trade counterparties and vouch subjects stay well below it.
        assert_eq!(established_member_count(&db, t).unwrap(), 2);
    }

    #[test]
    fn an_established_confirmer_stakes_without_grace() {
        let db = fresh_db();
        let (patron_a, patron_b, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 10 * MONTH;
        earn_raw_standing(&db, &patron_a, &station, t);
        earn_raw_standing(&db, &patron_b, &station, t);
        append_vouch(&db, &patron_a, &addr(&patron_b), t);
        append_vouch(&db, &patron_b, &addr(&patron_a), t);

        // patron_a is established, so confirming is allowed on their own standing.
        match evaluate_tier2_confirmation(&db, &addr(&patron_a), t).unwrap() {
            Tier2Eligibility::Allowed {
                stake_centi,
                via_grace,
            } => {
                assert!(!via_grace, "an established member does not need grace");
                assert!(stake_centi >= composite_to_centi(BAND_MEMBER_MIN));
            }
            other => panic!("expected an established allowance, got {other:?}"),
        }
    }

    /// Anchors `n` members over the Member band by minting raw standing for each
    /// and cross-vouching them, the recipe the two-member test above uses,
    /// generalized. Returns the established keypairs.
    fn establish_members(db: &Database, station: &Keypair, n: usize, at: i64) -> Vec<Keypair> {
        let members: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
        for m in &members {
            earn_raw_standing(db, m, station, at);
        }
        // Every member vouches for every other, so each is anchored by a peer.
        for voucher in &members {
            for subject in &members {
                if addr(voucher) != addr(subject) {
                    append_vouch(db, voucher, &addr(subject), at);
                }
            }
        }
        members
    }

    #[test]
    fn in_grace_until_the_threshold_is_reached() {
        let station = Keypair::generate();
        let t = 10 * MONTH;

        // A fresh log has no established members — squarely in grace.
        let db0 = fresh_db();
        assert!(in_grace(&db0, t).unwrap());

        // Two established is still short of the threshold of three.
        let db2 = fresh_db();
        establish_members(&db2, &station, 2, t);
        assert_eq!(established_member_count(&db2, t).unwrap(), 2);
        assert!(in_grace(&db2, t).unwrap());

        // Three established tips the community out of grace.
        let db3 = fresh_db();
        establish_members(&db3, &station, 3, t);
        assert_eq!(established_member_count(&db3, t).unwrap(), 3);
        assert!(!in_grace(&db3, t).unwrap());
    }

    #[test]
    fn grace_electorate_unions_founders_while_bootstrapping() {
        let db = fresh_db();
        let t = 10 * MONTH;
        let (f1, f2) = (Keypair::generate(), Keypair::generate());
        let founders = [addr(&f1), addr(&f2)];

        // No established members yet: the electorate is exactly the founders.
        let electorate = grace_electorate(&db, &founders, t).unwrap();
        assert_eq!(electorate.len(), 2);
        assert!(electorate.contains(&addr(&f1)));
        assert!(electorate.contains(&addr(&f2)));
    }

    #[test]
    fn grace_electorate_adds_early_established_non_founders() {
        let db = fresh_db();
        let station = Keypair::generate();
        let t = 10 * MONTH;
        let founder = Keypair::generate();

        // Two members establish (still in grace); neither is the founder.
        let established = establish_members(&db, &station, 2, t);
        let electorate = grace_electorate(&db, &[addr(&founder)], t).unwrap();

        // The union is the two established members plus the founder.
        assert_eq!(electorate.len(), 3);
        assert!(electorate.contains(&addr(&founder)));
        for m in &established {
            assert!(electorate.contains(&addr(m)));
        }
    }

    #[test]
    fn grace_electorate_does_not_double_count_an_established_founder() {
        let db = fresh_db();
        let station = Keypair::generate();
        let t = 10 * MONTH;

        // Two members establish, and one of them is also named a founder.
        let established = establish_members(&db, &station, 2, t);
        let founder_addr = addr(&established[0]);
        let electorate = grace_electorate(&db, &[founder_addr], t).unwrap();

        // The overlapping founder is not added twice.
        assert_eq!(electorate.len(), 2);
    }

    #[test]
    fn grace_electorate_is_established_only_once_grace_ends() {
        let db = fresh_db();
        let station = Keypair::generate();
        let t = 10 * MONTH;

        // Three members establish → grace is over.
        establish_members(&db, &station, 3, t);
        assert!(!in_grace(&db, t).unwrap());

        // A founder who never established is now excluded: the electorate is the
        // established set alone.
        let outsider = Keypair::generate();
        let electorate = grace_electorate(&db, &[addr(&outsider)], t).unwrap();
        assert_eq!(electorate.len(), 3);
        assert!(!electorate.contains(&addr(&outsider)));
    }
}
