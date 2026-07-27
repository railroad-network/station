//! Snapshot — a materialized cache of reputation profiles over the log.
//!
//! Scoring replays the whole log, which is fine for correctness but wasteful to
//! repeat on every read. A snapshot is the scored profile stored in the
//! `reputation_snapshots` table so hot paths can read it back without a replay.
//! The log stays canonical; a snapshot is only a cache, always re-derivable and
//! safe to drop.
//!
//! [`get_cached_profile`] serves a stored profile if it is fresh enough for the
//! caller's tolerance; [`refresh_snapshot`] recomputes one identity and writes it;
//! [`refresh_all_snapshots`] is the station's hourly sweep over every known
//! identity. Writes are last-write-wins on the computation time (see
//! [`rrn_storage::reputation_snapshot::put`]): because every station derives the
//! same profile from the same log, the only thing a merge has to decide is which
//! computation is fresher.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rrn_crypto::serialize::{from_canonical_bytes, to_canonical_bytes};
use rrn_identity::address::Address;
use rrn_identity::vouch::Vouch;
use rrn_ledger::state::{LedgerSnapshot, TransactionState};
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::reputation_snapshot as store;

use crate::model::ReputationProfile;
use crate::scoring::ReputationScorer;
use crate::sybil::check_velocity;
use crate::Result;

/// Returns the cached profile for `address` if one is stored and no older than
/// `max_age_seconds`, else `None` (a miss the caller resolves with
/// [`refresh_snapshot`]).
///
/// Freshness is judged against the wall clock — a cache decision, not a scored
/// value, so reading the system time here does not affect determinism: the stored
/// profile was itself computed deterministically.
pub fn get_cached_profile(
    db: &Database,
    address: &Address,
    max_age_seconds: i64,
) -> Result<Option<ReputationProfile>> {
    let Some(snapshot) = store::get(db, &address.public_key().to_bytes())? else {
        return Ok(None);
    };
    if now_secs().saturating_sub(snapshot.last_computed_at) > max_age_seconds {
        return Ok(None);
    }
    Ok(Some(from_canonical_bytes::<ReputationProfile>(
        &snapshot.profile_cbor,
    )?))
}

/// Recomputes `address`'s profile as of `now` and writes it to the cache,
/// last-write-wins on `now`. Returns the freshly computed profile.
///
/// The refresh is also where the velocity cap is measured, since it is the only
/// place two consecutive profiles for an identity meet
/// ([`crate::sybil::check_velocity`]). A violation is logged for operator review
/// and nothing else: the snapshot is still written and the score still stands, by
/// design — humans decide what an implausible gain means.
pub fn refresh_snapshot(db: &Database, address: &Address, now: i64) -> Result<ReputationProfile> {
    let profile = ReputationScorer::new(db).score(address, now)?;

    if let Some(previous) = stored_profile(db, address)? {
        if let Err(violation) = check_velocity(&previous, &profile) {
            // The operator UI that surfaces this is a later milestone; the log
            // line is the Phase 1 alert.
            tracing::warn!(
                address = %address,
                %violation,
                "reputation velocity cap exceeded — flagged for review"
            );
        }
    }

    let bytes = to_canonical_bytes(profile.clone());
    store::put(db, &address.public_key().to_bytes(), now, &bytes)?;
    Ok(profile)
}

/// The stored profile for `address` whatever its age, or `None` if there is no
/// snapshot yet. Unlike [`get_cached_profile`] this ignores freshness: the
/// velocity check wants the previous profile precisely because it is old.
fn stored_profile(db: &Database, address: &Address) -> Result<Option<ReputationProfile>> {
    let Some(snapshot) = store::get(db, &address.public_key().to_bytes())? else {
        return Ok(None);
    };
    Ok(Some(from_canonical_bytes::<ReputationProfile>(
        &snapshot.profile_cbor,
    )?))
}

/// Recomputes and writes a snapshot for every identity that appears in the log.
/// Returns how many identities were refreshed. This is the body of the station's
/// hourly background refresh.
pub fn refresh_all_snapshots(db: &Database, now: i64) -> Result<usize> {
    let addresses = known_addresses(db)?;
    let count = addresses.len();
    for address in addresses {
        refresh_snapshot(db, &address, now)?;
    }
    Ok(count)
}

/// Every distinct identity that appears anywhere in the log — as a transacting
/// party or on either side of a vouch. These are exactly the identities that can
/// have a non-empty profile, and the set is derived from the canonical log so it
/// is identical on every replica.
fn known_addresses(db: &Database) -> Result<Vec<Address>> {
    let log = AppendLog::new(db);
    let mut addresses: HashSet<Address> = HashSet::new();

    let ledger = LedgerSnapshot::derive(&log)?;
    for (_, state) in ledger.iter() {
        if let Some(proposal) = proposal_of(state) {
            addresses.insert(proposal.sender);
            addresses.insert(proposal.receiver);
        }
    }

    for entry in log.iter_from(1) {
        let entry = entry?;
        if let Ok(vouch) = from_canonical_bytes::<Vouch>(&entry.payload.bytes) {
            addresses.insert(Address::from_public_key(entry.payload.signer));
            addresses.insert(vouch.subject);
        }
    }

    Ok(addresses.into_iter().collect())
}

/// The (sender, receiver) of a transaction state, or `None` for the disputed stub
/// that carries no proposal.
fn proposal_of(state: &TransactionState) -> Option<Parties> {
    match state {
        TransactionState::Proposed { proposal }
        | TransactionState::Confirmed { proposal, .. }
        | TransactionState::Settled { proposal, .. }
        | TransactionState::Cancelled { proposal, .. } => Some(Parties {
            sender: proposal.payload.sender,
            receiver: proposal.payload.receiver,
        }),
        TransactionState::DisputedStub => None,
    }
}

/// The two parties to a transaction.
struct Parties {
    sender: Address,
    receiver: Address,
}

/// Current wall-clock Unix seconds — used only for cache-freshness decisions.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_crypto::keypair::Keypair;
    use rrn_crypto::signed::SignedPayload;
    use rrn_ledger::settlement::SettlementRecord;
    use rrn_ledger::transaction::{TransactionConfirmation, TransactionProposal};
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

    /// Appends a settled transaction so the parties have real evidence to score.
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
        log.append(SignedPayload::sign(proposal, sender)).unwrap();
        let confirmation = TransactionConfirmation {
            proposal_id: pid,
            confirmer: addr(receiver),
            confirmed_at: at,
        };
        log.append(SignedPayload::sign(confirmation, receiver))
            .unwrap();
        let settlement = SettlementRecord {
            proposal_id: pid,
            sender: addr(sender),
            receiver: addr(receiver),
            amount_centi: 300,
            settled_at: at,
        };
        log.append(SignedPayload::sign(settlement, station))
            .unwrap();
    }

    #[test]
    fn snapshot_written_and_read_back_identical() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 8 * MONTH;
        append_settled(&db, &alice, &bob, &station, 0, t);

        let written = refresh_snapshot(&db, &addr(&alice), t).unwrap();
        // A generous max age so freshness never rejects it here.
        let read = get_cached_profile(&db, &addr(&alice), i64::MAX).unwrap();
        assert_eq!(read, Some(written));
    }

    #[test]
    fn cache_miss_returns_none_then_refresh_populates() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 8 * MONTH;
        append_settled(&db, &alice, &bob, &station, 0, t);

        // No snapshot stored yet → miss.
        assert_eq!(
            get_cached_profile(&db, &addr(&alice), i64::MAX).unwrap(),
            None
        );
        // Refresh writes it; now it hits.
        let refreshed = refresh_snapshot(&db, &addr(&alice), t).unwrap();
        assert_eq!(
            get_cached_profile(&db, &addr(&alice), i64::MAX).unwrap(),
            Some(refreshed)
        );
    }

    #[test]
    fn stale_snapshot_is_a_miss() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        append_settled(&db, &alice, &bob, &station, 0, 8 * MONTH);
        // Computed "long ago" relative to the wall clock, so any small max age misses.
        refresh_snapshot(&db, &addr(&alice), 1).unwrap();
        assert_eq!(get_cached_profile(&db, &addr(&alice), 60).unwrap(), None);
    }

    #[test]
    fn refresh_all_covers_every_known_identity() {
        let db = fresh_db();
        let (alice, bob, carol, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 8 * MONTH;
        append_settled(&db, &alice, &bob, &station, 0, t);
        append_settled(&db, &bob, &carol, &station, 0, t);

        // alice, bob, carol all appear as transaction parties.
        assert_eq!(refresh_all_snapshots(&db, t).unwrap(), 3);
        for who in [&alice, &bob, &carol] {
            assert!(get_cached_profile(&db, &addr(who), i64::MAX)
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn older_recompute_does_not_clobber_a_newer_snapshot() {
        let db = fresh_db();
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 8 * MONTH;
        append_settled(&db, &alice, &bob, &station, 0, t);

        // Write a newer snapshot, then attempt an older recompute.
        let newer = refresh_snapshot(&db, &addr(&alice), t + 5 * MONTH).unwrap();
        let _older = refresh_snapshot(&db, &addr(&alice), t).unwrap();
        // The stored row is still the newer one (LWW guard held).
        let stored = get_cached_profile(&db, &addr(&alice), i64::MAX).unwrap();
        assert_eq!(stored, Some(newer));
    }

    #[test]
    fn two_stations_produce_the_same_snapshot() {
        let (alice, bob, station) = (
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        );
        let t = 6 * MONTH;
        let build = |db: &Database| append_settled(db, &alice, &bob, &station, 0, t);

        let db_a = fresh_db();
        let db_b = fresh_db();
        build(&db_a);
        build(&db_b);

        let now = t + 2 * MONTH;
        refresh_snapshot(&db_a, &addr(&alice), now).unwrap();
        refresh_snapshot(&db_b, &addr(&alice), now).unwrap();
        // Compare the stored bytes directly: identical logs → identical snapshots.
        let a = store::get(&db_a, &addr(&alice).public_key().to_bytes()).unwrap();
        let b = store::get(&db_b, &addr(&alice).public_key().to_bytes()).unwrap();
        assert_eq!(a, b);
    }
}
