//! Equivalence proof for the kind-dispatch rewrite of listing-lifecycle replay.
//!
//! [`lifecycle::scan`] used to trial-decode each of the four listing record types
//! against every log entry; it now parses the entry once and dispatches on the
//! `kind` discriminator. Both paths fold a decoded record through the same
//! `fold_*` helpers, so what this test isolates is the routing: whether kind
//! dispatch selects the same record (or the same skip) as trial decoding.
//!
//! [`lifecycle::compute_all`] (dispatch) is asserted equal to
//! [`lifecycle::compute_all_reference`] (trial decode) over randomly generated
//! logs of creations, updates, closes and sales — including forged-signer records
//! and garbage the scan must skip — at several `now` instants. `ListingState`
//! derives `PartialEq`, so the full state of every listing must match.

use proptest::prelude::*;

use rrn_crypto::keypair::Keypair;
use rrn_crypto::serialize::to_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_storage::db::Database;
use rrn_storage::log::{AppendLog, StoredPayload};
use rrn_storage::migrations;

use dcbor::prelude::Map;

use rrn_marketplace::lifecycle::{
    compute_all, compute_all_reference, CloseReason, ListingClosed, ListingPatch, ListingUpdated,
    StockConsumed,
};
use rrn_marketplace::listing::{
    Availability, AvailabilityStatus, Listing, ListingId, Pricing, PricingModel, Requirements,
    Surface,
};

fn addr(kp: &Keypair) -> Address {
    Address::from_public_key(kp.public_key())
}

fn listing_of(provider: &Keypair, capacity: Option<u32>, expires_at: Option<i64>) -> Listing {
    Listing::new(
        addr(provider),
        "commons".into(),
        Surface::Goods,
        "food".into(),
        "Winter squash".into(),
        "By the crate.".into(),
        Pricing {
            amount_centi: 250,
            model: PricingModel::Fixed,
            negotiable: false,
        },
        Availability {
            status: AvailabilityStatus::Available,
            capacity,
            next_slot: None,
        },
        Requirements {
            min_reputation: 0.0,
            community_member_only: false,
            federation_only: false,
        },
        1,
        false,
        1_000,
        expires_at,
    )
    .unwrap()
}

/// Appends a raw payload the scan must skip: a listing-kind map of the wrong
/// shape, an unrelated kind, or non-canonical / non-map bytes.
fn append_garbage(log: &mut AppendLog, signer: &Keypair, which: usize) {
    let bytes = match which % 7 {
        // A wrong-shape stock-consumed record.
        5 => {
            let mut m = Map::new();
            m.insert("kind", "rrn.marketplace.stock_consumed.v1");
            m.insert("junk", 1u64);
            to_canonical_bytes(m)
        }
        // A map with no `kind` key.
        6 => {
            let mut m = Map::new();
            m.insert("no_kind_here", 1u64);
            to_canonical_bytes(m)
        }
        0 => {
            let mut m = Map::new();
            m.insert("kind", "rrn.marketplace.listing.v1");
            m.insert("junk", 1u64);
            to_canonical_bytes(m)
        }
        1 => {
            let mut m = Map::new();
            m.insert("kind", "rrn.marketplace.listing_closed.v1");
            m.insert("junk", 1u64);
            to_canonical_bytes(m)
        }
        2 => {
            let mut m = Map::new();
            m.insert("kind", "rrn.tx.proposal");
            m.insert("junk", 1u64);
            to_canonical_bytes(m)
        }
        3 => vec![0x18, 0x17],
        _ => to_canonical_bytes(9u64),
    };
    let signature = signer.sign(&bytes);
    log.append_raw(
        StoredPayload {
            bytes,
            signer: signer.public_key(),
            signature,
        },
        0,
    )
    .unwrap();
}

#[derive(Clone, Debug)]
enum Action {
    /// Create a listing, signed by provider `p` (or, when `honest` is false, by
    /// someone else — a forged creation the scan must reject).
    Create {
        p: usize,
        honest: bool,
        capacity: Option<u32>,
        expires: bool,
    },
    /// Update an existing listing (by index into the created set), signed by `by`.
    Update {
        listing: usize,
        by: usize,
        price: i64,
    },
    /// Close a listing, signed by `by` (a member) or the station, for `reason`.
    Close {
        listing: usize,
        by_station: bool,
        by: usize,
        reason: usize,
    },
    /// A station-attested (or, when `honest` is false, forged) sale.
    Consume {
        listing: usize,
        honest: bool,
    },
    Garbage {
        which: usize,
    },
}

fn action_strategy(n: usize) -> impl Strategy<Value = Action> {
    prop_oneof![
        (
            0..n,
            any::<bool>(),
            prop::option::of(1u32..4),
            any::<bool>()
        )
            .prop_map(|(p, honest, capacity, expires)| Action::Create {
                p,
                honest,
                capacity,
                expires
            }),
        (
            0usize..8,
            0..n,
            prop::sample::select(vec![100i64, 199, 300])
        )
            .prop_map(|(listing, by, price)| Action::Update { listing, by, price }),
        (0usize..8, any::<bool>(), 0..n, 0usize..3).prop_map(
            |(listing, by_station, by, reason)| Action::Close {
                listing,
                by_station,
                by,
                reason
            }
        ),
        (0usize..8, any::<bool>())
            .prop_map(|(listing, honest)| Action::Consume { listing, honest }),
        (0usize..7).prop_map(|which| Action::Garbage { which }),
    ]
}

fn plan_strategy() -> impl Strategy<Value = (usize, Vec<Action>)> {
    (2usize..=4).prop_flat_map(|n| {
        proptest::collection::vec(action_strategy(n), 0..=24).prop_map(move |actions| (n, actions))
    })
}

const CLOSE_REASONS: [CloseReason; 3] = [
    CloseReason::ProviderClosed,
    CloseReason::ExpirationReached,
    CloseReason::StationCleanup,
];

/// Builds a log from the plan using **unguarded** appends (`log.append`), so
/// forged-signer and out-of-order records reach replay exactly as gossip would
/// deliver them — replay's own authorization is what this exercises.
fn build_log(db: &Database, members: &[Keypair], station: &Keypair, plan: &[Action]) {
    let mut log = AppendLog::new(db);
    // Created listings in order, with the keypair that legitimately provides each.
    let mut listings: Vec<(ListingId, usize)> = Vec::new();
    for action in plan {
        match action {
            Action::Create {
                p,
                honest,
                capacity,
                expires,
            } => {
                let expires_at = expires.then_some(9_000_000);
                let listing = listing_of(&members[*p], *capacity, expires_at);
                let id = listing.id;
                let signer = if *honest {
                    &members[*p]
                } else {
                    &members[(*p + 1) % members.len()]
                };
                log.append(SignedPayload::sign(listing, signer), 0).unwrap();
                if *honest {
                    listings.push((id, *p));
                }
            }
            Action::Update { listing, by, price } => {
                if let Some((id, _)) = listings.get(*listing) {
                    let update = ListingUpdated {
                        listing_id: *id,
                        patch: ListingPatch {
                            pricing: Some(Pricing {
                                amount_centi: *price,
                                model: PricingModel::Fixed,
                                negotiable: false,
                            }),
                            ..ListingPatch::empty()
                        },
                        signed_by: addr(&members[*by]),
                    };
                    log.append(SignedPayload::sign(update, &members[*by]), 0)
                        .unwrap();
                }
            }
            Action::Close {
                listing,
                by_station,
                by,
                reason,
            } => {
                if let Some((id, _)) = listings.get(*listing) {
                    let close = ListingClosed {
                        listing_id: *id,
                        reason: CLOSE_REASONS[*reason],
                        closed_at: 5_000,
                    };
                    let signer = if *by_station { station } else { &members[*by] };
                    log.append(SignedPayload::sign(close, signer), 0).unwrap();
                }
            }
            Action::Consume { listing, honest } => {
                if let Some((id, provider)) = listings.get(*listing) {
                    let consumed = StockConsumed {
                        listing_id: *id,
                        tx_id: rrn_ledger::transaction::TransactionId(rrn_crypto::hash::Hash::of(
                            &[*listing as u8],
                        )),
                        consumed_at: 4_000,
                    };
                    let signer = if *honest {
                        station
                    } else {
                        &members[*provider]
                    };
                    log.append(SignedPayload::sign(consumed, signer), 0)
                        .unwrap();
                }
            }
            Action::Garbage { which } => append_garbage(&mut log, station, *which),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn dispatch_matches_trial_decode(
        (num_members, plan) in plan_strategy(),
        now in prop::sample::select(vec![0i64, 4_500, 6_000, 10_000_000]),
    ) {
        let db = Database::open_in_memory().unwrap();
        migrations::run(&db).unwrap();
        let station = Keypair::generate();
        let members: Vec<Keypair> = (0..num_members).map(|_| Keypair::generate()).collect();

        build_log(&db, &members, &station, &plan);
        let log = AppendLog::new(&db);
        let station_pub = station.public_key();

        let dispatched = compute_all(&log, &station_pub, now).unwrap();
        let reference = compute_all_reference(&log, &station_pub, now).unwrap();
        prop_assert!(
            dispatched == reference,
            "dispatch and trial-decode listing states differ at now={now}"
        );
    }
}
