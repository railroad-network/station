//! Property tests for the framing/reassembly layer (T2.2.5) — the heart of the
//! ticket. Chunking must be exactly invertible under arbitrary reordering and
//! duplication; it must never yield a *wrong* payload under loss; and a full
//! bundle must survive a lossy, duplicating, reordering, corrupting carrier with a
//! retransmit-until-complete driver.

use proptest::prelude::*;

use rrn_crypto::hash::Hash;
use rrn_protocol::framing::{chunk, Reassembler, ReassemblerConfig, HEADER_LEN, MAX_CHUNKS};
use rrn_protocol::transport::mock::{FaultConfig, FaultTransport, LoopbackNet, SplitMix64};
use rrn_protocol::transport::{Endpoint, FrameTransport};

/// A payload and a chunk capacity that always splits it into at most `MAX_CHUNKS`
/// chunks (so `chunk` never refuses). `cap` is the payload bytes per frame; the
/// frame budget handed to `chunk` is `HEADER_LEN + cap`.
fn payload_and_cap(max_len: usize) -> impl Strategy<Value = (Vec<u8>, usize)> {
    proptest::collection::vec(any::<u8>(), 0..max_len).prop_flat_map(|payload| {
        let min_cap = payload.len().div_ceil(MAX_CHUNKS).max(1);
        (Just(payload), min_cap..=4096usize)
    })
}

/// Like [`payload_and_cap`] but guarantees at least two chunks (`cap < len`), for
/// the drop test where a *proper* subset must be dropped.
fn multichunk_payload_and_cap() -> impl Strategy<Value = (Vec<u8>, usize)> {
    (2usize..8192).prop_flat_map(|len| {
        let min_cap = len.div_ceil(MAX_CHUNKS).max(1);
        let hi = (len - 1).min(4096);
        (
            proptest::collection::vec(any::<u8>(), len..=len),
            min_cap..=hi,
        )
    })
}

proptest! {
    /// Chunk, then deliver every chunk in an arbitrary order with an arbitrary
    /// subset duplicated: the reassembler returns exactly the original payload.
    #[test]
    fn reassembles_under_arbitrary_reorder_and_duplication(
        (payload, cap) in payload_and_cap(16 * 1024),
        seed in any::<u64>(),
    ) {
        let frames = chunk(&payload, HEADER_LEN + cap).unwrap();
        let mut rng = SplitMix64::new(seed);

        // A random permutation of the chunk indexes...
        let mut order: Vec<usize> = (0..frames.len()).collect();
        for i in (1..order.len()).rev() {
            let j = rng.below(i + 1);
            order.swap(i, j);
        }
        // ...with a random subset each delivered twice.
        let mut delivery = Vec::new();
        for idx in order {
            delivery.push(idx);
            if rng.next_f64() < 0.3 {
                delivery.push(idx);
            }
        }

        let mut r = Reassembler::new(ReassemblerConfig::default());
        let mut got = None;
        for idx in delivery {
            match r.accept(&frames[idx], 0) {
                Ok(Some(p)) => got = Some(p),
                Ok(None) => {}
                Err(e) => prop_assert!(false, "unexpected framing error: {e}"),
            }
        }
        prop_assert_eq!(got.as_ref(), Some(&payload));
        // Fully delivered ⇒ nothing left in flight.
        prop_assert_eq!(r.inflight(), 0);
    }

    /// With a proper subset of chunks dropped, the reassembler never completes
    /// (never returns a wrong payload), and `missing` reports exactly the dropped
    /// indexes.
    #[test]
    fn drops_never_complete_and_missing_is_exact(
        (payload, cap) in multichunk_payload_and_cap(),
        seed in any::<u64>(),
    ) {
        let frames = chunk(&payload, HEADER_LEN + cap).unwrap();
        prop_assert!(frames.len() >= 2);
        let payload_id = Hash::of(&payload).to_bytes();
        let mut rng = SplitMix64::new(seed);

        // Choose a nonempty *proper* subset to drop.
        let mut dropped: Vec<u16> = Vec::new();
        let mut delivered: Vec<usize> = Vec::new();
        for i in 0..frames.len() {
            if rng.next_f64() < 0.4 {
                dropped.push(i as u16);
            } else {
                delivered.push(i);
            }
        }
        if dropped.is_empty() {
            // force at least one drop
            dropped.push(delivered.pop().unwrap() as u16);
        } else if delivered.is_empty() {
            // keep at least one delivered so the payload becomes known
            let keep = dropped.pop().unwrap();
            delivered.push(keep as usize);
        }
        dropped.sort_unstable();

        // Deliver the kept chunks shuffled, with a random subset delivered twice:
        // a duplicate must never spuriously bump the payload to completion while a
        // dropped chunk is still missing.
        for i in (1..delivered.len()).rev() {
            let j = rng.below(i + 1);
            delivered.swap(i, j);
        }
        let mut delivery = Vec::new();
        for idx in &delivered {
            delivery.push(*idx);
            if rng.next_f64() < 0.5 {
                delivery.push(*idx);
            }
        }
        let mut r = Reassembler::new(ReassemblerConfig::default());
        for idx in &delivery {
            match r.accept(&frames[*idx], 0) {
                Ok(None) => {}
                Ok(Some(_)) => prop_assert!(false, "completed despite a dropped chunk"),
                Err(e) => prop_assert!(false, "unexpected framing error: {e}"),
            }
        }
        // `missing` names exactly the dropped indexes.
        prop_assert_eq!(r.missing(&payload_id), Some(dropped));
    }

    /// End to end: a payload chunked and pushed over a `FaultTransport` wrapping a
    /// `LoopbackNet` — dropping, duplicating, corrupting, and reordering frames —
    /// is delivered intact by a bounded retransmit-until-complete driver.
    #[test]
    fn survives_a_faulty_carrier_with_retransmits(
        (payload, cap) in payload_and_cap(8 * 1024),
        seed in any::<u64>(),
    ) {
        let max_frame = HEADER_LEN + cap;
        let frames = chunk(&payload, max_frame).unwrap();
        let payload_id = Hash::of(&payload).to_bytes();

        let net = LoopbackNet::new(max_frame);
        let sender = net.endpoint("s");
        let receiver = FaultTransport::new(
            net.endpoint("r"),
            FaultConfig {
                drop_prob: 0.25,
                dup_prob: 0.2,
                corrupt_prob: 0.1,
                reorder_window: 4,
                seed,
            },
        );
        let to_r = Endpoint::new("r");

        // Initial burst.
        for f in &frames {
            sender.send(&to_r, f.clone()).unwrap();
        }

        let mut r = Reassembler::new(ReassemblerConfig::default());
        let mut result = None;
        let max_iters = frames.len() * 60 + 500;
        for _ in 0..max_iters {
            for (_, f) in receiver.poll_recv().unwrap() {
                if let Ok(Some(p)) = r.accept(&f, 0) {
                    result = Some(p);
                }
                // Corrupted / conflicting frames are ignored and re-requested.
            }
            if result.is_some() {
                break;
            }
            // Retransmit what is still missing; if the payload is not yet known
            // (every initial frame lost), resend the whole burst.
            match r.missing(&payload_id) {
                Some(missing) => {
                    for idx in missing {
                        sender.send(&to_r, frames[idx as usize].clone()).unwrap();
                    }
                }
                None => {
                    for f in &frames {
                        sender.send(&to_r, f.clone()).unwrap();
                    }
                }
            }
        }
        prop_assert_eq!(result.as_ref(), Some(&payload));
    }
}
