//! Airtime budgeting for constrained carriers (T2.6.2, ADR-0013).
//!
//! LoRa is honest about its ceiling: ~250 raw bytes/second, and duty-cycle rules
//! in some regions cut *sustained* throughput to single-digit bytes/second
//! (design overview §10.3). Reticulum's own announces and path requests share
//! that channel with our ledger and gossip traffic (ADR-0013's announce-budget
//! consequence). So a station that carries traffic over such a link must **pace**
//! it, and pace it by **importance**: a settlement or a certificate must not wait
//! behind a marketplace listing.
//!
//! This module is the pacing primitive, carrier-agnostic (it moves opaque frames
//! to opaque [`Endpoint`](crate::transport::Endpoint)s and knows nothing about
//! Reticulum): a **token bucket** at the sustained rate, capped at a burst, drains
//! **three strict-priority FIFO queues**. It is deliberately clock-injected — every
//! method takes `now: i64` (Unix seconds) rather than reading a clock — so the
//! deterministic tests fast-forward simulated hours without sleeping, and the
//! daemon feeds it its own injected clock.
//!
//! Strict priority means a lower-priority frame is **never** sent while a
//! higher-priority frame is waiting — even a small [`Priority::Bulk`] frame that
//! would fit the current tokens does not jump ahead of a large
//! [`Priority::Economic`] frame that does not. That is head-of-line by design: it
//! guarantees economic traffic is never starved by bulk (the reverse — bulk
//! starved under sustained economic load — is accepted, see the threat model).

use std::collections::VecDeque;

use crate::transport::Endpoint;

/// The three traffic classes, drained in strict priority order (`Economic`
/// first). The discriminants are the queue order and are load-bearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Money and its proof: transactions, certificates, delivery receipts. Never
    /// dropped, never starved.
    Economic = 0,
    /// Governance and disputes: proposals, votes, verdicts, ballots.
    Governance = 1,
    /// Everything else — marketplace, reputation gossip, discovery. Dropped
    /// oldest-first under queue pressure; starved under sustained higher-class
    /// load. This is the class that yields.
    Bulk = 2,
}

impl Priority {
    /// All three, highest priority first — the strict drain order.
    pub const ORDER: [Priority; 3] = [Priority::Economic, Priority::Governance, Priority::Bulk];
}

/// Classifies a signed record `kind` discriminator (`"rrn.<area>.<name>"`) into a
/// pacing [`Priority`]. Money moves first, governance second, the rest last; an
/// unknown kind is [`Priority::Bulk`] — the safe default, since misclassifying
/// *down* only ever delays a frame, never a settlement.
///
/// A **bundle** carries several records and takes the highest priority among
/// them ([`bundle_priority`]); a station sending over a constrained carrier should
/// therefore assemble single-class bundles (the DTN wiring does).
pub fn classify(kind: &str) -> Priority {
    // Money and its proof.
    if kind.starts_with("rrn.tx.") || kind.starts_with("rrn.credit.") || kind == "rrn.dtn.receipt" {
        return Priority::Economic;
    }
    // Governance and disputes.
    if kind.starts_with("rrn.gov.") || kind.starts_with("rrn.dispute.") {
        return Priority::Governance;
    }
    Priority::Bulk
}

/// The highest [`Priority`] among a bundle's carried records — the class the whole
/// bundle is paced at. A bundle whose records cannot be decoded (it should never
/// happen post-validation) is treated as [`Priority::Bulk`], never elevated.
pub fn bundle_priority(bundle: &crate::bundle::Bundle) -> Priority {
    bundle
        .record_kinds()
        .into_iter()
        .map(|k| classify(&k))
        .min() // min discriminant == highest priority (Economic = 0)
        .unwrap_or(Priority::Bulk)
}

/// The sustained rate and burst ceiling a [`PacedSender`] paces to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AirtimeBudget {
    /// Long-run bytes/second the carrier may sustain (raw rate × duty cycle).
    pub sustained_bytes_per_sec: f64,
    /// The token-bucket ceiling in bytes — the largest burst allowed after an
    /// idle period, and (necessarily) the largest single frame that can ever be
    /// sent on this budget.
    pub burst_bytes: u32,
}

impl AirtimeBudget {
    /// Derives a budget from a raw carrier rate and a duty-cycle **percentage**
    /// (`1.0` = 1%): `sustained = raw × duty / 100`. Burst is passed through.
    pub fn from_duty_cycle(
        raw_bytes_per_sec: f64,
        duty_cycle_percent: f64,
        burst_bytes: u32,
    ) -> Self {
        Self {
            sustained_bytes_per_sec: raw_bytes_per_sec * duty_cycle_percent / 100.0,
            burst_bytes,
        }
    }
}

/// Per-queue depth caps (in whole frames). Defaults are generous for the economic
/// and governance classes and tighter for bulk, since bulk is the class that
/// yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueCaps {
    /// Max queued [`Priority::Economic`] frames before [`enqueue`](PacedSender::enqueue)
    /// refuses new ones (backpressure — never a silent drop).
    pub economic: usize,
    /// Max queued [`Priority::Governance`] frames before backpressure.
    pub governance: usize,
    /// Max queued [`Priority::Bulk`] frames before the **oldest** is dropped to
    /// make room.
    pub bulk: usize,
}

impl Default for QueueCaps {
    fn default() -> Self {
        Self {
            economic: 1024,
            governance: 1024,
            bulk: 256,
        }
    }
}

impl QueueCaps {
    fn cap_for(&self, p: Priority) -> usize {
        match p {
            Priority::Economic => self.economic,
            Priority::Governance => self.governance,
            Priority::Bulk => self.bulk,
        }
    }
}

/// The queue was full and the frame was refused (only ever raised for
/// [`Priority::Economic`] / [`Priority::Governance`] — bulk drops its oldest
/// instead). The caller must hold the frame and retry: economic traffic is never
/// silently dropped, so backpressure is surfaced, not swallowed.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("{priority:?} airtime queue is full ({depth} frames); frame refused (backpressure)")]
pub struct Backpressure {
    /// The class whose queue was full.
    pub priority: Priority,
    /// The queue depth at refusal (== the cap).
    pub depth: usize,
}

/// The outcome of a successful [`enqueue`](PacedSender::enqueue).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// The frame was queued and nothing was dropped.
    Accepted,
    /// The frame was queued after dropping the oldest bulk frame to make room.
    AcceptedDroppedOldest,
}

/// A pending frame: its destination and bytes.
#[derive(Clone, Debug)]
struct Frame {
    to: Endpoint,
    bytes: Vec<u8>,
}

/// A token-bucket, strict-priority pacer over a constrained carrier (module docs).
///
/// Clock-injected: [`enqueue`](Self::enqueue) records nothing about time;
/// [`pump`](Self::pump) takes `now` and is the only place the bucket refills and
/// frames leave. Not `Send`-shared internally — wrap it in the daemon's own
/// mutex/task if shared.
pub struct PacedSender {
    budget: AirtimeBudget,
    caps: QueueCaps,
    /// Available tokens, in bytes. A frame of N bytes costs N tokens.
    tokens: f64,
    /// The `now` of the last refill.
    last_refill: i64,
    /// One FIFO per class, indexed by `Priority as usize`.
    queues: [VecDeque<Frame>; 3],
    /// Count of bulk frames dropped to make room, for observability.
    dropped_bulk: u64,
}

impl PacedSender {
    /// A new pacer for `budget`, its bucket starting **full** (so an idle station
    /// may burst up to `burst_bytes` immediately), with default [`QueueCaps`].
    /// `now` seeds the refill clock.
    pub fn new(budget: AirtimeBudget, now: i64) -> Self {
        Self::with_caps(budget, QueueCaps::default(), now)
    }

    /// [`new`](Self::new) with explicit queue caps.
    pub fn with_caps(budget: AirtimeBudget, caps: QueueCaps, now: i64) -> Self {
        PacedSender {
            tokens: budget.burst_bytes as f64,
            budget,
            caps,
            last_refill: now,
            queues: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            dropped_bulk: 0,
        }
    }

    /// Queues `bytes` for `to` at `priority`. Economic/governance overflow raises
    /// [`Backpressure`] (the caller must hold and retry); bulk overflow drops its
    /// oldest frame and reports [`Enqueued::AcceptedDroppedOldest`].
    ///
    /// A frame larger than the budget's `burst_bytes` can never be sent (the
    /// bucket cannot hold enough tokens); it is refused as backpressure rather
    /// than queued to starve the class forever. Callers chunk to
    /// [`TransportProfile::max_frame_bytes`](crate::transport::TransportProfile),
    /// which a correct config keeps ≤ `burst_bytes`.
    pub fn enqueue(
        &mut self,
        priority: Priority,
        to: Endpoint,
        bytes: Vec<u8>,
    ) -> Result<Enqueued, Backpressure> {
        if bytes.len() as u64 > self.budget.burst_bytes as u64 {
            return Err(Backpressure {
                priority,
                depth: self.queues[priority as usize].len(),
            });
        }
        let cap = self.caps.cap_for(priority);
        let q = &mut self.queues[priority as usize];
        let mut outcome = Enqueued::Accepted;
        if q.len() >= cap {
            match priority {
                Priority::Bulk => {
                    q.pop_front();
                    self.dropped_bulk += 1;
                    outcome = Enqueued::AcceptedDroppedOldest;
                }
                Priority::Economic | Priority::Governance => {
                    return Err(Backpressure {
                        priority,
                        depth: q.len(),
                    });
                }
            }
        }
        q.push_back(Frame { to, bytes });
        Ok(outcome)
    }

    /// Refills the bucket to `now` and drains as many queued frames as the tokens
    /// allow, in strict priority order, handing each to `send`. Returns the number
    /// of frames sent.
    ///
    /// Stops at the first frame that does not fit the current tokens **without
    /// considering lower-priority queues** — head-of-line strict priority. A frame
    /// costs its byte length in tokens.
    pub fn pump<F: FnMut(Endpoint, Vec<u8>)>(&mut self, now: i64, mut send: F) -> usize {
        self.refill(now);
        let mut sent = 0;
        loop {
            // The highest-priority non-empty queue.
            let next = Priority::ORDER
                .into_iter()
                .find(|p| !self.queues[*p as usize].is_empty());
            let Some(p) = next else { break };
            let front_len = self.queues[p as usize]
                .front()
                .map(|f| f.bytes.len())
                .unwrap_or(0);
            if (front_len as f64) > self.tokens {
                // Token-limited at the head: wait for refill; do NOT serve a lower
                // class (that would be priority inversion).
                break;
            }
            self.tokens -= front_len as f64;
            let frame = self.queues[p as usize].pop_front().expect("front present");
            send(frame.to, frame.bytes);
            sent += 1;
        }
        sent
    }

    /// Tops the bucket up by the time elapsed since the last refill, capped at
    /// `burst_bytes`. Time going backwards (a clock adjustment) adds nothing.
    fn refill(&mut self, now: i64) {
        let dt = (now - self.last_refill).max(0) as f64;
        self.last_refill = now;
        let refilled = self.tokens + dt * self.budget.sustained_bytes_per_sec;
        self.tokens = refilled.min(self.budget.burst_bytes as f64);
    }

    /// Total queued frames across all classes.
    pub fn queued(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Queued frames in one class.
    pub fn queued_in(&self, p: Priority) -> usize {
        self.queues[p as usize].len()
    }

    /// Count of bulk frames dropped (oldest-first) to make room, cumulative.
    pub fn dropped_bulk(&self) -> u64 {
        self.dropped_bulk
    }

    /// The budget this pacer runs on.
    pub fn budget(&self) -> AirtimeBudget {
        self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> Endpoint {
        Endpoint::new(s)
    }

    #[test]
    fn classify_maps_kinds_to_classes() {
        // Economic: money and its proof.
        for k in [
            "rrn.tx.proposal",
            "rrn.tx.confirmation",
            "rrn.tx.settlement",
            "rrn.tx.cancellation",
            "rrn.tx.contract_charge",
            "rrn.tx.dispute",
            "rrn.credit.certificate",
            "rrn.credit.cert_request",
            "rrn.credit.cert_return",
            "rrn.credit.equivocation",
            "rrn.credit.equivocation_verdict",
            "rrn.dtn.receipt",
        ] {
            assert_eq!(classify(k), Priority::Economic, "{k}");
        }
        // Governance and disputes.
        for k in [
            "rrn.gov.proposal",
            "rrn.gov.vote",
            "rrn.gov.charter",
            "rrn.gov.proposal_cosign",
            "rrn.gov.proposal_implemented",
            "rrn.dispute.verdict",
            "rrn.dispute.escalation",
            "rrn.dispute.equivocation_ballot",
            "rrn.dispute.equivocation_reseat",
            "rrn.dispute.escalation_ballot",
        ] {
            assert_eq!(classify(k), Priority::Governance, "{k}");
        }
        // Everything else, including unknowns and the raw outbox wrapper, is Bulk.
        for k in [
            "rrn.market.listing",
            "rrn.rep.snapshot",
            "rrn.dtn.outbox",
            "nonsense",
            "",
        ] {
            assert_eq!(classify(k), Priority::Bulk, "{k}");
        }
    }

    #[test]
    fn duty_cycle_derivation() {
        // 250 raw B/s at 1% duty → 2.5 sustained B/s (the design's LoRa figure).
        let b = AirtimeBudget::from_duty_cycle(250.0, 1.0, 500);
        assert_eq!(b.sustained_bytes_per_sec, 2.5);
        assert_eq!(b.burst_bytes, 500);
    }

    #[test]
    fn burst_cap_bounds_accumulated_tokens() {
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 10.0,
            burst_bytes: 100,
        };
        let mut s = PacedSender::new(budget, 0);
        // Idle for an hour: tokens must not exceed the 100-byte burst cap.
        let mut sent = Vec::new();
        // One 100-byte frame should go; a second should not (bucket was capped at
        // 100, not 36_000).
        s.enqueue(Priority::Bulk, ep("p"), vec![0u8; 100]).unwrap();
        s.enqueue(Priority::Bulk, ep("p"), vec![0u8; 100]).unwrap();
        let n = s.pump(3600, |_, b| sent.push(b.len()));
        assert_eq!(n, 1, "burst cap should permit exactly one 100-byte frame");
        assert_eq!(sent, vec![100]);
    }

    #[test]
    fn sustained_rate_honored_over_simulated_hours() {
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 2.0,
            burst_bytes: 10,
        };
        let mut s = PacedSender::new(budget, 0);
        // Queue far more than can be sent: 200 frames of 10 bytes = 2000 bytes.
        for _ in 0..200 {
            s.enqueue(Priority::Economic, ep("p"), vec![0u8; 10])
                .unwrap();
        }
        // Pump once per simulated second for 1000s. At 2 B/s sustained, ~2000
        // bytes = ~200 frames of 10 bytes should clear (plus the initial burst of
        // 10 tokens = 1 frame). Allow the burst slop.
        let mut total_bytes = 0usize;
        for now in 1..=1000 {
            s.pump(now, |_, b| total_bytes += b.len());
        }
        // 1000s × 2 B/s = 2000 sustained, + up to burst (10). Everything queued
        // (2000 bytes) should be gone within the bound.
        assert_eq!(
            s.queued(),
            0,
            "all frames should clear within the time budget"
        );
        assert_eq!(total_bytes, 2000);
        // And the average rate never exceeded sustained+burst over the run.
        assert!(total_bytes as f64 <= 1000.0 * 2.0 + budget.burst_bytes as f64);
    }

    #[test]
    fn strict_priority_economic_before_bulk_never_reverse() {
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 1.0,
            burst_bytes: 10,
        };
        let mut s = PacedSender::new(budget, 0);
        // Bulk enqueued first, economic second — priority, not arrival, decides.
        s.enqueue(Priority::Bulk, ep("p"), vec![b'B'; 10]).unwrap();
        s.enqueue(Priority::Economic, ep("p"), vec![b'E'; 10])
            .unwrap();
        let mut order = Vec::new();
        // t=0: 10 burst tokens → exactly one 10-byte frame; must be the economic one.
        s.pump(0, |_, b| order.push(b[0]));
        assert_eq!(order, vec![b'E']);
        assert_eq!(s.queued_in(Priority::Bulk), 1, "bulk must still be waiting");
        // t=10: +10 tokens → the bulk frame now clears.
        s.pump(10, |_, b| order.push(b[0]));
        assert_eq!(order, vec![b'E', b'B']);
    }

    #[test]
    fn a_large_economic_head_blocks_a_small_bulk_frame() {
        // Head-of-line: a bulk frame that WOULD fit must not jump a not-yet-fitting
        // economic frame.
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 1.0,
            burst_bytes: 100,
        };
        let mut s = PacedSender::new(budget, 0);
        // Drain the initial full bucket so tokens are ~0.
        s.enqueue(Priority::Bulk, ep("p"), vec![0u8; 100]).unwrap();
        s.pump(0, |_, _| {});
        // A 100B economic head and a 5B bulk frame; at t=5 only 5 tokens exist.
        s.enqueue(Priority::Economic, ep("p"), vec![0u8; 100])
            .unwrap();
        s.enqueue(Priority::Bulk, ep("p"), vec![0u8; 5]).unwrap();
        let mut sent = 0;
        let n = s.pump(5, |_, _| sent += 1);
        assert_eq!(
            n, 0,
            "the small bulk frame must not jump the large economic head"
        );
        assert_eq!(sent, 0);
        // Later, the economic head clears first (it takes a whole burst's worth of
        // tokens); the bulk frame clears only on a subsequent pump. Economic before
        // bulk, always.
        let mut order = Vec::new();
        s.pump(200, |_, b| order.push(b.len())); // ~100 tokens (burst cap) → economic
        s.pump(400, |_, b| order.push(b.len())); // more tokens → bulk
        assert_eq!(order, vec![100, 5]);
    }

    #[test]
    fn bulk_overflow_drops_oldest_economic_overflow_backpressures() {
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 0.0, // never refills; we never pump — pure queue behavior
            burst_bytes: 100,
        };
        let caps = QueueCaps {
            economic: 2,
            governance: 2,
            bulk: 2,
        };
        let mut s = PacedSender::with_caps(budget, caps, 0);
        // Bulk: third enqueue drops the oldest and reports it.
        assert_eq!(
            s.enqueue(Priority::Bulk, ep("p"), vec![1]).unwrap(),
            Enqueued::Accepted
        );
        assert_eq!(
            s.enqueue(Priority::Bulk, ep("p"), vec![2]).unwrap(),
            Enqueued::Accepted
        );
        assert_eq!(
            s.enqueue(Priority::Bulk, ep("p"), vec![3]).unwrap(),
            Enqueued::AcceptedDroppedOldest
        );
        assert_eq!(s.queued_in(Priority::Bulk), 2);
        assert_eq!(s.dropped_bulk(), 1);
        // Economic: third enqueue is refused as backpressure, nothing dropped.
        s.enqueue(Priority::Economic, ep("p"), vec![1]).unwrap();
        s.enqueue(Priority::Economic, ep("p"), vec![1]).unwrap();
        let err = s.enqueue(Priority::Economic, ep("p"), vec![1]).unwrap_err();
        assert_eq!(err.priority, Priority::Economic);
        assert_eq!(s.queued_in(Priority::Economic), 2);
    }

    #[test]
    fn a_frame_larger_than_burst_is_refused_not_wedged() {
        let budget = AirtimeBudget {
            sustained_bytes_per_sec: 100.0,
            burst_bytes: 50,
        };
        let mut s = PacedSender::new(budget, 0);
        let err = s
            .enqueue(Priority::Economic, ep("p"), vec![0u8; 51])
            .unwrap_err();
        assert_eq!(err.priority, Priority::Economic);
        assert_eq!(s.queued(), 0);
    }
}
