//! The pluggable transport seam (ADR-0013).
//!
//! ADR-0013 committed to a transport abstraction in `rrn-protocol` — "deliver a
//! self-contained signed payload to a peer, independent of whether the bytes move
//! over TCP, Reticulum, LoRa, or SMS" — and deferred the *code* until "the trait
//! lands with its first real second implementor." Phase 2 is that moment: LoRa
//! (T2.6.2) and SMS (T2.7.1) both carry [`crate::bundle::Bundle`]s far larger than
//! their frame sizes over lossy, reordering, duplicating carriers. This module is
//! the seam; [`crate::framing`] is the carrier-agnostic chunking above it.
//!
//! # What the seam is, and is not (ADR-0013)
//!
//! A [`FrameTransport`] is a **dumb carrier**. It moves opaque frames between
//! [`Endpoint`]s and knows nothing about identity, sessions, sockets, or IP — an
//! `Endpoint` is a carrier-local routing handle ("bind, do not collapse"), never
//! an RRN identity. Integrity and authenticity live *above* the transport, in the
//! sealed-and-signed envelopes of ADR-0008/0020, exactly as they do over the
//! mobile↔station HTTP hop. A transport compromise can drop, reorder, duplicate,
//! or corrupt frames; it can never forge a record, because it never holds a key.
//!
//! # Sync and poll-based on purpose
//!
//! The trait is deliberately synchronous and poll-based — no `async_trait`, no
//! runtime dependency in this wire-format crate (a build assertion the ticket
//! enforces). LoRa and SMS carriers are polled by their nature; an async push
//! carrier adapts by draining into a buffer its `poll_recv` returns. The daemon
//! wraps polling in its own runtime. ADR-0013 notes the seam is fresh and
//! unshipped, so its first real integrator (T2.6.2) may revise this against the
//! sidecar's API at near-zero cost; it is intentionally not gold-plated here.

/// An opaque, carrier-specific peer designation — a *routing handle only*, never
/// an identity (ADR-0013: "bind, do not collapse"). For a TCP carrier it might be
/// `"host:port"`; for Reticulum, a destination hash; for the loopback mock, a
/// node name. Nothing above the transport interprets its contents.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint(pub String);

impl Endpoint {
    /// Wraps a string as an endpoint.
    pub fn new(s: impl Into<String>) -> Self {
        Endpoint(s.into())
    }
}

/// Carrier properties a caller adapts to — frame budgeting (chunk sizing) and
/// pacing (airtime/duty-cycle). Advisory: a transport reports these; the framing
/// layer sizes chunks to [`max_frame_bytes`](TransportProfile::max_frame_bytes),
/// and later a pacing layer (T2.6.2) respects the byte budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportProfile {
    /// The largest frame this carrier delivers whole, in bytes. The framing layer
    /// never hands [`FrameTransport::send`] a frame larger than this.
    pub max_frame_bytes: usize,
    /// A rough sustained throughput budget in bytes/second, duty-cycle-adjusted;
    /// `None` means effectively unconstrained (e.g. TCP). Used by a later pacing
    /// layer (T2.6.2), not here.
    pub sustained_bytes_per_sec: Option<u32>,
    /// Whether frames can arrive dropped, duplicated, or reordered. `false` for an
    /// ordered reliable carrier (TCP, loopback); `true` for LoRa/SMS.
    pub lossy: bool,
}

/// Why a transport operation failed. Carrier-agnostic: a concrete backend maps its
/// own errors onto these. Kept small — the seam does not model a carrier's full
/// error taxonomy, only what a caller can act on.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// A frame larger than the carrier's [`TransportProfile::max_frame_bytes`] was
    /// handed to [`FrameTransport::send`]. The framing layer should have chunked
    /// it; this guards a caller that did not.
    #[error("frame is {found} bytes, over the carrier's {max}-byte frame budget")]
    FrameTooLarge {
        /// The oversized frame's length.
        found: usize,
        /// The carrier's per-frame budget.
        max: usize,
    },
    /// The peer [`Endpoint`] is not reachable on this carrier (unknown node, no
    /// route, closed link).
    #[error("endpoint {0:?} is not reachable on this transport")]
    Unreachable(String),
    /// The backend failed for a carrier-specific reason (I/O, radio, modem). The
    /// string is diagnostic, not machine-matched.
    #[error("transport backend error: {0}")]
    Backend(String),
}

/// A carrier that moves opaque frames between [`Endpoint`]s (ADR-0013).
///
/// Send is fire-and-forget: reliability is not this layer's job — it lives above
/// (delivery receipts, ADR-0020 §3) and below (the carrier's own link). Receive
/// is poll-based: [`poll_recv`](FrameTransport::poll_recv) drains whatever frames
/// have arrived since the last poll.
pub trait FrameTransport: Send + Sync {
    /// This carrier's [`TransportProfile`].
    fn profile(&self) -> TransportProfile;

    /// Queues one frame for delivery to `to`. Non-blocking send-and-forget: it may
    /// return before the frame is on the wire, and success is not delivery. A
    /// frame over [`TransportProfile::max_frame_bytes`] is a
    /// [`TransportError::FrameTooLarge`].
    fn send(&self, to: &Endpoint, frame: Vec<u8>) -> Result<(), TransportError>;

    /// Drains the frames received since the last poll, each paired with the
    /// [`Endpoint`] it came from. Returns an empty vec when nothing has arrived.
    fn poll_recv(&self) -> Result<Vec<(Endpoint, Vec<u8>)>, TransportError>;
}

/// Deterministic, seeded mock transports for exercising the framing layer against
/// loss, duplication, reordering, and corruption without any real network.
///
/// These live in the library (not behind `#[cfg(test)]`) so downstream crates'
/// tests — the T2.4.1 offline integration, the T2.6.2 LoRa budget — can drive the
/// same carriers this crate's proptests do. The randomness is a small inline
/// [`SplitMix64`] rather than the `rand` crate, so a wire-format crate gains no
/// runtime `rand` dependency and a fixed seed pins *exact* fault sequences (golden
/// statistical assertions, not flaky probabilistic ones).
pub mod mock {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::{Endpoint, FrameTransport, TransportError, TransportProfile};
    use crate::framing::HEADER_LEN;

    /// A tiny deterministic PRNG (SplitMix64). Not cryptographic — a reproducible
    /// fault generator whose sequence is pinned forever by its seed, so a mock's
    /// behavior is a fixed function of `(seed, inputs)` across toolchains.
    #[derive(Clone, Debug)]
    pub struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        /// Seeds the generator.
        pub fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        /// The next 64-bit value.
        pub fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A value in `[0, 1)`.
        pub fn next_f64(&mut self) -> f64 {
            // Top 53 bits → a double in [0,1), the standard construction.
            (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
        }

        /// A value in `[0, n)` (0 when `n == 0`).
        pub fn below(&mut self, n: usize) -> usize {
            if n == 0 {
                0
            } else {
                (self.next_u64() % n as u64) as usize
            }
        }
    }

    /// An in-memory, ordered, lossless network of named endpoints. A
    /// [`LoopbackTransport`] handle attached to it is one node; `send` enqueues on
    /// the recipient's inbox and `poll_recv` drains this node's inbox in order.
    /// The "pair" the ticket calls for is just two handles on one net.
    #[derive(Clone)]
    pub struct LoopbackNet {
        inner: std::sync::Arc<Mutex<Inner>>,
        max_frame_bytes: usize,
    }

    struct Inner {
        // Per-endpoint inbox: frames delivered to that endpoint, oldest first.
        inboxes: std::collections::HashMap<Endpoint, VecDeque<(Endpoint, Vec<u8>)>>,
    }

    impl LoopbackNet {
        /// A fresh network whose carriers deliver frames up to `max_frame_bytes`.
        pub fn new(max_frame_bytes: usize) -> Self {
            Self {
                inner: std::sync::Arc::new(Mutex::new(Inner {
                    inboxes: std::collections::HashMap::new(),
                })),
                max_frame_bytes,
            }
        }

        /// A transport handle for the node named `me` on this network.
        pub fn endpoint(&self, me: impl Into<String>) -> LoopbackTransport {
            LoopbackTransport {
                me: Endpoint::new(me),
                net: self.clone(),
            }
        }
    }

    /// One node's handle on a [`LoopbackNet`] (see its docs).
    #[derive(Clone)]
    pub struct LoopbackTransport {
        me: Endpoint,
        net: LoopbackNet,
    }

    impl FrameTransport for LoopbackTransport {
        fn profile(&self) -> TransportProfile {
            TransportProfile {
                max_frame_bytes: self.net.max_frame_bytes,
                sustained_bytes_per_sec: None,
                lossy: false,
            }
        }

        fn send(&self, to: &Endpoint, frame: Vec<u8>) -> Result<(), TransportError> {
            if frame.len() > self.net.max_frame_bytes {
                return Err(TransportError::FrameTooLarge {
                    found: frame.len(),
                    max: self.net.max_frame_bytes,
                });
            }
            let mut inner = self.net.inner.lock().expect("loopback net poisoned");
            inner
                .inboxes
                .entry(to.clone())
                .or_default()
                .push_back((self.me.clone(), frame));
            Ok(())
        }

        fn poll_recv(&self) -> Result<Vec<(Endpoint, Vec<u8>)>, TransportError> {
            let mut inner = self.net.inner.lock().expect("loopback net poisoned");
            Ok(inner
                .inboxes
                .get_mut(&self.me)
                .map(|q| q.drain(..).collect())
                .unwrap_or_default())
        }
    }

    /// Fault parameters for a [`FaultTransport`]. All probabilities are in
    /// `[0, 1]`; a fixed `seed` makes the whole fault sequence reproducible.
    #[derive(Clone, Copy, Debug)]
    pub struct FaultConfig {
        /// Probability a delivered frame is dropped.
        pub drop_prob: f64,
        /// Probability a delivered frame is duplicated (an extra identical copy).
        pub dup_prob: f64,
        /// Probability a delivered frame's *payload* has one byte flipped (a
        /// carrier bit-flip; caught by the chunk CRC — see [`crate::framing`]).
        pub corrupt_prob: f64,
        /// Frames are shuffled within sliding windows of this size (`0` or `1`
        /// disables reordering).
        pub reorder_window: usize,
        /// PRNG seed — pins the exact fault sequence.
        pub seed: u64,
    }

    impl FaultConfig {
        /// A no-fault config (an honest carrier) with the given seed.
        pub fn none(seed: u64) -> Self {
            Self {
                drop_prob: 0.0,
                dup_prob: 0.0,
                corrupt_prob: 0.0,
                reorder_window: 0,
                seed,
            }
        }
    }

    /// Wraps any [`FrameTransport`] and injects deterministic delivery faults on
    /// the *receive* path — the delivered batch is dropped/duplicated/corrupted/
    /// reordered per [`FaultConfig`]. `send` passes straight through to the inner
    /// carrier (which still enforces its frame budget). Faults model the carrier,
    /// so applying them where frames are delivered keeps the sender honest.
    pub struct FaultTransport<T: FrameTransport> {
        inner: T,
        config: FaultConfig,
        rng: Mutex<SplitMix64>,
    }

    impl<T: FrameTransport> FaultTransport<T> {
        /// Wraps `inner` with the given fault config.
        pub fn new(inner: T, config: FaultConfig) -> Self {
            let rng = Mutex::new(SplitMix64::new(config.seed));
            Self { inner, config, rng }
        }

        /// The wrapped transport.
        pub fn inner(&self) -> &T {
            &self.inner
        }
    }

    impl<T: FrameTransport> FrameTransport for FaultTransport<T> {
        fn profile(&self) -> TransportProfile {
            // Advertise loss so callers plan retransmits.
            TransportProfile {
                lossy: true,
                ..self.inner.profile()
            }
        }

        fn send(&self, to: &Endpoint, frame: Vec<u8>) -> Result<(), TransportError> {
            self.inner.send(to, frame)
        }

        fn poll_recv(&self) -> Result<Vec<(Endpoint, Vec<u8>)>, TransportError> {
            let incoming = self.inner.poll_recv()?;
            let mut rng = self.rng.lock().expect("fault rng poisoned");
            let mut out: Vec<(Endpoint, Vec<u8>)> = Vec::with_capacity(incoming.len());
            for (ep, frame) in incoming {
                if rng.next_f64() < self.config.drop_prob {
                    continue;
                }
                let mut frame = frame;
                if rng.next_f64() < self.config.corrupt_prob {
                    // Flip a byte in the *payload* region only (index >= HEADER_LEN),
                    // so the chunk CRC — which covers the payload — reliably catches
                    // it. A frame with no payload byte to flip is left intact.
                    if frame.len() > HEADER_LEN {
                        let i = HEADER_LEN + rng.below(frame.len() - HEADER_LEN);
                        frame[i] ^= 1 << (rng.below(8) as u8);
                    }
                }
                let dup = rng.next_f64() < self.config.dup_prob;
                out.push((ep.clone(), frame.clone()));
                if dup {
                    out.push((ep, frame));
                }
            }
            reorder_within_windows(&mut out, self.config.reorder_window, &mut rng);
            Ok(out)
        }
    }

    /// Shuffles `items` within contiguous windows of `window` using `rng`
    /// (Fisher–Yates per window). A window of 0 or 1 is a no-op.
    fn reorder_within_windows<X>(items: &mut [X], window: usize, rng: &mut SplitMix64) {
        if window < 2 {
            return;
        }
        let len = items.len();
        let mut start = 0;
        while start < len {
            let end = (start + window).min(len);
            // Fisher–Yates over items[start..end].
            for i in (start + 1..end).rev() {
                let j = start + rng.below(i - start + 1);
                items.swap(i, j);
            }
            start = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;

    #[test]
    fn loopback_delivers_in_order_and_bidirectionally() {
        let net = LoopbackNet::new(1024);
        let a = net.endpoint("a");
        let b = net.endpoint("b");
        let ep_a = Endpoint::new("a");
        let ep_b = Endpoint::new("b");

        a.send(&ep_b, b"one".to_vec()).unwrap();
        a.send(&ep_b, b"two".to_vec()).unwrap();
        b.send(&ep_a, b"reply".to_vec()).unwrap();

        // B receives A's two frames in order, tagged with A's endpoint.
        let got = b.poll_recv().unwrap();
        assert_eq!(
            got,
            vec![
                (ep_a.clone(), b"one".to_vec()),
                (ep_a.clone(), b"two".to_vec())
            ]
        );
        // A second poll drains nothing.
        assert!(b.poll_recv().unwrap().is_empty());
        // A receives B's reply.
        assert_eq!(a.poll_recv().unwrap(), vec![(ep_b, b"reply".to_vec())]);
        // Profile: lossless, unconstrained, the configured frame budget.
        let p = a.profile();
        assert_eq!(p.max_frame_bytes, 1024);
        assert!(!p.lossy);
        assert_eq!(p.sustained_bytes_per_sec, None);
    }

    #[test]
    fn loopback_refuses_an_oversize_frame() {
        let net = LoopbackNet::new(8);
        let a = net.endpoint("a");
        assert_eq!(
            a.send(&Endpoint::new("b"), vec![0u8; 9]),
            Err(TransportError::FrameTooLarge { found: 9, max: 8 })
        );
    }

    #[test]
    fn fault_transport_none_is_a_faithful_passthrough() {
        let net = LoopbackNet::new(1024);
        let a = net.endpoint("a");
        let b = FaultTransport::new(net.endpoint("b"), FaultConfig::none(1));
        a.send(&Endpoint::new("b"), b"hello".to_vec()).unwrap();
        assert_eq!(
            b.poll_recv().unwrap(),
            vec![(Endpoint::new("a"), b"hello".to_vec())]
        );
        assert!(b.profile().lossy, "a fault transport advertises loss");
    }

    /// With a fixed seed the fault sequence is exact, not statistical: this pins
    /// the precise drop/duplicate/reorder outcome so a change in the mock is caught.
    #[test]
    fn fault_transport_is_deterministic_for_a_fixed_seed() {
        let run = || {
            let net = LoopbackNet::new(1024);
            let a = net.endpoint("a");
            let b = FaultTransport::new(
                net.endpoint("b"),
                FaultConfig {
                    drop_prob: 0.3,
                    dup_prob: 0.3,
                    corrupt_prob: 0.0,
                    reorder_window: 3,
                    seed: 42,
                },
            );
            // Send 12 identifiable single-byte frames.
            for i in 0u8..12 {
                a.send(&Endpoint::new("b"), vec![i]).unwrap();
            }
            b.poll_recv()
                .unwrap()
                .into_iter()
                .map(|(_, f)| f[0])
                .collect::<Vec<u8>>()
        };
        // Two independent runs with the same seed produce byte-identical output.
        let first = run();
        let second = run();
        assert_eq!(first, second, "same seed ⇒ same fault sequence");
        // And it actually perturbed the stream (dropped and/or reordered), so the
        // test is meaningful rather than trivially equal to the input.
        assert_ne!(first, (0u8..12).collect::<Vec<u8>>());
    }
}
