//! SMS as a DTN carrier (T2.7.1, Overview §10.3 "No internet — SMS").
//!
//! When a community has cellular text messaging but no data, a paired member's
//! phone can still reach its station: the app encodes its outbox into SMS text
//! chunks and texts them to the station's number; the station decodes, ingests the
//! carried bundle through the **same** front door the online path uses (ADR-0020
//! §3), and texts the signed delivery receipt back. SMS is a *carrier for signed
//! payloads*, nothing more — exactly like paper, LoRa, or a courier (ADR-0008/0013).
//! The feature-phone "text `PAY 5 TO ALICE`" model is deliberately **out of scope**
//! (it would need custodial keys, breaking ADR-0006); there is no command parser
//! here. See `docs/spec/sms-carrier.md`.
//!
//! ## What this module is, and is not
//!
//! - The **wire** (chunk grammar, budget) is [`rrn_protocol::paper`], generalized by
//!   T2.7.1 with an SMS-sized budget ([`paper::sms_chunk_budget_bytes`]). The chunk
//!   alphabet is GSM-7-safe (audited there), so no transcoding is needed.
//! - The **seam** is [`SmsGateway`]: `send` one text, `poll_recv` inbound texts.
//!   T2.7.1 ships only [`MockSmsGateway`] (a deterministic, fault-injecting
//!   in-memory channel for tests); the real modem/gateway that drives a production
//!   [`sms_gateway_loop`] is T2.7.2.
//! - The **engine** is [`SmsRelay`]: per-sender reassembly, the sender registry
//!   ("paired"/"open"), a per-sender inbound rate cap, and a strict-priority
//!   (money-first) outbound queue. It is clock-injected and pull-driven, mirroring
//!   [`crate::dtn_sync::DtnSyncer`] — ingest stays the caller's job so the engine is
//!   testable without a ledger.
//!
//! ## Security posture (see the threat model)
//!
//! An MSISDN is forgeable at the carrier, so the sender registry is **spam control,
//! not authentication** — the security boundary is the per-record signature the
//! carried bundle already verifies at ingest. SMS content is cleartext to the
//! carrier (metadata + payload visible); the carried payloads are already
//! community-public signed records, but the *metadata* (who texts the station,
//! when) is a surveillance residual, mitigated only by preferring paper/LoRa where
//! that matters.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use rrn_protocol::airtime::Priority;
use rrn_protocol::binding::valid_msisdn;
use rrn_protocol::paper::{
    encode_chunks_with_budget, PaperError, PaperKind, PaperReassembler, GSM7_CONCAT_PART_CHARS,
};

/// Rolling-window length for the per-sender inbound rate cap, in seconds (one hour).
const RATE_WINDOW_SECS: i64 = 3600;
/// The shortest interval between "inbound SMS dropped" log lines — so a flood is
/// reported once with a running count, never one line per dropped text.
const DROP_LOG_THROTTLE_SECS: i64 = 300;
/// The most distinct senders with an in-progress reassembly the relay tracks at
/// once — a bound so a flood of one chunk each from many (spoofed) numbers, in
/// "open" mode, cannot grow the relay's memory without limit.
const MAX_TRACKED_SENDERS: usize = 512;
/// How long a partial reassembly (or an idle rate-window) is kept before the poll
/// prune sweep discards it. A member who abandons a half-sent bundle, or a spoofed
/// number that sent one junk chunk, ages out — so the [`MAX_TRACKED_SENDERS`] cap is
/// a true bound, not a permanent lockout. One hour matches the rate window.
const STALE_STATE_TTL_SECS: i64 = RATE_WINDOW_SECS;

/// A validated E.164 phone number (MSISDN): `+` then 8–15 digits, leading digit
/// non-zero. The one source of truth for the format is
/// [`rrn_protocol::binding::valid_msisdn`], shared with the `rrn.net.sms_binding`
/// record so a number that binds is a number the gateway accepts.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Msisdn(String);

impl Msisdn {
    /// Parses and validates an E.164 MSISDN, or [`SmsError::BadMsisdn`].
    pub fn parse(s: impl Into<String>) -> Result<Self, SmsError> {
        let s = s.into();
        if valid_msisdn(&s) {
            Ok(Msisdn(s))
        } else {
            Err(SmsError::BadMsisdn(s))
        }
    }

    /// The underlying `+…` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Msisdn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An SMS carrier fault or a backend failure.
#[derive(thiserror::Error, Debug)]
pub enum SmsError {
    /// A string was not a well-formed E.164 MSISDN.
    #[error("not a valid E.164 MSISDN: {0}")]
    BadMsisdn(String),
    /// The gateway backend (modem, HTTP provider, or the mock) failed.
    #[error("sms gateway backend error: {0}")]
    Backend(String),
}

/// One inbound text as the gateway surfaces it: who sent it, its content, and when
/// the gateway received it (the carrier's clock — testimony, never used for any
/// window or ordering decision, ADR-0022).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundSms {
    /// The sender's number (as reported by the carrier — forgeable; see the module
    /// docs).
    pub from: Msisdn,
    /// The message text (one chunk of the `rrnp:` grammar, in the carrier path).
    pub text: String,
    /// When the gateway received it (Unix seconds).
    pub received_at: i64,
}

/// The SMS transport seam: a carrier that sends and receives text messages. The
/// real modem/HTTP-provider implementation is T2.7.2; T2.7.1 ships [`MockSmsGateway`].
pub trait SmsGateway: Send + Sync {
    /// Sends one text message to `to`. An error is a backend fault the caller may
    /// retry; the reliability model (re-send until the receipt returns) tolerates a
    /// dropped message without a station-side retransmit protocol.
    fn send(&self, to: &Msisdn, text: &str) -> Result<(), SmsError>;
    /// Returns the inbound texts received since the last poll (draining them).
    fn poll_recv(&self) -> Result<Vec<InboundSms>, SmsError>;
}

/// A shared gateway is a gateway: so a caller can hold an [`std::sync::Arc`] handle
/// to the backend (to inject or inspect in tests, or share one modem across tasks)
/// while the [`SmsRelay`] owns another clone.
impl<G: SmsGateway + ?Sized> SmsGateway for std::sync::Arc<G> {
    fn send(&self, to: &Msisdn, text: &str) -> Result<(), SmsError> {
        (**self).send(to, text)
    }
    fn poll_recv(&self) -> Result<Vec<InboundSms>, SmsError> {
        (**self).poll_recv()
    }
}

/// Which inbound senders the station processes (`[sms] allowed_senders`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowedSenders {
    /// Process inbound texts only from numbers a `rrn.net.sms_binding` record names
    /// (the default). Spam control; the signatures are still the security boundary.
    #[default]
    Paired,
    /// Process inbound texts from any number — still signature-gated at ingest.
    Open,
}

/// The registry the relay checks in `"paired"` mode: the set of currently-bound
/// MSISDNs, derived from the log's `rrn.net.sms_binding` records (latest-wins per
/// identity). The station computes it; the relay only reads it.
pub type BoundSenders = HashSet<Msisdn>;

/// Outbound message pacing: SMS is a per-message-cost carrier (a modem sends on the
/// order of one text per second, and each costs money/airtime), so the relay paces
/// outbound texts through a token bucket **in whole messages** — the message-unit
/// analogue of [`rrn_protocol::airtime::AirtimeBudget`], drained strict-priority so
/// a delivery receipt never waits behind a bulk message.
#[derive(Clone, Copy, Debug)]
pub struct MessageBudget {
    /// Long-run messages/second the carrier may sustain.
    pub messages_per_sec: f64,
    /// Token-bucket ceiling in whole messages — the burst after an idle period.
    pub burst: u32,
}

impl Default for MessageBudget {
    fn default() -> Self {
        // ~1 SMS/second, a modest modem; burst of 8 covers a multi-chunk receipt.
        Self {
            messages_per_sec: 1.0,
            burst: 8,
        }
    }
}

/// Tuning for an [`SmsRelay`].
#[derive(Clone, Copy, Debug)]
pub struct SmsRelayConfig {
    /// Raw payload bytes per chunk — from [`paper::sms_chunk_budget_bytes`] for the
    /// station's `max_parts_per_message`.
    pub chunk_budget_bytes: usize,
    /// Whether inbound is gated to bound senders.
    pub allowed_senders: AllowedSenders,
    /// The most inbound texts one sender may send per fixed 1-hour window before the rest
    /// are dropped (with a throttled log line).
    pub max_inbound_per_hour: u32,
    /// Outbound message pacing.
    pub message_budget: MessageBudget,
}

impl Default for SmsRelayConfig {
    fn default() -> Self {
        Self {
            chunk_budget_bytes: rrn_protocol::paper::sms_chunk_budget_bytes(4),
            allowed_senders: AllowedSenders::default(),
            max_inbound_per_hour: 60,
            message_budget: MessageBudget::default(),
        }
    }
}

/// A payload that finished reassembling from a sender's texts this poll: what it is
/// ([`PaperKind`]) and its bytes. The caller ingests a [`PaperKind::Bundle`] and
/// queues the resulting receipt back with [`SmsRelay::queue_payload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmsCompleted {
    /// The number the payload arrived from.
    pub from: Msisdn,
    /// The payload family (Bundle / Receipt / SpendVoucher).
    pub kind: PaperKind,
    /// The reassembled payload bytes.
    pub bytes: Vec<u8>,
}

/// One queued outbound text: its recipient and content.
struct OutMsg {
    to: Msisdn,
    text: String,
}

/// A sender's fixed-window inbound counter.
struct RateWindow {
    window_start: i64,
    count: u32,
}

/// A sender's in-progress reassembly plus when it was last fed — the `last_seen`
/// lets the poll prune sweep evict abandoned partials so tracked state stays bounded.
struct Reassembly {
    re: PaperReassembler,
    last_seen: i64,
}

/// The SMS relay engine (module docs): reassembly, registry, rate cap, and paced
/// strict-priority outbound. Clock-injected and pull-driven.
pub struct SmsRelay<G: SmsGateway> {
    gateway: G,
    config: SmsRelayConfig,
    /// Per-sender in-progress reassembly (a person collating their own sheets),
    /// with a `last_seen` so abandoned partials are pruned (bounding tracked state).
    reassemblers: HashMap<Msisdn, Reassembly>,
    /// Per-sender fixed-window inbound counters, pruned once idle past the window.
    rates: HashMap<Msisdn, RateWindow>,
    /// Strict-priority outbound FIFOs, indexed by `Priority as usize`.
    outbound: [VecDeque<OutMsg>; 3],
    /// Message-pacing token bucket (bytes → messages).
    tokens: f64,
    last_refill: i64,
    /// Throttled drop reporting: cumulative dropped count and last log time.
    dropped_inbound: u64,
    last_drop_log_at: i64,
}

impl<G: SmsGateway> SmsRelay<G> {
    /// A new relay over `gateway`, its message bucket starting full, clock seeded at
    /// `now`.
    pub fn new(gateway: G, config: SmsRelayConfig, now: i64) -> Self {
        Self {
            tokens: config.message_budget.burst as f64,
            gateway,
            config,
            reassemblers: HashMap::new(),
            rates: HashMap::new(),
            outbound: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            last_refill: now,
            dropped_inbound: 0,
            last_drop_log_at: i64::MIN,
        }
    }

    /// The gateway, for inspection / injection in tests.
    pub fn gateway(&self) -> &G {
        &self.gateway
    }

    /// Drains the gateway's inbound texts and processes each: enforce the sender
    /// registry (in `"paired"` mode) and the per-sender rate cap, then feed the text
    /// to that sender's reassembler. Returns the payloads that completed this poll.
    ///
    /// A refused text (unpaired sender, over the rate cap, an unbound sender past the
    /// tracking cap, a non-chunk text, or a chunk that fails to parse/decode — a
    /// truncated or corrupt SMS) is dropped; the reassembler simply waits for a
    /// re-send. Registry/rate/cap drops are counted and logged at most once per
    /// [`DROP_LOG_THROTTLE_SECS`]; codec-level refusals are only traced.
    ///
    /// Stale tracked state (an abandoned partial reassembly, an idle rate window) is
    /// pruned each poll past [`STALE_STATE_TTL_SECS`], so the per-sender maps stay
    /// bounded even under a flood of one text each from many (spoofed) numbers.
    pub fn poll(&mut self, now: i64, bound: &BoundSenders) -> Result<Vec<SmsCompleted>, SmsError> {
        self.prune_stale(now);
        let inbound = self.gateway.poll_recv()?;
        let mut completed = Vec::new();
        for msg in inbound {
            // (1) Sender registry (spam control; signatures are the real gate).
            if self.config.allowed_senders == AllowedSenders::Paired && !bound.contains(&msg.from) {
                self.note_drop(now, "unpaired sender");
                continue;
            }
            // (2) Per-sender fixed-window rate cap.
            if self.over_rate(&msg.from, now) {
                self.note_drop(now, "over the inbound rate cap");
                continue;
            }
            // (3) Only `rrnp:` multi-part chunks are reassembled; a non-chunk text
            // (wrong number, a carrier notice, a single-QR form the station does not
            // ingest) is ignored WITHOUT allocating a tracking slot for its sender.
            if !msg.text.starts_with(rrn_protocol::paper::MULTIPART_PREFIX) {
                tracing::debug!(from = %msg.from, "inbound SMS is not a chunk; ignored");
                continue;
            }
            // (4) Bound the number of distinct in-progress senders (a real bound,
            // since stale slots are pruned above).
            if !self.reassemblers.contains_key(&msg.from)
                && self.reassemblers.len() >= MAX_TRACKED_SENDERS
            {
                self.note_drop(now, "too many in-progress senders");
                continue;
            }
            // (5) Feed the chunk to the sender's reassembler. Scoped so the map
            // borrow ends before a completed payload's slot is removed below.
            let result = {
                let slot = self
                    .reassemblers
                    .entry(msg.from.clone())
                    .or_insert_with(|| Reassembly {
                        re: PaperReassembler::new(),
                        last_seen: now,
                    });
                slot.last_seen = now;
                match slot.re.accept(&msg.text) {
                    // A chunk of a DIFFERENT payload than the one in progress
                    // (`Mixed`): SMS is machine-driven and a member re-sending its
                    // outbox re-encodes it with a fresh `payload_id8` (the bundle's
                    // assembled_at is in the bytes), so a new payload SUPERSEDES the
                    // stalled one rather than being refused forever. Reset and take
                    // this chunk as the new payload's first.
                    Err(PaperError::Mixed) => {
                        slot.re = PaperReassembler::new();
                        slot.re.accept(&msg.text)
                    }
                    other => other,
                }
            };
            match result {
                Ok(Some((kind, bytes))) => {
                    self.reassemblers.remove(&msg.from); // completed → forget the slot
                    completed.push(SmsCompleted {
                        from: msg.from,
                        kind,
                        bytes,
                    });
                }
                Ok(None) => {} // still incomplete, or a duplicate chunk
                Err(e) => {
                    tracing::debug!(from = %msg.from, error = %e, "inbound SMS chunk refused");
                }
            }
        }
        Ok(completed)
    }

    /// Evicts per-sender state idle longer than [`STALE_STATE_TTL_SECS`]: abandoned
    /// partial reassemblies and rate windows whose hour has elapsed. Keeps the
    /// tracking maps bounded to senders active within the window.
    fn prune_stale(&mut self, now: i64) {
        self.reassemblers
            .retain(|_, r| now.saturating_sub(r.last_seen) < STALE_STATE_TTL_SECS);
        self.rates
            .retain(|_, w| now.saturating_sub(w.window_start) < RATE_WINDOW_SECS);
    }

    /// Chunk-encodes `payload` at the SMS budget and enqueues its texts for `to` at
    /// `priority` (a delivery receipt is [`Priority::Economic`]). Returns the number
    /// of texts queued, or the encoding error (a payload too large to chunk).
    pub fn queue_payload(
        &mut self,
        to: &Msisdn,
        kind: PaperKind,
        payload: &[u8],
        priority: Priority,
    ) -> Result<usize, PaperError> {
        let chunks = encode_chunks_with_budget(kind, payload, self.config.chunk_budget_bytes)?;
        let n = chunks.len();
        let q = &mut self.outbound[priority as usize];
        for text in chunks {
            q.push_back(OutMsg {
                to: to.clone(),
                text,
            });
        }
        Ok(n)
    }

    /// Refills the message bucket to `now` and sends as many queued texts as the
    /// bucket allows, in strict priority order (money first), to the gateway.
    /// Returns the number sent. A backend send error holds the text (re-tried next
    /// pump) and stops this pump — never a panic, never a lost economic message.
    pub fn pump(&mut self, now: i64) -> usize {
        self.refill(now);
        let mut sent = 0;
        while let Some(p) = Priority::ORDER
            .into_iter()
            .find(|p| !self.outbound[*p as usize].is_empty())
        {
            if self.tokens < 1.0 {
                break; // paced out until the next refill
            }
            let msg = self.outbound[p as usize]
                .pop_front()
                .expect("front present");
            match self.gateway.send(&msg.to, &msg.text) {
                Ok(()) => {
                    self.tokens -= 1.0;
                    sent += 1;
                }
                Err(e) => {
                    tracing::warn!(to = %msg.to, error = %e, "sms send failed; will retry");
                    self.outbound[p as usize].push_front(msg);
                    break;
                }
            }
        }
        sent
    }

    /// Total queued outbound texts across all classes.
    pub fn outbound_queued(&self) -> usize {
        self.outbound.iter().map(|q| q.len()).sum()
    }

    /// Cumulative inbound texts dropped by a *policy* gate — unpaired sender,
    /// over-rate, or over the tracked-sender cap. Codec-level refusals (a
    /// non-chunk text, or a chunk that fails to parse/decode) are traced, not
    /// counted here, since they are the carrier's fault, not an attacker signal.
    pub fn dropped_inbound(&self) -> u64 {
        self.dropped_inbound
    }

    /// Whether `from` has exceeded the inbound cap over the current **fixed**
    /// 1-hour window ([`RATE_WINDOW_SECS`]), advancing its counter as a side effect
    /// (each accepted call counts one text). Fixed rather than sliding: a burst
    /// straddling a window boundary can admit up to 2× the cap across that boundary,
    /// an accepted 2× overshoot in exchange for O(1) per-sender state.
    fn over_rate(&mut self, from: &Msisdn, now: i64) -> bool {
        let w = self.rates.entry(from.clone()).or_insert(RateWindow {
            window_start: now,
            count: 0,
        });
        if now.saturating_sub(w.window_start) >= RATE_WINDOW_SECS {
            w.window_start = now;
            w.count = 0;
        }
        if w.count >= self.config.max_inbound_per_hour {
            return true;
        }
        w.count += 1;
        false
    }

    /// Counts a dropped text and logs it at most once per throttle window.
    fn note_drop(&mut self, now: i64, reason: &str) {
        self.dropped_inbound += 1;
        if now.saturating_sub(self.last_drop_log_at) >= DROP_LOG_THROTTLE_SECS {
            tracing::warn!(
                dropped_total = self.dropped_inbound,
                reason,
                "inbound SMS dropped (rate-limited log)"
            );
            self.last_drop_log_at = now;
        }
    }

    fn refill(&mut self, now: i64) {
        let dt = now.saturating_sub(self.last_refill).max(0) as f64;
        self.last_refill = now;
        let refilled = self.tokens + dt * self.config.message_budget.messages_per_sec;
        self.tokens = refilled.min(self.config.message_budget.burst as f64);
    }
}

// ---------------------------------------------------------------------------
// Mock gateway (tests only in spirit, but `pub` for cross-crate integration tests)
// ---------------------------------------------------------------------------

/// Deterministic carrier faults for [`MockSmsGateway`]: real SMS carriers drop,
/// duplicate, reorder, and truncate concatenated messages. All are seeded so a test
/// is reproducible.
#[derive(Clone, Copy, Debug)]
pub struct SmsFaults {
    /// Probability each message is dropped entirely.
    pub drop_prob: f64,
    /// Probability each surviving message is duplicated.
    pub dup_prob: f64,
    /// Probability each surviving text is truncated at a concatenated-part boundary
    /// (a carrier losing a trailing part) — the chunk then fails to decode or hashes
    /// wrong and is refused, so reassembly waits for a re-send.
    pub truncate_prob: f64,
    /// Whether a drained inbound batch is delivered reversed (a deterministic
    /// reorder) — the reassembler is order-independent, so this proves it.
    pub reorder: bool,
    /// RNG seed.
    pub seed: u64,
}

impl SmsFaults {
    /// A faultless carrier with the given seed.
    pub fn none(seed: u64) -> Self {
        Self {
            drop_prob: 0.0,
            dup_prob: 0.0,
            truncate_prob: 0.0,
            reorder: false,
            seed,
        }
    }
}

struct MockInner {
    faults: SmsFaults,
    rng: u64,
    /// Pending inbound (member → station), faults applied on drain.
    inbound: VecDeque<InboundSms>,
    /// Sent (station → member), faults applied at send; readable by the test to
    /// simulate the member receiving.
    sent: HashMap<Msisdn, Vec<String>>,
    /// When set, `send` fails once (to exercise the send-error path).
    fail_send: bool,
}

/// An in-memory, deterministic, fault-injecting [`SmsGateway`] for tests. Inbound is
/// injected with [`push_inbound`](Self::push_inbound); [`poll_recv`] drains it with
/// faults applied. Outbound [`send`](SmsGateway::send)s are recorded per recipient
/// (with faults) and read back with [`sent_to`](Self::sent_to).
pub struct MockSmsGateway {
    inner: Mutex<MockInner>,
}

impl MockSmsGateway {
    /// A new mock carrier with the given fault profile.
    pub fn new(faults: SmsFaults) -> Self {
        Self {
            inner: Mutex::new(MockInner {
                rng: faults.seed.max(1),
                faults,
                inbound: VecDeque::new(),
                sent: HashMap::new(),
                fail_send: false,
            }),
        }
    }

    /// Queues one inbound text (a member texting the station). Faults are applied
    /// when [`poll_recv`] drains it.
    pub fn push_inbound(&self, from: &Msisdn, text: &str, received_at: i64) {
        self.inner.lock().unwrap().inbound.push_back(InboundSms {
            from: from.clone(),
            text: text.to_string(),
            received_at,
        });
    }

    /// The texts the station has sent to `to` so far (post-fault), for the test to
    /// reassemble on the member side.
    pub fn sent_to(&self, to: &Msisdn) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .sent
            .get(to)
            .cloned()
            .unwrap_or_default()
    }

    /// Arms the next [`send`](SmsGateway::send) to fail once (exercises the retry
    /// path).
    pub fn fail_next_send(&self) {
        self.inner.lock().unwrap().fail_send = true;
    }
}

/// SplitMix64 — a tiny deterministic RNG so faults are reproducible from the seed.
fn next_u64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn chance(state: &mut u64, p: f64) -> bool {
    if p <= 0.0 {
        return false;
    }
    if p >= 1.0 {
        return true;
    }
    (next_u64(state) as f64) / (u64::MAX as f64) < p
}

/// Truncates `text` at a concatenated-part boundary (a multiple of
/// [`GSM7_CONCAT_PART_CHARS`]) strictly shorter than it, modelling a carrier that
/// dropped a trailing part. Returns `text` unchanged when it is a single part.
fn truncate_at_part(text: &str, state: &mut u64) -> String {
    let total_parts = text.chars().count().div_ceil(GSM7_CONCAT_PART_CHARS);
    if total_parts <= 1 {
        return text.to_string();
    }
    // Keep 1..total_parts parts.
    let keep = 1 + (next_u64(state) as usize) % (total_parts - 1);
    let cut = keep * GSM7_CONCAT_PART_CHARS;
    text.chars().take(cut).collect()
}

impl SmsGateway for MockSmsGateway {
    fn send(&self, to: &Msisdn, text: &str) -> Result<(), SmsError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_send {
            inner.fail_send = false;
            return Err(SmsError::Backend("mock: armed send failure".into()));
        }
        let faults = inner.faults; // Copy, so `rng` can be borrowed mutably below
                                   // Apply drop/dup/truncate on the station→member leg too.
        if chance(&mut inner.rng, faults.drop_prob) {
            return Ok(()); // "sent" but lost by the carrier
        }
        let truncate = chance(&mut inner.rng, faults.truncate_prob);
        let dup = chance(&mut inner.rng, faults.dup_prob);
        let delivered = if truncate {
            truncate_at_part(text, &mut inner.rng)
        } else {
            text.to_string()
        };
        let bucket = inner.sent.entry(to.clone()).or_default();
        bucket.push(delivered.clone());
        if dup {
            bucket.push(delivered);
        }
        Ok(())
    }

    fn poll_recv(&self) -> Result<Vec<InboundSms>, SmsError> {
        let mut inner = self.inner.lock().unwrap();
        let faults = inner.faults; // Copy, so `rng` can be borrowed mutably below
        let pending: Vec<InboundSms> = inner.inbound.drain(..).collect();
        let mut out = Vec::with_capacity(pending.len());
        for mut msg in pending {
            if chance(&mut inner.rng, faults.drop_prob) {
                continue; // carrier dropped it
            }
            if chance(&mut inner.rng, faults.truncate_prob) {
                msg.text = truncate_at_part(&msg.text, &mut inner.rng);
            }
            let dup = chance(&mut inner.rng, faults.dup_prob);
            out.push(msg.clone());
            if dup {
                out.push(msg);
            }
        }
        if faults.reorder {
            out.reverse();
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrn_protocol::paper::{sms_chunk_budget_bytes, PaperKind};

    fn msisdn(s: &str) -> Msisdn {
        Msisdn::parse(s).unwrap()
    }

    fn open_relay(gw: MockSmsGateway) -> SmsRelay<MockSmsGateway> {
        SmsRelay::new(
            gw,
            SmsRelayConfig {
                allowed_senders: AllowedSenders::Open,
                // Generous burst so pacing doesn't slow a roundtrip test.
                message_budget: MessageBudget {
                    messages_per_sec: 1.0,
                    burst: 10_000,
                },
                ..SmsRelayConfig::default()
            },
            0,
        )
    }

    #[test]
    fn msisdn_parse_matches_the_binding_validator() {
        assert_eq!(msisdn("+15551234567").as_str(), "+15551234567");
        assert!(Msisdn::parse("not-a-number").is_err());
        assert!(Msisdn::parse("+0123456789").is_err()); // leading zero
    }

    /// A payload rides member → SMS chunks → a lossy carrier (drop/dup/truncate/
    /// reorder) → the relay's reassembler, byte-identical, within bounded re-sends.
    /// Deterministic across a table of seeds (the repo's seeded-roundtrip idiom).
    #[test]
    fn a_payload_reassembles_over_a_lossy_carrier_within_bounded_resends() {
        for seed in [1u64, 2, 3, 7, 42, 1000] {
            let faults = SmsFaults {
                drop_prob: 0.35,
                dup_prob: 0.15,
                truncate_prob: 0.15,
                reorder: true,
                seed,
            };
            let mut relay = open_relay(MockSmsGateway::new(faults));
            let from = msisdn("+15550001234");
            let bound = BoundSenders::new(); // open mode ignores it

            let payload: Vec<u8> = (0..2_000u32)
                .map(|i| ((i.wrapping_mul(31)) ^ (seed as u32)) as u8)
                .collect();
            let chunks =
                encode_chunks_with_budget(PaperKind::Bundle, &payload, sms_chunk_budget_bytes(4))
                    .unwrap();
            assert!(chunks.len() >= 4, "expected a multi-chunk payload");

            let mut got = None;
            // Bounded re-send rounds: the member re-texts every chunk each round
            // until the relay reassembles it (SMS has no ack; re-send drives it).
            for round in 0..200i64 {
                for text in &chunks {
                    relay.gateway().push_inbound(&from, text, round);
                }
                for c in relay.poll(round, &bound).unwrap() {
                    got = Some((c.kind, c.bytes));
                }
                if got.is_some() {
                    break;
                }
            }
            let (kind, bytes) = got.unwrap_or_else(|| panic!("seed {seed}: never reassembled"));
            assert_eq!(kind, PaperKind::Bundle);
            assert_eq!(bytes, payload, "seed {seed}: byte-identical after carriage");
        }
    }

    #[test]
    fn a_truncated_chunk_is_refused_and_completes_on_resend() {
        // A single-chunk payload that the carrier always truncates on the first
        // delivery: refused (no completion), then completes once a clean copy
        // arrives.
        let faults = SmsFaults {
            drop_prob: 0.0,
            dup_prob: 0.0,
            truncate_prob: 0.0,
            reorder: false,
            seed: 5,
        };
        let mut relay = open_relay(MockSmsGateway::new(faults));
        let from = msisdn("+15550009999");
        let bound = BoundSenders::new();
        // A multi-part payload so truncation has a part boundary to cut at.
        let payload: Vec<u8> = (0..1_200u32).map(|i| i as u8).collect();
        let chunks =
            encode_chunks_with_budget(PaperKind::Bundle, &payload, sms_chunk_budget_bytes(4))
                .unwrap();

        // Hand a truncated first chunk directly: it must be refused (no completion),
        // leaving the reassembler waiting.
        let truncated: String = chunks[0].chars().take(GSM7_CONCAT_PART_CHARS).collect();
        relay.gateway().push_inbound(&from, &truncated, 0);
        assert!(relay.poll(0, &bound).unwrap().is_empty());

        // Then the clean chunks complete it.
        let mut got = None;
        for text in &chunks {
            relay.gateway().push_inbound(&from, text, 1);
        }
        for c in relay.poll(1, &bound).unwrap() {
            got = Some(c.bytes);
        }
        assert_eq!(got, Some(payload));
    }

    #[test]
    fn a_new_payload_supersedes_a_stalled_one_from_the_same_sender() {
        // The reliability model re-sends the outbox, and a re-encoded bundle has a
        // fresh payload_id8 (its assembled_at is in the bytes). So after a partial
        // send is stranded (a chunk lost), the sender's NEXT, different payload must
        // reset the reassembler — never be refused forever as `Mixed`.
        let mut relay = open_relay(MockSmsGateway::new(SmsFaults::none(11)));
        let from = msisdn("+15557778888");
        let bound = BoundSenders::new();
        let budget = sms_chunk_budget_bytes(4);

        let payload_a: Vec<u8> = (0..900u32).map(|i| i as u8).collect();
        let payload_b: Vec<u8> = (0..900u32).map(|i| (i.wrapping_mul(3) + 1) as u8).collect();
        let a = encode_chunks_with_budget(PaperKind::Bundle, &payload_a, budget).unwrap();
        let b = encode_chunks_with_budget(PaperKind::Bundle, &payload_b, budget).unwrap();
        assert!(a.len() >= 2 && b.len() >= 2, "both must be multi-chunk");

        // Only the first chunk of A arrives — A is stranded.
        relay.gateway().push_inbound(&from, &a[0], 0);
        assert!(relay.poll(0, &bound).unwrap().is_empty());

        // Now B arrives in full. Its first chunk supersedes the stalled A (rather
        // than being refused `Mixed`), and B completes byte-identical.
        let mut got = None;
        for text in &b {
            relay.gateway().push_inbound(&from, text, 1);
        }
        for c in relay.poll(1, &bound).unwrap() {
            got = Some(c.bytes);
        }
        assert_eq!(
            got,
            Some(payload_b),
            "the new payload supersedes the stalled one"
        );
    }

    #[test]
    fn a_wrong_bytes_truncation_recovers_via_hash_reset() {
        // A truncation that leaves a base64-VALID but shorter data field fills the
        // slot with wrong bytes; the clean re-send conflicts, and the completion
        // hash mismatch resets the partial so a subsequent clean pass rebuilds it.
        let mut relay = open_relay(MockSmsGateway::new(SmsFaults::none(2)));
        let from = msisdn("+15551212121");
        let bound = BoundSenders::new();
        let budget = sms_chunk_budget_bytes(4);
        let payload: Vec<u8> = (0..900u32).map(|i| (i ^ 0x3C) as u8).collect();
        let chunks = encode_chunks_with_budget(PaperKind::Bundle, &payload, budget).unwrap();
        assert_eq!(chunks.len(), 3);

        // Truncate chunk index 2's data to a shorter length that still decodes
        // (drop 4 base64 chars = a whole 3 bytes, so it stays base64-valid).
        let c1 = &chunks[1];
        let cut = &c1[..c1.len() - 4];
        relay.gateway().push_inbound(&from, &chunks[0], 0);
        relay.gateway().push_inbound(&from, cut, 0);
        relay.gateway().push_inbound(&from, &chunks[2], 0);
        assert!(
            relay.poll(0, &bound).unwrap().is_empty(),
            "the wrong-bytes chunk must not complete a valid payload"
        );
        // A clean re-send of all three chunks then completes it (the bad slot is
        // discarded on the hash mismatch, and the fresh pass rebuilds).
        let mut got = None;
        for _round in 0..5 {
            for text in &chunks {
                relay.gateway().push_inbound(&from, text, 1);
            }
            for c in relay.poll(1, &bound).unwrap() {
                got = Some(c.bytes);
            }
            if got.is_some() {
                break;
            }
        }
        assert_eq!(got, Some(payload));
    }

    #[test]
    fn stale_partial_reassemblies_are_pruned() {
        // An abandoned partial ages out so MAX_TRACKED_SENDERS is a bound, not a
        // permanent lockout.
        let mut relay = open_relay(MockSmsGateway::new(SmsFaults::none(4)));
        let from = msisdn("+15553334444");
        let bound = BoundSenders::new();
        let chunks = encode_chunks_with_budget(
            PaperKind::Bundle,
            &(0..900u32).map(|i| i as u8).collect::<Vec<u8>>(),
            sms_chunk_budget_bytes(4),
        )
        .unwrap();
        assert!(chunks.len() >= 2);
        relay.gateway().push_inbound(&from, &chunks[0], 0);
        assert!(relay.poll(0, &bound).unwrap().is_empty());
        // A poll well past the TTL prunes the abandoned partial.
        assert!(relay
            .poll(STALE_STATE_TTL_SECS + 1, &bound)
            .unwrap()
            .is_empty());
        assert!(
            relay.reassemblers.is_empty(),
            "the abandoned partial must be pruned"
        );
    }

    #[test]
    fn paired_mode_drops_unpaired_then_the_registry_flips_it() {
        let mut relay = SmsRelay::new(
            MockSmsGateway::new(SmsFaults::none(9)),
            SmsRelayConfig {
                allowed_senders: AllowedSenders::Paired,
                ..SmsRelayConfig::default()
            },
            0,
        );
        let from = msisdn("+15551110000");
        let payload = b"a small single-chunk bundle stand-in";
        let chunks =
            encode_chunks_with_budget(PaperKind::Bundle, payload, sms_chunk_budget_bytes(4))
                .unwrap();
        assert_eq!(chunks.len(), 1);

        // Unpaired: dropped, nothing completes, and the drop is counted.
        let empty = BoundSenders::new();
        relay.gateway().push_inbound(&from, &chunks[0], 0);
        assert!(relay.poll(0, &empty).unwrap().is_empty());
        assert_eq!(relay.dropped_inbound(), 1);

        // Now the registry names the sender — the identical text is processed.
        let mut bound = BoundSenders::new();
        bound.insert(from.clone());
        relay.gateway().push_inbound(&from, &chunks[0], 1);
        let completed = relay.poll(1, &bound).unwrap();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].bytes, payload);
    }

    #[test]
    fn inbound_rate_cap_drops_the_excess_from_one_sender() {
        let mut relay = SmsRelay::new(
            MockSmsGateway::new(SmsFaults::none(3)),
            SmsRelayConfig {
                allowed_senders: AllowedSenders::Open,
                max_inbound_per_hour: 5,
                ..SmsRelayConfig::default()
            },
            0,
        );
        let from = msisdn("+15552223333");
        let bound = BoundSenders::new();
        // 12 texts within the hour; only 5 are processed, 7 dropped. (They are junk
        // chunks — none completes — so this measures the cap, not reassembly.)
        for _ in 0..12 {
            relay
                .gateway()
                .push_inbound(&from, "rrnp:b/AAAAAAAA/1/9/AAAA", 10);
        }
        let _ = relay.poll(10, &bound).unwrap();
        assert_eq!(relay.dropped_inbound(), 7);

        // A fresh hour resets the window.
        for _ in 0..3 {
            relay
                .gateway()
                .push_inbound(&from, "rrnp:b/AAAAAAAA/1/9/AAAA", 10 + RATE_WINDOW_SECS);
        }
        let _ = relay.poll(10 + RATE_WINDOW_SECS, &bound).unwrap();
        assert_eq!(relay.dropped_inbound(), 7, "the new window admits all 3");
    }

    #[test]
    fn outbound_is_economic_first_and_paced() {
        // burst = 1 token, refilling 1/sec: exactly one message leaves per pump, so
        // strict priority is observable — the economic receipt must precede the bulk.
        let mut relay = SmsRelay::new(
            MockSmsGateway::new(SmsFaults::none(1)),
            SmsRelayConfig {
                allowed_senders: AllowedSenders::Open,
                message_budget: MessageBudget {
                    messages_per_sec: 1.0,
                    burst: 1,
                },
                ..SmsRelayConfig::default()
            },
            0,
        );
        let econ = msisdn("+15550000001");
        let bulk = msisdn("+15550000002");
        // Single-chunk payloads to each recipient. Bulk queued FIRST, to prove
        // priority beats arrival order.
        relay
            .queue_payload(&bulk, PaperKind::Bundle, b"bulk payload", Priority::Bulk)
            .unwrap();
        relay
            .queue_payload(
                &econ,
                PaperKind::Receipt,
                b"receipt payload",
                Priority::Economic,
            )
            .unwrap();

        // t=0: one burst token → exactly one send, and it must be the economic one.
        assert_eq!(relay.pump(0), 1);
        assert_eq!(relay.gateway().sent_to(&econ).len(), 1);
        assert!(relay.gateway().sent_to(&bulk).is_empty(), "bulk must wait");

        // t=1: +1 token → the bulk message clears.
        assert_eq!(relay.pump(1), 1);
        assert_eq!(relay.gateway().sent_to(&bulk).len(), 1);
        assert_eq!(relay.outbound_queued(), 0);
    }

    #[test]
    fn a_send_backend_failure_holds_the_message_for_retry() {
        let mut relay = open_relay(MockSmsGateway::new(SmsFaults::none(1)));
        let to = msisdn("+15554445555");
        relay
            .queue_payload(&to, PaperKind::Receipt, b"receipt", Priority::Economic)
            .unwrap();
        relay.gateway().fail_next_send();
        // The armed failure holds the message; nothing is sent, nothing is lost.
        assert_eq!(relay.pump(0), 0);
        assert_eq!(relay.outbound_queued(), 1);
        assert!(relay.gateway().sent_to(&to).is_empty());
        // The retry succeeds.
        assert_eq!(relay.pump(1), 1);
        assert_eq!(relay.gateway().sent_to(&to).len(), 1);
    }
}
