//! T2.10.1 — the 72-hour outage simulation harness (Phase-2 exit gate, part 1).
//!
//! The exit criterion made executable (ADR-0017): a community of ~20 members and
//! one station run through a **72-hour full connectivity loss** with realistic
//! economic activity over the offline channels — direct courier `bundle_submit`,
//! multi-courier carriage with delay / duplication / gaps / loss, a paper leg, and
//! a mock constrained-carrier (LoRa) leg — then reconnect, drain, settle, and
//! assert **mechanically**: no ledger forks, value conservation, full
//! reconciliation (no credits lost), the debt-floor invariant at every log prefix,
//! escrow honored, exactly the planted equivocations detected, settlement windows
//! respected, and that adversarial inputs left nothing but refusals — all
//! **deterministic** across seeds.
//!
//! It extends the T2.4.1 offline scaffolding (`offline_lifecycle.rs`): one real
//! `station` daemon on an injected manual clock, driven over its Unix socket, with
//! members' offline records arriving as DTN bundles (ADR-0020 §3). Simulated time
//! (injected clocks end to end) keeps the 72 hours to seconds of wall-clock.
//!
//! Runs as `cargo test` (CI drives seeds {1,2,3}); the narrated single-seed run
//! for humans is `scripts/demo-phase-2-outage.sh`.
//!
//! ## Divergences from the ticket sketch (PROCESS.md rule 3; ADR wins)
//!
//! - **Certificates are the operator's.** The ticket sketch says "certificates
//!   issued to 8 members". Per ADR-0021 and the shipped `cert_request` RPC,
//!   headroom certificates are issued **only for the station wallet** (issuance is
//!   a live operator round-trip; a DTN cert request is refused `unroutable-kind`).
//!   The behavioral requirement — cert-backed offline spends, an at-cap spend, and
//!   a planted double-spend (equivocation) — is preserved with the operator as the
//!   sole certificate holder (exactly the T2.4.1 model).
//! - **All amounts are Tier-1 (< 500 centi).** The Tier-2 confirmation gate
//!   (T1.8.2) depends on the reputation electorate; keeping every amount Tier-1
//!   makes the harness a pure function of its seed and independent of the
//!   reputation formula, so determinism (assertion 9) is exact. The near-floor and
//!   double-spend mechanics do not need Tier-2 amounts.
//! - **The "unknown-key" adversarial input is admitted, not refused.** The ledger
//!   is permissionless (ADR-0020): a self-consistent proposal from a key with no
//!   standing is a valid proposal. It is admitted but, with no counterparty
//!   confirmation, never settles and moves no credit (see `outage_unknown_key_inert`).
//!   The ticket's "no trace beyond refusals" is upheld by the forged-authorship,
//!   tampered-record, and replay cases, which DO refuse; the unknown-key case is
//!   asserted for its true behavior instead of routed around (PROCESS.md rule 3).
//! - **The activity structure is fixed; the seed varies keypairs, content-id
//!   ordering, and the mock-carrier fault pattern.** The scenario is a fixed matrix
//!   rather than a randomly drawn one, so the exact-count invariants (one planted
//!   double-spend, one fork) stay assertable; every invariant nonetheless holds for
//!   any seed, which is assertion 9's property.
//! - **Not exercised here (covered elsewhere or out of scope):** disputes
//!   (rrn-dispute has its own suites), payment requests (the receiver-side floor
//!   check, ADR-0018, is unit-tested in rrn-ledger), a governance vote (T2.8.2 is
//!   unimplemented), and a real SMS leg (T2.7.1). The paper leg exercises the
//!   `rrn_protocol::paper` codec in-process rather than the CLI's `payload.txt`
//!   file round trip (T2.5.2 covers the file I/O).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rrn_station::core::{hex, unhex};
use rrn_station::dtn_sync::{DtnSyncer, PayloadKind, SyncConfig};
use rrn_station::rpc::{BalanceResult, CertRequestResult};
use rrn_station::rpc_client::UnixClient;
use rrn_station::station::{Station, StationParams, DB_FILE, WALLET_FILE};
use rrn_station::Clock;

use rrn_crypto::hash::{Hash, Hasher};
use rrn_crypto::keypair::{Keypair, SecretKey};
use rrn_crypto::serialize::from_canonical_bytes;
use rrn_crypto::signed::SignedPayload;
use rrn_identity::address::Address;
use rrn_identity::wallet::WalletContents;
use rrn_ledger::credit::{committed_debits_centi, CreditConfig, DEFAULT_DEBT_FLOOR_CENTI};
use rrn_ledger::escrow::{CertId, EquivocationBasis};
use rrn_ledger::settlement::SettlementRecord;
use rrn_ledger::state::LedgerSnapshot;
use rrn_ledger::transaction::{
    SignedConfirmation, SignedProposal, TransactionConfirmation, TransactionProposal,
};
use rrn_protocol::airtime::{AirtimeBudget, Priority};
use rrn_protocol::bundle::{Bundle, EntryEnvelope};
use rrn_protocol::outbox::{OutboxEntry, SignedOutboxEntry};
use rrn_protocol::paper::{encode_chunks, PaperKind, PaperReassembler};
use rrn_protocol::receipt::{self, Disposition, RefusalReason, SignedReceipt};
use rrn_protocol::transport::mock::{FaultConfig, FaultTransport, LoopbackNet};
use rrn_protocol::transport::Endpoint;
use rrn_storage::db::Database;
use rrn_storage::log::AppendLog;
use rrn_storage::migrations;

const PASSPHRASE: &str = "outage-72h-passphrase";
/// Simulated wall-clock anchor (Unix seconds).
const START: i64 = 1_000_000;
/// Uniform settlement/dispute window (seconds) — short so 72 simulated hours plus
/// the settlement horizon fit in a few seeded steps.
const WINDOW: u64 = 60;
/// 72 hours in simulated seconds.
const OUTAGE_SECS: i64 = 72 * 60 * 60;
/// Members beyond the station operator (who is member A / index 0).
const MEMBER_COUNT: usize = 20;
/// The debt floor the engine enforces (default; ADR-0018). Mirrored here so the
/// prefix checker asserts against the same bound the daemon used.
const FLOOR: i64 = DEFAULT_DEBT_FLOOR_CENTI;

/// A tiny deterministic PRNG (SplitMix64) — the same one the mock transports use,
/// so the whole scenario is a fixed function of its seed across toolchains.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A fault seed derived from the run seed and a domain tag, so each mock
    /// carrier is deterministic yet distinct.
    fn fault_seed(&mut self, domain: u64) -> u64 {
        self.next_u64() ^ domain.wrapping_mul(0x100_0000_01b3)
    }
}

/// The cast: the station operator (index 0, its wallet key) plus `MEMBER_COUNT-1`
/// member keypairs, all deterministically derived from the seed so a run is
/// reproducible.
struct Cast {
    keys: Vec<Keypair>,
}
impl Cast {
    fn new(seed: u64) -> Self {
        let mut keys = Vec::with_capacity(MEMBER_COUNT);
        for i in 0..MEMBER_COUNT {
            keys.push(member_key(seed, i));
        }
        Cast { keys }
    }
    fn key(&self, i: usize) -> &Keypair {
        &self.keys[i]
    }
    fn addr(&self, i: usize) -> Address {
        Address::from_public_key(self.keys[i].public_key())
    }
}

/// Narration for the human-facing demo (`scripts/demo-phase-2-outage.sh`): prints
/// only when `RRN_OUTAGE_NARRATE` is set, so `cargo test` stays quiet.
fn narrate(msg: &str) {
    if std::env::var_os("RRN_OUTAGE_NARRATE").is_some() {
        println!("{msg}");
    }
}

/// Deterministic per-member secret from (seed, index) — index 0 is the operator.
fn member_key(seed: u64, i: usize) -> Keypair {
    let mut h = Hasher::new();
    h.update(b"rrn-outage-member");
    h.update(&seed.to_be_bytes());
    h.update(&(i as u64).to_be_bytes());
    Keypair::from_secret(SecretKey::from_bytes(h.finalize().to_bytes()))
}

/// A keypair outside the cast — the adversary who signs forged/tampered records.
fn outsider_key(seed: u64) -> Keypair {
    let mut h = Hasher::new();
    h.update(b"rrn-outage-outsider");
    h.update(&seed.to_be_bytes());
    Keypair::from_secret(SecretKey::from_bytes(h.finalize().to_bytes()))
}

/// An outsider proposes to member 17 with a self-consistent (author == signer)
/// entry: admitted (permissionless), but never confirmed, so it never settles.
async fn outage_unknown_key_inert(h: &mut Harness) {
    let expires = START + 100 * OUTAGE_SECS;
    let outsider = outsider_key(h.seed);
    let outsider_addr = Address::from_public_key(outsider.public_key());
    let prop = SignedProposal::sign(
        TransactionProposal::new(
            outsider_addr,
            h.cast.addr(17),
            100,
            None,
            0,
            h.now(),
            expires,
        ),
        &outsider,
    );
    let entry = OutboxEntry::wrapping(
        outsider_addr,
        0,
        Hash::from_bytes([0u8; 32]),
        &prop,
        h.now(),
    );
    let signed = SignedPayload::sign(entry, &outsider);
    let r = h.submit(&[signed]).await;
    h.reconcile("unknown-key proposal (inert)", &r, &[Expect::Admit]);
    // No confirmation is ever authored, so this proposal cannot settle: member 17's
    // balance stays 0, which the final reconciliation checks.
}

/// Per-member outbox-chain builder: tracks each device's next position and
/// previous-entry hash so bundles carry correctly-chained entries (ADR-0020 §2).
struct Outboxes {
    next_pos: HashMap<usize, u64>,
    prev_hash: HashMap<usize, Hash>,
}
impl Outboxes {
    fn new() -> Self {
        Self {
            next_pos: HashMap::new(),
            prev_hash: HashMap::new(),
        }
    }
    /// Wraps `record` as the next signed outbox entry for member `i`, advancing
    /// that member's chain.
    fn wrap<T: Clone + Into<dcbor::CBOR>>(
        &mut self,
        cast: &Cast,
        i: usize,
        record: &SignedPayload<T>,
        authored_at: i64,
    ) -> SignedOutboxEntry {
        let pos = *self.next_pos.get(&i).unwrap_or(&0);
        let prev = self
            .prev_hash
            .get(&i)
            .copied()
            .unwrap_or_else(|| Hash::from_bytes([0u8; 32]));
        let entry = OutboxEntry::wrapping(cast.addr(i), pos, prev, record, authored_at);
        let signed = SignedPayload::sign(entry, cast.key(i));
        self.next_pos.insert(i, pos + 1);
        self.prev_hash.insert(i, signed.payload.entry_hash());
        signed
    }
}

/// A signed outbox entry authored by member `i` at an explicit position — for the
/// fork and gap cases, which need control of the outbox position independent of
/// the contiguous chain the [`Outboxes`] helper builds.
fn raw_entry<T: Clone + Into<dcbor::CBOR>>(
    cast: &Cast,
    i: usize,
    pos: u64,
    prev: Hash,
    record: &SignedPayload<T>,
    authored_at: i64,
) -> SignedOutboxEntry {
    let entry = OutboxEntry::wrapping(cast.addr(i), pos, prev, record, authored_at);
    SignedPayload::sign(entry, cast.key(i))
}

/// What the harness intends each submitted record to become — the intent side of
/// the reconciliation ledger (assertion 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Admit,
    Known,
    Refuse(RefusalReason),
}

fn matches(disposition: &Disposition, expect: Expect) -> bool {
    match (disposition, expect) {
        (Disposition::Admitted { .. }, Expect::Admit) => true,
        (Disposition::Known { .. }, Expect::Known) => true,
        (Disposition::Refused { reason }, Expect::Refuse(want)) => *reason == want,
        _ => false,
    }
}

fn write_config(dir: &Path) {
    // No peers, no mDNS: a station that has lost every reachable link. Timers long
    // enough that only the harness's explicit `sweep()` settles — determinism.
    let text = format!(
        "[network]\nlisten = \"127.0.0.1:0\"\n\n\
         [mobile]\nadvertise = false\nlisten = \"127.0.0.1:0\"\n\n\
         [settlement]\nwindow_seconds = {WINDOW}\n\n\
         [timers]\nsweep_interval_secs = 3600\ngossip_interval_secs = 3600\n"
    );
    std::fs::write(dir.join("config.toml"), text).unwrap();
}

/// Initializes a data dir with a **deterministic** operator wallet (the cast's
/// index-0 key), a migrated database, and the harness config — the deterministic
/// analogue of [`Station::init`], whose wallet key is random. A fixed operator key
/// is what makes two runs of the same seed produce a byte-identical log
/// (assertion 9).
fn init_deterministic(dir: &Path, operator: &Keypair) {
    std::fs::create_dir_all(dir).unwrap();
    let wallet = WalletContents {
        secret_key: operator.secret_key().clone(),
        address: Address::from_public_key(operator.public_key()),
        created_at: START,
        metadata: std::collections::BTreeMap::new(),
    };
    wallet
        .save_to_file(&dir.join(WALLET_FILE), PASSPHRASE)
        .unwrap();
    let db = Database::open(&dir.join(DB_FILE)).unwrap();
    migrations::run(&db).unwrap();
    write_config(dir);
}

/// The scenario driver: one real station, the cast, the harness's own ledger of
/// intent (`expected` balances + a reconciliation tally), and the RNG.
struct Harness {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    station: Station,
    client: UnixClient,
    clock: Clock,
    cast: Cast,
    outboxes: Outboxes,
    rng: Rng,
    seed: u64,
    /// Next transaction nonce per author index (proposals + cert requests share it
    /// for the operator; ADR-0021 §1). Advanced only on an admitted authoring
    /// record, matching `LedgerSnapshot::next_nonce`.
    nonce: HashMap<usize, u64>,
    /// The harness's expectation of every member's settled balance once the
    /// horizon elapses — updated the instant a payment's both legs are admitted.
    expected: HashMap<usize, i64>,
    /// Reconciliation tally: (admitted, known, refused) record dispositions seen.
    admitted: u64,
    known: u64,
    refused: u64,
    /// The content hashes of every record the station reported as `admitted` — the
    /// authoritative set of what SHOULD be on the log (assertion 8's length audit).
    admitted_hashes: HashSet<[u8; 32]>,
}

impl Harness {
    async fn new(seed: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cast = Cast::new(seed);
        init_deterministic(dir.path(), cast.key(0));

        let clock = Clock::manual(START);
        let station = Station::open(StationParams {
            data_dir: dir.path().to_path_buf(),
            passphrase: PASSPHRASE.into(),
            clock: clock.clone(),
        })
        .await
        .unwrap();
        let client = UnixClient::new(station.socket_path());
        let db_path = dir.path().join(DB_FILE);

        Harness {
            _dir: dir,
            db_path,
            station,
            client,
            clock,
            cast,
            outboxes: Outboxes::new(),
            rng: Rng::new(seed),
            seed,
            nonce: HashMap::new(),
            expected: HashMap::new(),
            admitted: 0,
            known: 0,
            refused: 0,
            admitted_hashes: HashSet::new(),
        }
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    fn nonce_of(&self, i: usize) -> u64 {
        *self.nonce.get(&i).unwrap_or(&0)
    }

    fn bump_nonce(&mut self, i: usize) {
        *self.nonce.entry(i).or_insert(0) += 1;
    }

    fn expect_balance(&mut self, from: usize, to: usize, amount: i64) {
        *self.expected.entry(from).or_insert(0) -= amount;
        *self.expected.entry(to).or_insert(0) += amount;
    }

    // --- record construction ------------------------------------------------

    /// A signed positive-amount proposal by member `from` to `to`, using `from`'s
    /// current nonce (the caller bumps it iff the proposal is admitted).
    fn proposal(&self, from: usize, to: usize, amount: i64, expires_at: i64) -> SignedProposal {
        let p = TransactionProposal::new(
            self.cast.addr(from),
            self.cast.addr(to),
            amount,
            None,
            self.nonce_of(from),
            self.now(),
            expires_at,
        );
        SignedProposal::sign(p, self.cast.key(from))
    }

    /// A signed confirmation of `proposal` by its receiver `to`.
    fn confirmation(&self, to: usize, proposal: &SignedProposal) -> SignedConfirmation {
        SignedConfirmation::sign(
            TransactionConfirmation {
                proposal_id: proposal.payload.id,
                confirmer: self.cast.addr(to),
                confirmed_at: self.now(),
            },
            self.cast.key(to),
        )
    }

    // --- submission channels ------------------------------------------------

    /// Submits a bundle of already-chained entries over the operator socket and
    /// returns the verified station receipt (the direct-courier path).
    async fn submit(&self, entries: &[SignedOutboxEntry]) -> SignedReceipt {
        let envs: Vec<EntryEnvelope> = entries.iter().map(EntryEnvelope::from_signed).collect();
        let bundle_hex = hex(&Bundle::new(envs, self.now()).encode());
        self.submit_bundle_hex(&bundle_hex).await
    }

    /// Submits a bundle hex and returns the raw receipt hex alongside the decoded
    /// receipt (so callers can prove idempotent replays are byte-identical).
    async fn submit_bundle_hex_raw(&self, bundle_hex: &str) -> (SignedReceipt, String) {
        let v = self
            .client
            .call(
                "bundle_submit",
                serde_json::json!({ "bundle_hex": bundle_hex }),
            )
            .await
            .unwrap();
        let receipt_hex = v["receipt_hex"].as_str().unwrap().to_string();
        let signed = receipt::decode_signed(&unhex(&receipt_hex).unwrap()).unwrap();
        assert!(signed.verify().is_ok(), "station receipt must verify");
        (signed, receipt_hex)
    }

    async fn submit_bundle_hex(&self, bundle_hex: &str) -> SignedReceipt {
        let v = self
            .client
            .call(
                "bundle_submit",
                serde_json::json!({ "bundle_hex": bundle_hex }),
            )
            .await
            .unwrap();
        let receipt_hex = v["receipt_hex"].as_str().unwrap();
        let signed = receipt::decode_signed(&unhex(receipt_hex).unwrap()).unwrap();
        assert!(signed.verify().is_ok(), "station receipt must verify");
        signed
    }

    /// Ingests raw bundle bytes through the DTN front door — the path a carrier
    /// (the mock LoRa syncer) delivers on.
    async fn ingest(&self, bytes: Vec<u8>) -> SignedReceipt {
        let out = self
            .station
            .core()
            .ingest_bundle_bytes(bytes)
            .await
            .expect("ingest returns a signed receipt");
        let signed = receipt::decode_signed(&out).unwrap();
        assert!(signed.verify().is_ok(), "station receipt must verify");
        signed
    }

    /// Asserts each outcome of `receipt` matches `expects` positionally and folds
    /// it into the reconciliation tally.
    fn reconcile(&mut self, label: &str, receipt: &SignedReceipt, expects: &[Expect]) {
        let outcomes = &receipt.payload.outcomes;
        assert_eq!(
            outcomes.len(),
            expects.len(),
            "{label}: receipt reported {} outcomes, expected {}",
            outcomes.len(),
            expects.len()
        );
        for (i, (o, e)) in outcomes.iter().zip(expects).enumerate() {
            assert!(
                matches(&o.disposition, *e),
                "{label}: record {i} disposition {:?} did not match intent {:?}",
                o.disposition,
                e
            );
            match o.disposition {
                Disposition::Admitted { .. } => {
                    self.admitted += 1;
                    self.admitted_hashes.insert(o.record_hash.to_bytes());
                }
                Disposition::Known { .. } => self.known += 1,
                Disposition::Refused { .. } => self.refused += 1,
            }
        }
    }

    // --- high-level flows ---------------------------------------------------

    /// A whole payment carried in one bundle over the direct-courier path:
    /// proposal (sender) then confirmation (receiver), both admitted. Records the
    /// expected settled movement. Returns the entries (to allow replay/dup tests).
    async fn pay_via(&mut self, from: usize, to: usize, amount: i64) -> Vec<SignedOutboxEntry> {
        let expires = START + 100 * OUTAGE_SECS;
        let prop = self.proposal(from, to, amount, expires);
        let conf = self.confirmation(to, &prop);
        let at = self.now();
        let e1 = self.outboxes.wrap(&self.cast, from, &prop, at);
        let e2 = self.outboxes.wrap(&self.cast, to, &conf, at);
        let entries = vec![e1, e2];
        let receipt = self.submit(&entries).await;
        self.reconcile(
            &format!("pay {from}->{to} {amount}"),
            &receipt,
            &[Expect::Admit, Expect::Admit],
        );
        self.bump_nonce(from);
        self.expect_balance(from, to, amount);
        entries
    }

    /// Advances the clock past the settlement window from the latest admission and
    /// sweeps until nothing more settles (also drives equivocation resolution).
    async fn settle_all(&mut self) {
        self.clock.advance(WINDOW as i64 + 2);
        for _ in 0..8 {
            if self.station.sweep().await == 0 {
                break;
            }
        }
    }

    async fn balance(&self, i: usize) -> i64 {
        let v = self
            .client
            .call(
                "balance",
                serde_json::json!({ "address": self.cast.addr(i).to_string() }),
            )
            .await
            .unwrap();
        serde_json::from_value::<BalanceResult>(v)
            .unwrap()
            .balance_centi
    }
}

// ===========================================================================
// The tests: three CI seeds plus a determinism spot check.
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outage_72h_seed_1() {
    tokio::time::timeout(Duration::from_secs(120), run_and_assert(1))
        .await
        .expect("seed 1 must finish well inside the wall-clock budget");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outage_72h_seed_2() {
    tokio::time::timeout(Duration::from_secs(120), run_and_assert(2))
        .await
        .expect("seed 2 must finish well inside the wall-clock budget");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outage_72h_seed_3() {
    tokio::time::timeout(Duration::from_secs(120), run_and_assert(3))
        .await
        .expect("seed 3 must finish well inside the wall-clock budget");
}

/// Assertion 9 (determinism): the same seed produces a byte-identical final chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outage_72h_is_deterministic() {
    let a = tokio::time::timeout(Duration::from_secs(120), run_and_assert(1))
        .await
        .expect("first determinism run finishes");
    let b = tokio::time::timeout(Duration::from_secs(120), run_and_assert(1))
        .await
        .expect("second determinism run finishes");
    assert_eq!(
        a, b,
        "the same seed must yield an identical final chain digest (determinism, ADR-0017)"
    );
}

/// Runs the whole scenario for `seed`, asserts every invariant, and returns the
/// final chain digest (for the determinism check).
async fn run_and_assert(seed: u64) -> Hash {
    narrate(&format!(
        "\n=== 72-hour outage simulation (seed {seed}) ===\n\
         Cast: 1 station operator + {} members; debt floor {FLOOR} centicommons; \
         settlement window {WINDOW}s.",
        MEMBER_COUNT - 1
    ));
    let mut h = Harness::new(seed).await;

    // === T0: normal pre-outage operations, settled to spread balances =======
    narrate("\n[T0] Normal operations: settled payments spread balances (member 5 steered near the floor).");
    // A handful of settled payments; member 5 is deliberately steered to within
    // ~300 of the floor (four debits), so a later offline spend bounces it.
    h.pay_via(5, 6, 450).await;
    h.pay_via(5, 7, 450).await;
    h.pay_via(5, 8, 450).await;
    h.pay_via(5, 9, 350).await; // member 5 now at -1700 (floor -2000)
    h.pay_via(1, 2, 300).await;
    h.pay_via(3, 4, 250).await;
    let replay_fodder = h.pay_via(9, 10, 300).await; // kept for the replay adversary
                                                     // The operator is steered to -1440 as well, so the outage cert flow can show a
                                                     // cert-backed spend admitted where the *plain* debt floor would refuse it
                                                     // (assertion 5 — escrow honored). Recipients 14/15/16 are otherwise idle.
    h.pay_via(0, 14, 480).await;
    h.pay_via(0, 15, 480).await;
    h.pay_via(0, 16, 480).await;
    h.settle_all().await;

    // Conservation holds the instant the pre-outage books settle.
    assert_conservation(&h, "T0").await;

    // === T1..T2: 72 simulated hours of activity over offline channels ========
    narrate(
        "\n[T1] Connectivity lost. 72 simulated hours of activity flow over offline channels:\n\
         courier bundles (with gaps, duplication, loss), a paper leg, and a mock-LoRa leg —\n\
         plus a planted cert double-spend, an outbox fork, a floor bounce, and adversarial inputs.",
    );
    let outage_start = h.now();
    h.clock.set(outage_start); // (outage begins; the station keeps running LAN-less)

    // -- Gap / partial carriage: member 11 authors two proposals, delivered with
    //    their outbox positions OUT of order (pos 1 before pos 0). A leading gap
    //    is logged, not refused (ADR-0020 §2); both admit. --------------------
    outage_gap_leg(&mut h).await;

    // -- Duplicated carriage: the same bundle carried by two couriers; the second
    //    is all `known`, and the identical entry at the same position is a benign
    //    duplicate, NOT a fork. -----------------------------------------------
    outage_duplicated_carriage(&mut h).await;

    // -- Paper leg: a payment round-tripped through the T2.5.2 paper codec. -----
    outage_paper_leg(&mut h).await;

    // -- Mock-LoRa leg: a payment across a lossy, airtime-budgeted carrier via
    //    the DtnSyncer, then ingested. ----------------------------------------
    outage_lora_leg(&mut h).await;

    // -- A plain courier payment. ---------------------------------------------
    h.clock.advance(OUTAGE_SECS / 6);
    h.pay_via(8, 9, 250).await;

    // -- Operator cert flow: an at-cap spend, and the planted DOUBLE-SPEND. ----
    outage_cert_flow(&mut h).await;

    // -- The planted OUTBOX FORK (member 7). ----------------------------------
    outage_fork_leg(&mut h).await;

    // -- The engineered FLOOR BOUNCE (member 5, still settled at -1700). -------
    outage_floor_bounce(&mut h).await;

    // -- Adversarial garnish: forged authorship, a tampered inner record, and a
    //    replayed pre-outage bundle. All leave only refusals / known. ---------
    let adversarial_admitted_before = h.admitted;
    outage_adversarial(&mut h, &replay_fodder).await;
    assert_eq!(
        h.admitted, adversarial_admitted_before,
        "adversarial inputs must admit nothing (assertion 8)"
    );

    // -- Unknown-key proposal: an outsider's *self-consistent* proposal (author ==
    //    signer) is ADMITTED — the ledger is permissionless (ADR-0020) — but with no
    //    counterparty confirmation it never settles and moves no value. Documented
    //    divergence from the ticket's "no trace beyond refusals": an unknown key can
    //    write a proposal, it just cannot move credit. (Its receiver, member 17,
    //    stays at 0, verified by the final reconciliation.) --------------------
    outage_unknown_key_inert(&mut h).await;

    // -- Lost-forever bundle re-exported at reconnect. ------------------------
    // Member 4 pays member 5; the first carriage is "lost" (never submitted), so
    // the author re-exports the identical bundle at reconnect (T2). It admits.
    h.clock.advance(OUTAGE_SECS / 6);
    outage_lost_then_reexport(&mut h).await;

    // === T2: reconnect — conservation still holds (nothing has settled yet) ==
    narrate("\n[T2] Reconnect: all queued/lost carriage drains (the lost bundle is re-exported).");
    assert_conservation(&h, "T2").await;

    // WINDOW ENFORCEMENT (assertion 7, made non-vacuous): the just-re-exported
    // m4->m5 payment was confirmed at THIS instant, so its settlement window has
    // not elapsed. A sweep now must NOT settle it — member 5's balance stays at its
    // pre-outage -1700 (the +480 credit lands only after the horizon). Were the
    // settler to anchor on the (older) confirmed-at instead of the admission time,
    // this would settle early and the check would fail.
    h.station.sweep().await;
    assert_eq!(
        h.balance(5).await,
        -1700,
        "a payment must not settle before its confirmation-admission window elapses"
    );

    // === T3: settlement horizon — every window elapses, everything settles ===
    narrate(
        "[T3] Settlement horizon: every window elapses; the station settles the confirmed ledger.",
    );
    h.settle_all().await;
    assert_conservation(&h, "T3").await;
    narrate(&format!(
        "\nReconciliation tally: {} admitted, {} known, {} refused record dispositions.",
        h.admitted, h.known, h.refused
    ));

    // Full reconciliation: every member's settled balance equals the harness's
    // intent ledger. No credits lost or conjured (assertion 3).
    for i in 0..MEMBER_COUNT {
        let want = *h.expected.get(&i).unwrap_or(&0);
        let got = h.balance(i).await;
        assert_eq!(
            got, want,
            "reconciliation: member {i} settled to {got}, intent ledger says {want}"
        );
    }

    // Structural assertions read the log directly after a clean shutdown.
    let db_path = h.db_path.clone();
    let admitted_hashes = h.admitted_hashes.clone();
    let operator_addr = h.cast.addr(0);
    let forker_addr = h.cast.addr(13);
    let socket = h.station.socket_path().to_path_buf();
    h.station.shutdown().await;
    assert!(
        !socket.exists(),
        "the Unix socket must be removed on shutdown"
    );

    narrate("\nAsserting the exit invariants:");
    assert_no_forks(&db_path); // assertion 1
    narrate("  [1] no forks: the hash chain verifies; every signature verifies.");
    assert_conservation_from_log(&db_path); // assertion 2 (log-derived, all holders)
    narrate("  [2] conservation: settled balances summed to zero at T0, T2, T3.");
    narrate("  [3] reconciliation: every member's balance matches the intent ledger.");
    assert_floor_invariant_every_prefix(&db_path); // assertion 4
    narrate("  [4] floor invariant: held at every log prefix, for every participant.");
    assert_escrow_honored(&db_path); // assertion 5
    narrate("  [5] escrow honored: no cert overspent; the at-cap spend consumed to cap.");
    assert_exactly_the_planted_equivocations(&db_path, operator_addr, forker_addr); // assertion 6
    narrate("  [6] equivocation: exactly the planted double-spend + fork were recorded.");
    assert_windows_respected(&db_path); // assertion 7
    narrate("  [7] windows: no transaction settled before confirmation admission + window.");
    assert_no_phantom_admissions(&db_path, &admitted_hashes); // assertion 8
    narrate("  [8] adversarial: every logged member record was receipted `admitted` — no phantom writes.");

    let digest = chain_digest(&db_path); // assertion 9 material
    narrate(&format!(
        "  [9] determinism: final chain digest {}",
        hex(&digest.to_bytes())
    ));
    digest
}

// ===========================================================================
// Outage legs
// ===========================================================================

/// Member 11 authors two proposals whose outbox positions arrive out of order.
async fn outage_gap_leg(h: &mut Harness) {
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;

    // Transaction nonce order == admission order (0 then 1); outbox position order
    // is the reverse, which is the gap.
    let prop_a = h.proposal(11, 2, 200, expires); // nonce 0, outbox pos 1
    let conf_a = h.confirmation(2, &prop_a);
    h.bump_nonce(11);
    let prop_b = h.proposal(11, 12, 480, expires); // nonce 1, outbox pos 0
    let conf_b = h.confirmation(12, &prop_b);
    h.bump_nonce(11);

    let zero = Hash::from_bytes([0u8; 32]);
    // A genuine, correctly-linked chain: pos 0 (prop_b) then pos 1 (prop_a chained
    // onto pos 0's entry hash). We build pos 0 first only to compute that link — it
    // is delivered LAST, so the receiver sees the chain with a leading gap.
    let e_b = raw_entry(&h.cast, 11, 0, zero, &prop_b, h.now());
    let e_a = raw_entry(&h.cast, 11, 1, e_b.payload.entry_hash(), &prop_a, h.now());

    // Bundle 1 carries member 11's outbox pos 1 (ahead of the still-unseen pos 0)
    // plus member 2's confirmation. The gap is logged, not refused (ADR-0020 §2).
    let e_a_conf = h.outboxes.wrap(&h.cast, 2, &conf_a, h.now());
    let r1 = h.submit(&[e_a, e_a_conf]).await;
    h.reconcile("gap: pos1 first", &r1, &[Expect::Admit, Expect::Admit]);
    h.expect_balance(11, 2, 200);

    // Bundle 2 fills the gap with outbox pos 0 plus member 12's confirmation.
    let e_b_conf = h.outboxes.wrap(&h.cast, 12, &conf_b, h.now());
    let r2 = h.submit(&[e_b, e_b_conf]).await;
    h.reconcile("gap: pos0 later", &r2, &[Expect::Admit, Expect::Admit]);
    h.expect_balance(11, 12, 480);
}

/// The same records carried by two more couriers. The identical bundle is
/// answered idempotently (the byte-identical cached receipt); a *re-presentation*
/// of the same records in a different bundle is recognized as already `known`.
/// Neither double-counts, and neither is a fork (assertion 6).
async fn outage_duplicated_carriage(h: &mut Harness) {
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;

    // Build the payment (member 2 -> 4, 350) and its bundle once, so two couriers
    // can carry byte-identical copies.
    let prop = h.proposal(2, 4, 350, expires);
    let conf = h.confirmation(4, &prop);
    let e1 = h.outboxes.wrap(&h.cast, 2, &prop, h.now());
    let e2 = h.outboxes.wrap(&h.cast, 4, &conf, h.now());
    let entries = [e1, e2];
    let envs: Vec<EntryEnvelope> = entries.iter().map(EntryEnvelope::from_signed).collect();
    let bundle_hex = hex(&Bundle::new(envs, h.now()).encode());

    // First courier: both records admit.
    let (r1, hex1) = h.submit_bundle_hex_raw(&bundle_hex).await;
    h.reconcile(
        "duplicated carriage (first)",
        &r1,
        &[Expect::Admit, Expect::Admit],
    );
    h.bump_nonce(2);
    h.expect_balance(2, 4, 350);

    // Second courier: the identical bundle. The station replays its cached receipt
    // VERBATIM — byte-identical, re-admitting nothing.
    let (_r2, hex2) = h.submit_bundle_hex_raw(&bundle_hex).await;
    assert_eq!(
        hex1, hex2,
        "an identical duplicate bundle must return the byte-identical cached receipt"
    );

    // Third courier: the same records, re-bundled in a different order (a distinct
    // presentation). Now the per-record dedup answers `known` for both.
    let reordered: Vec<SignedOutboxEntry> = entries.iter().rev().cloned().collect();
    let r = h.submit(&reordered).await;
    h.reconcile(
        "duplicated carriage (re-presented)",
        &r,
        &[Expect::Known, Expect::Known],
    );
}

/// A payment round-tripped through the paper codec (encode → reassemble → submit).
async fn outage_paper_leg(h: &mut Harness) {
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;
    let prop = h.proposal(6, 3, 400, expires);
    let conf = h.confirmation(3, &prop);
    let e1 = h.outboxes.wrap(&h.cast, 6, &prop, h.now());
    let e2 = h.outboxes.wrap(&h.cast, 3, &conf, h.now());
    let bundle = Bundle::new(
        vec![
            EntryEnvelope::from_signed(&e1),
            EntryEnvelope::from_signed(&e2),
        ],
        h.now(),
    );
    let bytes = bundle.encode();

    // Paper round trip: chunk to card lines, reassemble, and confirm byte-identity.
    let chunks = encode_chunks(PaperKind::Bundle, &bytes).unwrap();
    let mut re = PaperReassembler::new();
    let mut recovered = None;
    for line in &chunks {
        if let Some((kind, out)) = re.accept(line).unwrap() {
            recovered = Some((kind, out));
        }
    }
    let (kind, out) = recovered.expect("paper chunks reassemble");
    assert_eq!(kind, PaperKind::Bundle);
    assert_eq!(out, bytes, "paper round trip must be byte-identical");

    let r = h.submit_bundle_hex(&hex(&out)).await;
    h.reconcile("paper leg", &r, &[Expect::Admit, Expect::Admit]);
    h.bump_nonce(6);
    h.expect_balance(6, 3, 400);
}

/// A payment delivered across a lossy, airtime-budgeted mock carrier (LoRa) via
/// the DtnSyncer, then ingested through the station's DTN front door.
async fn outage_lora_leg(h: &mut Harness) {
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;
    let prop = h.proposal(10, 1, 300, expires);
    let conf = h.confirmation(1, &prop);
    let e1 = h.outboxes.wrap(&h.cast, 10, &prop, h.now());
    let e2 = h.outboxes.wrap(&h.cast, 1, &conf, h.now());
    let bytes = Bundle::new(
        vec![
            EntryEnvelope::from_signed(&e1),
            EntryEnvelope::from_signed(&e2),
        ],
        h.now(),
    )
    .encode();

    let delivered = drive_lossy_carrier(&bytes, h.rng.fault_seed(0x10_4A));
    assert_eq!(delivered, bytes, "the bundle survives the lossy carrier");

    let r = h.ingest(delivered).await;
    h.reconcile("mock-LoRa leg", &r, &[Expect::Admit, Expect::Admit]);
    h.bump_nonce(10);
    h.expect_balance(10, 1, 300);
}

/// Runs a bundle through a drop/dup/reorder mock carrier at the design's punishing
/// LoRa airtime budget until the receiver reassembles it, returning the bytes.
fn drive_lossy_carrier(bundle_bytes: &[u8], fault_seed: u64) -> Vec<u8> {
    let net = LoopbackNet::new(180);
    let fault = FaultConfig {
        drop_prob: 0.15,
        dup_prob: 0.10,
        corrupt_prob: 0.0,
        reorder_window: 2,
        seed: fault_seed,
    };
    let budget = AirtimeBudget {
        sustained_bytes_per_sec: 6.0,
        burst_bytes: 400,
    };
    let cfg = SyncConfig {
        resend_interval_secs: 20,
        ..SyncConfig::default()
    };
    let mut sender = DtnSyncer::new(
        FaultTransport::new(net.endpoint("dev"), fault),
        budget,
        cfg,
        0,
    );
    let mut station = DtnSyncer::new(
        FaultTransport::new(net.endpoint("stn"), fault),
        budget,
        cfg,
        0,
    );
    let ep_stn = Endpoint::new("stn");
    assert!(sender.send(
        &ep_stn,
        PayloadKind::Bundle,
        bundle_bytes,
        Priority::Economic,
        0
    ));

    for now in 1..=30_000 {
        for _c in sender.tick(now).unwrap() {}
        for c in station.tick(now).unwrap() {
            if c.kind == PayloadKind::Bundle {
                return c.bytes;
            }
        }
    }
    panic!("bundle failed to cross the lossy carrier within the tick budget");
}

/// The operator's headroom-certificate flow: an at-cap spend (innocent) and the
/// planted double-spend (a second cert-backed spend that overspends the same
/// certificate — provable equivocation, ADR-0021 §5).
async fn outage_cert_flow(h: &mut Harness) {
    h.clock.advance(OUTAGE_SECS / 12);

    let expires = START + 100 * OUTAGE_SECS;

    // Certificate X (cap 480). Issued to the operator over the live socket. The
    // operator sits at settled -1440; issuance reserves 480 (projected -1920, still
    // above the -2000 floor).
    let cert_x = request_cert(h, 480).await;

    // ESCROW BYPASS (assertion 5): with the 480 reservation now held, a *plain* 480
    // debit by the operator would project -1440 - 480 - 480 = -2400 and is refused
    // at the floor — but the cert-backed spend below, riding its reserved headroom,
    // is admitted. This is the "admitted even where the floor would have refused it"
    // clause, exercised directly.
    let would_breach = h.proposal(0, 6, 480, expires); // NOT cert-backed
    let e = h.outboxes.wrap(&h.cast, 0, &would_breach, h.now());
    let r = h.submit(&[e]).await;
    h.reconcile(
        "escrow: a plain debit at the same size breaches the floor",
        &r,
        &[Expect::Refuse(RefusalReason::DebtFloor)],
    ); // refused → no nonce bump; the at-cap cert spend below reuses this nonce

    // Spend 1 — an AT-CAP cert-backed spend (480 == cap) that the plain floor would
    // have refused: admitted on the reserved headroom, fully consuming X.
    cert_spend(h, &cert_x, 3, 480, Expect::Admit).await;
    h.expect_balance(0, 3, 480);

    // Planted DOUBLE-SPEND (last cert action): a second cert-backed spend against X
    // (480) whose total (480 + 480) overspends the 480 cap. Refused `cert-overspent`;
    // the station records exactly one cert-overspend equivocation. A single
    // certificate carries all three cases (at-cap, bypass, double-spend) because an
    // un-overturned equivocation then disqualifies the operator from issuing any
    // further certificate (ADR-0025).
    cert_spend(
        h,
        &cert_x,
        4,
        480,
        Expect::Refuse(RefusalReason::CertOverspent),
    )
    .await;
}

/// Issues a cert for the operator over the socket and returns `(cert_id, expires)`.
async fn request_cert(h: &mut Harness, cap: i64) -> (CertId, i64) {
    let res: CertRequestResult = serde_json::from_value(
        h.client
            .call("cert_request", serde_json::json!({ "cap_centi": cap }))
            .await
            .unwrap(),
    )
    .unwrap();
    h.bump_nonce(0); // a cert request consumes the operator's proposal nonce
    (
        CertId(Hash::from_hex(&res.cert_id).unwrap()),
        res.expires_at,
    )
}

/// A cert-backed offline spend by the operator to `to`, carried (with the
/// receiver's confirmation) in one bundle. Bumps the operator nonce only when
/// admitted (a refused overspend does not advance it).
async fn cert_spend(h: &mut Harness, cert: &(CertId, i64), to: usize, amount: i64, expect: Expect) {
    let (cert_id, cert_expires) = *cert;
    let spend = SignedProposal::sign(
        TransactionProposal::new(
            h.cast.addr(0),
            h.cast.addr(to),
            amount,
            None,
            h.nonce_of(0),
            h.now(),
            cert_expires,
        )
        .with_certificate(cert_id),
        h.cast.key(0),
    );
    let conf = h.confirmation(to, &spend);
    let e1 = h.outboxes.wrap(&h.cast, 0, &spend, h.now());
    let e2 = h.outboxes.wrap(&h.cast, to, &conf, h.now());
    // On a refused spend the receiver's confirmation is refused too (its proposal
    // never became `Proposed`): NotProposed.
    let conf_expect = match expect {
        Expect::Admit => Expect::Admit,
        _ => Expect::Refuse(RefusalReason::NotProposed),
    };
    let r = h.submit(&[e1, e2]).await;
    h.reconcile(
        &format!("cert spend ->{to} {amount}"),
        &r,
        &[expect, conf_expect],
    );
    if expect == Expect::Admit {
        h.bump_nonce(0);
    }
}

/// The planted outbox fork: member 13 (who authors nothing else, so position 0 is
/// pristine) signs two DIFFERENT records at the same outbox position 0. The first
/// (a real payment) is admitted and settles; the second is refused `outbox-fork`,
/// and the station records exactly one outbox-fork equivocation (ADR-0021 §5).
async fn outage_fork_leg(h: &mut Harness) {
    const FORKER: usize = 13;
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;
    let zero = Hash::from_bytes([0u8; 32]);

    // Chain A: the honest payment, member 13 -> 8, 300.
    let prop_a = h.proposal(FORKER, 8, 300, expires);
    let conf_a = h.confirmation(8, &prop_a);
    let e_a = raw_entry(&h.cast, FORKER, 0, zero, &prop_a, h.now());
    let e_a_conf = h.outboxes.wrap(&h.cast, 8, &conf_a, h.now());
    let r1 = h.submit(&[e_a, e_a_conf]).await;
    h.reconcile("fork: chain A", &r1, &[Expect::Admit, Expect::Admit]);
    h.bump_nonce(FORKER);
    h.expect_balance(FORKER, 8, 300);

    // Chain B: a conflicting record at the SAME outbox position 0 (member 13 -> 9,
    // 250, a distinct proposal). Refused as an outbox fork.
    let prop_b = h.proposal(FORKER, 9, 250, expires); // nonce 1, but rejected before the engine
    let e_b = raw_entry(&h.cast, FORKER, 0, zero, &prop_b, h.now());
    let r2 = h.submit(&[e_b]).await;
    h.reconcile(
        "fork: chain B",
        &r2,
        &[Expect::Refuse(RefusalReason::OutboxFork)],
    );
}

/// Member 5, still settled at -1700, proposes a debit that would breach the floor.
async fn outage_floor_bounce(h: &mut Harness) {
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;
    let prop = h.proposal(5, 6, 400, expires); // -1700 - 400 = -2100 < floor -2000
    let e = h.outboxes.wrap(&h.cast, 5, &prop, h.now());
    let r = h.submit(&[e]).await;
    h.reconcile(
        "floor bounce",
        &r,
        &[Expect::Refuse(RefusalReason::DebtFloor)],
    );
    // Refused: no nonce bump, no balance movement.
}

/// Three adversarial bundles: forged authorship, a tampered inner record, and a
/// replay of a pre-outage bundle. None admits anything.
async fn outage_adversarial(h: &mut Harness, replay_fodder: &[SignedOutboxEntry]) {
    h.clock.advance(OUTAGE_SECS / 12);
    let expires = START + 100 * OUTAGE_SECS;
    let outsider = outsider_key(h.seed);
    let zero = Hash::from_bytes([0u8; 32]);

    // (1) Forged authorship: the entry CLAIMS member 1 as author but is signed by
    //     an outsider key. `author != signer` → bad-signature.
    let inner = SignedProposal::sign(
        TransactionProposal::new(
            h.cast.addr(1),
            h.cast.addr(2),
            100,
            None,
            0,
            h.now(),
            expires,
        ),
        &outsider,
    );
    let forged_entry = OutboxEntry::wrapping(h.cast.addr(1), 900, zero, &inner, h.now());
    let forged = SignedPayload::sign(forged_entry, &outsider); // signer = outsider != author 1
    let r = h.submit(&[forged]).await;
    h.reconcile(
        "adversary: forged authorship",
        &r,
        &[Expect::Refuse(RefusalReason::BadSignature)],
    );

    // (2) Tampered inner record: a valid outbox entry (author == signer) carrying a
    //     proposal whose signature belongs to a DIFFERENT proposal. The inner
    //     record signature no longer verifies its bytes → bad-signature.
    let real = TransactionProposal::new(
        h.cast.addr(1),
        h.cast.addr(2),
        120,
        None,
        0,
        h.now(),
        expires,
    );
    let decoy = TransactionProposal::new(
        h.cast.addr(1),
        h.cast.addr(3),
        130,
        None,
        0,
        h.now(),
        expires,
    );
    let decoy_sig = SignedProposal::sign(decoy, h.cast.key(1)).signature;
    let tampered = SignedProposal {
        payload: real,
        signer: h.cast.key(1).public_key(),
        signature: decoy_sig,
    };
    let tampered_entry = raw_entry(&h.cast, 1, 901, zero, &tampered, h.now());
    let r = h.submit(&[tampered_entry]).await;
    h.reconcile(
        "adversary: tampered inner record",
        &r,
        &[Expect::Refuse(RefusalReason::BadSignature)],
    );

    // (3) Replay: a pre-outage bundle re-presented (records in a fresh order, so
    //     the station reprocesses rather than replaying its cached receipt). Every
    //     record is already admitted → all `known`, nothing new is logged.
    let reordered: Vec<SignedOutboxEntry> = replay_fodder.iter().rev().cloned().collect();
    let r = h.submit(&reordered).await;
    h.reconcile(
        "adversary: replayed bundle",
        &r,
        &vec![Expect::Known; reordered.len()],
    );
}

/// A bundle whose first carriage is lost; the author re-exports the identical
/// bundle at reconnect, and it admits (member 4 -> 5, 480).
async fn outage_lost_then_reexport(h: &mut Harness) {
    let expires = START + 100 * OUTAGE_SECS;
    let prop = h.proposal(4, 5, 480, expires);
    let conf = h.confirmation(5, &prop);
    let e1 = h.outboxes.wrap(&h.cast, 4, &prop, h.now());
    let e2 = h.outboxes.wrap(&h.cast, 5, &conf, h.now());
    // (The first carriage is "lost": we simply never submit it.)
    // At reconnect the author re-exports the SAME entries and submits them.
    let r = h.submit(&[e1, e2]).await;
    h.reconcile("lost-then-reexport", &r, &[Expect::Admit, Expect::Admit]);
    h.bump_nonce(4);
    h.expect_balance(4, 5, 480);
}

// ===========================================================================
// Assertions
// ===========================================================================

async fn assert_conservation(h: &Harness, label: &str) {
    let mut sum = 0i64;
    for i in 0..MEMBER_COUNT {
        sum += h.balance(i).await;
    }
    assert_eq!(
        sum, 0,
        "conservation ({label}): settled balances must sum to zero"
    );
}

/// Assertion 1: the hash chain verifies (no forks), and every entry's signature
/// verifies.
fn assert_no_forks(db_path: &Path) {
    let db = Database::open(db_path).unwrap();
    let log = AppendLog::new(&db);
    let count = log.verify_chain().expect("the hash chain must verify");
    assert!(count > 0, "the log must be non-empty");
    for entry in log.iter_from(1) {
        let entry = entry.unwrap();
        assert!(
            entry.payload.verify().is_ok(),
            "every log entry signature must verify (seq {})",
            entry.seq
        );
    }
}

/// Assertion 4: replaying the final log, at EVERY prefix, every member's projected
/// position (settled balance minus committed debits) is ≥ the floor — exactly the
/// invariant the engine enforced at each admission (ADR-0018). O(n²), fine here.
fn assert_floor_invariant_every_prefix(db_path: &Path) {
    let src = Database::open(db_path).unwrap();
    let entries: Vec<_> = AppendLog::new(&src)
        .iter_from(1)
        .map(|e| e.unwrap())
        .collect();

    let cfg = CreditConfig::default();
    let prefix = Database::open_in_memory().unwrap();
    migrations::run(&prefix).unwrap();

    for entry in &entries {
        AppendLog::new(&prefix)
            .append_raw(entry.payload.clone(), entry.created_at)
            .unwrap();
        let log = AppendLog::new(&prefix);
        let snapshot = LedgerSnapshot::derive(&log).unwrap();
        let now = entry.created_at;

        // Check EVERY participant (any sender or receiver seen so far), not just
        // senders — a cert reservation, a payment-request receiver, and a plain
        // debtor can each move an account toward the floor.
        for addr in participants(&snapshot) {
            // The settled balance is DERIVED FROM THE LOG (the source of truth),
            // never from the balances cache — the prefix DB holds only log entries,
            // and the cache would read as zero. This is the same fold the daemon's
            // `ledger_view::balance_of` performs.
            let settled = rrn_station::ledger_view::balance_of(&prefix, &addr).unwrap();
            let committed = committed_debits_centi(&snapshot, &addr, now, &cfg);
            let projected = settled - committed;
            assert!(
                projected >= FLOOR,
                "floor invariant violated at log prefix seq {}: {} settled {settled} - committed {committed} = {projected} < floor {FLOOR}",
                entry.seq,
                addr
            );
        }
    }
}

/// Every address that appears as a sender or receiver in the snapshot — the full
/// set of accounts whose projected position the floor checker must watch.
fn participants(snapshot: &LedgerSnapshot) -> HashSet<Address> {
    let mut out = HashSet::new();
    for (_, state) in snapshot.iter() {
        let p = &state.proposal().payload;
        out.insert(p.sender);
        out.insert(p.receiver);
    }
    out
}

/// Assertion 5: every cert consumed no more than its cap, and the at-cap spend was
/// admitted (escrow honored — a cert-backed spend rides its reserved headroom).
fn assert_escrow_honored(db_path: &Path) {
    let db = Database::open(db_path).unwrap();
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    // The operator address (derivable from the wallet on disk).
    let wallet =
        WalletContents::load_from_file(&db_path.with_file_name(WALLET_FILE), PASSPHRASE).unwrap();
    let operator = wallet.address;

    let mut saw_at_cap_consumption = false;
    for cert in snapshot.outstanding_certs_of(&operator) {
        let cap = cert.certificate.payload.cap_centi;
        assert!(
            cert.consumed_centi <= cap,
            "escrow: cert consumed {} exceeds cap {cap}",
            cert.consumed_centi
        );
        if cert.consumed_centi == cap {
            saw_at_cap_consumption = true;
        }
    }
    assert!(
        saw_at_cap_consumption,
        "escrow: the at-cap cert-backed spend must have consumed its cert to the cap"
    );
}

/// Assertion 6: EXACTLY the planted double-spend and fork produced equivocation
/// records — one cert-overspend attributed to the operator, one outbox-fork
/// attributed to the forker — and nothing else.
fn assert_exactly_the_planted_equivocations(db_path: &Path, operator: Address, forker: Address) {
    let db = Database::open(db_path).unwrap();
    let snapshot = LedgerSnapshot::derive(&AppendLog::new(&db)).unwrap();
    let mut cert_overspend = 0;
    let mut outbox_fork = 0;
    for rec in snapshot.equivocations() {
        match rec.payload.basis {
            EquivocationBasis::CertOverspend => {
                cert_overspend += 1;
                assert_eq!(
                    rec.payload.member, operator,
                    "the cert-overspend equivocation must be attributed to the operator"
                );
            }
            EquivocationBasis::OutboxFork => {
                outbox_fork += 1;
                assert_eq!(
                    rec.payload.member, forker,
                    "the outbox-fork equivocation must be attributed to the forker"
                );
            }
        }
    }
    assert_eq!(
        cert_overspend, 1,
        "exactly one cert-overspend equivocation (the planted double-spend)"
    );
    assert_eq!(
        outbox_fork, 1,
        "exactly one outbox-fork equivocation (the planted fork)"
    );
}

/// Assertion 7: no transaction settled before its confirmation admission plus the
/// settlement window (ADR-0022 metadata vs. the settlement record's `settled_at`).
fn assert_windows_respected(db_path: &Path) {
    let db = Database::open(db_path).unwrap();
    let log = AppendLog::new(&db);
    let snapshot = LedgerSnapshot::derive(&log).unwrap();

    let mut settlements = 0;
    for entry in log.iter_from(1) {
        let bytes = &entry.unwrap().payload.bytes;
        let Ok(rec) = from_canonical_bytes::<SettlementRecord>(bytes) else {
            continue;
        };
        settlements += 1;
        let admission = snapshot
            .admission(&rec.proposal_id)
            .expect("a settled transaction has admission metadata");
        let confirmed_at = admission
            .confirmation_admitted_at
            .expect("a settled transaction was confirmed");
        assert!(
            rec.settled_at >= confirmed_at + WINDOW as i64,
            "window violated: tx settled at {} < confirmation admission {confirmed_at} + window {WINDOW}",
            rec.settled_at
        );
    }
    assert!(settlements > 0, "the run must have settled transactions");
}

/// Assertion 2 (log-derived, all holders): folding every settlement record in the
/// log, the total across *all* addresses it touches — not just the cast — is zero.
/// A complement to the per-point RPC conservation checks: it depends on nothing but
/// the log, and it would catch value settled to an address the cast never named.
fn assert_conservation_from_log(db_path: &Path) {
    let db = Database::open(db_path).unwrap();
    let mut settled: BTreeMap<[u8; 32], i64> = BTreeMap::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for entry in AppendLog::new(&db).iter_from(1) {
        let bytes = &entry.unwrap().payload.bytes;
        let Ok(rec) = from_canonical_bytes::<SettlementRecord>(bytes) else {
            continue;
        };
        // Each transaction settles once (mirrors `ledger_view::balance_of`).
        if !seen.insert(rec.proposal_id.0.to_bytes()) {
            continue;
        }
        *settled
            .entry(rec.sender.public_key().to_bytes())
            .or_insert(0) -= rec.amount_centi;
        *settled
            .entry(rec.receiver.public_key().to_bytes())
            .or_insert(0) += rec.amount_centi;
    }
    let total: i64 = settled.values().sum();
    assert_eq!(
        total, 0,
        "conservation: the sum of every settled balance in the log must be zero"
    );
}

/// Assertion 8 (log-length audit): every member record on the log — every proposal
/// and confirmation, the kinds that arrive by DTN — was reported `admitted` on some
/// receipt. A station that logged a refused, tampered, forged, or replayed record
/// while returning a refusal would leave a log entry with no matching admission,
/// which this catches. (Station-authored records — settlements, certificates,
/// equivocations, vouches — are not member DTN records and are skipped.)
fn assert_no_phantom_admissions(db_path: &Path, admitted: &HashSet<[u8; 32]>) {
    let db = Database::open(db_path).unwrap();
    let mut audited = 0;
    for entry in AppendLog::new(&db).iter_from(1) {
        let entry = entry.unwrap();
        let bytes = &entry.payload.bytes;
        let is_member_record = from_canonical_bytes::<TransactionProposal>(bytes).is_ok()
            || from_canonical_bytes::<TransactionConfirmation>(bytes).is_ok();
        if !is_member_record {
            continue;
        }
        audited += 1;
        assert!(
            admitted.contains(&entry.content_hash.to_bytes()),
            "phantom admission: log seq {} is a member record never receipted `admitted`",
            entry.seq
        );
    }
    assert!(
        audited > 0,
        "the audit must have seen member records to be meaningful"
    );
}

/// The final chain digest: blake3 over every entry's content hash in sequence
/// order — a fingerprint of the whole log's content and ordering (assertion 9).
fn chain_digest(db_path: &Path) -> Hash {
    let db = Database::open(db_path).unwrap();
    let mut h = Hasher::new();
    for entry in AppendLog::new(&db).iter_from(1) {
        h.update(&entry.unwrap().content_hash.to_bytes());
    }
    h.finalize()
}
