# Phase 2 red-team checklist

**Scope:** the single-community resilience surface Phase 2 added — delay-tolerant
submission (ADR-0020), headroom certificates and equivocation (ADR-0021,
ADR-0025), the admission clock (ADR-0022), emergency governance (ADR-0023,
ADR-0027), the Reticulum/LoRa and SMS carriers (ADR-0013, ADR-0026), the paper
fallback, and at-rest encryption (ADR-0024).
**Audience:** the independent audit team, and a community running its own
self-test before or during the 72-hour outage drill.
**Date:** 2026-09-13, against `main` at the Phase 2 consolidation.

## How to read this

Every row names an attack, the defense as **built** (a file, function, or test
you can open), the behavior you should observe, and how you would actually try
it. Where the honest answer is "not defended", the row says **accepted
residual** and points at the ADR that accepted it. The checklist's value is that
honesty: a red-teamer who finds a row's defense missing has found a bug; one who
finds an undocumented residual has found a documentation bug — report either.

Paths are relative to the repository root. `core.rs` means
`crates/rrn-station/src/core.rs`. Tests can be run with `cargo test -p <crate>
<name>`. The automated 72-hour scenario that exercises most of the courier and
member rows at once is `crates/rrn-station/tests/it/outage_72h.rs` (see
[`phase-2-exit-evidence.md`](../phase-2-exit-evidence.md)).

The single principle behind almost every defense: **a carrier is a dumb pipe**.
Integrity and authenticity live in the per-record `SignedPayload` signatures the
station re-verifies at its one front door (ADR-0008, ADR-0013, ADR-0020). If an
attack does not obtain a member's key, it can at most delay, drop, or observe.

---

## 1. Attacker: the courier

A courier is anyone who carries a bundle — a member's phone, an outside
volunteer, a radio hop, an SMS gateway, a printed sheet.

| Attack | Defense as built | Expected behavior | How to attempt it |
|---|---|---|---|
| **Drop** a bundle or one entry from it | Per-device outbox chains: entries carry `position` and `prev_hash`; a hole is detectable by the station (`rrn_protocol::outbox::validate_chain`) and the contiguous head does not advance past it (`core.rs` `ingest_bundle`, `DtnStore::note_entry`). Delivery is best-effort by design. | The dropped record is simply not admitted; the author's device sees no receipt and re-sends. Nothing else in the bundle is affected. | Delete one entry from a bundle file before `rrn paper ingest` or `bundle_submit`; observe the receipt lists only the carried records and a later carriage fills the gap (harness leg `outage_gap_leg`). |
| **Duplicate** carriage (two couriers, or re-ingesting the same sheet) | Idempotent ingest: a byte-identical presentation returns the stored receipt verbatim (`issued_receipts`, keyed by the Blake3 of the ordered record-hash list); an already-admitted record answers `known` via `AppendLog::admission_of`. | No second admission, ever. The second courier gets the same receipt. | Submit the same bundle twice, then a differently-framed bundle carrying the same records (harness leg `outage_duplicated_carriage`). |
| **Tamper** with a carried record | `outbox::validate` checks the outer entry signature, `author == signer`, and the embedded record signature (`AuthorSignerMismatch`, `BadEmbeddedSignature`); the engine re-verifies at its front door. Framing adds CRC-32 per frame and a Blake3 payload id (`rrn_protocol::framing`, `PayloadHashMismatch`). | Refused `bad-signature`; the bundle continues; nothing lands on the log. | Flip a byte in `record_bytes` or in an amount; re-submit (test `outbox::tests::tampered_record_bytes_fails_validation`; harness leg `outage_adversarial`). |
| **Reorder** entries in a bundle | `Bundle::decode` refuses same-author entries out of position order (`EntriesOutOfOrder`); cross-author order is arrival order and carries no window weight (ADR-0022). | Bundle refused at decode, or admitted with no effect on any window. | Swap two same-author entries in a bundle (test `bundle::tests::same_author_disorder_is_refused`). |
| **Forge** a bundle or an entry | A bundle is unsigned and grants nothing; an entry needs the author's key. | Refused `bad-signature`. | Sign an entry with an outsider key (harness leg `outage_unknown_key_inert`). |
| **Withhold** a delivery receipt | Receipts are queued per record (`receipt_deliveries`); only the author's authenticated fetch or the operator's `receipts_ack` marks one delivered; a courier fetch only bumps a counter; unconfirmed rows are retained 4× longer (`RETENTION_UNCONFIRMED_MULTIPLIER`). Re-submitting the record returns `known`. | A delay, never a loss. A later carrier re-fetches it. | Fetch receipts with `rrn paper export-receipts` and discard them; re-run the export and observe the same receipts reappear. |
| **Forge** a receipt to a member ("your spend landed") | Receipts are station-signed; the mobile FFI `receipt_parse` takes the expected station key and refuses anything else. On the outbound-push path the station correlates a receipt only if it verifies, is signed by the station it names, matches the exact presented record set, arrives from the peer pushed to, and (when addressed by `rrn1…`) is signed by the station the binding directory resolves (`core.rs` `do_dtn_receipt`). | A forged receipt is ignored; the push stays `pending` and is later `abandoned`, visibly, in `rrn dtn status`. | Craft a receipt under another key; feed it to `receipt_parse` or return it over a mock transport. |
| **Read** what is carried | **Accepted residual.** Bundles and receipts are cleartext to the courier (`docs/spec/dtn-bundles.md` §6); their content is already community-public. Sealing bundles/receipts to the station/author is tracked backlog. | The courier learns who transacted with whom, at the hash level, and memos. | Open a bundle file. |
| **Flood** the station with well-formed bundles | Size caps before the CBOR is walked (`MAX_BUNDLE_BYTES` 4 MiB, `MAX_BUNDLE_ENTRIES` 512); the mobile route is pairing-gated; the operator socket is local. **No per-member rate limit** — accepted residual at pilot scale (threat model, "Known limitations"). | Each bundle is bounded work; a paired member can still loop. | Submit many small bundles from one paired phone; watch core latency. |

## 2. Attacker: the equivocating member

A member who signs conflicting commitments while partitioned, hoping one lands.

| Attack | Defense as built | Expected behavior | How to attempt it |
|---|---|---|---|
| **Certificate double-spend** — spend one certificate's cap with two receivers | Cert-backed spends are admitted in arrival order until the cap is exhausted; the excess is refused `CertOverspent` (with cap/consumed/attempted carried structurally, `rrn-ledger::engine::check_cert_backed`); the station appends a station-signed `EquivocationRecord` embedding the member-signed proofs (`core.rs` `record_cert_overspend_equivocation`), which zeroes trade-reliability and attestation-accuracy (`rrn-reputation::scoring`, `EQUIVOCATION_WEIGHT`), disqualifies the member from new certificates (`EquivocationBlocked`), and opens a jury case (`rrn-dispute::equivocation`). | Second spend refused; one record per `(member, certificate)`; the stranded receiver can see the proof (`equivocation_for_cert`); the member is de-established. Exposure ≤ `cert_max_cap_centi` (default 10 Commons). | Request a 10-Common certificate, sign two 8-Common spends against it to two receivers, courier both (harness leg `outage_cert_flow`; test `cert_backed_spends::overspend_is_refused_with_the_three_amounts`). |
| **Outbox fork** — two different records at one outbox position | `outbox::is_fork`; ingest refuses the later side `outbox-fork`, persists both envelopes to `outbox_forks`, and records a fork `EquivocationRecord` (`core.rs` `record_fork_equivocation`). A byte-identical re-send is a duplicate, never a fork. | One admission, one refusal, one record per `(author, position)`. | Sign two proposals at the same outbox position; deliver both (harness leg `outage_fork_leg`; test `outbox::tests::fork_detection_positive_and_negative`). |
| **Nonce games** — replay or skip a proposal nonce | Per-sender gap-free monotonic nonce (`Error::BadNonce`), content-addressed ids (`Error::DuplicateProposal`); certificate requests share the nonce sequence. | Refused `nonce-gap` / `duplicate`. | Re-carry an old bundle after reconnect (harness leg `outage_adversarial`, replayed batch). |
| **Hidden history** — conceal earlier cert spends from a new receiver | **Accepted residual (ADR-0021 Consequences).** The receiver's offline check (`rrn-mobile-ffi` `offline_spend_verify`) is only as good as presented history; the cap bounds the loss; the overspend is later refused and provable. A receiver may demand the spender's outbox segment since issuance, where a suppressed entry shows as a gap. | The receiver's phone says `Ok`; the station later refuses the overspend. | Present a spend voucher with an empty `history` to a second receiver. |
| **Fragment** an overspend so it cannot be proven in one evidence bundle | `MAX_MEMO_BYTES` (2048) caps a proposal's memo; `CertBackedSpendLimit` refuses the 16th admitted cert-backed spend per certificate, reserving one evidence slot (`MAX_EVIDENCE_ITEMS` 16). | Every overspend stays provable in ≤ 16 items. | Sign 16+ tiny spends against one certificate. |
| **Grind the jury draw** for a friendly panel | The equivocation sortition seed is `Blake3(case identity ‖ admission seq of the opening record ‖ community anchor)` — content-independent (`rrn-dispute::equivocation`). Recusal = subject ∪ their vouchers ∪ injured payees, computed at the admission position. | Re-mining the evidence moves nothing. **Residual:** the admission seq is a public counter; padding the log to shift it is a weak, costly lever (ADR-0025). | Vary the second commitment's bytes and check the draw is unchanged. |
| **Re-seat spam** to retry the draw | A re-seat is admitted only against a genuinely lapsed round and re-anchors the seed to its own admission seq; `Confirmed`/`Overturned` are final. | One uncontrollable seed per 14-day window. | Submit `equivocation_reseat` records against a live round (test `equivocation::a_ballot_in_the_wrong_round_or_by_a_non_juror_is_refused`). |
| **Self-sign an Overturn** to lift the penalty | The verdict kind is refused on DTN (`UnroutableKind`) and has no RPC; reputation and the snapshot honor an Overturn only when its signer is the **community station key** (T2.11.3 pins `signer == station` in `overturned_equivocations` and the snapshot's `equivocation_verdict`). **Closed:** a community-key pin, not a record-author gate, so it holds even once foreign records are admitted — a self-signed Overturn is skipped at derivation. | Inert: wrong signer is dropped. | Courier a member-signed `rrn.credit.equivocation_verdict`. |
| **Overspend again after an Overturn** | **Accepted residual.** Dedup is first-wins per `(member, certificate)`; a later genuine overspend on the same certificate is refused (no ledger loss) but records no fresh proof or penalty (threat model, known limitation). | Refused, unrecorded. | Overturn, then overspend the same certificate. |

## 3. Attacker: the hostile counterparty

| Attack | Defense as built | Expected behavior | How to attempt it |
|---|---|---|---|
| **Refuse to confirm** a proposal to strand the sender's headroom | An unconfirmed proposal stops counting against the committed position once past its expiry plus skew (`rrn-ledger::credit`, ADR-0018); the engine refuses its confirmation past that boundary by the station clock. | Headroom returns at expiry. | Propose, never confirm; watch `rrn balance` headroom after expiry. |
| **Strand a certificate** by never accepting cert-backed spends | The reservation releases at `spend_admissible_until` (expiry + delivery grace + skew), the one shared boundary; the member can return it early (`CertificateReturn`). | Idle escrow is the cost of going offline; it self-releases. | Request a certificate and let it expire. |
| **Dispute-window games under DTN delay** — backdate a confirmation to shrink the sender's dispute window | Windows run from the confirmation's **admission** time (`AdmissionTimes`, `find_eligible`, `raise_dispute`); `confirmed_at` is testimony, refused only if future-dated (`FutureDated`) or inconsistent (`InconsistentTimestamp`). Dispute sortition and resolution windows anchor the same way (`rrn-dispute::sortition::disputed_info`), and the jury pool, escalation electorate, and equivocation re-seat eligibility are **position-bounded** at the anchoring admission seq (`grace_electorate_asof`/`tier2_stake_centi_asof`), so a back-dated vouch or settlement admitted after a round opened cannot pack a pool or shift a weight (ADR-0022 §5). | A confirmation carried for days serves its full window from arrival. Backdating moves nothing, and back-dated standing admitted after a dispute opens is bounded out of its pool. | Sign a confirmation with `confirmed_at` = `proposed_at`; deliver it a week later (harness check `assert_windows_respected`; tests `jury.rs::party_opened_at_is_ignored_for_the_draw_and_window`, `jury.rs::a_back_dated_vouch_cannot_pack_the_jury_pool`). |
| **Accept goods against an uncertificated offline proposal** and dispute later | **Accepted by design (ADR-0021 §7).** An uncertificated spend takes its chances at the front door; the receiver knew it carried no escrow. | Refused-at-arrival is a nuisance, not a crisis. | Deliver against a plain proposal from a member at their floor. |
| **Collude bilaterally** on a fake Tier-1/2 trade | **Accepted residual (ADR-0011).** Bilateral confirmation cannot detect a two-party conspiracy; Tier 3+ witnesses are Phase 3. | Settles. | Two colluding phones. |
| **Confirm a Tier-2 payment with no standing** over DTN | `Core::tier2_confirmation_gate` is one shared pre-engine check on all three admission paths (operator, mobile channel, DTN). | Refused `tier2-stake` after bootstrap grace ends. | Courier a Tier-2 confirmation from a below-band member (test `dtn_tier2_confirmation_is_held_to_the_staking_bar`). |

## 4. Attacker: the station operator

The operator is a trust root (ADR-0005, ADR-0022 §6). These rows are about what
a *dishonest* operator can and cannot do, so a community can decide what to
watch.

| Attack | Defense as built | Expected behavior | How to attempt it |
|---|---|---|---|
| **Weaken config floors** — raise `debt_floor_centi`, `cert_max_cap_centi`, `cert_max_outstanding` | **Accepted residual (ADR-0018, ADR-0021).** These are per-station config until a governance surface exists; the station enforces the Tier-2 ceiling on certificate caps. | The community's offline exposure rises silently. The config file is the audit artifact. | Edit `config.toml`. Mitigation is social: publish the config; review it at the outage drill. |
| **Clock manipulation** — step the station clock | Admission times are clamped monotone non-decreasing per log order (`AppendLog::append`, `now.max(tail.created_at)`), so a backward step cannot reorder windows; a forward step stretches everyone's windows uniformly and is **not self-correcting** (threat model, `rrn-storage` admission clock). Windows and eligibility never read party clocks (ADR-0022). | Uniform, visible distortion; no per-member advantage. | Step the clock forward a day and observe every pending settlement land early; step it back and observe nothing moves. |
| **Refuse issuance or ingest** | **Accepted residual (ADR-0020 Consequences: the station is the liveness SPOF).** Members' outboxes preserve everything signed; a replacement station is re-bootstrapped from the ADR-0016 backup or a member-held VMK quorum (ADR-0024) and outboxes are replayed. | Availability loss, never integrity loss. | Stop the daemon; verify members' phones keep signed records and re-deliver to a restored station. |
| **Forge a settlement / certificate / contract charge** | Station-signed by design (ADR-0005) and **now signer-pinned to the community station key at every replay reader** (T2.11.3: `LedgerSnapshot::derive`, `balance_of`, events, history, portability, the reputation scorer). A forged `SettlementRecord`/`ContractCharge` injected via `append_raw` is skipped — moves no balance; a forged certificate reserves nothing (a spend naming it is refused `UnknownCertificate`). Invariants in `crates/rrn-ledger/tests/it/ledger_signer_pinning.rs`. **Residual:** a gossip read-replica pinning under a *different* key sees no station-signed state at all (loud, tested); pilot runs a single writer. | Inert: a forged station-kind record is invisible to derivation. | Configure a hostile gossip peer serving a forged `SettlementRecord`. |
| **Fabricate an equivocation** against an honest member | `EquivocationRecord::verify_evidence` re-checks every embedded member signature on replay; a record that fails is ignored by scoring and by the snapshot and cannot poison the dedup slot. | No reputation effect. | Append a record whose evidence sums within the cap (test `escrow::tests::verify_evidence_rejects_amounts_within_cap`). |
| **Forge a governance attestation** — window, enactment, emergency activation/refusal/anchor | Replay pins the envelope signer of all five station-signed governance kinds to the community station key and skips any other (`window::window_and_seq_of`, `statute::enacted_statutes`, `emergency::derive_emergencies`); `crates/rrn-governance/tests/it/station_signer_pinning.rs`. | Forged records are invisible; derivation completes. | Inject via gossip (tests `a_forged_activation_does_not_enter_the_timeline`, `a_forged_refusal_does_not_kill_a_declaration`). |
| **Declare an emergency alone** | Activation needs distinct electorate co-signatures reaching `ceil(2N/3)` (`rrn-governance::emergency::declaration_threshold`), re-derived on replay; the operator is one elector. | One signature compresses nothing (except in a ≤ 2-member grace electorate — ADR-0023 residual). | `rrn governance emergency-declare` with no co-signers. |
| **Perpetual emergency** | Renewal count ≤ 2, chain ≤ 14 d, fixed 14 d cooldown, all log-proximity-derived; declaration TTL 7 d; first-crossing-only activation with a station-signed refusal marker (ADR-0027). | ≤ 50 % duty cycle, never a standing state. | Chain declarations (tests `a_chain_cannot_exceed_the_duration_cap`, `the_cooldown_refuses_a_fresh_declaration_too_soon_after_a_chain`). |
| **Read everything at rest / hand the disk over** | Plaintext profile: **accepted** (the operator already holds the data). Encrypted profile (ADR-0024): the operator alone cannot open a powered-off node — the VMK is Shamir-split among member holders, no keyslot exists, no holder list is on the boot dir. | See §5. | — |

## 5. Attacker: physical

| Attack | Defense as built | Expected behavior | How to attempt it |
|---|---|---|---|
| **Seize the node powered off** — plaintext profile | **Accepted residual (default profile).** The wallet is passphrase-encrypted; the ledger, memos, and vouch graph are plaintext. | Full disclosure of community data; the signing key stays sealed. | Image the SD card. |
| **Seize the node powered off** — encrypted profile | LUKS2 container with **zero keyslots** (`storage::volume::DmCryptVolume::open` refuses any keyslot; provisioning kills the throwaway one); VMK reconstructed only from a `K`-of-`N` member quorum (`storage::vmk`); wallet, ledger, adapter identity, and index all inside; boot dir discloses only the VMK address and `K`/`N`. | An encrypted brick. `< K` holders learn nothing. | `scripts/drill-seizure-recovery.sh --profile encrypted` (marker sweep + positive control + `luksDump` zero keyslots); test `at_rest_dmcrypt::brick_property_no_plaintext_at_rest_with_positive_control`. |
| **Seize the node running** | **Accepted residual (ADR-0024 "Not covered").** The volume is mapped and the key is in kernel memory; cold-boot and live imaging recover it. Mitigations are physical custody, a tamper-evident enclosure, and rapid re-bootstrap. Swap/core dumps must be disabled by the operator (runbook §4.4). | Disclosure. | Pull the plug last. |
| **Phish the unlock ceremony** with an imaged boot dir | The ceremony request is unsigned by necessity; the **console fingerprint** (`ceremony_fingerprint`, `docs/spec/vmk-boot-ceremony.md`) is the authenticator holders confirm out-of-band. Console-only; no pre-unlock network listener. | A forged ceremony shows a different fingerprint. **Residual:** a holder who skips the check. | Mint a request from a copied descriptor; ask a holder to respond without reading the fingerprint. |
| **Coerce the operator** for a passphrase | There is no operator-passphrase unlock on the encrypted profile, by decision (ADR-0024). | Nothing to extract. | — |
| **Coerce `K` holders** | **Accepted:** the threshold is the trust model (ADR-0004). Holder identities are not on the boot dir. | — | — |
| **Jam the radio** | **Accepted residual.** Jamming is a connectivity event; economic frames are never dropped by the budgeter (backpressure surfaced); the next rung is paper. | Pushes stay `pending`, then `abandoned` visibly. | Key a transmitter on the channel during the field test. |
| **Direction-find a transmitting station** | **Not mitigated** (threat model, "physical radio interface"). A community under RF-hunting threat should not transmit. | — | — |
| **Intercept SMS** at the carrier | **Accepted residual.** Content is community-public signed records; **metadata** (which numbers talk to the station, when) is exposed with no transport-layer fix (`docs/spec/sms-carrier.md` §6). | — | — |
| **Steal a printed sheet** | Sheets are public information; re-scanning is idempotent; a lost receipt sheet is re-exported. | Delay, not loss. | Take one. |
| **Steal a member's phone** | Mobile repo: OS keystore + passphrase + lock screen; `station unpair`; social recovery. Actions taken with a live key before revocation stand (bearer-key limit). | — | — |

## 6. Attacker: the outsider

Someone with no member key: on the LAN, on the air, on the phone network, or
owning the sidecar process.

| Attack | Defense as built | Expected behavior | How to attempt it |
|---|---|---|---|
| **Bundle spam** over LoRa/Reticulum | Framing bounds: `Reassembler` caps in-flight partials (64), payload size (4 MiB), chunk count (4096), TTL (7 d); a partial that never completes is pruned; forged headers can at most waste bounded memory. The airtime budgeter drains economic before governance before bulk. **Residual:** oldest-first eviction lets 64 cheap forged ids evict honest partials — the retransmit driver re-requests (threat model, "Carrier framing"). | Bounded memory; honest traffic delayed, never corrupted. | Stream chunks for many random payload ids (proptest `framing_proptests::drops_never_complete_and_missing_is_exact`). |
| **SMS flood** | Per-sender cap `max_inbound_per_hour` (60) with a single rate-limited log line; `"paired"` mode drops unbound senders before reassembly; tracked-sender bound (`MAX_TRACKED_SENDERS` 512) with idle eviction. **Residual:** outbound-cost amplification in `"open"` mode (a spoofed number earns a receipt text). | Excess dropped; relay memory bounded. | Text junk from many numbers (test `sms::tests::inbound_rate_cap_drops_the_excess_from_one_sender`). |
| **Spoof a sender number** | The registry is spam control; the security boundary is the per-record signature at ingest. A binding is self-signed by the bound identity (`validate_sms_binding`). | At most re-carries public records or junk. | Send a bundle from a number bound to someone else. |
| **Forge `RRNC` control frames** (fake ack / request-missing) | Control frames carry only carriage metadata; a forged ack can make the sender drop its cache — delivery denied until app-level tracking re-bundles (`dtn_sync.rs`). | Connectivity event, not forgery. | Inject frames on a mock transport. |
| **Redirect a member's traffic** with a forged `rrn.net.binding` | Self-signed by the bound identity (`binding::validate`); misrouting only denies delivery — the bundle is still signed/sealed. | Refused as `Rejected` at the DTN front door. | Courier a binding signed by another key. |
| **Compromise `rnsd` / the LXMF adapter** | Carrier-only powers (ADR-0013, ADR-0026): no RRN key, no plaintext of anything that matters, no RPC into the station; bundles are signed per entry. **Residual:** same OS user → shared filesystem; run under a separate service account (threat model, "Reticulum transport sidecar"). Under the encrypted profile the adapter identity lives inside the container. | Drop/delay/observe only. A crash-loop backs off (5 s → 300 s) and never takes the station down. | Replace the adapter script; observe `rrn status` degrade. |
| **Impersonate the station on the LAN** | Sealed, signed envelope with the recipient key bound inside the mobile's signature; pairing SAS code compared in person (ADR-0008). | Refused; pairing codes differ. | ARP-spoof the station IP during pairing. |
| **Gossip a forged or ungated record** to the community's writer | **CLOSED (T2.11.4, ADR-0020 §7):** the writer never pulls — it runs no gossip client and refuses to start with a peer list — so no gossiped record reaches the writer's chain (`do_append_entries` also refuses on a writer). Only a **replica** pulls, and it admits nothing (writes refused, sweep timers off). `append_raw` still re-verifies signature/content hash and re-chains locally. **Residual:** a replica's own derived views are empty (it pins to its own key, not the writer's — loud, tested); a replica's copy is non-authoritative. | Refused at the writer; lands only in a non-authoritative replica copy. | Configure yourself as the writer's peer (rejected: a writer takes no peers). |
| **Deeply nested CBOR** at any decode boundary | `rrn_crypto::serialize::checked_from_data` depth pre-scan (`MAX_CBOR_DEPTH` 128) wired into every untrusted-bytes decode. | `TooDeeplyNested`, never a stack overflow. | 50 000 nested arrays in a bundle (test `bundle::tests::deeply_nested_bytes_are_refused_not_a_stack_overflow`). |
| **Crafted paper sheet** | Bounded reassembly (`MAX_CHUNKS` 64, `CHUNK_PAYLOAD_BYTES` 720, `SINGLE_QR_MAX_BYTES` 740), `Mixed`/`ChunkConflict`/`HashMismatch` tripwires, `BadAlphabet`. | Per-payload error, never a process abort. | Hand-edit a `rrnp:` line. |

## 7. Residuals index

The rows above marked **accepted residual**, in one place, each with its record:

1. Cleartext bundles and receipts to couriers — `docs/spec/dtn-bundles.md` §6; sealing is backlog.
2. No per-member rate limit on bundle submission, receipt fetch, marketplace, governance, or vouches — threat model "Known limitations".
3. Hidden certificate history — ADR-0021 Consequences.
4. ~~Overturn gate is a record-author gate, not a community-key pin~~ — CLOSED (T2.11.3): pinned to the community station key.
5. No re-recording after an Overturn — threat model `rrn-ledger`, known limitation.
6. Ledger station-signed records unpinned on replay — threat model `rrn-governance`, residual list.
7. ~~Gossip ingest bypasses the front door~~ — CLOSED (T2.11.4, ADR-0020 §7 Clarification): a writer never pulls, a replica never admits. Surviving residual is a replica's empty derived views (see item 6 / `rrn-governance` residual list).
8. Config floors are operator-set — ADR-0018, ADR-0021.
9. A forward clock step is not self-correcting — threat model `rrn-storage`, admission clock.
10. Station liveness is a single point of failure — ADR-0020 Consequences.
11. Running-node seizure — ADR-0024 "Not covered".
12. Ceremony relies on holders checking the fingerprint — ADR-0024, `docs/spec/vmk-boot-ceremony.md`.
13. Jamming and direction-finding — threat model "physical radio interface"; spectrum compliance is the operator's.
14. SMS metadata to the carrier — `docs/spec/sms-carrier.md` §6.
15. Framing oldest-first eviction under a forged-id flood — threat model "Carrier framing".
16. Emergency: a ≤ 2-member grace electorate declares at two signatures; measure-cycling at ≤ 50 % duty cycle; scope is testimony — ADR-0023 Consequences.
17. Declaration TTL does not bound an off-log colluding bundle — ADR-0027 D2 residuals.
18. Bilateral collusion at Tiers 1–2 — ADR-0011.
19. Bulk-traffic starvation on a constrained link is by design — threat model "DTN transport over a constrained carrier".

## 8. What this checklist does not cover

The Phase 0/1 surface (crypto primitives, wallet, Shamir, marketplace,
reputation, ordinary governance) is covered by `docs/threat-model.md` and the
August 2026 review (`audit-2026-08.md`). The mobile client's device surface is
the sibling repository's. Real radios, real SMS gateways (the modem backend is
not built), and real people are the field exercise's, not this document's — see
the outage drill in `docs/community-setup.md`.
