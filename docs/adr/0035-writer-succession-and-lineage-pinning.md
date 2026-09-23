# 0035 — Writer succession and lineage-aware signer pinning

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review; it returned accept-with-changes for the set of eight and the changes
are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted against the maintainer's scope
> decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification at the
> maintainer's delegation. The review's
> findings folded into this ADR: activation eligibility and `N` are evaluated at the successor's own attested anchor instant, never at a re-stamped `created_at`; a profile that changes `successor` is held until the partner's operator confirms it out of band (seized-key redirect residual); dead-branch certificates and orphaned partner-side records are stated as residuals.
> Implementation tickets are written against this ratified text.

## Context

[ADR-0020](0020-single-writer-log-dtn-submission.md) made the community log a
single linear chain with a single writer, and named the price plainly: "the
station is a single point of *liveness* failure," bounded for one-community
scale by [ADR-0016](0016-station-backup-and-key-recovery.md) re-bootstrap plus
member outbox replay, with "succession/failover" deferred to Phase 3 as "an
additive feature, not a redesign." Its 2026-09-14 Clarification then split every
station into a **writer** (owns the chain, never pulls) or a **replica** (pulls a
copy, admits nothing), and recorded a residual it could not close: a replica's
derived views are empty, because every station-signed reader pins records to
*this* station's runtime key and a replica's key is not the writer's. It left
"a replica-supplied expected-writer key at the pinning boundary" as a follow-up.

Phase 3 changes the stakes in three ways:

1. **Loss of the writer now strands more than one community.** Under
   [ADR-0031](0031-cross-community-credit-treaty-accounts.md) a partner's
   provisional commits, prepares, and settlements wait on the home writer; a
   community whose writer is seized or destroyed freezes every treaty it holds
   until a writer exists again. ADR-0016's answer — restore the same key from an
   encrypted backup, or reconstruct it through the holder ceremony — assumes the
   *key* is recoverable and the *operator* is available. Seizure ([ADR-0024](0024-station-at-rest-encryption-key-ceremony.md))
   is exactly the case where neither may hold.
2. **A second station already exists.** The replica role is a warm second copy
   for audit and backup, pulling the chain continuously. It is, mechanically, a
   station that holds everything except write authority. Turning that into a
   standby is what ADR-0020 anticipated.
3. **Partners and devices pin the writer key.** Treaty partners pin a community's
   writer key on first sight ([ADR-0029](0029-federation-identity-profiles-and-carriage.md)),
   and every phone and `rrn wallet` pins the station key at pairing
   ([ADR-0008](0008-mobile-station-transport.md), [ADR-0028](0028-non-mobile-member-wallet.md)).
   A new writer key is a new trust root for all of them, so a succession is not
   merely a local role flip — it is an event every counterparty must be able to
   verify from the log.

The forces, in tension:

- **A failover protocol done casually is a fork generator** (ADR-0020,
  Alternatives). Two stations that both believe they hold the pen produce two
  chains. Whatever authorizes a succession must make "two valid writers at one
  position" impossible by construction, not by operator discipline.
- **The authority to hand over the pen belongs to the community, not the
  operator.** An operator-promoted standby means a rogue or coerced operator can
  fork by promoting while the writer is alive. The maintainer chose a
  governance-elected successor activated by a member supermajority
  **(maintainer decision, 2026-09-23)**.
- **The old writer may be alive.** Succession must be safe when the writer is
  merely partitioned from a two-thirds faction, not only when it is destroyed —
  and it must be safe when a destroyed writer's *key* later comes back through
  ADR-0016 recovery.
- **Replay must be able to tell which key is the writer at every position.**
  Today the answer is "the runtime key"; after a succession there are two keys
  and a boundary between them. This is the same problem the ADR-0020 residual
  posed, and one mechanism should answer both.

## Decision

**A community names one standing replica as its successor by an ordinary
governance vote; when the writer is lost, a supermajority of the electorate
co-signs an activation against the successor's copy of the chain, the successor
appends a single station-signed succession record at that position under its own
key, and from that position on every station-signed reader pins to the new key
through a log-derived writer lineage. The old writer, if it reappears, demotes;
whatever it admitted past the succession point is orphaned and re-delivered from
member outboxes.** Eight sub-decisions follow.

### 1. Designation: a statute-bar proposal names the successor

A community designates its successor through a new
`ProposalKind::Successor { station: Address }`, run at the **statute bar**
(`governance_structure`: default 50 % approval, 30 % quorum, 7-day deliberation,
7-day implementation delay). The statute bar, not the charter bar, is deliberate:
designating a standby is routine preparedness a community should do early and
revise as hardware changes, and the guarded step is activation (§2), not
designation. On implementation the station appends, station-signed:

| `rrn.gov.successor_designated` | type | meaning |
|---|---|---|
| `successor` | Address | the designated replica's station key |
| `proposal_id` | Hash | the passed `Successor` proposal |
| `designated_at` | i64 | admission instant, station-attested (ADR-0022) |

and republishes its `rrn.fed.profile` with `successor` set (ADR-0029 §2), so
treaty partners learn the designation through the ordinary directory path. The
**latest admitted** designation is the effective one; designating a new
successor supersedes the old without a revocation record. A community may have
at most one designated successor at any log position.

**The standing-replica requirement.** The designated station must be running as
`[network] role = replica`, pulling from this writer, with `[network] writer_key`
set to this writer's key (§5). Designation does not verify this — governance
cannot see another machine's config — but activation (§2) refuses against a copy
that is not at the named position, so a successor that was never actually
pulling cannot activate. The operator runbook records the check
(`station status` on the replica shows the pulled tail and the configured
writer key).

### 2. Activation: a member supermajority co-signs against the successor's copy

An activation is a member-signed record:

| `rrn.gov.succession_activation` | type | meaning |
|---|---|---|
| `community` | CommunityId | the community whose writer is being succeeded |
| `successor` | Address | must equal the effective designation at `last_seq` |
| `last_seq` | u64 | the successor's log tail as presented to the signer |
| `last_hash` | Hash | `content_hash` of the entry at `last_seq` |
| `signer` | Address | an electorate member |
| `reason` | String (≤ 500) | human-readable: seizure, destruction, unreachable since… |
| `signed_at` | i64 | the signer's clock — testimony only |

Counting reuses the ADR-0023/ADR-0027 declaration machinery with the parameters
fixed here, so nothing about "how a supermajority forms on a log" is invented
twice:

- **Threshold.** `ceil(2N/3)` distinct eligible signers, where `N` and
  eligibility are the electorate (established members, or the ADR-0015 grace
  electorate) **pinned at `last_seq`** — the last position the writer admitted
  that the successor holds. Back-dated standing cannot pack the activation
  because nothing after `last_seq` exists on the successor's copy to score from
  (ADR-0022 §5). The *instant* the scorer decays to is **not** the successor's
  own `created_at` for entry `last_seq` — that value is a pulled copy's
  re-stamp (ADR-0022 §1) and differs on every verifier. It is the signed
  `admitted_at` of the successor's `rrn.gov.succession_activation_admitted`
  anchor (below): eligibility and `N` are evaluated at the single attested pin
  `(last_seq, admitted_at)`, ADR-0027 D1b's discipline, so the old writer's
  database, a partner, and any later replica compute the same electorate.
- **First crossing, and only it** (ADR-0027 D1). The activation takes effect at
  the first admitted activation record at which the count reaches the threshold.
  A repeat signer or an ineligible signer is refused at the door and is not a
  candidate position.
- **Time-to-live** (ADR-0027 D2). Activations for a given `(successor, last_seq,
  last_hash)` triple cease to count if the crossing is not reached within
  **7 days** of the *successor's* admission of the first one. The anchor is a
  station-signed **`rrn.gov.succession_activation_admitted`** `{ activation_hash:
  Hash, admitted_at: i64 }`, appended by the successor atomically with the first
  activation of a triple, exactly as `emergency_declaration_admitted` anchors a
  declaration (ADR-0027 D2). It is a distinct kind with its own dCBOR fixture.
- **Dead on refusal** (ADR-0027 D1b). A crossing the successor must refuse —
  because `successor` is not the effective designation at `last_seq`, because a
  `rrn.gov.succession` is already admitted at or after `last_seq`, or because
  `(last_seq, last_hash)` does not match the successor's own copy — is recorded
  with a station-signed `rrn.gov.succession_refused { activation_hash,
  refused_instant }` appended atomically with the crossing record, and that
  triple never activates. A fresh triple (typically a corrected `last_seq`) may
  be started.

**Why activations are admitted on the successor's copy, not the writer's.** The
writer is, by hypothesis, gone. The successor's copy is the only chain that can
still be appended to, and appending to it is precisely what the activation
authorizes; admitting the co-signs there makes the authorization part of the
chain it authorizes, so any later verifier — a replica, a partner, an auditor —
replays the same evidence at the same positions. The successor's first
**own-authored** appends (everything before is pulled copy via `append_raw`) are
therefore the activation co-signs, their admission attestation, and, at the
crossing, the succession record. Until that crossing the successor is a replica and refuses
every other write exactly as ADR-0020 §7 requires; the activation records are
the single carve-out, and they are refused on any replica that is not the
effective designated successor.

What the signer is attesting is narrow: "I am a member of this community's
electorate, I believe the writer is lost, and I authorize the designated
successor to continue the chain from this exact tail." The member's device
obtains `(last_seq, last_hash)` from the successor over the ordinary paired
channel or reads them from a `rrn paper`-rendered sheet; it does not — cannot —
verify that the writer is lost. That judgment is the community's, which is why
the bar is two-thirds and not one operator.

### 3. The succession record: one station-signed record, new key, atomic with the crossing

At the first crossing the successor appends, in the same `LogBatch` as the
crossing activation:

| `rrn.gov.succession` | type | meaning |
|---|---|---|
| `previous_writer` | Address | the writer being succeeded (= `writer_at(at_seq)`, §5) |
| `new_writer` | Address | the successor's own key — the record's signer |
| `at_seq` | u64 | = `last_seq` of the activation triple |
| `at_hash` | Hash | = `last_hash` |
| `activation_hashes` | [Hash] | content hashes of the counted activation records, in admission order |
| `succeeded_at` | i64 | the successor's admission instant (ADR-0022) |

Signed by the **new** key. Its legitimacy does not come from the signature — a
key can sign anything about itself — but from what replay can check about the
chain beneath it:

1. `new_writer` equals the effective `successor_designated` at `at_seq`, and
   that designation was signed by `writer_at(at_seq)` (§5);
2. the entries named in `activation_hashes` are admitted activations between
   `at_seq + 1` and this record, naming this `(successor, at_seq, at_hash)`, whose
   distinct eligible signers — judged at `(at_seq, admitted_at)` where
   `admitted_at` is the signed instant of the triple's
   `succession_activation_admitted` anchor, never at any entry's re-stamped
   `created_at` — number at least `ceil(2N/3)`, with the first admitted one
   inside the TTL;
3. the chain's entry at `at_seq` has `content_hash == at_hash`;
4. `previous_writer == writer_at(at_seq)`.

A succession record failing any check is **skipped** on replay (skip, never
halt — the pinning discipline of the station-signer work), and then every record
the new key signs afterward is unpinned and skipped too, so an illegitimate
succession produces a loudly empty suffix rather than a quietly poisoned one.
A station whose own key does not validate as `writer_at(tail)` refuses to start
as a writer.

The atomic append matters for the same reason it did in ADR-0027 D1b: a crash
between the crossing co-sign and the succession record would leave a chain on
which the threshold is met but no succession exists, and replay must never
synthesize one. It fails closed instead: threshold met, no succession record,
no writer change.

### 4. The old writer: demote, orphan, re-deliver

Succession is designed for a writer that is gone, but it must be *safe* for a
writer that is merely unreachable. Two rules:

**A live writer that learns of its own succession demotes.** A writer that
ingests — from any carrier: a member's bundle, a partner's federation outbox, a
replica's peer connection, or the operator's `station demote` command — a
`rrn.gov.succession` naming itself as `previous_writer` whose `at_hash` matches
its own entry at `at_seq` and whose checks (§3) pass against its own chain,
stops admitting immediately, records the fact in `station status`, and on next
start runs as a replica of `new_writer`. `station demote --successor <addr>` is
the operator's explicit form of the same transition. For a *planned* hand-over
the order is fixed: the live writer **demotes first** (stops admitting, so its
tail freezes), and only then do members sign activations against that frozen
`(last_seq, last_hash)`; signing against a still-moving tail would make every
triple stale before its 7-day TTL (see Alternatives). A writer never *pulls* (ADR-0020 §7), so it learns of a
succession only through bytes brought to it; a partitioned writer that nobody
reaches keeps admitting into a dead branch until someone does. That branch is
what the next rule handles.

**Records the old writer admitted after `at_seq` are orphaned, and the chain
converges through member outboxes.** Nothing the old writer appended past the
succession point exists on the successor's chain. Two classes of record were
there:

- *Member-authored records* (proposals, confirmations, votes, vouches, dispute
  records) live in their authors' outbox chains (ADR-0020 §2) at fixed
  positions. When the author's device pairs with the successor (§6) and syncs,
  the outbox re-delivers every entry the successor does not hold, in chain
  order, through the idempotent front door. The same signed bytes land at new
  positions; nothing is signed twice, so nothing equivocates. A member who
  transacted on both sides of the partition submitted *one* chain of records to
  two stations, and the successor ends up holding all of it.
- *Station-signed records* (settlements, cancellations, certificates, window
  attestations, emergency markers) are derived state the successor recomputes
  by its own sweeps from the re-delivered member records, on its own admission
  clock. A settlement the old writer signed on its dead branch never existed as
  far as the surviving chain is concerned; the successor's settlement of the
  same confirmation is the one that counts, and it runs its window in full from
  the successor's admission (ADR-0022) — later, never earlier.

The economic exposure of a split is bounded the way ADR-0020 bounds
everything — each front door enforces the debt floor and the certificate caps
in its own arrival order, and the union of member records is one outbox chain
per member — but the dead branch does leave **residuals that must be stated,
not argued away**:

- *Dead-branch headroom certificates are void.* A `HeadroomCertificate` the old
  writer issued past `at_seq` never exists on the surviving chain, so a
  cert-backed spend a receiver accepted offline on the strength of that
  station signature (ADR-0021's whole point) is refused on re-delivery, and
  that receiver is stranded. The loss is bounded by `cert_max_cap_centi` per
  certificate and is a jury matter, not a ledger one.
- *Partner-side records from the old key past `at_seq` are orphaned.* A
  partner that admitted the old key's `prepare`/`commit`/`settlement` records
  past `at_seq` holds records with no counterpart on the survivor; the
  successor re-issues what its own chain supports (a prepare for a proposal it
  re-admitted, a commit for a confirmation it re-admitted), and the partner's
  position converges only once those arrive — until then the two positions
  disagree, visibly, in `status`.
- *Re-run settlements may now fail the floor.* A member who spent against a
  settlement the old writer signed on the dead branch may find the successor's
  re-run of that settlement lands after a debit that no longer fits.

`station status` on the successor therefore shows a **post-succession warning
window** — from `succeeded_at` until every designated partner has acknowledged
the succession (§7) and no member outbox has re-delivered in the last
`settlement_window_secs` — during which operators are told to expect these
effects and members are told not to accept old-branch certificates.

### 5. Writer lineage: `writer_at(seq)` replaces the runtime key at every pinning boundary

`rrn-storage` gains a `lineage` module holding **`WriterLineage`** *and* the
`rrn.gov.succession` record type itself (storage owns the log-structural
record so the lineage can decode it without a governance dependency;
`rrn-governance` re-exports the type and owns designation and activation).
`WriterLineage` is built from a **root key** and the ordered admitted
`rrn.gov.succession` records, exposing `writer_at(seq) → PublicKey`: the root
for `seq ≤ at_seq` of the first valid succession, its `new_writer` up to the
next, and so on. Every station-signed reader that today
pins to the runtime station key — ledger settlement/cancellation/certificate/
equivocation/verdict/contract-charge readers, governance window/implemented/
emergency attestations, `ScoringContext`, dispute resolution — pins instead to
`writer_at(entry.seq)`.

The root key comes from configuration, not from the log: a writer uses its own
key; a replica **must** set `[network] writer_key = rrn1…` (the option ADR-0020's
Clarification named as the follow-up) and refuses to start without it. The root
is the one trust-on-first-use fact in the system — the same posture ADR-0012
takes toward a genesis charter — and everything after it is log-derived.

This closes the ADR-0020 §7 residual as a side effect: a replica configured with
the writer's key now derives the same balances, tallies, and emergency state the
writer does, because the pin is the writer's key at each position rather than
the replica's own. The property "a replica's derived views are empty" stops
being true the day this lands, and the threat-model residual and the
`offline_lifecycle` legible-fail test are retired with it.

A **treaty partner** builds a partner-side `WriterLineage` for this community
the same way, without holding the chain — and derives it **from its own log on
replay**, never from its directory cache: its root is the writer key in the
partner's own station-signed `rrn.fed.partner_pin` record for this community
(ADR-0029 §2, appended at first pin), and its succession records are the
foreign `rrn.gov.succession` records the partner admitted to its own log under
§7, each in the same `LogBatch` as a fresh `partner_pin` for the new key. The
`at_seq` boundaries are read on this community's seq space, which every
writer-signed federation record now carries as `home_seq` (ADR-0029 §4) and
every checkpoint carries as `seq`; the partner pins a carried record to
`writer_at(home_seq)`. A succession record reaches a partner only through the
routing carve-out ADR-0030 defines in its lifecycle section (§6): it is the
position-0 entry of a *fresh* per-partner federation outbox chain authored by
the new key — the successor's federation outbox toward every partner restarts
at position 0 under the new key, and the old key's chain simply ends. ADR-0029
§4 (federation ingest) and ADR-0032 §2 (history verification) pin foreign
station-signed records to that lineage's `writer_at`, never to a single static
key; a replica or restored partner station re-derives every partner lineage
from its own chain.

### 6. Devices re-pair with the successor — a human step

A phone or `rrn wallet` pins the station key at pairing and authenticates every
sealed request to it (ADR-0008, ADR-0028). It does not hold the log and cannot
run the §3 checks, so it must **not** accept a new station key on the strength
of a succession record alone: a device that would re-pin on any signed
"I am your new station" is a device that a stolen replica key could capture.

A succession therefore requires each member to **pair again** with the
successor through the in-person SAS ceremony that pairing already is
(`docs/community-setup.md`), and then re-anchor the outbox head (ADR-0028 §7,
`rrn wallet sync`) before signing anything new. The successor serves the same
pairing surface as any station. What the app must show, and the mobile ticket
must build: when the paired station is unreachable and the discovery/pairing
surface presents a station whose `rrn.gov.succession` names the paired key as
`previous_writer`, a "your community's station has changed — confirm with an
organizer and pair again" state that explains the SAS step, never an automatic
switch. `rrn wallet` gets the equivalent message on `sync`.

This is a deliberate human gate. It costs each member one ceremony per
succession, which is rare; it buys the property that no key anywhere can move a
member's trust root without a person in the loop.

### 7. Treaty partners accept a succession only from the pinned successor

A partner station holds this community's last pinned profile (ADR-0029 §2),
including `successor`. On receiving a `rrn.gov.succession` in a federation
bundle it accepts the new writer key — re-pinning the directory entry and the
treaty's expected writer — **iff** `new_writer` equals the `successor` of the
pinned profile. If the record verifies against the pinned lineage
(`previous_writer`, `at_hash`, co-sign evidence) but `new_writer` is **not** that
`successor`, every treaty with that community moves to
`Suspended("writer-unverified")` — an evidence suspension in the ADR-0030
lifecycle that is lifted **only** by the suspending partner's own
`ProposalKind::TreatyResume` (statute bar), after its operator has confirmed the
change out of band; it never lifts automatically and never on this community's
say-so. A partner cannot verify the electorate count behind an activation
(it holds no copy of the chain), so it verifies the one fact it does hold: that
the community named this key in advance.

That fact is only as good as the profile that carries it, and the profile is
signed by the *old* writer key — the key a seizure hands to the attacker. A
seized key could sign a profile naming the attacker's own key as `successor`,
push it, and then "succeed" in every partner's eyes with no member vote. So a
profile that **changes `successor`** relative to the one the partner has
pinned is **not applied on arrival**: the partner stores it as unverified and
applies the new `successor` only after its operator confirms the change out of
band (`rrn federation confirm-successor <community> <address>`, the same human
posture as lifting `writer-unverified`). A profile that leaves `successor`
unchanged updates freely. The residual is stated: a seized writer key can
*attempt* to redirect partner pins, and until humans talk it can act as the
community toward partners that have not yet confirmed — bounded by
`credit_limit_centi` per treaty and by the confirmation step.

### 8. Encrypted profiles, backups, and a recovered old key

- **ADR-0024 is per station.** The successor's encrypted at-rest profile, its
  VMK holders, and its boot ceremony are its own; designation does not share or
  copy them. A community that runs the encrypted profile on its writer should
  run it on its designated successor too, with its own holder set, from day one —
  the runbook says so. Likewise ADR-0016 backups: the successor has been
  backed up as a replica all along, and after succession its backups are the
  community's.
- **A recovered old key must not write after a succession.** ADR-0016 lets the
  community reconstruct the old writer's key through the holder ceremony, and
  `station restore` can rebuild the old station from a backup that predates the
  succession. Lineage forbids that station from ever being the writer again:
  its key is `writer_at(seq)` only for `seq ≤ at_seq`, so anything it signs past
  that point is unpinned. It may run as a replica of the successor. The gap is a
  *restored* old station that has not yet seen the succession record (its backup
  predates it, it never pulls): it would start as a writer of a dead branch. The
  mitigation is the same as §4 — the first bundle, peer, or partner that reaches
  it carries the succession and demotes it — plus the runbook rule that a
  restore after any outage begins with `station status` on the successor, and
  the residual is stated in the threat model rather than pretended away.

### The fork-proofing argument, in one place

- At any `seq` there is at most one effective designation (latest admitted wins).
- For a given `(successor, at_seq, at_hash)` there is at most one crossing (first
  crossing on the successor's single-writer copy), hence at most one valid
  `rrn.gov.succession` at `at_seq`.
- Two different replicas cannot both succeed: only the designated one's
  succession validates (§3 check 1).
- The same successor cannot succeed twice at different tails: the second
  activation triple is refused because a succession is already admitted at or
  after its `last_seq` (§2 dead-on-refusal).
- The old writer's continued branch has no succession record naming a *third*
  key it could validate under, and its own key is not `writer_at(seq)` for any
  `seq > at_seq` on the surviving chain, so it is not a competing chain — it is
  an orphan whose member records converge into the survivor (§4).
- Devices and partners move only through a human ceremony (§6) or a pre-pinned
  fact (§7), so a stolen replica key cannot capture them.

## Consequences

- **Liveness loss of the writer becomes recoverable without the writer's key or
  operator**, bounded by one governance vote done in advance and one supermajority
  act in the moment. The Phase 2 residual "the station is the liveness single
  point of failure" is downgraded to "until the successor activates."
- **The ADR-0020 §7 replica residual closes** as a side effect of lineage pinning;
  replicas become true mirrors of derived state.
- **A new configuration obligation on every replica** (`[network] writer_key`),
  enforced at startup. Existing replica deployments must add it.
- **Every station-signed reader changes** from "pin to my key" to "pin to
  `writer_at(seq)`" — a mechanical but wide refactor across ledger, governance,
  reputation, and dispute readers, with the same skip-not-halt discipline. This is
  the largest implementation cost and the reviewer should expect it.
- **Succession is a re-pairing event for every member.** Rare, human-gated,
  and documented; the mobile app and `rrn wallet` gain a state for it.
- **Partners re-pin only a pre-announced successor**; a community that never
  designated one, or whose profile a partner never refreshed, sees its treaties
  suspended until humans talk. This is the intended failure mode.
- **The reused ADR-0023/0027 counting semantics** (first crossing, TTL,
  dead-on-refusal, atomic markers) get a second consumer, which is an argument
  for extracting them into a shared "supermajority act" helper in
  `rrn-governance` rather than copying.
- **Orphaned station-signed state re-runs on the successor's clock**, so a
  settlement that was hours from landing on the old writer may take a full window
  again. Latency is honest (ADR-0020); a dead branch's clocks do not count.
- **Threat-model obligations** for the implementation: a rogue designated
  successor (bounded: it can only ever be activated by two-thirds, and only from
  a tail the members were shown); activation by a colluding two-thirds while the
  writer is alive (a governance-capture variant of ADR-0023's standing-faction
  residual — the succession is *valid*, and the defense is social, as with any
  supermajority act); split-brain during a partition (§4: convergent through
  outboxes, exposure bounded by per-door floors); orphaned records and the
  latency they incur; a restored old station starting as a writer of a dead
  branch (§8); a stolen replica key attempting to capture devices or partners
  (§6, §7); a seized *writer* key redirecting partner pins through a forged
  `successor` (§7, held for human confirmation); void dead-branch certificates
  and orphaned partner-side records (§4).

## Alternatives Considered

- **Operator-driven failover** (promote a replica by command, no vote). Rejected
  **(maintainer decision, 2026-09-23)**: a rogue or coerced operator can fork by
  promoting while the writer is alive, and nothing on the log distinguishes a
  legitimate promotion from a hijack.
- **Planned hand-over only** (the live writer signs a hand-over record naming the
  new key, then stops). Rejected as the *only* mechanism because it does not cover
  seizure or destruction, which are the cases that matter. It is retained as the
  degenerate case of this design: `station demote --successor` on a live writer,
  after a designation, freezes the tail first, and members then activate against
  that frozen tail — a planned hand-over with the activation bar still met by
  members, not by the operator alone.
- **Multiple co-equal writers with automatic election** (Raft-style leadership).
  Rejected by ADR-0020 for the ledger layer and not reopened: the design overview's
  Raft cluster is about crash tolerance among trusted local nodes, and Phase 3's
  problem is authority under adversarial loss, which a leader election among
  machines does not answer.
- **Succession record signed by the old key** (only). Rejected: the old key is by
  hypothesis unavailable. Dual-signing when it *is* available adds nothing replay
  cannot already check and would make the record's validity depend on which
  failure occurred.
- **Devices auto-accept a succession record.** Rejected (§6): a device cannot run
  the chain checks, so auto-acceptance is capture by any signed claim.
- **Threshold below two-thirds, or a simple majority.** Rejected: succession is a
  constitutional act with the same capture profile as an emergency declaration,
  and ADR-0023's bar is the community's already-ratified answer to that profile.
- **No succession; rely on ADR-0016 restore + outbox replay.** The Phase 2 status
  quo. Rejected for Phase 3 because seizure removes the key and the operator
  together, and because a frozen writer now freezes treaty partners too.

## References

- [ADR-0020](0020-single-writer-log-dtn-submission.md) — one log, one writer;
  the liveness residual; the 2026-09-14 Clarification (writer/replica roles, the
  expected-writer-key follow-up this ADR closes)
- [ADR-0023](0023-emergency-governance-modes.md), [ADR-0027](0027-emergency-declaration-activation-and-ttl.md)
  — the supermajority-act machinery reused for activation: `ceil(2N/3)`, first
  crossing, declaration TTL, station-signed refusal markers, atomic append
- [ADR-0022](0022-admission-clock-time-trust.md) — position-pinned electorates;
  windows re-run on the successor's admission clock
- [ADR-0016](0016-station-backup-and-key-recovery.md) — station backup and key
  recovery; why a recovered old key may not write
- [ADR-0024](0024-station-at-rest-encryption-key-ceremony.md) — the encrypted
  profile is per station
- [ADR-0008](0008-mobile-station-transport.md), [ADR-0028](0028-non-mobile-member-wallet.md)
  — devices pin the station key at pairing; re-anchoring the outbox head
- [ADR-0012](0012-charter-format-and-amendments.md), [ADR-0015](0015-electorate-bootstrap-grace.md)
  — the electorate the activation counts
- [ADR-0021](0021-escrowed-offline-spending-certificates.md) — why a dead-branch
  certificate strands its receiver (§4)
- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) — profiles carry
  `successor`; partners pin the writer key on their own log (`rrn.fed.partner_pin`)
  and read `home_seq` on carried records
- [ADR-0030](0030-treaties-ratification-depth-lifecycle.md) — the
  `Suspended("writer-unverified")` treaty state
- [ADR-0031](0031-cross-community-credit-treaty-accounts.md) — why a frozen home
  writer freezes partners
- Design overview §10.4 (consensus layer), §12 Phase 3 deliverables
- [`docs/threat-model.md`](../threat-model.md) — to gain a "Writer succession"
  section covering the obligations listed in Consequences
