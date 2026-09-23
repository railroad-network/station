# 0029 — Federation identity, community profiles, and the federation carriage protocol

## Status

Proposed

Date: 2026-09-23

> **Human-review checkpoint.** Drafted by Fable 5.1 for maintainer ratification
> before any Phase 3 implementation ticket is written. Maintainer decisions it
> encodes are marked **(maintainer decision, 2026-09-23)**. This ADR is the
> substrate the rest of the Phase 3 set (ADR-0030 treaties, ADR-0031 credit,
> ADR-0032 recognition, ADR-0033 oracle tiers, ADR-0034 tribunal and arbitration,
> ADR-0035 succession, ADR-0036 matching) builds on; ratify it first.

## Context

Phase 2 closed on simulation evidence (ADR-0017 criterion, `docs/phase-2-exit-evidence.md`)
with one community, one writer station, and a carriage layer — per-device outbox
chains, unsigned bundles, station-signed delivery receipts (ADR-0020), framed over
any dumb carrier (ADR-0013, ADR-0026): TCP, the Reticulum sidecar, SMS, paper.
Phase 3 is multi-community federation (design overview §8, §10.4–10.6, §12). Its
first question is not credit or treaties but the two things every later record
presupposes: **what a community *is* at the boundary, and how bytes get from one
community's log to another's without a second writer.**

The forces:

- **A community has no federation-grade identity today.** `Charter::community_id`
  is a human-chosen string (`"rrn-testville"`, `"commons"`); `VOUCH_COMMUNITY` is
  a hard-coded `"rrn-phase0"` in the station, the CLI wallet, and the tests.
  Neither is unique, neither is verifiable. ADR-0012 already anticipated the
  answer: `charter_hash = blake3(canonical(charter))` is "the stable federation
  anchor the overview asks for", and the genesis charter is self-authenticating
  (founder multisig, trust on first use). What is missing is naming it and giving
  it a display form.
- **ADR-0020 already chose the shape of federation.** "Phase 3's own log topology
  is *already* 'multiple single-writer chains' — one per community — so merge
  semantics get built exactly once, at the inter-community boundary." And: "the
  store-and-forward carriage layer built here is exactly what Phase 3 federation
  gossip rides on." So federation must add **no** writer to any log; a foreign
  record is admitted by *this* writer, in arrival order, after verification,
  exactly like a couriered member record. The only genuinely new thing is which
  records may cross, and how the receiving writer knows who carried them.
- **The Phase 0 gossip stub was retired in place** (ADR-0020 §7 and its
  2026-09-14 Clarification): a writer never pulls, a replica never admits, and
  the peer port (`peer_handshake`, `log_tail`, `log_range`) serves whole-chain
  copies to replicas. Full-log replication between *communities* is the wrong
  primitive — it leaks every intra-community record to a partner and does not fit
  a ~65 B/s radio — and the maintainer has decided against it **(maintainer
  decision, 2026-09-23: federation-scoped records only, never full partner logs)**.
- **Disconnection is the default** (ADR-0017's reason for sequencing resilience
  first). Two communities may share a wire, a radio path with hours of latency, a
  propagation node that holds a message while neither is online, or nothing but a
  person walking between them. The overview names that person the **conductor**
  (§8.8, §10.3) and Phase 3 owes the role a formal definition.
- **Time cannot be shared.** ADR-0022 made the station's admission clock the only
  window-bearing clock and explicitly deferred the cross-station question:
  "Reconsider at Phase 3 where *another* community must trust our windows."
  Phase 3 has to answer it before the credit protocol (ADR-0031) can define an
  expiry.
- **The Reticulum decision left one hard requirement open.** ADR-0026 §7 made
  propagation-node store-and-forward (LXMF `PROPAGATED`) an explicit acceptance
  criterion that T2.6.2 then deferred; the transport today does DIRECT delivery
  only. ADR-0013's "conductor pattern as a protocol primitive" ROI rides on the
  propagated path.

## Decision

**A community's federation identity is its genesis charter hash. Communities
exchange only federation-scoped records, carried in per-partner outbox chains
authored by the writer key, ingested through the existing bundle path, over any
dumb carrier including a person. Each writer admits foreign records onto its own
log under its own admission clock; nothing else is shared.** Nine numbered
sub-decisions follow.

### 1. `CommunityId` is the genesis charter hash — (maintainer decision, 2026-09-23)

```rust
/// The federation identity of a community: blake3 of its genesis Charter's
/// canonical bytes (ADR-0012). Immutable for the life of the community.
pub struct CommunityId(pub Hash);
```

- **Value.** `CommunityId = founder_charter_hash(db)` — the hash of the
  version-1, founder-multisigned Charter, *not* of the current amended one. An
  amendment changes `charter_hash` but not `CommunityId`; a replacement charter
  with no lineage to the genesis (`previous_hash` chain broken) is a *different*
  community by construction, which is exactly the "re-root triggers
  renegotiation" rule the overview (§8.3) and ADR-0012 ask for. ADR-0030 uses it.
- **Display form.** bech32m over the 32 bytes with HRP **`rrnc`** — `rrnc1…` —
  parallel to the `rrn1…` member address of ADR-0003 and visibly distinct from it.
  A short form is the first 12 characters after `rrnc1`, for spoken and printed
  confirmation (the same role the pairing SAS plays for a device: a human reads
  it aloud across a table or a radio). Every CLI, RPC, and mobile surface renders
  a `CommunityId` this way; the raw hash never appears to a human.
- **What it replaces, and what it does not.** `Charter::community_id` stays as
  the community's *display name* (it is inside the signed genesis bytes and cannot
  move). The station-wide `VOUCH_COMMUNITY = "rrn-phase0"` constant is retired
  in favour of the display name from the effective charter, with the station
  refusing a vouch whose `community` does not match; this is a Phase-3 cleanup
  the first implementation ticket performs, and the vouch record shape is
  unchanged. `Listing::community` likewise carries the display name.
- **The writer key is bound by configuration and lineage, not by the charter.**
  The genesis Charter names founders, not a station key (ADR-0012 §3), and this
  ADR does not retrofit one into signed genesis bytes. The community's **writer
  key** is a *lineage root* that comes from configuration — a writer uses its
  own key; a replica or a partner uses the key it was configured with or pinned
  (`[network] writer_key` on a replica, the pinned profile writer on a partner)
  — extended by the ordered `rrn.gov.succession` records into a `WriterLineage`
  whose `writer_at(seq)` answers "who held the pen at this position" (ADR-0035
  §5). The log's first station attestation (ADR-0005) must be signed by that
  root; it is a consistency check against the configured root, never the source
  of it. For a *partner*, the binding is operational: a `rrn.fed.profile` (§2)
  is signed by the writer and names the `CommunityId`; a `rrn.fed.checkpoint`
  (§5) is signed by the same key over a chain whose genesis hash is that
  `CommunityId`. Anyone holding the chain can verify both; a partner that does
  not hold the chain pins the key on first sight (§2). A hostile party can always
  mint a *new* community (new genesis, new key); it cannot impersonate an
  existing one once its writer key is pinned.

### 2. Community profiles: own profile on the log, foreign profiles in a cache

A community describes itself with a writer-signed **`rrn.fed.profile`**:

| field | type | meaning |
|---|---|---|
| `community` | `CommunityId` | the genesis charter hash |
| `community_id` | string | the display name from the charter |
| `charter_hash` | `Hash` | the *current* effective charter's hash |
| `charter_version` | u32 | its version |
| `writer` | `Address` | the writer key that signs this profile and the log's attestations |
| `successor` | `Address`, **omitted when absent** | the designated successor writer (ADR-0035) |
| `founded_at` | i64 | the genesis charter's `created_at` (testimony) |
| `established_members` | u32 | the established-member count at issue |
| `production` | [string] | categories offered (from `CATEGORIES`) |
| `needs` | [string] | categories sought |
| `open_to_treaties` | bool | whether the community is receiving treaty proposals |
| `active_treaties` | [`TreatyId`] | the treaties it holds Active (ADR-0030) |
| `bindings` | [bytes] | zero or more signed `rrn.net.binding` / `rrn.net.sms_binding` envelopes for reaching the writer |
| `issued_at` | i64 | the writer's clock at issue (testimony) |

This is the overview's §8.3 profile with two corrections: `charter_hash` is the
*current* hash and `community` the *genesis* hash, so a partner can walk the
lineage between them (ADR-0012), and the reachability handles are the existing
signed bindings rather than bare addresses ("bind, do not collapse", ADR-0013).

- **Our own profile is a log record.** The writer appends a new profile whenever
  a field changes (charter amendment, treaty state change, successor designation,
  binding rotation, a member establishing) and at least on every treaty
  acceptance; the latest admitted profile is the current one. It is on the log
  so replicas serve it, so it is replay-derivable, and so a *later* claim about
  what this community said about itself can be checked against what it signed.
- **Foreign profiles are a cache, never a log record.** Received profiles go in
  the station-local **`federation_directory`** table keyed by `community`:
  `{ community, profile_envelope (the signed bytes), writer, issued_at,
  first_seen_at, last_seen_at, pinned_writer }`. The latest `issued_at` for a
  community wins; a lower one is ignored (not an error — carriers reorder).
- **TOFU, then pin.** The first profile seen for a `CommunityId` pins its
  `writer`; every later profile for that community must be signed by the pinned
  key or it is refused and logged at `warn` with both keys. The pin changes only
  through ADR-0035 succession evidence (a `rrn.gov.succession` record signed by
  the key the pinned profile named as `successor`). This is the same
  trust-on-first-use posture ADR-0012 takes toward a genesis charter and ADR-0008
  toward a paired device, lifted to the community, with the same mitigation: a
  human compares the `rrnc1…` short form out of band (a conductor's letter of
  introduction, a radio call, a printed sheet) before ratifying a treaty.
- **The directory is the gossiped profile set. There is no server —
  (maintainer decision, 2026-09-23).** Every station forwards every profile it
  holds (its own and its cache) to every partner it exchanges bundles with, and
  includes its own profile (payload kind `0x05`, §6) in Reticulum announces where
  the sidecar is enabled. Forwarding rule: a station forwards a foreign profile
  only if it is newer than what the peer last acknowledged (the federation
  outbox is acked per record, so the station knows), and never more than one
  profile per community per bundle. A community is discoverable once *any*
  station it has ever exchanged bundles with has seen it. `rrn federation
  directory` lists the cache with provenance (who we received it from, when).
  The Phase 4 "designated directory" role is explicitly not built.
- **Profile freshness is testimony.** `issued_at` orders profiles from one
  writer; it is never compared to our clock for any decision other than display
  ("last heard from 41 days ago").
- **The charter lineage travels beside the profile.** A profile names the
  current `charter_hash`, but a partner holding neither our chain nor our
  charters cannot walk from the pinned genesis to it (ADR-0012, ADR-0030). So
  the writer also signs a **`rrn.fed.charter_lineage`** `{ community:
  CommunityId, charters: [bytes], issued_at }` — `charters` being the canonical
  `Charter` payload bytes from genesis to current, in order — carried in the
  federation outbox whenever the profile's `charter_hash` changes and on every
  treaty acceptance, and cached in `federation_directory` next to the profile
  (never on our log). A partner verifies it as a chain: the first charter's hash
  equals the pinned `CommunityId`, each `previous_hash` links to the hash before
  it, and the last hash equals the profile's `charter_hash`. That each amendment
  was *ratified* is attested only by the writer's signature on the record — the
  partner cannot replay the home's votes; this is a stated residual, not a
  verified property.

### 3. The federation outbox: one chain per partner, authored by the writer key

ADR-0020 §2 gave every signing *device* an append-only, hash-chained outbox whose
entries wrap signed records, so that a carried bundle is tamper-evident,
suppression by a courier is a visible gap, and double-authorship is a provable
fork. **The station becomes a device toward each partner.** For each treaty
partner (and, before a treaty exists, for each community it is exchanging the
pre-treaty records with — exactly the profile, the charter lineage, the hello,
and a treaty acceptance; no treaty *proposal* ever crosses the wire, ADR-0030)
the writer maintains a **federation outbox chain**: `OutboxEntry` unchanged — `author` = this community's writer address,
`position` dense from 0 per partner, `prev_hash` chaining, `record_signer` /
`record_sig` / `record_bytes` the carried record — signed by the writer key and
stored in a station-local `federation_outbox` table `{ partner: CommunityId,
position, entry_hash, envelope, acked_at? }`.

What a federation outbox carries, and nothing else:

| carried record | signer | defined in |
|---|---|---|
| `rrn.fed.profile` (ours, and forwarded foreign ones) | a writer | this ADR |
| `rrn.fed.charter_lineage` (ours) | our writer | this ADR |
| `rrn.fed.checkpoint` (ours; the first entry of every bundle, §5) | our writer | this ADR |
| `rrn.fed.treaty_acceptance`, `_suspension`, `_resumption`, `_termination` | our writer | ADR-0030 |
| `rrn.fed.prepare`, `_refuse`, `_commit`, `_abort`, `_settlement` | our writer | ADR-0031 |
| `rrn.tx.proposal` with `receiver_community`, and the matching `rrn.tx.confirmation` / `rrn.tx.dispute` / `rrn.tx.dispute.response` | our members | ADR-0031 |
| `rrn.fed.history_request`; marketplace `listing.v1`/`need_announced.v1`/`inquiry_*` records that cross | our writer / our members | ADR-0032 |
| `rrn.oracle.artifact`, `rrn.oracle.witness`, `rrn.fed.validation` | our members / our writer | ADR-0033 |
| `rrn.fed.arbitration_request`, `_opened`, `_ballot`, `_verdict` | our members / our writer | ADR-0034 |
| `rrn.gov.succession` | our (new) writer | ADR-0035 |

Why reuse the outbox rather than define a "federation message":

- **Carriage attestation for free.** A record in a partner's federation outbox is
  a record that partner's *writer* chose to carry. For a member-signed record
  (a foreign proposal, a foreign inquiry) that is exactly the attestation the
  receiving writer needs — "this is a member of mine, in good standing under my
  rules, and I have admitted this record" — without a second signature wrapper.
- **Suppression is a gap; equivocation is a fork.** A partner writer that drops
  a record it owes us leaves a visible hole in a chain it signed; a partner
  writer that shows two communities two different position-`n` entries has
  produced an outbox fork, which the existing `DtnStore::record_fork` machinery
  already persists as evidence. ADR-0030 turns partner forks into automatic
  treaty suspension.
- **Idempotent, already.** Ingest is idempotent by content hash and presentation
  hash (ADR-0020 §3); re-carried federation bundles yield `known`, never a second
  admission, on any carrier, in any order.
- **Receipts come back the same way.** The partner's `DeliveryReceipt` for our
  bundle is the ack for our federation outbox rows (`acked_at`), carried back by
  whatever carrier is available, exactly as member receipts are (ADR-0020 §3).

Every federation bundle also carries the issuer's current **checkpoint** (§5) as
its first entry — wrapped as an ordinary, position-consuming federation outbox
entry, so it is re-issued (and re-signed at a new position) per bundle rather
than re-sent — and its profile if the partner has not acked the latest one.

### 4. Federation ingest: the partner-writer routing rule

Federation bundles enter through the **existing** bundle ingest path
(`Core::ingest_bundle` — RPC `bundle_submit`, mobile `POST /bundle`, transport
DTN, paper). One new rule in the router:

> If an outbox entry's `author` is a writer key known to this station — the
> pinned writer of an Active or Proposed treaty (ADR-0030), or the pinned writer
> of a `federation_directory` entry for the pre-treaty records (exactly
> `rrn.fed.profile`, `rrn.fed.charter_lineage`, `rrn.fed.hello`, and
> `rrn.fed.treaty_acceptance`; anything else from a pre-treaty writer is refused
> `fed-no-treaty`) — the entry is dispatched to **federation ingest** instead of
> the member routing table.

Federation ingest, per entry in bundle order:

1. `OutboxEntry::validate` (outer signature by the partner writer, author match,
   inner signature by the record signer) — as today.
2. Chain-track the partner's federation outbox in the existing `seen_outbox_heads`
   / `outbox_forks` tables (gap policy: route, do not advance the head; fork
   policy: persist evidence, refuse the later entry `outbox-fork`, and raise the
   ADR-0030 suspension).
3. **Pin check.** The partner writer key must equal `writer_at(seq)` of the
   partner-side `WriterLineage` we hold for that community (ADR-0035 §5): its
   root is the pinned profile writer, extended by the `rrn.gov.succession`
   records that partner has carried to us, with `at_seq` boundaries on the
   partner's own seq space — so "the pin" is lineage-aware from the first
   implementation, never a single frozen key. Mismatch → `refused /
   fed-writer-unpinned`.
4. Dispatch by the carried record's `kind` to the federation routing table
   (owned by `rrn-federation`, extended by ADR-0030–0035): profiles update the
   cache; checkpoints go to `federation_checkpoints`; treaty, credit, oracle,
   arbitration, and marketplace kinds go to their front doors; a member-signed
   record that names one of our members as counterparty goes through the **same
   engine front door** the member path uses, with a `foreign: true` context so
   the home-only checks (debt floor, tier stake, electorate) are applied to *our*
   member and the partner's are trusted to the partner's commit (ADR-0031).
5. Answer with one station-signed `DeliveryReceipt` (unchanged shape). The
   refusal slugs below are **the one federation registry** — ADR-0030 through
   ADR-0036 adopt these names and add none of their own beyond the two domestic
   tribunal slugs ADR-0034 owns (`not-a-party`, `already-voted`); each is registered in
   `docs/spec/dtn-bundles.md` with the ADR that owns its meaning:

   | slug | meaning | owner |
   |---|---|---|
   | `fed-no-treaty` | no treaty exists between the two communities | ADR-0030 |
   | `fed-treaty-inactive` | a treaty exists but is not `Active` | ADR-0030 |
   | `fed-depth` | the treaty's depth does not permit this record | ADR-0030 |
   | `fed-writer-unpinned` | the carrying writer key is not `writer_at(seq)` of the pin/lineage | this ADR |
   | `fed-unroutable-kind` | a kind federation ingest does not route | this ADR |
   | `fed-checkpoint-conflict` | a checkpoint contradicts one already held (§5) | this ADR |
   | `fed-not-home` | the sender/confirmer is not a home member here | ADR-0031 |
   | `fed-foreign-party-unknown` | the named foreign party is not a home member of its community | ADR-0031 |
   | `fed-position-limit` | the export/import limit check failed | ADR-0031 |
   | `fed-request-unsupported` | a negative-amount (payment-request) proposal across the boundary | ADR-0031 |
   | `fed-cert-unsupported` | a certificate-backed spend across the boundary | ADR-0031 |
   | `fed-stale-prepare` | a prepare for a transaction already terminal here | ADR-0031 |
   | `fed-contract-unsupported` | a service contract across the boundary | ADR-0032 |
   | `fed-standing-unavailable` | a gate needs recognized standing and none is held | ADR-0032 |
   | `fed-standing-stale` | held recognized standing is past its TTL | ADR-0032 |
   | `fed-members-only` | a `community_member_only` listing approached from outside | ADR-0032 |
   | `artifact-required`, `artifact-limit`, `artifact-unavailable` | Tier 3/4 artifact rules | ADR-0033 |
   | `validator-required`, `validator-not-neutral` | Tier 4 validator rules | ADR-0033 |
   | `tribunal-cannot-seat`, `tier-below-tribunal`, `reasoning-too-short`, `case-kind-unsupported` | tribunal rules | ADR-0034 |
   | `forum-not-neutral`, `forum-not-in-treaty`, `forum-busy` | arbitration rules | ADR-0034 |

What is **not** on our log: foreign profiles, foreign charter lineages, partner
checkpoints, foreign listings and needs, foreign standing, our own checkpoints,
and our federation outbox rows. Each is a station-local cache or evidence store, documented as such
(PROCESS convention: "the log is the source of truth; everything else is a cache
or local metadata"). What **is** on our log: every foreign record we *admit* —
because from admission on it binds one of our members or one of our positions,
and replay must re-derive that binding.

### 5. Checkpoints and provable rollback

A writer-signed **`rrn.fed.checkpoint`** `{ community: CommunityId, seq: u64,
content_hash: Hash, issued_at: i64 }` commits the issuer to its own log tail. It
is **not** appended to the issuer's own log (it would be self-referential and
would move the tail it describes); it rides as the first entry of every
federation bundle the issuer sends — a position-consuming federation outbox
entry like any other carried record (§3), so each bundle's checkpoint is a fresh
signed statement, not a re-sent one — and is stored by each receiver in
`federation_checkpoints { community, seq, content_hash, issued_at, received_at,
envelope }`, all of them, never overwritten.

Two checkpoints from one writer are **provable rollback or fork** when either

- they carry the same `seq` and different `content_hash`, or
- the later-`issued_at` checkpoint carries a *lower* `seq` than an earlier one.

Both are self-contained proofs (two signed statements by one key that cannot both
describe one append-only chain). The receiver persists the pair as evidence and
raises an ADR-0030 automatic suspension (`partner-rollback`). This is the
cross-community answer to the threat model's open "log fork / rollback" item: a
community cannot prove its own honesty, but every partner accumulates
commitments it cannot later retract, and a conductor carrying a bundle carries
the commitment with it. Checkpoints are also what a **replica** of a partner
could later be checked against; that audit tool is a follow-up, not this ADR.

A receiver never *verifies* a checkpoint against the partner's chain (it does
not hold it); it verifies the signature and the consistency of the set. That is
deliberately the same standard ADR-0021 applies to equivocation: provable from
what we hold, without trusting anything we do not.

### 6. Carriers — (maintainer decision, 2026-09-23)

All federation traffic is bytes on the ADR-0013 `FrameTransport` seam: framing,
airtime pacing, RRNC reliability, and the `DtnSyncer` are reused unchanged. Four
carriers ship in Phase 3; a treaty partner may be reached over any subset.

1. **Direct TCP.** The peer port grows a federation method set beside the replica
   set: `fed_hello`, `fed_bundle` (submit a federation bundle, get the receipt),
   `fed_receipt` (return a receipt), `fed_profile` (fetch the current profile).
   The handshake is a writer-signed **`rrn.fed.hello`** `{ community, writer,
   nonce: [u8;32], peer_nonce?: [u8;32] (omitted on the opening message),
   profile_hash: Hash, sent_at }`: each side signs the other's nonce, so a TCP
   peer proves control of the writer key before any bundle is accepted, and a
   replay of a captured hello fails on the nonce. No transport encryption is
   added — the payloads are already signed and community-public; the residual
   (metadata, listing text in the clear on the wire) is stated in the threat
   model as it is for every other carrier. `[federation] peers = ["host:port",
   …]` configures outbound TCP partners; the writer/replica role rule of
   ADR-0020 §7 is untouched — a *writer* may dial federation peers, because a
   federation exchange never pulls a chain, it submits bundles.
2. **Reticulum, direct delivery.** Unchanged from T2.6.2/T2.6.4: the partner
   writer's `rrn.net.binding` (carried in its profile) resolves to a destination
   and the `DtnLoop` pushes bundles and correlates receipts.
3. **Reticulum, propagation nodes — a hard requirement.** LXMF `PROPAGATED`
   delivery, so a federation bundle survives with *neither* station online — the
   store-and-forward ADR-0026 §7 named as an acceptance criterion and T2.6.2
   deferred. The implementing ticket settles the LXMF-stamp stance (ADR-0026 §7)
   and whether a station may *be* a propagation node; this ADR requires only that
   a bundle sent while the partner is unreachable is delivered when it is.
4. **Conductor carriage — paper and USB.** A bundle whose entries are a
   federation outbox run is rendered by the existing `rrn paper` tools
   (`PaperKind::Bundle`), or written as a file to removable media, and carried
   by a person; the receipt comes back the same way. The conductor is formalized
   in §7.

Three payload-kind tags are added to `docs/spec/dtn-bundles.md` §7.1 and
`dtn_sync::PayloadKind`: **`0x03`** a `PortableReputationHistory` (evidence,
ADR-0032), **`0x04`** an artifact blob (ADR-0033), **`0x05`** a bare signed
profile (for announces and letters of introduction). Three `PaperKind`s are added
with letters `p` (profile), `h` (history), `a` (artifact), all riding the
existing `rrnp:` multi-part form (`docs/spec/qr-payloads.md` §5); no new QR
prefix. SMS is *not* a federation carrier in Phase 3: a federation bundle exceeds
any sane SMS budget, and the modem gateway does not exist.

### 7. The conductor

A **conductor** is anyone who physically carries federation bundles, receipts,
and profiles between communities. The role is formalized as follows, and it
needs **no trust and no key**:

- A conductor holds `PaperKind::Bundle`/`Receipt` sheets or a bundle file, and
  one or more `PaperKind::Profile` sheets — a community's **letter of
  introduction**, the signed profile a not-yet-federated community hands to
  someone travelling to a neighbour.
- Nothing a conductor carries can be forged (every record is signed), silently
  dropped (chain gaps), or replayed to effect (idempotent ingest). A conductor
  can *delay* and can *read* — the same residuals as any courier (threat model,
  "cleartext carriage").
- `rrn paper` gains no new command for conductors beyond rendering and ingesting
  the new kinds; `rrn federation export --partner <rrnc1…>` produces the bundle a
  conductor carries and `rrn federation import` ingests what they bring back.
  The overview's "traveler networks" (§8.8) are exactly this.

### 8. Cross-community time — an extension of ADR-0022 (maintainer decision, 2026-09-23)

ADR-0022 deferred cross-station time trust. The rule for Phase 3:

> **Each station judges every window, deadline, expiry, and ordering by its own
> admission clock, over records admitted to its own log.** A partner-signed
> instant (`issued_at`, `prepared_at`, a prepare's `expires_at`, `accepted_at`)
> is testimony: displayed, and used by the *partner's* own accounting, never an
> input to ours. Where two logs must agree on one outcome, one of them is
> **authoritative** for that outcome and the other **mirrors** it: the paying
> side for a cross-community payment (ADR-0031), the side that opened a case for
> a dispute, the forum for an arbitration (ADR-0034), the successor for a
> succession (ADR-0035). The mirroring side runs its own windows from *its*
> admission of the authoritative side's record.

No beacon, no shared clock, no "later of the two admissions". A partner whose
clock is wrong stretches or compresses its *own* windows and so harms its own
members — the same operator trust ADR-0022 §6 already accepted, with the same
blast radius. ADR-0022 gains a dated cross-reference to this section.

### 9. The `rrn-federation` crate

Federation logic lives in a new crate, **`rrn-federation`**, layered after
`rrn-dispute` and before `rrn-station`/`rrn-cli`:

```
rrn-crypto → rrn-storage → rrn-identity → rrn-ledger
  → { rrn-reputation, rrn-governance, rrn-marketplace } → rrn-dispute
  → rrn-federation → rrn-station / rrn-cli
```

It owns: `CommunityId` and its bech32m form; the profile, checkpoint, and hello
records and their fixtures; the `federation_directory`, `federation_checkpoints`,
`federation_outbox` stores (migrations in `rrn-storage::migrations`, tables
documented as station-local); federation outbox assembly and the federation
routing table; and, per the later ADRs, treaties, cross-community credit state,
recognition verification, and arbitration records. It depends on `rrn-protocol`
for `OutboxEntry`/`Bundle`/`DeliveryReceipt` and on `rrn-dispute` for sortition.
`rrn-marketplace` gains **no** dependency on it (ADR-0036 reads federation caches
through a trait). `rrn-crypto` is untouched.

### Non-goals (explicit)

- **Not full-log replication** between communities; the replica peer methods
  remain replica-only and a writer still never pulls a chain.
- **Not a second writer.** No foreign key ever appends to our log; our writer
  admits foreign records after verification.
- **Not a directory service.** No station answers directory queries for
  communities it has not itself received profiles from; there is no index, no
  registration, no search across the federation beyond one's own cache.
- **Not transport security.** Reticulum's link crypto and the TCP hello are
  reachability and liveness aids; integrity and authenticity remain in the signed
  records (ADR-0008, ADR-0013).
- **Not identity collapse.** A `CommunityId` is not a Reticulum destination and
  not a writer key; the writer key is a rotatable-under-succession handle *for*
  the community, rooted in configuration and extended by succession records (§1, ADR-0035).

## Consequences

- **Every later Phase 3 ADR is small.** Treaties, credit, oracle validation,
  arbitration, and succession each add records to a routing table and rows to
  a per-partner chain; none of them needs a transport, a handshake, a
  replication protocol, or a time model of its own.
- **The single-writer guarantees survive federation intact.** Reputation,
  sortition, tallies, balances, and treaty positions replay identically on any
  copy of a community's chain, because there is still exactly one order of events
  per community. Cross-community outcomes are pairs of station-signed records,
  one authoritative and one mirroring (§8), never a merge.
- **Partition tolerance is inherited, not designed.** A treaty partner that is
  unreachable for a week accumulates federation outbox rows; when a path or a
  conductor appears they flow, in order, idempotently — the Phase 2 machinery,
  unchanged. This is the retrofit ADR-0017 was sequenced to avoid.
- **Bandwidth is bounded by what crosses.** Profiles, treaties, prepares,
  commits, settlements, and the member records that bind a foreign party are
  each a few hundred bytes; a 65 B/s radio moves a day's cross-community trade
  for a small community in minutes. Foreign listings (ADR-0032) are the largest
  class and are opt-in per listing (`federation_visible`).
- **TOFU is a stated risk.** Before a treaty is ratified, a partner's writer key
  rests on the first profile seen. The mitigation is human (compare the `rrnc1…`
  short form out of band, the same discipline as the pairing SAS) and
  procedural (a treaty runs at the charter-amendment bar over 30 days, ADR-0030
  — ample time to notice). An eclipse that feeds a community a fabricated
  partner from the start is the residual, stated in the threat model.
- **Metadata leaks widen.** Which communities trade with which, how often, and
  what categories they list are visible to every carrier and every partner's
  partner (profile forwarding). Content is community-public by design; the
  residual is the trade graph.
- **A second supervised Python surface grows** if a station is made a
  propagation node (§6.3); the appliance discipline of ADR-0026 applies.
- **`VOUCH_COMMUNITY` retirement touches the wallet and tests.** A one-time
  cleanup; vouch bytes and fixtures are unchanged because the value is a string
  field.
- **Follow-up work created:** the `rrn-federation` crate scaffold; migrations
  for the three stores; router extension and refusal slugs; peer-port federation
  methods; PROPAGATED delivery and the stamps decision; `PayloadKind`/`PaperKind`
  extensions with fixtures; `rrn federation` CLI family (`directory`, `profile`,
  `export`, `import`, `checkpoints`); mobile handoff for rendering `rrnc1…`
  identities and profiles; threat-model sections (below); ADR-0022 dated
  cross-reference; docs-site pages for organizers (what a profile says about you)
  and operators (configuring partners, running as a propagation node).

**Threat-model obligations for the implementing tickets** (STRIDE sections under
a new `rrn-federation` heading, plus additions to `rrn-station`):

- *Eclipse via the directory* — a station whose only partners lie about the rest
  of the federation; mitigation: profiles are signed by their subjects and
  forwarded verbatim, so a lie must be a withheld profile, not a forged one;
  residual: withholding.
- *Profile spoofing before pin* — the TOFU window; mitigation as above.
- *Checkpoint equivocation* — a partner showing different checkpoints to
  different peers; mitigation: any two conflicting checkpoints are a
  self-contained proof once they meet (a partner's partner forwards them);
  residual: they may never meet.
- *Announce and forwarding budget on constrained links* — profile forwarding
  competes with money on a LoRa channel; mitigation: profiles are `Bulk`
  priority (§7.3 of the DTN spec) and at most one per community per bundle.
- *Metadata leakage* — the trade graph; residual, stated.
- *Federation outbox growth* — unacked rows to a partner that never returns;
  mitigation: bounded retention after treaty termination, surfaced in `status`.

## Alternatives Considered

- **Full-log replication between communities (evolve the replica gossip).**
  Rejected (maintainer decision): leaks every intra-community record to
  partners, does not fit constrained carriers, and reintroduces the multi-chain
  merge problem ADR-0020 confined to the boundary.
- **A writer-key-based `CommunityId`.** Rejected: a succession or a
  restore-under-new-key would read as a new community and void every treaty;
  the genesis hash is invariant across both.
- **A pair `(genesis hash, writer key)` as identity.** Rejected as identity —
  the pair is exactly what a profile *is*, and it belongs in a signed,
  rotatable statement, not in the name.
- **A bespoke "federation message" envelope instead of the outbox chain.**
  Rejected: it would need its own sequencing, fork detection, receipts, and
  fixtures — everything the outbox already has — and would give the receiver no
  proof of suppression.
- **Signing our own checkpoints onto our own log.** Rejected: self-referential
  (the record moves the tail it attests) and useless to us; a checkpoint is a
  commitment *to others*.
- **Signed time beacons or "later of the two admissions" for cross-community
  windows.** Rejected (maintainer decision): a beacon is a new trusted role and a
  new record on every window; the max rule couples each side's windows to the
  other's clock honesty. Home-side authority with own-clock mirroring needs
  neither.
- **A federation directory service (designated directory stations).**
  Rejected for Phase 3 (maintainer decision): a directory is a trust and
  censorship point needing its own signing rules; the overview places it in
  Phase 4 and the gossiped set discovers everything a small federation needs.
- **SMS as a federation carrier.** Rejected: bundle sizes exceed any SMS
  budget and the modem gateway is unbuilt.
- **Putting federation logic in `rrn-station`.** Rejected: the daemon is the
  wrong audit boundary for a wire-format-and-state-machine surface that the CLI
  wallet, the FFI, and the outage harness all need without a daemon.

## References

- [ADR-0012](0012-charter-format-and-amendments.md) — `charter_hash` as the
  federation anchor; genesis self-authentication; lineage via `previous_hash`
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — one writer per log;
  outbox chains, bundles, receipts; "Phase 3 inherits the right shape"; the §7
  Clarification (writer never pulls, replica never admits)
- [ADR-0013](0013-federation-transport-reticulum.md),
  [ADR-0026](0026-reticulum-sidecar-ratified.md) — the transport seam, Reticulum
  as a carrier only, the deferred PROPAGATED requirement and stamps stance
- [ADR-0022](0022-admission-clock-time-trust.md) — the admission clock; the
  deferred cross-station question §8 answers
- [ADR-0008](0008-mobile-station-transport.md) — sealed/signed envelopes as
  the security boundary; TOFU pairing with a human-compared code
- [ADR-0003](0003-bech32-address-format.md) — bech32m with HRP `rrn`; `rrnc` is
  its community sibling
- [ADR-0017](0017-resilience-before-federation.md) — why federation starts from
  a partition-proven carriage layer; the Conductor role moved to Phase 3
- ADR-0030–0036 (this set) — the records this substrate carries
- Design overview §8 (Federation Protocol, §8.3 profile, §8.8 discovery), §10.3
  (degradation ladder), §10.4 (between-community consistency), §12 Phase 3
- `docs/spec/dtn-bundles.md` §7 (payload-kind tags, RRNC, airtime, bindings);
  `docs/spec/qr-payloads.md` §5 (`rrnp:` multi-part)
- `crates/rrn-protocol/src/{outbox,bundle,receipt,binding}.rs`,
  `crates/rrn-storage/src/dtn.rs`, `crates/rrn-station/src/{gossip,dtn_sync,dtn_loop,reticulum}.rs`
- [`docs/threat-model.md`](../threat-model.md) — to gain the `rrn-federation`
  section listed under Consequences
