# 0010 — A listing is a signed record on the log; the search index is a view that can be thrown away

## Status

Accepted

Date: 2026-07-27

## Context

Everything the network has recorded so far is something that *happened*: a
transaction was proposed, confirmed, settled; a vouch was given; a reputation was
derived from those facts. The marketplace records something different — a
standing *offer*. "I will treat patients for 3 Commons" is not an event; it is a
claim about the future that stays true until the provider says otherwise, and
that other members act on.

That difference is what this ADR has to resolve. A mutable offer sits awkwardly
on an append-only, hash-chained log, and the pull toward keeping listings in an
ordinary SQLite table — where an `UPDATE` is one statement — is strong. The
forces against it:

- **A listing is a commitment other people rely on.** A buyer decides to
  transact because a listing said 3 Commons and a 48-hour slot. If the provider
  can silently rewrite the price after the fact, the buyer has no evidence of
  what they agreed to, and the dispute layer (design overview Section 7) has
  nothing to adjudicate. The audit posture that made transactions non-repudiable
  has to extend to the offers that induced them.

- **The marketplace feeds reputation, so it inherits reputation's constraints.**
  ADR-0009 fixed domain competence as a dimension fed by "marketplace
  transactions tagged with a controlled category vocabulary." Reputation is
  replayable from the log by design (T1.5.7), and it can only stay replayable if
  its inputs are on the log too. A listing category living in a mutable table
  would be a reputation input that a receiving station cannot verify.

- **Search wants the opposite properties from the log.** Browsing needs
  filtering, ranking, text relevance, and pagination over *currently active*
  listings — none of which a hash chain provides. So there must be a second,
  query-shaped representation, and the moment there is a second representation
  the question is which one is allowed to be wrong.

- **Phase 1 measures almost nothing about a provider yet.** The design doc's
  listing primitive (Section 9.2) carries a `history` summary — completed
  transactions, disputes, average rating. Phase 1 has no dispute mechanism
  (M1.8+) and no reviews at all (explicitly out of scope). The same honesty
  problem ADR-0009 hit with dormant dimensions arrives here, in a place buyers
  look at when deciding whom to trust.

- **Reputation gates the marketplace, and Phase-1 reputation has a ceiling.**
  `Requirements.min_reputation` lets a provider demand a minimum standing. But
  the highest composite anyone can currently reach is **2.75**, not 5.0, because
  three of five dimensions are structurally dormant (ADR-0009, amended
  2026-07-27). A provider who types "3.0" would publish a listing that no member
  of the network can ever satisfy — and unlike the anchoring deadlock, which was
  global and loud, this fails silently, one listing at a time.

The M1.6 task spec fixes the field shapes. This ADR adopts them, resolves the
places where they under-specify or collide with decisions already locked, and
records why.

## Decision

**A listing is a signed record on the append-only log. Its lifecycle is derived
by replaying the log, exactly as transaction state and reputation are. The
materialized index and the full-text index are caches — rebuildable from the log
and authoritative over nothing.**

### The listing primitive

One schema serves all three surfaces, with a `surface` discriminant:

| Field | Type | Notes |
|---|---|---|
| `id` | `ListingId(Hash)` | Content address — Blake3 of the canonical bytes of every *other* field. Not part of the signed content; see below. |
| `provider` | `Address` | The lister. Must equal the signer of the record. Immutable. |
| `community` | `String` | The community the listing belongs to. Immutable. |
| `surface` | `Surface` | `Goods` \| `Services` \| `Commons`. Immutable. |
| `category` | `String` | One of the controlled vocabulary below. Immutable. |
| `title` | `String` | Non-empty. |
| `description` | `String` | Markdown *permitted*, rendered as plain text with newlines preserved. Nothing parses it in Phase 1. |
| `pricing` | `Pricing` | `{ amount_centi: i64, model: PricingModel, negotiable: bool }`. |
| `availability` | `Availability` | `{ status, capacity: Option<u32>, next_slot: Option<i64> }`. |
| `requirements` | `Requirements` | `{ min_reputation: f32, community_member_only: bool, federation_only: bool }`. |
| `oracle_tier` | `u8` | The M1.8 ladder. Phase 1 accepts `1` or `2` only. |
| `federation_visible` | `bool` | Phase 2. **Must be `false` in Phase 1**; validation rejects `true` rather than accepting a promise nothing honors. |
| `created_at` | `i64` | Unix seconds, from the provider's signed content. |
| `expires_at` | `Option<i64>` | `None` = no expiry. |

`amount_centi` is signed integer centicommons, the same unit and the same sign
convention as `TransactionProposal` (ADR-0005 / M0.5): never floats, and the sign
carries direction.

**`history` is not a field.** Design overview Section 9.2 shows it inside the
listing; it is instead **derived at read time** from settled transactions
referencing the listing. A provider must not sign a claim about their own track
record — it would be self-attested, and it would go stale the moment the next
transaction settles. Of its three components, only `completed` has a Phase-1
source: `disputes` has no mechanism until M1.8+, and `avg_rating` has none at all
(reviews are out of scope for the milestone). **The two unsourced components are
reported as absent, never as `0`** — a listing showing "0 disputes" when disputes
cannot be recorded is a claim the system cannot back, and the M1.7 UI must render
absence, following the same rule the Standing screen follows for dormant
dimensions.

### The three surfaces

Shared schema, different meanings for the same fields:

| Surface | `availability.capacity` | `availability.next_slot` | `pricing.amount_centi` |
|---|---|---|---|
| **Goods** | Inventory units. `Some(0)` = sold out (the index stops surfacing it); `None` = unlimited. | Unused. | `>= 0`. |
| **Services** | Concurrent bookings, when bounded. | Next bookable slot, Unix seconds. | `>= 0`. |
| **Commons** | Units available from the pool. | Next availability for pooled resources. | **May be `<= 0`.** |

The `amount_centi >= 0` validation is deliberately **surface-scoped**: Commons is
the community-pooled surface, where zero cost is the normal case and a *negative*
amount is a subsidy — the community paying a member to take on a pooled
responsibility. The ledger already expresses that direction (a negative
`amount_centi` reverses who pays whom), so the marketplace does not need a second
mechanism for it, only permission to use the one that exists.

`PricingModel` is `Fixed` or `Negotiable`; `Auction` is Phase 2+ and is not in
the enum. The spec carries both `model` and a `negotiable` flag, which overlap;
they are given distinct meanings rather than one being dropped:

- `model` says what `amount_centi` **is** — a price (`Fixed`) or an opening ask
  (`Negotiable`);
- `negotiable` says whether the provider **invites offers**.

`Fixed` + `negotiable: true` is meaningful ("3 Commons, but make me an offer") and
allowed. `Negotiable` + `negotiable: false` is a contradiction — an opening ask
the provider will not negotiate — and is **rejected at construction**.

### Record kinds and the lifecycle

Three log record types, each with its own top-level `kind` discriminant in its
canonical CBOR (ADR-0002):

| Kind | Payload | Signer |
|---|---|---|
| `rrn.marketplace.listing.v1` | `Listing` | The provider. |
| `rrn.marketplace.listing_updated.v1` | `ListingUpdated { listing_id, patch, signed_by }` | The provider. |
| `rrn.marketplace.listing_closed.v1` | `ListingClosed { listing_id, reason, closed_at }` | The provider **or the station**. |

**Creation puts the signed `Listing` on the log directly — there is no
`ListingCreated` wrapper record.** The task spec sketches
`ListingCreated { listing: SignedListing }`, but a log entry already *is* a signed
payload: `AppendLog::append` stores the exact canonical bytes that were signed
alongside the signer and signature. Wrapping an already-signed listing in a second
signed record would sign `CBOR(CBOR(Listing))` — precisely the double-encoding
the log's own module documentation warns against, and the reason `StoredPayload`
exists. Creation therefore follows the vouch precedent (`append_vouch`): a thin
helper in this crate over `log.append`, not a new envelope. `rrn-storage` gains no
knowledge of listings; it cannot depend on `rrn-marketplace` without inverting the
stack.

`ListingUpdated.signed_by` is redundant with the envelope's signer, and is kept
anyway: replay validates **both** that `signed_by == listing.provider` and that
the envelope signer's address equals `signed_by`. A record whose signed content
disagrees with its signature is rejected rather than resolved in favor of either.

`ListingPatch` may change **price, description, availability, and `expires_at`**.
It may not change `id`, `provider`, `community`, `surface`, or `category`. The
immutable set is exactly the fields that other systems key on: `id` is the content
address, `provider` is who is accountable, and `category` feeds domain competence
in ADR-0009. Letting a listing change category after it has accumulated
transactions would move reputation between domains without any work being done.

`CloseReason` is `ExpirationReached`, `ProviderClosed`, or `StationCleanup`. The
station may sign a close for the first and third only — the ADR-0005 pattern,
where the station attests to something that happened with no party present. It may
never sign `ProviderClosed`.

Derived state, computed by replaying the entries for one `listing_id`:

```
Draft    — constructed in memory, not yet appended. Never observed by a replay.
Active   — created, not closed, not past expires_at.
Expired  — past expires_at with no close entry. Still Active's data, but the
           index hides it and the station's sweep will close it.
Closed   — a close entry exists. Terminal.
```

`Expired` is a *derived* state, not a record. It exists because the log cannot
notice the passage of time on its own: a listing becomes stale at a moment when
nobody is acting. The station's background sweep converts it to a real
`ListingClosed` record, exactly as the settlement sweep converts an elapsed
window into a settlement record. Until the sweep runs, readers must treat
`Expired` as not-for-sale — the sweep's latency must never make a stale listing
purchasable.

Closed listings **stay on the log forever**; the index hides them by default.

### Content addressing

`ListingId` is the Blake3 hash of the listing's canonical bytes, and `id` is
**excluded from the hashed content** — it *is* that hash. Encoding omits it;
decoding recomputes it. A decoded listing therefore cannot carry an id that
disagrees with its own contents. This mirrors `TransactionId` exactly (M0.5), for
the same reason.

### Linking transactions to listings

`TransactionProposal` gains one optional field, `listing_id: Option<ListingId>`.
Transactions without it remain valid and remain the norm for direct payment;
commercial transactions carry it, which is what lets a listing's completed-count
be derived and what will feed domain competence in M1.7.

**The field is omitted from the canonical CBOR when `None` — not encoded as
null.** This deviates from the convention `memo` established (explicit
`CBOR::null()`), and the deviation is the whole point. `TransactionProposal`
recomputes its id from its encoded bytes on decode; if a new key appeared in every
proposal's map, then every proposal already on the log would decode to a
*different* id than the one it was created with, breaking the confirmation and
settlement records that reference it. The general rule this establishes: **a field
added to a content-addressed record must be absent when unset, or every existing
record's identity changes underneath it.** Decoding already tolerates an absent
key, so old proposals round-trip byte-identically.

### The controlled category vocabulary

`category` is drawn from a fixed Phase-1 set: `food`, `agriculture`, `medical`,
`construction`, `tools`, `education`, `transportation`, `other`. A listing outside
the vocabulary is rejected at construction.

The vocabulary is controlled because **a marketplace category and a reputation
`DomainTag` are the same namespace** (ADR-0009: domain competence is
`BTreeMap<DomainTag, f32>`, fed by categorized marketplace transactions). Free-form
categories would mean free-form reputation dimensions — a member could mint a
private domain, be the only participant in it, and hold a perfect score there. A
bounded vocabulary is what keeps the domain-competence map a shared measurement.
Expanding it is a protocol change, not a config value.

### Requirements, and the reputation ceiling

`min_reputation` is validated at construction against the **highest composite
currently reachable** — the ADR-0009 weights minus the dormant dimensions, `2.75`
today — and a listing demanding more is rejected. A provider cannot publish an
offer that is arithmetically closed to everyone.

The bound is derived from the dormant-dimension list, never written as a literal,
so it rises on its own as M1.7 and M1.9 light dimensions up. That it varies by
phase is acceptable because **it only ever moves up**: validation is a create-time
gate, never re-applied on read, so no already-published listing becomes invalid
when the ceiling moves, and the rejected cases become accepted rather than the
reverse.

Two consequences of reputation gating that the implementation must respect:

- The score compared against `min_reputation` is the member's **capped** (public)
  composite — what the Standing screen shows them — not the raw score. The raw
  score exists solely to make anchoring computable (ADR-0009) and must not leak
  into a second decision.
- `federation_only` is Phase 2 and, like `federation_visible`, **must be `false`**
  in Phase 1; validation rejects `true`.

### The materialized index and search

Two derived structures, both rebuildable from the log:

- **`listings_index`** — a SQLite table keyed by `listing_id`, carrying `surface`,
  `category`, `provider`, `status`, `expires_at`, `price_centi`,
  `reputation_at_creation`, `created_at`, indexed for filter queries. Per house
  style (T1.5.5) its SQL lives in `rrn-storage`; `rrn-marketplace` never issues
  raw SQL.
- **A tantivy index** over `title + description + category`, persisted at
  `<data_dir>/marketplace_index/`.

Tantivy is adopted as specified, over the alternative of SQLite FTS5, for its
relevance model and because the `SearchQuery` API stays clean as the corpus grows.
The cost is accepted explicitly: it is a second store outside the database
transaction that writes the log, so it **can** diverge from the log in a way FTS5
could not. The mitigation is the rule stated at the top of this decision — the
index is authoritative over nothing. It is rebuilt by full replay, deleting the
directory is always a safe repair, and a rebuild must produce results identical to
the incrementally-maintained index.

Ranking is text relevance from tantivy **multiplied** by a provider-reputation
factor, so reputation breaks ties and lifts strong providers without letting a
high score surface an irrelevant listing.

Reputation enters ranking from the **M1.5 snapshot cache**, never a fresh replay.
Scoring is O(N) in log size, and anchoring made it O(V·N); a search returning
fifty results must not trigger fifty replays on the station's single writer thread
(the residual already noted for `reputation_band` in T1.5.9). `reputation_at_creation`
is stored in the index as a historical fact about the moment of listing, for audit
and for tie-breaking stability — current standing is what ranks.

### What is locked

The record kinds and their `kind` strings, the immutable field set, the
content-addressing rule, the category vocabulary, the surface-scoped pricing
rules, and the log-is-canonical / index-is-a-cache relationship. Changing a `kind`
string or the immutable set is a protocol change requiring a new ADR, because
existing log entries cannot be re-encoded. Index schema and ranking weights are
implementation detail and may change freely — a rebuild is always available.

## Consequences

- **Listings are as auditable as transactions, and as permanent.** A buyer can
  prove what an offer said when they acted on it, which is what the dispute layer
  will need. The cost is that a provider who publishes a mistake cannot erase it —
  only supersede it with an update or a close. This is the correct trade for a
  commitment, and it needs to be said plainly in the UI before the first publish.

- **The log grows with marketplace churn, not just with settled economic
  activity.** A provider editing a price five times writes five entries. At Phase-1
  scale this is not a problem; it does mean replay cost is now driven partly by
  editing behavior, and it is the first place a compaction discussion will start.

- **The tantivy index is the project's first store outside the log's transaction.**
  Every other derived structure — balances, reputation snapshots — lives in the
  same SQLite file and commits with the write that caused it. This one does not, so
  crash-consistency between log and index is now something the code must handle
  rather than something SQLite guarantees. The deterministic-rebuild test is what
  keeps it honest; the recovery path is deletion.

- **Reputation and the marketplace are now mutually dependent.** Reputation ranks
  listings; listing categories will feed domain competence in M1.7. The cycle is
  broken only by the direction of derivation: both are computed from the log, and
  neither reads the other's cache as an input to its own scoring. Search reads
  reputation snapshots; reputation must never read the marketplace index.

- **`min_reputation` gating is weak in Phase 1 and should not be marketed as
  strong.** With a 2.75 ceiling and most members near the bottom of it, any
  threshold above roughly 1.0 excludes nearly everyone. Providers will set it low
  or not at all, which is fine — but the feature should not be presented as
  meaningful access control until more dimensions are live.

- **Every listing field is provider-asserted.** Nothing verifies that the grain
  exists, that the slot is real, or that the capacity is honest. Oracle tiers
  (M1.8) and the dispute window are what will bind claims to reality; until then
  the marketplace's integrity guarantee is narrow and exact: *the provider said
  this, signed, at this time, and cannot deny it.* The threat model's
  `rrn-marketplace` section must state that boundary rather than imply the
  signature validates the offer.

## Alternatives Considered

- **Listings in a mutable SQLite table, log only the transactions.** The obvious
  and much simpler design. Rejected because it makes the offer unprovable: the
  evidence a dispute needs is what the listing said at the moment of agreement, and
  an `UPDATE` destroys it. It would also put a reputation input (category) outside
  the replayable log, breaking T1.5.7 portability.

- **A separate schema per surface.** Goods, Services, and Commons genuinely use
  the availability fields differently, and three types would encode that in the
  type system. Rejected because search, the index, and the transaction linkage
  would each need three code paths for one concept, and the surfaces share far more
  than they differ. One schema with a discriminant and surface-scoped validation
  keeps the shared 90% shared.

- **SQLite FTS5 instead of tantivy.** Would keep the index inside the same database
  and the same transaction as the log, making drift impossible by construction and
  rebuild trivial, at no dependency cost (FTS5 ships in the bundled rusqlite).
  Rejected in favor of tantivy's relevance model and headroom; the drift risk it
  would have eliminated is instead handled by making the index disposable and
  testing rebuild equivalence.

- **Allow any `min_reputation`, and warn in the UI.** Simpler, and it keeps the
  signed record exactly what the provider typed. Rejected because it reproduces the
  anchoring failure — a constraint no one can satisfy, failing silently — and
  pushes the fix into a client that the protocol cannot require to exist.

- **Clamp `min_reputation` down to the ceiling instead of rejecting.** Never
  rejects, never dead. Rejected because the record is signed: it would make the
  provider's signature cover a number they did not choose. A signed record must say
  what its signer said.

- **Defer `listing_id` on `TransactionProposal` to M1.7.** Would keep M1.6 purely
  station-side with no mobile coupling. Rejected because the linkage is the part of
  the data model that most needs locking now, and adding a field to a
  content-addressed record is exactly the change that benefits from landing with
  its ADR rather than alongside UI work.

- **Version listings with a monotonic counter instead of a patch record.** Rejected
  as redundant: the log already orders entries, and a counter would be a second
  ordering that can disagree with the first.

## References

- Design overview [Section 9, The Marketplace](../design/Railroad-Network-Overview.md#9-the-marketplace) — full source, in particular 9.1 (three surfaces), 9.2 (the listing primitive), 9.4 (predictive matching, whose Phase-1 form is the `Need` record in T1.6.7), 9.5 (end-to-end transaction flow).
- [ADR-0002](0002-canonical-serialization-dcbor.md) — canonical dCBOR and the `kind` discriminant convention these records follow.
- [ADR-0005](0005-station-signed-settlement.md) — the station-as-signer pattern that `ListingClosed` reuses for expiry.
- [ADR-0009](0009-universal-reputation-algorithm.md) — the reachable-composite ceiling that bounds `min_reputation`, the `DomainTag` namespace the category vocabulary shares, and the snapshot cache search ranks from.
- M0.5 transaction format (`rrn-ledger::transaction`) — `TransactionProposal`, the sign convention for `amount_centi`, and the content-addressing pattern `ListingId` mirrors.
- M1.6 task spec (`Phase 1 Tasks/M1.6 Marketplace Data Model.md`) — T1.6.2 through T1.6.7 implement this ADR.
