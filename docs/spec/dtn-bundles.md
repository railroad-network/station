# DTN Wire Formats: Outbox Chains, Bundles, and Delivery Receipts

**Status:** current · **Task:** T2.2.1 (M2.2 DTN core) · **ADR:** [0020](../adr/0020-single-writer-log-dtn-submission.md), [0022](../adr/0022-admission-clock-time-trust.md)

This document locks the wire layer of ADR-0020's **delay-tolerant submission**:
the tamper-evident structures by which a member's signed records travel
store-and-forward — over LoRa, SMS, paper, or another member's phone — to the
community's single-writer station, and by which the station answers. It is the
human-readable twin of `crates/rrn-protocol` (`outbox.rs`, `bundle.rs`,
`receipt.rs`); where this doc and the code disagree, the code and its committed
fixture (`crates/rrn-protocol/tests/fixtures/cross_platform_dtn.json`) win.

Everything here is **carriage and evidence**, never a second ledger. The
community log stays one linear hash chain with the station as sole writer
(ADR-0020); these records move signed commitments *to* that writer and prove
what was carried and what was admitted. All integrity and authenticity live in
`SignedPayload` at the application layer (ADR-0002); a carrier is a dumb pipe
(ADR-0008/0013).

All records are canonical dCBOR (RFC 8949 §4.2.1, ADR-0002): map keys in
bytewise-sorted order, integers shortest-form, text NFC. Amounts anywhere below
a carried record are integer centicommons. Timestamps here are **testimony**
(ADR-0022 §3) — display and evidence only, never an input to a window, deadline,
ordering, or eligibility decision.

---

## 1. Outbox entry — `rrn.dtn.outbox`

Every signing device keeps its own append-only, hash-chained **outbox**: one
chain per signing key. Each entry wraps exactly one already-signed application
record (a proposal, confirmation, vote, vouch, dispute opening, …) and is itself
a `SignedPayload<OutboxEntry>` signed by that device (member) key. The chain
makes carried records tamper-evident, makes a courier that drops an entry leave
a detectable **gap**, and makes an owner who signs two entries at the same
position an **outbox fork** — provable equivocation (ADR-0021, T2.3.3).

`OutboxEntry` body (the signed canonical CBOR):

| CBOR key | type | meaning |
|---|---|---|
| `kind` | text | `"rrn.dtn.outbox"` |
| `author` | bstr(32) | the chain owner's address (public-key bytes); MUST equal the outer signer |
| `position` | uint | 0-based, strictly sequential per author |
| `prev_hash` | bstr(32) | Blake3 of the previous entry's canonical body bytes; all-zero at position 0 |
| `record_signer` | bstr(32) | Ed25519 public key of the carried record's signer |
| `record_sig` | bstr(64) | signature over `record_bytes` |
| `record_bytes` | bstr | the carried record's canonical dCBOR (the exact signed bytes) |
| `authored_at` | int | testimony timestamp |

The carried record travels as the `record_signer` / `record_sig` /
`record_bytes` triple — **never re-serialized, never re-signed** — mirroring
`rrn-storage::log::StoredPayload` but as explicit CBOR map entries. Two derived
identifiers:

- **`entry_hash`** = Blake3 of the entry body's canonical bytes. This is what the
  *next* entry's `prev_hash` chains to, and what fork detection compares.
- **`record_hash`** = Blake3 of `record_bytes` — the *same* content hash the log
  admits under, so receipts, dedup, and admission all speak one identifier.

**Validation** (`outbox::validate`, needs the enclosing `SignedPayload`):

1. the outer signature verifies over the entry body;
2. `author == outer signer` (the chain owner is the signer);
3. the embedded signature (`record_sig` by `record_signer` over `record_bytes`)
   verifies.

**Chain validation** (`outbox::validate_chain`) additionally requires positions
`0, 1, 2, …` and each `prev_hash` linking to the prior `entry_hash`.

**Fork** (`outbox::is_fork`): two *valid* entries, same `author`, same
`position`, different `entry_hash`. Same position **and** same hash is a
duplicate (the same entry carried twice), not a fork.

---

## 2. Bundle — carriage envelope (unsigned)

A **bundle** carries a run of signed outbox entries from one or more devices.
It is **not** a signed record — integrity lives on each entry (ADR-0013
dumb-carrier), so any device or peer may carry any bundle.

`Bundle` CBOR map:

| key | type | meaning |
|---|---|---|
| `v` | uint | format version, `1` |
| `entries` | array of bstr | each element the **canonical bytes** of a signed outbox entry envelope (below) |
| `assembled_at` | int | testimony timestamp |

Each `entries` element is a byte string wrapping the canonical CBOR of an
**entry envelope** — a 3-field map mirroring `StoredPayload`:

| key | type | meaning |
|---|---|---|
| `signer` | bstr(32) | the device key that signed `body` |
| `sig` | bstr(64) | signature over `body` |
| `body` | bstr | the `OutboxEntry`'s canonical dCBOR |

Carrying entries as opaque byte-string blobs keeps a courier from needing to
understand them and makes `bundle_id` a stable function of the concatenated
carriage.

**`bundle_id`** = Blake3 of the bundle's encoded bytes. It identifies a
*carriage unit* (for chunking in T2.2.5) and is deliberately **not** stable
under re-bundling: the same record in two bundles has two `bundle_id`s. Receipts
therefore key on `record_hash`, never on `bundle_id`.

**Decode** (`Bundle::decode`) refuses, in order:

- an input over **`MAX_BUNDLE_BYTES` = 4 MiB** (before the CBOR is walked);
- non-canonical or mis-shaped CBOR, or a wrong `v`;
- more than **`MAX_BUNDLE_ENTRIES` = 512** entries;
- a garbage (non-decodable) entry;
- a bundle whose *same-author* entries are out of position order.

Entries from multiple authors may share a bundle. For one author, the carried
positions must be **non-decreasing** in carriage order — a **gap is legal**
(partial carriage), and an **equal position is legal** too: both sides of an
outbox fork (§1), or a byte-identical duplicate, may ride in one bundle, so a
witness need not split equivocation evidence across bundles and one fork pair
cannot poison an otherwise-valid bundle. Only a strictly **decreasing** position
is refused (the courier-reorder tripwire). Signatures are **not** checked at
decode — this order check is structural hygiene over *claimed* authors, not a
security boundary; ingest (T2.2.3) verifies signatures and answers a fork's
losing side per record (`outbox-fork`, or `known` for a duplicate).

---

## 3. Delivery receipt — `rrn.dtn.receipt`

When the station ingests a bundle it answers with a **station-signed**
`SignedPayload<DeliveryReceipt>` enumerating, per presented record, what it did.
Receipts travel back by the same carriers.

`DeliveryReceipt` body:

| CBOR key | type | meaning |
|---|---|---|
| `kind` | text | `"rrn.dtn.receipt"` |
| `station` | bstr(32) | issuing station's address |
| `outcomes` | array of maps | one per record presented, in presented order |
| `received_at` | int | the station's admission-clock reading at ingest (testimony) |

Each **outcome** map:

| CBOR key | type | presence | meaning |
|---|---|---|---|
| `record_hash` | bstr(32) | always | Blake3 of the presented record's bytes |
| `outcome` | text | always | `"admitted"` / `"known"` / `"refused"` |
| `seq` | uint | iff admitted/known | the admitting log sequence |
| `reason` | text | iff refused | a machine-stable refusal slug (below) |

`seq` and `reason` are **omitted when absent — never `null`** (ADR-0010
additive-field discipline): a refused outcome carries no `seq`, an admitted one
no `reason`.

A receipt is **transport state, not community state**: it is **never appended to
the community log**. The ledger facts it reports (a settlement, a cancellation)
are their own station-signed records (ADR-0005); T2.2.3 persists receipts in a
local, unsigned table for redelivery.

Ingestion is idempotent (ADR-0020 §3): re-submitting a bundle can only reproduce
the same outcome content (`known` instead of a second `admitted`), never a
duplicate admission.

### Refusal-slug registry

A closed set (`RefusalReason`), never free text — the decoder rejects any slug
outside this table, so the set is also the length bound:

| slug | meaning |
|---|---|
| `bad-signature` | a record or outbox-entry signature did not verify |
| `nonce-gap` | the sender's per-sender nonce was a gap or duplicate |
| `debt-floor` | admitting the record would commit its signer below the debt floor (ADR-0018) |
| `expired` | the proposal had expired by the admission clock (ADR-0022 §4) |
| `unroutable-kind` | the record's `kind` is not one the station admits over DTN |
| `outbox-fork` | the entry is one side of an outbox fork (ADR-0020 §2 / ADR-0021) |

A reader that does not recognise a slug treats the outcome as an unknown refusal
(the decoder rejects an unknown slug rather than guessing).

---

## 4. Security notes

- **Dumb carrier.** No integrity or confidentiality is claimed for the bundle
  envelope. A tampered bundle can corrupt or drop entries — which then fail
  `outbox::validate` at ingest, or show as a chain gap — but can never forge a
  signed record or admission.
- **Fork = equivocation evidence.** An outbox fork (`is_fork`) is a signed,
  self-incriminating pair: two entries the same key signed at one position. It
  is the evidence primitive ADR-0021/T2.3.3 turn into an automatic dispute.
- **`bundle_id` is unstable by design.** It names a carriage unit, not content;
  never use it to identify or dedup a record. `record_hash` is the content
  identifier.
- **DoS bounds.** `MAX_BUNDLE_BYTES` (4 MiB) and `MAX_BUNDLE_ENTRIES` (512) cap
  what a single decode will process; the byte cap is checked before the CBOR is
  walked.
- **Time is testimony.** `authored_at`, `assembled_at`, and `received_at` never
  enter window or ordering arithmetic; admission order is arrival order and
  windows run from the station's admission clock (ADR-0022).

---

## 5. Consumed by

- **T2.2.2** — outbox store in `rrn-storage` (persist a device's outbox chain).
- **T2.2.3** — station bundle ingest + signed delivery-receipt issuance; the
  local receipt table.
- **T2.4.2** — mobile FFI over these types; the mobile repo verifies
  `cross_platform_dtn.json` byte-identically.
- **T2.5.1** — paper/QR encodings of bundles and certificates.

## 6. Future (out of scope here)

- **Sealed bundles.** Bundles are cleartext today; the carried records were
  already log-public *within the community*, so this leaks nothing new to a
  community member. Sealing a bundle to the station key (privacy against an
  outside courier — ADR-0008 sealed envelopes) is a later privacy upgrade, not
  built in T2.2.1.
