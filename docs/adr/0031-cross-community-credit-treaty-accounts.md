# 0031 — Cross-community credit: treaty accounts and the prepare/commit protocol

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review; it returned accept-with-changes for the set of eight and the changes
are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted against the maintainer's scope
> decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification at the
> maintainer's delegation. The review's
> findings folded into this ADR: the receiver appends its import settlement only on admission of the home's terminal export settlement (never on a window from the commit — the reviewer showed the earlier text could create Commons across a courier link); a late home outcome after the receiver's provisional commit is honored unconditionally; the Tier 1–2 final-commit instant is stated; `rrn.fed.settlement` is recorded as an ADR-0009 trade-reliability input; the receiver-side dispute-window residual is stated.
> Implementation tickets are written against this ratified text.

## Context

Phase 3 (ADR-0017) connects communities, and the first thing the design
overview asks of federation is that a member of one community can pay a member
of another in the Common (§8.5, "Credit Flow Across Communities"). The overview
sketches the *economic* shape — a bilateral clearing system with a mutual
credit limit per treaty, trade pausing at the limit until goods flow back or
the limit is renegotiated — and the *consistency* shape (§10.4, "Between
Communities — Eventual Consistency"): a two-phase prepare/commit handshake with
a deterministic reconciliation rule, aiming for *detectable, convergent*
outcomes rather than impossible atomicity across an unreliable network. It
does not say how any of that lands on the ledger.

Everything Phase 2 locked constrains the answer:

- **One log, one writer** (ADR-0020). Each community's log is a single linear
  chain appended only by its own station. ADR-0020 anticipated exactly this
  moment: "Phase 3's own log topology is *already* 'multiple single-writer
  chains' — one per community — so merge semantics get built exactly once, at
  the inter-community boundary." A cross-community payment must therefore be
  two admissions on two logs, each by its own writer, never one record on a
  shared log and never a second writer on either.
- **The debt floor** (ADR-0018) is enforced at one front door against a
  member's *committed position*: settled balance minus every pending signed
  debit. A payment to a foreign member is a signed debit like any other and
  must count from the moment the home station admits it.
- **Headroom certificates** (ADR-0021) reserve floor headroom for offline
  spends and make overspend provable. They are scoped to one station's
  accounting.
- **The admission clock** (ADR-0022) is the only window-bearing clock a
  station has. Its Alternatives section deferred one question to Phase 3:
  what to do "where *another* community must trust our windows."
- **Balances are a PN-Counter derived from settlement records** (ADR-0005,
  `rrn-storage::replay::BalanceHandler`), keyed by `Address`. An `Address`
  wraps an Ed25519 `PublicKey`, and `PublicKey::from_bytes` validates the
  curve point — so there is no way to mint a "treaty account address" from a
  hash. Roughly half of all 32-byte strings are not points at all, and the
  other half would be addresses someone could conceivably hold the secret
  for.
- **Amounts are integer centicommons**, the tier floor is a pure function of
  `|amount_centi|` (ADR-0011), and Tier 3+ is refused today.

The maintainer resolved the ledger shape on 2026-09-23 from three candidates
(see Alternatives): **treaty accounts** — each station keeps a partner-community
account on its own log; a payment from A (community X) to B (community Y)
debits A and credits the Y-treaty account on X's log, mirrored on Y's log;
prepare/commit/expire records are exchanged station to station; the net
treaty account is the bilateral limit; no member ever holds a balance on a
foreign log; multi-hop routing is out of scope. This ADR turns that decision
into records, state, and rules.

## Decision

**A cross-community payment is two ordinary, single-writer admissions — one on
the sender's home log, one on the receiver's home log — joined by four
station-signed federation records (`prepare`, `refuse`, `commit`, `abort`) and
settled by a station-signed `settlement` on each log that moves the member's
balance and the *treaty position* together. Treaty positions are a separate,
replay-derived balance space keyed by `TreatyId`, bounded on both logs by the
treaty's `credit_limit_centi`. The sender's home log is authoritative for the
outcome; the receiver's log mirrors it and never settles first. Every window
is judged by each station's own admission clock.** (maintainer decision,
2026-09-23)

Fourteen sub-decisions follow. Vocabulary is the federation spine's: `CommunityId`
(genesis charter hash), `TreatyId`, *home* (the community whose log holds a
member's vouches), *foreign*, *writer key*, *federation outbox*.

### 1. Treaty positions are a distinct balance space keyed by `TreatyId`, never a synthetic member address

Each log carries, per active treaty, one signed integer **treaty position** in
centicommons:

```
position(T) = Σ amount of `rrn.fed.settlement{treaty_id: T, direction: export}`
            − Σ amount of `rrn.fed.settlement{treaty_id: T, direction: import}`
```

Positive means this community has **exported** credit — its members have paid
partner members more than partner members have paid them — and, in the
overview's words, the partner "owes" it goods or services back. The position
is derived by replay, exactly as member balances are; the `BalanceHandler`
gains a second counter map keyed by `TreatyId` beside the address-keyed
PN-Counter, and `BalanceView` gains `position_of(treaty_id)`.

The position is **not** a member. There is no `Address` for it, no key, no
nonce, no reputation, no debt floor of its own, and nothing can be signed *as*
it. This is forced, not chosen: an `Address` must be a valid Ed25519 point
(`PublicKey::from_bytes` rejects anything else), so "derive an address from
the partner's community hash" is not constructible in general, and deriving a
*keypair* from a public seed would put a signable identity on the log that
anyone can impersonate. Keeping positions out of the address space means the
existing engine front doors need no "is this address secretly an account"
check anywhere, and no existing record kind changes shape.

### 2. The ledger picture

For A (home X) paying B (home Y) `amount` through treaty T = (X, Y):

```
X's log (home / paying side):      A         − amount
                                   position(T)   + amount    (export)

Y's log (receiver side):           position(T)   − amount    (import)
                                   B         + amount
```

Read on either log alone, the sums are zero: X's log records that credit
left A and is now held against Y; Y's log records that credit arrived from X
and now belongs to B. Read across both logs, the two positions are mirror
images (`position_X(T) = −position_Y(T)`) whenever both sides are caught up,
and differ only by settlements one side has admitted and the other has not
yet received — the temporary, visible divergence §10 bounds. The Common stays
zero-sum across the federation because a treaty position is not spendable by
anyone: it is a ledger of *obligation between communities*, discharged by
trade in the other direction, not a balance a member can draw on.

Worked example. T has `credit_limit_centi = 50_000` (500 Commons). Alice (X)
pays Bob (Y) 1_250 (12.50 Commons) for eggs; later Carol (Y) pays Dave (X)
800 for a repair. After both settle everywhere:

| | X's log | Y's log |
|---|---|---|
| Alice | −1_250 | — |
| Bob | — | +1_250 |
| Carol | — | −800 |
| Dave | +800 | — |
| `position(T)` | +1_250 − 800 = **+450** | −1_250 + 800 = **−450** |

X has net-exported 4.50 Commons of credit to Y. Neither position is anyone's
balance.

### 3. A cross-community proposal is an ordinary proposal with one additive field, and the sender is always a home member

`TransactionProposal` gains `receiver_community: Option<CommunityId>`. When
present the proposal is cross-community and `receiver` is a member of that
community; when absent the proposal is exactly what it is today, and because
the field is **omitted from the canonical CBOR when `None`** (ADR-0010
discipline, the `listing_id`/`cert_id` precedent) every existing proposal's
content id, signature, and fixture are byte-unchanged. The mobile and
`rrn wallet` signers add the field only when the payee is foreign.

**Home member** is a defined term from here on: an address is a home member
of a community when it is **anchored** on that community's log — it has an
admitted vouch by an established member (ADR-0009 identity anchoring,
`is_anchored_bounded(at_time = the proposal's admission instant on the judging
log, max_seq = that admission's seq, station = writer_at(seq))`) — or it is a genesis
founder of that community's charter. An unanchored address may transact
domestically today, but it may not cross the boundary in either role: the
sender must be a home member of the home community, the receiver a home
member of the receiver community, and each station judges only its own
members (`fed-not-home` for a sender or confirmer who is not ours;
`fed-foreign-party-unknown` for a named foreign party the partner reports as
not theirs). Anchoring is the one membership signal the log already carries,
and it is the Sybil bound the boundary needs: a fresh key with no voucher
cannot spend a community's treaty headroom.

Three rules fix which station does what:

- **The sender's home station admits the proposal first and is the
  transaction's home.** A member signs a cross-community proposal and submits
  it to *their own* station (live, courier, radio, or paper), never to the
  partner's. A station that receives a proposal whose `sender` is not one of
  its members through any member-facing door refuses it (`fed-not-home`);
  the only door a foreign-sender proposal may enter is federation ingest
  (§4), carried by the sender's home writer.
- **Payment requests do not cross the boundary in Phase 3.** A proposal with
  `amount_centi ≤ 0` (ADR-0018's receiver-debit form) and a
  `receiver_community` is refused at the home front door with
  `fed-request-unsupported`. A request inverts who is debited at
  *confirmation* time, which would make the *receiver's* station the paying
  side while the *sender's* station holds the home role — two authoritative
  logs for one transaction. Rather than build a second, mirrored protocol
  for the rarer direction, Phase 3 ships one: the paying member always
  proposes from home. Requests across the boundary are a Phase 4 candidate.

### 4. The four federation records, and the settlement record

All are writer-signed (the issuing station's writer key) canonical dCBOR,
carried in the issuer's federation outbox to the partner (ADR-0029), admitted
by the partner as foreign records through federation ingest, and pinned on
replay to `writer_at(home_seq)` on the partner-side lineage — the lineage the
admitting log itself records through its `rrn.fed.partner_pin` records and the
admitted foreign `rrn.gov.succession` records that precede the pinned record
(ADR-0029 §4, ADR-0035 §5), never the directory cache. Optional fields are
omitted when absent.

Every writer-signed record in this section carries **`home_seq: u64`** — the
issuer's own log seq at which the record is appended. The issuer knows it at
signing (it holds the single-writer lock and appends the record in the same
`LogBatch` as the admission that triggers it), and the partner uses it as the
position at which to pin the signer (ADR-0029 §4). It is a structural
coordinate, not a timestamp.

`rrn.fed.prepare` — signed by the **home** writer at proposal admission.

| field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | the proposal's content id |
| `treaty_id` | `TreatyId` | the treaty this rides on |
| `sender_community` | `CommunityId` | the home community |
| `receiver_community` | `CommunityId` | the receiver's community (= the proposal's field) |
| `amount_centi` | `i64` (> 0) | restated from the proposal |
| `expires_at` | `i64` | home admission instant + `treaty.prepare_ttl_secs`, station-attested (ADR-0022) |
| `home_seq` | `u64` | the issuer's log seq of this record (ADR-0029 §4) |
| `prepared_at` | `i64` | home admission instant |

`rrn.fed.refuse` — signed by the **receiver** writer when it will not admit a
carried proposal.

| field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | |
| `treaty_id` | `TreatyId` | |
| `reason` | string slug | from the ADR-0029 §4 registry (§13 lists the subset this ADR issues) |
| `home_seq` | `u64` | the issuer's log seq of this record (ADR-0029 §4) |
| `refused_at` | `i64` | receiver admission instant |

`rrn.fed.commit` — signed by **each** writer in turn.

| field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | |
| `treaty_id` | `TreatyId` | |
| `community` | `CommunityId` | which side is committing |
| `home_seq` | `u64` | the issuer's log seq of this record (ADR-0029 §4) |
| `committed_at` | `i64` | that side's admission instant |

The receiver's commit is **provisional** — it means "the confirmation is
admitted on my log and my rules passed." The home's commit is **final** (§5).

`rrn.fed.abort` — signed by the **home** writer only.

| field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | |
| `treaty_id` | `TreatyId` | |
| `reason` | `"expired" \| "refused" \| "cancelled" \| "dispute-upheld" \| "witness-quorum" \| "artifact-required" \| "approval-not-met" \| "validation-failed"` | the last four are ADR-0033's conditions, one abort reason per unmet condition |
| `home_seq` | `u64` | the issuer's log seq of this record (ADR-0029 §4) |
| `aborted_at` | `i64` | home admission instant |

`rrn.fed.settlement` — signed by the writer of **each** log, one per log.

| field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | |
| `treaty_id` | `TreatyId` | |
| `member` | `Address` | the home member whose balance moves on *this* log |
| `counterparty_community` | `CommunityId` | the other side |
| `amount_centi` | `i64` (> 0) | |
| `direction` | `"export" \| "import"` | `export` on the home log (member −, position +); `import` on the receiver log (member +, position −) |
| `home_seq` | `u64` | the issuer's log seq of this record (ADR-0029 §4) |
| `settled_at` | `i64` | this log's admission instant |

`rrn.fed.settlement` is a **new kind**, not a reuse of `rrn.tx.settlement`:
the existing record names two `Address` parties and the PN-Counter applies to
both, and there is no address for the position (§1). Keeping the domestic
settlement record untouched means the Phase 0–2 replay path is unchanged for
every existing log.

### 5. The home log is authoritative; the receiver's log mirrors it

Every cross-community transaction has exactly one **outcome authority**: the
sender's home log. The receiver's log never reaches a terminal state the home
log has not reached first:

- The receiver **settles only on admission of the home's terminal
  `rrn.fed.settlement{export}`** (§9), never on a window of its own. Until
  then B's credit is `Confirmed`-pending, exactly like a domestic confirmation
  inside its settlement window.
- The receiver **cancels only on the home's `abort`**, or on its own `refuse`
  (which the home turns into an `abort`).
- The receiver's own `commit` is a promise the home may rely on ("B confirmed
  and I checked my rules"), not a decision — and it binds the receiver: once
  issued, whatever home outcome follows (`settlement{export}` or `abort`) is
  honored unconditionally, even if the receiver's local exposure accounting
  has moved on in the meantime (§10).

This asymmetry is what makes the protocol *convergent* without a coordinator.
Two logs, each with one writer, cannot both decide; if both could, a partition
at the wrong moment produces two committed-but-different histories with no
rule for choosing. Naming the paying side as the authority gives every
disagreement a resolution that both logs can compute from the records they
hold: the home's final record wins, and the receiver's provisional records
are, by construction, always compatible with either outcome because nothing
on the receiver's side has moved a balance yet.

Why the *paying* side and not the receiving side: the paying member's debt
floor and the home's export limit are the two constraints most likely to
bind, both are checked at the home, and the home is where the proposal is
signed and first admitted. The receiver's constraints (its import limit, B's
Tier-2 stake) are checked at the receiver and reported back as `refuse` or a
provisional `commit`, so the home's final decision already incorporates them.

### 6. Two limit checks, on two logs, against pending exposure

The bilateral limit is enforced **at prepare on both sides** (maintainer
decision) so that neither community can be pushed past the limit by the
other's admissions.

Define per log and treaty:

```
pending_exposure(T) = Σ amount of prepares admitted on this log for T
                      whose tx has no settlement and no abort on this log
                      (i.e. Proposed / Confirmed / Disputed, not yet settled)
```

- **Home (export) check**, at admission of the proposal:
  `position(T) + pending_exports(T) + amount ≤ credit_limit_centi`, where
  `pending_exports` counts pending exposure for transactions whose
  `sender_community` is this community. Fails → `fed-position-limit` refusal
  at the front door; no prepare is issued.
- **Receiver (import) check**, at admission of the carried proposal+prepare:
  `−position(T) + pending_imports(T) + amount ≤ credit_limit_centi`, where
  `pending_imports` counts pending exposure for transactions whose
  `receiver_community` is this community. Fails → the receiver appends
  `refuse{reason: "fed-position-limit"}` and does **not** admit the proposal;
  the home aborts on receipt.

Both checks read only the local log, so each is replay-verifiable locally,
and each side's exposure is bounded by its own admissions regardless of what
the partner does. Because positions are mirror images when caught up, the
two checks are the same inequality seen from each side; because they are
evaluated against each log's *own* pending set, a partner cannot exhaust our
headroom with prepares we have not admitted.

Worked example. `credit_limit_centi = 50_000`. `position_X(T) = +48_000`
(X has exported 480 Commons net). Two X members each propose 1_500 to Y
members. The first is admitted: `48_000 + 0 + 1_500 = 49_500 ≤ 50_000`, a
prepare issues, `pending_exports = 1_500`. The second is refused:
`48_000 + 1_500 + 1_500 = 51_000 > 50_000` → `fed-position-limit`. Meanwhile a Y member
pays an X member 2_000; on Y's log that is an export check against
`position_Y(T) = −48_000`: `−48_000 + 0 + 2_000 ≤ 50_000`, fine. Once it
settles everywhere, `position_X = +46_000` and the second X proposal, if
re-signed, fits. Trade pauses at the limit and resumes when credit flows
back — the overview's mechanism, made arithmetic.

**Position invariant (restated from the spine).** No sequence of admissions,
in any arrival order, lands `|position(T)| + pending exposure` above
`credit_limit_centi` on either log. It holds because the only records that
move `position` are settlements, every settlement was preceded on the same
log by a prepare that passed the check at admission, and prepares that never
settle release their exposure on abort.

### 7. Debt-floor interaction: a cross-community debit is a pending signed debit, and certificates cannot back it

The sender's floor check is unchanged in form: at proposal admission the home
engine projects A's committed position — settled balance minus every pending
signed debit minus outstanding certificate caps (ADR-0018 §2, ADR-0021 §2) —
including *this* proposal, and refuses with `DebtFloorExceeded` if it would
fall below the floor. From admission until settlement or abort, the proposal
counts as a pending signed debit exactly like a domestic `Proposed`/
`Confirmed`/`Disputed` transaction, because it *is* one on the home log. The
abort releases the headroom (as expiry and cancellation do today).

**Floor invariant (restated).** No sequence of admissions lands a member's
committed position below the debt floor. Cross-community adds no new path
around the front door: the only door a cross-community debit enters is the
home `submit_proposal`, which runs the check.

**ADR-0021 headroom certificates may not back a cross-community spend in
Phase 3.** A proposal carrying both `cert_id` and `receiver_community` is
refused (`fed-cert-unsupported`). Three reasons, any one sufficient:

1. A certificate's admission carve-out ("admitted without a fresh floor
   check") exists so a *home* receiver can accept a spend offline against
   station-signed evidence. A foreign receiver's station cannot verify the
   certificate's remaining allowance (it holds none of X's cert history), so
   the receiver-side value of the carve-out is nil while its risk (an
   overspend the receiver cannot detect) is whole.
2. A cert-backed spend skips the floor check but must not skip the **export
   limit** check (§6), which needs the home's live position — so it cannot be
   admitted "unconditionally on arrival" anyway. The carve-out and the limit
   check contradict each other.
3. Overspend consequences (ADR-0025 equivocation cases) are single-community
   jury machinery; opening them from a foreign receiver's evidence is
   ADR-0034 territory and is not needed for the pilot federation.

Offline cross-community spending therefore rides the uncertificated path
(ADR-0021 §7): sign at home, carry, take your chances at the home front door.
A certificate-backed cross-community instrument is a Phase 4 candidate once
recognition (ADR-0032) gives receivers verifiable foreign evidence.

### 8. Tier interaction

- **The floor tier is unchanged**: `tier_floor(|amount_centi|)` at both
  stations, computed identically from the same signed amount (ADR-0011). A
  listing or party may still opt *up* via `oracle_tier`.
- **Tier 1**: bilateral confirmation plus the home settlement window. No
  new rule. For Tier 1 and Tier 2 the home's **final `commit` is appended in
  the same `LogBatch` as the admission of the receiver-carried confirmation**
  — that admission is the instant every home window claim below is measured
  from.
- **Tier 2**: the confirmer's reputation stake (ADR-0011) is a derived
  eligibility gate evaluated where the confirmer's standing lives — B's
  **home station Y**, at admission of B's confirmation
  (`evaluate_tier2_confirmation` against Y's own log). X does not evaluate
  B's stake: it has no standing for B and must not invent one. Y's
  provisional `commit` attests that Y applied its rules; a Y that commits a
  Tier-2 confirmation from an ineligible confirmer is a partner-honesty
  matter handled by treaty suspension (ADR-0030), not by X second-guessing.
- **Tiers 3 and 4** are defined by ADR-0033 (artifact evidence, three
  witnesses, cross-community validation, governance approval). For a
  cross-community Tier 3/4 transaction the home's final commit is withheld
  until ADR-0033's conditions are met on the home log; an unmet condition
  becomes `abort{reason: "artifact-required" | "witness-quorum" |
  "approval-not-met" | "validation-failed"}`, one reason per condition. This
  ADR only reserves those abort reasons; the window they run under is §9.

### 9. Every window on its own admission clock; the receiver settles only on the home's terminal settlement

This is the ADR-0022 extension the maintainer chose (each side its own
admission clock; the partner's station-signed instants are testimony):

- **Home settlement window** runs from the home's admission of B's
  confirmation (carried back in Y's federation outbox), for
  `treaty.settlement_window_secs` on the home's clock; for Tier 1–2 the
  final `commit` is appended in that same `LogBatch` (§8). During the window
  the home transaction is `Confirmed` (or `Disputed`), exactly as a domestic
  one. At the window's end, if no dispute is live and none was upheld (§11),
  the home appends `rrn.fed.settlement{direction: export}` — the
  **terminal** record — and carries it to the receiver.
- **Receiver settlement has no window.** The receiver appends
  `rrn.fed.settlement{direction: import}` **on admission of the home's
  `settlement{export}`**, in the same `LogBatch`, and at no other moment.
  B's balance moves when, and only when, the home's terminal record is on
  the receiver's log. The receiver may *display* an estimate ("expected after
  the other community's window, about N days") computed from its own
  admission of the home's final commit; that estimate is never a trigger.
- The `prepare.expires_at`, `prepared_at`, `committed_at`, and `settled_at`
  values a partner signs are **testimony** on our log: displayed, stored,
  and used to reason about the partner's accounting, never fed to our window
  arithmetic. A partner whose clock is wrong stretches or compresses only
  its own members' waits.
- **Tier 3 and 4 windows.** For a cross-community Tier 3/4 transaction the
  home window is `max(treaty.settlement_window_secs, tier window)` on the
  home clock, where the tier window is `tier3_window_seconds` or the
  charter-derived Tier-4 window of ADR-0033. The receiver still settles only
  on the home's terminal settlement.

A consequence worth stating: **B waits the home window plus two carriages**
(B's confirmation Y→X, then the home's settlement X→Y). At the default 48 h
Tier-2 window that is two days plus courier time each way. Honest latency
(ADR-0020 Consequences) — the system never pretends a cross-community
transfer settled before the authoritative log said it did.

Why the receiver keys on the *terminal settlement* and not on the final
commit: after its final commit the home can still abort — an upheld dispute
(a 14-day window), a tribunal (21 days, ADR-0034), or federation arbitration
(up to `arbitration_wait_secs`, 45 days) — and the arrival of that abort at
the receiver is carriage-dependent. Had the receiver run its own window from
the commit, a weekly courier could deliver the commit, let the receiver's
window close and credit B, and only then deliver the dispute record and the
abort: A never debited, B credited, `position_X = 0`, `position_Y = −amount`
— the Common would have stopped being zero-sum across the federation with no
rule to reconcile it. Keying on the terminal record makes the receiver's
move a pure mirror of the home's: a dispute at home *delays* B (the home
issues no settlement while it is live) but can never *reverse* B. The
saving the commit-based rule offered — one carried record instead of two —
is about a hundred bytes and is not worth a hole in conservation.

### 10. Expiry and abort: divergence is temporary and never silent

Prepare expiry is judged **by the home's clock** against the home-attested
`expires_at`: if the home has not admitted a confirmation for `tx_id` by
then, the sweep appends `abort{reason: "expired"}` (and the domestic
`cancellation{Expired}` for the proposal, so A's headroom releases). The
receiver, on admitting an abort, cancels its copy — nothing has moved, so
there is nothing to reverse.

The race the overview names — "one side can commit while the other times
out" — plays out like this:

```
Late confirmation (receiver committed provisionally, home already expired):

  Y admits B's confirmation + provisional commit     (Y's clock, day 3)
  X sweep: no confirmation admitted by expires_at   (X's clock, day 3 + ε)
  X appends abort{expired} + cancellation{Expired}
  courier brings Y's confirmation + provisional commit to X   (day 5)
  X: tx is Cancelled → confirmation refused `not-proposed`; receipt says so
  courier brings X's abort to Y                                (day 6)
  Y: admits abort → tx Cancelled(FedAborted); B's pending credit vanishes;
     B never had a settled balance from it. Y's provisional commit is
     harmless: it never moved a balance and the home's abort supersedes it.
```

The rule that reconciles every such race is deterministic and local: **a
home `abort` or home final `commit` is the outcome; a receiver-side record
that conflicts with it is superseded on the receiver's log when the home
record is admitted.** No timestamp comparison is ever needed, because the
home decides by *its* admission order alone (ADR-0022 §5) and the receiver
mirrors whatever the home decided. Divergence is therefore bounded by
carriage delay, visible on both logs (the receiver's provisional commit and
the home's abort both exist, and the arbitration path can cite them), and
self-healing on the next successful exchange. It is never silent: the
receiver's `status` for the transaction reads `Confirmed (awaiting home
commit)` until the home's record arrives, and the receipt for the late
confirmation names the refusal.

Three more paths:

```
Receiver refuses (limit, ineligible confirmer, unknown receiver):
  X: proposal + prepare admitted                       (X day 0)
  Y: check fails → refuse{fed-position-limit}; proposal NOT admitted on Y
  X: admits refuse → abort{refused} + cancellation{RejectedByReceiver}
  A's headroom and X's pending export release.

Sender withdraws before confirmation:
  X: cancel_proposal (existing door) → cancellation{WithdrawnBySender}
     + abort{cancelled}; carried to Y; Y cancels its copy if it had one.

Partner stalls (no records for a long time):
  X: proposal expires → abort{expired}. Exposure releases at home.
  Y: if Y admitted the prepare and hears nothing, Y's pending import
     exposure would hang forever — so Y ALSO drops a prepare from its
     pending set once its own clock passes Y's OWN admission instant of
     the carried prepare + prepare_ttl_secs + treaty.settlement_window_secs
     (a local release, not a decision, and it affects only NEW prepare
     admissions: once Y has issued its provisional commit for a transaction,
     any home outcome that later arrives — a `settlement{export}` or an
     `abort` — is honored unconditionally, and the import settles even if
     the released exposure now overshoots the limit).
```

The last point releases exposure on the receiver's clock alone — anchored
on the receiver's admission of the prepare, never on the home-attested
`prepared_at`/`expires_at`, which stay testimony (§9) — and it acts only to
*stop counting* exposure against itself, never to move a balance or to
override the home. Its purpose is that a treaty partner who vanishes cannot
permanently freeze our import headroom. The price is a **bounded, transient
overshoot**: if the home's terminal settlement arrives after the release, the
import settles and `|position| + pending` may exceed `credit_limit_centi` by
at most the released amount until trade in the other direction discharges
it. The overshoot is visible in `status`, admits no *new* prepare while it
lasts, and is a stated residual — the alternative, refusing late and leaving
B unpaid after Y promised, would break §5's promise and have no
reconciliation rule at all.

### 11. Disputes

- Either party may raise a dispute on their **home** log during the home
  settlement window, through the existing `raise_dispute` door (ADR-0014).
  A dispute raised by B on Y is carried to X and admitted there as a foreign
  record opening (or joining) the home dispute; a dispute raised by A on X is
  carried to Y and admitted to Y's log as a foreign record (ADR-0029 puts
  every admitted foreign record on the log, never in a cache). The **home**
  window is the one that freezes settlement; the receiver has no window of
  its own — it settles only on the home's terminal settlement (§9), which
  the home does not issue while a dispute is live — so the carried dispute
  record on the receiver's log is informational (it explains B's wait) and
  never a trigger.
- **B's effective dispute window is shorter than the home's.** B's dispute
  must reach the *home* inside the home window, which is measured from the
  home's admission of B's confirmation; B therefore has `W − (Y→X carriage)`,
  which on a courier link can be zero. This is a stated residual. Treaty
  authors should set `settlement_window_secs` to at least twice the expected
  carriage latency between the two communities, and the wallet and app show
  B the home deadline as best known. B is protected in the other direction
  regardless: nothing settles at Y before the home has decided.
- Layer 2 jury sortition on the home draws from the home's pool only —
  foreign members are never jurors. An **upheld** ruling at home appends
  `abort{reason: "dispute-upheld"}` plus the domestic `cancellation{DisputeUpheld}`;
  the receiver cancels on admitting it. A rejected or lapsed dispute settles
  as confirmed.
- **Tier ≥ 3** cross-community disputes are heard by the home **tribunal**
  (ADR-0034 §1) in the first instance, from the home's pool only; either
  party may instead request federation arbitration, which supersedes per the
  next bullet.
- A party who wants a *neutral* forum requests federation arbitration per
  ADR-0034, which names the forum from the treaty and returns a forum-signed
  verdict both homes enact. An admitted `rrn.fed.arbitration_request` for the
  case **supersedes** any home panel from its admission position: no home
  jury or tribunal is seated after it, and a home panel already seated stops
  counting ballots (its case is recorded `Superseded`, record-only). If the
  home panel has already reached a terminal ruling, the request is admissible
  only as an appeal per ADR-0034 §12 (a tribunal verdict, basis
  `appeal-own-community`; a terminal Tier 1–2 jury ruling keeps the ADR-0014 §5
  electorate appeal and is refused `case-kind-unsupported`). ADR-0034 defines the
  enactment; this one only guarantees the hook: the home's transaction stays
  `Disputed` (settlement frozen) while an arbitration request naming it is
  live on the home log, for at most `arbitration_wait_secs` (45 d, home
  clock, ADR-0034) — after which the home fails open to the status quo.

### 12. Replay derives everything

From either log alone, replay recomputes:

- every member balance (unchanged `rrn.tx.settlement` handling plus
  `rrn.fed.settlement` applied to `member` by `direction`);
- every treaty position (§1);
- every pending exposure set (§6) — prepares minus settlements minus aborts;
- every cross-community transaction's state:
  `Proposed → Confirmed → Settled | Cancelled | Disputed` on the home log with
  the same `TransactionState` machine as today (the prepare is an attestation
  beside the proposal, not a new state), and on the receiver log a mirrored
  state that additionally records "home commit admitted" (a display state),
  "home settlement admitted" (the transition that settles) and "home abort
  admitted" (the transition that cancels).

Foreign-signed records (the partner's prepares, commits, aborts, settlements,
refusals; foreign members' proposals and confirmations) are pinned on replay
to `writer_at(home_seq)` on the partner-side lineage, and skipped — never
halting replay — when the signer does not match. That lineage is itself
derived from **this log**: its root is the station-signed
`rrn.fed.partner_pin` record our writer appended when it first pinned the
partner's profile, and it advances only through the admitted foreign
`rrn.gov.succession` records (each paired with a fresh `partner_pin`) that
precede the record being pinned (ADR-0029 §4, ADR-0035 §5). Nothing about a
partner's identity is read from the directory cache on replay. A replica of
X, or an X restored from an ADR-0016 backup plus outbox replay, derives the
same positions X does, because the lineage it pins with is on the log it
copied.

**ADR-0009 input revision.** `rrn.fed.settlement` scores for `member`
exactly as `rrn.tx.settlement` does today — one settled trade in the
trade-reliability dimension, at `settled_at` on this log — and nothing else
in the locked formula changes. Recorded here so that every implementation,
and every portable history a partner verifies (ADR-0032), agrees on it.

### 13. Refusal slugs

The federation refusal-slug registry lives in **ADR-0029 §4** (and is added
to `docs/spec/dtn-bundles.md`); this table is the subset this ADR issues:

| slug | issued by | meaning |
|---|---|---|
| `fed-not-home` | any station | a sender or confirmer who is not a home member here (§3) reached a member-facing door |
| `fed-no-treaty` | either | no treaty exists between the two communities |
| `fed-treaty-inactive` | either | a treaty exists but is not `Active` at admission (ADR-0030) |
| `fed-depth` | either | treaty depth does not permit this record (reserved; Trade suffices for payments) |
| `fed-position-limit` | either | the export/import check of §6 failed |
| `fed-request-unsupported` | home | negative-amount (payment request) across the boundary |
| `fed-cert-unsupported` | home | `cert_id` present on a cross-community proposal |
| `fed-foreign-party-unknown` | receiver | the named `receiver` is not a home member of the receiver community (§3) |
| `fed-stale-prepare` | receiver | the carried prepare's `tx_id` is already `Cancelled`/`Settled` here, or no matching proposal is carried |
| `fed-writer-unpinned` | either | the carrying federation outbox author is not the treaty partner's pinned writer at this position (ADR-0035 lineage) |

Domestic slugs (`debt-floor`, `nonce-gap`, `expired`, `duplicate`,
`tier-unsupported`, `not-proposed`, `bad-signature`) apply unchanged at
whichever front door the record enters.

### 14. No multi-hop routing

A payment crosses exactly one treaty: the one between the sender's and the
receiver's home communities. If none is `Active`, the proposal is refused
(`fed-no-treaty`); the station does not search for a path through a third
community, and no record kind here names an intermediary. (maintainer
decision, 2026-09-23) The overview's "routing layer finds credit paths
through the network" is Phase 4 at the earliest; the position accounting
here is deliberately bilateral so that a later routing layer would compose
treaties end to end rather than redefine them.

## Consequences

- **The single-writer property survives federation intact.** Neither log
  gains a writer; a foreign record is admitted by *our* writer, in arrival
  order, after verification, and the whole state of a cross-community
  transaction on our log is derivable from our log alone (§12). ADR-0020's
  promise that merge semantics land "exactly once, at the inter-community
  boundary" is kept with no merge at all — only mirroring with one authority.
- **No new liability appears.** A member's exposure is bounded by the debt
  floor as before; a community's exposure to a partner is bounded by
  `credit_limit_centi` on its own log regardless of the partner's behaviour
  (§6). The worst case from a hostile or broken partner is *stuck* credit —
  a position that cannot be discharged because trade in the other direction
  never comes — never *lost* credit at the member level, because B is only
  ever credited by mirroring X's terminal settlement and A is only ever
  debited by that same terminal settlement at X.
- **The receiver waits on the home plus two carriages** (§9). Members will
  notice; the wallet and app must render "awaiting the other community"
  states clearly. This is the honest cost of one authority and no coordinator.
- **Positions can strand.** When a treaty is suspended or terminated
  (ADR-0030), its position freezes; Phase 3 has no netting or settlement-
  in-goods mechanism to discharge it. This is recorded as a residual, not
  papered over: the overview's "settlement required: physical goods/services
  delivery" is a social process outside the ledger until a later ADR.
- **Two window parameters per treaty** (`prepare_ttl_secs`,
  `settlement_window_secs`) are **treaty text** (ADR-0030), not station
  `[settlement]` config: neither operator can change them alone, and the
  engine reads them from the Active treaty at admission.
- **Additive changes to shipped shapes.** `TransactionProposal` gains an
  optional field (bytes unchanged when absent); `CancelReason` gains five
  variants across the set — `FedAborted` (introduced here) and
  `ArtifactRequired`, `WitnessQuorumNotMet`, `ApprovalNotMet`,
  `ValidationNotMet` (introduced by ADR-0033); `TransactionState` gains no
  variants on the home log. Six new signed kinds
  (`rrn.fed.prepare/refuse/commit/abort/settlement` plus the ADR-0033
  `validation` this ADR reserves an abort reason for) need fixtures.
- **Devices sign one new field and verify nothing new.** The phone and
  `rrn wallet` add `receiver_community` when the payee is foreign; they do
  not verify prepares or commits — the home station renders the state. The
  mobile handoff is small.
- **The prepare is an attestation, not a state.** Choosing to keep the home
  `TransactionState` machine untouched (the prepare rides beside `Proposed`)
  means every existing sweep, view, and test keeps working on a
  cross-community transaction; the cost is that "prepared" is a derived flag
  the views must compute, not a variant they can match on.
- **Threat-model obligations for the implementing tickets** (STRIDE sections
  under `rrn-federation` and the `rrn-ledger` cross-community rows):
  - *Position inflation* — a partner forging settlements or prepares to move
    our position: mitigated by writer-key pinning at position and by the
    rule that only *our* settlement records move *our* position; a partner
    can only refuse to mirror, never write to us.
  - *Prepare replay* — re-carrying an old prepare to re-open exposure:
    mitigated by content-address dedup (`admission_of`) and by `tx_id`
    binding; a prepare for a `Cancelled`/`Settled` tx is `fed-stale-prepare`.
  - *Partner refuses to settle* — Y never admits X's export settlement (so
    never imports; B unpaid) or never carries B's confirmation: bounded by
    the home expiry (nothing moves at X without a confirmation) and, after
    the home settled, visible as a position discrepancy both logs can show;
    remedy is ADR-0030 suspension and ADR-0034 arbitration, not ledger
    reversal. A Y that admits the export settlement *must* import in the
    same `LogBatch` — a Y that does not is a partner-honesty matter its own
    members and replicas can see.
  - *Stalled terminal records* — the home's settlement or abort never
    reaches the receiver: B waits; nothing is lost; the receiver's local
    exposure release (§10) stops the hang from freezing import headroom, and
    a late arrival is honored unconditionally (bounded overshoot, §10); the
    courier/DTN retry machinery (ADR-0020 §3, `dtn_pushes`) re-sends
    idempotently.
  - *Limit races* — two proposals admitted on the two logs simultaneously
    each passing its own check: cannot exceed the limit on either log
    because each check counts its own pending set; the transient sum across
    both logs can exceed the limit by at most one side's pending exposure,
    which is the accepted price of two clocks (documented).
  - *Clock abuse* — a partner attesting absurd `expires_at`/`committed_at`:
    testimony only; affects only its own members' waits.

## Alternatives Considered

- **Synthetic treaty-account addresses** (an `Address` derived from the
  partner's community hash, so `rrn.tx.settlement` could be reused
  unchanged). Rejected: not constructible in general (`PublicKey::from_bytes`
  validates the point), and where constructible it would place an
  impersonable identity in the address space that every front door would
  then have to special-case.
- **Foreign member accounts** (under recognition, a member holds a guest
  balance on the partner log and pays there directly). Rejected by the
  maintainer: two balances per member, a debt floor split across logs, and a
  second admission path for foreign identities in `rrn-identity`.
- **Station-to-station only** (only stations settle community balances;
  members transact through a local treasury). Rejected by the maintainer:
  smallest protocol, weakest product — members could not pay each other.
- **Symmetric two-phase commit with a neutral beacon or a mutual clock**
  (both sides commit atomically, ordering by a shared time source). Rejected:
  ADR-0022's reasoning against beacons still holds; a coordinator is a new
  trusted role; and the maintainer chose per-side admission clocks. The
  home-authority rule buys convergence without either.
- **Reuse `rrn.tx.settlement` with a `direction` flag.** Rejected: it would
  change the shape of the most replayed record in the system for every
  existing log, to save one kind.
- **Certificates for cross-community offline spending now.** Rejected for
  Phase 3 (§7); revisit after ADR-0032 recognition gives receivers evidence.
- **Multi-hop routing through third communities.** Out of scope by
  maintainer decision (§14).

## References

- Design overview §8.5 "Credit Flow Across Communities", §10.4 "Between
  Communities — Eventual Consistency", §4.3 tiers, §12 Phase 3 deliverables
- [ADR-0005](0005-station-signed-settlement.md) — station-signed settlement,
  the attestation model the federation records extend
- [ADR-0010](0010-marketplace-data-model.md) — additive optional fields
  omitted when absent
- [ADR-0011](0011-oracle-tier-model-phase-1.md) — tier floor and the Tier-2
  stake as a derived gate
- [ADR-0014](0014-phase-1-dispute-resolution.md) — the home dispute window
  and jury this ADR hooks into
- [ADR-0017](0017-resilience-before-federation.md) — Phase 3 scope
- [ADR-0018](0018-debt-floor.md) — committed position; the floor invariant
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — one writer per log;
  "several single-writer chains + a carriage layer"; idempotent ingest
- [ADR-0021](0021-escrowed-offline-spending-certificates.md) — why
  certificates stay home-only in Phase 3
- [ADR-0022](0022-admission-clock-time-trust.md) — each side's own
  admission clock; partner instants as testimony (the Phase 3 question its
  Alternatives deferred)
- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) — `CommunityId`,
  the federation outbox, checkpoints, federation ingest, `home_seq`, and the
  `rrn.fed.partner_pin` record the partner-side lineage is rooted in
- [ADR-0030](0030-treaties-ratification-depth-lifecycle.md) — `Treaty`,
  `TreatyId`, `credit_limit_centi`, `prepare_ttl_secs`,
  `settlement_window_secs`, suspension and position freeze
- [ADR-0033](0033-oracle-tiers-3-and-4.md) — Tier 3/4 conditions the home
  must meet before its final commit and terminal settlement
- [ADR-0034](0034-community-tribunal-and-federation-arbitration.md) —
  the neutral forum and verdict enactment
- [ADR-0035](0035-writer-succession-and-lineage-pinning.md) — lineage-aware
  pinning of partner writer keys
- `crates/rrn-ledger/src/{transaction,settlement,credit,tier}.rs`,
  `crates/rrn-storage/src/replay.rs`, `docs/spec/dtn-bundles.md` (refusal
  slugs)
