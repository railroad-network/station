# 0023 — Emergency governance: deciding faster in a crisis without building a coup lever

## Status

Proposed

Date: 2026-09-08

## Context

A community mid-disaster cannot run a seven-day proposal window. The storm is
tonight; the grid is down now; the member whose device holds the community's
only working radio needs authority to spend on fuel before dawn. The design
overview names this as a Phase-2 deliverable — "emergency governance modes:
fast decision making under crisis conditions" (§12) — and §2.7 already sketches
the shape: an emergency is *declared*, its scope is *strictly limited to the
declared domain* ("a flood emergency does not authorize economic
restructuring"), it *expires automatically* unless renewed, everything done
under it is *logged and reviewable*, and the *burden falls on renewal, not
termination*. What the overview does not do — and what this ADR must — is turn
that sketch into a locked, machine-checkable, replay-derivable mechanism that
survives a partition and does not quietly become a lever for capture.

Because the failure mode of designing this badly is not slowness. It is a coup.
Every emergency-powers mechanism in political history has been abused by the
people who declared the emergency, and the overview says so itself: §2.8 names
**governance capture** the *existential* threat, and §2.4 explains why the
ordinary implementation delay exists — it "gives dissenters time to exit,
appeal, or organize." An emergency measure takes effect immediately, with no
delay: it removes exactly that runway. Speed and the exit right are in direct
tension, and a careless emergency mode spends the second to buy the first.

The forces this ADR must hold together:

- **The crisis is real and the current tools do not meet it.** Phase 1 already
  ships a `ProposalKind::Emergency { expires_at }`: it takes effect the instant
  it passes (no implementation delay) at a raised approval bar
  (`emergency_threshold_pct`, 67% by default). But it still runs the *full*
  ordinary `deliberation_window_days` — seven days by default — and its
  `expires_at` is neither bounded nor, today, enforced anywhere in
  `statute.rs`/`lifecycle.rs`. The one thing a crisis needs, a compressed
  *decision* window, is precisely the thing the code notes as deferred: "a
  dedicated emergency window is Phase 2" (`proposal.rs`). This ADR designs that
  window — and, because it is about to make the Emergency kind *fast*, it must
  also close the `expires_at` gap so that fast never means permanent.

- **It must work while partitioned.** Under ADR-0020 the station is the sole log
  writer and members submit signed records store-and-forward over any carrier;
  under ADR-0022 the station's clock at admission is the *only* clock that bears
  on windows, deadlines, and eligibility — party-asserted timestamps are
  testimony, never arithmetic. A crisis is when partitions happen. So an
  emergency's declaration, its window, and its expiry must all be signed records
  that travel by courier and are anchored on the **admission clock**, not on any
  author's self-set `created_at`.

- **Governance windows are, today, on the author's clock.** ADR-0022 re-anchored
  the *ledger's* windows (settlement, dispute, certificate validity) to admission
  time, but it never reached `rrn-governance`: a proposal's
  `voting_ends_at = created_at + window_days` is still computed from the author's
  self-asserted `created_at` (`proposal.rs`), and a ballot is valid iff
  `created_at ≤ cast_at ≤ voting_ends_at`. On a seven-day window the backdating
  exposure is real but slow to exploit. On a *compressed* window measured in
  hours it is trivial: an author who sets their clock back publishes a proposal
  that is "already closing," and a colluder who sets theirs forward votes in a
  window everyone else sees as shut. **A compressed governance window is unsafe
  on the author clock.** The emergency path therefore cannot ship until it is
  admission-anchored — this ADR makes that a precondition, not a nicety.

- **The declared powers must not compound.** The overview's scope limit is the
  whole game. Compressing a *decision* window is a legitimate response to a
  storm. Freezing dissent, packing the electorate, rewriting the charter,
  entrenching a measure past the crisis, or reaching into the *economic* windows
  (settlement and dispute delays are not bureaucracy — they are the members'
  protection against a bad or coerced trade) are not. The narrow design is the
  one that hands a community exactly one new power — *decide faster, for a
  measure that then lapses* — and withholds every adjacent one.

- **There is a precedent for a rule-relaxing mode that ends itself.** ADR-0015's
  bootstrap grace is the model: a mode that relaxes a rule (eligibility) while a
  log-derived predicate holds, is visible to every member, and *lapses on its
  own* with no switch to throw and no migration. Emergency governance is the
  same shape with a different trigger — not "the community is too young" but "the
  community declared a crisis" — and, unlike grace, it must be *hard* to enter
  and *fast* to leave, because grace's power is benign and an emergency's is not.

## Decision

**An emergency changes how fast the community may decide, and — for a temporary
measure that then lapses — nothing else.** It compresses a single parameter,
the deliberation/voting window, for a single narrow class of proposals, under a
declaration that is itself a supermajority act of the ordinary electorate; it
self-expires within days; it freezes the constitution and pins the electorate
while it holds; every measure it passes is time-bounded so that durability still
costs the ordinary process; and its every effect is a log-derived,
replay-reconstructible fact anchored on the admission clock. No new role is
created, no existing bar is lowered, and no economic window moves. What follows
is numbered and concrete. Recommended constant values appear inline; the ones
the maintainer should confirm or redirect are collected in the PR body, but the
ADR commits to a concrete default for each so it stands as a complete record.

### 1. Two gates, both required: a declaration unlocks compression, an Emergency proposal uses it — and the measure it passes must expire

Fast decision-making requires **both** of two independent things to be true, and
either alone changes nothing:

- an **emergency is active** (a declaration in force, §2); and
- the proposal is a **`ProposalKind::Emergency`** (immediate effect, raised
  approval bar).

An `Emergency` proposal raised while *no* declaration is in force keeps its
Phase-1 behaviour exactly — the full ordinary window, immediate effect, 67% bar —
so this ADR is backward-compatible and adds no new power to the un-declared
state. Only the intersection — an `Emergency` proposal admitted during an active
declaration — runs on the compressed window (§3). Speed is the product of a
collective act (the declaration) and a self-limiting instrument (the Emergency
kind), never of one member's choice.

But two gates are not enough on their own, because **`ProposalKind::Emergency`
is narrow by *effect*, not by *content*.** Its variant carries only
`expires_at` plus the same free-text `title`/`body` any `Statute` carries
(`proposal.rs`), so "suspend member X's trading" or "reassign the fuel budget"
can be filed as an `Emergency` just as easily as a genuine crisis response. The
compressed window would then let a supermajority faction enact an ordinary power
measure in hours — and if that measure's `expires_at` were unbounded, it would
be *permanent*, defeating the overview's Sunset rule ("emergency powers cannot
become permanent without full normal legislative process"). So the third,
load-bearing rule:

> **An emergency-passed measure must itself lapse.** A measure enacted on the
> compressed path (an `Emergency` proposal that passed while a declaration was
> active) must carry `expires_at ≤ effective_expiry(emergency at proposal
> admission) + EMERGENCY_MEASURE_GRACE`, where `effective_expiry` is the
> *actual* end of the declaration active at the proposal's admission — shortened
> by an `emergency_lapse` if one arrives, not the originally scheduled expiry.
> The recommended grace is one ordinary `implementation_delay_days` (7 days):
> long enough to legislate a durable replacement through the *normal* full-window
> process, not long enough to be a standing law. Making a crisis measure
> permanent therefore always costs the ordinary process.

Two enforcement details this ADR fixes, because the implementation ticket needs
them decided: **(i)** an `Emergency` proposal admitted *during* an emergency with
an out-of-bound `expires_at` is **refused at admission** with a typed refusal —
it is not silently downgraded onto the ordinary window, so a member always gets
an explicit "your emergency measure's lifetime exceeds the cap" rather than a
surprise. **(ii)** `expires_at` is **enforced for every `Emergency`-kind
measure** (kind-level: an expired measure has no effect in `enacted_statutes`),
and only the *bound* above is compressed-path-specific. Today the field is
entirely inert — serialized but read by nothing in `statute.rs`/`lifecycle.rs` —
so enforcing it at all is new work T2.8.2 must do; making it fast without making
it enforced would be the bug.

This converts the "two gates" claim into a real one: an ordinary
`Statute`/`AdministrativeRule`/`CharterAmendment` raised during an emergency
runs its normal uncompressed window regardless, and an `Emergency` measure that
*does* ride the compressed window is temporary by construction.

### 2. The declaration is a collective, co-signed, admission-anchored record

An emergency begins with a signed **`rrn.gov.emergency_declaration`** and takes
force only once a supermajority of the electorate has **co-signed** it. Sketched
fields (canonical dCBOR, `kind = "rrn.gov.emergency_declaration"`):

| field | type | meaning |
|---|---|---|
| `community_id` | string | the community this declares an emergency in |
| `author` | Address | the electorate member raising the declaration |
| `reason` | string | the crisis, human-readable (storm, grid loss, security incident) |
| `scope` | string | the declared emergency *domain* — testimony and display only (see §6 and Non-goals) |
| `duration_secs` | i64 | requested lifetime; clamped to `[EMERGENCY_DURATION_FLOOR, EMERGENCY_DURATION_CEILING]` (§4) |
| `stated_renewal_index` | u32 | the author's claim of position in a renewal chain; **advisory** — the effective count is log-derived (§4) |
| `previous_declaration_hash` | Hash, **omitted when absent** | links a claimed renewal to the declaration it extends; absent for an initial declaration (ADR-0010 additive-field discipline) |
| `created_at` | i64 | the author's clock — retained as bounded testimony only, never arithmetic (ADR-0022) |

Co-signatures are separate **`rrn.gov.emergency_cosign`** records
(`kind = "rrn.gov.emergency_cosign"`; fields: the target `declaration_hash` and
the `signer` Address), mirroring the shape of the existing `rrn.gov.proposal_cosign`
so they can be admitted one at a time as they arrive. Note a carriage caveat:
**no `rrn.gov.*` kind is DTN-routable today** — `route_dtn_record` refuses
governance kinds as `UnroutableKind`, so proposals, co-signs, and votes do not
yet ride bundles at all. The partition argument below therefore rests on
routing that T2.8.2 must *add* (extending the router's kind table and airtime
classification); it is a required part of this work, not an existing capability,
and the implementation sketch lists it.

- **Who may declare and co-sign.** The declaration author and its co-signers must
  be members of the electorate — established members, or the ADR-0015 grace
  electorate (founders ∪ established) while the community is in bootstrap grace.
  This reuses the one electorate the whole governance stack already trusts; it
  introduces **no council, executive, or operator role**, because a new
  privileged declarer *is* the power ladder we are trying not to build. As with
  ordinary proposals (`proposal.rs`), the author cannot co-sign their own
  declaration — the threshold below counts *other* electorate members.

- **The threshold is a supermajority, and it is the primary anti-abuse defense.**
  The declaration takes force at the admission of the co-signature that crosses
  `emergency_declaration_pct` of the electorate. Recommended default **67%**,
  with a floor `EMERGENCY_DECLARATION_PCT_FLOOR = 67%` — a charter may raise this
  bar but **never lower it below two-thirds** (§4 explains why every emergency
  parameter needs a floor). The denominator is the electorate at the **log
  position of the crossing co-signature** (§3c's position-bounded rule, applied
  here too), not a wall-clock instant, so the "how many is two-thirds" question
  has one deterministic answer. Requiring a supermajority *collective* act to
  unlock compression is what stops a faction from squatting on the emergency
  lever: one member, or a bare majority, cannot compress anything.

- **Declarer and co-signer eligibility is judged at admission position, not on
  the author clock.** Ordinary co-signs record an author-clock `cosigned_at` and
  gate eligibility on it (`proposal.rs`); the emergency path explicitly does
  **not** — a declaration/co-sign counts only if its *signer* is in the
  position-bounded electorate as of that record's admission. This is part of the
  admission-anchoring precondition, and it is where the emergency path diverges
  from the inherited author-clock governance behaviour.

- **It is anchored on the admission clock, and the station attests the boundary.**
  The emergency is *active* from the admission of the threshold-crossing
  co-signature — the **activation instant** — for the effective `duration_secs`
  thereafter, measured by the station clock at admission (ADR-0022), never by any
  `created_at`. But admission time is *station-local, unsigned metadata that a
  replica re-stamps on its own clock* (ADR-0022 §1; `rrn-storage::log`), so a
  predicate written purely over "admission time" is **not** replica-identical —
  a read-replica, or a station re-bootstrapped by outbox replay (ADR-0020),
  would recompute a different activation instant from its own receipt timing.
  ADR-0022 §1 resolves exactly this by requiring every decision with downstream
  effect to be **restated in a station-signed record** (the ADR-0005 pattern the
  ledger uses for settlement, and governance already uses for enactment via the
  station-signed `ProposalImplemented`). So this ADR adds a fourth,
  **station-signed** record kind, **`rrn.gov.emergency_activated`**
  (`kind = "rrn.gov.emergency_activated"`; fields: the `declaration_hash`, the
  station-attested `activation_instant`, the `effective_expiry`, and the
  log-derived `renewal_count` of §4), written by the station when it admits the
  crossing co-signature. The activation instant is then a *signed, replicated
  fact*, not a per-replica clock reading, and every downstream rule (§3–§5) reads
  it from that record — so the mode has exactly one clock and every replica
  agrees. A compressed proposal's effective window end is fixed the same way: the
  station stamps it at the proposal's admission (a station attestation), so
  replicas replay the boundary rather than re-deriving it.

- **The partition tradeoff is deliberate.** A community fully partitioned from
  its own electorate *cannot* declare an emergency — there is no one to reach the
  threshold. That is correct: the members who are *co-present* in the crisis (the
  ones who would benefit from a fast local decision) are exactly the ones who can
  co-sign locally and courier the bundle to the station. A supermajority that can
  never be gathered unilaterally is the feature, not a bug.

### 3. Effect: one window compresses; the constitution freezes and the electorate pins; everything else is untouched

An active emergency has exactly three effects, on a clearly delimited scope:

**(a) Window compression — scoped to `Emergency`-kind proposals admitted during
the emergency, and *only* those.** For such a proposal the deliberation/voting
window becomes `emergency_window_secs` instead of `deliberation_window_days`,
**starting at the proposal's own admission** and ending
`emergency_window_secs` later (the station-attested close of §2). Every other
proposal kind — including an ordinary `Statute` raised during the emergency —
runs its normal, uncompressed window.

Two rules this scope needs decided, because tallies depend on them:

- **The ballot rule.** A ballot on a compressed-path proposal counts iff its
  **admission ≤ the proposal's station-attested close** — nothing else. The
  emergency's *own* lapse or expiry does **not** retroactively close an
  already-open compressed window: once a compressed proposal is admitted its
  window is fixed, so a vote signed during the emergency but admitted after the
  emergency lapses is counted exactly if it reached the station before that
  proposal's close, and ignored otherwise. The ballot's own `cast_at` is
  testimony, bounded only by the no-future-dating rule (ADR-0022 §4), never
  arithmetic. (T2.8.2 lists this as a required-in-ADR case; it is here.)
- **The publication gate inside a compressed window.** A proposal must still be
  *published* (reach its co-sign publication threshold,
  `DEFAULT_COSIGN_THRESHOLD = 3` outside grace) before it can pass, and under
  compression that publication must now complete *inside* the compressed window
  measured from admission. The window does **not** restart at publication — it
  runs from admission — so a proposal that fails to gather its publication
  co-signs in time simply lapses unpublished, exactly as an ordinary proposal
  does when its window closes first. The collective declaration is the emergency
  gate; the ordinary publication threshold is unchanged and unrelaxed.

**(b) Charter freeze — community-wide while the emergency is active, on *every*
path the effective charter can change.** No `CharterAmendment` proposal is
*admitted*, and any already-open amendment's *enactment* is *deferred* until the
emergency lapses (its 30-day window keeps running; it simply cannot take effect
inside the emergency). The freeze is defined on the **effective charter**, not on
the amendment-proposal path alone: `effective_charter` also roots on the
highest-version founder-authorized charter (`charter.rs`'s `founder_charter`
selects it with no lineage or vote gate), so T2.8.2 must freeze *that* door too —
no higher-version founder charter takes effect during an emergency — rather than
bolt the amendment path shut and leave the founder path open. (That path is
latent today — the RPC pins version 1 and it is not DTN-routable — but the ADR
names it so the freeze is on the asset, not one of its doors.) The constitution
is the layer everything references (ADR-0012); an emergency that could rewrite it
could restructure power under cover of the crisis, so the rules of the game are
held fixed for the emergency's short life.

**(c) Electorate pin — community-wide, at the activation co-signature's log
*position*.** Every emergency tally counts the electorate as derived from the
**log prefix ending at the activation co-signature's position**, and this pin
governs **both** the quorum denominator **and** ballot eligibility: a member
whose established standing is manufactured by records admitted *after* that
position is neither counted in the denominator nor allowed to cast a valid
emergency ballot. The pin must be **position-bounded, not time-bounded**, and
this distinction is load-bearing: reputation counts evidence by the party's own
signed `issued_at` (`rrn-reputation::scoring`), and ADR-0022 §3 makes
arbitrarily-old testimony legal, so a *wall-clock* pin at the activation instant
`T_a` would still admit vouches back-dated `issued_at < T_a` but *admitted after*
`T_a` — reopening the "declare, then manufacture members, then vote" path the pin
exists to close. Binding the electorate to a log *position* (ADR-0022 §5,
"ordering is log order, full stop") closes it: nothing admitted after the
activation co-signature can enter the pinned set, whatever timestamp it claims.
This needs a position-bounded `established_members`/`grace_electorate` variant in
`rrn-reputation` (today's helpers take a time `at`); T2.8.2 owes it.

The parameter table, normal vs emergency, with floors:

| Parameter | Normal | Emergency | Rule |
|---|---|---|---|
| Decision window (Emergency-kind proposals) | `deliberation_window_days` (7 d) | `emergency_window_secs` (charter; default **24 h**) | Clamped to hard floor `EMERGENCY_WINDOW_FLOOR_SECS` = **12 h**; **compresses, never below the floor** |
| Implementation delay | `implementation_delay_days` (7 d) | 0 | Already the Emergency kind's behaviour; unchanged |
| Measure lifetime (`expires_at`) | n/a | `≤ emergency_expiry + EMERGENCY_MEASURE_GRACE` (7 d), **enforced** | §1 — a compressed-path measure must lapse |
| Approval bar | `statute_approval_pct` (50%) | `emergency_threshold_pct` (67%) | **Raised, never lowered** — speed does not cheapen passage |
| Quorum | `statute_quorum_pct` (30%) | same (never lowered) | Emergency may not *reduce* the quorum bar or denominator |
| Declaration bar | n/a | `emergency_declaration_pct` (67%) | Floor 67%; charter may raise, never lower (§2) |
| Charter amendment | allowed | **frozen** (admit + enact) | §3(b) |
| Electorate | live | **pinned at the activation co-sign's log position** (denominator + eligibility) | §3(c) |
| Settlement window (ADR-0011) | 24 / 48 h | **unchanged** | Economic protection — never compresses |
| Dispute window (ADR-0014) | = settlement | **unchanged** | Economic protection — never compresses |
| Debt floor / certificates / reputation | — | **unchanged** | Out of scope; see Non-goals |

The load-bearing *omission*: the **settlement and dispute windows do not move.**
They are not bureaucratic delay — they are the interval in which a member can
dispute a coerced or mistaken trade before value moves (ADR-0011/0014). A crisis
is when coercion is *most* likely, not least. Compressing them would use the
emergency to strip members' economic protection at the worst possible moment. The
overview's scope limit — a flood does not authorize economic restructuring — is
enforced here by simply never wiring the emergency state into the ledger's window
arithmetic at all (Non-goals).

**On the window floor's honesty.** `EMERGENCY_WINDOW_FLOOR_SECS` cannot make a
compressed window "DTN-safe": under ADR-0020 a confirmation "carried for three
days settles three days late," and nothing measured in *hours* can include a
member whose carrier takes *days*. The floor's job is narrower — to stop the
window collapsing toward zero, which would be instant capture — not to promise
inclusivity it cannot deliver. Any emergency vote structurally excludes
deeply-partitioned members; that is an honest cost of deciding in a crisis, named
in Consequences, not a defect the floor repairs.

### 4. Expiry: automatic, short, renewable only by a fresh collective act, and hard-capped by log-derived proximity

- **Automatic.** An emergency ends when `activation_instant + duration_secs ≤ now`
  at the admission of the record being judged. There is no "until lifted"; the
  *default* state is off, and staying on takes work.

- **Short, with floors and a ceiling.** The declaration's requested
  `duration_secs` is the sole source of the emergency's length, clamped to
  `[EMERGENCY_DURATION_FLOOR, EMERGENCY_DURATION_CEILING]` — there is no separate
  charter "duration" parameter to reconcile against it; the charter tunes only the
  floor/ceiling, and those are themselves bounded by hard constants a charter
  cannot breach. Recommended default (an absent/typical request) **72 h**, floor
  **24 h** (an emergency shorter than a day is not worth the ceremony), ceiling
  **14 days** (the overview's upper "7–14 day" band and ADR-0021's DTN delivery
  grace). Reconciling the ticket's "72 h" with the overview's "7–14 days": the
  default is 72 h and the ceiling is 14 days, so a community may lawfully choose
  within the overview's band while the shipped default stays conservative.

- **Renewal is a fresh collective act, and "consecutive" is log-derived, not
  self-asserted.** A renewal is a fresh `emergency_declaration` that must gather
  the full co-sign supermajority again — the burden is on renewal, as the
  overview requires. Crucially, the renewal *count* is **not** read from the
  author-chosen `stated_renewal_index`: replay derives it from log proximity. A
  declaration whose activation instant falls within `EMERGENCY_COOLDOWN_SECS` of
  the previous emergency's end is a **continuation** and inherits the prior
  chain's count, regardless of what index it claims. This closes the trivial
  bypass of "hit the cap, then re-declare with index 0": a self-reset index buys
  nothing, because proximity, not the field, governs.

- **Hard-capped, then a cooldown longer than the chain.** A continuation chain
  may renew at most `MAX_CONSECUTIVE_RENEWALS` times (recommend **2** — at most
  three back-to-back activations, capped by a ceiling constant a charter cannot
  exceed). Once the cap is reached the emergency lapses, and — because
  "consecutive" is proximity-based — any further declaration whose activation
  would fall within the cooldown of that lapse simply **does not activate**:
  replay refuses to treat it as effective. The cooldown must be **at least the
  chain's own total active duration** (`EMERGENCY_COOLDOWN_SECS ≥ Σ chain
  durations`, and strictly greater than `EMERGENCY_MEASURE_GRACE`), so a community
  can never spend more than half its calendar time under emergency and a lapsing
  measure's grace can never dovetail straight into the next chain (see the
  Consequences residual on cycling, which this bound answers). Both the cap and
  the cooldown are pure functions of admission times in the log — no free-text
  statute is parsed. This makes a *perpetual emergency state* impossible; it
  bounds, but does not forbid, a faction *cycling* emergencies at the ceiling,
  which Consequences names honestly.

- **Early lift is allowed; late lift is not needed.** A signed
  **`rrn.gov.emergency_lapse`** (`kind = "rrn.gov.emergency_lapse"`; fields: the
  target `declaration_hash` and `author`) ends an active emergency before its
  automatic expiry, so a community is not trapped in crisis mode after the crisis
  passes. It carries the **same co-sign supermajority** as a declaration —
  reusing the `emergency_cosign` kind, whose `declaration_hash` target may be a
  declaration or a lapse — and its co-signers are drawn from the **same
  position-pinned electorate** the emergency itself uses (§3c), so a lift is
  governed by the same body that would vote its measures, not a differently-drawn
  one. The lapse takes effect at the admission of its own threshold-crossing
  co-signature; the station records it, shortening `effective_expiry`. The
  *absence* of a lift never extends anything — expiry is unconditional.

### 5. Record: emergency state is a pure function of the log, forever reconstructible

Emergency state is not stored as mutable state, and — the correction the review
forced — it is *not* a pure function of per-replica admission clocks either.
Because admission time is station-local and re-stamped on replicas (§2), the
authority is the **station-signed `emergency_activated` attestation** (§2): the
station evaluates the boundary once, at admission, and freezes it into a signed,
replicated record. Whether a given proposal ran under emergency is then a
function of *signed records*, which every replica reads identically:

```
emergency_active_for(proposal P) :=
    ∃ an emergency_activated record A (station-signed) and no emergency_lapse
      superseding A, such that
        A was admitted before P,
        A.renewal_count did not exceed the §4 cap and A's activation was not
          refused by the §4 cooldown (both derivable from prior signed
          activation records), and
        A.activation_instant < station_admission(P) ≤ A.effective_expiry
```

where `station_admission(P)` is the station's own attested admission of `P`
(§3a), not a replica's re-stamp. Every input — which co-signature crossed the
threshold, the attested activation instant and effective expiry, whether a lapse
arrived first, whether the cooldown refused activation — is a *station-signed*
record at a definite log position, so every replica, every read-replica, and a
station re-bootstrapped by outbox replay (ADR-0020) all compute the identical
answer, and *which window governed every admission is reconstructible for all
time* (T2.8.2 invariant 1). An `Emergency` proposal's window is
`emergency_window_secs` iff `emergency_active_for(P)`; a proposal whose station
admission falls one second past `effective_expiry` runs the ordinary window.
This is the ADR-0015 grace discipline (`in_grace` derivable from the log) made
replica-safe by the ADR-0005/0022 station-signed-restatement pattern, because an
emergency's boundaries are far more consequential to get identically right on
every device than grace's are.

### 6. Abuse review: visible while it holds, flagged after, amendable always

- **Visible.** Emergency state is surfaced over RPC and to the phone banner
  exactly as bootstrap grace is (ADR-0015 §5): a member is never told a
  compressed-window vote was an ordinary one. The banner names the active
  emergency, its reason, and its expiry.

- **Flagged and reviewable.** Every measure passed under an emergency is
  identifiable by replay (an `Emergency` proposal admitted under an active
  declaration), which makes an honest post-emergency review possible without new
  machinery. The overview's "logged and subject to post-emergency review" is
  satisfied by the log itself; a community that wants a *mandatory* automatic
  review may adopt it as a statute. We recommend against *building in* a
  compulsory dispute per emergency (Consequences explains why).

- **Amendable always, and self-lapsing regardless.** Because the charter is
  frozen (§3b) and every emergency measure expires (§1), nothing enacted under
  emergency can be entrenched: it repeals itself at `expires_at`, and in the
  meantime is a repealable measure like any other once normal governance resumes.
  Emergency power buys speed for a temporary measure; it never buys permanence.

### Non-goals

Named explicitly, so the scope limit is in the permanent record and not only in
review comments:

- **No emergency power over the ledger.** The debt floor (ADR-0018), settlement
  and dispute windows (ADR-0011/0014), offline certificates (ADR-0021), and
  reputation (ADR-0009) are untouched by the emergency state, by construction —
  the state is never read by `rrn-ledger` or `rrn-reputation`. A flood emergency
  does not authorize economic restructuring (overview §2.7).
- **No new governance role.** No executive, council, or operator office is
  created; the declarers are the ordinary electorate (§2).
- **No lowered bar.** Emergency changes *how long* you have to reach a threshold,
  never *how high* it is (§3).
- **No general governance re-anchoring — but the emergency path is
  non-negotiably admission-anchored.** This ADR does not re-anchor *ordinary*
  governance windows to the admission clock (ADR-0022 never did, and doing it
  generally is a larger change). It *requires* the emergency declaration, window,
  and expiry to be admission-anchored (Context), and flags the broader gap as
  recommended follow-up (Consequences), but does not decide it here.
- **No machine-enforced scope.** `reason`/`scope` are testimony and display; the
  machine does not verify that an `Emergency` measure is germane to the declared
  crisis (Alternatives explains why not, and Consequences names the residual).

## Consequences

### Coup-risk analysis (the reason this ADR is cautious)

The attack this mechanism most plausibly enables: **a supermajority faction
declares an emergency, files an ordinary power measure as an `Emergency`
proposal, and rams it through in hours — before dispersed or offline members can
see it, deliberate, or organize.** Compression removes the §2.4 exit runway by
construction — that is what compression *is* — so this risk cannot be designed to
zero, only bounded. The bounds this ADR places on it:

1. **Declaration is collective, not unilateral** (§2): a supermajority of the
   electorate must co-sign before *any* window compresses.
2. **The passing bar does not fall** (§3): a measure still needs 67% approval.
   Speed never lowers the threshold, so a faction that lacks a real supermajority
   cannot pass a real measure fast.
3. **The measure lapses** (§1): a compressed-path measure carries a bounded,
   enforced `expires_at`, so nothing durable can be enacted fast — durability
   still costs the ordinary process. This is the answer to the "narrow by effect,
   not content" gap.
4. **The constitution is frozen** (§3b): the rules of the game cannot be
   rewritten under the crisis, so power cannot be *restructured*, only
   temporarily exercised.
5. **The electorate is pinned** (§3c), denominator *and* eligibility, so the
   deciding body cannot be packed mid-emergency.
6. **It self-expires fast and cannot be sustained** (§4): 72 h default; renewal
   is a fresh supermajority act; the cap and cooldown are proximity-derived, so
   serial re-declaration cannot manufacture a perpetual emergency.
7. **It is visible while it holds and flagged after** (§6).

**Residual risks, stated plainly:**

- **Emergency structurally favours the connected.** A co-present faction that
  *also* holds a real supermajority of the *reachable* electorate can pass fast,
  temporary measures that partitioned members will not see until they are already
  admitted. The window floor (§3) mitigates but cannot eliminate this — the lower
  a community sets `emergency_window_secs`, the more it becomes an in-person,
  connected-members-only decision. This is an honest cost of deciding in a crisis.
- **Freeze-as-a-lever, and measure-cycling at the ceiling.** The charter freeze
  (§3b) is a protection, but its inverse is a lever: a 67% faction can declare an
  emergency *specifically* to freeze an amendment that would curb it, and can
  *cycle* emergencies to extend both the freeze and a "temporary" measure. The §4
  cap-plus-cooldown makes a perpetual emergency *state* impossible, but the
  ceiling numbers should be stated honestly: at the 14-day ceiling with two
  renewals, one chain runs ~42 days; the cooldown bound (`≥` the chain's total
  duration, §4) then forces at least ~42 days *outside* emergency before the next
  chain — so a faction cannot hold the charter frozen, or a re-filed measure in
  force, more than roughly **half** the calendar time, and at the 72 h default far
  less. That the cooldown must exceed `EMERGENCY_MEASURE_GRACE` is what stops a
  lapsing measure's grace from dovetailing straight into the next chain's re-pass.
  Half-time cycling by a standing two-thirds supermajority is a real residual, not
  fully closed; the honest backstops remain the supermajority itself, the frozen
  charter (they cannot entrench the cycle), and full visibility.
- **Scope is testimony, not enforcement.** `reason`/`scope` are free text; the
  machine cannot verify that an `Emergency` measure is germane. A "flood response"
  declaration can host a measure that is really a power play. The backstops are
  the ones above — the raised bar, the frozen charter, the pinned electorate, the
  enforced measure expiry, visibility — plus the community's own review; machine
  scoping is considered and rejected as brittle (Alternatives).
- **A mandatory automatic review could itself be weaponized.** A compulsory
  dispute per emergency would let bad actors tie up every legitimate emergency in
  process, chilling the exact fast response the mode exists to enable. Review is
  therefore *possible and honest* (the log flags everything), not *compulsory* —
  the residual being that, absent a community's own discipline, an emergency
  measure can pass and simply never be revisited before it lapses.
- **A tiny or bootstrap electorate compounds.** During bootstrap grace (ADR-0015)
  a three-founder community reaches a 67% declaration bar at two signatures and
  passes emergency measures with two ballots; the general small-electorate
  critique (overview §2.8, threat model) applies, and emergency *adds* compression
  on top. Named for honesty; the mitigation is the same as grace's — the numbers
  reflect the true size of the deciding body.

### Other consequences

- **A real crisis is now serviceable by a stock binary.** A storm-night fuel
  authorization that must pass in hours can, given a co-present supermajority, and
  what it passes lapses on its own.
- **The Phase-1 `Emergency` kind gains its missing half and loses a latent bug.**
  It already dropped the implementation delay; it now gains the compressed
  *decision* window the code flagged as deferred (only under a declaration), and
  its long-inert `expires_at` becomes bounded and enforced.
- **Governance must finally meet the admission clock — at least on this path.**
  Shipping a compressed window on the author's `created_at` would be unsafe
  (Context), so T2.8.2 must anchor the emergency declaration, window, and expiry
  on admission time (ADR-0022). This surfaces the broader, pre-existing gap that
  ADR-0022 never re-anchored *ordinary* governance windows either; closing that
  generally is recommended follow-up, not decided here (Non-goals).
- **A new capture surface must be threat-modeled.** `docs/threat-model.md` has no
  emergency/coup section today; T2.8.2 must add one — assets: the integrity of the
  compression gate, of the enforced measure-expiry, of the position-pinned
  electorate, and of the station-signed emergency boundary; threats: squatting the
  declaration lever, fast-path capture of the connected electorate, an
  unbounded-`expires_at` durable measure, a self-reset renewal index,
  freeze-as-a-lever and measure-cycling, back-dated reputation evidence packing a
  time-pinned electorate, replica divergence if the boundary is not
  station-signed, and back-dated windows if admission-anchoring is skipped;
  mitigations: §§1–5; residuals: those named above.
- **Four new signed record kinds and their fixtures.** Three member-signed —
  `emergency_declaration`, `emergency_cosign`, `emergency_lapse` — and one
  **station-signed**, `emergency_activated` (§2), the attestation that makes the
  emergency boundary replica-identical. Each needs a distinct discriminator,
  `From/TryFrom<CBOR>`, roundtrip tests, and a committed CBOR fixture for the
  mobile repo (PROCESS.md). A renewal is *not* a new kind — it is a declaration
  whose continuation status is derived (§4); a compressed proposal's window end
  is a station attestation on the proposal's admission, not a fifth kind.
- **One predicate, carefully scoped.** `emergency_active` becomes a governance
  input the way `in_grace` did, but — unlike grace — it is deliberately withheld
  from the ledger, so its blast radius is one window, two freezes, and a measure
  cap, no more.

## Alternatives Considered

**On whether to have the mode at all, and who triggers it (Question 1):**

- **No emergency mode; keep the seven-day window.** Rejected: it makes the
  community ungovernable exactly when governance matters most, and the overview
  names fast crisis decision-making as a required Phase-2 deliverable.
- **Operator (or a new "executive/council") declares by fiat.** The overview's
  sketch says "a council or executive role," and a single declarer is fastest.
  Rejected: Phase 1 has no such role, and *creating* one is precisely the power
  ladder §2.8 warns against — a standing office that can unilaterally compress
  windows is a coup mechanism with a title. A supermajority collective act (§2)
  keeps the speed without minting a privileged declarer.

**On what changes (Question 2):**

- **Full parameter freedom: compress or waive any window, including settlement,
  dispute, quorum, and the approval bar.** Rejected outright: it converts "decide
  faster" into "suspend every protection at once," which is the whole content of
  the scope limit. Compressing the *economic* windows in particular strips members'
  dispute protection when they are most exposed.
- **Emergency lowers the quorum/approval bar instead of (or as well as)
  compressing the window.** Tempting when few members are reachable. Rejected:
  lowering the bar is how a *minority* passes a measure a majority would reject —
  the classic captured vote. Emergency changes how long you have to reach the bar,
  never how high it is.
- **Machine-enforced scope: tag statutes with categories and forbid an emergency
  measure from touching categories outside its declared domain.** Rejected for now
  as brittle: an expressive-enough taxonomy is complex enough to be gamed or to
  block a legitimate germane measure, and the enforcement becomes a capture
  surface itself (who defines the categories?). We accept `scope` as testimony and
  lean on the raised bar, the frozen charter, the pinned electorate, enforced
  measure expiry, and visibility — flagging machine scoping as future work if the
  advisory limit proves insufficient in the pilot.
- **Leave `expires_at` unbounded (the Phase-1 status quo).** Rejected: combined
  with the compressed window it produces permanent law from a fast vote, breaking
  the Sunset rule (§1).

**On expiry (Question 3):**

- **"Until lifted" / operator-terminated emergency.** Rejected: it inverts the
  burden the overview places on *renewal*, and a mode that must be actively ended
  is a mode that quietly persists. Automatic expiry with the default off is the
  self-terminating shape ADR-0015 established.
- **Long fixed duration (the overview's 7–14 days as the default).** Rejected as
  the *default*: a two-week compressed-governance window is a long time to hold
  the exit runway shut. We keep 14 days as the charter *ceiling* but default to
  72 h, so the conservative choice ships and the community can opt into the band.
- **Trust `stated_renewal_index` for the cap.** Rejected: the declarer chooses the
  field, so a self-reset defeats the cap (§4); proximity-derived counting is the
  only tamper-resistant version.

**On the record (Question 4):**

- **A station-stored emergency flag / mutable "emergency mode" row.** Rejected: a
  *mutable* flag breaks the source-of-truth invariant (state must be
  replay-derivable), so replicas could disagree on whether a given past vote ran
  under emergency, and the history would not be reconstructible. Note the distinct
  thing this ADR *does* adopt (§2, §5): an **append-only, station-signed
  `emergency_activated` attestation** is not a mutable flag — it is a signed log
  record like `ProposalImplemented`, replicated and immutable, which is precisely
  how ADR-0022 §1 says a station-local decision (here, the admission-timed
  activation boundary) must be restated to stay replica-identical. The alternative
  rejected is mutable station state; the mechanism chosen is a signed record.

**On abuse review (Question 5):**

- **Mandatory automatic post-emergency dispute review.** Rejected as a built-in: a
  compulsory review per emergency is itself weaponizable to chill legitimate fast
  response (Consequences). The log makes review *possible*; a community may make it
  *mandatory* by statute.

## Implementation sketch (for T2.8.2)

**Crates touched:**

- `rrn-governance` — the four record kinds; the `emergency_active_for` predicate
  (§5) reading the **station-signed `emergency_activated`** attestation, plus the
  proximity-based renewal count and chain-scaled cooldown (§4); the
  compressed-window derivation, the ballot rule (§3a), and the §1 bounded,
  **enforced** `expires_at` in `proposal.rs`/`statute.rs`/`lifecycle.rs`
  (`expires_at` is inert today — enforcement in `enacted_statutes` is new); the
  charter-freeze (on the **effective charter**, both the amendment path *and*
  `founder_charter`'s highest-version path, §3b) and the electorate-pin logic;
  and — the precondition — admission-clock anchoring, under which the signed
  `voting_ends_at`/`implementation_at` (derived from author `created_at`) become
  non-authoritative for an Emergency-under-declaration proposal, the `vote.rs`
  ballot-window check moves to station admission, and declarer/co-signer
  eligibility is judged at admission position, not author-clock `cosigned_at`.
- `rrn-reputation` — a **position-bounded** `established_members`/`grace_electorate`
  variant (today's helpers take a wall-clock `at`; §3c needs a log-prefix bound to
  defeat back-dated evidence).
- `rrn-station` — the station-signed `emergency_activated` attestation and the
  per-proposal admission attestation on the writer path; **DTN routing**:
  `route_dtn_record` and the airtime classifier must learn the emergency (and,
  as a prerequisite, the governance) kinds — they are `UnroutableKind` today, so
  without this the partition story does not hold; and RPC/banner surfacing of
  emergency state, mirroring the grace banner.
- `rrn-cli` — declare / co-sign / lapse / status verbs and display.

**New charter parameters** on `GovernanceStructure`: `emergency_window_secs`,
`emergency_declaration_pct`, `max_consecutive_renewals`, and the duration
floor/ceiling — each bounded by a hard constant a charter cannot breach
(`EMERGENCY_WINDOW_FLOOR_SECS`, `EMERGENCY_DECLARATION_PCT_FLOOR`,
`EMERGENCY_DURATION_FLOOR/CEILING`, the renewal-cap ceiling), plus
`EMERGENCY_MEASURE_GRACE` and `EMERGENCY_COOLDOWN_SECS` (the latter `≥` a chain's
total duration and `>` the grace). The declaration's requested `duration_secs` is
the sole length source, clamped to the floor/ceiling (no separate charter
duration param). **Record kinds:** four —
`rrn.gov.emergency_declaration`, `rrn.gov.emergency_cosign`,
`rrn.gov.emergency_lapse` (member-signed), and `rrn.gov.emergency_activated`
(station-signed) — each with a discriminator, canonical dCBOR, roundtrip tests,
and a committed fixture; plus the threat-model STRIDE section. **Two load-bearing
preconditions, called out for the reviewer:** (i) the emergency boundary must be
a **station-signed** fact, not a per-replica admission-clock computation, or two
replicas disagree on which window governed a past vote (T2.8.2 invariant 1);
(ii) the emergency path must be **admission-anchored** (ADR-0022), because a
compressed window on the author clock is trivially back-dated. Neither is
optional.

## References

- [ADR-0012](0012-charter-format-and-amendments.md) — the Charter, its
  parameters, the electorate, and the amendment lineage this ADR freezes during
  an emergency.
- [ADR-0014](0014-phase-1-dispute-resolution.md) — the dispute window this ADR
  deliberately does **not** compress.
- [ADR-0011](0011-oracle-tier-model-phase-1.md) — the settlement window this ADR
  deliberately does **not** compress.
- [ADR-0015](0015-electorate-bootstrap-grace.md) — the rule-relaxing-mode-with-
  automatic-exit precedent this ADR follows, and the grace electorate an
  emergency's declarers are drawn from.
- [ADR-0020](0020-single-writer-log-dtn-submission.md) — single-writer log and
  DTN submission; why a declaration must be a courier-carried signed record and
  no governance tally closes until admission.
- [ADR-0022](0022-admission-clock-time-trust.md) — the admission clock; the rule
  this ADR extends to the emergency governance path, and the gap (governance
  windows on the author clock) it surfaces.
- [ADR-0021](0021-escrowed-offline-spending-certificates.md) — the DTN delivery
  grace (14 days) that bounds the outer duration ceiling considered here.
- Design overview §2.4 (implementation delay as exit runway), §2.7 (the emergency
  governance sketch this ADR locks), §2.8 (governance capture as the existential
  threat), §12 (the Phase-2 deliverable).
