# 0023 — Emergency governance: deciding faster in a crisis without building a coup lever

## Status

Accepted

Date: 2026-09-08 (ratified 2026-09-08)

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
> active) must carry `expires_at ≤ scheduled_expiry(emergency at proposal
> admission) + EMERGENCY_MEASURE_GRACE`, where `scheduled_expiry` is the
> emergency's `activation_instant + duration_secs` as attested at the proposal's
> admission (§2). The recommended grace is one ordinary `implementation_delay_days`
> (7 days): long enough to legislate a durable replacement through the *normal*
> full-window process, not long enough to be a standing law. Making a crisis
> measure permanent therefore always costs the ordinary process.

The bound is checked against the **scheduled** expiry, deliberately, and this
resolves a subtlety the review surfaced: the bound is evaluated at *proposal
admission*, when no early `emergency_lapse` may exist yet, so it cannot depend on
one. An early lapse ends the *emergency* going forward — it stops compression, the
freeze, and the pin (§4) — but it does **not** retroactively re-shorten a measure
that already passed: that measure runs to its own signed `expires_at`. Anything
else would make an enacted statute's effective lifetime differ from its signed
content and force a second station-signed restatement per measure; the scheduled
bound avoids that entirely, at the cost of a measure outliving an early-lifted
emergency by at most the grace — an acceptable, and visible, slack.

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
it enforced would be the bug. And because enforcing it kind-wide now gives the
*un*-declared Emergency kind — an "immediate effect at 67%, no exit runway"
instrument with, today, no lifetime bound at all — a bound too: an Emergency
measure passed with **no** active declaration must carry
`expires_at ≤ voting_ends_at + 30 d`, so the ordinary-path Emergency kind cannot
be a permanent law either. This is consistent with the Sunset rule and closes a
latent hole the compressed path would otherwise have left beside it.

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
  privileged declarer *is* the power ladder we are trying not to build. Unlike an
  ordinary proposal (where the author cannot co-sign their own motion), the
  **author's own signature counts toward the declaration threshold** — a
  declaration is a signed act, not a motion seeking endorsement, so there is no
  "other members" subtraction to reason about.

- **The threshold is a supermajority, stated as an exact integer, and it is the
  primary anti-abuse defense.** The declaration takes force at the admission of
  the co-signature that brings the count of **distinct electorate signatures
  (the author's included)** to at least `ceil(N × emergency_declaration_pct /
  100)`, where `N` is the size of the electorate at the **log position of the
  crossing co-signature** (§3c's position-bounded rule, applied to the
  denominator too — so `N` and the count have one deterministic answer, computed
  the way `founder_threshold` computes `ceil(n × 3 / 4)` in integer arithmetic).
  Recommended default `emergency_declaration_pct` = **67%**, with a floor
  `EMERGENCY_DECLARATION_PCT_FLOOR = 67%` — a charter may raise this bar but
  **never lower it below two-thirds** (§4 explains why every emergency parameter
  needs a floor). Worked cases: a 20-member electorate needs `ceil(20 × 0.67)` =
  14 signatures; a 3-member grace electorate needs `ceil(3 × 0.67)` = 2 (author
  plus one). Requiring a supermajority *collective* act to unlock compression is
  what stops a faction from squatting on the emergency lever: one member, or a
  bare majority, cannot compress anything. (A small electorate makes 2 signatures
  a real emergency — named honestly in Consequences.)

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
  station-attested `activation_instant`, the `scheduled_expiry`
  (`= activation_instant + duration_secs`), and the log-derived `renewal_count`
  of §4), written by the station when it admits the
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
| Decision window (Emergency-kind proposals) | `deliberation_window_days` (7 d) | `emergency_window_secs` (charter; default **24 h**) | Clamped to hard floor `EMERGENCY_WINDOW_FLOOR_SECS` = **24 h**; **compresses, never below the floor** (§3, "window floor") |
| Implementation delay | `implementation_delay_days` (7 d) | 0 | Already the Emergency kind's behaviour; unchanged |
| Measure lifetime (`expires_at`) | n/a | `≤ scheduled_expiry + EMERGENCY_MEASURE_GRACE` (7 d), **enforced** | §1 — a compressed-path measure must lapse |
| Approval bar | `statute_approval_pct` (50%) | `emergency_threshold_pct` (67%) | **Raised, never lowered** — speed does not cheapen passage |
| Quorum | `statute_quorum_pct` (30%) | `emergency_quorum_pct` (**50%**) | **Raised, floor 50%** — the measure bar must not be *lower* than the declaration's collective act (§3, "measure quorum") |
| Declaration bar | n/a | `emergency_declaration_pct` (67% of electorate, author included) | Floor 67%; charter may raise, never lower (§2) |
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

**On the measure quorum.** The emergency raises the *quorum* for a compressed-path
measure to `emergency_quorum_pct` (default 50%, floor 50%), and this is not
cosmetic — it closes an inversion the design would otherwise have. The
declaration is a hard collective gate (67% of the *whole* electorate must
sign, §2), but the measure it unlocks would, at the ordinary `statute_quorum_pct`
(30%), pass on a turnout of 6 of 20 — so a storm declaration co-signed by
everyone would become a fast lane on which a handful decide, at the ordinary bar,
for the emergency's life. The code already anticipated this: `tally.rs` notes
"configurable emergency quorum is Phase 2." Raising the measure quorum to a
majority of the *pinned* electorate keeps the deciding body's size honest: an
emergency compresses *time*, but the number of people who must actually turn out
to bind everyone does not fall below half. The approval bar stays the raised 67%
of decisive votes; neither bar is ever *lowered* (Non-goals).

**On the window floor's honesty.** `EMERGENCY_WINDOW_FLOOR_SECS` cannot make a
compressed window "DTN-safe": under ADR-0020 a confirmation "carried for three
days settles three days late," and nothing measured in *hours* can include a
member whose carrier takes *days*. So the floor is not about DTN inclusivity at
all — it is about how much *notice* the reachable-but-absent get, and the one
DTN-real notice number the system already commits to is ADR-0011's **Tier-1 24 h
settlement window**: the minimum a member gets to contest even a small trade. A
statute that binds everyone should not get *less* notice than a 5-Common trade,
so the floor is **24 h**, equal to the default — the window is not
charter-lowerable in Phase 2. One honesty this forces: the Context's "fuel before
dawn" urgency is **not** served by any floor on offer — a same-night decision is
below every number here — and, more fundamentally, governance authorizes but does
not *move* credit (ADR-0012), so "spend on fuel" is an act a member takes, not a
tally the station closes in hours. The value a fast window actually delivers is
collective, visible, expiring *authorization*, not disbursement; the ADR states
that plainly rather than implying an hours-scale spend.

### 4. Expiry: automatic, short, renewable only by a fresh collective act, and hard-capped by log-derived proximity

- **Automatic.** An emergency ends when `activation_instant + duration_secs ≤ now`
  at the admission of the record being judged. There is no "until lifted"; the
  *default* state is off, and staying on takes work.

- **Short, with a ceiling derived from the ordinary process — not analogised.**
  The declaration's requested `duration_secs` is the sole source of one
  emergency's length, clamped to `[EMERGENCY_DURATION_FLOOR,
  EMERGENCY_DURATION_CEILING]` — there is no separate charter "duration"
  parameter; the charter tunes only the floor/ceiling, themselves bounded by hard
  constants. Recommended default (an absent/typical request) **72 h**, floor
  **24 h** (an emergency shorter than a day is not worth the ceremony), and a
  **per-declaration ceiling of 7 days**. The ceiling is *derived*, not borrowed:
  the whole thesis of §1 is that durability must cost the ordinary process, and
  the ordinary process takes exactly `deliberation_window_days +
  implementation_delay_days` = **14 days** to put a statute into effect. An
  emergency longer than that exists only to *avoid* a process that could have
  completed meanwhile, so no single declaration may run longer than half of it
  (7 days), and no *chain* (§4, next bullet) longer than all of it (14 days). This
  supersedes an earlier draft that set the ceiling at 14 days by analogy to
  ADR-0021's DTN delivery grace — a carriage-latency number with no bearing on how
  long a community should hold its exit runway shut; the derived bound is the
  right one, and it keeps a chain inside the overview's "7–14 day" band while the
  default stays a conservative 72 h.

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

- **Two caps — a count and a duration — then a fixed cooldown.** A count cap
  alone bounds nothing useful (three 7-day activations is still 21 days), so a
  chain is capped on *both*: at most `MAX_CONSECUTIVE_RENEWALS` renewals (recommend
  **2** — three activations) **and** at most `EMERGENCY_CHAIN_MAX_SECS` = **14
  days** of total active time across the proximity-derived chain (the running
  total T2.8.2 accumulates as it admits each continuation). Whichever binds first
  ends the chain. Then a **fixed** cooldown: `EMERGENCY_COOLDOWN_SECS` = **14
  days**, a plain constant — not the earlier draft's "≥ Σ chain durations," which
  was circular (continuation is *defined* by proximity within the cooldown, so a
  cooldown that depends on the chain it gates cannot be evaluated in one pass). A
  fixed 14 days is `≥` any 14-day-capped chain and strictly `>`
  `EMERGENCY_MEASURE_GRACE` (7 days), which gives the same **≤ 50% duty cycle**
  and stops a lapsing measure's grace from dovetailing straight into the next
  chain's re-pass — while staying a pure constant replay can check. Any
  declaration whose activation would fall within the cooldown of a chain's end
  simply **does not activate**. The honest cost, which the earlier draft skipped:
  the cooldown also refuses a *genuine* second crisis — a storm, then a flood ten
  days later — and 14 days is chosen as tolerable for that, where a 42-day cooldown
  would not be. Both caps and the cooldown are pure functions of admission times;
  no free-text statute is parsed. This makes a *perpetual emergency state*
  impossible; it bounds, but does not forbid, a faction *cycling* emergencies,
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
  co-signature, ending the emergency's **compression, freeze, and pin from that
  admission forward**; a measure that already passed keeps its own signed
  `expires_at` and is *not* retroactively shortened (§1), which is why the measure
  bound is checked against the *scheduled* expiry and no per-measure restatement is
  needed. The *absence* of a lift never extends anything — expiry is unconditional.

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
        A.activation_instant < station_admission(P) ≤ A.scheduled_expiry
          (and, if an emergency_lapse superseded A before P, no later than that
           lapse's admission)
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
admission falls one second past `scheduled_expiry` (or past an early lapse) runs
the ordinary window.
This is the ADR-0015 grace discipline (`in_grace` derivable from the log) made
replica-safe by the ADR-0005/0022 station-signed-restatement pattern, because an
emergency's boundaries are far more consequential to get identically right on
every device than grace's are.

### 6. Abuse review: visible while it holds, flagged after, amendable always

- **Visible.** Emergency state is surfaced over RPC and to the phone banner
  exactly as bootstrap grace is (ADR-0015 §5): a member is never told a
  compressed-window vote was an ordinary one. The banner names the active
  emergency, its reason, and its expiry.

- **Flagged, and served as a report.** Every measure passed under an emergency is
  identifiable by replay (an `Emergency` proposal admitted under an active
  declaration). The overview's "logged and subject to post-emergency review" is
  met not by a mandatory dispute but by a **derived, station-served emergency
  report** (RPC + CLI, **no new record kinds**): for each activation it lists the
  declaration, its co-signers, every measure passed under it, and each measure's
  expiry; the banner shows "passed under emergency X, expires Y" until the measure
  lapses. A community that wants a *mandatory* review may still adopt one by
  statute, but the accountability requirement is satisfied by a surface the log
  already supports rather than a statute a community might never pass. We do not
  *build in* a compulsory dispute (Consequences explains the real reason — there
  is no machine effect for its verdict to reverse).

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
- **No general governance re-anchoring *in this ADR* — but it is owed, as
  conformance, before T2.8.2.** This ADR decides only the emergency path's
  admission anchoring. Re-anchoring *ordinary* governance windows and eligibility
  is **not a new decision** — ADR-0022 already ruled the admission clock "the only
  clock that bears on windows, deadlines, ordering, and eligibility," so today's
  author-clock governance (`proposal.rs`, `vote.rs`) is a *conformance gap against
  an Accepted ADR*, not a design question. It therefore needs **no new ADR**, but
  it does need its own ticket (**T2.1.3**, filed with this work), and that ticket
  must land **before T2.8.2** — otherwise the crate carries two window regimes and
  two eligibility gates at once, doubling the derivation and its tests. That
  ticket also fixes a **live ordinary-path bug** this ADR's §3c analysis exposed:
  `tally.rs` pins the electorate at `voting_ends_at` by *time* (`grace_electorate(
  db, founders, at_time)`), so a vouch admitted after a vote closes but back-dated
  earlier (legal under ADR-0022 §3) silently changes a *concluded* tally's
  denominator on replay — contradicting the "concluded quorum stays stable"
  guarantee. This ADR closes that hole for emergencies (position-bounded pin);
  T2.1.3 closes it everywhere.
- **No machine-enforced scope — with one forward pre-commitment.** `reason`/`scope`
  are testimony and display; the machine does not verify that an `Emergency`
  measure is germane to the declared crisis (Alternatives explains why not, and
  Consequences names the residual). But one bound is worth committing to the
  record now, because it becomes enforceable the moment it matters: **when the
  statute→config rule engine lands** (the ADR-0012 follow-up that gives a passed
  statute a mechanical effect), **a compressed-path measure may not mutate any
  charter or config parameter.** That is machine-checkable without any taxonomy —
  it is a flat "no config writes on the fast path" — and it closes, in advance,
  the future world in which a fast measure could quietly re-tune the very
  parameters (quorum, windows, the emergency constants themselves) that bound it.

## Consequences

### Coup-risk analysis (the reason this ADR is cautious)

First, what the mechanism actually *creates*, since it bounds the whole analysis:
an emergency's only **mechanical** effects are the compressed window, the
**charter freeze**, and the **electorate pin**. A passed statute binds nothing by
itself today — governance does not move credit or execute anything (ADR-0012) —
so the fear is not that a fast measure "does" something in the ledger; it is that
the freeze and the pin, plus a fast, low-visibility *authorization*, tilt the
community's politics. The coup-risk analysis is therefore written around the
freeze and the pin, not around an imagined economic action a governance measure
cannot take.

The attack this mechanism most plausibly enables: **a supermajority faction
declares an emergency, files an ordinary power measure as an `Emergency`
proposal, and rams it through in hours — before dispersed or offline members can
see it, deliberate, or organize.** Compression removes the §2.4 exit runway by
construction — that is what compression *is* — so this risk cannot be designed to
zero, only bounded. The bounds this ADR places on it:

1. **Declaration is collective, not unilateral** (§2): a supermajority of the
   electorate must co-sign before *any* window compresses.
2. **Neither passing bar falls, and the quorum *rises*** (§3): a measure still
   needs 67% approval of decisive votes, and — the fix for the declaration-harder-
   than-measure inversion — its quorum rises to a majority (`emergency_quorum_pct`,
   50%) of the *pinned* electorate. Speed never lowers a threshold; the number who
   must turn out to bind everyone stays at least half.
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
  caps make a perpetual emergency *state* impossible, but the ceiling numbers
  should be stated honestly: a chain runs at most **14 days** (the duration cap,
  reached as two 7-day activations or three shorter ones), then a **fixed 14-day
  cooldown** forces an equal span *outside* emergency before the next chain — a
  **≤ 50% duty cycle**, and at the 72 h default far less. Because the cooldown
  (14 d) exceeds `EMERGENCY_MEASURE_GRACE` (7 d), a lapsing measure's grace cannot
  dovetail straight into the next chain's re-pass. Half-time cycling by a standing
  two-thirds supermajority — one that also musters the 50% emergency quorum each
  time — is a real residual, not fully closed; the honest backstops remain the
  supermajority itself, the raised quorum, the frozen charter (they cannot
  entrench the cycle), and full visibility. The same 14-day cooldown has a
  symmetric cost, named for honesty: it will refuse a *genuine* unrelated second
  crisis inside the fortnight.
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

- **A real crisis is now serviceable by a stock binary — as fast collective
  *authorization*, not disbursement.** Given a co-present supermajority, a
  community can pass a binding, visible, self-expiring measure in a day rather
  than a week. What that measure is, honestly, is *authorization and mandate* — a
  member still acts on it (governance does not move credit, ADR-0012) — and the
  24 h floor means it is a day, not the Context's literal "before dawn." The value
  is real; the ADR just refuses to overstate it as an hours-scale spend.
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
  from the ledger, so its blast radius is one window, a freeze, a pin, and a measure
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
- **No declaration at all: let an Emergency proposal close early on arithmetic
  certainty.** Since a co-present group can bundle the whole thing at once anyway,
  a simpler fast lane exists — an `Emergency` proposal closes at the earlier of its
  ordinary window or the admission of the ballot that makes passage certain
  against the position-pinned electorate (≥ the approval bar of the whole
  electorate). Zero new record kinds, no declaration lever to squat, no cooldown.
  Rejected deliberately, and it is the closest alternative: early-close buys speed
  but gives up the three things the declaration is *for* — the **notice period**
  the compressed window still guarantees the absent, the **banner/visibility** that
  a fast decision is happening, and the **charter freeze + electorate pin** that
  keep the fast lane from being used to restructure power. Those three are worth
  the four record kinds; a mechanism that only makes a *certain* vote close sooner
  protects no one who was not already present. We keep the declaration.

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
- **Long fixed duration (the overview's 7–14 days as the default), or a 14-day
  per-declaration ceiling.** Rejected: a two-week compressed-governance window is
  a long time to hold the exit runway shut, and a 14-day *single* declaration was
  an earlier draft's mistake (it borrowed ADR-0021's carriage-latency grace as if
  it bounded political duration). We derive the ceiling from the ordinary
  time-to-effect instead (§4): **7 days per declaration, 14 days per chain**, with
  a 72 h default — so the conservative choice ships, a real multi-week crisis still
  gets one renewal, and nothing runs longer than the ordinary process it is
  substituting for.
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

**Sequencing:** **T2.1.3** (admission-clock conformance for governance — Non-goals)
must land **before** this ticket, so the emergency path is not built atop
author-clock windows. **New charter parameters** on `GovernanceStructure`:
`emergency_window_secs`, `emergency_declaration_pct`, `emergency_quorum_pct`,
`max_consecutive_renewals` — each bounded by a hard constant a charter cannot
breach (`EMERGENCY_WINDOW_FLOOR_SECS` = 24 h, `EMERGENCY_DECLARATION_PCT_FLOOR` =
67%, `EMERGENCY_QUORUM_PCT_FLOOR` = 50%, `EMERGENCY_DURATION_FLOOR` = 24 h /
`EMERGENCY_DURATION_CEILING` = 7 d, the renewal-cap ceiling) — plus the standalone
constants `EMERGENCY_MEASURE_GRACE` (7 d), `EMERGENCY_CHAIN_MAX_SECS` (14 d), and
`EMERGENCY_COOLDOWN_SECS` (14 d fixed). The declaration's requested `duration_secs`
is the sole length source, clamped to the duration floor/ceiling (no separate
charter duration param). `tally.rs` applies `emergency_quorum_pct` (not
`statute_quorum_pct`) on the compressed path; `enacted_statutes` enforces
`expires_at` kind-wide, bounding an *un*-declared Emergency measure to
`voting_ends_at + 30 d` (§1). `rrn-station` also serves the derived
**emergency report** (§6). **Record kinds:** four —
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

## Clarifications

*Clarifications record a corrected reading of the decision above; they do not change
it. Flagged for maintainer ratification alongside this ADR.*

- **2026-09-09 (T2.8.2) — the declaration threshold is a true two-thirds,
  `ceil(2N/3)`.** §2 states the bar as `ceil(N × emergency_declaration_pct / 100)`
  with `pct = 67`, but its worked cases fix the *intent* at two-thirds: a 3-member
  grace electorate needs 2 ("author plus one") and a 20-member one 14 — which is
  `ceil(2N/3)`, not `ceil(N × 67/100)` (that reads `ceil(2.01) = 3` at N=3, i.e.
  *unanimity*, and generally two-thirds+1 wherever N is a multiple of 3, the very
  sizes where two-thirds is exact). A `u8` percent cannot spell 66.67, and the ADR's
  own precedent — `founder_threshold`'s `ceil(n × 3/4)` — is an exact rational, not a
  percent. T2.8.2 therefore implements the floor value 67 as exactly `ceil(2N/3)`
  and any charter-**raised** bar literally as `ceil(N × pct/100)` (never below
  two-thirds, monotone in N and `pct`). Author-plus-one for three founders grants
  nothing ADR-0015 grace does not already grant, whereas a holdout veto would defeat
  §2's own co-present-supermajority partition rationale. See
  `rrn_governance::emergency::declaration_threshold`.

- **2026-09-09 (T2.8.2) — span boundary and genesis-resolved legitimacy parameters.**
  Two readings the implementation fixes: (i) §4's "ends when `activation_instant +
  duration_secs ≤ now`" and §5's `activation_instant < admission(P) ≤ scheduled_expiry`
  are reconciled in favour of §5 — a proposal is governed for admissions in the span
  `(activation_instant, scheduled_expiry]`; a record admitted in the exact second of
  activation is ungoverned (strict `<`), an immaterial one-tick edge. (ii) The
  parameters deciding **whether a past emergency was legitimate** — the declaration bar
  and the renewal cap — are resolved from the **immutable genesis (founder) charter**,
  not the amendable effective charter, so no post-emergency amendment can retroactively
  rewrite which activations were legitimate (invariant 1 / §5 "reconstructible for all
  time"); a signed-but-forgeable attestation field would instead let a forged
  attestation choose its own bar. The cost: those legitimacy parameters are effectively
  non-amendable in Phase 2 (the compressed-window seconds and the measure quorum —
  threshold *numbers* like the ordinary statute bars — still track the effective
  charter). A general position-bounded charter resolution, wanted by the ordinary tally
  thresholds too, is recommended follow-up.

*The two entries below are **open decisions raised by a second review (2026-09-10)**,
not settled readings: each states the gap and a recommended resolution but changes §2 /
§4 behaviour, so each needs a maintainer's call and is **not yet implemented**. They are
recorded here so ratification of this ADR settles them alongside the readings above.*

- **2026-09-10 (T2.8.2 review) — a declaration must activate only on its crossing
  co-signature, and a part-signed declaration should expire. [Open — pending
  ratification; not yet implemented.]** Two related gaps in the activation trigger.
  *(i) The activation instant is the crossing co-signature, and only it.* §2 says an
  emergency "takes force at the admission of the **co-signature that brings the count
  to ≥ threshold**." The implementation instead re-evaluates activation on *every*
  declaration/co-sign append while the count stands at or above the bar, anchoring the
  instant on whichever append it happens to run for. So a declaration whose crossing
  co-signature is refused for falling inside a §4 chain cooldown ("simply does not
  activate") can be **revived** by any later co-signature once the cooldown lapses —
  activating on consents gathered for the earlier, refused crisis — and every
  post-crossing co-signature needlessly re-derives the trigger. The intended, narrower
  rule is the one §2's text already implies: activation is judged **only for the record
  that is itself the crossing co-signature**, against the §4 caps as of that instant;
  a declaration the caps refuse at its crossing does not activate and is not retried on
  a later append. *(ii) A declaration/co-signature time-to-live.* Even under (i),
  nothing bounds how long a declaration may sit part-signed: a faction can gather
  `threshold − 1` co-signatures, hold one back, and fire it months later as a
  pre-signed trigger, crossing on long-stale intent. Re-judging every co-signer's
  eligibility at the crossing position (which this ADR already requires) *mitigates*
  this — a signer who has since left the electorate is dropped — but a still-eligible
  member's months-old signature still counts. ADR-0023 sets no TTL. **Recommended:** a
  declaration and its co-signatures cease to count toward activation if the threshold
  is not reached within a bounded window of the declaration's admission — a natural
  value is `EMERGENCY_DURATION_CEILING` (7 days): a crisis whose supermajority cannot
  be assembled within the longest single emergency is no longer the same crisis. A TTL
  measured from admission instants / log positions stays replica-deterministic
  (invariant 1). The maintainer's call is *whether* to add a TTL and *what* window.

- **2026-09-10 (T2.8.2 review) — competing lapse motions split the lift supermajority.
  [Open — pending ratification; not yet implemented.]** §4 says a lapse "carries the
  same co-sign supermajority as a declaration … reusing the `emergency_cosign` kind,
  whose `declaration_hash` target may be a declaration or a lapse," but does not say how
  co-signatures aggregate when **more than one** member raises a lapse against the same
  emergency. The implementation gives each `emergency_lapse` a distinct content hash
  (`H(declaration_hash, author)`), and a lapse co-signature targets one lapse hash — so
  two members each raising a lapse split the electorate across two hashes: against a
  14-of-N bar an 8/7 split ends the emergency by neither, though 15 members want out,
  and a faction member can pre-empt a genuine lift by raising a decoy lapse to force the
  split. The emergency still auto-expires, so severity is low, but a minority can
  frustrate an early lift the supermajority wants. **Recommended:** make a lift's
  co-signatures aggregate **per emergency, not per lapse record** — count every distinct
  eligible co-signer across all lapse records targeting the same `declaration_hash`
  toward one lapse threshold, or have lapse co-signatures target the `declaration_hash`
  under a "lapse" discriminator so the raiser's identity cannot partition the pool.
  Either keeps the lift boundary a log position (invariant 1). Relatedly, when two
  emergencies overlap, a lapse resolves against the *earliest* still-active one
  (`active_emergency_at` returns the earliest governing emergency), so the later of two
  overlapping emergencies cannot be lapsed until the earlier ends; overlaps are rare and
  bounded by expiry, but the maintainer should confirm this ordering is acceptable or
  ask for lapses to target a specific activation.
