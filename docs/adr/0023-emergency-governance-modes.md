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
> active) must carry `expires_at ≤ emergency_expiry + EMERGENCY_MEASURE_GRACE`,
> and `expires_at` is **enforced** — after it, the measure has no effect. The
> recommended grace is one ordinary `implementation_delay_days` (7 days): long
> enough to legislate a durable replacement through the *normal* full-window
> process, not long enough to be a standing law. Making a crisis measure
> permanent therefore always costs the ordinary process. (Enforcing `expires_at`
> at all is new work — today the field is inert; T2.8.2 wires it in.)

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
(`kind = "rrn.gov.emergency_cosign"`, referencing the declaration's content
hash), exactly mirroring the existing `rrn.gov.proposal_cosign` pattern so they
travel independently over DTN and are admitted as they arrive.

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
  parameter needs a floor). Requiring a supermajority *collective* act to unlock
  compression is what stops a faction from squatting on the emergency lever: one
  member, or a bare majority, cannot compress anything.

- **It is anchored on the admission clock.** The emergency is *active* from the
  admission time of the threshold-crossing co-signature — call this the
  **activation instant** — for `duration_secs` thereafter, measured by the
  station clock at admission (ADR-0022), never by any `created_at`. This is the
  same "late knowledge delays, never truncates" rule ADR-0022 applies to
  settlement: a declaration carried three days by courier begins its life on
  arrival, not retroactively. The activation instant is the single reference
  point every downstream rule (§3–§5) uses, so the mode has exactly one clock.

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
window becomes `emergency_window_secs` instead of `deliberation_window_days`.
Every other proposal kind — including an ordinary `Statute` raised during the
emergency — runs its normal, uncompressed window.

**(b) Charter freeze — community-wide while the emergency is active.** No
`CharterAmendment` proposal is *admitted*, and any already-open amendment's
*enactment* is *deferred* until the emergency lapses (its 30-day window keeps
running; it simply cannot take effect inside the emergency). The constitution is
the layer everything references (ADR-0012); an emergency that could rewrite it
could restructure power under cover of the crisis, so the rules of the game are
held fixed for the emergency's short life.

**(c) Electorate pin — community-wide, as of the activation instant.** Every
emergency tally counts the electorate as it stood at the activation instant (§2),
and this pin governs **both** the quorum denominator **and** ballot eligibility:
a member who becomes established *after* the activation instant is neither
counted in the denominator nor allowed to cast a valid emergency ballot. Pinning
only the denominator would leave the "declare, then manufacture new established
members, then vote" path open, so the pin must cover eligibility too.

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
| Electorate | live | **pinned at activation instant** (denominator + eligibility) | §3(c) |
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

- **Short, with floors and a ceiling.** `duration_secs` is clamped to
  `[EMERGENCY_DURATION_FLOOR, EMERGENCY_DURATION_CEILING]`; recommended default
  **72 h**, floor **24 h** (an emergency shorter than a day is not worth the
  ceremony), ceiling **14 days** (the overview's upper "7–14 day" band and
  ADR-0021's DTN delivery grace). Reconciling the ticket's "72 h" with the
  overview's "7–14 days": the default is 72 h and the ceiling is 14 days, so a
  community may lawfully choose within the overview's band while the shipped
  default stays conservative.

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

- **Hard-capped, then a real cooldown.** A continuation chain may renew at most
  `MAX_CONSECUTIVE_RENEWALS` times (recommend **2** — at most three back-to-back
  activations, capped by a ceiling constant a charter cannot exceed). Once the cap
  is reached the emergency lapses, and — because "consecutive" is proximity-based
  — any further declaration whose activation would fall within
  `EMERGENCY_COOLDOWN_SECS` (recommend **7 days**) of that lapse simply **does not
  activate**: replay refuses to treat it as effective. Only after the community
  has spent the cooldown *outside* emergency may a fresh chain begin. Both the cap
  and the cooldown are pure functions of admission times in the log — no
  free-text statute needs to be parsed, and perpetual emergency by serial renewal
  is genuinely impossible, not merely discouraged.

- **Early lift is allowed; late lift is not needed.** A signed
  **`rrn.gov.emergency_lapse`** (`kind = "rrn.gov.emergency_lapse"`, same co-sign
  supermajority as a declaration) ends an active emergency before its automatic
  expiry, so a community is not trapped in crisis mode after the crisis passes.
  The *absence* of a lift never extends anything — expiry is unconditional.

### 5. Record: emergency state is a pure function of the log, forever reconstructible

Nothing about the emergency is stored as authoritative mutable state. Whether a
given log position sits inside an emergency is computed by replay:

```
emergency_active(log, at_position) :=
    ∃ a declaration chain D with threshold-crossing co-signature X such that
        admitted(X) is at position ≤ at_position,
        D has not been ended by an emergency_lapse at or before at_position,
        D's activation was not refused by the §4 cooldown, and
        admitted(X) + D.duration_secs > admission_time(at_position)
```

Every input — which co-signature crossed the threshold, when it was admitted,
whether a lapse arrived first, whether the cooldown refused activation — is a
signed record at a definite log position, so every replica computes the identical
answer and *which windows applied to which admissions is reconstructible for all
time*. An `Emergency` proposal's window is `emergency_window_secs` iff
`emergency_active` held at *that proposal's own admission*; a proposal admitted
one second after expiry runs the ordinary window. All of it on the admission
clock (ADR-0022), never on `created_at`. This is the same discipline ADR-0015
uses for grace (`in_grace` is a pure function of the log at an instant), applied
to a mode whose boundaries are, if anything, more consequential to get
identically right on every device.

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
- **Freeze-as-a-lever.** The charter freeze (§3b) is a protection, but its inverse
  is a lever: a 67% faction can declare an emergency *specifically* to freeze an
  amendment that would curb it. This is bounded — the freeze lasts only as long as
  the emergency, which the §4 cap and cooldown hold to a few days per chain — but
  a determined faction can buy that delay. Named here so it is not a surprise.
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
  compression gate, of the enforced measure-expiry, and of the log-derived
  emergency state; threats: squatting the declaration lever, fast-path capture of
  the connected electorate, an unbounded-`expires_at` durable measure, a
  self-reset renewal index, freeze-as-a-lever, backdated windows if
  admission-anchoring is skipped; mitigations: §§1–5; residuals: the four above.
- **Three new signed record kinds and their fixtures.** `emergency_declaration`,
  `emergency_cosign`, `emergency_lapse` each need distinct discriminators,
  `From/TryFrom<CBOR>`, roundtrip tests, and committed CBOR fixtures for the
  mobile repo (PROCESS.md). A renewal is *not* a new kind — it is a declaration
  whose continuation status is derived (§4).
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

- **A station-stored emergency flag / mutable "emergency mode" row.** Rejected: it
  breaks the source-of-truth invariant (state must be replay-derivable), so
  replicas could disagree on whether a given past vote ran under emergency, and the
  history would not be reconstructible. Emergency state is a pure function of
  signed log records (§5), like every other governance fact.

**On abuse review (Question 5):**

- **Mandatory automatic post-emergency dispute review.** Rejected as a built-in: a
  compulsory review per emergency is itself weaponizable to chill legitimate fast
  response (Consequences). The log makes review *possible*; a community may make it
  *mandatory* by statute.

## Implementation sketch (for T2.8.2)

**Crates touched:** `rrn-governance` — the three record kinds; the
`emergency_active` replay predicate (§5) including the proximity-based renewal
count and cooldown (§4); the compressed-window derivation and the §1 bounded,
**enforced** `expires_at` in `proposal.rs`; the charter-freeze and
electorate-pin logic across `proposal.rs`/`tally.rs`/`lifecycle.rs`; and — the
precondition — admission-clock anchoring for the emergency path, which means the
signed `voting_ends_at`/`implementation_at` (`proposal.rs`, derived from author
`created_at`) become non-authoritative for an Emergency-under-declaration
proposal and the `vote.rs` ballot-window check moves to admission time, while the
`DEFAULT_COSIGN_THRESHOLD = 3` publication gate must now be reachable *inside* the
compressed window. `rrn-station` — RPC/banner surfacing of emergency state,
mirroring the grace banner. `rrn-cli` — declare / co-sign / lapse / status verbs
and display. **New charter parameters** on `GovernanceStructure`:
`emergency_window_secs`, `emergency_declaration_pct`, `emergency_duration_secs`,
`max_consecutive_renewals`, each with a floor/ceiling constant a charter cannot
breach (`EMERGENCY_WINDOW_FLOOR_SECS`, `EMERGENCY_DECLARATION_PCT_FLOOR`,
`EMERGENCY_DURATION_FLOOR/CEILING`, the renewal-cap ceiling), plus
`EMERGENCY_MEASURE_GRACE` and `EMERGENCY_COOLDOWN_SECS`. **Record kinds:** three
(`rrn.gov.emergency_declaration`, `rrn.gov.emergency_cosign`,
`rrn.gov.emergency_lapse`), each with a discriminator, canonical dCBOR, roundtrip
tests, and a committed fixture; plus the threat-model STRIDE section. The
load-bearing precondition, called out for the reviewer: **the emergency
declaration, window, and expiry must be anchored on admission time (ADR-0022),
not author `created_at`** — a compressed window on the author clock is unsafe, so
this is not optional.

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
