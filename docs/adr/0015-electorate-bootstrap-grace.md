# 0015 — Bootstrapping the electorate: a governance and dispute grace so a young community can actually govern

## Status

Proposed

Date: 2026-08-14

## Context

ADR-0012 gave the community a constitution and ADR-0014 gave it courts, and both
rest on the same load-bearing predicate: an **established member** — a member
whose *effective* (anchored) composite reputation sits at or above the Member
band, `BAND_MEMBER_MIN = 2.0`. Established members are the governance electorate
(who may co-sign a proposal, who may vote, what the quorum denominator counts),
and — through ADR-0014 §2 — the eligible pool a dispute jury is drawn from and
the body a stalemate escalates to.

That predicate is unsatisfiable in a brand-new community, and not by accident:

- **The composite ceiling is 2.75, and it is earned, not given.** ADR-0009 fixes
  a full divisor over five dimensions, of which only two carry a Phase-1 input:
  `trade_reliability` (0.30) and `attestation_accuracy` (0.25). Every other
  dimension reads a structural `0.0`. The highest composite anyone can reach
  today is `(0.30 + 0.25) × 5.0 = 2.75`, and crossing the 2.0 line inside that
  narrow band takes a real, accumulated history of completed trades and
  un-disproven attestations. A member who joined yesterday scores near zero.

- **Genesis is the one place trust is granted, not earned — but only for the
  charter.** ADR-0012 lets founders authorize the genesis Charter by TOFU: the
  Charter is valid when ≥ 75 % of its named founders co-sign it, with no
  reputation gate at all. That is the single bootstrap exception in the whole
  governance stack, and it stops at the Charter's edge. The moment the community
  wants to do anything *else* — amend a statute, raise a proposal, seat a jury —
  it is back to needing established members it does not have.

- **The oracle ladder already solved this exact shape, once.** ADR-0011's Tier-2
  confirmations face the same wall: a young community has no established members
  to confirm deliberate purchases. Its answer is a **bootstrap grace**
  (`staking::BOOTSTRAP_GRACE_THRESHOLD = 3`): while fewer than three members are
  established, a below-band member *may* confirm a Tier-2 transaction, flagged
  `via_grace`, and the allowance evaporates on its own once three members cross
  the band. The mechanism is shipped, tested, and surfaced to the phone as a
  banner. Governance and disputes simply never got the equivalent.

- **The gap has been papered over, not closed.** Every live exercise of
  governance (M1.9) and disputes (M1.10) to date has required standing up a
  *test-build* station that manufactured established members, because a
  stock binary cannot produce a functioning electorate from a fresh log. The
  Phase-1 exit criteria require a real 20-plus-member community to run for 90
  days and to exercise governance and the dispute system at least once. A
  community that cannot seat a single voter or juror for the weeks it takes
  standing to accrue cannot meet that bar. This is the last structural blocker
  on the pilot, and it is on the Phase-1 critical path, not Phase 2.

The forces, then: the eligibility *rule* is correct for a mature community and
wrong for a newborn one; the reputation *scores* must stay earned and
log-derived (ADR-0009's whole point is that nobody manufactures standing); and
there already exists a precedent — the Tier-2 grace — for relaxing a rule,
visibly and temporarily, while a community bootstraps.

## Decision

**A young community governs and adjudicates through a bootstrap grace that seats
its founders as the electorate until enough members have genuinely earned their
standing — relaxing the eligibility rule, never the reputation scores, and
ending itself automatically.** The relaxation is symmetric with the Tier-2
oracle grace and keyed off the same threshold, so a community is either
bootstrapping or it is not, uniformly across oracle, governance, and disputes.

### 1. One grace state, shared with the oracle ladder

The community is **in grace** exactly when `established_member_count(db, at) <
BOOTSTRAP_GRACE_THRESHOLD` — the same predicate, the same constant (`3`), that
already governs Tier-2 confirmations. There is no new flag and nothing stored:
the state is a pure function of the log at an instant, so every replica agrees
and the moment it flips is deterministic. When three members hold an anchored
composite ≥ 2.0, grace is over — for oracle, governance, and disputes at once.

### 2. The grace electorate is founders ∪ established members

While in grace, the body that may govern and be drawn for juries is the union of
the genesis **founders** (named, unchanging, in the effective Charter's
`founders`) and any **genuinely established** members. Outside grace it is the
established set alone, exactly as ADR-0012/0014 define it today.

This choice is deliberate on both ends of the union:

- **Founders, because they are the one pre-vetted set.** They are named in a
  Charter that ≥ 75 % of them co-signed; the set is fixed at genesis, so seating
  it adds no sybil surface — pairing a phone does not make anyone a founder. It
  is the same TOFU trust ADR-0012 already extends to the Charter, now extended to
  operating under it.

- **∪ established, because early real standing should count.** The instant a
  non-founder earns their way over 2.0, they join the electorate rather than
  waiting for grace to end. The set only grows toward the steady state it
  becomes.

Founders are eligible during grace **without** an anchoring or standing
requirement; their eligibility is their genesis membership, not a score. (A
founder who never anchors simply drops out when grace ends and the union
collapses to the established set.)

### 3. Governance runs on the grace electorate, with a clamped co-sign threshold

During grace, "established member" is read as "member of the grace electorate"
everywhere ADR-0012 uses it:

- **Co-signing a proposal.** Founders may co-sign. The Charter's co-sign
  threshold clamps to `min(threshold, |grace electorate| − 1)` — the number of
  *other* eligible members, since the author cannot endorse their own motion — so
  a two-founder community publishes on its one other founder's co-signature and a
  lone founder publishes with none, rather than being deadlocked by a rule asking
  for three co-signers it can never field. Outside grace the configured threshold
  applies unchanged.

- **Voting.** A ballot is accepted from any member of the grace electorate as of
  when it was cast, replacing the bare `is_established` gate for the duration.

- **Quorum and approval.** The denominator is the size of the grace electorate at
  the tally instant — the honest count of who was eligible — so quorum means the
  same "enough of the people who could vote did" it always means.

### 4. Disputes draw from the grace electorate

ADR-0014's sortition and escalation read the same substitution: the eligible
jury pool is the grace electorate minus the two parties (retaining §5's
voucher-recusal, and its relaxation when the pool is too thin), and an escalation
puts the question to the grace electorate minus the parties. Everything
downstream is unchanged — the standing-weighted draw, the panel of three, the
no-show redraw, and above all the **fail-open lapse**: if even the grace
electorate cannot seat a panel (a genuinely tiny community, or too many
recusals), the dispute still lapses to the confirmed status quo rather than
trapping the transaction. Grace widens the pool; it does not remove the safety
valve.

### 5. Grace is visible, and it ends on its own

The bootstrap-grace status already exposed over RPC for the oracle banner is
widened to state that governance and disputes are operating under grace, so a
member is never told a founder-seated vote is an ordinary one. No action ends
grace; accruing standing does. When `established_member_count` reaches three,
the union in §2 collapses to the established set and every relaxation above
lapses in the same instant, for every subsystem, with no migration and no
switch to throw.

## Consequences

- **A stock binary can run a real pilot.** Founders co-sign and vote, raise and
  resolve disputes, and amend statutes from day one; the test-build station that
  faked established members is retired. The Phase-1 exit criteria (governance and
  disputes each exercised in a real 90-day community) become reachable without a
  scaffold.

- **The reputation invariant is untouched.** No founder is handed a score; the
  log still derives every composite the same way. What changed is *which rule is
  read* while `established < 3`, not *what anyone's standing is*. Anchoring,
  decay, sybil-velocity, and the ceiling all keep working exactly as ADR-0009
  specifies.

- **Founders hold real power during grace — bounded, visible, and temporary.** A
  founder majority could pass statutes or resolve disputes in its own favor while
  grace lasts. This is the same genesis trust ADR-0012 already vests in founders
  to write the constitution, now exercised under it; it is disclosed (§5), it
  self-terminates (§1), and anything enacted under grace is amendable once the
  electorate broadens. It is not a new concentration of power so much as an
  honest naming of the one the genesis model already contains.

- **Quorum can be thin in a two- or three-person genesis.** With a tiny grace
  electorate, a quorum percentage rounds to one or two people. That is the true
  size of the deciding body, not a loophole; the ADR-0012 thresholds still apply
  to the count that actually exists.

- **The grace boundary is a step, and steps invite gaming.** A community sitting
  at two established members has a materially different electorate than one at
  three, and the transition is abrupt. The same critique applies to the Tier-2
  grace and is accepted for the same reason: a hard, log-derivable threshold is
  worth more than a smooth curve nobody can independently recompute. Gaming it
  requires *earning* a third established member, which is the outcome we want.

- **One predicate now fans out to three subsystems.** `in_grace` becomes a
  shared input to oracle, governance, and disputes, so its definition must not
  drift. Consolidating it behind a single reputation-layer helper (rather than
  three copies of `< 3`) is a small implementation debt this ADR takes on
  deliberately.

## Alternatives Considered

- **Seed founders with genesis standing.** Record a genesis event that lifts each
  founder's live dimensions over 2.0, making them established outright. Rejected:
  it manufactures reputation in the log, the exact thing ADR-0009 exists to
  forbid, and the fabricated standing would then decay, portability-transfer, and
  weight juries as if earned — corrupting every downstream computation to save a
  branch in the eligibility check.

- **Do nothing; let standing accrue organically.** Require the pilot to trade and
  vouch until three members cross 2.0 before any governance or dispute works.
  Rejected: it leaves a real community with no constitution-in-motion and no
  courts for the opening weeks of its life — precisely when disputes are most
  likely and norms are being set — and the 2.75 ceiling makes the climb slow and
  fragile. It is a description of the cliff, not a way down it.

- **Seat all paired members during grace.** Let anyone paired to the station
  govern until grace ends. Rejected: pairing is a network convenience, not a
  trust decision (ADR-0008); this would open a sybil path where standing up
  phones buys votes and jury seats, inverting the whole point of the reputation
  gate.

- **A separate governance-grace threshold.** Give governance its own constant
  rather than reusing `BOOTSTRAP_GRACE_THRESHOLD`. Rejected: two thresholds mean
  a community can be bootstrapping for the oracle and not for governance (or vice
  versa), a confusing split state with no user-visible meaning; one "is this
  community young?" line is easier to reason about and to display.

## References

- [ADR-0009](0009-universal-reputation-algorithm.md) — the composite, the Member
  band, and the earned-not-given invariant this ADR must not break.
- [ADR-0011](0011-oracle-tier-model-phase-1.md) — the Tier-2 bootstrap grace this
  ADR generalizes, and `BOOTSTRAP_GRACE_THRESHOLD`.
- [ADR-0012](0012-charter-format-and-amendments.md) — founders, TOFU genesis
  authorization, and the established-member electorate.
- [ADR-0014](0014-phase-1-dispute-resolution.md) — sortition from the established
  pool, escalation, and the fail-open lapse grace widens but preserves.
