# 0014 — Phase-1 dispute resolution: a sortition jury with a governance backstop, and the Tier-2 stake that finally bites

## Status

Proposed

Date: 2026-08-11

## Context

ADR-0011 shipped the Phase-1 oracle ladder with a hole cut deliberately in the
middle of it. Tier 2 stakes the confirmer's reputation on a deliberate purchase,
but the stake is **consequence-free**: there is no path by which a
proven-fraudulent confirmation costs the confirmer anything. ADR-0011 said so in
as many words — the forfeiture path is "Phase 2 work, gated on the
dispute-resolution system Phase 1 omits" — and left the value reconstructible
from the log so a later mechanism could claw it back. This ADR is that
mechanism, pulled forward.

The pull-forward is not gold-plating. The Phase-1 exit criteria in the design
overview require that "the dispute system [is] exercised at least once" before a
real community's 90-day pilot counts. A pilot cannot exercise a system that does
not exist, so the dispute system is on the Phase-1 critical path, not Phase 2.
It is the last unbuilt Phase-1 deliverable.

Four forces shape how it has to be built:

- **The seam already exists, inert.** `rrn-ledger`'s state machine has a real
  `TransactionState::DisputedStub` and a legal `Confirmed → Disputed` edge whose
  own doc comment says it "is accepted but does nothing" and is
  "never-constructed." Phase 1 laid the rail; this ADR runs a train on it.

- **The dispute window *is* the settlement window.** A confirmed transaction
  waits out 24h (Tier 1) or 48h (Tier 2) and then `Settler::sweep` moves it to
  `Settled` and applies the balance change. There is no separate dispute clock.
  If a dispute is raised at hour 47 of 48, there is no time to adjudicate before
  the sweep settles it. So raising a dispute must **freeze** the transaction —
  suspend the sweep for it indefinitely — decoupling adjudication from the
  settlement window. Until this ADR, freezing was impossible; the stub carried
  no proposal and the sweep never consulted it.

- **Single community, no outside arbiter.** Phase 1 has no cross-community
  arbitration (Tier 4) and no witness quorum (Tier 3). Whoever resolves a
  dispute has to come from *inside* the one community — which raises the
  centralization problem the whole project exists to avoid. A fixed arbiter
  role concentrates exactly the power the network is built to disperse.

- **Reputation is derived, and it already has the dent we need.** ADR-0009's
  `attestation_accuracy` dimension (weight 0.25) is documented as the "ratio of
  this member's attestations that were **not later proven wrong**." Today
  `score_raw_at` only ever feeds it the *positive* side — every confirmation and
  vouch counts for the attester. Nothing yet supplies a "proven wrong" event.
  A dispute upheld against a confirmer *is* that event. The forfeiture the
  Tier-2 stake promised is therefore already shaped into the reputation model,
  waiting for an input — no new stored balance, no mutable "locked reputation,"
  no fight with the derive-from-log invariant.

## Decision

**Phase 1 resolves disputes by sortition: a standing-weighted, log-derivable
random draw of a three-member jury, majority rules, inside a bounded
dispute-resolution window that fails open — a dispute nobody resolves in time
lapses and the confirmed transaction stands.** Raising a dispute freezes
settlement for that window only, not forever. The established-member governance
vote is retained as an *optional* escalation and appeal, never a requirement that
stalls a transaction. An upheld dispute voids the pending transfer *and* records
the adverse attestation that dents the confirmer's reputation — which is what
finally gives the Tier-2 stake teeth. Six sub-decisions follow.

### 1. A dispute is a signed record that freezes settlement

Either party to a Tier-1 or Tier-2 transaction may raise a dispute while the
transaction is `Confirmed` and inside its settlement window. A dispute is a
new signed log record (`DisputeRecord`: disputed `tx_id`, `raiser`, a bounded
free-text `reason`, `opened_at`, and an optional content hash for out-of-band
evidence). It drives the state machine across the now-live `Confirmed → Disputed`
edge (the `DisputedStub` variant becomes a real `Disputed { proposal,
dispute, .. }`).

`Settler::sweep` gains one rule: **a `Disputed` transaction does not settle while
its dispute is live.** The freeze is *bounded*, not indefinite: opening a dispute
starts a fixed **dispute-resolution window** (default 14 days — a `DisputeConfig`
constant alongside the settlement windows, tunable later) during which the sweep
skips the transaction. Because settlement is what moves balances, a frozen
transaction has moved no credits, so nothing needs clawing back while it waits —
and, per §5, if the window closes with no ruling the freeze simply lifts and the
transaction settles as it was confirmed.

The evidence channel is deliberately thin: a text statement from each party plus
an optional hash reference. The rich artifact-evidence channel is Tier-3, Phase-2
work; a Phase-1 jury rules on the parties' statements and whatever they exchange
out of band.

### 2. The jury is drawn by verifiable, standing-weighted sortition

When a dispute opens, the station snapshots the **eligible pool** and draws a
panel from it. Eligibility reuses the governance electorate: established members
(composite reputation ≥ `BAND_MEMBER_MIN` = 2.0, the same bar
`rrn-governance` uses for the vote), **minus both parties** (recusal), **minus
direct vouchers of either party** (the obvious collusion edge; the vouch graph is
already on the log).

The draw is a **deterministic function of the log**, not a call to a random
number generator: a seed `= hash(dispute_id ‖ genesis_anchor)` drives a
weighted selection over the snapshot, each candidate weighted by their raw
composite standing at `opened_at` (`score_raw_at`). Determinism is the point —
anyone replaying the log recomputes the identical panel and can prove the station
did not hand-pick friendly jurors. Phase 1 runs on one station and cannot yet
*enforce* that cross-check, but building selection to be verifiable now is cheap;
retrofitting it after federation is not.

### 3. Panel of three, majority rules

Three jurors are drawn, not one. In a twenty-person community the eligible pool
after recusal can be as small as a handful, and a lone juror is cheap to bribe or
happens to be biased; a three-member panel with a majority verdict is robust to a
single bad juror and still terminates on a clean 2–1. Each juror casts a signed
verdict (uphold the dispute / reject it); the majority is the ruling.

### 4. A juror who goes silent is redrawn around

Each drawn juror has a **response deadline** shorter than the overall resolution
window. A juror who has not cast a verdict by their deadline is a *no-show*: the
sortition redraws a replacement from the remaining eligible pool (deterministic
again — the next candidate the same seeded draw yields), excluding the no-show.
No-shows carry **no reputation penalty in Phase 1** (see Consequences); civic
non-participation feeding `governance_participation` is a later refinement, kept
out to bound this milestone.

### 5. The window fails open; governance is an optional escalation, not a mandatory backstop

Every path is bounded, and every bound fails the same way — **open**. If the
dispute-resolution window closes with no terminal ruling, the dispute lapses, is
recorded as expired, and the confirmed transaction settles exactly as if the
dispute had been rejected (§6). The bilaterally-confirmed transaction is the
status quo; overturning it takes an affirmative ruling, and absent one the status
quo holds. This is what replaces an indefinite freeze — a griefer delays
settlement by at most the window, never forever.

The established-member governance vote (ADR-0012) is retained as an **optional
escalation**, not an automatic backstop:

- A party may **appeal** a jury ruling, suspending its enactment and putting the
  same question to the electorate; a vote that reaches quorum is final and can
  overturn the jury.
- A party may **escalate** when the jury cannot seat a panel — recusal plus
  no-show redraws exhaust the eligible pool — asking the electorate to rule where
  the jury could not. (Recusal relaxes before this: voucher-recusal is dropped
  before party-recusal if that is what seats a panel; the two parties are never
  eligible to judge their own dispute.)

An escalation vote runs on its own bounded sub-window inside the
dispute-resolution window, and it fails open too: a vote that does not reach
quorum in time leaves the confirmed transaction standing. Governance is thus the
avenue for a community that *actively wants* to overturn a deal — never a
requirement that stalls one. Reusing `rrn-governance` means the contested cases
lean on machinery already built, tallied, and device-verified rather than a
second bespoke procedure.

### 6. An upheld dispute voids the transfer and dents the confirmer

A terminal ruling resolves the freeze one of two ways:

- **Dispute rejected** — the confirmation stands. The transaction leaves
  `Disputed` and settles normally (`Disputed → Settled`), balances applying as
  originally proposed. A dispute that **lapses** unresolved when the window
  closes (§5) settles by this same path — a non-ruling is a rejection.

- **Dispute upheld** — the confirmation was a false attestation. The pending
  transfer is **voided**, not reversed (`Disputed → Cancelled`, a
  dispute-upheld `CancelReason`): because the freeze caught it before settlement,
  no balance ever moved, so there is nothing to reverse. Separately, the ruling
  records that the confirmer's confirmation was **proven wrong**, which
  `score_raw_at` folds into their `attestation_accuracy` as the negative event
  that dimension was always documented to hold. That reputation dent *is* the
  forfeiture ADR-0011 deferred — the staked standing, reconstructible from the
  log exactly as promised, now actually costs the confirmer.

Frivolous-dispute penalties on the *raiser* (a cost for losing a dispute you
opened in bad faith) are deferred: Phase 1 makes an honest confirmer whole by
letting the transaction settle, and leaves the disputant-side deterrent to a
later pass rather than widening this milestone.

## Consequences

- **Positive.** The Tier-2 stake finally bites, through the reputation dimension
  built to receive it — no new stored balance, no locked-reputation mutation, no
  violation of ADR-0009's derive-from-log rule. Adjudication disperses rather
  than centralizes: no permanent arbiter role, no charter-anointed judge, and a
  selection anyone can audit by replay. The hard cases reuse the M1.9 governance
  vote instead of a second bespoke procedure. The `Confirmed → Disputed` rail
  laid inert in Phase 1 gets used for what it was cut for, and the Phase-1 exit
  criterion "dispute system exercised at least once" becomes reachable.

- **Negative / accepted.** The bounded window caps a meritless dispute's damage
  to a *delay* — settlement postponed by at most the dispute-resolution window,
  never parked forever — but with no frivolous-dispute penalty in Phase 1 the
  griefer still pays nothing for that delay. Failing open cuts the other way: a
  genuine fraud victim whose community neither seats a jury nor musters a quorum
  gets no remedy, because the confirmed transaction stands by default; the remedy
  exists (rally the vote) but demands participation. A no-show juror slows
  resolution with no consequence, and voucher-recusal shrinks an already-small
  pool. All are accepted for Phase 1: the deterrents and the richer evidence
  channel are Phase-2 depth, and every path terminates — at worst by lapsing to
  the confirmed status quo.

- **Follow-up.** Phase 2 adds the disputant-side penalty, juror civic-duty
  feeding `governance_participation`, the Tier-3 artifact-evidence channel a
  jury could weigh, and — once federation exists — the cross-station replay that
  turns verifiable sortition from a courtesy into an enforced check. A new
  `rrn-dispute` crate orchestrates the draw, deadlines, redraws, tally and
  escalation; the `DisputeRecord` type and the `Disputed` state live in
  `rrn-ledger` (kept free of reputation/governance dependencies), and
  `rrn-dispute` depends on `rrn-ledger`, `rrn-reputation`, and `rrn-governance`.
  The mobile surface (raise a dispute from `TransactionDetail`, respond as the
  counterparty, cast a juror verdict, see the outcome) and the threat-model
  dispute-layer section that ADR-0011 left as a Phase-2 placeholder are tracked
  in the M1.10 task set.

## Alternatives Considered

- **A charter-named arbiter (or panel of founders) signs resolutions.** Rejected:
  simplest and fastest, but it invents the permanent, centralized trust role the
  network exists to avoid, and hands a founder standing power over every
  member's disputes. Sortition delivers a decision procedure without a standing
  office.

- **Freeze settlement indefinitely until a decision is reached (this ADR's first
  draft).** Rejected: an indefinite freeze lets a meritless dispute park a
  counterparty's credits forever and makes liveness hostage to the community
  always producing a ruling. A bounded window that fails open to the confirmed
  transaction caps the damage and guarantees termination — at the cost of leaving
  a genuinely-wronged disputant without remedy when the community is apathetic,
  the burden-of-proof tradeoff we accept because a bilaterally-confirmed
  transaction is the status quo a dispute must affirmatively overturn.

- **Every dispute is a governance vote.** Rejected as the *primary* path:
  authoritative and it reuses built machinery, but mobilizing the whole
  electorate for a five-Common disagreement is disproportionate and slow, and a
  community would quickly stop bothering. Kept as the optional escalation and
  appeal, where its weight is warranted.

- **A single juror instead of a panel of three.** Rejected: cheapest state
  machine, but in a pool that can be a handful of people a lone juror is cheap to
  corrupt and carries no tie of a second opinion. Three-with-majority is robust
  to one bad or bought juror at modest extra coordination.

- **A stored `AttestationStake` record with a locked-reputation balance that a
  ruling debits.** Rejected, consistent with ADR-0011: it adds a signed record
  and a mutable balance that fights the derive-from-log invariant, to express a
  forfeiture the `attestation_accuracy` dimension already represents as a
  replayable "proven wrong" event. The derived dent is additive and needs no new
  stored quantity.

- **Reverse the balance on an upheld dispute (a post-settlement clawback).**
  Rejected as unnecessary in Phase 1: freezing settlement on dispute means
  balances never moved, so voiding the pending transfer is sufficient and
  avoids a reversal record. A clawback only becomes relevant if a future tier
  settles before its dispute window closes, which Phase 1 does not do.

- **Panel size / recusal / windows as charter parameters from day one.**
  Rejected for this ADR: the panel is fixed at three and recusal is fixed as
  specified so Phase-1 behavior is uniform and testable; making them
  governance-tunable is a clean additive follow-up if a community demands it,
  the same way ADR-0011 earmarked only the settlement *windows* for tuning.

## References

- [ADR-0011](0011-oracle-tier-model-phase-1.md) — the oracle ladder; §3 defers
  the stake-forfeiture path and the dispute-resolution system to Phase 2, which
  this ADR delivers for Phase 1. ADR-0011 stays Accepted; its Tier-3/Tier-4
  deferral is untouched.
- [ADR-0009](0009-universal-reputation-algorithm.md) — reputation is derived
  from the log; the `attestation_accuracy` dimension this ADR feeds the
  "proven wrong" side of.
- [ADR-0012](0012-charter-format-and-amendments.md) — the established-member
  electorate and vote that serve as the dispute backstop and appeal.
- [ADR-0005](0005-station-signed-settlement.md) — station-signed settlement and
  the `Settler` sweep that a dispute now freezes.
- Design overview, Section 4.3 — "The Tiered Oracle Model"; Section 7 — the
  dispute layer; Phase-1 exit criteria (dispute system exercised at least once).
- Threat model — `rrn-ledger` § "Oracle tiering and the reputation stake"
  (to gain a dispute-layer subsection under M1.10).
