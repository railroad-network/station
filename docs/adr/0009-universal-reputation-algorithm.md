# 0009 — One reputation formula runs on every station and no community can tune it

## Status

Accepted

Date: 2026-07-23

## Context

M1.4 gave the network its first reputation *input*: an in-person vouch, signed by
the voucher's mobile and appended to the log, carrying a reputation stake
([ADR references in `docs/threat-model.md`](../threat-model.md), "Vouching
surface"). A vouch is only worth staking against if there is a reputation to
stake. M1.5 builds the thing the stake is denominated in: a score, derived from
the log, that says how much the network should trust a member.

This is the first protocol-level *scoring* system in the project, and it is
different in kind from everything decided so far. ADRs 0002–0008 fixed
mechanisms — how bytes are serialized, addressed, signed, sealed, recovered. A
mechanism is right or wrong. A scoring formula is a *policy*: it encodes a
judgment about what the community should value, and reasonable people will
disagree with the specific numbers. The danger is not that we pick imperfect
numbers — we will — but that the numbers become negotiable, per-community, or
silently mutable over time. Any of those turns reputation from a shared
measurement into a marketing surface.

The forces:

- **Reputation is load-bearing for five other systems.** Per design overview
  Section 5, one score simultaneously serves as oracle weight, credit
  trustworthiness, inter-community passport, governance weight, and market
  signal. A number that means different things on different stations is not a
  passport; it is a forgery waiting to happen.

- **Communities have a structural incentive to inflate.** Design overview
  Section 5.3 names the failure directly: if a community can relax its scoring to
  attract high-reputation members from elsewhere, federation becomes a race to
  the bottom and reputation becomes regulatory arbitrage. The only defense is to
  take the formula out of any single community's hands. It must be *the same
  computation everywhere*, changeable only by federation-wide governance — not a
  config value, not a per-community weight, not an operator setting.

- **The score has to survive travel.** Section 5.6 requires that reputation move
  between communities as a *signed history, not just a number*: the receiving
  station replays the exporter's log entries through the identical algorithm and
  arrives at the identical score, or the export is rejected. That is only
  possible if "the algorithm" is a single, fully-specified, deterministic
  function — same log plus same clock in, same profile out, on any station, in
  any phase, forever.

- **Most of what the formula will eventually measure does not exist yet.** Two of
  the five dimensions — community contribution and domain competence — have no
  data source in Phase 1. Community contribution is a Phase 2+ concept; domain
  competence is fed by marketplace transactions tagged with categories, which
  arrive in M1.7. The formula has to name all five now (so it never changes
  shape) while honestly producing nothing for the two that have no inputs.

- **Sybil resistance is mostly this formula's job in Phase 1.** The heavier
  defenses in design overview Section 5.4 — network-graph analysis of Sybil
  clusters — are a Phase 2 federation problem. What M1 can enforce locally is
  *rate*: a fake identity cannot fast-build a reputation because real
  relationships and real transactions have natural speed limits. The velocity cap
  is therefore not a tuning knob; it is the primary structural defense, and it
  belongs in the locked formula.

The M1.5 task spec proposes concrete starter values for every weight and
threshold. This ADR adopts them and records *why* they are defensible, so that a
future federation-governance proposal to change them argues against stated
reasoning rather than against a wall of unexplained constants.

## Decision

**Reputation is computed by one algorithm, specified here in full, that runs
byte-identically on every station. Weights, dimensions, decay, bands, and the
velocity cap are fixed at the federation-protocol level. No community can adjust
any of them. Changing any value requires federation-wide governance.**

### The five dimensions

Reputation is multidimensional internally and presents a single composite
externally (design overview Section 5.1). Each dimension is scored on `0.0..=5.0`
and stored as `f32` (two-decimal display precision is sufficient across the
range).

| Dimension | Weight | Phase-1 input |
|---|---:|---|
| Trade reliability | 0.30 | Count and recency of settled transactions, weighted by transaction tier (tiers arrive in M1.8; until then all tiers weight equally). Confirmed-and-settled is positive signal; cancelled-by-counterparty is neutral; disputed-against is negative (no disputes in Phase 1 — the slot is reserved). |
| Attestation accuracy | 0.25 | For every attestation this member signed (vouches, transaction confirmations), the ratio of accurate-to-total, where "inaccurate" means later proven wrong by a fraud finding. No fraud-finding mechanism exists in Phase 1, so every attestation counts as accurate and the dimension rewards attestation *volume* — see Consequences. |
| Governance participation | 0.15 | Votes cast, proposals authored (quality-weighted by whether they passed), council service (M2+ placeholder). No governance mechanism ships in M1.5, so this reads 0 until M1.9. |
| Community contribution | 0.15 | Non-economic contributions. **Phase 1: always 0.0** — no data source until Phase 2+. Named now so the formula never changes shape. |
| Domain competence | 0.15 | Per-category score, `BTreeMap<DomainTag, f32>`, fed by marketplace transactions tagged with a controlled category vocabulary (M1.6/M1.7). **Phase 1: empty map, contributes 0.0.** |

The weights sum to 1.0 and are a deliberate ordering of what the network values:
**demonstrated trade behavior first** (0.30 — Section 5.2 calls transaction
history "the bedrock input"), **honesty about others second** (0.25 — attestation
accuracy is what makes the vouching and oracle layers trustworthy), and the
remaining three civic/competence dimensions equal at 0.15. These are starter
values and a judgment call; they are locked, but they are not claimed to be
optimal, and this ADR is the record a future re-weighting proposal must engage.

### The composite

```
composite = 0.30·trade_reliability
          + 0.25·attestation_accuracy
          + 0.15·governance_participation
          + 0.15·community_contribution
          + 0.15·domain_competence
```

where `domain_competence` folds its per-tag map into a single scalar (mean across
present tags; 0.0 when the map is empty).

**The divisor is the full fixed weight sum (1.0), always — including dimensions
that have no Phase-1 input.** A dimension with no data reads 0.0 and genuinely
pulls the composite down. We do **not** renormalize over "active" dimensions.

This is the load-bearing decision of the ADR, and it is a direct consequence of
the portability requirement. If the divisor changed as dimensions came online —
0.70 in Phase 1 when only trade/attestation/governance are live, 1.0 later — then
the *same log would produce a different composite in Phase 1 than in Phase 2*,
with the member having done nothing. Section 5.6's promise ("the universal
algorithm produces the same score it would produce anywhere") would hold across
*space* but break across *time*, and a reputation exported in Phase 1 and
verified in Phase 2 would fail to reconcile. A frozen divisor keeps the formula
invariant across both.

The accepted, visible cost: **the maximum composite reachable in Phase 1 is
3.50**, because community contribution and domain competence (0.30 of the weight)
are structurally 0.0. The two upper bands are therefore unreachable until M1.7+
supplies their inputs. This is honest rather than a defect: "Trusted" and
"Senior" are supposed to require demonstrated domain competence and community
contribution, and Phase 1 does not yet measure either. The UI must present the
Phase-1 ceiling truthfully and must not imply the upper bands are attainable yet.

### External bands

The raw composite stays visible for inter-community use (Section 5.1). For local
presentation it maps to a band via half-open intervals, so boundaries belong to
exactly one band:

| Band | Composite range |
|---|---|
| New | `[0.0, 2.0)` |
| Member | `[2.0, 3.5)` |
| Trusted | `[3.5, 4.5)` |
| Senior | `[4.5, 5.0]` |

In Phase 1, with the 3.50 ceiling, every member lands in **New** or **Member**;
a member exactly at the 3.50 ceiling is "Trusted" only in the unreachable limit
and in practice reads "Member."

### Time decay

Per design overview Section 5.5, reputation drifts down without ongoing activity.
Each dimension loses **0.1 per 30-day month** of elapsed time, applied as a
fractional value:

```
decayed_dim = max(0.0, dim − 0.1 · (to_time − from_time) / (30 · 86400))
```

Decay floors at 0.0 (never negative) and is applied per-dimension; each domain
tag decays independently (Section 5.5 — "medical reputation decays if you stop
practicing"). Decay is folded into scoring so a live profile is always "as of
`now`"; because every station applies the identical decay to the identical log,
decay does not disturb cross-station or cross-time determinism.

### Reputation velocity limit

**No dimension may gain more than 0.5 per calendar week.** This is the single most
important Sybil defense M1 has, and it is structural, not tunable. A refresh
interval finer than weekly accumulates the gain over a trailing 7-day window;
exceeding the cap is a *flag for human review*, never an automatic punishment
(humans decide — see `sybil.rs`, T1.5.8).

### Identity anchoring

A soft cap complementing velocity (Section 5.4): a new identity's reputation
cannot exceed **1.0 in any dimension until it has received at least one vouch
from a member whose composite is 3.0 or higher.** The rest of the algorithm keeps
running; the dimension is simply capped at 1.0 until the chain-of-trust condition
is met. Fake identities thus cannot self-anchor — they need a genuinely
reputable member to stake on them, which is exactly the vouching-chain corruption
cost Section 5.4 is designed to impose.

### What is locked, and how it changes

Every constant above — the five dimensions and their weights, the full-divisor
composite, the four band thresholds, the 0.1/month decay rate, the 0.5/week
velocity cap, and the 1.0 anchoring cap with its 3.0 voucher threshold — is fixed
at the federation-protocol level. A station operator cannot override any of them;
there is no config surface for them by design. They change only through a
federation-wide governance process (mechanism itself is a Phase 2 concern). This
ADR is the source of truth; the `rrn-reputation` implementation (T1.5.2–T1.5.8)
follows it, and any divergence is a bug in the code, not a local policy choice.

## Consequences

- **The formula is portable by construction.** Because the computation is total,
  deterministic, and phase-invariant, `verify_history` (T1.5.7) on a receiving
  station replays the exporter's log entries and must arrive at the same profile
  the exporter published, or reject the export. Reputation becomes a
  passport that cannot be forged by inflating it at home.

- **Phase 1 scores look low, and that is intended.** The 3.50 ceiling means the
  network will not show anyone as "Trusted" or "Senior" for the whole phase. This
  needs to be communicated in the product so members do not read the ceiling as
  the system undervaluing them; the honest framing is that the upper bands measure
  things Phase 1 does not yet track.

- **Attestation accuracy rewards volume until fraud detection exists.** With no
  fraud-finding mechanism in Phase 1, every attestation scores as accurate, so the
  dimension effectively rewards *making* attestations rather than making them
  *well*. This is a soft farming surface (cheap vouches inflate attestation
  accuracy), bounded for now by the velocity cap and identity anchoring, and
  closed properly when M1.8+ adds fraud findings that can retroactively mark an
  attestation wrong. It must be named in the threat model (T1.5.8).

- **Three of five dimensions are dark in Phase 1** (governance until M1.9,
  community contribution in Phase 2+, domain competence in M1.7). The code carries
  all five so the shape never changes, but reviewers should expect the Phase-1
  composite to be driven almost entirely by trade reliability and attestation
  accuracy.

- **Scoring is O(N) in log size per fresh computation.** Fine at Phase 1 scale
  (hundreds of members, thousands of entries); the snapshot cache (T1.5.5) exists
  so queries do not pay the replay cost every time, with the log remaining
  canonical and the snapshot a derived view.

- **Weights are now a governance artifact, not an engineering one.** Tuning them
  later is a federation proposal with this ADR as its starting point, not a code
  review. That is heavier on purpose: the whole value of the number is that it
  cannot be quietly changed.

## Alternatives Considered

- **Per-community configurable weights.** Rejected as the central architectural
  choice (design overview Section 5.3). Community-tunable scoring is a race to the
  bottom and turns the inter-community passport into local currency. This is the
  one thing the milestone exists to prevent.

- **Renormalize the composite over active dimensions (divisor 0.70 in Phase 1).**
  Lets the full New→Senior range be reached immediately, which is friendlier.
  Rejected because it makes the same log score differently across phases: when
  M1.7 activates domain competence the divisor changes and every member's
  composite shifts with no behavior change, breaking portability and
  determinism-across-time — the properties T1.5.7 depends on. We took the honest
  ceiling instead.

- **Drop the two Phase-1-empty dimensions from the model until they have inputs.**
  Would raise the ceiling to 5.0 now, but re-adding them later is exactly the
  shape-change we are trying to avoid, and it would mean two different "universal"
  formulas over the project's life. Naming all five upfront, with placeholders at
  0.0, keeps one formula forever.

- **Store reputation as an authoritative value rather than deriving it from the
  log.** Rejected: a stored score is a second source of truth that can drift from
  the log and cannot be re-verified by a receiving community. The profile is a
  derived view; the log is canonical (Section 5.6). The snapshot table (T1.5.5)
  is a cache, not an authority.

- **Auto-penalize velocity violations.** Rejected per task spec: a burst of
  genuine activity and a Sybil farm can look alike at the threshold. Velocity
  violations flag for human review; humans decide. Automatic punishment would make
  the cap a griefing vector.

- **Heavier Sybil defenses now (graph analysis, time-locked attestation power).**
  Graph analysis of Sybil clusters (Section 5.4) is inherently a federation-scale,
  cross-community problem and is deferred to Phase 2. Phase 1 leans on the two
  local, deterministic defenses — velocity limiting and identity anchoring — which
  are sufficient at single-community scale and, unlike graph analysis, fit inside
  the locked formula.

## References

- Design overview [Section 5, The Reputation System](../design/Railroad-Network-Overview.md#5-the-reputation-system) — full source, in particular 5.1 (multidimensional/composite), 5.3 (universal algorithm), 5.4 (Sybil resistance), 5.5 (decay), 5.6 (portability).
- [ADR-0002](0002-canonical-serialization-dcbor.md) — canonical dCBOR; the replay determinism this ADR depends on rests on it.
- [ADR-0005](0005-station-signed-settlement.md) — settlement is the trade-reliability input source.
- [ADR-0008](0008-mobile-station-transport.md) — the log entries scored here arrive as signed, sealed envelopes.
- `docs/threat-model.md`, "Vouching surface (M1.4)" — vouches are a reputation input; the attestation-accuracy farming surface named above extends it.
- M1.5 task spec (`Phase 1 Tasks/M1.5 Reputation Scoring.md`) — T1.5.1 through T1.5.8 implement this ADR.
