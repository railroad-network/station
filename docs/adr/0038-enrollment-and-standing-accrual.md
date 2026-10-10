# 0038 — Enrollment: who may go into debt and whose activity earns standing

## Status

Proposed

Date: 2026-10-10

> **Ratification questions.** Each one has a recommended answer, and that answer
> is what the Decision below says. Strike or change any answer and the Decision
> is re-planned around it. The implementing changes do not start until this ADR
> is ratified.
>
> - **Q1 — What "enrolled" means.** A station-signed `rrn.member.enrollment`
>   record on the log. The writer appends it at `pair_confirm`, at
>   `station enroll <address>`, and for the charter's founders. It is derived on
>   replay, pinned to the community station key, and skipped (never a halt) when
>   the signer is wrong. A `founder` record upgrades an existing enrollment, so a
>   founder who paired first is still a root. The station's own identity is
>   enrolled by derivation, but it is never a founder, never established, and
>   never anchored. A revoked founder stops being a root for good. (§1, §5)
> - **Q2 — Which doors it gates.** For ledger kinds, the check is inside the
>   `rrn-ledger` `Engine`, so every door gets it by construction. Door-level
>   checks exist only for the two binding kinds. A replica pull is not a door. (§2)
> - **Q3 — What a never-enrolled key may still do.** Receive; spend what it
>   holds; dispute its own transactions; return a certificate; request one only
>   against positive headroom. It may not go below zero, land a binding, earn
>   standing, or anchor anyone. (§3)
> - **Q4 — How the floor binds a person.** The configured floor applies per
>   enrolled identity. An unenrolled key's floor is `UNENROLLED_FLOOR_CENTI = 0`,
>   a protocol constant, applied as `max(0, debt_floor_centi)`. The refusal is
>   `Error::NotEnrolled` with the new receipt slug `not-enrolled`. (§4, §5)
> - **Q5 — Self-sends.** Refused at the engine front door
>   (`Error::SelfPayment`). Any already on a log earn nothing on replay. (§7)
> - **Q6 — Unenrolled accrual.** An event counts only if every party it names was
>   enrolled before the event's admitting entry. A confirmation counts only once
>   its transaction settles. History from before an identity's enrollment never
>   counts. (§8)
> - **Q7 — The velocity limit becomes enforcing.** At most
>   `VELOCITY_CAP_PER_WEEK` (0.5) is credited per dimension per trailing seven
>   days. The event times are `settled_at` for trades and confirmations and
>   `issued_at` for vouches. A vouch's `issued_at` must be within
>   `CLOCK_SKEW_TOLERANCE_SECS` of its admission. (§9, §10)
> - **Q8 — Voucher anchoring.** Anchoring is a chain of trust from the
>   `founder`-basis roots, computed as a least fixed point over eligible vouches.
>   A revocation removes the identity from the anchored set, and any identity
>   anchored only through it becomes unanchored too. A party's vouchees are
>   recused from its jury along with its vouchers. (§11)
> - **Q9 — Bootstrap grace.** The predicate and the threshold (3) are unchanged.
>   *Established* now also requires being enrolled and anchored. Founders keep
>   their grace seat from the charter. Grace lasts at least 49 days, and that is
>   disclosed. A community whose only founder is the station never leaves grace.
>   (§12)
> - **Q10 — Existing logs.** At startup the writer appends `founder` and
>   `pairing` enrollments for every founder and paired address that has no
>   enrollment record. No standing is credited retroactively. (§6)
> - **Q11 — Wire impact.** One new station-signed kind (with a ledger fixture and
>   no mobile copy), one new receipt slug, two new ledger error variants and one new error enum,
>   and three
>   operator-socket methods. (Wire summary, below)

## Context

The October 2026 internal audit (`docs/security/audit-2026-10.md`) reproduced
two High findings against `791db58`. Each one turns on a question no ADR
answers.

**RRN-A-016: the delay-tolerant door admits debits from keys nobody
enrolled.** A spending identity on the live paths is a device the operator paired
after comparing a code in person. The paired channel binds the record's signer
to that device. A DTN bundle checks less. The bundle entry must be signed by its
author and the embedded record by its signer, and nothing else is required. The
engine then applies ADR-0018's debt floor to the signing key. That key has a
balance of zero and a floor of −20 Commons, so the debit is admitted. The audit
had three never-seen keys each pay 4.99 to one receiver, inside one bundle, and
every proposal and confirmation was admitted. After the settlement window the
receiver held +14.97 and each throwaway key held −4.99. The floor bounds debt
per *key*, and keys cost nothing to make. So the walk-away bound ADR-0018 set
("−20 Commons per departing member") does not hold for a person. Anyone who can
reach a carrier can sign debits:

- a paired member carrying bundles as a "courier" over their own channel;
- anyone whose paper sheet the operator ingests;
- anyone in range of the radio adapter.

**RRN-A-017: established standing can be manufactured in one settlement
window.** Four properties combine:

1. A payment to oneself is admitted. Scoring counts it as a trade for the
   sender and its confirmation as an attestation for the confirmer.
2. Ten one-centicommon self-payments give a raw composite of 2.748, which is
   above the Member band, once they settle. ADR-0009's velocity limit is a log
   line and caps nothing.
3. Never-enrolled keys can do the same over the DTN door.
4. An anchoring voucher is judged on its *raw* composite. So an identity that
   did step 2 can anchor others without being anchored itself.

In the audit's reproduction, one identity anchored three throwaway keys. Those
keys became the community's only established members, which ended bootstrap
grace (ADR-0015). They became the whole electorate and the whole jury pool, and
governance records ride the DTN door. The audit's verdict was that this "needs a
decision record, not a patch: *who may go into debt*". Several of the fixes also
change ADR-0009's locked formula, which only a new ADR may do.

**Why pairing cannot be the answer as it stands.** Today the paired list is
`paired_mobiles.json` (`rrn-station/src/paired.rs`). It is local, unsigned and
off the log, so replay cannot derive it and a replica never sees it. Treating it
as the enrolled set would make `unpair` silently change someone's credit. It
would also make a member's floor depend on which station process happens to be
asked. The ceremony behind pairing is still the right one. `pair_confirm` records
that "the operator has compared the code in person and vouches for the pair".
That ceremony is the community's only existing in-person check on a key, and the
one this ADR builds on.

**What three earlier ADRs assumed.** ADR-0009 assumed velocity and anchoring
would bound a fake identity, and it named the cost: "a patient pair" can anchor
each other. Its 2026-07-27 amendment recorded the stronger rule, a chain of
trust from a genesis identity, as the direction. ADR-0015 assumed seating
founders "adds no sybil surface". That remains true, but the *end* of grace was
manipulable. ADR-0018 assumed each debtor is a member, which holds only on the
paired channel.

## Decision

**A key may go into debt only once the community has enrolled it, through a
station-signed record that the writer appends at an in-person ceremony. Only
activity between enrolled identities earns standing. Credit for that activity is
capped by rate. Anchoring is a chain of trust that starts at the founders.**

The Decision has two parts. Part A (§1–§6) covers enrollment and the floor.
Part B (§7–§12) covers how standing accrues. Each section gives the rule, then a
short *Why*.

### Part A — Enrollment

#### 1. The enrollment record, and how it is derived

A new station-signed record kind is defined in `rrn-ledger`. `rrn-ledger`
already owns, and pins, every station-signed credit record:

| Field | Type | Meaning |
|---|---|---|
| `kind` | text | `"rrn.member.enrollment"` |
| `member` | Address | the enrolled (or revoked) identity |
| `action` | text | `"enroll"` or `"revoke"` |
| `basis` | text | `"founder"`, `"pairing"`, or `"operator"`; a `revoke` always carries `"operator"` |
| `recorded_at` | i64 | the writer's admission clock when it appended the record (display only) |

**Who appends it.** Only the writer appends it, and it is signed with the
community station key. The writer appends one in these cases:

- **Founder.** It appends a `founder` enrollment for every founder named by an
  effective charter, other than the station's own identity, who has neither a
  `founder`-basis record nor any `revoke` record. It does this in the same
  `LogBatch` that admits the charter, and also at startup (§6). Founders
  usually pair before the founding ceremony so they can sign the charter from
  their phones (`docs/community-setup.md`, Part 3). So a founder is often
  already enrolled with basis `pairing`, and this record upgrades them (see the
  fold, below). A founder who paired first is still a root.
- **Pairing.** It appends a `pairing` enrollment at `pair_confirm` when the
  address is not currently enrolled. This includes an address that was revoked
  earlier: re-pairing is a fresh in-person decision.
- **Operator.** It appends an `operator` enrollment at `station enroll
  <address>`. This is for a member who never pairs, such as a paper-first member
  or one on radio only.
- **Revocation.** It appends a `revoke` at `station enroll --revoke <address>`,
  and only there.

**Unpairing is not revocation.** It removes a device from the channel and
leaves the enrollment in place.

At `pair_confirm`, the enrollment is appended before the paired list is written.
A crash between the two leaves a member who is enrolled but not paired. That is
harmless, and re-pairing is idempotent.

**How it is derived.** The enrolled set is derived on replay from these records
alone. Nothing at replay time reads `paired_mobiles.json`, a charter, or the
configuration. The fold is in log order:

- A record counts only if it is signed by the community station key, or by
  `writer_at(seq)` once ADR-0035 §5 lands. Any other signer, or a malformed
  record, is skipped. Replay never halts on one.
- An `enroll` with basis `founder` for an identity that is already enrolled
  changes its current basis to `founder`. Its enrollment position stands.
- Any other `enroll` for an identity that is already enrolled is a no-op: the
  original basis and position stand.
- A `revoke` for an identity that is not enrolled is a no-op.
- A `revoke` whose basis is not `operator` is malformed, and is skipped.

**Enrolled at a position.** An identity is *enrolled at position p* when its
most recent effective `enroll` or `revoke` with `seq < p` is an `enroll`. Its
*current basis* at `p` is that record's basis, or `founder` if a founder
upgrade was admitted after that record and before `p`.

**The station's own identity.** The station identity is enrolled at every
position by derivation, with no record, because the operator socket's `propose`,
`confirm`, `vouch` and `dtn_bind` sign with the station key. It is not a person
(ADR-0006). It is skipped when founder enrollments are appended, even when a
charter names it, so a charter that names it has one fewer root. It is never in
the anchored set (§11), and it is excluded from the established set (§12) and
from every jury pool.

**Routing.** The record is station-only. It is not a DTN-routable kind, so a
carried one is refused `unroutable-kind`. A member-signed record of this kind
that reaches a log by any path is inert, because it fails the signer pin.

*Why.* A record signed by the community station key is the only form of
"enrolled" that every reader can derive from the log. The ledger already trusts
that key for settlements, so this adds no new trust. The in-person check stays
where the operator already performs it.

#### 2. Which doors it gates

**Ledger kinds.** The rule is enforced inside `rrn-ledger`'s `Engine`, in the
floor check that `submit_proposal`, `submit_confirmation` and
`submit_certificate_request` already call. So every door that reaches the engine
gets it by construction:

- DTN bundle ingest over every carrier, all through `ingest_bundle` →
  `route_dtn_record`:
  - operator-socket `bundle_submit`;
  - `rrn paper ingest`, which calls it;
  - channel courier `bundle_submit`;
  - Reticulum and SMS `Command::IngestBundle`.
- The paired channel's live writes.
- The operator socket.

**Non-ledger kinds.** A door-level check exists only for the two binding kinds,
`rrn.net.binding` and `rrn.net.sms_binding` (§3). Governance, emergency and
dispute records are already gated by electorate or party rules.

**Replicas.** A replica pull is not an admission door. Under the ADR-0020
Clarification, a writer never pulls and a replica never admits. Replicas
re-derive and never re-enforce (ADR-0018). Enrollment records are pinned to the
writer, so until ADR-0035 §5 gives a replica the writer's key, a replica's
enrolled set reads empty. Its derived balances read empty the same way.

*Why.* Putting the rule at the engine, rather than at each door, is what keeps
the next carrier from reopening the hole. The audit found the gap exactly where
a door had checked something the engine did not.

#### 3. What a never-enrolled key may still do

**Allowed:**

- receive payments, and confirm proposals that credit it;
- spend what it holds, down to the floor of §4, including confirming a payment
  request within that;
- raise and answer disputes on its own transactions. The fail-open protections
  of ADR-0014 are for whoever was paid, enrolled or not;
- return a certificate;
- request a certificate, but only against positive settled headroom, since §4's
  floor applies to issuance (ADR-0021 §1).

**Not allowed:**

- go below zero (§4);
- land an `rrn.net.binding` or `rrn.net.sms_binding`. These are refused with
  `not-enrolled`, because a reachability claim from a stranger's key is a
  routing-directory pollution surface and carries no credit;
- earn standing (§8);
- anchor anyone (§11).

**Already gated elsewhere.** Governance is gated by the electorate.
Member marketplace writes are channel-only, so they need a paired device, which §1 and
§6 make an enrolled one. A revoked member who stays paired can still list and
inquire. Listing creates no debt, and an operator who wants them off the channel
also unpairs them.

*Why.* An unenrolled key is a stranger. The community can always take its money
and let it spend that money, and it should not extend it credit, standing or
routing.

#### 4. The floor binds a person, not a key

**The rule.** The configured floor (ADR-0018, `[credit] debt_floor_centi`)
applies to an identity enrolled at the admission position. Any other key's floor
is:

```
max(UNENROLLED_FLOOR_CENTI, debt_floor_centi)   where UNENROLLED_FLOOR_CENTI = 0
```

`UNENROLLED_FLOOR_CENTI` is a protocol constant in `rrn-ledger`, not a
configuration value. Taking the `max` means an unenrolled key's floor is never
looser than an enrolled member's.

**The projected position.** It is the same committed position ADR-0018 defines:
settled balance, minus pending signed debits, minus outstanding certificate caps.

**The refusal.** An unenrolled debtor whose projected position would fall below
its floor is refused with:

- error `rrn_ledger::Error::NotEnrolled { projected_centi }`;
- new receipt slug **`not-enrolled`**;
- RPC reason `ledger.not_enrolled` under ADR-0037 §1, with RPC message "not
  enrolled in this community: you can spend only what you hold".

An enrolled debtor still gets `DebtFloorExceeded`, exactly as before.

`not-enrolled` depends on state, like `debt-floor`. The same record can be
admitted later, after an inflow or after enrollment.

**The person-binding.** It is the enrollment ceremony: one in-person check per
enrollment.

**Key replacement.** A member who lost their phone with no recovery has their
old key revoked and their new key enrolled. The old key's debt stays on the old
key. That is ADR-0018's exit-with-debt residual, and it is now bounded per
person.

*Why.* A zero floor costs a stranger nothing it was ever owed. A floor below
zero is credit, and credit needs to know whom it was extended to. A protocol
constant, rather than a configuration value, means no operator can re-open the
hole while tuning the member floor.

#### 5. Revocation

**From the revocation onward:**

- The revoked identity's floor is §4's unenrolled floor. Debits it signed
  earlier stay pending and settle as usual. It cannot sign a new debit that
  takes it below zero.
- Its outstanding certificates are still honored. A cert-backed spend arriving
  within validity plus grace is admitted without a fresh floor check, because
  the headroom was reserved at issuance (ADR-0021 §4). Revocation does not void
  escrow that a receiver may already have relied on offline.
- It is excluded from the established set (§12) and from the anchored set (§11),
  and it earns nothing (§8).

**What revocation does not undo.** It does not erase events credited while the
identity was enrolled, and it does not remove a founder's grace seat, which the
charter grants and the operator does not (§12).

**Root status is lost for good.** A revoked founder is no longer a root, and
the operator cannot restore that. Re-pairing gives basis `pairing`, `station
enroll` gives `operator`, and §1's founder rule skips any identity with a
`revoke` record. That includes a founder whose lost key is replaced under §4:
the new key was never a founder. No console form grants basis `founder`, because
that would hand the operator the genesis lever ADR-0012 gives the charter.

*Why.* Revocation is the operator's remedy for a key that is not, or is no
longer, a person in the community. It has to stop new credit without stranding
anyone who relied on credit already granted.

#### 6. Existing logs

**At startup.** The writer appends, in one `LogBatch`:

- a `founder` enrollment for every founder of the effective charter that §1's
  founder rule covers (not the station, with no `founder`-basis record, never
  revoked);
- a `pairing` enrollment for every address in the paired list that has **no
  enrollment record at all**: never enrolled and never revoked.

That makes the backfill idempotent. Because a founder record upgrades an
existing enrollment, the order of the two lists in the batch does not matter. A
revoked member who is still paired is not re-enrolled on every restart. The paired list is read here, as a one-time input on the writer's side.
It is never an input to replay. A replica appends nothing.

**No retroactive standing.** Every event already on a log precedes these
records, so §8 makes all of it ineligible. On upgrade, every existing community
starts standing from zero and returns to bootstrap grace. No pilot has started,
so in practice no member loses standing they earned.

*Why.* Existing communities must keep working on the day this lands. Paired
members and founders keep their credit. Standing that may have been farmed does
not carry over.

### Part B — Standing accrual

#### 7. Self-sends

A proposal whose sender is its receiver is refused at the engine front door.
The error is `rrn_ledger::Error::SelfPayment`. Its receipt slug is the existing
catch-all `rejected`, and its RPC reason is `ledger.self_payment`.

A self-send already on a log still settles as before; its net balance effect is
zero. On replay it is neither a trade event nor an attestation event, for
anyone.

*Why.* A self-send has no economic meaning, so refusing it is the legible
answer. Admitting it but never scoring it would keep a record kind whose only
historical use was farming.

#### 8. Which events earn standing

**The eligibility rule.** A positive scoring event counts only if **every party
it names was enrolled before the event's admitting entry**, in log order:

- **A trade and its confirmation.** Sender and receiver must both be enrolled
  before the confirmation's admitting entry (`AdmissionTimes::confirmation_seq`).
- **A vouch.** Voucher and subject must both be enrolled before the vouch's own
  entry.

**Settlement.** A confirmation is credited to its confirmer only once its
transaction **settles**. A confirmed transaction that is cancelled or upheld in
dispute credits no one.

**Pre-enrollment history.** History before an identity's enrollment never
counts, including on logs that predate this ADR (§6).

**Future inputs.** The rule binds every future positive input, such as
governance participation and domain competence, the same way.

**Penalties are not gated.** Penalties apply to any identity, enrolled or not:
an upheld dispute (ADR-0014 §6) or a proven equivocation (ADR-0025).

**Order, not seq.** Eligibility is judged by log *order*. So a portable history
that re-chains a subset of entries in their original order (ADR-0032 §1)
reaches the same verdict, as long as it carries the enrollment records.

*Why.* Judging enrollment at the event's own position makes eligibility a fact
fixed at admission. A later revocation cannot strip an honest counterparty's
past standing. Enrolling a farm after the fact cannot credit what it did before.

#### 9. Event times, and the vouch bound

An eligible event is credited at a time that a forger cannot back-date and that
a portable replay preserves:

- **Trades and confirmations: the station-signed `settled_at`** of the
  settlement record. Today a confirmation is scored at its party-asserted
  `confirmed_at`, which is unbounded in the past (ADR-0022 §3). That stops.
- **Vouches: `issued_at`**, with a **new plausibility bound** at both live vouch
  front doors: channel `submit_vouch` and operator `vouch`. The rule is
  `|issued_at − now| ≤ CLOCK_SKEW_TOLERANCE_SECS`, two-sided.
  - The error is a new enum `rrn_identity::vouch::VouchError` with the variant
    `IssuedAtOutOfBounds { issued_at, now }`. Its RPC reason is
    `identity.vouch.issued_at_out_of_bounds`.
  - Neither door bounds `issued_at` today. `create_vouch`, which the operator
    door uses, stamps `issued_at` from the system clock. It must take `now` as a
    parameter so the station's injected clock stamps and checks the same
    instant.
  - The tolerance is the ledger's constant, passed in by the caller.
  - Vouches are live-only: the vouch kind is not DTN-routable. So the
    two-sided bound costs offline members nothing.

No event time is a log entry's `created_at`. That is station-local, and
ADR-0032's scratch replay re-stamps it, so it does not survive travel.

*Why.* The velocity cap of §10 is arithmetic over event times. An event time a
member can choose freely would let a farm spread its events across fictitious
weeks.

#### 10. The velocity cap is enforced by the scorer

**The rule.** For each identity and each dimension, the scorer walks the
eligible positive events in ascending `(event time, log order)`. An event at
time `t` is **credited** only if the credited increments already falling in
`(t − 7 days, t]`, plus this event's `EVENT_INCREMENT`, total no more than
`VELOCITY_CAP_PER_WEEK`. With the current constants (0.5 and 0.5), that is at
most one credited event per dimension in any trailing seven days.

**Uncredited events.** An eligible event that is not credited adds nothing to
the dimension. It still counts as activity for decay, because an active member
is not decaying.

**Determinism.** The credited set is a pure function of the log prefix.

**What is unchanged.** The weights, bands, increment, decay, ceiling and
penalties do not change.

**Establishment takes at least 49 days.** The Member band needs at least eight
credited events in one of the two live dimensions: seven and seven give only
0.30·3.5 + 0.25·3.5 = 1.925. Eight and seven (2.075) is one way to get there;
so is ten and four (2.00). The cap spaces those eight events at least seven days
apart. So no identity
is established sooner than 49 days after its first credited event: about eight
weeks of steady activity.

**The review flag.** `sybil::check_velocity` has no positive gain left to flag.
It stops being the defense, and it may be retired.

*Why.* ADR-0009's argument against acting on the cap ("flag, never punish") is
about *penalties*. A penalty could be pushed at someone by driving transactions
at them. A cap on *credit* cannot be pushed at anyone: it only slows the
identity whose own activity is being counted. A trailing window, unlike calendar
weeks, has no boundary at which two weeks' credit can be taken back to back.

#### 11. Anchoring is a chain of trust from the founders

**The roots.** The **roots** are the identities whose current enrollment has
basis `founder`.

**The anchored set** is the least fixed point, at the evaluation instant and
prefix, of:

- every root (anchored by definition); and
- every subject of an *eligible* vouch (§8) whose voucher is already anchored,
  is enrolled at the prefix, and has a **raw** composite of at least
  `ANCHOR_VOUCHER_MIN_COMPOSITE` (2.0, unchanged) at the evaluation instant.

**Two boundary rules.** The station identity is never in the anchored set. A
vouch is considered once its entry is in the prefix and its `issued_at` is no
later than the evaluation instant, as `anchoring_voucher` reads it today.

**Roots anchor only once they have standing.** A root anchors others only once
its own raw composite reaches 2.0. Founders earn standing like everyone else
before they can extend it.

**Revocation cascades.** A revoked identity leaves the anchored set from its
revocation onward. A subject that only it anchored becomes unanchored, and one
vouch from any anchored member re-anchors an honest one.

**Computability.** The raw composite still does not depend on anchoring. So the
computation is well-founded and terminates, for the same reason ADR-0009 gives.
The anchoring cap (1.0 per dimension until anchored) is unchanged.

**Recusal.** A dispute's jury recuses the parties, the parties' vouchers, and
now also the parties' **vouchees**: every identity a party vouched for in the
dispute's prefix, whether the vouch was eligible or not. Vouchee recusal is soft
and sits in the same tier as voucher recusal. It relaxes with voucher recusal,
before party recusal, when that is what seats a panel (ADR-0014 §5).

*Why.* This is the variant ADR-0009's 2026-07-27 amendment named as "the one
variant a Sybil pair cannot self-bootstrap", and §1 now supplies the genesis
definition it lacked. Two enrolled identities trading only with each other build
raw standing but never become anchored. The recusal closes the edge the audit
used: a party's own sybils were drawn as its jury.

#### 12. Bootstrap grace

ADR-0015's grace predicate is unchanged in form: established count below
`BOOTSTRAP_GRACE_THRESHOLD = 3`. The threshold is unchanged too, and so is the
Tier-2 grace allowance.

**Established** now means all of:

- enrolled at the prefix (so not revoked);
- anchored (§11);
- effective composite ≥ 2.0;
- not the station's own identity.

**The founders' grace seat.** In grace, founders are still seated from the
effective charter's `founders`, not from enrollment. The genesis trust behind
that seat is the charter's, so an operator's revocation does not unseat a
founder from the grace electorate. It only removes the founder's credit (§5)
and root status (§11).

**Disclosure.** Under §10 nobody is established in under 49 days. So every
community spends at least that long in grace, and the founders' grace power
lasts as long. If no founder ever reaches raw 2.0, nobody can be anchored and
grace never ends. The same holds for a community whose only founder is the
station, which is the runbook's solo bootstrap (`docs/community-setup.md`,
Part 3, Option A). The implementing change must re-describe or retire that
option. That is disclosed in the same banner ADR-0015 §5 already
shows.

*Why.* Grace ending was the manipulable step. With enrollment and the
chain of trust, grace ends only when three enrolled, anchored people have each
earned standing at a bounded rate.

### Interactions

- **ADR-0006.** Pairing becomes the enrollment ceremony. The member device
  still holds the only key, and the station still holds no member key.
- **ADR-0009.** Parts of it are superseded:
  - the velocity flag becomes a credit cap (§10);
  - raw-composite anchoring becomes the chain of trust (§11);
  - event eligibility (§7, §8) and event times (§9) are new.
  The weights, dimensions, bands, decay, increment, ceiling and full divisor are
  unchanged.
- **ADR-0014.** Vouchee recusal joins voucher recusal in §2's soft tier (§11).
  Juror weights still use the raw composite, now under §8's eligibility.
- **ADR-0015.** *Established* is redefined, and "adds no sybil surface" is
  corrected to cover the end of grace. Founders keep their grace seat from the
  charter (§12).
- **ADR-0018.** The floor applies per enrolled identity, and an unenrolled key's
  floor is zero (§4). The "−20 Commons per departing member" worst case now
  holds per person, up to the residual of one person enrolled twice.
- **ADR-0020.** Carriage stays permissionless: anyone may carry anything.
  Admission becomes identity-aware at the engine. Replicas re-derive, and their
  enrolled set reads empty under writer pinning (§2).
- **ADR-0021.** Issuance uses the floor that applies to the identity (§3, §4).
  Revocation does not void escrow (§5).
- **ADR-0020 §5 and ADR-0021 §7, on vouches.** Both describe vouches as signed
  offline and carried in bundles. In the code the vouch kind is not
  DTN-routable, and §9's two-sided `issued_at` bound depends on that staying
  true. A later ADR that routes vouches over DTN must revisit §9.
- **ADR-0022.** Scoring event times are the station-signed `settled_at` and a
  vouch's `issued_at`, which gains a two-sided bound at admission (§9). This is
  the one place a party-asserted time enters arithmetic, and the bound is what
  admits it.
- **ADR-0028.** A CLI wallet that pairs is enrolled at `pair_confirm`. A wallet
  that never pairs needs `station enroll` before it can go below zero.
- **ADR-0032.** A portable history must carry:
  - the enrollment records of its subject and of every counterparty whose events
    it counts (§8);
  - the whole anchor chain back to a root: each voucher's evidence, plus the
    root's `founder` enrollment.
  This discloses more than the first-voucher rule does today. A foreign member
  is unenrolled here, which is consistent with ADR-0032 §5: no residency, and
  no standing earned here.
- **ADR-0035.** The enrollment pin becomes lineage-aware (`writer_at(seq)`)
  along with every other station-signed kind. Enrollments by a predecessor
  writer stay valid at their positions.
- **ADR-0037.** This adds the reason slugs `ledger.not_enrolled`,
  `ledger.self_payment` and `identity.vouch.issued_at_out_of_bounds`, and the
  receipt slug `not-enrolled`.

### Wire summary

- **New station-signed kind `rrn.member.enrollment`** (§1). It has a canonical
  CBOR fixture under `crates/rrn-ledger/tests/fixtures/`. No member device signs
  or verifies it, so there is no copy in the mobile repo and no mobile change.
- **New receipt refusal slug `not-enrolled`.** It goes in `RefusalReason`, with
  its encode and decode arms, and in the registry in `docs/spec/dtn-bundles.md`
  §3. Older receipt decoders reject an unknown slug. The phone shows no
  receipts, and `rrn wallet` and the FFI are rebuilt from this repo, so no
  shipped reader breaks.
- **New error variants:**
  - `rrn_ledger::Error::NotEnrolled { projected_centi }`;
  - `rrn_ledger::Error::SelfPayment`;
  - a new enum `rrn_identity::vouch::VouchError`, with the variant
    `IssuedAtOutOfBounds { issued_at, now }`.
  Each gets its ADR-0037 reason slug once `rrn-reason` exists.
- **New operator-socket methods:** `enroll`, `enroll_revoke`, `list_enrolled`.
  Their console forms are `station enroll <address>`,
  `station enroll --revoke <address>` and `station enroll --list`. No member
  channel method changes.

## Consequences

- **Honest onboarding costs one ceremony and about eight weeks.** A new member
  pairs or is enrolled by the operator, and can then run the ADR-0018 floor.
  Establishment takes at least 49 days of steady activity with other enrolled
  members. A member who trades heavily accrues standing at the same rate as one
  who trades weekly. Standing now measures sustained participation over time,
  not volume.
- **The operator becomes the enrollment authority.** This is the same trust
  already vested in the operator for pairing and for the floor setting. It is
  more visible than before: every enrollment and revocation is on the log, with
  its basis and time, for every member and auditor to read (`list_enrolled`).
  That is a transparency gain over the local paired list. The privacy cost is
  small: addresses are already on the log, and this adds when each was enrolled.
- **Communities start standing again at upgrade** (§6), and each returns to
  grace for at least 49 days.
- **Residual: an operator can enroll one person twice.** Two keys for one person
  double that person's walk-away exposure. The only control is social: the log
  shows every enrollment. That is the same posture as a corrupt operator
  pairing a stranger.
- **Residual: an operator can revoke anyone's credit.** That includes a
  founder's. It does not touch a founder's grace seat (§12) or any standing
  already earned (§5), and every revocation is on the log.
- **Residual: a corrupt anchored member can anchor enrolled sybils.** Each sybil
  still needs its own in-person enrollment, and still needs seven weeks of
  rate-limited activity with enrolled counterparties before it is established.
  Graph analysis remains the federation-scale answer.
- **Residual: the operator can drive standing for a member.** Trades between
  the station identity (operator-socket `propose`/`confirm`) and an enrolled
  member are eligible events for the member. The velocity cap bounds this, and
  the operator already holds the enrollment authority.
- **Residual: a founder who is revoked, or whose key is replaced, stops being a
  root for good** (§5). A small community can be left one root short of ever
  anchoring anyone.
- **Residual: a community whose founders never reach raw 2.0 stays in grace
  indefinitely** (§12). So does one whose only founder is the station. The founders then govern until they do. This is
  disclosed and not mitigated.
- **Unchanged and out of scope here:** the contract-charge floor path
  (ADR-0018's residual), what the floor reads, member-writable field bounds, and
  the jury seed. Each is a separate decision.

## Alternatives Considered

- **Enrolled = paired device** (Q1). `paired_mobiles.json` is local, unsigned
  and off the log. Replay and replicas cannot derive it, and `unpair` would
  silently change a member's credit.
- **Enrolled = vouch chain from the founders** (Q1). It needs no new record,
  but any enrolled member could enroll any number of keys for free, so the floor
  would be per key again.
- **Door-level checks at each carrier** (Q2). Every new carrier or door would
  have to remember the rule. The audited gap was exactly a door that checked
  what the engine did not.
- **Sponsor liability: a voucher carries its vouchee's debt** (Q4). It needs new
  accounting, and it punishes honest vouchers for a stranger's walk-away.
  Deferred.
- **Reputation-scaled floors** (Q4, ADR-0018 §5). The input is the very thing
  being attacked. Deferred until standing is trustworthy, which this ADR is a
  precondition for.
- **A configurable unenrolled floor** (Q4). An operator tuning the floor could
  re-open the hole without meaning to.
- **Refuse all DTN debits** (Q2/Q4). This would close RRN-A-016, but it would
  also end offline spending for enrolled members, which is the point of
  ADR-0020 and ADR-0021.
- **Admit self-sends but never score them** (Q5). The record has no economic
  meaning, and refusing it is more legible.
- **Judge enrollment at the end of the prefix** (Q6). A revocation would
  retroactively strip honest counterparties' standing. Enrolling a farm after
  the fact would credit it retroactively.
- **Require only the identity's own enrollment** (Q6). An enrolled identity
  could still farm events against throwaway counterparties.
- **Count events per distinct counterparty** (the audit's suggestion, Q6/Q7).
  It penalizes honest repeated trade, like a weekly purchase from the same
  baker. It is unnecessary once credit is rate-capped and counterparties must be
  enrolled.
- **Keep the velocity flag** (Q7). It is a log line, and the reproduction shows
  it caps nothing.
- **Calendar-week velocity buckets** (Q7). Two buckets' worth of credit can be
  taken either side of a boundary.
- **Admission time (`created_at`) as event time** (Q7). It is station-local and
  re-stamped by a portable replay, so the score would not travel.
- **Keep raw-composite anchoring and add "voucher enrolled"** (Q8). A patient
  enrolled pair still anchors itself: the cost ADR-0009 named, left unpaid.
- **Require k distinct anchored vouchers** (Q8). It is stronger, but it slows
  honest onboarding in a small community. Deferred.
- **Anchoring that never lapses once given** (Q8). Revoking a sybil source would
  leave every identity it anchored anchored.
- **Seat founders from enrollment in grace** (Q9). That would give the operator
  a lever over the genesis electorate, which ADR-0012 places with the charter.

## References

- `docs/security/audit-2026-10.md`: RRN-A-016, RRN-A-017, and the RRN-A-007
  status row.
- [ADR-0006](0006-m1-client-architecture.md): the member device holds the key.
- [ADR-0009](0009-universal-reputation-algorithm.md): the formula, the velocity
  limit, anchoring, and its 2026-07-27 amendment.
- [ADR-0014](0014-phase-1-dispute-resolution.md): §2 recusal, §5 relaxation.
- [ADR-0015](0015-electorate-bootstrap-grace.md): bootstrap grace.
- [ADR-0018](0018-debt-floor.md): the debt floor.
- [ADR-0020](0020-single-writer-log-dtn-submission.md): single writer, DTN
  submission, and the 2026-09-14 Clarification.
- [ADR-0021](0021-escrowed-offline-spending-certificates.md): certificates and
  escrow.
- [ADR-0022](0022-admission-clock-time-trust.md): the admission clock and
  testimony timestamps.
- [ADR-0028](0028-non-mobile-member-wallet.md): the CLI member wallet.
- [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md):
  portable histories.
- [ADR-0035](0035-writer-succession-and-lineage-pinning.md): lineage-aware
  pinning.
- [ADR-0037](0037-localization-codes-on-the-wire-readers-translate.md): reason
  slugs.
- `crates/rrn-ledger/src/engine.rs`, `credit.rs`, `state.rs`;
  `crates/rrn-reputation/src/context.rs`, `sybil.rs`, `portability.rs`;
  `crates/rrn-dispute/src/sortition.rs`; `crates/rrn-station/src/core.rs`
  (`route_dtn_record`, `m_pair_confirm`), `paired.rs`.
