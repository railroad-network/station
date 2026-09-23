# 0033 — Oracle Tiers 3 and 4: artifact evidence, witnesses, and cross-community validation

## Status

Accepted — ratified 2026-09-23 (the maintainer delegated the ratification
review; it returned accept-with-changes for the set of eight and the changes
are folded in — see the ratification note below)

Date: 2026-09-23

> **Ratification note (2026-09-23).** Drafted against the maintainer's scope
> decisions of 2026-09-23 (marked **(maintainer decision, 2026-09-23)** below),
> reconciled across the eight-ADR set, then reviewed for ratification at the
> maintainer's delegation. The review's
> findings folded into this ADR: cross-community validation is attested by a quorum of the validator community's established members (`rrn.oracle.validation_attest`) rather than decided by one operator; the Tier ≥ 3 gate applies on every transition into `Settled`; suspended-treaty and equivocating-validator cases are stated.
> Implementation tickets are written against this ratified text.

## Context

[ADR-0011](0011-oracle-tier-model-phase-1.md) realized the first two rungs of the
overview's tiered oracle ladder (§4.3) and pinned down what Phase 1 does with the
other two: a transaction whose effective tier exceeds `MAX_PHASE1_TIER = 2` is
**refused, never clamped** (`Error::TierNotSupported`), because clamping would
silently give a fifty-Common purchase the scrutiny of a five-Common one. Every
payment of 50 Commons or more has been blocked at the front door since. The
overview names the missing machinery precisely:

| Tier | Range (centicommons) | Requirements |
|---|---|---|
| 3 | `5_000 ≤ |amount| < 50_000` | Tier 2 + physical-artifact evidence + three community witnesses |
| 4 | `|amount| ≥ 50_000` | Tier 3 + cross-community validation + governance approval |

Three forces shape how those rungs are built now rather than "just do §4.3":

- **The log is the source of truth and holds no blobs.** Every state is derived by
  replay of signed records ([ADR-0020](0020-single-writer-log-dtn-submission.md));
  a photograph of a delivered pallet is not a signed record and does not belong on
  a chain that every replica and every treaty partner copies. Yet the overview's
  "evidence is cryptographically timestamped" is the whole point of Tier 3. The
  answer is the same one the DTN layer already uses for bundles: a signed record
  carries a **content hash**, and the bytes live in a bounded, content-addressed,
  station-local store. **(maintainer decision, 2026-09-23: hash-anchored artifacts
  with the blob off-log.)**
- **Every window reads the admission clock** ([ADR-0022](0022-admission-clock-time-trust.md)),
  every derived gate is replay-reconstructible ([ADR-0009](0009-universal-reputation-algorithm.md)),
  and every bounded path fails to the status quo ([ADR-0014](0014-phase-1-dispute-resolution.md)).
  A witness quorum is a *bounded* requirement, so it needs a deadline and a
  fail-direction; for a transfer that has not yet moved balances, the status quo is
  "no transfer" — Tier 3 fails **closed** on the money and open on everything else,
  exactly the ADR-0021 posture that a refused spend is a nuisance, not a loss.
- **Tier 4 is the first rung that needs another community.** Cross-community
  validation presupposes a treaty at Recognition depth
  ([ADR-0030](0030-treaties-ratification-depth-lifecycle.md), [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md)):
  the validator must be able to verify the witnesses' standing without trusting the
  home station's word for it. Tier 4 therefore lands with federation, not before
  ([ADR-0017](0017-resilience-before-federation.md) moved it here deliberately).

Two things this ADR does **not** reopen: the tier floor is still a pure function of
the absolute amount, and opt-up is still upward only (ADR-0011).

## Decision

**Tiers 3 and 4 are served by the same ledger front door, with two new
member-signed evidence kinds (an artifact reference and a witness attestation), a
settle-or-cancel rule evaluated by the settlement sweep at the end of a
tier-specific window, and — for Tier 4 only — a governance approval proposal plus
a validation from a neutral Recognition-depth treaty partner, attested by at
least two of that partner's established members and merely carried by its
writer.
Anything above Tier 4 stays refused. Artifacts are hash-anchored records whose
bytes live off-log; witnesses are established members under a derived stake gate
and party/voucher recusal; the windows read the admission clock; a transaction
that misses its quorum, its approval, or its validation is cancelled, never
settled with less scrutiny than its value demands.** Nine sub-decisions follow.

### 1. The ceiling lifts to four; the block-never-clamp rule stays

`MAX_PHASE1_TIER` is renamed `MAX_SERVICEABLE_TIER` and set to `4`
(`is_phase1_serviceable` → `is_serviceable`). `tier_floor` is unchanged:
`TIER_3_FLOOR_CENTI = 5_000`, and a new `TIER_4_FLOOR_CENTI = 50_000`. Nothing
above Tier 4 exists in the ladder, so `effective_tier > 4` remains a
`TierNotSupported` refusal — the invariant "value sets the floor and is never
lowered" is preserved verbatim, and `is_valid_opt_up` accepts `3` and `4`.

The effective tier is still computed at **proposal admission** by the home
station and is immutable for the transaction's life. A listing may now claim
`oracle_tier` in `1..=4` (`ORACLE_TIER_MAX = 4` in `rrn-marketplace`); a
transaction paying for that listing takes `max(tier_floor(amount),
listing.oracle_tier, proposal.oracle_tier)` exactly as today.

### 2. Artifacts are hash-anchored records; the bytes are evidence, not state

A new member-signed kind in `rrn-ledger::oracle`:

| `rrn.oracle.artifact` field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | the transaction this evidences |
| `blob_hash` | `Hash` | blake3 of the artifact bytes |
| `media_type` | `String` (≤ 64) | IANA media type, e.g. `image/jpeg`, `application/pdf` |
| `size` | `u64` (≤ 262 144) | byte length of the blob |
| `caption` | `String` (≤ 280) | what the artifact shows, human-readable |
| `submitted_at` | `i64` | testimony (ADR-0022 §3) |

Either party may sign an artifact record for their transaction (`Error::NotAParty`
otherwise); a transaction admits at most **8** artifact records
(`ARTIFACTS_PER_TX_MAX`; the ninth is refused `artifact-limit`). The record is
admitted only while the transaction is `Proposed`, `Confirmed`, or `Disputed`.

The bytes travel as DTN payload kind **`0x04` Artifact** (ADR-0029 §6) — the
tag byte, then the raw blob — and over the member channel as a new
`artifact_submit` method on the sealed `/rpc` channel, gated exactly like
`bundle_submit` (there is no separate route). They are stored in **`artifact_blobs`**, a
station-local content-addressed table (`blob_hash BLOB PK, media_type, size,
bytes BLOB, first_seen_at INTEGER, last_referenced_at INTEGER`), documented as
evidence storage, never a log record. Bounds: a blob is refused if it exceeds
`size`'s cap, if its blake3 does not equal a `blob_hash` that some admitted (or
in-the-same-bundle) artifact record names, or if the store would exceed
`[oracle] artifact_store_max_bytes` (default 512 MiB). Retention: blobs whose
every referencing transaction has been `Settled` or `Cancelled` for longer than
`[oracle] artifact_retention_secs` (default 365 days) are pruned by the existing
DTN prune sweep; the records stay on the log forever.

**A missing blob does not invalidate the record.** The artifact record is a
signed, timestamped commitment by a party that *this* file existed at submission;
replay counts records, not bytes. A station that never received the blob, or has
pruned it, renders "artifact unavailable" and the human readers of the evidence —
witnesses, jurors, the validator — decide what that absence is worth. This keeps
the settle-or-cancel rule (§4) a pure function of the log and keeps a blob-store
failure from re-writing ledger history.

Tier 3 and Tier 4 require **at least one** artifact record admitted before the
window ends (`artifact-required` on the cancellation, §4).

### 3. Witnesses: three staked established members, recused from both parties

A new member-signed kind in `rrn-ledger::oracle`:

| `rrn.oracle.witness` field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | the transaction witnessed |
| `witness` | `Address` | the signer; must equal the envelope signer |
| `statement` | `String` (≤ 500) | what the witness attests to having seen |
| `artifacts` | `[Hash]` | `blob_hash`es of admitted artifact records the witness has examined (may be empty) |
| `witnessed_at` | `i64` | testimony |

Admission rules, all evaluated **as of the transaction proposal's admission
position and instant on the judging log** — `*_asof(at_time = the proposal's
admission instant, max_seq = its seq, station = writer_at(seq))`, ADR-0022 §5 —
so a witness cannot be manufactured after the fact and every replica derives the
same answer:

1. **Established.** The witness's anchored composite standing is ≥ `BAND_MEMBER_MIN`
   (2.0) at that position — the same bar the electorate and the jury pool use.
   During bootstrap grace (ADR-0015) the grace electorate (founders ∪ established)
   may witness, exactly as it may judge.
2. **Recused.** The witness is neither party, nor a direct voucher of either party
   (`vouchers_of_until` at that position — the ADR-0014 §2 collusion edge).
3. **Distinct.** One witness record per `(tx_id, witness)`; a second is `known`,
   never a second vote.
4. **Staked, by derivation.** Witnessing is a reputation-staked attestation in the
   ADR-0011 sense: there is no locked balance and no transferable points. The
   witness's stake is `tier2_stake_centi(composite)` applied to the witness,
   recorded nowhere, and enforced by the reputation consequence in §8 — a witness
   who attests to a transaction later voided by a tribunal or arbitration verdict
   has signed a proven-false attestation.

A witness record may be admitted while the transaction is `Proposed`,
`Confirmed`, or `Disputed`. Because the quorum is judged at the window's end
(§4), witnesses may sign before or after the receiver confirms.

### 4. The Tier-3 rule: settle only with the quorum, otherwise cancel

A Tier-3 transaction moves through the existing state machine with one new
gate at the sweep. Let `W3 = [settlement] tier3_window_seconds` (default **7
days**), running from the **confirmation's admission** (ADR-0022 §2, as Tiers 1–2
do). At the first sweep at or after `confirmed_admission + W3`:

```
Tier 3, at window end (home station's admission clock):
  disputed and dispute live          → skip (ADR-0014 §1 freeze; tribunal window governs)
  artifact records admitted   == 0   → Cancelled(ArtifactRequired)
  valid witness records       <  3   → Cancelled(WitnessQuorumNotMet)
  otherwise                           → Settled   (station-signed rrn.tx.settlement, unchanged shape)
```

The gate is a property of the **transition**, not of the sweep that usually runs
it: for a Tier ≥ 3 transaction it is evaluated on *every* path into `Settled`,
including `Disputed → Settled` after a dispute lapses or is rejected (ADR-0014
§6). A lapsed dispute never lets a Tier-3 transaction settle with fewer than
three witnesses; if the requirements are unmet when the freeze lifts, the
cancellation reason above applies at that transition.

`CancelReason` gains **four** variants here — `ArtifactRequired`,
`WitnessQuorumNotMet`, `ApprovalNotMet`, and `ValidationNotMet` (the last two for
§6) — and a fifth, `FedAborted`, is introduced by ADR-0031 for a cross-community
transaction cancelled by its home's `rrn.fed.abort`. Across the two ADRs the
variant set is exactly those five. A cancellation is a station-signed
`rrn.tx.cancellation` exactly as today: replay trusts the record (the ledger
model), so replicas never recompute the window. The debt-floor headroom the
proposal reserved is released on cancellation as for any other cancel.

Why *cancel* rather than *wait longer*: an unsettled Tier-3 debit holds the
sender's headroom (ADR-0018 point 2) and the receiver's expectation; a bounded
window with a definite outcome is what both parties can plan around. A pair who
missed the quorum simply propose again with their witnesses lined up.

A Tier-3 transaction cannot be **certificate-backed**: `cert_id` on a proposal
whose effective tier is ≥ 3 is refused `CertificateMisuse` at admission (ADR-0021
already caps certificates at the Tier-2 ceiling; this closes the opt-up route
around it). The debt floor applies at proposal as for any debit — a Tier-3
payment needs a committed position of at least `amount − 2_000` centi, which is
the intended friction, not a bug.

### 5. Opt-up composes with the rule

A party or listing may elect Tier 3 for a small transaction (a 3-Common medical
consultation listed at Tier 3). The consequence is exactly the Tier-3 rule: the
7-day window, at least one artifact, three witnesses, tribunal disputes. Nothing
about the amount changes what evidence is demanded — the tier does. Opting up
to Tier 4 likewise pulls in §6 in full, including the governance approval; a
listing that elects Tier 4 for a five-Common item is asking its community to vote
on every sale, which is permitted and silly.

### 6. Tier 4 adds a governance approval and a neutral validation

Tier 4 is the Tier-3 rule plus two further admitted facts, judged at the end of a
longer window `W4`:

**(a) Governance approval.** A new `ProposalKind::TransactionApproval { tx_id:
Hash, amount_centi: i64, parties: [Address; 2] }`, running at the **statute bar**
(`deliberation_window_days`, `statute_quorum_pct`, `statute_approval_pct`, then
`implementation_delay_days`; never immediate). Any electorate member may raise
it; the station refuses one whose `tx_id` is unknown, not Tier 4, or already
terminal, and refuses a second live approval for the same `tx_id` (`known`). The
approval counts once its `rrn.gov.proposal_implemented` attestation is admitted.
It is a distinct kind, so the ADR-0023 compressed emergency window can never
apply to it — a Tier-4 approval always runs the full ordinary process, even
during a declared emergency.

**(b) Neutral validation.** `TransactionProposal` gains an additive field
`validator_community?: CommunityId` (omitted when absent — ADR-0010 discipline;
every existing proposal's id is unchanged). For a Tier-4 transaction it is
**required** at admission (`validator-required`), and the named community must,
at the proposal's admission position, hold an **Active Recognition-depth treaty**
(ADR-0030) with the home community and — for a cross-community transaction —
with the receiver's community too. It must not be the home of either party
(`validator-not-neutral`). The home writer carries the proposal, its artifact and
witness records, and the blobs it holds to the validator in the federation outbox
(ADR-0029). The validator's answer is **a statement of its members, carried by
its writer — never an operator's click.** A transfer of 500 Commons or more must
not hinge on one person at one keyboard (the "administrator clicked a button"
posture ADR-0030 §4 rejects for treaties), and a seized validator writer key
(ADR-0024, ADR-0035) must not be able to manufacture a verdict on its own. So a
verdict is built from a new member-signed kind in `rrn-ledger::oracle`:

| `rrn.oracle.validation_attest` field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | the transaction examined |
| `home_community` | `CommunityId` | where the transaction lives |
| `attestor` | `Address` | the signer; must equal the envelope signer; an established member of the validator community at the attestation's admission position on the validator's log |
| `checked` | `{ witness_history_roots: [Hash], artifact_blobs: [Hash] }` | the `HistoryRoot` hashes of the witness histories and the `blob_hash`es the attestor actually examined — the audit trail the validator community's own members can check |
| `verdict` | `"valid"` \| `"invalid"` | the attestor's judgment |
| `reason?` | `String` (≤ 280) | required when `invalid` |
| `attested_at` | `i64` | testimony |

Attestors are recused if they appear as vouchers in either party's recognized
history (the ADR-0014 §2 collusion edge, applied across the boundary; there is
no party-recusal to apply — the parties are foreign by construction). A
validation attestation is admitted to the **validator's own log** first, under
the validator writer's standing check; the writer then assembles the envelope:

| `rrn.fed.validation` field | type | meaning |
|---|---|---|
| `tx_id` | `TransactionId` | the transaction validated |
| `home_community` | `CommunityId` | where the transaction lives |
| `validator` | `CommunityId` | the answering community (must equal the signer's pinned community) |
| `verdict` | `"valid"` \| `"invalid"` | the community's judgment |
| `attestations` | `[bytes]` (≥ 2) | the canonical signed `rrn.oracle.validation_attest` records, each from a distinct attestor, each agreeing with `verdict` |
| `reason?` | `String` (≤ 280) | required when `invalid` |
| `home_seq` | `u64` | the validator's own log seq at which this record is appended (ADR-0029 §4: the pin input) |
| `validated_at` | `i64` | testimony |

The home log admits the envelope as a foreign record under the ADR-0029 pinning
rules — the writer signature pinned to `writer_at(home_seq)` on the validator's
partner-side lineage — **and** re-verifies each embedded attestation's signature
and distinctness; an envelope with fewer than two agreeing attestations, or one
whose attestations disagree with its `verdict`, is refused `validation-quorum`.
The writer is therefore a *carrier* of its members' judgment: it can withhold a
verdict (a stated residual — a seized or hostile validator writer key delays,
and delay cancels at the window; the remedy is naming a different validator on a
fresh proposal), but it cannot invent one.

What an attestor checks, on the validator station's evidence view: the
proposal's and confirmation's signatures against the parties' addresses; that
every witness record verifies and that each witness's **recognized standing** —
obtained through the ADR-0032 portable-history path from the witness's home
writer, never taken from the home station's say-so — meets the established bar
at the recorded position; that the artifact records verify and that the station
holds the blobs they name — a validator missing a blob does **not** guess: the
station sends the home writer one re-carriage request for the missing
`blob_hash` (slug `artifact-unavailable`, a request rather than a verdict) and
an attestor answers `invalid` with reason `artifact-unavailable` only if the
blob is still absent after `[oracle] artifact_recarriage_secs` (default **7
days**) on the validator's own clock; and the community's own independence per
the neutrality rule. One `valid` envelope suffices; an `invalid` envelope
admitted before the window ends is terminal (`Cancelled(ValidationNotMet)` at
the next sweep, without waiting). Two contradictory envelopes from one validator
are its equivocation against the treaty (ADR-0030): the **first admitted** is
terminal and the later one is `known`, never a reversal. An envelope arriving
while the home↔validator treaty is `Suspended` is refused under ADR-0030 §10 like
any other record from a suspended partner, and the transaction then cancels
`ValidationNotMet` at the window's end unless a fresh, admissible one lands
first.

**The Tier-4 window.** `W4` is computed **from the effective charter at the
confirmation's admission**: `deliberation_window_days + implementation_delay_days`
(so the approval can complete) `+ 7 days` (so witnesses and the validator have
the Tier-3 window's worth of time after it), as `[settlement]
tier4_extra_seconds` (default 7 d) makes explicit. The sweep rule:

```
Tier 4, at window end:
  disputed and dispute live                  → skip
  artifact records admitted == 0             → Cancelled(ArtifactRequired)
  valid witness records < 3                  → Cancelled(WitnessQuorumNotMet)
  no implemented TransactionApproval         → Cancelled(ApprovalNotMet)
  no `valid` validation (or an `invalid`)    → Cancelled(ValidationNotMet)
  otherwise                                  → Settled
```

The order is fixed so the recorded reason is deterministic; the first unmet
requirement names the cancellation.

One race is noted rather than solved: `W4` is read from the charter at the
*confirmation's* admission, while the `TransactionApproval` proposal's own
window is read from the charter at *its* admission (`window_for`). A charter
amendment that lengthens the statute process between the two can make `W4`
end before the approval can complete, cancelling `ApprovalNotMet` through no
fault of the parties. The parties re-propose; a station may warn when the two
readings differ.

### 7. Cross-community Tier 3 and 4

A cross-community transaction (ADR-0031: `receiver_community` present) at Tier 3
or 4 follows the ADR-0031 prepare/commit flow with the evidence rule layered on
the **home** (paying) log, which is authoritative for the outcome; the receiver's
log mirrors by admitting the home's **terminal** record — its
`rrn.fed.settlement{export}` or its abort — and an unmet requirement
surfaces as an `rrn.fed.abort` whose `reason` names it — `"artifact-required"`,
`"witness-quorum"`, `"approval-not-met"`, or `"validation-failed"` (the ADR-0031
§4 enum) — which the receiver mirrors as `Cancelled(FedAborted)`.

**The cross-community window.** A cross-community Tier-3 or Tier-4 transaction
runs, on the home clock, a window of `max(treaty.settlement_window_secs, tier
window)` — the tier window being `W3` or the charter-derived `W4` of §4/§6 — so
the treaty's own settlement term can lengthen but never shorten the evidence
window. The receiver mirrors as ADR-0031 §9 describes: it appends its own
`rrn.fed.settlement{import}` only on admission of the home's
`rrn.fed.settlement{export}` — never on a window of its own run from the commit
— so no evidence gate, dispute, or arbitration outcome on the home side can be
outrun by the receiver's clock. Any window the receiver shows is a display
estimate.

Witnesses may be members of **either** party's community. Each witness record is
admitted first by the witness's *home* writer, which applies §3's rules against
its own standing and vouch graph (it is the only station that can) — for a
foreign witness the eligibility position is the witness's home log's admission
position of the *carried proposal*, not the home-of-transaction's seq — and then
carried to the other community in the federation outbox, where it is admitted as
a foreign record — verified for signature and carriage, with the home writer's
admission standing in for the standing check. Artifacts likewise: submitted to
either home, carried to the other. The three-witness count on the home log
therefore includes foreign witnesses whose eligibility the partner writer
attested by admitting them; a partner that admits an ineligible witness has
equivocated against its treaty (ADR-0030), which is the accountability the
treaty exists to create.

For Tier 4 across communities, the validator must be a third community with
Active Recognition treaties with **both** homes; the `TransactionApproval`
proposal runs in the **home** (paying) community only.

### 8. The reputation input (ADR-0009 revision)

ADR-0009 locks the scoring algorithm "at the federation-protocol level" and says
its constants change only by federation-wide governance. This is that level:
the federation ADR set defines the protocol the federation runs. In the same way
[ADR-0021](0021-escrowed-offline-spending-certificates.md) carried "a scoring
input under ADR-0009's locked formula revision accompanying this ADR", this ADR
adds **one input and no constants**:

> A `rrn.oracle.witness` record is an attestation for the
> `attestation_accuracy` dimension. It counts **accurate** once the witnessed
> transaction is `Settled`, and **inaccurate** if the transaction is later voided
> by an upheld tribunal verdict (ADR-0034 Layer 3) or an upheld federation
> arbitration verdict (Layer 4) whose case names that transaction. A witness
> record on a transaction that is cancelled for any other reason (quorum,
> approval, validation, expiry, withdrawal) is neither — it is not scored.

Weights, dimensions, decay, velocity, bands, and anchoring are untouched; the
`ScoringContext` single-replay derivation extends to the new kind. A residual
follows from "accurate on `Settled`": a friend circle can farm attestation
*volume* by opting up micro-trades to Tier 3 and witnessing each other. ADR-0009's
velocity limit (0.5 per dimension per week) bounds what that buys, exactly as it
bounds confirmation-volume farming today; it is stated, not solved. This is the
"fraud-finding mechanism" ADR-0009 said Phase 1 lacked, arriving where the
overview put it: at Tier 3.

### 9. Disputes at Tier 3 and above go to the tribunal

A dispute on a Tier-3 or Tier-4 transaction (raised by either party inside the
window, as today) is heard by the **community tribunal** (ADR-0034 Layer 3),
not the three-juror jury; a cross-community one may be taken to federation
arbitration (Layer 4) by either party. The freeze, the fail-open lapse, and the
`Disputed → Settled | Cancelled(DisputeUpheld)` outcomes are ADR-0014's; only the
forum changes. A tribunal that upholds the dispute voids the transfer and, per
§8, marks every witness on it inaccurate.

## Consequences

- **The refused half of the ladder opens.** Payments of 50 Commons and up admit,
  with the scrutiny §4.3 asked for, and the docs' standing "No Tier 3 or higher"
  line comes down when this ships.
- **The log still holds only signed records.** Blobs are a bounded, prunable,
  station-local evidence store; a station can lose every blob and derive the
  identical ledger. The cost is that artifact evidence is best-effort for a
  replica or a distant validator — stated, not hidden.
- **Three new member-signed kinds (`rrn.oracle.artifact`, `rrn.oracle.witness`,
  `rrn.oracle.validation_attest`) and one new station-signed kind
  (`rrn.fed.validation`)**, each with a discriminator, a dCBOR fixture, and a
  threat-model section; `CancelReason` gains
  four variants here (five across the set with ADR-0031's `FedAborted`; additive
  to a station-signed record, so replay of old logs is unaffected). `TransactionProposal` gains one additive optional field.
- **Windows lengthen with the tier.** Seven days is the honest price of gathering
  three humans and a photograph; Tier 4 is bounded by the community's own statute
  process. Both are admission-anchored and deterministic per log.
- **Tier 4 is unreachable without a Recognition treaty** — by design. A lone
  community can trade at Tier 3 and stops there, which matches ADR-0017's
  sequencing and the overview's "neutral third community validates".
- **Mobile and CLI surfaces.** The phone and `rrn wallet` gain "add evidence" and
  "witness this" signing paths (FFI: `artifact_record_sign`, `witness_sign`; blob
  upload over the member channel); the operator console gains
  `rrn oracle validate` (which shows the evidence view and collects the members'
  attestations) for a validator station. The mobile repo receives fixtures
  and a handoff note.
- **Threat-model obligations** (`rrn-ledger::oracle` section, same PR): witness
  collusion (three colluders must all be established and unrecused, and each stakes
  their attestation accuracy against a tribunal; residual: a faction that owns the
  tribunal too — ADR-0014's coordinated-capture residual, restated); artifact
  substitution (the hash is signed; a swapped blob fails content addressing; a
  *misleading* artifact is a witness/tribunal question, not a crypto one); blob DoS
  (per-record size cap, per-transaction record cap, store cap, prune sweep,
  member-channel gate; residual: no per-member rate limit, as everywhere);
  validator capture (neutrality rule, Recognition-only, a two-attestor member
  quorum with an audit trail so no operator can sign a verdict alone, treaty
  suspension as the remedy; residuals: a validator writer key can *withhold* a
  verdict, and a validator community whose members attest carelessly is
  accountable only through its treaty).

## Alternatives Considered

- **Blobs on the log.** Rejected: every replica, partner, and paper sheet would
  carry every photograph forever; the log stops fitting on a LoRa link or a QR
  page, and a blob bug becomes a ledger bug.
- **Witnesses only, no artifact channel.** Rejected (maintainer decision): it
  drops "evidence is cryptographically timestamped" and leaves a witness with
  nothing to point at; the hash-anchored form costs one record kind.
- **Wait indefinitely for the quorum.** Rejected: an open-ended pending debit
  holds the sender's headroom forever and is the indefinite freeze ADR-0014 §5
  refused to build.
- **Clamp a large transaction to Tier 2 when no witnesses exist.** Rejected, as in
  ADR-0011: value sets a floor that is never lowered.
- **Validator drawn by sortition from the federation directory.** Deferred: it
  needs a federation-wide electorate the Phase 4 governance body will define; a
  party-named validator constrained to Recognition partners and neutrality is
  verifiable today.
- **A locked witness stake balance.** Rejected, as ADR-0011 rejected it for Tier 2:
  a mutable "locked reputation" is a second source of truth; the derived gate plus
  the §8 accuracy consequence is reconstructible from the log.
- **Tier 3 only in Phase 3.** Rejected (maintainer decision): the exit criterion's
  inter-community dispute and "the system has teeth" milestone want Tier 4's
  neutral validation in the same phase as federation.

## References

- Design overview §4.3 (the tiered oracle model), §4.4 (every oracle reduces to
  social trust), §7.3 (the four-layer resolution stack)
- [ADR-0011](0011-oracle-tier-model-phase-1.md) — Tiers 1–2, block-never-clamp,
  the derived stake gate this extends to witnesses
- [ADR-0009](0009-universal-reputation-algorithm.md) — the locked formula;
  attestation accuracy gains its first fraud-finding input here
- [ADR-0014](0014-phase-1-dispute-resolution.md) — freeze, fail-open, recusal
- [ADR-0018](0018-debt-floor.md), [ADR-0021](0021-escrowed-offline-spending-certificates.md)
  — headroom at proposal; certificates capped below Tier 3
- [ADR-0022](0022-admission-clock-time-trust.md) — every window here is
  admission-anchored; `*_asof` position bounding for witness eligibility
- [ADR-0029](0029-federation-identity-profiles-and-carriage.md) — payload kind
  `0x04`, the federation outbox, foreign-record admission and writer-key pinning
- [ADR-0030](0030-treaties-ratification-depth-lifecycle.md) — Recognition depth, treaty state, partner
  accountability
- [ADR-0031](0031-cross-community-credit-treaty-accounts.md) — the prepare/commit flow this rule
  layers on, and §9's rule that the receiver settles only on the home's terminal
  `settlement{export}`; the `abort` reason enum (`artifact-required`, `witness-quorum`,
  `approval-not-met`, `validation-failed`) and `CancelReason::FedAborted`
- [ADR-0032](0032-recognition-portable-standing-cross-community-marketplace.md) — the
  portable-history path a validator uses to verify foreign witnesses
- [ADR-0034](0034-community-tribunal-and-federation-arbitration.md) — where Tier 3+
  disputes are heard, and the verdicts that make a witness attestation inaccurate
- `crates/rrn-ledger/src/{tier,settlement,state,credit}.rs`,
  `crates/rrn-storage/src/dtn.rs` (the blob store's neighbour),
  `docs/spec/dtn-bundles.md` §7.1 (payload-kind registry)
