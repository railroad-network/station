# 0012 — The Charter: a self-bootstrapping constitutional document, and how a community changes it

## Status

Accepted

Date: 2026-08-06

## Context

The design overview (Section 2.2) layers a community's governance on a stack of
documents, each with its own permanence and its own bar for change: the
**Charter** (constitutional), **statutes** (legislative), **administrative
rules** (operational), and **precedent** (common law). M1.9 builds the first two
layers and the direct-voting machinery that moves a proposal through the
lifecycle in Section 2.4. This ADR fixes the **Charter** — its format, how it is
signed into being, and how it is amended — because it is the layer everything
else references and, by design (Section 2.2.1), the hardest to change after the
fact. Getting the format wrong is expensive later; getting it right now is cheap.

The Charter is described in the overview as "a cryptographically hashed document
— any change produces a different hash, and treaty partners can verify they are
still dealing with the same community they originally federated with" (Section
2.2.1, echoed by the community profile in Section 8.3). That gives us three fixed
requirements up front: a canonical byte encoding, a stable hash over it, and a
version/lineage so one Charter can supersede another without ambiguity.

Two forces specific to *this* codebase shape the rest of the decision:

- **There is no roster and no notion of a "founder" anywhere in the system
  today.** Membership is derived from the log at read time — `known_addresses`
  (`rrn-reputation::snapshot`) is simply every address that has appeared as a
  transaction party or in a vouch. A station has an *operator* (its own wallet
  key); everyone else becomes a member implicitly by transacting or being
  vouched. Nothing records who founded a community. So the task sketch's
  `founders: Vec<Address>` and its "≥ 75 % of founding members sign" rule have no
  pre-existing source of truth to read from — the founding set has to come from
  somewhere, and that somewhere cannot be a table we do not keep.

- **Reputation is the only earned, Sybil-resistant signal we have** (ADR-0009),
  and it is derived from the log. Any definition of "who may vote" that we want to
  be capture-resistant (Section 2.8) has to lean on it rather than on raw address
  count, which a Sybil can inflate for free.

## Decision

Phase 1 ships the Charter, statutes, and **direct voting only**
(`VotingMechanism::Direct`). Liquid democracy, sortition, councils, consent-based,
and quadratic voting (overview Section 2.3) are all Phase 2+, and the schema is
shaped so adding them later is additive. Five sub-decisions follow.

### 1. The Charter schema

A Charter is a canonical-CBOR document (ADR-0002) carrying its own governance
parameters, its founding set, and its lineage:

```rust
pub struct Charter {
    pub version: u32,                         // 1 at genesis; +1 per amendment
    pub community_id: String,
    pub founding_principles: Vec<String>,
    pub rights_floor: Vec<String>,            // rights above the federation universal floor
    pub governance_structure: GovernanceStructure,
    pub amendment_rules: AmendmentRules,
    pub created_at: i64,
    pub founders: Vec<Address>,               // the genesis founding set (see §3)
    pub previous_hash: Option<Hash>,          // None at genesis; the prior charter_hash on amendment
}

pub struct GovernanceStructure {
    pub voting_mechanism: VotingMechanism,    // Phase 1: Direct only
    pub statute_quorum_pct: u8,               // default 30
    pub statute_approval_pct: u8,             // default 50 (simple majority of cast yes/no)
    pub deliberation_window_days: u8,         // default 7 for statutes
    pub implementation_delay_days: u8,        // default 7 for non-emergency
    pub emergency_threshold_pct: u8,          // default 67 (higher bar; immediate effect)
}

pub struct AmendmentRules {
    pub charter_quorum_pct: u8,               // default 50
    pub charter_approval_pct: u8,             // default 75
    pub charter_deliberation_window_days: u8, // default 30
}

pub enum VotingMechanism { Direct }          // Liquid, Sortition, Council, Consent, Quadratic in Phase 2+
```

`charter_hash = Blake3(to_canonical_bytes(charter))`. Because the encoding is
deterministic, the hash is stable across runs and machines, which is exactly the
property the community profile (Section 8.3) and future federation partners pin.
The defaults above are the overview's numbers where it gives them (75 %/30-day for
amendments, 7-day statute deliberation, higher emergency bar) and conservative
Phase-1 choices where it does not; every one is a Charter field, so a community
may set its own — the ADR only fixes the *shape*, not the *values*.

### 2. `MultiSignedPayload<T>` — the multisig primitive

`SignedPayload<T>` (`rrn-crypto::signed`) carries exactly one signer and one
signature. A Charter needs N of them. We add a sibling rather than overload it:

```rust
pub struct MultiSignedPayload<T> {
    pub payload: T,
    pub signers: Vec<PublicKey>,
    pub signatures: Vec<Signature>,  // signatures[i] is signers[i] over to_canonical_bytes(payload)
}
```

`verify()` checks each `(signer, signature)` pair against the canonical bytes of
the same payload, rejects duplicate signers, and returns the set of *distinct
valid signers* so a caller can apply its own threshold. This keeps the primitive
threshold-agnostic — the Charter supplies the threshold, the crypto layer supplies
verification — and it is the same content-addressing model as `SignedPayload`, so
the cross-platform CBOR fixtures extend rather than fork. It is a new signed
shape, so it gets its own cross-platform fixture: mobile must be able to *verify*
a Charter even in Phase 1, and to *co-sign* one whenever charter authorship
reaches the phone (Phase 1 mobile signs single-sig proposals and votes; a phone
co-signing a genesis Charter is a Phase-1-optional path called out in T1.9.7b).

### 3. The founding set is self-declared at genesis — trust on first use

Because no roster or founder record exists to draw from (see Context), the
Charter **is** the source of truth for its own founders. At genesis:

- The Charter names its founders in `founders`, and is published as a
  `MultiSignedPayload<Charter>`.
- It is **valid iff the distinct valid signers are a subset of `founders` of size
  ≥ `ceil(founders.len() * 0.75)`.** The founding set is, definitionally, whoever
  co-signs the first Charter; there is no prior authority to appoint them, so the
  genesis Charter is self-authenticating and the community (and later, federation
  partners) pin the resulting `charter_hash` on first sight.

This is the same trust-on-first-use posture the rest of the system already takes
toward a fresh identity, lifted to the community. The ≥ 75 % founder threshold is
what stops any single named founder from being able to stand up a Charter alone —
the multisig has to be genuinely multi.

### 4. Amendments go through the vote lifecycle, not a second multisig

The overview treats a Charter amendment as a *proposal* (Section 2.4;
`ProposalKind::CharterAmendment { new_charter }` in T1.9.4), and once a community
exists it has the machinery to ratify one properly. So an amendment is **not** a
fresh founder-style multisig — it is an ordinary proposal carrying the full
replacement Charter, run at charter-level thresholds:

- 30-day deliberation (`charter_deliberation_window_days`), then a direct vote
  requiring `charter_quorum_pct` participation and `charter_approval_pct` approval
  (defaults 50 % / 75 %).
- The replacement Charter sets `version = prior.version + 1` and
  `previous_hash = Some(prior_charter_hash)`, chaining the lineage. On passage the
  station publishes it (`charter_published`), and it supersedes the prior Charter;
  `current_charter` is always the highest-version published Charter whose lineage
  is intact.

Choosing the vote path over the task sketch's "signed by ≥ X % of current members"
phrasing avoids two parallel ratification mechanisms: the vote log *is* the
authorization, already immutable and auditable, and it reuses the same tally the
rest of governance uses. `founders` on an amended Charter is retained unchanged as
historical record — it is a genesis fact, not a live membership list.

### 5. "Current member" — for voting and quorum — is an established member

Voting eligibility and the quorum denominator both need a concrete member set,
and `known_addresses` is the wrong one: it includes every address that ever
transacted, a drive-by counterparty who has since left inflating the denominator
and making quorum unreachable. Phase 1 defines the electorate as the
**established members** — those whose *effective* (anchored) composite reputation
is ≥ 2.0, the Member band — reusing M1.8's `established_member_count`
(`rrn-reputation::staking`) rather than inventing a new roster.

The consequence is deliberate and worth stating plainly: Phase 1 direct voting is
**one established-member, one vote.** Proposal *authorship* already requires the
same ≥ 2.0 (T1.9.4); this extends the bar to the ballot, which is the
capture-resistant choice — a flood of fresh or Sybil identities carries no
governance weight until it has earned standing, exactly the defense Section 2.8
asks for. It interacts with M1.8's bootstrap grace: a community with fewer than
three established members has an electorate of zero to two, so it effectively has
no formal governance yet. That is acceptable — a community that small settles
things by talking, not by quorum — and it resolves the same way bootstrap grace
does, automatically, as members reach the Member band. Abstentions count toward
quorum but not toward the approval ratio (`yes / (yes + no)`); silence is
non-participation, not abstention.

### Scope boundaries

`rrn-governance` depends on `rrn-reputation` (the eligibility signal) but **not on
`rrn-ledger`**: governance in Phase 1 decides policy, it does not move credit.
This preserves the crate's stated dependency posture and matches the scope — a
statute that would change a ledger parameter (say, the settlement window ADR-0011
earmarked for governance tuning) records the *intent* in the statute body in Phase
1; wiring a passed statute to actually mutate a config value is a Phase 2 rule
engine (T1.9.7 "out of scope"). No credit-moving path means no ledger dependency.

## Consequences

- **Positive.** The Charter is self-bootstrapping: a brand-new community can stand
  up its constitution with nothing but the founders' own keys, and the resulting
  hash is the stable federation anchor the overview asks for. Defining the
  electorate as established members makes one-member-one-vote genuinely
  Sybil-resistant for free, reusing machinery M1.8 already built. Amendments reuse
  the ordinary vote lifecycle, so there is exactly one ratification path to reason
  about and audit. `MultiSignedPayload` is a small, general primitive that other
  future N-of-M needs can share.
- **Negative / accepted.** A very young community (< 3 established members) has no
  working formal governance — by construction. Tying the vote to the ≥ 2.0 floor
  means governance weight tracks reputation, which is a policy choice, not a
  neutral one; it is the intended anti-capture posture but it does concentrate
  early influence in the first members to establish standing. A statute cannot yet
  *enforce* itself against a config value — Phase 1 records and displays it, humans
  apply it.
- **Follow-up.** Phase 2 adds the other voting mechanisms (the enum is ready for
  them), the statute→config rule engine, constitutional-conflict review of
  statutes against the Charter (Section 2.2.2), precedent linking (Section 2.2.4),
  and membership/expulsion governance (Section 2.6). The mobile Charter co-signing
  path and any federation-side hash pinning are called out where they arise
  (T1.9.7b, Phase 2 federation).

## Alternatives Considered

- **Derive founders from the log (first N addresses, or established members at
  genesis time).** Rejected: arbitrary and fragile — "first to appear" is a race,
  and a genesis-time reputation snapshot is empty in a community that has no
  history yet. Self-declaration is honest about where the trust actually comes
  from (the founders themselves) and pins it in the hash.
- **Operator is the sole founder / single-signature genesis Charter.** Rejected:
  it defeats the whole point of the founder multisig, which exists so no one
  person can author a community's constitution unilaterally.
- **Amendments as a fresh member multisig (the task sketch's literal reading).**
  Rejected: it creates a second ratification mechanism parallel to the vote
  lifecycle, with its own signature-collection UX and its own audit path, for no
  gain over running a `CharterAmendment` proposal at charter-level thresholds.
- **Electorate = any log-present address (`known_addresses`).** Rejected: it
  inflates the quorum denominator with departed counterparties and hands a Sybil
  free voting weight, gutting one-member-one-vote.
- **A stored, explicit membership roster.** Rejected: membership stays derived
  from the log, consistent with the rest of the system; a maintained roster is a
  new source of truth to keep correct and a new thing to attack.
- **Depending on `rrn-ledger` so statutes can change config directly.** Rejected
  for Phase 1: nothing in scope moves credit, and the rule engine that would apply
  a config-changing statute is explicitly Phase 2; the dependency would buy
  nothing now and contradict the crate's design note.

## References

- Design overview, Section 2.2 (constitutional architecture) and 2.2.1 (the
  Charter); Section 2.3 (voting mechanisms); Section 2.4 (proposal lifecycle);
  Section 2.8 (governance capture); Section 8.3 (the community profile and its
  hash).
- [ADR-0002](0002-canonical-serialization-dcbor.md) — deterministic CBOR, the
  encoding the charter hash is stable over.
- [ADR-0009](0009-universal-reputation-algorithm.md) — reputation derived from the
  log; the composite the ≥ 2.0 electorate floor reads.
- [ADR-0011](0011-oracle-tier-model-phase-1.md) — the settlement window earmarked
  for per-community governance tuning; the bootstrap-grace / established-member
  machinery this reuses.
- `rrn-crypto::signed::SignedPayload` — the single-signer envelope
  `MultiSignedPayload` extends.
- Threat model — `rrn-governance` § (to be populated at the M1.9 exit criterion).
