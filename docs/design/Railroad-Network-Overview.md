# Railroad Network
## Federated Community Platform — Design, Architecture & Implementation Strategy

*A blueprint for self-organizing communities with federated governance, mutual credit economics, decentralized identity, and resilient peer-to-peer trade — inspired by Harriet Tubman's Underground Railroad.*

> **Status note (2026-07-04).** Parts of this overview predate the implementation and the
> Architecture Decision Records. Where this document and an ADR in [`docs/adr/`](../adr/)
> conflict, **the ADR is authoritative**. Locked implementation decisions (libraries,
> formats, units) are summarized in the repository's `CLAUDE.md`.

---

## Table of Contents

1. [Vision & Design Philosophy](#1-vision--design-philosophy)
2. [Governance & Political Design](#2-governance--political-design)
3. [The Mutual Credit System — The Commons](#3-the-mutual-credit-system--the-commons)
4. [The Oracle Problem](#4-the-oracle-problem)
5. [The Reputation System](#5-the-reputation-system)
6. [Identity Layer](#6-identity-layer)
7. [Dispute Resolution](#7-dispute-resolution)
8. [The Federation Protocol](#8-the-federation-protocol)
9. [The Marketplace](#9-the-marketplace)
10. [Technical Architecture](#10-technical-architecture)
11. [User Experience Design](#11-user-experience-design)
12. [Development Roadmap](#12-development-roadmap)
13. [Legal & Political Landscape](#13-legal--political-landscape)
14. [Key Design Decisions Summary](#14-key-design-decisions-summary)
- [Appendix](#appendix)

---

## 1. Vision & Design Philosophy

Railroad Network is a federated platform enabling self-organizing communities to establish their own governance, economics, identity systems, and trade relationships — both within and across community boundaries. It is designed to function as civilization infrastructure: the minimum viable coordination stack for human organization above the family and tribe level.

The name Railroad Network is a deliberate nod to Harriet Tubman's Underground Railroad — a decentralized, federated network of trusted nodes operating under hostile conditions, with no central authority, using reputation and personal vouching as its trust layer. The Underground Railroad succeeded not because it had perfect technology, but because its human trust architecture was sound. Railroad Network encodes those same principles into software.

### 1.1 The Core Analogy

| Underground Railroad | Railroad Network |
|---|---|
| **Stations** | Communities — autonomous, self-governing nodes providing shelter, resources, and passage |
| **Conductors** | High-reputation inter-community facilitators who move people, goods, and information between communities |
| **Freedom seekers** | New community members who arrive with no local reputation, relying on the vouching chain |
| **Routes** | Federation treaties — established trust corridors between communities built on transaction history |
| **Compromised stations** | Communities with poor reputation scores that the network routes around |
| **The North Star** | The universal rights floor — the non-negotiable founding principle of freedom and dignity |
| **Safe harbor** | Communities with open admission for refugees from collapsed or captured communities |
| **Need-to-know** | Pseudonymous identity — contextual disclosure, not full transparency |
| **Letters of introduction** | Signed community profiles carried by conductors between communities |
| **Word of mouth** | Gossip protocol for reputation propagation through the network |
| **Station master** | Community node operator earning a small credit stipend |

### 1.2 The Use Case Spectrum

Railroad Network is designed primarily for the **medium-collapse scenario**: regional grid instability, intermittent connectivity, physical security threats, and localized governance vacuums. This is the most likely and most interesting engineering challenge. The system is useful across a spectrum:

| Scenario | Description |
|---|---|
| **Soft collapse** | Institutions weakened, supply chains disrupted, currency unstable, internet mostly works. Example: Argentina 2001, Venezuela, post-Soviet states. |
| **Medium collapse** | Regional grid instability, intermittent connectivity, physical security threats, governance vacuums. **PRIMARY DESIGN TARGET.** |
| **Hard collapse** | No reliable internet, no power grid, physical infrastructure gone. System degrades to LoRa radio, SMS, and paper fallback. |
| **Pre-collapse (today)** | Intentional communities, mutual aid networks, worker cooperatives, and underserved rural communities benefit immediately. |

### 1.3 Design Constraints

Everything in the architecture flows from these non-negotiable constraints:

- **Offline-first** — the system works with zero connectivity; connectivity adds capability but is never required
- **Local-first** — community data lives on community hardware, not in a cloud owned by any third party
- **Byzantine-aware** — assumes some nodes are malicious or compromised and designs around that reality: misbehavior is made detectable and attributable through signed, hash-chained records rather than assumed away (see 10.4 for the precise consensus trust model)
- **Incrementally deployable** — a single community can run the full system in isolation; federation adds value but is not required to bootstrap
- **Low-resource capable** — runs on a Raspberry Pi 4; does not require data center infrastructure
- **Useful at every phase** — each roadmap phase delivers standalone value; the project does not require full completion to be useful

### 1.4 Historical Precedents

Railroad Network encodes lessons from governance and trade systems that operated without central authority for centuries:

- **Iroquois Confederacy** — Federated sovereign nations with shared meta-governance under a constitution — the Great Law of Peace, preserved orally and in wampum — predating the US Constitution
- **Hanseatic League** — Federated trade network spanning 200 cities across northern Europe for 400 years, with shared commercial law, mutual dispute resolution, and collective sanctions — all without a central government
- **Medieval guild systems** — Cross-community professional standards, credentialing, and reputation networks that maintained quality and trust across trade routes
- **Somali xeer** — Customary law that functions without a state, enforced through clan reputation and mutual obligation
- **LETS systems** — Local Exchange Trading Systems operating since the 1980s in hundreds of communities globally, demonstrating that zero-sum credit creation is practically viable
- **Wörgl Experiment (1932)** — Austrian town ran a complementary currency with demurrage during the Great Depression; unemployment dropped 25% while surrounding towns deteriorated; terminated by the central bank after 13 months

---

## 2. Governance & Political Design

Governance is the constitutional layer everything else rests on. Every other system — credit, reputation, identity, disputes — operates within the governance framework a community establishes.

### 2.1 The Fundamental Tension

Every governance system must resolve a core tradeoff between **efficiency** (decisions made fast, by capable people) and **legitimacy** (decisions feel fair, everyone had a voice). Most real-world governments fail at one or both. Software-mediated governance can do better — but it can also fail in new ways.

### 2.2 The Constitutional Architecture

All governance sits on a layered document structure. Each layer has different thresholds for change, different scope, and different permanence.

#### 2.2.1 The Charter — Constitutional Layer

The Charter is the founding document of every community. It establishes the community's core values and purpose, fundamental rights that cannot be legislated away, the governance structure itself, and the amendment process — which is deliberately hard. Charter amendments require a supermajority (typically 75%) plus a mandatory deliberation window of at least 30 days.

The Charter is stored as a cryptographically hashed document — any change produces a different hash, and treaty partners can verify they are still dealing with the same community they originally federated with.

#### 2.2.2 Statutes — Legislative Layer

Regular community laws passed through normal governance. Statutes cannot contradict the Charter — a constitutional review mechanism flags conflicts before passage. They can be repealed and amended through the normal process.

#### 2.2.3 Administrative Rules — Operational Layer

Day-to-day operational decisions delegated to specific roles or committees. Low threshold to change, high transparency requirement. Administrative rules automatically sunset if not renewed periodically.

#### 2.2.4 Precedent — Common Law Layer

Dispute resolutions establishing standing interpretations of the Charter and statutes. Builds organically over time, allowing the system to develop nuance without requiring the legislature to anticipate every scenario in advance. Precedent records are permanently stored and linked to the decisions that informed them.

### 2.3 Voting Mechanisms

Different decisions warrant different voting mechanisms. A single mechanism for everything is a design failure.

| Mechanism | Description & Best Use |
|---|---|
| **Direct vote** | Every member votes directly. Best for constitutional amendments, major resource decisions, membership expulsions. High legitimacy, high friction. |
| **Liquid democracy** | Vote directly OR delegate your vote to someone you trust, per issue. Delegation chains form naturally around expertise. Solves the expertise problem while preserving direct participation rights. |
| **Sortition panels** | Random selection from qualified members, like jury duty. Eliminates campaigning, reduces factional capture. Best for reviewing administrative decisions and constitutional interpretation. |
| **Delegated councils** | Elected or appointed small groups with authority over specific domains. Medical council governs health standards. Each council has defined scope and term limits. |
| **Consent-based** | Proposal passes unless actively blocked by a threshold of objectors. Dramatically reduces friction for non-controversial matters. |
| **Quadratic voting** | Members allocate a budget of voice points across issues ("points", not "credits" — unrelated to Commons). Diminishing returns on any single issue lets intensity of preference matter. Minority positions with deep convictions can make themselves heard. |

### 2.4 Proposal Lifecycle

1. **Drafting** — Any member above a reputation threshold drafts a proposal. Requires co-signatures from N members to advance.
2. **Deliberation window** — Published to all members. Fixed window: 7 days for statutes, 30 days for charter amendments. Open comment period with amendment capability.
3. **Voting** — Appropriate mechanism per decision type. Quorum requirement ensures minimum participation. Result recorded cryptographically and immutably.
4. **Implementation delay** — Non-emergency laws have a delay before taking effect. Gives dissenters time to exit, appeal, or organize.
5. **Precedent linking** — New laws linked to any dispute precedents that informed them, creating an auditable legislative history.

### 2.5 The Rights Layer

#### 2.5.1 Federation-Level Universal Rights

Agreed by all communities as a condition of federation membership. No community can violate these regardless of internal governance:

- No member can be expelled without due process and a right to present a defense
- No member can be denied access to emergency services regardless of credit balance
- No collective punishment — individuals are responsible for their own actions
- Right to exit — any member can leave any community at any time, taking their identity and reputation with them
- Right to appeal — any governance decision affecting an individual can be appealed to federation arbitration
- No retroactive laws — statutes cannot criminalize actions that were legal when performed

#### 2.5.2 Community Charter Rights

Each community adds their own rights above the federation floor, reflecting the community's values and protected from simple majority erosion.

### 2.6 Membership Governance

#### 2.6.1 Admission

Standard elements: application or introduction process, existing member sponsorship (the vouching layer), a probationary period with limited governance rights, and full membership granted after probation.

#### 2.6.2 Expulsion

Requires formal process. Evidence standard scales with severity. The accused has a right to present their case. Appeals available to the federation layer. Graduated sanctions apply before expulsion: warning → restriction → suspension → expulsion. An expelled member retains their identity and reputation record — they are not erased, just removed from this specific community.

### 2.7 Emergency Governance

- **Trigger** — Declared by a council or executive role with immediate community-wide notification
- **Scope** — Strictly limited to the declared emergency domain; a flood emergency does not authorize economic restructuring
- **Duration** — Automatic expiration after N days (typically 7-14, community-defined) unless renewed by explicit vote
- **Accountability** — All emergency actions logged and subject to post-emergency review
- **Sunset** — Emergency powers cannot become permanent without full normal legislative process; burden falls on renewal, not termination

### 2.8 Governance Capture — The Existential Threat

A community's governance can be captured by a faction that accumulates voting power, controls reputation, monopolizes proposal-making, or uses expulsion to remove opposition. Defenses:

- Reputation velocity limits prevent rapid accumulation of governance weight
- Sortition introduces genuine randomness that factions cannot control
- Charter rights protect minorities from majority overreach
- Federation oversight provides an external check on captured communities
- **Exit rights** are the most powerful anti-capture mechanism — a community that becomes oppressive loses members; the captured community weakens

---

## 3. The Mutual Credit System — The Commons

The economic foundation of Railroad Network is a universal mutual credit system with a single credit unit called **the Common**. Every transaction everywhere is denominated in Commons. No exchange rates, no forex, no community-specific currencies.

### 3.1 How Mutual Credit Works

No tokens are pre-minted. The ledger tracks balances only. Every member starts at zero. When you provide value, your balance goes positive. When you receive value, your balance goes negative. **Every ledger entry is balanced, so the sum of all balances in the network — member accounts plus each community's commons-pool account — always equals zero.**

Mechanisms that create or retire credit outside of trade — base issuance, contribution minting, demurrage, jubilees (see 3.3 and 3.5–3.6) — are booked against the community's **commons pool**, an ordinary ledger account, so the invariant holds everywhere.

```
Example transaction:

  Dr. Sarah treats patient James:
    Sarah's balance:  0 → +3 Commons
    James's balance:  0 → -3 Commons
    Network total:    still 0

  Sarah buys 8 Commons of grain from Valley Farm:
    Sarah's balance: +3 → -5 Commons
    Farm's balance:   0 → +8 Commons
    Network total:    still 0
```

Amounts are recorded as signed integer **centicommons** (1 Common = 100 centicommons) in the ledger and in every signed payload — never floating point. Whole-Common amounts in this document are readable shorthand for their centicommon values.

### 3.2 Why One Universal Credit Unit

A critical design decision: rather than each community issuing its own credits with floating exchange rates, Railroad Network uses a single federated credit unit — the Common.

| Benefit | Explanation |
|---|---|
| **No forex friction** | A doctor charges 3 Commons. A farmer charges 5 Commons. Immediately comparable, no conversion. |
| **Portable credit history** | Your balance and reputation travel natively across communities — no translation layer. |
| **Simpler mental model** | Users think about one number. Enormous UX advantage in low-tech scenarios. |
| **Inter-community trade trivial** | No exchange rate negotiation, no trusted third party needed to bridge currencies. |

The 'centralization' is in the accounting unit, not in governance of it. All nodes replicate the same ledger state, but no single node controls it. This is the EU model applied to micro-communities: local sovereignty over everything except the shared monetary infrastructure.

### 3.3 Credit Creation Mechanisms

#### 3.3.1 Mutual Credit Base (Core)
Credits are created by the act of trade. When you provide a service, your balance goes up; the receiver's goes down. No one mints anything. This is the most collapse-resilient option: no prior coordination required, no central issuer that can fail, scales naturally with economic activity.

#### 3.3.2 Basic Activity Issuance (Optional)
Communities can optionally enable a small base issuance (e.g., 10 Commons per active member per week) to bootstrap participation for new members. Issuance rate governed at the federation level to prevent inflation. Issuance is booked as a debit against the community's commons-pool account, preserving the zero-sum invariant.

#### 3.3.3 Contribution-Based Minting (Advanced)
Some transaction categories — environmental stewardship, community infrastructure work — can trigger net credit creation when verified work occurs. Requires a robust oracle. Phase 3+ feature. Minting rate set through federation governance. Like base issuance, minted credits are debited from the commons pool.

### 3.4 Free Market Pricing and Price Discovery

| Mechanism | How It Works |
|---|---|
| **Demand pressure** | If Dr. Sarah has a 3-week waitlist, the platform surfaces this: "High demand — consider adjusting your rate." She raises her price. Equilibrium found. |
| **Comparative indexing** | Platform shows what the same service costs across federated communities. Visible market pressure without central price-setting. |
| **Reputation multiplier** | Base rate exists per service category. High-reputation providers command a multiplier. New doctor = 1x base. Experienced trusted doctor = 3x base. |
| **Scarcity alerts** | When a category drops below community threshold, governance is automatically notified to attract more providers or set temporary price caps. |

### 3.5 Credit Velocity and Economic Health

A healthy mutual credit economy needs credits moving, not hoarding:

- **Demurrage** — Credits decay slightly over time if not spent (community-configurable, e.g., -1% per month). Based on Silvio Gesell's concept, tested successfully in the 1932 Wörgl Experiment. Forces circulation. Decayed credits are credited back to the commons pool, not destroyed.
- **Credit ceilings** — Members cannot accumulate more than X Commons. Forces high earners to spend or donate to the commons pool.
- **Contribution requirements** — Members provide a minimum labor or service to the community regardless of credit balance, creating a social contract baseline.

### 3.6 Addressing the Scarcity Problem — Essential Services

In post-collapse scenarios, certain skills become extraordinarily valuable. A pure free market creates tension: should a child die because their family cannot afford the doctor's market rate? Communities resolve this according to their own values using platform tools:

- **Universal basic services** — Certain services provided at zero cost, funded by a community tax on positive balances
- **Tiered access** — Basic version of any service is cheap or free; premium version is market-priced
- **Jubilee cycles** — Periodic partial balance resets, inspired by the biblical Jubilee; prevents permanent underclass formation; resets are booked against the commons pool
- **Debt forgiveness governance** — Community votes to forgive specific debts in specific circumstances, with the forgiven amount absorbed by the commons pool

---

## 4. The Oracle Problem

The oracle problem is probably the hardest unsolved problem in the entire stack. The ledger is digital — it has no eyes. Something must bridge physical reality to digital truth. That bridge is an oracle. Any oracle is a point of trust, and trust is a point of attack.

### 4.1 The Attack Surface

| Attack Type | Description |
|---|---|
| **Collusion** | Two people fake transactions, minting Commons out of thin air |
| **Coercion** | A powerful member forces others to confirm services never rendered |
| **Sybil oracle** | One person creates multiple fake identities, all vouching for each other |
| **Reputation laundering** | Build legitimate history, then exploit it for one large fraudulent claim |
| **Denial attacks** | Maliciously reject legitimate work confirmations to punish someone |
| **Pattern attacks** | File a stream of small disputes to grind down someone's reputation |

### 4.2 Oracle Mechanisms

#### 4.2.1 Bilateral Confirmation
Credits only move when both parties confirm. Table stakes — necessary but not sufficient. Collusion between two cooperating parties is trivially easy. Every advanced mechanism builds on top of this.

#### 4.2.2 Reputation Staking *(selected core feature)*
When someone confirms a transaction, they stake their reputation on it being true. If fraud is later detected, the confirmer loses reputation. Collusion now requires your co-conspirator to risk their entire economic identity. Most people will not do that for small gains.

Each confirmation is a signed attestation linked to the confirmer's identity. Fraud detection triggers retroactive reputation penalties for all attestors. High-reputation attestors carry more weight.

#### 4.2.3 Social Witness / Community Attestation
For higher-value transactions, N community members above a reputation threshold must witness or attest. Collusion cost scales with N. Getting 2 people to lie is easy. Getting 7 independent witnesses with reputation stakes is hard.

#### 4.2.4 Proof of Work — Physical Evidence
Require artifact evidence before credits move. Medical consultations produce anonymized treatment records. Construction work produces geotagged before/after photos. Agricultural deliveries produce signed receipts. The platform becomes a tamper-evident evidence repository. Optional enhancement in low-device scenarios.

#### 4.2.5 Delayed Settlement with Dispute Window
Credits do not move instantly. A settlement delay (community-configurable, default 48 hours) allows anyone in the community to raise a dispute. After the window closes with no dispute, credits move automatically. Leverages the community's social fabric — people in small communities notice when someone games the system.

#### 4.2.6 Cross-Community Oracle Validation
For high-value inter-community transactions, a third community acts as neutral validator. They earn a small Commons fee. This creates a market for trusted third-party validation — communities build reputations as reliable arbiters.

#### 4.2.7 Statistical Fraud Detection
At the federation level, the system watches aggregate patterns. Fraud leaves signatures: a provider's earnings are 10x the community average; two accounts confirm each other's transactions exclusively; a new community generates massive credit flows immediately. The system flags anomalies for human review — not automated punishment.

### 4.3 The Tiered Oracle Model *(selected core feature)*

| Tier | Transaction Range | Requirements | Oracle Mechanism |
|---|---|---|---|
| **Tier 1** | under 5 Commons | Bilateral confirmation | Delayed settlement window only. Low friction, some fraud acceptable at micro scale. |
| **Tier 2** | 5 to under 50 Commons | Bilateral + reputation stake | Settlement window doubles as dispute window (default 48h). Community social fabric is the oracle. Attestors stake reputation. |
| **Tier 3** | 50 to under 500 Commons | Tier 2 + physical artifacts + 3 community witnesses | Fraud becomes expensive and socially visible. Evidence is cryptographically timestamped. |
| **Tier 4** | 500 Commons and up | Tier 3 + cross-community validation + governance approval | Essentially a notarized contract. Neutral third community validates. Full audit trail. |

Boundaries are half-open and evaluated in integer centicommons (500 / 5,000 / 50,000). Transaction value sets the tier **floor** — a listing or either party may opt a transaction *up* to a higher tier (e.g., a 3-Common medical consultation listed at Tier 2), never down.

### 4.4 The Philosophical Foundation

Every oracle mechanism ultimately reduces to social trust. There is no cryptographic proof that a patient was healed. The question is only how many people have to lie for fraud to succeed, and how costly that lying is.

In a small, high-trust, interdependent community — the kind that forms post-collapse — social pressure is a very powerful oracle. The failure mode is not individual fraud. The failure mode is **coordinated capture** — a faction taking control of enough attestation power to systematically extract credits.

---

## 5. The Reputation System

Reputation is the connective tissue of the entire platform. Without it, the oracle layer is weak, inter-community trust does not scale, and the credit system is gameable. Reputation simultaneously serves as: oracle weight, credit trustworthiness, inter-community passport, governance weight, and market signal.

### 5.1 Architecture — Multidimensional, Composite Output

Reputation is multidimensional internally but presents a composite score externally:

```
Internal reputation model:

  Trade reliability:          Score 0-5 (transaction history, delivery record)
  Domain competence:          Score 0-5 per domain (medical, construction, etc.)
  Governance participation:   Score 0-5 (voting, proposals, council service)
  Community contribution:     Score 0-5 (non-economic contributions)
  Attestation accuracy:       Score 0-5 (oracle confirmation track record)

  Composite = weighted average; weights set by federation protocol
  External presentation: "Trusted Member" / "Senior Member" / "New Member"
  Raw score visible for inter-community use: 4.7 / 5.0
```

### 5.2 Score Inputs

| Input | Mechanics |
|---|---|
| **Transaction history** | Bedrock input. Every completed trade, confirmed delivery, honored commitment. Volume and consistency matter. 1,000 small successful trades is more signal than one large one. |
| **Attestation accuracy** | When you stake reputation to confirm a transaction and it is later found fraudulent, your score drops. Consistently accurate attestations build a specific trust signal. |
| **Dispute record** | How many disputes raised against you, and how they resolved. One lost dispute is not catastrophic. A pattern is. False disputes filed against others also penalize the filer. |
| **Governance behavior** | Showing up to votes, quality of proposals, honoring community decisions even when you voted against them. |
| **Time and consistency** | A 4.5 score held over 3 years is worth more than a 4.8 score from last month. Naturally resists reputation laundering. |
| **Vouching accuracy** | When you vouch for a new member who turns out to be fraudulent, your score is penalized. Incentivizes careful vouching. |

### 5.3 The Universal Scoring Algorithm

**Critical design decision**: the reputation scoring algorithm is a protocol-level standard, not community-configurable. One algorithm runs the same everywhere. Communities cannot relax their standards to attract high-reputation members from other communities — this would create a race to the bottom and enable regulatory arbitrage.

Communities contribute raw data. The protocol computes the score using the universal formula. The formula can only be changed through federation-level governance requiring broad consensus.

### 5.4 Sybil Resistance

- **Identity anchoring** — Reputation only accumulates on identities vouched for by existing community members. Each vouch is a reputation stake. Fake identities require corrupting the vouching chain.
- **Reputation velocity limits** — You cannot accumulate reputation faster than a certain rate. Real relationships and genuine transactions have natural speed limits.
- **Graph analysis** — Sybil clusters leave network signatures — fake accounts interact mostly with each other. The fraud detection layer watches for isolated dense subgraphs.
- **Time locks** — New identities have limited attestation power for their first N days regardless of score. You cannot rush-build a fake reputation for immediate high-value oracle use.

### 5.5 Reputation Decay and Maintenance

- Scores drift slowly downward if inactive (~-0.1 per month of no activity)
- Recent behavior weighted more heavily than old behavior
- Domain scores decay independently — medical reputation decays if you stop practicing
- Established members cannot coast forever on old reputation

### 5.6 Reputation Portability

When someone crosses community lines, their reputation travels as a **signed history, not just a score**. The system exports a cryptographically signed ledger of transaction history, attestations, and dispute records. The universal algorithm then produces the same score it would produce anywhere. No community can inflate someone's reputation artificially. The history is tamper-evident — you cannot selectively delete the bad parts.

### 5.7 Reputation as an Economic Primitive

- **Reputation as collateral** — High-reputation members can vouch for new members or back larger credit limits, earning a small fee but taking on risk
- **Reputation markets** — Communities actively recruit high-reputation individuals, creating talent acquisition via trust
- **Reputation guilds** — Specialists form associations that collectively vouch for each other's competence; the guild itself has a reputation score

---

## 6. Identity Layer

Identity is the foundation everything else rests on. The system must balance privacy (protection from surveillance) against accountability (people must be answerable for their actions).

### 6.1 Design Philosophy — Minimum Necessary Disclosure

Different contexts require different levels of identity exposure. Voting might need pseudonymity. A medical license needs verified identity. Cross-community trade needs portable reputation. The identity system provides context-sensitive disclosure: the minimum information required for each specific interaction.

### 6.2 The Three-Layer Identity Model

#### Layer 1 — Cryptographic Identity
At the foundation, you are your private key. A public/private keypair generated on your device is your root identity. Everything you do is signed with your private key. No one can impersonate you without it. No central authority issued it — you generated it locally. This is fully self-sovereign. The problem: it is just a key. A Sybil attacker generates a thousand keys trivially.

#### Layer 2 — Community Identity
When you join a community, existing members vouch for you by cryptographically signing a statement linking your public key to your physical personhood.

```json
{
  "voucher": "rrn1q4a7l2v...",
  "vouched": "rrn1x9f2cw8...",
  "community": "blue_ridge_collective",
  "statement": "I attest this key belongs to a real, unique individual known to this community.",
  "reputation_stake": 0.5,
  "timestamp": 1934961780,
  "signature": "8b3f..."
}
```

*(Example payloads in this document are shown as JSON for readability. The wire format is canonical CBOR (`dcbor`), identities are bech32m `rrn1...` addresses, and times are Unix seconds as signed 64-bit integers.)*

#### Layer 3 — Verified Claims
On top of community identity, members attach verifiable claims: medical licenses, labor hour records, citizenship attestations, skill certifications. These are held in the member's identity wallet and presented selectively when needed. The receiver verifies the signature — no central registry required. Self-sovereign identity: you hold your own credentials.

### 6.3 The Identity Wallet

Every person's identity lives in a local application — their identity wallet. It holds:
- Private key (never leaves the device)
- Received vouches
- Verified claims and credentials
- Complete signed transaction history
- Reputation record

Losing the wallet is equivalent to losing your passport and credit history simultaneously. Key recovery is therefore a critical design problem.

### 6.4 Pseudonymity by Default

Members operate under a persistent pseudonym — not necessarily their legal name. The pseudonym is consistent and persistent but protects users from outside surveillance, physical targeting in collapse scenarios, and social context collapse. **Contextual identity** — known differently in different contexts, consistently within each context.

### 6.5 Social Key Recovery *(selected core feature)*

Social recovery using Shamir's Secret Sharing is the selected key management approach. It is technically elegant, requires no special hardware, and reinforces community interdependence as a feature.

**Implementation:**

1. During account setup, your private key is mathematically split into N shards (typically 5-7)
2. You distribute shards to trusted community members in different households and roles
3. Any K of N shards (typically 3 of 5 or 4 of 7) can reconstruct your key
4. Shard holders are referenced by public key — not names — so the recovery network is known to you but not readable by observers
5. If you lose your device, gather K trusted people, present their shards, reconstruct your key

**Shard management rules:**
- Distribute to different households and roles — do not put 3 of 5 shards in one family
- **Shard refresh** — if your relationship with a shard holder deteriorates, re-split the key with a fresh random polynomial and distribute new shards; old and new shards cannot be combined. Caveat: plain Shamir has no true revocation — any K holders of the *old* shard set can still reconstruct the key together. If K or more old shards may be compromised or colluding, rotate the underlying key itself
- In collapse context, key recovery may be a physical gathering — a designed social ritual, not just a technical process

### 6.6 The Duplicate Identity Problem

The hardest attack: one person joining multiple communities under different identities. Defenses:

- **Social graph analysis** — Duplicate identities have non-overlapping social graphs; real people have relationships that bleed across contexts
- **Vouching chain analysis** — If the same voucher appears in the origin chain of two supposedly different identities, that is flagged
- **Inter-community identity treaties** — Two communities formally agree to cross-check member lists (opt-in, not universal)
- **Zero-knowledge proofs (long-term)** — A member proves "I am not already registered in this federation" without revealing who they are; the correct long-term answer

### 6.7 Offline Identity

- **Physical identity cards** — Printed cards with the member's public key as a QR code, signed by community leadership; verifiable without network connectivity
- **Oral attestation** — Community members physically vouch for each other in person; digital record catches up on reconnect
- **Offline signing** — Transactions signed locally, queued in wallet, synced when any connectivity appears; ledger reconciles on reconnect via CRDT merge

---

## 7. Dispute Resolution

Dispute resolution is where the system gets tested. Everything works when people cooperate. Disputes are the stress test of every mechanism.

### 7.1 Dispute Taxonomy

| Type | Description |
|---|---|
| **Type 1 — Delivery disputes** | Service or goods not delivered as agreed. Doctor did not show up. Grain was rotted. |
| **Type 2 — Valuation disputes** | Both parties agree something happened but disagree on what it was worth. |
| **Type 3 — Fraud disputes** | One party alleges the other fabricated a transaction entirely. |
| **Type 4 — Governance disputes** | A member alleges a community law was applied unfairly or unconstitutionally. |
| **Type 5 — Inter-community disputes** | Community A alleges Community B violated a trade treaty. |

### 7.2 Core Design Principles

- Resolution should be proportional to stakes — a 2 Common dispute should not require the same apparatus as a 500 Common dispute
- The process itself should not be weaponizable — filing a dispute must have a cost
- Resolution should be final and binding — an appeal mechanism is fine, but infinite appeals make the system unenforceable
- Transparency vs. privacy — outcomes inform reputation scores (public), but case details may need protection

### 7.3 The Four-Layer Resolution Stack

#### Layer 1 — Automated Resolution
For small, clear-cut cases: transaction not confirmed within settlement window auto-cancels; both parties agreeing to cancellation triggers immediate resolution with no reputation impact; amounts below micro-threshold resolved in favor of the receiver by default. Zero overhead.

#### Layer 2 — Peer Mediation
A randomly selected panel of 3 community members above a reputation threshold reviews evidence and makes a binding decision. Random selection prevents factional control. Panelists earn a small Commons fee. Panelists who consistently make decisions overturned on appeal take a small reputation hit — incentivizing honest judgment.

#### Layer 3 — Community Tribunal
For larger stakes or appealed peer mediation. A formal panel of 7 members including at least one elected official. Structured evidence submission, longer deliberation window, **written reasoning required**. Written reasoning creates precedent — over time the community builds a body of case law.

#### Layer 4 — Federation Arbitration
For inter-community disputes or cases where a member alleges their own community treated them unfairly. A cross-community panel from neutral third communities. The federation's supreme court equivalent — slow, expensive to invoke, but genuinely independent. Decisions set federation-wide precedent.

### 7.4 The Staking Mechanism

Every dispute filing requires staking reputation:

```
Disputed value             Reputation stake required
under 5 Commons            0.1 points
5 to under 50 Commons      0.5 points
50 to under 500 Commons    1.5 points
500 Commons and up         3.0 points

On win:  stake returned + portion of loser's stake
On loss: stake forfeited + additional reputation hit
Fraud finding: heavier penalty than honest disagreement
```

Stakes are absolute points on the 0–5 scale, so filing a large dispute requires substantial standing — deliberate friction against frivolous high-value claims — but the top stake is capped well below the maximum score so that established members, not only perfect ones, can file.

### 7.5 The Pattern Attack Defense

A powerful faction could file a stream of small disputes against someone to grind down their reputation. Two specific defenses:

- **Dispute rate limiting** — If Party A files more than N disputes against Party B within a time window, the system flags it as potential harassment, routes to Layer 3 automatically, with elevated stakes for the filer
- **Meta-dispute mechanism** — A member can file a dispute about a *pattern* of disputes: "This community faction is systematically targeting me." Routes directly to Federation Arbitration and treated as a potential rights floor violation.

### 7.6 Post-Resolution Effects

- **Ledger adjustment** — Credits moved, reversed, or cancelled per ruling
- **Reputation update** — Both parties' scores update based on outcome and behavior during the process
- **Precedent recording** — Layer 3+ rulings published to the community's case law repository
- **Fraud detection learning** — System ingests outcomes as training data, continuously improving pattern recognition

---

## 8. The Federation Protocol

Federation is where individual communities become something larger than themselves. Federation is not merger. Communities agree to a shared communication protocol, shared identity standard, shared credit unit, minimum rights floor, and inter-community dispute resolution interface. Everything else remains locally sovereign.

### 8.1 The Federation as Protocol

The closest technical analogy is email. Gmail and Outlook are completely different systems that interoperate because both speak SMTP. Railroad Network's federation protocol is SMTP for community interoperability — a standard at the boundary that allows any compliant node to communicate without knowing how the other side works internally.

### 8.2 The Federation Handshake

1. **Discovery** — Community A broadcasts its federation profile; Community B receives and reviews it
2. **Proposal** — One community formally proposes federation with trade terms, credit limits, treaty scope, and dispute resolution agreement
3. **Internal ratification** — Each community runs the proposal through its own governance with a meaningful approval threshold
4. **Cryptographic signing** — Both governance keys sign the treaty; published to both ledgers as an immutable record
5. **Active federation** — Credit flows begin, marketplace listings become visible, identity vouches recognized across the boundary

Federation is deliberately not automatic. It should be a conscious community decision — not something that happens because an administrator clicked a button.

### 8.3 The Community Profile

```json
{
  "community_id": "blue_ridge_collective",
  "founded": 1934668800,
  "population": 340,
  "location_type": "rural_mountain",
  "governance_model": "liquid_democracy",
  "production": {
    "primary": ["grain", "timber", "medical_services"],
    "surplus": ["grain", "timber"]
  },
  "needs": {
    "critical": ["fuel", "electronics"],
    "preferred": ["protein", "specialized_labor"]
  },
  "federation": {
    "open_to_new_treaties": true,
    "active_treaties": ["valley_commune", "ridge_watch"],
    "credit_limit_per_partner": 500,
    "min_reputation_for_trade": 3.5
  },
  "charter_hash": "9f2c...",
  "governance_key": "rrn1g0vk3y...",
  "last_updated": 1947110400
}
```

The `charter_hash` is critical: a cryptographic fingerprint of the community's founding document. Any charter change produces a different hash. Treaty partners can verify they are still dealing with the same community they originally federated with. A community that rewrites its charter mid-treaty triggers an automatic renegotiation requirement.

### 8.4 Treaty Types — Graduated Federation Depth

| Treaty Type | Rights and Obligations |
|---|---|
| **Trade treaty** | Marketplace listings visible. Credit flows up to agreed limit. Transaction dispute resolution only. No identity recognition beyond transaction pseudonyms. Lightest touch. |
| **Recognition treaty** | Trade treaty plus: mutual identity vouching recognized, reputation scores portable, citizens can apply for residency in either community. |
| **Alliance treaty** | Recognition treaty plus: mutual defense obligations, shared commons pool contributions, joint governance on shared resources, coordinated emergency response. |
| **Full federation** | Alliance treaty plus: shared governance council, free movement of members, unified marketplace. Approaching merger without full merger. |

### 8.5 Credit Flow Across Communities

When two communities sign a trade treaty, they agree on a mutual credit limit — how much net imbalance they will tolerate before settlement is required. This is a bilateral clearing system.

```
Bilateral credit position example:

  Blue Ridge <-> Valley Commune
  Mutual credit limit: 500 Commons
  Current position: Blue Ridge owes Valley Commune 230 Commons net
  Status: Within limit, trade continues freely

  If Blue Ridge reaches 500 Commons owed:
  -> New Blue Ridge transactions to Valley Commune paused
  -> Settlement required: physical goods/services delivery
  -> Or limit renegotiated by treaty amendment
```

For multi-hop transactions, a routing layer finds credit paths through the network automatically. Users see only a transaction.

### 8.6 Federation Governance

Key federation-level decisions: who can change the universal reputation algorithm, what constitutes a rights floor violation, how rogue communities are sanctioned, how universal credit rules are amended.

Recommended structure: **hybrid** — day-to-day maintenance via a delegate assembly (one delegate per community), with fundamental changes requiring a supermajority of all member communities via direct vote.

### 8.7 Community Sanctions

| Level | Consequences |
|---|---|
| **Level 1 — Warning** | Formal notice published to all federation members. Remediation period of N days. |
| **Level 2 — Trade suspension** | Credit flows frozen. Marketplace listings hidden. Economic pressure without full exclusion. |
| **Level 3 — Recognition suspension** | Identity vouches from community not recognized. Members lose cross-community reputation portability. |
| **Level 4 — Expulsion** | Community removed from federation. All treaties voided. Credit balances settled per treaty terms. |

**Critical principle**: Sanctions should hurt the leadership and governance of the offending community, not innocent members. Individual members retain their personal identity, reputation, and credit history.

### 8.8 Discovery

- **Internet scenario** — Distributed federation directory that any node can query
- **Degraded connectivity** — Geographic propagation over radio/mesh to physical neighbors
- **Complete isolation** — Traveler networks: people physically moving between communities carry signed community profiles as introductions (the conductor role in the Railroad analogy)

---

## 9. The Marketplace

The marketplace is where the abstract economy becomes concrete and daily. Three distinct surfaces with different mechanics.

### 9.1 Three Surfaces

| Surface | Description |
|---|---|
| **Goods marketplace** | Physical items, inventory-based. Farmers posting grain. Builders offering materials. |
| **Services marketplace** | Labor and skills, time-based. Doctors, builders, teachers, security patrols. Immediate, scheduled, and recurring service contracts. |
| **Commons marketplace** | Community-pooled resources available to all members at subsidized or zero cost. Tool libraries, shared land, community facilities. |

### 9.2 The Listing Primitive

```json
{
  "listing_id": "8f3a...",
  "provider": "dr_sarah",
  "community": "blue_ridge_collective",
  "type": "service",
  "category": "medical",
  "title": "General Consultation",
  "pricing": {
    "amount": 3,
    "unit": "commons",
    "model": "fixed",
    "negotiable": true
  },
  "availability": {
    "status": "available",
    "capacity": 4,
    "next_slot": "2031-09-05"
  },
  "requirements": {
    "min_reputation": 0,
    "community_member": false,
    "federation_only": false
  },
  "oracle_tier": 2,
  "federation_visible": true,
  "history": {
    "completed": 312,
    "disputes": 2,
    "avg_rating": 4.8
  }
}
```

### 9.3 Service Contracts

Recurring services are a distinct primitive from one-off transactions:

```json
{
  "contract_type": "recurring_service",
  "provider": "ridge_watch",
  "service": "community_perimeter_patrol",
  "terms": {
    "frequency": "daily",
    "duration_weeks": 12,
    "commons_per_week": 8,
    "payment_schedule": "weekly"
  },
  "performance_metrics": {
    "response_time_minutes": 15,
    "patrol_coverage_pct": 95
  },
  "termination": {
    "notice_period_days": 7,
    "early_termination_penalty_commons": 20
  }
}
```

Performance metrics in service contracts serve as the oracle. The dispute window is where performance claims are challenged.

### 9.4 Predictive Matching *(selected core feature)*

Rather than waiting for both parties to simultaneously post matching offers and needs, the platform continuously models community production cycles and proactively surfaces trade opportunities:

```
Simplified predictive matching logic:

  1. Analyze historical listing patterns per community:
     "Valley Farm posts grain surplus every September"
     "Blue Ridge needs grain every winter"

  2. Project upcoming surplus/deficit cycles:
     "Blue Ridge will likely have timber surplus in 6 weeks"
     "3 communities have grain as critical need this winter"

  3. Cross-reference projected supply against known needs:
     Match before either party has posted a listing

  4. Rank matches by:
     - Geographic proximity (physical goods require physical movement)
     - Historical trade relationship strength
     - Reputation scores of both parties
     - Treaty depth between communities

  5. Surface proactively to community trade coordinators
```

In a collapse scenario, anticipating scarcity before it becomes a crisis is the difference between resilience and catastrophe. A community that knows its grain supply will run short in 8 weeks can arrange a trade now at normal terms. A community that discovers the shortage when it arrives negotiates from a position of desperation.

### 9.5 Transaction Flow End-to-End

1. **Discovery** — Buyer finds listing via search, browsing, or proactive predictive match alert
2. **Inquiry / Negotiation** — Buyer sends inquiry; price negotiation if listing is negotiable; terms confirmed
3. **Transaction initiation** — Both parties cryptographically agree to terms; transaction recorded as pending; if escrow required, credits locked
4. **Fulfillment** — Goods delivered or service performed; evidence submitted per oracle tier
5. **Confirmation window** — Bilateral confirmation plus the community dispute window (the settlement window, default 48 hours)
6. **Settlement** — Credits move; transaction recorded as complete; reputation scores updated
7. **Review** — Optional rating and attestation feeds into provider's reputation

### 9.6 Collapse-Specific Marketplace Features

- **Resource triage listings** — Emergency resource sharing with no credit transaction, tracked for future reciprocity
- **Barter fallback** — Direct barter when credit system is disrupted; recorded on ledger for relationship continuity
- **Offline marketplace** — Local-only listing in full connectivity loss, synced to federation on reconnect
- **Latent skill discovery** — Members register skills they have but are not actively advertising; community knows its full capacity

---

## 10. Technical Architecture

The architecture is designed around a single principle: **graceful degradation rather than hard failure**. Every layer has a fallback that works in worse conditions. The system never fully stops — it only runs slower.

### 10.1 The Full Stack

```
APPLICATION LAYER
  Marketplace · Governance · Identity · Disputes
  Credit · Reputation · Federation Manager

PROTOCOL LAYER
  Federation Protocol · Oracle Protocol
  Credit Protocol · Identity Protocol

SYNC LAYER
  CRDT State · Gossip Protocol
  Conflict Resolution · Delta Sync

CONSENSUS LAYER
  Local Raft Consensus · Ledger
  Transaction Ordering · Finality

TRANSPORT LAYER
  TCP/IP · LoRa · Mesh · Delay-Tolerant Networking

IDENTITY LAYER
  Ed25519 Keypairs · Vouching DAG · Credentials
  Shamir's Secret Sharing · ZK Proofs
```

### 10.2 Identity Layer — Implementation

- **Keypairs**: Ed25519. Fast, small signatures, well-audited, works on low-power ARM hardware
- **Vouching chain**: Stored as a directed acyclic graph (DAG). Sybil detection runs graph analysis looking for isolated clusters
- **Credential wallet**: Local storage of signed claims. Selective disclosure using ZK proofs for sensitive attributes
- **Social recovery**: Shamir's Secret Sharing implemented locally. Key split into N shards on setup

### 10.3 Transport Layer — Graceful Degradation

| Connectivity Level | Available Transport |
|---|---|
| **Full internet** | TCP/IP, standard networking. Full feature set, real-time sync. |
| **Partial/regional** | Tor-like onion routing for privacy. Core features work with delayed sync. |
| **Local network only** | WiFi mesh, Bluetooth mesh. Community fully functional, federation delayed. |
| **No internet — LoRa** | Low-power radio, 5-15km range, ~250 bytes/second. Credit transactions, governance votes, and identity work. Marketplace degraded. |
| **Complete isolation** | Store-and-forward via physical carriers. Conductors carry sync payloads. Ledgers reconcile on reconnect. |

**LoRa (Long Range radio)** achieves 5-15km range at very low power. At 250 bytes per second, it can handle credit transactions, governance votes, and identity attestations — the economic backbone of the system. Communities stay economically connected when the internet is entirely gone.

### 10.4 Consensus Layer

#### Within a Community — Raft Consensus
Raft provides consistent ledger ordering, automatic leader failover, and clear finality. A community runs 3-7 nodes on devices owned by trusted community members. Running a node is a form of community contribution earning a small credit stipend.

**Trust model:** Raft tolerates crashed nodes, not Byzantine ones — the operator set is semi-trusted, which matches the deployment reality (nodes run by known community members). Tampering or equivocation by an operator is not *prevented* by consensus; it is made **detectable and attributable** by the signature-gated, hash-chained append-only log, and handled through governance and reputation. This is a deliberate trade: honest-but-crashy is the common failure mode inside a community, and social accountability is the defense against the rare malicious operator.

#### Between Communities — Eventual Consistency
Each community's ledger is authoritative for its own transactions. Inter-community transactions use a two-phase commit handshake with log-based reconciliation:

```
Phase 1 — Prepare:
  Community A's ledger reserves credits (pending)
  Community B's ledger reserves inventory (pending)
  Both record transaction as pending with timeout

Phase 2 — Commit:
  Both communities confirm readiness
  Each ledger records a signed commit entry; the
  transaction is final once both entries exist

Failure handling:
  If either community goes offline mid-transaction,
  the pending transaction expires after N hours.
  A partner that committed before the outage learns
  the true outcome on reconnect: commit and expiry
  records are exchanged during log sync, and a
  deterministic rule (a commit signed before the
  expiry deadline wins) reconciles both ledgers.
```

A two-phase handshake cannot guarantee atomic commit across an unreliable network — one side can commit while the other times out. The design goal is therefore *detectable, convergent* outcomes via the signed logs, not impossible atomicity: divergence is temporary and self-healing, never silent.

### 10.5 Sync Layer — CRDTs

Conflict-free Replicated Data Types (CRDTs) are mathematical data structures that can be merged from any two states without conflicts, regardless of the order updates arrived. This is the core primitive that makes offline-first work.

| Data Type | CRDT Variant |
|---|---|
| **Credit balances** | PN-Counter CRDT (positive/negative increment counter) |
| **Marketplace listings** | OR-Set CRDT (observed-remove set) |
| **Reputation scores** | LWW-Register CRDT (last-write-wins with logical timestamps) |
| **Governance votes** | 2P-Set CRDT (two-phase set — votes cannot be uncast) |
| **Community membership** | OR-Set CRDT |
| **Attestation records** | Append-only log with cryptographic chaining |

State propagates via **gossip protocol** — each node periodically selects random peers and exchanges state deltas. Information spreads in O(log N) rounds without central coordination. Nodes exchange only deltas, keeping bandwidth minimal for LoRa transport.

### 10.6 Protocol Layer — Four Core Protocols

| Protocol | Responsibilities |
|---|---|
| **Identity Protocol** | Key registration and vouching, credential issuance and verification, ZK proof generation, social recovery coordination |
| **Credit Protocol** | Transaction initiation/pending/commit/rollback, balance queries, credit limit enforcement, settlement triggers |
| **Oracle Protocol** | Transaction confirmation requests, attestation collection and weighting, dispute window management, tier escalation |
| **Federation Protocol** | Community profile broadcast and discovery, treaty negotiation and signing, inter-community transaction routing, sanctions propagation |

Each protocol is a defined message format plus a state machine. Any node implementing the protocols can participate regardless of hardware or OS. The protocols are the permanent layer — everything above them can be replaced.

### 10.7 Node Hardware Classes

*("Class" rather than "tier" — oracle tiers in Section 4.3 are unrelated.)*

| Class | Description |
|---|---|
| **Class 1 — Full node** | Raspberry Pi 4, 4GB RAM, 128GB storage. Runs full ledger, all protocols, local API server. Solar-powered. Community's primary node. ~$80 hardware cost. |
| **Class 2 — Light node** | Smartphone or low-power laptop. Holds personal wallet and identity. Connects to full node via local WiFi or Bluetooth. |
| **Class 3 — Minimal node** | Basic phone with SMS capability. Interacts via structured SMS commands to a community hub. Functional for core credit transactions and governance votes. |
| **Class 4 — Paper fallback** | Printed QR codes representing signed transaction records. Physically carried between communities by conductors. Scanned and ingested on reconnect. |

### 10.8 Security Architecture

| Attack Vector | Mitigation |
|---|---|
| **Eclipse attack** | Maintain peer lists from multiple independent sources, prefer geographically diverse peers, detect isolation via heartbeat failures |
| **Ledger fork** | Raft quorum prevents accidental forks; a malicious leader can still equivocate, so every entry is signed and hash-chained — equivocation is automatically detectable, attributable to its signer, and punishable through governance |
| **Sybil federation** | Community reputation scores are slow to build; new communities have limited governance weight during probation |
| **Replay attack** | Every transaction includes a monotonically increasing nonce per identity plus a timestamp; nodes reject previously-seen nonces |
| **Physical node seizure** | Data at rest encrypted with keys held by community members, not stored on the node; seizing a powered-off node yields an encrypted brick. Residual risk: a node seized while running has keys in memory — the mitigations there are physical custody and rapid re-bootstrap, not encryption |

### 10.9 The Technology Stack

| Component | Technology & Rationale |
|---|---|
| **Primary language** | Rust — performance, memory safety, works on low-power ARM, strong crypto library ecosystem, no GC pauses (ADR-0001) |
| **Local database** | SQLite via `rusqlite` (bundled, WAL mode, foreign keys ON) + custom CRDT layer — embedded, no server required, works offline, tiny footprint |
| **Cryptography** | `ed25519-dalek` v2 (signatures), `blake3` (hashing), XChaCha20-Poly1305 via `chacha20poly1305` (symmetric), `argon2` (key derivation) — audited pure-Rust crates, fast on ARM |
| **Canonical serialization** | `dcbor` — Deterministic CBOR (RFC 8949 §4.2.1); signatures always cover the canonical CBOR bytes of the payload (ADR-0002) |
| **Addresses** | bech32m with HRP `rrn` — addresses read `rrn1...` (ADR-0003) |
| **Shamir secret sharing** | Own implementation over GF(256), Rijndael polynomial, in `rrn-identity` — existing crates evaluated and rejected (ADR-0004) |
| **Consensus** | Custom Raft (evaluate `openraft` first) — small codebase, well-understood, adaptable to low-bandwidth. Phase 2+; a single-station community needs no consensus protocol |
| **Mobile client** | React Native + TypeScript UI over the Rust core (`rrn-crypto`, `rrn-identity`) compiled for iOS/Android, bindings generated by `uniffi-rs` (ADR-0006, ADR-0007) |
| **SMS interface** | Simple AT command parser — runs on any device with serial port access to a radio modem |
| **ZK proofs** | arkworks-rs — Rust ZK library for duplicate identity detection |
| **Radio transport** | LoRa via standard SX127x chipsets — widely available, low cost, 5-15km range |

Estimated total core codebase: **50,000–80,000 lines of Rust** for the full node. Lean enough to audit. Complex enough to be production-grade.

### 10.10 Degradation Profile

```
Full internet     →  Full feature set, real-time sync
Partial internet  →  Delayed sync, core features work
Local mesh only   →  Community fully functional, federation delayed
LoRa only         →  Credit transactions, governance votes, identity
                     Marketplace degraded
No connectivity   →  Local community operates independently
                     Paper fallback for inter-community
```

---

## 11. User Experience Design

The best UX for Railroad Network is one where the underlying complexity disappears entirely. A farmer should not know what a CRDT is. A doctor should not think about oracle tiers. Every technical primitive has a human analog that the interface surfaces instead.

### 11.1 The Core Translation Table

| Technical Concept | Human Analog in UI |
|---|---|
| Mutual credit ledger | Community tab at the general store |
| Oracle attestation | Your neighbor vouching for you |
| Reputation score | Being known as reliable |
| Federation treaty | Trading relationship with the next town |
| Dispute resolution | Community elder mediation |
| Governance proposal | Town hall meeting |
| Social key recovery | Trusted friends holding a spare key |
| Shamir's Secret Sharing | "Choose 3 trusted people" (never mentioned by name) |
| Tier 2 oracle attestation | Tapping "All good" after a transaction |
| CRDT merge | Invisible sync when connection restores |

### 11.2 The Five Surfaces

Every feature lives in one of five primary surfaces:

1. **Home** — "What's happening in my community today?"
2. **Market** — "What do I need? What can I offer?"
3. **Wallet** — "What do I have? What do I owe?"
4. **Community** — "Who are we? How do we decide things?"
5. **Network** — "Who's out there? Who are we connected to?"

No feature orphans. No settings graveyards. Five human questions.

### 11.3 Transaction UX — Conversational by Design

When a transaction initiates, it looks like a message thread — not a form. The formal transaction record emerges naturally from conversation and is presented for confirmation at the end:

```
Dr. Sarah Chen

  Sarah: Hi, I have availability Tuesday at 2pm or Wednesday morning.
         3 Commons for a consultation.

  You:   Tuesday 2pm works perfectly.

  Sarah: Great. I'll send a confirmation.

  ┌─────────────────────────────────────┐
  │ Transaction ready to agree          │
  │ General Consultation                │
  │ Tuesday Sept 5, 2pm                 │
  │ 3 Commons                           │
  │                                     │
  │ [Decline]              [Agree ✓]    │
  └─────────────────────────────────────┘
```

After the transaction, confirmation is a single tap:
```
How did it go?

Consultation with Dr. Sarah Chen — Tuesday Sept 5

[Something went wrong]        [All good ✓]
```

"All good" is the Tier 2 oracle attestation with reputation staking. The user has no idea. They just said it went fine.

### 11.4 Dispute UX — Gentle Entry

"Something went wrong" opens the dispute flow:

```
What happened?

○ The service wasn't provided
○ It wasn't what was agreed
○ There's a disagreement on price
○ Something else

We'll help you sort it out.
```

No legal language. No reputation stakes mentioned. No oracle tiers. Just: "what happened, we'll help you sort it out."

### 11.5 Onboarding — Community First

```
Welcome to Railroad Network

Marcus Chen has invited you to join Blue Ridge Collective.

Blue Ridge is a community of 340 people sharing skills, goods,
and governance in the Blue Ridge valley.

To join, you'll need:
  · Marcus's vouching (done ✓)
  · One more community member to vouch for you
  · A brief introduction to the community

                                          [Continue]
```

The vouching requirement is framed as a community introduction, not identity verification. Key generation happens invisibly during setup. Social recovery is "choose 3 trusted people who can help you recover your account if you ever lose your phone."

### 11.6 Offline Mode UX

When connectivity is lost, the app continues working with only a subtle indicator:

```
Blue Ridge Collective              ⚡ Offline

Working from local data
Last synced: 2 hours ago

[Everything else appears and functions normally]

Transactions will complete when connection is restored
```

No panic. No broken UI. The system is designed so offline mode feels like normal mode running slightly slower.

### 11.7 SMS Interface

```
SMS command reference:

  PAY [name] [amount] [description]
  REQUEST [name] [amount] [description]
  CONFIRM [transaction_id]
  BALANCE
  VOTE [proposal_id] YES/NO
  NEED [description]
  HELP

Example:
  "PAY dr_sarah 3 COMMONS consultation"
  -> Hub parses, initiates transaction, returns SMS confirmation
```

### 11.8 Five Core UX Principles

1. **Name things what they are to humans.** Credits not tokens. Standing not reputation score. Connected communities not federated nodes.
2. **Surface actions not states.** "Valley Farm has grain, matches your need" not "demand-supply match detected."
3. **Make the right thing the easy thing.** Confirming a transaction is one tap. Filing a dispute requires slightly more effort — not because it is punished, but because friction should match importance.
4. **Collapse gracefully, never catastrophically.** Every UI state has an offline version. No screen should ever be blank because connectivity is gone.
5. **Trust the community, not the algorithm.** When the system makes a suggestion, show why in human terms. "Valley Farm has sold grain to 3 community members this month" not "confidence score: 0.87."

---

## 12. Development Roadmap

Each phase delivers standalone value. No phase requires the next to be useful. This de-risks the build and creates real-world feedback loops at every stage.

### Phase 0 — Foundation (Months 1-4)

Before any user-facing product, get the core cryptographic primitives right. This is the hardest phase to stay disciplined about — there is nothing to show anyone.

**Deliverables:**
- Ed25519 identity and keypair generation
- Local SQLite ledger with CRDT data structures
- Basic mutual credit transaction engine — bilateral confirmation, settlement window
- Core signing and verification across all data types
- Shamir's Secret Sharing for social key recovery
- External cryptographic audit before any real users

**Exit criteria:** Two people on the same local network can transact, confirm, and have balances update correctly. Command line only. The cryptographic foundation is correct and audited.

### Phase 1 — Single Community MVP (Months 5-10)

Build the minimum viable community product. A group of 10-50 people can run a self-contained local economy.

**Deliverables:**
- Identity wallet — mobile app, keypair management, vouching flow
- Community node software — runs on Raspberry Pi or modest laptop
- Basic marketplace — post listings, browse, initiate transactions
- Tier 1 and Tier 2 oracle — bilateral confirmation plus reputation staking
- Simple reputation scoring from transaction history
- Basic governance — proposals, direct voting, charter storage
- Local-only operation — no federation yet

**Target early adopters:** Intentional communities and ecovillages, mutual aid networks, worker cooperatives, remote rural communities with weak connection to mainstream economy.

**Exit criteria:** One real community of 20+ people uses it for 90 days with genuine transactions. Dispute system exercised at least once. Governance produces at least one real community decision.

### Phase 2 — Multi-Community Federation (Months 11-18)

Connect communities together. This is where the Railroad metaphor becomes real.

**Deliverables:**
- Federation protocol — community profiles, discovery, treaty negotiation
- Inter-community credit flows — two-phase commit, credit limits, bilateral clearing
- Reputation portability — identity and scores cross community boundaries
- Tier 3 and Tier 4 oracle — artifact evidence, cross-community validation
- Cross-community dispute resolution — federation arbitration layer
- Gossip protocol for state propagation between nodes
- Predictive matching engine — first version, basic surplus/needs correlation

**The interesting milestone:** The first inter-community dispute resolved through federation arbitration. That is when the system proves it has teeth.

**Exit criteria:** Three communities actively trading. At least one inter-community dispute resolved. Predictive matching surfaces at least one trade that would not have happened through manual search.

### Phase 3 — Resilience Layer (Months 19-26)

Make the system work when infrastructure fails. This is Railroad Network's core differentiator.

**Deliverables:**
- LoRa radio integration — transactions and governance over radio
- Delay-tolerant networking — store and forward for disconnected nodes
- Offline-first hardening — full functionality with zero connectivity
- SMS interface — basic transactions via text message
- Physical credential layer — QR code printed cards, paper fallback
- Conductor role formalization — trusted inter-community sync carriers
- Emergency governance modes — fast decision making under crisis conditions
- Node seizure resistance — encrypted at-rest data, rapid re-bootstrap

**Testing methodology:** Deliberately take communities offline for 72-hour simulated outages with real economic activity. Does everything reconcile correctly on reconnect? Red team the physical security.

**Exit criteria:** Simulated 72-hour full connectivity loss across 3 communities. All transactions reconcile. No credits lost. No ledger forks.

### Phase 4 — Federation Scale (Months 27-36)

Grow the network to where emergent properties appear.

**Deliverables:**
- Federation governance body — delegate assembly, protocol change voting
- Advanced predictive matching — machine learning on production cycles, seasonal modeling
- Community health metrics — economic indicators, governance participation, resilience scores
- Reputation guild system — domain-specific credentialing bodies
- Federation directory — discoverable network of all member communities
- Advanced ZK proofs — privacy-preserving duplicate identity detection
- Cross-federation bridges — connecting separate Railroad Network instances

**The emergent milestone:** The first community that joins primarily because of trade value, not because they knew the founders. That is organic network growth.

### Phase 5 — Antifragility (Ongoing from Month 37)

- Continuous security audits — not one-time, ongoing
- Protocol ossification — freezing stable layers so communities can depend on them
- Reference hardware kits — pre-configured Raspberry Pi nodes communities can order
- Training and onboarding materials — non-technical community setup guides
- Governance experimentation — different communities try different models, learnings propagate

### 12.1 Risk-Adjusted Sequencing

| Risk | Mitigation |
|---|---|
| **Crypto primitives wrong** | External audit after Phase 0 before any real users |
| **CRDT conflicts in practice** | Chaos testing throughout Phase 1 before federation |
| **Community cold start** | Seed 3 communities yourself before opening to others |
| **Governance capture** | Constitutional layer locked before first real community deployment |
| **LoRa regulatory issues** | Research spectrum licensing per geography in parallel with development |
| **Key loss / recovery failure** | Beta test social recovery with deliberate key destruction in Phase 1 |
| **Credibility — founder as operator** | Structure as foundation from day one; genuine not performative |

### 12.2 Meta-Governance of the Project

Railroad Network must practice what it preaches from day one. The project itself should be governed using the tools it builds. Core contributors form the founding community. Roadmap decisions made through the governance engine. Protocol changes require community ratification. No single founder has unilateral control over the protocol.

A platform for decentralized community governance that is itself centrally controlled is a credibility problem that cannot be recovered from.

---

## 13. Legal & Political Landscape

Railroad Network is not just a productivity application. At full vision it is parallel economic and governance infrastructure that operates outside traditional state systems. Understanding and navigating the legal landscape is as important as the technical architecture.

### 13.1 How Governments Perceive Railroad Network by Phase

| Phase | Regulatory Perception |
|---|---|
| **Phase 1 — Single community app** | Mostly invisible. Local currencies and time banks exist legally in most jurisdictions. Annoying to regulators but not threatening. |
| **Phase 2 — Federated credit system** | Attracts attention. A federated credit system moving value across communities looks like an unlicensed payment network to financial regulators. |
| **Phase 3 — Resilience layer** | Explicitly building infrastructure to operate outside state-controlled networks. National security framing enters. |
| **Phase 4+ — Meaningful scale** | A parallel economy with its own governance, currency, dispute resolution, and identity system. Direct challenge to state monopolies. |

### 13.2 Specific Legal Threat Vectors

#### Money Transmission Laws
In the US, operating a money transmission business without a license is a federal crime. FinCEN defines money transmission broadly. The mutual credit argument has some legal basis but has not been tested at scale. Each US state has its own licensing regime, making 50-state operation deliberately prohibitive. EU PSD2 and UK Payment Services Regulations create similar frameworks.

#### Securities Law
If Commons credits are tradeable, hold value, and are issued by an entity, regulators may classify them as securities under the SEC's Howey Test. Credits with demurrage, ceilings, and no speculative market look less like securities than freely-tradeable tokens. Design choices throughout affect this determination.

#### Anti-Money Laundering and KYC
Know Your Customer laws require financial service providers to verify the real-world identity of users. Railroad Network's pseudonymous identity system is a direct conflict with KYC requirements. This is probably the most immediate practical legal problem in a non-collapse scenario.

#### Parallel Dispute Resolution
Most jurisdictions have laws against operating private courts that purport to replace the state legal system. The design must stay clearly on the binding arbitration side of that line — voluntary, contractual, limited scope.

#### Tax
Every credit transaction is potentially a taxable barter event. The IRS explicitly requires reporting of barter income at fair market value. Tax guidance should be published for users and reporting tooling provided.

### 13.3 Historical Precedents

| Precedent | Lesson |
|---|---|
| **Liberty Dollar** | Bernard von NotHaus convicted of counterfeiting in 2011 for operating an alternative US currency. Do not make it look like a competing national currency. |
| **E-Gold** | Digital gold currency with 5 million users shut down by DOJ in 2007 for AML failures. AML compliance becomes existential at scale. |
| **Ithaca HOURS** | Local currency operating since 1991, never prosecuted. Positioned as community development, not political challenge. Framing and positioning matter as much as design. |
| **Tornado Cash** | Fully open source Ethereum mixer. Developers arrested in 2022 despite public code. Continued maintenance and promotion knowing it was used for money laundering. Continued active involvement is continued liability. |
| **Tor Project** | Open source anonymity network, developers not prosecuted. Non-profit structure, human rights framing, proactive legal engagement. Structure and positioning enable 20 years of operation. |
| **LETS systems** | Mutual credit networks operating globally since the 1980s, largely tolerated when small and local. Scale changes the calculus. |

### 13.4 The Open Source Shield

Publishing a protocol is legally similar to publishing a book. The shield holds when:

- You publish the protocol and step back — you are an **author**, not an operator
- You do not operate the network commercially — no hosted services, no transaction fees, no custody of keys
- The primary design purpose is legitimate, documented, and consistent
- Your documentation and communications are focused on legal use cases

The shield fails when continued active involvement makes you look like an operator, or when the primary design purpose appears to be illegal activity.

### 13.5 Participating as a Community Member

The founder can participate in communities without triggering operator liability if participation is genuine and bounded:

- **Clearly fine:** Regular member transactions, voting, having a reputation score — this is use, not operation
- **Probably fine with documentation:** Code contributions, writing documentation, speaking publicly about design
- **Gets complicated:** Being the de facto decision-maker the federation defers to, running infrastructure others depend on
- **Clearly problematic:** Unilateral merge rights over the codebase, custody of any funds, resolving disputes by personal authority

**The control question is what actually matters.** Prosecutors look at de facto control — who makes decisions, who has the keys, who the network depends on.

The posture: **author who uses their own work, not operator who happens to have published the code.**

### 13.6 Strategic Recommendations

1. **Positioning** — Frame Railroad Network as a mutual aid and community resilience platform. Emphasize disaster preparedness and economic resilience for underserved communities. All true. All less threatening. All more legally defensible.
2. **Legal entity** — A cooperative or nonprofit in a permissive jurisdiction. Wyoming (crypto-friendly DAO legislation), Switzerland (civil society protections), or Estonia (digital governance pioneer) are viable options.
3. **Open source from day one** — No proprietary core. No single entity controls the protocol.
4. **KYC at the platform level** — Any commercial operations comply with applicable requirements. Individual communities make their own decisions.
5. **Explicit arbitration framing** — Terms of service make clear that dispute resolution is binding arbitration under existing legal frameworks, not a replacement for law.
6. **Tax tooling** — Publish guidance and provide transaction history exports in tax-reportable format.
7. **Proactive regulatory engagement** — Engage regulators in target jurisdictions before scale. Being the cooperative actor who came to regulators first is a fundamentally different position.

---

## 14. Key Design Decisions Summary

### 14.1 Finalized Design Decisions

| Decision | Rationale |
|---|---|
| **Universal credit unit (the Common)** | One credit unit across all communities. No per-community currencies, no forex. Simplicity and interoperability over local monetary sovereignty. |
| **Mutual credit mechanics** | Zero-sum ledger, no pre-minting. Credit created by the act of trade. No central issuer that can fail. |
| **Tiered oracle model** | Four tiers scaling from bilateral confirmation to cross-community arbitration based on transaction value. Right friction for right stakes. |
| **Reputation staking on attestations** | Confirmers stake real reputation points. Makes collusion costly. The single most important fraud deterrent. |
| **Universal reputation algorithm** | Same formula everywhere. Communities cannot tune it to attract members. Prevents regulatory arbitrage race to the bottom. |
| **Three-layer identity** | Cryptographic keypair + community vouching + verifiable claims. Each layer adds a different kind of trust. |
| **Social key recovery** | Shamir's Secret Sharing distributed to trusted community members. No special hardware required. Reinforces community interdependence. |
| **Pseudonymity by default** | Minimum necessary disclosure per context. Protection from surveillance and physical targeting. |
| **Four-layer dispute escalation** | Automated → peer mediation → community tribunal → federation arbitration. Right process for right stakes. |
| **Federation as protocol** | Minimum viable interoperability standard. Communities retain sovereignty over everything not required for interoperability. |
| **Four treaty depths** | Trade → Recognition → Alliance → Full Federation. Graduated commitment matching graduated trust. |
| **Predictive marketplace matching** | Platform models production cycles, surfaces trade opportunities proactively. Anticipatory supply chain for collapse resilience. |
| **Rust implementation** | Performance, memory safety, low-power ARM capability, strong crypto library ecosystem. |
| **CRDT sync layer** | Offline-first state management. Any two nodes can merge state automatically regardless of disconnection duration. |
| **LoRa radio transport** | Keeps economic backbone operational when internet is gone. 5-15km range at very low power. |

### 14.2 Rejected Approaches

| Rejected Approach | Reason |
|---|---|
| **Per-community currencies** | Creates forex complexity, information asymmetry, and requires exchange rate infrastructure. |
| **Community-level reputation interpretation** | Creates regulatory arbitrage race to the bottom. |
| **Reputation inheritance** | Reputation should be earned, not inherited. Mentor's attestation carries weight; score does not transfer. |
| **Cloud-first architecture** | Collapses under the exact conditions the platform is designed for. |
| **Token-based economics** | Creates speculative dynamics, attracts securities regulatory scrutiny, introduces wealth concentration problems. |
| **Single unified governance mechanism** | Different decisions require different mechanisms. One-size-fits-all fails at both efficiency and legitimacy. |

---

## Appendix

### A. Glossary

| Term | Definition |
|---|---|
| **Common** | The universal mutual credit unit used across all Railroad Network communities |
| **Charter** | A community's founding constitutional document; cryptographically hashed and immutable except through supermajority amendment |
| **Conductor** | A high-reputation member who facilitates inter-community trade, carries sync payloads, and brokers new federation relationships |
| **CRDT** | Conflict-free Replicated Data Type; mathematical data structure enabling automatic merge of distributed state without conflicts |
| **Demurrage** | A periodic decay applied to accumulated credits to encourage circulation rather than hoarding |
| **Federation** | The network of communities connected through the Railroad Network protocol; not a merger, a protocol agreement |
| **Gossip protocol** | Mechanism for propagating state changes through the network via random peer exchanges |
| **LoRa** | Long Range radio protocol; 5-15km range at very low power; used for collapse-scenario transport |
| **Oracle** | Any mechanism that bridges physical reality to the digital ledger, attesting that a real-world event occurred |
| **Raft** | A distributed consensus algorithm for maintaining consistent ledger state within a community's node set |
| **Reputation staking** | Cryptographically linking your reputation score to an attestation, putting it at risk if the attestation proves false |
| **Shamir's Secret Sharing** | A cryptographic scheme for splitting a secret into N shares, where any K shares can reconstruct the original |
| **Station** | Two meanings, kept deliberately distinct: (1) the `station` daemon — the node software a community runs ("update your station to v0.4"); (2) per the Underground Railroad analogy, a community itself. Prefer "community" for the social/federation entity and "station" for the running software |
| **Treaty** | A formal federation agreement between two communities, signed by both governance keys and recorded on both ledgers |
| **ZK Proof** | Zero-knowledge proof; allows proving a statement is true without revealing the underlying information |

### B. Further Reading

- Iroquois Great Law of Peace — the constitutional model for federated sovereign governance
- Silvio Gesell, *The Natural Economic Order* (1906) — the theoretical foundation for demurrage
- Lewis Hyde, *The Gift* — on gift economies and the circulation of value
- James C. Scott, *Seeing Like a State* — on why centralized planning fails and local knowledge matters
- Kate Raworth, *Doughnut Economics* — on designing economies within planetary and social boundaries
- Nick Szabo, *Formalizing and Securing Relationships on Public Networks* (1997) — the intellectual foundation for smart contracts
- Martin Kleppmann, *Designing Data-Intensive Applications* — the technical foundation for distributed systems and CRDTs
- Diego Ongaro, *Consensus: Bridging Theory and Practice* (2014) — the Raft consensus algorithm

---

*— End of Document —*
