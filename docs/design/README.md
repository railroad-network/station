# Design Documents

This directory holds the canonical design references for Railroad Network.

| Document | Summary |
|---|---|
| [Railroad-Network-Overview.md](Railroad-Network-Overview.md) | Full design overview: vision, governance, the mutual-credit economy, the oracle problem, reputation, identity, dispute resolution, federation protocol, marketplace, technical architecture, UX, roadmap, and legal landscape. |

**How it is maintained.** The overview is the long-form *intent* document and
predates most of the implementation. It is updated in place with **dated
notes** (`> **Updated 2026-09-13.** …`) wherever the implementation diverged,
a criterion was discharged, or a phase closed, so a reader sees both the
original reasoning and what actually shipped. Locked decisions are not made
here: they are Architecture Decision Records in [`../adr/`](../adr/README.md),
and where the overview and an ADR disagree, **the ADR wins**. Phase numbering
changed in ADR-0017 (Phase 2 is single-community resilience, Phase 3 is
federation); the overview uses the new numbering.

For the plain-language version of all of this, written for members,
organizers, and operators, see <https://railroad-network.github.io>.
