# 0013 — Federation and collapse-mode transport is pluggable; Reticulum is the adopted backend, run as an external sidecar

## Status

Accepted

Date: 2026-08-11

## Context

[ADR-0008](0008-mobile-station-transport.md) settled the mobile↔station link and,
in doing so, established a principle it deliberately scoped to Phase 1: **the
sealed-and-signed envelope is the security boundary and the transport is a dumb
carrier**, so "the identical bytes flow over HTTP today, over mesh or LoRa later,
and on a USB stick carried by a conductor in the fully-isolated case — with no
redesign and no second security review." It also left an explicit hole:
"Federation transport between stations is a separate decision (Phase 2, likely
libp2p) and is not settled here."

Two later phases have to fill that hole, and the design overview names their
requirements precisely:

- **Phase 2 — Multi-Community Federation** (design overview §Phase 2): community
  profiles, discovery, treaty negotiation, gossip-based state propagation, and
  inter-community credit flows. Federation is defined as *protocol, not merger*
  (§8.1) — communities exchange signed payloads and conductors carry letters of
  introduction.
- **Phase 3 — Resilience Layer** (design overview §Phase 3, §10.3): the transport
  must degrade across WiFi mesh, Tor-like routing, LoRa at ~250 bytes/second, and
  finally store-and-forward by physical carriers. The design names LoRa SX127x
  radio directly and formalizes the conductor role.

The "likely libp2p" placeholder is a poor fit for that mandate: libp2p assumes IP
connectivity as its substrate and does not degrade to LoRa or packet radio. The
Reticulum Network Stack (RNS) is built for exactly the §10.3 degradation ladder —
it addresses destinations by a hash of an Ed25519/X25519 identity with no
registrar, self-configures multi-hop routing across a mix of TCP, LoRa (via
RNode), serial, and packet-radio carriers, and its LXMF layer is delay- and
disruption-tolerant store-and-forward that maps almost one-to-one onto the
conductor pattern. A full fit assessment (kept out-of-tree with the project's
planning notes) evaluated it against the locked stack; this ADR is its outcome.

The forces:

- **The federation-transport slot is genuinely open** and ADR-0008 already did the
  conceptual work — a self-contained envelope that survives any carrier. What is
  missing is (a) a station↔station transport abstraction and (b) a chosen backend.
- **Reticulum's reference implementation is Python; our workspace is locked Rust**
  ([ADR-0001](0001-rust-workspace-and-dual-license.md)). The two things that most
  justify Reticulum for us — driving an RNode over LoRa, and LXMF store-and-forward
  — are, as of the assessment, effectively **available only in the Python
  reference**. The Rust port (reticulum-rs) has neither yet. So the phases that
  make Reticulum worth adopting cannot be served by a pure-Rust path today.
- **Reticulum has no formal spec** (the reference implementation is authoritative)
  and **has not been externally security-audited.** Adopting it as an *integrity*
  boundary would be reckless; adopting it as a *carrier* behind our own signed,
  sealed envelopes is not, because a transport compromise cannot forge a
  transaction or an attestation.

## Decision

**Federation and collapse-mode transport is pluggable behind an `rrn-protocol`
transport seam, and Reticulum is the adopted backend for it — as a carrier only.**
This extends ADR-0008's dumb-carrier principle from the mobile↔station hop to the
station↔station hop.

Concretely, this ADR locks four things and defers one.

**1. The seam.** `rrn-protocol` gains a transport abstraction: "deliver a reliable,
self-contained signed payload (and, where the carrier supports it, a stream) to a
peer identified by an RRN identity," independent of whether the bytes move over
local TCP, Reticulum, or a future carrier. No IP address, socket, or session
assumption leaks into the wire layer or any caller. The mobile↔station HTTP path
of ADR-0008 is unaffected and continues unchanged; it is one concrete carrier
among several, not the abstraction's only shape.

**2. Reticulum is the adopted federation/collapse-mode carrier** — for WAN
federation traffic (treaty exchange, signed community profiles, reputation gossip)
and for the Phase 3 LoRa/store-and-forward path. This displaces ADR-0008's
"likely libp2p" placeholder.

**3. Reticulum is a carrier and nothing else. Explicit non-goals:**

- **Not the identity root.** The three-layer identity (Ed25519 keypair + vouching
  DAG + verifiable claims) stays the trust root. An RRN identity may *bind* a
  Reticulum destination by signing a statement associating the two, and re-bind
  after recovery or rotation — the RRN identity is the durable root that carries
  reputation and survives social recovery; the Reticulum destination is a
  disposable, rotatable reachability handle underneath it. **Bind, do not
  collapse** — even though both use Ed25519.
- **Not the ledger's integrity boundary.** Transactions, attestations, and
  governance payloads are signed and sealed at the app layer with our own
  primitives (`ed25519-dalek`, `blake3`, XChaCha20-Poly1305 AEAD over canonical
  dCBOR, per [ADR-0002](0002-canonical-serialization-dcbor.md)) regardless of
  transport. Reticulum's own link encryption (Ed25519/X25519, AES-256-CBC +
  HMAC-SHA256, Fernet-style) is a bonus outer layer, never the integrity guarantee.
  Nobody may "simplify" by relying on it.
- **Not the within-community consensus path.** Raft is chatty and latency-sensitive
  and runs on the 3–7 local household nodes (design overview §10.4). It never runs
  over a LoRa or WAN Reticulum hop. Reticulum carries CRDT merges, inter-community
  WAN traffic, and the collapse fallback — not the hot Raft path.
- **Not the mobile↔station local transport.** That stays local-network **plain HTTP
  over TCP** with sealed envelopes per ADR-0008. Reticulum adds nothing on a
  same-WiFi hop.

**4. The integration path is the Python reference daemon (`rnsd`), run as an
external, supervised, version-pinned OS service** — treated like `tor` or
`postgres`, not like a library. `rrn-station` speaks to it over its
socket/API. It is deliberately **not** a Cargo dependency: the Rust workspace and
its hermetic `cargo` CI stay pure Rust, and integration tests run against a pinned
`rnsd`. This is chosen because the LoRa/RNode and LXMF capabilities that motivate
the whole adoption live only in the reference today, and because the reference is
the canonical Schelling point of a now-multi-implementation ecosystem (Python,
reticulum-rs, C++ microReticulum, Go, Zig) — the node most likely to survive a
maintainer transition.

**Deferred (not locked here):** the *binding, final* choice between the Python
sidecar and a native path is ratified by a **Phase 2 spike** in a follow-up ADR.
The sidecar is the committed presumptive path; the seam keeps two escape hatches
open at near-zero switching cost — **reticulum-rs** (native embeddable Rust) if it
matures to drive an RNode, and **microReticulum** (C++, FFI) for embedded targets
too small to host a Python runtime. The spike's job is to confirm the sidecar
end-to-end and answer one question that decides whether the native path is even
viable for Phase 3: *does reticulum-rs drive an RNode over LoRa yet, or is the
reference required for the radio story?*

This ADR does **not** yet write the transport-trait code. The abstraction is
committed as a principle; the trait lands with its first real second implementor
(the Phase 2 federation carrier), so it is shaped against a real requirement
rather than an imagined one.

## Consequences

- **Phase 3 becomes a transport *integration*, not a radio-stack *build*.** LoRa
  framing, airtime management, multi-hop routing, path discovery, retransmission
  over lossy links, and radio↔internet bridging are Reticulum's core competency.
  The Phase 3 plan should be rewritten to integrate a transport and delete those
  bespoke tasks — a net scope *reduction*. This is the clearest ROI of the whole
  decision.
- **…but that ROI is contingent on the sidecar.** Because the radio and LXMF
  capabilities are Python-only today, the "delete a radio stack" win arrives
  bundled with "run a supervised Python service on every station, including
  constrained collapse nodes." The footprint is not the problem — the RNS
  reference is built to run on a Raspberry Pi / low-power SBC, and on a collapse
  node the binding constraint is LoRa airtime (~250 B/s), not the interpreter's
  tens of MB. The real cost is **operational**: a second runtime and a second
  process to supervise, restart, and keep from silently failing in the field where
  the operator is a non-technical volunteer. Packaging `rnsd` as a managed,
  appliance-style service is what contains that cost.
- **The seam converts a foundational bet into a swappable dependency.** Committing
  to the sidecar costs nothing we cannot undo: if reticulum-rs matures, we swap the
  backend behind the same seam with no change to callers. Version pinning plus the
  seam is the mitigation for the no-spec / maintainer-transition / partial-interop
  risk the assessment flagged.
- **Federation gossip and treaty exchange get a substrate for free.** Announce /
  path propagation and LXMF store-and-forward move the app-level payloads; a
  community that is currently unreachable has its payload held and forwarded when a
  path appears — the conductor pattern as a protocol primitive.
- **Forward secrecy across two ADRs stays deliberately separate.** ADR-0008
  accepted "no forward secrecy" on the LAN hop and named Noise_KK as its upgrade
  path; Reticulum Links provide FS on the WAN/radio hop. These remain independent
  answers — adopting Reticulum for federation does **not** retroactively resolve
  ADR-0008's mobile↔station FS follow-up, and nobody should assume it does.
- **Initiator anonymity shifts a requirement onto the app layer.** Reticulum
  packets carry no source address. Anything that must be attributable — a
  reputation-staked attestation — must name and sign its signer at the app layer.
  We already sign there, so this is a non-issue *as long as it is stated*.
  Truncated-hash addressing has a finite collision space — fine at our scale, to be
  noted in the threat model.
- **Bandwidth contention on constrained links is a new tuning surface.** Reticulum's
  own announces and path requests share the ~250 B/s LoRa channel with ledger and
  gossip traffic. Link keepalive (~0.44 bps) is negligible; announce storms are the
  thing to budget, especially under Bootstrap-tier single-node rules with less
  redundancy to absorb loss.
- **A new open-source-posture check.** The public-domain protocol dedication (2016)
  is clean, but the reference *code* is under the Reticulum License; path A ships
  that code as a runtime dependency, so its license must be confirmed compatible
  with our distribution posture before Phase 3.
- **CI grows an integration surface.** Unit and workspace tests stay pure-Rust and
  hermetic. A new, separately-gated integration lane exercises `rrn-station`
  against a pinned `rnsd` (and, when relevant, a reticulum-rs↔Python interop check
  against the exact versions we would deploy).

## Alternatives Considered

- **libp2p** (ADR-0008's placeholder). Rejected as the *primary* federation
  transport: it assumes IP as its substrate and does not degrade to LoRa or
  store-and-forward, so it cannot serve the §10.3 ladder or Phase 3 at all —
  precisely the mandate that most differentiates this project.
- **Roll our own Rust RNS.** Rejected. It means perpetually chasing an unversioned
  reference with no formal spec, for a carrier we treat as replaceable. All cost,
  no strategic upside.
- **reticulum-rs (native Rust) as the integration path now.** Rejected *for now*,
  not on merit: it fits the stack and would avoid the second runtime, but per the
  assessment it cannot drive an RNode over LoRa and has no LXMF — so it cannot serve
  the Phase 2/3 capabilities that justify adopting Reticulum. Retained as the
  primary seam-swap target if it matures; the Phase 2 spike checks exactly this.
- **microReticulum (C++, FFI).** Not chosen as the default (C++ FFI surface, another
  implementation to track), but retained as the embedded escape hatch for station
  hardware too constrained to host a Python runtime.
- **Collapsing the RRN identity into the Reticulum identity** (both are Ed25519).
  Rejected — see the "bind, do not collapse" non-goal. Reticulum destinations are
  ephemeral and rotatable and model none of Shamir recovery, the vouching DAG,
  verifiable claims, or per-context personas.
- **Relying on Reticulum's link encryption as the integrity boundary.** Rejected,
  and stated explicitly so nobody reads convenience as license: the transport is
  unaudited and its crypto is independent of ours; integrity stays at the app layer.

## References

- [ADR-0008](0008-mobile-station-transport.md) — the dumb-carrier / sealed-envelope
  principle this ADR extends from the mobile↔station hop to station↔station; source
  of the "likely libp2p" placeholder this supersedes for federation transport
- [ADR-0001](0001-rust-workspace-and-dual-license.md) — the locked-Rust workspace
  whose hermeticity the external-sidecar framing preserves
- [ADR-0002](0002-canonical-serialization-dcbor.md) — canonical dCBOR, the bytes the
  app layer signs regardless of transport
- [ADR-0006](0006-m1-client-architecture.md) — the mobile holds the keys; app-layer
  authentication is transport-independent
- The Reticulum fit assessment (kept out-of-tree with the project's planning
  notes) — the full evaluation behind this decision
- Design overview §8 "The Federation Protocol", §10.3 "Transport Layer — Graceful
  Degradation", §10.4 "Consensus Layer", §Phase 2, §Phase 3
- [`docs/threat-model.md`](../threat-model.md) — to gain a Reticulum-transport
  section (initiator anonymity, truncated-hash addressing, unaudited transport
  crypto, announce-budget) when integration lands
