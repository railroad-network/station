# 0026 — The Reticulum sidecar is ratified: pinned `rnsd` 1.5, driven from the station, native Rust deferred

## Status

Proposed

Date: 2026-09-07

> **Human-review checkpoint (T2.6.1).** This ADR records the outcome of the
> Phase-2 spike that [ADR-0013](0013-federation-transport-reticulum.md)
> chartered, and it **stops here for maintainer review**. It is deliberately left
> *Proposed*: the maintainer ratifies (marks it Accepted) or redirects before
> T2.6.2 begins building the `FrameTransport` backend on top of the decision. The
> supervisor, the spike, and the threat-model section it references have already
> landed with this ADR; only the *decision* awaits ratification.
>
> **ADR-number note.** ADR-0013 anticipated this taking number 0023. By the time
> the ticket ran, the README board had reserved 0023 (emergency governance,
> T2.8.1) and 0024 (at-rest encryption, T2.9.1), and 0025 was written — so this
> takes the next free number, **0026**. Cross-references (T2.6.x tickets, threat
> model, the board) point here.

## Context

ADR-0013 committed to Reticulum as the federation/collapse-mode carrier and made
one binding promise it did not yet keep: the *final* choice between the Python
reference daemon (`rnsd`) run as an external sidecar and a native-Rust path would
be "ratified by a **Phase 2 spike** in a follow-up ADR." It named the spike's job
precisely — "confirm the sidecar end-to-end and answer one question that decides
whether the native path is even viable for Phase 3: *does reticulum-rs drive an
RNode over LoRa yet, or is the reference required for the radio story?*" — and
flagged three things to verify before committing: the exact pinned versions, the
Rust↔`rnsd` interface for T2.6.2, and the Reticulum-License distribution posture.

This ADR is that follow-up. Its inputs are the T2.6.1 spike
(`crates/rrn-station/tests/reticulum_spike.rs`, run against a pinned `rnsd`) and a
fresh survey of the Reticulum ecosystem as of the ticket date (2026-09-07); the
out-of-tree Reticulum fit assessment (2026-08-10) is its predecessor and several
of its facts have since moved.

## Decision

**Ratify the sidecar.** The station drives Reticulum as an external, supervised,
version-pinned `rnsd` — exactly ADR-0013's presumptive path — and native Rust
stays a deferred seam-swap target, not the Phase-2/3 integration path. Concretely:

**1. Pin `rns` 1.5, `lxmf` 1.1.** The spike ran green against `rns` 1.5.2 (PyPI,
2026-08-29) and `lxmf` 1.1.1, on CPython 3.11 with `cryptography` 50.0.1 and
`pyserial` 3.5. The station's default version pin is the dotted prefix `"1.5"`
(`DEFAULT_PINNED_RNSD_VERSION`), accepting any `1.5.x` and refusing anything else
unless an operator sets `allow_version_drift`. The CI spike lane installs
`rns==1.5.2 lxmf==1.1.1`.

**2. The integration surface is the in-process Python `RNS` + `LXMF` API, reached
through `rnsd`'s shared instance — not a language-neutral RPC.** The spike
confirmed, and the survey corroborated, that **RNS exposes no application-level
send/receive RPC.** There are two local channels and neither is one: the *shared
instance* socket carries raw HDLC-framed Reticulum packets with no authentication
(a packet carrier, not an API — a non-Python client would have to reimplement the
Reticulum packet/link/crypto layer to use it), and the *control* RPC
(`multiprocessing.connection` on port 37429) serves only status/drop operations
— what `rnstatus`/`rnpath` use — with no message layer. The supported way to send
or receive an LXMF message is an in-process Python program that imports `RNS` and
`LXMF` and attaches transparently to the running `rnsd` shared instance. **This is
the single most important finding for T2.6.2** and it shapes the Rust↔`rnsd`
interface below.

**3. The T2.6.2 Rust↔`rnsd` interface: a thin Python LXMF adapter co-process, not
a socket the station speaks directly.** Because there is no neutral RPC, the
station cannot "talk to `rnsd` over its socket" the way it talks to, say,
`postgres`. T2.6.2 therefore implements the `FrameTransport` seam over a **small,
supervised Python adapter** (an evolution of the spike's `scripts/spike/`
helper into a supported component) that the station drives over a local line
protocol — hand it opaque outbound bundle bytes + a destination, receive inbound
bytes — while the adapter attaches to `rnsd` and does the `LXMF.LXMessage` /
`handle_outbound` / delivery-callback dance. `LXMessage` takes opaque `bytes`
content directly (`set_content_from_bytes`), so our sealed/signed bundle rides as
the message body unmodified. The adapter is *carrier plumbing* and holds no RRN
key; the station stays the master process that supervises it (the T2.6.1
supervisor already manages `rnsd`; T2.6.2 extends the pattern to the adapter, or
folds the adapter into the same supervised subtree). The status/health probe uses
the control RPC (`rnstatus`) that the generated config's shared instance exposes.

**4. Native Rust (reticulum-rs) remains deferred — and is now blocked on license,
not only on capability.** ADR-0013's decisive question was whether reticulum-rs
drives an RNode over LoRa yet. As of 2026-09-07 the answer is still **no** for the
seam-swap target we named: BeechatNetworkSystemsLtd/**Reticulum-rs** (crates.io
`reticulum` 0.1.0, MIT) ships only TCP/serial/Kaonic interfaces — no RNode/LoRa
module, no LXMF. Newer entrants *have* closed the capability gap (FreeTAKTeam
**LXMF-rs** v0.11.0 with a bearer-neutral RNode backend and full LXMF; codeberg
**leviculum**, "LoRa radio support … tested against Python Reticulum on real
hardware") — but both are under copyleft licenses our `cargo deny` allowlist
denies (EPL-2.0 and AGPL-3.0-or-later respectively), so neither is an available
native path for a crate we would *link*. The sidecar keeps Reticulum's code out
of our link/license graph entirely (see §6), which is now a *stronger* reason for
it than when ADR-0013 chose it. reticulum-rs stays the seam-swap target if it
gains RNode/LXMF under a permissive license; microReticulum (C++, Apache-2.0)
remains the embedded escape hatch but still lacks LXMF.

**5. The spike is genuinely faithful to the adoption thesis.** It boots two
station-*supervised* `rnsd` instances linked over a local TCP interface, and
carries a **real signed `Bundle`** (from the T2.2.1 record types) A→B over LXMF,
asserting byte-identical delivery **including with the receiver started after the
send** — the store-and-forward property that is the entire point of adopting
Reticulum (ADR-0013 §Consequences). It passed in ~14 s. The Python side is a
<100-line spike-support helper under `scripts/spike/`; the production Rust↔`rnsd`
interfacing choice is §3 above, part of this ADR per ADR-0013's charter.

**6. Distribution posture: the sidecar is operator-installed, and its license
stays out of our graph — but is disclosed.** ADR-0013 flagged a "new
open-source-posture check": the protocol is public-domain (2016) but the reference
*code* is under the Reticulum License, and it "must be confirmed compatible with
our distribution posture." Confirmed: the reference code is under the **"Reticulum
License"** — the MIT text plus two field-of-use restrictions (the software may not
be used in a system that can "purposefully do harm to human beings," nor "in the
creation of an artificial intelligence, machine learning or language model
training dataset"). It is **not OSI-approved** (field-of-use restrictions), and is
reported marked non-free by Debian (unverified against Debian primary sources). We
neither bundle nor link it: `rnsd`/`lxmf` are **operator-installed** runtime
dependencies (`pipx install rns lxmf`), so they never enter the Cargo graph, the
`cargo deny` license allowlist, or the shipped artifact — the workspace stays
Apache-2.0/MIT and license-clean. What we *do* owe is disclosure: an operator who
enables `[sidecar]` runs field-restricted software whose two use-restrictions
attach to any system that uses it. That is documented in the threat model and the
operator runbook (community-setup), not resolved in code. This is a *stronger*
argument for the sidecar over a linked native port than ADR-0013 had — a linked
Reticulum-License (or EPL/AGPL, §4) crate would fail our allowlist outright.

## Consequences

- **T2.6.2 has a concrete shape.** It builds the `FrameTransport` impl over a
  supervised Python LXMF adapter (§3), not over a mythical neutral `rnsd` socket.
  This is a larger surface than "open a socket" — a second supervised co-process
  and a local line protocol — but it is the only supported programmatic path, and
  the T2.6.1 supervisor is the reusable half of it. Announce-budget/airtime pacing
  (ADR-0013's constrained-link concern) lives in that same layer.
- **The hermetic, license-clean Rust workspace is preserved, and that is now a
  headline benefit.** `rnsd`, `lxmf`, and their Python dependency tree are
  operator-installed (`pipx install`), never Cargo dependencies, so `cargo deny`'s
  allowlist and the pure-Rust CI stay untouched even though the reference code is
  under a license our allowlist would reject (§6).
- **A second runtime and now a second co-process to supervise.** ADR-0013 already
  accepted the operational cost of a supervised Python service on every station
  that enables the carrier; §3 adds the LXMF adapter to that supervised subtree.
  The appliance discipline (version pin, backoff, clean kill, status legibility)
  that T2.6.1 built for `rnsd` is what contains it, and applies to the adapter
  too.
- **Off by default.** `[sidecar] enabled = false`; a station carries traffic over
  Reticulum only where an operator opts in. No pilot or single-community
  deployment is affected until it chooses to be.
- **The version pin is a maintenance commitment.** `rns` cut 1.5.0→1.5.2 inside a
  week during the spike window; the pin (`"1.5"`) tracks a minor line, and moving
  it is a deliberate, tested step, not an automatic upgrade — exactly the
  no-spec/maintainer-transition mitigation ADR-0013 called for.

## Alternatives Considered

- **reticulum-rs as the Phase-2/3 integration path now.** Rejected, on both
  capability and license: no RNode/LoRa and no LXMF (crates.io `reticulum` 0.1.0),
  so it cannot serve the radio/store-and-forward story the adoption is for.
  Retained as the seam-swap target if it matures under a permissive license.
- **LXMF-rs / leviculum (native Rust, with LoRa + LXMF today).** Rejected as a
  *linked* dependency purely on license — EPL-2.0 and AGPL-3.0-or-later are denied
  by our `cargo deny` allowlist (the AGPL family by policy). Worth re-examining
  only if one relicenses permissively, or if run as an external process (which
  would forfeit the "native, no second runtime" benefit that motivates them).
- **Speak `rnsd`'s shared-instance socket directly from Rust.** Rejected: it
  carries raw HDLC-framed Reticulum packets with no authentication, so using it
  means reimplementing the Reticulum packet/link/crypto layer in Rust — ADR-0013's
  rejected "roll our own RNS," in through the back door.
- **Embed RNS in-process another way (PyO3, a bundled interpreter).** Rejected for
  Phase 2: it drags CPython into the station's own process and license/packaging
  graph, forfeiting the sidecar's central benefit — a separately-installed,
  separately-supervised carrier that cannot compromise the station's integrity or
  its clean license posture.

## References

- [ADR-0013](0013-federation-transport-reticulum.md) — the decision this
  ratifies: pluggable transport seam, Reticulum as carrier-only, the sidecar as
  presumptive path, and the Phase-2 spike charter this ADR closes out.
- [ADR-0008](0008-mobile-station-transport.md) — the dumb-carrier / sealed-envelope
  principle Reticulum extends to the station↔station hop.
- [ADR-0002](0002-canonical-serialization-dcbor.md) — the canonical dCBOR the app
  layer signs, transport-independent.
- T2.6.1 — this ticket: the supervisor (`rrn-station::sidecar`), the spike
  (`crates/rrn-station/tests/reticulum_spike.rs`), the spike helper
  (`scripts/spike/lxmf_pingpong.py`), and the CI `reticulum-spike` lane.
- T2.6.2 (next) — the `FrameTransport` backend and announce/airtime budget over
  the interface decided in §3; T2.6.3 — RNode/LoRa interface template and hardware
  bring-up.
- [`docs/threat-model.md`](../threat-model.md) — "Reticulum transport sidecar"
  section (process compromise = carrier compromise, announce budget, initiator
  anonymity, truncated-hash addressing, distribution posture).
- The Reticulum fit assessment (out-of-tree planning notes, 2026-08-10) — this
  ADR's predecessor; superseded on the version, RPC-surface, and native-port facts
  by the spike and the 2026-09 survey.
