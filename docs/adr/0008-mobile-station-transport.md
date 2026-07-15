# 0008 — The mobile↔station envelope is the security boundary; the transport is a dumb carrier

## Status

Accepted

Date: 2026-07-14

## Context

[ADR-0006](0006-m1-client-architecture.md) settled *who holds the keys* (the
mobile) and left a constraint for M1.3: "the mobile–station transport is not a
trusted channel where the station vouches for the caller; every request carries
the mobile's signature and is verified against the paired identity." M1.3 now
has to build that link. This ADR fixes how the bytes get from a phone to a
station, and — more importantly — *which layer is responsible for protecting
them*.

Today the station speaks line-delimited JSON over a Unix domain socket
(`crates/rrn-station/src/rpc.rs`), and the socket's `0o600` permissions are the
entire authorization story. That works for a CLI on the same box and not at all
for a phone on the LAN. Nothing in the workspace does HTTP, TLS, or mDNS yet, so
whatever we pick here is greenfield on both sides.

The forces:

- **Confidentiality is not optional.** A mutual-credit ledger's payloads are
  amounts, counterparty addresses, memos, and — in aggregate — the social graph
  of a community. Stations are deployed on shared WiFi at community centers,
  which is exactly where a passive observer sits. Anything readable on the wire
  is readable by the room.
- **The transport will not stay TCP.** Design overview Section 10.3 commits this
  network to degrading across WiFi mesh, Tor-like routing, LoRa at ~250
  bytes/second, and finally store-and-forward by physical carriers. Phase 1 only
  needs the local-network case, but a Phase 1 decision that *cannot* survive the
  others is a decision we pay for twice.
- **Platform dependence is a project risk, not just an engineering cost.** The
  further our security properties live inside Apple's and Google's stacks, the
  more of our threat model is downstream of their policy changes, their review
  processes, and their release schedules.
- **We already own the primitive.** M0.4's social recovery seals each Shamir
  shard to its holder: X25519 ECDH over keys converted from the holder's Ed25519
  identity, then XChaCha20-Poly1305, keyed through blake3's `derive_key` KDF
  (`crates/rrn-identity/src/recovery/encryption.rs`). That is precisely
  "encrypt this to an Ed25519 identity." A station *is* an Ed25519 identity, and
  pairing is what puts its public key in the mobile's hands. The code is written,
  tested against cross-implementation vectors, and already crosses the mobile FFI
  (T1.2.3).

The M1.3 task spec proposed HTTPS with self-signed per-station certificates and
fingerprint pinning at pairing time. **This ADR deliberately departs from that
proposal**; the reasoning is recorded under Alternatives Considered so the
departure is legible rather than looking like drift.

## Decision

**Application-layer sealed-and-signed envelopes are the security boundary. The
transport is a dumb carrier and is not trusted with anything.**

For Phase 1 that carrier is **plain HTTP over local TCP**. No TLS.

The envelope, not the connection, carries every security property:

- **Signed, per ADR-0006.** The canonical request payload — canonical dCBOR, per
  [ADR-0002](0002-canonical-serialization-dcbor.md) — is signed with the
  mobile's Ed25519 identity key.
- **Sealed to the recipient's paired identity**, reusing the M0.4 sealed-box
  scheme unchanged: ephemeral X25519 keypair, ECDH against the recipient's
  identity key converted Edwards→Montgomery, XChaCha20-Poly1305 under a
  blake3-derived key. Mobile→station is sealed to the station's identity;
  station→mobile responses are sealed to the mobile's identity, which the
  station learned at pairing.
- **Sign, then seal — and bind the recipient inside the signed bytes.** The
  signature covers the payload *including the intended recipient's public key*,
  and the signed payload-plus-signature is what gets sealed. The recipient
  binding is load-bearing: without it a station could peel a signed request out
  of its envelope and re-seal it to a third party, who would then hold a valid
  signature from a member on a message that member never sent them.
- **Replay defense inside the signed bytes**: a per-mobile monotonic nonce and a
  timestamp, matching the ledger's existing discipline (design overview Section
  10.8) and specified concretely in T1.3.4.

**Pairing binds static public keys and nothing else** (T1.3.3). There is no
certificate, so there is no certificate to pin, expire, or rotate. The station's
identity key *is* its identity. The human-verifiable confirmation code is derived
from both static public keys, so it authenticates the pair rather than a
rotatable credential.

This ADR scopes **Phase 1 only**. Federation transport between stations is a
separate decision (Phase 2, likely libp2p) and is not settled here.

## Consequences

- **The same envelope survives every transport in Section 10.3.** Because each
  envelope is self-contained and self-protecting, the identical bytes flow over
  HTTP today, over mesh or LoRa later, and on a USB stick carried by a conductor
  in the fully-isolated case — with no redesign and no second security review. A
  session-oriented channel could not do this: TLS requires a reliable ordered
  stream and dies at the first store-and-forward hop. This is the single
  strongest reason for the decision.
- **Our security properties depend on our own Rust, not on a platform TLS
  stack.** The seal and the signature are computed by `rrn-identity` code that
  already runs on both platforms through the uniffi surface from M1.1
  ([ADR-0007](0007-rust-mobile-ffi-uniffi.md)). One implementation, one audit
  surface, identical behaviour on iOS and Android — rather than a custom trust
  module written twice in two platform languages, which is exactly where our
  Android coverage is weakest today.
- **No certificate lifecycle.** Nothing expires. A self-signed cert on a
  Raspberry Pi that lapses would have broken pairing for every member of that
  community at once; that failure mode simply does not exist here.
- **Accepted: no forward secrecy.** Compromise of a station's long-term identity
  key retroactively decrypts any captured traffic sealed to it. The M1.3 spec
  already deems per-request forward secrecy "overkill for Phase 1," and we
  concur for the local-network case. **Follow-up:** because pairing already
  establishes both static keys, a Noise_KK session is a clean upgrade path if
  this trade stops being acceptable — that would be a new ADR superseding this
  one's transport-secrecy properties.
- **Accepted: identity keys do double duty for signing and key exchange.** The
  seal converts an Ed25519 identity key to its Montgomery form for ECDH, so one
  long-term key serves two algorithms. `recovery/encryption.rs` already accepts
  this trade on the grounds that "recovery holders are identified by exactly one
  long-term key"; the same holds for a station and for a paired mobile, so the
  reasoning carries over unchanged rather than being extended to a new case.
- **Accepted: we lose plaintext wire debugging.** `curl` and browser tooling
  against a sealed body show ciphertext, which costs us the ergonomics the
  HTTPS proposal was partly chasing. **Mitigation:** `rrn-cli` speaks the same
  envelope and is the supported debugging path; a station-side debug mode can
  log decrypted envelopes on an operator's own box.
- **Accepted: metadata is still exposed.** Sealing hides content, not traffic
  patterns. An observer on the LAN still learns which mobile talks to which
  station, how often, and roughly how large the messages are. Traffic analysis is
  out of scope for Phase 1.
- **One remaining platform dependency: cleartext HTTP needs an ATS allowance on
  iOS.** `NSAllowsLocalNetworking` exists for exactly this case and permits
  cleartext to local destinations without the broad `NSAllowsArbitraryLoads`
  flag; mDNS (T1.3.2) gives us a `.local` name to target.
  `NSLocalNetworkUsageDescription` is required for LAN access regardless of
  transport choice. Both are to be confirmed during T1.3.4 implementation.
- **The station grows an HTTP server.** A plain-HTTP listener is new dependency
  surface for `rrn-station` (the workspace has no HTTP crate today), though a
  markedly smaller one than an HTTP + TLS + cert-generation stack.
- **Downstream tasks shift.** T1.3.2's mDNS TXT records drop the proposed
  `cert_fp` field, keeping `address` and `version`. T1.3.3 stores
  `(station_pubkey, station_host)` rather than a cert fingerprint, and derives its
  8-hex confirmation code from the two static keys. T1.3.4's envelope is the
  sealed form specified here rather than a bare JSON `auth` block.
- **The threat model's existing prediction holds.** `docs/threat-model.md`'s
  mobile–station transport section already anticipated that "the channel is
  encrypted with keys established at pairing" — this decision is what makes that
  sentence true. Converting its *planned* mitigations to shipped ones is
  T1.3.4's job.

## Alternatives Considered

- **HTTPS with self-signed per-station certs, fingerprint-pinned at pairing**
  (the M1.3 spec's proposal). Rejected on three counts. *Platform dependence:*
  React Native's `fetch` exposes no hook to override certificate trust — iOS ATS
  and NSURLSession reject a self-signed cert outright and Android's OkHttp
  consults the system trust store — so pinning would require a bespoke native
  module per platform, placing a security-critical property inside the vendors'
  stacks and their policy changes. *Lifecycle:* certificates expire, and cert
  rotation under pinning is a known-nasty operational problem for unattended
  Raspberry Pi hardware. *Transport lock-in:* TLS cannot cross LoRa or
  store-and-forward, so Section 10.3's degraded carriers would need this work
  done a second time. It buys a property we can already produce ourselves in
  Rust that we already ship on both platforms.
- **Plain HTTP with signatures but no encryption at all.** Rejected. Signatures
  give authenticity and integrity but not confidentiality, so amounts,
  counterparty addresses, and memos would be readable by anyone on the shared
  community-center WiFi that is our actual deployment environment. It also
  contradicts the threat model's standing commitment to an encrypted channel. The
  saving over the chosen design is small, because the sealing primitive already
  exists.
- **A Noise session (Noise_KK) over TCP.** Rejected *for Phase 1*, not on
  merit — it is a well-analyzed framework, WireGuard-proven, and pairing already
  gives both sides the static keys Noise_KK wants. But it adds handshake state,
  session resumption, and reconnection logic to buy forward secrecy that the M1.3
  spec explicitly scopes out, and a session is the thing that cannot cross
  store-and-forward. Retained as the named upgrade path above.
- **Hand-rolled bespoke transport encryption.** Rejected, and worth stating
  explicitly so nobody reads this ADR as license for it. The chosen design is not
  a new construction: it reuses M0.4's existing, tested, cross-implementation-
  vetted sealed-box scheme, with a deliberately boring composition (canonical
  dCBOR, sign-then-seal, recipient bound into the signed bytes, nonce and
  timestamp). Novel cryptography remains out of bounds.
- **QUIC or gRPC.** Rejected: more moving parts and thinner React Native
  ecosystem support, for no benefit at our scale — and both carry the same
  session-oriented transport lock-in as TLS.
- **WebSocket as the primary channel.** Rejected: request/response is the
  dominant pattern, and long-poll (T1.3.5) covers push more simply than
  WebSocket reconnection logic. Revisit in Phase 2 if push rates spike.

## References

- [ADR-0006](0006-m1-client-architecture.md) — the mobile holds the keys and
  authenticates per request; this ADR implements that constraint
- [ADR-0002](0002-canonical-serialization-dcbor.md) — canonical dCBOR, the bytes
  that get signed
- [ADR-0007](0007-rust-mobile-ffi-uniffi.md) — the FFI that already carries the
  sealing primitive to both platforms
- [ADR-0004](0004-own-shamir-implementation.md) — social recovery, whose
  shard-sealing scheme (`rrn-identity/src/recovery/encryption.rs`) this reuses
  unchanged
- Design overview, Section 10.3 "Transport Layer" — the degradation ladder that
  makes a self-contained envelope the load-bearing choice
- Design overview, Section 10.8 "Security Architecture" — per-identity monotonic
  nonce plus timestamp as the replay defense
- `crates/rrn-station/src/rpc.rs` — the M0.6.3 IPC envelope this extends
- [`docs/threat-model.md`](../threat-model.md) — mobile–station transport section
- M1.3 task spec — T1.3.2 discovery, T1.3.3 pairing, T1.3.4 authenticated
  requests, T1.3.5 push; all constrained by this ADR
