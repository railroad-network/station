# 0006 — The mobile client holds the keys; the station is a local backend

## Status

Accepted

Date: 2026-07-04

## Context

Phase 1 introduces a second piece of software beside the `station` daemon: a
mobile client (the `mobile` repo, React Native + TypeScript). Before either
implementation matures, we have to fix the relationship between the two, because
that relationship decides where cryptographic identity lives — and every M1 task
from M1.1 through M1.4 is shaped by the answer.

The forces:

- **Self-sovereign identity is a design commitment, not an implementation
  detail.** Design overview Section 6.3 ("Identity Wallet") describes an
  identity as a keypair the *member* holds. If the keys live anywhere else, the
  member is not sovereign over their identity — someone else can sign as them.
- **The station is physically seizable.** In the deployment model a station runs
  on modest always-on hardware — a Raspberry Pi at a community center, a shared
  node. That hardware can be confiscated, stolen, or coerced out of an operator.
  A phone in a member's pocket can be seized too, but only from that one person,
  and not silently for the whole community at once.
- **The station is a shared, multi-tenant service.** One station serves many
  members and replicates the ledger for a community. A design that put member
  keys on the station would concentrate every member's signing power in one box.
- **Offline use matters.** Members will act while their station is unreachable
  (mesh gaps, LoRa, the station is down). If producing a signature requires a
  round-trip to the station, the product stops working exactly when
  connectivity is worst.

The question this ADR settles: *who is the authoritative holder of a member's
keypair — the mobile client, or the station?*

## Decision

**The mobile client is the authoritative key-holder.** A member's keypair lives
on their mobile device; the mobile's keypair is what signs.

**The station is a local backend that mobile pairs with** for ledger
replication, peer gossip, and remote-of-record state. It is not the source of
identity — it is infrastructure the identity uses.

Concretely:

- **Many-to-many by design.** Multiple mobiles can pair with one station (a
  household, a community center kiosk serving several members). Multiple
  stations can each hold a replica of the same member's ledger state. Neither
  relationship is exclusive. What is singular is the *key*: the member's mobile
  keypair is the one authority that signs on their behalf.
- **Pairing is a one-time bond, not per-request authentication.** A mobile and a
  station pair once (the pairing protocol is specified in M1.3.3); thereafter
  the mobile authenticates individual requests with its own signature, rather
  than re-establishing trust on every call.

## Consequences

- **Crypto runs on mobile.** Because the mobile signs, the Rust cryptographic
  core (`rrn-crypto`, `rrn-identity`) must execute *on the device*. This directly
  constrains **M1.1**, which ships that Rust code to iOS and Android; the tool
  for doing so is decided in [ADR-0007](0007-rust-mobile-ffi-uniffi.md).
- **The station never sees a secret key.** It receives only signed payloads. A
  seized or compromised station therefore cannot forge any member's signature —
  it can withhold or corrupt replicated data (a availability/integrity concern
  handled by the log's hash-chaining and by replication), but it cannot *become*
  a member. Station compromise is not identity compromise.
- **The transport authenticates per request via the mobile's signature.** This
  constrains **M1.3**: the mobile–station transport is not a trusted channel
  where the station vouches for the caller; every request carries the mobile's
  signature and is verified against the paired identity.
- **Offline signing works.** Signatures are produced locally, so the member can
  act (propose transactions, sign attestations, cast votes) without the station
  online; those signed payloads replicate when connectivity returns.
- **Key loss is now a device problem.** Losing the phone risks losing the key,
  which raises the stakes on device-level protection (Keychain/Keystore, see the
  threat model's mobile section) and on the existing Shamir social-recovery path
  (`rrn-identity::recovery`, ADR-0004) as the recovery story for a lost device.

## Alternatives Considered

- **The station holds keys on the member's behalf.** Rejected. Physical seizure
  of one station would then be identity theft for *every* member it serves, and
  it contradicts the self-sovereign-identity commitment in design Section 6.3.
  It also makes station compromise equal to total identity compromise.
- **Mobile as a pure thin client with no local crypto.** Rejected. It requires
  the station to be online to produce any signature, degrading offline UX
  precisely in the low-connectivity conditions the project is built to survive,
  and it puts the signing key back on the station (see above).
- **Hardware-wallet integration** (keys on a dedicated external device).
  Rejected *for Phase 1* as scope creep — it adds a hardware dependency and a
  pairing surface we don't need to prove the model. Worth revisiting in Phase 2+
  as an optional enhancement for members who want it.

## References

- Design overview, Section 6.3 "Identity Wallet" — keys live with the member
- [ADR-0004](0004-own-shamir-implementation.md) — social recovery, the story for
  a lost key-holding device
- [ADR-0007](0007-rust-mobile-ffi-uniffi.md) — the FFI tool that gets the Rust
  crypto onto mobile, built directly on this decision
- M1.1 task spec — Rust crypto on mobile (constrained by this ADR)
- M1.3 task spec — mobile–station transport and pairing (constrained by this ADR)
