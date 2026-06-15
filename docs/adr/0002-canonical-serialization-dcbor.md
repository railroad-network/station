# 0002 — Canonical serialization via deterministic CBOR (`dcbor`)

## Status

Accepted

Date: 2026-06-15

## Context

Railroad Network is a signature-driven system: identities, vouches, ledger
transactions, and the append-only log are all signed values, and a signature
covers a *byte string*, not an abstract value. For two independent
implementations (or the same implementation on two platforms, two library
versions, or two struct field orderings) to agree on whether a signature is
valid, the value being signed must serialize to one — and only one — canonical
byte sequence. RFC 8949 §4.2.1 defines exactly such a canonical/deterministic
encoding for CBOR: map keys sorted by their bytewise encoding, integers in
shortest form, definite-length items only.

Two forces pull on the choice of how to achieve this:

1. **Audit surface.** `rrn-crypto` is the project's audit boundary (ADR-0001).
   Any code that decides canonical byte order sits in the most security-critical
   path in the system — a "forgot to sort here" bug is a consensus/forgery bug.
   We want as little of that logic written by us as possible.
2. **Interoperability.** Per the Repository Strategy, third-party
   implementations are expected eventually. A canonicalization defined by a
   published specification is something they can target; a canonicalization
   defined by *our wrapper around a general-purpose encoder* is something they
   would have to reverse-engineer.

A complication surfaced while implementing this task (M0.1, T0.1.3) that
invalidated an assumption baked into the original task spec: the spec sketched a
serde-based API (`to_canonical_bytes<T: Serialize>`), but **`dcbor` has no serde
integration** — it has its own CBOR data model and `From`/`TryFrom`
(`CBORCodable`) conversions. The serde assumption could not be satisfied by
`dcbor` as written. See "Alternatives" for how this reshaped the decision.

## Decision

1. Use **`dcbor`** (Blockchain Commons' Deterministic CBOR, `dcbor = "0.25"`),
   which implements RFC 8949 §4.2.1 **by construction** — there is no sorting or
   ordering layer to add, omit, or get wrong.
2. Use `dcbor`'s **native type model**, not serde. A value is canonically
   serializable iff it implements `Into<CBOR>` (encode) and `TryFrom<CBOR>`
   (decode). Each signed type provides a small, explicit `From<T> for CBOR` /
   `TryFrom<CBOR> for T` mapping.
3. Wrap `dcbor` behind `rrn_crypto::serialize`'s `to_canonical_bytes` /
   `from_canonical_bytes` so the dependency is swappable later without rippling
   through downstream crates. `to_canonical_bytes` is infallible (conversion to
   `CBOR` is total and canonical encoding cannot fail); `from_canonical_bytes`
   returns an error for non-canonical or mis-shaped input.
4. serde remains in use for **non-canonical** serialization only — JSON/CBOR
   wire envelopes, config, logs — e.g. the base64 string forms of `PublicKey`
   and `Signature`. The bytes that are *signed* never pass through serde. (The
   signature covers the payload's canonical CBOR, never the wire envelope.)

Floats: `dcbor` encodes floats deterministically (it canonicalizes NaN to
`f97e00` and reduces integral floats to integers), so floats are not a
canonicalization hazard. They are nonetheless **forbidden in signed
monetary/amount payloads** by project policy — amounts are integer centicommons,
never floats — to avoid precision ambiguity. This is enforced by review and by
types not exposing float fields, not by the encoder.

## Consequences

- **Canonical by construction, minimal audit surface.** We write no sorting,
  shortest-integer, or length-encoding logic; correctness of canonicalization is
  delegated to a single-purpose, spec-driven library. An auditor reviews the
  thin `serialize` wrapper plus each type's `From`/`TryFrom` mapping, not a
  bespoke encoder.
- **Spec-anchored interop.** "Canonical encoding" means "RFC 8949 §4.2.1 / the
  dCBOR specification," which a third-party implementation can target directly.
- **Cost: no `#[derive]` for signed types.** Because we do not use serde for
  canonical bytes, signed types hand-write their `CBOR` mappings instead of
  deriving them. This is more boilerplate, but it keeps each signed type's
  on-the-wire shape explicit and reviewable — appropriate for the values whose
  bytes are the thing being signed. Non-signed types are unaffected and may use
  serde freely.
- **Two serialization paths coexist** (serde for envelopes, `dcbor` for signed
  bytes). This is intentional and matches the rule "sign the canonical payload,
  not the envelope," but contributors must not confuse the two.
- **Downstream crates depend on `dcbor`'s type model**, transitively via
  `rrn-crypto`. The `serialize` wrapper limits the blast radius if we ever swap
  encoders, but type-level `From<T> for CBOR` impls would need revisiting.
- A transitive build-time dependency (`paste`, via `dcbor`) is unmaintained
  (RUSTSEC-2024-0436, an "unmaintained" notice, not a vulnerability); it is
  explicitly allow-listed in `deny.toml` with a documented rationale.

## Alternatives Considered

- **`dcbor` with a serde bridge** (the original task-spec assumption): not
  viable. `dcbor` has no serde support, and writing a serde `Serializer` that
  targets `dcbor`'s `CBOR` model would put a bespoke encoder back into the audit
  path — the very thing this decision avoids. Rejected; the native-trait model
  (above) was adopted instead, and the task's API signatures were updated to
  `T: Into<CBOR>` / `T: TryFrom<CBOR>`.
- **`ciborium` + a bespoke deterministic wrapper:** rejected. Adds bespoke
  encoder/sorting code in the audit path, introduces a class of "forgot to sort
  here" bugs, and forces third-party implementations to reverse-engineer our
  wrapper to interoperate.
- **`cbor4ii` with "deterministic mode":** rejected. Inspection of the current
  release (`cbor4ii` 1.2.2) found it has serde integration but **no canonical
  mode** — no map-key sorting at all. Using it for signing would require us to
  write the same bespoke canonicalization layer rejected for `ciborium`, with no
  offsetting benefit. Retained only as an emergency fallback if `dcbor` becomes
  untenable, and adopting it would require a new ADR superseding this one.
- **JSON canonicalization (RFC 8785):** rejected. Text-based, larger encoding,
  no efficiency win, and still requires a canonicalization pass.
- **Protobuf:** rejected. Not natively deterministic, and requires schema
  management infrastructure we do not otherwise need.
- **Hand-rolled fixed-layout binary format:** rejected for Phase 0. The most
  robust option in principle, but carries a high schema-evolution cost; revisit
  only if both `dcbor` and `cbor4ii` prove inadequate.

## References

- [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949) — CBOR, §4.2.1
  "Core Deterministic Encoding Requirements"
- dCBOR specification (Blockchain Commons) and the `dcbor` crate
  (<https://crates.io/crates/dcbor>)
- [ADR-0001](0001-rust-workspace-and-dual-license.md) — audit-boundary posture
- `CLAUDE.md` — Locked technical decisions table (canonical serialization:
  `dcbor`, fallback `cbor4ii`)
- `crates/rrn-crypto/src/serialize.rs` — the wrapper this ADR governs
- `docs/threat-model.md` — `rrn-crypto` (tampering / encoding determinism)
