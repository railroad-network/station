# 0007 — uniffi-rs generates the mobile bindings to our Rust crypto

## Status

Accepted

Date: 2026-07-04

## Context

[ADR-0006](0006-m1-client-architecture.md) decided that the mobile client is the
authoritative key-holder, which means our Rust cryptographic core (`rrn-crypto`,
`rrn-identity`) must run *on the device* — on both iOS (Swift) and Android
(Kotlin), reached from a React Native (TypeScript) app.

Getting Rust onto those platforms means crossing a foreign-function boundary,
and the boundary code is security-critical: it marshals keys, signatures, and
canonical bytes. Two properties matter most. First, **correctness** — a
hand-written JNI (Android) / JSI (iOS/RN) layer is error-prone exactly where we
can least afford errors. Second, **no drift** — hand-written bindings become a
second, parallel description of the API that silently diverges from the Rust
source every time the Rust changes, and each change is several manual edits
across two platforms. We want the bindings *generated* from a single contract so
they cannot drift, and we want a narrow, curated surface rather than a
mechanical export of every internal type.

## Decision

Use **`uniffi-rs`** (the Mozilla project, used in production in Firefox Sync and
related components) to generate Swift and Kotlin bindings to `rrn-crypto` and
`rrn-identity`, reached from React Native via a community wrapper.

- The uniffi interface definitions (the `.udl` files, or the equivalent proc-
  macro attributes) are **the contract**. Keep them small and stable.
- Expose a **curated, mobile-friendly API surface** — only the operations mobile
  actually needs (generate/load a wallet, sign a payload, derive an address,
  verify) — not every internal Rust type. A small surface is a small attack
  surface and a small maintenance surface.

## Consequences

- **One source of truth.** The Swift and Kotlin bindings are generated from the
  same interface, so they cannot silently diverge from each other or from the
  Rust; an API change regenerates both.
- **Less hand-written unsafe glue.** The error-prone JNI/JSI marshalling is
  generated and exercised by Mozilla's production users, rather than being
  bespoke to us.
- **Accepted risk: React Native support is the weak spot.** uniffi's first-class
  targets are Swift and Kotlin; React Native is reached through the community
  `react-native-uniffi` wrapper, which is less battle-tested than the core.
  **Mitigation:** keep the FFI surface narrow (fewer operations = fewer places
  the wrapper can fail), and **fall back to a hand-written JSI binding for any
  single operation that does not go cleanly through uniffi.** The decision is
  "uniffi by default," not "uniffi for everything at any cost."
- **A stable contract to hold the line on.** Because the `.udl` is the contract,
  API review for the mobile surface happens in one small, reviewable place.

## Alternatives Considered

- **`flutter_rust_bridge`.** Rejected: it is Flutter-oriented and would push us
  toward Flutter, conflicting with the React Native choice for the mobile app.
- **Hand-written JSI bindings (no generator).** Rejected: very high maintenance
  cost — every API change is multiple manual edits across platforms — and it is
  the error-prone, drift-prone path this ADR exists to avoid. Retained only as
  the per-operation *fallback* above.
- **WebAssembly-compiled Rust.** Rejected: viable, but it adds a heavy runtime,
  mobile JS engines vary in how well they run WASM, and its performance is worse
  than native for the crypto operations we care about.
- **`cargo-mobile` + manual glue.** Rejected: it still leaves us writing more
  per-surface glue code than uniffi generates for us.

## References

- [ADR-0006](0006-m1-client-architecture.md) — decided crypto runs on mobile,
  which is what created the need for a binding generator
- uniffi-rs (Mozilla) — used in Firefox Sync and other production code
- M1.1 task spec — the actual FFI implementation (this ADR only fixes the tool)
