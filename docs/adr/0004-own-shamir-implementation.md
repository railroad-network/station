# 0004 — Own Shamir's Secret Sharing implementation over GF(256)

## Status

Accepted

Date: 2026-06-15

Supersedes the earlier (draft) plan to depend on `vsss-rs`, which had been
provisionally earmarked as ADR-0004 in earlier task drafts. This ADR replaces
that plan.

## Context

Social recovery (design overview Section 6.5) splits an identity's Ed25519
secret key into `N` shards held by distinct, trusted people; any `K` of them
can reconstruct the key, while any `K-1` learn nothing about it. The primitive
underneath that ritual is **Shamir's Secret Sharing** (Adi Shamir, *How to
Share a Secret*, 1979): represent the secret as the constant term of a random
degree-`K-1` polynomial over a finite field, hand each holder one evaluation
point, and recover the constant term by Lagrange interpolation.

The default engineering instinct — correctly — is **"don't roll your own
crypto."** The justification for that rule is that cryptographic code is
subtle, that bugs are silent and catastrophic, and that a widely-used library
has absorbed years of review and attack that your fresh code has not. We take
that rule seriously and this ADR exists to argue, explicitly, why this specific
primitive is the rare case where implementing it ourselves is the *more*
defensible choice — not to wave the rule away.

Two facts drive the decision:

1. **The project's posture is "audit the whole stack."** Per design overview
   Section 13.5 and milestone M0.7, an external security audit covers
   everything that touches key material, *including our dependencies*. There is
   no "trusted, unaudited" tier for code on the secret-key path. So the usual
   payoff of a third-party crate — "someone else's reviewed code you don't have
   to audit" — does not apply here: we audit it either way.

2. **The available Rust crates are not "battle-tested" in the sense the rule
   relies on.** They are small, have modest user bases, and would themselves
   require our audit. If we are going to audit a Shamir implementation
   regardless, auditing one we wrote — tailored to exactly our needs (32-byte
   secrets, GF(256), our error and zeroization conventions), with no unused
   surface — is a smaller and cleaner audit target than auditing a general
   library through a dependency we don't control.

## Decision

Implement Shamir's Secret Sharing **ourselves**, from scratch, in
`crates/rrn-identity/src/recovery/`, over **GF(256)** using the **Rijndael
(AES) field polynomial** `x^8 + x^4 + x^3 + x + 1` (`0x11b`). Estimated 300–500
LOC for the core split/reconstruct, plus substantially more in tests.

- `recovery/gf256.rs` — finite-field arithmetic: a `Gf256(u8)` element with
  `add`/`sub` (XOR), table-based `mul`, `inv`, `div`, `pow`. Built on precomputed
  log / antilog (`LOG`/`EXP`) tables.
- `recovery/shamir.rs` — `split_secret` (polynomial generation + Horner
  evaluation) and `reconstruct_secret` (Lagrange interpolation evaluated at
  `x = 0`).

We do byte-wise sharing: the 32-byte secret is split as 32 independent GF(256)
sharings, one per byte position, sharing the same set of `x` indices. A shard is
`(index: 1..=255, data: [u8; 32])`.

### Why this is defensible against the usual rule

- **Shamir is among the simplest cryptographic primitives.** It is polynomial
  evaluation and Lagrange interpolation over a finite field — first-course
  linear algebra, no exotic math, no novel construction. There is no "secret"
  specialist knowledge that a library author has and we lack.
- **No patents, no IP encumbrance.** The 1979 scheme is unencumbered; GF(256)
  arithmetic is the same field AES uses and is described in countless public
  references.
- **Multiple well-documented reference implementations exist to validate
  against** — SLIP-0039 (Trezor), academic implementations, and Trezor's Python
  `shamir-mnemonic`. We can check our output byte-for-byte against independent
  implementations (T0.4.5), which is *stronger* evidence of correctness than
  "many people use this crate."
- **The risk surface is small and well-bounded.** The things that can go wrong
  are enumerable: finite-field arithmetic correctness, constant-time discipline
  on secret-dependent operations, and correct CSPRNG usage. Each is directly
  addressable with deliberate code and exhaustive tests (the full 256×256
  multiplication table is testable; the field laws are property-testable).
- **An external audit (M0.7) covers this code regardless of provenance**, so we
  capture the tailoring benefit without giving up review.

### Standards followed

- Adi Shamir, "How to Share a Secret," *Communications of the ACM*, 1979.
- GF(256) with the Rijndael (AES) reduction polynomial
  `x^8 + x^4 + x^3 + x + 1` (`0x11b`), generator `0x03` — **the same field
  choice as SLIP-0039 (Trezor)**, specifically so our raw Shamir step can be
  cross-validated against SLIP-0039's published vectors and against
  `shamir-mnemonic`. Using a non-standard field would be a code smell and would
  forfeit that cross-validation.

### Cross-validation targets (consumed by T0.4.5)

The "did we roll our own correctly" test matches our output against at least two
independent published implementations:

1. **Hand-computed vectors** — a handful of small cases (K=2 N=2, K=2 N=3,
   K=3 N=5) worked out by hand / with a four-function GF(256) calculator, locked
   in as fixed `(secret, seed) → shards` expectations.
2. **SLIP-0039 reference vectors** —
   <https://github.com/satoshilabs/slips/blob/master/slip-0039.md>. We validate
   the *raw Shamir step* only, stripping SLIP-0039's wrapper layers (RS1024
   checksum, identifier/encoding, the encryption pass); full SLIP-0039
   compatibility is explicitly **not** a goal.
3. **Trezor `shamir-mnemonic`** (Python reference implementation) — used offline
   to pre-generate 50+ random `(secret, K, N) → shards` cases, committed as a
   JSON fixture so the Rust test has **no Python runtime dependency in CI**.

If our output ever differs from a reference for identical inputs (same field,
same polynomial, same coefficient derivation), that difference *is* the bug —
to be investigated, not papered over with "our convention differs."

## Consequences

- **We own a piece of cryptographic code on the secret-key path.** That is a
  real, permanent maintenance and review obligation, accepted deliberately.
- **Correctness is established by construction-independent tests, not by
  popularity.** The exhaustive multiplication table, the field-law property
  tests, the round-trip property tests, and the byte-for-byte cross-validation
  against SLIP-0039 and `shamir-mnemonic` are the evidence. This is a higher bar
  than most dependencies clear.
- **The audit surface is minimal and self-contained.** An auditor can read the
  whole implementation in one sitting; there is no transitive dependency on a
  general-purpose secret-sharing crate.
- **Constant-time discipline is our responsibility.** Field multiplication uses
  log/antilog table lookups; the *values* operated on are secret-dependent, so
  the residual cache-timing channel is acknowledged in the threat model
  (`rrn-identity::recovery::gf256`) and accepted under the local-execution
  deployment model (recovery runs on the user's own device, against their own
  shards — there is no co-resident remote attacker in the Phase 0 model).

### Risks accepted and their mitigations

| Risk | Mitigation |
|---|---|
| Implementation bug in field arithmetic or interpolation | Exhaustive 256×256 multiplication test against an independent reference multiply; field-law property tests; round-trip and reference-vector validation (T0.4.5) |
| Constant-time failure (secret-dependent branch) | Table-based multiplication with branchless (`subtle`) handling of the zero operand; no data-dependent branches in field ops; cache-timing channel acknowledged in the threat model |
| CSPRNG misuse (predictable coefficients) | Coefficients drawn from a `CryptoRng` supplied by the caller; index `0` forbidden as a share (it *is* the secret); coefficients zeroized after evaluation |
| Maintenance burden | Small LOC, no unused surface, single-file core |
| Audit findings | Expected; addressed before Phase 0 closure (M0.7) |

## Alternatives Considered

- **`vsss-rs`** — maintained, but a small user base and minimal code; it would
  still require our own audit, and its exposure is not large enough to constitute
  "battle-tested." Rejected: no audit saving, less tailored than our own.
- **`sharks`** — appears unmaintained. Rejected.
- **`libsodium`** — does not expose Shamir's Secret Sharing at the API level.
  Rejected: not applicable.
- **Hardware Security Modules** — incompatible with the offline-first design and
  the target hardware (Raspberry Pi 4 and smaller). Rejected.

## References

- Adi Shamir, "How to Share a Secret," *Comm. ACM* 22(11), 1979.
- [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) —
  Shamir-based mnemonic recovery (raw-Shamir step used for cross-validation).
- Trezor [`shamir-mnemonic`](https://github.com/trezor/python-shamir-mnemonic) —
  Python reference implementation used to generate fixtures.
- `crates/rrn-identity/src/recovery/` — the implementation this ADR governs.
- `docs/threat-model.md` — `rrn-identity::recovery` (own-implementation risk;
  GF(256) table-lookup cache-timing).
- `CLAUDE.md` — Locked technical decisions table (Shamir: own implementation
  over GF(256), Rijndael polynomial).
