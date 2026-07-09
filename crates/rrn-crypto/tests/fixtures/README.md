# Test fixtures

## `cross_platform_sign.json` — mobile/station signing parity (T1.1.4)

Locks the Ed25519 signature for a set of `(seed, message)` pairs so the
**mobile** client and the **station** produce byte-identical signatures and
agree on which triples verify. `rrn_crypto::keypair` (Ed25519 via
`ed25519-dalek`, ADR-0001) *is* the source of truth; mobile reaches the same
code through the uniffi FFI (`rrn-mobile-ffi`) rather than reimplementing
Ed25519. Ed25519 signing is deterministic (RFC 8032 §5.1.6), so this is a hard
equality check, not merely "both verify".

Generated and verified by
[`tests/cross_platform_sign.rs`](../cross_platform_sign.rs); the mobile repo
commits a copy at `__tests__/fixtures/cross_platform_sign.json` and its
`sign.test.ts` reads it. Contents: 100 deterministic vectors (blake3-derived
seeds → keypairs signing messages of length 0..=32), 2 locked known-answer
vectors (all-zero and all-ones seed signing `"railroad network"`), and 3
tampered triples the verifier must reject (bit-flipped signature, wrong message,
wrong key).

Regenerate (reproducible bit-for-bit — no RNG):

```sh
RRN_REGEN=1 cargo test -p rrn-crypto --test cross_platform_sign
cp crates/rrn-crypto/tests/fixtures/cross_platform_sign.json \
   ../mobile/__tests__/fixtures/cross_platform_sign.json
```

The `committed_fixture_is_in_sync` test fails if the committed JSON drifts from
what the generator produces, so a stale fixture cannot pass CI unnoticed.
