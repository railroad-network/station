# Test fixtures

## `cross_platform_signed_payload.json` — mobile/station signed-proposal parity (T1.1.7)

Locks the milestone's load-bearing claim: a `SignedPayload<TransactionProposal>`
signed on **mobile** and the same proposal signed on the **station** produce
byte-identical signatures, because both sign the same canonical dCBOR (ADR-0002).
`TransactionProposal`'s canonical form carries **byte-string** fields
(`sender`/`receiver` are `Address::to_byte_string`) and 64-bit integers, so this
is the vector that exercises the parts of the mobile tagged-value model plain JSON
could not carry.

Each vector records the proposal fields (numeric values as decimal **strings**,
to survive the JSON hop into JavaScript's doubles), the `payload` the mobile app
builds, the `canonical_hex` (== `From<TransactionProposal> for CBOR`), and the
`signature_hex`. The generator asserts, at build time, that the mobile
`canonical_bytes` FFI turns `payload` into exactly `canonical_hex` — so the two
encoders are proven equal, not assumed. The generic dCBOR type-surface vectors
live in `rrn-mobile-ffi` (`cross_platform_canonical.json`).

Generated and verified by
[`tests/cross_platform_signed_payload.rs`](../cross_platform_signed_payload.rs)
(dev-depends on `rrn-mobile-ffi` to drive the real FFI); the mobile repo commits a
copy at `__tests__/fixtures/cross_platform_signed_payload.json` and its
`SignedPayload.test.ts` reads it. Deterministic (blake3 seeds + RFC 8032 Ed25519),
reproducible bit-for-bit. Regenerate:

```sh
RRN_REGEN=1 cargo test -p rrn-ledger --test cross_platform_signed_payload
cp crates/rrn-ledger/tests/fixtures/cross_platform_signed_payload.json \
   ../mobile/__tests__/fixtures/cross_platform_signed_payload.json
```
