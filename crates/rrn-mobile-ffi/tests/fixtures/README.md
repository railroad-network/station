# Test fixtures

## `cross_platform_canonical.json` — canonical-CBOR type model

Locks the mobile **tagged-value model** → canonical dCBOR mapping so the mobile
`canonical_bytes` FFI and the station agree byte-for-byte across the whole dCBOR
type surface (text, byte strings, i64/u64 integers, bool, null, arrays, maps),
and so floats and malformed nodes are rejected with clean, named errors.
`rrn_crypto::serialize` (dCBOR, ADR-0002) *is* the source of truth; mobile
reaches the same encoder through `canonical_bytes` rather than carrying its own.

Generated and verified by
[`tests/it/cross_platform_canonical.rs`](../it/cross_platform_canonical.rs); the mobile
repo commits a copy at `__tests__/fixtures/cross_platform_canonical.json` and its
`cbor.test.ts` reads it. Contents: `vectors` (each a tagged `payload` and the
`canonical_hex` it must encode to) and `invalid` (payloads that must raise a named
`PayloadError`). The `SignedPayload<TransactionProposal>` end-to-end vector lives
in `rrn-ledger` (it needs the ledger's proposal type).

Reproducible bit-for-bit (no RNG). Regenerate:

```sh
RRN_REGEN=1 cargo test -p rrn-mobile-ffi --test it cross_platform_canonical
cp crates/rrn-mobile-ffi/tests/fixtures/cross_platform_canonical.json \
   ../mobile/__tests__/fixtures/cross_platform_canonical.json
```

The `committed_fixture_is_in_sync` test fails if the committed JSON drifts from
what the generator produces, so a stale fixture cannot pass CI unnoticed.

## `cross_platform_dtn_certs.json` — DTN + certificate FFI

Locks the wire bytes for every new envelope the mobile app encodes or decodes
through the delay-tolerant-submission and escrowed-offline-spending FFI surface
(ADR-0020 / ADR-0021): an outbox entry envelope and the bundle they assemble
into, a station delivery receipt envelope, a certificate request, a
station-signed certificate, a cert-backed proposal, and three
`offline_spend_verify` scenarios (good spend, overspend, expired certificate).
Every `*_envelope_hex` / `bundle_hex` is the portable `{signer, sig, body}`
canonical dCBOR triple; `rrn_crypto::serialize` (ADR-0002) is the source of
truth, reached through the FFI rather than reimplemented on mobile.

Generated and verified by
[`tests/it/cross_platform_dtn_certs.rs`](../it/cross_platform_dtn_certs.rs), which
drives the FFI **decode/verify** functions (`bundle_parse`, `receipt_parse`,
`certificate_parse`, `offline_spend_verify`) over the recorded bytes. The
producer functions (`outbox_next_entry`, `certificate_request_sign`,
`proposal_sign_with_certificate`) are covered by the in-crate round-trip tests;
their byte-identity follows because every consumer re-encodes and re-verifies the
decoded payload, so a non-canonical body could not verify. The mobile repo
commits a copy at `__tests__/fixtures/cross_platform_dtn_certs.json`.
Reproducible bit-for-bit (blake3 seeds, RFC 8032). Regenerate:

```sh
RRN_REGEN=1 cargo test -p rrn-mobile-ffi --test it cross_platform_dtn_certs
cp crates/rrn-mobile-ffi/tests/fixtures/cross_platform_dtn_certs.json \
   ../mobile/__tests__/fixtures/cross_platform_dtn_certs.json
```

## `recovery_fingerprint.json` — recovery ceremony fingerprint (ADR-0016)

Locks the human-comparable **ceremony fingerprint** (`xxxxx-xxxxx`) the app
displays when rebuilding a lost key, and every holder confirms out-of-band before
contributing a share. Each vector is a fixed ephemeral recovery public key and
the fingerprint it must render to; `rrn_identity::recovery::ceremony::fingerprint`
(the first ten hex chars of `blake3("rrn.recovery.fingerprint" ‖ recovery pubkey)`)
is the source of truth, reached on mobile through `parse_recovery_request` and
`RecoverySession.fingerprint()`. If the two platforms rendered different codes,
the out-of-band check would be worthless, so the mobile repo asserts its displayed
code against this table.

Generated and verified by
[`tests/it/recovery_ceremony.rs`](../it/recovery_ceremony.rs). Reproducible
bit-for-bit (blake3 seeds). Regenerate:

```sh
RRN_REGEN=1 cargo test -p rrn-mobile-ffi --test it recovery_ceremony
cp crates/rrn-mobile-ffi/tests/fixtures/recovery_fingerprint.json \
   ../mobile/__tests__/fixtures/recovery_fingerprint.json
```
