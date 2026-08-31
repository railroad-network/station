# Test fixtures

## `cross_platform_dtn.json` — DTN wire parity (T2.2.1)

Locks the canonical dCBOR and Ed25519 signatures of the three ADR-0020
delay-tolerant-submission wire records, so the mobile repo can prove it produces
**byte-identical** encodings (ADR-0002). One fully-populated vector each:

- `outbox_entry` — a mid-chain `SignedPayload<OutboxEntry>` (position 3, real
  `prev_hash`) whose author, embedded record signer, and outer signer are one
  device key. Records the entry body `canonical_hex`, the device
  `entry_signature_hex`, and the derived `entry_hash` / `record_hash`.
- `bundle` — a `Bundle` carrying three entries from two authors (correctly
  ordered), with each `{signer, sig, body}` envelope's canonical bytes in
  `entry_envelopes_hex`, the whole bundle `canonical_hex`, and its `bundle_id`.
- `receipt` — a station-signed `DeliveryReceipt` with one admitted, one known,
  and one refused (`debt-floor`) outcome; records the receipt body
  `canonical_hex` and the station `signature_hex`.

Numeric values are decimal **strings** to survive the JSON hop into JavaScript's
doubles. Generated and verified by
[`tests/cross_platform_dtn.rs`](../cross_platform_dtn.rs); the
`committed_bytes_match_the_typed_encoders` test rebuilds every value from the
recorded seeds and fails on any encoding or field-order change. Deterministic
(blake3-derived seeds + RFC 8032 Ed25519), reproducible bit-for-bit. Regenerate:

```sh
RRN_REGEN=1 cargo test -p rrn-protocol --test cross_platform_dtn
# then copy crates/rrn-protocol/tests/fixtures/cross_platform_dtn.json into the
# mobile repo alongside the other cross_platform_* fixtures.
```
