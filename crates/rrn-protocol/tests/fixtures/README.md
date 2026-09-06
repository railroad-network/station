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

## `paper/*.txt` — paper/QR text-encoding vectors (T2.5.1)

Exact emitted QR strings (one per line) for the paper-fallback forms of
`docs/spec/qr-payloads.md` §§5–7, so the mobile repo's paper parser can verify
byte-identical output. A paper payload is opaque bytes to the encoding layer, so
these are built from fully-specified deterministic input bytes — no signing
needed — documented in `tests/paper_qr.rs`:

- `multipart_bundle.txt` — a 1500-byte bundle payload (`b[i] = (i·31 + 7) mod
  256`) split into three `rrnp:b/<id8>/<i>/3/<base64url>` chunks.
- `certificate.txt` — a 300-byte certificate envelope (`b[i] = (i·17 + 3) mod
  256`) as one `rrncert:<base64url>` string.
- `spend_voucher.txt` — a `SpendVoucher` (120-byte proposal, 90-byte cert, one
  80-byte history entry) as one `rrnspend:<base64url>` string.
- `voucher_multipart.txt` — a larger `SpendVoucher` (300-byte proposal, 285-byte
  cert, six 300-byte history entries) that overflows the single-QR budget and so
  rides as `rrnp:s/<id8>/<i>/<n>/<base64url>` chunks — the kind-`s` route.

Generated and verified by [`tests/paper_qr.rs`](../paper_qr.rs), which also
reassembles/decodes each vector back to its input. Regenerate:

```sh
RRN_REGEN=1 cargo test -p rrn-protocol --test paper_qr
# then copy crates/rrn-protocol/tests/fixtures/paper/ into the mobile repo.
```
