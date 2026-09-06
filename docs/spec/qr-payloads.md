# QR Payload Formats

**Status:** current · **Tasks:** T1.4.2 (M1.4 Vouching Flow); §§5–7 added by
T2.5.1 (M2.5 paper fallback, ADR-0020)

This document locks the formats of the QR codes the Railroad Network apps render
and scan, so they stay stable and interoperable across the mobile app and the
station CLI. It describes what ships **today**; forward-looking forms are marked
**reserved** and are not yet implemented.

A QR code carries a text string. The scanner decodes the string; the app decides
what kind of payload it is by its shape (a bech32 `rrn1…` prefix, or a `rrn:` /
`rrnrecovery:` / `rrnp:` / `rrncert:` / `rrnspend:` scheme prefix) and parses
accordingly. An unrecognized string is rejected, not guessed at. The Rust
`rrn_protocol::paper::classify` is the one prefix-dispatch that routes every form
below to its parser.

---

## 1. Address

Used to receive a payment (the [Receive] screen) and as a **vouch target**: the
subject shows their address QR and the voucher scans it (M1.4).

### Canonical form — bare bech32

The address QR is the **bare bech32m address string**, exactly as rendered
elsewhere:

```
rrn18d4z00xwk6jz6c4r4rgz5mcdwdjny9thrh3y8f36cpy2rz6emg5scr4w0n
```

This is what the mobile app generates today (`Receive.tsx` renders the address
directly) and what `Send.tsx` scans. Generators SHOULD emit this form.

### Optional URI envelope

A generator MAY instead emit a URI envelope carrying the same address plus an
optional display **nickname**:

```
rrn:address?addr=<bech32>&n=<url-encoded nickname>
```

- `addr` (**required**) — the bech32m `rrn1…` address.
- `n` (optional) — a display-only nickname. URL-encoded (`%20` or `+` for spaces).
  Length-bounded to 200 characters; empty is treated as absent.

**Parsers MUST accept both forms.** The address is validated with the one Rust
bech32m implementation (reached via the mobile FFI, per ADR-0003); an invalid or
absent `addr` makes the whole payload invalid.

The **address is the identity**. The `n=` nickname is an untrusted display hint —
never use it for routing, matching, or trust decisions. In the vouch flow the
voucher enters/edits a nickname locally at review time regardless of what the QR
carried.

Mobile reference: `src/ledger/addressQr.ts` (`parseAddressQr` / `encodeAddressQr`).

---

## 2. Recovery shard

Used by social-recovery distribution: a member hands each holder one sealed shard
of their wallet secret, as a QR (M1.2.3).

### Form — `rrnrecovery:` prefix

```
rrnrecovery:<base64>
```

- `<base64>` — standard RFC-4648 base64 (with `=` padding) of the shard payload
  bytes. The payload is canonical CBOR of the **sealed** shard plus non-secret
  routing metadata, produced by the Rust FFI (`RecoveryPackage.shardPayload`).

The prefix disambiguates a shard QR from a plain address QR so a scanner rejects
the wrong kind of code rather than mis-parsing it.

**No secrets are exposed.** Each shard is sealed to its holder's public key, so a
captured QR is useless without that holder's secret key. Even so, shards are
handed out deliberately, not broadcast.

Mobile reference: `src/wallet/recoveryShard.ts` (`SHARD_QR_PREFIX`,
`encodeShardQr` / `decodeShardQr`).

**Note on the encoding alphabet.** This shard form uses standard RFC-4648 base64
(with `=` padding). The paper-fallback forms in §§5–7 below instead use
**base64url without padding** (RFC 4648 §5), so their strings are URL-safe and
carry no `/` that would collide with the §5 chunk-field separator. Both are
accepted; each form's section states which it uses.

---

## 3. Pairing — no QR (network + SAS)

Mobile↔station pairing does **not** use a QR code. It is a network handshake: the
mobile POSTs a signed pairing request to the station over the LAN, the operator
confirms on the station CLI, and both sides compare an 8-hex Short Authentication
String (SAS) derived from both static public keys (ADR-0008, T1.3.3). A headless
Pi cannot scan a QR, and one QR cannot carry both parties' keys — hence the
network+SAS design instead.

See `docs/adr/0008-mobile-station-transport.md` and the station `pairing.rs` /
`paired.rs` wire contract.

---

## 4. Reserved: the `rrn:` URL scheme

The `rrn:` URI scheme (used above only for the optional address envelope) is
**reserved** for future OS-level deep linking — tapping an `rrn:` link in another
app to open the mobile app at the right screen. The intended future routes are:

| URI                         | Opens                          | Status    |
| --------------------------- | ------------------------------ | --------- |
| `rrn:address?addr=…&n=…`    | receive / vouch target         | parsed (§1); not OS-registered |
| `rrn:pair?…`                | pairing                        | reserved  |
| `rrn:shard?…`               | recovery-shard receive         | reserved (ships today as `rrnrecovery:`, §2) |

OS URL-scheme registration (iOS `CFBundleURLTypes`, Android `intent-filter`) and
react-navigation deep-link routing are **deferred** — the in-person flows scan a
QR with the in-app camera and need only the parsers above, not URL registration.
Deep links will be added when they are both needed and verifiable end-to-end.

When a reserved form is implemented, update this document and prefer a `?…` query
envelope consistent with §1; keep the bare/base64 forms already shipped.

### Allocated scheme prefixes

The scanner routes by prefix, so every prefix is a reserved namespace. Allocated:

| Prefix          | Form                                | Status              |
| --------------- | ----------------------------------- | ------------------- |
| `rrn1…`         | bare bech32m address (§1)           | shipped             |
| `rrn:`          | address URI envelope / deep links   | §1 parsed; rest reserved |
| `rrnrecovery:`  | recovery shard (§2)                 | shipped             |
| `rrnp:`         | multi-part paper chunk (§5)         | implemented (T2.5.1) |
| `rrncert:`      | single-QR certificate (§6)          | implemented (T2.5.1) |
| `rrnspend:`     | spend voucher (§7)                  | implemented (T2.5.1) |

---

## 5. Multi-part paper payload — prefix `rrnp:`

Bundles (`rrn_protocol::bundle::Bundle`) and receipt envelopes
(`rrn_protocol::receipt::encode_signed`) exceed one QR's practical capacity, so
on paper they are split into ordered **paper chunks**, one per QR:

```
rrnp:<kind>/<payload_id8>/<index>/<count>/<data>
```

- `kind` — one letter: `b` (bundle) · `r` (receipt envelope) · `s` (spend
  voucher too large for a single §7 QR).
- `payload_id8` — the first **8 base64url characters** of `Blake3(payload)`. A
  human-checkable grouping key ("all sheets say `A6k9QzTw`"), **not** an
  integrity proof; the full hash is recomputed and checked on reassembly (below),
  and a caller holding an independently-known full id compares all 32 bytes by
  hashing the reassembled payload.
- `index` / `count` — decimal, **1-based** `index`, `count ≤ 64`.
- `data` — **base64url without padding** of that chunk's payload slice. The raw
  payload is split into slices of **720 bytes** in order (see the budget note); a
  decoder MUST refuse a `data` field longer than the base64url of 720 bytes (960
  characters) before decoding it, and MUST accept only canonical decimal `index`/
  `count` (ASCII digits, no sign, no leading zero) so encoders and decoders agree
  byte-for-byte.

**Chunk budget.** Each emitted string is kept at or under **1000 characters**
(well within a version-40 EC-M QR's ~2331-byte byte-mode capacity, and under the
1100-character conformance bound). Because base64url expands 3 bytes to 4
characters, a 720-byte slice is ≤ 960 characters of `data`, plus ≤ 22 characters
of prefix and header fields. The normative unit is the **≤ 1000-character emitted
string**; the 720-byte slice is derived from it.

**Reassembly.** The first chunk pins the payload's `kind`, `payload_id8`, and
`count`; a later chunk disagreeing on any of them is refused (sheets of two
payloads mixed together). A repeat of a chunk already held is idempotent; a
*different* body at a held `index` is refused. Completion requires every index
`1..=count` present **and** a full-hash match — `Blake3(concatenation)`'s first 8
base64url characters must equal the sheets' `payload_id8`; a mis-collated set is
refused and discarded so a clean re-scan can rebuild it. A `+`, `=`, or `/` in
`data` (standard-base64 artifacts) is rejected as a bad alphabet.

Rust reference: `rrn_protocol::paper` (`encode_chunks`, `PaperReassembler`).

---

## 6. Certificate — prefix `rrncert:`

A station-signed headroom certificate (ADR-0021) envelope is small and rides in a
single QR:

```
rrncert:<base64url of the signed certificate envelope>
```

The envelope is the portable `{signer, sig, body}` triple whose `body` is the
certificate's canonical dCBOR. base64url without padding; the decoder refuses a
body over the single-QR budget (740 bytes) as one that could never have fit a QR.
The certificate's station signature is verified by the receiver after decoding
(the mobile FFI's `certificate_parse` / `offline_spend_verify`), not by the codec.

Rust reference: `rrn_protocol::paper` (`encode_certificate`, `decode_certificate`).

---

## 7. Spend voucher — prefix `rrnspend:`

The offline point-of-sale form: one code the **payer** renders, the receiver
scans and verifies entirely offline (ADR-0021 §3, via the mobile FFI's
`offline_spend_verify` or the T2.5.2 CLI):

```
rrnspend:<base64url of a SpendVoucher CBOR container>
```

`SpendVoucher` is a **container, not a signed record** — canonical dCBOR of a
`{v, proposal, cert, history}` map:

- `v` — container version, `1`.
- `proposal` — the signed cert-backed `TransactionProposal` envelope bytes.
- `cert` — the signed `HeadroomCertificate` envelope bytes it is backed by.
- `history` — an array of the payer's presented cert-backed spend envelopes
  (bounded to 64 on decode).

These are exactly the inputs to `offline_spend_verify`; the codec treats each as
opaque bytes and the receiver's verifier checks the signatures inside. base64url
without padding. When the container exceeds the single-QR budget (a long history),
it is carried instead as §5 `rrnp:` chunks with `kind` letter `s` and reassembled
before decoding. A decoder tolerates unknown extra map keys (forward-compatible
within version `1`) but requires `v`, `proposal`, `cert`, and `history` present
and well-typed, and caps `history` at 64 entries.

Rust reference: `rrn_protocol::paper` (`SpendVoucher`, `encode_spend_voucher`,
`decode_spend_voucher`).

---

## Mobile reference (paper forms §§5–7)

To be implemented in the mobile repo — see the T2.4.2 / T2.5.1 handoff. The Rust
codecs in `rrn_protocol::paper` are canonical; the mobile parser must produce
byte-identical strings, verified against the committed vectors in
`crates/rrn-protocol/tests/fixtures/paper/` (`multipart_bundle.txt`,
`certificate.txt`, `spend_voucher.txt`).
