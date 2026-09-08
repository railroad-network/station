# SMS Carrier Format

**Status:** current · **Task:** T2.7.1 (M2.7 SMS interface, Overview §10.3 "No
internet — SMS") · **Depends on:** the `rrnp:` chunk grammar (T2.5.1,
[`qr-payloads.md`](qr-payloads.md) §5) and DTN bundle ingest (ADR-0020,
[`dtn-bundles.md`](dtn-bundles.md))

This document locks how signed payloads travel over SMS, so the mobile app (which
composes the texts) and the station (which decodes and ingests them) stay
interoperable. It describes what ships **today** in T2.7.1: the wire codec, the
sender registry, and the station relay. The physical modem/gateway that carries the
texts is **T2.7.2**; the mobile app's SMS-composition UI is the mobile repo. Both
consume the format defined here.

## 1. What SMS is, in one line

SMS is a **carrier for already-signed payloads** — nothing more. A paired phone
encodes its DTN outbox into text chunks and texts them to the station's number; the
station decodes, ingests each carried bundle through the *same* front door every
other carrier uses (ADR-0020 §3), and texts the station-signed delivery receipt
back. Integrity and authenticity live in the per-record signatures inside the
carried bytes (ADR-0008/0013), never in SMS. This is the same posture as paper
(T2.5.x) and LoRa/Reticulum (T2.6.2): a dumb carrier on the degradation ladder.

**Not custody.** The feature-phone model — a human texting `PAY 5 TO ALICE` with the
station holding the member's keys — is deliberately **out of scope**: it would break
the keys-stay-with-members principle (ADR-0006). There is no command parser. See §7.

## 2. Wire grammar — shared with `rrnp:`

SMS carries the **exact** multi-part chunk grammar of the paper/QR path
([`qr-payloads.md`](qr-payloads.md) §5), byte for byte:

```
rrnp:<kind>/<payload_id8>/<index>/<count>/<data>
```

- `<kind>` — `b` bundle · `r` receipt · `s` spend voucher (one letter).
- `<payload_id8>` — first 8 base64url chars of the payload's Blake3 hash (a
  human-checkable grouping key, **not** an integrity proof).
- `<index>`/`<count>` — 1-based sheet number and total (canonical decimals, no
  leading zero), `count ≤ 64`.
- `<data>` — base64url (no padding) of this chunk's raw payload slice.

A receiver reassembles order-independently, deduplicates repeats, and refuses a
mis-collated set (the recomputed `payload_id8` must match). The reassembler is
**budget-agnostic** — it reads `count`/`index` off each chunk — so chunks produced
at the SMS budget (§3) and at the QR budget interoperate with the same code
(`rrn_protocol::paper::PaperReassembler`). The only difference between the SMS and
QR paths is **how many raw bytes go in one chunk** (§3); the emitted strings are the
same grammar.

### GSM-7 safety (audited)

The grammar emits only these characters: the literal `rrnp:`, the `/` separator, the
kind letters `b`/`r`/`s`, decimal digits, and the base64url alphabet
(`A–Z a–z 0–9 - _`). **Every one is in the GSM 03.38 basic character set** — a single
7-bit septet, no escape — including `_` (0x11) and `-` (0x2D), which the ticket
flagged for verification. So SMS needs **no** alphabet transcoding and no
SMS-specific variant of the grammar; a chunk string is sent as-is in GSM-7. This is
asserted by a test (`paper::tests::gsm7_alphabet_audit_*`) so a future grammar change
that introduced an extension-table character (`^ { } \ [ ] ~ |`, which cost two
septets) would fail the build.

## 3. The SMS chunk budget

A concatenated GSM-7 SMS carries **153 septets per part** (an 8-bit-reference
concatenation UDH consumes 7 of the 160, per 3GPP TS 23.040 §9.2.3.24); a single
non-concatenated SMS carries 160. One chunk rides in **one SMS message** of up to
`[sms] max_parts_per_message` concatenated parts (default **4**). The raw payload
budget is therefore:

```
data_chars = 153 × max_parts − MAX_CHUNK_HEADER_CHARS      (= 153×4 − 22 = 590 @ default)
budget_bytes = floor(data_chars × 3 / 4)                   (= 442 @ default)
```

`MAX_CHUNK_HEADER_CHARS = 22` is the worst-case header:
`rrnp:`(5) + kind(1) + `/`(1) + id8(8) + `/`(1) + index(≤2) + `/`(1) + count(≤2) +
`/`(1). base64url expands 3 bytes to 4 chars, so `floor(data_chars × 3/4)` is the
largest raw slice whose encoding still fits `data_chars`. Computed by
`rrn_protocol::paper::sms_chunk_budget_bytes(max_parts)` and pinned by a test.

The budget is clamped to `CHUNK_PAYLOAD_BYTES` (720, the reassembler's per-chunk
memory bound), so raising `max_parts` past ~6 stops increasing the chunk size. A
larger `max_parts` means fewer, longer messages (fewer per-message costs) at the
price of more parts lost if any one part drops.

| `max_parts` | message chars | chunk budget (bytes) |
|---|---|---|
| 1 | 153 | 98 |
| 4 (default) | 612 | 442 |
| 6 | 918 | 672 |
| ≥ 7 | — | 720 (clamped) |

## 4. Sender registry (`[sms] allowed_senders`)

The station maps phone numbers to identities with a member-signed record,
`rrn.net.sms_binding` (`rrn_protocol::binding`):

```
{ kind: "rrn.net.sms_binding", address: rrn1…, msisdn: "+…", bound_at: <unix secs> }
```

- **Self-signed:** the enclosing `SignedPayload`'s signer MUST be `address`'s key
  (`binding::validate_sms_binding`), so a member can only bind *their own* identity
  to a number. A later binding for the same identity supersedes an earlier one
  (`bound_at`); rebinding to a new number drops the old one from the registry.
- **`msisdn`** is validated E.164: `+` then 8–15 digits, leading digit non-zero
  (`binding::valid_msisdn`, the single source of truth the record and the station's
  `Msisdn` type share).
- **Admitted via the normal DTN path** — a member registers a number by sending the
  binding over *any* carrier; the station appends it to the log verbatim
  (`append_raw`) and derives the registry from the log on demand (a cache, never
  authoritative state — ADR-0020). Cross-platform wire fixture:
  `rrn-protocol/tests/fixtures/cross_platform_sms_binding.json`.

`allowed_senders` selects the inbound policy:

- **`"paired"`** (default) — process inbound texts only from numbers a current
  binding names. This is **spam control, not authentication** (§6): the signatures
  are the security boundary.
- **`"open"`** — process inbound from any number; still fully signature-gated at
  ingest. Useful before a community has registered numbers, or for a station that
  accepts drop-ins.

An inbound text from an unpaired sender (in `"paired"` mode) or beyond the per-sender
rate cap (`[sms] max_inbound_per_hour`, default 60, fixed 1-hour window) is dropped with a
**single rate-limited log line**, never one per text.

## 5. Part loss and retry

SMS has **no acknowledgement or retransmit protocol** of its own. The reliability
model is re-send driven, exactly like paper:

- A carrier may drop, duplicate, reorder, or **truncate** a concatenated message
  (losing a trailing part). A truncated chunk fails its base64/length check or, if it
  decodes, fails the reassembly hash — it is **refused**, never accepted as wrong
  bytes; the reassembler waits.
- The sender **re-sends** its outbox until the delivery receipt returns. A re-send
  need **not** be byte-identical: re-encoding an outbox produces a fresh
  `payload_id8` (the bundle's `assembled_at` is in the bytes), so the station relay
  treats the re-sent payload as a *new* one — it supersedes any stalled partial from
  that sender rather than colliding with it. The station **re-ingests idempotently**
  (a byte-identical presentation returns the cached receipt; already-admitted records
  answer `known` — ADR-0020 §3), and re-queues the same receipt, which the carrier
  eventually carries back intact.
- Outbound (station → member) is **paced money-first**: a strict-priority queue
  (economic before governance before bulk) drained through a per-message token
  bucket, so a delivery receipt never waits behind a bulk message on a
  per-message-cost carrier.

## 6. Security and privacy

- **A sender number is forgeable.** The registry is spam control; the security
  boundary is the per-record signature re-verified at ingest. A spoofed sender can at
  most re-carry someone's already-public signed bundle (idempotent, harmless) or junk
  (refused).
- **SMS is cleartext to the carrier.** The carrier sees the sender/recipient numbers,
  the timing, and the payload bytes. The payloads are already community-public signed
  records, so their *content* leaks nothing new — but the **metadata** (a number's
  association with a Railroad community and its activity pattern) is a real
  surveillance residual with no transport-layer fix. **SMS trades privacy for
  reach.** A community under surveillance pressure should route sensitive activity
  over LoRa (no carrier) or paper (no electronic trace) instead. This is the design
  overview's §13 sensitivity, stated factually. See the threat model, *SMS as a DTN
  carrier*.

## 7. Future (reserved, not implemented)

- **Feature-phone commands** (`PAY 5 TO ALICE`) — needs custodial keys on the
  station, which breaks ADR-0006. Out of scope pending a new ADR that resolves
  custody; **no command parser exists**.
- **Binary SMS / 8-bit (UDH) mode** — sending the raw payload bytes in an 8-bit data
  SMS (140 bytes/part) instead of base64url over GSM-7 would recover the ~33%
  base64url expansion. A possible future efficiency gain; not implemented (many
  gateways and handsets handle 8-bit data SMS poorly, and it would fork the wire
  grammar). Noted for T2.7.2's gateway evaluation.
