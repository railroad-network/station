# Mobile↔station pairing, version 2 (ADR-0008)

Pairing is the one-time, in-person bond between a member device (the phone or
an `rrn wallet`) and the community station. It binds the two static Ed25519
keys and nothing else ([ADR-0008](../adr/0008-mobile-station-transport.md)),
and it is also the enrollment ceremony
([ADR-0038 §1](../adr/0038-enrollment-and-standing-accrual.md)). This document
pins the version-2 handshake that ADR-0008's 2026-10-14 Clarification, Part A,
describes: the routes, the JSON bodies, the exact signed byte layouts, how the
confirmation code is rendered, and the error strings. The station
(`rrn_identity::pairing`, `rrn_station::pairing`) and the phone (through the
`rrn-mobile-ffi` pairing functions) must agree byte-for-byte.

Version 1 (`POST /pair`, a single signed request with an 8-hex code over the
two static keys) is retired; see [Retired: version 1](#retired-version-1).

## Overview

```
mobile                                               station
  mobile_nonce ← 32 random bytes
  commitment = H_commit(mobile_pk, mobile_nonce)
  POST /pair/start {commitment, requested_at, sig_M(start)}  ──►
                                                     check sig, clock skew
                                                     station_nonce ← 32 random bytes
                                                     hold AwaitingReveal
  ◄──  200 {station_address, station_nonce, sig_S(offer)}
  check station_address, then sig_S(offer)
  POST /pair/finish {station_address, mobile_nonce, sig_M(finish)} ──►
                                                     check station, sig, commitment opens
                                                     code = H_code(...); hold AwaitingOperator
  ◄──  200 {"status":"awaiting-operator"}
  code = H_code(...) — shown on the device

operator reads the code from the device and runs
  station pair-mobile <mobile_address> --code <code>  → station compares, pairs, enrolls
```

The station never sends the code. The device shows it; the station lists it
for its operator; the operator types the device's code, and the station
confirms only if it equals its own.

## Byte layouts

All values are raw bytes; `‖` is concatenation. Tags are ASCII with no
terminator. `mobile_pk` and `station_pk` are 32-byte Ed25519 public keys (the
key behind each `rrn1…` address). Nonces are 32 bytes. `requested_at` is an
`i64` Unix-seconds value, 8 bytes big-endian (two's complement). `H` is
BLAKE3 with a 32-byte output.

| Name | Bytes | Signed by |
|---|---|---|
| commitment | `H("rrn-pair-commit-v2" ‖ mobile_pk ‖ mobile_nonce)` | — |
| start | `"rrn-pair-start-v2" ‖ mobile_pk ‖ commitment ‖ requested_at` | mobile |
| offer | `"rrn-pair-offer-v2" ‖ station_pk ‖ mobile_pk ‖ commitment ‖ station_nonce` | station |
| finish | `"rrn-pair-finish-v2" ‖ station_pk ‖ mobile_pk ‖ commitment ‖ station_nonce ‖ mobile_nonce` | mobile |
| code digest | `H("rrn-pair-code-v2" ‖ station_pk ‖ mobile_pk ‖ mobile_nonce ‖ station_nonce)` | — |

Signatures are Ed25519 over exactly these bytes (verified with
`verify_strict`). These are fixed concatenations, not canonical dCBOR:
pairing is the bootstrap that establishes the keys the sealed channel later
relies on, and a fixed layout is the easiest thing to make identical on two
platforms.

The start names no station: a phone that reached the station by a typed IP
address does not know its key yet. The finish is the station-bound request.

## The confirmation code

`code = render(code digest, 10, 5)`, using the shared human-code renderer
(`rrn_identity::human_code`):

- **Alphabet** (Crockford base32): `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
- **render(digest, chars, group):** read the digest as a big-endian bit string,
  take the first `chars × 5` bits (at most 51 characters), and map each 5-bit
  group, most significant first, to the alphabet. Insert `-` after every `group`
  characters except at the end. For the pairing code: 50 bits from the first 7
  digest bytes, rendered `XXXXX-XXXXX`.
- **normalize(input):** uppercase; drop `-` and whitespace; map `O` → `0`,
  `I` and `L` → `1`. Two codes match when their normalized forms are equal.
  The operator's typed code is normalized before comparison; the station's
  own code is already in normal form apart from the hyphen.

An online attacker who substitutes a key on either side matches the genuine
code with probability 2^-50 per operator-confirmed attempt: each side's nonce
is fixed before it sees the other's, so neither the station's nor the mobile's
contribution can be chosen to steer the digest.

## Routes

Both routes take and return `application/json`, under the mobile server's
small default body limit. Hex fields are lowercase or uppercase hex of the
exact byte length shown; any other length or a non-hex character is
malformed.

### `POST /pair/start`

Request:

```json
{
  "v": 2,
  "mobile_address": "rrn1…",
  "commitment": "<hex, 32 bytes>",
  "requested_at": 1760400000,
  "signature": "<hex, 64 bytes: Ed25519 over the start layout>"
}
```

The station checks, in order: the version; the address parses; the
commitment and signature are well formed; the signature verifies against the
key behind `mobile_address`; `requested_at` is within 300 seconds of the
station clock (either direction).

`200` response:

```json
{
  "station_address": "rrn1…",
  "station_nonce": "<hex, 32 bytes>",
  "signature": "<hex, 64 bytes: Ed25519 over the offer layout>"
}
```

The client checks `station_address` against the station it expected (a
pinned key; a discovery claim when it has one) **before** verifying the
signature against the key behind that address, so a wrong station gives a
precise "not the station you expected" error. A phone that has no
expectation (it reached the station by typed IP) takes the key from the offer;
the code comparison is what authenticates it.

### `POST /pair/finish`

Request:

```json
{
  "v": 2,
  "mobile_address": "rrn1…",
  "station_address": "rrn1…",
  "mobile_nonce": "<hex, 32 bytes>",
  "signature": "<hex, 64 bytes: Ed25519 over the finish layout>"
}
```

The station checks, in order: the version; the address parses; the fields
are well formed; `station_address` is its own; a session for
`mobile_address` is awaiting its reveal; the signature verifies over the
finish layout (built from the station's own key, the session's commitment and
station nonce, and the revealed mobile nonce); the mobile nonce opens the
commitment. Then it computes the code and moves the session to awaiting the
operator.

`200` response: `{"status": "awaiting-operator"}`. It is not signed: the
human comparison is the check, and the station never sends the code.

### `POST /pair` (retired)

Always `410 Gone`, body `pairing protocol v1 is retired; update the app`.

## Station session state

The station holds pending sessions in memory only, keyed by mobile address:

- **AwaitingReveal** `{mobile_pk, commitment, station_nonce}` — after a start.
- **AwaitingOperator** `{code}` — after a valid finish.

Each session expires 300 seconds after it entered its current stage (the
reveal resets the clock). A new start for an address replaces that address's
session, except when its commitment equals the current one: a session still
awaiting its reveal answers with the same offer (a retried start is
idempotent), and a session awaiting the operator refuses it as a replay and
is kept. The operator's pending list (`station pair-mobile` with no address)
shows only sessions awaiting the operator, as address, code, and age.

The operator confirms with `station pair-mobile <address> --code <code>`
(RPC `pair_confirm {address, code}`). A normalized match pairs the device and,
on a writer, enrolls the member (ADR-0038 §1). A mismatch is refused with
`the code does not match the pending request from <address>; compare again`
and the session stays in place.

Pairings already confirmed are untouched by any of this: a paired device
authenticates on `/rpc` and `/subscribe` exactly as before.

## Errors

A refused request answers with an HTTP status and a short plain-text body,
which a client may show to the user.

| Body | Status | When |
|---|---|---|
| `unsupported pairing version` | 400 | `v` is not 2 |
| `invalid mobile address` | 400 | `mobile_address` is not a bech32 `rrn1…` identity address |
| `invalid nonce or commitment` | 400 | `commitment`, `mobile_nonce`, or `station_nonce` is not 32 hex-encoded bytes |
| `malformed signature` | 400 | `signature` is not 64 hex-encoded bytes, or not a valid Ed25519 signature encoding |
| `signature does not verify` | 400 | the signature does not verify over the layout |
| `requested_at outside allowed clock skew` | 400 | start only: more than 300 s from the station clock |
| `request names a different station` | 400 | finish only: `station_address` is not this station |
| `no pairing in progress for this address; start again` | 400 | finish only: no session awaiting a reveal (never started, expired, or already revealed) |
| `revealed nonce does not open the commitment` | 400 | finish only |
| `pairing request already used` | 400 | start only: same commitment as a session already awaiting the operator |
| `pairing protocol v1 is retired; update the app` | 410 | `POST /pair` |
| `station unavailable` | 503 | the station is shutting down |

## Fixtures

The cross-platform fixture is
`crates/rrn-identity/tests/fixtures/cross_platform_pairing_v2.json`,
generated by `crates/rrn-identity/tests/it/cross_platform_pairing_v2.rs` with
`RRN_REGEN=1` from BLAKE3-derived seeds and nonces. It holds one full
handshake (seeds, public keys, addresses, nonces, commitment, all three signed
byte strings and their signatures, the code), code vectors including the case
with the two keys swapped, and start-layout vectors with `requested_at` ∈
{0, 1, −1, 2^53−1}. The phone copies it byte-for-byte to
`__tests__/fixtures/cross_platform_pairing_v2.json`; see
`crates/rrn-identity/tests/fixtures/README.md`.

The phone does not re-implement the layouts or the renderer. `rrn-mobile-ffi`
exposes `pairing_nonce`, `pairing_commitment`, `pairing_start_signed_bytes`,
`pairing_offer_signed_bytes`, `pairing_finish_signed_bytes`, and
`pairing_code`, each a thin wrapper over `rrn_identity::pairing` that refuses
a wrong-length input with `CryptoError::WrongLength`.

## Retired: version 1

Version 1 was a single round: the mobile signed
`"rrn-pair-req-v1" ‖ mobile_pk ‖ token ‖ requested_at`, the station answered
with a signature over `"rrn-pair-resp-v1" ‖ station_pk ‖ token`, and both
sides showed the first eight hex characters of
`H("rrn-pair-sas-v1" ‖ station_pk ‖ mobile_pk)`. With 32 bits over static
keys and no commitment, a party on the pairing LAN could search keys offline
for a colliding code (security review finding RRN-A-023). It has no
compatibility window: if it still worked, an attacker would use it.
