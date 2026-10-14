# Ceremony fingerprint (ADR-0016, ADR-0024)

Every key-recovery ceremony runs the same way: the requester mints an ephemeral
recovery keypair, publishes a `rrnrecover-req:` request (a `RecoveryRequest`,
`rrn_identity::recovery::ceremony`), and collects holders' `rrnrecover-resp:`
responses sealed to that key. The request is unsigned, so before responding a
holder confirms a **ceremony fingerprint** with the requester: a 16-character
code that the requester's screen and the holder's screen each derive from the
request. A forged request — a different ephemeral key, or a different target —
shows a different code.

This document pins the one algorithm that every ceremony uses, so the station,
the `rrn wallet` CLI, and the phone agree byte-for-byte:

| Ceremony | Requester shows the code | Holder's device shows the code |
|---|---|---|
| Member key recovery on a laptop | `rrn wallet recover` | the app's "help recover" screen (`parse_recovery_request`) |
| Member key recovery on a phone | `RecoverySession.fingerprint()` (mobile FFI) | the same |
| Station key recovery | `station recovery restore` | the same |
| Encrypted-profile unlock and VMK re-split | `station unlock`, `station vmk refresh` (the console) | the same |

All of them call `rrn_identity::recovery::ceremony::fingerprint`. The phone
reaches it through the mobile FFI and never re-implements it. No ceremony may
show a code from any other algorithm (ADR-0024's 2026-10-14 Clarification).

## Inputs

The `RecoveryRequest`, decoded from the scanned or pasted
`rrnrecover-req:<base64>` payload:

- `rk` — the ephemeral Ed25519 recovery public key, 32 bytes.
- `addr` — the target identity (a member's address, the station's address, or
  the VMK's address), as the 32-byte Ed25519 public key behind its `rrn1…`
  string.

`request_bytes` is the request's canonical dCBOR encoding
(`RecoveryRequest::to_bytes`, ADR-0002): a two-entry map, keys in canonical
order. For the current two fields that is 77 bytes:

```
a2                      map, 2 entries
  62 72 6b              "rk"
  58 20 <32 bytes>      byte string: recovery public key
  64 61 64 64 72        "addr"
  58 20 <32 bytes>      byte string: target public key
```

The holder hashes the canonical re-encoding of the request it decoded, not the
received bytes as they arrived. Decoding enforces canonical form, so for any
request a holder accepts, the two are equal to the requester's bytes.

## Algorithm

1. `digest = BLAKE3("rrn.ceremony.fingerprint.v2" ‖ request_bytes)`, a 32-byte
   output. The tag is ASCII with no terminator.
2. `code = render(digest, 16, 4)` with the shared human-code renderer
   (`rrn_identity::human_code`, also used by pairing — `docs/spec/pairing.md`):
   - **Alphabet** (Crockford base32): `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
   - Read the digest as a big-endian bit string; take the first **80 bits**
     (the first 10 bytes); map each 5-bit group, most significant first, to the
     alphabet.
   - Insert `-` after every 4 characters except at the end:
     `XXXX-XXXX-XXXX-XXXX` (19 characters displayed).
3. **Comparison.** When a person types a code back, normalize both sides before
   comparing: uppercase; drop `-` and whitespace; map `O` → `0`, and `I` and
   `L` → `1`.

The code binds both fields: the same recovery key with a different target gives
a different code. Finding a fresh ephemeral key whose request collides with a
genuine one on 80 bits costs about 2^80 hash evaluations.

## Procedure

A holder responds only after confirming that all sixteen characters on their
screen equal the requester's (ADR-0016's 2026-10-14 Clarification):

- **In person:** scan the request from the requester's own screen or console
  and compare the codes side by side.
- **Relayed:** when the request arrives by message, read all four groups back
  to the requester over a voice channel you already trust to reach them (a
  number you already had, a voice you know). A code that arrives in the same
  message as the request proves nothing.

A holder whose app shows a shorter code (the earlier ten-character fingerprint)
must update the app before responding. That code never matches a current
requester's, and declining is the right response to any mismatch.

## Test vectors

The cross-platform fixture
`crates/rrn-mobile-ffi/tests/fixtures/recovery_fingerprint.json` carries
member vectors, a vector that shares a recovery key with a different target
(and so a different code), and the vector below. The mobile repo copies the
fixture byte-for-byte and asserts the code its screens display.

| input | value |
| --- | --- |
| recovery key | Ed25519 public key derived from the 32-byte seed `01 01 … 01`: `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| target | the address of the Ed25519 public key derived from the seed `02 02 … 02` (a VMK address): `rrn1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2qtx73gq` |
| `request_bytes` | `a262726b58208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c646164647258208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| **fingerprint** | `E26N-ZE0W-1TX8-Z4KF` |

This vector is the fixture's `vmk-spec-vector`, and `rrn-station`'s
`vmk::tests::fingerprint_pinned_spec_vector` asserts it.
