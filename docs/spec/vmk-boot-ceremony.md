# VMK boot-ceremony console fingerprint (ADR-0024)

The encrypted at-rest profile unlocks its container with a **wallet-free boot
ceremony**: the station mints an ephemeral recovery keypair, publishes a
`rrnrecover-req:` request, and collects holders' `rrnrecover-resp:` shares. Because
no station keypair exists before unlock, the request is unsigned — so the only thing
authenticating the ceremony to a holder is a short **console fingerprint** the
operator reads aloud and the holder confirms out-of-band before responding. A seizer
who imaged the boot dir and minted their own ephemeral key would show a *different*
fingerprint, which the holder would catch.

For this to work, a holder's app must compute the **same** fingerprint from the
request it scans. This document pins the algorithm so the station
(`rrn_station::storage::vmk::ceremony_fingerprint`) and the mobile client agree
byte-for-byte.

## Inputs

Both are recovered from the scanned `rrnrecover-req:<base64>` payload (a
`RecoveryRequest`, see `rrn_identity::recovery::ceremony`):

- `recovery_pubkey` — the ephemeral Ed25519 public key, 32 raw bytes.
- `target_address` — the VMK's `rrn1…` address; its underlying Ed25519 public key is
  32 raw bytes.

## Algorithm

1. Concatenate the two 32-byte public keys, in order: `recovery_pubkey ‖ vmk_pubkey`
   (64 bytes total).
2. Hash with BLAKE3 (the workspace hash, `rrn_crypto::hash::Hash::of`) → a 32-byte
   digest.
3. Take the first **10** digest bytes. For each byte `b`, emit
   `ALPHABET[b % 32]` where
   `ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"` (RFC 4648 base32, uppercase).
4. Format as two groups of five: `XXXXX-XXXXX`.

## Test vector

| input | value |
| --- | --- |
| `recovery_pubkey` | Ed25519 public key derived from the 32-byte seed `01 01 … 01` |
| `vmk_pubkey` | Ed25519 public key derived from the 32-byte seed `02 02 … 02` |
| **fingerprint** | `B523J-DY6LH` |

This vector is asserted in `rrn-station`'s `vmk::tests::fingerprint_pinned_test_vector`.
The mobile client must reproduce it before the fingerprint check can be relied on;
until it does, the mitigation is only as strong as an operator reading the string and
a holder eyeballing it against a station display.
