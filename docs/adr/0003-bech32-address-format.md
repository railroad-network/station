# 0003 — Human-readable address format: bech32m with HRP `rrn`

## Status

Accepted

Date: 2026-06-15

## Context

A Railroad Network identity is an Ed25519 public key — 32 raw bytes. But those
bytes are shown to humans constantly: in CLI output, error messages, log lines,
on-screen "send to this address" prompts, and eventually QR codes and
read-aloud-over-radio fallbacks. A raw-byte or hex rendering has two practical
failure modes in those settings:

1. **No error detection.** Hex has no checksum. A user who mistypes or
   mis-transcribes one character of a hex address gets a *different, equally
   valid-looking* 32-byte value — which, if it happens to be a real key, sends
   value to the wrong identity with no warning. In a mutual-credit system where
   addresses are exchanged informally, this is a real hazard.
2. **No recognizable shape.** Hex addresses are not visually distinguishable
   from any other hex blob (hashes, signatures, nonces all look alike), so users
   cannot tell at a glance that a string is "an address for *this* network."

We want an address encoding that is checksummed, has a recognizable
network-specific prefix, and is friendly to the channels addresses travel
through (case-insensitive, QR-efficient, unambiguous alphabet).

## Decision

Encode addresses as **bech32m** with the human-readable part (HRP) **`rrn`**, so
addresses read as `rrn1…` (the `1` is bech32's fixed HRP/data separator). The
payload is the 32 raw public-key bytes; the encoding appends a 6-character
checksum. A typical address is ~62 characters.

- **Variant: bech32m, not bech32.** bech32m (BIP-350) fixes a known weakness in
  the original bech32 checksum where certain insertions/deletions are not
  detected. We have no SegWit-style versioning reason to keep the older variant,
  so we use bech32m unconditionally.
- **Strict decoding.** Parsing uses an explicit bech32m check
  (`CheckedHrpstring::new::<Bech32m>`), *not* the `bech32` crate's top-level
  `decode`, which leniently accepts either bech32 or bech32m. An address with a
  valid *bech32* (non-m) checksum is rejected.
- **HRP must match `rrn`** (case-insensitively — an all-uppercase address is
  still valid bech32). A correctly-checksummed address under any other HRP
  (e.g. Bitcoin's `bc1…`) is rejected with a distinct error.
- **Wrong payload length is rejected.** Only a 32-byte payload that decodes to a
  canonical Ed25519 curve point becomes an `Address`; everything else is a parse
  error, not a silently-truncated key.
- **The `Address` type owns this format** (`rrn-identity::address`). Its
  `Display`/`FromStr` are the bech32m text form; its `serde` impls use that same
  string (for wire envelopes/config); and inside a *signed* attestation an
  address is the raw 32 bytes as canonical CBOR, never the text form. The text
  encoding is strictly a presentation concern.

The `bech32` crate is pinned to `0.12` (the task spec's `0.11` is superseded; the
0.12 API takes/returns raw bytes and handles the 8↔5-bit base32 conversion
internally).

## Consequences

- **Typos are caught.** A single mistyped character almost always fails the
  checksum, so a malformed address is rejected at parse time rather than
  resolving to the wrong identity. This is the primary reason for the choice.
- **Addresses are self-identifying.** The `rrn1` prefix makes it obvious a string
  is a Railroad Network address, and distinguishes it from a hash or signature.
- **QR / radio friendly.** bech32's restricted, case-insensitive alphabet
  encodes compactly in QR codes and survives lossy/manual transcription better
  than mixed-case hex.
- **Cost: an encoding layer to trust.** Address parsing now depends on the
  `bech32` crate's checksum logic. This sits *outside* the `rrn-crypto` audit
  boundary (it is presentation, not signing) — the bytes that are signed are the
  raw key, never the bech32 text — so it does not enlarge the crypto audit
  surface. A correctness bug in bech32 could misrender or wrongly reject an
  address, but cannot alter what is signed or forge a signature.
- **Not a stealth/confidential address scheme.** bech32m gives integrity
  (checksum) and ergonomics, not privacy: an address is the public key in the
  clear. Address-unlinkability is out of scope for Phase 0.
- **Deviation from the spec's API sketch, recorded for auditors.** The spec
  sketched inherent `to_string`/`from_str` methods; these are provided via the
  standard `Display`/`FromStr` traits instead, because an inherent `to_string`
  beside a `Display` impl (and an inherent `from_str`) trip `clippy` lints CI
  treats as errors. The ergonomic surface is unchanged.

## Alternatives Considered

- **Hex (base16):** rejected. No checksum (the decisive factor), and visually
  indistinguishable from other hex blobs in the system.
- **Base58 / Base58Check (Bitcoin legacy addresses):** rejected. Base58 itself
  has no standard checksum; Base58Check adds one but is case-sensitive, less
  QR-efficient, and has weaker, less idiomatic Rust-ecosystem support than
  bech32. bech32m was designed for exactly this address use case.
- **bech32 (original, BIP-173) instead of bech32m:** rejected. bech32m supersedes
  it with strictly better error detection and no offsetting downside for our
  use; keeping the older variant would only invite the lenient-decode ambiguity.
- **Base32/Base64 with an ad-hoc checksum:** rejected. Reinvents what bech32m
  already specifies and would force third-party implementations to target our
  bespoke scheme.

## References

- [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) —
  bech32 (HRP, separator, checksum, case rules)
- [BIP-350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) —
  bech32m, and why it replaces bech32
- `crates/rrn-identity/src/address.rs` — the `Address` type this ADR governs
- [ADR-0002](0002-canonical-serialization-dcbor.md) — why a signed address is
  raw CBOR bytes, not the bech32 text form
- `docs/threat-model.md` — `rrn-identity` (Tampering: address typos / wrong-HRP)
- `CLAUDE.md` — Locked technical decisions table (address format: bech32m, HRP
  `rrn`)
