# QR Payload Formats

**Status:** current · **Task:** T1.4.2 (M1.4 Vouching Flow)

This document locks the formats of the QR codes the Railroad Network apps render
and scan, so they stay stable and interoperable across the mobile app and the
station CLI. It describes what ships **today**; forward-looking forms are marked
**reserved** and are not yet implemented.

A QR code carries a text string. The scanner decodes the string; the app decides
what kind of payload it is by its shape (a bech32 `rrn1…` prefix, or a `rrn:` /
`rrnrecovery:` scheme prefix) and parses accordingly. An unrecognized string is
rejected, not guessed at.

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
