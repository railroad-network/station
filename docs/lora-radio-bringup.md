# Bringing up a LoRa radio link

This guide takes an RNode-class LoRa radio from unflashed hardware to carrying
station traffic over the air. Radio is one of the offline transports Railroad
Network can fall back to when the internet is unavailable.

The transport layer is carrier-agnostic: the station moves the same signed records
and paces them to the same airtime budget whether they travel over TCP or over a
radio. Moving from a TCP link to a real radio is therefore a **firmware and
configuration change, not a code change** — nothing in the transport or the
delay-tolerant sync engine changes.

The steps below involve physical hardware — flashing firmware and testing over the
air — so they are run by hand. This guide is the checklist for that work.

## Prerequisites

Install Reticulum, which provides the `rnodeconf`, `rnstatus`, `rnpath`, and
`rnprobe` tools used throughout. Pin the version the station is validated against
(it supervises `rnsd` with a version check and refuses to manage an unpinned
build; any `1.5.x` is accepted):

```sh
pipx install "rns==1.5.2" "lxmf==1.1.1"
rnsd --version    # confirm it reports 1.5.x
```

## 1. Will this board work?

Reticulum talks to LoRa through its `RNodeInterface`, which drives a board running
**RNode firmware** over USB serial. A usable device must:

1. carry a **Semtech LoRa transceiver** — SX1276/78 (SX127x) or SX1262/68
   (SX126x); newer handhelds are usually SX1262;
2. be on the RNode firmware
   [supported-boards list](https://github.com/markqvist/RNode_Firmware) — commonly
   **ESP32** boards (LilyGO T-Beam/T3, Heltec LoRa32) and **nRF52840** boards
   (RAK4631-class);
3. match your **regional LoRa band** — 868 MHz (EU) or 915 MHz (US) — agreed on
   both ends of the link.

**Definitive check (about five minutes, no code):**

```sh
rnodeconf --autoinstall
```

`rnodeconf` detects the connected board and offers firmware **only if it is
supported** — that is the authoritative yes/no. A device currently running
Meshtastic is a good sign that it is a LoRa board; a supported one can be reflashed
to RNode firmware (the two firmwares are mutually exclusive — you are converting the
device, not dual-booting it).

You need **two** radios to test an over-the-air hop: one on the station and one on a
peer. A single radio only proves the station-to-radio USB path, not a link.

> **Handheld all-in-one radios (e.g. ThinkNode M1):** confirm the LoRa chip and MCU
> from the spec sheet, or from `rnodeconf`'s detection, before committing to a
> fleet. If `--autoinstall` does not recognize the board, it is not an RNode target,
> and you should test with a known-good RNode instead (a LilyGO T-Beam or RAK4631 is
> a safe reference).

## 2. Flash and verify the radio

```sh
# 1. Flash RNode firmware (interactive; pick your board when prompted).
rnodeconf --autoinstall

# 2. Inspect the flashed device — confirms firmware, EEPROM, and region.
rnodeconf -i /dev/ttyACM0     # nRF52840 boards are usually ACM;
                              # many ESP32 boards are /dev/ttyUSB0.
                              # Run `ls /dev/tty*` before and after plugging in.

# 3. After provisioning the radio parameters (next section):
rnstatus                      # should list the RNode interface, up.
```

## 3. Configure the radio interface

Configure the radio in the **station** config — the station templates the matching
Reticulum interface for you. Set `[lora.rnode]` in `config.toml`:

```toml
[sidecar]
enabled = true
# ... rnsd_path, config_dir left at defaults for most setups ...

[lora]
# Use an ABSOLUTE path — the station resolves it against its working directory,
# which is "/" under systemd and other service managers.
adapter_script = "/opt/railroad/station/scripts/reticulum/lxmf_adapter.py"
# raw_bytes_per_sec / duty_cycle_percent: see the airtime-budget presets below;
# re-tune to your measured on-air rate after step 5.

[lora.rnode]
# Serial port of the radio (see `ls /dev/tty*`); nRF52 boards are usually ACM,
# many ESP32 boards are USB.
port = "/dev/ttyACM0"
# frequency_hz and tx_power_dbm have NO defaults — you MUST choose values that are
# legal for your region (see the compliance table below) and identical on every
# node on this LoRa network.
frequency_hz = 867200000     # EU-868 example; US-915 e.g. 915000000
tx_power_dbm = 7             # start low; stay within your region's EIRP cap
# Optional radio parameters (defaults shown); must also match on every node:
# bandwidth_hz = 125000       # 125 kHz is the robust default
# spreading_factor = 8        # 7..12 — higher = more range, less throughput
# coding_rate = 5             # the x in 4/x
```

On first run the station writes `<data_dir>/reticulum/config` with a matching
`[[RNode LoRa Interface]]` stanza and **never overwrites your edits** afterward. If
`[lora.rnode]` is absent, that generated config instead carries a *commented*
example and a pointer back to this guide — the station never transmits on a
frequency or power nobody chose. (You may also hand-edit the generated Reticulum
config directly; the station leaves an operator's edits alone.)

> **If the station already ran once** (e.g. you brought the sidecar up over TCP
> first), that generated config is now on disk and will **not** be regenerated when
> you add `[lora.rnode]` — so no radio appears. Either delete
> `<data_dir>/reticulum/config` (the station rewrites it on the next start) or add
> the `[[RNode LoRa Interface]]` stanza to it by hand.

### Regional spectrum compliance — read before you transmit

**Choosing a frequency, duty cycle, and power that are legal where you operate is
your responsibility, and it varies by country.** LoRa runs in license-free ISM
bands, but the band edges, duty-cycle limits, and radiated-power caps differ by
region, and **antenna gain counts toward the radiated-power cap**. Use this table
as a starting point and confirm against your national regulator before keying up.

| Region | Band / example centre | Duty cycle | Radiated power cap | `duty_cycle_percent` |
|---|---|---|---|---|
| EU (EU-868) | 863–870 MHz; e.g. 867.2 MHz | 1% on most sub-bands (some 0.1%/10%) | 14 dBm ERP (25 mW) typical | `1.0` (or `0.1`) |
| US (US-915) | 902–928 MHz; e.g. 915 MHz | No fixed duty cycle; FHSS/dwell-time rules | 30 dBm conducted (EIRP higher w/ FHSS) | `10.0` (no duty limit; pace conservatively) |
| Generic ISM | follow your national plan | follow your national plan | follow your national plan | conservative: `1.0` |

Sources to check for current, authoritative limits (the numbers above summarize and
can lag rule changes):

- Reticulum RNode interface docs — parameters and per-region notes:
  <https://reticulum.network/manual/interfaces.html>
- RNode firmware region/band references:
  <https://github.com/markqvist/RNode_Firmware>
- EU: ETSI EN 300 220 (SRD, 25–1000 MHz) and your national administration.
- US: FCC Part 15.247 (902–928 MHz) and the LoRa Alliance regional parameters.

> ADR-0017 flagged spectrum compliance as the long pole of radio bring-up. When in
> doubt, transmit at the lowest power that carries the link and the most
> conservative duty cycle — the station will simply pace traffic more slowly.

### Airtime-budget presets

SF8 at 125 kHz is roughly 2 kbit/s raw on air, and the duty cycle cuts *sustained*
throughput to single-digit bytes per second. The station's airtime budget
(`[lora] raw_bytes_per_sec × duty_cycle_percent / 100`) paces to that, so
money-bearing records always go ahead of bulk traffic. These are safe starting
points; **replace them with your measured on-air rate after step 5.**

| Region | `raw_bytes_per_sec` | `duty_cycle_percent` | ≈ sustained | Notes |
|---|---|---|---|---|
| EU-868 (1% sub-band) | `250` | `1.0` | ~2.5 B/s | The conservative default. |
| EU-868 (0.1% sub-band) | `250` | `0.1` | ~0.25 B/s | Slowest; paper/courier stay primary. |
| US-915 (dwell-limited) | `250` | `10.0` | ~25 B/s | No hard duty cycle; keep headroom for dwell rules. |
| Faster SF (SF7, wider BW) | measure | as region | measure | Re-measure `raw_bytes_per_sec` at your settings. |

## 4. Two-node link test (over the air)

1. Flash **both** radios identically (same frequency, bandwidth, and spreading
   factor).
2. Bring up Reticulum and the station on each node (or one station and one bare
   Reticulum peer).
3. On node A: `rnstatus` shows the RNode interface up; `rnpath` shows a path to B
   appearing after B announces.
4. Send a probe: `rnprobe lxmf.delivery <B-destination-hash>` — expect a reply with
   RSSI and SNR.
5. Then the real check: submit a small record batch on A and confirm it is ingested
   on B and its delivery receipt returns to A — the same
   receive → ingest → receipt path the automated tests exercise over a simulated
   link, now over real air.

### Reading the station's own status surfaces

Alongside the Reticulum tools, the station reports its own view:

- `rrn status` — the daemon's health, including the connectivity block: whether the
  sidecar is running and whether the station currently believes it has a path out.
- `rrn dtn status` — every tracked outbound push: peer, record count, state
  (`queued` / `delivered` / `abandoned`), attempt count, and the correlated
  delivery receipt's outcome. This is where you watch a record you pushed cross the
  radio and its receipt come back.

### The scripted acceptance run

`scripts/field-test-lora.sh` automates the software half: it drives a signed
bundle across the radio and confirms the delivery receipt returns. It does **not**
spawn a station or a radio — start a station on each machine yourself (per §3),
then point the script at the running one with `--data-dir`.

```sh
# Rehearse the stages with no hardware (also the CI smoke test):
scripts/field-test-lora.sh --dry-run

# On the receiver machine — prints its LXMF destination hex, then waits:
scripts/field-test-lora.sh --role receiver --data-dir /path/to/station-data

# On the sender machine — push a bundle to the receiver's destination hex:
scripts/field-test-lora.sh --role sender --data-dir /path/to/station-data \
    --peer <receiver-destination-hex> --bundle ./payload.bundle
```

Run the **receiver** first: its Stage 2 prints this station's LXMF destination hex
(derived from `<data_dir>/reticulum/adapter.identity`, the value the adapter
announces on the air). Copy that hex to the sender's `--peer`. The sender then
pushes the bundle (`rrn dtn push`) and polls `rrn dtn status` until the push shows
**delivered** with a correlated receipt; the receiver waits for the bundle to
arrive and ingest (the station returns its signed receipt automatically). Timeouts
are minute-scale because radio is slow.

> Passing an `rrn1…` address to `--peer` instead of the hex only works once the
> peer's transport binding has reached this station inside an ingested bundle;
> across two fresh stations, use the destination hex the receiver prints.

> **Two machines, not one host.** Two `rnsd` instances cannot share one host's
> Reticulum control ports, so run one station on each of two machines — the `sender`
> and `receiver` roles above. (A same-host rehearsal would need each station given
> distinct `shared_instance_port` / `instance_control_port` by hand; the real field
> run avoids that entirely.)

> **Scope — what crosses the radio here.** This run verifies the DTN
> bundle-push + receipt path: a signed record travels A → B over LoRa and its
> receipt returns. The member-side outbox export a full payment round-trip needs
> now exists — `rrn wallet` (ADR-0028). The sending member runs
> `rrn wallet pay … --carrier slow` (the two-week expiry survives a slow carrier)
> and `rrn wallet export bundle --out .`, and the sender station pushes the
> resulting `payload.bundle` with `rrn dtn push --peer <hex> --bundle
> payload.bundle`. The receiving member confirms with their own `rrn wallet`.
>
> **Carrying the receipt back.** `rrn dtn status` on the sender shows only a
> one-line `receipt_summary` for a delivered push, not the receipt bytes, so the
> member does *not* apply a receipt from `dtn status`. The receiving member gets
> its station-signed receipt the normal way — `rrn wallet sync` when it can reach
> the writer's LAN, or a courier carrying `rrn paper export-receipts` output from
> the writer, applied with `rrn wallet receipts apply`. Settlement is observed on
> the writer (`rrn balance`). The human field sign-off is still what remains.

### Troubleshooting

- **No serial port / permission denied.** On Linux your user must be in the serial
  group (`dialout` on Debian/Ubuntu, `uucp` on Arch): `sudo usermod -aG dialout
  $USER`, then log out and back in. Confirm the device with `ls -l /dev/ttyACM* /dev/ttyUSB*`.
- **`rnodeconf`/`rnstatus` not found.** Install Reticulum, pinned to the version
  the station manages: `pipx install "rns==1.5.2" "lxmf==1.1.1"` (see Prerequisites).
- **No carrier / no path to B.** Both radios must share frequency, bandwidth, and
  spreading factor exactly; confirm with `rnstatus` on each, and give `rnpath` time
  after B announces.
- **Wrong region on the flashed board.** Re-check with `rnodeconf -i <port>`; the
  EEPROM region must match your configured frequency.
- **The station runs but no radio interface appears.** Confirm `[lora.rnode]` is set
  (not just `[lora]`) and that `[sidecar] enabled = true`; the station only
  templates the RNode stanza when `[lora.rnode]` is present. If the station had
  already run before you added `[lora.rnode]`, its Reticulum config was written
  without a radio and is never regenerated — delete `<data_dir>/reticulum/config`
  (or add the stanza by hand) and restart.

## 5. Field acceptance checklist

Run this yourself with the hardware in hand and **record the results in the PR or
tracking issue** (this is the human sign-off; the software half is already
CI-verified via `field-test-lora.sh --dry-run`). **Pass** = every stage of
`scripts/field-test-lora.sh` green over radio — the signed bundle delivered A → B
and its receipt returned — with no manual intervention. (The full
propose → confirm → settle payment round-trip over radio is gated on a later
ticket's station-side outbox export; see the scope note in §4.)

- [ ] `rnodeconf -i` confirms RNode firmware and the correct region on both units.
- [ ] `rnstatus` shows the RNode interface up on both.
- [ ] `rnpath` resolves a path between A and B over LoRa (not TCP).
- [ ] `rnprobe` returns RSSI/SNR at the intended separation (on the bench, then in
      the field).
- [ ] `scripts/field-test-lora.sh` runs green over the radio at (a) bench range and
      (b) real range ≥ 1 km if feasible; record RSSI/SNR (from `rnstatus`),
      wall-clock sync latency, and any retransmit counts.
- [ ] A real signed record batch crosses from A to B over LoRa, byte-identical, and
      its receipt returns (`rrn dtn status` shows it delivered).
- [ ] Measure the **actual** sustained on-air bytes per second at your settings and
      set the station's airtime budget to it; re-run and confirm money-bearing
      traffic is paced ahead of bulk.
- [ ] Soak test: a multi-hour run at field distance with periodic record batches,
      confirming no money-bearing record is lost (couriers and paper remain the
      fallback if the link drops).

## What this does not cover

Multi-hop mesh behavior at scale, antenna and RF tuning, regulatory compliance
sign-off, and a live community exercise are field and operational work beyond this
checklist. If your all-in-one handheld is not an RNode target, this guide still
applies verbatim to a known-good RNode (LilyGO T-Beam, RAK4631); only the flashing
step differs.
