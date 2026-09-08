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
`rnprobe` tools used throughout:

```sh
pip install rns
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

The station generates a Reticulum config file on first run with a TCP interface, and
never overwrites your edits. Add a radio interface to
`<data_dir>/reticulum/config`, under the existing `[interfaces]` section.

The values are **region- and link-specific**. The stanza below is an EU-868,
conservative-range starting point.

```ini
  [[RNode LoRa Interface]]
    type = RNodeInterface
    interface_enabled = True
    # Serial port of the radio (see `ls /dev/tty*`); nRF52 boards are usually ACM.
    port = /dev/ttyACM0
    # Radio parameters — MUST match on every node on this LoRa network.
    frequency = 867200000       # Hz  (EU 868 band; for US 915, e.g. 915000000)
    bandwidth = 125000          # Hz  (125 kHz is the robust default)
    txpower = 7                 # dBm (start low; raise within legal limits)
    spreadingfactor = 8         # 7..12 — higher = more range, less throughput
    codingrate = 5              # 4/5
    # Optional identity beacon for a shared channel:
    # id_callsign = RRN-STATION-1
    # id_interval = 600
```

**Throughput reality.** SF8 at 125 kHz is roughly 2 kbit/s raw on air, and regional
duty-cycle rules cut *sustained* throughput to single-digit bytes per second. This
is exactly what the station's airtime budget paces to, so money-bearing records are
always sent ahead of bulk traffic. Once you have measured your link's real on-air
rate (step 5), set the station's airtime budget to it.

Enable the radio transport in the station config:

```toml
[sidecar]
enabled = true
# ... rnsd_path, config_dir ...

[lora]
adapter_script = "scripts/reticulum/lxmf_adapter.py"
# raw_bytes_per_sec / duty_cycle_percent tuned to your region and settings (step 5).
```

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

## 5. Field acceptance checklist

- [ ] `rnodeconf -i` confirms RNode firmware and the correct region on both units.
- [ ] `rnstatus` shows the RNode interface up on both.
- [ ] `rnpath` resolves a path between A and B over LoRa (not TCP).
- [ ] `rnprobe` returns RSSI/SNR at the intended separation (on the bench, then in
      the field).
- [ ] A real signed record batch crosses from A to B over LoRa, byte-identical, and
      its receipt returns.
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
