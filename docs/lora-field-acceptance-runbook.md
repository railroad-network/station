# LoRa field-acceptance runbook (two-agent, two-machine)

This is an **execution runbook** for the LoRa radio field-acceptance run — the human-gated
checklist in `docs/lora-radio-bringup.md §5`. It is written to be followed step-by-step by a
an automated agent session running on **each** of two machines, one radio per machine. It is the
operational companion to `docs/lora-radio-bringup.md` (the reference: firmware, config keys,
compliance table); when the two disagree, that guide and the ADRs win.

The goal is the acceptance **PASS**: a signed bundle crosses one station to the other **over
LoRa only**, is ingested, and its station-signed delivery receipt returns — with no manual
intervention — recording RSSI/SNR, latency, and retransmits at bench range and at real range
(≥ 1 km if feasible). Observing a full settlement on the writer is an **optional** extra step
(§R5), not part of the PASS bar.

---

## 0. Roles and how the two agents coordinate

There are two roles. The human tells each machine's agent which one it is at the start:

- **RECEIVER (Machine B)** — also the community **writer**: it holds the log, admits the
  member, and returns the signed receipt. Follow §§1–2, then **§R**, then §F.
- **SENDER (Machine A)** — originates the radio push and hosts the **member wallet**. Follow
  §§1–2, then **§S**, then §F.

The two agents **cannot message each other.** A handful of values must pass between the
machines; the **human relays them by hand.** Watch for these markers:

- 🔴 **STOP — ASK THE HUMAN.** Do not proceed or guess. (Region/frequency/power and any
  hardware ambiguity are always STOP gates — an agent must never invent a transmit frequency
  or power.)
- 📤 **RELAY OUT.** Print this value clearly and tell the human to carry it to the other
  machine.
- 📥 **RELAY IN.** You need a value the other machine produced; ask the human for it and wait.

**Failure policy (both roles):** radio is slow and flaky. If a radio/`rnsd`/`rnstatus` step
fails, retry at most **2–3 times**, then STOP and report what you tried and the exact error —
do **not** loop. The scripted stages already budget minute-scale timeouts; let them run.

**Shell-state note (important for an agent).** Each shell command runs in a fresh shell —
environment variables and background jobs do **not** persist between commands. This runbook
therefore keeps all variables and passphrases in an env file you `source` at the top of
**every** command block (§2), and starts each daemon detached with `nohup` (or your tool's
background-execution mode) so it survives.

Fill in the **Results** table (§F5) as you go; that table is the deliverable the human pastes
into the tracking issue.

---

## 1. Preconditions (BOTH machines)

Run these and confirm each line. Substitute the real serial port (`ls /dev/tty*`;
Heltec/ESP32 is usually `/dev/ttyUSB0`, macOS `/dev/tty.usbserial-*`).

```sh
# Reticulum tools, pinned to the version the station supervises (any 1.5.x is accepted):
rnsd --version                       # must report 1.5.x  — if missing: pipx install "rns==1.5.2" "lxmf==1.1.1"

# Confirm the radio is on RNode firmware and shows the correct region:
rnodeconf -i /dev/ttyUSB0            # ✅ record firmware + region for the Results table

# The LXMF adapter and the acceptance script both need `import RNS, LXMF`.
# pipx installs into isolated venvs, so the SYSTEM python3 usually CANNOT import them:
python3 -c "import RNS, LXMF" 2>&1 && echo "system python OK" || echo "system python cannot import RNS/LXMF — use the pipx venv python (see §2)"
```

Build the binaries (from the repo root of this checkout):

```sh
cargo build --release --bin station --bin rrn
```

🔴 **STOP — ASK THE HUMAN** for the radio parameters, and confirm they are **identical on
both machines** (the human is relaying the same numbers to each):

- `frequency_hz` — legal for this region (band edge + duty cycle + EIRP cap are the human's
  responsibility per `docs/lora-radio-bringup.md §3`).
- `tx_power_dbm` — within the region's EIRP cap; start low (e.g. 7).
- `bandwidth_hz`, `spreading_factor`, `coding_rate` — must match on both nodes; SF8 / 125 kHz
  / CR 4/5 is a robust default.
- `duty_cycle_percent` for the airtime budget (EU-868 → `1.0`; US-915 → `10.0`).

Also 🔴 **ASK THE HUMAN** for a station passphrase and (Machine A only) a wallet passphrase.
Do not proceed until you have the radio parameters, confirmation the other machine uses the
same values, and the passphrases.

---

## 2. Environment (BOTH machines)

Write an env file once, and `source` it at the top of every later command block. This is what
carries the variables and passphrases across the fresh shells each command runs in.

```sh
cat > "$HOME/rrn-field.env" <<EOF
export REPO="$(pwd)"                       # this checkout
export RRN="$(pwd)/target/release/rrn"
export STATION="$(pwd)/target/release/station"
export FIELD="$(pwd)/scripts/field-test-lora.sh"
export ADAPTER="$(pwd)/scripts/reticulum/lxmf_adapter.py"   # absolute path for [lora] adapter_script
export RRN_LOG=info
export RRN_PASSPHRASE="<the station passphrase the human gave you>"
export RRN_WALLET_PASSPHRASE="<the wallet passphrase — Machine A only>"
# If §1's python check FAILED, point the adapter and the script at the pipx venv that has both
# RNS and LXMF (the lxmf venv; confirm the path with: pipx list). Otherwise leave both unset.
export RRN_ADAPTER_PYTHON="\$HOME/.local/pipx/venvs/lxmf/bin/python"   # or comment out if system python was OK
EOF
source "$HOME/rrn-field.env"
```

If §1's python check succeeded, delete the `RRN_ADAPTER_PYTHON` line (the config default
`python3` is fine). If it failed, keep it **and** set `adapter_python` in the `[lora]` config
block below to the same path.

Rehearse the acceptance script's own logic with **no hardware** (this is the CI smoke path;
expect `ALL STAGES PASSED`):

```sh
source "$HOME/rrn-field.env"
"$FIELD" --dry-run
```

If the dry run is not all-green, STOP — the script or the build is wrong; report it. Do not
touch the radios until the dry run passes.

---

## R. RECEIVER / WRITER track (Machine B only)

### R1. Initialize and configure the writer

```sh
source "$HOME/rrn-field.env"
export B="$HOME/rrn-writer"
WRITER_ADDR="$("$STATION" init --data-dir "$B")"
echo "WRITER_ADDR=$WRITER_ADDR"          # you relay this AFTER the station is up (R2)
```

Write `"$B/config.toml"` with the radio parameters the human gave you in §1 (this example is
EU-868 — **use the human's actual numbers**):

```toml
[peers]
list = []                        # a writer's normal setting (it refuses to start with gossip peers)

[network]
listen = "0.0.0.0:7411"

[mobile]
advertise = false
listen = "0.0.0.0:7412"          # the member on Machine A pairs here over LAN (plain TCP, not Reticulum)

[settlement]
window_seconds = 60              # short window so an optional bench settlement is observable quickly

[sidecar]
enabled = true
# Leave tcp_listen / tcp_peers UNSET: the generated Reticulum config then carries only the
# radio interface, so the bundle can only cross LoRa — nothing routes over TCP/LAN.

[lora]
adapter_script = "<ABSOLUTE path to scripts/reticulum/lxmf_adapter.py>"
# adapter_python = "<pipx lxmf venv python>"   # ONLY if §1's python check failed
raw_bytes_per_sec = 250          # starting preset; replace with your measured rate in F3
duty_cycle_percent = 1.0         # ← human's value

[lora.rnode]
port = "/dev/ttyUSB0"            # ← this machine's radio port
frequency_hz = 867200000         # ← human's value (MUST be region-legal)
tx_power_dbm = 7                 # ← human's value
# bandwidth_hz = 125000          # ← human's value; must match Machine A
# spreading_factor = 8           # ← human's value; must match Machine A
# coding_rate = 5                # ← human's value; must match Machine A
```

> If this station was **ever started before** you added `[lora.rnode]`, its generated
> `"$B/reticulum/config"` has no radio and is never regenerated. Delete
> `"$B/reticulum/config"` and restart, or add the `[[RNode LoRa Interface]]` stanza by hand.

### R2. Start the writer and confirm the radio

```sh
source "$HOME/rrn-field.env"; export B="$HOME/rrn-writer"
nohup "$STATION" run --data-dir "$B" >"$B/station.log" 2>&1 &   # detached; survives the command
for _ in $(seq 1 50); do [ -S "$B/station.sock" ] && break; sleep 0.2; done
"$RRN" --socket "$B/station.sock" status             # sidecar running, path-out state
rnstatus --config "$B/reticulum" | grep -i rnode     # ✅ RNode interface up on B
```

If the socket never appears, `tail "$B/station.log"` — a passphrase prompt means
`RRN_PASSPHRASE` was not in the environment (re-`source` the env file). If `rnstatus` shows no
`rnode` interface: confirm `[lora.rnode]` and `[sidecar] enabled=true`, delete
`"$B/reticulum/config"`, restart once, re-check. Then STOP if still absent.

📤 **RELAY OUT (only now that the station is up and the mobile listener is bound):** give the
human **`$WRITER_ADDR`** and this machine's **LAN IP** — the sender needs both to provision
the member wallet.

### R3. Confirm the member (after the sender relays the member address + SAS)

📥 **RELAY IN:** wait for the human to bring you the **member's `rrn1…` address** and the
**pairing SAS** the sender printed. ⏱ The pending pairing **expires 5 minutes** after the
sender ran `wallet pair` — if the relay is slower than that, ask the human to have Machine A
re-run `wallet pair` and relay a fresh SAS.

```sh
source "$HOME/rrn-field.env"; export B="$HOME/rrn-writer"
MEMBER_ADDR="<the member address the human relayed>"
# 1. List the pending request and READ its SAS code:
"$STATION" pair-mobile --data-dir "$B"          # prints:  <sas>   <addr>   (<age>s ago)
# 🔴 STOP — compare that <sas> to the SAS the human relayed from Machine A. Only if they MATCH:
"$STATION" pair-mobile "$MEMBER_ADDR" --data-dir "$B"    # confirms the pairing
# 2. Vouch for the member (needed for standing; the debt floor lets a zero-balance member pay):
"$RRN" --socket "$B/station.sock" vouch "$MEMBER_ADDR" --statement "field-test member"
```

📤 **RELAY OUT:** tell the human "member confirmed — Machine A may now `sync`."

### R4. Run the acceptance as the receiver

**Start the receiver FIRST** (before the sender pushes). It prints the destination hex the
sender needs:

```sh
source "$HOME/rrn-field.env"; export B="$HOME/rrn-writer"
"$FIELD" --role receiver --data-dir "$B"
```

📤 **RELAY OUT:** from **Stage 2** of that output, copy the line
`LXMF destination hex: <HEX>` and give **`<HEX>`** to the human for Machine A.

The script then waits (minute-scale) for the pushed bundle to arrive and ingest; it returns
the signed receipt automatically. When it prints `ALL STAGES PASSED`, note it — that is your
half of the PASS.

### R5. Optional — observe a full settlement (beyond the PASS bar)

The acceptance PASS is the bundle+receipt path above. If you also want to watch the payment
settle: after the bundle is ingested, the member's *proposal* is now in this station's log and
you (the receiver/operator) confirm it.

```sh
source "$HOME/rrn-field.env"; export B="$HOME/rrn-writer"
"$RRN" --socket "$B/station.sock" transactions "$MEMBER_ADDR"    # find the pending proposal's tx id
"$RRN" --socket "$B/station.sock" confirm <tx_id>                # you are the receiver of the 1.00 payment
sleep 65                                                          # wait past window_seconds
"$RRN" --socket "$B/station.sock" balance "$MEMBER_ADDR"         # expect -1.00 (the member spent)
```

Go to §F.

---

## S. SENDER track (Machine A only)

### S1. Initialize the sender station

```sh
source "$HOME/rrn-field.env"
export A="$HOME/rrn-sender"
"$STATION" init --data-dir "$A" >/dev/null
```

Write `"$A/config.toml"` — same radio parameters as Machine B (📥 the human relayed them),
but this machine's own serial port. It does **not** need a `[mobile]` listener:

```toml
[peers]
list = []

[network]
listen = "0.0.0.0:7411"

[sidecar]
enabled = true
# Leave tcp_listen / tcp_peers UNSET (radio-only), same as Machine B.

[lora]
adapter_script = "<ABSOLUTE path to scripts/reticulum/lxmf_adapter.py>"
# adapter_python = "<pipx lxmf venv python>"   # ONLY if §1's python check failed
raw_bytes_per_sec = 250
duty_cycle_percent = 1.0         # ← human's value, same as B

[lora.rnode]
port = "/dev/ttyUSB0"            # ← THIS machine's radio port
frequency_hz = 867200000         # ← human's value, IDENTICAL to B
tx_power_dbm = 7                 # ← human's value
# bandwidth_hz / spreading_factor / coding_rate  ← human's values, IDENTICAL to B
```

```sh
source "$HOME/rrn-field.env"; export A="$HOME/rrn-sender"
nohup "$STATION" run --data-dir "$A" >"$A/station.log" 2>&1 &
for _ in $(seq 1 50); do [ -S "$A/station.sock" ] && break; sleep 0.2; done
"$RRN" --socket "$A/station.sock" status
rnstatus --config "$A/reticulum" | grep -i rnode     # ✅ RNode interface up on A
```

### S2. Provision the member wallet and export a signed bundle

📥 **RELAY IN:** get **`$WRITER_ADDR`** and **Machine B's LAN IP** from the human, and confirm
**Machine B's station is already up** (its mobile listener binds only after R2 — pairing
against a not-yet-started B gets connection-refused and burns your retries). Do the wallet
provisioning while A and B are on the **same LAN**.

```sh
source "$HOME/rrn-field.env"
export MEMBER="$HOME/rrn-member"
WRITER_ADDR="<relayed from Machine B>"

# 1. create the wallet, pinned to the writer's address:
MEMBER_ADDR="$("$RRN" wallet --home "$MEMBER" init --station "$WRITER_ADDR")"
echo "MEMBER_ADDR=$MEMBER_ADDR"
# 2. pair over the sealed channel to B's mobile listener (prints a line beginning "SAS:"):
"$RRN" wallet --home "$MEMBER" pair --url "<B-LAN-IP>:7412"
```

📤 **RELAY OUT:** give the human the **`$MEMBER_ADDR`** and the **SAS** so Machine B can
compare and confirm the pairing. ⏱ Machine B must confirm within **5 minutes** — if it
lapses, re-run `wallet pair` and relay the new SAS. 📥 Then wait for "member confirmed."

```sh
source "$HOME/rrn-field.env"; export MEMBER="$HOME/rrn-member"
WRITER_ADDR="<relayed from Machine B>"
# 3. sync now that the member is confirmed (re-anchors nonce/outbox/balance):
"$RRN" wallet --home "$MEMBER" sync
# 4. sign a payment bound for a SLOW carrier (two-week TTL survives a slow radio) and export:
"$RRN" wallet --home "$MEMBER" pay "$WRITER_ADDR" 1.00 --memo "lora field test" --carrier slow
"$RRN" wallet --home "$MEMBER" export bundle --out "$HOME/rrn-out"
ls "$HOME/rrn-out/payload.bundle"     # this is what crosses the radio
```

### S3. Confirm the LoRa path, then push

📥 **RELAY IN:** get the **receiver destination hex** the human copied from Machine B's
Stage 2.

🔴 **Hard gate — do NOT run the sender script until a LoRa path resolves.** The adapter drops
an outbound frame when no path to the recipient is known yet, so pushing blind can burn the
600 s budget on a dropped first send.

```sh
source "$HOME/rrn-field.env"; export A="$HOME/rrn-sender"
rnpath --config "$A/reticulum" <receiver-destination-hex>    # must print a path over LoRa; give it up to ~2 min after B announces
rnprobe --config "$A/reticulum" lxmf.delivery <receiver-destination-hex>   # ✅ record RSSI/SNR
```

If `rnpath` shows no path after ~2 minutes, STOP and report it — do not run the sender script.
Once a path resolves (the receiver must already be running per R4):

```sh
source "$HOME/rrn-field.env"; export A="$HOME/rrn-sender"
"$FIELD" --role sender --data-dir "$A" \
    --peer <receiver-destination-hex> \
    --bundle "$HOME/rrn-out/payload.bundle"
"$RRN" --socket "$A/station.sock" dtn status    # the push moves queued → delivered, receipt correlated
```

When the script prints `ALL STAGES PASSED`, note the **new** push id and the wall-clock from
push to `delivered`. Go to §F.

---

## F. Finish, measure, and record (BOTH machines)

### F1. Bench PASS

Confirm both scripts printed `ALL STAGES PASSED` with the radios ~1 m apart. **PASS** = every
stage green over the radio, bundle ingested on B, receipt returned to A, no manual
intervention. Record bench RSSI/SNR (from `rnprobe`/`rnstatus`), push→receipt latency, and any
retransmit counts.

### F2. Field PASS (≥ 1 km if feasible)

Move Machine A (radio) to real separation.

⚠️ **You MUST sign and export a FRESH bundle for the field run.** `dtn push` is idempotent on
the bundle's content hash: re-pushing the *same* `payload.bundle` returns the old `delivered`
row instantly, so the sender would print a false PASS with nothing crossing the radio while the
receiver times out. So on Machine A, before the field push:

```sh
source "$HOME/rrn-field.env"; export MEMBER="$HOME/rrn-member"
WRITER_ADDR="<from B>"
"$RRN" wallet --home "$MEMBER" pay "$WRITER_ADDR" 1.00 --memo "lora field test 2" --carrier slow
"$RRN" wallet --home "$MEMBER" export bundle --out "$HOME/rrn-out-field"
```

Then re-run R4 (receiver) / S3 (sender) with `--bundle "$HOME/rrn-out-field/payload.bundle"`.
The field PASS requires **both** the receiver's Stage 3 green **and** a **new** push id on the
sender. Record RSSI/SNR/latency/retransmits at distance.

### F3. Measure the real rate and tune the budget

From the delivered bundle size and the observed wall-clock, compute the **actual** sustained
on-air bytes/sec at your settings, set `[lora] raw_bytes_per_sec` to it in **both**
`config.toml` files, restart both stations, re-run, and confirm money-bearing records are
paced ahead of bulk.

### F4. Soak (optional but recommended)

Leave both up at field distance for a multi-hour run pushing a **fresh** bundle periodically
(each push needs a new signed payment + export, per F2); confirm **no money-bearing record is
lost** (couriers/paper remain the fallback if the link drops).

### F5. Record the sign-off

Fill this table and give it to the human to paste into the tracking issue.

| Metric | Bench (~1 m) | Field (≥ __ km) |
|---|---|---|
| RNode firmware / region (both units) | | |
| RSSI (dBm) | | |
| SNR (dB) | | |
| Push → receipt wall-clock | | |
| Retransmit count | | |
| `field-test-lora.sh` result | PASS / FAIL | PASS / FAIL |
| New push id on the sender (not a re-push) | | |
| Bundle ingested on B (Stage 3 green) | yes / no | yes / no |
| Receipt returned to A (`dtn status` delivered) | yes / no | yes / no |
| Optional: settlement observed on writer (§R5) | yes / no / n/a | yes / no / n/a |
| Measured sustained on-air B/s (F3) | | |
| Soak: money-bearing record loss (F4) | none / __ | none / __ |

---

## Scope reminder (do not overreach)

- The acceptance bar is the **DTN bundle-push + receipt** path. The receipt returns to the
  *member* the normal way (`rrn wallet sync` over LAN, or a courier carrying
  `rrn paper export-receipts`), **not** from `rrn dtn status` (which shows only a one-line
  summary). A full settlement (§R5) is optional and observed on the writer with `rrn balance`.
- Region/spectrum compliance is the human's responsibility. Never invent a transmit frequency
  or power; both are §1 STOP gates.
- Not in scope: multi-hop mesh, antenna/RF tuning, mobile-to-station radio (phones use
  paper/SMS/LAN in Phase 2), regulatory sign-off.
