# Setting up a Railroad Network community

*The steward's runbook*

This guide walks one person — the **station steward** — through standing up a
Railroad Network community from nothing: a small always-on computer running the
`station` daemon, and a handful of Android phones running the mobile app,
paired to it. It assumes you are comfortable typing commands into a terminal
but not that you are a programmer. Every command you need is written out in
full.

By the end you will have:

1. A running station that holds your community's shared ledger.
2. Your members' phones paired to it, each holding its own identity key.
3. A ratified founding Charter, so governance and disputes work from day one.
4. Encrypted backups and a social key-recovery net, so no single lost laptop,
   forgotten passphrase, or stolen phone can destroy the community's history.

Read the whole thing once before you start. Part 4 (backups and recovery) is
not optional homework for later — do it the same day you found the community.

---

## Before you start: honest warnings

- **This is research-stage software.** The cryptography has not been
  independently audited. Do not use it to hold, transfer, or represent
  anything of real value. Run a pilot with play stakes, not livelihoods.
- **One station, one network.** There is no federation between communities
  yet, and no relaying over the internet. Your community is one station plus
  the phones that can reach it — in practice, everyone on the same Wi‑Fi /
  LAN. Members sync when their phone can reach the station; that's by design
  for now.
- **The phone traffic is plain HTTP, on purpose.** Every message is
  individually encrypted and signed end-to-end ("sealed envelopes",
  ADR‑0008), so the transport doesn't need TLS. The security ceremony that
  matters is the in-person pairing code comparison — take it seriously.
- **Android only, sideloaded.** There is no app-store distribution. Members
  install a signed APK you give them (see the mobile repo's
  [`SIDELOAD.md`](https://github.com/railroad-network/mobile/blob/main/SIDELOAD.md)).

## What you need

| Thing | Details |
| --- | --- |
| A station machine | Any always-on Linux or macOS box: a Raspberry Pi 4/5 with a 64-bit OS (4 GB+ RAM), a spare laptop, a mini-PC. It must stay powered and on the network. |
| A network | A Wi‑Fi network all members' phones can join. The station needs a stable reachable address on it — give it a DHCP reservation or static IP in your router if you can. |
| Phones | Android, arm64 (roughly anything from 2017 on). iPhones can only run development builds today. |
| The software | The `station` binary is built from source (10–30 minutes, once). The phone app is a single `app-release.apk` file. |
| Two safe places | For the passphrase and backups: e.g. a fireproof folder at home plus a sealed envelope with a trusted member. You'll thank yourself in Part 4. |

---

## Part 1 — Stand up the station

### 1.1 Build the software

Install the Rust toolchain (one command, from [rustup.rs](https://rustup.rs)):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then fetch and build the station:

```sh
git clone https://github.com/railroad-network/station.git
cd station
cargo build --release -p rrn-station -p rrn-cli
```

This produces two programs:

- `target/release/station` — the **daemon**: holds the wallet and ledger,
  talks to the phones. This is the thing that runs forever.
- `target/release/rrn` — the **CLI client**: your admin tool. It talks to the
  running daemon over a local socket; it only works while the daemon is up.

For convenience, put both on your `PATH` (e.g.
`sudo cp target/release/{station,rrn} /usr/local/bin/`). The commands below
assume you did.

### 1.2 Initialize the station

```sh
station init
```

You will be prompted (twice) for a **wallet passphrase**. Stop and choose this
carefully:

- It protects the station's identity key and, later, encrypts every backup.
- You will type it each time the station starts and each time you take a
  backup.
- **Write it down, on paper, in two places.** A passphrase that exists only
  in one person's head has already been lost twice in this project's own
  history. Part 4.2 builds a safety net for a lost passphrase, but the net
  only exists if you set it up.

`init` creates the data directory — `~/.railroad/station` by default (use
`--data-dir` everywhere if you want it elsewhere) — and prints your station's
address: a long string starting `rrn1…`. That address *is* the station's
identity. Inside the directory:

| File | What it is |
| --- | --- |
| `wallet.rrnwallet` | The station's identity key, encrypted under your passphrase. Irreplaceable. |
| `station.db` (+ `-wal`, `-shm`) | The community ledger: every transaction, vouch, vote, and dispute. Irreplaceable. |
| `paired_mobiles.json` | Which phones are paired. Losing it means re-pairing everyone (annoying, not fatal). |
| `config.toml` | Settings (next section). |
| `station.sock`, `marketplace_index/` | Runtime scratch; rebuilt automatically. Never back these up. |

### 1.3 Configuration

`config.toml` in the data directory. The defaults are right for a
single-community pilot; the section you may want to touch is `[mobile]`:

```toml
[peers]
list = []                    # station-to-station federation: leave empty (not built yet)

[network]
listen = "127.0.0.1:7400"    # station-to-station port: loopback-only is correct today

[mobile]
listen = "0.0.0.0:7500"      # where phones connect; 7500 is what the app expects
advertise = true             # announce the station on the LAN (mDNS) so phones find it by name
# name = "Railroad Station — Maple Street"   # optional friendly name shown on phones;
                                             # omitted = a stable name derived from the address

[timers]
sweep_interval_secs = 30
gossip_interval_secs = 5

# [settlement] uses per-tier defaults: Tier 1 = 24h, Tier 2 = 48h.
```

Two practical notes:

- **Firewall:** if the machine runs one, allow inbound TCP **7500** from your
  LAN. Port 7400 should stay unreachable from other machines.
- **`advertise = true`** is what makes the station appear automatically in
  the app's "Join your community" list. Leave it on unless your network
  blocks mDNS/Bonjour — in that case members type the station's IP and port
  by hand (the app has an "Add by address" option for exactly this).

### 1.4 Run it

```sh
station run
```

It prompts for the passphrase (typed invisibly) and then serves until
stopped. That's the whole job: keep this process running.

**Handling the passphrase in scripts.** `station run` also accepts the
passphrase from the `RRN_PASSPHRASE` environment variable. Never write the
passphrase literally on a command line or in a script — it ends up in shell
history and process listings. If you automate startup, fetch it from the OS
secret store at the moment of use, e.g. on macOS:

```sh
# one-time: store it (prompts you; nothing lands in history)
security add-generic-password -a "$USER" -s rrn-station-passphrase -w

# every start:
RRN_PASSPHRASE=$(security find-generic-password -s rrn-station-passphrase -w) station run
```

**Surviving reboots (Linux/Pi).** A minimal systemd service:

```ini
# /etc/systemd/system/rrn-station.service
[Unit]
Description=Railroad Network station
After=network-online.target
Wants=network-online.target

[Service]
User=railroad
EnvironmentFile=/etc/railroad/station.env   # contains RRN_PASSPHRASE=…; chmod 600, owned by root
ExecStart=/usr/local/bin/station run
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now rrn-station
```

The `EnvironmentFile` holds the passphrase on disk readable by root only —
an accepted pilot-grade trade-off so the station comes back by itself after a
power cut. If that's not acceptable to your community, skip the service and
start it by hand after each reboot.

**Check it's alive** (from the station machine):

```sh
rrn whoami        # prints the station's rrn1… address
rrn history       # the ledger log (empty at first — that's fine)
```

---

## Part 2 — Get the phones on

### 2.1 Install the app

Each member installs the `app-release.apk` you distribute. The full
walkthrough — including the maintainer side of building and signing that APK —
is the mobile repo's
[`SIDELOAD.md`](https://github.com/railroad-network/mobile/blob/main/SIDELOAD.md).
The member half in one breath: get the file onto the phone, open it, allow
"install unknown apps" for the app you opened it from, tap Install.

### 2.2 Create a wallet

On first launch the app walks the member through creating their identity: a
passphrase, optional biometric unlock, and a generated `rrn1…` address of
their own. **The key never leaves the phone** — the station cannot spend,
vote, or speak for a member.

The app will nudge each member to set up **social recovery** ("Protect your
account" on the Home screen): their wallet key is split into shards held by
friends, so a lost phone isn't a lost identity. Encourage everyone to do this
in the first week, once there are a few members to hand shards to.

### 2.3 Pair each phone with the station

Pairing is a short in-person ceremony between the member and you. It's the
step that proves to the phone it's talking to the real station, and to the
station that this phone is welcome — the code comparison below is the actual
security boundary, so do it face to face, reading the code aloud.

**On the phone:** after creating the wallet, the member taps **Join your
community** (or later: Settings → Station pairing). The station appears in
the list by name — or they tap *Add by address* and type the station's IP and
port 7500. They unlock their wallet; the phone then shows an **8-character
code**.

**On the station:**

```sh
station pair-mobile
```

lists the pending requests, each with the same style of 8-character code and
the phone's `rrn1…` address.

**Together:** compare the code on the phone's screen with the one the station
printed. If — and only if — they match:

```sh
station pair-mobile <the-phone's-rrn1-address>
```

and the member confirms on their phone. Done: the phone now syncs with the
station, receives push updates, and can transact.

If the codes *don't* match, refuse: something on the network answered in the
station's place. Find out what before pairing anyone.

Housekeeping commands you'll use over the community's life:

```sh
station list-mobiles          # who is paired
station unpair <rrn1-addr>    # revoke a lost or departed member's phone
```

---

## Part 3 — Found the community

A community exists once its **Charter** is ratified: the founding document
naming the community, its principles, its guaranteed rights, and its
founders. Until then, phones can pair and look around, but governance and
disputes have nothing to stand on. Found the community as soon as the
founders' phones are paired.

**Why founders matter beyond ceremony:** membership standing is earned
through vouches and trade, which takes time. To avoid a dead zone where
nobody can vote or sit on a dispute jury, the network runs a **bootstrap
grace** (ADR‑0015): while the community has fewer than three established
members, the electorate is the founders plus whoever is established. Your
founders *are* the functioning government of the early community — the app
shows a banner while this grace is active. Choose founders accordingly:
three to five trusted people is a good shape for a ~20-person pilot.

### Option A — solo bootstrap (station is the only founder)

One command, no ceremony:

```sh
rrn governance charter-init \
  --community-id maple-street-commons \
  --principle "Mutual aid before profit" \
  --principle "Decisions in the open" \
  --right "Any member may call a vote" \
  --right "Any member may contest a transaction"
```

Quick, but it makes the station wallet — i.e. you, the steward — the sole
founder, and therefore the whole grace-period electorate. Fine for a
technical trial; not a great founding story for a real community.

### Option B — the founding ceremony (recommended)

Founders keep their keys on their own phones and sign the Charter there —
nobody's key ever leaves their device. Pair every founder's phone first
(Part 2.3), then open the ceremony from the station:

```sh
rrn governance charter-begin \
  --community-id maple-street-commons \
  --principle "Mutual aid before profit" \
  --principle "Decisions in the open" \
  --right "Any member may call a vote" \
  --right "Any member may contest a transaction" \
  --founder <station-rrn1-address> \
  --founder <alice-phone-rrn1-address> \
  --founder <bob-phone-rrn1-address>
```

(Founder addresses: each member can read theirs off their app; paired phones
also show up in `station list-mobiles`. Including the station's own address
makes it co-sign immediately — leave it out for an all-phones founding.)

Each phone-holding founder then opens the app: **Community → Governance**
shows a *"Sign the founding charter"* nudge. They review the Charter — it
must say exactly what was declared above — and tap **Sign**.

The Charter publishes automatically once **75% of the declared founders**
(rounded up) have signed. Watch progress from the station:

```sh
rrn governance charter-status    # who has signed, threshold, body
rrn governance charter           # the effective Charter, once ratified
```

When it flips to published, the phones' Governance screens show
**Ratified** — your community exists. From here on, day-to-day governance
(proposals, co-signing, voting, statutes) and disputes all run from the
phones and the `rrn governance` / `rrn dispute` commands.

---

## Part 4 — Protect the community (do this now)

The station directory holds the only copy of your community's history and
the key that is its identity. Three failure modes will eventually visit any
long-running community: the machine dies, the passphrase is lost, or both at
once. Each has a prepared exit — but only if you prepare it **before** the
failure. Both preparations together take about fifteen minutes.

### 4.1 Backups

```sh
station backup
```

Safe to run while the station is serving (the ledger is snapshotted
consistently, no downtime). It verifies your passphrase, then writes a single
**encrypted** archive, `station-backup-<timestamp>.rrnbak`, bundling the
wallet, the ledger, the paired-phones list, and the config. Use `--out` to
choose the destination.

Because the archive is encrypted, it is safe to copy anywhere convenient —
a USB stick in a drawer, another machine, a cloud drive. What it is *not*
safe to do is keep the only copy on the station machine itself.

A pilot-grade routine:

- **Weekly**, and additionally before any software upgrade: run
  `station backup`, copy the archive off the machine.
- **Keep the last three or four** archives, not just the newest.
- **Once, early on: rehearse the restore** into a scratch directory so you
  know it works and you know the passphrase does too:

  ```sh
  station restore station-backup-<timestamp>.rrnbak --data-dir /tmp/restore-drill
  rm -rf /tmp/restore-drill
  ```

To actually restore after losing a machine: install the station software on
the new machine (Part 1.1), then

```sh
station restore <archive>
station run
```

Restore refuses to overwrite an existing station unless you add `--force`.
It restores everything, pairings included — members' phones simply resume.
The ledger resumes from the snapshot: anything transacted after your last
backup is gone, which is why the routine is weekly, not yearly.

### 4.2 Key recovery — the lost-passphrase net

A backup you can't decrypt is a paperweight, and the archive is (rightly)
encrypted under the passphrase. So the station also supports **social key
recovery** (ADR‑0016): the station's key is split into shards sealed to
trusted members' phones. A threshold of them, cooperating in person, can
reconstruct the key — which also unlocks any backup archive, passphrase or
no passphrase.

**Arm it** as soon as you have a few paired members you trust:

```sh
station recovery setup \
  --threshold 3 \
  --holder <alice-rrn1-address> \
  --holder <bob-rrn1-address> \
  --holder <carol-rrn1-address> \
  --holder <dan-rrn1-address> \
  --holder <erin-rrn1-address>
```

Rules of thumb: **3-of-5** is the sweet spot for a small community — no
single holder (or pair of holders) can act alone, and losing one or two
doesn't sink you. Holders must be paired members; pick people unlikely to
leave together.

The command prints a **QR code per holder**. Each holder scans theirs, in
person, with the app: **Settings → Shards you hold → scan**. The phone
stores the shard; the holder needs to do nothing else, possibly for years.
If a holder leaves the community, **re-run `setup`** with a new roster — a
re-run re-splits the key and quietly invalidates every previously issued
shard. (`station recovery status` shows the current roster;
`station recovery show-shard <addr>` re-displays one QR for redelivery.)

**Use it** the day the passphrase is gone. Gather a threshold of holders in
one room:

```sh
station recovery restore                        # passphrase lost, data dir intact
station recovery restore --from-backup <archive>  # machine AND passphrase lost
```

The command prints a **request QR**. Each holder opens **Settings → Shards
you hold → Help someone recover**, scans the request, checks that the
station address shown is really yours, unlocks with their own passphrase,
and their phone displays a **response QR**. Scan each response with any QR
reader and paste the resulting `rrnrecover-resp:…` lines into the waiting
command. (The responses are sealed to this recovery session — they're safe
to relay over chat if a holder can't attend, as long as you trust the
request QR reached them intact.) With enough responses in, you choose a
**new passphrase** and the station is yours again. Take a fresh backup
immediately — the old archives still answer only to the old key wrapping.

### 4.3 The disaster table

| What happened | What saves you | Prepared by |
| --- | --- | --- |
| Station machine dies | `station restore <archive>` on a new machine | 4.1 backups |
| Passphrase lost, machine fine | `station recovery restore` (re-keys in place) | 4.2 recovery |
| Machine dies **and** passphrase lost | `station recovery restore --from-backup <archive>` | both |
| A member loses their phone | The member's own social recovery (shards held by friends) | each member, in-app |
| A member's phone is stolen | `station unpair <addr>` + the member recovers on a new phone | — |

The first three rows protect the *community*. The last two protect a
*member* — which is why nudging everyone through in-app social recovery
setup (Part 2.2) is steward work too.

---

## Part 5 — Life with the network

### Phones that go quiet in the background

Android aggressively suspends backgrounded apps, and some vendors (Motorola
and Samsung are repeat offenders; Xiaomi/Huawei even more so) cut a
suspended app's network entirely. The symptom: a member gets no
notifications and their app shows stale balances until they open it.

The short version, once per phone at onboarding: in the app, **Settings →
Notifications** — allow notifications and turn on **"Sync while the app is
closed"**, accepting the battery dialog the app then shows. (If that dialog
was missed: system **Settings → Apps → Railroad Network → Battery →
Unrestricted**.) Some brands need one extra vendor-specific setting on top.

The full story — what background sync actually does, the per-vendor traps
(Samsung sleep lists, Xiaomi autostart, and friends), a ten-minute
verification drill for each phone, and the expectations to set with
members — is its own runbook:
[`background-reliability.md`](background-reliability.md). Make its
checklist part of every member's day-one setup, right after pairing.

Momentary blips are normal: on a cold start the app may show a
**Connecting…** pill for a second while it re-establishes its subscription,
and brief Wi‑Fi drops heal on their own. "Offline" that persists while the
phone is on the right Wi‑Fi is what's worth investigating.

### Updating

- **The app:** build a new signed APK (bump `versionCode`), hand it out;
  members install it *over* the old one — never uninstall first, that erases
  the wallet. Details in `SIDELOAD.md`.
- **The station:** take a backup first (4.1), then
  `git pull && cargo build --release -p rrn-station -p rrn-cli`, stop the
  daemon, and start the new one. The phones reconnect by themselves.
- Update the station before the app when a release notes say they moved
  together — the app is built against a pinned station version.

### When a member reports a problem

Every error the app hits is recorded on the phone, surviving restarts. Ask
the member for **Settings → Advanced → Diagnostics**: it lists recent
errors with a **copy** button, so they can paste the details to you over
any channel. If the app ever crashes to an error screen, that screen offers
the same copy-and-recover path. (One known gap: a crash in the app's dying
breath may not be captured — an empty Diagnostics screen doesn't prove
nothing happened.)

### Troubleshooting quick table

| Symptom | Likely cause → fix |
| --- | --- |
| Phone's Join screen finds no station | Phone on guest/other Wi‑Fi → same network. mDNS blocked → *Add by address* with the station's IP, port 7500. Station down → start it. |
| *Add by address* fails too | Firewall on the station machine → allow TCP 7500 from LAN. Wrong IP → check the router / `ip addr`. |
| Pairing codes don't match | Something else answered in the station's place. Don't pair; identify the machine that owns that IP. |
| App says the station "couldn't be verified" | Same as above — the endpoint can't prove it holds the station key. Refuse. |
| Member gets no notifications when app is closed | Battery optimization → set Unrestricted (see above). |
| A tap fails with a transient error, retry works | Usually a momentary network race; if a member can reproduce one, Diagnostics → copy → send it to the maintainers. |
| Station machine won't start the daemon: wrong passphrase | It's the *wallet* passphrase from `init`, not the machine login. Lost it? → Part 4.2, today. |

---

## Appendix — command quick reference

```sh
# lifecycle
station init                      # once: create identity + storage (prompts passphrase)
station run                       # serve (prompts passphrase, or RRN_PASSPHRASE)

# phones
station pair-mobile               # list pending pair requests + codes
station pair-mobile <rrn1-addr>   # confirm one, after comparing codes in person
station list-mobiles              # who is paired
station unpair <rrn1-addr>        # revoke a phone

# founding
rrn governance charter-begin --community-id <id> --principle … --right … --founder <addr> …
rrn governance charter-status     # ceremony progress
rrn governance charter            # the effective Charter

# safety net
station backup [--out <file>]     # encrypted archive; safe while running
station restore <archive> [--force]
station recovery setup --threshold K --holder <addr> …   # arm; prints shard QRs
station recovery status | show-shard <addr>
station recovery restore [--from-backup <archive>]       # the ceremony

# everyday admin / poking around
rrn whoami | balance | history | transactions
rrn governance list | show | statutes
rrn dispute list | show
```

*Everything here is pre-audit research software. Run it with people you
trust, for stakes you can afford to lose, and report what breaks.*
