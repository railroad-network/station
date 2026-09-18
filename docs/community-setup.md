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
5. A plan for the day the network goes away — certificates, couriers, paper,
   radio, and a rehearsed outage drill (Part 6).

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
| Laptops (optional) | A member with a computer and no phone can use the built-in `rrn wallet` instead (§2.4) — same self-custody key, driven from the command line, works offline. |
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
[network]
listen = "127.0.0.1:7400"    # station-to-station port: loopback-only is correct today
role = "writer"              # this station owns the community's log (the default)

[mobile]
listen = "0.0.0.0:7500"      # where phones connect; 7500 is what the app expects
advertise = true             # announce the station on the LAN (mDNS) so phones find it by name
# name = "Railroad Station — Maple Street"   # optional friendly name shown on phones;
                                             # omitted = a stable name derived from the address

[timers]
sweep_interval_secs = 30

# [settlement] uses per-tier defaults: Tier 1 = 24h, Tier 2 = 48h.
```

Your community's station is a **writer** — it owns the log, and there is exactly
one per community. A writer never pulls from other stations, so it has no
`[peers]`; if you add a peer list to a writer it refuses to start (with a message
telling you to remove the peers or set `role = "replica"`). You do not need
`[peers]` at all for a single station.

Two practical notes:

- **Firewall:** if the machine runs one, allow inbound TCP **7500** from your
  LAN. Port 7400 should stay unreachable from other machines.
- **`advertise = true`** is what makes the station appear automatically in
  the app's "Join your community" list. Leave it on unless your network
  blocks mDNS/Bonjour — in that case members type the station's IP and port
  by hand (the app has an "Add by address" option for exactly this).

**Running a read-replica (optional).** You can run a second station as a
read-only *replica*: a warm second copy of the writer's chain, useful for a live
off-site backup or an audit workstation. A replica pulls the writer's log and
re-derives from it, but **admits nothing** — every attempt to write to it (a
payment, a vouch, a courier bundle) is refused with a "this station is a
read-replica" message, so it can never accidentally fork the community. Point it
at the writer and set the role:

```toml
[peers]
list = ["192.168.1.10:7400"]   # the writer's station-to-station address

[network]
listen = "127.0.0.1:7401"
role = "replica"
```

`station peers list` prints the role and peers of whichever station you run it
against, and `rrn status` shows the role at the top. A replica is **not** a
failover standby — if the writer is lost, you recover it from the encrypted
backup (§4.1), not by promoting a replica; writer succession is a later-phase
feature. Because the writer signs its own settlement and governance records, a
replica shows the *chain* faithfully but reads its own balance/governance views
as empty (it cannot re-derive records signed by a different station's key) — use
the replica for chain integrity and audit, and the writer for balances.

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

## Part 2 — Get the members on

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

### 2.4 Members without a smartphone — the CLI wallet

A member with a computer and no Android phone can still hold their own key and
transact, using the built-in `rrn wallet` (ADR-0028). It is the same identity
model as the phone — the member's key never leaves their machine — driven from
the command line, and it works offline (sign now, carry on paper or a USB stick
later).

**They learn the station's address from you, in person.** The wallet *pins*
that address, and every station-signed thing it later accepts (receipts,
certificates, the pairing reply) is checked against the pin. That in-person
hand-off is the security boundary here, exactly as the code comparison is for a
phone — so read the station's `rrn1…` address to them, don't email it.

```sh
# on the member's laptop (set a passphrase once; it is never taken on the command line):
export RRN_WALLET_PASSPHRASE='something the member chooses'
rrn wallet init  --station rrn1<your-station-address>   # prints their new rrn1… address
rrn wallet pair  --url 192.168.4.1:7500                 # shows an 8-char SAS
```

**Confirm the pair as in §2.3:** compare the SAS the wallet prints with what
`station pair-mobile` lists, then `station pair-mobile <their-rrn1-address>`.
The member then runs `rrn wallet sync` to pull their nonce, balance, and any
receipts. To pay offline they `rrn wallet pay …` and `rrn wallet export qr`
(or `--format bundle`); a courier carries the sheets to you, you `rrn paper
ingest` them, and the member applies the returned receipts with `rrn wallet
receipts apply`. Online, `rrn wallet submit` does the whole round trip.

**Two things the member must understand.** First, **back up the whole wallet
home directory** (`~/.railroad/wallet` by default), not just the key file — the
outbox and its cursors live beside the key, and a backup of the key alone loses
the chain. Second, **full-disk encryption is their responsibility**: the wallet
encrypts its key file, but the decrypted key is in memory while a command runs.
If a member restores from a backup, they must reach the station's LAN once and
run `rrn wallet sync` before they can sign again (this re-anchors their chain so
it cannot fork).

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
| A member loses their phone | The member rebuilds their key from their circle: **Recover an existing identity** in the app, or `rrn wallet recover` on a laptop | each member, in-app |
| A member's phone is stolen | `station unpair <addr>` **first**, then the member recovers on a new phone and re-pairs | — |

The first three rows protect the *community*. The last two protect a
*member* — which is why nudging everyone through in-app social recovery
setup (Part 2.2) is steward work too.

**Recovering a member.** A member who lost their phone rebuilds their key on a new
device with the same social-recovery circle that armed it — the reconstruction
runs entirely on the member's device and never touches the station (their key is
theirs alone). On a new phone: **Welcome → Recover an existing identity → From my
recovery circle**, then scan at least the threshold number of holder responses.
On a laptop: `rrn wallet recover --station rrn1<station> --address rrn1<theirs>`,
which prints a request QR and a **ceremony fingerprint** for the holders to
confirm, then reads their pasted responses. Either way the recovered wallet is
treated as restored — it refuses to sign until one `rrn wallet sync` (or the
app's first sync) re-anchors it. Order matters when a phone was **stolen** (the
thief holds the same key until you act): `station unpair <addr>` first, *then* let
the member recover and re-pair. Every holder must confirm the fingerprint out of
band before contributing — a recovery request is exactly as trustworthy as the
person showing it. See the member docs for the step-by-step.

### 4.4 Seizure resistance — the encrypted profile (optional, Linux)

By default a station stores its database in the clear: only the wallet's secret
key is encrypted. A powered-off station that is seized or imaged hands over the
whole community — every balance, memo, and who-vouched-for-whom. If your
community faces that threat, the **encrypted at-rest profile** (ADR-0024) turns a
powered-off node into an encrypted brick: the ledger, the wallet, and the radio
identity all live inside a LUKS2 container whose key is **held by members, not
stored on the machine**. No single person — and no seized machine — can open it.

**The trade is real, and you choose it knowingly.** Every power loss (a blackout,
an unplugged cable, a reboot) makes the station a locked brick until **K of your
N key-holders gather to run an unlock ceremony**. Where holders share a building
that is minutes; where they are dispersed it can be a scheduled meetup — days.
So:

- **A UPS is close to mandatory.** It turns brownouts and blips — the *common*
  cause of downtime — into non-events, and shuts the station down cleanly on low
  battery. Without one, ordinary power flicker means a ceremony.
- **This profile is Linux-only** (it uses the kernel's `dm-crypt`). macOS and
  other hosts run the plaintext profile.
- **There is no operator-passphrase shortcut.** A passphrase one person knows is
  exactly what coercion extracts — the member-held quorum exists to remove that
  single seizable human. If you want single-operator unlock, you want the
  plaintext profile; use it honestly.

**Before you turn it on — hardening the host** (do these first; the encryption is
only as good as the machine around it):

```sh
# Disable swap (or use encrypted swap) so VMK bytes / DB pages never page out:
sudo swapoff -a          # and remove swap from /etc/fstab
# Suppress core dumps so a crash can't spill plaintext to disk:
echo 'kernel.core_pattern=|/bin/false' | sudo tee /etc/sysctl.d/50-no-cores.conf
# Keep logs off any plaintext partition (journald to volatile storage is fine).
```

**Privileged helper commands.** `encrypt-in-place` and `unlock` drive the kernel's
`cryptsetup`/`losetup`/`mount`/`mkfs.ext4`/`chown` via `sudo -n` (the daemon itself
stays unprivileged). If you run the station as a dedicated non-root user, give that
user a **scoped** sudoers rule for exactly those tools — do not grant blanket sudo:

```
# /etc/sudoers.d/rrn-station  (visudo -f), for user "rrn":
rrn ALL=(root) NOPASSWD: /usr/sbin/cryptsetup, /usr/sbin/losetup, /bin/mount, \
    /bin/umount, /sbin/mkfs.ext4, /bin/chown
```

Be honest about the residual: granting `mount`/`chown`/`cryptsetup` to a user is
close to root-equivalent on that host. This is the trade for a code-driven,
testable key ceremony; a community that wants a smaller privileged surface can run
the ceremony as root interactively instead of via a service account.

**Turn it on — one-way migration.** Take a backup first, then migrate. You need
each key-holder's `rrn1…` address (they read it from their wallet app):

```sh
station backup --out ~/before-encrypt.rrnbak        # keep this somewhere safe
station encrypt-in-place \
    --holder rrn1<alice> --holder rrn1<bob> --holder rrn1<carol> \
    --holder rrn1<dave>  --holder rrn1<erin> \
    --threshold 3
#   → provisions the container, moves the wallet + ledger inside, splits the
#     Volume Master Key 3-of-5, and prints a QR per holder to scan into their
#     wallet. The volume is left unlocked so you can `station run` right away.
```

Have each holder scan their QR **in person**. Their phone stores it as an
ordinary recovery shard (it will read "a shard for `rrn1…`" — that is expected).

**After migrating, destroy the old media.** `encrypt-in-place` securely erases the
plaintext files it moved, but secure erase is **unreliable on SD cards and other
wear-levelled flash** — the old blocks may survive remapping. For a real threat
model, physically destroy the card the station ran on before the migration.

**Every boot from now on — the unlock ceremony.** After any power loss the
station will not start until K holders help:

```sh
station status          # shows "state volume: LOCKED (not mounted)"
station unlock          # prints a request QR + a short console fingerprint
#   Read the fingerprint aloud. Each holder confirms it matches on their end,
#   THEN scans the request in their wallet's "help recover" flow and reads you
#   back a response line. Paste K responses; the volume mounts.
station run             # now the daemon starts normally
```

The console fingerprint is the safety check: it stops anyone who stole a copy of
the machine from tricking your holders into unlocking it for them. If the
fingerprint a holder sees does not match yours, **stop** — someone else is
running the ceremony.

**Rotating who holds keys.** When a relationship changes, re-split to a new set —
the volume must be unlocked first:

```sh
station vmk status                                   # current holders
station vmk refresh --holder … --holder … --threshold 3
```

A refresh gives every holder a brand-new shard and makes old and new shards
**un-mixable** — a leftover old shard is useless next to the new ones. It does
**not** change the underlying volume key, though, so a *full quorum of the former
holders*, acting together, could still reconstruct it. If you need to lock former
holders out completely (not just re-key who cooperates going forward), rotate the
key onto a **new** container — `encrypt-in-place` refuses to run on a station that
is already encrypted, so the rotation is a fresh migration:

```sh
station unlock && station backup --out rotate.rrnbak   # while still unlocked
station restore rotate.rrnbak --data-dir /path/to/fresh # a fresh, plaintext dir
station --data-dir /path/to/fresh encrypt-in-place \
    --holder … --holder … --threshold 3               # new holders, new VMK
cp <old-boot-dir>/config.toml /path/to/fresh/          # backups omit the boot config
```

Then move the fresh dir into place and **physically destroy the old media** — on the
same SD card the restore step re-writes the plaintext ledger, and secure erase is
unreliable on flash. Only after this do the former holders' shards protect a key that
no longer opens anything.

> **Backups under the encrypted profile** cover everything *inside* the container
> (ledger, wallet, pairings), but not the boot-dir `config.toml` (peers, listen
> address, tuning). Keep a copy of `config.toml` with your backups, or expect to
> re-enter that configuration when you restore onto fresh hardware.

**If the station is seized anyway** — the recovery drill. Practice it before you
need it:

```sh
scripts/drill-seizure-recovery.sh --profile plaintext   # runs anywhere
scripts/drill-seizure-recovery.sh --profile encrypted   # Linux, exercises the brick
```

What each profile actually checks:

- `--profile plaintext` rehearses the **community-continues** path end to end:
  stand up a station, back it up, delete the data dir ("seize"), `station restore`
  onto fresh storage, and confirm the same identity with an openable ledger and
  wallet.
- `--profile encrypted` proves the **brick property**: with the volume closed, a
  planted marker appears nowhere in the container bytes or on the boot dir (with a
  positive control proving the sweep works), the holder set is absent from the boot
  dir, and the LUKS header has zero keyslots.

Recovering an **encrypted** station onto fresh hardware is a manual sequence, not
something the drill runs for you: `station restore <archive>` (4.1) to get the
ledger and wallet back, then `station encrypt-in-place` to provision a new
keyslot-less container and re-arm the VMK to your (possibly changed) holder set,
then the `station unlock` ceremony. The unlock ceremony and the ledger's
durability across a remount are exercised by the `at-rest-dmcrypt` test lane.

> **Heads-up for `systemd`:** under the encrypted profile `station run` exits until
> the volume is unlocked, so a unit with `Restart=always` will crash-loop after a
> reboot until someone runs `station unlock`. That is expected — unlock is a
> deliberate human step. Use `Restart=on-failure` (as the sample unit in §3 does)
> and start the service *after* the ceremony, or leave it enabled and simply expect
> the restart backoff until K holders have gathered.

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

### Paper fallback — when there is no network at all

When a member's phone cannot reach the station by any means — no Wi‑Fi, no mesh,
no radio — a payment can still travel on **paper**. The member confirms (or
spends) offline on their phone, which produces QR codes; those get printed or
photographed, physically carried to the station, scanned back to text, and
ingested. The station's delivery receipt makes the return trip the same way.

What you need: a printer (any monochrome laser is plenty) and any commodity
**QR scanner app** or webcam tool. The `rrn` CLI does **not** read camera images
— a headless station has no camera — so scanning happens with a phone/scanner app
and produces *text*: one QR payload string per line, saved to a file. That file
is what you feed the CLI.

The operator commands (all under `rrn paper`):

```sh
# Ingest a carried sheet: scan its QRs to text (one payload per line), then
rrn paper ingest --in scanned.txt --out carryback/
#   → prints each carried record's outcome (admitted / known / refused) and
#     writes the station's delivery receipts to carryback/ for the return trip.

# Inspect a sheet without ingesting (works with the daemon stopped):
rrn paper show --in scanned.txt

# Export pending receipts for a member to carry home:
rrn paper export-receipts --author rrn1… --out receipts/

# Print a member credential card (their address QR):
rrn paper credential --address rrn1… --name "Jordan" --out cards/

# Print a headroom-certificate wallet card for the station's OWN wallet, to spend
# offline later (the cert reserves this station's debt-floor headroom):
rrn paper cert --request 10 --out cards/            # reserve + print a 10-Common cert
rrn paper cert --cert-id <hex> --out cards/         # print an existing live one

# Re-render any exported *.txt to a printable sheet (chunk_*.png + sheet.pdf):
rrn paper render --in receipts/receipts.txt --out sheets/
```

Each `--out` directory gets individual `chunk_NN_of_MM.png` files, a captioned
`sheet.pdf` (every QR labelled with its payload id and index, so a dropped page
is identifiable by eye), and a `*.txt` of the raw strings (the no-printer path).

**Courier handling.** Sheets are *public information* — a bundle, a receipt, or a
certificate carries no secret, so losing one is a **delay, not a loss of funds**.
Re-scanning the same sheet is safe: the station recognizes it and never admits a
payment twice. If a receipt sheet goes missing, just run `export-receipts` again;
the receipt is proof of what actually landed. A member without a phone originates
their own payments offline with `rrn wallet` and prints them with `rrn wallet
export` (§2.4); these `rrn paper` tools are the *courier's* verify-and-ingest
side. See the end-to-end walkthroughs in
[`scripts/demo-phase-2-paper.sh`](../scripts/demo-phase-2-paper.sh) (the phone)
and [`scripts/demo-phase-2-wallet.sh`](../scripts/demo-phase-2-wallet.sh) (the
laptop member).

### Reticulum carrier — optional, off by default (experimental)

Between paper and full internet sits a middle rung: carrying traffic over
**Reticulum**, the mesh/LoRa/packet-radio stack the network adopted as its
federation and collapse-mode carrier (ADR-0013). In this build the station can
*supervise* the Reticulum daemon (`rnsd`) as a managed background service and
carry delay-tolerant traffic over it — including over a LoRa radio. To take a
station onto a radio end to end (flashing, config, and a scripted field
acceptance), follow [the LoRa radio bring-up guide](lora-radio-bringup.md).

It is **off unless you turn it on** (`[sidecar] enabled = false` by default), and
turning it on asks something of you first:

- **Install the daemon yourself.** `rnsd` is not bundled with the station — you
  install it separately, pinned: `pipx install "rns==1.5.2" "lxmf==1.1.1"` (any
  `1.5.x` is accepted; the station refuses to manage an unpinned build). Confirm
  with `rnsd --version`.
- **Know what you're installing.** Reticulum's code is under the **Reticulum
  License** — permissive (MIT-style) but with two use restrictions (no use in a
  system built to harm people; no use in building AI/ML training datasets). It is
  not an OSI-approved license. The station never bundles or links it — you install
  it as a separate program — but by enabling the sidecar you choose to run that
  software. If that is a problem for your community, leave the sidecar off; nothing
  else depends on it.
- **Turn it on** by adding a `[sidecar]` block to `config.toml` (`enabled = true`,
  optionally `rnsd_path`, `tcp_listen`, `tcp_peers`). The station generates a
  Reticulum config under `<data_dir>/reticulum/` on first run and never overwrites
  your edits.

Watch it with `rrn status`: the `connectivity.sidecar` block reads `disabled`,
`running` (with the version), `degraded` (with a reason — e.g. a version
mismatch), or `restarting`. A degraded or crashed sidecar **never takes the
station down** — its loss is a connectivity event, exactly like an unreachable
peer.

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

## Part 6 — Resilience: when the network goes away

*Added 2026-09-13 at the close of Phase 2 (single-community resilience,
ADR-0017). This part is the operator's story for the day the internet, the
Wi-Fi, or the power is gone. Everything in it runs on the same station and
phones you already have; nothing here needs federation.*

The design principle to hold onto: **the station is the only thing that writes
the ledger** (ADR-0020). When members cannot reach it, they do not stop — they
keep signing on their phones, and their signed records travel to the station
later over whatever still works: another member's phone, a radio, a text
message, or a printed sheet. Nothing *settles* until the record arrives, and
every settlement window is served in full from arrival (ADR-0022). Offline mode
is normal mode, running late.

### 6.1 The "before the storm" ritual — headroom certificates

A member who will be out of reach and expects to *pay* someone should reserve a
**headroom certificate** first, while still connected (ADR-0021). A certificate
sets aside part of the member's credit headroom so a later offline payment
against it is accepted on arrival no matter what else happened in the meantime
— the receiver can hand over the goods knowing the credit was already reserved.

What the numbers are, and where they come from (`config.toml` `[credit]`,
defaults shown):

| Setting | Default | Meaning |
| --- | --- | --- |
| `cert_max_cap_centi` | 1000 (10 Commons) | The most one certificate can reserve. |
| `cert_max_outstanding` | 4 | How many live certificates one member may hold. |
| `cert_validity_seconds` | 7 days | How long a certificate can be spent against. |
| `cert_delivery_grace_seconds` | 14 days | How late a spend against it may *arrive* and still be admitted. |

The trade: **reserved headroom is idle headroom.** A member holding a 10-Common
certificate has 10 Commons less to spend online until it expires or they return
it. So the ritual is: reserve before a market day, a storm warning, a trip up
the valley; return what you did not use when you are back.

Members do this from their phones. The station's own wallet can do it from the
console (the same rules apply to the steward):

```sh
rrn cert request 10          # reserve a 10-Common certificate (Commons, not centicommons)
rrn cert list                # what is outstanding, with caps and expiries
rrn paper cert --cert-id <hex> --out cards/   # print it as a wallet card (Part 5)
```

What a receiver checks offline, on their phone, before handing over goods: the
certificate is station-signed, it belongs to the payer, the payment fits the
remaining cap, and it has not expired. The phone also shows the payer's earlier
spends against that certificate — but only the ones the payer *presents*. A
payer can hide earlier spends; the cap still bounds what the community can lose
per certificate, and the double-spend is refused and recorded as **provable
equivocation** when the records reach the station: the member's standing drops
to nothing, they can issue no new certificates, and a jury case opens
(ADR-0025). Tell members this plainly. It is the one fraud the system cannot
prevent offline, only price.

### 6.2 The courier workflow

A **courier** is anyone who physically moves records between a cut-off member
and the station: a neighbour walking to the community hall, the person who
drives to town, a bicycle. Couriers need no trust — every record is signed by
its author and the station re-checks every signature. A courier can lose,
delay, or duplicate what they carry; they cannot forge or alter it.

The three kinds of thing a courier carries:

- **A bundle**: one or more members' signed records, going *to* the station.
  On a phone, this is the app's outbox exported for carriage; on paper it is a
  printed sheet.
- **Delivery receipts**: the station's signed answer, going *back* to each
  author, saying per record whether it was admitted, was already known, or was
  refused and why. A member whose phone has not seen a receipt simply re-sends;
  re-sending is always safe.
- **Certificates and credential cards**: printed once (Part 5), carried by
  their owner.

At the station, the courier's arrival is:

```sh
# A paper sheet, scanned to text (one QR payload per line):
rrn paper ingest --in scanned.txt --out carryback/
#   → per-record outcome (admitted / known / refused) + receipts to carry back

# Receipts for a member who is about to walk home:
rrn paper export-receipts --author rrn1… --out receipts/
```

A courier phone paired with the station submits its carried bundles itself when
it comes into Wi-Fi range; you do not need to do anything at the console.

Rules of thumb for members: **a receipt is proof; the absence of a receipt is
not proof of anything.** Keep re-sending until the receipt comes back. Two
couriers carrying the same bundle is fine. A refused record names its reason;
the commonest are `nonce-gap` (an earlier record has not arrived yet — wait) and
`debt-floor` (the payer was at their credit limit and had no certificate).

### 6.3 Radio and text message

Two electronic carriers sit between "Wi-Fi to the station" and "paper":

- **LoRa radio via Reticulum** — the station supervises a Reticulum daemon and,
  with an RNode-class radio attached, can push bundles to and receive them from
  another station or a member's radio, kilometres away with no infrastructure.
  Bring-up, spectrum compliance (your responsibility, per region), and the field
  acceptance checklist are in [the LoRa radio bring-up
  guide](lora-radio-bringup.md). Watch a push cross with `rrn dtn status`.
  The radio is **off unless you configure it** (`[lora.rnode]` has no default
  frequency or power, on purpose).
- **SMS** — a phone with cellular text but no data can text its records to the
  station's number as `rrnp:` chunks, and the station texts the receipt back.
  The codec, the sender registry (`[sms] allowed_senders = "paired"` — spam
  control, not security), the per-sender rate cap, and money-first pacing are
  built and tested against a mock gateway. **The physical modem gateway is not
  built yet** ([`spec/sms-carrier.md`](spec/sms-carrier.md) §7 records what is
  reserved), so today SMS is a tested seam, not a carrier you can switch on.

Both are dumb carriers: they see only signed, already-public records. What they
leak is *metadata* — a phone number's association with the community, a radio's
location. A community under surveillance pressure should prefer paper (Part 5)
for sensitive traffic; the honest trade is spelled out in the threat model.

### 6.4 Seizure drills

If your community runs the encrypted profile (§4.4), practise the two things
that only work if practised:

| Drill | How often | Command |
| --- | --- | --- |
| The unlock ceremony, with the real holders | After arming, after every holder change, and at least twice a year | `station unlock` (K holders present, fingerprint read aloud) |
| The community-continues path (restore from backup on fresh storage) | Quarterly, and before any upgrade | `scripts/drill-seizure-recovery.sh --profile plaintext` |
| The brick property (the closed container leaks nothing) | After arming and after every re-key | `scripts/drill-seizure-recovery.sh --profile encrypted` (Linux) |
| The UPS | Monthly: pull the mains and confirm the station shuts down cleanly on low battery rather than losing power | — |

The ceremony drill matters most. The failure mode is not cryptographic; it is
three holders who cannot be found, or who have never actually scanned the
request before. Under the plaintext profile only the second row applies.

### 6.5 Emergency governance — deciding faster, and nothing else

In a real crisis a seven-day proposal window is too slow. Emergency governance
(ADR-0023, ADR-0027) lets the community **compress the decision window** for a
narrow class of temporary measures — and deliberately does nothing else. It is
the sharpest capture lever in the system, so know exactly what it does:

- **Declaring takes a supermajority.** A declaration activates only once
  distinct electorate members' signatures reach two-thirds of the electorate
  (`ceil(2N/3)`, the author's own included). One person, or a bare majority,
  compresses nothing.
- **What it compresses:** the deliberation/voting window for `Emergency`-kind
  proposals admitted while the declaration is active — down to 24 hours (the
  floor; a charter cannot go lower). Everything else runs its normal window.
- **What it freezes and pins:** no charter amendment *or replacement founder
  charter* can be admitted (or enacted) while the emergency holds — the whole
  constitution is frozen, not just one door — and the electorate (who counts,
  who may vote) is pinned at the moment of activation, so nobody can be minted
  into it mid-crisis.
- **What it never touches:** settlement and dispute windows, the debt floor,
  certificates, reputation. A flood does not authorize economic restructuring.
- **How it ends:** by itself. Default 72 hours, at most 7 days per declaration,
  at most 14 days per chain of renewals (each renewal needs the full
  supermajority again), then a fixed 14-day cooldown. A part-signed declaration
  expires after 7 days. Every measure passed under it carries an enforced
  expiry. A community can also lift it early with the same supermajority.

The console commands (members do the same from their phones; declarations and
co-signatures also travel by courier):

```sh
rrn governance emergency-declare "Flood — river road closed" "logistics" \
    --duration-secs 172800                 # request 48 h (clamped to 24 h … 7 d)
rrn governance emergency-cosign <declaration-hash>   # each electorate member
rrn governance emergency-status            # active? reason, expiry, pinned electorate
rrn governance propose "…" "…" --kind emergency --expires-at <unix-secs>
rrn governance emergency-lapse <declaration-hash>    # start an early lift; needs co-signs too
rrn governance emergency-report            # afterwards: who declared, who signed, what passed
```

`rrn governance emergency-status` is the console banner; `rrn status` and
`rrn whoami` carry the same `emergency` field in their `--format json` output
(the plain text renderers do not print it), and the phones show a banner. Read
the report together when it is over; the design relies on that review being
*possible*, not on it being compulsory.

### 6.6 The outage drill — a facilitator's guide

The software's 72-hour outage scenario runs in seconds
([`phase-2-exit-evidence.md`](phase-2-exit-evidence.md)). The community's
version takes a half-day and real people, and it is the only way to learn where
*your* community actually breaks. Run it before you need it. This guide is for
the person facilitating.

**What you need.** The station on a UPS or battery; a printer and a phone
scanner app (Part 5); optionally a LoRa pair (6.3); paper and pens; about 8–20
members; four hours. Take a `station backup` first.

**Roles.** Assign before the day:

- *Facilitator* — runs the clock, calls the phases, keeps the log sheet.
- *Steward* — at the station console the whole time (ingest, export, status).
- *Two couriers* — one on foot, one "slow" (deliberately delays and reorders
  what they carry).
- *A merchant and a customer or two* — trade for real, with real goods (lunch
  works).
- *A holder quorum* — if you run the encrypted profile, the K key-holders.
- *One adversary* — briefed privately (below).
- *Everyone else* — members who transact, vote, and try to break things.

**Timeline.**

| Time | Phase | What happens |
| --- | --- | --- |
| T−1 day | Prepare | Every member who will pay reserves a certificate (6.1). Steward prints credential cards for anyone who wants one. Facilitator briefs the adversary. |
| 0:00 | Normal | Fifteen minutes of ordinary trade on Wi-Fi. Steward notes `rrn balance` for a few members and the log length (`rrn history`). |
| 0:15 | **Cut** | Turn off the Wi-Fi access point. Phones can no longer reach the station. Announce it. |
| 0:15–2:15 | Outage | Trade continues *offline*: certificate-backed payments accepted on phones, plain payments signed and queued, a vouch or two, a governance vote if one is open. Couriers carry bundles to the steward on foot; the steward ingests and hands back receipt sheets. The slow courier holds one bundle back deliberately. One member's phone "dies" (turn it off) after signing. If you have radios, push at least one bundle over LoRa. |
| 1:15 | **Emergency** (optional) | Declare a drill emergency (6.5) and co-sign it in person; pass one temporary measure through the compressed window. Watch the banner appear. |
| 2:15 | Power loss (encrypted profile only) | Pull the station's power. Convene the holders and run `station unlock` — read the fingerprint aloud. Time it. |
| 2:45 | **Reconnect** | Wi-Fi back on. Phones drain their queues; the slow courier finally delivers. |
| 3:00 | Reconcile | Steward reads every receipt outcome aloud: admitted / known / refused (and why). The adversary reveals what they tried. |
| 3:30 | Settle & debrief | Wait out the settlement window if you shortened it for the drill (`[settlement]` uniform override), or read the pending list. Debrief. |

**The adversary's brief** (choose two or three; the software should catch every one):

1. Sign the same certificate twice to two different receivers (expect the
   second refused as an overspend and the member's standing gone — do this
   with a throwaway identity or accept the consequence).
2. Hand a courier a bundle with one record deleted (expect: the rest lands,
   the author re-sends the missing one later).
3. Re-scan the same sheet twice (expect: same receipt, nothing double-counted).
4. Edit one character of a QR payload line before ingest (expect: refused,
   `bad-signature`).
5. Try to co-sign the emergency declaration with a phone that is not in the
   electorate (expect: refused).

**The log sheet.** Record, per event: time, who, what carrier, and the receipt
outcome. Afterwards verify with the steward:

- every value is conserved — balances still sum to zero (`rrn balance` across
  members; the harness's `assert_conservation` is the software version);
- no record was silently lost — everything on the log sheet has a receipt or a
  known re-send;
- exactly the planted double-spend was flagged, and nothing honest was;
- no settlement happened before its window elapsed from *arrival*;
- the ceremony completed with the holders you actually had.

**What you are really testing** is not the software. It is: does everyone know
how to reserve a certificate; can the couriers find the steward; do the holders
answer the phone; does the merchant trust an offline payment. Write down what
surprised you and fix the people-side before the storm.

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

# seizure resistance — encrypted at-rest profile (optional, Linux; §4.4)
station status                                            # at-rest profile + unlock state
station encrypt-in-place --holder <addr> … [--threshold K]  # migrate; K defaults to config (3)
station unlock                                            # boot ceremony → mount the volume
station vmk status | refresh --holder <addr> … [--threshold K]
scripts/drill-seizure-recovery.sh --profile plaintext|encrypted

# resilience (Part 6)
rrn cert request <commons> | list [<addr>]                # headroom certificates (§6.1)
rrn paper ingest --in <txt> --out <dir>                   # courier arrival (§6.2, Part 5)
rrn paper export-receipts --author <addr> --out <dir>     # receipts to carry back
rrn dtn push --peer <hex|addr> --bundle <file> | status | bind --destination <hex>
rrn governance emergency-declare <reason> <scope> [--duration-secs N]
rrn governance emergency-cosign <hash> | emergency-lapse <hash>
rrn governance emergency-status | emergency-report
scripts/demo-phase-2-outage.sh [1|2|3]                    # the narrated 72-hour simulation

# everyday admin / poking around
rrn whoami | balance | history | transactions | status
rrn governance list | show | statutes
rrn dispute list | show
```

*Everything here is pre-audit research software. Run it with people you
trust, for stakes you can afford to lose, and report what breaks.*
