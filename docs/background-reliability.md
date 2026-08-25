# Keeping phones in sync when the app is closed

*The background reliability runbook*

A Railroad Network phone is only as useful as its last sync. When the app is
open it holds a live connection to the station and everything is instant.
The moment it goes to the background — and even more so once Android kills
the process — the phone is at the mercy of the operating system's power
management, and on many phones the factory settings will quietly starve the
app: no notifications, stale balances, members who miss vouches, payment
confirmations, votes, and dispute deadlines.

This runbook is for the **station steward** onboarding pilot members. It
explains what the app actually does in the background, the two in-app
switches and one system setting every phone needs, the vendor-specific traps
(each phone brand hides its own app-killer), and how to verify a phone
end-to-end. The companion guide for everything else is
[`community-setup.md`](community-setup.md).

---

## 1. How background sync actually works

The app has three operating modes. Knowing which one a phone is in tells you
what behavior is *normal* — half of "background sync is broken" reports are
actually correct behavior with unset expectations.

**Foreground (app open, unlocked).** The app holds a live long-poll
subscription to the station. New events — payments, vouches, proposals,
dispute updates — arrive within seconds. Nothing in this runbook affects
foreground behavior.

**Backgrounded (app not on screen, process still alive).** The app asks the
OS scheduler to wake it periodically — **at minimum every 15 minutes**, and
the OS is free to space wakes out much further for an app it considers
unimportant. Each wake runs one short drain pass: connect to the station,
pull whatever events queued since the phone's last cursor, raise a local
notification for each one the member's preferences allow, and go back to
sleep.

**Killed or rebooted.** Android eventually kills every backgrounded process,
and reboots kill everything. The app registers a *headless* task that lets
the OS wake it even then, including after a reboot, without the app ever
appearing on screen. But a freshly woken process has no unlocked wallet —
and the sync request must be signed, because the station only talks to
authenticated members. This is why killed-app sync **only works if the
member has opted in to background sync** (next section): the opt-in
provisions a special signing credential the headless task can use.

The consequences to internalize:

- Background sync is a **polling cadence, not a push channel**. "Within
  15–30 minutes" is healthy; "instantly, while the phone is in a pocket" was
  never on offer. Opening the app always syncs immediately.
- **Every layer below can silently veto the wakes.** The rest of this
  document is about finding and disarming those vetoes.

## 2. The per-phone setup (do this at onboarding)

Three things, in order, on every member's phone. With the member present
this takes under two minutes, and doing it at pairing time (see
[`community-setup.md`](community-setup.md) Part 2) is much cheaper than
diagnosing a silent phone a week later.

**1. Allow notifications.** In the app: **Settings → Notifications** —
enable *Local notifications*, and check the *Notify me about* list matches
what the member wants. (On first run Android also shows its own
notification-permission prompt — it must be accepted; a declined prompt can
be fixed later in system Settings → Apps → Railroad Network →
Notifications.)

**2. Turn on "Sync while the app is closed."** Same screen, under
*Background sync*. This is the switch that makes killed-app and
after-reboot sync possible at all. Two things happen when it's flipped:

- The app provisions a **background signing credential**: the wallet is
  re-encrypted under a random machine-held secret stored so that the
  background task can sign sync requests without prompting for a
  passphrase. The trade-off is real and deliberate: while the *device* is
  unlocked, the app process can sign without the member's passphrase. It is
  opt-in, device-bound, and documented in the threat model — but a member
  who declines it simply gets no sync while the app is closed, which is a
  legitimate choice. Notifications then only cover the backgrounded-alive
  window.
- The app immediately shows the system **battery-exemption dialog** — the
  one-tap "let this app run in the background" request. **The member should
  accept it.** This is not cosmetic: on many builds (Motorola verified
  first-hand in this project) Android's battery optimizer doesn't just slow
  a backgrounded app down, it **cuts its network access entirely** — the
  wake fires, the drain pass runs, and the station is simply unreachable.

**3. Check the vendor's own app-killer.** Stock Android's exemption is
necessary but on several brands not sufficient — see the table in §3. Find
the phone's brand and clear its extra traps now.

If the dialog in step 2 was dismissed, the manual path is: system
**Settings → Apps → Railroad Network → Battery → Unrestricted** (wording
varies: "Don't optimize", "No restrictions", "Allow background activity").

## 3. Per-vendor traps

Stock Android already has two throttles — **Doze** (deep sleep when the
phone sits still) and **App Standby buckets** (rarely used apps get rarer
wakes). The battery exemption from §2 handles those. On top of that, most
vendors ship their own "battery manager" that kills or freezes apps by its
own rules, ignoring the stock exemption. Those are the ones that produce
the "phone went quiet three days in" reports.

| Brand | Trap | What to set |
| --- | --- | --- |
| **Motorola** | Battery optimizer cuts background network on the LAN (verified in this project's own testing). | The §2 exemption dialog is usually enough: Battery → **Unrestricted**. |
| **Google Pixel** | Closest to stock; standby buckets still apply. | The §2 exemption is enough. |
| **Samsung** | "Sleeping apps" / "deep sleeping apps" lists, plus *put unused apps to sleep* — apps get frozen after a few days of light use. | Settings → Battery → Background usage limits: remove the app from **Sleeping** / **Deep sleeping** lists, add it to **Never sleeping apps**; turn off *Put unused apps to sleep*. |
| **Xiaomi / Redmi / POCO (MIUI)** | The most aggressive: separate Autostart permission, its own battery saver per-app mode, and swipe-away-kills-the-app by default. | Security app → Permissions → **Autostart: on**. Settings → Battery → App battery saver → Railroad Network → **No restrictions**. In Recents, drag the app down to **lock** it so swiping doesn't kill it. |
| **Huawei / Honor (EMUI)** | "App launch" auto-manages apps and kills background tasks; no Play Services on recent models is a separate problem, but sync doesn't need them. | Settings → Battery → App launch → Railroad Network → switch to **Manage manually**, enable all three (Auto-launch, Secondary launch, Run in background). |
| **OnePlus / Oppo / Realme / Vivo (ColorOS, OxygenOS, Funtouch)** | Battery optimization plus a separate autostart/"app quick freeze" layer. | Battery → **Don't optimize**; Settings → Apps → Autostart (or "Startup manager") → allow; disable any "sleep standby" / "quick freeze" entry for the app. |

Two universal gotchas, all brands:

- **Force-stop kills everything.** Settings → Apps → Force stop (and on
  some vendors, swiping the app out of Recents) puts the app in a state
  where Android delivers **no** background wakes until the member manually
  opens the app again. Members troubleshooting by force-stopping are
  disabling the very thing they're testing. On the swipe-happy brands
  (MIUI especially), use the recents-lock instead.
- **The trap resets.** OS updates, vendor "battery usage reviews", and
  periodic "we noticed this app runs in the background" nudge
  notifications can re-enable optimization. If a previously fine phone
  goes quiet, re-walk §2 before suspecting anything else.

The community-maintained [dontkillmyapp.com](https://dontkillmyapp.com) has
per-brand, per-OS-version walkthroughs with screenshots when the wording
above has drifted — vendors rename these screens constantly.

## 4. The network is part of "background"

A wake that fires on schedule still syncs nothing if the phone can't reach
the station at that moment:

- **The station is LAN-only.** Away from the community's Wi‑Fi there is
  nothing to sync — the phone catches up when it's back. This is by design;
  don't chase it as a bug.
- **Wi‑Fi sleep.** Some phones drop Wi‑Fi minutes into deep sleep and lean
  on mobile data — which can't reach the station. Symptom: phone quiet
  overnight on the shelf, instantly current when picked up. Look for a
  "keep Wi‑Fi on during sleep" / Wi‑Fi power-saving setting (location
  varies; some brands bundle it into the battery manager).
- **Guest/isolated Wi‑Fi.** Client isolation blocks phone→station traffic
  entirely (foreground too — this one shows up at pairing time already).
  Members must be on the same real network as the station.

## 5. Verifying a phone (the ten-minute drill)

Run this once per phone at onboarding, and again whenever someone reports
silence. It separates "misconfigured phone" from "normal cadence" in one
pass.

1. **Setup check:** §2 all done — notifications allowed, *Sync while the
   app is closed* on, battery Unrestricted, vendor trap cleared. In-app
   Settings → Notifications should show background sync enabled.
2. **Background the app** with Home (do **not** force-stop, do not swipe
   it away on MIUI-family phones), turn the screen off, leave the phone on
   the community Wi‑Fi.
3. **Queue an event from the station** — anything addressed to that member
   works; a vouch is the classic:

   ```sh
   rrn vouch <member-rrn1-address> --statement "background sync drill"
   ```

4. **Wait up to ~30 minutes** (one wake at the 15-minute floor plus OS
   slack). A local notification arriving = the backgrounded path works.
5. **The killed-app path, once per phone model:** reboot the phone, do
   *not* open the app, queue another event, wait again. A notification on
   a locked, never-opened-since-boot phone proves the whole chain —
   boot-time registration, headless wake, background credential, LAN
   reachability.
6. **Log the result.** Keep a simple roster note per phone: brand/model,
   date verified, which settings it needed beyond stock. The next phone of
   the same model onboards in a minute, and "worked when verified" is
   priceless when triaging later reports.

If step 4 or 5 fails, work §3's table and §4's network checks for that
brand, then re-run. For a phone that still fails, have the member open the
app — if a backlog of missed notifications appears immediately, wakes are
being suppressed (keep digging in the vendor's battery manager); if
nothing appears even in the foreground, it's not a background problem at
all — check pairing and Wi‑Fi (see
[`community-setup.md`](community-setup.md) troubleshooting).

## 6. Setting member expectations

Tell members plainly, once, at onboarding:

- Notifications while the app is closed arrive in **batches, up to half an
  hour behind** — that's the platform, not a fault. Time-critical checks
  (an expiring dispute-response window, a payment you're waiting on):
  open the app; that syncs instantly.
- **Off the community Wi‑Fi you're offline** — the app catches up when
  you're back in range.
- **Don't force-stop the app** or swipe it away to "save battery" — it
  costs almost nothing (one short network touch every 15+ minutes) and
  killing it turns off your notifications until you next open it.
- If your phone ever asks about the app "running in the background" or
  "using battery", answer **Allow / Keep** — the "optimization" it offers
  is what breaks your notifications.

## 7. iOS, for completeness

The pilot fleet is Android (sideloaded). On iOS the same drain code runs
under iOS Background App Refresh: there is no vendor app-killer zoo and no
background-network firewall, but iOS grants wakes purely opportunistically
(no 15-minute floor, no boot wake, no exemption to request), so cadence is
noticeably lazier and nothing here can improve it. The foreground behavior
is identical.

---

### Steward's one-glance checklist (per phone)

- [ ] Notification permission accepted; *Local notifications* on
- [ ] *Sync while the app is closed* on (member understood the trade-off)
- [ ] Battery → **Unrestricted** (accepted the in-app dialog)
- [ ] Vendor trap cleared per §3 (Samsung sleep lists / MIUI autostart+lock / EMUI app-launch / ColorOS autostart)
- [ ] Phone on the real community Wi‑Fi (not guest/isolated)
- [ ] Drill passed: backgrounded notification (§5.4)
- [ ] Drill passed once per model: post-reboot notification (§5.5)
- [ ] Roster note written
