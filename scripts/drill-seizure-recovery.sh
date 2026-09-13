#!/usr/bin/env bash
#
# drill-seizure-recovery.sh — the ADR-0024 node-seizure recovery drill, and the
# operator drill referenced from docs/community-setup.md.
#
# Two profiles:
#
#   --profile plaintext   (runs on any platform, incl. macOS)
#       The platform-agnostic core of invariant 6: stand up a station, take an
#       ADR-0016 backup, "seize" it (delete the data dir), restore onto fresh
#       storage from the backup, and confirm the restored station is the same
#       identity with an intact, openable ledger — i.e. the community continues.
#
#   --profile encrypted   (Linux only — needs dm-crypt/cryptsetup/losetup + sudo)
#       Additionally provisions the encrypted profile (`station encrypt-in-place`)
#       and proves the BRICK PROPERTY: with the volume closed, a planted plaintext
#       marker appears NOWHERE in the raw container bytes or the unencrypted boot
#       dir — while a positive-control plaintext station DOES leak the same marker
#       (so the sweep is proven to detect plaintext at all). It also asserts the
#       LUKS header has ZERO keyslots (no wrapped key on the device).
#
# The interactive unlock ceremony (holder QR responses) and the crash/verify_chain
# invariants are exercised by the Rust lane `tests/at_rest_dmcrypt.rs`, which has
# the ceremony helpers a shell script cannot reconstruct.
#
# Usage:
#   scripts/drill-seizure-recovery.sh --profile plaintext
#   scripts/drill-seizure-recovery.sh --profile encrypted
#
set -euo pipefail

PROFILE="plaintext"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

MARKER="MEMBER-MEMO-DO-NOT-LEAK-$RANDOM$RANDOM"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/rrn-drill.XXXXXX")"
export RRN_PASSPHRASE="drill-passphrase"
STATION=""
MAPPING=""

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
info() { printf '  ....  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1" >&2; exit 1; }

cleanup() {
  # Best-effort teardown: unmount and close any dm-crypt mapping we opened.
  if [[ -n "$MAPPING" ]]; then
    sudo umount "$WORK/boot/state" 2>/dev/null || true
    sudo cryptsetup close "$MAPPING" 2>/dev/null || true
  fi
  # Detach any loop devices still pointing at our container.
  if [[ -f "$WORK/boot/state.img" ]]; then
    for d in $(losetup -j "$WORK/boot/state.img" 2>/dev/null | cut -d: -f1); do
      sudo losetup -d "$d" 2>/dev/null || true
    done
  fi
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

build_binaries() {
  info "building station + rrn (release-off, debug)"
  ( cd "$ROOT" && cargo build -q -p rrn-station -p rrn-cli )
  STATION="$ROOT/target/debug/station"
  [[ -x "$STATION" ]] || fail "station binary not found at $STATION"
}

# Generate a throwaway rrn1… address by initialising a scratch station.
new_address() {
  local d; d="$(mktemp -d "$WORK/holder.XXXXXX")"
  "$STATION" --data-dir "$d" init 2>/dev/null | head -n1
}

drill_plaintext() {
  local BOOT="$WORK/plain"
  info "init a station at $BOOT"
  local addr; addr="$("$STATION" --data-dir "$BOOT" init | head -n1)"
  [[ -n "$addr" ]] || fail "init produced no address"
  pass "station initialised: $addr"

  # Plant a known plaintext marker in a companion file that a backup carries.
  printf '{"mobiles":[],"note":"%s"}' "$MARKER" > "$BOOT/paired_mobiles.json"

  info "take an ADR-0016 backup"
  local archive="$WORK/backup.rrnbak"
  "$STATION" --data-dir "$BOOT" backup --out "$archive" >/dev/null
  [[ -s "$archive" ]] || fail "backup archive is empty"
  pass "backup written ($(wc -c < "$archive") bytes)"

  info "SEIZE: delete the entire data dir"
  rm -rf "$BOOT"
  [[ ! -e "$BOOT" ]] || fail "seize did not remove the data dir"
  pass "data dir gone"

  info "restore onto fresh storage from the backup"
  local dest="$WORK/restored"
  local restored; restored="$("$STATION" --data-dir "$dest" restore "$archive" | head -n1)"
  [[ "$restored" == "$addr" ]] || fail "restored identity $restored != original $addr"
  pass "restored the same identity: $restored"
  [[ -f "$dest/station.db" ]] || fail "restored ledger missing"
  [[ -f "$dest/wallet.rrnwallet" ]] || fail "restored wallet missing"
  # The wallet still opens under the same passphrase (proven by a second backup).
  "$STATION" --data-dir "$dest" backup --out "$WORK/rebackup.rrnbak" >/dev/null \
    || fail "restored station's wallet does not open under the passphrase"
  pass "restored ledger + wallet intact; community continues"

  echo
  pass "PLAINTEXT SEIZURE-RECOVERY DRILL GREEN"
}

require_linux_tools() {
  [[ "$(uname -s)" == "Linux" ]] || fail \
    "the encrypted profile requires Linux dm-crypt (ADR-0024); run on the CI lane or a Linux host, or use --profile plaintext"
  for t in cryptsetup losetup mkfs.ext4; do
    command -v "$t" >/dev/null 2>&1 || fail "missing required tool: $t"
  done
  sudo -n true 2>/dev/null || fail "passwordless sudo is required for the encrypted drill"
}

drill_encrypted() {
  require_linux_tools
  local BOOT="$WORK/boot"
  info "init a plaintext station to migrate"
  "$STATION" --data-dir "$BOOT" init >/dev/null
  # Plant the marker in a companion file that migrates INTO the container.
  printf '{"mobiles":[],"note":"%s"}' "$MARKER" > "$BOOT/paired_mobiles.json"

  info "generate 3 VMK holder addresses"
  local h1 h2 h3; h1="$(new_address)"; h2="$(new_address)"; h3="$(new_address)"
  [[ -n "$h1$h2$h3" ]] || fail "could not generate holder addresses"

  info "encrypt-in-place (provision keyslot-less LUKS2 container + arm VMK 2-of-3)"
  "$STATION" --data-dir "$BOOT" encrypt-in-place \
      --holder "$h1" --holder "$h2" --holder "$h3" --threshold 2 >/dev/null
  [[ -f "$BOOT/state.img" ]] || fail "container was not provisioned"
  [[ -f "$BOOT/vmk.descriptor" ]] || fail "VMK descriptor not written"
  MAPPING="$(findmnt -no SOURCE "$BOOT/state" 2>/dev/null | sed 's#/dev/mapper/##')"
  pass "migrated; container mounted via mapping ${MAPPING:-?}"

  # The marker is present in the mounted (decrypted) view…
  grep -raq "$MARKER" "$BOOT/state" || fail "marker not found inside the mounted volume"
  pass "marker present inside the decrypted volume (as expected)"

  info "SEIZE: power off — unmount + close the dm-crypt mapping"
  sudo umount "$BOOT/state"
  sudo cryptsetup close "$MAPPING"
  MAPPING=""
  rmdir "$BOOT/state" 2>/dev/null || true

  info "BRICK SWEEP: the marker must appear nowhere at rest"
  # Sweep the raw container bytes and every file on the unencrypted boot dir.
  if grep -raq "$MARKER" "$BOOT/state.img"; then
    fail "plaintext marker LEAKED into the container bytes — not a brick!"
  fi
  # Everything on the boot dir except (self-evidently) nothing should carry it.
  if grep -raq "$MARKER" "$BOOT" --exclude=state.img; then
    fail "plaintext marker LEAKED onto the unencrypted boot dir"
  fi
  pass "no plaintext marker in the container or boot dir"

  info "POSITIVE CONTROL: the same sweep DOES find the marker in a plaintext station"
  local PLAIN="$WORK/control"
  "$STATION" --data-dir "$PLAIN" init >/dev/null
  printf '{"mobiles":[],"note":"%s"}' "$MARKER" > "$PLAIN/paired_mobiles.json"
  grep -raq "$MARKER" "$PLAIN" || fail "positive control failed — the sweep cannot detect plaintext!"
  pass "sweep detects plaintext in the control (so the brick result is meaningful)"

  info "assert the LUKS header has ZERO keyslots (no wrapped key on the device)"
  local slots
  slots="$(sudo cryptsetup luksDump --dump-json-metadata "$BOOT/state.img" \
            | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("keyslots",{})))' 2>/dev/null || echo -1)"
  [[ "$slots" == "0" ]] || fail "LUKS header has $slots keyslot(s); expected 0"
  pass "LUKS header has zero keyslots — the VMK is the only way in"

  echo
  pass "ENCRYPTED BRICK-PROPERTY DRILL GREEN"
  info "the unlock ceremony + crash/verify_chain invariants run in tests/at_rest_dmcrypt.rs"
}

echo "Railroad Network — node-seizure recovery drill (profile: $PROFILE)"
build_binaries
case "$PROFILE" in
  plaintext) drill_plaintext ;;
  encrypted) drill_encrypted ;;
  *) fail "unknown profile: $PROFILE (use plaintext or encrypted)" ;;
esac
