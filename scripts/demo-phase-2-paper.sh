#!/usr/bin/env bash
#
# demo-phase-2-paper.sh — the M2.5 paper-fallback loop, end to end, with real
# binaries.
#
# One `station` daemon (the operator) and one offline member (a *phone*, played
# by the `paper-phone-sim` example over the real `rrn-mobile-ffi` wire types).
# The member confirms a payment while completely disconnected; the confirmation
# is turned into printable QR sheets, "carried" (a file copy), scanned back to
# text, ingested at the station, and the station's delivery receipt is carried
# back to the phone. No network path between the phone and the station exists —
# only paper.
#
# This is the human acceptance path for T2.5.2. macOS + Linux only; it does the
# release build for you.

set -euo pipefail

# --- configuration ----------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATION="$REPO_ROOT/target/release/station"
RRN="$REPO_ROOT/target/release/rrn"
PHONE="$REPO_ROOT/target/release/examples/paper_phone_sim"

STATION_PORT=7431
WINDOW_SECONDS=8          # short settlement window so the demo doesn't drag
SWEEP_SECONDS=1
GOSSIP_SECONDS=60
PROPAGATION_TIMEOUT=20

export RRN_PASSPHRASE="demo-passphrase"
export RRN_LOG="${RRN_LOG:-warn}"

# --- scratch space + cleanup ------------------------------------------------

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rrn-paper-demo.XXXXXX")"
OP_DIR="$WORKDIR/operator"
OP_SOCK="$OP_DIR/station.sock"
OP_PID=""

# The "physical" world: what gets printed, carried, and scanned.
PRINTED="$WORKDIR/printed"       # QR sheets the operator prints
CARRIED="$WORKDIR/carried"       # what the courier physically moves
BACK="$WORKDIR/carryback"        # receipts headed back to the phone
CARDS="$WORKDIR/cards"           # certificate / credential cards
PHONE_KEY="$WORKDIR/phone.key"

cleanup() {
  set +e
  [ -n "$OP_PID" ] && kill "$OP_PID" 2>/dev/null
  [ -n "$OP_PID" ] && wait "$OP_PID" 2>/dev/null
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

say() { printf '\n=== %s ===\n' "$1"; }

write_config() {
  cat >"$OP_DIR/config.toml" <<EOF
[peers]
list = []

[network]
listen = "127.0.0.1:${STATION_PORT}"

[settlement]
window_seconds = ${WINDOW_SECONDS}

[timers]
sweep_interval_secs = ${SWEEP_SECONDS}
gossip_interval_secs = ${GOSSIP_SECONDS}
EOF
}

wait_for_balance() {
  local addr="$1" expected="$2" what="$3"
  local deadline=$(( $(date +%s) + PROPAGATION_TIMEOUT ))
  while :; do
    if [ "$("$RRN" --socket "$OP_SOCK" balance "$addr" 2>/dev/null)" = "$expected" ]; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out waiting for ${what} (got: $("$RRN" --socket "$OP_SOCK" balance "$addr" 2>/dev/null))" >&2
      exit 1
    fi
    sleep 0.3
  done
}

# --- 0. build ---------------------------------------------------------------

say "Building release binaries + the phone stand-in"
cargo build --release --bin station --bin rrn --manifest-path "$REPO_ROOT/Cargo.toml"
cargo build --release --example paper_phone_sim -p rrn-station --manifest-path "$REPO_ROOT/Cargo.toml"

mkdir -p "$OP_DIR" "$PRINTED" "$CARRIED" "$BACK" "$CARDS"

# --- 1. start the operator's station ----------------------------------------

say "Initializing and starting the operator's station"
OP_ADDR="$("$STATION" init --data-dir "$OP_DIR")"
write_config
"$STATION" run --data-dir "$OP_DIR" &
OP_PID=$!
for _ in $(seq 1 50); do [ -S "$OP_SOCK" ] && break; sleep 0.2; done
[ -S "$OP_SOCK" ] || { echo "station did not start" >&2; exit 1; }
echo "Operator station up: $OP_ADDR"

# --- 2. the member's phone, entirely offline --------------------------------

say "Creating the member's phone identity (offline)"
PHONE_ADDR="$("$PHONE" gen-key "$PHONE_KEY")"
echo "Phone member: $PHONE_ADDR"

say "Operator vouches for the member and proposes a 3 Common payment"
"$RRN" --socket "$OP_SOCK" vouch "$PHONE_ADDR" --statement "known good" >/dev/null
TX_ID="$("$RRN" --socket "$OP_SOCK" pay "$PHONE_ADDR" 3.00 --memo "lunch")"
echo "Proposed transaction: $TX_ID"

say "The member confirms OFFLINE on the phone (no station in reach)"
"$PHONE" sign-confirmation "$PHONE_KEY" "$TX_ID" "$WORKDIR/payload.txt"

# --- 3. print → carry → inspect → ingest ------------------------------------

say "Operator prints the confirmation to QR sheets"
"$RRN" --socket "$OP_SOCK" paper render --in "$WORKDIR/payload.txt" --out "$PRINTED"
ls -1 "$PRINTED"

say "A courier carries the paper to the station (a file copy stands in)"
cp "$WORKDIR/payload.txt" "$CARRIED/payload.txt"

say "The courier inspects the sheet before handing it over (works with no station)"
"$RRN" paper show --in "$CARRIED/payload.txt"

say "The station scans and ingests the carried confirmation"
"$RRN" --socket "$OP_SOCK" paper ingest --in "$CARRIED/payload.txt" --out "$BACK"

say "Re-scanning the same sheet is idempotent (no double-spend)"
"$RRN" --socket "$OP_SOCK" paper ingest --in "$CARRIED/payload.txt"

# --- 4. receipts carried back to the phone ----------------------------------

say "Operator exports the delivery receipt for the member to carry back"
"$RRN" --socket "$OP_SOCK" paper export-receipts --author "$PHONE_ADDR" --out "$BACK"

say "The courier carries the receipt back; the phone reads it"
"$PHONE" read-receipt "$BACK/receipts.txt"

# --- 5. credential + certificate cards --------------------------------------

say "Operator prints the member's credential card (the bare address QR)"
"$RRN" paper credential --address "$PHONE_ADDR" --name "Member" --out "$CARDS"

say "Operator reserves and prints a headroom-certificate wallet card"
"$RRN" --socket "$OP_SOCK" paper cert --request 5 --out "$CARDS"
"$RRN" paper show --in "$CARDS/certificate.txt"

# --- 6. settle and report ---------------------------------------------------

say "Waiting out the ${WINDOW_SECONDS}s settlement window"
wait_for_balance "$PHONE_ADDR" "3.00 Commons" "the member's balance after paper settlement"

say "Final balances"
printf 'Operator = %s\nMember   = %s\n' \
  "$("$RRN" --socket "$OP_SOCK" balance "$OP_ADDR")" \
  "$("$RRN" --socket "$OP_SOCK" balance "$PHONE_ADDR")"

echo
echo "Paper-fallback demo complete: a payment confirmed offline, carried on"
echo "paper, ingested, receipted, and settled — operator -3.00, member +3.00 Commons."
