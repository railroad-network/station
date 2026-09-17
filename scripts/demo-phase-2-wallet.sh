#!/usr/bin/env bash
#
# demo-phase-2-wallet.sh — the ADR-0028 self-custody CLI member wallet, end to
# end, with real binaries.
#
# One `station` daemon (the operator) and one **laptop member** who holds their
# own key and runs `rrn wallet` — no smartphone. The member pairs and syncs over
# the sealed channel, confirms a payment while offline, prints it to QR sheets, a
# courier carries them to the station (a file copy), the station ingests them and
# hands back a delivery receipt the member applies, and finally the member pays
# some of it back online. Both balances settle.
#
# This is the human acceptance path for the CLI member wallet. macOS + Linux
# only; it does the release build for you.

set -euo pipefail

# --- configuration ----------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATION="$REPO_ROOT/target/release/station"
RRN="$REPO_ROOT/target/release/rrn"

STATION_PORT=7451
MOBILE_PORT=7452
WINDOW_SECONDS=8          # short settlement window so the demo doesn't drag
SWEEP_SECONDS=1
GOSSIP_SECONDS=60
PROPAGATION_TIMEOUT=30

export RRN_PASSPHRASE="demo-station-passphrase"
export RRN_WALLET_PASSPHRASE="demo-wallet-passphrase"
export RRN_LOG="${RRN_LOG:-warn}"

# --- scratch space + cleanup ------------------------------------------------

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rrn-wallet-demo.XXXXXX")"
OP_DIR="$WORKDIR/operator"
OP_SOCK="$OP_DIR/station.sock"
OP_PID=""
MEMBER="$WORKDIR/member"          # the laptop member's wallet home
PRINTED="$WORKDIR/printed"        # QR sheets the member prints
CARRIED="$WORKDIR/carried"        # what the courier physically moves
BACK="$WORKDIR/carryback"         # receipts headed back to the member

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

[mobile]
advertise = false
listen = "127.0.0.1:${MOBILE_PORT}"

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

wallet() { "$RRN" wallet --home "$MEMBER" "$@"; }

# --- 0. build ---------------------------------------------------------------

say "Building release binaries"
cargo build --release --bin station --bin rrn --manifest-path "$REPO_ROOT/Cargo.toml"

mkdir -p "$OP_DIR" "$PRINTED" "$CARRIED" "$BACK"

# --- 1. start the operator's station ----------------------------------------

say "Initializing and starting the operator's station"
OP_ADDR="$("$STATION" init --data-dir "$OP_DIR")"
write_config
"$STATION" run --data-dir "$OP_DIR" &
OP_PID=$!
for _ in $(seq 1 50); do [ -S "$OP_SOCK" ] && break; sleep 0.2; done
[ -S "$OP_SOCK" ] || { echo "station did not start" >&2; exit 1; }
echo "Operator station up: $OP_ADDR"

# --- 2. the member's laptop wallet ------------------------------------------

say "The member creates a wallet on their laptop, pinned to the station"
MEMBER_ADDR="$(wallet init --station "$OP_ADDR")"
echo "Member wallet: $MEMBER_ADDR"

say "The member pairs with the station over the sealed channel"
wallet pair --url "127.0.0.1:${MOBILE_PORT}"

say "The operator confirms the pairing in person (compares the SAS), then the member syncs"
"$STATION" pair-mobile "$MEMBER_ADDR" --data-dir "$OP_DIR"
wallet sync

# --- 3. the operator pays the member; the member confirms OFFLINE -----------

say "Operator vouches for the member and proposes a 3 Common payment"
"$RRN" --socket "$OP_SOCK" vouch "$MEMBER_ADDR" --statement "known good" >/dev/null
TX_ID="$("$RRN" --socket "$OP_SOCK" pay "$MEMBER_ADDR" 3.00 --memo "lunch")"
echo "Proposed transaction: $TX_ID"

say "The member confirms OFFLINE on the laptop (no station in reach)"
wallet confirm "$TX_ID"

say "The member prints the confirmation to QR sheets"
wallet export qr --out "$PRINTED"
ls -1 "$PRINTED"

# --- 4. carry → ingest → receipt → apply ------------------------------------

say "A courier carries the paper to the station (a file copy stands in)"
cp "$PRINTED/bundle.txt" "$CARRIED/bundle.txt"

say "The courier inspects the sheet before handing it over (needs no station)"
"$RRN" paper show --in "$CARRIED/bundle.txt"

say "The station scans and ingests the carried confirmation"
"$RRN" --socket "$OP_SOCK" paper ingest --in "$CARRIED/bundle.txt" --out "$BACK"

say "Operator exports the delivery receipt for the member to carry back"
"$RRN" --socket "$OP_SOCK" paper export-receipts --author "$MEMBER_ADDR" --out "$BACK"

say "The courier carries the receipt back; the member applies it"
wallet receipts apply --in "$BACK/receipts.txt"

# --- 5. the member pays some of it back, online -----------------------------

say "Waiting out the settlement window so the member's balance lands"
wait_for_balance "$MEMBER_ADDR" "3.00 Commons" "the member's balance after paper settlement"

say "The member pays 1 Common back — online this time — and submits it"
TX2="$(wallet pay "$OP_ADDR" 1.00 --memo "thanks")"
wallet submit
echo "Return transaction: $TX2"

say "The operator (the receiver) confirms the member's payment over its socket"
"$RRN" --socket "$OP_SOCK" confirm "$TX2"

say "Waiting out the settlement window for the return payment"
wait_for_balance "$MEMBER_ADDR" "2.00 Commons" "the member's balance after paying 1 back"

# --- 6. report --------------------------------------------------------------

say "Final balances"
printf 'Operator = %s\nMember   = %s\n' \
  "$("$RRN" --socket "$OP_SOCK" balance "$OP_ADDR")" \
  "$("$RRN" --socket "$OP_SOCK" balance "$MEMBER_ADDR")"

echo
echo "CLI member-wallet demo complete: a member with no phone held their own key,"
echo "confirmed a payment offline, carried it on paper, applied the receipt, and"
echo "paid some back online — operator -2.00, member +2.00 Commons."
