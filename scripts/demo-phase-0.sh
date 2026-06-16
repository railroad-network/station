#!/usr/bin/env bash
#
# demo-phase-0.sh — Phase 0, end to end, with real binaries.
#
# Brings up two independent `station` daemons on localhost (Alice and Bob), has
# Alice vouch for Bob and pay him 3 Commons, has Bob confirm, waits for the
# (deliberately short) settlement window to elapse, and prints both balances as
# seen by *both* stations. This is the human-runnable cousin of the in-process
# `two_station_e2e` integration test.
#
# macOS + Linux only. Requires a release build (the script does it for you).

set -euo pipefail

# --- configuration ----------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATION="$REPO_ROOT/target/release/station"
RRN="$REPO_ROOT/target/release/rrn"

ALICE_PORT=7411
BOB_PORT=7412
WINDOW_SECONDS=8          # short settlement window so the demo doesn't drag
SWEEP_SECONDS=1           # how often each station sweeps settlement
GOSSIP_SECONDS=1          # how often stations gossip
PROPAGATION_TIMEOUT=20    # max seconds to wait for any gossip step

export RRN_PASSPHRASE="demo-passphrase"   # non-interactive wallet unlock
export RRN_LOG="${RRN_LOG:-warn}"         # keep daemon logs quiet by default

# --- scratch space + cleanup ------------------------------------------------

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rrn-demo.XXXXXX")"
ALICE_DIR="$WORKDIR/alice"
BOB_DIR="$WORKDIR/bob"
ALICE_SOCK="$ALICE_DIR/station.sock"
BOB_SOCK="$BOB_DIR/station.sock"
ALICE_PID=""
BOB_PID=""

cleanup() {
  set +e
  [ -n "$ALICE_PID" ] && kill "$ALICE_PID" 2>/dev/null
  [ -n "$BOB_PID" ] && kill "$BOB_PID" 2>/dev/null
  [ -n "$ALICE_PID" ] && wait "$ALICE_PID" 2>/dev/null
  [ -n "$BOB_PID" ] && wait "$BOB_PID" 2>/dev/null
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

say() { printf '\n=== %s ===\n' "$1"; }

# Writes a station's config.toml: peer, listen port, short windows/timers.
write_config() {
  local dir="$1" listen_port="$2" peer_port="$3"
  cat >"$dir/config.toml" <<EOF
[peers]
list = ["127.0.0.1:${peer_port}"]

[network]
listen = "127.0.0.1:${listen_port}"

[settlement]
window_seconds = ${WINDOW_SECONDS}

[timers]
sweep_interval_secs = ${SWEEP_SECONDS}
gossip_interval_secs = ${GOSSIP_SECONDS}
EOF
}

# Polls a station's history until an entry of the given kind appears.
wait_for_kind() {
  local sock="$1" kind="$2" what="$3"
  local deadline=$(( $(date +%s) + PROPAGATION_TIMEOUT ))
  while :; do
    if "$RRN" --socket "$sock" history 2>/dev/null | grep -q "  ${kind} "; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out waiting for ${what}" >&2
      exit 1
    fi
    sleep 0.3
  done
}

# Polls until a station reports the expected balance for an address.
wait_for_balance() {
  local sock="$1" addr="$2" expected="$3" what="$4"
  local deadline=$(( $(date +%s) + PROPAGATION_TIMEOUT ))
  while :; do
    if [ "$("$RRN" --socket "$sock" balance "$addr" 2>/dev/null)" = "$expected" ]; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out waiting for ${what} (got: $("$RRN" --socket "$sock" balance "$addr" 2>/dev/null))" >&2
      exit 1
    fi
    sleep 0.3
  done
}

# --- 0. build ---------------------------------------------------------------

say "Building release binaries"
cargo build --release --bin station --bin rrn --manifest-path "$REPO_ROOT/Cargo.toml"

# --- 1. initialize two stations ---------------------------------------------

say "Initializing stations"
mkdir -p "$ALICE_DIR" "$BOB_DIR"
ALICE_ADDR="$("$STATION" init --data-dir "$ALICE_DIR")"
BOB_ADDR="$("$STATION" init --data-dir "$BOB_DIR")"
write_config "$ALICE_DIR" "$ALICE_PORT" "$BOB_PORT"
write_config "$BOB_DIR" "$BOB_PORT" "$ALICE_PORT"
echo "Alice: $ALICE_ADDR"
echo "Bob:   $BOB_ADDR"

# --- 2. start both daemons --------------------------------------------------

say "Starting daemons"
"$STATION" run --data-dir "$ALICE_DIR" &
ALICE_PID=$!
"$STATION" run --data-dir "$BOB_DIR" &
BOB_PID=$!

# Wait for both sockets to come up.
for _ in $(seq 1 50); do
  [ -S "$ALICE_SOCK" ] && [ -S "$BOB_SOCK" ] && break
  sleep 0.2
done
[ -S "$ALICE_SOCK" ] && [ -S "$BOB_SOCK" ] || { echo "daemons did not start" >&2; exit 1; }
echo "Both stations are up (Alice :$ALICE_PORT, Bob :$BOB_PORT)."

# --- 3. vouch ---------------------------------------------------------------

say "Alice vouches for Bob"
"$RRN" --socket "$ALICE_SOCK" vouch "$BOB_ADDR" --statement "known good"
wait_for_kind "$BOB_SOCK" "vouch" "the vouch to reach Bob"
echo "Bob's station received the vouch."

# --- 4. pay + confirm -------------------------------------------------------

say "Alice pays Bob 3 Commons"
TX_ID="$("$RRN" --socket "$ALICE_SOCK" pay "$BOB_ADDR" 3.00 --memo "lunch")"
echo "Proposed transaction: $TX_ID"
wait_for_kind "$BOB_SOCK" "proposal" "the proposal to reach Bob"

say "Bob confirms"
"$RRN" --socket "$BOB_SOCK" confirm "$TX_ID"
wait_for_kind "$ALICE_SOCK" "confirmation" "the confirmation to reach Alice"

# --- 5. settle --------------------------------------------------------------

say "Waiting out the ${WINDOW_SECONDS}s settlement window"
# Real wall-clock wait: the window is short by config. Each station's sweep
# timer settles once the window elapses; gossip carries the result across.
wait_for_balance "$ALICE_SOCK" "$BOB_ADDR" "3.00 Commons" "Bob's balance on Alice's station"
wait_for_balance "$BOB_SOCK" "$BOB_ADDR" "3.00 Commons" "Bob's balance on Bob's station"

# --- 6. report --------------------------------------------------------------

say "Final balances"
printf 'As seen by Alice:  Alice = %s, Bob = %s\n' \
  "$("$RRN" --socket "$ALICE_SOCK" balance "$ALICE_ADDR")" \
  "$("$RRN" --socket "$ALICE_SOCK" balance "$BOB_ADDR")"
printf 'As seen by Bob:    Alice = %s, Bob = %s\n' \
  "$("$RRN" --socket "$BOB_SOCK" balance "$ALICE_ADDR")" \
  "$("$RRN" --socket "$BOB_SOCK" balance "$BOB_ADDR")"

say "History (Alice's view)"
"$RRN" --socket "$ALICE_SOCK" history

echo
echo "Phase 0 demo complete. Both stations agree: Alice -3.00, Bob +3.00 Commons."
