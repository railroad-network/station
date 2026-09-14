#!/usr/bin/env bash
#
# demo-phase-0.sh — a community's writer + a read-replica, end to end, with real
# binaries.
#
# A community has exactly one *writer* station — it owns the log and admits
# records at its front door — and any number of *replicas*, read-only copies that
# pull the writer's chain and re-derive state but admit nothing (ADR-0020 §1/§7,
# and its T2.11.4 Clarification: the writer never pulls; a replica never admits).
#
# This demo brings up:
#   - a WRITER station (the community's station), with no peers, and
#   - a REPLICA of it (a warm second copy, e.g. for audit/backup), and
#   - one offline MEMBER (Bob), played by the `paper-phone-sim` example over the
#     real mobile wire types.
#
# The writer vouches for Bob and pays him 3 Commons; Bob confirms OFFLINE and his
# confirmation reaches the writer on paper (a file copy stands in for the
# courier); the writer settles. The replica then shows it holds a byte-identical
# copy of the writer's chain — and refuses any write, because a replica never
# admits. This is the human-runnable cousin of the `two_station_e2e` integration
# test.
#
# macOS + Linux only. Requires a release build (the script does it for you).

set -euo pipefail

# --- configuration ----------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATION="$REPO_ROOT/target/release/station"
RRN="$REPO_ROOT/target/release/rrn"
PHONE="$REPO_ROOT/target/release/examples/paper_phone_sim"

WRITER_PORT=7411
WINDOW_SECONDS=8          # short settlement window so the demo doesn't drag
SWEEP_SECONDS=1           # how often the writer sweeps settlement
GOSSIP_SECONDS=1          # how often the replica pulls
PROPAGATION_TIMEOUT=20    # max seconds to wait for any replication step

export RRN_PASSPHRASE="demo-passphrase"   # non-interactive wallet unlock
export RRN_LOG="${RRN_LOG:-warn}"         # keep daemon logs quiet by default

# --- scratch space + cleanup ------------------------------------------------

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rrn-demo.XXXXXX")"
WRITER_DIR="$WORKDIR/writer"
REPLICA_DIR="$WORKDIR/replica"
WRITER_SOCK="$WRITER_DIR/station.sock"
REPLICA_SOCK="$REPLICA_DIR/station.sock"
CARRIED="$WORKDIR/carried"        # what the courier physically moves
PHONE_KEY="$WORKDIR/phone.key"
WRITER_PID=""
REPLICA_PID=""

cleanup() {
  set +e
  [ -n "$WRITER_PID" ] && kill "$WRITER_PID" 2>/dev/null
  [ -n "$REPLICA_PID" ] && kill "$REPLICA_PID" 2>/dev/null
  [ -n "$WRITER_PID" ] && wait "$WRITER_PID" 2>/dev/null
  [ -n "$REPLICA_PID" ] && wait "$REPLICA_PID" 2>/dev/null
  rm -rf "$WORKDIR"
}
trap cleanup EXIT INT TERM

say() { printf '\n=== %s ===\n' "$1"; }

# The writer's config: no peers (a writer never pulls), a fixed listen port so
# the replica can dial it, short windows/timers.
write_writer_config() {
  cat >"$WRITER_DIR/config.toml" <<EOF
[network]
listen = "127.0.0.1:${WRITER_PORT}"
role = "writer"

[mobile]
advertise = false
listen = "127.0.0.1:0"

[settlement]
window_seconds = ${WINDOW_SECONDS}

[timers]
sweep_interval_secs = ${SWEEP_SECONDS}
EOF
}

# The replica's config: it pulls the writer, binds an ephemeral port, runs no
# sweep timers (it re-derives, never admits).
write_replica_config() {
  cat >"$REPLICA_DIR/config.toml" <<EOF
[peers]
list = ["127.0.0.1:${WRITER_PORT}"]

[network]
listen = "127.0.0.1:0"
role = "replica"

[mobile]
advertise = false
listen = "127.0.0.1:0"

[settlement]
window_seconds = ${WINDOW_SECONDS}

[timers]
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

# Polls until the writer reports the expected balance for an address.
wait_for_balance() {
  local addr="$1" expected="$2" what="$3"
  local deadline=$(( $(date +%s) + PROPAGATION_TIMEOUT ))
  while :; do
    if [ "$("$RRN" --socket "$WRITER_SOCK" balance "$addr" 2>/dev/null)" = "$expected" ]; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "timed out waiting for ${what} (got: $("$RRN" --socket "$WRITER_SOCK" balance "$addr" 2>/dev/null))" >&2
      exit 1
    fi
    sleep 0.3
  done
}

# --- 0. build ---------------------------------------------------------------

say "Building release binaries"
cargo build --release --bin station --bin rrn --manifest-path "$REPO_ROOT/Cargo.toml"
cargo build --release --example paper_phone_sim --manifest-path "$REPO_ROOT/Cargo.toml"

# --- 1. initialize the writer and its replica -------------------------------

say "Initializing the writer and a read-replica"
mkdir -p "$WRITER_DIR" "$REPLICA_DIR" "$CARRIED"
WRITER_ADDR="$("$STATION" init --data-dir "$WRITER_DIR")"
"$STATION" init --data-dir "$REPLICA_DIR" >/dev/null
write_writer_config
write_replica_config
echo "Writer:  $WRITER_ADDR"

# --- 2. start both daemons --------------------------------------------------

say "Starting the writer and the replica"
"$STATION" run --data-dir "$WRITER_DIR" &
WRITER_PID=$!
"$STATION" run --data-dir "$REPLICA_DIR" &
REPLICA_PID=$!

for _ in $(seq 1 50); do
  [ -S "$WRITER_SOCK" ] && [ -S "$REPLICA_SOCK" ] && break
  sleep 0.2
done
[ -S "$WRITER_SOCK" ] && [ -S "$REPLICA_SOCK" ] || { echo "daemons did not start" >&2; exit 1; }
echo "Both stations are up (writer :$WRITER_PORT, replica pulling from it)."
echo "Replica role, per its own status:"
"$RRN" --socket "$REPLICA_SOCK" status | grep -E '^role:' || true

# --- 3. the offline member --------------------------------------------------

say "Creating the member's phone identity (offline)"
BOB_ADDR="$("$PHONE" gen-key "$PHONE_KEY")"
echo "Member (Bob): $BOB_ADDR"

# --- 4. vouch + pay (on the writer) -----------------------------------------

say "The writer vouches for Bob and proposes a 3 Common payment"
"$RRN" --socket "$WRITER_SOCK" vouch "$BOB_ADDR" --statement "known good" >/dev/null
TX_ID="$("$RRN" --socket "$WRITER_SOCK" pay "$BOB_ADDR" 3.00 --memo "lunch")"
echo "Proposed transaction: $TX_ID"

# --- 5. Bob confirms OFFLINE; the confirmation reaches the writer on paper ---

say "Bob confirms OFFLINE on the phone (no station in reach)"
"$PHONE" sign-confirmation "$PHONE_KEY" "$TX_ID" "$WORKDIR/payload.txt"

say "A courier carries the paper confirmation to the writer (a file copy stands in)"
cp "$WORKDIR/payload.txt" "$CARRIED/payload.txt"

say "The writer scans and ingests the carried confirmation"
"$RRN" --socket "$WRITER_SOCK" paper ingest --in "$CARRIED/payload.txt" >/dev/null

# --- 6. a replica never admits ----------------------------------------------

say "The replica refuses to admit anything itself (it is a read-only copy)"
if "$RRN" --socket "$REPLICA_SOCK" vouch "$BOB_ADDR" --statement "should be refused" 2>"$WORKDIR/replica.err"; then
  echo "ERROR: the replica admitted a write; it must refuse (ADR-0020 §7)" >&2
  exit 1
fi
echo "Refused, as expected:"
grep -i "read-replica" "$WORKDIR/replica.err" || cat "$WORKDIR/replica.err"

# --- 7. settle (on the writer) ----------------------------------------------

say "Waiting out the ${WINDOW_SECONDS}s settlement window (the writer sweeps)"
wait_for_balance "$BOB_ADDR" "3.00 Commons" "Bob's balance on the writer after settlement"

# --- 8. the replica converges on the writer's chain -------------------------

say "The replica pulls the writer's chain (settlement record included)"
wait_for_kind "$REPLICA_SOCK" "settlement" "the settlement to replicate to the replica"
echo "The replica now holds the settlement record — a faithful copy of the chain."

# --- 9. report --------------------------------------------------------------

say "Final balances (the writer's authoritative view)"
printf 'Writer = %s, Bob = %s\n' \
  "$("$RRN" --socket "$WRITER_SOCK" balance "$WRITER_ADDR")" \
  "$("$RRN" --socket "$WRITER_SOCK" balance "$BOB_ADDR")"

say "History (the replica's copy of the writer's chain)"
"$RRN" --socket "$REPLICA_SOCK" history

echo
echo "Demo complete: the writer admitted and settled a payment (writer -3.00,"
echo "Bob +3.00 Commons); the replica copied the chain and refused every write."
