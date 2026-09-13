#!/usr/bin/env bash
#
# field-test-lora.sh — scripted radio field-acceptance run for two stations.
#
# Drives one signed bundle across a LoRa radio link and confirms its delivery
# receipt returns, printing PASS/FAIL per stage:
#
#     sender:   health checks → push a signed bundle to the peer over radio →
#               the peer's signed delivery receipt returns (push shows delivered)
#     receiver: health checks → the pushed bundle arrives and is ingested →
#               the station returns a signed receipt
#
# This is the software half of the field-acceptance checklist in
# docs/lora-radio-bringup.md §5. The radio hardware steps around it — flashing,
# antennas, spectrum compliance, placement — are the human's, per that runbook.
#
# SCOPE: this exercises the DTN bundle-push + receipt path (the "a signed record
# crosses A→B over radio and its receipt returns" check). A *full*
# propose→confirm→settle payment round-trip over radio additionally needs a
# station-side outbox export that does not exist yet (deferred to a later ticket:
# `rrn paper export-outbox` / a CLI wallet); supply the bundle to push with
# `--bundle` (e.g. one produced by the paper/mobile tooling) until then.
#
# TOPOLOGY: run one station on each of two machines (two `rnsd` instances cannot
# share one host's Reticulum control ports). Start each station yourself per the
# runbook, then run this script against the already-running station — it never
# spawns a daemon or a radio; it drives the one you point it at.
#
# Usage:
#   # On the receiver machine (prints its endpoint; waits for the bundle):
#   scripts/field-test-lora.sh --role receiver --data-dir /path/to/station-data
#
#   # On the sender machine (push a bundle to the receiver's endpoint):
#   scripts/field-test-lora.sh --role sender --data-dir /path/to/station-data \
#       --peer <rrn1… | reticulum-destination-hex> --bundle ./payload.bundle
#
#   scripts/field-test-lora.sh --dry-run     # rehearse the stages, no station/radio
#   scripts/field-test-lora.sh --help
#
# --dry-run exercises every stage and the pass/fail reporting WITHOUT a station,
# an `rnsd` sidecar, or a radio — so the script's own logic is CI-testable without
# hardware. It is what the `field_test_lora_dryrun` smoke test runs.
#
# macOS + Linux only.

set -euo pipefail

# --- argument handling ------------------------------------------------------

DRY_RUN=0
ROLE=""
PEER=""
BUNDLE=""
DATA_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --role) ROLE="${2:-}"; shift ;;
    --peer) PEER="${2:-}"; shift ;;
    --bundle) BUNDLE="${2:-}"; shift ;;
    --data-dir) DATA_DIR="${2:-}"; shift ;;
    -h|--help)
      # Print the leading comment block (everything after the shebang up to the
      # first non-comment line), with the `# ` prefix stripped.
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "unknown argument: $1 (see --help)" >&2
      exit 2
      ;;
  esac
  shift
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RRN="$REPO_ROOT/target/release/rrn"

# In dry-run the role is a rehearsal of the sender path (the fuller of the two).
if [ "$DRY_RUN" = 1 ]; then
  ROLE="${ROLE:-sender}"
else
  # --data-dir is required in real mode: it locates the running station's socket
  # and Reticulum config. Requiring it also keeps the arg arrays below non-empty,
  # which matters under `set -u` on macOS's bash 3.2.
  [ -n "$DATA_DIR" ] || { echo "real mode needs --data-dir <station-data-dir> (see --help)" >&2; exit 2; }
  case "$ROLE" in
    sender)
      [ -n "$PEER" ] || { echo "--role sender needs --peer <endpoint>" >&2; exit 2; }
      [ -n "$BUNDLE" ] || { echo "--role sender needs --bundle <file>" >&2; exit 2; }
      ;;
    receiver) ;;
    *)
      echo "--role must be 'sender' or 'receiver' (see --help)" >&2
      exit 2
      ;;
  esac
fi

# Radio is slow (single-digit bytes/second once the duty cycle bites), so a
# cross-node exchange can take minutes. Poll gently; budget generously.
DELIVERY_TIMEOUT=600       # max seconds to wait for a bundle + its receipt
POLL_SECONDS=5

# Socket + Reticulum config are derived from the running station's data dir when
# given; otherwise the `rrn` / `rnstatus` defaults are used.
SOCK_ARGS=()
RNSTATUS_ARGS=()
if [ -n "$DATA_DIR" ]; then
  SOCK_ARGS=(--socket "$DATA_DIR/station.sock")
  RNSTATUS_ARGS=(--config "$DATA_DIR/reticulum")
fi

export RRN_LOG="${RRN_LOG:-warn}"

# --- pass/fail bookkeeping --------------------------------------------------

STAGES_RUN=0
STAGES_FAILED=0

banner() { printf '\n=== %s ===\n' "$1"; }
progress() { printf '  … %s\n' "$1"; }

pass() {
  STAGES_RUN=$((STAGES_RUN + 1))
  printf '  [PASS] %s\n' "$1"
}
fail() {
  STAGES_RUN=$((STAGES_RUN + 1))
  STAGES_FAILED=$((STAGES_FAILED + 1))
  printf '  [FAIL] %s\n' "$1" >&2
}

# ------------------------------------------------------------------------------
# Stage helpers. Each short-circuits to a canned success under --dry-run, so the
# real and rehearsed paths share one control flow. Real bodies drive the running
# station's binaries; dry-run bodies never touch a station or a radio.
# ------------------------------------------------------------------------------

# The station daemon answers on its socket.
require_station_up() {
  if [ "$DRY_RUN" = 1 ]; then
    progress "[dry-run] would confirm the station daemon is up"
    return 0
  fi
  "$RRN" "${SOCK_ARGS[@]}" status >/dev/null 2>&1
}

# The radio interface is up (RNS reports an RNode interface for this station).
require_radio_up() {
  if [ "$DRY_RUN" = 1 ]; then
    progress "[dry-run] would confirm the RNode interface via rnstatus"
    return 0
  fi
  if ! command -v rnstatus >/dev/null 2>&1; then
    progress "rnstatus not found (install Reticulum: see the runbook prerequisites)"
    return 1
  fi
  # A healthy radio shows an RNode interface (by name or type); TCP-only would not.
  rnstatus "${RNSTATUS_ARGS[@]}" 2>/dev/null | grep -qi "rnode"
}

# Push a bundle to the peer over the DTN transport; echo the push id (or empty).
push_bundle() {
  if [ "$DRY_RUN" = 1 ]; then
    echo "dryrun-push-0001"
    return 0
  fi
  # `rrn dtn push` prints a line ending in the push id; grab the id token.
  "$RRN" "${SOCK_ARGS[@]}" dtn push --peer "$PEER" --bundle "$BUNDLE" 2>/dev/null \
    | grep -oE '[0-9a-f]{8,}' | head -1
}

# Wait until `rrn dtn status` shows the push delivered (its receipt correlated).
wait_for_delivered() {
  local push_id="$1"
  if [ "$DRY_RUN" = 1 ]; then
    progress "[dry-run] would wait for the delivery receipt to return over radio"
    return 0
  fi
  local deadline=$(( $(date +%s) + DELIVERY_TIMEOUT ))
  while :; do
    # The status line for a delivered push carries "delivered" (state) and a
    # bracketed receipt summary; match the push id and the delivered state.
    if "$RRN" "${SOCK_ARGS[@]}" dtn status 2>/dev/null \
        | grep -E "^${push_id:0:12}" | grep -qi "delivered"; then
      return 0
    fi
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    progress "waiting for the receipt over radio (up to ${DELIVERY_TIMEOUT}s)…"
    sleep "$POLL_SECONDS"
  done
}

# Receiver: derive and print the LXMF delivery destination hex the sender needs
# for `--peer`. It is the hash of the adapter's identity under the lxmf/delivery
# aspects (the adapter announces exactly this at startup); RNS derives it from the
# identity file the station keeps at <data_dir>/reticulum/adapter.identity.
print_receiver_endpoint() {
  if [ "$DRY_RUN" = 1 ]; then
    progress "[dry-run] would print this station's LXMF destination hex for the sender"
    return 0
  fi
  local ident="$DATA_DIR/reticulum/adapter.identity"
  if [ ! -f "$ident" ]; then
    progress "no adapter identity yet at $ident — start the station with the radio"
    progress "sidecar + adapter configured once, then re-run this role."
    return 1
  fi
  local py="${RRN_ADAPTER_PYTHON:-python3}"
  "$py" - "$ident" <<'PY'
import sys, RNS
ident = RNS.Identity.from_file(sys.argv[1])
print(RNS.Destination.hash(ident, "lxmf", "delivery").hex())
PY
}

# Receiver: wait until an inbound DTN-carried record lands in history. This keys
# on any growth in the history line count, so in a live community an unrelated
# local record could also satisfy it — fine for a supervised bench/field run where
# the pushed bundle is the only activity; tighten to a DTN-specific match if this
# is ever run against a busy station.
wait_for_inbound_record() {
  if [ "$DRY_RUN" = 1 ]; then
    progress "[dry-run] would wait for the pushed bundle to arrive and ingest"
    return 0
  fi
  local before after
  before="$("$RRN" "${SOCK_ARGS[@]}" history 2>/dev/null | wc -l | tr -d ' ')"
  local deadline=$(( $(date +%s) + DELIVERY_TIMEOUT ))
  while :; do
    after="$("$RRN" "${SOCK_ARGS[@]}" history 2>/dev/null | wc -l | tr -d ' ')"
    [ "${after:-0}" -gt "${before:-0}" ] && return 0
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    progress "waiting for an inbound bundle over radio (up to ${DELIVERY_TIMEOUT}s)…"
    sleep "$POLL_SECONDS"
  done
}

# ------------------------------------------------------------------------------
# The run.
# ------------------------------------------------------------------------------

cat <<EOF

########################################################################
#  Railroad Network — LoRa radio field-acceptance run.                 #
#  Role: ${ROLE}. A signed bundle crosses the radio and its receipt returns.
$( [ "$DRY_RUN" = 1 ] && echo "#  MODE: --dry-run (no station, no rnsd, no radio).                    #" )
########################################################################
EOF

# --- Stage 1 — health checks (both roles) -----------------------------------

banner "Stage 1 — health checks"
if require_station_up; then pass "the station daemon is up"; else fail "the station daemon is not answering"; fi
if require_radio_up; then pass "the radio interface is up"; else fail "the radio interface is not up"; fi

if [ "$ROLE" = "receiver" ]; then
  # --- Receiver: announce, then wait for the inbound bundle + auto-receipt. ---
  banner "Stage 2 — this station's endpoint (hand it to the sender)"
  ENDPOINT="$(print_receiver_endpoint || true)"
  if [ "$DRY_RUN" = 1 ]; then
    pass "endpoint published"
  elif [ -n "$ENDPOINT" ]; then
    printf '  LXMF destination hex: %s\n' "$ENDPOINT"
    printf '  Give the sender:  --peer %s\n' "$ENDPOINT"
    pass "endpoint derived"
  else
    fail "could not derive this station's endpoint (see the message above)"
  fi

  banner "Stage 3 — the pushed bundle arrives and is ingested over radio"
  if wait_for_inbound_record; then
    pass "an inbound bundle was ingested (the station returns its signed receipt automatically)"
  else
    fail "no inbound bundle arrived within ${DELIVERY_TIMEOUT}s"
  fi
else
  # --- Sender: push the bundle and wait for the receipt to return. ------------
  banner "Stage 2 — push the signed bundle to the peer over radio"
  # `|| true`: a failed push (bad bundle, no binding, no transport) must reach the
  # FAIL branch below, not abort the script under `set -e` / `pipefail`.
  PUSH_ID="$(push_bundle || true)"
  if [ -n "$PUSH_ID" ]; then pass "bundle queued for push ($PUSH_ID)"; else fail "the push was not accepted"; fi

  banner "Stage 3 — the delivery receipt returns over radio"
  if [ -n "$PUSH_ID" ] && wait_for_delivered "$PUSH_ID"; then
    pass "the peer's signed delivery receipt returned (push shows delivered)"
  else
    fail "no delivery receipt returned within ${DELIVERY_TIMEOUT}s"
  fi
fi

# --- summary ----------------------------------------------------------------

banner "Result"
if [ "$STAGES_FAILED" -eq 0 ]; then
  echo "ALL STAGES PASSED ($STAGES_RUN checks)."
  if [ "$DRY_RUN" = 1 ]; then
    echo "(dry run — nothing crossed a radio. Run on hardware with --role sender/receiver."
    echo " Record RSSI/SNR, sync latency, and retransmits per docs/lora-radio-bringup.md §5.)"
  fi
  exit 0
else
  echo "FAILED: $STAGES_FAILED of $STAGES_RUN checks did not pass." >&2
  exit 1
fi
