#!/usr/bin/env bash
#
# demo-phase-2-outage.sh — the 72-hour outage simulation, narrated.
#
# Runs the outage simulation for a single scenario with narration turned on, so you
# can watch the timeline step by step: normal operations, then 72 simulated hours of
# activity over courier / paper / long-range-radio channels while connectivity is
# lost, then reconnect, reconcile, and settle — with each guarantee checked in turn.
#
# It is the human-narrated companion to the plain test run,
# `cargo test -p rrn-station --test outage_72h`. Simulated time keeps the whole
# 72-hour scenario to a few seconds of wall-clock.
#
# Usage:  scripts/demo-phase-2-outage.sh [SCENARIO]   (1, 2, or 3; defaults to 1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="${1:-1}"

case "$SEED" in
  1) TEST="outage_72h_seed_1" ;;
  2) TEST="outage_72h_seed_2" ;;
  3) TEST="outage_72h_seed_3" ;;
  *)
    echo "This demo runs one of the three scenarios. Usage: $0 [1|2|3]" >&2
    exit 2
    ;;
esac

cat <<'EOF'

########################################################################
#  Railroad Network — the 72-hour outage simulation.                   #
#                                                                      #
#  A community of ~20 members and one station run through a 72-hour    #
#  full connectivity loss with realistic economic activity over every  #
#  offline channel, then reconnect, reconcile, and settle — verifying  #
#  full reconciliation, value conservation, ledger integrity, and      #
#  that no credit limit is bypassed.                                   #
########################################################################
EOF

echo
echo "=== Running the outage simulation (scenario $SEED), narrated ==="
echo

# `--nocapture` lets the narration reach the terminal; the env var is what turns it
# on (the same test stays silent under a plain `cargo test`).
RRN_OUTAGE_NARRATE=1 cargo test \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p rrn-station --test outage_72h "$TEST" \
  -- --exact --nocapture

echo
echo "=== Simulation complete (scenario $SEED). ==="
echo "Run every scenario plus the reproducibility check with:"
echo "    cargo test -p rrn-station --test outage_72h"
echo "See docs/phase-2-exit-evidence.md for what this proves and what it does not."
