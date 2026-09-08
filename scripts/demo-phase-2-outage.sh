#!/usr/bin/env bash
#
# demo-phase-2-outage.sh — the Phase-2 exit criterion, narrated.
#
# Runs the 72-hour outage simulation harness (`outage_72h.rs`) for a single seed
# with narration on, so a human can watch the timeline (T0 normal ops → 72h
# connectivity loss over courier / paper / mock-LoRa channels → reconnect →
# settlement horizon) and see each of the nine exit invariants asserted in turn.
#
# This is the human-runnable cousin of `cargo test -p rrn-station --test
# outage_72h`; CI drives seeds {1,2,3} with narration off. Simulated time
# (injected clocks end to end) keeps the 72 hours to a few seconds of wall-clock.
#
# Usage:  scripts/demo-phase-2-outage.sh [SEED]   (SEED defaults to 1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEED="${1:-1}"

case "$SEED" in
  1) TEST="outage_72h_seed_1" ;;
  2) TEST="outage_72h_seed_2" ;;
  3) TEST="outage_72h_seed_3" ;;
  *)
    echo "This demo narrates one of the CI seeds. Usage: $0 [1|2|3]" >&2
    exit 2
    ;;
esac

cat <<'EOF'

########################################################################
#  Railroad Network — Phase 2 exit criterion (ADR-0017), executable.   #
#                                                                      #
#  A community of ~20 members and one station run through a 72-hour    #
#  full connectivity loss with realistic economic activity over every  #
#  offline channel, then reconnect, reconcile, and settle. The harness #
#  asserts — mechanically — full reconciliation, value conservation,   #
#  no ledger forks, and no credit limit violated.                      #
########################################################################
EOF

echo
echo "=== Running the outage simulation (seed $SEED), narrated ==="
echo

# `--nocapture` lets the harness's narration reach the terminal; the env var is
# what turns that narration on (the same test stays silent under plain `cargo test`).
RRN_OUTAGE_NARRATE=1 cargo test \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  -p rrn-station --test outage_72h "$TEST" \
  -- --exact --nocapture

echo
echo "=== Exit criterion demonstrated for seed $SEED. ==="
echo "Run the full gate (all seeds + determinism) with:"
echo "    cargo test -p rrn-station --test outage_72h"
echo "See docs/phase-2-exit-evidence.md for what this proves and what it does not."
