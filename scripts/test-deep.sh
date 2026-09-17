#!/usr/bin/env bash
# The deep lane: every property test at 1024 cases (PROPTEST_CASES overrides the
# fast per-test defaults). Slow by design; run before a release tag, on the
# weekly CI schedule, or when touching a property-tested invariant.
#
# With no arguments it runs the whole workspace. Any arguments are passed to
# nextest verbatim and REPLACE the default `--workspace` — so
# `scripts/test-deep.sh -p rrn-ledger --test cert_backed_spends` scopes the run
# (cargo silently ignores `-p` when `--workspace` is also present, so the two
# must not be combined).
set -euo pipefail
export PROPTEST_CASES="${PROPTEST_CASES:-1024}"
if [ "$#" -eq 0 ]; then
    set -- --workspace
fi
cargo nextest run "$@"
