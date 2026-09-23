#!/usr/bin/env bash
#
# Report the size and entry count of the build directory, and optionally sweep
# stale artifacts. A `target/debug/deps` that grows to ~1M entries / ~99 GB
# makes every freshly linked test binary stall 30-80 s before main() on the
# first exec on macOS — a fresh binary execs in < 1 s from any other
# directory, so the cause is that directory's accumulated size, not the
# binaries. Keep target/ trimmed to keep local test runs fast. See the
# "Local build hygiene" note in the repository conventions.
#
#   scripts/target-hygiene.sh           report du + deps entry count
#   scripts/target-hygiene.sh --sweep   also run `cargo sweep --time 14`
#                                        (needs `cargo install cargo-sweep --locked`)
#
# `cargo clean` is the sledgehammer; `cargo sweep --time 14` keeps artifacts
# touched in the last 14 days. This script never cleans without --sweep.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="$REPO_ROOT/target"

if [ ! -d "$TARGET" ]; then
  echo "no target/ directory at $TARGET (nothing built yet)"
  exit 0
fi

echo "target size:        $(du -sh "$TARGET" 2>/dev/null | cut -f1)"
if [ -d "$TARGET/debug/deps" ]; then
  # -f lists entries unsorted (no per-entry stat for ordering); fast even on a
  # huge directory. -U is a no-op harmless belt-and-suspenders across ls variants.
  count="$(/bin/ls -fU "$TARGET/debug/deps" 2>/dev/null | grep -cv '^\.\{1,2\}$' || true)"
  echo "debug/deps entries: $count"
  if [ "${count:-0}" -gt 300000 ]; then
    echo "  warning: debug/deps is large; a fresh test binary may stall on first exec (see the repository's 'Local build hygiene' note)."
    echo "  run: scripts/target-hygiene.sh --sweep   (or: cargo clean)"
  fi
fi

if [ "${1:-}" = "--sweep" ]; then
  if ! command -v cargo-sweep >/dev/null 2>&1; then
    echo "cargo-sweep not installed. Install it with: cargo install cargo-sweep --locked" >&2
    exit 1
  fi
  echo
  echo "sweeping artifacts older than 14 days…"
  ( cd "$REPO_ROOT" && cargo sweep --time 14 )
  echo "target size now:    $(du -sh "$TARGET" 2>/dev/null | cut -f1)"
fi
