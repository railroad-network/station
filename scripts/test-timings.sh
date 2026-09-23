#!/usr/bin/env bash
#
# Rank the test suite by per-test time and write a markdown report, per binary
# and per test. Two modes:
#
#   scripts/test-timings.sh nextest [nextest args…]
#       Runs `cargo nextest run --workspace --profile default`, parses the
#       JUnit report, prints per-binary totals + the slowest tests + the sum.
#       The normal path.
#
#   scripts/test-timings.sh libtest [cargo test args…]
#       The nextest-free path, for hosts where nextest's `--list` stalls
#       (macOS with a huge target/debug/deps — see the "Local build hygiene"
#       note in the repository conventions; inside a sandbox nextest can hang indefinitely).
#       Enumerates the test executables with `cargo test --no-run`, then runs
#       each with libtest's own `--report-time --format=json`.
#       `RUSTC_BOOTSTRAP=1` only unlocks libtest's flag parser at run time — it
#       compiles nothing and changes no code. Works on stable.
#
# Both modes report a per-test time (nextest's per-test duration, or libtest's
# exec_time), not full-run wall-clock: on macOS a per-binary first-exec stall
# dominates wall-clock. Reports are written under target/test-timings/.
#
# Env: TIMINGS_N — how many slowest tests to list (default 25).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PARSER="$SCRIPT_DIR/ci/slowest-tests.py"
N="${TIMINGS_N:-25}"

mode="${1:-}"
if [ -z "$mode" ]; then
  echo "usage: test-timings.sh nextest [nextest args…] | libtest [cargo test args…]" >&2
  exit 2
fi
shift || true

ts="$(date +%Y%m%d-%H%M%S)"
outdir="$REPO_ROOT/target/test-timings"
mkdir -p "$outdir"
out="$outdir/${mode}-${ts}.md"

cd "$REPO_ROOT"

case "$mode" in
  nextest)
    junit="$REPO_ROOT/target/nextest/default/junit.xml"
    # Delete any prior report first, so a run that fails before writing a fresh
    # one (build error, or an interrupt at the --list stall) can never be
    # mistaken for a new measurement — the file-existence check below then
    # aborts instead of printing stale numbers.
    rm -f "$junit"
    # SLOW warnings are expected and test failures still produce a JUnit file,
    # so don't let a non-zero exit abort the report; warn if it was non-zero.
    if ! cargo nextest run --workspace --profile default "$@"; then
      echo "note: nextest exited non-zero (test failures?) — report reflects what it wrote" >&2
    fi
    if [ ! -f "$junit" ]; then
      echo "no JUnit report at $junit — did nextest fail to build?" >&2
      exit 1
    fi
    {
      echo "# test-timings (nextest) — $ts"
      echo
      python3 "$PARSER" "$junit" "$N"
    } | tee "$out"
    ;;

  libtest)
    # Default to the whole workspace, but let the caller narrow with e.g.
    # `-p rrn-crypto` or `--test <name>` (passing --workspace too would clash).
    if [ "$#" -eq 0 ]; then
      set -- --workspace
    fi
    # Enumerate test executables (no run). Emit: <exe>\t<label>\t<manifest_dir>.
    enum="$(cargo test --no-run --message-format=json "$@" \
      | python3 -c '
import json, os, sys
for line in sys.stdin:
    line = line.strip()
    if not line or line[0] != "{":
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact":
        continue
    prof = m.get("profile") or {}
    if not prof.get("test"):
        continue
    exe = m.get("executable")
    if not exe:
        continue
    tgt = m.get("target") or {}
    # package_id is a URL: "path+file:///…/rrn-crypto#0.1.0" or
    # "path+file:///…#rrn-crypto@0.1.0". Pull out just the crate name.
    pid = m.get("package_id") or "?"
    frag = pid.split("#")[-1]
    if "@" in frag:
        pkgname = frag.split("@")[0]
    else:
        pkgname = pid.split("#")[0].rstrip("/").split("/")[-1]
    kinds = tgt.get("kind") or []
    label = pkgname + (" (lib)" if "lib" in kinds else "::" + (tgt.get("name") or "?"))
    # The crate directory (where `cargo test` runs the binary) is the dir of
    # the package manifest — exact for every target kind, incl. src/bin/*.
    manifest = m.get("manifest_path") or ""
    mdir = os.path.dirname(manifest) if manifest else "."
    print("\t".join([exe, label, mdir]))
')"

    tsv="$(mktemp)"
    trap 'rm -f "$tsv"' EXIT
    while IFS=$'\t' read -r exe label mdir; do
      [ -n "$exe" ] || continue
      [ -d "$mdir" ] || mdir="$REPO_ROOT"
      # Run from the crate directory; --report-time/--format=json are libtest
      # unstable options unlocked by RUSTC_BOOTSTRAP at run time only. Redirect
      # stdin from /dev/null so a test that reads stdin cannot swallow the
      # remaining enumerated lines of the here-string driving this loop.
      ( cd "$mdir" && RUSTC_BOOTSTRAP=1 "$exe" -Z unstable-options --report-time --format=json </dev/null 2>/dev/null || true ) \
        | LABEL="$label" python3 -c '
import json, os, sys
label = os.environ["LABEL"]
for line in sys.stdin:
    line = line.strip()
    if not line or line[0] != "{":
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("type") != "test" or m.get("event") not in ("ok", "failed"):
        continue
    et = m.get("exec_time")
    if et is None:
        continue
    print("%f\t%s\t%s" % (float(et), label, m.get("name", "?")))
' >> "$tsv"
    done <<< "$enum"

    {
      echo "# test-timings (libtest) — $ts"
      echo
      python3 "$PARSER" --tsv "$N" < "$tsv"
    } | tee "$out"
    ;;

  *)
    echo "unknown mode '$mode' (expected: nextest | libtest)" >&2
    exit 2
    ;;
esac

echo
echo "wrote $out"
