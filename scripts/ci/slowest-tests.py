#!/usr/bin/env python3
"""Rank tests by execution time and print two markdown tables.

Two input paths, one renderer — so the nextest run (JUnit) and the
libtest `--report-time` run (per-test JSON) produce byte-identical tables:

  slowest-tests.py <junit.xml> [N]   parse a cargo-nextest JUnit report
  slowest-tests.py --tsv [N]         read `exec_time<TAB>binary<TAB>test`
                                     records from stdin (the libtest path)

N is how many slowest tests to list (default 25). Both paths print:
  (a) per-binary totals, descending;
  (b) the N slowest individual tests;
  (c) the sum of all per-test times.

The per-test time is nextest's own per-test duration (one process per test)
in the JUnit path, and libtest's `exec_time` in the `--tsv` path; both are
close to the time spent inside the test and neither is a full-run wall-clock,
which on macOS is dominated by a per-binary first-exec stall (see the build
hygiene note in the repository conventions). stdlib only (xml.etree); no third-party deps, so
it runs anywhere python3 does.
"""

import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

DEFAULT_N = 25


def records_from_junit(path):
    """Yield (exec_time_seconds, binary, test_name) from a nextest JUnit file.

    nextest emits one <testsuite name="<binary-id>"> per test binary, whose
    <testcase> children carry the test name and a `time` attribute in seconds.
    """
    tree = ET.parse(path)
    root = tree.getroot()
    # The root may be <testsuites> (nextest) or a bare <testsuite>.
    suites = root.iter("testsuite")
    for suite in suites:
        binary = suite.get("name") or "?"
        for case in suite.iter("testcase"):
            name = case.get("name") or "?"
            try:
                t = float(case.get("time", "0"))
            except ValueError:
                t = 0.0
            yield (t, binary, name)


def records_from_tsv(stream):
    """Yield (exec_time_seconds, binary, test_name) from `time<TAB>bin<TAB>name`."""
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            t = float(parts[0])
        except ValueError:
            continue
        yield (t, parts[1], parts[2])


def render(records, n):
    records = list(records)
    per_binary = defaultdict(lambda: [0.0, 0])
    for t, binary, _name in records:
        per_binary[binary][0] += t
        per_binary[binary][1] += 1
    total = sum(t for t, _b, _n in records)

    out = []
    out.append(f"**{len(records)} tests, sum exec_time {total:.1f} s.**")
    out.append("")
    out.append("Per-binary totals (descending):")
    out.append("")
    out.append("| exec_time (s) | tests | binary |")
    out.append("|---:|---:|---|")
    for binary, (t, count) in sorted(
        per_binary.items(), key=lambda kv: kv[1][0], reverse=True
    ):
        out.append(f"| {t:.1f} | {count} | `{binary}` |")
    out.append("")
    out.append(f"{n} slowest tests:")
    out.append("")
    out.append("| exec_time (s) | binary | test |")
    out.append("|---:|---|---|")
    for t, binary, name in sorted(records, key=lambda r: r[0], reverse=True)[:n]:
        out.append(f"| {t:.2f} | `{binary}` | `{name}` |")
    out.append("")
    return "\n".join(out)


def main(argv):
    args = argv[1:]
    if args and args[0] == "--tsv":
        n = int(args[1]) if len(args) > 1 else DEFAULT_N
        recs = records_from_tsv(sys.stdin)
    elif args:
        path = args[0]
        n = int(args[1]) if len(args) > 1 else DEFAULT_N
        recs = records_from_junit(path)
    else:
        sys.stderr.write(
            "usage: slowest-tests.py <junit.xml> [N] | --tsv [N] < records\n"
        )
        return 2
    print(render(recs, n))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
