#!/usr/bin/env python3
"""Regenerate NGINX_TEST_PROGRESS.md from results.tsv.

Reads env vars:
  RESULTS_TSV  — path to TSV (status \\t file \\t failed \\t total \\t reason)
  OUT_MD       — path to NGINX_TEST_PROGRESS.md to overwrite
  TODAY, NGINX_TESTS_REV — optional; recorded in the header when set
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict


# Files whose failures are, wholly or in part, ruxen's HTTP/2 following
# RFC 9113 / RFC 7541 where nginx doesn't (decided 2026-10-21, #347). Shown
# next to the file in the failing list; the issues that cover the rest are
# named too. Keep in step with the sweep: drop an entry once its file passes.
NOTES = {
    "h2_error_page.t": "by design: RFC 9113, #347",
    "h2_headers.t": "by design: RFC 9113 and 7541, #347; frames over the announced size, #506",
    "h2_host.t": "by design: RFC 9113, #347",
    "h2_keepalive.t": "by design: the two-step GOAWAY, #347",
    "h2_priority.t": "by design: priorities ignored, as RFC 9113 deprecates them, #347",
    "h2_request_body.t": "by design: Content-Length mismatches, the WINDOW_UPDATE size "
    "and a malformed request's 400, #347",
    "h2_request_body_preread.t": "by design: #347",
}


def read_results(path: str) -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            while len(parts) < 5:
                parts.append("")
            rows.append(tuple(parts[:5]))  # type: ignore[arg-type]
    return rows


def main() -> int:
    tsv = os.environ["RESULTS_TSV"]
    out = os.environ["OUT_MD"]

    rows = read_results(tsv)

    passing = sorted(name for status, name, *_ in rows if status == "PASS")
    failing = sorted(
        (name, failed, total)
        for status, name, failed, total, _reason in rows
        if status in ("FAIL", "TIMEOUT")
    )
    skipped_by_reason: dict[str, list[str]] = defaultdict(list)
    for status, name, _f, _t, reason in rows:
        if status == "SKIP":
            skipped_by_reason[reason].append(name)

    total_files = len(rows)
    n_pass = len(passing)
    n_fail = len(failing)
    n_skip = sum(len(v) for v in skipped_by_reason.values())

    parts: list[str] = []
    parts.append("# nginx-tests Progress (compat profile)\n\n")

    parts.append(
        "Reproduce: `scripts/run_nginx_tests.sh` (or `--update-progress` to regenerate this file). "
        "The script runs every `.t` file sequentially against `target/release/ruxen` "
        "and writes per-file logs under `.nginx-tests-out/logs/`. "
        "Run files sequentially — running the suite in parallel introduces flakes from "
        "shared TLS-session-cache / port races and gives false negatives.\n\n"
    )

    rev = os.environ.get("NGINX_TESTS_REV")
    if rev:
        parts.append(f"Last run: {os.environ.get('TODAY', 'unknown')} against `nginx-tests` {rev}.\n\n")

    parts.append("## Summary\n\n")
    parts.append(f"- **Total tests tracked:** {total_files}\n")
    parts.append(f"- **Passing in ruxen:** {n_pass}\n")
    parts.append(f"- **Intentionally skipped (`-V` banner excludes the module):** {n_skip}\n")
    parts.append(f"- **Failing — work in progress:** {n_fail}\n\n")
    parts.append(f"The three groups below are mutually exclusive and sum to {total_files}.\n\n")

    parts.append(f"## Passing in ruxen ({n_pass})\n\n")
    parts.append(
        "Tests where ruxen passes the upstream `Test::Nginx` suite end-to-end "
        "(sequential `prove`, `TEST_NGINX_BINARY=$PWD/target/release/ruxen`, "
        "`RUXEN_NGINX_IDENTITY=1`).\n\n"
    )
    for name in passing:
        parts.append(f"- `{name}`\n")
    parts.append("\n")

    parts.append(f"## Failing — actively being worked on ({n_fail})\n\n")
    parts.append(
        "Tests that ran (not skipped by `has_module`) but produced at least one failed assertion "
        "or non-zero exit. The fraction is **failed subtests / total subtests** "
        "(`0/0` means harness died during setup before reaching the plan; `0/N` means subtests "
        "passed but the file exited non-zero — typically `-t` config check).\n\n"
    )
    parts.append(
        "**HTTP/2 follows the RFCs where nginx doesn't (decided 2026-10-21, #347).** ruxen is a "
        "drop-in replacement for nginx, and a product of its own: where nginx's HTTP/2 is more "
        "lenient than RFC 9113 and RFC 7541, or answers with other error codes, ruxen keeps the "
        "RFC behaviour of the `h2` crate. A malformed request is a stream error (RST_STREAM), "
        "not a 400; HPACK and frame errors get the RFC's GOAWAY codes; Huffman padding longer "
        "than 7 bits is refused; a graceful GOAWAY comes in two steps; priorities are ignored. "
        "Real clients don't depend on any of these. nginx-tests checks of them fail on purpose: "
        "the files marked *by design* below fail only for that, or name the issues behind the "
        "rest.\n\n"
    )
    for name, failed, total in failing:
        note = NOTES.get(name)
        suffix = f"; {note}" if note else ""
        parts.append(f"- `{name}` — {failed}/{total}{suffix}\n")
    parts.append("\n")

    parts.append(f"## Intentionally skipped ({n_skip})\n\n")
    parts.append(
        "These test files call `has_module(...)` (or similar guards) that fail against ruxen's "
        "pinned `-V` banner — so the entire file is skipped before any subtest runs. They are "
        "out of scope for the current compat profile and intentional, not regressions. Grouped "
        "below by skip reason; the leading count is the number of test files in that group.\n\n"
    )
    # Sort reasons by group size desc, then by reason text asc.
    reasons_sorted = sorted(
        skipped_by_reason.items(), key=lambda kv: (-len(kv[1]), kv[0])
    )
    for reason, names in reasons_sorted:
        parts.append(f"### {reason} ({len(names)})\n\n")
        for name in sorted(names):
            parts.append(f"- `{name}`\n")
        parts.append("\n")

    with open(out, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))

    return 0


if __name__ == "__main__":
    sys.exit(main())
