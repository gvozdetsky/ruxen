#!/usr/bin/env bash
# Run every nginx-tests .t file against ruxen, sequentially, and (with
# --update-progress) regenerate NGINX_TEST_PROGRESS.md from the results.
#
# Output:
#   - summary printed to stdout
#   - per-file results in <out_dir>/results.tsv  (status, file, failed, total, reason)
#     status ∈ {PASS, FAIL, SKIP, TIMEOUT}
#   - per-file prove transcript in <out_dir>/logs/<name>.log
#
# Use --update-progress to overwrite NGINX_TEST_PROGRESS.md from the TSV.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TESTS_DIR="${REPO_ROOT}/../nginx-tests"
RUXEN_BIN="${REPO_ROOT}/target/release/ruxen"
OUT_DIR="${REPO_ROOT}/.nginx-tests-out"
PROGRESS_MD="${REPO_ROOT}/NGINX_TEST_PROGRESS.md"
TIMEOUT_SECS=120
BUILD_RELEASE=1
UPDATE_PROGRESS=0

usage() {
    cat <<'EOF'
Usage: scripts/run_nginx_tests.sh [options] [glob ...]

Runs every nginx-tests .t file against ruxen, sequentially. Captures
pass / skip (with reason) / fail (with subtest fraction) per file.

Options:
  --tests-dir <path>     nginx-tests checkout (default: ../nginx-tests)
  --binary <path>        ruxen binary (default: target/release/ruxen)
  --out-dir <path>       directory for results.tsv + per-file logs (default: .nginx-tests-out)
  --timeout <secs>       per-file timeout (default: 120)
  --no-build             skip cargo build --release
  --update-progress      rewrite NGINX_TEST_PROGRESS.md from results.tsv
  -h, --help             show this help

Examples:
  scripts/run_nginx_tests.sh
  scripts/run_nginx_tests.sh --no-build --update-progress
  scripts/run_nginx_tests.sh 'http_*.t' 'proxy_*.t'
EOF
}

die() { echo "error: $*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date -u +'%H:%M:%S')" "$*" >&2; }

declare -a FILE_PATTERNS=()

while (($# > 0)); do
    case "$1" in
        --tests-dir) TESTS_DIR="$2"; shift 2 ;;
        --binary) RUXEN_BIN="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --timeout) TIMEOUT_SECS="$2"; shift 2 ;;
        --no-build) BUILD_RELEASE=0; shift ;;
        --update-progress) UPDATE_PROGRESS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) FILE_PATTERNS+=("$1"); shift ;;
    esac
done

command -v prove >/dev/null 2>&1 || die "missing required command: prove"
[[ -d "${TESTS_DIR}" ]] || die "tests directory not found: ${TESTS_DIR}"
[[ -d "${TESTS_DIR}/lib" ]] || die "missing lib directory: ${TESTS_DIR}/lib"

if ((BUILD_RELEASE == 1)); then
    command -v cargo >/dev/null 2>&1 || die "missing required command: cargo"
    log "building ruxen release binary"
    (cd "${REPO_ROOT}" && cargo build --release) || die "cargo build failed"
fi

[[ -x "${RUXEN_BIN}" ]] || die "ruxen binary is not executable: ${RUXEN_BIN}"

mkdir -p "${OUT_DIR}/logs"
RESULTS_TSV="${OUT_DIR}/results.tsv"
: > "${RESULTS_TSV}"

declare -a TEST_FILES=()
if ((${#FILE_PATTERNS[@]} == 0)); then
    mapfile -d '' -t TEST_FILES < <(find "${TESTS_DIR}" -maxdepth 1 -type f -name '*.t' -print0 | sort -z)
else
    declare -A seen=()
    for pattern in "${FILE_PATTERNS[@]}"; do
        while IFS= read -r -d '' file; do
            if [[ -z "${seen["${file}"]+x}" ]]; then
                TEST_FILES+=("${file}")
                seen["${file}"]=1
            fi
        done < <(find "${TESTS_DIR}" -maxdepth 1 -type f -name "${pattern}" -print0)
    done
    if ((${#TEST_FILES[@]} > 0)); then
        mapfile -d '' -t TEST_FILES < <(printf '%s\0' "${TEST_FILES[@]}" | sort -z)
    fi
fi

TOTAL=${#TEST_FILES[@]}
((TOTAL > 0)) || die "no test files found under ${TESTS_DIR}"
log "running ${TOTAL} test files (timeout=${TIMEOUT_SECS}s) against ${RUXEN_BIN}"

n_pass=0; n_fail=0; n_skip=0; n_timeout=0
i=0
for f in "${TEST_FILES[@]}"; do
    i=$((i+1))
    name=$(basename "$f")
    logfile="${OUT_DIR}/logs/${name}.log"

    TEST_NGINX_BINARY="${RUXEN_BIN}" TEST_NGINX_GLOBALS='' \
        timeout --kill-after=10 "${TIMEOUT_SECS}" \
        prove -I "${TESTS_DIR}/lib" "$f" >"${logfile}" 2>&1
    rc=$?

    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        printf 'TIMEOUT\t%s\t0\t0\ttimeout after %ss\n' "$name" "$TIMEOUT_SECS" >> "${RESULTS_TSV}"
        n_timeout=$((n_timeout+1))
        printf '[%d/%d] TIMEOUT %s\n' "$i" "$TOTAL" "$name"
        continue
    fi

    skip_line=$(grep -m1 -E '\.\. skipped:' "${logfile}" || true)
    if [[ -n "$skip_line" ]]; then
        reason=$(sed -E 's/.*\.\. skipped: //' <<<"$skip_line" | tr '\t' ' ')
        printf 'SKIP\t%s\t0\t0\t%s\n' "$name" "$reason" >> "${RESULTS_TSV}"
        n_skip=$((n_skip+1))
        printf '[%d/%d] SKIP %s — %s\n' "$i" "$TOTAL" "$name" "$reason"
        continue
    fi

    # Prefer the "Failed N/M subtests" line — M is the planned count, even if
    # the plan wasn't reached, so this is more informative than Files=1,Tests=N
    # for setup-error cases (where Tests reports 0).
    fail_line=$(grep -oE 'Failed [0-9]+/[0-9]+ subtests' "${logfile}" | head -1 || true)
    if [[ -n "$fail_line" ]]; then
        failed=$(awk '{print $2}' <<<"$fail_line" | cut -d/ -f1)
        total=$(awk '{print $2}' <<<"$fail_line" | cut -d/ -f2)
    else
        failed=0
        total=$(grep -oE 'Files=1, Tests=[0-9]+' "${logfile}" | head -1 | grep -oE '[0-9]+$' || echo 0)
    fi

    if grep -q '^Result: PASS' "${logfile}"; then
        printf 'PASS\t%s\t0\t%s\t\n' "$name" "$total" >> "${RESULTS_TSV}"
        n_pass=$((n_pass+1))
        printf '[%d/%d] PASS %s (%s)\n' "$i" "$TOTAL" "$name" "$total"
    elif grep -q '^Result: NOTESTS' "${logfile}"; then
        printf 'FAIL\t%s\t0\t0\tno tests reached (setup error)\n' "$name" >> "${RESULTS_TSV}"
        n_fail=$((n_fail+1))
        printf '[%d/%d] FAIL %s (NOTESTS)\n' "$i" "$TOTAL" "$name"
    else
        printf 'FAIL\t%s\t%s\t%s\t\n' "$name" "$failed" "$total" >> "${RESULTS_TSV}"
        n_fail=$((n_fail+1))
        printf '[%d/%d] FAIL %s (%s/%s)\n' "$i" "$TOTAL" "$name" "$failed" "$total"
    fi
done

echo
echo "=== nginx-tests run summary ==="
echo "Total files: ${TOTAL}"
echo "Passed:      ${n_pass}"
echo "Failed:      ${n_fail}"
echo "Skipped:     ${n_skip}"
echo "Timed out:   ${n_timeout}"
echo
echo "Results: ${RESULTS_TSV}"
echo "Per-file logs: ${OUT_DIR}/logs/"

if ((UPDATE_PROGRESS == 1)); then
    log "rewriting ${PROGRESS_MD}"
    tests_rev="$(git -C "${TESTS_DIR}" log -1 --format='%h (%cs)' 2>/dev/null || echo unknown)"
    OUT_MD="${PROGRESS_MD}" RESULTS_TSV="${RESULTS_TSV}" TODAY="$(date -u +%Y-%m-%d)" \
        NGINX_TESTS_REV="${tests_rev}" \
        python3 "${SCRIPT_DIR}/_render_test_progress.py" \
        || die "rendering NGINX_TEST_PROGRESS.md failed"
    echo "Wrote ${PROGRESS_MD}"
fi
