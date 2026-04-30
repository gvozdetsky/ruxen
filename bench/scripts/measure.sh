#!/usr/bin/env bash
# Run ruxen once for a scenario and append a row to its history TSV. The
# nginx baseline (captured by baseline.sh) is the comparison reference.
#
# Appends:
#   bench/<config-dir>/history_<scenario>.tsv
# Then regenerates bench/<config-dir>/RESULTS.md.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

SCENARIO_ID=""
NOTE=""
RUNS=1
RUXEN_ENV=""

usage() {
    cat <<'EOF'
Usage: bench/scripts/measure.sh <scenario_id> [--runs N] [--note "text"] [--env "VAR=val ..."]

Runs ruxen against <scenario_id> (default 1 iteration; pass --runs >1 to
take the median across N iterations) and appends a row to the scenario's
history TSV. Records the current commit SHA, dirty flag, and timestamp.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)  RUNS="${2:-}";  shift 2 ;;
        --note)  NOTE="${2:-}";  shift 2 ;;
        --env)   RUXEN_ENV="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --*) die "unknown option: $1" ;;
        *)
            if [[ -z "$SCENARIO_ID" ]]; then
                SCENARIO_ID="$1"
                shift
            else
                die "unexpected positional argument: $1"
            fi
            ;;
    esac
done

[[ -n "$SCENARIO_ID" ]] || { usage >&2; die "missing <scenario_id>"; }
[[ "$RUNS" =~ ^[0-9]+$ ]] || die "--runs must be a positive integer"
(( RUNS >= 1 )) || die "--runs must be >= 1"

require_cmd wrk
require_cmd curl
[[ -x "${REPO_ROOT}/target/release/ruxen" ]] \
    || die "missing ${REPO_ROOT}/target/release/ruxen (run: cargo build --release)"

mapfile -t scenario_fields < <(lookup_scenario "$SCENARIO_ID") \
    || die "unknown scenario: $SCENARIO_ID (see bench/scenarios/manifest.tsv)"
[[ ${#scenario_fields[@]} -eq 14 ]] \
    || die "scenario $SCENARIO_ID: expected 14 fields, got ${#scenario_fields[@]}"

_id="${scenario_fields[0]}"
_desc="${scenario_fields[1]}"
port="${scenario_fields[2]}"
path="${scenario_fields[3]}"
threads="${scenario_fields[4]}"
connections="${scenario_fields[5]}"
duration="${scenario_fields[6]}"
warmup="${scenario_fields[7]}"
cooldown="${scenario_fields[8]}"
conf_rel="${scenario_fields[9]}"
_prepare="${scenario_fields[10]}"
header_mode="${scenario_fields[11]}"
headers_raw="${scenario_fields[12]}"
scheme="${scenario_fields[13]}"

conf_abs="${REPO_ROOT}/${conf_rel}"
[[ -f "$conf_abs" ]] || die "missing config: $conf_abs"

config_dir="$(dirname "$conf_abs")"
history_file="${config_dir}/history_${SCENARIO_ID}.tsv"

url="${scheme}://127.0.0.1:${port}${path}"

# Git context — works whether or not the working tree is clean.
commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
dirty=0
if git -C "$REPO_ROOT" diff --quiet 2>/dev/null \
   && git -C "$REPO_ROOT" diff --cached --quiet 2>/dev/null; then
    dirty=0
else
    dirty=1
fi

work_dir="$(mktemp -d -t ruxen-measure-XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

log "scenario=${SCENARIO_ID} url=${url} commit=${commit}$([[ $dirty == 1 ]] && echo -n '*') runs=${RUNS}"

req_file="${work_dir}/req.txt"
p50_file="${work_dir}/p50.txt"
p99_file="${work_dir}/p99.txt"
non2xx_file="${work_dir}/non2xx.txt"
: >"$req_file"; : >"$p50_file"; : >"$p99_file"; : >"$non2xx_file"

for ((i = 1; i <= RUNS; i++)); do
    iter_log="${work_dir}/iter_${i}.wrk.txt"
    server_log="${work_dir}/iter_${i}.server.log"

    log "iteration ${i}/${RUNS} (ruxen)"
    run_iteration ruxen "$conf_abs" "$server_log" "$url" "$threads" "$connections" \
        "$warmup" "$duration" "$header_mode" "$headers_raw" "$scheme" "$iter_log" "$RUXEN_ENV"

    req="$(wrk_metric_requests_sec "$iter_log")"
    p50_raw="$(wrk_metric_latency "$iter_log" "50%")"
    p99_raw="$(wrk_metric_latency "$iter_log" "99%")"
    non2xx="$(wrk_metric_non2xx "$iter_log")"
    [[ -n "$req" && -n "$p50_raw" && -n "$p99_raw" ]] \
        || die "missing metrics in $iter_log (look there for wrk output)"

    p50_ms="$(latency_to_ms "$p50_raw")"
    p99_ms="$(latency_to_ms "$p99_raw")"

    printf '%s\n' "$req"     >>"$req_file"
    printf '%s\n' "$p50_ms"  >>"$p50_file"
    printf '%s\n' "$p99_ms"  >>"$p99_file"
    printf '%s\n' "$non2xx"  >>"$non2xx_file"

    log "  req/s=${req} p50=${p50_raw} p99=${p99_raw} non-2xx=${non2xx}"

    if (( i < RUNS )) && [[ "$cooldown" != "0" ]]; then
        sleep "$cooldown"
    fi
done

# For RUNS=1 the median equals the single value.
req_stats="$(compute_stats <"$req_file")"
p50_stats="$(compute_stats <"$p50_file")"
p99_stats="$(compute_stats <"$p99_file")"
non2xx_total="$(awk '{ s += $1 } END { print (s + 0) }' "$non2xx_file")"

req_median="$(awk -F'\t' '{ print $2 }' <<<"$req_stats")"
p50_median="$(awk -F'\t' '{ print $2 }' <<<"$p50_stats")"
p99_median="$(awk -F'\t' '{ print $2 }' <<<"$p99_stats")"

# Format numerics for the on-disk row.
req_fmt="$(printf '%.2f' "$req_median")"
p50_fmt="$(printf '%.4f' "$p50_median")"
p99_fmt="$(printf '%.4f' "$p99_median")"

timestamp="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
note_clean="${NOTE//$'\t'/ }"
note_clean="${note_clean//$'\n'/ }"

mkdir -p "$config_dir"
printf '%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\n' \
    "$timestamp" "$commit" "$dirty" \
    "$req_fmt" "$p50_fmt" "$p99_fmt" \
    "$non2xx_total" "$note_clean" \
    >>"$history_file"

log "appended to $history_file"

"${SCRIPT_DIR}/render_results.sh" "$config_dir"

# Compute delta vs baseline if available.
baseline_file="${config_dir}/baseline_${SCENARIO_ID}.tsv"
delta=""
if [[ -f "$baseline_file" ]]; then
    IFS=$'\t' read -r _ _ _ b_req _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ <"$baseline_file" || true
    if [[ -n "$b_req" ]]; then
        delta="$(awk -v now="$req_median" -v base="$b_req" 'BEGIN { if (base+0 > 0) printf "%+.1f%%", (now - base) / base * 100; else print "—" }')"
    fi
fi

cat <<EOF

ruxen ${commit}$([[ $dirty == 1 ]] && echo '*') on ${SCENARIO_ID} (${RUNS} run$([[ $RUNS == 1 ]] || echo s)):
  req/s: ${req_fmt}${delta:+   (Δ baseline: ${delta})}
  p50:   ${p50_fmt} ms
  p99:   ${p99_fmt} ms

History: ${history_file}
Results: ${config_dir}/RESULTS.md
EOF
