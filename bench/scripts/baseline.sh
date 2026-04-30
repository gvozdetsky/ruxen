#!/usr/bin/env bash
# Capture (or recapture) the frozen nginx baseline for a scenario.
#
# Runs N iterations of (warmup + measurement) with cooldown between, computes
# mean/median/stddev/min/max for req/s, p50, p99, and writes:
#   bench/<config-dir>/baseline_<scenario>.tsv
# Then regenerates bench/<config-dir>/RESULTS.md.
#
# Refuses to overwrite an existing baseline unless --force is passed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

SCENARIO_ID=""
RUNS=5
FORCE=0
COOLDOWN_OVERRIDE=""

usage() {
    cat <<'EOF'
Usage: bench/scripts/baseline.sh <scenario_id> [--runs N] [--cooldown S] [--force]

Captures the nginx baseline for <scenario_id>. Default 5 iterations. Refuses
to overwrite an existing baseline unless --force is passed.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs) RUNS="${2:-}"; shift 2 ;;
        --cooldown) COOLDOWN_OVERRIDE="${2:-}"; shift 2 ;;
        --force) FORCE=1; shift ;;
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
require_cmd nginx

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

[[ -n "$COOLDOWN_OVERRIDE" ]] && cooldown="$COOLDOWN_OVERRIDE"

conf_abs="${REPO_ROOT}/${conf_rel}"
[[ -f "$conf_abs" ]] || die "missing config: $conf_abs"

config_dir="$(dirname "$conf_abs")"
baseline_file="${config_dir}/baseline_${SCENARIO_ID}.tsv"

if [[ -f "$baseline_file" && "$FORCE" != "1" ]]; then
    die "baseline already exists: $baseline_file (pass --force to recapture)"
fi

url="${scheme}://127.0.0.1:${port}${path}"
work_dir="$(mktemp -d -t ruxen-baseline-XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

log "scenario=${SCENARIO_ID} url=${url} runs=${RUNS} duration=${duration} warmup=${warmup} cooldown=${cooldown}"

req_file="${work_dir}/req.txt"
p50_file="${work_dir}/p50.txt"
p99_file="${work_dir}/p99.txt"
: >"$req_file"; : >"$p50_file"; : >"$p99_file"

for ((i = 1; i <= RUNS; i++)); do
    iter_log="${work_dir}/iter_${i}.wrk.txt"
    server_log="${work_dir}/iter_${i}.server.log"

    log "iteration ${i}/${RUNS} (nginx)"
    run_iteration nginx "$conf_abs" "$server_log" "$url" "$threads" "$connections" \
        "$warmup" "$duration" "$header_mode" "$headers_raw" "$scheme" "$iter_log"

    req="$(wrk_metric_requests_sec "$iter_log")"
    p50_raw="$(wrk_metric_latency "$iter_log" "50%")"
    p99_raw="$(wrk_metric_latency "$iter_log" "99%")"
    [[ -n "$req" && -n "$p50_raw" && -n "$p99_raw" ]] \
        || die "missing metrics in $iter_log (look there for wrk output)"

    p50_ms="$(latency_to_ms "$p50_raw")"
    p99_ms="$(latency_to_ms "$p99_raw")"

    printf '%s\n' "$req"    >>"$req_file"
    printf '%s\n' "$p50_ms" >>"$p50_file"
    printf '%s\n' "$p99_ms" >>"$p99_file"

    log "  req/s=${req} p50=${p50_raw} p99=${p99_raw}"

    if (( i < RUNS )) && [[ "$cooldown" != "0" ]]; then
        sleep "$cooldown"
    fi
done

req_stats="$(compute_stats <"$req_file")"
p50_stats="$(compute_stats <"$p50_file")"
p99_stats="$(compute_stats <"$p99_file")"

captured_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
nginx_version="$(nginx -v 2>&1 | sed -E 's|^nginx version: nginx/||; s| .*||' | head -1)"
kernel="$(uname -r)"
cpu="$(awk -F': ' '/^model name/ { gsub(/^ +/, "", $2); print $2; exit }' /proc/cpuinfo)"
[[ -z "$cpu" ]] && cpu="unknown"
governor="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"

# Strip tabs from free-form fields just in case.
nginx_version="${nginx_version//$'\t'/ }"
cpu="${cpu//$'\t'/ }"

# Each *_stats string is already tab-separated; the printf tabs join the
# blocks. The result is 21 tab-separated fields total.
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$captured_at" "$RUNS" "$req_stats" "$p50_stats" "$p99_stats" \
    "$nginx_version" "$kernel" "$cpu" "$governor" \
    >"$baseline_file"

log "wrote $baseline_file"

"${SCRIPT_DIR}/render_results.sh" "$config_dir"

# Echo a friendly summary.
IFS=$'\t' read -r req_mean req_median req_std req_min req_max <<<"$req_stats"
IFS=$'\t' read -r p50_mean p50_median p50_std p50_min p50_max <<<"$p50_stats"
IFS=$'\t' read -r p99_mean p99_median p99_std p99_min p99_max <<<"$p99_stats"

cat <<EOF

Baseline captured for ${SCENARIO_ID} (nginx ${nginx_version}, ${RUNS} runs):
  req/s:    median=${req_median}  stddev=${req_std}  min=${req_min}  max=${req_max}
  p50 (ms): median=${p50_median}  stddev=${p50_std}
  p99 (ms): median=${p99_median}  stddev=${p99_std}

Baseline file: ${baseline_file}
Results doc:   ${config_dir}/RESULTS.md
EOF
