#!/usr/bin/env bash
# Interleaved A/B ("ABBA") comparison of two servers on one scenario.
#
# Single runs on a shared client/server machine drift by up to ±10%
# (CPU boost after idle, thermal state, background load). Alternating the
# order — A B, B A, A B, … — exposes both sides to the same drift, and the
# geometric mean of the per-pair B/A ratios is stable to about 1% on the
# reference laptop. There is a small order effect (the second run of a pair
# reads a few percent differently), so an even number of pairs — equal
# counts of "A first" and "B first" — is what cancels it. Use this, not
# single measure.sh rows, to decide whether a change helps.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

SCENARIO_ID=""
PAIRS=6
DURATION="10s"
WARM_DURATION="20s"
COOLDOWN=3
A_KIND="nginx"
B_KIND="ruxen"
A_BIN=""
B_BIN=""
A_ENV=""
B_ENV=""

usage() {
    cat <<'USAGE'
Usage: bench/scripts/pair.sh <scenario_id> [options]

Compares server A and server B with interleaved runs (A B, B A, ...) and
prints the median B/A throughput ratio. Defaults: A = nginx, B = ruxen
(target/release/ruxen). One longer throwaway run of A goes first: a CPU
coming out of idle boosts for tens of seconds, and short runs straight
after idle read 30-100% high.

Options:
  --pairs N          measured pairs (default 6; keep it even so both run
                     orders appear equally often)
  --duration D       wrk duration per run, e.g. 10s (default 10s; the
                     scenario's own warmup runs before every measurement)
  --warm-duration D  length of the throwaway first run (default 20s)
  --cooldown S       seconds between runs (default 3; long pauses let the
                     CPU re-boost, which adds noise)
  --a nginx|ruxen    kind of server A (default nginx)
  --b nginx|ruxen    kind of server B (default ruxen)
  --a-bin PATH       ruxen binary for A (implies --a ruxen)
  --b-bin PATH       ruxen binary for B (default target/release/ruxen)
  --a-env "K=V ..."  extra env for A when it is ruxen
  --b-env "K=V ..."  extra env for B when it is ruxen

Examples:
  # ruxen vs nginx
  bench/scripts/pair.sh static_8k
  # this build vs a saved build of main
  bench/scripts/pair.sh static_8k --a-bin /tmp/ruxen-main
  # same binary, feature toggled by env
  bench/scripts/pair.sh m5_conditional_304 --a ruxen --a-env RUXEN_UNSHARE_FILES=0

Exit status is 1 if any run saw error responses or wrk timeouts.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pairs)    PAIRS="${2:-}"; shift 2 ;;
        --duration) DURATION="${2:-}"; shift 2 ;;
        --cooldown) COOLDOWN="${2:-}"; shift 2 ;;
        --warm-duration) WARM_DURATION="${2:-}"; shift 2 ;;
        --a)        A_KIND="${2:-}"; shift 2 ;;
        --b)        B_KIND="${2:-}"; shift 2 ;;
        --a-bin)    A_BIN="${2:-}"; A_KIND="ruxen"; shift 2 ;;
        --b-bin)    B_BIN="${2:-}"; B_KIND="ruxen"; shift 2 ;;
        --a-env)    A_ENV="${2:-}"; shift 2 ;;
        --b-env)    B_ENV="${2:-}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        --*) die "unknown option: $1" ;;
        *)
            [[ -z "$SCENARIO_ID" ]] || die "unexpected positional argument: $1"
            SCENARIO_ID="$1"; shift ;;
    esac
done

[[ -n "$SCENARIO_ID" ]] || { usage >&2; die "missing <scenario_id>"; }
[[ "$PAIRS" =~ ^[1-9][0-9]*$ ]] || die "--pairs must be a positive integer"
(( PAIRS % 2 == 0 )) || log "warning: odd --pairs leaves the run order unbalanced"
for kind in "$A_KIND" "$B_KIND"; do
    [[ "$kind" == "nginx" || "$kind" == "ruxen" ]] || die "server kind must be nginx or ruxen: $kind"
done
require_cmd wrk
require_cmd curl
require_cmd awk
default_bin="${REPO_ROOT}/target/release/ruxen"
for bin in "${A_BIN:-$default_bin}" "${B_BIN:-$default_bin}"; do
    [[ -x "$bin" ]] || die "missing ruxen binary: $bin (run: cargo build --release)"
done

mapfile -t f < <(lookup_scenario "$SCENARIO_ID") \
    || die "unknown scenario: $SCENARIO_ID (see bench/scenarios/manifest.tsv)"
port="${f[2]}" path="${f[3]}" threads="${f[4]}" connections="${f[5]}"
warmup="${f[7]}" conf_abs="${REPO_ROOT}/${f[9]}" header_mode="${f[11]}"
headers_raw="${f[12]}" scheme="${f[13]}"
[[ -f "$conf_abs" ]] || die "missing config: $conf_abs"
url="${scheme}://127.0.0.1:${port}${path}"

work_dir="$(mktemp -d -t ruxen-pair-XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

label() { # side kind bin
    if [[ "$2" == "nginx" ]]; then echo "nginx"; else echo "ruxen:$(basename "${3:-$default_bin}")"; fi
}
A_LABEL="$(label A "$A_KIND" "$A_BIN")"
B_LABEL="$(label B "$B_KIND" "$B_BIN")"
[[ "$A_LABEL" == "$B_LABEL" && "$A_ENV" == "$B_ENV" && "$A_BIN" == "$B_BIN" ]] \
    && log "warning: A and B are identical; this measures noise"

# run_side <A|B> <tag> -> prints "rps errors"
run_side() {
    local side="$1" tag="$2" kind bin env_line
    if [[ "$side" == "A" ]]; then kind="$A_KIND" bin="$A_BIN" env_line="$A_ENV"
    else kind="$B_KIND" bin="$B_BIN" env_line="$B_ENV"; fi
    local wrk_log="${work_dir}/${tag}.wrk.txt" server_log="${work_dir}/${tag}.server.log"
    RUXEN_BIN="${bin:-$default_bin}" run_iteration "$kind" "$conf_abs" "$server_log" "$url" \
        "$threads" "$connections" "$warmup" "$DURATION" "$header_mode" "$headers_raw" \
        "$scheme" "$wrk_log" "$env_line" >&2
    local rps non2xx timeouts
    rps="$(wrk_metric_requests_sec "$wrk_log")"
    non2xx="$(wrk_metric_non2xx "$wrk_log")"
    timeouts="$(wrk_metric_socket_error "$wrk_log" timeout)"
    [[ -n "$rps" ]] || die "no Requests/sec in $wrk_log"
    echo "$rps $((non2xx + timeouts))"
}

log "scenario=${SCENARIO_ID} url=${url} A=${A_LABEL}${A_ENV:+ [$A_ENV]} B=${B_LABEL}${B_ENV:+ [$B_ENV]} pairs=${PAIRS} duration=${DURATION}"
log "throwaway warm-up run (A, ${WARM_DURATION})"
DURATION_SAVED="$DURATION"; DURATION="$WARM_DURATION"
run_side A warm >/dev/null
DURATION="$DURATION_SAVED"
sleep "$COOLDOWN"

ratios=()
errors=0
for ((i = 0; i < PAIRS; i++)); do
    if (( i % 2 == 0 )); then
        read -r a_rps a_err < <(run_side A "a$i"); sleep "$COOLDOWN"
        read -r b_rps b_err < <(run_side B "b$i")
    else
        read -r b_rps b_err < <(run_side B "b$i"); sleep "$COOLDOWN"
        read -r a_rps a_err < <(run_side A "a$i")
    fi
    sleep "$COOLDOWN"
    # run_side runs in a process substitution, so its `die` can't stop us.
    [[ -n "${a_rps:-}" && -n "${b_rps:-}" ]] || die "pair $i: a run failed (see messages above)"
    ratio="$(awk -v a="$a_rps" -v b="$b_rps" 'BEGIN { printf "%.2f", b / a * 100 }')"
    ratios+=("$ratio")
    errors=$((errors + a_err + b_err))
    printf 'pair %d  A=%-12s B=%-12s B/A=%6s%%  errors A/B=%s/%s\n' \
        "$i" "$a_rps" "$b_rps" "$ratio" "$a_err" "$b_err"
done

printf '%s\n' "${ratios[@]}" | sort -n | awk -v a="$A_LABEL" -v b="$B_LABEL" '
    { r[NR] = $1; lsum += log($1) }
    END {
        med = (NR % 2) ? r[(NR + 1) / 2] : (r[NR / 2] + r[NR / 2 + 1]) / 2
        printf "%s / %s: %.1f%% (geometric mean; median %.1f%%, min %.1f%%, max %.1f%%, %d pairs)\n",
            b, a, exp(lsum / NR), med, r[1], r[NR], NR
    }'
if (( errors > 0 )); then
    log "ERROR: ${errors} error responses / timeouts — the ratio is not meaningful"
    exit 1
fi
