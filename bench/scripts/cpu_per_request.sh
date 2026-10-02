#!/usr/bin/env bash
# Server-side CPU cost per request (user + system µs) for one scenario.
#
# Throughput only compares servers when the server is the bottleneck. On the
# no-keepalive scenarios neither nginx nor ruxen saturates the CPU (wrk and
# the kernel's TCP setup are the limit), so req/s barely moves while the
# server's own cost per request does. Read utime/stime of the server
# processes from /proc around one measured wrk run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

SCENARIO_ID=""
KIND="ruxen"
BIN=""
ENV_LINE=""
DURATION="10s"

usage() {
    cat <<'USAGE'
Usage: bench/scripts/cpu_per_request.sh <scenario_id> [--server nginx|ruxen]
                                        [--bin PATH] [--env "K=V ..."] [--duration 10s]

Starts the server, warms up with the scenario's warmup, then reports req/s
and the server's user/system CPU microseconds per request over one run.
Run it a few times alternating servers; differences under ~2% are noise.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)   KIND="${2:-}"; shift 2 ;;
        --bin)      BIN="${2:-}"; KIND="ruxen"; shift 2 ;;
        --env)      ENV_LINE="${2:-}"; shift 2 ;;
        --duration) DURATION="${2:-}"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        --*) die "unknown option: $1" ;;
        *)
            [[ -z "$SCENARIO_ID" ]] || die "unexpected positional argument: $1"
            SCENARIO_ID="$1"; shift ;;
    esac
done
[[ -n "$SCENARIO_ID" ]] || { usage >&2; die "missing <scenario_id>"; }
[[ "$KIND" == "nginx" || "$KIND" == "ruxen" ]] || die "--server must be nginx or ruxen"
require_cmd wrk
require_cmd curl

mapfile -t f < <(lookup_scenario "$SCENARIO_ID") \
    || die "unknown scenario: $SCENARIO_ID (see bench/scenarios/manifest.tsv)"
port="${f[2]}" path="${f[3]}" threads="${f[4]}" connections="${f[5]}"
warmup="${f[7]}" conf_abs="${REPO_ROOT}/${f[9]}" header_mode="${f[11]}"
headers_raw="${f[12]}" scheme="${f[13]}"
url="${scheme}://127.0.0.1:${port}${path}"
work_dir="$(mktemp -d -t ruxen-cpu-XXXXXX)"
pid=""

cleanup() {
    if [[ "$KIND" == "nginx" ]]; then stop_nginx "$conf_abs" || true
    elif [[ -n "$pid" ]]; then stop_ruxen "$pid" || true; fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

if [[ "$KIND" == "nginx" ]]; then
    start_nginx "$conf_abs" "${work_dir}/server.log"
    pid_file="$(awk '$1 == "pid" { gsub(";", "", $2); print $2; exit }' "$conf_abs")"
    [[ -n "$pid_file" ]] || die "config has no pid directive: $conf_abs"
else
    pid="$(RUXEN_BIN="${BIN:-${REPO_ROOT}/target/release/ruxen}" start_ruxen "$conf_abs" "$ENV_LINE" "${work_dir}/server.log")"
fi
wait_for_http "$url" 100 "$scheme" || die "server did not become ready: $url"

server_pids() {
    if [[ "$KIND" == "nginx" ]]; then ps -o pid= --ppid "$(cat "$pid_file")"; else echo "$pid"; fi
}
# Sum of utime (field 14) or stime (15) in clock ticks over the server's processes.
ticks() {
    local field="$1" total=0 p
    for p in $(server_pids); do
        total=$((total + $(awk -v f="$field" '{ print $f }' "/proc/$p/stat")))
    done
    echo "$total"
}

mapfile -t headers < <(resolve_wrk_headers "$header_mode" "$headers_raw" "$url" "$scheme")
wrk_cmd=(wrk -t "$threads" -c "$connections")
for h in "${headers[@]}"; do wrk_cmd+=(-H "$h"); done

"${wrk_cmd[@]}" -d "$warmup" "$url" >/dev/null 2>&1 || true
u0="$(ticks 14)" s0="$(ticks 15)"
out="$("${wrk_cmd[@]}" -d "$DURATION" "$url")"
u1="$(ticks 14)" s1="$(ticks 15)"

requests="$(awk '/requests in/ { print $1; exit }' <<<"$out")"
rps="$(awk '/^Requests\/sec:/ { print $2; exit }' <<<"$out")"
errors="$(awk '/^Non-2xx or 3xx responses:/ { print $5 }' <<<"$out")"
[[ -n "$requests" && "$requests" -gt 0 ]] || die "wrk reported no requests"
hz="$(getconf CLK_TCK)"
awk -v k="$KIND" -v r="$rps" -v n="$requests" -v du="$((u1 - u0))" -v ds="$((s1 - s0))" -v hz="$hz" -v e="${errors:-0}" 'BEGIN {
    us = 1e6 / hz
    printf "%s req/s=%.0f cpu/req: user=%.2fus sys=%.2fus total=%.2fus errors=%d\n",
        k, r, du * us / n, ds * us / n, (du + ds) * us / n, e
}'
