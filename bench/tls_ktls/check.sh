#!/usr/bin/env bash
# Check actual kTLS use, separately for nginx and ruxen, before timing it.
# The counters cover this network namespace: run without other kTLS traffic.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../scripts/lib.sh"

if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
    echo 'Usage: [RUXEN_BIN=/path/to/ruxen] bench/tls_ktls/check.sh'
    echo 'Uses nginx from PATH. Requires the kernel tls module and a kTLS-enabled nginx/OpenSSL.'
    exit 0
fi
[[ $# == 0 ]] || die 'unexpected arguments (see --help)'
[[ -r /proc/net/tls_stat ]] \
    || die 'kernel TLS counters unavailable; load the tls module (sudo modprobe tls) first'
require_cmd nginx
require_cmd curl
binary="${RUXEN_BIN:-${REPO_ROOT}/target/release/ruxen}"
[[ -x "$binary" ]] || die "missing ruxen binary: $binary (run cargo build --release)"

tx_sessions() {
    awk '$1 == "TlsTxSw" || $1 == "TlsTxDevice" { n += $2; found = 1 }
         END { if (!found) exit 1; printf "%.0f\n", n }' /proc/net/tls_stat
}

conf="${SCRIPT_DIR}/nginx.conf"
url=https://127.0.0.1:8460
work_dir="$(mktemp -d -t ruxen-ktls-check-XXXXXX)"
active_server="" pid=""
stop_server() {
    if [[ "$active_server" == nginx ]]; then
        stop_nginx "$conf"
    elif [[ "$active_server" == ruxen ]]; then
        stop_ruxen "$pid"
    fi
    active_server=""
}
cleanup() { stop_server; rm -rf "$work_dir"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run_prepare bench/tls2/generate.sh

for server in nginx ruxen; do
    ! port_in_use "$url/" || die "port 8460 is already in use"
    if [[ "$server" == nginx ]]; then
        start_nginx "$conf" "$work_dir/$server.log"
    else
        pid="$(RUXEN_BIN="$binary" start_ruxen "$conf" '' "$work_dir/$server.log")"
    fi
    active_server="$server"
    if ! wait_for_http "$url/hello1k.txt" 100 https; then
        cat "$work_dir/$server.log" >&2
        die "$server did not become ready"
    fi
    # Ruxen's startup capability probes also open kernel TLS sessions.
    # Measure only fresh requests after readiness, never across startup.
    for fixture in 'hello1k.txt 1024' '1M.bin 1048576'; do
        read -r path size <<< "$fixture"
        before="$(tx_sessions)" || die 'kernel TLS TX counters unavailable'
        response="$(probe_url "$url/$path" https none '')"
        after="$(tx_sessions)" || die 'kernel TLS TX counters unavailable'
        [[ "$response" == "200 $size" ]] \
            || die "$server /$path returned $response (status, bytes), expected 200 $size"
        (( after > before )) \
            || die "$server did not open any kernel TLS TX sessions for /$path; do not label this a kTLS result"
        log "$server /$path: $response (status, bytes), kernel TLS TX sessions +$((after - before))"
    done
    stop_server
done
