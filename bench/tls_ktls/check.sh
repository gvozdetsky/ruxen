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

tx_sessions() {
    awk '$1 == "TlsTxSw" || $1 == "TlsTxDevice" { n += $2; found = 1 }
         END { if (!found) exit 1; printf "%.0f\n", n }' /proc/net/tls_stat
}

for scenario in tls_static_1k_ktls tls_static_1m_ktls; do
    for server in nginx ruxen; do
        args=(--a "$server" --b "$server")
        if [[ "$server" == ruxen ]]; then
            binary="${RUXEN_BIN:-${REPO_ROOT}/target/release/ruxen}"
            args+=(--a-bin "$binary" --b-bin "$binary")
        fi
        before="$(tx_sessions)" || die 'kernel TLS TX counters unavailable'
        "${BENCH_SCRIPTS_DIR}/pair.sh" "$scenario" "${args[@]}" --check
        after="$(tx_sessions)" || die 'kernel TLS TX counters unavailable'
        (( after > before )) \
            || die "$server did not open any kernel TLS TX sessions for $scenario; do not label this a kTLS result"
        log "$server $scenario: kernel TLS TX sessions +$((after - before))"
    done
done
