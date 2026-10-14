#!/usr/bin/env bash
# Server CPU used by idle keep-alive connections (#146, #127).
#
# Not a wrk shape: N connections each make one request and then stay open
# without sending anything, while the server's utime/stime are read from
# /proc over a window. A server that wakes idle connections (a timer per
# connection, a periodic tick) spends CPU here; nginx spends none.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib.sh"

SCENARIO_ID=""
KIND="ruxen"
BIN=""
ENV_LINE=""
CONNECTIONS=10000
SECONDS_IDLE=10

usage() {
    cat <<'USAGE'
Usage: bench/scripts/idle_cpu.sh <scenario_id> [--server nginx|ruxen]
                                 [--bin PATH] [--env "K=V ..."]
                                 [--connections 10000] [--seconds 10]

Starts the server with the scenario's config, opens the given number of
keep-alive connections (one request each, then idle), and reports the
server's user/system CPU over the idle window, as a share of one core.
The scenario's keepalive_timeout must outlast the window (m1_hello: 65s).
Raise `ulimit -n` above the connection count first.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)      KIND="${2:-}"; shift 2 ;;
        --bin)         BIN="${2:-}"; KIND="ruxen"; shift 2 ;;
        --env)         ENV_LINE="${2:-}"; shift 2 ;;
        --connections) CONNECTIONS="${2:-}"; shift 2 ;;
        --seconds)     SECONDS_IDLE="${2:-}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        --*) die "unknown option: $1" ;;
        *)
            [[ -z "$SCENARIO_ID" ]] || die "unexpected positional argument: $1"
            SCENARIO_ID="$1"; shift ;;
    esac
done
[[ -n "$SCENARIO_ID" ]] || { usage >&2; die "missing <scenario_id>"; }
[[ "$KIND" == "nginx" || "$KIND" == "ruxen" ]] || die "--server must be nginx or ruxen"
require_cmd python3
require_cmd curl

mapfile -t f < <(lookup_scenario "$SCENARIO_ID") \
    || die "unknown scenario: $SCENARIO_ID (see bench/scenarios/manifest.tsv)"
port="${f[2]}" path="${f[3]}" conf_abs="${REPO_ROOT}/${f[9]}" scheme="${f[13]}"
[[ "$scheme" == "http" ]] || die "idle_cpu.sh needs a plain-HTTP scenario"
url="$(url_scheme "$scheme")://127.0.0.1:${port}${path}"
work_dir="$(mktemp -d -t ruxen-idle-XXXXXX)"
pid=""
holder=""

cleanup() {
    [[ -n "$holder" ]] && kill "$holder" 2>/dev/null || true
    if [[ "$KIND" == "nginx" ]]; then stop_nginx "$conf_abs" || true
    elif [[ -n "$pid" ]]; then
        stop_ruxen "$pid" || true
        # Not our child (started in a subshell), so `wait` doesn't wait:
        # let it finish closing the connections and removing its pid file
        # before the next server starts with the same config.
        for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    fi
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

# Open the connections, one request each, then hold them until killed.
# Prints "ready N" once N connections got their response.
python3 - "$port" "$path" "$CONNECTIONS" >"${work_dir}/holder.out" 2>&1 <<'PY' &
import socket, sys, time
port, path, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
held = []
for _ in range(n):
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(req)
    got = b""
    while b"\r\n\r\n" not in got:
        chunk = s.recv(65536)
        if not chunk:
            break
        got += chunk
    held.append(s)
print(f"ready {len(held)}", flush=True)
while True:
    time.sleep(3600)
PY
holder=$!
for _ in $(seq 1 600); do
    grep -q '^ready' "${work_dir}/holder.out" 2>/dev/null && break
    kill -0 "$holder" 2>/dev/null || die "connection holder failed: $(cat "${work_dir}/holder.out")"
    sleep 0.1
done
grep -q '^ready' "${work_dir}/holder.out" || die "connections not open after 60s"
held="$(awk '/^ready/ { print $2 }' "${work_dir}/holder.out")"

# Let the opening burst settle before the window.
sleep 1
u0="$(ticks 14)" s0="$(ticks 15)"
sleep "$SECONDS_IDLE"
u1="$(ticks 14)" s1="$(ticks 15)"

hz="$(getconf CLK_TCK)"
awk -v k="$KIND" -v n="$held" -v du="$((u1 - u0))" -v ds="$((s1 - s0))" -v hz="$hz" -v t="$SECONDS_IDLE" 'BEGIN {
    printf "%s idle=%d window=%ss cpu: user=%.1f%% sys=%.1f%% total=%.1f%% of one core\n",
        k, n, t, du / hz / t * 100, ds / hz / t * 100, (du + ds) / hz / t * 100
}'
