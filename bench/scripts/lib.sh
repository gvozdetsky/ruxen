#!/usr/bin/env bash
set -euo pipefail

BENCH_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_ROOT="$(cd "${BENCH_SCRIPTS_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BENCH_ROOT}/.." && pwd)"

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    printf '[%s] %s\n' "$(date -u +'%H:%M:%S')" "$*" >&2
}

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: ${cmd}"
}

wait_for_http() {
    local url="$1"
    local attempts="${2:-100}"
    local scheme="${3:-http}"
    local -a tls_opts=()
    if [[ "$scheme" == "https" ]]; then
        tls_opts=(-k)
    fi
    local i
    for ((i = 0; i < attempts; i++)); do
        if curl -sS -m 1 "${tls_opts[@]}" -o /dev/null "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Both servers run with the config's own directory as the prefix (`-p`), so
# relative `root` / `auth_basic_user_file` paths in bench configs resolve the
# same way for nginx and ruxen, regardless of where the repo is checked out.
conf_prefix() {
    printf '%s/\n' "$(dirname "$1")"
}

start_nginx() {
    local conf="$1"
    local server_log="$2"
    local prefix
    prefix="$(conf_prefix "$conf")"
    nginx -p "$prefix" -c "$conf" -s quit >/dev/null 2>&1 || true
    nginx -p "$prefix" -c "$conf" >"$server_log" 2>&1
}

stop_nginx() {
    local conf="$1"
    nginx -p "$(conf_prefix "$conf")" -c "$conf" -s quit >/dev/null 2>&1 || true
}

start_ruxen() {
    local conf="$1"
    local env_line="$2"
    local server_log="$3"
    local -a env_parts=()

    if [[ -n "$env_line" ]]; then
        read -r -a env_parts <<<"$env_line"
    fi

    env "${env_parts[@]}" "${REPO_ROOT}/target/release/ruxen" -p "$(conf_prefix "$conf")" -c "$conf" >"$server_log" 2>&1 &
    echo $!
}

stop_ruxen() {
    local pid="$1"
    if [[ -z "$pid" ]]; then
        return 0
    fi

    kill -QUIT "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
}

extract_etag() {
    local url="$1"
    local scheme="${2:-http}"
    local -a tls_opts=()
    if [[ "$scheme" == "https" ]]; then
        tls_opts=(-k)
    fi
    curl -fsSI "${tls_opts[@]}" "$url" \
        | tr -d '\r' \
        | awk 'BEGIN { IGNORECASE=1 } $1=="ETag:" { print $2; exit }'
}

extract_last_modified() {
    local url="$1"
    local scheme="${2:-http}"
    local -a tls_opts=()
    if [[ "$scheme" == "https" ]]; then
        tls_opts=(-k)
    fi
    curl -fsSI "${tls_opts[@]}" "$url" \
        | tr -d '\r' \
        | awk 'BEGIN { IGNORECASE=1 } tolower($1)=="last-modified:" { sub(/^[^:]*: */, ""); print; exit }'
}

wrk_metric_requests_sec() {
    local file="$1"
    awk '/^Requests\/sec:/ { print $2; exit }' "$file"
}

wrk_metric_transfer_sec() {
    local file="$1"
    awk '/^Transfer\/sec:/ { print $2; exit }' "$file"
}

wrk_metric_latency() {
    local file="$1"
    local percentile="$2"
    awk -v p="$percentile" '$1 == p { print $2; exit }' "$file"
}

wrk_metric_total_requests() {
    local file="$1"
    awk '/requests in/ { gsub(/,/, "", $1); print $1; exit }' "$file"
}

wrk_metric_elapsed() {
    local file="$1"
    awk '/requests in/ { v=$4; gsub(/,/, "", v); print v; exit }' "$file"
}

wrk_metric_non2xx() {
    local file="$1"
    awk '
        /^Non-2xx or 3xx responses:/ { print $4; found=1; exit }
        END { if (!found) print 0 }
    ' "$file"
}

wrk_metric_socket_error() {
    local file="$1"
    local key="$2"
    awk -v key="$key" '
        /^Socket errors:/ {
            for (i = 1; i <= NF; i++) {
                token = $i
                gsub(/,/, "", token)
                if (token == key) {
                    value = $(i + 1)
                    gsub(/,/, "", value)
                    print value
                    found = 1
                    exit
                }
            }
        }
        END { if (!found) print 0 }
    ' "$file"
}

or_na() {
    local value="${1:-}"
    if [[ -n "$value" ]]; then
        echo "$value"
    else
        echo "NA"
    fi
}

# Convert a wrk latency token (e.g. "1.23ms", "456.00us", "1.50s", "1.00m") to milliseconds.
# Order matters: check "ms" before "s".
latency_to_ms() {
    local v="$1"
    awk -v v="$v" 'BEGIN {
        if (v ~ /us$/)      { sub(/us$/, "", v); printf "%.4f\n", v / 1000.0 }
        else if (v ~ /ms$/) { sub(/ms$/, "", v); printf "%.4f\n", v + 0.0 }
        else if (v ~ /m$/)  { sub(/m$/,  "", v); printf "%.4f\n", v * 60000.0 }
        else if (v ~ /s$/)  { sub(/s$/,  "", v); printf "%.4f\n", v * 1000.0 }
        else                { printf "%.4f\n", v + 0.0 }
    }'
}

# Reads numbers (one per line) on stdin and prints "mean median stddev min max"
# (sample stddev, tab-separated). Uses sort -n externally for mawk compatibility.
compute_stats() {
    sort -n | awk '
        { v[NR] = $1 + 0; sum += $1 }
        END {
            n = NR
            if (n == 0) { print "0\t0\t0\t0\t0"; exit }
            mean = sum / n
            sumsq = 0
            for (i = 1; i <= n; i++) sumsq += (v[i] - mean) * (v[i] - mean)
            stddev = (n > 1) ? sqrt(sumsq / (n - 1)) : 0
            if (n % 2 == 1) median = v[(n + 1) / 2]
            else            median = (v[n / 2] + v[n / 2 + 1]) / 2
            printf "%.4f\t%.4f\t%.4f\t%.4f\t%.4f\n", mean, median, stddev, v[1], v[n]
        }
    '
}

# Look up a scenario row in scenarios/manifest.tsv. On success prints the
# 14 fields ONE PER LINE (id, description, port, path, threads, connections,
# duration, warmup, cooldown, conf_rel, prepare_rel, header_mode,
# headers_raw, scheme). Use `mapfile -t` to read into an array; bash `read`
# with IFS=$'\t' collapses empty fields between adjacent tabs and drops them.
lookup_scenario() {
    local scenario_id="$1"
    local manifest="${BENCH_ROOT}/scenarios/manifest.tsv"
    [[ -f "$manifest" ]] || die "missing manifest: $manifest"
    awk -F'|' -v want="$scenario_id" '
        /^#/ || NF < 13 { next }
        $1 == want {
            scheme = (NF >= 14 && $14 != "") ? $14 : "http"
            printf "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, scheme
            found = 1; exit
        }
        END { if (!found) exit 2 }
    ' "$manifest"
}

# Build the wrk header argv based on header_mode/headers_raw/url. Echoes one
# header per line; caller reads with mapfile.
resolve_wrk_headers() {
    local header_mode="$1"
    local headers_raw="$2"
    local url="$3"
    local scheme="$4"

    case "$header_mode" in
        none)
            ;;
        static)
            if [[ -n "$headers_raw" ]]; then
                local IFS=';'
                local h
                for h in $headers_raw; do
                    printf '%s\n' "$h"
                done
            fi
            ;;
        etag)
            local etag
            etag="$(extract_etag "$url" "$scheme")"
            [[ -n "$etag" ]] || die "failed to fetch ETag for $url"
            printf 'If-None-Match: %s\n' "$etag"
            ;;
        last_modified)
            local lm
            lm="$(extract_last_modified "$url" "$scheme")"
            [[ -n "$lm" ]] || die "failed to fetch Last-Modified for $url"
            printf 'If-Modified-Since: %s\n' "$lm"
            ;;
        *)
            die "unknown header_mode '$header_mode'"
            ;;
    esac
}

# Run one (warmup + measurement) cycle against the chosen server. Writes the
# measurement wrk output to $wrk_log. Caller is responsible for cooldown
# between iterations.
#
# Args: server_kind conf server_log url threads connections warmup duration
#       header_mode headers_raw scheme wrk_log [env_line]
run_iteration() {
    local server_kind="$1"
    local conf="$2"
    local server_log="$3"
    local url="$4"
    local threads="$5"
    local connections="$6"
    local warmup="$7"
    local duration="$8"
    local header_mode="$9"
    local headers_raw="${10}"
    local scheme="${11}"
    local wrk_log="${12}"
    local env_line="${13:-}"

    local pid=""
    if [[ "$server_kind" == "nginx" ]]; then
        start_nginx "$conf" "$server_log"
    elif [[ "$server_kind" == "ruxen" ]]; then
        pid="$(start_ruxen "$conf" "$env_line" "$server_log")"
    else
        die "unknown server_kind: $server_kind"
    fi

    _stop_server() {
        if [[ "$server_kind" == "nginx" ]]; then
            stop_nginx "$conf" || true
        else
            [[ -n "$pid" ]] && stop_ruxen "$pid" || true
        fi
    }

    local -a tls_opts=()
    [[ "$scheme" == "https" ]] && tls_opts=(-k)

    local ready=0 attempt
    for ((attempt = 0; attempt < 120; attempt++)); do
        if curl -sS -m 1 "${tls_opts[@]}" -o /dev/null "$url" >/dev/null 2>&1; then
            ready=1
            break
        fi
        if [[ "$server_kind" == "ruxen" && -n "$pid" ]] && ! kill -0 "$pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    if [[ "$ready" != "1" ]]; then
        if [[ -s "$server_log" ]]; then
            echo "$server_kind startup log:" >&2
            tail -n 40 "$server_log" >&2
        fi
        _stop_server
        die "server did not become ready: $url"
    fi

    local -a headers=()
    mapfile -t headers < <(resolve_wrk_headers "$header_mode" "$headers_raw" "$url" "$scheme")

    local -a wrk_cmd=(wrk -t "$threads" -c "$connections" --latency)
    local h
    for h in "${headers[@]}"; do
        wrk_cmd+=(-H "$h")
    done

    local warmup_log
    warmup_log="$(mktemp)"
    set +e
    "${wrk_cmd[@]}" -d "$warmup" "$url" >"$warmup_log" 2>&1
    set -e
    rm -f "$warmup_log"

    set +e
    "${wrk_cmd[@]}" -d "$duration" "$url" >"$wrk_log" 2>&1
    local wrk_rc=$?
    set -e

    _stop_server

    if [[ $wrk_rc -ne 0 ]]; then
        echo "wrk failed (rc=$wrk_rc) for $url:" >&2
        tail -n 40 "$wrk_log" >&2 || true
        return $wrk_rc
    fi
}
