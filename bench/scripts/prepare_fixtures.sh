#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ensure_file_size() {
    local path="$1"
    local size="$2"
    local actual_size=0

    if [[ -f "${path}" ]]; then
        actual_size="$(wc -c <"${path}" | tr -d '[:space:]')"
    fi

    if [[ "${actual_size}" != "${size}" ]]; then
        dd if=/dev/urandom of="${path}" bs="${size}" count=1 status=none
    fi
}

ensure_file_size "${BENCH_ROOT}/m3/hello.txt" "1024"
ensure_file_size "${BENCH_ROOT}/m5/hello.txt" "1024"
ensure_file_size "${BENCH_ROOT}/static_8k/hello.txt" "8192"
"${BENCH_ROOT}/m19/generate.sh"

ls -lh "${BENCH_ROOT}/m3/hello.txt" "${BENCH_ROOT}/m5/hello.txt" \
    "${BENCH_ROOT}/static_8k/hello.txt" \
    "${BENCH_ROOT}/m19/1M.bin" "${BENCH_ROOT}/m19/128M.bin"
