#!/usr/bin/env bash
# Fixtures for this bench config (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
f() { [ "$(stat -c %s "$1" 2>/dev/null)" = "$2" ] || head -c "$2" /dev/urandom > "$1"; }
mkdir -p html/files html/internal
f html/files/64k.bin 65536; f html/files/1M.bin 1048576; f html/internal/hello1k.txt 1024
