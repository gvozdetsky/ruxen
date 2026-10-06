#!/usr/bin/env bash
# Fixtures for this bench config (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
f() { [ "$(stat -c %s "$1" 2>/dev/null)" = "$2" ] || head -c "$2" /dev/urandom > "$1"; }
mkdir -p html
f html/hello1k.txt 1024
