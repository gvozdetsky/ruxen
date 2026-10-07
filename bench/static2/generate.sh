#!/usr/bin/env bash
# Fixtures for this bench config (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
f() { [ "$(stat -c %s "$1" 2>/dev/null)" = "$2" ] || head -c "$2" /dev/urandom > "$1"; }
mkdir -p html/nosf html/dir html/spa html/alias-src html/exp html/list
: > html/0.txt
f html/hello1k.txt 1024; f html/16k.bin 16384; f html/64k.bin 65536; f html/256k.bin 262144
f html/nosf/hello1k.txt 1024; f html/nosf/1M.bin 1048576
f html/dir/index.html 1024
f html/spa/index.html 1024; f html/spa/app.js 1024
f html/alias-src/hello1k.txt 1024
f html/exp/hello1k.txt 1024
for i in $(seq -w 0 99); do f html/list/file-$i.txt 100; done
