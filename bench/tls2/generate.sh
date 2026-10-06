#!/usr/bin/env bash
# Fixtures for this bench config (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"
f() { [ "$(stat -c %s "$1" 2>/dev/null)" = "$2" ] || head -c "$2" /dev/urandom > "$1"; }
../tls/generate.sh >/dev/null
d=/tmp/ruxen-bench-tls
[ -s $d/rsa-key.pem ] || openssl req -x509 -nodes -newkey rsa:2048 -keyout $d/rsa-key.pem -out $d/rsa-cert.pem -days 365 -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
mkdir -p html
f html/hello1k.txt 1024; f html/1M.bin 1048576
