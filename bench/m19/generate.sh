#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f 1M.bin ]; then
  dd if=/dev/urandom of=1M.bin bs=1M count=1 status=none
fi

if [ ! -f 128M.bin ]; then
  dd if=/dev/urandom of=128M.bin bs=1M count=128 status=none
fi

ls -lh 1M.bin 128M.bin
