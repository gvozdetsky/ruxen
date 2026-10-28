#!/usr/bin/env bash
# Long fuzzing runs (#477). Not for CI: a crash must go through SECURITY.md
# before it is public, so run this on a private machine.
#
#   scripts/fuzz_long.sh [--secs N] [--workers N] OUT [target...]
#   scripts/fuzz_long.sh --report OUT/fuzz-hours.tsv [since-date]
#
# Runs each fuzz/ target (all by default) for N seconds (default 1800) with
# N workers (default 4), from the corpus kept in OUT/corpus-<target> and the
# seeds; crashes go to OUT/artifacts-<target>/. Appends one line per target
# to OUT/fuzz-hours.tsv:
#   date  rev  target  wall_s  workers  execs  crashes  corpus
# `--report` sums the lines (from since-date, `YYYY-MM-DD`, on) per target:
# the release table's fuzzing column (ROADMAP.md).
set -u

if [ "${1:-}" = --report ]; then
  tsv=${2:?usage: --report OUT/fuzz-hours.tsv [since-date]}
  since=${3:-0000}
  awk -F'\t' -v since="$since" '
    $1 >= since {
      h[$3] += $4 * $5 / 3600; e[$3] += $6; c[$3] += $7; n[$3]++
      H += $4 * $5 / 3600; E += $6; C += $7
    }
    END {
      printf "%-18s %6s %10s %16s %8s\n", "target", "runs", "cpu-hours", "executions", "crashes"
      for (t in h) printf "%-18s %6d %10.1f %16.0f %8d\n", t, n[t], h[t], e[t], c[t] | "sort"
      close("sort")
      printf "%-18s %6s %10.1f %16.0f %8d\n", "total", "", H, E, C
    }' "$tsv"
  exit
fi

secs=1800
workers=4
while [ $# -gt 0 ]; do
  case $1 in
    --secs) secs=$2; shift 2 ;;
    --workers) workers=$2; shift 2 ;;
    *) break ;;
  esac
done
out=${1:?usage: fuzz_long.sh [--secs N] [--workers N] OUT [target...]}
shift
mkdir -p "$out"
out=$(cd "$out" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/fuzz" || exit 1
rev=$(git -C "$repo" rev-parse --short HEAD)
triple=$(rustc -vV | sed -n 's/^host: //p')
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=($(ls fuzz_targets | sed 's/\.rs$//'))

cargo +nightly fuzz build -O --target "$triple" > "$out/build.log" 2>&1 || {
  echo "fuzz build failed, see $out/build.log" >&2
  exit 1
}
bin="$repo/fuzz/target/$triple/release"

for t in "${targets[@]}"; do
  corpus="$out/corpus-$t" artifacts="$out/artifacts-$t" work="$out/work-$t"
  mkdir -p "$corpus" "$artifacts" "$work"
  rm -f "$work"/fuzz-*.log
  seeds=()
  [ -d "seeds/$t" ] && seeds=("$repo/fuzz/seeds/$t")
  before=$(ls "$artifacts" | wc -l)
  start=$(date +%s)
  # -jobs writes each worker's log to fuzz-<n>.log in the working directory.
  (cd "$work" && timeout $((secs + 300)) "$bin/$t" -max_total_time="$secs" \
    -jobs="$workers" -workers="$workers" -print_final_stats=1 \
    -artifact_prefix="$artifacts/" "$corpus" "${seeds[@]}" > run.log 2>&1)
  wall=$(($(date +%s) - start))
  execs=$(cat "$work"/fuzz-*.log 2>/dev/null |
    awk '/^stat::number_of_executed_units:/ { s += $2 } END { printf "%.0f", s }')
  crashes=$(($(ls "$artifacts" | wc -l) - before))
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -I)" "$rev" "$t" "$wall" "$workers" \
    "${execs:-0}" "$crashes" "$(ls "$corpus" | wc -l)" >> "$out/fuzz-hours.tsv"
  [ "$crashes" -gt 0 ] && echo "$t: $crashes new artifact(s) in $artifacts" >&2
done
exit 0
