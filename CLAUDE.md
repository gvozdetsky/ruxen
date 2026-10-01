# ruxen — notes for Claude Code

Rust port of nginx (Linux-only, HTTP/1.1, thread-per-core on monoio/io_uring).
Read `DESIGN.md` first: philosophy, architecture decisions, and per-milestone
notes from the nginx C source.

## Layout on the dev machine

Sibling checkouts are expected one directory up:

- `../nginx` — upstream nginx source at tag `release-1.24.0`. The reference
  implementation: when behavior is unclear, read the C.
- `../nginx-tests` — upstream Perl test suite, driven by
  `scripts/run_nginx_tests.sh`.

## Commands

- `cargo test --release` — unit + integration tests (`tests/*.rs` spawn the
  real binary; TLS tests need `curl` on `PATH`).
- `scripts/run_nginx_tests.sh [--no-build] [--update-progress] ['glob*.t']` —
  nginx-tests sweep. Always sequential. `--update-progress` rewrites
  `NGINX_TEST_PROGRESS.md`.
- `bench/scripts/{baseline,measure}.sh <scenario>` — see `bench/README.md`.
  Scenarios live in `bench/scenarios/manifest.tsv`. Don't hand-edit
  `bench/*/RESULTS.md`; it is rendered from the TSVs next to it.

## Rules

- Performance contract (DESIGN.md): ≥95% of nginx 1.24.0 throughput on the
  bench configs. Re-measure after hot-path changes.
- Unknown directives are an explicit allowlist, and `-V` feature claims are
  minimal on purpose. Widening either unlocks nginx-tests files, so do it only
  together with the implementation.
- The code is not rustfmt-clean and has clippy warnings. Don't mass-reformat
  unrelated code inside a feature change.
