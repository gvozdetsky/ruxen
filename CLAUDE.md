# ruxen — notes for Claude Code

Rust port of nginx (Linux-only, HTTP/1.1, thread-per-core on monoio/io_uring).
Read `DESIGN.md` first: philosophy, architecture decisions, and per-milestone
notes from the nginx C source. `ROADMAP.md` holds the positioning (edge server:
TLS termination, reverse proxy, static files) and the phases behind the
milestones.

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
- Code is rustfmt-clean and CI enforces `cargo fmt --check`; run `cargo fmt`
  before committing. Clippy still has ~100 warnings and is not gated — don't
  mix clippy cleanups into feature changes.
- Access restrictions ruxen can't enforce yet fail closed (`[emerg]`), never
  go on the allowlist (`config::reject_unenforced`).

## Backlog

The backlog is GitHub issues, nothing else; there is no backlog file.

- Query it: `gh issue list --state open --json number,title,labels,milestone`,
  narrowed with `--label area:proxy`, `--milestone v0.1.1`, etc. Labels:
  `area:{proxy,http,tls,config,static,cli,core,logging}`, `size:{S,M,L}`,
  `nginx-compatibility`, `performance`, `bug`, `documentation`,
  `good first issue`, `help wanted`. Milestones: `v0.1.1`, `v0.2.0`.
- One issue = one root cause. Sections: Summary, Repro (minimal config +
  command, nginx vs ruxen), nginx reference (`file.c:line` at 1.24.0),
  Unlocks (nginx-tests files), Notes, Where in ruxen (files, no line
  numbers), and "Reproduced on `<sha>`". Re-check the repro on main before
  working on an older issue.
- Before filing, search for a duplicate. `good first issue` / `help wanted`
  issues are left for contributors.
- Possible vulnerabilities are never filed as issues: see `SECURITY.md`.
- Every PR ends with a "Follow-ups" section: new issue numbers, or "none".
