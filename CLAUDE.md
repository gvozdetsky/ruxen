# ruxen — notes for Claude Code

Rust port of nginx (Linux-only, HTTP/1.1 and HTTP/2, thread-per-core on
monoio: io_uring, epoll where io_uring is unavailable).
Read `DESIGN.md` first: philosophy, architecture decisions, and per-milestone
notes from the nginx C source. `ROADMAP.md` holds the positioning (edge server:
TLS termination, reverse proxy, static files) and the phases behind the
milestones.

## Layout on the dev machine

Sibling checkouts are expected one directory up:

- `../nginx` — upstream nginx source at tag `release-1.30.6`, the reference
  version since 0.2.1 (DESIGN.md, "Reference version"). When behavior is
  unclear, read the C. Older notes and issues cite 1.24.0.
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

- Performance contract (DESIGN.md): ≥95% of nginx 1.30 (stable) throughput on the
  bench configs is the target; a release must not regress the headline
  scenarios (ROADMAP.md). Re-measure after hot-path changes.
- Unknown directives are an explicit allowlist, and `-V` feature claims are
  minimal on purpose. Widening either unlocks nginx-tests files, so do it only
  together with the implementation.
- Code is rustfmt-clean and CI enforces `cargo fmt --check`; run `cargo fmt`
  before committing. CI also runs `cargo clippy --all-targets -- -D warnings`
  on a pinned toolchain (the `clippy` job in `.github/workflows/ci.yml`);
  keep it clean.
- Access restrictions ruxen can't enforce yet fail closed (`[emerg]`), never
  go on the allowlist (`config::reject_unenforced`).

## Measuring a PR

A PR on the hot path (the request, response, proxy or TLS path) merges after
an ABBA run: `bench/scripts/pair.sh <scenario> --a-bin <A> --b-bin <B>`, with
A built from the PR's merge-base with main and B from its head, on a quiet
machine. A short run (2–4 scenarios the change touches, 6 pairs) is enough
unless the change is about performance. While one waits, the PR has the
`needs-abba` label, and the results arrive as a PR comment starting with
"ABBA on"; merge when B / A is within noise (about ±0.5%) or better. A PR
that changes only startup, configuration or docs doesn't need one.

## Backlog

The backlog is GitHub issues, nothing else; there is no backlog file.

- Query it: `gh issue list --state open --json number,title,labels,milestone`,
  narrowed with `--label area:proxy`, `--milestone v0.2.1`, etc. Labels:
  `area:{proxy,http,tls,config,static,cli,core,logging}`, `size:{S,M,L}`,
  `nginx-compatibility`, `performance`, `bug`, `documentation`,
  `good first issue`, `help wanted`. Milestones: minor versions (`v0.3.0`)
  are the phases in `ROADMAP.md`; patch versions (`v0.2.1`, `v0.2.2`, …)
  order the work in between (see `ROADMAP.md`, Releases).
- One issue = one root cause. Sections: Summary, Repro (minimal config +
  command, nginx vs ruxen), nginx reference (`file.c:line` at 1.30.6),
  Unlocks (nginx-tests files), Notes, Where in ruxen (files, no line
  numbers), and "Reproduced on `<sha>`". Re-check the repro on main before
  working on an older issue.
- Before filing, search for a duplicate. `good first issue` / `help wanted`
  issues are left for contributors.
- Possible vulnerabilities are never filed as issues: see `SECURITY.md`.
- Every PR ends with a "Follow-ups" section: new issue numbers, or "none".
