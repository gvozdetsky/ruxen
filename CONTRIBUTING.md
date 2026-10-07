# Contributing to ruxen

Thanks for looking. ruxen is early: small, well-scoped contributions are the
most useful kind, and an issue that pins down one nginx/ruxen difference is
as valuable as a patch.

Issues labelled [`good first issue`](https://github.com/gvozdetsky/ruxen/labels/good%20first%20issue)
and [`help wanted`](https://github.com/gvozdetsky/ruxen/labels/help%20wanted) are
ones the maintainer is not working on. Comment on one before starting so two
people don't do the same work.

Found a security problem? Please don't open an issue; see
[`SECURITY.md`](SECURITY.md) for how to report it privately.

## The one rule: behave like nginx

ruxen aims for nginx's observable behaviour, not its source structure (see
[`DESIGN.md`](DESIGN.md)). When it is unclear what the right behaviour is:

1. Run the same config and request against nginx and compare.
2. Read the nginx C source for the directive or phase involved.
3. Write down the answer — in the test, the commit message, or `DESIGN.md`.

"nginx does X because of Y in `ngx_http_foo_module.c`" is the most useful
sentence a PR description can contain.

## Setup

You need Linux with `io_uring` (any recent kernel; Docker blocks io_uring by
default — use `--security-opt seccomp=unconfined`), a stable Rust toolchain,
and `curl`.

```bash
git clone https://github.com/gvozdetsky/ruxen.git
cd ruxen
cargo build --release
cargo test --release
git config core.hooksPath .githooks   # refuse commits that aren't rustfmt-clean
```

Integration tests (`tests/*.rs`) start the real binary on loopback ports; the
TLS tests call the system `curl` and generate throw-away certificates.

### nginx-tests (compatibility)

The upstream nginx test suite is the main compatibility signal. Clone it, and
the nginx source for reference, next to ruxen:

```bash
cd ..
git clone https://github.com/nginx/nginx-tests.git
git clone https://github.com/nginx/nginx.git && git -C nginx checkout release-1.24.0
cd ruxen

scripts/run_nginx_tests.sh                       # every .t file, sequential, ~20 min
scripts/run_nginx_tests.sh --no-build 'map*.t'   # a subset
```

Logs land in `.nginx-tests-out/logs/<file>.t.log`. You need `perl` and
`prove`; a few test files also want Perl modules such as `IO::Socket::SSL`
and are skipped without them. Run files sequentially (the script does) —
parallel runs collide on ports.

[`NGINX_TEST_PROGRESS.md`](NGINX_TEST_PROGRESS.md) lists which files pass,
fail, or are skipped. If your change makes a file pass, regenerate it with
`--update-progress` and include it in the PR.

CI runs the files listed there as passing (`scripts/run_nginx_tests.sh
--passing`, about a minute) against the nginx-tests commit in
`scripts/nginx-tests.rev`, and fails if one of them no longer passes. Run the
same locally with your checkout at that commit. To move to a newer
nginx-tests, change the commit and regenerate the progress file in the same
PR.

### Benchmarks (performance)

See [`bench/README.md`](bench/README.md). Short version: single runs on a
laptop drift by ±10%, so compare with interleaved pairs:

```bash
cp target/release/ruxen /tmp/ruxen-before     # before your change
# ... change, cargo build --release ...
bench/scripts/pair.sh static_8k --a-bin /tmp/ruxen-before
```

Benchmark results from hardware other than the maintainer's laptop are very
welcome — open an issue with the "Benchmark results" template.

## Making a change

- **One logical change per PR**, with a test that fails before it and passes
  after. Behaviour changes need an integration test under `tests/`.
- **`cargo fmt`** before committing; CI runs `cargo fmt --check`, and the
  hook in `.githooks/` (enabled in Setup) catches it locally. Clippy is
  not gated yet — please don't mix clippy-only cleanups into feature PRs.
- **Run `cargo test --release`.** If you touched request handling, also run
  the relevant nginx-tests files and say which ones in the PR.
- **Hot-path changes** (parsing, the worker loop, response building, file
  serving): include `pair.sh` numbers for an affected scenario and a control
  scenario. The project's contract is ≥ 95% of nginx's throughput
  ([`DESIGN.md`](DESIGN.md)).
- **New directives:** unknown directives are rejected on purpose (an explicit
  allowlist, see `src/config/mod.rs`), and the `-V` banner only claims
  modules that are implemented. Widen either only together with the
  implementation.
- Commit messages: what changed and *why*, with numbers when it's about
  performance. Look at `git log` for the house style.

## Reporting a difference from nginx

Use the "nginx/ruxen behave differently" issue template. The minimum useful
report is a config small enough to paste, one request (a `curl` command),
and both responses. Reducing a failing nginx-tests file to that shape is a
great first contribution on its own.

## Releasing

For the maintainer. The tag drives the GitHub release; crates.io is a
separate step, so do them in this order:

1. On `main`, bump `version` in `Cargo.toml` (and `Cargo.lock` with
   `cargo update -p ruxen`), and add `.github/release-notes/v<version>.md`.
   Merge that through a PR so CI runs on it.
2. `cargo publish --dry-run --locked` on that commit: it packages the
   crate and builds the package on its own.
3. Tag the commit `v<version>` and push the tag. `release.yml` checks the
   tag against `Cargo.toml` and the notes file, runs `cargo fmt --check`
   and `cargo test`, builds, smoke-tests (`-V`, `-t` on `examples/`), and
   publishes the release with the versioned tarball, a version-less copy
   for the README's `releases/latest` link, and `SHA256SUMS`.
4. When the release is up, `cargo publish --locked`. A crates.io version
   can't be replaced, only yanked, so this goes last.
5. Security fixes in the release: publish their advisories (see
   `SECURITY.md`) and file any follow-up issues they mention.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the project's license.
