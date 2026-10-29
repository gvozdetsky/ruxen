# Contributing to ruxen

Thanks for looking. Small, well-scoped contributions are the most useful
kind, and an issue that pins down one nginx/ruxen difference is as valuable
as a patch.

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

You need Linux with `io_uring` (any recent kernel), Rust 1.88 or newer, `cmake`
and a C compiler (for rustls's `aws-lc-rs` backend), and `curl`. Without
`io_uring` ruxen runs on epoll, but the benchmarks and most development use
`io_uring`. Docker's default seccomp profile blocks `io_uring`; from the
repository root, pass
`--security-opt seccomp=contrib/docker/seccomp-io_uring.json` to `docker run`
to use the bundled profile, which allows the required `io_uring` syscalls
while keeping the other default restrictions. See the README's
[Docker instructions](README.md#run-as-a-service) for a complete example.

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
git clone https://github.com/nginx/nginx.git && git -C nginx checkout release-1.30.6
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

### Differential testing (nginx as the oracle)

`scripts/difftest/` sends the same requests to nginx and ruxen on the same
configuration and reports where the answers differ (#750). It needs Python 3
and an nginx 1.30 binary (`--nginx`, or `$DIFFTEST_NGINX`; build one from
`../nginx` with `--with-http_ssl_module --with-http_v2_module` and the
modules your configs use).

```bash
cargo build --release
scripts/difftest/difftest.py run --quick --nginx PATH/TO/nginx   # curated + bench configs, under a minute
scripts/difftest/difftest.py run --nginx PATH/TO/nginx           # + nginx-tests and corpus configs
scripts/difftest/difftest.py list --suite corpus                 # which cases a suite has
```

The report, `difftest-out/report.md`, groups differences by class (status,
header, body, framing, connection, upstream request) so one root cause shows
up once, with example requests. Requests are generated from `--seed`
(default 1); to look at one, rerun it with both answers printed:

```bash
scripts/difftest/difftest.py run --only curated:proxy --request 't0:localhost/base:/uri/'
```

What is normalised away (`Date`, the server version, gzip bytes, request
ids, …) is listed in `normalise.py`; anything else that differs is
reported. Upstreams go to `echo_upstream.py`, which answers with the request
it received, so the proxy's request rewriting is compared too. Differences
that are by design, or already have an issue, go into `expected.tsv` with
the reason (an issue number), and `difftest.py report` re-renders the last
run with it; configurations `ruxen --compat` flags are reported apart.
HTTP/2 is not exercised (the h2 crate follows the RFC where nginx doesn't,
#347).

To try a configuration, `--config FILE`; to keep it, drop it into
`scripts/difftest/configs/`: any ports, any upstream host names (they are
mapped), `root html;` gets a fixture tree. A new difference becomes an
issue (one root cause each), then a line in `expected.tsv` until it is
fixed.

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
  hook in `.githooks/` (enabled in Setup) catches it locally. CI also runs
  `cargo clippy --all-targets -- -D warnings` (on the toolchain pinned in
  the `clippy` job); a new warning fails the PR.
- **Run `cargo test --release`.** If you touched request handling, also run
  the relevant nginx-tests files and say which ones in the PR.
- **Hot-path changes** (parsing, the worker loop, response building, file
  serving): include `pair.sh` numbers for an affected scenario and a control
  scenario. The project's contract is ≥ 95% of nginx's throughput
  ([`DESIGN.md`](DESIGN.md)).
- **New directives:** unknown directives are rejected on purpose (an explicit
  allowlist, see `src/config/mod.rs`), and the `-V` banner only claims
  modules that are implemented. Widen either only together with the
  implementation, and rerun `scripts/directives.py` (it needs the `../nginx`
  checkout and a release build) so [`docs/directives.md`](docs/directives.md)
  says so.
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
   The same PR adds the release's row to `ROADMAP.md`'s table; its
   fuzzing column comes from the private machine's log,
   `scripts/fuzz_long.sh --report <out>/fuzz-hours.tsv <date of the previous release>`.
   Merge that through a PR so CI runs on it.
2. `cargo publish --dry-run --locked` on that commit: it packages the
   crate and builds the package on its own.
3. Tag the commit `v<version>` and push the tag. `release.yml` checks the
   tag against `Cargo.toml` and the notes file, runs `cargo fmt --check`
   and `cargo test`, builds, smoke-tests (`-V`, `-t` on `examples/`), and
   publishes the release with the versioned tarball, a version-less copy
   for the README's `releases/latest` link, an SBOM per target and
   `SHA256SUMS`. The binaries are built with `cargo auditable`, and the
   tarballs get build-provenance and SBOM attestations (#480).
4. When the release is up, the workflow's `crates-io` job runs `cargo
   publish --locked` with a token from crates.io's trusted publishing
   (#672): no API token is stored anywhere. A crates.io version can't be
   replaced, only yanked, so this goes last. If the job fails, rerun it
   from the run's page once the cause is fixed.
5. Security fixes in the release: publish their advisories (see
   `SECURITY.md`) and file any follow-up issues they mention.

## License

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the project's license.
