# ruxen

**An experimental nginx-compatible HTTP server and reverse proxy written from scratch in Rust.**

ruxen explores how nginx's architecture and configuration semantics can be reimplemented in idiomatic Rust — without translating the C code line by line.

It is Linux-only, built around a thread-per-core model using [monoio](https://github.com/bytedance/monoio) and `io_uring`, and currently targets HTTP/1.1.

> [!WARNING]
> **ruxen is an active prototype. It is not production-ready yet.**

## Why ruxen?

nginx has decades of engineering behind its event loop, HTTP state machine, configuration system, request routing, and upstream handling.

The goal of ruxen is to study those ideas and reproduce their behaviour using Rust's ownership model and type system rather than copying nginx's C implementation.

Three things guide the project:

- **nginx compatibility** — support a useful subset of nginx configuration and behaviour;
- **external validation** — test against the upstream [`nginx-tests`](https://github.com/nginx/nginx-tests) suite, not only project-specific tests;
- **performance as a constraint** — compare ruxen and nginx on reproducible workloads throughout development.

See [`DESIGN.md`](DESIGN.md) for the architecture notes and the reasoning behind individual design decisions.

## Current status

The v0.1 scope is deliberately limited:

- Linux only
- HTTP/1.1 only
- hand-written HTTP parser
- thread-per-core workers
- `io_uring` via monoio
- nginx-style configuration
- static file serving
- reverse proxying and upstreams
- TLS 1.2/1.3 termination via rustls
- no module system
- no HTTP cache
- no HTTP/2 yet

The upstream `nginx-tests` suite is used as a compatibility test. **63 of the 105 test files that ruxen currently opts into pass end-to-end** (v0.1.1).

See [`NGINX_TEST_PROGRESS.md`](NGINX_TEST_PROGRESS.md) for the per-file status, and [`ROADMAP.md`](ROADMAP.md) for where ruxen is going: first a memory-safe edge server (TLS termination, reverse proxy, static files) that takes your nginx configuration.

## Quick start

### Requirements

- Linux on x86_64 with `io_uring` available. ruxen is developed and tested on kernels 6.x–7.0. `io_uring` must not be turned off with the `kernel.io_uring_disabled` sysctl.
- To build from source (including `cargo install`): Rust 1.88 or newer, plus `cmake` and a C compiler for the `aws-lc-rs` crypto backend that rustls uses. aws-lc refuses GCC 9 (`Your compiler (cc) is not supported due to a memcmp related bug`); on Ubuntu 20.04, install `gcc-10 g++-10` and build with `CC=gcc-10 CXX=g++-10`.
- `curl` to try the server.

### Install

**Prebuilt binary** from [GitHub Releases](https://github.com/gvozdetsky/ruxen/releases):

| tarball | runs on |
| --- | --- |
| `ruxen-x86_64-linux-gnu.tar.gz` | x86_64 with glibc 2.35 or newer (Ubuntu 22.04, Debian 12 and later) |
| `ruxen-aarch64-linux-gnu.tar.gz` | ARM64 with glibc 2.35 or newer (Graviton, Ampere, Raspberry Pi 5 on a 64-bit OS) |
| `ruxen-x86_64-linux-musl.tar.gz` | any x86_64 Linux, static (Alpine, older glibc). See the release notes for its performance. |

```bash
curl -LO https://github.com/gvozdetsky/ruxen/releases/latest/download/ruxen-x86_64-linux-gnu.tar.gz
tar xzf ruxen-x86_64-linux-gnu.tar.gz
cd ruxen-v*-x86_64-linux-gnu
./ruxen -V
```

On a glibc older than 2.35 the gnu builds fail with ``version `GLIBC_2.34' not found``: use the musl build, or build from source. Each release also has the tarballs under versioned names (`ruxen-v<version>-<target>.tar.gz`) and a `SHA256SUMS` file.

**From crates.io:**

```bash
cargo install ruxen --locked
```

**From source:**

```bash
git clone https://github.com/gvozdetsky/ruxen.git
cd ruxen
cargo build --release
# the binary is target/release/ruxen
```

**In Docker**, the default seccomp profile blocks `io_uring`, so ruxen cannot create its `io_uring` runtime. Run the container with `--security-opt seccomp=unconfined` (or a profile that allows the `io_uring_*` syscalls).

ruxen does not switch to an unprivileged user the way nginx's `user` directive does, so it refuses to start as root unless the configuration says `user root;`. Containers usually run as root: either add `user root;` or run the container with `--user`.

### Run

[`examples/minimal.conf`](examples/minimal.conf) is the smallest useful configuration:

```nginx
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    server {
        listen 8080;
        server_name _;

        location / {
            return 200 "hello from ruxen\n";
        }
    }
}
```

Check the configuration, then start the server in the foreground:

```bash
ruxen -t -c examples/minimal.conf
ruxen -c examples/minimal.conf
```

As with nginx, a valid configuration prints `… syntax is ok` and `… test is successful` (on stderr; `-q` silences them) and exits with status 0.

Then, from another terminal:

```bash
curl -i http://127.0.0.1:8080/
```

You should get a `200` response with:

```text
hello from ruxen
```

[`examples/static.conf`](examples/static.conf) serves files from a directory and [`examples/proxy.conf`](examples/proxy.conf) proxies to two backends with keep-alive upstream connections.

You are now serving an nginx-style configuration with ruxen.

## What works

### HTTP and routing

- hand-written HTTP/1.1 parser
- persistent connections and nginx-style keep-alive behaviour
- virtual hosts on multiple `listen` addresses
- `server_name` exact, wildcard and regex matching
- nginx-style `location` matching:
  - exact (`=`)
  - longest prefix
  - `^~`
  - regex (`~`, `~*`)
  - named locations
- `internal` locations
- `listen` port ranges and `listen … proxy_protocol` (PROXY protocol v1 and v2, `$proxy_protocol_*`)
- `worker_connections`, `client_header_timeout`, `client_body_timeout`, `send_timeout`
- request bodies of any `client_max_body_size`, spilled to private temp files (`client_body_temp_path`), with an early 413
- `limit_rate`, `limit_rate_after` and `$limit_rate`

### Static files

Supported functionality includes:

- `root`
- `alias`
- `index`
- `try_files`
- ETag and `Last-Modified`
- conditional requests
- byte ranges
- streamed large files
- zero-copy `sendfile on|off` (plain TCP)
- URI decoding and normalization
- trailing-slash redirects
- `autoindex`

### Reverse proxy and upstreams

ruxen supports a growing subset of nginx's proxy functionality, including:

- `proxy_pass`
- named `upstream` blocks
- path rewriting
- weighted round-robin
- `least_conn`
- backup and down peers
- `max_fails` / `fail_timeout`
- per-worker upstream keep-alive pools
- `proxy_http_version`
- `proxy_set_header`
- request-body forwarding and `proxy_set_body`
- `proxy_next_upstream` (including `_tries` / `_timeout`)
- `proxy_intercept_errors`
- `proxy_redirect`, including the implicit default
- `proxy_hide_header` / `proxy_pass_header`
- `X-Accel-Redirect`, `X-Accel-Limit-Rate` and `proxy_ignore_headers`
- `$upstream_*` per-attempt variables, `$proxy_host`, `$proxy_port`

### TLS

TLS termination uses [rustls](https://github.com/rustls/rustls).

Currently supported:

- TLS 1.2 and TLS 1.3
- `ssl_certificate`
- `ssl_certificate_key`
- RSA and ECDSA certificates
- multiple certificates per server
- SNI
- `ssl_session_cache` (in memory, shared by the workers), `ssl_session_tickets`, `ssl_session_timeout`
- nginx-style `$ssl_*` variables

ALPN currently advertises HTTP/1.1 only.

### Configuration and request processing

A growing nginx-compatible configuration surface is implemented, including:

- `return`
- `add_header`
- `add_trailer`
- `expires`
- `error_page` and `recursive_error_pages`
- `post_action`
- `set`
- `if`
- `rewrite`
- `map` (including `hostnames`)
- `split_clients`
- `auth_basic`
- `auth_basic_user_file`
- `log_format`
- `access_log` and `error_log`, including `syslog:` targets

Many common nginx variables are also available, including request, response, upstream, TLS, cookie, header and rewrite variables.

### nginx CLI compatibility

The currently implemented nginx-style command-line surface includes:

```text
-c
-p
-e
-g
-t
-T
-q
-V
-s stop | quit | reopen
```

`-V` starts with `nginx version: nginx/1.29.2`, followed by `ruxen version: ruxen/<version>`. The nginx line and the `configure arguments` list are what the nginx-tests harness reads to decide which tests apply, so they describe ruxen as an nginx build: the arguments list only the modules ruxen actually implements.

Responses identify ruxen itself: `Server: ruxen/<version>` (plain `ruxen` with `server_tokens off`), and the same name in the footer of built-in error pages. `scripts/run_nginx_tests.sh` sets `RUXEN_NGINX_IDENTITY=1`, which makes them say `nginx/1.29.2` instead, because the upstream tests assert nginx's header.

ruxen also supports pid files, graceful shutdown via `SIGQUIT` (waits for in-flight requests), fast shutdown via `SIGTERM` or `SIGINT` (does not wait; the pid file is removed either way) and log reopening via `SIGUSR1`. `-s stop|quit|reopen` send `SIGTERM`/`SIGQUIT`/`SIGUSR1` to the PID in the config's `pid` file, as nginx does. `-s reload` is refused: ruxen can't re-read its configuration yet, so restart it instead.

## Compatibility philosophy

ruxen is **not** a line-by-line Rust port of nginx.

The approach is:

> understand why nginx does something, then implement that behaviour in a way that makes sense in Rust.

For example, nginx uses memory pools, pointer-based configuration structures and arrays of function pointers because those are natural solutions in C.

ruxen does not reproduce those mechanisms where Rust already provides safer or simpler alternatives.

The aim is behavioural and architectural compatibility where it matters — not source-code similarity.

More detail is in [`DESIGN.md`](DESIGN.md).

## Testing

Run the Rust unit and integration tests:

```bash
cargo test --release
```

The HTTPS integration tests use the system `curl` binary and generate temporary certificates at runtime.

### nginx-tests

ruxen can also run the upstream nginx Perl test suite.

From the repository root:

```bash
scripts/run_nginx_tests.sh
```

Run only selected groups:

```bash
scripts/run_nginx_tests.sh --no-build 'http_*.t' 'proxy_*.t'
```

By default the script expects an `nginx-tests` checkout at:

```text
../nginx-tests
```

A different location can be supplied with:

```bash
scripts/run_nginx_tests.sh --tests-dir /path/to/nginx-tests
```

Passing tests, failing tests and skipped tests are tracked in [`NGINX_TEST_PROGRESS.md`](NGINX_TEST_PROGRESS.md).

## Performance

Performance is treated as part of the design, not as a final optimization pass.

The benchmark suite runs equivalent scenarios against nginx and ruxen and stores the nginx baseline and ruxen history for each workload.

See [`bench/README.md`](bench/README.md) for the benchmark methodology and individual scenarios.

The current v0.1 performance contract for the minimal serving path is to reach at least **95% of nginx's throughput on the same hardware**, while keeping p99 latency within the project's target and producing zero errors.

See [`DESIGN.md`](DESIGN.md) for the current baseline and performance notes.

## v0.1 limitations

The following are intentionally outside the current v0.1 scope:

- HTTP/2
- nginx's module ecosystem
- HTTP caching
- TLS to upstream servers (`proxy_ssl_*`)
- OCSP stapling
- client certificate authentication
- 0-RTT / TLS early data
- persistent TLS session caches (the cache lives in memory and is lost on restart)
- hot certificate reload
- password-protected private keys
- full nginx process supervision and binary upgrade behaviour
- switching workers to an unprivileged `user`

Access restrictions that ruxen can't enforce yet — `limit_except`, `ssl_verify_client on`, `ssl_reject_handshake on`, and `disable_symlinks … from=` with a variable other than `$document_root` — are rejected when the configuration is loaded instead of being ignored. Accepted with a warning: `ssl_ciphers` and `ssl_ecdh_curve` (rustls's defaults — AEAD suites, modern groups — are used) and `ssl_verify_client optional|optional_no_ca` (no client certificate is requested, and `$ssl_client_verify` is always `NONE`).

Missing functionality is expected at this stage. ruxen should not yet be treated as a drop-in production replacement for nginx.

## Contributing

ruxen is still early enough that small experiments and compatibility reports can be genuinely useful.

Good ways to contribute include:

- finding a configuration where nginx and ruxen behave differently;
- reducing a compatibility problem to a small reproducible example;
- running the benchmark suite on different hardware;
- investigating a failing upstream `nginx-tests` case;
- improving documentation;
- implementing a missing nginx behaviour.

If you find something interesting, open an issue — even if you are not planning to implement it yourself.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup (tests, nginx-tests, benchmarks) and how changes are reviewed.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
