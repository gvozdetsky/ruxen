# ruxen

**An nginx-compatible HTTP server and reverse proxy written from scratch in Rust.**

ruxen takes an nginx configuration and serves it the way nginx would: TLS termination, reverse proxying with caching, and static files, over HTTP/1.1 and HTTP/2. It reimplements nginx's architecture and configuration semantics in idiomatic Rust instead of translating the C code line by line.

It is Linux-only and thread-per-core, on [monoio](https://github.com/bytedance/monoio) with `io_uring`, and on epoll where `io_uring` is unavailable.

ruxen covers a subset of nginx, not all of it (see [What works](#what-works) and [Limitations](#limitations)); `ruxen --compat` tells you whether your configuration is in that subset. It is pre-1.0, so the supported surface still grows from release to release.

## Why ruxen?

nginx serves a large share of the web, and edge servers parse untrusted input all day, which is where memory-safety bugs matter most. Rust servers exist, but they ask you to rewrite your configuration or are libraries for building your own proxy. ruxen keeps the nginx configuration and reproduces nginx's behaviour with Rust's ownership model and type system rather than its C implementation.

Three things guide the project:

- **nginx compatibility** — support a useful subset of nginx configuration and behaviour;
- **external validation** — test against the upstream [`nginx-tests`](https://github.com/nginx/nginx-tests) suite, not only project-specific tests;
- **performance as a constraint** — compare ruxen and nginx on reproducible workloads throughout development.

See [`DESIGN.md`](DESIGN.md) for the architecture notes and the reasoning behind individual design decisions.

## Current status

Version 0.2.2. In short:

- Linux only, x86_64 and aarch64
- HTTP/1.1, and HTTP/2 for clients (`http2 on`; over TLS through ALPN, and cleartext with prior knowledge)
- thread-per-core workers on `io_uring` via monoio, epoll where `io_uring` is unavailable
- a hand-written HTTP/1.1 parser
- nginx-style configuration, checked against your own with `--compat`
- static files, reverse proxying with upstreams, WebSocket tunnels and a proxy cache
- TLS 1.2/1.3 termination via rustls
- configuration reload without dropping connections (`SIGHUP`, `-s reload`)
- no dynamic modules

The upstream `nginx-tests` suite is used as a compatibility test. **182 of the 197 test files that ruxen currently opts into pass end-to-end** (v0.2.2; v0.2.1: 172 of 192).

See [`NGINX_TEST_PROGRESS.md`](NGINX_TEST_PROGRESS.md) for the per-file status, and [`ROADMAP.md`](ROADMAP.md) for where ruxen is going: first a memory-safe edge server (TLS termination, reverse proxy, static files) that takes your nginx configuration.

## Quick start

### Requirements

- Linux on x86_64 or aarch64. ruxen runs on `io_uring` and is developed and tested on kernels 6.x–7.0. Where `io_uring` is unavailable (denied by a seccomp profile, turned off with the `kernel.io_uring_disabled` sysctl, or an old kernel), it runs on epoll instead, which is slower, and says so once in the error log at `notice`. `RUXEN_DRIVER=epoll` picks epoll anyway; `RUXEN_DRIVER=io_uring` refuses to start without `io_uring`.
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

The tarball also holds this README, `examples/`, and the systemd unit, logrotate file and seccomp profile from [Run as a service](#run-as-a-service) under `contrib/`.

On a glibc older than 2.35 the gnu builds fail with ``version `GLIBC_2.34' not found``: use the musl build, or build from source. Each release also has the tarballs under versioned names (`ruxen-v<version>-<target>.tar.gz`), a CycloneDX SBOM per target (`ruxen-v<version>-<target>.cdx.json`) and a `SHA256SUMS` file. The tarballs carry build-provenance and SBOM attestations, signed with the release workflow's identity: `gh attestation verify ruxen-x86_64-linux-gnu.tar.gz -R gvozdetsky/ruxen`. The binaries embed their crate list (`cargo audit bin ruxen`, Trivy and Syft read it).

**Container image** (amd64 and arm64, so also Docker Desktop on Apple Silicon), published with every release after 0.1.2:

```bash
docker run --rm -p 8080:8080 ghcr.io/gvozdetsky/ruxen
curl http://127.0.0.1:8080/      # hello from ruxen
# your configuration (listen on a port above 1024):
docker run --rm -p 8080:8080 -v "$PWD/my.conf:/etc/ruxen/ruxen.conf:ro" ghcr.io/gvozdetsky/ruxen
```

Under Docker's default seccomp profile ruxen runs on epoll; for `io_uring`, see Docker under [Run as a service](#run-as-a-service).

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

Started as root, ruxen binds its ports, opens certificates and logs, then switches to the configured `user` (nginx's default `nobody`) before it accepts a connection, as nginx's workers do. ruxen's workers are threads of one process, so the whole server process switches. What nginx's master still does as root afterwards, a small helper process does: it stays root, recreates the log files logrotate moved away and gives them to the user on `SIGUSR1`, and removes the pid file when ruxen exits. It takes only fixed one-byte commands from the server and exits with it. Started as an unprivileged user, as the service and container setups below do, ruxen ignores `user` with nginx's warning.

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

Without `-c`, ruxen reads `/etc/ruxen/ruxen.conf`, the path the systemd unit and the container image use. `ruxen -h` lists the options, which are nginx's plus `--compat`.

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

### Check your nginx configuration

`--compat` reads a whole configuration and lists everything ruxen doesn't do as nginx, with the file and line, instead of stopping at the first problem the way `-t` does:

```bash
ruxen --compat -c /etc/nginx/nginx.conf
```

```text
ruxen 0.2.2: checking /etc/nginx/nginx.conf
/etc/nginx/sites-enabled/app:14: unsupported: fastcgi_pass unix:/run/php/php-fpm.sock — unknown directive in a location block (FastCGI isn't in ruxen: README, Limitations)
/etc/nginx/nginx.conf:41: differs: ssl_early_data on — TLS 1.3 early data is not accepted
-: differs: "ssl_protocols": TLSv1, TLSv1.1 not supported and ignored, rustls speaks TLSv1.2 and TLSv1.3 only
ignored: 2 tuning directives with no effect in ruxen: tcp_nopush, types_hash_max_size
what to do: https://github.com/gvozdetsky/ruxen/blob/v0.2.2/docs/migrating.md#fastcgi-uwsgi-scgi-memcached
what to do: https://github.com/gvozdetsky/ruxen/blob/v0.2.2/docs/migrating.md#ssl_early_data-on
what to do: https://github.com/gvozdetsky/ruxen/blob/v0.2.2/docs/migrating.md#ssl_protocols
ruxen does not start with this configuration: 1 unsupported, 2 behaving differently
```

- **unsupported:** ruxen refuses to start with it. This covers unknown directives and access restrictions ruxen can't enforce yet.
- **differs:** ruxen starts, but does something other than nginx would. The directive is accepted and ignored where its value matters. A directive set to nginx's default, such as `ssi off`, is not listed.
- **ignored:** tuning knobs with no visible effect.
- **what to do:** the section of the migration guide, [`docs/migrating.md`](docs/migrating.md), for each kind of finding: what ruxen does instead, when it matters, what to do, and the issue that tracks it. The guide also covers running ruxen in nginx's place (systemd, `user`, reload, log rotation, containers).

With nothing unsupported, the configuration is then loaded the way `-t` does it (certificates, roots, log files). The exit status is 0 when ruxen starts with the configuration. A `#N` refers to the GitHub issue that tracks the gap. `-t` errors also carry nginx's ` in file:line`.

### Try it on your traffic, behind nginx

Your nginx can keep answering every request while ruxen answers copies of them on the side: nginx's `mirror` sends ruxen each `GET` and `HEAD`, ruxen's answers are thrown away, and `scripts/shadow-report.py` compares the two access logs and lists where ruxen answered differently. [`docs/shadow.md`](docs/shadow.md) has the setup and what it costs (repeated `GET`s reach your application twice; a hung ruxen delays the next request on a keep-alive connection by up to the mirror's timeout).

### Run as a service

ruxen stays in the foreground (`daemon` is ignored). `SIGQUIT` stops it gracefully, `SIGTERM` at once, `SIGUSR1` reopens the log files, and `SIGHUP` (or `ruxen -s reload`) reloads the configuration: new workers start with it on the same listening sockets, and the old ones finish their requests. A configuration that fails to load leaves the running one in place.

**systemd:** [`contrib/systemd/ruxen.service`](contrib/systemd/ruxen.service) runs `/usr/local/bin/ruxen -c /etc/ruxen/ruxen.conf` as a dynamic unprivileged user that may bind ports below 1024, checks the configuration first, stops it with `SIGQUIT`, and maps `systemctl reload` to a configuration reload. [`contrib/logrotate/ruxen`](contrib/logrotate/ruxen) rotates `/var/log/ruxen/*.log` and has ruxen reopen them with `SIGUSR1`.

**Docker:** the default seccomp profile denies `io_uring`, so there ruxen runs on epoll. For `io_uring`, use [`contrib/docker/seccomp-io_uring.json`](contrib/docker/seccomp-io_uring.json): Docker's default profile ([moby/profiles](https://github.com/moby/profiles) `6fe7deb`) plus `io_uring_setup`, `io_uring_enter` and `io_uring_register`, and `unshare` with `CLONE_FILES` alone (each worker's own fd table; no namespaces); use it rather than `seccomp=unconfined`, which turns filtering off. [`contrib/docker/Dockerfile`](contrib/docker/Dockerfile) builds an image that runs ruxen as an unprivileged user on port 8080:

```bash
docker build -f contrib/docker/Dockerfile -t ruxen .
docker run --rm -p 8080:8080 ruxen       # epoll
curl http://127.0.0.1:8080/              # hello from ruxen
docker run --rm -p 8080:8080 \
    --security-opt seccomp=contrib/docker/seccomp-io_uring.json \
    -v "$PWD/my.conf:/etc/ruxen/ruxen.conf:ro" ruxen    # io_uring, your config
```

**Kubernetes:** the `RuntimeDefault` seccomp profile denies `io_uring` too, so ruxen runs on epoll there. For `io_uring`, install `seccomp-io_uring.json` on the nodes (under the kubelet's `seccomp/` directory) and refer to it with `securityContext.seccompProfile: {type: Localhost, localhostProfile: seccomp-io_uring.json}`.

## What works

### HTTP and routing

- hand-written HTTP/1.1 parser
- HTTP/2 for clients: `http2 on`, `listen … http2`, ALPN `h2`, cleartext HTTP/2 with prior knowledge, `http2_max_concurrent_streams`, `http2_body_preread_size`, `http2_chunk_size`
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
- `listen` port ranges, `listen unix:` and `listen … proxy_protocol` (PROXY protocol v1 and v2, `$proxy_protocol_*`)
- `worker_connections`, `client_header_timeout`, `client_body_timeout`, `send_timeout`
- request bodies of any `client_max_body_size`, spilled to private temp files (`client_body_temp_path`), with an early 413
- `limit_rate`, `limit_rate_after` and `$limit_rate`
- `limit_req` and `limit_conn` on zones shared by the workers and kept across a reload
- `stub_status` and the `$connections_*` variables
- gzip compression (`gzip`, `gzip_types`, `gzip_min_length`, `gzip_comp_level`, `gzip_vary`, `gzip_http_version`, `gzip_proxied`, `gzip_disable`) of static files, `return`, error pages and proxied responses, as nginx decides it: the same statuses, types, `Accept-Encoding` q-values, weak `ETag`, no `Accept-Ranges`. A file gzip compresses is sent whole even for a `Range` request, as from nginx. Not yet: `gzip_static`, `gunzip`, `$gzip_ratio`, and gzip under `limit_rate` (such a response goes out unpaced).

### Static files

Supported functionality includes:

- `root`
- `alias`
- `index`
- `try_files`
- ETag and `Last-Modified`
- conditional requests
- byte ranges (one range per request; `max_ranges 0` turns them off)
- streamed large files
- zero-copy `sendfile on|off` (plain TCP)
- URI decoding and normalization
- trailing-slash redirects
- `autoindex`

### Reverse proxy and upstreams

ruxen supports a growing subset of nginx's proxy functionality, including:

- `proxy_pass`, with variables (literal addresses, `upstream` names, `unix:` paths, and host names through `resolver` / `resolver_timeout`), to TCP and `unix:` upstreams
- HTTPS upstreams (`proxy_pass https://`): `proxy_ssl_server_name`, `proxy_ssl_name`, `proxy_ssl_session_reuse`, `proxy_ssl_protocols`, with nginx's defaults (no SNI, sessions reused, the certificate not verified); certificate verification with `proxy_ssl_verify`, `proxy_ssl_trusted_certificate`, `proxy_ssl_verify_depth` and `proxy_ssl_crl`, by OpenSSL's rules (AWS-LC's X.509 code: commonName fallback, depth, CRLs) and nginx's error-log lines; client certificates to upstreams with `proxy_ssl_certificate` / `proxy_ssl_certificate_key` (`""` cancels an inherited one, `proxy_ssl_password_file` for an encrypted key; paths with variables are rendered per request, and an empty certificate means none)
- named `upstream` blocks
- path rewriting
- weighted round-robin, `least_conn`, `hash` (including `consistent`) and `ip_hash`
- backup and down peers
- `max_fails` / `fail_timeout`, `max_conns`, and `zone` for peer state shared by the workers
- per-worker upstream keep-alive pools
- `proxy_bind` (including `transparent`)
- WebSocket and other `Upgrade` connections, tunnelled after the upstream's 101
- responses relayed as they arrive when nothing needs them whole (no cache or `add_trailer`), gzip-compressed on the way when gzip is on; otherwise buffered
- `proxy_http_version` (`2`: HTTP/2 to the upstream, h2c or ALPN `h2`), `proxy_method`, `proxy_pass_trailers`
- `proxy_set_header`
- request-body forwarding and `proxy_set_body`
- `proxy_next_upstream` (including `_tries` / `_timeout`)
- `proxy_intercept_errors`
- client aborts: a client that closes while the upstream is awaited ends the exchange (499 in the access log), unless `proxy_ignore_client_abort on`
- byte ranges on proxied responses as nginx allows them: `proxy_force_ranges`, cacheable and cached responses (multipart from the cache), `max_ranges`
- `proxy_redirect`, including the implicit default
- `proxy_hide_header` / `proxy_pass_header`
- `X-Accel-Redirect`, `X-Accel-Limit-Rate` and `proxy_ignore_headers`
- `$upstream_*` per-attempt variables, `$proxy_host`, `$proxy_port`
- `proxy_cache` on `proxy_cache_path` zones: `proxy_cache_key`, `proxy_cache_valid`, `proxy_cache_methods`, `proxy_cache_min_uses`, `proxy_cache_bypass`, `proxy_no_cache`, `proxy_cache_convert_head`, `proxy_cache_revalidate`, `proxy_cache_use_stale`, `proxy_cache_background_update`, `proxy_cache_lock` (`_timeout`, `_age`), `Vary`, and `$upstream_cache_status`

### TLS

TLS termination uses [rustls](https://github.com/rustls/rustls).

Currently supported:

- TLS 1.2 and TLS 1.3
- `ssl_certificate`
- `ssl_certificate_key`, encrypted ones with `ssl_password_file` (each line tried in order, as nginx does)
- RSA and ECDSA certificates
- multiple certificates per server
- SNI, and `ssl_reject_handshake`
- client certificates: `ssl_verify_client on|optional|optional_no_ca`, `ssl_client_certificate`, `ssl_trusted_certificate`, `ssl_verify_depth`, `ssl_crl`, per server, checked by OpenSSL's rules (AWS-LC's X.509 code); refused requests get nginx's 400 pages (495 / 496, which `error_page` can take) and a Host naming another verifying server 421; `$ssl_client_verify` and the certificate's fields (`$ssl_client_cert`, `_raw_cert`, `_escaped_cert`, `_s_dn`, `_i_dn` and their `_legacy` forms, `_serial`, `_fingerprint`, `_v_start`, `_v_end`, `_v_remain`), printed as OpenSSL prints them
- OCSP stapling: `ssl_stapling`, `ssl_stapling_file`, `ssl_stapling_responder`, `ssl_stapling_verify`; responses fetched from the responder (`http://`, resolved at startup) in the background, verified, and refreshed as nginx does, one fetch for all workers
- `ssl_session_cache` (in memory, shared by the workers, kept across a reload), `ssl_session_tickets`, `ssl_session_ticket_key` in nginx's ticket layout, `ssl_session_timeout`
- nginx-style `$ssl_*` variables

ALPN offers `h2` where the server has `http2 on` (or `listen … http2`), else HTTP/1.1.

### Configuration and request processing

A growing nginx-compatible configuration surface is implemented. [`docs/directives.md`](docs/directives.md) lists every directive of nginx's core, events and http modules and what ruxen does with it; the main ones:

- `include`, with patterns (`include conf.d/*.conf;`: the matches sorted, none is fine, as nginx's glob)
- `return`, including `return URL;` (a 302)
- `add_header` and `add_trailer`, at http, server and location level, with `add_header_inherit` / `add_trailer_inherit` (`merge` keeps the inherited headers under a level's own)
- `types {}` (`include mime.types`) and `default_type`, as nginx sets Content-Type: no charset is added, and without `types` only .html, .gif and .jpg have a type
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
- `auth_request`, `auth_request_set` (authentication by a subrequest, e.g. to oauth2-proxy or Authelia)
- `allow` / `deny`, `satisfy` and `limit_except`
- realip: `set_real_ip_from`, `real_ip_header` (including `proxy_protocol`), `real_ip_recursive`
- `user`: started as root, ruxen switches to it after binding (see [Install](#install))
- `log_format`
- `access_log` and `error_log`, including `syslog:` targets; `open_log_file_cache` for access_log paths with variables

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
-s stop | quit | reopen | reload
```

and one option nginx doesn't have: `--compat`, the configuration check described in [Check your nginx configuration](#check-your-nginx-configuration).

`-V` starts with `ruxen version: ruxen/<version>`, followed by a `configure arguments` list in nginx's format that names only the modules ruxen actually implements: the nginx-tests harness reads it to decide which tests apply. `-v` prints the first line only, as nginx's `-v` does.

Responses identify ruxen itself: `Server: ruxen/<version>` (plain `ruxen` with `server_tokens off`), and the same name in the footer of built-in error pages. `scripts/run_nginx_tests.sh` sets `RUXEN_NGINX_IDENTITY=1`, which makes them say `nginx/1.30.6` instead, because the upstream tests assert nginx's header, and puts `nginx version: nginx/1.30.6` at the top of `-V`, which the harness needs too.

ruxen also supports pid files, graceful shutdown via `SIGQUIT` (waits for in-flight requests), fast shutdown via `SIGTERM` or `SIGINT` (does not wait; the pid file is removed either way) log reopening via `SIGUSR1`, and configuration reload via `SIGHUP`. `-s stop|quit|reopen|reload` send `SIGTERM`/`SIGQUIT`/`SIGUSR1`/`SIGHUP` to the PID in the config's `pid` file, as nginx does. A reload starts new workers with the new configuration (certificates included) on the same listening sockets, so connections aren't refused or reset in the handover, and the old workers finish their requests, within `worker_shutdown_timeout` if set; a configuration that fails to load is logged and the running one stays. After a switch to `user`, a reload reads the configuration as that user and can't bind new ports below 1024.

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

### Fuzzing

`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the parsers that read untrusted bytes:
- `request`: the HTTP request parser, which must also give the same answer when its input arrives in two pieces;
- `chunked`: the chunked request-body decoder;
- `host`: `Host` validation;
- `uri`: path normalization;
- `proxy_protocol`: PROXY protocol v1/v2;
- `upstream_head` and `upstream_chunked`: an upstream's response head and a relayed chunked body, as a broken or hostile upstream would send them;
- `dns_response`: a name server's response to the resolver;
- `config`: the configuration parser.

They need a nightly toolchain:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run request fuzz/corpus/request fuzz/seeds/request
```

CI runs each target for 30 seconds on every pull request. If a crash could be a vulnerability, report it as `SECURITY.md` describes, not in a public issue.

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

The performance contract is at least **95% of the throughput of nginx's current stable release (1.30) on the same hardware** on every bench scenario, with zero errors; the few scenarios still below it have issues. Changes to the hot path are measured as ABBA pairs against the previous build before they merge, and a release must not regress the headline scenarios.

See [`DESIGN.md`](DESIGN.md) for the performance notes behind individual design decisions.

## Limitations

Not implemented yet (`--compat` names the ones a configuration uses):

- gRPC upstreams (`grpc_pass`), and HTTP/3 (`listen … quic`, `http3` and `quic_*` are accepted and have no effect: the TCP listens serve HTTP/1.1 and HTTP/2)
- FastCGI, uwsgi, SCGI and memcached upstreams, the stream and mail modules, SSI, `sub_filter`, `geo`, the charset filter (`charset` adds nothing to `Content-Type` yet, #464; no conversion), and third-party modules
- streaming request bodies to the upstream (`proxy_request_buffering off`); bodies are read whole, spilling to a temp file
- OCSP checks of client certificates (#142), 0-RTT / TLS early data
- persistent TLS session caches (sessions survive a reload, not a restart)
- nginx's binary upgrade (`SIGUSR2`); a reload can't bind new ports below 1024 once ruxen runs as `user`
- variables in `root` and `alias` (#232)

Access restrictions that ruxen can't enforce yet — `disable_symlinks … from=` with a variable other than `$document_root` — are rejected when the configuration is loaded instead of being ignored. So are `root` and `alias` with variables (`root /var/www/$host;`, `alias /srv/$1;`): ruxen would take the path literally and serve other files than nginx, until #232 renders them per request. `ssl_ciphers` is evaluated as OpenSSL would over the TLS 1.2 suites rustls has (all ECDHE with AES-GCM or ChaCha20-Poly1305; the weaker ones a list names don't exist here), and `ssl_prefer_server_ciphers` picks whose order counts. Accepted with a warning: `ssl_ecdh_curve` (rustls's modern groups are used).

Before moving a site, run `ruxen --compat -c /etc/nginx/nginx.conf`: it lists what ruxen refuses and what it knowingly does differently, and [`docs/migrating.md`](docs/migrating.md) says what to do about each. Anything else that behaves unlike nginx is a bug; please report it.

## Contributing

Compatibility reports are the most useful contribution: every configuration that ruxen refuses or serves differently from nginx says what to build next.

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

Licensed under the [Apache License, Version 2.0](LICENSE). [`NOTICE`](NOTICE) lists the material that comes from nginx (`mime.types`, among others) and its 2-clause BSD licence; the release tarballs and images carry both files.
