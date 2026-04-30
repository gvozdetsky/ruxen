# ruxen

A Rust port of [nginx](https://nginx.org), the high-performance HTTP server and reverse proxy.

**Status:** active prototype. v0.1 scope is intentionally tiny: Linux-only, HTTP/1.1, no modules, no cache.

## What works

- **Core serving:** hand-written HTTP/1.1 parser, keep-alive, response-side `Connection` header parity, `keepalive_timeout` semantics (`0` disables reuse; optional `Keep-Alive: timeout=N` hint; idle timeout actively closes idle sockets), `keepalive_requests` (default cap 1000, server/location override), `keepalive_disable` (`none|msie6|safari`) and `keepalive_time` policy semantics, thread-per-core on io_uring via monoio, `SO_REUSEPORT`.
- **Routing:** virtual hosts across multiple `listen` addresses, `server_name` (case-insensitive exact, wildcard, regex, and empty-name forms), `location` (`=`, longest-prefix, `^~`, `~`, `~*`, internal-only named `@name`), hash-indexed header dispatch.
- **Static files:** `root`, `alias` (prefix/exact/regex, including regex `add_uri_to_alias` flow), URI decoding + normalization, strong ETag / `Last-Modified`, single-range `Range`/`If-Range`, conditional `If-Modified-Since`/`If-Unmodified-Since`/`If-None-Match`/`If-Match`, streamed large-file bodies (bounded-memory write path), `index` (including `$var` entries and nginx-style internal reroute), `try_files` (including named-location fallback), 301 trailing-slash redirect, symlink-escape-safe containment, `autoindex on;` in `html|xml|json|jsonp` formats with `autoindex_exact_size` and `autoindex_localtime`.
- **TLS termination:** `listen … ssl;` via [rustls](https://github.com/rustls/rustls) 0.23 (over the upstream [`monoio-rustls`](https://crates.io/crates/monoio-rustls) adapter), TLS 1.2 + 1.3 (insecure SSLv2/SSLv3/TLSv1/TLSv1.1 rejected at `-t`), `ssl_certificate` / `ssl_certificate_key` (PKCS#8, PKCS#1 RSA, SEC1 EC), multi-cert per server (RSA + ECDSA picked by client signature schemes), SNI dispatch with exact + leading-wildcard match, ALPN advertising `http/1.1` only, in-memory session cache with `ssl_session_timeout`, 60s handshake timeout. Common `$ssl_*` variables are wired into `add_header` / `return` / `log_format`.
- **Reverse proxy/upstream:** `proxy_pass` (literal `http://host:port`, named `upstream`, and path-rewrite form `proxy_pass http://up/path;`), `upstream { server ... }` with weighted round-robin and `least_conn`, `down`/`backup`, `max_fails`/`fail_timeout`, per-worker keepalive pools (`keepalive`, `keepalive_requests`, `keepalive_timeout`, `keepalive_time`), `proxy_http_version 1.0|1.1`, `proxy_set_header`, `proxy_pass_request_headers`, `proxy_pass_request_body`, `proxy_next_upstream` (+ `_tries`, `_timeout`), `proxy_intercept_errors`, and buffered Content-Length or chunked client request bodies up to 1 MiB.
- **Directives:** `return` (with `$var` expansion; 3xx forms emit `Location` redirects), `add_header NAME VALUE [always];` and `add_trailer NAME VALUE [always];` (server + location scope, nginx merge semantics, `add_header Last-Modified` suppress/override for static responses), `expires`, `error_page STATUS... [=NNN] URI;` (server + location scope, internal URI, named-location, or external URL targets), `post_action`, rewrite-module core (`set`, `if (...) { ... }`, `rewrite ... [last|break|redirect|permanent]`), `split_clients` at http scope, `map $source $dest { ... }` at http scope (exact / `~` / `~*` / `default`), `auth_basic "realm"` + `auth_basic_user_file` (http/server/location scope with `off` inheritance break; htpasswd `{PLAIN}` / `{SHA}` / `{SSHA}` / `$apr1$` / `$1$` and system `crypt(3)` entries).
- **Logging:** minimal `log_format` + `access_log` sinks at http/server/location scope, including `if=$arg_*` gating and `$sent_http_*` rendering, plus server/location `error_log` + `log_not_found` 404 side effects with per-sink levels, multiple sinks, and `syslog:` targets (`server=unix:...` and UDP server forms).
- **Variables:** `$uri`, `$request_uri`, `$host`, `$server_name`, `$status`, `$args`/`$query_string`, `$is_args`, `$arg_*`, `$cookie_*`, `$scheme`, `$remote_addr`, `$remote_port`, `$remote_user`, `$hostname`, `$http_NAME`, `$sent_http_NAME`, `$sent_trailer_NAME`, `$request_body`, `$request_body_file`, `$connection`, `$connection_requests`, `$connection_time`, `$request_time`, `$limit_rate`, `$upstream_http_NAME`, `$upstream_cookie_NAME`, `$upstream_response_length`, `$upstream_response_time`, `$ssl_protocol`, `$ssl_cipher`, `$ssl_server_name`, `$ssl_session_reused`, rewrite captures `$1..$9`, and user-defined `$name` from `set` / `split_clients`.
- **Interop:** nginx-compatible CLI (`-c / -p / -e / -g / -t / -T / -V / -s`), `pid` file, SIGQUIT graceful shutdown. Upstream Perl test suite (`nginx-tests`) runs end-to-end against several files.

## What's intentionally not in v0.1 TLS

The TLS surface is deliberately minimal so the v0.1 scope stays
finishable. The following are tracked as future work, not bugs — please
don't file issues for them:

- HTTP/2 (ALPN advertises `http/1.1` only)
- OCSP stapling (`ssl_stapling*` parse and are silently ignored)
- Client certificate auth (`ssl_verify_client`, `ssl_client_certificate`, `ssl_trusted_certificate`, `ssl_crl`, `$ssl_client_*` variables)
- Session ticket key rotation, persistent / shared session cache (`ssl_session_ticket_key`, `ssl_session_tickets`, `ssl_session_cache shared:…`)
- 0-RTT / early data (`ssl_early_data`)
- TLS to upstreams (`proxy_ssl_*`)
- Per-location TLS overrides (TLS config is per-listen, resolved at startup)
- Hot certificate reload (cert/key files are read once at startup)
- Password-protected keys (`ssl_password_file`)
- Rehandshake / renegotiation (rustls does not support it)
- TLS hot-path perf tuning (buffer sizes, syscall counts in the read/write pump, owned-buffer round-trips, session cache size). The first measured number is in [`bench/tls/RESULTS.md`](bench/tls/RESULTS.md) — currently within ~10% of nginx on steady-state throughput and ~15% slower on single-thread fresh handshakes; expected to close.

See [`DESIGN.md`](DESIGN.md) for philosophy, architecture decisions, and roadmap; [`bench/README.md`](bench/README.md) for the benchmark suite and per-scenario results vs nginx 1.24.0.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

## Running tests

From the repository root (`/home/eugene/ruxen`):

The HTTPS integration tests in `tests/tls.rs` shell out to the system
`curl` binary and generate ephemeral certs at runtime via the `rcgen`
dev-dependency — install `curl` if it isn't already on your `PATH`. No
checked-in `.pem` files; nothing to refresh on cert expiry.

```bash
# 1) Run all Rust unit + integration tests.
cargo test --release

# 2) Run the upstream nginx-tests sweep (every .t file, sequential).
#    Builds target/release/ruxen automatically; per-file prove logs land
#    under .nginx-tests-out/logs/.
scripts/run_nginx_tests.sh

# 3) Run only selected test-file globs.
scripts/run_nginx_tests.sh --no-build 'http_*.t' 'proxy_*.t'
```

The sweep always runs every `.t` file (skipped tests are recorded as
SKIP with the `has_module` reason; tests that ran but failed are
recorded with their failed/total subtest fraction). If your
`nginx-tests` checkout is not at `../nginx-tests`, pass
`--tests-dir /path/to/nginx-tests`.
