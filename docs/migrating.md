# Migrating from nginx

ruxen reads nginx's configuration as it is, and has no directives of its
own: what it can't do the way nginx does, `ruxen --compat` lists. This guide
says, for each of its findings, what ruxen does instead, when that matters,
what to do about it, and which issue tracks it. Within each part, the most
common findings in real configurations come first (the corpus in
[`corpus/RESULTS.md`](../corpus/RESULTS.md)).

Checked against ruxen 0.2.2 and nginx 1.30.6.

## The steps

1. **Check.** `ruxen --compat -c /etc/nginx/nginx.conf`. Every `unsupported`
   line has to go before ruxen starts with the configuration; each `differs`
   line is a decision. Below, each finding has a section; `--compat` prints
   the links to the ones it found.
2. **Shadow.** Before ruxen answers a client, let it answer copies of your
   real traffic next to nginx: [`docs/shadow.md`](shadow.md). nginx stays in
   front, and `scripts/shadow-report.py` lists where ruxen answered
   differently. That also finds what `--compat` can't see.
3. **Switch.** Run ruxen as a service in nginx's place: [Running ruxen in
   place of nginx](#running-ruxen-in-place-of-nginx).
4. **Rollback** is starting nginx again: the configuration is still an
   nginx configuration.

## Reading `--compat`

```text
$ ruxen --compat -c /etc/nginx/nginx.conf
ruxen 0.2.2: checking /etc/nginx/nginx.conf
/etc/nginx/sites-enabled/mastodon:74: differs: gzip_static on — precompressed .gz files are not served (#760)
/etc/nginx/sites-enabled/mastodon:141: differs: proxy_buffering off — ruxen relays a response as it arrives either way, except where it still reads it whole (…: #463)
ignored: 4 tuning directives with no effect in ruxen: gzip_buffers, proxy_buffering, tcp_nodelay
what to do: https://github.com/gvozdetsky/ruxen/blob/v0.2.2/docs/migrating.md#gzip_static-on
what to do: https://github.com/gvozdetsky/ruxen/blob/v0.2.2/docs/migrating.md#proxy_buffering-off
ruxen starts with this configuration; 2 directives behave differently from nginx
```

- **unsupported**: ruxen refuses to start with it.
- **differs**: ruxen starts and does something other than nginx. A
  directive set to nginx's default (`ssi off`) isn't listed. Lines that
  start with `-:` are warnings without a place; the directive they name is
  enough to find it.
- **ignored**: tuning knobs with no visible effect, summed up in one line.

With nothing unsupported, the configuration is then loaded as `-t` loads it
(certificates, roots, log files). The exit status is 0 when ruxen starts
with the configuration.

## What stops ruxen (`unsupported`)

### FastCGI, uwsgi, SCGI, memcached

`fastcgi_pass`, `uwsgi_pass`, `scgi_pass`, `memcached_pass` and every other
directive of these modules (`fastcgi_param` from `fastcgi_params`, …).

- **ruxen:** proxies HTTP only (`proxy_pass`). These modules are out of
  scope for now ([`ROADMAP.md`](../ROADMAP.md), Positioning).
- **Do:** where the application server also speaks HTTP, proxy to that:
  uWSGI with `--http-socket` and `proxy_pass`, gunicorn or uvicorn instead
  of uWSGI. PHP-FPM speaks FastCGI only: keep nginx for PHP sites.
- **Issue:** none. Comment on the roadmap's positioning if you need one.

### `stream` and `mail`

- **ruxen:** HTTP only; no TCP/UDP proxy, no mail proxy.
- **Do:** move the `stream {}` or `mail {}` block to an nginx (or another
  TCP proxy) of its own, on its own ports, and run ruxen with the `http {}`
  part. Both can read the same `include` files.
- **Issue:** none; out of scope for now ([`ROADMAP.md`](../ROADMAP.md)).

### `root` or `alias` with variables

`root /var/www/$host;`, `alias /srv/$1;`.

- **ruxen:** refuses them. Taken literally, the path would point at a
  directory named `$host` and serve other files than nginx serves.
- **Do:** a literal `root` and `try_files` with the variable:
  ```nginx
  root /var/www;
  location / {
      try_files /$host$uri /$host$uri/index.html =404;
  }
  ```
  ruxen refuses a `Host` with `/`, `..` or a leading `.` (400), as nginx
  does, so `$host` can't leave the root. For `alias` with captures, one
  `location` per directory with a literal `alias`.
- **Issue:** [#232] (open).

### `grpc_pass`

- **ruxen:** no gRPC proxying: it needs HTTP/2 to the upstream and
  trailers.
- **Do:** keep nginx for the gRPC services.
- **Issue:** [#599] (open: HTTP/2 to upstreams, which gRPC needs first).

### `sub_filter`

- **ruxen:** doesn't rewrite response bodies.
- **Do:** produce the right body in the application, or keep nginx for
  that location.
- **Issue:** none.

### `location $var`

A predicate location (nginx 1.31.5): it matches when the variable is
neither empty nor `0`.

- **ruxen:** refuses it. Read as a prefix, as nginx 1.30 does, it would
  never match, and `location $blocked { return 403; }` would block nothing.
- **Do:** the same test with `if`, in the server:
  `if ($blocked) { return 403; }`.
- **Issue:** none yet; [#596] (closed) made ruxen refuse it.

### Other modules and unknown directives

`--compat` names the module when it knows it:

| module | do |
| --- | --- |
| `mirror` | keep it in the nginx in front; ruxen can be the mirror's target ([`docs/shadow.md`](shadow.md)) |
| `geo`, GeoIP | `map` on `$remote_addr` for single addresses, `allow`/`deny` for access; ranges need nginx |
| `secure_link` | `auth_request` to a service that checks the link |
| Lua (OpenResty), njs, embedded Perl | the logic moves to the application or an `auth_request` service |
| `image_filter`, XSLT, MP4/FLV streaming, WebDAV, `slice`, `userid` | keep nginx for those locations |

Any other unknown directive is a typo, a third-party module, or something
ruxen doesn't have yet. [`docs/directives.md`](directives.md) lists every
directive of nginx's core, events and http modules and what ruxen does with
it. If one you need is missing, please open an issue.

### An `include` that can't be read

- **ruxen:** can't start without it, and `--compat` goes on without its
  directives, so they are unchecked.
- **Do:** fix the path or the permissions and run `--compat` again. Run it
  as the user ruxen will run as when the files are readable only by some.

### `ssl_protocols` with only `TLSv1` or `TLSv1.1`

See [`ssl_protocols`](#ssl_protocols) below: with TLSv1.2 or TLSv1.3 listed
too, the line only differs.

## When the check stops

`--compat` goes past unknown directives, but any other error ends it
(`error: … the check stopped here`), as `-t` does. The ones real
configurations hit:

- `bad value for upstream server param: service=…`: SRV records for an
  upstream `server` (nginx 1.27.3). `server … resolve` without `service=`
  works. [#597] (open).
- `invalid location regex … repetition quantifier expects a valid decimal`:
  a `{` that doesn't start a quantifier, often a template variable that was
  never substituted (`^${PREFIX}/`). nginx's PCRE reads it as a literal.
  Escape it (`\{`), or substitute the template. [#763] (open).
- `bad value for disable_symlinks from=`: `from=` with a variable other
  than `$document_root`. ruxen refuses it rather than not enforce it; use
  `$document_root` or a literal path.

`error: … does not start with it on this machine` comes after the
configuration was read: a certificate, a root or a log file that can't be
opened, a port that can't be bound. Run `--compat` where ruxen will run.

## What ruxen does differently (`differs`)

### `proxy_buffering off`

- **ruxen:** relays every proxied response as it arrives, whatever
  `proxy_buffering` says. It still reads a response whole first where
  something needs all of it: a `proxy_cache` store, `add_trailer`, a status
  `proxy_next_upstream` may fail over on or `proxy_intercept_errors`
  intercepts, a range under `proxy_force_ranges`.
- **Matters:** for long-lived responses (server-sent events, long polling)
  in a location with one of those. With `proxy_buffering on`, nginx's
  default, the difference goes the other way: a slow client keeps the
  upstream busy until it has read the response (beyond what the socket
  buffers hold), where nginx reads the response into its buffers and frees
  the upstream. That counts for application servers with a few synchronous
  workers.
- **Do:** usually nothing. Keep streamed responses away from caching,
  `add_trailer` and failover on their status.
- **Issue:** [#463] (open: the cases still read whole), [#764] (open: buffering
  for slow clients).

### `ssl_protocols`

- **ruxen:** speaks TLS 1.2 and 1.3 only (rustls). `TLSv1` and `TLSv1.1` in
  the list are ignored with a warning; a list with nothing newer is refused
  (`unsupported`).
- **Matters:** only for clients that can't do TLS 1.2 (Android 4.3 and
  older, Java 6); browsers dropped 1.0 and 1.1 in 2020.
- **Do:** `ssl_protocols TLSv1.2 TLSv1.3;`. Keep nginx for a server whose
  clients need TLS 1.0.
- **Issue:** none; [#36] (closed) made the old names a warning.

### `gzip_static on`

- **ruxen:** doesn't look for `file.gz`; it sends `file`, compressed per
  request when `gzip on` and `gzip_types` cover it.
- **Matters:** CPU per request instead of once at build time, and the
  compressed response is chunked, with a weak `ETag`. With `gzip_static
  always`, clients without gzip get the plain file, which is what they can
  read anyway.
- **Do:** `gzip on;` with the types in `gzip_types` (`text/html` is always
  included).
- **Issue:** [#760] (open).

### `proxy_request_buffering off`

- **ruxen:** reads the whole request body before it connects to the
  upstream, spilling to `client_body_temp_path` beyond
  `client_body_buffer_size`, as nginx does with the default `on`.
- **Matters:** for large uploads: the upstream sees the body only once it
  is complete, and the disk holds it meanwhile. Applications that read a
  body as it streams in (progress, early rejection) wait.
- **Do:** room in `client_body_temp_path` and a `client_max_body_size`
  that fits; keep nginx for upload endpoints that need streaming.
- **Issue:** [#134] (open).

### `alias` and the trailing slash

`location /static { alias /srv/static/; }`: only one of them ends with `/`.

- **ruxen:** joins the location and the path with one `/`. nginx joins
  them as written, so `/static../x` maps to `/srv/static/../x`, outside the
  directory, and `location /img/ { alias /srv/img; }` maps `/img/x` to
  `/srv/imgx`.
- **Matters:** only for those URIs; ruxen's answer is the one the
  configuration most likely meant.
- **Do:** end both or neither with `/`. Then nginx and ruxen agree.

### Variables that are always empty

`variable "$date_gmt" is not supported yet and is always empty`.

- **ruxen:** renders the variable empty. Among them: `$date_gmt`,
  `$date_local`, `$request_completion`, `$nginx_version`, `$bytes_received`,
  `$gzip_ratio`, `$tcpinfo_*`, `$ssl_curve`, `$ssl_alpn_protocol`,
  `$upstream_trailer_*`, and those of modules ruxen doesn't have (`$geoip_*`,
  `$secure_link`, `$uid_*`).
- **Matters:** in a `log_format`, a missing field; in a header, an empty
  header; in `if` or `map`, a different branch.
- **Do:** check each use. Please open an issue for one you need.

### TLS settings in a server without TLS

`server with ssl_* directives but no listen … ssl; on its address`.

- **ruxen:** ignores them, as nginx does: no server on that address listens
  with `ssl`. Often a snippet (certbot's `options-ssl-nginx.conf`) included
  in a plain-HTTP server.
- **Do:** check the server is meant to be plain HTTP; otherwise add `ssl`
  to its `listen`.

### `ssl_ciphers`

`"ssl_ciphers" "…" selects none of the TLS 1.2 cipher suites ruxen has`.

- **ruxen:** applies `ssl_ciphers` as OpenSSL would, over the TLS 1.2
  suites rustls has (ECDHE with AES-GCM or ChaCha20-Poly1305), and
  `ssl_prefer_server_ciphers` decides whose order counts. A list that names
  none of them leaves TLS 1.2 with no suite: only TLS 1.3 is offered (an
  error when TLS 1.3 is off too). TLS 1.3 suites aren't affected.
- **Do:** add `ECDHE+AESGCM:ECDHE+CHACHA20` to the list, unless TLS 1.3
  only is what you want.

### `ssl_ecdh_curve`

- **ruxen:** uses rustls's default key exchange groups.
- **Matters:** only where a policy requires a specific list.
- **Do:** nothing, or keep nginx where the policy applies.

### HTTP/3 and QUIC

`listen … quic`, `http3`, `quic_*`.

- **ruxen:** no HTTP/3. A `quic` listen is ignored (no socket at all), and
  the other directives have nothing to apply to. The TCP listens serve
  HTTP/1.1 and HTTP/2; a server whose only listens are `quic` can't be
  reached.
- **Matters:** clients that came by HTTP/3 use TCP. An `Alt-Svc: h3=…`
  header you add makes them try UDP first, then fall back.
- **Do:** remove the `Alt-Svc` header while ruxen answers.
- **Issue:** none; HTTP/3 is in the 1.0 phase of [`ROADMAP.md`](../ROADMAP.md).

### `ssl_early_data on`

- **ruxen:** doesn't accept TLS 1.3 early data (0-RTT): a resumed client
  sends its first request after the handshake. `$ssl_early_data` is empty.
- **Matters:** one round trip on resumed connections; nothing breaks.
- **Do:** nothing.

### `ssl_conf_command`

- **ruxen:** its TLS is rustls; OpenSSL commands aren't applied.
- **Do:** check what the command set. `Options KTLS`: kernel TLS is [#673]
  (open). `Ciphersuites`: rustls's TLS 1.3 suites are AES-GCM and
  ChaCha20-Poly1305.

### `ssi`

`ssi on` differs; `ssi_types` and `ssi_silent_errors` are ignored; any other
`ssi_*` directive is `unsupported`.

- **ruxen:** no server-side includes: the `<!--# … -->` commands reach the
  client as they are.
- **Do:** keep nginx for those locations, or render the pages in the
  application.
- **Issue:** none.

### Charset conversion

`charset $variable`, `source_charset`, `override_charset on`.

- **ruxen:** adds a literal `charset` to `Content-Type` (`charset_types`),
  and converts nothing. A charset from a variable adds nothing; with
  `source_charset` different from `charset`, the response goes out without
  a charset.
- **Do:** serve the files in the charset you declare, and declare it
  literally.
- **Issue:** none; [#464] (closed) added the literal `charset`.

### `proxy_store`

- **ruxen:** doesn't write proxied responses to disk.
- **Do:** `proxy_cache` for a cache; for a mirror-on-demand of files, keep
  nginx.
- **Issue:** none.

### `gzip` in `if`

- **ruxen:** applies `gzip` in a location's `if`, not in a server's.
- **Do:** move it into a location.

### `chunked_transfer_encoding`

- **ruxen:** reads it in `server` and `location`; at `http` level or in
  `if` it is ignored (`on` everywhere).
- **Do:** set it in each server or location that needs `off`.

### Warnings nginx gives too

`low address bits of … are meaningless`, `load balancing method
redefined`, `the "http2_…" directive is obsolete`: `--compat` lists them
among the `differs` lines, but nginx warns and behaves the same.

## Ignored tuning directives

`ignored: N tuning directives with no effect in ruxen: …`: accepted and
ignored, since they tune nginx's own machinery (`tcp_nopush`,
`types_hash_max_size`, `proxy_buffers`, `open_file_cache`, `aio`, `*_temp_path`
of modules ruxen doesn't have, …). Nothing to do. Some notes:

- `daemon`, `master_process`: ruxen stays in the foreground, one process.
- `worker_cpu_affinity`, `worker_priority`: use the service manager
  (`CPUAffinity=`, `Nice=` in systemd).
- `aio`, `thread_pool`: file reads run on the worker; a slow disk stalls
  its connections ([#526], open).
- `env`: ruxen has no embedded languages to pass variables to.

## Running ruxen in place of nginx

### Processes and signals

One process with one worker thread per `worker_processes` (`auto`: one per
CPU), plus, when started as root, a small helper that stays root (see
[`user` and ports below 1024](#user-and-ports-below-1024)). Signals are
nginx's: `SIGHUP` reloads, `SIGQUIT` stops gracefully, `SIGTERM` and
`SIGINT` stop at once, `SIGUSR1` reopens the logs; `ruxen -s
reload|quit|stop|reopen` sends them to the process in the `pid` file.
`SIGUSR2` and `SIGWINCH` do nothing. Scripts that count nginx worker
processes see one process.

Responses carry `Server: ruxen/<version>` (`ruxen` with `server_tokens
off`), and the built-in error pages say ruxen. Change monitoring that
matches on `nginx`.

### systemd

[`contrib/systemd/ruxen.service`](../contrib/systemd/ruxen.service):
`Type=notify` (ruxen reports ready, reloading and stopping), a watchdog that
restarts ruxen when a worker stops making progress, a configuration check
before start and reload, `SIGQUIT` to stop, an unprivileged dynamic user
with `CAP_NET_BIND_SERVICE`, and hardening that lets io_uring through. It
reads `/etc/ruxen/ruxen.conf`; use absolute paths in it, since the working
directory is `/`, and the directories the unit creates: `/var/log/ruxen`,
`/var/cache/ruxen`, `/run/ruxen`. nginx's packaged unit is
`Type=forking` with a `PIDFile`; ruxen's doesn't fork.

### `user` and ports below 1024

Started as root, ruxen binds its ports, opens certificates and logs, then
switches the whole process to `user` (nginx's default `nobody`) before it
accepts a connection. A helper process stays root to recreate rotated log
files for that user and remove the pid file; it takes only fixed one-byte
commands. After the switch, a reload reads the configuration as `user` and
can't bind a new port below 1024 ([#344], open): restart to add one.
Started unprivileged, as the systemd unit and the container image do,
ruxen ignores `user` with nginx's warning; grant `CAP_NET_BIND_SERVICE` for
ports below 1024.

### Reload and binary upgrade

A reload (`SIGHUP`, `systemctl reload`) starts new workers with the new
configuration on the same listening sockets, so no connection is refused
or reset, and the old workers finish their requests, within
`worker_shutdown_timeout` if set. A configuration that fails to load is
logged and the running one stays. TLS session caches and the
`limit_req`, `limit_conn` and upstream zones carry over.

There is no binary upgrade (`SIGUSR2`). A new ruxen binary means a
restart: on `SIGQUIT` ruxen closes its listening sockets at once and
finishes the requests in flight, so new connections are refused until the
new process listens. Upgrade behind a load balancer, or at a quiet time.

### Log rotation

[`contrib/logrotate/ruxen`](../contrib/logrotate/ruxen) rotates
`/var/log/ruxen/*.log` and sends `SIGUSR1`, as nginx's does. No
`copytruncate` and no `create` needed: ruxen reopens the files and creates
them if moved away, through the root helper when it switched to `user`.

### Containers and the epoll fallback

ruxen runs on io_uring. Where io_uring isn't available it runs on epoll
and logs once at `notice`: `io_uring is not available, using epoll: …`.
That happens under Docker's and Kubernetes' default seccomp profiles, with
the `kernel.io_uring_disabled` sysctl, and on old kernels.
`RUXEN_DRIVER=epoll` picks epoll anyway; `RUXEN_DRIVER=io_uring` refuses to
start without it.

- **Matters:** epoll is slower for small requests (keep-alive throughput
  below 95% of nginx, [#337], open), and faster for large proxied bodies
  ([#757], open).
- **Do:** for io_uring in Docker, run with
  `--security-opt seccomp=contrib/docker/seccomp-io_uring.json`; in
  Kubernetes, install that profile on the nodes and refer to it as a
  `Localhost` profile. The README's [Run as a service](../README.md#run-as-a-service)
  has the commands, and the image (`ghcr.io/gvozdetsky/ruxen`) reads
  `/etc/ruxen/ruxen.conf`.

[#36]: https://github.com/gvozdetsky/ruxen/issues/36
[#134]: https://github.com/gvozdetsky/ruxen/issues/134
[#232]: https://github.com/gvozdetsky/ruxen/issues/232
[#337]: https://github.com/gvozdetsky/ruxen/issues/337
[#344]: https://github.com/gvozdetsky/ruxen/issues/344
[#463]: https://github.com/gvozdetsky/ruxen/issues/463
[#464]: https://github.com/gvozdetsky/ruxen/issues/464
[#526]: https://github.com/gvozdetsky/ruxen/issues/526
[#596]: https://github.com/gvozdetsky/ruxen/issues/596
[#597]: https://github.com/gvozdetsky/ruxen/issues/597
[#599]: https://github.com/gvozdetsky/ruxen/issues/599
[#673]: https://github.com/gvozdetsky/ruxen/issues/673
[#757]: https://github.com/gvozdetsky/ruxen/issues/757
[#760]: https://github.com/gvozdetsky/ruxen/issues/760
[#763]: https://github.com/gvozdetsky/ruxen/issues/763
[#764]: https://github.com/gvozdetsky/ruxen/issues/764
