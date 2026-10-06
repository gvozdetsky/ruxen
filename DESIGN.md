# ruxen — design notes

Working document. Captures what we've decided, why, and what we've learned from reading the nginx C source. Grows as we go. See `README.md` for the current feature set. Pre-release development history was squashed into the initial public commit; the milestone notes that still matter (M40–M43) live inline below.

## Philosophy

**Design-faithful, implementation-idiomatic.** Read the C to understand *why* nginx does what it does (phases, event loop, request state machine, output chains), then write Rust that captures the intent — not the mechanics.

We are not doing:

- **Pure 1:1 port.** nginx's memory pools, ref-counting, and function-pointer module arrays exist largely because C has no RAII, no ownership, no traits. Porting them verbatim fights the borrow checker to recreate problems Rust already solved.
- **Incremental FFI.** Replacing C modules one at a time via bindgen would bury us in `unsafe` and ABI glue before we learn anything about nginx itself.

## v0.1 scope

- Linux only
- HTTP/1.1 only, keep-alive required (benchmarks use it)
- TLS termination via rustls (server-side only); no modules; no caching
- **Thread-per-core** worker model with `SO_REUSEPORT` from day one (single-threaded wouldn't match nginx)
- **Zero-alloc request parsing and prebuilt `return` path.** Static-file responses still build a per-request header `Vec<u8>`; with `sendfile on` the body itself is sent zero-copy (see "Static file bodies and `sendfile`").
- Config: the smallest subset that proves the architecture

## Performance contract

**ruxen v0.1 must serve its minimal config at ≥ 95% of nginx 1.24.0's throughput on the same hardware, with p99 latency ≤ 4 ms and zero errors.**

Original baseline (measured 2026-04-16; the raw run log was not carried into the public repo — the current frozen nginx baseline for this workload is in [`bench/m1/RESULTS.md`](bench/m1/RESULTS.md)):

- nginx 1.24.0, 32 workers, `wrk -t16 -c512 -d30s` → **1,675,733 req/s**, p50 158 µs, p99 3.57 ms, 0 errors.

**Gate:** ≥ 1,591,946 req/s (95%), p99 ≤ 4 ms, 0 errors, same wrk invocation. Re-run after every change to the hot path — regressions are ship-blockers to fix.

## Runtime & I/O

- **monoio** — thread-per-core async runtime, io_uring-native. Rationale: nginx's performance comes from process-per-core + `SO_REUSEPORT` + per-worker accept queues = zero cross-core contention. Tokio's default multi-thread runtime is work-stealing, which has cache-line bouncing that's the exact opposite of what this workload wants. Published benchmarks show monoio/glommio matching or beating nginx on plaintext; tokio+hyper typically lags by 30–50%.
- **io_uring**, not epoll. We're Linux-only and kernel 6.17 has the full feature set — no reason to use the older interface.
- **No hyper.** Strict version. Writing the HTTP/1.1 parser and response path ourselves is the whole point of the project.
- **No `tokio` anywhere.** Monoio has its own TCP/IO primitives.

## Architectural decisions still in force

- **Graceful shutdown** lives in `worker::RuntimeState` — a shared `AtomicBool` polled between `accept` calls in the accept loop. The per-connection hot path is untouched.
- **Two path prefixes, as in nginx.** `-p` (the cycle prefix) is applied by `chdir` at startup, so `root`, `alias`, logs, and `pid` resolve against cwd. `include`, `ssl_certificate`, `ssl_certificate_key`, and `auth_basic_user_file` resolve against the main config's directory (nginx's conf prefix, `ngx_conf_full_name(cycle, name, 1)`), recorded by the lexer and applied at parse time. The two differ whenever `-c` points outside `-p`.
- **`Date` on every response, stamped at write time.** Like nginx's `ngx_cached_http_time`, the value is a per-thread cached IMF-fixdate (`src/http_date.rs`, `CLOCK_REALTIME_COARSE`, reformatted once per second). Builders write `Date` right after `Server`, but prebuilt heads are built at config time and their per-worker variant caches are shared, so the worker write path overwrites the 29-byte value in place (`stamp_date`, offset recorded by `scan_response_headers`) just before sending; prebuilt responses are copied into the connection's scratch buffer for that. Cost vs no `Date` in ABBA pairs (2026-10-02): `m1_hello` −1.1%, `add_header_many` −1.2%, 304 unchanged. The proxy drops the upstream's `Date` and sends its own, as nginx does by default.
- **Startup errors are `[emerg]` + exit 1, never a panic.** `worker::prepare` returns `Result`: it is where config meets the filesystem (certificates, `root`/`alias` fds, access/error log files), and `-t` runs it too, like `nginx -t` runs module init. Workers report readiness over a channel once their listeners are bound; `main` waits for all of them, so a busy port is one `bind() to … failed (98: …)` line, and the pid file — which Test::Nginx polls as "started" — appears only after every listener accepts. A missing `root` directory is not a startup error: as in nginx it is a 404 per request (`root` defaults to `html`). ruxen opens the root as its `openat2` anchor at startup when it exists, else in each worker on first use (`PreparedRoot::fd`; fds are per worker, see `unshare(CLONE_FILES)`). Remaining `panic!`s in `prepare` guard parser invariants.
- **`-g` inline directives** are prepended as a synthesized prefix before the config file is tokenized. Matches nginx semantics and reuses the existing parser.
- **`-V` feature claims** are intentionally minimal — only the `http` + `rewrite` "absence of `--without-…`" regexes in `Test::Nginx::has_module()` are satisfied. Expanding this is how we opt in to each new test group; a too-generous `-V` silently unlocks tests that fail for bad reasons.
- **Client timeouts on long-lived per-connection timers.** `client_header_timeout`, `client_body_timeout` and `send_timeout` (nginx's 60 s defaults; http and server scope) bound the first-request wait, the whole request header, each body read and each write — `send_timeout` per partial write, as nginx re-arms its timer after every send, so a slow but steady download isn't cut. The connection uses its address's default server's values throughout (nginx switches body/send timeouts to the chosen server/location). A `monoio::time::timeout` per operation cost ~3% on `m1_hello` / `proxy_hello` (ABBA): every call is a `Handle::current()`, a timer-wheel insert and a remove. Instead each connection owns three `Sleep`s (`worker::ConnTimers`: io, idle, tick) that are only moved forward, and monoio extends a registered timer to a later deadline without touching the wheel. The keep-alive wait's per-request `sleep`s moved onto them too, which pays for the new checks: 100.3% / 99.5% of the previous build on those scenarios.
- **Request bodies: memory, then a temp file; read before routing.** Bodies are read right after the header, before the location is known, into a `BodySink`: in memory up to 1 MiB (the proxy forwards those without a copy), then spilled to a temp file as they arrive. The chunked decoder streams chunk data into the sink and drops consumed input, so memory stays bounded whatever the chunk sizes. Before reading, the request is routed far enough to find the location's `client_max_body_size` (`phase::first_body_limit`, nginx's default 1m; `0` = unlimited), so a Content-Length over it is a 413 without reading the body, as nginx does. The spill files are created `0600` and exclusively, in `client_body_temp_path` (http scope) or a private `0700` directory under `$TMPDIR`. A body in the file has an empty `$request_body` and a `$request_body_file`, as in nginx, and `run_proxy` streams it to the upstream after the header block, reopening the file per attempt so failover re-sends it.
- **`worker_connections` per worker, with idle reuse.** `events { worker_connections N; }` (default 512) caps each worker's connections at N minus the listening sockets, as listeners use slots in nginx. Upstream connections count too, in the pool as well (`UpstreamSlot`), since nginx takes them from the same table; there is no master channel, so a worker has one slot more than nginx's. A new upstream connection without a slot first closes an idle keep-alive one, else the request gets a 500 with the `[alert]` below (ngx_http_upstream_connect); a new client closes an idle keep-alive upstream connection before it is refused. Accounting is thread-local (`WorkerConns`: active / idle / drain) because a worker owns its connections. Like `ngx_drain_connections`, when free slots drop to a sixteenth, up to 32 (an eighth) of the connections waiting for a request are asked to close; they notice on their 50 ms idle tick. With no slot left, the new connection is closed and `[alert] N worker_connections are not enough` is logged, at most once a second (the reuse case logs `[warn] …, reusing connections`). Without the reuse, idle sockets could hold every slot until their timeouts.
- **Error-log lines use nginx's layout and context.** `2026/10/02 14:00:00 [error] <pid>#<tid>: *<connection> <message>, client: …, server: …, request: "…", upstream: "…", host: "…"` (`worker::write_error_log`; times in UTC like `$time_local`). Failed upstream attempts are logged with nginx's wording (`connect() failed (111: Connection refused) while connecting to upstream`, `upstream timed out … while reading response header from upstream`, `no live upstreams …`): `proxy::run_proxy` appends them as `AttemptFailure`s to a `Vec` the worker passes in, and the worker adds the request context. The happy path allocates and formats nothing; the reason is boxed inside `AttemptOutcome::Failed` because growing that enum (every attempt returns one) cost ~1.5% on `proxy_hello` in ABBA pairs, and so did wrapping the result in a second async layer. `error_log` is inherited like nginx's (location ← server ← http ← top level). With none in scope, lines go to stderr at level `error` (nginx's default is its compiled-in `logs/error.log`; ruxen runs in the foreground and `-e` redirects stderr). `syslog:` targets send nginx's RFC 3164 datagrams (`src/syslog.rs`), for `access_log` too.
- **Responses say ruxen; the test harness gets nginx.** `Server` and the built-in error pages' footer carry `ruxen/<version>` (`http::identity`). nginx-tests asserts `nginx/<version>` (`server_tokens.t`, error-page bodies), so `scripts/run_nginx_tests.sh` sets `RUXEN_NGINX_IDENTITY=1`, read once at config preparation, never on the request path. `-V` keeps its nginx line in both modes: Test::Nginx parses it to decide which tests apply.
- **Unknown-directive policy** is an explicit allowlist, not "accept everything". An unknown directive in a test config almost always means the test exercises a feature we don't implement; silently accepting would produce a wrong-looking pass instead of a clear "not yet" failure. The allowlist is for tuning knobs only: a directive that restricts access (`limit_except`, `ssl_verify_client on`, `ssl_reject_handshake on`, `user` when started as root) fails closed with an `[emerg]` until it is implemented, because ignoring it would serve what the config says to protect (`config::reject_unenforced`, checked by the lexer for every directive; `user` in `main::check_privileges`). Warnings only: `ssl_ciphers` / `ssl_ecdh_curve` (rustls has no weak suites or groups to fall back to), and `ssl_verify_client optional|optional_no_ca` — nginx admits certless clients there too and leaves the decision to `$ssl_client_verify`, which ruxen always renders `NONE`, so a `= SUCCESS` check denies.
- **Out of scope for nginx-tests interop:** any `.t` that uses `Test::Nginx::Stream`, `Test::Nginx::IMAP`, `Test::Nginx::SMTP`, `Test::Nginx::POP3`; any test whose conf references directives outside the allowlist; any test requiring dynamic-module loading. The full per-file pass/fail/skip taxonomy lives in [`NGINX_TEST_PROGRESS.md`](NGINX_TEST_PROGRESS.md); regenerate it via `scripts/run_nginx_tests.sh --update-progress`.

### Why the nginx-tests track matters

- External validation. The upstream suite encodes corner cases we haven't thought of (method handling, Host edge cases, 404 vs 403 policy, header canonicalization). Passing even a handful of its `.t` files is a stronger correctness signal than any tests we write ourselves.
- Forcing function for CLI and lifecycle surface — real nginx interop required the `-c / -p / -e / -g` handshake, PID files, and signal-driven lifecycle.
- Feeds future planning. Every failing `.t` file is a direct vote for which directive or module to implement next, replacing guesses about what matters.

## Notes from reading the C source

### `src/core/ngx_conf_file.c` — config parser

**Architecture:** tokenizer-driven recursive descent. Two functions do everything.

- `ngx_conf_read_token` (lexer). Reads one directive's worth of whitespace-separated tokens into `cf->args`, returns a **terminator code**: `NGX_OK` (`;`), `NGX_CONF_BLOCK_START` (`{`), `NGX_CONF_BLOCK_DONE` (`}`), `NGX_CONF_FILE_DONE` (EOF).
- `ngx_conf_parse` (loop). Call tokenizer → dispatch `cf->args[0]` via `ngx_conf_handler` → if terminator was `{`, recurse into `ngx_conf_parse` in `parse_block` mode.

**Dispatch is table-driven.** Each module exposes `ngx_command_t[]`: `{ name, type-bitmask, set-fn, conf, offset, post }`. Parser matches on name, validates `type` (allowed arg count *and* allowed context like "only inside `http {}`"), calls the `set` handler. The `offset` field is a pointer-arithmetic substitute for "write this field of the conf struct" — Rust gets this for free.

**Lexer handles:** `#` line comments, `"…"` / `'…'` quoted strings, `\` escape, `$` variable prefix, buffered refills of `b->pos..b->last`.

**Rust mapping:**

- Tokenizer: `Iterator<Item = Directive>` where `struct Directive { args: Vec<String>, kind: Terminator }` with `Terminator = Semicolon | BlockOpen | BlockClose | Eof`. Kills the int-return-code + `cf->args` side-channel pattern.
- Dispatch: a `DirectiveHandler` trait + a registry keyed on name. Replaces the `ngx_command_t` table, function pointers, and `void *` offsets.
- Config parsing happens **once at startup** and produces an immutable `HttpConfig` tree. No allocation concerns here — the hot path never touches the parser.

### `src/http/ngx_http_parse.c` — request-line & header state machine

**Shape.** One function per thing (`ngx_http_parse_request_line`, `ngx_http_parse_header_line`, `…_uri`, `…_chunked`). Each is a `for (p = b->pos; p < b->last; p++) switch (state)` loop. Compilers lower this to a computed-goto jump table (the comment on line 105 even says so). Each byte costs one table-jump + one comparison.

**Resumable by design.** On exhaustion of the buffer the function writes back `b->pos = p; r->state = state; r->header_hash = hash; r->lowcase_index = i` and returns `NGX_AGAIN`. Caller reads more bytes into the same buffer (appends at `b->last`), then re-enters the parser — which picks up exactly where it left off, mid-header, mid-URI, wherever.

**Tricks worth stealing.**
- **`usual[]` bitmap** (line 17): 256-bit table of "benign" URI chars, packed into 8 `uint32_t`s. `usual[ch >> 5] & (1U << (ch & 0x1f))` is a branchless tchar check.
- **`lowcase[]` LUT** in `parse_header_line` (line 875): 256-byte table that returns the lowercased char for valid token chars and `0` for everything else. Validates + normalizes in one lookup.
- **Rolling hash** built per-byte while parsing the name (`hash = ngx_hash(hash, c)`). At header-done, `ngx_hash_find` dispatches to the handler by hash — no strcmp per known header. Combined with `lowcase_header[NGX_HTTP_LC_HEADER_LEN]` (power-of-two ring-buffered lowercase copy) the hash-match is confirmed with one memcmp.
- **`ngx_str3_cmp` / `ngx_str4cmp`** on little-endian + unaligned hosts: the method switch reads 4 bytes as a single `uint32_t` and compares against a packed literal. `"GET "` as `'G' | ('E'<<8) | ('T'<<16) | (' '<<24)` = one load, one `==`.

### `src/http/ngx_http_request.c` — request lifecycle

**Handler chain, not a function.** A "request" isn't a call — it's a sequence of epoll callbacks:

```
accept →
  ngx_http_init_connection  (no buffer yet; sets rev->handler = wait_request_handler)
    wait_request_handler    (only here does c->buffer get allocated; reads first bytes)
      process_request_line  (loops: read → parse_request_line; NGX_AGAIN re-arms epoll)
        process_request_headers  (loops: read → parse_header_line; per-header dispatch)
          process_request   (run 11 phases: rewrite, access, content, …)
            write body / filter chain
              finalize_request → set_keepalive
                (idle)        → keepalive_handler → wait_request_handler (loop)
                (pipelined)   → create_request → process_request_line   (loop)
                (close)       → close_connection
```

**Lazy buffer allocation is the keep-alive memory trick.** `wait_request_handler` only calls `ngx_create_temp_buf` once readable data arrives; `set_keepalive` calls `ngx_pfree(c->pool, b->start)` on transition to idle, and uses `b->pos = NULL` as a sentinel meaning "buffer is gone". Idle keep-alive connections thus hold only the `ngx_connection_t` + `ngx_http_connection_t` + a tiny pool — no 8 KiB read buffer. At 10 k idle keep-alives that's the difference between ~80 MB and ~1 MB.

**Pipelining.** After `set_keepalive`, if `b->pos < b->last` there's a follow-up request already in the buffer — nginx does **not** memmove; it creates a new `ngx_http_request_t` over the remaining bytes in place (`r = ngx_http_create_request(c); r->pipeline = 1;`) and posts the parse directly.

**Header dispatch.** After each header is parsed, nginx does `ngx_hash_find(&cmcf->headers_in_hash, h->hash, lowcase_key, len)` and calls the per-header handler (`ngx_http_process_connection`, `ngx_http_process_host`, …) which writes into `r->headers_in` struct fields.

**`post_action` runs after the main response and suppresses its own output.** `ngx_http_finalize_request` calls `ngx_http_post_action` after the main request is done but before keep-alive finalization. The helper reads the effective core location config's `post_action`, sets `r->http_version = NGX_HTTP_VERSION_9`, `r->header_only = 1`, and `r->post_action = 1`, then internally redirects to a `/uri` target or jumps to a named location. `ngx_http_send_header` returns `NGX_OK` immediately for post-action requests, so the post-action body/header never reaches the client, but the internally redirected request still runs content handlers and reaches access logging.

### `src/core/nginx.c` + `src/os/unix/ngx_process_cycle.c` — process model

Master-worker via `fork()`: `ngx_start_worker_processes` spawns N workers, keeps socketpair channels for control messages (`NGX_CMD_OPEN_CHANNEL`, reload, shutdown). `SO_REUSEPORT` is set per-listen-socket in the workers, same as we do.

We use OS threads, not processes. Consequences:
- Shared address space → `&'static PreparedServer` works, no IPC needed for config.
- Worker crash = whole-process crash; no per-worker supervision.
- No live reload via `SIGHUP`-then-exec-then-handoff-listen-fds (nginx's binary upgrade path).
- **One fd table per worker anyway.** Threads share the process fd table, and every `open`/`close` takes its spinlock (`alloc_fd`, `file_close_fd`). With one open + close per static request on 32 workers, that lock was 5–8% of CPU on the 304 bench (`native_queued_spin_lock_slowpath`); nginx's worker processes never contend on it. Each worker calls `unshare(CLONE_FILES)` first thing, which gives the thread a private copy of the table. That is safe because no fd crosses threads after startup (root-dir fds and stdio are opened before the workers spawn and get copied; listeners, the io_uring ring, connections, per-request files, and access-log handles are opened by the worker that uses them). Measured with ABBA pairs on one binary (`RUXEN_UNSHARE_FILES=0` restores the shared table): 304 +4.7%, 1 KiB static +3.6%, `return 200` unchanged. `tests/m46_worker_fd_table.rs` checks it via `/proc/<pid>/task/*/fd`.

All acceptable for v0.1. Reload-without-drop is a v1+ concern; we can either re-exec like nginx or move to a master-supervisor model later.

### `src/http/ngx_http.c` + `ngx_http_core_module.c` — virtual servers, locations, phases

File:line citations are against the stock 1.24.0 checkout one directory up.

**Server name match tables are built per-listen-socket.** `ngx_http_server_names` (ngx_http.c:1541–1654) walks every `server_name` directive in every `server {}` under one `listen`, partitions them into four categories by first byte (`ngx_http.c:4486–4523`):

- Exact names → one hash (`hash.hash`)
- `*.foo.com` (wildcard-head) → `wc_head` hash
- `.foo.com` / `foo.*` (wildcard-tail) → `wc_tail` hash
- `~regex` → `regex[]` array

Exact + both wildcard hashes go into an `ngx_hash_combined_t`, looked up in that order by `ngx_hash_find_combined` (ngx_http_request.c:2501–2503). Regex is tried last, linearly (request.c:2512–2568). All names are **lowercased at config time** (`ngx_hash_key_lc`, ngx_http.c:1601), so lookup is pure hash-compare; the incoming Host is lowercased *by the parser* before the hash is finalized (request.c:2251–2253, 2388–2395). No per-request casefolding on the hot path.

**Default server is a per-listen-socket field, not a server_name.** `addr->default_server` (ngx_http.c:1661) is resolved at config merge; picked when every lookup misses. Unknown or missing Host → default server, *not* 404.

**Host validation happens in `ngx_http_validate_host`** (request.c:2210–2404). Port suffix is **stripped before matching** — `*hostp` is returned port-less, `*portp` holds the port separately (request.c:2266, 2397–2401). Trailing dot is peeled (2380–2382). IPv6 literals in `[...]` are allowed. Empty host → `NGX_DECLINED` (2384–2386). Missing Host on HTTP/1.1 = 400 (request.c:2034–2039); HTTP/1.0 is allowed through with empty `server.len`, which also falls to default. Duplicate Host header = 400 (request.c:1873–1881).

**Location matching is a binary search tree, not a trie.** `ngx_http_core_find_static_location` (core_module.c:1494–1570) walks an `ngx_location_tree_node_t` tree keyed on prefix. On an exact `=` hit at the current node (`node->exact`), it returns `NGX_OK` immediately — that's final. Otherwise it tracks "best prefix so far" via `rv = NGX_AGAIN` (line 1531) and keeps descending. Regex locations (if any) are tried after the prefix walk in a linear loop (core_module.c:1454–1478), **unless** the matched prefix was declared `^~` (noregex flag).

**Longest prefix wins via tree depth**, not a separate sort. We use a length-sorted `Vec` because our counts are tiny; the complexity of a location tree only pays off past a few dozen locations.

**Phases: 11, enum `ngx_http_phases` in core_module.h:111–129.** Order: POST_READ, SERVER_REWRITE, **FIND_CONFIG**, REWRITE, POST_REWRITE, PREACCESS, ACCESS, POST_ACCESS, PRECONTENT, **CONTENT**, LOG.

- `FIND_CONFIG_PHASE` is **hardcoded** — not registerable like the others. `ngx_http_core_find_config_phase` (core_module.c:970) just calls `ngx_http_core_find_location(r)` inline.
- Every other phase is a list of `ngx_http_phase_handler_t` entries; modules push to `cmcf->phases[i]` at config time, then `ngx_http_init_phase_handlers` linearizes them into one flat `phase_engine.handlers[]` array.
- Each handler has a `checker` (phase semantics) and a `handler` (the actual work). Checker returns `NGX_OK` → next phase (`r->phase_handler = ph->next`), `NGX_DECLINED` → next handler (`r->phase_handler++`), `NGX_AGAIN`/`NGX_DONE` → pause (core_module.c:906–939).
- **`return` is a rewrite-module directive, not a content handler.** It answers in SERVER_REWRITE / REWRITE, so ACCESS (`auth_basic`) never runs for it — `location / { auth_basic "x"; return 200; }` serves 200 without credentials. A `break` ends the rewrite script before a later `return` is reached, so access control does run then. ruxen stores a top-level location `return` as `PreparedHandler::Return` and skips access control for it unless the rewrite program ended on `break`.

**Header dispatch is a real hash, built at startup.** The `ngx_http_headers_in[]` static array (request.c:80–206) pairs name → `offsetof(ngx_http_headers_in_t, field)` + handler. `ngx_http_init` (ngx_http.c:418–446) calls `ngx_hash_init` over this array, case-folding keys. During parsing, the rolling hash `hash = ((hash << 5) + hash) ^ c` is computed byte-by-byte in the sw_name state; at `:` the finished hash + lowercased key + length goes to `ngx_hash_find` (request.c:1540–1541).

**Mapping for ruxen.** Rust's `match` on `(hash, len)` with the lowercased copy confirmed by memcmp is strictly simpler than porting `ngx_hash_t`'s bucket-chain structure — same complexity, none of the pointer arithmetic. A `struct HeadersIn { host: Range, connection_keep_alive: bool, ... }` full of typed fields, populated in `ParseState`, matches nginx's flat-struct `r->headers_in` without the `offsetof` dance.

### `src/http/modules/ngx_http_static_module.c` + `ngx_http_index_module.c` + `ngx_http_try_files_module.c` — filesystem routing

All three are CONTENT-phase (or PRECONTENT, for try_files) handlers that share a single concern: how to map a request URI into a file on disk.

**`ngx_http_static_module.c` — the baseline.** One handler (`ngx_http_static_handler`, 278 LoC) registered on `NGX_HTTP_CONTENT_PHASE`. Flow (static_module.c:49):

- If the URI ends with `/`, return `NGX_DECLINED` (line 67–69). That lets the index module take over. This is the protocol between static and index — not a fallthrough, a two-handler chain.
- Otherwise `ngx_http_map_uri_to_path` builds `<root><uri>` (line 78).
- Open the file via `ngx_open_cached_file`. ENOENT/ENOTDIR/ENAMETOOLONG → 404; EACCES/EMLINK/ELOOP → 403; other errors → 500 (line 106–134).
- If the opened entity is a *directory* (URI without trailing slash), emit `301 Moved Permanently` with `Location: <uri>/?<args>` (line 148–204). Args are preserved; URI is re-escaped if it contains characters that need encoding.
- Otherwise it's a file: set headers (ETag, Last-Modified, Content-Length, Content-Type), `r->allow_ranges = 1`, send headers + the file via the output filter chain.

**`ngx_http_index_module.c` — directory → file.** One handler (`ngx_http_index_handler`, 185 LoC) also on CONTENT_PHASE, also runs only when the URI ends with `/` (line 112–114). For each configured index name:

- If the name is *absolute* (starts with `/`) and has no variables, `ngx_http_internal_redirect(r, &index[i].name, &r->args)` (line 135–137) — the name becomes the new URI and re-enters location matching.
- Else compute `<root><uri><name>` (`ngx_http_map_uri_to_path` + `ngx_memcpy`, line 162–178), `open_cached_file` with `test_only = 1`. On ENOENT, fall through to the next index. On other errors, 500 or 403.
- Between the first probe and subsequent ones, `ngx_http_index_test_dir` checks that the *directory itself* exists (line 242–250). This differentiates "index names missing" (403 per `ngx_http_index_error`) from "directory doesn't exist" (404).
- On hit: `ngx_http_internal_redirect(r, &uri, &r->args)` with `uri = <request uri><index name>` (line 277).
- Merge rule (`ngx_http_index_merge_loc_conf`, line 405–439): child list, if non-null, replaces parent's. If both empty, default to `["index.html"]`.

**`ngx_http_try_files_module.c` — probe-then-rewrite.** One handler on `NGX_HTTP_PRECONTENT_PHASE` (try_files_module.c:395–396) — note the phase is *earlier* than static/index, so a try_files match rewrites `r->uri` before those handlers run. For each probe except the last:

- Name ending with `/` and not the last arg → `test_dir = 1` (line 318–325).
- `open_cached_file` with `test_only = 1` (line 222). ENOENT/ENOTDIR → `continue`; match against `of.is_dir == test_dir` to confirm file-vs-dir (line 248–250).
- On hit: `r->uri = path` (the URI under root), then `NGX_DECLINED` (line 252–283). That lets the content phase re-dispatch under the new URI.

The last arg is the fallback:

- Starts with `=` → parse code, `return tf->code` (line 196–198 and 350–362).
- Starts with `@` → `ngx_http_named_location` (line 203–204).
- Else → `ngx_http_internal_redirect` with the URI (line 206–210).

### `src/http/modules/ngx_http_map_module.c` — `map $source $dest { ... }`

- **Two match surfaces, same block.** The parser splits entries into (a) an exact-string hash and (b) a declaration-ordered regex list (map_module.c:`ngx_http_map_find`). Exact lookups run first; the regex list runs only when no exact hit and is linear (short-circuits on first match). This is why exact-matches beat regex patterns even when both would apply.
- **`default` is optional.** Absent default ⇒ unmatched renders empty — nginx distinguishes this from an explicit `""` default only to the extent that the fallback vs. empty-string sites diverge elsewhere; for rendering purposes both produce the same bytes.
- **Values are complex values.** RHS may reference other `$vars`, including the source. Rendering happens lazily per request — maps are not pre-rendered at startup.
- **Rust mapping.** We fold the exact side into a `HashMap<Vec<u8>, &'static [PreparedValuePart]>` (nginx uses `ngx_hash_t`; the shape is the same), keep regex entries in declaration order with pre-compiled `regex::bytes::Regex`, and stash `default` as an `Option`. Dispatch lives in the `Variable::Unknown` render path right after `split_clients` — same architectural slot, different matching rule. Deferred: `ngx_http_geo_module` (IP-keyed sibling). `hostnames` and `volatile` are implemented since.
- **Caching.** nginx caches every cacheable variable in `r->variables` for the whole request, internal redirects included. ruxen caches only `map` results: the first one per map is kept in `RewriteState` (which already outlives internal redirects and is kept for the access log), unless the map is `volatile`. Other variables, `split_clients` included, are evaluated on each reference; that differs from nginx only when their inputs change mid-request, which `map` over `$uri` (`map_volatile.t`) is the known case of.

### `src/http/ngx_http_special_response.c` + `ngx_http_core_module.c` — `error_page`

- **Merge rule is pointer inheritance.** `ngx_http_core_merge_loc_conf` copies `prev->error_pages` only when the child pointer is null (core_module.c:3844–3845). That means repeated `error_page` directives at one scope accumulate, but any child scope with at least one entry replaces the parent list outright.
- **Parser shape:** `error_page status... [=NNN|=] target;` (core_module.c:4919–5031). The parser compiles the target as a complex value, so variables are legal, and pre-splits literal `/uri?args` forms once at config time.
- **Runtime dispatch lives in special-response handling.** `ngx_http_special_response_handler` checks the current location's `error_pages` before building the builtin error body (special_response.c:464–474). Default recursion policy is off: once an `error_page` reroute has fired, nginx suppresses a second pass unless `recursive_error_pages on` is configured.
- **Internal URI targets** call `ngx_http_internal_redirect(r, &uri, &args)` (special_response.c:617–631). `r->uri` and `r->args` are replaced, but `r->unparsed_uri` remains the original request line and `valid_unparsed_uri` is cleared (core_module.c:2559–2603). This is why `$request_uri` stays original while `$args` changes on an error-page reroute.
- **Named-location targets** call `ngx_http_named_location(r, &uri)` (special_response.c:633–635). That jumps straight to the prepared named location without rewriting `r->uri` or splitting args, which is why `$uri` / `$args` stay on the current request URI when `error_page ... @name` fires.
- **Absolute-URL targets** do not reroute; nginx synthesizes a fresh `Location` header and defaults the response code to 302 unless the explicit overwrite code is itself a redirect status (special_response.c:640–676).

**Rust mapping.** Nginx's three-module split isn't load-bearing for us — we have no filter chain, no subrequest engine, no open_file_cache. We fold static + index + try_files into one `fs_resolve::resolve()` function returning an `Outcome` enum. Phases stay a name, not a dispatch table: `FindConfig` + `ResolveFsPath` + `Content`. Try_files runs first, then static/index; the hop budget lives in `phase::process` so all reroutes share one counter.

**Performance note.** Root containment is one `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` from the root's dirfd (`fs_resolve`), which walks and checks the path in a single syscall. (It used to be `std::fs::canonicalize` on every served file, about six syscalls per request.)

### `src/http/ngx_http_upstream.c` + `ngx_http_upstream_round_robin.c` + `ngx_http_modules/ngx_http_proxy_module.c` + `ngx_http_upstream_keepalive_module.c` — reverse proxy

**Five-phase upstream state machine** (`ngx_http_upstream.c`). Each phase is an event-driven step the runtime re-enters; the request keeps moving between read/write handlers as the kernel signals readiness. State per-attempt: `request_sent`, `response_received`, `header_sent`, the read buffer (`u->buffer`, lazy-alloc on first recv), parsed `headers_in`, and timing fields. Order:

1. **`init_request`** (line 581) — allocate request buffer, call `u->create_request()` (proxy module fills it with the request line + headers), set up read/write handlers. All validation before any I/O.
2. **`connect`** (1557) — LB `get_peer()` then non-blocking `connect()`. NGX_OK/AGAIN/DONE → arm send/process handlers; NGX_BUSY → no live peers (FT_NOLIVE fallover); NGX_DECLINED → LB error (FT_ERROR fallover).
3. **`send_request`** (2148) — write request body. ERROR → fallover; AGAIN → arm send_timeout; OK → mark `request_body_sent=1`, arm read_timeout, possibly call process_header inline if read ready.
4. **`process_header`** (2440) — read into `u->buffer`, call `u->process_header()` (proxy: parse status line, then headers). On parse error → FT_INVALID_HEADER fallover; on success → `send_response`.
5. **`send_response`** (3250) — write client response headers, then either buffered (event pipe) or non-buffered (process_non_buffered_*) body forwarding.

**Half-closed states.** After full request sent but before response: read_timeout governs. If read event fires while write pending → posted via `ngx_post_event`. On fallover mid-response → SSL clean shutdown, free peer FAILED, reconnect.

**Fallover boundary** (`ngx_http_upstream_next`, 4573). Continue to next peer **only if** `tries > 0` AND error type is in `next_upstream` bitmask AND not (idempotency violated: POST/PATCH after request already sent) AND `next_upstream_timeout` not exceeded. Else: map fault type to client status (TIMEOUT→504, ERROR→502, HTTP_500→500, etc.). Idempotent + body sent + non-idempotent method → mark FT_NON_IDEMPOTENT and stop.

**Round-robin LB** (`ngx_http_upstream_round_robin.c`). Three-function contract: `init_peer` (per-request setup, tried bitset), `get_peer` (select among eligible), `free_peer` (post-attempt accounting).

- **Eligibility filter** in `get_peer` (811): skip if already-tried, `peer->down`, or `fails >= max_fails && (now - checked) <= fail_timeout`, or `conns >= max_conns`.
- **Weighted RR via smoothed weights**: each peer carries `weight` (immutable config), `effective_weight` (gets penalized on failure, recovers up to `weight`), `current_weight` (per-round accumulator). Each call adds `effective_weight` into `current_weight`, picks max, deducts total weight from chosen.
- **`free_peer`** (1008): on PEER_FAILED, increment `fails` and decrement `effective_weight` by `weight/max_fails` (floor at 0). On success, reset `fails`. Recovery is automatic: peer becomes eligible again `fail_timeout` after the last check.

**Proxy module** (`ngx_http_proxy_module.c`).

- **`create_request`** (1176) builds the upstream wire bytes: `METHOD URI HTTP/<version>\r\nHost: ...\r\n[custom headers]\r\n\r\n[body]`. The Host header is computed from `proxy_pass`, **not** the client's Host (this is the canonical surprise — `$proxy_host` is the upstream's host:port, not the request's).
- **Default headers always overridden** (747–757): `Connection`, `Proxy-Connection`, `TE`, `Keep-Alive`, `Expect`, `Upgrade` are blanked (hop-by-hop; never forwarded). `Content-Length`/`Transfer-Encoding` recomputed from request body length / chunked flag. RFC 7230 §6.1 enumerates the canonical hop-by-hop set.
- **`process_status_line`** (1742) parses the response status; HTTP/1.0 response sets `headers_in.connection_close = 1`. **`process_header`** (1828) reuses the request-header parser in response mode and dispatches each header to handlers that mark semantically important ones (Content-Length, Connection, Transfer-Encoding).
- Directives → location conf: `proxy_pass` (parsed at config time, stored as upstream-block reference or literal host:port; `$var` form requires resolver — out of scope for v0.1), `proxy_set_header` (compiled into a script, evaluated per-request), `proxy_pass_request_headers/body` (booleans), `proxy_http_version` (1.0/1.1), `proxy_*_timeout` (ms).

**Keepalive pool** (`ngx_http_upstream_keepalive_module.c`). Per-upstream-block queue of `{ connection, sockaddr }` items. Linear search by sockaddr (240–248). Lifecycle:

- **`get_keepalive_peer`** (205) wraps the LB's get_peer, then searches the cache for a connection matching the chosen peer's sockaddr. Hit → reset connection state, mark `pc->cached=1`, return NGX_DONE. Miss → use a fresh connection.
- **`free_keepalive_peer`** (278) decides whether to cache. **Don't cache** if: PEER_FAILED, EOF / error / timeout on either direction, `c->requests >= conf->requests`, age `> conf->time`, `!u->keepalive` (upstream said `Connection: close`), `!u->request_body_sent`, or graceful shutdown. Otherwise enqueue with idle timeout.
- **HTTP/1.1 + Connection blanking is mandatory.** `proxy_http_version 1.1` + `proxy_set_header Connection ""` is the recipe — without both, upstream sees the client's `Connection: close` (or omitted Connection on HTTP/1.0) and won't keep the socket alive.

**Mapping for ruxen.**

- **No event-driven recursion.** monoio gives us `async fn` directly — the whole upstream attempt is one `async fn run_proxy_attempt() -> Result<Bytes, ProxyError>` with explicit `await` points at connect/send/recv. No equivalent of `ngx_post_event` is needed.
- **Sync→async handoff via `Response::Proxy(ProxyPlan)`.** `phase::process_with_meta` stays sync; the location handler emits a plan; the worker task awaits `proxy::run_proxy(plan)` and feeds the result back into the existing add_header / Connection-injection / write path. Mirrors how `Response::File` carries an fd that the worker streams.
- **Per-worker keepalive pool, no shared state.** `RefCell<Vec<PooledConn>>` keyed on `(upstream_index, peer_index)` is enough — thread-per-core means no locking. The M42 implementation uses this shape.
- **Hop-by-hop strip table is a small `&[&[u8]]` constant.** `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`, `Transfer-Encoding`, `Upgrade`. Strip both directions. Plus `Connection`'s value is itself a comma-separated list of additional headers to strip (per RFC 7230).
- **Timeouts via `monoio::time::timeout(Duration, fut)`.** No timer wheel needed; one timeout wrapper per I/O step.
- **Out of scope for v0.1**: `$var` in `proxy_pass` URL (rejected at parse time — needs `resolver`), `proxy_buffering off`, `proxy_request_buffering off`, `proxy_cache*`, `proxy_ssl_*`, UNIX-domain `server unix:/path`, `ip_hash` / `hash` / `random` / `sticky`, gRPC / HTTP/2, `mirror`, `proxy_protocol`.

**M40 status (2026-04-28).** Minimum-viable proxy landed: `proxy_pass http://host:port` and `proxy_pass http://upstream_name` parse + work end-to-end. Upstream connection is a fresh TCP per request, HTTP/1.0 with `Connection: close`, read until EOF, hop-by-hop strip on the response. Hardcoded 60s connect/read/send timeouts. Tests: `tests/m40_proxy.rs` (5 cases: direct, upstream-ref, hop-by-hop strip, 502 on connect failure, undeclared-upstream `-t` rejection). The acceptance criterion "one nginx-tests `proxy*.t` passes that didn't before" slips to **M41** — every reachable upstream `.t` config uses at least one of `proxy_set_header`, `proxy_*_timeout`, `add_header X-Proxy-Host $upstream_*`, or `proxy_pass http://X/path` (path rewriting), all of which land in M41. Tracking this slip explicitly so a future session doesn't re-derive the conclusion.

**M41 status (2026-04-28).** Header overrides + body forwarding + per-directive timeouts landed: `proxy_set_header NAME VALUE` (with `$var` expansion, empty-value-deletes semantics), `proxy_pass_request_headers on/off`, `proxy_pass_request_body on/off`, and `proxy_connect_timeout` / `proxy_read_timeout` / `proxy_send_timeout`. Inheritance for all six is location → server → defaults (60s timeouts, `on` toggles, empty set-header list). New variables `$proxy_host` (the matched proxy_pass URL's authority — host:port or upstream block name) and `$proxy_add_x_forwarded_for` (the incoming XFF header followed by `, $remote_addr`, or just `$remote_addr` when absent). Request bodies up to 1 MiB are buffered in a per-request `Vec<u8>` and forwarded as Content-Length-framed at this milestone; chunked request-body decoding landed later in the worker request loop. Tests: `tests/m41_proxy_headers.rs` (7 cases). Upstream nginx-tests acceptance unlocked: **`proxy_pass_request.t` passes 5/5** under `TEST_NGINX_BINARY=ruxen`. The `-V` banner now omits `--without-http_proxy_module` so `Test::Nginx::has(qw/http proxy/)` stops skipping.

**M41 architecture decisions worth carrying.**
- The upstream-side request is still HTTP/1.0 with `Connection: close`. M42 introduces HTTP/1.1 + keepalive pool, at which point `proxy_http_version 1.1` becomes load-bearing.
- `RenderCtx` gained a `proxy_host: &[u8]` slot. It's set only when the location's handler is `PreparedHandler::Proxy`; for every other handler (Return, Root) it's empty so a `proxy_set_header X $proxy_host` outside a proxy context renders to nothing. The render path doesn't branch — proxy_set_header is rendered *before* the upstream request bytes are built, with `proxy_host` stamped into the ctx for that one render.
- Forward-headers strategy: render `proxy_set_header` overrides into a small `Vec<(name, value)>` first, then walk the raw client header block and append every header that isn't (a) hop-by-hop, (b) already overridden, or (c) one of the auto-recomputed `Host` / `Content-Length` slots. The overrides Vec owns the names + rendered values so the final `Vec<ProxyHeader<'_>>` can borrow from both it and the request's lowercased header bytes without lifetime conflicts.
- `Content-Length` on the upstream side is always recomputed from the actual forwarded body length, never copied from the client header. With `proxy_pass_request_body off;` the upstream sees `Content-Length: 0` for non-GET/HEAD methods (so it doesn't wait for a body) and no CL at all for GET/HEAD.
- Status-line rewriting: ruxen always emits `HTTP/1.1` to the client regardless of what the upstream sent. Matches nginx (`ngx_http_upstream_send_response` always writes the proxy's own version). Without this, an HTTP/1.0 upstream would surface as `HTTP/1.0` to a client that just sent an HTTP/1.1 request, confusing pipeline state.
- Upstream-response framing tolerates bare-LF line endings. Test::Nginx's Perl helper daemons emit `\n`-terminated headers (heredoc shape), and nginx itself accepts that. `proxy.rs::find_head_end` / `find_line_end` look for both `\r\n\r\n` / `\n\n` and `\r\n` / `\n`.
- Request-body buffering happens in the worker read loop right after `parse_request` returns Complete. A per-request `Vec<u8>` is allocated for Content-Length bodies and for decoded `Transfer-Encoding: chunked` bodies, bounded at 1 MiB; bodies that exceed that produce a 400. `read_start` advances by the bytes consumed from the current buffer, and any bytes read past a chunked terminator are spliced back in so pipelined requests parse correctly.

**M40 architecture decisions worth carrying.**
- `Response::Proxy(ProxyPlan)` is the sync→async handoff. `phase::process_with_meta` builds the plan from the `PreparedHandler::Proxy` arm and returns it; the worker connection task awaits `proxy::run_proxy(plan)` before re-entering the existing write path (Connection-header injection, access logging). Mirrors `Response::File`.
- The PreparedHandler's `Proxy` variant is dispatched **before** the `inner = match ...` ladder in `run_location_handler`, which was the M40 sync→async handoff. Current proxy responses carry the matched location metadata through `ProcessMeta`; after `run_proxy` resolves, the worker applies proxy `add_header` / `add_trailer` with `$upstream_*` variables populated, and `proxy_intercept_errors` can return a normal internal `Response::Reroute`.
- `RequestCtx::method_bytes` carries the original method spelling so `Method::Other` (POST/PUT/DELETE/etc.) survives into the upstream request line. The hot-path read buffer can't co-borrow as a slice — the worker copies the method into a small stack array (`[u8; 16]`) up front, before `normalize_host_in_place` takes `&mut buf`.
- Upstream-name resolution validation happens at parse-end (`validate_proxy_upstream_refs`), not at prepare. So `ruxen -t` catches `proxy_pass http://typo;` typos.
- Hop-by-hop strip table lives in `proxy.rs::is_hop_by_hop` — RFC 7230 §6.1 set + Proxy-Authenticate / Proxy-Authorization. Applied symmetrically: response-side strip in `run_proxy`, request-side filter in `worker::forward_client_headers` so `proxy_pass_request_headers on` (the default) doesn't propagate `Connection: keep-alive` etc. to the upstream.

**M42 status (2026-04-28).** Round-robin LB across upstream peers, per-worker keepalive pool, `proxy_http_version 1.1`, and explicit Connection-header semantics all landed.

- **LB.** `src/upstream.rs::pick_peer` runs nginx's smoothed weighted round-robin (`current_weight += effective_weight`, pick max, deduct total) every plan-build. Per-peer state lives in a `thread_local! RefCell<HashMap<*const PreparedUpstream, UpstreamRt>>` keyed on the leaked-static upstream pointer — shared-nothing, no locking. `down` peers are skipped; if every primary is down, backup peers become eligible. Failure tracking + `proxy_next_upstream` landed in M43.
- **Keepalive pool.** Same `thread_local!` pattern (different map keyed on `(upstream_ptr, peer_index)`). Storage is `VecDeque<PooledConn>`, LIFO push/pop so the most-recently-used socket is the next to be reused. Eviction is opportunistic at take-time — drops entries past `keepalive_timeout` (idle) or `keepalive_time` (lifetime). On insert, when the queue is at `keepalive` (max_idle) capacity, the oldest entry (back of the deque) is evicted to make room. monoio's `TcpStream` is `!Send` because the io_uring backing is per-thread, which is exactly what `thread_local!` wants.
- **Pool eligibility = HTTP/1.1 + `keepalive N;` on the upstream block.** `PreparedProxy::upstream` is now always non-`None`: `proxy_pass http://host:port` synthesizes a single-peer no-keepalive `PreparedUpstream` so the LB and pool layers have one shape to dispatch against.
- **Stale-conn fallback.** A pooled connection that fails before the response headers parse triggers exactly one fresh-connect retry when the request is safe to replay. Idempotent-method gating was added with the M43 `proxy_next_upstream` work.
- **Response framing.** `proxy.rs::attempt` now parses Content-Length / Transfer-Encoding: chunked / Connection: close from the upstream response and reads exactly the right number of bytes. Chunked bodies are decoded into a `Vec<u8>` and re-framed as `Content-Length` for the client. The pre-M42 read-until-EOF path remains as a fallback when the upstream signals `Connection: close` without framing headers (HTTP/1.0 default).
- **Connection header on the upstream side** is no longer auto-injected by the request builder; the location handler decides: (a) explicit `proxy_set_header Connection ...` wins, (b) otherwise default to `Connection: keep-alive` when pooling is on or `Connection: close` otherwise. The `proxy_set_header Connection ""` recipe drops Connection entirely, which is the canonical "let HTTP/1.1 default to keep-alive" form.
- **Bench result (2026-04-28).** `bench/m42/` config: ruxen-as-proxy at **608,863 req/s** (p50 670 µs, p99 4.43 ms) vs nginx-as-proxy at **512,815 req/s** (p50 772 µs, p99 5.70 ms) — both fronting a separate nginx-as-upstream on port 8090. ruxen is **118.7%** of the nginx baseline, well above the 95% gate. The pool reuse is what makes this possible — without it, the per-request `connect()` would be the bottleneck.
- **Upstream nginx-tests unlocked.** At M42, `proxy_pass_request.t` stayed 5/5 (M41 baseline) and `upstream_keepalive.t` reached 9/13 with `RUXEN_WORKERS=1`. The remaining failures were path-rewrite and finer `keepalive_time` edge cases; later milestones closed the path-rewrite side. Current pass/fail status lives in [`NGINX_TEST_PROGRESS.md`](NGINX_TEST_PROGRESS.md).
- **`PreparedUpstream` shape** carries the four resolved knobs (`keepalive_max_idle`, `keepalive_requests`, `keepalive_idle_timeout_ms`, `keepalive_max_lifetime_ms`) so `pool_take` / `pool_release` don't have to chase config indirection on the hot path.
- **Moved to M43 and now landed:** `proxy_next_upstream`, `max_fails` / `fail_timeout` enforcement, `least_conn`, `proxy_intercept_errors`, path-rewrite for `proxy_pass http://up/path;`, and idempotent-only retry on stale pooled conns.

**M43 status (2026-04-28).** Failover machinery, least_conn, path rewriting, and proxy_intercept_errors all landed.

- **`proxy_next_upstream` failover.** `proxy.rs::run_proxy` is now a multi-attempt loop. The plan carries a `LeasedPeer` for the first peer pick plus the parsed `proxy_next_upstream` mask, the `proxy_next_upstream_tries` cap (with `0` meaning "as many peers as we have"), and `proxy_next_upstream_timeout` as an overall budget. After each failed attempt the loop reports failure to the LB, picks the next peer with the failed peer masked out, and retries. Failure classification mirrors `ngx_http_upstream_next`'s ft_type bitmask: connect/protocol errors → `error`, timeouts → `timeout`, malformed status line / oversized header block → `invalid_header`, upstream status codes from the `http_*` flags. **Idempotency:** non-idempotent methods (POST/PATCH at our classification, anything outside `GET/HEAD/PUT/DELETE/OPTIONS/TRACE`) only retry when the request body is empty *or* the user opted in via `proxy_next_upstream non_idempotent`. Computed once in the worker against `req.method_bytes` and stamped onto `ProxyPlan.method_idempotent`.
- **`max_fails` / `fail_timeout`.** Per-peer failure counters live in `PeerRtState::fails` next to the smoothed-weight state in `src/upstream.rs`. `report_failure` increments `fails`, decrements `effective_weight` by `weight / max_fails` (matches nginx rr.c:1051), and refreshes `fails_started`. `peer_eligible` skips a peer when `fails >= max_fails` and `now - fails_started < fail_timeout`. `report_success` zeroes the counter and gradually walks `effective_weight` back up to `weight` (matches the lazy-recovery shape in rr.c:1083). Both `report_failure` and `report_success` initialize the LB state via `ensure_rt` if no pick has happened yet — needed because the failover loop sometimes records a failure before the first pick lands in the same map.
- **`least_conn` LB.** New `LbAlgorithm::LeastConn` variant on `UpstreamBlock` and `PreparedUpstream`. `pick_peer` dispatches to `least_conn_pick`, which compares `(active, weight)` ratios via `c1 * w2` vs `c2 * w1` (i128, no float math) and falls back to a constrained smoothed-weight RR pick when multiple peers tie on `c/w` — exactly the shape `ngx_http_upstream_get_least_conn_peer` uses at lc.c:171. Active-conn tracking is driven by a `LeasedPeer` RAII guard returned from `pick_peer`: increment on pick, decrement on Drop. The proxy plan owns the lease for the full attempt; the multi-attempt loop swaps the lease (drops the old one, grabs a new one) on each failover hop.
- **`proxy_pass http://up/path;` rewriting.** Parser now stores `request_path: Option<String>` on both `ProxyPass::Direct` and `ProxyPass::UpstreamRef`. Prepare validates: regex and named (`@`) locations with a path on `proxy_pass` are an `[emerg]` with nginx's message (its parse-time rejection in `ngx_http_proxy_module.c::ngx_http_proxy_pass`). `PreparedProxy` carries `location_prefix` + `request_path` byte slices; when both are non-empty, `run_location_handler` strips the prefix from the client URI's path, prepends `request_path`, and re-stitches with `?args` before building the upstream request line. Empty `request_path` means "forward client URI verbatim" (M40-style behavior).
- **`proxy_intercept_errors`.** Plan-build time pre-renders every `error_page` rule's target into bytes (uses the per-request `RenderCtx` so `$var` interpolation works the same as a non-proxy intercept) and attaches the list to `ProxyPlan.intercept`. After the upstream returns OK, `run_proxy` checks the response status against the rules and — on a match — returns `Response::Reroute` instead of the upstream bytes. The worker feeds that reroute back into `phase::process_with_meta_from_reroute`, so URI and named targets both reuse the same internal reroute loop, including args replacement and error-page status override semantics. Absolute-URL intercept targets remain unsupported in the proxy path.
- **Stale-pooled-conn retry is now idempotent-only.** `attempt(plan, peer_idx, Some(c))` returning `PooledStale` now collapses inside the run_proxy loop: a fresh-connect retry happens only when `body_safe_to_retry` is true (idempotent method, or empty body, or `non_idempotent` flag). Otherwise it's surfaced as `FailKind::Error` and may failover to the next peer per `proxy_next_upstream`.
- **Tests:** `tests/m43_proxy_failover.rs` (10 cases) covering connect-refused failover, `proxy_next_upstream off`, http_500 failover, intercept on/off, named intercept reroute, preserved-status/args intercept semantics, path rewriting, least_conn smoke test, and one-shot POST behavior.
- **`RequestCtx` is now `Copy + Clone`** — needed so the worker can build a path-overridden ctx via struct update syntax for the post-proxy intercept reroute. All fields are already Copy refs and small ints; the derive is free.

**M43 architecture decisions worth carrying.**
- Plan-build-time peer leasing: `pick_peer` now returns a `LeasedPeer` RAII guard. The plan owns it across `run_proxy.await`; failover replaces it via Drop+pick. Active-conn counters can't underflow because the guard always runs.
- `upstream::Tried` is the per-request set of peers already tried, nginx's `rrp->tried`: one inline `u64` for the first 64 peers, and a heap bitmap only once a peer past index 63 is tried. (Until #125 it was a single `u64` whose bit 63 stood for every peer from 63 up.)
- `last_failure: Option<Response>` is the sticky "what we'd return if this is the final attempt" buffer. Reset every loop iteration after a Failed; survives across iterations because failover may skip multiple peers before exhausting `tries`.
- `proxy_intercept_errors`'s pre-render-then-reroute shape avoids needing `RenderCtx` to live across an `await`. The downside is that the same target bytes are rendered for every request even when intercept never fires; cheap for typical configs (one or two `error_page` rules) and avoids a second-pass render.
- `is_idempotent_method_bytes` lives in worker.rs because it reads raw method bytes; the `Method` enum's coarse classification (Get/Head/Trace/Connect/Other) loses PUT/DELETE/OPTIONS distinction needed for the gate.
- `proxy_intercept_errors` and `proxy_next_upstream*` stay in `IGNORED_STMT` so http-scope occurrences (TEST_GLOBALS_HTTP preambles) keep loading; the explicit handlers at server/location scope take precedence via match-arm ordering.

## Static file bodies and `sendfile`

`sendfile on|off` (http / server / location, default off as in nginx) picks how file bodies leave the process. Measured on static_8k (8 KiB, `wrk -t16 -c512`): the copying path was at 89% of nginx; with sendfile on both servers ruxen is at ~96.5%.

- **`sendfile off`** (and any TLS connection): bodies up to 8 KiB are `pread` into the response buffer and written with one io_uring write; larger bodies stream through a 64 KiB buffer (`stream_file`). Two user-space copies per body byte.
- **`sendfile on`, plain TCP, body ≥ 4 KiB**: `serve_path` returns `Response::File` and the worker calls `send_head_and_file`. The header block goes out with `send(MSG_MORE)` so the kernel coalesces it with the first file pages (nginx gets the same from `tcp_nopush`). The body goes out with `sendfile(2)` in ≤ 2 MiB chunks (`sendfile_max_chunk` default). No user-space copy.
- **Non-blocking without a new io_uring op.** monoio's `Pipe` doesn't expose its fds, so io_uring `splice` isn't reachable from outside the crate. Instead the socket is switched to `O_NONBLOCK` on first use and `send`/`sendfile` are called directly; on `EAGAIN` the worker awaits `TcpStream::writable()` (an io_uring PollAdd). io_uring ops on the same socket behave the same with or without the flag, because the kernel already tries non-blocking first and arms a poll on EAGAIN. `tests/m45_sendfile.rs` checks that a stalled reader doesn't block the worker.
- **Why 4 KiB.** Below it, `pread` + one io_uring write beats two direct syscalls: against the inline path, 1 KiB was −3%, 2 KiB break-even, 4 KiB +6%, 8 KiB +8%. nginx itself uses sendfile for every size.
- **File side is synchronous**, like the `pread` it replaces: a page-cache miss blocks the worker for the disk read. nginx has the same property without `aio`.

## TLS architecture

Server-side HTTPS lives in `src/tls.rs` (handshake glue + post-handshake
snapshot), `src/tls_stream.rs` (rustls ↔ monoio stream adapter) and
`src/tls_certs.rs` (PEM loader + SNI resolver + `ServerConfig` builder). Wired into the worker accept loop via
`spawn_connection`, which branches on `PreparedListen::tls`.

- **rustls 0.23.** Pure-Rust API surface, no OpenSSL link,
  MIT/Apache-2.0. BoringSSL via `boring` would likely be faster on some
  workloads but adds a C build dep. Revisit only if HTTPS bench shows a
  >20% gap to nginx and profiling traces it to crypto rather than I/O.
  Crypto provider is rustls's default `aws-lc-rs`.
- **Own rustls ↔ monoio adapter (`src/tls_stream.rs`).** Until
  2026-10 this was the `monoio-rustls` crate. We needed the negotiated
  session (`get_ref`) for `HandshakeInfo`, upstream left the PR adding
  it unreviewed and has had no release since 0.4.0 (May 2024), and
  crates.io refuses a package whose build depends on a git
  `[patch]`. The adapter is server-only, ~250 lines, and keeps the
  state ruxen needs visible: the negotiated `ServerConnection` and the
  ciphertext buffered ahead of rustls (needed for a TLS keepalive idle
  wait). Ciphertext buffers are allocated on first use rather than as
  two zeroed 16 KiB blocks per connection; each write drains rustls's
  whole outgoing queue into one socket write (upstream wrote in 16 KiB
  pieces); `writev` encrypts all iovecs as one run of records.
  Throughput on `tls_hello` is unchanged (ABBA pairs vs the old
  adapter, 2026-10-02: 99–100%).
- **Per-listen `TlsAcceptor`, built once at startup.** `build_listen_tls`
  walks every `server {}` on a given listen address, loads each
  `ssl_certificate` / `ssl_certificate_key` pair into a
  `rustls::sign::CertifiedKey`, and registers it with a
  `ServerNameResolver` keyed on `server_name`. Cert load failure is a
  startup abort, not a runtime degradation: `prepare` returns it as an
  `[emerg]` (`cannot load certificate "…" with key "…": …`), and since
  `-t` runs `prepare` too, `-t` catches an unreadable PEM or a key that
  doesn't match its certificate, as `nginx -t` does.
  Listens with no `ssl;` get `tls: None` and pay one `Option::is_some`
  on the accept path.
- **SNI resolver mirrors the HTTP `match_server` ladder**, as nginx's
  `ngx_http_ssl_servername` uses the same lookup as `Host`: exact, then
  leading wildcard (`*.example.com` registered under suffix
  `example.com`), then the longest trailing wildcard (`www.example.*`),
  then `~regex` names in declaration order (compiled a second time for
  the resolver at startup; they run only for SNI names that miss the
  tables before them). A name that matches nothing gets the listen's
  default certificate. Multi-cert per server (RSA + ECDSA both registered under
  one name) is supported by storing `Vec<Arc<CertifiedKey>>` per slot
  and selecting via `SigningKey::choose_scheme` against the
  `ClientHello`'s announced signature schemes — first match wins, falls
  through to the first registered key on no match so rustls can produce
  a clean handshake alert instead of us silently aborting.
- **Handshake-time vs request-time allocations.** A `HandshakeInfo`
  snapshot is built once after `accept_with_timeout` returns and
  threaded through the request loop as `Option<&HandshakeInfo>`.
  Request-path renders of `$ssl_protocol` / `$ssl_cipher` /
  `$ssl_server_name` / `$ssl_session_reused` are struct-field reads, not
  virtual calls into rustls. SNI is lowercased once at handshake time so
  per-request `find_config` does byte-equal comparisons against
  pre-lowercased `server_name` tables.
- **`Conn<S>` generic for the request loop.** `pub trait ConnIo:
  AsyncReadRent + AsyncWriteRent` with `idle_wait` as the only
  TLS-specific method. The handler `fn handle<S: ConnIo>(…)` is
  monomorphized for `TcpStream` and `ServerTlsStream<TcpStream>`. Plain
  TCP polls the kernel socket for readability without allocating a
  buffer (mirrors nginx's `wait_request_handler`). TLS does the same
  poll, with the keepalive deadline, unless the stream already holds
  input the socket won't signal again: ciphertext read but not yet
  handed to rustls, or plaintext rustls hasn't returned
  (`TlsStream::has_buffered_input`; TLS 1.3 clients send the first
  request in the same flight as Finished). Then it goes straight to the
  read. Until 2026-10 TLS skipped the poll entirely and never enforced
  the idle timeout. The poll costs `tls_hello` about 2–4% (ABBA vs the
  no-poll build): a keep-alive request now takes a readiness wait plus
  a read instead of one read, as plain TCP already does. A single read
  raced against the deadline would avoid that for both.
- **The handshake runs under `client_header_timeout`.** As in nginx
  1.24, which has no separate handshake timeout: the default server's
  `client_header_timeout` (60 s unless set) is armed at accept, and a
  PROXY protocol header read on the same listen shares it.
  `ssl_handshake_timeout` (nginx 1.25.3+) is an unknown directive here.
- **Session resumption follows nginx's defaults.** `ssl_session_cache`
  is off unless configured; when on, it is one in-memory
  `ServerSessionMemoryCache` (4096 entries) shared by all workers, with
  `ssl_session_timeout` enforced on lookup. `ssl_session_tickets` is on
  by default. No persistence across restarts. Session ticket key
  rotation, client cert auth, OCSP stapling, 0-RTT, hot cert reload,
  password-protected keys, and `proxy_ssl_*` are out of v0.1 scope (see
  README).
- **`$ssl_session_id` is ruxen's id for the session, not the wire bytes.**
  rustls exposes neither the TLS 1.2 session ID nor the TLS 1.3 ticket.
  When the variable is used and the listen resumes sessions, a full
  handshake draws 32 random bytes. They are stored in the session as
  rustls resumption data (`set_resumption_data`), and a TLS 1.3
  resumption gets them back. The value is 64 hex digits, as nginx's, and
  stable across resumptions, which is what log correlation and sticky
  keys need. rustls 0.23 doesn't return the data for a resumed TLS 1.2
  session, so that one renders empty. Without the variable in the
  config, handshakes are unchanged.

## Open questions

- `bumpalo` vs. fixed per-connection buffers vs. both. Current: fixed per-connection `Vec<u8>` (8 KiB, one alloc per connection, reused for every keep-alive request). No arena needed yet — revisit when we have a module/handler system that wants short-lived per-request allocations.
- CPU pinning strategy. **Decided (2026-04-16): opt-in via `RUXEN_PIN=1`, using `monoio::utils::bind_to_cpu_set` (no `core_affinity` dep — it's just a portability shim over the same `sched_setaffinity` syscall).** Default off, matches nginx's default (`worker_processes auto` + no `worker_cpu_affinity`). When enabled on the i9-13900HX (8P × 2 SMT + 16E), the tested layout is 16 workers pinned to CPUs 0–15 (all P-core logical threads, SMT on): per monoio/glommio and TFB plaintext results, naïve 0..31 pinning costs tail latency because SO_REUSEPORT doesn't rebalance and E-core queues back up. On a *colocated* client bench the effect is mixed — p99 improves ~37% but throughput drops because wrk on E-cores becomes the bottleneck (measured 2026-04-16; the raw affinity-comparison numbers were not carried into the public repo). With a dedicated client machine, pinning should be a clean win on both axes.
