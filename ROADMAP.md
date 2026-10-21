# ruxen roadmap

Where ruxen is going, and in what order. The work itself is tracked in GitHub issues and milestones; this file says why the milestones are what they are. Last revised 2026-10-14 (0.1.3).

## Positioning

**A memory-safe edge server that takes your nginx configuration.** ruxen aims first at what most nginx installations do at the edge: TLS termination, reverse proxying and static files. For that subset, a configuration written for nginx should load unchanged and behave the same way, with a worker that is at least as fast.

That is a narrower goal than "replace nginx". The mail proxy, the stream module, FastCGI and friends, and the long tail of third-party-module directives are out of scope for now. Unknown directives keep failing at startup rather than being ignored (see `DESIGN.md`). Widening toward full drop-in compatibility is a later decision, made on evidence such as the config corpus below rather than by default.

Why this is worth doing: nginx serves a large share of the web and is written in C. Edge servers parse untrusted input all day, which is where memory-safety bugs matter most. Rust servers exist, but they ask you to rewrite your configuration (Caddy, Envoy) or are libraries for building your own proxy (Pingora). Taking the nginx configuration as it is removes the migration cost.

## Where it stands

As of 0.1.3 most of phase 1 is in: HTTP/2 for clients, reload without dropping connections, WebSocket tunnels, gzip, `allow` / `deny`, realip, `user`, the epoll fallback with a container image and a systemd unit, panics contained per connection, the corpus, fuzzing of the request, URI, upstream-response and config parsers (in CI on every pull request), and the passing nginx-tests in CI (v0.2.0); rate and connection limits, `stub_status`, `hash` / `ip_hash`, variables in `proxy_pass`, `unix:` upstreams and most of proxy caching (v0.3.0).

Still open (2026-10-16, evening): for v0.2.0, closing the fuzzing issue (#217) and three bench scenarios below 95% on some machines (#247, #249, #289), which move to v0.3.0 unless a fix is confirmed before the release; for v0.3.0, cookie rewriting (#40), variables in `root` / `alias` (#232), the rest of the cache (#233), the proxied responses still read whole (#463) and the charset filter (#464). Done since 0.1.3: HTTP/2 for clients (#144), streaming upstream responses (#88), HTTPS upstreams with verification and client certificates (#116, #117, #138, #434), client certificate authentication (#113, #114, #139), the configuration blockers `return URL` (#16), `add_header` at http (#17), include globs (#35), old `ssl_protocols` names (#36) and `types {}` / `default_type` (#38), the directive table (#18, `docs/directives.md`), nginx's error pages (#34) and `absolute_redirect` (#15). The milestones in GitHub are the live list.

## Phase 1: in front of a real site

Goal: an operator can put ruxen in front of a typical website (HTTPS, a reverse-proxied application, static assets) with that site's nginx configuration, run it under systemd or in a container, and reload it without dropping traffic.

**v0.2.0, the essentials**
- HTTP/2 for clients (#144). A TLS terminator without it is not taken seriously.
- Reload on SIGHUP without dropping connections (#89).
- WebSocket and other `Upgrade` tunnels (#87); streaming upstream responses instead of buffering them whole (#88).
- gzip (#93), `allow` / `deny` (#91), realip (#92), dropping privileges to `user` (#98).
- Runs where people deploy: an epoll fallback where io_uring is blocked, as by Docker's default seccomp profile and some Kubernetes and cloud setups (#215); a container image and a systemd unit (#154).
- Common configuration blockers: `add_header` at `http {}` (#17), `return URL;` (#16), `types {}` and `default_type` (#38), `include` with globs (#35).
- Confidence:
  - a corpus of real nginx configurations and its load rate (#216);
  - fuzzing of the parsers that see untrusted input (#217);
  - the passing nginx-tests in CI (#131);
  - predictable behaviour when a worker panics (#130);
  - a list of supported directives (#18).

Some of these (#16, #17, #18, #35) are marked `good first issue` / `help wanted` and are open to contributors.

**v0.3.0, the rest of the edge**
- Rate and connection limits (#94, #95), `stub_status` (#96), `hash` / `ip_hash` (#97).
- Variables in `proxy_pass` (#100), `unix:` upstreams (#101), HTTPS upstreams and their verification (#116, #117), cookie rewriting (#40).
- Proxy caching (#233). Reverse-proxy configurations cache upstream responses often enough that the corpus counts cache directives among its top blockers.
- Request-body streaming to upstreams (`proxy_request_buffering off`, #134), reworked together with the 64 KiB POST rate (#289), and OCSP checks of client certificates (#142) on the stapling code from #141.
- The performance contract on every bench scenario (#127, #128, #129), and nginx's error pages and status phrases (#33, #34).

## Phase 2: first production users

Goal: a few sites run ruxen in production and report back. Milestone v0.4.0. It starts with metrics (#481), so that a pilot can be judged; the rest follows the pilots' reports. Client certificates, OCSP stapling and the resolver, once listed here, are done (#112–#115, #141, #133).

The most valuable single step is running ruxen in front of something real, starting with non-critical services.

## Phase 3: 1.0

A written compatibility statement (what is supported, and where ruxen deliberately differs), stability guarantees for that surface, an external security review, and HTTP/3. Extensions in the form of WASM filters, which nginx can't offer, are a possible differentiator here.

## Releases

Minor versions (v0.2.0, v0.3.0) are the milestones above, and the plan is made there. Patch releases in between (v0.2.1, v0.2.2, …) have milestones too, which order the work that comes next, mostly fixes, hardening and small compatibility items (since 0.2.0, the audit in #529). Each release is still a snapshot of `main`, cut when there is a reason, such as a security fix, a regression, or a finished patch milestone; what isn't done moves to the next one. `main` stays releasable because a feature reaches the directive allowlist and `-V` only together with its implementation.

## How progress is measured

Each release reports these four numbers:

1. **nginx-tests**: files passing, out of those that run (`NGINX_TEST_PROGRESS.md`).
2. **Config corpus** (#216): the share of a few hundred real-world nginx configurations that ruxen loads, from application docs, popular container images and certbot setups. This is the best proxy for "would ruxen work for me", and its failures say what to build next.
3. **Performance**: ruxen vs nginx's current stable release (1.30.6) on every bench scenario, measured as ABBA pairs on a dedicated quiet machine (`bench/README.md`). The contract is ≥ 95% everywhere.
4. **Robustness**: fuzzing hours on the HTTP parser, worker panics (target: none), and time to fix security reports (`SECURITY.md`).

## Communication

No broad announcement until phase 1's essentials are in: HTTP/2, reload, WebSocket and a container image. First impressions only happen once. All four are in since 0.1.3; until the announcement, short technical write-ups (for example, how a bisection on the quiet machine found 3% in connection timers) and the release notes.
