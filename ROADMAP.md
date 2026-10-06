# ruxen roadmap

Where ruxen is going, and in what order. The work itself is tracked in GitHub issues and milestones; this file says why the milestones are what they are. Last revised 2026-10-06.

## Positioning

**A memory-safe edge server that takes your nginx configuration.** ruxen aims first at what most nginx installations do at the edge: TLS termination, reverse proxying and static files. For that subset, a configuration written for nginx should load unchanged and behave the same way, with a worker that is at least as fast.

That is a narrower goal than "replace nginx". The mail proxy, the stream module, FastCGI and friends, and the long tail of third-party-module directives are out of scope for now. Unknown directives keep failing at startup rather than being ignored (see `DESIGN.md`). Widening toward full drop-in compatibility is a later decision, made on evidence such as the config corpus below rather than by default.

Why this is worth doing: nginx serves a large share of the web and is written in C. Edge servers parse untrusted input all day, which is where memory-safety bugs matter most. Rust servers exist, but they ask you to rewrite your configuration (Caddy, Envoy) or are libraries for building your own proxy (Pingora). Taking the nginx configuration as it is removes the migration cost.

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
- The performance contract on every bench scenario (#127, #128, #129), and nginx's error pages and status phrases (#33, #34).

## Phase 2: first production users

Goal: a few sites run ruxen in production and report back. The work then follows their reports, and the likely next items are:
- client certificates and OCSP (#112–#115, #141, #142);
- the resolver (#133);
- request-body streaming to upstreams (#134);
- metrics.

The most valuable single step is running ruxen in front of something real, starting with non-critical services.

## Phase 3: 1.0

A written compatibility statement (what is supported, and where ruxen deliberately differs), stability guarantees for that surface, an external security review, and HTTP/3. Extensions in the form of WASM filters, which nginx can't offer, are a possible differentiator here.

## How progress is measured

Each release reports these four numbers:

1. **nginx-tests**: files passing, out of those that run (`NGINX_TEST_PROGRESS.md`).
2. **Config corpus** (#216): the share of a few hundred real-world nginx configurations that ruxen loads, from application docs, popular container images and certbot setups. This is the best proxy for "would ruxen work for me", and its failures say what to build next.
3. **Performance**: ruxen vs nginx 1.24.0 on every bench scenario, measured as ABBA pairs on a dedicated quiet machine (`bench/README.md`). The contract is ≥ 95% everywhere.
4. **Robustness**: fuzzing hours on the HTTP parser, worker panics (target: none), and time to fix security reports (`SECURITY.md`).

## Communication

No broad announcement until phase 1's essentials are in: HTTP/2, reload, WebSocket and a container image. First impressions only happen once. Until then, short technical write-ups (for example, how a bisection on the quiet machine found 3% in connection timers) and the release notes.
