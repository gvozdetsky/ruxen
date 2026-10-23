# ruxen roadmap

Where ruxen is going, in what order, and why. This file is the only roadmap: it changes when the strategy does, through a pull request. What goes into which release is the [milestones](https://github.com/gvozdetsky/ruxen/milestones) (their descriptions point back to the phases here), and what each release brought is its release notes. Last revised 2026-10-22, after 0.2.1.

## Positioning

**A memory-safe edge server that takes your nginx configuration.** ruxen aims first at what most nginx installations do at the edge: TLS termination, reverse proxying and static files. For that subset, a configuration written for nginx should load unchanged and behave the same way, with a worker that is at least as fast.

That is a narrower goal than "replace nginx". The mail proxy, the stream module, FastCGI, uwsgi, gRPC proxying and the long tail of third-party-module directives are out of scope for now. Unknown directives keep failing at startup rather than being ignored (see `DESIGN.md`). Widening toward full drop-in compatibility is a later decision, made on evidence such as the config corpus rather than by default. Of the 238 corpus configurations nginx accepts, 6 use `stream {}`, 4 `fastcgi_pass`, 4 `uwsgi_pass` and 1 `grpc_pass` (2026-10-22).

Why this is worth doing: nginx serves a large share of the web and is written in C. Edge servers parse untrusted input all day, which is where memory-safety bugs matter most. Rust servers exist, but they ask you to rewrite your configuration (Caddy, Envoy) or are libraries for building your own proxy (Pingora). Taking the nginx configuration as it is removes the migration cost.

## How work is chosen

- **The reference is nginx's stable branch**, 1.30 (1.30.6 today): both the behaviour to match and the performance contract (`DESIGN.md`, "Reference version").
- **Compatibility in order of use.** First what the configurations in the corpus (#216) use, then the rest of nginx 1.30 at a lower priority. Directives that appeared in the 1.29 mainline are judged the same way: by use, not by novelty.
- **Correctness before the last percent of throughput.** The contract (≥ 95% of nginx on every bench scenario) stays, but a fix that keeps a site from breaking comes first.
- **Ready before anyone asks.** ruxen has no known production users and no candidates for a pilot. The plan doesn't wait for one: what a first operator would run into (lifecycle, logs, limits, metrics, a clear list of differences) is worth more than another feature.
- **Security findings are fixed in the open** while there are no users (`SECURITY.md`).
- **HTTP/2 follows the RFCs** where the h2 crate and nginx differ (#347, `DESIGN.md`).

## Phase 1: in front of a real site

Goal: an operator can put ruxen in front of a typical website (HTTPS, a reverse-proxied application, static assets) with that site's nginx configuration, run it under systemd or in a container, and reload it without dropping traffic.

**v0.2.0, the essentials: done.** HTTP/2 for clients, reload without dropping connections, WebSocket tunnels and streamed upstream responses, gzip, `allow` / `deny`, realip, `user`, the epoll fallback, a container image and a systemd unit, the common configuration blockers, and the confidence work: the corpus, fuzzing, nginx-tests in CI, contained worker panics, the directive table (`docs/directives.md`). The 0.1.x and 0.2.x releases also brought limits, `stub_status`, the `hash` balancers, HTTPS upstreams, client certificates, OCSP stapling and the resolver.

**Patch releases v0.2.2 and v0.2.3.** The rest of the 2026-10-18 production-readiness audit (#529): process lifecycle (signals during a reload, memory across reloads, logs, sd_notify), then trust (cargo-deny, build provenance and an SBOM, NOTICE, `-v`) and small compatibility items.

**v0.3.0, the rest of the edge.** Goal: a typical reverse-proxy or static-site configuration from the corpus loads and behaves as in nginx, and the performance contract holds on every scenario. In order of priority:
- Compatibility, by how many of the 238 corpus configurations use it: the rest of proxy caching (#233, 13), `charset` (#464, 12), streaming request bodies to upstreams with `proxy_request_buffering off` (#134, 4, together with the 64 KiB POST rate, #289), cookie rewriting (#40, 2), variables in `root` / `alias` (#232, 1), `server … resolve` in upstreams (#597, 1).
- Robustness: relay the proxied responses still read whole (#463), move blocking file I/O off the worker (#526), the two `&mut` to one stream (#501), fuzzing of the HTTP/2 glue, Range, rewrite and gzip with long runs on a schedule (#477), binding low ports on reload after `user` (#344).
- The performance contract: #249, #289, #334, #337, #451, #467, #545, #414.
- Lower priority, unused in the corpus: OCSP for client certificates (#142), `add_header_inherit` (#598). They move to a later milestone rather than hold up the release.

## Phase 2: ready for a first user

Goal: someone who finds ruxen can try it on their own configuration, see where it differs from nginx, and judge it in production. Milestone v0.4.0.
- Metrics in Prometheus format (#481), so that a trial can be judged.
- A migration guide built on `ruxen --compat`: what in a given configuration differs from nginx, and what to do about it.
- Differential testing against nginx: the same requests to both, the responses compared. It finds what neither the tests nor the corpus can, and it doesn't need a user. No issue yet.
- Lower priority, unused in the corpus: HTTP/2 to upstreams (#599), session affinity (#600).

The most valuable single step is still running ruxen in front of something real, starting with non-critical services. When a first user appears, their reports go ahead of everything in this phase.

## Phase 3: 1.0

A written compatibility statement (what is supported, and where ruxen deliberately differs), stability guarantees for that surface, an external security review, and HTTP/3. Extensions in the form of WASM filters, which nginx can't offer, are a possible differentiator here.

## Releases

Minor versions (v0.3.0, v0.4.0) are the phases above. Patch releases in between (v0.2.2, v0.2.3, …) have milestones too, which order the work that comes next: mostly fixes, hardening and small compatibility items. Each release is still a snapshot of `main`, cut when there is a reason, such as a security fix, a regression, or a finished patch milestone; what isn't done moves to the next one. `main` stays releasable because a feature reaches the directive allowlist and `-V` only together with its implementation.

## How progress is measured

Each release reports four numbers, and the release pull request adds its row to the table below:

1. **nginx-tests**: files passing, out of those that run (`NGINX_TEST_PROGRESS.md`).
2. **Config corpus** (#216): the share of a few hundred real-world nginx configurations that ruxen loads, from application docs, popular container images and certbot setups (`corpus/RESULTS.md`). This is the best proxy for "would ruxen work for me", and its failures say what to build next.
3. **Performance**: ruxen vs nginx's stable release on every bench scenario, measured as ABBA pairs on a dedicated quiet machine (`bench/README.md`). The contract is ≥ 95% everywhere.
4. **Robustness**: fuzzing, worker panics (target: none), and security fixes (`SECURITY.md`).

| release | nginx-tests | corpus | scenarios ≥ 95% of nginx, median (i7) | fuzzing | security fixes |
|---|---|---|---|---|---|
| 0.1.1 | 63 / 105 | 113 / 238 (47%) | — | — | 6 advisories |
| 0.1.2 | 65 / 106 | 149 / 238 (63%) | 64 of 83, 109.4% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.1.2/bench/campaign-0.1.2/REPORT.md)) | — | 1 advisory |
| 0.1.3 | 105 / 159 | 193 / 238 (81%) | 75 of 87, 118.8% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.1.3/bench/campaign-2026-10-14/REPORT.md)) | ~10.5 billion runs, 6 targets | — |
| 0.2.0 | 165 / 191 | 217 / 238 (91%) | 85 of 94, 120.2% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.2.0/bench/campaign-2026-10-17/REPORT.md)) | ~37 billion runs, 8 targets | 13 issues from the audit (#529) |
| 0.2.1 | 172 / 192 | 217 / 238 (91%) | 91 of 94, 121.5% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.2.1/bench/campaign-2026-10-21/REPORT.md)) | ASan nginx-tests sweep, no reports | 5 issues |
| 0.2.2 | 182 / 197 | 218 / 238 (92%) | no campaign; ABBA against 0.2.1 (i7, 6 pairs each): h2c_hello 106.2%, h2_tls_hello 104.7%, proxy_64k 100.3%, m1_hello 99.6%, tls_hello 99.5%, proxy_hello 99.2%, m3_static_1k 99.1%, gzip_html_8k 97.3% | ASan nginx-tests sweep, no reports; ~2.7 billion runs, 5 targets | 1 issue (#586), 1 dependency advisory |

Performance up to 0.2.0 is against nginx 1.24.0, from 0.2.1 against 1.30.6; on the bench configurations the two run at the same speed (±1.3%).

## Communication

The first announcement, on the Rust Users Forum, went out once phase 1's essentials were in (HTTP/2, reload, WebSocket and a container image). The next round (This Week in Rust, r/rust, later Show HN with the numbers and honest caveats) waits for 0.3.0. Until then: release notes and short technical write-ups.
