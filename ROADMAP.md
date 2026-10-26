# ruxen roadmap

Where ruxen is going, in what order, and why. This file is the only roadmap: it changes when the strategy does, through a pull request. What goes into which release is the [milestones](https://github.com/gvozdetsky/ruxen/milestones) (their descriptions point back to the phases here), and what each release brought is its release notes. Last revised 2026-10-26, after 0.2.2: the plan is now built around a first user rather than completeness.

## Positioning

**A memory-safe edge server that takes your nginx configuration.** ruxen aims first at what most nginx installations do at the edge: TLS termination, reverse proxying and static files. For that subset, a configuration written for nginx should load unchanged and behave the same way, with a worker that is at least as fast.

That is a narrower goal than "replace nginx". The mail proxy, the stream module, FastCGI, uwsgi, gRPC proxying and the long tail of third-party-module directives are out of scope for now. Unknown directives keep failing at startup rather than being ignored (see `DESIGN.md`). Widening toward full drop-in compatibility is a later decision, made on evidence such as the config corpus rather than by default. Of the 238 corpus configurations nginx accepts, 6 use `stream {}`, 4 `fastcgi_pass`, 4 `uwsgi_pass` and 1 `grpc_pass` (2026-10-22). The corpus comes mostly from application docs and container setups, so it undercounts PHP sites behind FastCGI; that is a known bias, not a reason to add FastCGI before someone asks.

Why this is worth doing: nginx serves a large share of the web and is written in C. Edge servers parse untrusted input all day, which is where memory-safety bugs matter most. Rust servers exist, but they ask you to rewrite your configuration (Caddy, Envoy) or are libraries for building your own proxy (Pingora). Taking the nginx configuration as it is removes the migration cost.

Who it is for first: teams that run nginx at the edge and are asked to reduce memory-safety risk in what faces the internet, but can't afford to rewrite and re-verify their configuration for another server.

## How work is chosen

- **A first user before completeness.** ruxen has no known production users. Features alone won't change that: nobody replaces their edge server with one that has never served real traffic. So the next phase is about trying ruxen without risk (next to nginx, on a copy of real traffic), showing where it answers differently from nginx, and the numbers to judge a trial. What a trial reports goes ahead of everything else.
- **The reference is nginx's stable branch**, 1.30 (1.30.6 today): the behaviour to match and the speed to compare with (`DESIGN.md`, "Reference version").
- **Compatibility in order of use.** First what the configurations in the corpus (#216) use, counting both what keeps a configuration from loading and what `--compat` reports as behaving differently; then the rest of nginx 1.30 at a lower priority. Directives that appeared in the 1.29 mainline are judged the same way: by use, not by novelty.
- **Performance: no regressions; the remaining gaps on demand.** ruxen's median is above nginx on the bench (121.5% at 0.2.1). The target stays ≥ 95% of nginx on every scenario (`DESIGN.md`, "Performance contract"), but what a release must hold is no regression against the previous release on the headline scenarios: `m1_hello`, `m3_static_1k`, `proxy_hello`, `proxy_64k`, `tls_hello`, `h2c_hello`, `h2_tls_hello`, `gzip_html_8k`. Scenarios still below 95% keep their issues without a milestone, and get one when a user's workload hits them or the fix is cheap. Hot-path changes are still measured before they merge.
- **Security findings are fixed in the open** while there are no users (`SECURITY.md`).
- **HTTP/2 follows the RFCs** where the h2 crate and nginx differ (#347, `DESIGN.md`).
- **A checkpoint.** On 2027-01-31 this plan is reviewed against one number: deployments outside the project, shadow ones included.

## Phase 1: in front of a real site (done in 0.2.x)

An operator can put ruxen in front of a typical website (HTTPS, a reverse-proxied application, static assets) with that site's nginx configuration, run it under systemd or in a container, and reload it without dropping traffic.

v0.2.0 brought HTTP/2 for clients, reload without dropping connections, WebSocket tunnels and streamed upstream responses, gzip, `allow` / `deny`, realip, `user`, the epoll fallback, a container image and a systemd unit, the common configuration blockers, and the confidence work: the corpus, fuzzing, nginx-tests in CI, contained worker panics, the directive table (`docs/directives.md`). The 0.1.x and 0.2.x releases also brought limits, `stub_status`, the `hash` balancers, HTTPS upstreams, client certificates, OCSP stapling and the resolver. v0.2.1 and v0.2.2 worked through the 2026-10-18 production-readiness audit (#529): a client or upstream can't stall or exhaust the server, process lifecycle, logs, sd_notify, and the supply chain (cargo-deny, build provenance, SBOMs). Patch releases (v0.2.3, …) carry fixes and small items until v0.3.0.

## Phase 2: a trial without risk (v0.3.0)

Goal: an operator can run ruxen next to their nginx on a copy of their real traffic, see where its answers differ, judge it by numbers, and move a non-critical site with a guide for each difference. Target: mid-December 2026. In order of priority:
- Trying it on real traffic: shadow mode behind nginx's `mirror` with a report of where the answers differ (#751), differential testing against nginx 1.30.6 in the lab (#750), metrics in Prometheus format (#481), a migration guide organised by what `--compat` reports (#752).
- The differences a typical configuration hits most, by corpus count: proxied responses still read whole, which is what `proxy_buffering off` (25 configurations) and failover depend on (#463); the rest of proxy caching (#233, 13); streaming request bodies with `proxy_request_buffering off` (#134, 4, together with the 64 KiB POST rate, #289).
- Robustness a trial would meet: blocking file I/O off the worker (#526), the two `&mut` to one stream (#501), fuzzing of the HTTP/2 glue, Range, rewrite and gzip with long runs on a schedule (#477).
- Performance: no regression on the headline scenarios.

## Phase 3: first users (v0.4.0)

Goal: a few sites run ruxen, at first non-critical ones, and what they report shapes the release. Their reports go ahead of everything. After them, by corpus use: variables in `root` / `alias` (#232, 1), `server … resolve` in upstreams (#597, 1), then the rest of nginx 1.30. The performance gaps without a milestone (#249, #334, #337, #451, #467, #545, …) are scheduled here when a user's workload hits them. Unused in the corpus and waiting for someone to ask: OCSP for client certificates (#142), HTTP/2 to upstreams (#599), session affinity (#600), the small 1.27–1.29 directives (#601).

## Phase 4: 1.0

A written compatibility statement (what is supported, and where ruxen deliberately differs), stability guarantees for that surface, an external security review, and HTTP/3. Extensions in the form of WASM filters, which nginx can't offer, are a possible differentiator here.

## Releases

Minor versions (v0.3.0, v0.4.0) are the phases above. Patch releases in between (v0.2.3, …) have milestones too, which order the work that comes next: mostly fixes, hardening and small compatibility items. Each release is still a snapshot of `main`, cut when there is a reason, such as a security fix, a regression, or a finished patch milestone; what isn't done moves to the next one. `main` stays releasable because a feature reaches the directive allowlist and `-V` only together with its implementation.

## How progress is measured

Each release reports five numbers, and the release pull request adds its row to the table below:

1. **Deployments**: sites outside the project known to run ruxen, shadow or live. The number the rest serve.
2. **nginx-tests**: files passing, out of those that run (`NGINX_TEST_PROGRESS.md`). The `-V` banner skips the files of modules ruxen doesn't claim: 314 of 511 at 0.2.2.
3. **Config corpus** (#216): the share of a few hundred real-world nginx configurations that ruxen loads, from application docs, popular container images and certbot setups, and the share that loads with nothing `--compat` reports as different (`corpus/RESULTS.md`). This is the best proxy for "would ruxen work for me", and its failures say what to build next.
4. **Performance**: ruxen vs nginx's stable release on every bench scenario, measured as ABBA pairs on a dedicated quiet machine (`bench/README.md`); between campaigns, the headline scenarios against the previous release.
5. **Robustness**: fuzzing, worker panics (target: none), and security fixes (`SECURITY.md`).

| release | deployments | nginx-tests | corpus | scenarios ≥ 95% of nginx, median (i7) | fuzzing | security fixes |
|---|---|---|---|---|---|---|
| 0.1.1 | 0 | 63 / 105 | 113 / 238 (47%) | — | — | 6 advisories |
| 0.1.2 | 0 | 65 / 106 | 149 / 238 (63%) | 64 of 83, 109.4% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.1.2/bench/campaign-0.1.2/REPORT.md)) | — | 1 advisory |
| 0.1.3 | 0 | 105 / 159 | 193 / 238 (81%) | 75 of 87, 118.8% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.1.3/bench/campaign-2026-10-14/REPORT.md)) | ~10.5 billion runs, 6 targets | — |
| 0.2.0 | 0 | 165 / 191 | 217 / 238 (91%) | 85 of 94, 120.2% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.2.0/bench/campaign-2026-10-17/REPORT.md)) | ~37 billion runs, 8 targets | 13 issues from the audit (#529) |
| 0.2.1 | 0 | 172 / 192 | 217 / 238 (91%) | 91 of 94, 121.5% ([report](https://github.com/gvozdetsky/ruxen/blob/v0.2.1/bench/campaign-2026-10-21/REPORT.md)) | ASan nginx-tests sweep, no reports | 5 issues |
| 0.2.2 | 0 | 182 / 197 | 218 / 238 (92%), 171 with no difference | no campaign; ABBA against 0.2.1 (i7, 6 pairs each): h2c_hello 106.2%, h2_tls_hello 104.7%, proxy_64k 100.3%, m1_hello 99.6%, tls_hello 99.5%, proxy_hello 99.2%, m3_static_1k 99.1%, gzip_html_8k 97.3% | ASan nginx-tests sweep, no reports; ~2.7 billion runs, 5 targets | 1 issue (#586), 1 dependency advisory |

Performance up to 0.2.0 is against nginx 1.24.0, from 0.2.1 against 1.30.6; on the bench configurations the two run at the same speed (±1.3%).

## Communication

The first announcement, on the Rust Users Forum, went out once phase 1's essentials were in (HTTP/2, reload, WebSocket and a container image). The next one doesn't wait for 0.3.0 to be complete: once shadow mode works (#751), a call for first operators to try ruxen next to their nginx, with the numbers and honest caveats (This Week in Rust, r/rust). Show HN waits for the first deployment's data. Until then: release notes and short technical write-ups.
