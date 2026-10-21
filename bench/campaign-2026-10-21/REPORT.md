# ruxen 0.2.1 candidate `cb24d29` vs nginx 1.30.6: performance campaign, 2026-10-20/21

The c017 campaign (`bench/campaign-2026-10-17/REPORT.md`, 0.2.0 candidate against nginx 1.24.0) repeated on main `cb24d29` against **nginx 1.30.6**, the current stable release, built with the same flags as the 1.24.0 reference (label `c021`). The method is the same: ABBA pairs with `bench/scripts/pair.sh`, both servers loading the same file, `wrk -t16 -c512` unless the scenario says otherwise, 6 pairs per scenario. All 94 scenarios ran on the i7 laptop, 2026-10-20 20:52 → 2026-10-21 05:12 (`results-i7.tsv`). The proxy_ext backend is still nginx 1.24.0. Every bench configuration passes `nginx -t` on 1.30.6; the only warning is the deprecation of `listen … http2`.

## The i9 rows didn't run

Every ruxen row on the i9 (32 threads; `results-i9.tsv` keeps them) failed at start with `io_uring_setup() failed (12: Cannot allocate memory)`: v0.2.0 and the candidate alike, at 32 workers. Linux 7.0, on both machines since the 26.04 upgrade, charges each io_uring ring to the user's `RLIMIT_MEMLOCK` (8 MiB) unless the process has `CAP_IPC_LOCK`. A worker's 4096-entry ring is about 0.5 MiB, so only about 16 workers fit. The i7's 12 workers fit. This is #612, fixed by #613. Only the i9's nginx 1.24.0 vs 1.30.6 rows ran there, plus a shorter set with #613 the same morning (below).

## Noise floor (i7)

| calibration | start | end |
|---|---:|---:|
| ruxen vs a copy of itself, `m1_hello` | 99.8% (100–100) | 99.9% (100–100) |
| ruxen vs a copy of itself, `proxy_hello` | 100.4% (100–101) | 100.1% (99–101) |

## nginx 1.30.6 against nginx 1.24.0

Both run as the "ruxen" side of `pair.sh` with `daemon off`, same configurations:

| scenario | i7 | i9 |
|---|---:|---:|
| `m1_hello` | 100.2% (99–101) | 100.5% (100–101) |
| `m1_no_keepalive` | 99.7% (99–100) | 100.2% (99–102) |
| `m3_static_1k` | 100.0% (99–102) | 100.2% (99–101) |
| `static_8k` | 100.0% (99–101) | 99.6% (99–100) |
| `m19_stream_1m` | 99.5% (98–101) | 99.9% (99–100) |
| `regex_locations_50` | 100.7% (100–102) | 100.2% (99–101) |
| `gzip_html_8k` | 100.1% (100–101) | 99.7% (99–100) |
| `proxy_hello` | 98.9% (97–100) | 99.5% (98–101) |
| `proxy_64k` | 99.8% (99–101) | 100.0% (100–100) |
| `proxy_post_64k` | 100.0% (100–100) | 99.7% (99–100) |
| `tls_hello` | 99.9% (99–101) | 99.3% (99–101) |
| `tls13_handshake` | 101.3% (96–110) | 100.1% (100–100) |
| `h2c_hello` | 99.5% (96–104) | 99.5% (96–104) |
| `h2_tls_hello` | 99.6% (98–101) | 100.5% (98–103) |
| `proxy_no_upstream_keepalive` | — | **8.8%** (9–9, 4 pairs) |

nginx 1.30.6 runs at nginx 1.24.0's speed wherever the configuration pins the upstream protocol: all rows above are within ±1.3%, inside the noise. The one large difference is a `proxy_pass` to an address with no `keepalive` (`proxy_no_upstream_keepalive`). There 1.30.6 runs at **8.8%** of 1.24.0 on the i9: 1.29.7 switched upstreams to HTTP/1.1 with no `Connection` header, so nginx now closes each upstream connection itself, and TIME_WAIT fills its own ephemeral ports (27,888 TIME_WAIT sockets for a range of 28,232). With `Connection: close` (1.24, and ruxen) the backend closes first. Details are in #582. The two no-keepalive proxy rows below (266%, 380%) measure this, not a ruxen change.

## i9: the short set, with #613

Run the same morning (06:20) on #613's head `2f4950eb`, 6 pairs per scenario. Under the i9's 8 MiB `RLIMIT_MEMLOCK` its 32 workers run 1024-entry rings instead of 4096. c017 is the i9 against nginx 1.24.0, at 4096 entries before the 26.04 upgrade.

| scenario | i9 vs 1.30.6 | c017 vs 1.24.0 |
|---|---:|---:|
| `m1_hello` | 102.2% (101–103) | 102.3% |
| `m1_no_keepalive` | 95.7% (93–97) | 95.3% |
| `m3_static_1k` | 105.0% (104–107) | 105.9% |
| `static_8k` | 100.9% (100–102) | 101.8% |
| `proxy_hello` | 97.2% (96–99) | 98.2% |
| `proxy_64k` | 110.5% (110–111) | 78.0% |
| `tls_hello` | 108.8% (106–112) | 110.8% |
| `h2c_hello` | 118.2% (114–121) | 115.8% |
| `regex_locations_50` | 125.5% (125–127) | 126.9% |
| `m19_stream_1m` | 112.2% (112–113) | 111.3% |

Everything is at c017's level except `proxy_64k` (+32, #538), within −2.0…+2.4 points against a different nginx. The smaller ring costs nothing visible. The same-binary check on the i7 is below.

## Summary (i7)

| | c021 vs 1.30.6 | c017 vs 1.24.0 |
|---|---:|---:|
| scenarios | 94 | 94 |
| ruxen ≥ 95% of nginx | 91 | 85 |
| ruxen ≥ 100% of nginx | 81 | 78 |
| median ruxen / nginx | 121.5% | 120.2% |

- **Fixed since c017:**
  - `proxy_64k` 75% → **102%** and `proxy_ext_64k` 77% → **106%** (#538);
  - `proxy_post_2m` 64% → 72% (#537);
  - `proxy_1m` 93% → 96.5%, `tls_static_1m` 94% → 97.5%, `proxy_ext_1m` 93% → 95.6%.
- **Under 95%, all with open issues:**
  - `proxy_post_64k` 69.6% and `proxy_post_2m` 71.6% (#289);
  - `m1_hello_c4096` 85.7% (#467).
- **Header-heavy rows,** 2.0–2.7 points below c017: `many_request_headers`, `add_header_many`, `expires_1k`. They are measured against a different nginx, so the candidate was also measured against v0.2.0 directly (next section).
- `proxy_no_upstream_keepalive` 266% and `proxy_ext_no_keepalive` 380% measure nginx 1.30's upstream defaults (above), not ruxen.

## Candidate against v0.2.0 (i7, same binaries)

`rc-cb24d29` / `rc3-fc9ba99` (v0.2.0), 6 pairs:

| scenario | B / A |
|---|---:|
| `m1_hello` | 99.6% (99.0–99.9) |
| `proxy_hello` | 100.0% (99.5–100.7) |
| `tls_hello` | 100.4% (99.7–101.6) |
| `many_request_headers` | **98.5%** (97.5–99.2) |
| `add_header_many` | 100.0% (98.8–100.6) |
| `expires_1k` | 99.4% (98.3–100.4) |

## epoll driver against nginx 1.30.6 (`RUXEN_DRIVER=epoll`, i7)

| scenario | c021 | c017 vs 1.24.0 |
|---|---:|---:|
| `m1_hello` | 98.7% (98–100) | 98.5% |
| `m1_no_keepalive` | 96.8% (96–97) | 96.8% |
| `m3_static_1k` | 109.3% (108–110) | 108.5% |
| `static_8k` | 106.5% (105–107) | 106.1% |
| `proxy_hello` | 94.1% (93–95) | 93.9% |
| `proxy_no_upstream_keepalive` | 322.8% (322–324) | 91.9% |
| `tls_hello` | 121.6% (121–124) | 122.0% |
| `tls13_handshake` | 125.9% (122–130) | 125.9% |

## `many_request_headers` against v0.2.0: bisected

98.3% (97.7–99.0, 8 pairs) on a repeat. Each step between v0.2.0 and the candidate, 6 pairs on the i7:

| step (B / A) | merges | result |
|---|---|---:|
| `fc9ba99` → `2dff464e` | #551, #555, #557, #556, #558 | 99.8% (99.4–100.2) |
| → `eb03a953` | #561 (resolver) | 99.0% (98.2–99.5) |
| → `65380399` | #562–#567 | 101.3% (100.2–102.2) |
| → `cd7a856a` | #568–#570, #572 | 99.8% (98.8–100.8) |
| → `f470a1da` | #571 | 100.3% (99.8–101.0) |
| → `077af89d` | #573 (config parsing only) | 99.0% (98.3–99.5) |
| → `cb24d29` | #576 | 99.6% (98.7–100.2) |

No step stands out. The two −1% steps are #561, which the next step gains back (+1.3%), and #573, which changes only configuration parsing and runs no code on this path. So the scenario moves by about ±1% with the binary's code layout, not with one change. `m1_hello`, `add_header_many` and `expires_1k` against v0.2.0 are within 99.4–100.0%. Against nginx it stays at 127%.

## PRs measured the same morning (i7, ABBA against their base, 6 pairs)

| PR | scenario | B / A |
|---|---|---:|
| #580 (#578, chunked trailer) | `proxy_post_1k` / `post_1k_return` | 99.8% / 100.1% |
| #606 (#581, 103 Early Hints) | `proxy_hello` / `proxy_64k` | 100.4% / 100.3% |
| #604 (#588, range limit) | `m5_range_206` / `m3_static_1k` | 100.0% / 99.6% |
| #608 (#592, h2 `:authority`) | `h2c_hello` / `h2_tls_hello` | 100.9% / 100.4% |
| #610 (#594, `http2_*` per location) | `m1_hello` / `h2c_static_8k` | 99.5% / 99.8% |
| #613 (#612, ring size), same binary at 1024 vs 4096 entries | `m1_hello` / `proxy_hello` / `m3_static_1k` | 99.7% / 100.3% / 100.0% |

## All scenarios (i7)

↑ / ↓: at least 2 points away from c017, with c017's value outside the range of the 6 pairs. c017 measured against a different nginx (1.24.0), so a difference is ruxen's change and nginx's together.

| scenario | i7 vs 1.30.6 | c017 vs 1.24.0 | Δ |
|---|---:|---:|---:|
| `m1_hello` | 122.0% (121–124) | 122.8% | -0.8 |
| `m1_no_keepalive` | 95.7% (95–96) | 95.7% | +0.0 |
| `m1_keepalive_requests_1` | 95.9% (95–97) | 95.7% | +0.2 |
| `m3_static_1k` | 145.7% (144–146) | 146.2% | -0.5 |
| `m3_static_1k_low_concurrency` | 119.0% (117–123) | 117.7% | +1.3 |
| `m3_static_1k_no_keepalive` | 95.2% (95–96) | 95.2% | +0.0 |
| `m5_conditional_304` | 131.0% (130–132) | 131.3% | -0.3 |
| `m5_if_modified_since_304` | 130.7% (130–132) | 131.1% | -0.4 |
| `m5_range_206` | 148.3% (147–150) | 148.4% | -0.1 |
| `m5_range_open_ended_206` | 147.6% (147–149) | 148.7% | -1.1 |
| `m5_range_suffix_206` | 148.7% (147–150) | 148.6% | +0.1 |
| `m19_stream_1m` | 102.7% (100–105) | 103.2% | -0.5 |
| `m19_stream_1m_low_concurrency` | 99.3% (99–100) | 98.4% | +0.9 |
| `m19_stream_128m` | 99.0% (93–106) | 99.6% | -0.6 |
| `static_8k` | 114.6% (112–118) | 113.9% | +0.7 |
| `add_header_many` | 118.2% (117–119) | 120.3% | -2.1 ↓ |
| `auth_basic_hello` | 150.1% (148–152) | 151.1% | -1.0 |
| `error_page_intercept` | 129.4% (128–131) | 130.8% | -1.4 |
| `rewrite_hello` | 127.5% (125–129) | 127.8% | -0.3 |
| `vars_map` | 125.7% (125–127) | 125.8% | -0.1 |
| `proxy_hello` | 122.2% (122–123) | 121.4% | +0.8 |
| `tls_hello` | 141.3% (141–142) | 141.4% | -0.1 |
| `m1_hello_c1` | 107.2% (97–129) | 108.1% | -0.9 |
| `m1_hello_c4096` | 85.7% (85–86) | 85.4% | +0.3 |
| `static_8k_c4096` | 112.8% (112–113) | 113.1% | -0.3 |
| `proxy_hello_c32` | 102.9% (102–104) | 101.3% | +1.6 |
| `proxy_cache_hit` | 138.0% (136–139) | 135.1% | +2.9 ↑ |
| `proxy_cache_miss` | 138.5% (137–140) | 135.1% | +3.4 ↑ |
| `tls_hello_c32` | 104.2% (102–107) | 104.1% | +0.1 |
| `redirect_301` | 119.9% (119–121) | 120.0% | -0.1 |
| `vars_render` | 119.8% (119–121) | 119.5% | +0.3 |
| `args_render` | 119.2% (118–120) | 118.6% | +0.6 |
| `set_if` | 119.7% (118–122) | 119.2% | +0.5 |
| `split_clients` | 118.0% (117–119) | 118.0% | +0.0 |
| `map_regex_50` | 184.1% (183–185) | 185.1% | -1.0 |
| `add_header_vars` | 113.3% (112–114) | 113.9% | -0.6 |
| `rewrite_captures` | 123.7% (122–125) | 123.8% | -0.1 |
| `error_page_named` | 122.2% (121–123) | 123.1% | -0.9 |
| `many_request_headers` | 127.2% (126–128) | 129.9% | -2.7 ↓ |
| `regex_locations_50` | 182.7% (181–184) | 183.4% | -0.7 |
| `prefix_locations_200` | 117.6% (116–118) | 118.6% | -1.0 |
| `vhost_exact_100` | 121.6% (121–123) | 122.5% | -0.9 |
| `vhost_wildcard_50` | 115.3% (114–117) | 115.6% | -0.3 |
| `vhost_regex_20` | 136.0% (134–138) | 137.8% | -1.8 |
| `static_0b` | 130.8% (130–132) | 132.4% | -1.6 |
| `static_16k` | 111.7% (111–112) | 111.8% | -0.1 |
| `static_64k` | 106.7% (106–107) | 106.8% | -0.1 |
| `static_256k` | 99.1% (98–100) | 99.5% | -0.4 |
| `static_1k_sendfile_off` | 131.0% (130–132) | 130.9% | +0.1 |
| `static_1m_sendfile_off` | 103.3% (102–104) | 103.8% | -0.5 |
| `static_index` | 135.2% (134–136) | 135.4% | -0.2 |
| `try_files_hit` | 144.2% (143–145) | 144.6% | -0.4 |
| `try_files_fallback` | 143.9% (143–144) | 143.1% | +0.8 |
| `alias_1k` | 146.2% (144–148) | 146.3% | -0.1 |
| `expires_1k` | 129.1% (128–130) | 131.1% | -2.0 ↓ |
| `autoindex_100` | 106.4% (106–107) | 106.9% | -0.5 |
| `access_log_hello` | 119.4% (118–121) | 120.1% | -0.7 |
| `access_log_static_1k` | 140.0% (140–141) | 140.1% | -0.1 |
| `post_1k_return` | 137.0% (137–138) | 137.2% | -0.2 |
| `proxy_post_1k` | 120.1% (119–121) | 119.2% | +0.9 |
| `proxy_post_64k` | 69.6% (69–71) | 69.2% | +0.4 |
| `proxy_post_2m` | 71.6% (70–74) | 63.5% | +8.1 ↑ |
| `proxy_no_upstream_keepalive` | 265.7% (253–273) | 76.5% | +189.2 ↑ |
| `proxy_rr4` | 121.7% (121–122) | 121.2% | +0.5 |
| `proxy_least_conn4` | 121.5% (121–122) | 121.3% | +0.2 |
| `proxy_hash4` | 122.6% (122–123) | 121.9% | +0.7 |
| `proxy_ip_hash4` | 122.0% (121–123) | 121.1% | +0.9 |
| `proxy_headers_vars` | 121.0% (120–122) | 120.8% | +0.2 |
| `proxy_64k` | 102.2% (101–103) | 75.3% | +26.9 ↑ |
| `proxy_1m` | 96.5% (95–97) | 92.9% | +3.6 ↑ |
| `proxy_intercept` | 872.7% (869–879) | 870.5% | +2.2 |
| `proxy_redirect_302` | 119.1% (118–121) | 118.5% | +0.6 |
| `proxy_xar` | 113.9% (113–114) | 114.0% | -0.1 |
| `proxy_client_no_keepalive` | 98.7% (98–99) | 98.7% | +0.0 |
| `tls12_hello` | 140.1% (139–141) | 140.5% | -0.4 |
| `tls13_handshake` | 125.0% (119–129) | 124.8% | +0.2 |
| `tls12_handshake` | 108.3% (107–110) | 108.6% | -0.3 |
| `tls13_rsa_handshake` | 127.7% (125–130) | 125.5% | +2.2 |
| `tls_static_1k` | 137.5% (136–138) | 137.6% | -0.1 |
| `tls_static_1m` | 97.5% (92–102) | 94.1% | +3.4 |
| `tls_proxy_hello` | 129.6% (129–131) | 128.1% | +1.5 |
| `proxy_https_hello` | 144.2% (144–145) | 143.4% | +0.8 |
| `proxy_ext_hello` | 111.2% (110–112) | 109.1% | +2.1 ↑ |
| `proxy_ext_no_keepalive` | 379.8% (376–383) | 109.6% | +270.2 ↑ |
| `proxy_ext_64k` | 105.7% (105–106) | 76.9% | +28.8 ↑ |
| `proxy_ext_1m` | 95.6% (92–99) | 93.0% | +2.6 |
| `proxy_ext_post_1k` | 110.9% (108–112) | 109.5% | +1.4 |
| `proxy_ext_post_64k` | 111.4% (111–112) | 110.7% | +0.7 |
| `proxy_ext_xar` | 110.5% (110–111) | 109.2% | +1.3 |
| `gzip_html_8k` | 114.9% (114–116) | 113.2% | +1.7 |
| `limit_req_static_1k` | 141.8% (141–142) | 142.3% | -0.5 |
| `h2c_hello` | 171.9% (169–175) | 171.1% | +0.8 |
| `h2c_static_8k` | 111.3% (111–112) | 110.5% | +0.8 |
| `h2_tls_hello` | 153.0% (151–154) | 151.9% | +1.1 |
