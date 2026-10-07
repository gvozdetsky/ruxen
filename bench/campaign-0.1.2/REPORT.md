# ruxen 0.1.2 vs nginx 1.24: performance report

Measured on 2026-10-06/07, the night before the 0.1.2 release, on the release binary (`ruxen/0.1.2`, commit `840b69d`: main `0be66b5` plus the version bump). Every scenario compares ruxen with nginx 1.24.0 loading **the same configuration file**. The configurations and the scenario list are in `bench/` (`bench/scenarios/manifest.tsv`). Only paths both servers support are included. Before measuring, each scenario was checked to give the same status, body size and header set from both servers. The exceptions are listed under Caveats.

## Method

- **ABBA pairs** (`bench/scripts/pair.sh`). A 20 s throwaway warm-up, then 8 pairs in alternating order (nginx ruxen, ruxen nginx, …). Each run gets a fresh server start, the scenario's 5 s wrk warm-up and a 10 s measurement. The ratio is the geometric mean of the 8 per-pair ruxen/nginx throughput ratios; min–max is the spread of those 8. Latency figures are the medians of wrk's p50 / p99 over the 8 runs of each server.
- **Load:** `wrk -t16 -c512` unless the scenario says otherwise (`_c1` = 1 connection, `_c32` = `-t4 -c32`, `_c4096` = 4096 connections). Client and server share the machine over loopback, as in every ruxen benchmark so far.
- **Noise floor**, measured the same way with the same binary on both sides:

| calibration | i7 laptop | i9 |
|---|---:|---:|
| ruxen vs a copy of itself, `m1_hello` | 99.5% (94.6–101.8) | 100.5% (99.5–102.8) on a rerun; the first run had one wild pair (161%, median 100.2%) |
| ruxen vs a copy of itself, `proxy_hello` | 99.5% (98.9–100.5) | 100.3% (99.6–101.5) |
| nginx vs nginx, `m1_hello` | 100.8% (99.4–103.0) | 100.1% (99.5–101.4) |

  Differences within about ±2% are noise. The i9 had one wild pair in its first calibration (a desktop session was open); the rerun at the end of the night was clean. The spread column shows when a scenario's run was affected.

  `m1_hello_c1` (one connection, latency-bound) is noisy on the i7 by nature: its first run spread 81–139%, and a rerun with 12 pairs gave 94.9% (86.1–105.4%).

## Machines

| | i7 laptop (dedicated bench machine) | i9 (desktop session open, idle at night) |
|---|---|---|
| CPU | Intel Core i7-9750H, 6 cores / 12 threads | Intel Core i9-13900HX, 24 cores (8P+16E) / 32 threads |
| Memory | 15 GB | 30 GB |
| OS | Ubuntu 24.04.5, Linux 7.0.0-38 | Ubuntu 24.04.5, Linux 7.0.0-38 |
| nginx | 1.24.0 (Ubuntu package) | 1.24.0 (Ubuntu package) |
| wrk | 4.1.0 (Debian package) | 4.1.0 (Debian package) |
| CPU governor | performance | powersave (intel_pstate) |
| workers | `worker_processes auto` (12) | `worker_processes auto` (32) |

## Summary

Out of 83 scenarios:

| | i7 | i9 |
|---|---:|---:|
| ruxen ≥ 100% of nginx | 60 | 26 |
| ruxen ≥ 95% of nginx (the performance contract) | 64 | 54 |
| median ruxen / nginx | 109.4% | 96.9% |

- **Faster than nginx or on par:** static files up to 256 KiB, 304 and range responses, `try_files`, `index`, `alias`, `auth_basic`, rewrites and variables, `map`, `split_clients`, prefix locations, exact and wildcard server names, access logging, TLS 1.2 and 1.3 (keep-alive and a handshake per request, ECDSA and RSA), TLS termination in front of a proxy, and the reverse proxy itself with small responses. On the i7, most of these are 105–140% of nginx. On the i9 most are 94–105%.
- **0.1.2 vs 0.1.1:** within noise on `m1_hello`, `proxy_hello`, `tls_hello`, `static_8k` and `m19_stream_1m` on both machines (99.8–101.3%).
- **Where ruxen is clearly behind.** Each case has an issue:

| area | worst case | issue |
|---|---|---|
| `X-Accel-Redirect` through a proxy: the upstream connection is closed after every redirect | 4–16% | #245 |
| request bodies over 2 KiB go to a temp file even when kept in memory | 38–94% (`*_post_64k`) | #246 |
| proxied responses are buffered whole | 36–97% (`proxy_ext_64k`, `proxy_ext_1m`) | #88 |
| 1 MiB responses at 512 connections on the 6-core machine | 51–66% (i9: 95–101%) | #247 |
| regex locations, regex server names and regex `map` on the i9 (the per-match cost; 8 workers don't change it) | 68–84% on the i9 (i7: 103–128%) | #248 |
| autoindex: a process-wide lock per entry (40% with 32 workers, 74% with 8) | 40% (i9), 76% (i7) | #250 |
| a new connection per request (no client keep-alive) | 84–94% | #128 |
| 4096 keep-alive connections on 6 cores | 76% (i9: 97%) | #127 |
| proxying to a server block of the same instance without upstream keep-alive (separate processes are on par) | 21% (i9), 67% (i7) | #249 |

In the other direction, with `proxy_intercept_errors` nginx closes the upstream connection after every intercepted error, and ruxen keeps it: ruxen is 8–25× faster there.

## All scenarios

ruxen / nginx throughput per scenario: geometric mean of 8 ABBA pairs (min–max of the pairs). ⚠ marks < 95%. The latency columns are from the i7, as the median over the 8 runs of each server.

| scenario | i7: ruxen / nginx (min–max) | i9: ruxen / nginx (min–max) | i7: req/s nginx → ruxen | i7: p50 nginx → ruxen | i7: p99 nginx → ruxen |
|---|---:|---:|---:|---:|---:|
| `m1_hello` — return 200 "hello", keep-alive | **113.4%** (112–116) | **99.3%** (98–100) | 327.1 k → 371.7 k | 1.25 ms → 1.06 ms | 6.89 ms → 7.06 ms |
| `m1_no_keepalive` — return 200 "hello", keepalive_timeout 0 | **93.4%** ⚠ (92–95) | **94.4%** ⚠ (93–95) | 85.0 k → 79.2 k | 3.11 ms → 3.97 ms | 12.78 ms → 21.88 ms |
| `m1_keepalive_requests_1` — return 200 "hello", keepalive_requests 1 | **93.2%** ⚠ (92–94) | **94.5%** ⚠ (92–97) | 84.6 k → 79.4 k | 3.11 ms → 3.96 ms | 12.68 ms → 22.86 ms |
| `m3_static_1k` — static 1 KiB file, keep-alive | **132.5%** (130–136) | **103.2%** (103–104) | 183.0 k → 241.4 k | 2.56 ms → 1.80 ms | 6.52 ms → 6.61 ms |
| `m3_static_1k_low_concurrency` — static 1 KiB file, low concurrency | **105.3%** (100–108) | **99.6%** (96–104) | 188.4 k → 199.5 k | 132 µs → 132 µs | 1.08 ms → 974 µs |
| `m3_static_1k_no_keepalive` — static 1 KiB file, keepalive disabled | **91.4%** ⚠ (90–93) | **90.5%** ⚠ (89–92) | 77.3 k → 70.9 k | 4.63 ms → 5.18 ms | 22.41 ms → 26.64 ms |
| `m5_conditional_304` — If-None-Match -> 304 | **117.7%** (116–120) | **96.2%** (96–97) | 224.8 k → 265.6 k | 2.02 ms → 1.59 ms | 6.21 ms → 6.50 ms |
| `m5_if_modified_since_304` — If-Modified-Since -> 304 | **118.0%** (116–119) | **95.9%** (96–96) | 224.0 k → 263.6 k | 2.02 ms → 1.62 ms | 6.29 ms → 6.46 ms |
| `m5_range_206` — Range bytes=0-511 -> 206 | **135.2%** (133–136) | **104.5%** (104–105) | 178.3 k → 240.9 k | 2.63 ms → 1.79 ms | 6.39 ms → 6.60 ms |
| `m5_range_open_ended_206` — Range bytes=512- -> 206 | **135.0%** (132–137) | **104.3%** (103–105) | 177.3 k → 239.0 k | 2.66 ms → 1.80 ms | 6.40 ms → 6.79 ms |
| `m5_range_suffix_206` — Range bytes=-512 -> 206 | **134.0%** (131–136) | **104.5%** (104–105) | 178.0 k → 239.0 k | 2.65 ms → 1.79 ms | 6.38 ms → 6.72 ms |
| `m19_stream_1m` — streamed 1 MiB file | **64.5%** ⚠ (64–66) | **101.2%** (101–102) | 5.1 k → 3.3 k | 70.75 ms → 138 ms | 304 ms → 356 ms |
| `m19_stream_1m_low_concurrency` — streamed 1 MiB file, low concurrency | **94.9%** ⚠ (94–96) | **93.1%** ⚠ (89–99) | 5.5 k → 5.3 k | 3.51 ms → 3.60 ms | 12.96 ms → 7.23 ms |
| `m19_stream_128m` — streamed 128 MiB file | **98.2%** (91–105) (errors) | **96.3%** (94–99) (errors) | 0.0 k → 0.0 k | 1090 ms → 1255 ms | 1970 ms → 1980 ms |
| `static_8k` — static 8 KiB file, keep-alive | **110.4%** (108–112) | **99.9%** (99–100) | 169.8 k → 186.9 k | 2.73 ms → 2.35 ms | 7.20 ms → 7.94 ms |
| `add_header_many` — return 200 + 6 add_header | **112.2%** (110–114) | **100.9%** (100–102) | 314.7 k → 352.6 k | 1.29 ms → 1.04 ms | 7.17 ms → 7.76 ms |
| `auth_basic_hello` — auth_basic {SHA} verify + 5-byte static file | **141.7%** (139–145) | **105.4%** (105–106) | 153.2 k → 216.0 k | 3.12 ms → 1.98 ms | 6.84 ms → 7.14 ms |
| `error_page_intercept` — try_files 404 -> error_page = /fallback | **120.4%** (119–122) | **100.7%** (100–101) | 269.3 k → 324.6 k | 1.63 ms → 1.23 ms | 6.14 ms → 6.77 ms |
| `rewrite_hello` — rewrite /foo -> /bar last | **117.5%** (116–119) | **98.2%** (98–99) | 300.1 k → 352.7 k | 1.42 ms → 1.14 ms | 6.59 ms → 6.26 ms |
| `vars_map` — map $http_user_agent -> return 200 $kind | **115.9%** (114–117) | **96.0%** (96–97) | 292.7 k → 337.4 k | 1.47 ms → 1.21 ms | 6.36 ms → 6.18 ms |
| `proxy_hello` — proxy_pass to in-process upstream with keepalive | **111.2%** (109–112) | **96.2%** (95–97) | 127.9 k → 142.6 k | 3.82 ms → 3.48 ms | 7.83 ms → 6.63 ms |
| `tls_hello` — TLS 1.3 return 200 "hello" | **135.0%** (133–138) | **109.6%** (106–112) | 177.4 k → 238.6 k | 2.46 ms → 1.54 ms | 8.91 ms → 8.95 ms |
| `m1_hello_c1` — return 200, one connection | **99.0%** (81–139) | **92.5%** ⚠ (91–94) | 52.3 k → 51.9 k | 16 µs → 17 µs | 34 µs → 44 µs |
| `m1_hello_c4096` — return 200, 4096 connections | **75.6%** ⚠ (75–76) | **97.2%** (96–98) | 315.4 k → 238.3 k | 10.03 ms → 13.05 ms | 27.46 ms → 42.48 ms |
| `static_8k_c4096` — static 8 KiB file, 4096 connections | **101.9%** (100–103) | **97.2%** (97–98) | 167.7 k → 171.1 k | 22.84 ms → 20.52 ms | 51.52 ms → 68.09 ms |
| `proxy_hello_c32` — proxy_pass with upstream keep-alive, low concurrency | **95.4%** (94–98) | **103.7%** (102–106) | 122.2 k → 116.3 k | 220 µs → 235 µs | 835 µs → 842 µs |
| `tls_hello_c32` — TLS 1.3 return 200, low concurrency | **101.3%** (99–103) | **107.3%** (100–116) | 147.9 k → 150.5 k | 163 µs → 118 µs | 428 µs → 252 µs |
| `redirect_301` — return 301 with $request_uri | **109.4%** (106–112) | **97.1%** (97–97) | 312.6 k → 342.6 k | 1.33 ms → 1.19 ms | 6.84 ms → 6.37 ms |
| `vars_render` — return 200 with eight variables | **111.7%** (111–113) | **96.7%** (96–97) | 307.8 k → 343.9 k | 1.38 ms → 1.17 ms | 6.62 ms → 6.25 ms |
| `args_render` — return 200 $arg_x $arg_y | **111.6%** (110–113) | **96.3%** (96–97) | 313.7 k → 350.3 k | 1.34 ms → 1.16 ms | 6.71 ms → 6.22 ms |
| `set_if` — set + two if (regex, comparison) | **107.6%** (106–109) | **91.5%** ⚠ (91–92) | 294.4 k → 317.2 k | 1.47 ms → 1.31 ms | 6.40 ms → 6.08 ms |
| `split_clients` — split_clients on remote_addr + request_uri | **108.4%** (107–110) | **95.5%** (95–96) | 317.7 k → 345.5 k | 1.31 ms → 1.17 ms | 6.86 ms → 6.22 ms |
| `map_regex_50` — map with 50 regex keys, last one matches | **128.2%** (126–130) | **84.1%** ⚠ (83–85) | 195.4 k → 251.2 k | 2.41 ms → 1.88 ms | 5.86 ms → 4.60 ms |
| `add_header_vars` — four add_header with variables | **104.3%** (102–106) | **93.5%** ⚠ (93–94) | 312.3 k → 326.1 k | 1.34 ms → 1.25 ms | 6.92 ms → 6.27 ms |
| `rewrite_captures` — rewrite with two captures -> last -> $arg_* | **115.7%** (114–117) | **92.8%** ⚠ (92–93) | 284.8 k → 329.1 k | 1.53 ms → 1.25 ms | 6.31 ms → 6.12 ms |
| `error_page_named` — return 404 -> error_page = @named | **114.6%** (112–117) | **99.1%** (99–100) | 316.7 k → 362.5 k | 1.33 ms → 1.10 ms | 6.75 ms → 6.78 ms |
| `many_request_headers` — return 200, 20 browser-like request headers | **111.7%** (110–114) | **94.3%** ⚠ (94–95) | 279.2 k → 311.9 k | 1.56 ms → 1.34 ms | 6.26 ms → 6.11 ms |
| `regex_locations_50` — 50 regex locations, last one matches | **106.2%** (104–108) | **67.9%** ⚠ (67–68) | 205.2 k → 217.6 k | 2.29 ms → 2.21 ms | 5.70 ms → 4.44 ms |
| `prefix_locations_200` — 200 prefix locations | **108.1%** (106–110) | **96.6%** (94–98) | 323.7 k → 348.9 k | 1.27 ms → 1.15 ms | 6.89 ms → 6.36 ms |
| `vhost_exact_100` — Host matches one of 100 exact server_names | **105.5%** (103–108) | **95.9%** (95–97) | 328.2 k → 346.4 k | 1.25 ms → 1.12 ms | 6.96 ms → 8.37 ms |
| `vhost_wildcard_50` — Host matches one of 50 wildcard server_names | **104.6%** (103–107) | **93.5%** ⚠ (93–94) | 325.6 k → 339.7 k | 1.25 ms → 1.20 ms | 6.91 ms → 6.39 ms |
| `vhost_regex_20` — Host matches the 20th regex server_name | **102.7%** (101–105) | **74.5%** ⚠ (74–75) | 250.0 k → 257.3 k | 1.80 ms → 1.74 ms | 5.72 ms → 6.36 ms |
| `static_0b` — static empty file | **123.1%** (121–125) | **98.4%** (98–99) | 217.0 k → 266.9 k | 2.12 ms → 1.58 ms | 6.05 ms → 6.68 ms |
| `static_16k` — static 16 KiB file | **107.6%** (106–109) | **98.7%** (98–99) | 163.2 k → 175.8 k | 2.79 ms → 2.50 ms | 7.67 ms → 8.59 ms |
| `static_64k` — static 64 KiB file | **104.6%** (103–106) | **99.2%** (99–100) | 109.8 k → 114.3 k | 4.06 ms → 3.81 ms | 11.03 ms → 11.25 ms |
| `static_256k` — static 256 KiB file | **99.1%** (98–101) | **105.3%** (104–106) | 49.5 k → 49.2 k | 6.63 ms → 6.05 ms | 20.04 ms → 17.77 ms |
| `static_1k_sendfile_off` — static 1 KiB file, sendfile off | **120.5%** (118–123) | **96.9%** (96–98) | 197.9 k → 238.8 k | 2.35 ms → 1.83 ms | 6.12 ms → 6.45 ms |
| `static_1m_sendfile_off` — static 1 MiB file, sendfile off | **65.6%** ⚠ (65–67) | **99.9%** (99–101) | 5.1 k → 3.4 k | 73.96 ms → 138 ms | 288 ms → 339 ms |
| `static_index` — directory request served by index.html | **125.1%** (123–128) | **99.3%** (99–100) | 167.1 k → 208.7 k | 2.83 ms → 2.17 ms | 6.51 ms → 6.40 ms |
| `try_files_hit` — try_files $uri /spa/index.html, file exists | **132.2%** (129–135) | **103.1%** (102–104) | 168.0 k → 221.5 k | 2.83 ms → 2.01 ms | 6.50 ms → 6.61 ms |
| `try_files_fallback` — try_files $uri /spa/index.html, SPA route | **132.8%** (129–136) | **103.8%** (103–104) | 156.8 k → 208.2 k | 3.04 ms → 2.17 ms | 6.64 ms → 6.56 ms |
| `alias_1k` — alias, 1 KiB file | **132.9%** (130–135) | **103.3%** (102–104) | 179.9 k → 239.1 k | 2.62 ms → 1.81 ms | 6.22 ms → 6.72 ms |
| `expires_1k` — expires 1h, 1 KiB file | **119.9%** (118–122) | **94.2%** ⚠ (94–95) | 176.8 k → 211.3 k | 2.66 ms → 2.12 ms | 6.41 ms → 6.56 ms |
| `autoindex_100` — autoindex of 100 files | **75.7%** ⚠ (74–78) | **39.9%** ⚠ (38–42) | 24.7 k → 18.6 k | 20.50 ms → 27.37 ms | 28.41 ms → 36.90 ms |
| `access_log_hello` — return 200 + access_log combined | **111.6%** (110–113) | **93.7%** ⚠ (93–95) | 296.1 k → 330.2 k | 1.43 ms → 1.23 ms | 6.61 ms → 6.34 ms |
| `access_log_static_1k` — static 1 KiB file + access_log combined | **129.9%** (127–132) | **98.6%** (98–99) | 170.3 k → 221.0 k | 2.77 ms → 2.00 ms | 6.39 ms → 6.62 ms |
| `post_1k_return` — POST 1 KiB body to a return | **123.5%** (122–124) | **100.1%** (99–101) | 274.7 k → 339.4 k | 1.55 ms → 1.19 ms | 6.59 ms → 6.39 ms |
| `proxy_post_1k` — POST 1 KiB body through proxy_pass | **105.8%** (105–107) | **96.3%** (96–97) | 110.7 k → 117.2 k | 4.45 ms → 4.20 ms | 8.33 ms → 8.04 ms |
| `proxy_post_64k` — POST 64 KiB body through proxy_pass | **38.4%** ⚠ (38–39) | **51.5%** ⚠ (51–52) | 24.7 k → 9.5 k | 20.87 ms → 54.02 ms | 27.91 ms → 71.91 ms |
| `proxy_no_upstream_keepalive` — proxy_pass to an address, new upstream connection per request | **67.3%** ⚠ (65–71) | **21.2%** ⚠ (20–23) | 58.4 k → 38.8 k | 8.73 ms → 11.29 ms | 13.02 ms → 93.42 ms |
| `proxy_rr4` — proxy_pass round robin over 4 servers, keep-alive | **110.4%** (109–113) | **94.2%** ⚠ (93–95) | 126.7 k → 139.5 k | 3.88 ms → 3.56 ms | 7.71 ms → 6.46 ms |
| `proxy_least_conn4` — proxy_pass least_conn over 4 servers, keep-alive | **110.1%** (109–112) | **94.9%** ⚠ (94–96) | 126.7 k → 139.6 k | 3.85 ms → 3.54 ms | 7.95 ms → 6.61 ms |
| `proxy_headers_vars` — proxy_pass + 5 proxy_set_header with variables | **109.9%** (109–111) | **93.6%** ⚠ (93–94) | 123.9 k → 136.2 k | 3.95 ms → 3.63 ms | 8.05 ms → 6.64 ms |
| `proxy_64k` — proxy_pass, 64 KiB upstream response | **53.2%** ⚠ (52–54) | **74.7%** ⚠ (74–76) | 37.1 k → 19.7 k | 13.54 ms → 25.48 ms | 23.59 ms → 45.52 ms |
| `proxy_1m` — proxy_pass, 1 MiB upstream response | **33.8%** ⚠ (33–34) | **54.8%** ⚠ (54–55) | 3.4 k → 1.2 k | 143 ms → 417 ms | 322 ms → 666 ms |
| `proxy_intercept` — upstream 404 -> proxy_intercept_errors -> error_page | **846.3%** (835–858) | **2502.2%** (2454–2541) | 15.4 k → 130.0 k | 18.89 ms → 3.81 ms | 139 ms → 6.85 ms |
| `proxy_redirect_302` — upstream 302, Location rewritten by proxy_redirect default | **108.9%** (107–110) | **93.9%** ⚠ (93–94) | 124.1 k → 134.8 k | 3.95 ms → 3.69 ms | 7.94 ms → 6.74 ms |
| `proxy_xar` — upstream X-Accel-Redirect to an internal 1 KiB file | **15.2%** ⚠ (15–16) | **4.1%** ⚠ (4–4) | 98.6 k → 15.0 k | 5.04 ms → 24.41 ms | 9.25 ms → 557 ms |
| `proxy_client_no_keepalive` — proxy_pass, client without keep-alive | **93.2%** ⚠ (91–95) | **84.3%** ⚠ (84–85) | 61.5 k → 57.3 k | 6.84 ms → 7.03 ms | 28.34 ms → 26.55 ms |
| `tls12_hello` — TLS 1.2 return 200, keep-alive | **133.1%** (130–134) | **109.6%** (106–111) | 183.3 k → 244.7 k | 2.37 ms → 1.58 ms | 8.30 ms → 8.27 ms |
| `tls13_handshake` — TLS 1.3, ECDSA P-256, a handshake per request | **125.1%** (122–129) | **104.0%** (98–111) | 6.0 k → 7.5 k | 25.78 ms → 14.87 ms | 132 ms → 51.22 ms |
| `tls12_handshake` — TLS 1.2, ECDSA P-256, a handshake per request | **112.5%** (109–116) | **104.6%** (104–105) | 13.5 k → 15.2 k | 10.21 ms → 7.36 ms | 57.59 ms → 24.23 ms |
| `tls13_rsa_handshake` — TLS 1.3, RSA 2048, a handshake per request | **123.3%** (119–127) | **104.8%** (100–115) | 6.0 k → 7.4 k | 24.76 ms → 15.12 ms | 139 ms → 48.88 ms |
| `tls_static_1k` — TLS 1.3 static 1 KiB file | **130.0%** (128–132) | **110.7%** (110–111) | 127.2 k → 165.4 k | 3.62 ms → 2.58 ms | 9.43 ms → 9.46 ms |
| `tls_static_1m` — TLS 1.3 static 1 MiB file | **50.9%** ⚠ (50–52) | **95.3%** (94–96) | 2.9 k → 1.5 k | 168 ms → 324 ms | 318 ms → 704 ms |
| `tls_proxy_hello` — TLS 1.3 termination in front of proxy_pass | **120.0%** (118–122) | **102.2%** (102–103) | 90.2 k → 107.9 k | 5.32 ms → 4.39 ms | 11.77 ms → 11.76 ms |
| `proxy_ext_hello` — proxy to external nginx backend, upstream keep-alive | **106.4%** (105–108) | **107.4%** (99–115) | 134.0 k → 141.5 k | 3.64 ms → 3.40 ms | 8.88 ms → 8.16 ms |
| `proxy_ext_no_keepalive` — proxy to external nginx backend, new upstream connection per request | **108.9%** (107–110) | **109.5%** (104–114) | 59.5 k → 64.8 k | 8.06 ms → 7.34 ms | 23.09 ms → 22.16 ms |
| `proxy_ext_64k` — proxy to external nginx backend, 64 KiB response | **52.3%** ⚠ (52–53) | **97.2%** (90–106) | 39.3 k → 20.5 k | 12.57 ms → 23.01 ms | 25.81 ms → 58.20 ms |
| `proxy_ext_1m` — proxy to external nginx backend, 1 MiB response | **35.8%** ⚠ (35–37) | **55.1%** ⚠ (54–56) | 3.3 k → 1.2 k | 153 ms → 424 ms | 279 ms → 662 ms |
| `proxy_ext_post_1k` — POST 1 KiB through proxy to external nginx backend | **106.7%** (105–108) | **116.5%** (104–136) | 114.2 k → 122.0 k | 4.30 ms → 4.00 ms | 9.63 ms → 9.00 ms |
| `proxy_ext_post_64k` — POST 64 KiB through proxy to external nginx backend | **55.4%** ⚠ (55–56) | **93.7%** ⚠ (93–94) | 25.0 k → 13.8 k | 19.62 ms → 34.52 ms | 40.46 ms → 74.68 ms |
| `proxy_ext_xar` — X-Accel-Redirect from external nginx backend to an internal 1 KiB file | **15.7%** ⚠ (15–16) | **7.1%** ⚠ (7–8) | 100.4 k → 15.8 k | 4.88 ms → 20.98 ms | 11.44 ms → 157 ms |


## Experiments behind the issues

**Worker count** (i9 with `worker_processes 8` instead of 32, same ABBA method):

| scenario | 32 workers | 8 workers |
|---|---:|---:|
| `autoindex_100` | 39.9% | 73.9% |
| `regex_locations_50` | 67.9% | 71.0% |
| `vhost_regex_20` | 74.5% | 75.7% |
| control: `prefix_locations_200` | 96.6% | 107.9% |

autoindex recovers far more than the control: a process-wide lock (#250). The regex scenarios recover less than the control, so they are limited by the per-match cost, not by contention (#248).

**Proxy without upstream keep-alive, frontend × backend in separate processes** (i7, `bench/proxy_ext` `/direct` in front of `bench/proxy_ext/backend.conf`, 4 alternating rounds of `wrk -t16 -c512 -d10s`):

| frontend → backend | req/s | p99 |
|---|---:|---:|
| nginx → nginx | 58.6–60.7 k | 22–24 ms |
| ruxen → nginx | 63.2–64.4 k | 22 ms |
| nginx → ruxen | 54.9–55.0 k | 30–34 ms |
| ruxen → ruxen | 58.7–59.3 k | 23–26 ms |

As a proxy, ruxen is faster than nginx. As a backend that accepts a connection per request, it is slower (#128). Only proxying inside one instance is far behind (#249).

**The X-Accel-Redirect fix** (#251, i7, 8 pairs, against the 0.1.2 build): `proxy_ext_xar` 667.4%, `proxy_xar` 686.5%, and the controls `proxy_hello` 100.1% and `proxy_ext_hello` 100.4%. Against nginx, `proxy_ext_xar` moves from 15.7% to 105.3%.

## Caveats

- **Client and server share each machine** over loopback. wrk takes CPU from the server, and on the no-keep-alive and handshake scenarios it is part of the bottleneck. Ratios there understate per-request cost differences in both directions.
- **Response bodies that differ:** for 301/302 responses (`redirect_301`, `proxy_redirect_302`) nginx sends its 150–180-byte HTML page and ruxen a 32-byte one (#34). `autoindex_100` bodies differ slightly in size, and nginx sends them chunked. Everything else was checked identical in status, body size and header names.
- **Access logs** are written to `/dev/null`: formatting and the `write` per request are measured, disk I/O is not.
- **In-process backends:** in `proxy_*` scenarios (except `proxy_ext_*`) the upstream is a server block of the server under test, so the number includes that server as a backend. `proxy_ext_*` measures the proxy alone.
- **`m19_stream_128m`** hits wrk's 2 s timeout (128 MiB per response at 64 connections). On the i7 that happened about 750 times per server over 8 runs, equally on both sides; on the i9 13 times for nginx and never for ruxen. Its ratio is indicative. No other scenario had a single error or timeout.
- **The i9** ran with the desktop session open (idle at night) and the `powersave` governor (intel_pstate, dynamic). Its calibration shows one wild pair; single scenarios with a wide min–max spread should be read with care.
- **CPU per request** (`bench/scripts/cpu_per_request.sh`) was tried for the no-keep-alive scenarios, but leftover nginx masters spoiled the repeat rounds. Only the first round is quoted in #128.

## Reproducing

Scenarios and configs: `bench/scenarios/manifest.tsv`, `bench/<dir>/nginx.conf` (the campaign's configs are generated by `bench/scripts/gen_campaign_configs.py`). Fixtures: `bench/scripts/prepare_fixtures.sh` and `bench/<dir>/generate.sh`. Then, from the repository root:

```bash
bench/scripts/pair.sh <scenario> --pairs 8 --b-bin path/to/ruxen      # ruxen vs nginx
```

For the `proxy_ext_*` scenarios, start the backend first: `nginx -p "$PWD/bench/proxy_ext/" -c "$PWD/bench/proxy_ext/backend.conf"`. The raw results of this run, one line per scenario and machine, are in `bench/campaign-0.1.2/results-i7.tsv` and `results-i9.tsv`.
