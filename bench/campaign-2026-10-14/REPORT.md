# ruxen main `fce8fa2` vs nginx 1.24: performance campaign, 2026-10-13/14

The 0.1.2 campaign (`bench/campaign-0.1.2/REPORT.md`) repeated a week later on main `fce8fa2` (2026-10-13, before that evening's merges). Same scenarios, configurations and method: ABBA pairs with `bench/scripts/pair.sh`, ruxen and nginx 1.24.0 loading the same file, `wrk -t16 -c512` unless the scenario says otherwise. The columns compare each ratio with the 0.1.2 campaign.

## Differences from the 0.1.2 run

- i7 laptop: 8 pairs per scenario, as before (results-i7.tsv, label `c015`).
- i9: 6 pairs per scenario. The first run of the night failed (`pair.sh` wanted a ruxen binary in the checkout for the nginx side, fixed in #378), and the rerun had to finish before morning (results-i9.tsv; the failed run is kept in results-i9-first-run.tsv).
- The i9 ran from a bare worktree in which the scenarios' `generate.sh` had not run. Scenarios that serve generated files measured two 404s there. Those 18 i9 rows are left out below: all of `bench/static2`, `access_log_static_1k`, `proxy_64k`, `proxy_1m`, `proxy_xar`, `tls_static_1k`, `tls_static_1m`. They rerun with the content in place on a later night. The laptop checkout had the content; its rows are valid.

## Noise floor

| calibration | i7 laptop | i9 |
|---|---:|---:|
| ruxen vs a copy of itself, `m1_hello` (start / end of the night) | 100.2% (99.6–100.6) / 100.0% (99.8–100.3) | 99.9% (99.5–100.2) / 100.1% (99.8–100.6) |
| ruxen vs a copy of itself, `proxy_hello` (start / end) | 100.1% (99.7–100.9) / 100.1% (99.0–100.7) | 99.9% (99.4–100.4) |

Much quieter than the 0.1.2 night. A change counts as clear (↑ / ↓) when the new min–max range lies wholly above or below the old one.

## Summary

| | i7 | i9 (valid rows) |
|---|---:|---:|
| scenarios | 87 | 71 |
| ruxen ≥ 95% of nginx | 75 | 56 |
| ruxen ≥ 100% of nginx | 70 | 31 |
| median ruxen / nginx | 118.8% | 97.8% |
| clearly better than 0.1.2 | 58 | 20 |
| clearly worse than 0.1.2 | 0 | 2 (`m1_hello_c4096` −2.2, `tls12_handshake` −1.0) |

- The week's proxy work shows up most: `proxy_xar` 15% → 112% (i7), `proxy_ext_xar` 16% → 115%, `proxy_1m` 34% → 89%, `proxy_ext_1m` 36% → 94% (i7) and 55% → 143% (i9), `proxy_ext_post_64k` 55% → 102% (i7) / 94% → 187% (i9), `proxy_post_64k` 38% → 79% (i7) / 52% → 257% (i9). These come from #245 (keep the upstream after X-Accel-Redirect), #246 (request bodies in memory) and #88 (relayed response bodies).
- Regex matching on the i9 (#248): `regex_locations_50` 68% → 122%, `map_regex_50` 84% → 124%, `vhost_regex_20` 75% → 93%.
- `autoindex_100` (#250): 76% → 106% (i7).
- `m1_hello` on the i7 is 119% of nginx (+5.7), `proxy_hello` 121% (+9.5).
- Still under 95%, with issues: a new connection per request (`*_no_keepalive`, 89–95%, #128); 1 MiB responses on the 6-core laptop (`m19_stream_1m` 66%, `static_1m_sendfile_off` 65%, `tls_static_1m` 53%, #247); `proxy_no_upstream_keepalive` (77% i7, 22% i9, #249); `proxy_64k` 72% and `proxy_ext_64k` 64% on the i7 (#88); a few variable-heavy scenarios at 91–95% on the i9 (`set_if`, `add_header_vars`, `rewrite_captures`).

## epoll driver against nginx (`RUXEN_DRIVER=epoll`, #337)

| scenario | i7 | i9 |
|---|---:|---:|
| `m1_hello` | 93.7% (92–95) | 97.5% (97–98) |
| `m1_no_keepalive` | 95.7% (95–96) | 95.9% (95–97) |
| `m3_static_1k` | 103.7% (103–105) | 103.6% (103–104) |
| `static_8k` | 103.2% (102–105) | — |
| `proxy_hello` | 92.4% (91–93) | 93.9% (94–95) |
| `proxy_no_upstream_keepalive` | 91.1% (90–92) | — |
| `tls_hello` | 115.0% (113–116) | 110.8% (110–111) |
| `tls13_handshake` | 121.3% (118–123) | — |

Keep-alive `m1_hello` and `proxy_hello` stay under 95% on epoll (#337); static files and TLS are above nginx.

## All scenarios

| scenario | i7 | vs 0.1.2 | i9 | vs 0.1.2 |
|---|---:|---:|---:|---:|
| `m1_hello` | 119.1% (118–120) | +5.7 ↑ | 99.6% (99–100) | +0.3 |
| `m1_no_keepalive` | 94.7% (94–95) | +1.3 | 93.7% (92–95) | -0.7 |
| `m1_keepalive_requests_1` | 94.7% (94–95) | +1.5 | 94.2% (94–94) | -0.3 |
| `m3_static_1k` | 139.0% (138–140) | +6.5 ↑ | 104.9% (105–105) | +1.7 ↑ |
| `m3_static_1k_low_concurrency` | 112.6% (106–119) | +7.3 | 100.7% (90–105) | +1.1 |
| `m3_static_1k_no_keepalive` | 93.6% (93–94) | +2.2 ↑ | 88.9% (88–90) | -1.6 |
| `m5_conditional_304` | 122.5% (121–124) | +4.8 ↑ | 96.0% (94–97) | -0.2 |
| `m5_if_modified_since_304` | 121.8% (120–124) | +3.8 ↑ | 94.5% (94–96) | -1.4 |
| `m5_range_206` | 139.6% (139–141) | +4.4 ↑ | 106.4% (106–107) | +1.9 ↑ |
| `m5_range_open_ended_206` | 139.6% (138–141) | +4.6 ↑ | 106.1% (106–107) | +1.8 ↑ |
| `m5_range_suffix_206` | 140.1% (139–141) | +6.1 ↑ | 105.8% (105–107) | +1.3 |
| `m19_stream_1m` | 65.7% (64–67) | +1.2 | 100.4% (100–101) | -0.8 |
| `m19_stream_1m_low_concurrency` | 96.9% (94–98) | +2.0 | 93.2% (90–97) | +0.1 |
| `m19_stream_128m` | 99.0% (94–105) | +0.8 | 97.8% (97–99) | +1.5 |
| `static_8k` | 109.8% (109–111) | -0.6 | 100.5% (100–101) | +0.6 |
| `add_header_many` | 116.1% (115–118) | +3.9 ↑ | 101.1% (100–102) | +0.2 |
| `auth_basic_hello` | 145.5% (145–146) | +3.8 ↑ | 108.1% (107–109) | +2.7 ↑ |
| `error_page_intercept` | 126.0% (125–128) | +5.6 ↑ | 100.8% (100–101) | +0.1 |
| `rewrite_hello` | 124.1% (123–126) | +6.6 ↑ | 97.6% (97–98) | -0.6 |
| `vars_map` | 120.9% (119–125) | +5.0 ↑ | 95.7% (95–96) | -0.3 |
| `proxy_hello` | 120.7% (120–122) | +9.5 ↑ | 97.6% (97–98) | +1.4 ↑ |
| `tls_hello` | 136.7% (136–139) | +1.7 | 112.8% (112–114) | +3.2 ↑ |
| `m1_hello_c1` | 101.9% (91–116) | +2.9 | 95.9% (96–96) | +3.4 ↑ |
| `m1_hello_c4096` | — |  | 95.0% (94–95) | -2.2 ↓ |
| `static_8k_c4096` | — |  | 96.4% (96–97) | -0.8 |
| `proxy_hello_c32` | 99.2% (97–100) | +3.8 | 104.3% (102–105) | +0.6 |
| `proxy_cache_hit` | 135.7% (133–138) |  | 110.1% (110–110) |  |
| `proxy_cache_miss` | 136.3% (135–137) |  | 110.2% (109–111) |  |
| `tls_hello_c32` | 101.4% (98–104) | +0.1 | 105.0% (100–114) | -2.3 |
| `redirect_301` | 115.8% (114–118) | +6.4 ↑ | 97.6% (97–98) | +0.5 |
| `vars_render` | 117.4% (116–118) | +5.7 ↑ | 97.2% (97–98) | +0.5 |
| `args_render` | 116.0% (115–117) | +4.4 ↑ | 96.3% (95–97) | +0.0 |
| `set_if` | 115.7% (114–116) | +8.1 ↑ | 91.4% (91–92) | -0.1 |
| `split_clients` | 115.0% (114–117) | +6.6 ↑ | 95.9% (96–96) | +0.4 |
| `map_regex_50` | 173.8% (172–175) | +45.6 ↑ | 123.7% (123–124) | +39.6 ↑ |
| `add_header_vars` | 111.4% (110–112) | +7.1 ↑ | 93.8% (93–94) | +0.3 |
| `rewrite_captures` | 121.4% (120–124) | +5.7 ↑ | 93.5% (93–94) | +0.7 |
| `error_page_named` | 120.4% (120–122) | +5.8 ↑ | 99.7% (99–100) | +0.6 |
| `many_request_headers` | 118.8% (118–120) | +7.1 ↑ | 94.5% (94–95) | +0.2 |
| `regex_locations_50` | 176.5% (175–180) | +70.3 ↑ | 122.4% (121–124) | +54.5 ↑ |
| `prefix_locations_200` | 114.3% (112–117) | +6.2 ↑ | 96.0% (96–97) | -0.6 |
| `vhost_exact_100` | 115.7% (115–116) | +10.2 ↑ | 99.4% (99–100) | +3.5 ↑ |
| `vhost_wildcard_50` | 111.8% (110–113) | +7.2 ↑ | 95.5% (95–96) | +2.0 ↑ |
| `vhost_regex_20` | 131.3% (130–134) | +28.6 ↑ | 93.4% (93–94) | +18.9 ↑ |
| `static_0b` | 127.3% (126–129) | +4.2 ↑ | (not valid, see below) |  |
| `static_16k` | 107.9% (107–109) | +0.3 | (not valid, see below) |  |
| `static_64k` | 104.7% (104–106) | +0.1 | (not valid, see below) |  |
| `static_256k` | 98.7% (98–99) | -0.4 | (not valid, see below) |  |
| `static_1k_sendfile_off` | 124.3% (123–126) | +3.8 | (not valid, see below) |  |
| `static_1m_sendfile_off` | 65.4% (64–66) | -0.2 | (not valid, see below) |  |
| `static_index` | 129.9% (128–131) | +4.8 ↑ | (not valid, see below) |  |
| `try_files_hit` | 137.2% (135–138) | +5.0 ↑ | (not valid, see below) |  |
| `try_files_fallback` | 136.9% (136–138) | +4.1 | (not valid, see below) |  |
| `alias_1k` | 139.0% (138–140) | +6.1 ↑ | (not valid, see below) |  |
| `expires_1k` | 125.9% (125–127) | +6.0 ↑ | (not valid, see below) |  |
| `autoindex_100` | 105.6% (105–106) | +29.9 ↑ | (not valid, see below) |  |
| `access_log_hello` | 116.2% (115–119) | +4.6 ↑ | 93.7% (93–94) | +0.0 |
| `access_log_static_1k` | 133.3% (132–135) | +3.4 ↑ | (not valid, see below) |  |
| `post_1k_return` | 131.7% (130–133) | +8.2 ↑ | 101.8% (101–103) | +1.7 |
| `proxy_post_1k` | 118.6% (118–120) | +12.8 ↑ | 98.6% (98–99) | +2.3 ↑ |
| `proxy_post_64k` | 78.5% (78–79) | +40.1 ↑ | 257.1% (256–258) | +205.6 ↑ |
| `proxy_no_upstream_keepalive` | 76.8% (74–84) | +9.5 ↑ | 21.8% (22–22) | +0.6 |
| `proxy_rr4` | 119.8% (119–121) | +9.4 ↑ | 95.2% (95–96) | +1.0 |
| `proxy_least_conn4` | 119.9% (118–121) | +9.8 ↑ | 96.3% (96–96) | +1.4 ↑ |
| `proxy_hash4` | 120.3% (120–121) |  | 96.6% (96–97) |  |
| `proxy_ip_hash4` | 120.0% (120–120) |  | 96.4% (96–97) |  |
| `proxy_headers_vars` | 119.2% (118–120) | +9.3 ↑ | 94.6% (94–95) | +1.0 |
| `proxy_64k` | 72.2% (71–73) | +19.0 ↑ | (not valid, see below) |  |
| `proxy_1m` | 89.0% (88–90) | +55.2 ↑ | (not valid, see below) |  |
| `proxy_intercept` | 853.8% (850–859) | +7.5 | 2607.3% (2580–2639) | +105.1 ↑ |
| `proxy_redirect_302` | 118.4% (118–119) | +9.5 ↑ | 95.6% (95–96) | +1.7 ↑ |
| `proxy_xar` | 112.1% (112–113) | +96.9 ↑ | (not valid, see below) |  |
| `proxy_client_no_keepalive` | 97.9% (97–99) | +4.7 ↑ | 85.0% (82–87) | +0.7 |
| `tls12_hello` | 135.4% (133–137) | +2.3 | 112.1% (111–113) | +2.5 |
| `tls13_handshake` | 121.9% (119–126) | -3.2 | 106.4% (99–114) | +2.4 |
| `tls12_handshake` | 110.4% (108–114) | -2.1 | 103.6% (103–104) | -1.0 ↓ |
| `tls13_rsa_handshake` | 123.3% (119–126) | +0.0 | 108.5% (100–115) | +3.7 |
| `tls_static_1k` | 131.5% (130–133) | +1.5 | (not valid, see below) |  |
| `tls_static_1m` | 52.8% (52–54) | +1.9 ↑ | (not valid, see below) |  |
| `tls_proxy_hello` | 126.0% (125–127) | +6.0 ↑ | 102.5% (102–103) | +0.3 |
| `proxy_ext_hello` | 121.7% (121–123) | +15.3 ↑ | 109.4% (98–120) | +2.0 |
| `proxy_ext_no_keepalive` | 117.0% (115–120) | +8.1 ↑ | 108.1% (105–114) | -1.4 |
| `proxy_ext_64k` | 64.2% (64–65) | +11.9 ↑ | 96.1% (91–101) | -1.1 |
| `proxy_ext_1m` | 94.1% (92–97) | +58.3 ↑ | 142.8% (140–146) | +87.7 ↑ |
| `proxy_ext_post_1k` | 121.7% (120–123) | +15.0 ↑ | 112.1% (99–128) | -4.4 |
| `proxy_ext_post_64k` | 101.6% (100–103) | +46.2 ↑ | 187.4% (183–190) | +93.7 ↑ |
| `proxy_ext_xar` | 114.8% (112–116) | +99.1 ↑ | 92.2% (86–100) | +85.1 ↑ |
| `gzip_html_8k` | 112.4% (112–113) |  | 96.1% (96–97) |  |
| `limit_req_static_1k` | 135.3% (134–137) |  | 102.2% (101–103) |  |

## Caveats

- `m1_hello_c4096` on the i7: wrk failed with "unable to create thread 15: Too many open files" (the night shell's file limit), so there is no row. The i9 row is valid.
- The i9 rows left out above are listed under "Differences". Their raw numbers are in results-i9.tsv; they are not ruxen's.
- The h2 scenarios (`h2c_*`, `h2_tls_hello`) are not in this campaign: h2load isn't installed on either machine (#348).
