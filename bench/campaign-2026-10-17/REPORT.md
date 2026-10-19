# ruxen 0.2.0 candidate `c45ade2` vs nginx 1.24: performance campaign, 2026-10-16/17

The campaign of 2026-10-13/14 (`bench/campaign-2026-10-14/REPORT.md`, label `c015`) repeated on the 0.2.0 release candidate `c45ade2` (main of 2026-10-16 evening, label `c017`). Same method: ABBA pairs with `bench/scripts/pair.sh`, ruxen and nginx 1.24.0 loading the same file, `wrk -t16 -c512` unless the scenario says otherwise. 94 scenarios on the i7 (12 more than c015: HTTP/2, HTTPS upstreams, 4096 connections, the external-backend proxy rows), 92 on the i9. The columns compare each ratio with c015.

## Differences from the c015 run

- i7 laptop: 8 pairs per scenario, 2026-10-16 23:30 → 2026-10-17 08:58 (results-i7.tsv). **The laptop was reinstalled with Ubuntu 26.04 between the two runs.** A check of the same code on both sides (c016d, 2026-10-16) gave `proxy_post_64k` 100.6% against itself, so its drop against c015 below (and the `proxy_ext_*` rows, whose backend nginx runs on the same machine) comes with the new system, not with ruxen.
- i9: 6 pairs per scenario, 2026-10-17 06:21 → 13:36, after the fuzz night (results-i9.tsv). `m1_hello_c4096` and `static_8k_c4096` didn't run there (`ulimit -n` wasn't raised for wrk).
- c015's i9 rows that measured 404s (no generated content in that worktree; left out of its report too) are left out of the comparison: `bench/static2`, `access_log_static_1k`, `proxy_64k`, `proxy_1m`, `proxy_xar`, `tls_static_1k`, `tls_static_1m`.

## Noise floor

| calibration | i7 laptop | i9 |
|---|---:|---:|
| ruxen vs a copy of itself, `m1_hello` (start) | 100.2% (100–101) | 99.8% (99–102) |
| ruxen vs a copy of itself, `proxy_hello` (start) | 99.7% (99–100) | 99.9% (99–101) |
| ruxen vs a copy of itself, `m1_hello` (end) | 100.2% (99–101) | 99.7% (99–101) |
| ruxen vs a copy of itself, `proxy_hello` (end) | 100.0% (100–100) | 100.0% (99–101) |

## Summary

| | i7 | i9 |
|---|---:|---:|
| scenarios | 94 | 92 |
| ruxen ≥ 95% of nginx | 85 | 82 |
| ruxen ≥ 100% of nginx | 78 | 56 |
| median ruxen / nginx | 120.2% | 102.0% |
| clearly better than c015 | 51 | 44 |
| clearly worse than c015 | 5 | 0 |

- **Large responses** (#247, fixed by writing each chunk as soon as it is read: #469, #471, #472): on the 6-core i7 `static_1m_sendfile_off` 65% → **104%**, `m19_stream_1m` 66% → **103%**, `tls_static_1m` 53% → **94%**; on the i9 112%, 111% and 118%. `proxy_1m` 89% → 93% (i7), 134% (i9).
- **HTTP/2** for the first time in a campaign: `h2c_hello` 171% / 116%, `h2_tls_hello` 152% / 110%, `h2c_static_8k` 111% / 81%.
- **HTTPS upstreams** (#116): `proxy_https_hello` 143% / 115%, `tls_proxy_hello` 128% / 105%.
- `m1_hello` 123% (i7, +3.7) and 102% (i9, +2.7); `proxy_hello` 121% / 98%.
- Still under 95%, with issues:
  - `proxy_64k` 75% (i7) / 78% (i9) and `proxy_ext_64k` 77% (i7): a relayed 64 KiB body was read whole with the header and copied, fixed after the campaign by #538 (`proxy_64k` +35%, 101% of nginx on the i7);
  - a 64 KiB / 2 MiB POST through `proxy_pass` on the i7 (69% / 64%, #289); `proxy_post_2m` gained 14% since with #537;
  - `proxy_no_upstream_keepalive` 77% / 22% (#249);
  - `m1_hello_c4096` 85% on the i7 (#467);
  - 1 MiB over TLS and from an upstream on the i7, 93–94% (#545);
  - on the i9 only, without an open issue: `h2c_static_8k` 81% (111% on the i7), a new connection per request for a proxied or static response (`proxy_client_no_keepalive` 88%, `m3_static_1k_no_keepalive` 92%; #128 is closed, the i7 is at 95–99% now), `proxy_xar` / `proxy_ext_xar` 92%, `m19_stream_1m_low_concurrency` 94% (93% in c015, part of #545), `set_if` 94%.

## After the campaign

Merged into main after `c45ade2`, each measured against its base on the i7 (ABBA) before it merged: #537 (request bodies past `client_body_buffer_size`: `proxy_post_2m` 113.8%, the rest 99.5–100.0%), #538 (relay buffers: `proxy_64k` 135.4%, `proxy_ext_64k` 145.3%, `proxy_1m` 103.2%, `proxy_hello` 100.0%), the security fixes #539, #540 (`proxy_hello` 99.3%), #542, #544, and the reliability fixes #546–#550 (99.7–100.1%).

The release builds against the campaign's candidate, ABBA on the i7:

| scenario | `rc2` 7b51237 / `c45ade2` (8 pairs) | `rc3` fc9ba99 / `rc2` (6 pairs) |
|---|---:|---:|
| `m1_hello` | 99.9% (100–100) | 100.2% (100–101) |
| `proxy_hello` | 99.6% (99–100) | 100.4% (99–101) |
| `static_8k` | 99.6% (99–100) | 100.0% (99–101) |
| `tls_hello` | 100.1% (99–102) | 100.2% (99–101) |
| `h2c_hello` | 100.5% (100–101) | — |
| `proxy_64k` | 135.3% (133–137) | — |

So the tables above hold for 0.2.0 (`fc9ba99`), with `proxy_64k` / `proxy_ext_64k` about 35–45% higher than measured here (101% of nginx on the i7).

## epoll driver against nginx (`RUXEN_DRIVER=epoll`, #337)

| scenario | i7 | i9 |
|---|---:|---:|
| `m1_hello` | 98.5% (97–100) | 101.0% (100–102) |
| `m1_no_keepalive` | 96.8% (96–97) | 95.3% (94–96) |
| `m3_static_1k` | 108.5% (107–110) | 104.9% (103–106) |
| `static_8k` | 106.1% (105–107) | 103.1% (102–103) |
| `proxy_hello` | 93.9% (93–95) | 96.5% (96–97) |
| `proxy_no_upstream_keepalive` | 91.9% (91–92) | 91.6% (91–93) |
| `tls_hello` | 122.0% (120–124) | 110.0% (108–111) |
| `tls13_handshake` | 125.9% (121–131) | 107.0% (102–110) |

## All scenarios

| scenario | i7 | vs c015 | i9 | vs c015 |
|---|---:|---:|---:|---:|
| `m1_hello` | 122.8% (122–124) | +3.7 ↑ | 102.3% (100–105) | +2.7 ↑ |
| `m1_no_keepalive` | 95.7% (95–96) | +1.0 | 95.3% (94–97) | +1.6 |
| `m1_keepalive_requests_1` | 95.7% (95–96) | +1.0 ↑ | 95.7% (95–97) | +1.5 ↑ |
| `m3_static_1k` | 146.2% (144–148) | +7.2 ↑ | 105.9% (105–107) | +1.0 |
| `m3_static_1k_low_concurrency` | 117.7% (114–124) | +5.1 | 105.0% (103–106) | +4.3 |
| `m3_static_1k_no_keepalive` | 95.2% (95–96) | +1.6 ↑ | 91.7% (90–93) | +2.8 ↑ |
| `m5_conditional_304` | 131.3% (130–133) | +8.8 ↑ | 99.9% (99–101) | +3.9 ↑ |
| `m5_if_modified_since_304` | 131.1% (130–132) | +9.3 ↑ | 99.4% (98–100) | +4.9 ↑ |
| `m5_range_206` | 148.4% (146–150) | +8.8 ↑ | 107.9% (107–108) | +1.5 ↑ |
| `m5_range_open_ended_206` | 148.7% (147–150) | +9.1 ↑ | 108.0% (107–108) | +1.9 ↑ |
| `m5_range_suffix_206` | 148.6% (146–150) | +8.5 ↑ | 107.6% (107–109) | +1.8 |
| `m19_stream_1m` | 103.2% (102–105) | +37.5 ↑ | 111.3% (110–112) | +10.9 ↑ |
| `m19_stream_1m_low_concurrency` | 98.4% (97–100) | +1.5 | 93.6% (90–96) | +0.4 |
| `m19_stream_128m` | 99.6% (96–104) | +0.6 | 102.5% (102–104) | +4.7 ↑ |
| `static_8k` | 113.9% (112–115) | +4.1 ↑ | 101.8% (101–102) | +1.3 ↑ |
| `add_header_many` | 120.3% (119–122) | +4.2 ↑ | 103.9% (103–105) | +2.8 ↑ |
| `auth_basic_hello` | 151.1% (150–153) | +5.6 ↑ | 114.8% (113–116) | +6.7 ↑ |
| `error_page_intercept` | 130.8% (130–133) | +4.8 ↑ | 103.3% (102–105) | +2.5 ↑ |
| `rewrite_hello` | 127.8% (126–129) | +3.7 ↑ | 101.1% (100–102) | +3.5 ↑ |
| `vars_map` | 125.8% (124–128) | +4.9 | 99.0% (98–100) | +3.3 ↑ |
| `proxy_hello` | 121.4% (120–122) | +0.7 | 98.2% (97–100) | +0.6 |
| `tls_hello` | 141.4% (140–143) | +4.7 ↑ | 110.8% (109–113) | -2.0 |
| `m1_hello_c1` | 108.1% (100–132) | +6.2 | 98.6% (98–99) | +2.7 ↑ |
| `m1_hello_c4096` | 85.4% (84–87) |  | — |  |
| `static_8k_c4096` | 113.1% (113–114) |  | — |  |
| `proxy_hello_c32` | 101.3% (98–106) | +2.1 | 105.0% (98–108) | +0.7 |
| `proxy_cache_hit` | 135.1% (134–136) | -0.6 | 109.4% (108–110) | -0.7 |
| `proxy_cache_miss` | 135.1% (134–136) | -1.2 | 109.0% (108–109) | -1.2 |
| `tls_hello_c32` | 104.1% (101–109) | +2.7 | 114.2% (110–118) | +9.2 |
| `redirect_301` | 120.0% (119–121) | +4.2 ↑ | 100.0% (99–101) | +2.4 ↑ |
| `vars_render` | 119.5% (118–120) | +2.1 | 99.3% (99–100) | +2.1 ↑ |
| `args_render` | 118.6% (118–120) | +2.6 ↑ | 99.1% (98–100) | +2.8 ↑ |
| `set_if` | 119.2% (118–121) | +3.5 ↑ | 94.1% (93–95) | +2.7 ↑ |
| `split_clients` | 118.0% (116–120) | +3.0 | 98.4% (97–100) | +2.5 ↑ |
| `map_regex_50` | 185.1% (184–186) | +11.3 ↑ | 127.3% (126–129) | +3.6 ↑ |
| `add_header_vars` | 113.9% (113–116) | +2.5 ↑ | 96.8% (96–97) | +3.0 ↑ |
| `rewrite_captures` | 123.8% (123–124) | +2.4 | 97.0% (96–98) | +3.5 ↑ |
| `error_page_named` | 123.1% (122–125) | +2.7 ↑ | 102.5% (101–103) | +2.8 ↑ |
| `many_request_headers` | 129.9% (129–131) | +11.1 ↑ | 103.1% (102–104) | +8.6 ↑ |
| `regex_locations_50` | 183.4% (181–185) | +6.9 ↑ | 126.9% (126–128) | +4.5 ↑ |
| `prefix_locations_200` | 118.6% (118–120) | +4.3 ↑ | 99.2% (98–100) | +3.2 ↑ |
| `vhost_exact_100` | 122.5% (122–124) | +6.8 ↑ | 102.4% (101–103) | +3.0 ↑ |
| `vhost_wildcard_50` | 115.6% (114–118) | +3.8 ↑ | 98.5% (98–99) | +3.0 ↑ |
| `vhost_regex_20` | 137.8% (136–141) | +6.5 ↑ | 96.6% (96–97) | +3.2 ↑ |
| `static_0b` | 132.4% (132–133) | +5.1 ↑ | 101.7% (101–102) |  |
| `static_16k` | 111.8% (111–113) | +3.9 ↑ | 100.2% (100–101) |  |
| `static_64k` | 106.8% (107–107) | +2.1 ↑ | 100.3% (100–100) |  |
| `static_256k` | 99.5% (99–100) | +0.8 | 101.5% (101–102) |  |
| `static_1k_sendfile_off` | 130.9% (126–133) | +6.6 | 100.9% (100–102) |  |
| `static_1m_sendfile_off` | 103.8% (102–106) | +38.4 ↑ | 112.0% (111–113) |  |
| `static_index` | 135.4% (134–137) | +5.5 ↑ | 102.8% (102–103) |  |
| `try_files_hit` | 144.6% (144–145) | +7.4 ↑ | 107.8% (107–109) |  |
| `try_files_fallback` | 143.1% (142–144) | +6.2 ↑ | 107.7% (107–109) |  |
| `alias_1k` | 146.3% (145–148) | +7.3 ↑ | 108.6% (108–109) |  |
| `expires_1k` | 131.1% (130–132) | +5.2 ↑ | 97.7% (97–99) |  |
| `autoindex_100` | 106.9% (105–108) | +1.3 | 99.9% (98–101) |  |
| `access_log_hello` | 120.1% (120–121) | +3.9 ↑ | 95.8% (95–96) | +2.1 ↑ |
| `access_log_static_1k` | 140.1% (138–141) | +6.8 ↑ | 103.0% (102–104) |  |
| `post_1k_return` | 137.2% (136–138) | +5.5 ↑ | 105.9% (105–107) | +4.1 ↑ |
| `proxy_post_1k` | 119.2% (118–120) | +0.6 | 101.3% (101–102) | +2.7 ↑ |
| `proxy_post_64k` | 69.2% (69–70) | -9.3 ↓ | 256.6% (256–258) | -0.5 |
| `proxy_post_2m` | 63.5% (62–64) |  | 89.4% (87–91) |  |
| `proxy_no_upstream_keepalive` | 76.5% (74–79) | -0.3 | 22.2% (22–23) | +0.4 |
| `proxy_rr4` | 121.2% (120–122) | +1.4 | 97.0% (96–99) | +1.8 ↑ |
| `proxy_least_conn4` | 121.3% (120–122) | +1.4 | 97.1% (97–98) | +0.8 ↑ |
| `proxy_hash4` | 121.9% (121–123) | +1.6 | 98.1% (97–99) | +1.5 ↑ |
| `proxy_ip_hash4` | 121.1% (121–122) | +1.1 ↑ | 97.8% (97–98) | +1.4 ↑ |
| `proxy_headers_vars` | 120.8% (120–122) | +1.6 | 96.8% (96–98) | +2.2 ↑ |
| `proxy_64k` | 75.3% (74–76) | +3.1 ↑ | 78.0% (78–78) |  |
| `proxy_1m` | 92.9% (91–94) | +3.9 ↑ | 134.1% (133–135) |  |
| `proxy_intercept` | 870.5% (867–876) | +16.7 ↑ | 2589.6% (2538–2662) | -17.7 |
| `proxy_redirect_302` | 118.5% (118–119) | +0.1 | 96.1% (96–96) | +0.5 |
| `proxy_xar` | 114.0% (113–114) | +1.9 ↑ | 92.0% (91–93) |  |
| `proxy_client_no_keepalive` | 98.7% (98–99) | +0.8 | 87.7% (87–89) | +2.7 ↑ |
| `tls12_hello` | 140.5% (137–142) | +5.1 | 109.2% (108–111) | -2.9 |
| `tls13_handshake` | 124.8% (121–128) | +2.9 | 101.6% (97–106) | -4.8 |
| `tls12_handshake` | 108.6% (106–110) | -1.8 | 105.9% (106–106) | +2.3 ↑ |
| `tls13_rsa_handshake` | 125.5% (122–131) | +2.2 | 107.4% (101–115) | -1.1 |
| `tls_static_1k` | 137.6% (137–139) | +6.1 ↑ | 114.1% (113–115) |  |
| `tls_static_1m` | 94.1% (89–100) | +41.3 ↑ | 117.9% (117–118) |  |
| `tls_proxy_hello` | 128.1% (127–130) | +2.1 ↑ | 104.7% (104–105) | +2.2 ↑ |
| `proxy_https_hello` | 143.4% (143–145) |  | 114.8% (114–116) |  |
| `proxy_ext_hello` | 109.1% (108–110) | -12.6 ↓ | 106.3% (94–116) | -3.1 |
| `proxy_ext_no_keepalive` | 109.6% (109–110) | -7.4 ↓ | 109.6% (105–113) | +1.5 |
| `proxy_ext_64k` | 76.9% (76–77) | +12.7 ↑ | 95.2% (91–99) | -0.9 |
| `proxy_ext_1m` | 93.0% (91–94) | -1.1 | 152.4% (151–154) | +9.6 ↑ |
| `proxy_ext_post_1k` | 109.5% (108–111) | -12.2 ↓ | 110.5% (100–122) | -1.6 |
| `proxy_ext_post_64k` | 110.7% (110–112) | +9.1 ↑ | 189.5% (183–195) | +2.1 |
| `proxy_ext_xar` | 109.2% (108–110) | -5.6 ↓ | 92.1% (84–106) | -0.1 |
| `gzip_html_8k` | 113.2% (112–114) | +0.8 | 98.2% (98–99) | +2.1 ↑ |
| `limit_req_static_1k` | 142.3% (141–144) | +7.0 ↑ | 103.0% (102–104) | +0.8 |
| `h2c_hello` | 171.1% (168–174) |  | 115.8% (113–117) |  |
| `h2c_static_8k` | 110.5% (110–111) |  | 80.7% (80–82) |  |
| `h2_tls_hello` | 151.9% (148–155) |  | 109.7% (108–111) |  |
