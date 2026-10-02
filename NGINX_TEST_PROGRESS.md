# nginx-tests Progress (compat profile)

Reproduce: `scripts/run_nginx_tests.sh` (or `--update-progress` to regenerate this file). The script runs every `.t` file sequentially against `target/release/ruxen` and writes per-file logs under `.nginx-tests-out/logs/`. Run files sequentially — running the suite in parallel introduces flakes from shared TLS-session-cache / port races and gives false negatives.

Last run: 2026-10-02 against `nginx-tests` 0b70854 (2026-09-30).

## Summary

- **Total tests tracked:** 505
- **Passing in ruxen:** 52
- **Intentionally skipped (`-V` banner excludes the module):** 401
- **Failing — work in progress:** 52

The three groups below are mutually exclusive and sum to 505.

## Passing in ruxen (52)

Tests where ruxen passes the upstream `Test::Nginx` suite end-to-end (sequential `prove`, `TEST_NGINX_BINARY=$PWD/target/release/ruxen`, `RUXEN_NGINX_IDENTITY=1`).

- `access_log_variables.t`
- `auth_basic.t`
- `auth_delay.t`
- `autoindex_format.t`
- `body.t`
- `body_chunked.t`
- `config_dump.t`
- `headers.t`
- `http_error_page.t`
- `http_expect_100_continue.t`
- `http_header_buffers.t`
- `http_headers_multi.t`
- `http_host.t`
- `http_keepalive.t`
- `http_location.t`
- `http_location_auto.t`
- `http_method.t`
- `http_request_port.t`
- `http_server_name.t`
- `http_try_files.t`
- `http_uri.t`
- `ignore_invalid_headers.t`
- `index.t`
- `map_complex.t`
- `merge_slashes.t`
- `not_modified.t`
- `post_action.t`
- `proxy_available.t`
- `proxy_chunked_extra.t`
- `proxy_intercept_errors.t`
- `proxy_limit_rate.t`
- `proxy_max_temp_file_size.t`
- `proxy_noclose.t`
- `proxy_pass_request.t`
- `proxy_request_buffering_keepalive.t`
- `proxy_upstream_cookie.t`
- `range_if_range.t`
- `rewrite.t`
- `rewrite_if.t`
- `rewrite_unescape.t`
- `server_tokens.t`
- `split_clients.t`
- `ssl_certificate_chain.t`
- `ssl_certificates.t`
- `ssl_curve.t`
- `ssl_sni_sessions.t`
- `trailers.t`
- `upstream.t`
- `upstream_keepalive.t`
- `worker_channel.t`
- `worker_shutdown_timeout.t`
- `worker_shutdown_timeout_proxy_upgrade.t`

## Failing — actively being worked on (52)

Tests that ran (not skipped by `has_module`) but produced at least one failed assertion or non-zero exit. The fraction is **failed subtests / total subtests** (`0/0` means harness died during setup before reaching the plan; `0/N` means subtests passed but the file exited non-zero — typically `-t` config check).

- `http_absolute_redirect.t` — 16/25
- `http_listen.t` — 0/0
- `http_resolver.t` — 0/0
- `http_resolver_cleanup.t` — 1/3
- `http_resolver_cname.t` — 11/13
- `http_variables.t` — 3/9
- `limit_rate.t` — 3/9
- `map.t` — 19/21
- `map_volatile.t` — 0/0
- `proxy.t` — 28/30
- `proxy_bind.t` — 3/7
- `proxy_cookie.t` — 8/11
- `proxy_cookie_flags.t` — 12/16
- `proxy_duplicate_headers.t` — 7/10
- `proxy_if.t` — 15/17
- `proxy_method.t` — 3/6
- `proxy_next_upstream.t` — 2/10
- `proxy_next_upstream_tries.t` — 8/10
- `proxy_non_idempotent.t` — 7/10
- `proxy_protocol2_tlv.t` — 14/16
- `proxy_redirect.t` — 15/17
- `proxy_request_buffering.t` — 2/20
- `proxy_request_buffering_chunked.t` — 3/24
- `proxy_request_buffering_ssl.t` — 18/20
- `proxy_set_body.t` — 2/4
- `proxy_ssl.t` — 8/10
- `proxy_ssl_certificate.t` — 5/7
- `proxy_ssl_certificate_empty.t` — 0/0
- `proxy_ssl_certificate_vars.t` — 0/0
- `proxy_ssl_crl.t` — 5/7
- `proxy_ssl_keepalive.t` — 3/5
- `proxy_ssl_verify.t` — 6/8
- `proxy_ssl_verify_ip.t` — 8/10
- `proxy_unix.t` — 5/7
- `proxy_variables.t` — 2/6
- `proxy_xar.t` — 16/18
- `ssl.t` — 4/23
- `ssl_cache.t` — 4/6
- `ssl_certificate_aux.t` — 0/0
- `ssl_client_escaped_cert.t` — 2/5
- `ssl_crl.t` — 5/7
- `ssl_ocsp.t` — 0/0
- `ssl_password_file.t` — 3/5
- `ssl_proxy_upgrade.t` — 28/32
- `ssl_reject_handshake.t` — 7/9
- `ssl_session_reuse.t` — 2/10
- `ssl_session_ticket_key.t` — 2/4
- `ssl_sni.t` — 1/10
- `ssl_sni_reneg.t` — 8/10
- `ssl_stapling.t` — 10/12
- `ssl_verify_client.t` — 14/16
- `ssl_verify_depth.t` — 9/11

## Intentionally skipped (401)

These test files call `has_module(...)` (or similar guards) that fail against ruxen's pinned `-V` banner — so the entire file is skipped before any subtest runs. They are out of scope for the current compat profile and intentional, not regressions. Grouped below by skip reason; the leading count is the number of test files in that group.

### no stream available (82)

- `stream_access.t`
- `stream_access_log.t`
- `stream_access_log_escape.t`
- `stream_access_log_none.t`
- `stream_error_log.t`
- `stream_geo.t`
- `stream_geo_ipv6.t`
- `stream_geo_unix.t`
- `stream_geoip.t`
- `stream_limit_conn.t`
- `stream_limit_conn_complex.t`
- `stream_limit_conn_dry_run.t`
- `stream_limit_rate.t`
- `stream_limit_rate2.t`
- `stream_map.t`
- `stream_pass.t`
- `stream_proxy.t`
- `stream_proxy_bind.t`
- `stream_proxy_complex.t`
- `stream_proxy_half_close.t`
- `stream_proxy_next_upstream.t`
- `stream_proxy_protocol.t`
- `stream_proxy_protocol2_tlv.t`
- `stream_proxy_protocol_ipv6.t`
- `stream_proxy_protocol_ssl.t`
- `stream_proxy_ssl.t`
- `stream_proxy_ssl_alpn.t`
- `stream_proxy_ssl_certificate.t`
- `stream_proxy_ssl_certificate_cache.t`
- `stream_proxy_ssl_certificate_vars.t`
- `stream_proxy_ssl_conf_command.t`
- `stream_proxy_ssl_name.t`
- `stream_proxy_ssl_name_complex.t`
- `stream_proxy_ssl_verify.t`
- `stream_realip.t`
- `stream_realip_hostname.t`
- `stream_resolver.t`
- `stream_server_name.t`
- `stream_set.t`
- `stream_split_clients.t`
- `stream_ssl.t`
- `stream_ssl_alpn.t`
- `stream_ssl_certificate.t`
- `stream_ssl_certificate_cache.t`
- `stream_ssl_conf_command.t`
- `stream_ssl_ocsp.t`
- `stream_ssl_preread.t`
- `stream_ssl_preread_alpn.t`
- `stream_ssl_preread_protocol.t`
- `stream_ssl_realip.t`
- `stream_ssl_reject_handshake.t`
- `stream_ssl_session_reuse.t`
- `stream_ssl_sni_protocols.t`
- `stream_ssl_stapling.t`
- `stream_ssl_variables.t`
- `stream_ssl_verify_client.t`
- `stream_status_variable.t`
- `stream_tcp_nodelay.t`
- `stream_udp_limit_conn.t`
- `stream_udp_limit_rate.t`
- `stream_udp_proxy.t`
- `stream_udp_proxy_requests.t`
- `stream_udp_stream.t`
- `stream_udp_upstream.t`
- `stream_udp_upstream_hash.t`
- `stream_udp_upstream_least_conn.t`
- `stream_unix.t`
- `stream_upstream.t`
- `stream_upstream_hash.t`
- `stream_upstream_least_conn.t`
- `stream_upstream_least_time.t`
- `stream_upstream_max_conns.t`
- `stream_upstream_random.t`
- `stream_upstream_resolve.t`
- `stream_upstream_resolve_reload.t`
- `stream_upstream_resolver.t`
- `stream_upstream_service.t`
- `stream_upstream_service_reload.t`
- `stream_upstream_zone.t`
- `stream_upstream_zone_ssl.t`
- `stream_variables.t`
- `worker_shutdown_timeout_stream.t`

### no http_v2 available (58)

- `grpc.t`
- `grpc_early_hints.t`
- `grpc_next_upstream.t`
- `grpc_pass.t`
- `grpc_request_buffering.t`
- `grpc_ssl.t`
- `grpc_trailers.t`
- `h2.t`
- `h2_absolute_redirect.t`
- `h2_auth_request.t`
- `h2_error_page.t`
- `h2_fastcgi_request_buffering.t`
- `h2_headers.t`
- `h2_host.t`
- `h2_http2.t`
- `h2_keepalive.t`
- `h2_limit_conn.t`
- `h2_limit_req.t`
- `h2_max_headers.t`
- `h2_priority.t`
- `h2_priority_update.t`
- `h2_proxy_cache.t`
- `h2_proxy_max_temp_file_size.t`
- `h2_proxy_protocol.t`
- `h2_proxy_request_buffering.t`
- `h2_proxy_request_buffering_redirect.t`
- `h2_proxy_request_buffering_ssl.t`
- `h2_proxy_ssl.t`
- `h2_request_body.t`
- `h2_request_body_extra.t`
- `h2_request_body_preread.t`
- `h2_server_tokens.t`
- `h2_ssl.t`
- `h2_ssl_proxy_cache.t`
- `h2_ssl_proxy_protocol.t`
- `h2_ssl_variables.t`
- `h2_ssl_verify_client.t`
- `h2_trailers.t`
- `h2_variables.t`
- `h3_server_name.t`
- `proxy_connection_headers.t`
- `proxy_early_hints.t`
- `proxy_h2.t`
- `proxy_h2_body.t`
- `proxy_h2_body_discard.t`
- `proxy_h2_cache.t`
- `proxy_h2_early_hints.t`
- `proxy_h2_headers.t`
- `proxy_h2_keepalive.t`
- `proxy_h2_method.t`
- `proxy_h2_next_upstream.t`
- `proxy_h2_pass_request.t`
- `proxy_h2_request_buffering.t`
- `proxy_h2_set_body.t`
- `proxy_h2_ssl.t`
- `proxy_h2_trailers.t`
- `proxy_trailers.t`
- `worker_shutdown_timeout_h2.t`

### no cache available (29)

- `auth_request.t`
- `image_filter_finalize.t`
- `not_modified_finalize.t`
- `not_modified_proxy.t`
- `proxy_cache.t`
- `proxy_cache_bypass.t`
- `proxy_cache_chunked.t`
- `proxy_cache_control.t`
- `proxy_cache_convert_head.t`
- `proxy_cache_error.t`
- `proxy_cache_lock.t`
- `proxy_cache_lock_age.t`
- `proxy_cache_lock_ssi.t`
- `proxy_cache_max_range_offset.t`
- `proxy_cache_min_free.t`
- `proxy_cache_path.t`
- `proxy_cache_range.t`
- `proxy_cache_revalidate.t`
- `proxy_cache_use_stale.t`
- `proxy_cache_valid.t`
- `proxy_cache_variables.t`
- `proxy_cache_vary.t`
- `proxy_extra_data.t`
- `proxy_force_ranges.t`
- `proxy_merge_headers.t`
- `proxy_unfinished.t`
- `range_charset.t`
- `range_clearing.t`
- `slice.t`

### no http_v3 available (23)

- `h3_absolute_redirect.t`
- `h3_congestion_ack.t`
- `h3_headers.t`
- `h3_keepalive.t`
- `h3_limit_conn.t`
- `h3_limit_req.t`
- `h3_max_headers.t`
- `h3_proxy.t`
- `h3_proxy_max_temp_file_size.t`
- `h3_request_body.t`
- `h3_request_body_extra.t`
- `h3_reusable.t`
- `h3_server_tokens.t`
- `h3_ssl_early_data.t`
- `h3_ssl_reject_handshake.t`
- `h3_ssl_session_reuse.t`
- `h3_ssl_sni.t`
- `h3_trailers.t`
- `quic_ciphers.t`
- `quic_final_size.t`
- `quic_key_update.t`
- `quic_migration.t`
- `quic_retry.t`

### no mail available (16)

- `mail_capability.t`
- `mail_error_log.t`
- `mail_imap.t`
- `mail_imap_ssl.t`
- `mail_max_errors.t`
- `mail_pop3.t`
- `mail_proxy_protocol.t`
- `mail_proxy_smtp_auth.t`
- `mail_resolver.t`
- `mail_smtp.t`
- `mail_smtp_greeting_delay.t`
- `mail_smtp_xclient.t`
- `mail_ssl.t`
- `mail_ssl_conf_command.t`
- `mail_ssl_session_reuse.t`
- `worker_shutdown_timeout_mail.t`

### no ssi available (14)

- `msie_refresh.t`
- `proxy_chunked.t`
- `proxy_keepalive.t`
- `proxy_ssi_body.t`
- `proxy_store.t`
- `proxy_upgrade.t`
- `request_id.t`
- `rewrite_set.t`
- `ssi.t`
- `ssi_delayed.t`
- `ssi_if.t`
- `ssi_include_big.t`
- `ssi_waited.t`
- `subrequest_output_buffer_size.t`

### FCGI not installed (13)

- `fastcgi.t`
- `fastcgi_body2.t`
- `fastcgi_buffering.t`
- `fastcgi_cache.t`
- `fastcgi_extra_data.t`
- `fastcgi_header_params.t`
- `fastcgi_merge_params.t`
- `fastcgi_merge_params2.t`
- `fastcgi_request_buffering.t`
- `fastcgi_request_buffering_chunked.t`
- `fastcgi_split.t`
- `fastcgi_unix.t`
- `fastcgi_variables.t`

### no sub available (8)

- `addition_buffered.t`
- `sub_filter.t`
- `sub_filter_buffering.t`
- `sub_filter_merge.t`
- `sub_filter_multi.t`
- `sub_filter_multi2.t`
- `sub_filter_perl.t`
- `sub_filter_ssi.t`

### no upstream_zone available (8)

- `upstream_random.t`
- `upstream_resolve.t`
- `upstream_resolve_reload.t`
- `upstream_resolver.t`
- `upstream_service.t`
- `upstream_service_reload.t`
- `upstream_zone.t`
- `upstream_zone_ssl.t`

### SCGI not installed (7)

- `scgi.t`
- `scgi_body.t`
- `scgi_cache.t`
- `scgi_extra_data.t`
- `scgi_gzip.t`
- `scgi_merge_params.t`
- `scgi_request_buffering.t`

### no limit_req available (7)

- `error_log.t`
- `http_keepalive_shutdown.t`
- `limit_req.t`
- `limit_req2.t`
- `limit_req_delay.t`
- `limit_req_dry_run.t`
- `syslog.t`

### no upstream_sticky available (7)

- `upstream_max_conns_sticky.t`
- `upstream_sticky.t`
- `upstream_sticky_drain.t`
- `upstream_sticky_learn.t`
- `upstream_sticky_learn_header.t`
- `upstream_sticky_next.t`
- `upstream_sticky_resolve.t`

### no uwsgi available (7)

- `proxy_ssl_conf_command.t`
- `uwsgi.t`
- `uwsgi_body.t`
- `uwsgi_ssl.t`
- `uwsgi_ssl_certificate.t`
- `uwsgi_ssl_certificate_vars.t`
- `uwsgi_ssl_verify.t`

### no access available (6)

- `access.t`
- `auth_request_satisfy.t`
- `http_include.t`
- `proxy_protocol.t`
- `proxy_protocol2.t`
- `ssl_proxy_protocol.t`

### no geo available (6)

- `geo.t`
- `geo_ipv6.t`
- `geo_unix.t`
- `geo_volatile.t`
- `ssl_certificate.t`
- `ssl_store_keys.t`

### no realip available (6)

- `proxy_protocol_ipv6.t`
- `proxy_protocol_unix.t`
- `realip.t`
- `realip_hostname.t`
- `realip_remote_addr.t`
- `realip_remote_port.t`

### Cache::Memcached not installed (5)

- `gunzip_memcached.t`
- `memcached.t`
- `memcached_keepalive.t`
- `memcached_keepalive_stale.t`
- `upstream_hash_memcached.t`

### no perl available (5)

- `perl.t`
- `perl_gzip.t`
- `perl_sleep.t`
- `perl_ssi.t`
- `ssl_certificate_perl.t`

### no charset available (4)

- `autoindex.t`
- `charset.t`
- `charset_gzip_static.t`
- `range.t`

### no gunzip available (4)

- `gunzip.t`
- `gunzip_perl.t`
- `gunzip_ssi.t`
- `gunzip_static.t`

### no inet6 support (4)

- `http_resolver_aaaa.t`
- `http_resolver_ipv4.t`
- `proxy_implicit.t`
- `proxy_ssl_name.t`

### no mp4 available (4)

- `mp4.t`
- `mp4_ssi.t`
- `mp4_start_key_frame.t`
- `range_mp4.t`

### can leave orphaned process group (3)

- `binary_upgrade.t`
- `control_api_upgrade.t`
- `h3_bpf_upgrade.t`

### must be root (3)

- `h3_bpf.t`
- `proxy_bind_transparent.t`
- `proxy_bind_transparent_capability.t`

### no --with-debug available (3)

- `debug_connection.t`
- `debug_connection_syslog.t`
- `debug_connection_unix.t`

### no dav available (3)

- `dav.t`
- `dav_chunked.t`
- `dav_utf8.t`

### no gzip available (3)

- `access_log.t`
- `gzip.t`
- `gzip_flush.t`

### no limit_conn available (3)

- `limit_conn.t`
- `limit_conn_complex.t`
- `limit_conn_dry_run.t`

### no openssl:1.0.2 available (3)

- `proxy_ssl_certificate_cache.t`
- `ssl_certificate_cache.t`
- `ssl_conf_command.t`

### no tunnel (3)

- `tunnel.t`
- `tunnel_auth_basic.t`
- `tunnel_next_upstream.t`

### no upstream_ip_hash available (3)

- `upstream_ip_hash.t`
- `upstream_ip_hash_ipv6.t`
- `upstream_sticky_route.t`

### no xslt available (3)

- `xslt.t`
- `xslt_external_entities.t`
- `xslt_params.t`

### not yet (3)

- `client_body_early_read.t`
- `http_location_predicate.t`
- `http_location_predicate_extra.t`

### listen on wildcard address (2)

- `http_listen_wildcard.t`
- `stream_udp_wildcard.t`

### long configuration parsing (2)

- `geo_binary.t`
- `stream_geo_binary.t`

### no control_api available (2)

- `control_api.t`
- `control_api_unix.t`

### no fastcgi available (2)

- `fastcgi_body.t`
- `fastcgi_keepalive.t`

### no memcached available (2)

- `memcached_fake.t`
- `memcached_fake_extra.t`

### no mirror available (2)

- `mirror.t`
- `mirror_proxy.t`

### no upstream_least_conn available (2)

- `upstream_least_conn.t`
- `upstream_max_conns.t`

### no userid available (2)

- `userid.t`
- `userid_flags.t`

### GD not installed (1)

- `image_filter.t`

### Protocol::WebSocket not installed (1)

- `proxy_websocket.t`

### Win32API::File not installed (1)

- `autoindex_win32.t`

### long test (1)

- `proxy_cache_manager.t`

### may not work, incompatible with sanitizers (1)

- `ssl_provider_keys.t`

### may not work, leaves coredump (1)

- `ssl_engine_keys.t`

### no addition available (1)

- `addition.t`

### no auth_request available (1)

- `auth_request_set.t`

### no disable_symlinks (1)

- `http_disable_symlinks.t`

### no empty_gif available (1)

- `empty_gif.t`

### no flv available (1)

- `range_flv.t`

### no http_geoip available (1)

- `geoip.t`

### no image_filter available (1)

- `image_filter_webp.t`

### no json available (1)

- `json_set.t`

### no least_time (1)

- `upstream_least_time.t`

### no max_headers (1)

- `http_max_headers.t`

### no openssl:1.1.1 available (1)

- `ssl_sni_protocols.t`

### no openssl:3.5 available (1)

- `ssl_sigalg.t`

### no proxy_limit_rate variables (1)

- `proxy_limit_rate2.t`

### no random_index available (1)

- `random_index.t`

### no referer available (1)

- `referer.t`

### no secure_link available (1)

- `secure_link.t`

### no slice available (1)

- `sub_filter_slice.t`

### no ssl_certificate_compression (1)

- `ssl_certificate_compression.t`

### no ssl_object_cache_inheritable (1)

- `ssl_cache_reload.t`

### no stub_status available (1)

- `stub_status.t`

### no upstream_hash available (1)

- `upstream_hash.t`

### not win32 (1)

- `http_location_win32.t`

### wants ssl_client_certificate (1)

- `ssl_verify_client_trusted.t`

