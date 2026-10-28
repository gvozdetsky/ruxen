# Directives

Every directive of nginx 1.30.6's core, events and http modules, and what ruxen
does with it. Rendered by `scripts/directives.py` from a build of ruxen: where
`ruxen -t` takes each directive (main, http, server, location, upstream) and what
`ruxen --compat` says about it. Don't edit by hand; rerun the script.

- **yes**: implemented. The contexts are where ruxen takes it.
- **accepted, no effect**: a tuning knob ruxen accepts and ignores ('any': at every level).
- **accepted, differs**: accepted, but ruxen does something other than nginx; the note says what.
- **refused**: known, but refused at load, since ignoring it would be unsafe.
- **no**: `unknown directive`; the configuration doesn't load.

Of 564 directives: 194 implemented, 18 accepted with a difference, 71 accepted with no effect, 0 refused, 281 unknown.

`ruxen --compat -c nginx.conf` checks a whole configuration against this.

## nginx

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `daemon` | accepted, no effect | any |  |
| `master_process` | accepted, no effect | any |  |
| `timer_resolution` | accepted, no effect | any |  |
| `pid` | yes | main |  |
| `lock_file` | accepted, no effect | any |  |
| `worker_processes` | yes | main |  |
| `debug_points` | accepted, no effect | any |  |
| `user` | yes | main |  |
| `worker_priority` | accepted, no effect | any |  |
| `worker_cpu_affinity` | accepted, no effect | any |  |
| `worker_rlimit_nofile` | yes | main |  |
| `worker_rlimit_core` | yes | main |  |
| `worker_shutdown_timeout` | yes | main |  |
| `working_directory` | accepted, no effect | any |  |
| `env` | accepted, no effect | any |  |
| `load_module` | accepted, no effect | any |  |

## conf_file

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `include` | yes | any |  |

## log

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `error_log` | yes | any |  |

## regex

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `pcre_jit` | accepted, no effect | any |  |

## thread_pool

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `thread_pool` | accepted, no effect | any |  |

## event

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `events` | accepted, no effect | events | the `events` block is read for `worker_connections` only |
| `worker_connections` | yes | events |  |
| `use` | accepted, no effect | events | the `events` block is read for `worker_connections` only |
| `multi_accept` | accepted, no effect | events | the `events` block is read for `worker_connections` only |
| `accept_mutex` | accepted, no effect | events | the `events` block is read for `worker_connections` only |
| `accept_mutex_delay` | accepted, no effect | events | the `events` block is read for `worker_connections` only |
| `debug_connection` | accepted, no effect | events | the `events` block is read for `worker_connections` only |

## event_openssl

Not supported: `ssl_engine`.

## event_openssl_cache

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `ssl_object_cache_inheritable` | yes | main |  |

## http

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `http` | yes | main |  |

## http_copy_filter

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `output_buffers` | accepted, no effect | any |  |

## http_core

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `variables_hash_max_size` | accepted, no effect | any |  |
| `variables_hash_bucket_size` | accepted, no effect | any |  |
| `server_names_hash_max_size` | accepted, no effect | any |  |
| `server_names_hash_bucket_size` | accepted, no effect | any |  |
| `server` | yes | http, upstream |  |
| `connection_pool_size` | accepted, no effect | any |  |
| `request_pool_size` | accepted, no effect | any |  |
| `client_header_timeout` | yes | any |  |
| `client_header_buffer_size` | yes | http, server |  |
| `large_client_header_buffers` | yes | http, server |  |
| `max_headers` | yes | http, server |  |
| `ignore_invalid_headers` | yes | any |  |
| `merge_slashes` | yes | http, server |  |
| `underscores_in_headers` | yes | any |  |
| `location` | yes | server, location |  |
| `listen` | yes | server |  |
| `server_name` | yes | server |  |
| `types_hash_max_size` | accepted, no effect | any |  |
| `types_hash_bucket_size` | accepted, no effect | any |  |
| `types` | yes | http, server, location |  |
| `default_type` | yes | http, server, location |  |
| `root` | yes | http, server, location |  |
| `alias` | yes | location |  |
| `limit_except` | yes | location |  |
| `client_max_body_size` | yes | any |  |
| `client_body_buffer_size` | yes | http, server, location |  |
| `client_body_timeout` | yes | any |  |
| `client_body_temp_path` | yes | http, server, location |  |
| `client_body_in_file_only` | accepted, no effect | any |  |
| `client_body_in_single_buffer` | accepted, no effect | any |  |
| `sendfile` | yes | any |  |
| `sendfile_max_chunk` | accepted, no effect | any |  |
| `subrequest_output_buffer_size` | no |  |  |
| `aio` | accepted, no effect | any |  |
| `aio_write` | accepted, no effect | any |  |
| `read_ahead` | accepted, no effect | any |  |
| `directio` | accepted, no effect | any |  |
| `directio_alignment` | accepted, no effect | any |  |
| `tcp_nopush` | accepted, no effect | any |  |
| `tcp_nodelay` | accepted, no effect | any |  |
| `send_timeout` | yes | any |  |
| `send_lowat` | no |  |  |
| `postpone_output` | accepted, no effect | any |  |
| `limit_rate` | yes | http, server, location |  |
| `limit_rate_after` | yes | http, server, location |  |
| `keepalive_time` | yes | http, server, location, upstream |  |
| `keepalive_timeout` | yes | http, server, location, upstream |  |
| `keepalive_min_timeout` | no |  |  |
| `keepalive_requests` | yes | http, server, location, upstream |  |
| `keepalive_disable` | yes | http, server, location |  |
| `satisfy` | yes | http, server, location |  |
| `auth_delay` | yes | http, server, location |  |
| `internal` | yes | location |  |
| `lingering_close` | accepted, no effect | any |  |
| `lingering_time` | accepted, no effect | any |  |
| `lingering_timeout` | accepted, no effect | any |  |
| `reset_timedout_connection` | accepted, no effect | any |  |
| `absolute_redirect` | yes | http, server, location |  |
| `server_name_in_redirect` | yes | http, server, location |  |
| `port_in_redirect` | yes | http, server, location |  |
| `msie_padding` | accepted, no effect | any |  |
| `msie_refresh` | accepted, no effect | any |  |
| `log_not_found` | accepted, no effect | any |  |
| `log_subrequest` | accepted, no effect | any |  |
| `recursive_error_pages` | yes | http, server, location |  |
| `server_tokens` | yes | http, server, location |  |
| `if_modified_since` | yes | http, server, location |  |
| `max_ranges` | yes | http, server, location |  |
| `chunked_transfer_encoding` | accepted, differs | any | not applied at this level (ruxen reads it in server and location only) |
| `etag` | yes | http, server, location |  |
| `early_hints` | no |  |  |
| `error_page` | yes | http, server, location |  |
| `post_action` | yes | http, server, location |  |
| `open_file_cache` | accepted, no effect | any |  |
| `open_file_cache_valid` | accepted, no effect | any |  |
| `open_file_cache_min_uses` | accepted, no effect | any |  |
| `open_file_cache_errors` | accepted, no effect | any |  |
| `open_file_cache_events` | no |  |  |
| `resolver` | yes | http, server, location |  |
| `resolver_timeout` | yes | http, server, location |  |
| `gzip_vary` | yes | any |  |
| `gzip_http_version` | yes | any |  |
| `gzip_proxied` | yes | any |  |
| `gzip_disable` | yes | any |  |
| `disable_symlinks` | yes | http, server, location |  |

## http_upstream

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `upstream` | yes | http |  |

## http_access

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `allow` | yes | http, server, location |  |
| `deny` | yes | http, server, location |  |

## http_addition_filter

Not supported: `add_before_body`, `add_after_body`, `addition_types`.

## http_auth_basic

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `auth_basic` | yes | http, server, location |  |
| `auth_basic_user_file` | yes | http, server, location |  |

## http_auth_request

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `auth_request` | yes | http, server, location |  |
| `auth_request_set` | yes | http, server, location |  |

## http_autoindex

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `autoindex` | yes | http, server, location |  |
| `autoindex_format` | yes | http, server, location |  |
| `autoindex_localtime` | yes | http, server, location |  |
| `autoindex_exact_size` | yes | http, server, location |  |

## http_browser

Not supported: `modern_browser`, `ancient_browser`, `modern_browser_value`, `ancient_browser_value`.

## http_charset_filter

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `charset` | yes | http, server, location |  |
| `source_charset` | accepted, differs | http, server, location | nothing is converted: a response is labelled only when it is already in `charset` |
| `override_charset` | accepted, differs | any | nothing is converted |
| `charset_types` | yes | http, server, location |  |
| `charset_map` | accepted, no effect | any |  |

## http_dav

Not supported: `dav_methods`, `create_full_put_path`, `min_delete_depth`, `dav_access`.

## http_degradation

Not supported: `degradation`, `degrade`.

## http_empty_gif

Not supported: `empty_gif`.

## http_fastcgi

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `fastcgi_pass` | no |  |  |
| `fastcgi_index` | no |  |  |
| `fastcgi_split_path_info` | no |  |  |
| `fastcgi_store` | no |  |  |
| `fastcgi_store_access` | no |  |  |
| `fastcgi_buffering` | no |  |  |
| `fastcgi_request_buffering` | no |  |  |
| `fastcgi_ignore_client_abort` | no |  |  |
| `fastcgi_bind` | no |  |  |
| `fastcgi_socket_keepalive` | no |  |  |
| `fastcgi_connect_timeout` | no |  |  |
| `fastcgi_send_timeout` | no |  |  |
| `fastcgi_send_lowat` | no |  |  |
| `fastcgi_buffer_size` | no |  |  |
| `fastcgi_pass_request_headers` | no |  |  |
| `fastcgi_pass_request_body` | no |  |  |
| `fastcgi_intercept_errors` | no |  |  |
| `fastcgi_read_timeout` | no |  |  |
| `fastcgi_buffers` | no |  |  |
| `fastcgi_busy_buffers_size` | no |  |  |
| `fastcgi_force_ranges` | no |  |  |
| `fastcgi_limit_rate` | no |  |  |
| `fastcgi_cache` | no |  |  |
| `fastcgi_cache_key` | no |  |  |
| `fastcgi_cache_path` | no |  |  |
| `fastcgi_cache_bypass` | no |  |  |
| `fastcgi_no_cache` | no |  |  |
| `fastcgi_cache_valid` | no |  |  |
| `fastcgi_cache_min_uses` | no |  |  |
| `fastcgi_cache_max_range_offset` | no |  |  |
| `fastcgi_cache_use_stale` | no |  |  |
| `fastcgi_cache_methods` | no |  |  |
| `fastcgi_cache_lock` | no |  |  |
| `fastcgi_cache_lock_timeout` | no |  |  |
| `fastcgi_cache_lock_age` | no |  |  |
| `fastcgi_cache_revalidate` | no |  |  |
| `fastcgi_cache_background_update` | no |  |  |
| `fastcgi_temp_path` | accepted, no effect | any |  |
| `fastcgi_max_temp_file_size` | no |  |  |
| `fastcgi_temp_file_write_size` | no |  |  |
| `fastcgi_next_upstream` | no |  |  |
| `fastcgi_next_upstream_tries` | no |  |  |
| `fastcgi_next_upstream_timeout` | no |  |  |
| `fastcgi_param` | no |  |  |
| `fastcgi_pass_header` | no |  |  |
| `fastcgi_hide_header` | no |  |  |
| `fastcgi_ignore_headers` | no |  |  |
| `fastcgi_catch_stderr` | no |  |  |
| `fastcgi_keep_conn` | no |  |  |

## http_flv

Not supported: `flv`.

## http_geo

Not supported: `geo`.

## http_geoip

Not supported: `geoip_country`, `geoip_org`, `geoip_city`, `geoip_proxy`, `geoip_proxy_recursive`.

## http_grpc

Not supported: `grpc_pass`, `grpc_bind`, `grpc_socket_keepalive`, `grpc_connect_timeout`, `grpc_send_timeout`, `grpc_intercept_errors`, `grpc_buffer_size`, `grpc_read_timeout`, `grpc_next_upstream`, `grpc_next_upstream_tries`, `grpc_next_upstream_timeout`, `grpc_set_header`, `grpc_pass_header`, `grpc_hide_header`, `grpc_ignore_headers`, `grpc_ssl_session_reuse`, `grpc_ssl_protocols`, `grpc_ssl_ciphers`, `grpc_ssl_name`, `grpc_ssl_server_name`, `grpc_ssl_verify`, `grpc_ssl_verify_depth`, `grpc_ssl_trusted_certificate`, `grpc_ssl_crl`, `grpc_ssl_certificate`, `grpc_ssl_certificate_key`, `grpc_ssl_certificate_cache`, `grpc_ssl_password_file`, `grpc_ssl_conf_command`.

## http_gunzip_filter

Not supported: `gunzip`, `gunzip_buffers`.

## http_gzip_filter

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `gzip` | yes | any |  |
| `gzip_buffers` | accepted, no effect | any |  |
| `gzip_types` | yes | any |  |
| `gzip_comp_level` | yes | any |  |
| `gzip_window` | no |  |  |
| `gzip_hash` | no |  |  |
| `postpone_gzipping` | no |  |  |
| `gzip_no_buffer` | no |  |  |
| `gzip_min_length` | yes | any |  |

## http_gzip_static

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `gzip_static` | yes | http, server, location |  |

## http_headers_filter

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `expires` | yes | http, server, location |  |
| `add_header` | yes | http, server, location |  |
| `add_trailer` | yes | http, server, location |  |
| `add_header_inherit` | yes | http, server, location |  |
| `add_trailer_inherit` | yes | http, server, location |  |

## http_image_filter

Not supported: `image_filter`, `image_filter_jpeg_quality`, `image_filter_webp_quality`, `image_filter_sharpen`, `image_filter_transparency`, `image_filter_interlace`, `image_filter_buffer`.

## http_index

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `index` | yes | http, server, location |  |

## http_limit_conn

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `limit_conn_zone` | yes | http |  |
| `limit_conn` | yes | http, server, location |  |
| `limit_conn_log_level` | yes | http, server, location |  |
| `limit_conn_status` | yes | http, server, location |  |
| `limit_conn_dry_run` | yes | http, server, location |  |

## http_limit_req

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `limit_req_zone` | yes | http |  |
| `limit_req` | yes | http, server, location |  |
| `limit_req_log_level` | yes | http, server, location |  |
| `limit_req_status` | yes | http, server, location |  |
| `limit_req_dry_run` | yes | http, server, location |  |

## http_log

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `log_format` | yes | any |  |
| `access_log` | yes | any |  |
| `open_log_file_cache` | yes | http, server, location |  |

## http_map

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `map` | yes | http |  |
| `map_hash_max_size` | accepted, no effect | any |  |
| `map_hash_bucket_size` | accepted, no effect | any |  |

## http_memcached

Not supported: `memcached_pass`, `memcached_bind`, `memcached_socket_keepalive`, `memcached_connect_timeout`, `memcached_send_timeout`, `memcached_buffer_size`, `memcached_read_timeout`, `memcached_next_upstream`, `memcached_next_upstream_tries`, `memcached_next_upstream_timeout`, `memcached_gzip_flag`.

## http_mirror

Not supported: `mirror`, `mirror_request_body`.

## http_mp4

Not supported: `mp4`, `mp4_buffer_size`, `mp4_max_buffer_size`, `mp4_start_key_frame`.

## http_proxy

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `proxy_pass` | yes | location |  |
| `proxy_redirect` | yes | http, server, location |  |
| `proxy_cookie_domain` | yes | http, server, location |  |
| `proxy_cookie_path` | yes | http, server, location |  |
| `proxy_cookie_flags` | yes | http, server, location |  |
| `proxy_store` | accepted, differs | any | proxied responses are not stored |
| `proxy_store_access` | accepted, no effect | any |  |
| `proxy_buffering` | accepted, differs | any | ruxen relays a response as it arrives either way (#88, #463) |
| `proxy_request_buffering` | accepted, differs | any | request bodies are still read whole before they are proxied (#134) |
| `proxy_ignore_client_abort` | yes | http, server, location |  |
| `proxy_bind` | yes | http, server, location |  |
| `proxy_socket_keepalive` | accepted, no effect | any |  |
| `proxy_connect_timeout` | yes | http, server, location |  |
| `proxy_send_timeout` | yes | http, server, location |  |
| `proxy_send_lowat` | no |  |  |
| `proxy_intercept_errors` | yes | http, server, location |  |
| `proxy_set_header` | yes | http, server, location |  |
| `proxy_headers_hash_max_size` | no |  |  |
| `proxy_headers_hash_bucket_size` | no |  |  |
| `proxy_set_body` | yes | http, server, location |  |
| `proxy_method` | yes | http, server, location |  |
| `proxy_pass_request_headers` | yes | http, server, location |  |
| `proxy_pass_request_body` | yes | http, server, location |  |
| `proxy_pass_trailers` | no |  |  |
| `proxy_buffer_size` | accepted, no effect | any |  |
| `proxy_read_timeout` | yes | http, server, location |  |
| `proxy_buffers` | accepted, no effect | any |  |
| `proxy_busy_buffers_size` | accepted, no effect | any |  |
| `proxy_force_ranges` | yes | http, server, location |  |
| `proxy_limit_rate` | yes | http, server, location |  |
| `proxy_cache` | yes | http, server, location |  |
| `proxy_cache_key` | yes | http, server, location |  |
| `proxy_cache_path` | yes | http |  |
| `proxy_cache_bypass` | yes | http, server, location |  |
| `proxy_no_cache` | yes | http, server, location |  |
| `proxy_cache_valid` | yes | http, server, location |  |
| `proxy_cache_min_uses` | yes | http, server, location |  |
| `proxy_cache_max_range_offset` | yes | http, server, location |  |
| `proxy_cache_use_stale` | yes | http, server, location |  |
| `proxy_cache_methods` | yes | http, server, location |  |
| `proxy_cache_lock` | yes | http, server, location |  |
| `proxy_cache_lock_timeout` | yes | http, server, location |  |
| `proxy_cache_lock_age` | yes | http, server, location |  |
| `proxy_cache_revalidate` | yes | http, server, location |  |
| `proxy_cache_convert_head` | yes | http, server, location |  |
| `proxy_cache_background_update` | yes | http, server, location |  |
| `proxy_temp_path` | accepted, no effect | any |  |
| `proxy_max_temp_file_size` | accepted, no effect | any |  |
| `proxy_temp_file_write_size` | accepted, no effect | any |  |
| `proxy_next_upstream` | yes | http, server, location |  |
| `proxy_next_upstream_tries` | yes | http, server, location |  |
| `proxy_next_upstream_timeout` | yes | http, server, location |  |
| `proxy_pass_header` | yes | http, server, location |  |
| `proxy_hide_header` | yes | http, server, location |  |
| `proxy_ignore_headers` | yes | http, server, location |  |
| `proxy_http_version` | yes | http, server, location |  |
| `proxy_ssl_session_reuse` | yes | http, server, location |  |
| `proxy_ssl_protocols` | yes | http, server, location |  |
| `proxy_ssl_ciphers` | accepted, no effect | any |  |
| `proxy_ssl_name` | yes | http, server, location |  |
| `proxy_ssl_server_name` | yes | http, server, location |  |
| `proxy_ssl_verify` | yes | http, server, location |  |
| `proxy_ssl_verify_depth` | yes | http, server, location |  |
| `proxy_ssl_trusted_certificate` | yes | http, server, location |  |
| `proxy_ssl_crl` | yes | http, server, location |  |
| `proxy_ssl_certificate` | yes | http, server, location |  |
| `proxy_ssl_certificate_key` | yes | http, server, location |  |
| `proxy_ssl_certificate_cache` | no |  |  |
| `proxy_ssl_password_file` | yes | http, server, location |  |
| `proxy_ssl_conf_command` | no |  |  |

## http_random_index

Not supported: `random_index`.

## http_realip

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `set_real_ip_from` | yes | http, server, location |  |
| `real_ip_header` | yes | http, server, location |  |
| `real_ip_recursive` | yes | http, server, location |  |

## http_referer

Not supported: `valid_referers`, `referer_hash_max_size`, `referer_hash_bucket_size`.

## http_rewrite

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `rewrite` | yes | server, location |  |
| `return` | yes | server, location |  |
| `break` | yes | server, location |  |
| `if` | yes | server, location |  |
| `set` | yes | server, location |  |
| `rewrite_log` | accepted, no effect | any |  |
| `uninitialized_variable_warn` | no |  |  |

## http_scgi

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `scgi_pass` | no |  |  |
| `scgi_store` | no |  |  |
| `scgi_store_access` | no |  |  |
| `scgi_buffering` | no |  |  |
| `scgi_request_buffering` | no |  |  |
| `scgi_ignore_client_abort` | no |  |  |
| `scgi_bind` | no |  |  |
| `scgi_socket_keepalive` | no |  |  |
| `scgi_connect_timeout` | no |  |  |
| `scgi_send_timeout` | no |  |  |
| `scgi_buffer_size` | no |  |  |
| `scgi_pass_request_headers` | no |  |  |
| `scgi_pass_request_body` | no |  |  |
| `scgi_intercept_errors` | no |  |  |
| `scgi_read_timeout` | no |  |  |
| `scgi_buffers` | no |  |  |
| `scgi_busy_buffers_size` | no |  |  |
| `scgi_force_ranges` | no |  |  |
| `scgi_limit_rate` | no |  |  |
| `scgi_cache` | no |  |  |
| `scgi_cache_key` | no |  |  |
| `scgi_cache_path` | no |  |  |
| `scgi_cache_bypass` | no |  |  |
| `scgi_no_cache` | no |  |  |
| `scgi_cache_valid` | no |  |  |
| `scgi_cache_min_uses` | no |  |  |
| `scgi_cache_max_range_offset` | no |  |  |
| `scgi_cache_use_stale` | no |  |  |
| `scgi_cache_methods` | no |  |  |
| `scgi_cache_lock` | no |  |  |
| `scgi_cache_lock_timeout` | no |  |  |
| `scgi_cache_lock_age` | no |  |  |
| `scgi_cache_revalidate` | no |  |  |
| `scgi_cache_background_update` | no |  |  |
| `scgi_temp_path` | accepted, no effect | any |  |
| `scgi_max_temp_file_size` | no |  |  |
| `scgi_temp_file_write_size` | no |  |  |
| `scgi_next_upstream` | no |  |  |
| `scgi_next_upstream_tries` | no |  |  |
| `scgi_next_upstream_timeout` | no |  |  |
| `scgi_param` | no |  |  |
| `scgi_pass_header` | no |  |  |
| `scgi_hide_header` | no |  |  |
| `scgi_ignore_headers` | no |  |  |

## http_secure_link

Not supported: `secure_link`, `secure_link_md5`, `secure_link_secret`.

## http_slice_filter

Not supported: `slice`.

## http_split_clients

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `split_clients` | yes | http |  |

## http_ssi_filter

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `ssi` | accepted, differs | any | server-side includes are not processed |
| `ssi_silent_errors` | accepted, no effect | any |  |
| `ssi_ignore_recycled_buffers` | no |  |  |
| `ssi_min_file_chunk` | no |  |  |
| `ssi_value_length` | no |  |  |
| `ssi_types` | accepted, no effect | any |  |
| `ssi_last_modified` | no |  |  |

## http_ssl

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `ssl_certificate` | yes | http, server |  |
| `ssl_certificate_key` | yes | http, server |  |
| `ssl_certificate_cache` | yes | http, server |  |
| `ssl_ech_file` | no |  |  |
| `ssl_password_file` | yes | http, server |  |
| `ssl_certificate_compression` | yes | http, server |  |
| `ssl_dhparam` | accepted, no effect | http, server |  |
| `ssl_ecdh_curve` | accepted, differs | http, server | "ssl_ecdh_curve" is not supported yet and is ignored: rustls's default key exchange groups are used |
| `ssl_protocols` | yes | http, server |  |
| `ssl_ciphers` | yes | http, server |  |
| `ssl_buffer_size` | accepted, no effect | http, server |  |
| `ssl_verify_client` | yes | http, server |  |
| `ssl_verify_depth` | yes | http, server |  |
| `ssl_client_certificate` | yes | http, server |  |
| `ssl_trusted_certificate` | yes | http, server |  |
| `ssl_prefer_server_ciphers` | yes | http, server |  |
| `ssl_session_cache` | yes | http, server |  |
| `ssl_session_tickets` | yes | http, server |  |
| `ssl_session_ticket_key` | yes | http, server |  |
| `ssl_session_timeout` | yes | http, server |  |
| `ssl_crl` | yes | http, server |  |
| `ssl_ocsp` | no |  |  |
| `ssl_ocsp_responder` | no |  |  |
| `ssl_ocsp_cache` | no |  |  |
| `ssl_stapling` | yes | http, server |  |
| `ssl_stapling_file` | yes | http, server |  |
| `ssl_stapling_responder` | yes | http, server |  |
| `ssl_stapling_verify` | yes | http, server |  |
| `ssl_early_data` | accepted, differs | http, server | TLS 1.3 early data is not accepted |
| `ssl_conf_command` | accepted, differs | http, server | OpenSSL commands are not applied: ruxen's TLS is rustls |
| `ssl_reject_handshake` | yes | http, server |  |

## http_stub_status

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `stub_status` | yes | location |  |

## http_sub_filter

Not supported: `sub_filter`, `sub_filter_types`, `sub_filter_once`, `sub_filter_last_modified`.

## http_try_files

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `try_files` | yes | location |  |

## http_upstream_hash

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `hash` | yes | upstream |  |

## http_upstream_ip_hash

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `ip_hash` | yes | upstream |  |

## http_upstream_keepalive

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `keepalive` | yes | upstream |  |

## http_upstream_least_conn

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `least_conn` | yes | upstream |  |

## http_upstream_random

Not supported: `random`.

## http_upstream_sticky

Not supported: `sticky`.

## http_upstream_zone

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `zone` | yes | upstream |  |

## http_userid_filter

Not supported: `userid`, `userid_service`, `userid_name`, `userid_domain`, `userid_path`, `userid_expires`, `userid_flags`, `userid_p3p`, `userid_mark`.

## http_uwsgi

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `uwsgi_pass` | no |  |  |
| `uwsgi_modifier1` | no |  |  |
| `uwsgi_modifier2` | no |  |  |
| `uwsgi_store` | no |  |  |
| `uwsgi_store_access` | no |  |  |
| `uwsgi_buffering` | no |  |  |
| `uwsgi_request_buffering` | no |  |  |
| `uwsgi_ignore_client_abort` | no |  |  |
| `uwsgi_bind` | no |  |  |
| `uwsgi_socket_keepalive` | no |  |  |
| `uwsgi_connect_timeout` | no |  |  |
| `uwsgi_send_timeout` | no |  |  |
| `uwsgi_buffer_size` | no |  |  |
| `uwsgi_pass_request_headers` | no |  |  |
| `uwsgi_pass_request_body` | no |  |  |
| `uwsgi_intercept_errors` | no |  |  |
| `uwsgi_read_timeout` | no |  |  |
| `uwsgi_buffers` | no |  |  |
| `uwsgi_busy_buffers_size` | no |  |  |
| `uwsgi_force_ranges` | no |  |  |
| `uwsgi_limit_rate` | no |  |  |
| `uwsgi_cache` | no |  |  |
| `uwsgi_cache_key` | no |  |  |
| `uwsgi_cache_path` | no |  |  |
| `uwsgi_cache_bypass` | no |  |  |
| `uwsgi_no_cache` | no |  |  |
| `uwsgi_cache_valid` | no |  |  |
| `uwsgi_cache_min_uses` | no |  |  |
| `uwsgi_cache_max_range_offset` | no |  |  |
| `uwsgi_cache_use_stale` | no |  |  |
| `uwsgi_cache_methods` | no |  |  |
| `uwsgi_cache_lock` | no |  |  |
| `uwsgi_cache_lock_timeout` | no |  |  |
| `uwsgi_cache_lock_age` | no |  |  |
| `uwsgi_cache_revalidate` | no |  |  |
| `uwsgi_cache_background_update` | no |  |  |
| `uwsgi_temp_path` | accepted, no effect | any |  |
| `uwsgi_max_temp_file_size` | no |  |  |
| `uwsgi_temp_file_write_size` | no |  |  |
| `uwsgi_next_upstream` | no |  |  |
| `uwsgi_next_upstream_tries` | no |  |  |
| `uwsgi_next_upstream_timeout` | no |  |  |
| `uwsgi_param` | no |  |  |
| `uwsgi_string` | no |  |  |
| `uwsgi_pass_header` | no |  |  |
| `uwsgi_hide_header` | no |  |  |
| `uwsgi_ignore_headers` | no |  |  |
| `uwsgi_ssl_session_reuse` | no |  |  |
| `uwsgi_ssl_protocols` | no |  |  |
| `uwsgi_ssl_ciphers` | no |  |  |
| `uwsgi_ssl_name` | no |  |  |
| `uwsgi_ssl_server_name` | no |  |  |
| `uwsgi_ssl_verify` | no |  |  |
| `uwsgi_ssl_verify_depth` | no |  |  |
| `uwsgi_ssl_trusted_certificate` | no |  |  |
| `uwsgi_ssl_crl` | no |  |  |
| `uwsgi_ssl_certificate` | no |  |  |
| `uwsgi_ssl_certificate_key` | no |  |  |
| `uwsgi_ssl_certificate_cache` | no |  |  |
| `uwsgi_ssl_password_file` | no |  |  |
| `uwsgi_ssl_conf_command` | no |  |  |

## http_xslt_filter

Not supported: `xml_entities`, `xslt_stylesheet`, `xslt_param`, `xslt_string_param`, `xslt_types`, `xslt_last_modified`.

## http_v2

| directive | ruxen | contexts | notes |
| --- | --- | --- | --- |
| `http2` | yes | http, server |  |
| `http2_recv_buffer_size` | yes | http, server |  |
| `http2_pool_size` | yes | http, server |  |
| `http2_max_concurrent_streams` | yes | http, server |  |
| `http2_max_concurrent_pushes` | accepted, differs | http, server | the "http2_max_concurrent_pushes" directive is obsolete, ignored |
| `http2_max_requests` | accepted, differs | http, server | the "http2_max_requests" directive is obsolete, use the "keepalive_requests" directive instead |
| `http2_max_field_size` | accepted, differs | http, server | the "http2_max_field_size" directive is obsolete, use the "large_client_header_buffers" directive instead |
| `http2_max_header_size` | accepted, differs | http, server | the "http2_max_header_size" directive is obsolete, use the "large_client_header_buffers" directive instead |
| `http2_body_preread_size` | yes | http, server |  |
| `http2_streams_index_size` | yes | http, server |  |
| `http2_recv_timeout` | accepted, differs | http, server | the "http2_recv_timeout" directive is obsolete, use the "client_header_timeout" directive instead |
| `http2_idle_timeout` | accepted, differs | http, server | the "http2_idle_timeout" directive is obsolete, use the "keepalive_timeout" directive instead |
| `http2_chunk_size` | yes | http, server, location |  |
| `http2_push_preload` | accepted, differs | http, server, location | the "http2_push_preload" directive is obsolete, ignored |
| `http2_push` | accepted, differs | http, server, location | the "http2_push" directive is obsolete, ignored |
