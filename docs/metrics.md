# Metrics: `ruxen_metrics`

`ruxen_metrics;` in a `location` answers with ruxen's counters in the
Prometheus text format (version 0.0.4). It is ruxen's own directive, not
nginx's; nginx open source has only `stub_status`, and the per-upstream
numbers are in NGINX Plus's `api` module or third-party modules.

```nginx
server {
    listen 127.0.0.1:9113;
    location = /metrics {
        ruxen_metrics;
        allow 127.0.0.1;
        deny all;
    }
}
```

```yaml
scrape_configs:
  - job_name: ruxen
    static_configs:
      - targets: ["127.0.0.1:9113"]
```

It goes where `stub_status` goes (a location, no arguments) and answers `GET`
and `HEAD`; another method gets a 405. Restrict it as you would `stub_status`:
the page names your servers, listen addresses and upstream peers.

Nothing is counted unless some location has `ruxen_metrics`: without it, the
configuration has no counters and requests don't touch any.

## Series

| name | type | labels | what |
| --- | --- | --- | --- |
| `ruxen_connections_active` | gauge | | client connections open, idle ones included (`stub_status`'s "Active connections") |
| `ruxen_connections_reading` | gauge | | reading a request head |
| `ruxen_connections_writing` | gauge | | processing a request or writing its response |
| `ruxen_connections_waiting` | gauge | | idle keep-alive connections |
| `ruxen_connections_accepted_total` | counter | | connections accepted |
| `ruxen_connections_handled_total` | counter | | connections taken on (not refused at `worker_connections`) |
| `ruxen_http_requests_total` | counter | | client requests |
| `ruxen_server_responses_total` | counter | `server`, `listen`, `code` | responses by status class (`1xx` … `5xx`) |
| `ruxen_server_sent_bytes_total` | counter | `server`, `listen` | bytes sent to clients, response heads included (`$bytes_sent`) |
| `ruxen_upstream_peer_requests_total` | counter | `upstream`, `peer` | attempts on the peer, retries included |
| `ruxen_upstream_peer_failures_total` | counter | `upstream`, `peer` | failed attempts, as `max_fails` counts them: errors, timeouts, and the `proxy_next_upstream` statuses other than 403 and 404 |
| `ruxen_upstream_peer_response_seconds` | histogram | `upstream`, `peer` | from the start of an attempt until its response is in (its head, for a response streamed to the client) |
| `ruxen_upstream_peer_up` | gauge | `upstream`, `peer` | 1 if the peer can be picked, 0 if it is `down` or cooling off after `max_fails` |
| `ruxen_limit_req_requests_total` | counter | `zone`, `status` | requests by `$limit_req_status` (`PASSED`, `DELAYED`, `REJECTED`, `DELAYED_DRY_RUN`, `REJECTED_DRY_RUN`), for the zone that decided |
| `ruxen_limit_conn_requests_total` | counter | `zone`, `status` | requests by `$limit_conn_status` (`PASSED`, `REJECTED`, `REJECTED_DRY_RUN`) |
| `ruxen_cache_requests_total` | counter | `zone`, `status` | requests by `$upstream_cache_status` (`MISS`, `BYPASS`, `EXPIRED`, `STALE`, `UPDATING`, `REVALIDATED`, `HIT`) |

Labels:

- `server`: the server block's first `server_name` (empty without one);
  `listen`: the address it listens on (`127.0.0.1:80`, `[::]:443`,
  `unix:/run/ruxen.sock`). A server block with two `listen` lines has a series
  for each.
- `upstream`: the `upstream {}` block's name, or the `host:port` of a
  `proxy_pass` without one; `peer`: the peer's address. A `proxy_pass` with
  variables that resolves a name at run time (`resolver`) isn't counted.
  The peers of a `server … resolve` line have series while some answer has
  their address: up to 64 addresses at once per `upstream` block (more aren't
  counted). An address that comes back counts from zero again.
- `zone`: the `limit_req_zone`, `limit_conn_zone` or `proxy_cache_path`
  `keys_zone` name.
- Label values are escaped as the format requires (`\\`, `\"`, `\n`).

The histogram's buckets are Prometheus's defaults: 5 ms to 10 s.

A request that ends before a server is chosen (a malformed request line, a
head that never completes) counts for the address's default server.

With several `limit_req` in a location, a request counts once, for the zone
whose limit decided it: the one that rejected it, the one that asked for the
longest delay, or the last one checked when it passed. With several
`limit_conn`, a request that passes counts in each zone, a rejected one in the
zone that rejected it. A `proxy_cache_background_update` request counts as
`EXPIRED` too.

## How the numbers behave

- Each worker thread counts into its own slots, without locked instructions;
  a scrape sums them, so it may see a worker's counts a moment old.
- **Reload**: the per-server and per-peer counters start again at zero with the
  new configuration (Prometheus treats that as a counter reset). The
  `ruxen_connections_*` and `ruxen_http_requests_total` counters belong to the
  process and carry on, as nginx's `stub_status` counters do. So do the counts
  of a `limit_req`, `limit_conn` or cache zone that the reload keeps (one
  declared the same way, as its state is kept); those zones count whether or
  not a location has `ruxen_metrics`.
- **Peer state**: with `zone` in the `upstream` block, `ruxen_upstream_peer_up`
  is what every worker sees. Without it each worker keeps its own failure
  counts, as each nginx worker process does, and the gauge shows the state of
  the worker that answered the scrape.

Not here: per-location series (their label sets would be unbounded), a push
exporter, and NGINX Plus's JSON API.
