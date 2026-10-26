# Shadow mode: try ruxen on your traffic behind nginx

nginx stays in front and keeps answering every request. Its `mirror` module
sends a copy of each `GET` and `HEAD` to ruxen, which runs your configuration on
other ports; ruxen's answers are thrown away. Both servers write one JSON line
per request, keyed by nginx's `$request_id`, and
[`scripts/shadow-report.py`](../scripts/shadow-report.py) tells you where ruxen
answered differently: status, content type and encoding, redirects, body size,
upstream status.

Clients only ever see nginx's answers. What the shadow can still cost you is
listed under [What it costs](#what-it-costs); read it before you start.

Checked with nginx 1.30.6 in front and ruxen 0.2.2.

## 1. ruxen: your site on other ports

First see whether ruxen takes your configuration at all:

```bash
ruxen --compat -c /etc/nginx/nginx.conf
```

Then copy it (say to `/etc/ruxen/shadow/`) and change the copy:

- **Listeners.** Each `listen 80` becomes `listen 127.0.0.1:18080` and each
  `listen 443 ssl` becomes `listen 127.0.0.1:18443 ssl`, keeping the other
  parameters (`default_server`, `http2`, …). nginx passes the `Host` header on,
  so ruxen picks the same `server` block nginx did. Drop the `[::]` duplicates.
- **Redirects.** Add `port_in_redirect off;` to `http {}` when your site is on
  ports 80 and 443, or ruxen's absolute redirects carry `:18080`.
- **Client address.** ruxen sees every request coming from nginx. Replace
  your `real_ip_header` and `set_real_ip_from` lines with
  ```nginx
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  ```
  so `allow`/`deny`, `limit_req` and `geo` see the client's address.
- **Logs and files.** Give ruxen its own `pid`, `error_log` and log
  directory, and replace every `access_log` line (also `access_log off`) with
  `access_log /var/log/ruxen/shadow.log ruxen_shadow;`. Add the format to
  `http {}`:
  ```nginx
  log_format ruxen_shadow escape=json '{"id":"$http_x_shadow_request_id",'
      '"method":"$request_method","uri":"$request_uri","status":"$status",'
      '"bytes":"$body_bytes_sent","length":"$sent_http_content_length",'
      '"type":"$sent_http_content_type","encoding":"$sent_http_content_encoding",'
      '"location":"$sent_http_location","upstream_status":"$upstream_status"}';
  ```
- **Upstreams** can stay as they are: ruxen only gets `GET` and `HEAD`
  requests (see [side effects](#what-it-costs)). Point them at a staging copy
  of your application when even those change state.

```bash
ruxen -t -c /etc/ruxen/shadow/nginx.conf
ruxen -c /etc/ruxen/shadow/nginx.conf
```

## 2. nginx: mirror to ruxen

In `http {}`:

```nginx
log_format ruxen_shadow escape=json '{"id":"$request_id","mirrored":"$ruxen_mirrored",'
    '"method":"$request_method","uri":"$request_uri","status":"$status",'
    '"bytes":"$body_bytes_sent","length":"$sent_http_content_length",'
    '"type":"$sent_http_content_type","encoding":"$sent_http_content_encoding",'
    '"location":"$sent_http_location","upstream_status":"$upstream_status"}';

# Which requests go to ruxen: GET and HEAD.
map $request_method $ruxen_shadow {
    GET     1;
    HEAD    1;
    default 0;
}
# Set to 1 by the mirror location below when a request did go to ruxen.
map $ruxen_shadow $ruxen_mirrored {
    default 0;
}
map $scheme $ruxen_shadow_url {
    http  http://127.0.0.1:18080;
    https https://127.0.0.1:18443;
}
```

In each `server {}` to try:

```nginx
mirror /_ruxen_shadow;
mirror_request_body off;

location = /_ruxen_shadow {
    internal;
    if ($ruxen_shadow = 0) {
        return 204;
    }
    set $ruxen_mirrored 1;

    proxy_pass $ruxen_shadow_url$request_uri;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Shadow-Request-Id $request_id;
    proxy_ssl_server_name on;
    proxy_ssl_name $host;
    proxy_connect_timeout 1s;
    proxy_send_timeout 2s;
    proxy_read_timeout 2s;
}
```

And `access_log /var/log/nginx/shadow.log ruxen_shadow;` next to *every*
`access_log` line your configuration has. nginx uses the `access_log` lines of
the innermost level that has any, so a lone `access_log` added to a `server`
would end the logging the server inherited from `http`; several at one level
all write. With no `access_log` line at all, nginx logs to its default path
(`--http-log-path` in `nginx -V`): add both to `http {}`, the default as
`access_log /var/log/nginx/access.log;`.

```bash
nginx -t && nginx -s reload
```

Notes on the setup:

- `proxy_http_version 1.1` matters: over HTTP/1.0 ruxen would not gzip
  (`gzip_http_version 1.1`) and every compressed answer would differ.
- An `https` request goes to ruxen's TLS listener, so the shadow tries ruxen's
  TLS too, and `$scheme` and `$https` match. nginx doesn't verify ruxen's
  certificate (`proxy_ssl_verify off`, the default).
- nginx talks HTTP/1.1 to ruxen, so the shadow doesn't try ruxen's HTTP/2.
- `$ruxen_mirrored` works because a subrequest shares its parent's variables:
  the line nginx logs says whether ruxen got the request. Requests nginx
  answers before its content phase (`return`, `rewrite … redirect`, `deny`,
  `auth_basic`, a `limit_req` rejection) are never mirrored and log `"0"`.
- To try a share of the traffic only, sample by request:
  ```nginx
  split_clients $request_id $ruxen_sample {
      10%     1;
      *       0;
  }
  map $request_method:$ruxen_sample $ruxen_shadow {
      GET:1   1;
      HEAD:1  1;
      default 0;
  }
  ```

## 3. Compare

Let it run, then:

```bash
scripts/shadow-report.py /var/log/nginx/shadow.log /var/log/ruxen/shadow.log
```

From a test setup, with nginx on port 19000 (hence the redirects):

```text
## ruxen shadow report

- nginx answered 40 requests; 36 were mirrored to ruxen
- compared: 36; the same: 30 (83.3%); different: 6
- no ruxen answer for 0 mirrored requests (ruxen down or too slow, or the logs cover different periods)
- 3 requests were mirrored twice (an internal redirect in nginx); the first answer is compared

### Differences

| field | requests | nginx → ruxen, commonest |
| --- | --- | --- |
| location | 6 | `http://127.0.0.1:19000/dir/` → `http://127.0.0.1/dir/` (2); … |

### Not compared

- 5: compressed bodies: zlib builds compress differently, so sizes are not compared
- 5: the server's own error pages: they carry the server's name and version

### location: first 2

| request | nginx | ruxen | id |
| --- | --- | --- | --- |
| `GET /dir` | `301 location=http://127.0.0.1:19000/dir/ size=169` | `301 location=http://127.0.0.1/dir/ size=168` | 03a64aba2977b422875e041edcab0441 |
| `GET /api/redir` | `302 location=http://127.0.0.1:19000/api/index.html size=145` | `302 location=http://127.0.0.1/api/index.html size=145` | 304d017f0fdd9693dc63ed2fd4c3c85d |
```

Every field both formats log is compared, so a field you add to both (say
`"cache_control":"$sent_http_cache_control"`) is compared too;
`--ignore FIELD,...` leaves fields out. Rotated `.gz` logs are fine. The body
size is compared as declared (`Content-Length`) or else as sent, and not at
all where it can't be:

- **compressed bodies**: nginx's zlib and ruxen's zlib-rs compress the same
  page to different sizes;
- **bodies the mirror stopped reading**: nginx closes the shadow connection
  once it has the response header, so ruxen logs only what it sent until then
  (bodies over about 64 KB, on loopback);
- **the server's own error pages**, which carry its name and version.

A request is also skipped when either side logged `499`: the client gave up
on nginx, or nginx on ruxen (`proxy_read_timeout`).

## What it costs

- **Side effects.** A mirrored `GET` reaches your application twice: once
  through nginx, once through ruxen. Most `GET`s are safe to repeat; ones that
  count views, touch sessions or fire analytics are not. The application sees
  the copy's `X-Shadow-Request-Id` header and can skip such effects, or the
  shadow's upstreams can point at a staging copy. Bodies are never mirrored
  (`mirror_request_body off`; `POST`s get `204` from the mirror location
  without reaching ruxen).
- **Load.** Each mirrored request is one more request for the application,
  a new connection from nginx to ruxen, and, for `https`, a TLS handshake.
  Sample with `split_clients` to lower it.
- **Latency on keep-alive connections.** nginx sends the client its answer at
  once, but it doesn't read the client's next request on that connection
  before the mirror is done. If ruxen hangs, that next request waits up to
  `proxy_read_timeout` (measured: 1.0 s with a 1 s timeout; nothing extra
  when ruxen answers or isn't running). Requests on an HTTP/2 connection
  don't wait for each other. Keep `proxy_read_timeout` a little above your
  application's slowest normal answer, since ruxen waits for it too.
- **Error log.** Each mirrored request ruxen doesn't answer adds an `[error]`
  line to nginx's error log, with `subrequest: "/_ruxen_shadow"` (for
  example `connect() failed (111: Connection refused)` while ruxen is
  stopped). A subrequest can't have an `error_log` of its own.
- **Double mirroring.** After an internal redirect (`error_page`, for
  one), nginx mirrors the request again with the same id. The
  report compares the first answer and counts the others.

To stop, remove the `mirror` lines and reload nginx.

## Privacy and reporting

The logs and the report stay on your machine; nothing is sent anywhere. To
share a report, run it with `--hash-paths`: URIs and `Location` values are
printed with their host, path and query hashed (`http://h:12ca17b4:19000/h:5a37d6dc`),
so a difference in the scheme or the port still shows.

Please open an issue with the report, `ruxen -V`, `nginx -V`, and the part of
your configuration behind each difference. A report with no differences helps
too: it tells us ruxen ran on real traffic.
