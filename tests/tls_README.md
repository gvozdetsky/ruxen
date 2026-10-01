# Manual TLS repro recipes

Curl/openssl invocations used while developing the HTTPS path. Keep this
in sync with `tests/tls.rs` so a regression caught in CI can be
reproduced by hand without re-deriving the flags.

## Starting a one-off HTTPS server

Generate a self-signed cert with `openssl` (or use the rcgen-based test
harness — see `tests/common/tls.rs`):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/key.pem \
    -out /tmp/cert.pem -days 1 -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost'
```

Minimal `bench/tls/nginx.conf` (shared between nginx and ruxen):

```nginx
daemon off;
events { }
http {
    server {
        listen 127.0.0.1:8443 ssl;
        server_name localhost;
        ssl_certificate     /tmp/cert.pem;
        ssl_certificate_key /tmp/key.pem;
        location / { return 200 "ok\n"; }
    }
}
```

Run:

```bash
cargo run --release -- -c bench/tls/nginx.conf
```

## Smoke (matches `tls::smoke`)

```bash
curl -kv --http1.1 https://127.0.0.1:8443/
```

`-k` skips verification (self-signed); drop it and pass `--cacert ca.pem`
once you're testing a CA-issued chain.

## SNI dispatch (matches `tls::sni_dispatch`)

Pin the SNI name to loopback so two `server_name` blocks on the same
listen address can be hit independently:

```bash
curl -kv --resolve a.example:8443:127.0.0.1 https://a.example:8443/
curl -kv --resolve b.example:8443:127.0.0.1 https://b.example:8443/
```

To inspect which cert was actually served (CN/SAN), use `openssl
s_client`:

```bash
openssl s_client -connect 127.0.0.1:8443 -servername a.example \
    -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

## Wildcard SNI (matches `tls::wildcard_sni`)

Cert SAN is `*.example.test`. Request any single-label subdomain:

```bash
curl -kv --resolve foo.example.test:8443:127.0.0.1 \
    https://foo.example.test:8443/
```

Use a single-label subdomain for the verification path. Ruxen's SNI
resolver can select the wildcard cert for broader suffix matches, but
normal clients still apply their own certificate-name validation rules.

## ALPN (matches `tls::alpn_http11`)

Force the client to advertise both protocols and check what gets
selected:

```bash
openssl s_client -connect 127.0.0.1:8443 -alpn h2,http/1.1 \
    -servername localhost </dev/null 2>&1 | grep -i 'ALPN protocol'
```

Should print `ALPN protocol: http/1.1`; ruxen does not advertise HTTP/2.

For an `h2`-only client, rustls completes the TLS handshake with no ALPN
protocol selected because ruxen only advertises `http/1.1`:

```bash
openssl s_client -connect 127.0.0.1:8443 -alpn h2 \
    -servername localhost </dev/null
```

## Host vs SNI precedence (matches `tls::host_overrides_sni`)

SNI picks the cert; the HTTP `Host:` header picks the `server { … }`
block for routing. Easiest way to verify is to send a hand-crafted
request with mismatched `--resolve` and `-H Host:`:

```bash
curl -kv --resolve a.example:8443:127.0.0.1 \
    -H 'Host: b.example' https://a.example:8443/which-server
```

Expected: cert returned is `a.example`'s, but the response body comes
from the `server_name b.example` block.

## Bench (mirror of `bench/m1` for HTTPS)

Long-form lives in [`bench/tls/RESULTS.md`](../bench/tls/RESULTS.md). Quick smoke:

```bash
wrk -t8 -c128 -d10s --latency \
    --header 'Host: localhost' \
    https://127.0.0.1:8443/
```

`wrk` accepts self-signed by default. Use `wrk2` if you want a fixed
request rate for tail-latency comparisons.

## Useful one-liners

- Print negotiated TLS version + cipher:
  ```bash
  openssl s_client -connect 127.0.0.1:8443 -servername localhost \
      </dev/null 2>/dev/null | grep -E 'Protocol|Cipher\s+:'
  ```
- Dump full handshake (client side):
  ```bash
  openssl s_client -connect 127.0.0.1:8443 -servername localhost \
      -msg -state </dev/null
  ```
- Watch what ruxen logs during a handshake (tail the error log):
  ```bash
  tail -F /tmp/ruxen-error.log &
  curl -kv https://127.0.0.1:8443/
  ```
