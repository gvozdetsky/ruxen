# TLS bench — `tls_hello`

Steady-state HTTPS throughput and fresh-handshake rate against an
`return 200 "hello"` config. Both servers terminate TLS 1.3 with the same
ECDSA P-256 cert, listen on the same port, and serve the same 5-byte body
— the only difference under test is the TLS stack (rustls in ruxen,
OpenSSL in nginx).

## Files

- `nginx.conf` — shared by both ruxen and nginx: `listen 8443 ssl`,
  `ssl_protocols TLSv1.3;`, 5-byte return, `access_log off`.
- `generate.sh` — emits `/tmp/ruxen-bench-tls/{cert,key}.pem` (ECDSA
  P-256, SAN = `localhost`,`127.0.0.1`, 365-day validity). Runs at
  bench-time via the harness's `prepare_script` hook — the cert lives
  outside the repo and is regenerated when missing.

## Fairness

- **Same cert, same key.** Both servers load the same PEM files, so RSA
  vs ECDSA, key size, and chain depth aren't variables.
- **Same port (8443).** ABBA runs are sequential, so port collision
  isn't a problem; same port keeps client-side state identical.
- **TLS 1.3 only.** Both servers refuse anything older. Eliminates
  TLS 1.2 vs 1.3 negotiation as a confound.
- **Cipher: negotiated, observed identical.** The plan called for
  pinning to `TLS_AES_128_GCM_SHA256`. ruxen has no cipher-pinning
  knob (rustls's `ssl_ciphers` directive only covers TLS 1.2). With
  defaults on both sides, OpenSSL (client and nginx) and rustls both
  prefer `TLS_AES_256_GCM_SHA384` first, so that's what gets
  negotiated by both servers — verified via `openssl s_client`.
  Comparing the same crypto path is the property that mattered;
  forcing AES-128 instead of AES-256 was incidental.
- **Same workload tool.** `wrk -t16 -c512 -d30s --latency` for
  steady-state, ABBA-ordered. A Python `ssl` loop for handshake-only
  rate (see "Handshake measurement").

## Steady-state throughput

Driven by the existing harness:

```
./bench/scripts/run_all.sh --scenario tls_hello --server both \
    --variants workers_32 --server-order nginx-first \
    --output-dir /tmp/abba_tls
./bench/scripts/run_all.sh --scenario tls_hello --server both \
    --variants workers_32 --server-order ruxen-first \
    --output-dir /tmp/abba_tls
```

Numbers are in [`bench/RESULTS.md`](../RESULTS.md) under "TLS — hello".

## Handshake measurement

The plan asked for `openssl s_time -new -time 10`. Against nginx that
works fine; against ruxen, `s_time` aborts partway through every run
with a stderr `ERROR` from the OpenSSL client — consistent symptom on
TLS 1.3 *and* TLS 1.2, with or without `-www`. Ruxen logs no errors
during these runs; the failure is on the client side. Pending
investigation; `openssl s_time` numbers for ruxen are therefore
unreliable.

To still get a fair comparison we use a small Python `ssl`-stdlib loop
(`/tmp/hs_rate.py`) that opens a fresh TCP connection, drives a
TLS 1.3 handshake to completion, and closes — repeating in parallel
for a fixed wall-clock window. Numbers reported in `RESULTS.md`.
This isn't OpenSSL's hyper-tuned `s_time` so absolute numbers will be
lower than `s_time` would give, but the *ratio* between the two
servers under the same client is the meaningful signal.

## Known caveats

- Loopback bench: client and server contend for the same CPU; absolute
  numbers underestimate what either server would do over a NIC.
- ECDSA P-256 cert. RSA-2048 (and RSA-4096) numbers will differ
  materially because RSA private-key ops dominate handshake CPU.
- No session-resumption pass on the steady-state workload — wrk holds
  512 connections open for 30s, so all TLS-handshake cost is paid in
  the first ~ms and amortized over millions of requests. Expect the
  TLS overhead to bite harder on workloads with shorter connection
  lifetimes.
