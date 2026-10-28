"""Requests: the paths a case names, plus variations around what edge configs
branch on. Seeded per case, so a difference replays with the same seed."""

import random

LONG = "a" * 9000


def req(method, target, headers=(), body=b"", version="HTTP/1.1"):
    """A request as bytes; headers are (name, value) pairs sent verbatim."""
    line = f"{method} {target} {version}\r\n" if version else f"{method} {target}\r\n"
    head = line + "".join(f"{n}: {v}\r\n" for n, v in headers)
    if version is None:
        return line.encode("latin-1")
    return (head + "\r\n").encode("latin-1") + body


def chunked(*parts, trailer=""):
    out = b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in parts)
    return out + b"0\r\n" + trailer.encode() + b"\r\n"


def single(data, head=False):
    return [(data, 1, head)]


# Path variations: (id, function of a path).
PATHS = [
    ("plain", lambda p: p),
    ("args", lambda p: p + "?a=1&b=%20x"),
    ("frag", lambda p: p + "#frag"),
    ("dot-seg", lambda p: "/./" + p.lstrip("/")),
    ("dotdot", lambda p: "/x/../" + p.lstrip("/")),
    ("dotdot-escaped", lambda p: "/x/%2e%2e/" + p.lstrip("/")),
    ("dotdot-root", lambda p: "/../" + p.lstrip("/")),
    ("double-slash", lambda p: "/" + p.replace("/", "//")),
    ("slash-escaped", lambda p: p.rstrip("/") + "%2Fx"),
    ("trailing-slash", lambda p: p.rstrip("/") + "/"),
    ("trailing-dot", lambda p: p.rstrip("/") + "/."),
    ("no-trailing-slash", lambda p: p.rstrip("/") or "/"),
    ("pct-letter", lambda p: p.replace("e", "%65", 1) if "e" in p else p + "%41"),
    ("pct-bad", lambda p: p + "%zz"),
    ("pct-trunc", lambda p: p + "%4"),
    ("pct-nul", lambda p: p + "%00x"),
    ("utf8", lambda p: p.rstrip("/") + "/caf%C3%A9"),
    ("pct-latin1", lambda p: p.rstrip("/") + "/caf%E9"),
    ("raw-high", lambda p: p.rstrip("/") + "/caf\xe9"),
    ("backslash", lambda p: p.rstrip("/") + "\\x"),
    ("semicolon", lambda p: p.rstrip("/") + ";jsessionid=1"),
    ("upper", lambda p: p.upper()),
    ("index", lambda p: p.rstrip("/") + "/index.html"),
    ("missing", lambda p: p.rstrip("/") + "/no-such-file.txt"),
    ("long", lambda p: p + "?" + LONG),
    ("star", lambda p: "*"),
    ("no-slash", lambda p: p.lstrip("/") or "x"),
]

DATE_PAST = "Thu, 01 Jan 1970 00:00:01 GMT"
DATE_FUTURE = "Fri, 01 Jan 2100 00:00:00 GMT"


def host_variants(host, port):
    return [
        ("host-port", [("Host", f"{host}:{port}")]),
        ("host-upper", [("Host", host.upper())]),
        ("host-dot", [("Host", host + ".")]),
        ("host-other", [("Host", "other.example")]),
        ("host-ip", [("Host", "127.0.0.1")]),
        ("host-bad", [("Host", "bad/host")]),
        ("host-empty", [("Host", "")]),
        ("host-twice", [("Host", host), ("Host", host)]),
        ("host-badport", [("Host", f"{host}:x")]),
        ("host-v6", [("Host", "[::1]")]),
    ]


HEADER_VARIANTS = [
    ("ae-gzip", [("Accept-Encoding", "gzip")]),
    ("ae-gzip-q0", [("Accept-Encoding", "gzip;q=0")]),
    ("ae-many", [("Accept-Encoding", "br, gzip, deflate")]),
    ("ae-star", [("Accept-Encoding", "*")]),
    ("range-first", [("Range", "bytes=0-0")]),
    ("range-suffix", [("Range", "bytes=-5")]),
    ("range-open", [("Range", "bytes=5-")]),
    ("range-multi", [("Range", "bytes=0-1,3-4")]),
    ("range-overlap", [("Range", "bytes=0-5,2-8")]),
    ("range-beyond", [("Range", "bytes=1000000-")]),
    ("range-inverted", [("Range", "bytes=5-2")]),
    ("range-bad", [("Range", "bytes=abc")]),
    ("range-unit", [("Range", "items=0-1")]),
    ("range-gzip", [("Range", "bytes=0-9"), ("Accept-Encoding", "gzip")]),
    ("if-range-etag", [("Range", "bytes=0-3"), ("If-Range", "{etag}")]),
    ("if-range-date", [("Range", "bytes=0-3"), ("If-Range", "{last_modified}")]),
    ("if-range-stale", [("Range", "bytes=0-3"), ("If-Range", '"stale"')]),
    ("inm-match", [("If-None-Match", "{etag}")]),
    ("inm-weak", [("If-None-Match", "W/{etag}")]),
    ("inm-list", [("If-None-Match", '"a", {etag}')]),
    ("inm-star", [("If-None-Match", "*")]),
    ("inm-other", [("If-None-Match", '"other"')]),
    ("ims-same", [("If-Modified-Since", "{last_modified}")]),
    ("ims-past", [("If-Modified-Since", DATE_PAST)]),
    ("ims-future", [("If-Modified-Since", DATE_FUTURE)]),
    ("ims-bad", [("If-Modified-Since", "yesterday")]),
    ("ims-inm", [("If-Modified-Since", "{last_modified}"), ("If-None-Match", '"other"')]),
    ("im-match", [("If-Match", "{etag}")]),
    ("im-other", [("If-Match", '"other"')]),
    ("ius-past", [("If-Unmodified-Since", DATE_PAST)]),
    ("upgrade-ws", [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Version", "13"),
                    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")]),
    ("upgrade-h2c", [("Upgrade", "h2c"), ("Connection", "Upgrade, HTTP2-Settings"), ("HTTP2-Settings", "")]),
    ("expect-unknown", [("Expect", "something")]),
    ("cookie", [("Cookie", "a=1; b=2")]),
    ("xff", [("X-Forwarded-For", "10.0.0.1, 10.0.0.2")]),
    ("underscore", [("X_Under", "1")]),
    ("space-before-colon", [("X-Bad ", "1")]),
    ("obs-fold", [("X-Fold", "a\r\n b")]),
    ("long-header", [("X-Long", LONG)]),
    ("many-cookies", [("Cookie", f"c{i}=v{i}") for i in range(8)]),
    ("te-gzip", [("Transfer-Encoding", "gzip")]),
    ("te-identity", [("Transfer-Encoding", "identity")]),
    ("cl-bad", [("Content-Length", "abc")]),
    ("cl-negative", [("Content-Length", "-1")]),
    ("cl-huge", [("Content-Length", "99999999999999999999")]),
    ("cl-big", [("Content-Length", "2000000")]),
    ("accept", [("Accept", "application/json")]),
    ("auth", [("Authorization", "Basic dXNlcjpoZWxsbw==")]),
    ("origin", [("Origin", "http://other.example")]),
    ("connection-ka", [("Connection", "keep-alive")]),
    ("connection-token", [("Connection", "close, X-Hop"), ("X-Hop", "1")]),
]

METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "PROPFIND", "get", "FOO",
           "CONNECT"]


def with_conn(headers):
    if any(n.lower() == "connection" for n, _ in headers):
        return list(headers)
    return list(headers) + [("Connection", "close")]


def catalogue(host, port, path):
    """Every variation family once, on one path."""
    H = [("Host", host)]
    out = []
    for vid, f in PATHS:
        out.append((f"path:{vid}", single(req("GET", f(path), with_conn(H)))))
    for vid, hs in host_variants(host, port):
        out.append((f"host:{vid}", single(req("GET", path, with_conn(hs)))))
    out.append(("host:none-1.1", single(req("GET", path, with_conn([])))))
    out.append(("host:absolute-uri", single(req("GET", f"http://{host}{path}", with_conn([("Host", "x.example")])))))
    out.append(("host:absolute-uri-port", single(req("GET", f"http://{host}:{port}{path}", with_conn([])))))
    out.append(("host:absolute-uri-https", single(req("GET", f"https://{host}{path}", with_conn([])))))
    for vid, hs in HEADER_VARIANTS:
        out.append((f"hdr:{vid}", single(req("GET", path, with_conn(H + hs)))))
    for m in METHODS:
        out.append((f"method:{m}", single(req(m, path, with_conn(H)), head=(m == "HEAD"))))
    out.append(("method:HEAD-range", single(req("HEAD", path, with_conn(H + [("Range", "bytes=0-1")])), head=True)))
    out.append(("method:HEAD-gzip", single(req("HEAD", path, with_conn(H + [("Accept-Encoding", "gzip")])),
                                           head=True)))
    out += bodies(H, path)
    out += versions(host, path)
    out += sequences(H, path)
    return out


def bodies(H, path):
    out = []
    for m in ("POST", "PUT", "GET"):
        out.append((f"body:{m}-length", single(req(m, path, with_conn(H + [("Content-Length", "5")]), b"hello"))))
    out.append(("body:POST-chunked", single(req("POST", path, with_conn(H + [("Transfer-Encoding", "chunked")]),
                                                 chunked(b"hel", b"lo")))))
    out.append(("body:POST-chunked-trailer",
                single(req("POST", path, with_conn(H + [("Transfer-Encoding", "chunked")]),
                           chunked(b"hello", trailer="X-Trailer: 1\r\n")))))
    out.append(("body:POST-chunked-ext", single(req("POST", path, with_conn(H + [("Transfer-Encoding", "chunked")]),
                                                     b"5;ext=1\r\nhello\r\n0\r\n\r\n"))))
    out.append(("body:POST-chunked-bad", single(req("POST", path, with_conn(H + [("Transfer-Encoding", "chunked")]),
                                                     b"zz\r\nhello\r\n0\r\n\r\n"))))
    out.append(("body:POST-te-cl", single(req("POST", path, with_conn(H + [("Content-Length", "3"),
                                                                           ("Transfer-Encoding", "chunked")]),
                                             chunked(b"hello")))))
    out.append(("body:POST-cl-twice-same", single(req("POST", path, with_conn(H + [("Content-Length", "5")] * 2),
                                                       b"hello"))))
    out.append(("body:POST-cl-twice-diff", single(req("POST", path, with_conn(H + [("Content-Length", "5"),
                                                                                   ("Content-Length", "6")]),
                                                       b"hello!"))))
    out.append(("body:POST-no-length", single(req("POST", path, with_conn(H)))))
    out.append(("body:POST-large", single(req("POST", path, with_conn(H + [("Content-Length", "70000")]),
                                               b"x" * 70000))))
    head = req("POST", path, with_conn(H + [("Content-Length", "5"), ("Expect", "100-continue")]))
    out.append(("body:expect-100", [(head, 0, False), (b"hello", 1, False, 0.2)]))
    out.append(("body:expect-100-1.0", single(req("POST", path, H + [("Content-Length", "5"),
                                                                       ("Expect", "100-continue")],
                                                   b"hello", "HTTP/1.0"))))
    return out


def versions(host, path):
    H = [("Host", host)]
    return [
        ("version:1.0", single(req("GET", path, [], version="HTTP/1.0"))),
        ("version:1.0-host", single(req("GET", path, H, version="HTTP/1.0"))),
        ("version:0.9", single(req("GET", path, version=None))),
        ("version:1.2", single(req("GET", path, with_conn(H), version="HTTP/1.2"))),
        ("version:2.0", single(req("GET", path, with_conn(H), version="HTTP/2.0"))),
        ("version:lower", single(req("GET", path, with_conn(H), version="http/1.1"))),
        ("version:bad", single(req("GET", path, with_conn(H), version="HTTP/1"))),
        ("version:3", single(req("GET", path, with_conn(H), version="HTTP/3.0"))),
        ("line:two-spaces", single(f"GET  {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())),
        ("line:tab", single(f"GET\t{path}\tHTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())),
        ("line:lf-only", single(f"GET {path} HTTP/1.1\nHost: {host}\nConnection: close\n\n".encode())),
        ("line:leading-crlf", single(f"\r\nGET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                                     .encode())),
        ("line:space-in-uri", single(f"GET {path} x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())),
        ("line:control", single(f"GET {path}\x02 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())),
    ]


def sequences(H, path):
    ka = req("GET", path, H)
    close = req("GET", path, H + [("Connection", "close")])
    post = req("POST", path, H + [("Content-Length", "5")], b"hello")
    head = req("HEAD", path, H)
    return [
        ("ka:get-get", [(ka, 1, False), (close, 1, False)]),
        ("ka:head-get", [(head, 1, True), (close, 1, False)]),
        ("ka:post-get", [(post, 1, False), (close, 1, False)]),
        ("ka:open", [(ka, 1, False)]),
        ("ka:1.0-keepalive", [(req("GET", path, H + [("Connection", "keep-alive")], version="HTTP/1.0"), 1, False),
                              (close, 1, False)]),
        ("ka:pipelined", [(ka + head + close, 3, [False, True, False])]),
        ("ka:unread-body", [(req("POST", path, H + [("Content-Length", "5")]) + b"hel", 0, False),
                            (b"lo" + close, 2, False, 0.1)]),
    ]


def generate(seed, case_id, host, port, paths, n_random):
    """[(request id, steps)]: each path plainly, the catalogue on the first
    path, then `n_random` random combinations."""
    rng = random.Random(f"{seed}:{case_id}:{host}")
    out = []
    for p in paths:
        out.append((f"base:{p}", single(req("GET", p, with_conn([("Host", host)])))))
    out += [(f"{vid}@{paths[0]}", steps) for vid, steps in catalogue(host, port, paths[0])]
    # Path handling is where locations differ: the path variations on a few more.
    for p in paths[1:5]:
        out += [(f"path:{vid}@{p}", single(req("GET", f(p), with_conn([("Host", host)])))) for vid, f in PATHS]
    hosts = host_variants(host, port)
    for i in range(n_random):
        p = rng.choice(paths)
        pid, pf = rng.choice(PATHS)
        m = rng.choice(["GET"] * 6 + ["HEAD", "POST", "OPTIONS"])
        hs = [("Host", host)]
        tags = [pid, m]
        if rng.random() < 0.2:
            hid, hs = rng.choice(hosts)
            tags.append(hid)
        for _ in range(rng.choice([0, 1, 1, 2])):
            hid, extra = rng.choice(HEADER_VARIANTS)
            hs = hs + extra
            tags.append(hid)
        body = b""
        if m == "POST":
            hs = hs + [("Content-Length", "5")]
            body = b"hello"
        version = "HTTP/1.0" if rng.random() < 0.1 else "HTTP/1.1"
        if version == "HTTP/1.0":
            tags.append("1.0")
        data = req(m, pf(p), with_conn(hs) if version == "HTTP/1.1" else hs, body, version)
        out.append((f"rand{i}:{'+'.join(tags)}@{p}", single(data, head=(m == "HEAD"))))
    return out


def fill(steps, validators):
    """Substitutes `{etag}`/`{last_modified}` with what the server sent for a
    plain GET of the path; a request that needs one the server didn't send
    gets a fixed value."""
    etag = validators.get("etag") or '"none"'
    lm = validators.get("last_modified") or DATE_PAST
    return [(d.replace(b"{etag}", etag.encode("latin-1")).replace(b"{last_modified}", lm.encode("latin-1")),)
            + tuple(rest) for d, *rest in steps]
