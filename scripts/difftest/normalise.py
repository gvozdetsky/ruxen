"""What is compared, and what is not.

The normalisation is deliberately short; anything not listed here that
differs is reported:

- `Date` is dropped; `Server` is compared as `nginx`/`ruxen` without the
  version (ruxen runs with RUXEN_NGINX_IDENTITY=1 anyway).
- `Expires` is compared as an offset from `Date`: the two servers answer
  seconds apart.
- `Content-Length` and `Transfer-Encoding` are compared as the framing
  (length, chunked, to the close), not as values: the body is compared
  decoded.
- A gzip body is compared decompressed: zlib builds compress differently.
- Multipart boundaries, `$request_id` values (32 hex digits) and the
  current time in log-style formats are replaced by placeholders.
- Header names are compared lower-cased and sorted; the order of values of
  one name is kept.

File times need no rule: both servers serve the same sandbox, so
`Last-Modified` and `ETag` are the same files' and are compared.
"""

import email.utils
import gzip
import re
import zlib

DROP = {"date", "content-length", "transfer-encoding"}
REQUEST_ID = re.compile(rb"\b[0-9a-f]{32}\b")
TIME_PATTERNS = [
    (re.compile(rb"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}"), b"<time_local>"),
    (re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}"), b"<time_iso8601>"),
    (re.compile(rb"\b1\d{9}\.\d{3}\b"), b"<msec>"),
]
HTTP_DATE = re.compile(r"[A-Z][a-z]{2}, \d{2}[ -][A-Z][a-z]{2}[ -]\d{2,4} \d{2}:\d{2}:\d{2} GMT")


def _date(value):
    try:
        return email.utils.parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError):
        return None


def headers(r):
    """name -> [values], normalised."""
    out = {}
    date = None
    for n, v in r.get("headers", []):
        if n.lower() == "date":
            date = _date(v)
    boundary = _boundary(r)
    for n, v in r.get("headers", []):
        name = n.lower()
        if name in DROP:
            continue
        if name == "server":
            v = re.sub(r"^(nginx|ruxen)(/\S*)?", "<server>", v)
        elif name == "expires":
            t = _date(v)
            if t is not None and date is not None:
                v = f"Date{int(t - date):+d}s"
        elif name not in ("last-modified",):
            v = HTTP_DATE.sub("<date>", v)
        if boundary:
            v = v.replace(boundary, "<boundary>")
        v = REQUEST_ID.sub(b"<request_id>", v.encode("latin-1")).decode("latin-1")
        out.setdefault(name, []).append(v)
    return out


def _boundary(r):
    for n, v in r.get("headers", []):
        if n.lower() == "content-type":
            m = re.search(r"boundary=\"?([^\";]+)", v)
            if m:
                return m.group(1)
    return None


def body(r):
    """The body as compared: decoded, placeholders in."""
    b = r.get("body", b"")
    enc = ""
    for n, v in r.get("headers", []):
        if n.lower() == "content-encoding":
            enc = v.lower()
    if "gzip" in enc and b:
        try:
            b = gzip.decompress(b)
        except (OSError, EOFError, zlib.error):
            b = b"<undecodable gzip, %d bytes>" % len(b)
    boundary = _boundary(r)
    if boundary:
        b = b.replace(boundary.encode("latin-1"), b"<boundary>")
    b = REQUEST_ID.sub(b"<request_id>", b)
    for pat, rep in TIME_PATTERNS:
        b = pat.sub(rep, b)
    b = HTTP_DATE.sub("<date>", b.decode("latin-1")).encode("latin-1")
    return b


def brief(b, limit=160):
    s = b[:limit].decode("latin-1")
    s = s.encode("unicode_escape").decode("ascii")
    return s + ("…" if len(b) > limit else "") + f" ({len(b)} bytes)"


def outcome(r):
    if r.get("error"):
        return "error: " + r["error"]
    return "ok"


def raw_header(r, name):
    return [v for n, v in r.get("headers", []) if n.lower() == name]


def volatile(a, b):
    """Header names (and `upstream <name>`s) whose values differ between two
    answers of one server to the same request: `$pid`, `$remote_port`,
    `$connection` and the like. Not compared in that case."""
    out = set()
    ha, hb = headers(a), headers(b)
    out |= {n for n in set(ha) | set(hb) if ha.get(n) != hb.get(n)}
    ea, eb = echoed(body(a)), echoed(body(b))
    if ea and eb:
        out |= {f"upstream {n}" for n in set(ea[1]) | set(eb[1]) if ea[1].get(n) != eb[1].get(n)}
    return out


def compare(n_resps, n_after, r_resps, r_after, skip=frozenset()):
    """Differences of one request spec: [(class, field, nginx, ruxen)]. The
    first-level difference hides what follows from it (a different status
    brings different headers and body). `skip`: volatile fields."""
    diffs = []
    if len(n_resps) != len(r_resps):
        diffs.append(("connection", "responses", f"{len(n_resps)} responses, then {n_after}",
                      f"{len(r_resps)} responses, then {r_after}"))
    for i, (a, b) in enumerate(zip(n_resps, r_resps)):
        tag = f"#{i + 1} " if len(n_resps) > 1 else ""
        oa, ob = outcome(a), outcome(b)
        if (oa != "ok" or ob != "ok") and (oa, a.get("code")) != (ob, b.get("code")):
            diffs.append(("connection", tag + "response",
                          f"{a.get('code', '-')} {oa}", f"{b.get('code', '-')} {ob}"))
            return diffs
        if a.get("code") != b.get("code"):
            diffs.append(("status", tag + "status", str(a.get("code")), str(b.get("code"))))
            return diffs
        if a.get("status_line") != b.get("status_line"):
            diffs.append(("status", tag + "status line", a.get("status_line"), b.get("status_line")))
        if a["interim"] != b["interim"]:
            diffs.append(("interim", tag + "1xx", "; ".join(a["interim"]) or "(none)",
                          "; ".join(b["interim"]) or "(none)"))
        ha, hb = headers(a), headers(b)
        for name in sorted(set(ha) | set(hb)):
            va, vb = ha.get(name), hb.get(name)
            if name == "expires" and raw_header(a, name) == raw_header(b, name):
                # An absolute time (`expires epoch`, `@15h`) is the same; its offset from Date isn't.
                continue
            if va != vb and name not in skip:
                diffs.append(("header", tag + name, " | ".join(va) if va else "(absent)",
                              " | ".join(vb) if vb else "(absent)"))
        if a["framing"] != b["framing"]:
            diffs.append(("framing", tag + "framing", a["framing"], b["framing"]))
        ba, bb = body(a), body(b)
        if ba != bb:
            ea, eb = echoed(ba), echoed(bb)
            if ea and eb:
                diffs += [d for d in upstream_diffs(tag, ea, eb) if d[1][len(tag):] not in skip]
            else:
                diffs.append(("body", tag + "body", brief(ba), brief(bb)))
    n_after, r_after = settled(n_resps, n_after), settled(r_resps, r_after)
    if not diffs and n_after != r_after:
        diffs.append(("connection", "after the last response", n_after, r_after))
    return diffs


def echoed(b):
    """The request the echo upstream received, if the body is its answer:
    (request line, {name: [values]}, framing, body)."""
    head, sep, rest = b.partition(b"\n\n")
    lines = head.decode("latin-1").split("\n")
    if not sep or len(lines) < 2 or not lines[-1].startswith("framing: "):
        return None
    hs = {}
    for ln in lines[1:-1]:
        n, _, v = ln.partition(": ")
        hs.setdefault(n, []).append(v)
    return lines[0], hs, lines[-1][9:], rest


def upstream_diffs(tag, a, b):
    """What the proxy sent upstream, compared part by part."""
    out = []
    if a[0] != b[0]:
        out.append(("upstream", tag + "upstream request line", a[0], b[0]))
    for n in sorted(set(a[1]) | set(b[1])):
        va, vb = a[1].get(n), b[1].get(n)
        if va != vb:
            out.append(("upstream", tag + f"upstream {n}", " | ".join(va) if va else "(absent)",
                        " | ".join(vb) if vb else "(absent)"))
    if a[2] != b[2]:
        out.append(("upstream", tag + "upstream body framing", a[2], b[2]))
    if a[3] != b[3]:
        out.append(("upstream", tag + "upstream body", brief(a[3]), brief(b[3])))
    return out


def settled(resps, after):
    """A connection the response said it closes counts as closed while the
    server still drains it (nginx's lingering close)."""
    if after == "open" and resps and any(n.lower() == "connection" and v.lower() == "close"
                                         for n, v in resps[-1].get("headers", [])):
        return "closed"
    return after


def shape(cls, field, nv, rv):
    """The group a difference falls in: one root cause should show up once."""
    field = re.sub(r"^#\d+ ", "", field)
    if cls in ("header", "upstream") and field != "upstream request line":
        if nv == "(absent)":
            return f"{field}: only ruxen sends it"
        if rv == "(absent)":
            return f"{field}: ruxen doesn't send it"
        return f"{field}: value differs"
    if cls == "body":
        return "body differs"
    if field == "upstream request line":
        if "#" in nv and nv.split("#")[0] + " " + nv.rsplit(" ", 1)[-1] == rv:
            return "upstream request line: ruxen drops the #fragment"
        return "upstream request line differs"
    return f"{field}: nginx {nv}, ruxen {rv}"
