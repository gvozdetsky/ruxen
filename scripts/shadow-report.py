#!/usr/bin/env python3
"""Shadow report: where ruxen answered a site's real traffic differently.

    scripts/shadow-report.py NGINX_LOG RUXEN_LOG [--examples N] [--hash-paths]
                             [--ignore FIELD,...]

Reads the two `ruxen_shadow` access logs of a shadow setup (docs/shadow.md):
nginx in front mirrors requests to ruxen, both log one JSON object per
request, joined by nginx's `$request_id`. Prints, as Markdown that can be
pasted into an issue, how many answers agree, the differences per field
with the commonest value pairs, and the first requests of each. Logs may be
gzip-compressed (`.gz`). Nothing is sent anywhere.

Every field both sides log is compared, so a field added to both
`log_format`s (say `"cache_control":"$sent_http_cache_control"`) is
compared too. The body size is compared as declared (`length`, the
Content-Length) or else as sent (`bytes`), and not at all where it can't
be: compressed bodies, bodies the mirror stopped reading, and the server's
own error pages, which carry its name and version.

See issue #751.
"""

import argparse
import collections
import gzip
import hashlib
import json
import sys
import urllib.parse

# Fields that identify a request rather than describe the answer.
NOT_COMPARED = {"id", "mirrored", "bytes", "length"}
# Fields whose values are paths or URLs: hashed with --hash-paths.
PATH_FIELDS = {"uri", "location"}

# Why a pair wasn't compared, in report order.
SKIPPED = {
    "compressed": "compressed bodies: zlib builds compress differently, so sizes are not compared",
    "cut": "bodies the mirror stopped reading (nginx closes the shadow connection after the response header)",
    "error_page": "the server's own error pages: they carry the server's name and version",
    "nginx_499": "the client closed the connection before nginx answered (nginx logged 499)",
    "ruxen_499": "nginx gave up on the shadow before ruxen answered (ruxen logged 499: proxy_read_timeout)",
}


def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def read_log(path, stats, side):
    """Yields the JSON entries of a log; counts the lines that aren't."""
    with open_log(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                stats[f"{side}_unparsed"] += 1
                continue
            if isinstance(entry, dict) and entry.get("id"):
                yield entry
            else:
                stats[f"{side}_no_id"] += 1


def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def compare_size(n, r):
    """None when the body sizes agree, a SKIPPED key when they can't be
    compared, "size" when they differ."""
    n_size = n.get("length") or n.get("bytes")
    r_size = r.get("length") or r.get("bytes")
    if n_size == r_size:
        return None
    if n.get("encoding") and n.get("encoding") == r.get("encoding"):
        return "compressed"
    n_bytes, r_bytes = number(n.get("bytes")), number(r.get("bytes"))
    if not r.get("length") and n_bytes is not None and r_bytes is not None and r_bytes < n_bytes:
        return "cut"
    status = number(n.get("status")) or 0
    if status >= 300 and not n.get("upstream_status") and not r.get("upstream_status"):
        return "error_page"
    return "size"


def compare(n, r, ignore):
    """(differing fields, reason the pair was skipped or None)."""
    if n.get("status") == "499":
        return [], "nginx_499"
    if r.get("status") == "499":
        return [], "ruxen_499"
    fields = sorted(k for k in n.keys() & r.keys() if k not in NOT_COMPARED and k not in ignore)
    diffs = [k for k in fields if n[k] != r[k]]
    skipped = None
    if "status" not in diffs and "size" not in ignore:
        verdict = compare_size(n, r)
        if verdict == "size":
            diffs.append("size")
        else:
            skipped = verdict
    return diffs, skipped


def size_of(entry):
    length, sent = entry.get("length"), entry.get("bytes")
    if length and length != sent:
        return f"{length} (sent {sent})"
    return length or sent or "-"


def shown(field, value, hash_paths):
    if value in (None, ""):
        return "-"
    if hash_paths and field in PATH_FIELDS:
        return hash_url(value)
    value = str(value)
    return value if len(value) <= 60 else value[:57] + "..."


def hash_url(url):
    """The URL with its host, path and query hashed, so that a difference
    in the scheme or the port still shows."""
    h = lambda text: "h:" + hashlib.sha256(text.encode()).hexdigest()[:8]  # noqa: E731
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return h(url)
    out = ""
    if parts.scheme:
        out += parts.scheme + "://"
    if parts.hostname:
        out += h(parts.hostname) + (f":{port}" if port else "")
    if parts.path in ("", "/"):
        out += parts.path
    else:
        out += "/" + h(parts.path)
    if parts.query:
        out += "?" + h(parts.query)
    return out


def value_of(entry, field, hash_paths):
    if field == "size":
        return size_of(entry)
    return shown(field, entry.get(field), hash_paths)


def report(nginx_log, ruxen_log, examples, hash_paths, ignore, out):
    stats = collections.Counter()
    shadow = {}
    for entry in read_log(ruxen_log, stats, "ruxen"):
        if entry["id"] in shadow:
            # nginx mirrors again after an internal redirect (error_page,
            # for one): the same request, answered twice.
            stats["twice"] += 1
            continue
        shadow[entry["id"]] = entry

    pairs = collections.defaultdict(collections.Counter)
    samples = collections.defaultdict(list)
    sampled = collections.defaultdict(set)
    seen = set()
    for n in read_log(nginx_log, stats, "nginx"):
        stats["nginx"] += 1
        if n.get("mirrored", "1") in ("0", ""):
            stats["not_mirrored"] += 1
            continue
        r = shadow.get(n["id"])
        if r is None:
            stats["no_answer"] += 1
            continue
        seen.add(n["id"])
        diffs, skipped = compare(n, r, ignore)
        if skipped:
            stats["skip_" + skipped] += 1
        if not diffs:
            stats["same"] += 1
            continue
        stats["different"] += 1
        for field in diffs:
            pairs[field][(value_of(n, field, hash_paths), value_of(r, field, hash_paths))] += 1
            # One example per request line: the same URL a hundred times
            # says less than five URLs.
            line = (n.get("method"), n.get("uri"))
            if len(samples[field]) < examples and line not in sampled[field]:
                sampled[field].add(line)
                samples[field].append((n, r))
    shadow_only = len(shadow.keys() - seen)

    p = lambda *a: print(*a, file=out)  # noqa: E731
    compared = stats["same"] + stats["different"]
    mirrored = stats["nginx"] - stats["not_mirrored"]
    p("## ruxen shadow report")
    p()
    p(f"- nginx answered {stats['nginx']} requests; {mirrored} were mirrored to ruxen")
    p(f"- compared: {compared}; the same: {stats['same']} ({percent(stats['same'], compared)}); "
      f"different: {stats['different']}")
    p(f"- no ruxen answer for {stats['no_answer']} mirrored requests "
      "(ruxen down or too slow, or the logs cover different periods)")
    if shadow_only:
        p(f"- {shadow_only} ruxen answers have no nginx entry (the logs cover different periods)")
    if stats["twice"]:
        p(f"- {stats['twice']} requests were mirrored twice (an internal redirect in nginx); "
          "the first answer is compared")
    for side in ("nginx", "ruxen"):
        if stats[f"{side}_unparsed"] or stats[f"{side}_no_id"]:
            p(f"- {side} log: {stats[f'{side}_unparsed']} lines are not JSON, "
              f"{stats[f'{side}_no_id']} have no id (not from the mirror)")

    p()
    p("### Differences")
    p()
    if not pairs:
        p("None.")
    else:
        p("| field | requests | nginx → ruxen, commonest |")
        p("| --- | --- | --- |")
        for field, counter in sorted(pairs.items(), key=lambda kv: -sum(kv[1].values())):
            top = "; ".join(f"`{a}` → `{b}` ({c})" for (a, b), c in counter.most_common(3))
            p(f"| {field} | {sum(counter.values())} | {top} |")

    skipped = [(key, stats["skip_" + key]) for key in SKIPPED if stats["skip_" + key]]
    if skipped:
        p()
        p("### Not compared")
        p()
        for key, count in skipped:
            p(f"- {count}: {SKIPPED[key]}")

    for field, items in sorted(samples.items()):
        p()
        p(f"### {field}: first {len(items)}")
        p()
        p("| request | nginx | ruxen | id |")
        p("| --- | --- | --- | --- |")
        for n, r in items:
            request = f"{n.get('method', '?')} {shown('uri', n.get('uri'), hash_paths)}"
            p(f"| `{request}` | `{brief(n, field, hash_paths)}` | `{brief(r, field, hash_paths)}` "
              f"| {n['id']} |")
    return stats


def brief(entry, field, hash_paths):
    """The status, the differing field and the size: enough to tell a
    request's answer apart without its body."""
    parts = [entry.get("status", "?")]
    if field not in ("status", "size"):
        parts.append(f"{field}={value_of(entry, field, hash_paths)}")
    parts.append(f"size={size_of(entry)}")
    return " ".join(parts)


def percent(part, whole):
    return f"{100 * part / whole:.1f}%" if whole else "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("nginx_log", help="nginx's ruxen_shadow log (.gz is fine)")
    ap.add_argument("ruxen_log", help="ruxen's ruxen_shadow log (.gz is fine)")
    ap.add_argument("--examples", type=int, default=5, metavar="N",
                    help="requests shown per differing field (default 5)")
    ap.add_argument("--hash-paths", action="store_true",
                    help="print URIs and Location values as hashes, to share the report")
    ap.add_argument("--ignore", default="", metavar="FIELD,...",
                    help="fields not to compare (\"size\" for body sizes)")
    args = ap.parse_args()
    ignore = {f.strip() for f in args.ignore.split(",") if f.strip()}
    report(args.nginx_log, args.ruxen_log, args.examples, args.hash_paths, ignore, sys.stdout)


if __name__ == "__main__":
    main()
