#!/usr/bin/env python3
"""Render docs/directives.md (#18): every directive of nginx 1.30.6's http,
core and events modules, and what ruxen does with it.

The facts come from the binary, not from a hand-kept list:
- the directive names, from ../nginx (the release-1.30.6 checkout), the
  `ngx_command_t` tables of src/core, src/event and src/http;
- where ruxen takes each one: `ruxen -t` on a configuration with the
  directive in main, http, server and location; anything but "unknown
  directive" means ruxen knows it there;
- whether it is ignored or behaves differently: `ruxen --compat` on the
  first of those.

    scripts/directives.py [--bin target/release/ruxen] [--nginx ../nginx]

Rerun after a change to the directive surface; don't edit the output.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONTEXTS = ["main", "http", "server", "location", "upstream"]


def nginx_directives(src):
    """(name, module) for each directive of the modules ruxen ports."""
    out = OrderedDict()
    dirs = ["src/core", "src/event", "src/http", "src/http/modules", "src/http/v2"]
    for d in dirs:
        path = os.path.join(src, d)
        for f in sorted(os.listdir(path)):
            if not f.endswith(".c"):
                continue
            text = open(os.path.join(path, f), encoding="latin-1").read()
            for table in re.findall(r"static ngx_command_t\s+\w+\[\]\s*=\s*\{(.*?)ngx_null_command", text, re.S):
                for name in re.findall(r'\{\s*ngx_string\("([a-z0-9_]+)"\)', table):
                    out.setdefault(name, f[:-2])
    return out


def conf(ctx, directive, block=False):
    # A block directive (`types`, `limit_except`, …) is probed as one too.
    d = f"{directive} {{ }}" if block else f"{directive} x;"
    return {
        "main": f"{d}\nevents {{}}\nhttp {{}}\n",
        "http": f"events {{}}\nhttp {{ {d} }}\n",
        "server": f"events {{}}\nhttp {{ server {{ listen 127.0.0.1:1; {d} }} }}\n",
        "location": f"events {{}}\nhttp {{ server {{ listen 127.0.0.1:1; location / {{ {d} }} }} }}\n",
        "upstream": "events {}\nhttp { upstream u { server 127.0.0.1:2; "
        + d
        + " } server { listen 127.0.0.1:1; location / { proxy_pass http://u; } } }\n",
    }[ctx]


def run(binary, path, flag):
    # In the probe's directory: `access_log x` and the like create files.
    p = subprocess.run(
        [binary, flag, "-c", path], capture_output=True, text=True, cwd=os.path.dirname(path)
    )
    return p.stdout + p.stderr


def probe(binary, name, work):
    path = os.path.join(work, "nginx.conf")
    known = []
    block = False
    for ctx in CONTEXTS:
        for b in (False, True):
            open(path, "w").write(conf(ctx, name, b))
            if "unknown directive" not in run(binary, path, "-t"):
                known.append(ctx)
                block = block or b
                break
    if not known:
        return known, None, ""
    ctx = next((c for c in ["http", "server", "location", "upstream"] if c in known), known[0])
    open(path, "w").write(conf(ctx, name, block))
    for line in run(binary, path, "--compat").splitlines():
        m = re.match(r"^(?:\S+: )?(unsupported|differs|ignored): (.*)$", line)
        if not m:
            continue
        kind, text = m.groups()
        text = re.sub(rf"^{re.escape(name)} x — ", "", text)
        text = re.sub(r"^1 tuning directive with no effect in ruxen: .*", "", text)
        if kind == "unsupported" and "open()" in text:
            continue  # the probe's `x` isn't a file
        return known, kind, text.strip()
    return known, "yes", ""


EVENTS_USED = {"worker_connections"}

STATUS = {
    "yes": "yes",
    "ignored": "accepted, no effect",
    "differs": "accepted, differs",
    "unsupported": "refused",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=os.path.join(ROOT, "target/release/ruxen"))
    ap.add_argument("--nginx", default=os.path.join(ROOT, "..", "nginx"))
    ap.add_argument("--out", default=os.path.join(ROOT, "docs/directives.md"))
    args = ap.parse_args()
    directives = nginx_directives(args.nginx)
    modules = OrderedDict()
    counts = {"yes": 0, "ignored": 0, "differs": 0, "unsupported": 0, None: 0}
    with tempfile.TemporaryDirectory() as work:
        for name, module in directives.items():
            if module == "ngx_event":
                kind = "yes" if name in EVENTS_USED else "ignored"
                row = (name, "events", kind, "" if kind == "yes" else "the `events` block is read for `worker_connections` only")
            else:
                known, kind, note = probe(args.bin, name, work)
                where = "any" if len(known) == len(CONTEXTS) else ", ".join(known)
                row = (name, where, kind, note)
            counts[row[2]] += 1
            modules.setdefault(module, []).append(row)
    lines = [
        "# Directives",
        "",
        "Every directive of nginx 1.30.6's core, events and http modules, and what ruxen",
        "does with it. Rendered by `scripts/directives.py` from a build of ruxen: where",
        "`ruxen -t` takes each directive (main, http, server, location, upstream) and what",
        "`ruxen --compat` says about it. Don't edit by hand; rerun the script.",
        "",
        "- **yes**: implemented. The contexts are where ruxen takes it.",
        "- **accepted, no effect**: a tuning knob ruxen accepts and ignores ('any': at every level).",
        "- **accepted, differs**: accepted, but ruxen does something other than nginx; the note says what.",
        "- **refused**: known, but refused at load, since ignoring it would be unsafe.",
        "- **no**: `unknown directive`; the configuration doesn't load.",
        "",
        f"Of {len(directives)} directives: {counts['yes']} implemented, "
        f"{counts['differs']} accepted with a difference, {counts['ignored']} accepted with no effect, "
        f"{counts['unsupported']} refused, {counts[None]} unknown.",
        "",
        "`ruxen --compat -c nginx.conf` checks a whole configuration against this.",
        "",
    ]
    for module, rows in modules.items():
        title = module.replace("ngx_", "", 1).replace("_module", "")
        if all(r[2] is None for r in rows):
            names = ", ".join(f"`{r[0]}`" for r in rows)
            lines += [f"## {title}", "", f"Not supported: {names}.", ""]
            continue
        lines += [f"## {title}", "", "| directive | ruxen | contexts | notes |", "| --- | --- | --- | --- |"]
        for name, where, kind, note in rows:
            status = STATUS.get(kind, "no")
            note = note.replace("|", "\\|")
            lines.append(f"| `{name}` | {status} | {where if kind else ''} | {note} |")
        lines.append("")
    open(args.out, "w").write("\n".join(lines))
    print(f"{args.out}: {len(directives)} directives, {counts['yes']} implemented", file=sys.stderr)


if __name__ == "__main__":
    main()
