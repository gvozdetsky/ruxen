#!/usr/bin/env python3
"""Config corpus: how many real-world nginx configurations ruxen loads.

    scripts/corpus.py build-nginx
    scripts/corpus.py run [--ruxen BIN] [--nginx BIN] [--only ID]
    scripts/corpus.py sample-github [--count N]

`run` fetches every source in corpus/sources.tsv and corpus/github.tsv
(cached in corpus/.cache), turns each into one or more test cases, makes
each case's environment self-contained (stub certificates and includes,
upstream host names pointed at 127.0.0.1, fragments wrapped in
events/http/server), checks it with `nginx -t` and `ruxen -t`, and writes
corpus/RESULTS.md. Only cases nginx itself accepts count: the corpus
measures ruxen, not the samples or the normalisation.

`sample-github` refreshes corpus/github.tsv from GitHub code search (needs
the gh CLI), pinning each file to a commit.

See issue #216 and ROADMAP.md ("How progress is measured").
"""

import argparse
import collections
import fnmatch
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")
CACHE = os.path.join(CORPUS, ".cache")
STUBS = os.path.join(CORPUS, "stubs")
SOURCE_FILES = [os.path.join(CORPUS, "sources.tsv"), os.path.join(CORPUS, "github.tsv")]
# The control nginx: a current release with the modules distributions build,
# and prefix-relative default paths, so `-t` runs unprivileged.
NGINX_VERSION = "1.30.5"
NGINX_MODULES = [
    "--with-http_ssl_module", "--with-http_v2_module", "--with-http_realip_module",
    "--with-http_gzip_static_module", "--with-http_stub_status_module", "--with-http_sub_module",
    "--with-http_auth_request_module", "--with-http_secure_link_module", "--with-http_dav_module",
    "--with-http_addition_module", "--with-stream", "--with-stream_ssl_module",
    "--with-stream_realip_module", "--with-stream_ssl_preread_module", "--with-threads",
]
NGINX_BIN = os.path.expanduser(f"~/.cache/ruxen-corpus/nginx-{NGINX_VERSION}")
# Generated once, never committed: a throw-away certificate and key, DH
# parameters, a ticket key, a password and an empty htpasswd.
GENERATED = os.path.expanduser("~/.cache/ruxen-corpus/stubs")


def generated_stubs():
    os.makedirs(GENERATED, exist_ok=True)
    if not os.path.exists(os.path.join(GENERATED, "cert.pem")):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
             "-subj", "/CN=corpus.test", "-keyout", os.path.join(GENERATED, "key.pem"),
             "-out", os.path.join(GENERATED, "cert.pem")],
            check=True, capture_output=True,
        )
    if not os.path.exists(os.path.join(GENERATED, "dhparam.pem")):
        subprocess.run(["openssl", "dhparam", "-out", os.path.join(GENERATED, "dhparam.pem"), "2048"],
                       check=True, capture_output=True)
    for name, data in (("ticket.key", os.urandom(80)), ("password", b"corpus\n"), ("htpasswd", b"")):
        path = os.path.join(GENERATED, name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)


def stub_path(name):
    """A stub file: nginx's own config files from corpus/stubs, the rest
    generated."""
    shipped = os.path.join(STUBS, name)
    return shipped if os.path.exists(shipped) else os.path.join(GENERATED, name)

# Directives whose argument is a file or directory the case needs.
FILE_DIRECTIVES = {
    "ssl_certificate": "cert.pem",
    "ssl_certificate_key": "key.pem",
    "ssl_trusted_certificate": "cert.pem",
    "ssl_client_certificate": "cert.pem",
    "ssl_crl": None,
    "ssl_dhparam": "dhparam.pem",
    "ssl_password_file": "password",
    "ssl_session_ticket_key": "ticket.key",
    "ssl_stapling_file": None,
    "auth_basic_user_file": "htpasswd",
    "proxy_ssl_certificate": "cert.pem",
    "proxy_ssl_certificate_key": "key.pem",
    "proxy_ssl_trusted_certificate": "cert.pem",
}
DIR_DIRECTIVES = {
    "root",
    "alias",
    "client_body_temp_path",
    "proxy_temp_path",
    "fastcgi_temp_path",
    "uwsgi_temp_path",
    "scgi_temp_path",
    "proxy_cache_path",
    "fastcgi_cache_path",
}
LOG_DIRECTIVES = {"error_log", "access_log", "pid"}
PASS_DIRECTIVES = {
    "proxy_pass",
    "fastcgi_pass",
    "uwsgi_pass",
    "scgi_pass",
    "grpc_pass",
    "memcached_pass",
}
KNOWN_INCLUDES = {
    "mime.types",
    "fastcgi_params",
    "fastcgi.conf",
    "proxy_params",
    "scgi_params",
    "uwsgi_params",
    "koi-utf",
    "koi-win",
    "win-utf",
}


# ---------------------------------------------------------------- sources


def read_sources():
    out = []
    for path in SOURCE_FILES:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                cols = line.split("\t")
                cols += [""] * (5 - len(cols))
                out.append(
                    {"id": cols[0], "use": cols[1], "kind": cols[2], "url": cols[3], "entries": cols[4]}
                )
    return out


def fetch(url):
    """The body of `url`, cached by URL."""
    os.makedirs(CACHE, exist_ok=True)
    key = hashlib.sha256(url.encode()).hexdigest()[:24]
    path = os.path.join(CACHE, key)
    if not os.path.exists(path):
        req = urllib.request.Request(url, headers={"User-Agent": "ruxen-corpus"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
        with open(path, "wb") as f:
            f.write(data)
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def fetch_git(url):
    """A shallow clone of `url` (`url@ref` pins a ref), cached."""
    os.makedirs(CACHE, exist_ok=True)
    repo, _, ref = url.partition("@")
    key = hashlib.sha256(url.encode()).hexdigest()[:24]
    path = os.path.join(CACHE, key)
    if not os.path.isdir(path):
        subprocess.run(["git", "clone", "-q", "--depth", "1", repo, path], check=True)
        if ref:
            subprocess.run(["git", "-C", path, "fetch", "-q", "--depth", "1", "origin", ref], check=True)
            subprocess.run(["git", "-C", path, "checkout", "-q", "FETCH_HEAD"], check=True)
    return path


FENCE = re.compile(r"^[ \t]*(```+|~~~+)[ \t]*([A-Za-z0-9_+-]*)[^\n]*\n(.*?)^[ \t]*\1[ \t]*$", re.M | re.S)


def markdown_blocks(text):
    """nginx code blocks of a Markdown page: tagged nginx/conf, or untagged
    ones that look like nginx configuration."""
    blocks = []
    for m in FENCE.finditer(text):
        lang, body = m.group(2).lower(), m.group(3)
        looks = re.search(r"^\s*(server|location|upstream|http)\b[^;{]*\{", body, re.M)
        if lang in ("nginx", "nginxconf", "conf") or (lang == "" and looks):
            if looks or re.search(r"^\s*(proxy_pass|listen|server_name)\b", body, re.M):
                blocks.append(body)
    return blocks


def cases(source):
    """(case id, use, text, directory the text's relative includes resolve
    against or None) for one source."""
    kind = source["kind"]
    if kind == "file":
        yield source["id"], source["use"], fetch(source["url"]), None
    elif kind == "md":
        for i, block in enumerate(markdown_blocks(fetch(source["url"])), 1):
            yield f"{source['id']}#{i}", source["use"], block, None
    elif kind == "git":
        repo = fetch_git(source["url"])
        for entry in source["entries"].split(","):
            path = os.path.join(repo, entry)
            with open(path, encoding="utf-8", errors="replace") as f:
                yield f"{source['id']}:{entry}", source["use"], f.read(), os.path.dirname(path)
    else:
        raise SystemExit(f"unknown kind {kind!r} for {source['id']}")


# ---------------------------------------------------------- normalisation


def strip_comments(text):
    out = []
    for line in text.splitlines():
        quote = None
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "#":
                line = line[:i]
                break
        out.append(line)
    return "\n".join(out)


def top_level_words(text):
    """First words of the statements at brace depth 0."""
    words, depth, start = [], 0, True
    for tok in re.finditer(r"[{};]|[^\s{};]+", text):
        t = tok.group(0)
        if t == "{":
            depth += 1
            start = True
        elif t == "}":
            depth -= 1
            start = True
        elif t == ";":
            start = True
        else:
            if start and depth == 0:
                words.append(t)
            start = False
    return words


def wrap(text):
    """A complete configuration: fragments go into http/server, and a
    missing events block is added."""
    words = top_level_words(strip_comments(text))
    http_level = {"server", "upstream", "map", "geo", "split_clients", "limit_req_zone", "limit_conn_zone",
                  "proxy_cache_path", "fastcgi_cache_path", "log_format", "include", "ssl_protocols"}
    if "http" in words or "stream" in words or "mail" in words:
        body = text
    elif "server" in words or "upstream" in words or "map" in words:
        body = "http {\n" + text + "\n}\n"
    else:
        body = "http {\nserver {\nlisten 8080;\n" + text + "\n}\n}\n"
    if "events" not in words:
        body = "events {}\n" + body
    return body


IP = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|\[[0-9a-fA-F:.]+\])$")


def local_host(hostport, upstreams):
    """`host[:port]` with a name nginx would resolve replaced by 127.0.0.1."""
    if "$" in hostport or hostport.startswith("unix:"):
        return hostport
    if hostport.startswith("["):
        return hostport
    host, sep, port = hostport.partition(":")
    if host in upstreams or IP.match(host) or host == "localhost":
        return hostport
    return "127.0.0.1" + sep + port


def unprivileged(addr):
    """A listen address with a port below 1024 moved to 18000 + port."""
    m = re.match(r"^(.*:)?(\d+)$", addr)
    if m:
        prefix, port = m.group(1) or "", int(m.group(2))
        return f"{prefix}{port + 18000 if port < 1024 else port}"
    # An address without a port listens on 80.
    return f"{addr}:18080"


def add_certificate(text, sandbox):
    """A test certificate at http level when `listen … ssl` has none
    (documentation leaves it out, or it sits in an include not shipped)."""
    if not re.search(r"^\s*listen\s[^;]*\bssl\b", text, re.M) or re.search(r"^\s*ssl_certificate\s", text, re.M):
        return text
    cert = stub_path("cert.pem")
    key = stub_path("key.pem")
    return re.sub(r"(^|\n)(\s*http\s*\{)", lambda m: f"{m.group(1)}{m.group(2)}\nssl_certificate {cert};\nssl_certificate_key {key};\n", text, count=1)


class Sandbox:
    def __init__(self, root):
        self.root = root
        self.fs = os.path.join(root, "fs")

    def mapped(self, path):
        """Where an absolute path of the configuration lives in the sandbox."""
        return os.path.join(self.fs, path.lstrip("/"))

    def stub_file(self, path, stub):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            return
        if stub:
            shutil.copy(stub_path(stub), path)
        else:
            open(path, "w").close()


DIRECTIVE = re.compile(r"(?m)^([ \t]*)([a-z_0-9]+)([ \t]+)([^;{}\n]*?)([ \t]*;)")


def normalise(text, case_dir, sandbox):
    """Rewrite environment-dependent arguments; create what they need."""
    text = strip_comments(text)
    upstreams = set(re.findall(r"\bupstream\s+([^\s{]+)\s*\{", text))
    conf_dir = os.path.join(sandbox.root, "conf")

    def rewrite(m):
        indent, name, gap, args, end = m.groups()
        if "$" in args and name not in PASS_DIRECTIVES:
            return m.group(0)
        parts = args.split()
        if not parts:
            return m.group(0)
        first = parts[0].strip("\"'")
        if name == "include":
            target = first if os.path.isabs(first) else os.path.join(conf_dir, first)
            if os.path.isabs(first):
                target = sandbox.mapped(first)
            base = os.path.basename(first)
            if any(c in first for c in "*?["):
                os.makedirs(os.path.dirname(target), exist_ok=True)
            elif not os.path.exists(target):
                sandbox.stub_file(target, base if base in KNOWN_INCLUDES else None)
            return f"{indent}include{gap}{target}{end}"
        if name == "listen" and not first.startswith("unix:"):
            # `nginx -t` binds the listening sockets: no privileged ports.
            return f"{indent}listen{gap}{unprivileged(first)}{' '.join([''] + parts[1:])}{end}"
        if name == "load_module":
            return f"{indent}# load_module {args}{end}"
        if name in FILE_DIRECTIVES and not first.startswith("data:"):
            target = sandbox.mapped(first) if os.path.isabs(first) else os.path.join(conf_dir, first)
            sandbox.stub_file(target, FILE_DIRECTIVES[name])
            return f"{indent}{name}{gap}{target}{' '.join([''] + parts[1:])}{end}"
        if name in DIR_DIRECTIVES and os.path.isabs(first):
            target = sandbox.mapped(first)
            os.makedirs(target, exist_ok=True)
            return f"{indent}{name}{gap}{target}{' '.join([''] + parts[1:])}{end}"
        if name in DIR_DIRECTIVES:
            os.makedirs(os.path.join(sandbox.root, first), exist_ok=True)
            return m.group(0)
        if name in LOG_DIRECTIVES and os.path.isabs(first):
            target = sandbox.mapped(first)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            return f"{indent}{name}{gap}{target}{' '.join([''] + parts[1:])}{end}"
        if name in PASS_DIRECTIVES:
            m2 = re.match(r"^(\w+://)?([^/\s]+)(.*)$", first)
            if m2 and not first.startswith("unix:"):
                scheme, hostport, rest = m2.groups()
                fixed = (scheme or "") + local_host(hostport, upstreams) + rest
                return f"{indent}{name}{gap}{fixed}{' '.join([''] + parts[1:])}{end}"
        if name == "server" and re.match(r"^[A-Za-z0-9._-]+(:\d+)?$", first) and indent.strip() == "":
            # An upstream's `server host:port`; a server block never matches
            # here (it has no `;`).
            return f"{indent}server{gap}{local_host(first, set())}{' '.join([''] + parts[1:])}{end}"
        return m.group(0)

    text = DIRECTIVE.sub(rewrite, text)
    if case_dir:
        # Relative includes resolve against the configuration's directory:
        # bring the source tree along.
        shutil.copytree(case_dir, conf_dir, dirs_exist_ok=True)
        for dirpath, _, files in os.walk(conf_dir):
            for name in files:
                if name.endswith(".conf") or name in ("nginx.conf",):
                    p = os.path.join(dirpath, name)
                    with open(p, encoding="utf-8", errors="replace") as f:
                        inner = f.read()
                    with open(p, "w") as f:
                        f.write(DIRECTIVE.sub(rewrite, strip_comments(inner)))
    return text


# ------------------------------------------------------------------ check


def check(binary, conf, prefix, extra):
    try:
        r = subprocess.run(
            [binary, "-t", "-p", prefix + "/", "-c", conf] + extra,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        return False, "timed out"
    ok = r.returncode == 0
    lines = [l for l in (r.stderr + r.stdout).splitlines() if "[emerg]" in l or "error" in l.lower()]
    return ok, (lines[0] if lines else "").strip()


def blocker(message):
    """A short key for a ruxen error, to count configurations per cause."""
    m = re.search(r"unknown directive [`\"]([^`\"]+)[`\"]", message)
    if m:
        return f"unknown directive `{m.group(1)}`"
    m = re.search(r"\[emerg\]\s*(.*)", message)
    msg = m.group(1) if m else message
    msg = re.sub(r"\"[^\"]*\"", '"…"', msg)
    msg = re.sub(r"/[^\s:]+", "…", msg)
    msg = re.sub(r"\d+", "N", msg)
    return msg[:100]


def run(args):
    generated_stubs()
    ruxen = args.ruxen or os.path.join(ROOT, "target", "release", "ruxen")
    results = []
    for source in read_sources():
        if args.only and not source["id"].startswith(args.only):
            continue
        try:
            source_cases = list(cases(source))
        except Exception as e:  # noqa: BLE001 - a dead source is reported, not fatal
            results.append({"id": source["id"], "use": source["use"], "nginx": False,
                            "nginx_error": f"fetch failed: {e}", "ruxen": False, "ruxen_error": ""})
            continue
        for case_id, use, text, case_dir in source_cases:
            with tempfile.TemporaryDirectory(prefix="ruxen-corpus-") as tmp:
                sandbox = Sandbox(tmp)
                os.makedirs(os.path.join(tmp, "conf"))
                os.makedirs(os.path.join(tmp, "logs"))
                text2 = add_certificate(normalise(wrap(text), case_dir, sandbox), sandbox)
                if not re.search(r"^\s*pid\s", text2, re.M):
                    text2 = f"pid {tmp}/nginx.pid;\n" + text2
                conf = os.path.join(tmp, "conf", "nginx.conf")
                with open(conf, "w") as f:
                    f.write(text2)
                n_ok, n_err = check(args.nginx, conf, tmp, ["-e", os.path.join(tmp, "logs", "error.log")])
                r_ok, r_err = check(ruxen, conf, tmp, [])
            results.append({"id": case_id, "use": use, "nginx": n_ok, "nginx_error": n_err,
                            "ruxen": r_ok, "ruxen_error": r_err})
            if args.verbose:
                print(f"{case_id}: nginx={'ok' if n_ok else 'FAIL'} ruxen={'ok' if r_ok else 'FAIL'} {r_err if n_ok and not r_ok else ''}")
    version = subprocess.run([args.nginx, "-v"], capture_output=True, text=True).stderr.strip()
    write_report(results, args.output, version.split("/")[-1] and "nginx " + version.split("/")[-1])


def write_report(results, output, nginx_version):
    valid = [r for r in results if r["nginx"]]
    loaded = [r for r in valid if r["ruxen"]]
    by_use = collections.defaultdict(lambda: [0, 0])
    for r in valid:
        by_use[r["use"]][0] += 1
        by_use[r["use"]][1] += r["ruxen"]
    blockers = collections.defaultdict(list)
    for r in valid:
        if not r["ruxen"]:
            blockers[blocker(r["ruxen_error"])].append(r["id"])
    pct = lambda a, b: f"{100 * a / b:.0f}%" if b else "—"
    lines = [
        "# Config corpus results",
        "",
        "Generated by `scripts/corpus.py run`; do not edit by hand. Which real-world",
        "nginx configurations ruxen loads (`ruxen -t`), counting only the ones a",
        f"current nginx ({nginx_version}) accepts after the same normalisation: stub",
        "certificates and includes, upstream names pointed at 127.0.0.1, privileged",
        "ports moved up, fragments wrapped. See `corpus/README.md` and issue #216.",
        "",
        f"**ruxen loads {len(loaded)} of {len(valid)} configurations nginx accepts ({pct(len(loaded), len(valid))}).**"
        f" {len(results) - len(valid)} more cases were not valid for nginx either and don't count.",
        "",
        "| use | nginx accepts | ruxen loads | share |",
        "|---|---:|---:|---:|",
    ]
    for use in sorted(by_use):
        n, k = by_use[use]
        lines.append(f"| {use} | {n} | {k} | {pct(k, n)} |")
    lines += ["", "## What blocks the rest", "", "| configurations | first error in ruxen | examples |", "|---:|---|---|"]
    for key, ids in sorted(blockers.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"| {len(ids)} | {key} | {', '.join(ids[:4])}{' …' if len(ids) > 4 else ''} |")
    lines += ["", "## Every case", "", "| case | use | nginx | ruxen | ruxen's error |", "|---|---|---|---|---|"]
    for r in results:
        err = r["ruxen_error"] if r["nginx"] and not r["ruxen"] else ("" if r["nginx"] else "(" + (r["nginx_error"] or "nginx rejects it")[:80] + ")")
        err = err.replace("|", "\\|")
        lines.append(
            f"| {r['id']} | {r['use']} | {'ok' if r['nginx'] else '—'} | {'ok' if r['ruxen'] else ('FAIL' if r['nginx'] else '—')} | {err} |"
        )
    with open(output, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"ruxen loads {len(loaded)} of {len(valid)} ({pct(len(loaded), len(valid))}); {output}")


# --------------------------------------------------------- github sample


def sample_github(args):
    queries = [
        "filename:nginx.conf proxy_pass",
        "filename:nginx.conf server_name root",
        "filename:default.conf proxy_pass",
        "filename:default.conf location",
        "extension:conf listen 443 ssl_certificate proxy_pass",
    ]
    seen, rows = set(), []
    for q in queries:
        for page in range(1, 11):
            if len(rows) >= args.count:
                break
            r = subprocess.run(
                ["gh", "api", "-X", "GET", "search/code", "-f", f"q={q}", "-f", "per_page=100", "-f", f"page={page}"],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                break
            items = json.loads(r.stdout).get("items", [])
            if not items:
                break
            for it in items:
                repo, path = it["repository"]["full_name"], it["path"]
                ref = urllib.parse.parse_qs(urllib.parse.urlparse(it["url"]).query).get("ref", [""])[0]
                if not ref or (repo, path) in seen or repo.startswith(("nginx/", "nginxinc/")):
                    continue
                seen.add((repo, path))
                url = f"https://raw.githubusercontent.com/{repo}/{ref}/{urllib.parse.quote(path)}"
                rows.append(f"gh:{repo}/{path}\tgithub\tfile\t{url}")
                if len(rows) >= args.count:
                    break
    with open(os.path.join(CORPUS, "github.tsv"), "w") as f:
        f.write("# A sample of public nginx configurations from GitHub code search, pinned to\n")
        f.write("# commits. Regenerate with `scripts/corpus.py sample-github`. Same columns as\n")
        f.write("# sources.tsv; their use is unknown (\"github\").\n")
        f.write("\n".join(rows) + "\n")
    print(f"{len(rows)} configurations in corpus/github.tsv")


def build_nginx(_args):
    """Build the control nginx into ~/.cache/ruxen-corpus."""
    if os.path.exists(NGINX_BIN):
        print(NGINX_BIN)
        return
    work = tempfile.mkdtemp(prefix="ruxen-nginx-")
    try:
        tarball = os.path.join(work, "nginx.tar.gz")
        urllib.request.urlretrieve(f"https://nginx.org/download/nginx-{NGINX_VERSION}.tar.gz", tarball)
        subprocess.run(["tar", "-xzf", tarball, "-C", work], check=True)
        src = os.path.join(work, f"nginx-{NGINX_VERSION}")
        subprocess.run(["./configure", "--prefix=/nonexistent"] + NGINX_MODULES, cwd=src, check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(["make", f"-j{os.cpu_count() or 2}"], cwd=src, check=True, stdout=subprocess.DEVNULL)
        os.makedirs(os.path.dirname(NGINX_BIN), exist_ok=True)
        shutil.copy(os.path.join(src, "objs", "nginx"), NGINX_BIN)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(NGINX_BIN)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--ruxen")
    r.add_argument("--nginx", default=NGINX_BIN, help="the control nginx (default: build-nginx's)")
    r.add_argument("--only")
    r.add_argument("--output", default=os.path.join(CORPUS, "RESULTS.md"))
    r.add_argument("-v", "--verbose", action="store_true")
    g = sub.add_parser("sample-github")
    g.add_argument("--count", type=int, default=300)
    sub.add_parser("build-nginx")
    a = p.parse_args()
    {"run": run, "sample-github": sample_github, "build-nginx": build_nginx}[a.cmd](a)


if __name__ == "__main__":
    main()
