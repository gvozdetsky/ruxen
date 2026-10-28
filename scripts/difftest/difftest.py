#!/usr/bin/env python3
"""Differential testing: the same configuration and requests to ruxen and to
nginx, the responses compared after a short, explicit normalisation
(normalise.py). Issue #750.

    scripts/difftest/difftest.py run [--suite S,...] [--quick] [--seed N]
                                     [--only CASE] [--request ID] [-j N]
                                     [--config FILE] [--fail-on-new]
    scripts/difftest/difftest.py list [--suite S,...]
    scripts/difftest/difftest.py report [--out DIR]

Suites:
  curated      configurations in scripts/difftest/configs/ (edge features)
  bench        bench/*/nginx.conf
  nginx-tests  the configurations, files and requests of the nginx-tests
               files NGINX_TEST_PROGRESS.md lists as passing (HTTP/1 only)
  corpus       corpus/ cases both servers load (scripts/corpus.py)

Each case runs in a sandbox: its listen ports move to free loopback ports,
upstreams that aren't the configuration's own servers go to a deterministic
echo server (echo_upstream.py), and a fixed file tree (fixed mtimes) fills
its roots. nginx runs first, then ruxen on the same ports and a fresh copy
of the same sandbox. Requests are the case's own (its locations, or what
the nginx-tests file sends) plus variations (variations.py), generated from
the seed: the same seed replays the same requests.

Output, in --out (default difftest-out/): report.md, differences grouped by
class so that one root cause shows up once; differences.jsonl with what was
sent (and with -v or --request, both raw responses). Configurations
`ruxen --compat` flags as behaving differently, and the rules in
expected.tsv (by design, or tracked by an issue), are listed apart; `report`
re-renders after expected.tsv changes.
"""

import argparse
import collections
import concurrent.futures
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(1, os.path.dirname(HERE))  # scripts/corpus.py

import client  # noqa: E402
import conf  # noqa: E402
import echo_upstream  # noqa: E402
import normalise  # noqa: E402
import variations  # noqa: E402

# The oracle: $DIFFTEST_NGINX, the maintainer's 1.30.6 build, or nginx on PATH.
NGINX = os.environ.get("DIFFTEST_NGINX") or next(
    (p for p in (os.path.expanduser("~/ruxen-night/nginx-1.30/sbin/nginx"),) if os.path.exists(p)),
    shutil.which("nginx") or "nginx")
RUXEN = os.path.join(ROOT, "target", "release", "ruxen")
NGINX_TESTS = os.path.join(os.path.dirname(ROOT), "nginx-tests")
# Requests nginx may time out on before a case is cut short.
MAX_TIMEOUTS = 6
SUITES = ["curated", "bench", "nginx-tests", "corpus"]
QUICK_SUITES = ["curated", "bench"]
# 2026-01-01: the fixture tree's mtime, so ETag and Last-Modified replay.
FIXED_MTIME = 1767225600
# Bench configs that need fixtures too big for a quick run, or HTTP/2.
BENCH_SKIP = {"m19", "h2", "campaign-0.1.2", "campaign-2026-10-14", "campaign-2026-10-17",
              "campaign-2026-10-21", "scenarios", "scripts"}
# nginx-tests files that run the harness's way badly: HTTP/2, TLS-only
# protocols, stream/mail, and those whose requests depend on timing.
NGINX_TESTS_SKIP = re.compile(r"^(h2_|h3_|stream_|mail_|smtp|imap|pop3|grpc|quic|proxy_protocol|ssl_|"
                              r".*(_timeout|_delay|limit_rate|limit_req|limit_conn|reload|worker))")


class Skip(Exception):
    pass


# ------------------------------------------------------------------ ports

_ports_lock = threading.Lock()
_ports_used = set()


def alloc_port():
    """A free loopback port below the ephemeral range, never handed out twice
    in a run."""
    with _ports_lock:
        for _ in range(1000):
            p = random.randrange(20000, 32000)
            if p in _ports_used:
                continue
            try:
                for fam, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                    s = socket.socket(fam, socket.SOCK_STREAM)
                    try:
                        s.bind((addr, p))
                    finally:
                        s.close()
            except OSError:
                continue
            _ports_used.add(p)
            return p
    raise RuntimeError("no free port")


# --------------------------------------------------------------- fixtures

def fixture_tree(root):
    """The same small file tree in every root: text for gzip and ranges, an
    index, a directory without one, names that need escaping."""
    os.makedirs(root, exist_ok=True)
    if os.listdir(root):
        return
    text = "".join(f"line {i:04d} of a text file for ranges and gzip\n" for i in range(1500)).encode()
    files = {
        "index.html": b"<html><body>index</body></html>\n",
        "hello.txt": text[:1024],
        "big.txt": text[:65536],
        "style.css": b"body { color: black; }\n" * 40,
        "app.js": b"console.log('x');\n" * 60,
        "data.json": b'{"a": 1}\n',
        "image.png": bytes(range(256)) * 2,
        "favicon.ico": bytes(range(64)),
        "robots.txt": b"User-agent: *\n",
        "dir/index.html": b"<html>dir index</html>\n",
        "dir/file.txt": b"file in dir\n",
        "noindex/file.txt": b"file without index\n",
        "a b.txt": b"space\n",
        "caf\u00e9.txt": b"utf8 name\n",
        ".hidden": b"hidden\n",
        "index.php": b"<?php echo 1;\n",
        "api/index.html": b"api index\n",
        "static/app.css": b".a{}\n",
        "files/doc.pdf": b"%PDF-1.4\n" + bytes(200),
    }
    for name, data in files.items():
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    fix_mtimes(root)


def fix_mtimes(top):
    for dirpath, dirs, files in os.walk(top, topdown=False):
        for n in files + dirs:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                os.utime(p, (FIXED_MTIME, FIXED_MTIME))
    os.utime(top, (FIXED_MTIME, FIXED_MTIME))


def stub(name):
    """corpus.py's generated stubs (certificate, key, …)."""
    import corpus  # scripts/corpus.py
    corpus.generated_stubs()
    return corpus.stub_path(name)


# ------------------------------------------------------------------ cases

class Case:
    def __init__(self, suite, cid):
        self.suite, self.id = suite, cid
        self.dir = None  # the sandbox (also the prefix)
        self.conf = "difftest.conf"
        self.targets = []  # (port, host, tls, paths, primary)
        self.raw = []  # (request id, port, tls, steps): the suite's own requests
        self.compat = []


def finish(case, main_text, alloc, echo_port, extra_dir=None, default_paths=True, host=None):
    """Rewrites the main configuration and the files it may include (all of
    `extra_dir`), fills the roots, and works out the targets."""
    rw = conf.Rewriter(alloc, echo_port, case.dir)
    trees = {}
    try:
        trees[os.path.join(case.dir, case.conf)] = conf.parse(main_text)
    except ValueError as e:
        raise Skip(f"unparsable configuration: {e}")
    if extra_dir and os.path.isdir(extra_dir):
        for dirpath, _, names in os.walk(extra_dir):
            for n in names:
                p = os.path.join(dirpath, n)
                if p in trees or os.path.getsize(p) > 200000:
                    continue
                try:
                    with open(p, encoding="utf-8") as f:
                        t = f.read()
                    if "{" in t or ";" in t:
                        trees[p] = conf.parse(t)
                except (ValueError, UnicodeDecodeError):
                    pass
    main = os.path.join(case.dir, case.conf)
    rw.upstream_names = set()
    for t in trees.values():
        rw.upstream_names |= {conf.unquote(s.args[0]) for s, _ in conf.walk(t) if s.name == "upstream" and s.args}
        rw.collect_listens(t)
    for p, t in trees.items():
        t = rw.rewrite(t, top=(p == main))
        with open(p, "w") as f:
            f.write(conf.dump(t) + "\n")
        rw.servers_of(t)
        for s, _ in conf.walk(t):
            if s.name in ("root", "alias") and s.args and "$" not in s.args[0]:
                d = conf.unquote(s.args[0])
                d = d if os.path.isabs(d) else os.path.join(case.dir, d)
                if d.startswith(case.dir) and (s.name == "root" or d.endswith("/")):
                    fixture_tree(d)
    # A root nginx falls back to: <prefix>/html.
    fixture_tree(os.path.join(case.dir, "html"))
    seen = set()
    for ports, names, paths in rw.servers:
        h = host or conf.request_host(names)
        for port in ports[:1]:
            if (port, h) in seen:
                continue
            seen.add((port, h))
            ps = [p for p in dict.fromkeys(paths) if p.startswith("/") and "$" not in p and " " not in p]
            if default_paths:
                # The catalogue runs on the first path: "/" hits most configs' main location.
                ps = ["/"] + [p for p in ps if p != "/"]
                ps += [p for p in ("/hello.txt", "/big.txt", "/dir/", "/missing.html") if p not in ps]
            case.targets.append([port, h, port in rw.ssl_ports, ps[:16] or ["/"], False])
    if not case.targets and not case.raw:
        raise Skip("no HTTP server to send requests to")
    if case.targets:
        case.targets[0][4] = True
    fix_mtimes(case.dir)
    return rw


def curated_cases():
    d = os.path.join(HERE, "configs")
    for n in sorted(os.listdir(d)):
        if n.endswith(".conf"):
            yield f"curated:{n[:-5]}", prepare_curated(os.path.join(d, n))


def prepare_curated(path):
    def prep(case, alloc, echo_port):
        with open(path) as f:
            text = f.read()
        text = text.replace("%%CERT%%", stub("cert.pem")).replace("%%KEY%%", stub("key.pem"))
        text = text.replace("%%MIME%%", stub("mime.types"))
        with open(os.path.join(case.dir, "htpasswd"), "w") as f:
            f.write("user:{PLAIN}hello\n")
        finish(case, text, alloc, echo_port)
    return prep


def bench_cases():
    manifest = collections.defaultdict(list)
    with open(os.path.join(ROOT, "bench", "scenarios", "manifest.tsv")) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("|")
            if len(cols) > 9:
                manifest[cols[9]].append(cols[3])
    for name in sorted(os.listdir(os.path.join(ROOT, "bench"))):
        src = os.path.join(ROOT, "bench", name)
        if name in BENCH_SKIP or not os.path.isfile(os.path.join(src, "nginx.conf")):
            continue
        paths = manifest.get(f"bench/{name}/nginx.conf", [])
        yield f"bench:{name}", prepare_bench(src, paths)


def prepare_bench(src, paths):
    def prep(case, alloc, echo_port):
        case.conf = "nginx.conf"
        for n in os.listdir(src):
            p = os.path.join(src, n)
            if n.endswith((".tsv", ".md", ".lua", ".bin")) or n == "html":
                continue
            if os.path.isfile(p):
                shutil.copy(p, case.dir)
        gen = os.path.join(case.dir, "generate.sh")
        # tls2's generator runs ../tls/generate.sh.
        tls = os.path.join(os.path.dirname(case.dir), "tls")
        if not os.path.exists(tls):
            os.symlink(os.path.join(ROOT, "bench", "tls"), tls)
        if os.path.exists(gen):
            subprocess.run(["bash", gen], check=True, capture_output=True, timeout=60)
        if "tls" in open(os.path.join(case.dir, "nginx.conf")).read():
            subprocess.run(["bash", os.path.join(ROOT, "bench", "tls", "generate.sh")], capture_output=True)
        with open(os.path.join(case.dir, "nginx.conf")) as f:
            text = f.read()
        rw = finish(case, text, alloc, echo_port)
        for t in case.targets:
            t[3] = list(dict.fromkeys([p.split("?")[0] for p in paths] + t[3]))[:16]
        return rw
    return prep


def passing_nginx_tests():
    path = os.path.join(ROOT, "NGINX_TEST_PROGRESS.md")
    out, on = [], False
    with open(path) as f:
        for line in f:
            if line.startswith("## "):
                on = line.startswith("## Passing")
            m = re.match(r"^- `([^`]+\.t)`", line)
            if on and m:
                out.append(m.group(1))
    return out


def nginx_tests_cases():
    if not os.path.isdir(NGINX_TESTS):
        print(f"nginx-tests not found at {NGINX_TESTS}; suite skipped", file=sys.stderr)
        return
    for name in passing_nginx_tests():
        if NGINX_TESTS_SKIP.match(name):
            continue
        yield f"nginx-tests:{name}", prepare_nginx_test(name)


def prepare_nginx_test(name):
    def prep(case, alloc, echo_port):
        case.conf = "nginx.conf"
        env = dict(os.environ, DIFFTEST_DIR=case.dir)
        subprocess.run(["perl", "-I", os.path.join(HERE, "perl"), "-MTest::Nginx", name], cwd=NGINX_TESTS,
                       env=env, capture_output=True, timeout=30)
        main = os.path.join(case.dir, "nginx.conf")
        if not os.path.exists(main):
            raise Skip("the test file wrote no nginx.conf")
        with open(main) as f:
            text = f.read()
        recorded = []
        rp = os.path.join(case.dir, "requests.tsv")
        if os.path.exists(rp):
            with open(rp) as f:
                for line in f:
                    port, _, hexdata = line.rstrip("\n").partition("\t")
                    recorded.append((port, bytes.fromhex(hexdata)))
            os.unlink(rp)
        rw = finish(case, text, alloc, echo_port, extra_dir=case.dir, default_paths=False, host="localhost")
        paths = []
        for i, (port, data) in enumerate(recorded):
            tls = port.startswith("ssl:")
            old = int(port.split(":")[-1])
            if old not in rw.ports:
                continue
            new = rw.ports[old]
            head = data.split(b"\n", 1)[0].split()
            method = head[0] if head else b""
            case.raw.append((f"test{i}:{data[:60]!r}", new, tls or new in rw.ssl_ports,
                             [(data, 1, method == b"HEAD")]))
            if old == 8080 and len(head) > 1 and head[1].startswith(b"/"):
                paths.append(head[1].decode("latin-1"))
        # Variations against the main port, around the paths the test uses.
        main_port = rw.ports.get(8080)
        if main_port and paths:
            case.targets = [[main_port, "localhost", main_port in rw.ssl_ports,
                             list(dict.fromkeys(paths))[:16], True]]
        else:
            case.targets = []
    return prep


def corpus_cases(cache):
    import corpus
    if cache:
        corpus.CACHE = cache
    for source in corpus.read_sources():
        try:
            items = list(corpus.cases(source))
        except Exception as e:  # noqa: BLE001 - a dead source is skipped
            print(f"{source['id']}: {e}", file=sys.stderr)
            continue
        for cid, _use, text, case_dir in items:
            yield f"corpus:{cid}", prepare_corpus(text, case_dir)


def prepare_corpus(text, src_dir):
    def prep(case, alloc, echo_port):
        import corpus
        corpus.generated_stubs()
        sandbox = corpus.Sandbox(case.dir)
        os.makedirs(os.path.join(case.dir, "conf"), exist_ok=True)
        os.makedirs(os.path.join(case.dir, "logs"), exist_ok=True)
        text2 = corpus.add_certificate(corpus.normalise(corpus.wrap(text), src_dir, sandbox), sandbox)
        finish(case, text2, alloc, echo_port, extra_dir=os.path.join(case.dir, "conf"))
    return prep


def all_cases(suites, cache, files=()):
    for f in files:
        yield f"file:{os.path.basename(f)}", prepare_curated(os.path.abspath(f))
    gens = {"curated": curated_cases, "bench": bench_cases, "nginx-tests": nginx_tests_cases,
            "corpus": lambda: corpus_cases(cache)}
    for s in suites:
        yield from gens[s]()


# ---------------------------------------------------------------- servers

def start(binary, side, case):
    env = dict(os.environ)
    if side == "ruxen":
        env["RUXEN_NGINX_IDENTITY"] = "1"
    log = open(os.path.join(case.dir, "logs", f"{side}.stderr"), "wb")
    proc = subprocess.Popen(
        [binary, "-p", case.dir + "/", "-c", case.conf, "-e", f"logs/{side}-error.log",
         "-g", f"daemon off; worker_processes 1; pid logs/{side}.pid;"],
        cwd=case.dir, env=env, stdout=log, stderr=log, start_new_session=True)
    log.close()
    ports = sorted({t[0] for t in case.targets} | {r[1] for r in case.raw})
    deadline = time.monotonic() + 8
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            socket.create_connection(("127.0.0.1", pending[0]), timeout=0.5).close()
            pending.pop(0)
        except OSError:
            time.sleep(0.05)
    if pending:
        stop(proc)
        return None, startup_error(case, side)
    return proc, None


def startup_error(case, side):
    out = []
    for n in (f"{side}.stderr", f"{side}-error.log"):
        p = os.path.join(case.dir, "logs", n)
        if os.path.exists(p):
            with open(p, errors="replace") as f:
                out += [line.strip() for line in f if "[emerg]" in line or "error" in line.lower()]
    return (out[0] if out else "did not listen").replace(case.dir, "<sandbox>")


def stop(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(5)
    # Workers of the group the master didn't reap.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def check(binary, side, case):
    env = dict(os.environ, RUXEN_NGINX_IDENTITY="1")
    r = subprocess.run([binary, "-t", "-p", case.dir + "/", "-c", case.conf, "-e", f"logs/{side}-t.log",
                        "-g", f"daemon off; worker_processes 1; pid logs/{side}.pid;"],
                       capture_output=True, text=True, timeout=20, env=env)
    lines = [ln for ln in (r.stderr + r.stdout).splitlines() if "[emerg]" in ln or "rror" in ln]
    return r.returncode == 0, (lines[0] if lines else "").replace(case.dir, "<sandbox>")


def compat(binary, case):
    r = subprocess.run([binary, "--compat", "-p", case.dir + "/", "-c", case.conf], capture_output=True,
                       text=True, timeout=20)
    return sorted({ln.split(": differs: ", 1)[1][:120] for ln in r.stdout.splitlines() if ": differs: " in ln})


# ---------------------------------------------------------------- running

def requests_of(case, seed, quick):
    """[(request id, port, tls, sni, steps, path)] for one case."""
    out = [(rid, port, tls, "localhost", steps, None) for rid, port, tls, steps in case.raw]
    for ti, (port, host, tls, paths, primary) in enumerate(case.targets):
        if primary:
            gen = variations.generate(seed, case.id, host, port, paths, 10 if quick else 40)
        else:
            gen = [(f"base:{p}", variations.single(variations.req("GET", p, [("Host", host),
                                                                          ("Connection", "close")])))
                   for p in paths[:4]]
        for rid, steps in gen:
            path = rid.rsplit("@", 1)[1] if "@" in rid else rid.split(":", 1)[1]
            out.append((f"t{ti}:{host}/{rid}", port, tls, host, steps, path))
    return out


def run_side(binary, side, case, reqs, timeout):
    proc, err = start(binary, side, case)
    if proc is None:
        return None, err
    results = {}
    validators = {}
    slow = 0
    try:
        for rid, port, tls, sni, steps, path in reqs:
            if "/base:" in rid:
                resps, after = client.exchange(port, steps, tls, sni, timeout)
                if resps and not resps[0]["error"]:
                    h = {n.lower(): v for n, v in resps[0]["headers"]}
                    validators[(port, path)] = {"etag": h.get("etag"), "last_modified": h.get("last-modified")}
            else:
                steps = variations.fill(steps, validators.get((port, path), {}))
                resps, after = client.exchange(port, steps, tls, sni, timeout)
            results[rid] = (resps, after, steps)
            if side == "nginx" and any(r["error"] == "timeout" for r in resps):
                slow += 1
                if slow > MAX_TIMEOUTS:
                    break
        if proc.poll() is not None:
            results["(server)"] = ([], f"exited with {proc.returncode}", [])
    finally:
        stop(proc)
    return results, None


def run_case(name, prep, args, echo_port):
    case = Case(name.split(":", 1)[0], name)
    work = tempfile.mkdtemp(prefix="difftest-", dir=args.tmp)
    case.dir = os.path.join(work, "sb")
    os.makedirs(os.path.join(case.dir, "logs"))
    res = {"case": name, "state": "compared", "diffs": [], "requests": 0}
    try:
        try:
            prep(case, alloc_port, echo_port)
        except Skip as e:
            res.update(state="skipped", reason=str(e))
            return res
        n_ok, n_err = check(args.nginx, "nginx", case)
        if not n_ok:
            res.update(state="nginx rejects", reason=n_err)
            return res
        r_ok, r_err = check(args.ruxen, "ruxen", case)
        if not r_ok:
            res.update(state="ruxen rejects", reason=r_err)
            return res
        case.compat = compat(args.ruxen, case)
        res["compat"] = case.compat
        reqs = requests_of(case, args.seed, args.quick)
        if args.request:
            reqs = [r for r in reqs if r[0] == args.request or r[0].endswith("/" + args.request)]
        pristine = os.path.join(work, "pristine")
        shutil.copytree(case.dir, pristine, symlinks=True)
        n_res, n_err = run_side(args.nginx, "nginx", case, reqs, args.timeout)
        if n_res is not None and len(n_res) < len(reqs):
            # nginx kept timing out (a resolver nobody answers, …): the rest is not worth the wait.
            res["reason"] = f"stopped after {len(n_res)} of {len(reqs)} requests: nginx timed out"
            reqs = [r for r in reqs if r[0] in n_res]
        shutil.rmtree(case.dir)
        shutil.copytree(pristine, case.dir, symlinks=True)
        r_res, r_err = run_side(args.ruxen, "ruxen", case, reqs, args.timeout)
        if n_res is None:
            res.update(state="nginx did not start", reason=n_err)
            return res
        if r_res is None:
            res["diffs"].append({"request": "(startup)", "class": "startup", "field": "startup",
                                 "nginx": "listens", "ruxen": r_err, "shape": "startup: ruxen doesn't listen"})
            return res
        res["requests"] = len(reqs)
        # The catalogue's first request repeats the first base one: what nginx
        # answers differently to the two is volatile ($pid, $remote_port, …).
        skip = set()
        for rid in n_res:
            if "/path:plain@" in rid:
                twin = rid.replace("/path:plain@", "/base:")
                if twin in n_res and n_res[rid][0] and n_res[twin][0]:
                    skip |= normalise.volatile(n_res[rid][0][0], n_res[twin][0][0])
        res["volatile"] = sorted(skip)
        for rid, *_ in reqs + [("(server)",)]:
            if rid not in n_res and rid not in r_res:
                continue
            a = n_res.get(rid, ([], "(no run)", []))
            b = r_res.get(rid, ([], "(no run)", []))
            for cls, field, nv, rv in normalise.compare(a[0], a[1], b[0], b[1], skip):
                d = {"request": rid, "class": cls, "field": field, "nginx": nv, "ruxen": rv,
                     "shape": normalise.shape(cls, field, nv, rv),
                     "status": a[0][-1].get("code") if a[0] else None}
                if args.verbose or args.request:
                    d["sent"] = [s[0].decode("latin-1") for s in b[2]]
                    d["nginx_raw"] = [raw(r) for r in a[0]]
                    d["ruxen_raw"] = [raw(r) for r in b[0]]
                else:
                    d["sent"] = [s[0][:2000].decode("latin-1") for s in b[2]]
                res["diffs"].append(d)
        if args.request:
            for rid, *_ in reqs:
                for side, rr in (("nginx", n_res), ("ruxen", r_res)):
                    resps, after, steps = rr.get(rid, ([], "-", []))
                    print(f"===== {side}: {rid}")
                    for s in steps:
                        print(">>> " + s[0].decode("latin-1").replace("\r\n", "\n>>> ").rstrip("> \n"))
                    for r in resps:
                        print(raw(r))
                    print(f"(then: {after})")
        return res
    except Exception:  # noqa: BLE001 - one broken case doesn't stop the run
        res.update(state="harness error", reason=traceback.format_exc(limit=3).strip().splitlines()[-1])
        return res
    finally:
        if args.keep:
            res["sandbox"] = case.dir
        else:
            shutil.rmtree(work, ignore_errors=True)


def raw(r):
    head = [r.get("status_line", "(none)")] + [f"{n}: {v}" for n, v in r.get("headers", [])]
    body = r.get("body", b"")
    s = "\n".join(r["interim"] + head) + "\n\n" + body[:4000].decode("latin-1")
    if r.get("error"):
        s += f"\n[error: {r['error']}]"
    return s


# ----------------------------------------------------------------- report

def load_expected():
    rules = []
    with open(os.path.join(HERE, "expected.tsv")) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            cols += [""] * (6 - len(cols))
            rules.append([re.compile(c) for c in cols[:5]] + [cols[5]])
    return rules


def expected(rules, case, d):
    for cls, shape, cre, rre, vre, why in rules:
        if cls.search(d["class"]) and shape.search(d["shape"]) and cre.search(case) \
                and rre.search(f"{d['request']} {d.get('status')}") \
                and vre.search(f"{d['nginx']} -> {d['ruxen']}"):
            return why
    return None


def report(results, meta, out):
    rules = load_expected()
    groups = collections.defaultdict(list)  # (section, class, shape) -> [(case, diff)]
    for r in results:
        for d in r["diffs"]:
            why = expected(rules, r["case"], d)
            if why:
                section = "expected"
                key = (section, d["class"], why)
            elif r.get("compat"):
                section = "compat"
                key = (section, d["class"], d["shape"])
            else:
                section = "new"
                key = (section, d["class"], d["shape"])
            groups[key].append((r["case"], d))
    states = collections.Counter(r["state"] for r in results)
    compared = [r for r in results if r["state"] == "compared"]
    n_req = sum(r["requests"] for r in compared)
    n_diff = len({(r["case"], d["request"]) for r in compared for d in r["diffs"]})
    lines = [
        "# Differential test: ruxen vs nginx",
        "",
        f"Generated by `scripts/difftest/difftest.py run {' '.join(meta['argv'])}`; seed {meta['seed']},"
        f" {meta['elapsed']:.0f} s. nginx: `{meta['nginx']}`; ruxen: `{meta['ruxen']}`.",
        "",
        f"**{len(compared)} configurations compared, {n_req} request specs, {n_diff} with a difference.**",
        "",
        "| cases | state |",
        "|---:|---|",
    ]
    for s, n in states.most_common():
        lines.append(f"| {n} | {s} |")
    titles = {
        "new": "Differences",
        "compat": "In configurations `ruxen --compat` flags as differing",
        "expected": "Expected (expected.tsv)",
    }
    for section in ("new", "compat", "expected"):
        keys = [k for k in groups if k[0] == section]
        keys.sort(key=lambda k: (-len({c for c, _ in groups[k]}), -len(groups[k]), k))
        lines += ["", f"## {titles[section]} ({len(keys)} groups)", ""]
        if section == "compat":
            lines += ["These configurations use something ruxen says it handles differently;",
                      "differences there are expected until it doesn't.", ""]
        for k in keys:
            items = groups[k]
            cases = sorted({c for c, _ in items})
            lines.append(f"### {k[1]}: {k[2]}")
            lines.append("")
            lines.append(f"{len(items)} requests in {len(cases)} cases: {', '.join(cases[:6])}"
                         f"{' …' if len(cases) > 6 else ''}")
            lines.append("")
            pairs = collections.Counter((d["field"], d["nginx"], d["ruxen"]) for _, d in items)
            for (field, nv, rv), n in pairs.most_common(4):
                lines.append(f"- {n}× {field}: nginx `{clip(nv)}` / ruxen `{clip(rv)}`")
            fams = collections.Counter(family(d["request"]) for _, d in items)
            lines.append("- requests: " + ", ".join(f"{f} ×{n}" for f, n in fams.most_common(8))
                         + (" …" if len(fams) > 8 else ""))
            seen_fam = set()
            ex = []
            for c, d in items:
                if family(d["request"]) in seen_fam:
                    continue
                seen_fam.add(family(d["request"]))
                ex.append((c, d))
                if len(ex) == 4:
                    break
            for c, d in ex:
                lines.append(f"- e.g. `{c}` `{d['request']}`: `{clip(d['sent'][0] if d['sent'] else '', 200)}`")
            lines.append("")
    skipped = [r for r in results if r["state"] not in ("compared",)]
    if skipped:
        lines += ["## Not compared", "", "| case | state | why |", "|---|---|---|"]
        for r in sorted(skipped, key=lambda r: (r["state"], r["case"])):
            lines.append(f"| {r['case']} | {r['state']} | {clip(r.get('reason', ''), 120)} |")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    new = sum(1 for k in groups if k[0] == "new")
    print(f"{len(compared)} configurations, {n_req} request specs, {n_diff} differing; {new} new groups, "
          f"{sum(1 for k in groups if k[0] == 'compat')} in --compat-flagged configs, "
          f"{sum(1 for k in groups if k[0] == 'expected')} expected; {out}/report.md")
    return new


def family(rid):
    """The variation a request id comes from: `host:absolute-uri`, `base`,
    `random`, `nginx-tests`."""
    r = rid.split("/", 1)[-1]
    if r.startswith("test"):
        return "nginx-tests"
    if r.startswith("rand"):
        return "random"
    if r.startswith("base:"):
        return "base"
    return r.split("@", 1)[0]


def clip(s, n=100):
    s = str(s).replace("\r", "\\r").replace("\n", "\\n").replace("`", "'").replace("|", "\\|")
    return s[:n] + ("…" if len(s) > n else "")


def version(binary):
    r = subprocess.run([binary, "-v"], capture_output=True, text=True)
    return (r.stderr + r.stdout).strip().splitlines()[0] if (r.stderr + r.stdout).strip() else binary


# ------------------------------------------------------------------- main

def main():
    global NGINX_TESTS
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    rep = sub.add_parser("report", help="re-render report.md from a run's differences.jsonl (after editing "
                                        "expected.tsv)")
    rep.add_argument("--out", default=os.path.join(ROOT, "difftest-out"))
    for name in ("run", "list"):
        s = sub.add_parser(name)
        s.add_argument("--suite", help=f"comma-separated, of {','.join(SUITES)} (default: all; --quick: "
                                       f"{','.join(QUICK_SUITES)})")
        s.add_argument("--only", help="cases whose id starts with this")
        s.add_argument("--config", action="append", default=[],
                       help="also (or, without --suite, only) this configuration file, as a curated one")
        s.add_argument("--corpus-cache", help="corpus fetch cache (default corpus/.cache)")
        s.add_argument("--nginx-tests", default=NGINX_TESTS, help="nginx-tests checkout (default ../nginx-tests)")
    r = sub.choices["run"]
    r.add_argument("--nginx", default=NGINX)
    r.add_argument("--ruxen", default=RUXEN)
    r.add_argument("--seed", default="1", help="request generation seed (`random` picks one)")
    r.add_argument("--quick", action="store_true", help="fewer random variations, curated+bench suites")
    r.add_argument("--request", help="one request id of one case (--only): prints both answers")
    r.add_argument("-j", "--jobs", type=int, default=min(8, max(1, (os.cpu_count() or 2) // 4)))
    r.add_argument("--timeout", type=float, default=1.5, help="seconds to wait for a response")
    r.add_argument("--out", default=os.path.join(ROOT, "difftest-out"))
    r.add_argument("--tmp", default=None, help="where sandboxes go (default: $TMPDIR)")
    r.add_argument("--keep", action="store_true", help="keep the sandboxes")
    r.add_argument("-v", "--verbose", action="store_true", help="full raw responses in differences.jsonl")
    r.add_argument("--fail-on-new", action="store_true", help="exit 1 if a difference isn't in expected.tsv")
    a = p.parse_args()
    if a.cmd == "report":
        with open(os.path.join(a.out, "meta.json")) as f:
            meta = json.load(f)
        with open(os.path.join(a.out, "differences.jsonl")) as f:
            results = [json.loads(line) for line in f]
        report(results, meta, a.out)
        return 0
    a.argv = sys.argv[2:]
    NGINX_TESTS = a.nginx_tests
    suites = a.suite.split(",") if a.suite else (QUICK_SUITES if getattr(a, "quick", False) else SUITES)
    for s in suites:
        if s not in SUITES:
            p.error(f"unknown suite {s}")
    if a.config:
        suites = a.suite.split(",") if a.suite else []
    cases = [(n, prep) for n, prep in all_cases(suites, a.corpus_cache, a.config)
             if not a.only or n.startswith(a.only)]
    if a.cmd == "list":
        for n, _ in cases:
            print(n)
        return 0
    if a.seed == "random":
        a.seed = str(random.randrange(1 << 30))
    for b in (a.nginx, a.ruxen):
        if not os.access(b, os.X_OK):
            p.error(f"{b} is not executable")
    srv, echo_port = echo_upstream.start()
    t0 = time.monotonic()
    results = []
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
        futs = {ex.submit(run_case, n, prep, a, echo_port): n for n, prep in cases}
        for i, f in enumerate(concurrent.futures.as_completed(futs), 1):
            r = f.result()
            results.append(r)
            if a.verbose or len(cases) > 20:
                print(f"[{i}/{len(cases)}] {r['case']}: {r['state']} {len(r['diffs'])} diffs "
                      f"{r.get('reason', '')}"[:200], file=sys.stderr, flush=True)
    srv.shutdown()
    results.sort(key=lambda r: r["case"])
    if a.request:
        return 0
    meta = {"argv": a.argv, "seed": a.seed, "elapsed": time.monotonic() - t0, "nginx": version(a.nginx),
            "ruxen": version(a.ruxen)}
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "meta.json"), "w") as f:
        json.dump(meta, f)
    with open(os.path.join(a.out, "differences.jsonl"), "w") as f:
        for r in results:
            f.write(json.dumps(r, default=str) + "\n")
    new = report(results, meta, a.out)
    return 1 if a.fail_on_new and new else 0


if __name__ == "__main__":
    sys.exit(main())
