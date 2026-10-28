"""nginx configuration as a tree, and the rewrites that make one case runnable
on loopback: listen ports onto free ones, upstreams onto the echo server,
lifecycle and log paths into the sandbox."""

import re


class Stmt:
    __slots__ = ("name", "args", "block")

    def __init__(self, name, args, block=None):
        self.name, self.args, self.block = name, args, block


def tokens(text):
    """Raw tokens (quotes kept) and the `;`, `{`, `}` punctuation."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in ";{}":
            yield c
            i += 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in ";{}":
                if text[j] in "\"'" and j == i:
                    q, j = text[j], j + 1
                    while j < n and text[j] != q:
                        j += 2 if text[j] == "\\" else 1
                    j += 1
                    break
                if text[j] == "$" and j + 1 < n and text[j + 1] == "{":
                    j = text.find("}", j) + 1 or n
                    continue
                j += 1
            yield text[i:j]
            i = j


def parse(text):
    stack, cur, words = [], [], []
    for t in tokens(text):
        if t == ";":
            if words:
                cur.append(Stmt(words[0], words[1:]))
            words = []
        elif t == "{":
            st = Stmt(words[0] if words else "", words[1:], [])
            cur.append(st)
            stack.append(cur)
            cur, words = st.block, []
        elif t == "}":
            if words:
                cur.append(Stmt(words[0], words[1:]))
                words = []
            if not stack:
                raise ValueError("unbalanced }")
            cur = stack.pop()
        else:
            words.append(t)
    if stack:
        raise ValueError("unbalanced {")
    return cur


def dump(tree, depth=0):
    out = []
    pad = "    " * depth
    for st in tree:
        head = " ".join([st.name] + st.args)
        if st.block is None:
            out.append(f"{pad}{head};")
        else:
            out.append(f"{pad}{head} {{")
            out.append(dump(st.block, depth + 1))
            out.append(f"{pad}}}")
    return "\n".join(x for x in out if x != "")


def walk(tree, ctx=()):
    """(statement, enclosing block names) for every statement."""
    for st in tree:
        yield st, ctx
        if st.block is not None:
            yield from walk(st.block, ctx + (st.name,))


def unquote(s):
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'" else s


LISTEN_ADDR = re.compile(r"^(?:(\[[^\]]*\]|[^:\[]+):)?(\d+)$")
IPV4_OR_NAME = re.compile(r"^[A-Za-z0-9.*-]+$")


def listen_port(arg):
    """(host or None, port) of a listen argument; None for unix sockets."""
    a = unquote(arg)
    if a.startswith("unix:"):
        return None
    m = LISTEN_ADDR.match(a)
    if m:
        return m.group(1), int(m.group(2))
    # A bare address listens on 80.
    return a, 80


class Rewriter:
    """Maps the case's ports onto free ones, consistently across files."""

    def __init__(self, alloc, echo_port, sandbox):
        self.alloc = alloc
        self.echo_port = echo_port
        self.sandbox = sandbox
        self.ports = {}  # old listen port -> new port
        self.ssl_ports = set()  # new ports with `ssl`
        self.servers = []  # [(new ports, server names, location paths)]
        self.log_n = 0

    def port(self, old):
        if old not in self.ports:
            self.ports[old] = self.alloc()
        return self.ports[old]

    def collect_listens(self, tree):
        for st, _ in walk(tree):
            if st.name == "listen" and st.args:
                lp = listen_port(st.args[0])
                if lp:
                    self.port(lp[1])

    def rewrite(self, tree, top=True):
        """Rewrites the tree in place; `top` is the main file (lifecycle
        directives are dropped there)."""
        out = []
        for st in tree:
            n = st.name
            if top and n in ("daemon", "master_process", "pid", "worker_processes", "lock_file",
                             "worker_rlimit_nofile", "user", "load_module"):
                continue
            if n == "error_log":
                st.args = [f"logs/error-{self._n()}.log"] + st.args[1:2]
            elif n == "access_log" and st.args and unquote(st.args[0]) != "off":
                st.args = [f"logs/access-{self._n()}.log"] + [a for a in st.args[1:2] if "=" not in a]
            elif n == "listen" and st.args:
                lp = listen_port(st.args[0])
                if lp:
                    host, old = lp
                    new = self.port(old)
                    v6 = host is not None and host.startswith("[")
                    st.args[0] = f"[::1]:{new}" if v6 else f"127.0.0.1:{new}"
                    # Sequential runs on the same port: no reuseport races.
                    st.args = [a for a in st.args if a not in ("reuseport",) and not a.startswith("backlog=")]
                    if "ssl" in st.args[1:]:
                        self.ssl_ports.add(new)
            elif n in ("proxy_pass", "fastcgi_pass", "uwsgi_pass", "scgi_pass", "grpc_pass",
                       "memcached_pass") and st.args:
                st.args[0] = self.target(st.args[0])
            elif n == "server" and st.block is None and st.args:
                # An upstream's `server host:port`.
                st.args[0] = self.hostport(st.args[0])
            if st.block is not None:
                st.block = self.rewrite(st.block, top and n in ("", "http"))
                if n == "server" and not any(s.name == "listen" for s in st.block):
                    st.block.insert(0, Stmt("listen", [f"127.0.0.1:{self.port(80)}"]))
            out.append(st)
        return out

    def _n(self):
        self.log_n += 1
        return self.log_n

    def hostport(self, hp):
        q = unquote(hp)
        if "$" in q or q.startswith("unix:"):
            return hp
        m = re.match(r"^(\[[^\]]*\]|[^:/]+)(?::(\d+))?$", q)
        if not m:
            return hp
        port = int(m.group(2) or 80)
        if port in self.ports:
            return f"127.0.0.1:{self.ports[port]}"
        return f"127.0.0.1:{self.echo_port}"

    def target(self, url):
        q = unquote(url)
        m = re.match(r"^(\w+://)([^/$]+)(.*)$", q)
        if not m or "$" in m.group(2):
            return url
        scheme, hp, rest = m.groups()
        if hp in self.upstream_names:
            return url
        return scheme + self.hostport(hp) + rest

    def servers_of(self, tree):
        """Where to send requests: for each server block, its ports, names
        and literal location paths."""
        for st, ctx in walk(tree):
            if st.name != "server" or st.block is None or (ctx and ctx[-1] == "upstream"):
                continue
            ports, names, paths = [], [], []
            for s in st.block:
                if s.name == "listen" and s.args:
                    m = re.search(r":(\d+)$", unquote(s.args[0]))
                    if m and not s.args[0].startswith("[") and int(m.group(1)) not in ports:
                        ports.append(int(m.group(1)))
                elif s.name == "server_name":
                    names += [unquote(a) for a in s.args]
            for s, _ in walk(st.block):
                if s.name == "location" and s.block is not None and s.args:
                    a = [unquote(x) for x in s.args]
                    if a[0] in ("=", "^~") and len(a) > 1:
                        paths.append(a[1])
                    elif a[0].startswith("/"):
                        paths.append(a[0])
            if ports:
                self.servers.append((ports, names, paths))
        return self.servers

    def prepare(self, tree):
        self.upstream_names = {unquote(st.args[0]) for st, _ in walk(tree) if st.name == "upstream" and st.args}
        self.collect_listens(tree)
        return self.rewrite(tree)


def request_host(names):
    """The Host a client would send to a server block."""
    for n in names:
        if n and n not in ("_", '""', "localhost") and not n.startswith(("~", "*", ".")) and "*" not in n \
                and "$" not in n:
            return n
    return "localhost"
