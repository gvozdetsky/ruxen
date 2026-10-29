#!/usr/bin/env python3
"""Deterministic echo upstream for the differential harness.

    scripts/difftest/echo_upstream.py [--port N]

Answers every request with what it received, so the request rewriting of a
proxy is compared too: the request line, the headers sorted by lower-cased
name (order kept within a name: HTTP says the order across names doesn't
matter), how the body was framed, and the body. Nothing in the answer
depends on time or on the connection.

A few paths ask for upstream behaviour the proxy has to handle:
`/echo-status/NNN` answers NNN, `/echo-redirect` a 302 to the upstream's own
address, `/echo-chunked` a chunked body, `/echo-cache` cache validators and
`Set-Cookie`.
"""

import argparse
import socket
import socketserver
import threading


def read_request(rfile):
    """(request line, [(name, value)], body, framing) or None at EOF."""
    line = rfile.readline(65536)
    while line in (b"\r\n", b"\n"):
        line = rfile.readline(65536)
    if not line:
        return None
    headers = []
    while True:
        h = rfile.readline(65536)
        if h in (b"\r\n", b"\n", b""):
            break
        name, _, value = h.decode("latin-1").partition(":")
        headers.append((name.strip(), value.strip()))
    lower = {n.lower(): v for n, v in headers}
    body, framing = b"", "none"
    if "chunked" in lower.get("transfer-encoding", "").lower():
        framing = "chunked"
        while True:
            size = int(rfile.readline(1024).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while rfile.readline(65536) not in (b"\r\n", b"\n", b""):
                    pass
                break
            body += rfile.read(size)
            rfile.readline(16)
    elif "content-length" in lower:
        framing = "length"
        body = rfile.read(int(lower["content-length"]))
    return line.decode("latin-1").rstrip("\r\n"), headers, body, framing


def answer(reqline, headers, body, framing):
    parts = reqline.split()
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else "HTTP/0.9"
    lower = {n.lower(): v for n, v in headers}
    keep = version == "HTTP/1.1" and lower.get("connection", "").lower() != "close"

    order = {}
    for n, v in headers:
        order.setdefault(n.lower(), []).append(v)
    text = [reqline]
    for n in sorted(order):
        for v in order[n]:
            text.append(f"{n}: {v}")
    text.append(f"framing: {framing}")
    text.append("")
    out = "\n".join(text).encode("latin-1") + b"\n" + body

    status, extra, chunked = "200 OK", [], False
    if "/echo-status/" in path:
        code = path.split("/echo-status/")[1][:3]
        if code.isdigit() and code[0] in "12345":
            status = f"{code} Echo"
    if "/echo-redirect" in path:
        status = "302 Found"
        extra.append(f"Location: http://{lower.get('host', 'localhost')}/redirected/")
    if "/echo-chunked" in path:
        chunked = True
    if "/echo-cache" in path:
        extra += ["Cache-Control: max-age=60", 'ETag: "echo"', "Last-Modified: Thu, 01 Jan 2026 00:00:00 GMT",
                  "Set-Cookie: echo=1; Path=/", "Vary: Accept-Encoding"]
    head = [f"HTTP/1.1 {status}", "Content-Type: text/plain", "X-Echo: 1"] + extra
    if chunked:
        head.append("Transfer-Encoding: chunked")
        payload = b"".join(b"%x\r\n%s\r\n" % (len(c), c) for c in (out[:7], out[7:]) if c) + b"0\r\n\r\n"
    else:
        head.append(f"Content-Length: {len(out)}")
        payload = out
    if not keep:
        head.append("Connection: close")
    if method == "HEAD" or status[:3] in ("204", "304"):
        payload = b""
    return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + payload, keep


class Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self):
        try:
            while True:
                req = read_request(self.rfile)
                if req is None:
                    return
                data, keep = answer(*req)
                self.wfile.write(data)
                self.wfile.flush()
                if not keep:
                    return
        except (OSError, ValueError):
            return


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(port=0):
    """Starts the echo server in a thread; returns (server, port)."""
    srv = Server(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=0)
    a = p.parse_args()
    srv = Server(("127.0.0.1", a.port), Handler)
    print(f"echo upstream on 127.0.0.1:{srv.server_address[1]}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    socket.setdefaulttimeout(30)
    main()
