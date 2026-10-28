"""A raw HTTP/1.x client: sends bytes exactly as given, parses what comes back
without trusting it (the point is to see what the server did)."""

import socket
import ssl
import time

_TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE
_TLS.set_alpn_protocols(["http/1.1"])


class Conn:
    def __init__(self, port, tls=False, sni=None, timeout=2.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls:
            self.sock = _TLS.wrap_socket(self.sock, server_hostname=sni if sni and not sni[0].isdigit() else None)
        self.buf = b""
        self.eof = None  # None, "closed" or "reset"
        self.timeout = timeout

    def send(self, data):
        try:
            self.sock.sendall(data)
        except OSError:
            self.eof = self.eof or "reset"

    def _fill(self, deadline):
        if self.eof:
            return False
        left = deadline - time.monotonic()
        if left <= 0:
            return False
        self.sock.settimeout(left)
        try:
            data = self.sock.recv(65536)
        except (socket.timeout, TimeoutError, ssl.SSLWantReadError):
            return False
        except (ConnectionResetError, BrokenPipeError):
            self.eof = "reset"
            return False
        except (ssl.SSLError, OSError):
            self.eof = "reset"
            return False
        if not data:
            self.eof = "closed"
            return False
        self.buf += data
        return True

    def _line(self, deadline, limit=1 << 20):
        while b"\n" not in self.buf:
            if len(self.buf) > limit or not self._fill(deadline):
                return None
        line, _, self.buf = self.buf.partition(b"\n")
        return line.rstrip(b"\r")

    def _exact(self, n, deadline):
        while len(self.buf) < n:
            if not self._fill(deadline):
                return None
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def response(self, head_only=False):
        """One response as a dict; `error` says what went wrong reading it."""
        deadline = time.monotonic() + self.timeout
        r = {"interim": [], "headers": [], "body": b"", "framing": "none", "error": None}
        while True:
            while not self.buf and self._fill(deadline):
                pass
            if not self.buf:
                r["error"] = "timeout" if not self.eof else self.eof
                return r
            if not self.buf.startswith(b"HTTP/") and not b"HTTP/".startswith(self.buf[:5]):
                # HTTP/0.9: no status line, the body runs to the close.
                while self._fill(deadline):
                    pass
                r.update(status_line="(HTTP/0.9)", code=0, body=self.buf, framing="close")
                self.buf = b""
                return r
            line = self._line(deadline)
            if line is None:
                r["error"] = "truncated head"
                return r
            status_line = line.decode("latin-1")
            headers = []
            while True:
                h = self._line(deadline)
                if h is None:
                    r["error"] = "truncated head"
                    r["status_line"] = status_line
                    return r
                if h == b"":
                    break
                name, _, value = h.decode("latin-1").partition(":")
                headers.append((name, value.strip()))
            parts = status_line.split(" ", 2)
            try:
                code = int(parts[1])
            except (IndexError, ValueError):
                code = -1
            if 100 <= code < 200 and code != 101:
                r["interim"].append(status_line)
                continue
            r.update(status_line=status_line, code=code, headers=headers)
            break
        lower = {}
        for n, v in headers:
            lower.setdefault(n.lower(), v)
        if head_only or code in (101, 204, 304):
            return r
        if "chunked" in lower.get("transfer-encoding", "").lower():
            r["framing"] = "chunked"
            body = b""
            while True:
                size_line = self._line(deadline)
                if size_line is None:
                    r["error"] = "truncated chunked body"
                    break
                try:
                    size = int(size_line.split(b";")[0].strip(), 16)
                except ValueError:
                    r["error"] = "bad chunk size"
                    break
                if size == 0:
                    while True:
                        t = self._line(deadline)
                        if t is None or t == b"":
                            break
                    break
                data = self._exact(size + 2, deadline)
                if data is None:
                    r["error"] = "truncated chunked body"
                    break
                body += data[:-2]
            r["body"] = body
        elif "content-length" in lower:
            r["framing"] = "length"
            try:
                n = int(lower["content-length"])
            except ValueError:
                r["error"] = "bad content-length"
                return r
            data = self._exact(n, deadline)
            if data is None:
                r["error"] = "truncated body"
                data, self.buf = self.buf, b""
            r["body"] = data
        else:
            r["framing"] = "close"
            while self._fill(deadline):
                pass
            r["body"], self.buf = self.buf, b""
        return r

    def after(self, wait):
        """What the connection does after the last response: "closed",
        "reset", "open", or "extra bytes"."""
        if self.buf:
            return "extra bytes"
        deadline = time.monotonic() + wait
        while not self.eof and self._fill(deadline):
            pass
        if self.buf:
            return "extra bytes"
        return self.eof or "open"

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def exchange(port, steps, tls=False, sni=None, timeout=2.0, linger=0.3):
    """Runs one request spec: `steps` is a list of (bytes to send, number of
    responses to read, whether they answer HEAD[, delay before sending]). Returns (responses, what
    the connection did afterwards)."""
    try:
        c = Conn(port, tls, sni, timeout)
    except (OSError, ssl.SSLError) as e:
        return [], f"connect failed: {type(e).__name__}"
    out = []
    try:
        for data, n, head, *delay in steps:
            if delay:
                time.sleep(delay[0])
            c.send(data)
            for i in range(n):
                r = c.response(head_only=head[i] if isinstance(head, list) else head)
                out.append(r)
                if r["error"]:
                    return out, c.eof or r["error"]
        return out, c.after(linger)
    finally:
        c.close()
