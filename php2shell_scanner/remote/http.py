"""Minimal, bounded HTTP client (stdlib http.client) used by the remote checks.

One connection per request, bounded body reads, no redirects followed automatically,
identifiable User-Agent, and an optional politeness delay between requests.
"""

import http.client
import socket
import ssl
import threading
import time
from typing import Dict, List, NamedTuple, Optional, Tuple

from php2shell_scanner import __version__
from php2shell_scanner.remote.target import Target

USER_AGENT = ("php2shell-scanner/{} (+https://github.com/Evil0ctal/php2shell-scanner; "
              "non-destructive vulnerability check)".format(__version__))
MAX_BODY = 512 * 1024
READ_CHUNK = 8 * 1024
REQUEST_DEADLINE_FACTOR = 3     # total time per request = 3 x --timeout
MIN_REQUEST_BUDGET = 0.5        # do not start a request that cannot finish in time


class Response(NamedTuple):
    status: int
    reason: str
    headers: Tuple[Tuple[str, str], ...]
    body: bytes
    elapsed: float
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and self.status > 0

    def header(self, name: str) -> str:
        lower = name.lower()
        return next((v for k, v in self.headers if k.lower() == lower), "")

    def header_all(self, name: str) -> List[str]:
        lower = name.lower()
        return [v for k, v in self.headers if k.lower() == lower]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Client:
    """HTTP client bound to one target. Thread-confined: one Client per worker."""

    def __init__(self, target: Target, timeout: float = 10.0, delay: float = 0.2,
                 verify_tls: bool = True, allow_insecure_fallback: bool = True,
                 user_agent: str = USER_AGENT, budget: float = 300.0) -> None:
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.allow_insecure_fallback = allow_insecure_fallback
        self.tls_note = ""
        self.requests = 0
        self.deadline = time.time() + budget     # hard wall-clock limit for this target
        self.budget_exhausted = False
        self._last = 0.0
        self._lock = threading.Lock()

    def _connection(self) -> http.client.HTTPConnection:
        if self.target.scheme == "https":
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.target.host, self.target.port,
                                               timeout=self.timeout, context=context)
        return http.client.HTTPConnection(self.target.host, self.target.port, timeout=self.timeout)

    def _pace(self) -> None:
        with self._lock:
            wait = self.delay - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
            self.requests += 1

    def request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
                body: Optional[bytes] = None) -> Response:
        if time.time() > self.deadline:
            self.budget_exhausted = True
            return Response(0, "", (), b"", 0.0, "per-target time budget exhausted")
        self._pace()
        merged = {"User-Agent": self.user_agent, "Accept": "*/*", "Connection": "close",
                  "Host": self.target.netloc}
        merged.update(headers or {})
        response, cert_error = self._attempt(method, path, merged, body)
        # The scanner sends no credentials, so an untrusted certificate only affects how far
        # the result can be trusted: record it and continue, unless --strict-tls.
        if cert_error and self.verify_tls and self.allow_insecure_fallback:
            self.verify_tls = False
            self.tls_note = "TLS certificate not trusted ({}); continued without " \
                            "verification".format(response.error)
            response, _ = self._attempt(method, path, merged, body)
        return response

    def _attempt(self, method: str, path: str, headers: Dict[str, str],
                 body: Optional[bytes]) -> Tuple[Response, bool]:
        """Never raises: errors come back as Response.error (plus a cert-failure flag)."""
        started = time.time()
        try:
            return self._send(method, path, headers, body, started), False
        except (ssl.SSLError, ssl.CertificateError) as exc:
            cert = isinstance(exc, ssl.CertificateError) or \
                "CERTIFICATE_VERIFY_FAILED" in str(getattr(exc, "reason", "")) or \
                "certificate verify failed" in str(exc).lower()
            return Response(0, "", (), b"", time.time() - started, "TLS error: {}".format(exc)), cert
        except (OSError, http.client.HTTPException, ValueError) as exc:
            return Response(0, "", (), b"", time.time() - started,
                            "{}: {}".format(type(exc).__name__, exc)), False

    def _send(self, method: str, path: str, headers: Dict[str, str], body: Optional[bytes],
              started: float) -> Response:
        conn = self._connection()
        # Socket timeouts bound each recv, not the exchange: a server trickling its status
        # line/headers one byte at a time would otherwise hold us for days. The watchdog
        # shuts the socket down at the deadline, which unblocks any pending read.
        budget = min(self.timeout * REQUEST_DEADLINE_FACTOR, self.deadline - started)
        if budget < MIN_REQUEST_BUDGET:
            conn.close()
            self.budget_exhausted = True
            return Response(0, "", (), b"", 0.0, "per-target time budget exhausted")
        expired = threading.Event()
        watchdog = threading.Timer(budget, _shutdown, args=(conn, expired))
        watchdog.daemon = True
        watchdog.start()
        try:
            conn.connect()
            if expired.is_set():   # the watchdog fired while there was no socket to close
                return Response(0, "", (), b"", time.time() - started,
                                "request deadline exceeded during connect")
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = self._read_body(resp, started) if method != "HEAD" else b""
            return Response(resp.status, resp.reason, tuple(resp.getheaders()), data,
                            time.time() - started)
        except socket.timeout:
            return Response(0, "", (), b"", time.time() - started, "timeout")
        except (OSError, http.client.HTTPException) as exc:
            if expired.is_set():
                return Response(0, "", (), b"", time.time() - started,
                                "request deadline exceeded ({:.0f}s)".format(budget))
            raise exc
        finally:
            watchdog.cancel()
            conn.close()

    def _read_body(self, resp: http.client.HTTPResponse, started: float) -> bytes:
        """Bounded in size AND total time: a server trickling one byte per second must not
        hold the scan (socket timeouts only bound each individual read)."""
        deadline = started + self.timeout * REQUEST_DEADLINE_FACTOR
        chunks: List[bytes] = []
        size = 0
        while size < MAX_BODY and time.time() < deadline:
            chunk = resp.read1(min(READ_CHUNK, MAX_BODY - size))  # returns on any data
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)


def _shutdown(conn: http.client.HTTPConnection, expired: threading.Event) -> None:
    expired.set()
    sock = getattr(conn, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def multipart(fields: List[Tuple[str, str]], files: List[Tuple[str, str, bytes]],
              boundary: str) -> bytes:
    """RFC 7578 body. Field names/values are ours (constants), never user input."""
    out = []
    for name, value in fields:
        out.append("--{}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n".format(
            boundary, name, value).encode())
    for name, filename, content in files:
        out.append("--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n"
                   "Content-Type: text/plain\r\n\r\n".format(boundary, name, filename).encode()
                   + content + b"\r\n")
    out.append("--{}--\r\n".format(boundary).encode())
    return b"".join(out)
