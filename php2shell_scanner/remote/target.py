"""Target parsing: URLs, domains, IPv4/IPv6 with optional port and base path."""

import re
from typing import List, NamedTuple, Tuple
from urllib.parse import urlsplit

HTTPS_PORTS = frozenset((443, 8443, 9443))
HTTP_PORTS = frozenset((80, 8080, 8000, 8008, 8888))
HOST_RE = re.compile(r"^(?:\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.\-_]{1,253})$")


class Target(NamedTuple):
    raw: str
    scheme: str
    host: str      # without brackets
    port: int
    base_path: str

    @property
    def netloc(self) -> str:
        host = "[{}]".format(self.host) if ":" in self.host else self.host
        default = (self.scheme == "https" and self.port == 443) or \
                  (self.scheme == "http" and self.port == 80)
        return host if default else "{}:{}".format(host, self.port)

    @property
    def url(self) -> str:
        return "{}://{}{}".format(self.scheme, self.netloc, self.base_path)


def _split_host_port(text: str) -> Tuple[str, int]:
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 0
        return host, port
    if text.count(":") == 1:
        host, port = text.split(":")
        if not port.isdigit():
            raise ValueError("bad port in {!r}".format(text))
        return host, int(port)
    return text, 0     # bare host or bare IPv6 address


def parse_target(raw: str) -> List[Target]:
    """One or two candidate targets (https first when the scheme is ambiguous)."""
    text = raw.strip()
    if not text:
        raise ValueError("empty target")
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("unsupported target {!r}".format(raw))
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return [Target(raw, parts.scheme, parts.hostname, port, parts.path or "/")]
    hostport, slash, path = text.partition("/")
    host, port = _split_host_port(hostport)
    if not HOST_RE.match(host if ":" not in host else "[" + host + "]"):
        raise ValueError("invalid host in {!r}".format(raw))
    if not 0 <= port <= 65535:
        raise ValueError("invalid port in {!r}".format(raw))
    base = "/" + path if slash else "/"
    if port in HTTPS_PORTS:
        return [Target(raw, "https", host, port, base)]
    if port in HTTP_PORTS:
        return [Target(raw, "http", host, port, base)]
    if port:
        return [Target(raw, "https", host, port, base), Target(raw, "http", host, port, base)]
    return [Target(raw, "https", host, 443, base), Target(raw, "http", host, 80, base)]


def read_target_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return [line.strip() for line in handle
                if line.strip() and not line.lstrip().startswith("#")]
