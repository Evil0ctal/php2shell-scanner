"""The non-destructive request sequence run against one target.

What is sent (and what is deliberately NOT sent):
- GET/HEAD requests to the site, its PHP pages, common phpinfo paths, composer.json and
  the PHP < 5.5 easter-egg query strings;
- optionally (default on, --passive disables) ONE pair of small, spec-compliant
  multipart POSTs: a control and the same body plus a PHP_SESSION_UPLOAD_PROGRESS field.
  No session ID is sent anywhere, so PHP never writes upload progress into a session;
  the pair only shows whether an edge WAF filters the vulnerable feature.
- never: a PHPSESSID form field, crafted filenames, large/stalled/chunked bodies, or
  anything that crashes workers or executes code.
"""

import logging
import posixpath
import uuid
from typing import List, Optional, Set
from urllib.parse import urljoin, urlsplit

from php2shell_scanner.remote import fingerprint as fp
from php2shell_scanner.remote.http import Client, Response, multipart

LOG = logging.getLogger("php2shell_scanner")

PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo", "/test.php",
                 "/i.php", "/pi.php", "/php.php", "/infophp.php", "/dashboard/phpinfo.php",
                 "/_profiler/phpinfo")
EASTER_EGGS = ("/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42",
               "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000")
EXPOSED_FILES = ("/.env", "/.git/config")
BLOCK_STATUSES = frozenset((403, 406, 418, 429, 444, 501))
REDIRECTS = frozenset((301, 302, 303, 307, 308))
MAX_ENDPOINTS = 5


class ProbeData:
    """Evidence gathered for one target (mutable accumulator, local to one scan)."""

    def __init__(self) -> None:
        self.reachable = False
        self.error = ""
        self.home_status = 0
        self.redirect_to = ""          # same host, other scheme/port: scan_one re-targets
        self.distro: Set[str] = set()
        self.versions: List[fp.VersionSeen] = []
        self.phpinfo: Optional[fp.PhpInfo] = None
        self.phpinfo_path = ""
        self.signals: Set[str] = set()
        self.edge: Set[str] = set()
        self.sapi: Set[str] = set()
        self.long_session_ids: List[str] = []
        self.session_endpoints: List[str] = []
        self.composer_php = ""
        self.legacy_egg = False
        self.reachability = "skipped"
        self.exposed: List[str] = []
        self.endpoints: List[str] = []
        self.notes: List[str] = []

    def observe(self, response: Response, where: str) -> None:
        if not response.ok:
            return
        self.versions.extend(fp.versions_in(response, where))
        self.signals.update(fp.php_signals(response))
        for source, value in ((self.edge, fp.edge_provider(response)),
                              (self.sapi, fp.sapi_hint(response))):
            if value:
                source.add(value)
        distro = fp.distro_build(response)
        if distro:
            self.distro.add(distro)
        leak = fp.long_session_id(response)
        if leak:
            self.long_session_ids.append("{} ({})".format(leak, where))
        if fp.sets_session(response) and where not in self.session_endpoints:
            self.session_endpoints.append(where)


def _join(base: str, path: str) -> str:
    if path.startswith("/"):
        return path
    return posixpath.join(base if base.endswith("/") else base + "/", path)


def _home(client: Client, data: ProbeData) -> Optional[Response]:
    """GET the base path; follow at most ONE redirect, and only within the same host."""
    base = client.target.base_path
    response = client.request("GET", base)
    if not response.ok:
        data.error = response.error or "no response"
        return None
    data.reachable, data.home_status = True, response.status
    data.observe(response, base)
    if response.status not in REDIRECTS or not response.header("Location"):
        return response
    location = urljoin(client.target.url, response.header("Location"))
    parts = urlsplit(location)
    if parts.hostname != client.target.host:
        data.notes.append("Home page redirects to another host ({}) - not followed; scan it "
                          "explicitly if it is yours".format(parts.hostname))
        return response
    same_origin = parts.scheme == client.target.scheme and (parts.port or (
        443 if parts.scheme == "https" else 80)) == client.target.port
    if not same_origin:
        data.redirect_to = location
        return response
    path = parts.path or "/"
    follow = client.request("GET", path)
    data.observe(follow, path)
    if follow.ok:
        data.home_status = follow.status
        return follow
    return response


def _endpoints(client: Client, home: Response, extra: List[str]) -> List[str]:
    """User-supplied paths first, then the site root, index.php and linked PHP pages."""
    base = client.target.base_path
    user = [_join(base, p) for p in extra]
    auto = [base, _join(base, "index.php")] + fp.php_links(home, client.target.host)
    if "WordPress" in fp.php_signals(home):
        auto.append(_join(base, "wp-login.php"))
    ordered: List[str] = []
    for path in user + auto:
        if path not in ordered:
            ordered.append(path)
    return ordered[:len(user) + MAX_ENDPOINTS]


def _fingerprint_rounds(client: Client, data: ProbeData, rounds: int) -> None:
    """Repeat the passive fingerprint: catches load balancers with mixed PHP versions."""
    for _ in range(max(1, rounds)):
        for path in data.endpoints:
            data.observe(client.request("GET", path), path)


def _phpinfo(client: Client, data: ProbeData) -> None:
    for path in PHPINFO_PATHS:
        response = client.request("GET", path)
        info = fp.parse_phpinfo(response)
        if info:
            data.phpinfo, data.phpinfo_path = info, path
            data.signals.add("phpinfo page")
            data.exposed.append("phpinfo() exposed at {} (leaks version and configuration)"
                                .format(path))
            return


def _context(client: Client, data: ProbeData, home: Response) -> None:
    if not data.versions and not data.phpinfo:
        for path in EASTER_EGGS:
            if fp.legacy_easter_egg(client.request("GET", path), home):
                data.legacy_egg = True
                data.signals.add("PHP < 5.5 easter egg")
                break
    constraint = fp.composer_php_constraint(client.request("GET", "/composer.json"))
    if constraint:
        data.composer_php = constraint
        data.exposed.append("composer.json is public (PHP constraint {})".format(constraint))
    # Soft-404 baseline: a site answering 200 for any path proves nothing about .env.
    baseline = client.request("HEAD", "/php2shell-scanner-{}.txt".format(uuid.uuid4().hex[:12]))
    for path in EXPOSED_FILES:
        if baseline.status == 200:
            break
        head = client.request("HEAD", path)
        length = head.header("Content-Length")
        ctype = head.header("Content-Type").lower()
        if head.status == 200 and length.isdigit() and int(length) > 0 and "html" not in ctype:
            data.exposed.append("{} appears to be downloadable (HEAD 200, {} bytes) - not "
                                "fetched".format(path, length))


def _reachability(client: Client, data: ProbeData) -> None:
    # Always the site root: never POST into user-named handlers such as /upload.php.
    target = client.target.base_path
    boundary = "----php2shell-scanner-" + uuid.uuid4().hex[:16]
    files = [("probe", "php2shell-scanner.txt", b"php2shell-scanner reachability check")]
    headers = {"Content-Type": "multipart/form-data; boundary=" + boundary}
    control = client.request("POST", target, headers, multipart([("note", "control")], files,
                                                                 boundary))
    probe = client.request("POST", target, headers, multipart(
        [("PHP_SESSION_UPLOAD_PROGRESS", "php2shell-scanner")], files, boundary))
    if not (control.ok and probe.ok):
        data.reachability = "error"
    elif control.status in REDIRECTS or control.status >= 500:
        data.reachability = "inconclusive"
    elif probe.status in BLOCK_STATUSES and control.status not in BLOCK_STATUSES:
        data.reachability = "blocked-at-edge"
    elif probe.status in BLOCK_STATUSES:
        data.reachability = "multipart-blocked"
    else:
        data.reachability = "reachable"
    data.notes.append("Reachability POST to {}: control HTTP {}, upload-progress HTTP {}".format(
        target, control.status or control.error, probe.status or probe.error))
    after = client.request("GET", client.target.base_path)
    if data.reachable and not after.ok:
        data.notes.append("Target stopped answering after the reachability check "
                          "({}); re-check its health.".format(after.error))


def run_probes(client: Client, extra_paths: List[str], rounds: int, active: bool) -> ProbeData:
    data = ProbeData()
    home = _home(client, data)
    if home is None or data.redirect_to:
        return data
    data.endpoints = _endpoints(client, home, extra_paths)
    _fingerprint_rounds(client, data, rounds)
    _phpinfo(client, data)
    if data.phpinfo and data.phpinfo.sapi:
        data.sapi.add("Server API: " + data.phpinfo.sapi)
    _context(client, data, home)
    if active:
        _reachability(client, data)
    if client.tls_note:
        data.notes.append(client.tls_note)
    if client.budget_exhausted:
        data.notes.append("Per-target time budget exhausted; some checks were skipped")
    return data
