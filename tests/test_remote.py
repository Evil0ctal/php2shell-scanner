"""Remote scanner against a local fake web server (no network needed)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import pytest

from php2shell_scanner import cli
from php2shell_scanner.remote import verdict as v
from php2shell_scanner.remote.http import Client
from php2shell_scanner.remote.probes import run_probes
from php2shell_scanner.remote.target import parse_target

PHPINFO = ("<html><head><title>PHP 8.4.10 - phpinfo()</title></head><body><h1 class=\"p\">"
           "PHP Version 8.4.10</h1><table><tr><td class=\"e\">Server API </td><td class=\"v\">"
           "FPM/FastCGI </td></tr><tr><td class=\"e\">session.upload_progress.enabled</td>"
           "<td class=\"v\">Off</td><td class=\"v\">On</td></tr></table></body></html>")


class ThreadingServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def _record(self, body=b""):
        self.server.requests.append((self.command, self.path, dict(self.headers), body))

    def _send(self, status, body=b"", extra=None):
        behavior = self.server.behavior
        self.send_response(status)
        powered = behavior.get("powered")
        if isinstance(powered, list):
            powered = powered[len(self.server.requests) % len(powered)]
        if powered:
            self.send_header("X-Powered-By", powered)
        for key, value in list(behavior.get("headers", {}).items()) + list((extra or {}).items()):
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._record()
        behavior = self.server.behavior
        if self.path == "/" and behavior.get("redirect"):
            return self._send(301, b"", {"Location": behavior["redirect"]})
        if self.path == "/" and behavior.get("home_status"):
            return self._send(behavior["home_status"], b"forbidden")
        if behavior.get("catch_all"):
            return self._send(200, behavior.get("home", b"<html>spa</html>"))
        if self.path in ("/", "/index.php"):
            return self._send(200, behavior.get("home", b"<html><a href='/login.php'>x</a></html>"),
                              behavior.get("home_headers"))
        if self.path == "/login.php":
            return self._send(200, b"login")
        if self.path == "/phpinfo.php" and behavior.get("phpinfo"):
            return self._send(200, behavior["phpinfo"].encode())
        if self.path.startswith("/?=PHPE9568F34") and behavior.get("egg"):
            return self._send(200, b"GIF89a....", {"Content-Type": "image/gif"})
        if self.path == "/composer.json" and behavior.get("composer"):
            return self._send(200, json.dumps({"require": {"php": ">=8.2"}}).encode())
        return self._send(404, b"not found")

    def do_HEAD(self):
        self._record()
        if self.server.behavior.get("catch_all"):
            return self._send(200, b"<html>spa</html>", {"Content-Type": "text/plain"})
        if self.path == "/.env" and self.server.behavior.get("env"):
            return self._send(200, b"APP_KEY=secret\n", {"Content-Type": "text/plain"})
        return self._send(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self._record(body)
        if self.server.behavior.get("waf") and b"PHP_SESSION_UPLOAD_PROGRESS" in body:
            return self._send(403, b"blocked by WAF")
        return self._send(200, b"ok")


@pytest.fixture
def server():
    srv = ThreadingServer(("127.0.0.1", 0), Handler)
    srv.behavior, srv.requests = {}, []
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def scan(srv, rounds=2, active=True, paths=()):
    target = parse_target("http://127.0.0.1:{}/".format(srv.server_address[1]))[0]
    client = Client(target, timeout=5, delay=0)
    return v.evaluate(target.url, run_probes(client, list(paths), rounds, active), client.requests)


# ------------------------------------------------------------------ target parsing
@pytest.mark.parametrize("raw, expected", [
    ("example.com", [("https", "example.com", 443, "/"), ("http", "example.com", 80, "/")]),
    ("example.com:8443/app", [("https", "example.com", 8443, "/app")]),
    ("10.0.0.5:8080", [("http", "10.0.0.5", 8080, "/")]),
    ("http://[::1]:9000/x", [("http", "::1", 9000, "/x")]),
    ("[2001:db8::1]:8443", [("https", "2001:db8::1", 8443, "/")]),
    ("https://shop.example.com/", [("https", "shop.example.com", 443, "/")]),
])
def test_parse_target(raw, expected):
    assert [(t.scheme, t.host, t.port, t.base_path) for t in parse_target(raw)] == expected


@pytest.mark.parametrize("raw", ["", "ftp://x", "bad host!", "host:notaport"])
def test_parse_target_rejects(raw):
    with pytest.raises(ValueError):
        parse_target(raw)


# --------------------------------------------------------------------- verdicts
def test_vulnerable_header_version(server):
    server.behavior["powered"] = "PHP/8.2.20"
    result = scan(server)
    assert result.status == v.VULNERABLE and result.confidence == "high"
    assert "8.2.20" in result.versions


def test_patched_header_version(server):
    server.behavior["powered"] = "PHP/8.3.36"
    assert scan(server).status == v.NOT_VULNERABLE


def test_distribution_backport_is_only_likely(server):
    server.behavior["powered"] = "PHP/8.1.2-1ubuntu2.14"
    result = scan(server)
    assert result.status == v.LIKELY and any("backported" in r for r in result.reasons)


def test_phpinfo_beats_hidden_header_and_reports_mitigation(server):
    server.behavior.update(phpinfo=PHPINFO)
    result = scan(server)
    assert result.status == v.VULNERABLE and result.confidence == "high"
    assert any("upload_progress.enabled = Off" in m for m in result.mitigations)
    assert any("phpinfo() exposed" in e for e in result.exposures)
    assert any("FPM/FastCGI" in c for c in result.context)


def test_edge_waf_is_reported_as_mitigation(server):
    server.behavior.update(powered="PHP/8.4.10", waf=True)
    result = scan(server)
    assert result.status == v.VULNERABLE
    assert any("edge WAF" in m for m in result.mitigations)


def test_no_php(server):
    server.behavior["home"] = b"<html>static site</html>"
    result = scan(server)
    assert result.status == v.NOT_PHP and result.code == 0


def test_mixed_backends_worst_case(server):
    server.behavior["powered"] = ["PHP/8.3.36", "PHP/8.3.20"]
    result = scan(server, rounds=3)
    assert result.status == v.VULNERABLE
    assert any("several backends" in c for c in result.context)


def test_long_session_id_is_flagged(server):
    server.behavior.update(home_headers={"Set-Cookie": "PHPSESSID=" + "A" * 80 + "~!$@" + "; p=/"})
    result = scan(server)
    assert result.status == v.UNKNOWN            # a symptom, never a verdict on its own
    assert "heap memory leak" in result.exposures[0]


def test_legit_long_session_id_is_not_flagged(server):
    server.behavior.update(home_headers={"Set-Cookie": "PHPSESSID=" + "a1" * 64 + "; path=/"})
    assert not any("PHPSESSID" in e for e in scan(server).exposures)


def test_eol_branch_only_and_hints(server):
    server.behavior.update(powered="PHP/7.4", composer=True, env=True)
    result = scan(server)
    assert result.status == v.LIKELY
    assert any("composer.json" in e for e in result.exposures)
    assert any(".env appears to be downloadable" in e for e in result.exposures)


def test_unknown_when_php_hidden(server):
    server.behavior["home"] = b"<html><a href='/index.php?p=1'>home</a></html>"
    assert scan(server).status == v.UNKNOWN


def test_probes_are_non_destructive(server):
    server.behavior["powered"] = "PHP/8.2.20"
    result = scan(server, paths=("/login.php",))
    posts = [r for r in server.requests if r[0] == "POST"]
    assert len(posts) == 2
    for method, path, headers, body in server.requests:
        assert method in ("GET", "HEAD", "POST")
        assert "Cookie" not in headers and "cookie" not in headers
        assert b"PHPSESSID" not in body and b"<?" not in body and b"|O:" not in body
        assert len(body) < 2048
        assert "php2shell-scanner" in headers.get("User-Agent", "")
    assert result.requests == len(server.requests)


def test_passive_mode_sends_no_post(server):
    server.behavior["powered"] = "PHP/8.2.20"
    scan(server, active=False)
    assert not [r for r in server.requests if r[0] == "POST"]


# --------------------------------------------------------------------------- cli
def test_cli_scan_json_and_markdown(server, tmp_path):
    server.behavior["powered"] = "PHP/8.2.20"
    url = "http://127.0.0.1:{}/".format(server.server_address[1])
    out, md = str(tmp_path / "s.json"), str(tmp_path / "s.md")
    code = cli.main(["scan", "--yes", "-q", "--delay", "0", url, "--json", out, "--markdown", md])
    assert code == 3
    data = json.load(open(out))
    assert data["results"][0]["status"] == "VULNERABLE"
    text = open(md, encoding="utf-8").read()
    assert "# php2shell-scanner vulnerability scan" in text and "VULNERABLE" in text


def test_cli_requires_consent_when_not_interactive(server, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["scan", "127.0.0.1:1"]) == cli.EXIT_USAGE


def test_ambiguous_target_falls_back_to_http_and_unreachable(server):
    port = server.server_address[1]
    candidates = parse_target("127.0.0.1:{}".format(port))
    assert [c.scheme for c in candidates] == ["https", "http"]
    from php2shell_scanner.remote.cli import scan_one
    import argparse
    args = argparse.Namespace(timeout=3, delay=0, strict_tls=False, path=[], rounds=1,
                              passive=True)
    server.behavior["powered"] = "PHP/8.2.20"
    assert scan_one(candidates, args).target.startswith("http://")
    assert scan_one(parse_target("http://127.0.0.1:1/"), args).status == v.UNREACHABLE


@pytest.fixture
def tls_server(server, tmp_path):
    import shutil
    import ssl
    import subprocess
    if not shutil.which("openssl"):
        pytest.skip("openssl not available")
    key, crt = str(tmp_path / "k.pem"), str(tmp_path / "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    srv = ThreadingServer(("127.0.0.1", 0), Handler)
    srv.behavior, srv.requests = {"powered": "PHP/8.2.20"}, []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(crt, key)
    srv.socket = context.wrap_socket(srv.socket, server_side=True)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_self_signed_tls_fallback_and_strict_mode(tls_server):
    target = parse_target("https://127.0.0.1:{}/".format(tls_server.server_address[1]))[0]
    client = Client(target, timeout=5, delay=0)
    result = v.evaluate(target.url, run_probes(client, [], 1, False), client.requests)
    assert result.status == v.VULNERABLE
    assert any("TLS certificate not trusted" in c for c in result.context)
    strict = Client(target, timeout=5, delay=0, allow_insecure_fallback=False)
    assert v.evaluate(target.url, run_probes(strict, [], 1, False), 0).status == v.UNREACHABLE



# ------------------------------------------------------------ second review
def test_hostile_phpinfo_page_is_parsed_quickly():
    import time as _time
    from php2shell_scanner.remote import fingerprint as fp
    from php2shell_scanner.remote.http import Response
    body = ('PHP Version 8.2.1 class="e" ' + '<tr><td class="e">' + " " * 300000).encode()
    started = _time.time()
    fp.parse_phpinfo(Response(200, "OK", (), body, 0.0))
    assert _time.time() - started < 2


def test_redirect_to_other_host_is_not_followed(server):
    server.behavior.update(redirect="https://evil.example/", powered="PHP/8.2.20")
    result = scan(server)
    assert any("another host" in c for c in result.context)
    assert all(r[1] != "https://evil.example/" for r in server.requests)


def test_same_host_scheme_redirect_is_retargeted(server):
    import argparse
    from php2shell_scanner.remote.cli import scan_one
    port = server.server_address[1]
    server.behavior.update(redirect="http://127.0.0.1:{}/index.php".format(port),
                           powered="PHP/8.2.20")
    args = argparse.Namespace(timeout=3, delay=0, strict_tls=False, path=[], rounds=1,
                              passive=True, budget=60)
    result = scan_one(parse_target("http://127.0.0.1:{}/".format(port)), args)
    assert result.status == v.VULNERABLE


def test_forbidden_home_without_php_is_unknown_not_clean(server):
    server.behavior["home_status"] = 403
    result = scan(server)
    assert result.status == v.UNKNOWN and result.code == 1


@pytest.mark.parametrize("headers, powered, expected", [
    ({}, "PHP/7.4.3-4ubuntu2.24", v.LIKELY),                    # Ubuntu-built PHP
    ({}, "PHP/8.2.35-dev", v.LIKELY),
    ({}, "PHP/8.3.36RC1", v.LIKELY),
    ({}, "PHP/8.3.37-dev", v.NOT_VULNERABLE),
    ({}, "PHP/8.2.20+deb.sury.org+1", v.VULNERABLE),
])
def test_distribution_and_prerelease_builds(server, headers, powered, expected):
    server.behavior.update(powered=powered, headers=headers)
    assert scan(server).status == expected


def test_phpinfo_distribution_build_is_likely(server):
    server.behavior["phpinfo"] = PHPINFO.replace("8.4.10", "8.1.2-1ubuntu2.14")
    assert scan(server).status == v.LIKELY


def test_blog_post_mentioning_php_credits_is_not_an_easter_egg(server):
    server.behavior.update(catch_all=True,
                           home=b"<html><h1>PHP Credits</h1> a blog post, <a href='/a.php'>x</a>")
    result = scan(server)
    assert not any("easter-egg" in r for r in result.reasons)
    assert not any(".env" in e for e in result.exposures)   # soft-404 site


def test_target_time_budget_is_enforced(server):
    server.behavior["powered"] = "PHP/8.2.20"
    target = parse_target("http://127.0.0.1:{}/".format(server.server_address[1]))[0]
    client = Client(target, timeout=5, delay=0, budget=0.0001)
    import time as _time
    _time.sleep(0.01)
    data = run_probes(client, [], 3, True)
    assert not data.reachable or any("budget" in n for n in data.notes)
    assert len(server.requests) <= 1


def test_reachability_posts_only_to_site_root(server):
    server.behavior["powered"] = "PHP/8.2.20"
    scan(server, paths=("/upload.php",))
    assert {r[1] for r in server.requests if r[0] == "POST"} == {"/"}



def test_distro_token_only_in_server_header_stays_vulnerable_with_caveat(server):
    # e.g. the official php Docker image: Debian's Apache, upstream-built PHP
    server.behavior.update(powered="PHP/8.2.34", headers={"Server": "Apache/2.4.65 (Debian)"})
    result = scan(server)
    assert result.status == v.VULNERABLE and result.confidence == "medium"
    assert any("confirm the vendor's fix status" in r for r in result.reasons)
