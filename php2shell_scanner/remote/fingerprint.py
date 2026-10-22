"""Pure parsing of HTTP responses: PHP version, PHP presence, edge/CDN, SAPI, phpinfo."""

import json
import re
from typing import Dict, List, NamedTuple, Optional
from urllib.parse import urlsplit

from php2shell_scanner.remote.http import Response

VERSION_RE = re.compile(r"PHP/(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?([^\s,;()]*)", re.I)
# Distribution builds carry backported fixes without changing the upstream version.
BACKPORT_RE = re.compile(r"ubuntu|~?deb\d|\.el\d|el\d+_|amzn|\.fc\d|\+dfsg|-\d+(?:\.\d+)*$", re.I)
SURY_RE = re.compile(r"sury", re.I)   # deb.sury.org ships upstream releases, not backports
PHP_COOKIE_RE = re.compile(
    r"^\s*(PHPSESSID|laravel_session|XSRF-TOKEN|wordpress_|wp-settings|ci_session|"
    r"PrestaShop|OCSESSID|frontend|MOODLESESSION|Drupal\.visitor|joomla_|sid_[a-z0-9]+)=", re.I)
BODY_HINTS = (
    (re.compile(r"/wp-content/|/wp-includes/", re.I), "WordPress"),
    (re.compile(r"Powered by Discuz|discuz_uid", re.I), "Discuz!"),
    (re.compile(r"Joomla!|/media/jui/", re.I), "Joomla"),
    (re.compile(r"Drupal\.settings|drupal-settings-json", re.I), "Drupal"),
    (re.compile(r"Mage\.Cookies|/static/version\d+/", re.I), "Magento"),
    (re.compile(r"<b>(?:Warning|Fatal error|Notice|Deprecated)</b>:.{0,200}? on line <b>\d+",
                re.I | re.S), "PHP error message"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin"),
    (re.compile(r"ThinkPHP|think_template", re.I), "ThinkPHP"),
)
LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#?]{1,300}\.php)(?:[?#][^"']*)?["']""",
                     re.I)
PHPINFO_VERSION = re.compile(r"PHP Version\s*(?:</[a-z0-9]+>\s*)?(\d+\.\d+\.\d+[^<\s]*)", re.I)
# Unambiguous (no overlapping whitespace/lazy runs): linear on hostile pages.
PHPINFO_ROW = re.compile(r'<tr><td class="e">([^<]{1,80})</td><td class="v">([^<]{0,300})</td>',
                         re.I)
DISTRO_TOKEN = re.compile(r"\((Ubuntu|Debian|CentOS|Red Hat[^)]{0,40}|RHEL|AlmaLinux|Rocky Linux"
                          r"|Amazon[^)]{0,20}|Fedora|SUSE|Linux/SUSE|Oracle[^)]{0,20})\)", re.I)
PRERELEASE = re.compile(r"(?:-?dev|alpha\d*|beta\d*|rc\d*)$", re.I)
SID_CHARS = re.compile(r"^[A-Za-z0-9,\-]*$")
INTERESTING_DIRECTIVES = (
    "Server API", "session.upload_progress.enabled", "session.upload_progress.cleanup",
    "session.use_only_cookies", "session.use_strict_mode", "session.serialize_handler",
    "file_uploads", "expose_php", "session.save_path", "memory_limit", "disable_functions",
)


class VersionSeen(NamedTuple):
    version: str      # "8.2.20" or branch-only "8.2"
    suffix: str
    source: str       # "X-Powered-By on /index.php"
    backport: bool    # distribution build: fixes may be backported invisibly
    branch_only: bool
    prerelease: bool = False


class PhpInfo(NamedTuple):
    version: str
    sapi: str
    directives: Dict[str, str]


def versions_in(response: Response, where: str) -> List[VersionSeen]:
    found = []
    for header in ("X-Powered-By", "Server", "X-PHP-Version"):
        for value in response.header_all(header):
            # X-PHP-Version carries a bare "8.2.20"; the others say "PHP/8.2.20".
            text = "PHP/" + value.strip() if header == "X-PHP-Version" else value
            for match in VERSION_RE.finditer(text):
                major, minor, patch, suffix = match.groups()
                version = ".".join(p for p in (major, minor, patch) if p is not None)
                found.append(VersionSeen(version, suffix or "", "{} on {}".format(header, where),
                                         is_backport(suffix or ""), patch is None,
                                         bool(PRERELEASE.search(suffix or ""))))
    return found


def is_backport(suffix: str) -> bool:
    return bool(suffix) and bool(BACKPORT_RE.search(suffix)) and not SURY_RE.search(suffix)


def distro_build(response: Response) -> Optional[str]:
    """'Apache/2.4.41 (Ubuntu)' style token: PHP likely comes from distribution packages."""
    for header in ("Server", "X-Powered-By"):
        for value in response.header_all(header):
            found = DISTRO_TOKEN.search(value)
            if found:
                return found.group(1)
    return None


def php_signals(response: Response) -> List[str]:
    signals = []
    if "php" in response.header("X-Powered-By").lower() or "php/" in response.header("Server").lower():
        signals.append("X-Powered-By/Server header")
    for cookie in response.header_all("Set-Cookie"):
        named = PHP_COOKIE_RE.match(cookie)
        if named:
            signals.append("cookie " + named.group(1))
    location = response.header("Location")
    if re.search(r"\.php(?:$|[?#])", location):
        signals.append("redirect to .php")
    text = response.body[:262144].decode("utf-8", errors="replace")
    for regex, label in BODY_HINTS:
        if regex.search(text):
            signals.append(label)
    if LINK_RE.search(text):
        signals.append(".php links")
    return signals


def long_session_id(response: Response) -> Optional[str]:
    """Heap-leak symptom of CVE-2026-109618: an oversized PHPSESSID with leaked bytes.

    Hardened setups legitimately use session.sid_length up to 256 with the normal
    [A-Za-z0-9,-] alphabet, so require foreign characters or an absurd length.
    """
    for cookie in response.header_all("Set-Cookie"):
        found = re.match(r"\s*PHPSESSID=([^;]*)", cookie, re.I)
        if not found:
            continue
        value = found.group(1)
        if (len(value) >= 64 and not SID_CHARS.match(value)) or len(value) > 256:
            return value[:24] + "... ({} chars)".format(len(value))
    return None


def sets_session(response: Response) -> bool:
    return any(re.match(r"\s*PHPSESSID=", c, re.I) for c in response.header_all("Set-Cookie"))


def edge_provider(response: Response) -> Optional[str]:
    headers = {k.lower(): v.lower() for k, v in response.headers}
    server = headers.get("server", "")
    checks = (
        ("cf-ray" in headers or server == "cloudflare", "Cloudflare"),
        ("x-amz-cf-id" in headers or "cloudfront" in headers.get("via", ""), "Amazon CloudFront"),
        ("akamai" in server or "x-akamai-transformed" in headers, "Akamai"),
        ("x-served-by" in headers and "cache-" in headers.get("x-served-by", ""), "Fastly"),
        ("x-sucuri-id" in headers, "Sucuri"),
        ("x-iinfo" in headers, "Imperva Incapsula"),
        ("eo-log-uuid" in headers or "eo-cache-status" in headers, "Tencent EdgeOne"),
        ("yunjiasu" in server, "Baidu Yunjiasu"),
        ("x-swift-cachetime" in headers or "aliyun" in server, "Alibaba Cloud CDN"),
    )
    return next((name for hit, name in checks if hit), None)


def sapi_hint(response: Response) -> Optional[str]:
    server = response.header("Server").lower()
    powered = response.header("X-Powered-By").lower()
    if "php/" in server and "apache" in server:
        return "Apache mod_php (persistent workers: most exposed to CVE-2026-109619)"
    if "litespeed" in server:
        return "LiteSpeed lsphp"
    if powered.startswith("php") and any(s in server for s in ("nginx", "openresty", "caddy",
                                                               "tengine")):
        return "PHP-FPM behind {} (persistent workers)".format(server.split("/")[0])
    return None


def php_links(response: Response, host: str, limit: int = 10) -> List[str]:
    text = response.body[:262144].decode("utf-8", errors="replace")
    paths: List[str] = []
    for link in LINK_RE.findall(text):
        parts = urlsplit(link)
        if parts.netloc and parts.hostname != host:
            continue
        path = parts.path if parts.path.startswith("/") else "/" + parts.path.lstrip("./")
        if path not in paths and ".." not in path:
            paths.append(path)
        if len(paths) >= limit:
            break
    return paths


def parse_phpinfo(response: Response) -> Optional[PhpInfo]:
    if response.status != 200:
        return None
    text = response.body.decode("utf-8", errors="replace")
    version = PHPINFO_VERSION.search(text)
    if not version or 'class="e"' not in text:
        return None
    directives: Dict[str, str] = {}
    for name, value in PHPINFO_ROW.findall(text):
        name = name.strip()
        if name in INTERESTING_DIRECTIVES and name not in directives:
            directives[name] = value.strip()
    return PhpInfo(version.group(1), directives.get("Server API", "").strip(), directives)


def legacy_easter_egg(response: Response, home: Response) -> bool:
    """PHP < 5.5 answered the logo/credits GUID query string (requires expose_php=On).

    Must be a real GIF or the phpcredits() page, and different from the plain home page
    (sites that ignore the query string would otherwise trigger it).
    """
    if response.status != 200 or response.body[:4096] == home.body[:4096]:
        return False
    if response.body[:6] in (b"GIF89a", b"GIF87a"):
        return True
    return bool(re.search(rb"<h1[^>]{0,40}>PHP Credits</h1>", response.body[:65536]))


def composer_php_constraint(response: Response) -> Optional[str]:
    if response.status != 200:
        return None
    try:
        data = json.loads(response.body.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    require = data.get("require") if isinstance(data, dict) else None
    value = require.get("php") if isinstance(require, dict) else None
    return value[:60] if isinstance(value, str) else None
