"""Is PHP (still) installed / running, and is it a vulnerable build?

Answers the exposure side of the assessment and catches php.ini-level
persistence (auto_prepend_file) that survives a package removal.
"""

import os
import re
import stat
from typing import Dict, List, NamedTuple, Optional, Tuple

from php2shell_scanner.checks.common import file_meta
from php2shell_scanner.context import ScanContext, run_tool
from php2shell_scanner.discovery import FPM_CONF_GLOBS, NGINX_CONF_GLOBS, read_configs
from php2shell_scanner.fs import ELF_MAGIC, drop_cache
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable, scan
from php2shell_scanner.signatures import webshell as ws
from php2shell_scanner.versions import FIXED_TEXT, version_vulnerable

NAME = "php"
DESCRIPTION = "PHP binaries/packages/processes, vulnerable versions, php.ini backdoors"

BINARY_GLOBS = (
    "/usr/bin/php*", "/usr/sbin/php*", "/usr/local/bin/php*", "/usr/local/sbin/php*",
    "/usr/local/php*/bin/php*", "/usr/local/php*/sbin/php-fpm*", "/www/server/php/*/bin/php*",
    "/www/server/php/*/sbin/php-fpm*", "/opt/remi/php*/root/usr/bin/php*",
    "/opt/remi/php*/root/usr/sbin/php-fpm*", "/opt/cpanel/ea-php*/root/usr/bin/php*",
    "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm*", "/opt/alt/php*/usr/bin/php*",
    "/usr/local/lsws/lsphp*/bin/lsphp", "/opt/plesk/php/*/bin/php*", "/usr/lib/cgi-bin/php*",
    "/opt/bitnami/php/bin/php*", "/opt/bitnami/php/sbin/php-fpm*",
    "/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
    "/etc/httpd/modules/libphp*.so", "/usr/local/apache/modules/libphp*.so",
)
BINARY_NAME = re.compile(
    r"^(?:php[\d.]*|php-fpm[\d.]*|php[\d.]*-fpm|php-cgi[\d.]*|php[\d.]*-cgi|lsphp|libphp[\d.]*\.so)$")
VERSION_IN_BINARY = re.compile(rb"X-Powered-By: PHP/(\d+\.\d+\.\d+)")
VERSION_IN_OUTPUT = re.compile(r"^PHP (\d+\.\d+\.\d+)", re.M)
PHP_PACKAGE = re.compile(r"^(?:php[\d.]*(?:-\S+)?|libapache2-mod-php\S*|phpmyadmin|mod_php\S*)$",
                         re.I)
INI_PREPEND = re.compile(
    r"^[ \t]*(auto_prepend_file|auto_append_file)[ \t]*=[ \t]*[\"']?([^\"'\s;=]+)", re.M | re.I)
INI_URL_INCLUDE = re.compile(r"^\s*allow_url_include\s*=\s*(?:on|1|true|yes)\b", re.M | re.I)
INI_UPLOAD_PROGRESS_OFF = re.compile(
    r"^\s*session\.upload_progress\.enabled\s*=\s*(?:off|0|false|no|\"\"|'')\s*$", re.M | re.I)
FPM_LISTEN = re.compile(r"^\s*listen\s*=\s*(\S+)", re.M)
NGINX_PHP = re.compile(r"fastcgi_pass|\.php\$?", re.I)
CHUNK = 4 * 1024 * 1024


class PhpBuild(NamedTuple):
    path: str
    version: str
    source: str


def _version_from_binary(ctx: ScanContext, path: str) -> Optional[str]:
    try:
        with ctx.fs.open_binary(path) as handle:
            tail = b""
            try:
                while True:
                    chunk = handle.read(CHUNK)
                    if not chunk:
                        return None
                    found = VERSION_IN_BINARY.search(tail + chunk)
                    if found:
                        return found.group(1).decode()
                    tail = chunk[-64:]
            finally:
                drop_cache(handle)
    except (OSError, ValueError):
        return None


def _version_by_running(ctx: ScanContext, path: str, st: os.stat_result) -> Optional[str]:
    """Fallback only: never run binaries that a non-root user could have replaced."""
    if path.endswith(".so") or st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None
    result = run_tool(ctx, [path, "-n", "-v"], timeout=10)
    found = VERSION_IN_OUTPUT.search(result[1]) if result else None
    return found.group(1) if found else None


def find_builds(ctx: ScanContext) -> List[PhpBuild]:
    builds: Dict[str, PhpBuild] = {}
    for pattern in BINARY_GLOBS:
        for path in ctx.fs.glob(pattern):
            if not BINARY_NAME.match(os.path.basename(path)):
                continue
            real = os.path.realpath(ctx.fs.real(path))
            st = ctx.fs.stat(path)
            if real in builds or st is None or not stat.S_ISREG(st.st_mode):
                continue
            if (ctx.fs.read_bytes(path, 4) or b"") != ELF_MAGIC:
                continue
            version, source = _version_from_binary(ctx, path), "binary strings"
            if version is None:
                version, source = _version_by_running(ctx, path, st), "php -n -v"
            builds[real] = PhpBuild(path, version or "unknown", source if version else "")
    return sorted(builds.values())


def dpkg_packages(ctx: ScanContext) -> List[Tuple[str, str, str]]:
    """(package, version, state) from /var/lib/dpkg/status - works offline too."""
    text = ctx.fs.read_text("/var/lib/dpkg/status", 64 * 1024 * 1024) or ""
    packages = []
    for stanza in text.split("\n\n"):
        fields = dict(re.findall(r"^(Package|Status|Version): (.*)$", stanza, re.M))
        name = fields.get("Package", "")
        if not PHP_PACKAGE.match(name):
            continue
        status = fields.get("Status", "").split()
        state = status[-1] if status else "unknown"  # "installed", "config-files", ...
        packages.append((name, fields.get("Version", ""), state))
    return packages


def apk_packages(ctx: ScanContext) -> List[Tuple[str, str, str]]:
    """Alpine: /lib/apk/db/installed (P:name / V:version stanzas)."""
    text = ctx.fs.read_text("/lib/apk/db/installed", 64 * 1024 * 1024) or ""
    rows = []
    for stanza in text.split("\n\n"):
        fields = dict(re.findall(r"^([PV]):(.*)$", stanza, re.M))
        if PHP_PACKAGE.match(fields.get("P", "")):
            rows.append((fields["P"], fields.get("V", ""), "installed"))
    return rows


def pacman_packages(ctx: ScanContext) -> List[Tuple[str, str, str]]:
    """Arch: /var/lib/pacman/local/<pkg>/desc."""
    rows = []
    for desc in ctx.fs.glob("/var/lib/pacman/local/php*/desc"):
        text = ctx.fs.read_text(desc, 65536) or ""
        name = re.search(r"%NAME%\n(\S+)", text)
        version = re.search(r"%VERSION%\n(\S+)", text)
        if name and PHP_PACKAGE.match(name.group(1)):
            rows.append((name.group(1), version.group(1) if version else "", "installed"))
    return rows


def rpm_packages(ctx: ScanContext) -> List[Tuple[str, str, str]]:
    result = run_tool(ctx, ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"])
    if not result:
        return []
    rows = [line.split("\t") for line in result[1].splitlines() if "\t" in line]
    return [(name, version, "installed") for name, version in rows if PHP_PACKAGE.match(name)]


def _loads_libphp(pid: int) -> bool:
    try:
        with open("/proc/{}/maps".format(pid), "r", encoding="utf-8", errors="replace") as handle:
            return any("libphp" in line for line in handle)
    except OSError:
        return False


def _running_php(disc: Discovery) -> List[str]:
    names = []
    for proc in disc.processes:
        base = os.path.basename(proc.exe.replace(" (deleted)", "")) or proc.name
        is_php = bool(BINARY_NAME.match(base)) or (
            base in ("apache2", "httpd") and _loads_libphp(proc.pid))
        if is_php:
            names.append("{} (pid {})".format(proc.cmdline or base, proc.pid))
    return names


def check_builds(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    running = _running_php(disc)
    for build in find_builds(ctx):
        vulnerable = version_vulnerable(build.version)
        if vulnerable:
            sev = Severity.CRITICAL if running else Severity.HIGH
            title = "Vulnerable PHP {} {}".format(build.version, "RUNNING" if running else
                                                  "still installed")
        elif vulnerable is None:
            sev, title = Severity.MEDIUM, "PHP binary present, version unknown"
        else:
            sev, title = Severity.INFO, "PHP {} (not affected / patched)".format(build.version)
        findings.append(Finding(
            NAME, "PHP-BUILD", sev, Kind.EXPOSURE if sev > Severity.INFO else Kind.INFO, title,
            build.path, "version {} via {}".format(build.version, build.source or "n/a"),
            "Affected: 5.4.0 - 8.5.11. Fixed: " + FIXED_TEXT + ". Distribution "
            "packages may carry backported fixes - confirm with your distro advisory.",
            {"running": running[:10]}))
    if running and not findings:
        findings.append(Finding(NAME, "PHP-RUNNING", Severity.HIGH, Kind.EXPOSURE,
                                "PHP processes are running", evidence="; ".join(running[:3])))
    return findings


def check_packages(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    rows = dpkg_packages(ctx) or apk_packages(ctx) or pacman_packages(ctx) or rpm_packages(ctx)
    installed = [r for r in rows if r[2] == "installed"]
    leftovers = [r for r in rows if r[2] != "installed"]
    findings = []
    if installed:
        findings.append(Finding(
            NAME, "PHP-PACKAGES", Severity.INFO, Kind.INFO,
            "{} PHP/phpMyAdmin package(s) installed".format(len(installed)),
            evidence=", ".join("{} {}".format(n, v) for n, v, _ in installed[:8]),
            meta={"packages": ["{} {}".format(n, v) for n, v, _ in installed]}))
    if leftovers:
        findings.append(Finding(
            NAME, "PHP-PACKAGE-LEFTOVERS", Severity.LOW, Kind.EXPOSURE,
            "{} removed PHP package(s) left configuration behind".format(len(leftovers)),
            evidence=", ".join(n for n, _, _ in leftovers[:8]),
            detail="dpkg 'rc' state: run `apt purge` to drop old php.ini/pool configs."))
    return findings


def _prepend_finding(ctx: ScanContext, disc: Discovery, path: str, key: str, target: str
                     ) -> Finding:
    data = ctx.fs.read_bytes(target, 1024 * 1024) or b""
    matches = scan(ws.CONTENT_SIGNATURES, data)
    sev = Severity.CRITICAL if matches else Severity.HIGH
    return Finding(
        NAME, "PHP-INI-PREPEND", sev, Kind.COMPROMISE,
        "{} configured in php.ini".format(key), path, "{} = {}".format(key, target),
        ("Target matches: " + ", ".join(m.signature.rule for m in matches)) if matches else
        "Every PHP request includes this file. Make sure it is yours.",
        file_meta(ctx, disc, ctx.fs.lstat(target), target=target))


def check_ini(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for path in disc.php_ini_files:
        text = ctx.fs.read_text(path, 1024 * 1024) or ""
        for found in INI_PREPEND.finditer(text):
            target = found.group(2)
            if target.lower() in ("none", "off", "0", "") or target.endswith("wordfence-waf.php"):
                continue
            findings.append(_prepend_finding(ctx, disc, path, found.group(1), target))
        if INI_URL_INCLUDE.search(text):
            findings.append(Finding(NAME, "PHP-INI-URL-INCLUDE", Severity.MEDIUM, Kind.EXPOSURE,
                                    "allow_url_include is enabled", path))
        if INI_UPLOAD_PROGRESS_OFF.search(text):
            findings.append(Finding(NAME, "PHP-INI-MITIGATED", Severity.INFO, Kind.INFO,
                                    "session.upload_progress.enabled = Off (mitigation set)", path))
    return findings


def check_server_configs(ctx: ScanContext, disc: Discovery, has_php: bool) -> List[Finding]:
    findings = []
    for path, text in read_configs(ctx.fs, FPM_CONF_GLOBS):
        for found in FPM_LISTEN.finditer(text):
            value = found.group(1)
            if value.isdigit() or value.startswith(("0.0.0.0:", "[::]:", "*:")):
                findings.append(Finding(
                    NAME, "PHP-FPM-PUBLIC-LISTEN", Severity.HIGH if has_php else Severity.LOW,
                    Kind.EXPOSURE, "PHP-FPM pool listens on all interfaces", path,
                    printable(found.group(0)), "Unauthenticated FastCGI = remote code execution."))
    referencing = [p for p, t in read_configs(ctx.fs, NGINX_CONF_GLOBS) if NGINX_PHP.search(t)]
    if referencing and not has_php:
        findings.append(Finding(
            NAME, "PHP-STALE-SERVER-CONFIG", Severity.INFO, Kind.INFO,
            "Web server config still routes .php requests ({} file(s))".format(len(referencing)),
            evidence=", ".join(referencing[:5]),
            detail="If PHP is ever reinstalled, any webshell left in the web root is live again."))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    builds = check_builds(ctx, disc)
    has_php = any(f.rule in ("PHP-BUILD", "PHP-RUNNING") for f in builds)
    if not has_php:
        builds.append(Finding(NAME, "PHP-ABSENT", Severity.INFO, Kind.INFO,
                              "No PHP binary or PHP process found"))
    return (builds + check_packages(ctx, disc) + check_ini(ctx, disc)
            + check_server_configs(ctx, disc, has_php))
