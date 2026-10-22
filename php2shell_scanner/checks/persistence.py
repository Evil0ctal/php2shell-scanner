"""Persistence an attacker leaves after a webshell: cron, systemd, rc files, preload.

These survive uninstalling PHP, which is why they matter most for a host where
the vulnerable software is already gone.
"""

import os
import re
from typing import List, Tuple

from php2shell_scanner.checks.common import file_meta
from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable, scan
from php2shell_scanner.signatures.system import COMMAND_SIGNATURES

NAME = "persistence"
DESCRIPTION = "Cron, systemd, rc.local, shell profiles, ld.so.preload, web-user crontabs"

CRON_GLOBS = (
    "/etc/crontab", "/etc/anacrontab", "/etc/cron.d/*", "/etc/cron.hourly/*",
    "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
    "/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/tabs/*",
    "/etc/periodic/*/*", "/var/spool/anacron/*",
)
USER_CRON_DIRS = ("/var/spool/cron", "/var/spool/cron/crontabs", "/var/spool/cron/tabs")
SYSTEM_CRONTABS = ("/etc/crontab", "/etc/cron.d/")
CRON_ENV = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=")
SYSTEMD_DIRS = (
    "/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system", "/etc/systemd/user", "/usr/lib/systemd/user",
)
RC_GLOBS = (
    "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.d/*", "/etc/profile", "/etc/profile.d/*",
    "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc", "/etc/environment",
    "/etc/update-motd.d/*", "/etc/xdg/autostart/*",
)
HOME_RC_FILES = (".bashrc", ".bash_profile", ".profile", ".bash_login", ".zshrc", ".bash_logout")
# Package-managed locations: only report strong signals there to avoid noise.
PACKAGE_PREFIXES = ("/etc/init.d/", "/usr/lib/systemd/", "/lib/systemd/", "/etc/update-motd.d/",
                    "/etc/xdg/", "/etc/cron.hourly/", "/etc/cron.daily/", "/etc/cron.weekly/",
                    "/etc/cron.monthly/", "/etc/periodic/")
EXEC_LINE = re.compile(r"^\s*Exec\w*\s*=\s*-?(.+)$", re.M)
TMP_BINARY = re.compile(r"^(?:/tmp|/var/tmp|/dev/shm|/run/shm)/|/\.[^/\s]+/")


def _content_findings(ctx: ScanContext, disc: Discovery, path: str, text: str, what: str,
                      ) -> List[Finding]:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    body = "\n".join(lines)
    floor = Severity.HIGH if path.startswith(PACKAGE_PREFIXES) else Severity.LOW
    findings = []
    for match in scan(COMMAND_SIGNATURES, body):
        if match.signature.severity < floor:
            continue
        findings.append(Finding(
            NAME, match.signature.rule, match.signature.severity, Kind.COMPROMISE,
            "{}: {}".format(what, match.signature.title), path, match.snippet,
            "Malicious-looking command in a file that runs automatically.",
            file_meta(ctx, disc, ctx.fs.lstat(path))))
    return findings


def cron_commands(text: str, system: bool) -> List[str]:
    """Command part of each crontab entry (schedule and, for system crontabs, user removed)."""
    commands = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or CRON_ENV.match(stripped):
            continue
        fields = stripped.split()
        skip = 1 if fields[0].startswith("@") else 5
        skip += 1 if system else 0
        if len(fields) > skip:
            commands.append(" ".join(fields[skip:]))
    return commands


def _cron_tmp_findings(ctx: ScanContext, disc: Discovery, path: str, text: str,
                       inner: str) -> List[Finding]:
    system = inner == "/etc/crontab" or inner.startswith("/etc/cron.d/")
    findings = []
    for command in cron_commands(text, system):
        if TMP_BINARY.search(command.split()[0]):
            findings.append(Finding(
                NAME, "PERSIST-CRON-TMP-BINARY", Severity.HIGH, Kind.COMPROMISE,
                "Cron job runs a program from a temp/hidden directory", path, printable(command),
                "Droppers and miners are typically re-launched from /tmp, /dev/shm or a "
                "dot-directory by cron.", file_meta(ctx, disc, ctx.fs.lstat(path))))
    return findings


def _cron_files(ctx: ScanContext, disc: Discovery) -> List[Tuple[str, str]]:
    """(path, prefix) for host crontabs and crontabs inside container writable layers."""
    prefixes = [""] + [c.upper_dir for c in disc.containers if c.upper_dir]
    files = []
    for prefix in prefixes:
        for pattern in CRON_GLOBS:
            files.extend((path, prefix) for path in ctx.fs.glob(prefix + pattern)
                         if ctx.fs.isfile(path))
    return files


def _webuser_cron(ctx: ScanContext, disc: Discovery, path: str, owner: str, text: str
                  ) -> List[Finding]:
    active = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not active:
        return []
    return [Finding(
        NAME, "PERSIST-WEBUSER-CRON", Severity.HIGH, Kind.COMPROMISE,
        "Crontab owned by web user '{}'".format(owner), path, printable(active[0]),
        "Web server accounts essentially never have crontabs; this is the standard way a "
        "webshell makes itself persistent.",
        file_meta(ctx, disc, ctx.fs.lstat(path), entries=len(active)))]


def check_cron(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    container_web_names = set(disc.web_users) | {"www-data", "nginx", "apache", "www"}
    for path, prefix in _cron_files(ctx, disc):
        inner = path[len(prefix):] if prefix else path   # path as seen inside the container
        text = ctx.fs.read_text(path, 512 * 1024) or ""
        findings.extend(_content_findings(ctx, disc, path, text, "cron"))
        if not inner.startswith(PACKAGE_PREFIXES):
            findings.extend(_cron_tmp_findings(ctx, disc, path, text, inner))
        owner = os.path.basename(path)
        is_web = owner in (container_web_names if prefix else disc.web_users)
        if is_web and os.path.dirname(inner) in USER_CRON_DIRS:
            findings.extend(_webuser_cron(ctx, disc, path, owner, text))
    return findings


def _unit_files(ctx: ScanContext, disc: Discovery) -> List[str]:
    dirs = list(SYSTEMD_DIRS)
    for user in disc.users:
        if user.home and user.home != "/":
            dirs.append(os.path.join(user.home, ".config/systemd/user"))
    paths = []
    for directory in dirs:
        for path, _ in ctx.fs.walk(directory, max_depth=3, max_entries=50000):
            if path.endswith((".service", ".timer", ".socket", ".path")):
                paths.append(path)
    return paths


def check_systemd(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    for path in _unit_files(ctx, disc):
        text = ctx.fs.read_text(path, 256 * 1024) or ""
        exec_lines = "\n".join(m.group(1) for m in EXEC_LINE.finditer(text))
        if not exec_lines:
            continue
        findings.extend(_content_findings(ctx, disc, path, exec_lines, "systemd unit"))
        for line in exec_lines.splitlines():
            binary = line.strip().lstrip("@!+:").split()[0] if line.strip() else ""
            if binary and TMP_BINARY.search(binary):
                findings.append(Finding(
                    NAME, "PERSIST-UNIT-TMP-BINARY", Severity.CRITICAL, Kind.COMPROMISE,
                    "systemd unit runs a binary from a temp/hidden directory", path,
                    printable(line), "", file_meta(ctx, disc, ctx.fs.lstat(path))))
        if path.startswith(("/etc/", "/run/")) or "/.config/" in path:
            st = ctx.fs.lstat(path)
            if st is not None and ctx.recent(max(st.st_mtime, st.st_ctime)):
                findings.append(Finding(
                    NAME, "PERSIST-UNIT-RECENT", Severity.MEDIUM, Kind.COMPROMISE,
                    "systemd unit created/modified after --since", path,
                    printable(exec_lines.splitlines()[0]), "Confirm you installed this service.",
                    file_meta(ctx, disc, st)))
    return findings


def _rc_paths(ctx: ScanContext, disc: Discovery) -> List[Tuple[str, str]]:
    paths = [(p, "startup script") for pattern in RC_GLOBS for p in ctx.fs.glob(pattern)]
    for user in disc.users:
        if not user.home or user.home == "/":
            continue
        for name in HOME_RC_FILES:
            paths.append((os.path.join(user.home, name), "shell profile of " + user.name))
    return [(p, label) for p, label in paths if ctx.fs.isfile(p)]


def check_rc(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    for path, label in _rc_paths(ctx, disc):
        text = ctx.fs.read_text(path, 512 * 1024) or ""
        findings.extend(_content_findings(ctx, disc, path, text, label))
    return findings


def check_preload(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    text = ctx.fs.read_text("/etc/ld.so.preload", 64 * 1024)
    entries = [ln.strip() for ln in (text or "").splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    if entries:
        findings.append(Finding(
            NAME, "PERSIST-LD-PRELOAD", Severity.CRITICAL, Kind.COMPROMISE,
            "/etc/ld.so.preload injects a library into every process", "/etc/ld.so.preload",
            printable(", ".join(entries)),
            "Classic userland rootkit hook (hides files/processes from ps, ls, netstat). "
            "Results of live checks on this host may be falsified - image the disk and analyse "
            "it offline with --root.", file_meta(ctx, disc, ctx.fs.lstat("/etc/ld.so.preload"))))
    for path in ctx.fs.glob("/etc/ld.so.conf.d/*"):
        conf = ctx.fs.read_text(path, 64 * 1024) or ""
        for line in conf.splitlines():
            if TMP_BINARY.search(line.strip() + "/"):
                findings.append(Finding(
                    NAME, "PERSIST-LD-CONF", Severity.HIGH, Kind.COMPROMISE,
                    "Library search path points into a temp/hidden directory", path,
                    printable(line), "", file_meta(ctx, disc, ctx.fs.lstat(path))))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    return (check_cron(ctx, disc) + check_systemd(ctx, disc) + check_rc(ctx, disc)
            + check_preload(ctx, disc))
