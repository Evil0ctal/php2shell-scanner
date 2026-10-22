"""SSH / sudo / account activity from auth logs: how an attacker turned a webshell into access.

Reads /var/log/auth.log* (Debian/Ubuntu), /var/log/secure* (RHEL family),
/var/log/messages* (Alpine/openSUSE syslog) and journald (live).
"""

import re
import time
from collections import Counter
from datetime import datetime
from typing import Dict, List, NamedTuple, Optional, Set, Tuple

from php2shell_scanner.context import ScanContext, run_tool
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable

NAME = "auth"
DESCRIPTION = "Auth logs: SSH logins, web-user sudo/su, brute force, new accounts"

AUTH_GLOBS = ("/var/log/auth.log*", "/var/log/secure*")
# Alpine/openSUSE/busybox log auth to the general syslog; it is large, so it is only read
# when no dedicated auth log exists.
FALLBACK_GLOBS = ("/var/log/messages*",)
# Anchored on sshd's own message start and on the line end: usernames are attacker-chosen
# ("Accepted password for www-data from ..." is a valid *username* in a failure line).
# Every rule is applied to the MESSAGE of a line whose syslog header names the program
# that wrote it. Attacker-chosen text (SSH usernames, URLs) only ever appears inside an
# sshd message, so it can never be mistaken for a sudo/su/useradd record or vice versa.
SYSLOG_LINE = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S{8,32})"
    r"\s+\S{1,255}(?:\s+[a-z]{2,10}\.[a-z]{2,10})?\s+"           # host [busybox facility.level]
    r"(?P<prog>[\w.\-]{1,32})(?:\[\d{1,10}\])?:\s(?P<msg>.*)$")
# OpenSSH appends ": ED25519 SHA256:<fp>" to publickey results.
TAIL = r" from (\S{1,64}) port \d{1,5}(?: ssh\d)?(?:: [\w-]{1,40} \S{1,128})?\s*$"
ACCEPTED = re.compile(r"^Accepted (password|publickey|keyboard-interactive/pam|hostbased"
                      r"|gssapi-with-mic) for (\S{1,64})" + TAIL)
FAILED = re.compile(r"^(?:Failed \S{1,40} for (?:invalid user )?.{0,120}?|Invalid user "
                    r".{0,120}?)" + TAIL)
SUDO = re.compile(r"^\s*(\S{1,64}) : .{0,300}?COMMAND=(.{0,300})$")
SU = re.compile(r"session opened for user (\S{1,64}?)(?:\(uid=\d+\))? by (\S{1,64}?)"
                r"(?:\(uid=\d+\))?\s*$|^\(to (\S{1,64})\) (\S{1,64}) on")
USERADD = re.compile(r"^new user: name=([^,\s]{1,64}), UID=(\d+)")
GROUP_ADD = re.compile(r"^add '([^']{1,64})' to (?:shadow )?group '([^']{1,64})'"
                       r"|^user (\S{1,64}) added by \S+ to group (\S{1,64})")
SSHD_PROGRAMS = frozenset(("sshd", "sshd-session"))
PRIV_GROUPS = frozenset(("sudo", "wheel", "admin", "root", "docker", "lxd", "adm", "disk"))
BRUTE_THRESHOLD = 20
BRUTE_WINDOW = 3600          # failures must precede the successful login within this window
NOLOGIN = re.compile(r"(?:nologin|/false|/sync)$")
SHELL_FIELD = re.compile(r"\bshell=([^,\s]{1,128})")
TRIGGERS = ("Accepted ", "Failed ", "Invalid user", "sudo", "session opened", "su:", "su[",
            "useradd", "usermod", "gpasswd")


class Login(NamedTuple):
    user: str
    method: str
    ip: str


class State:
    def __init__(self) -> None:
        self.logins: Counter = Counter()
        self.login_times: Dict[Login, Tuple[str, str]] = {}
        self.failed: Counter = Counter()
        self.failure_times: Dict[str, List[float]] = {}
        self.events: List[Finding] = []
        self.seen_events: Set[Tuple[str, str]] = set()
        self.lines = 0


ROTATED = re.compile(r"\.(\d{1,3})(?:\.(?:gz|bz2|xz))?$")       # auth.log.2.gz
DATED = re.compile(r"-(\d{8})(?:\.(?:gz|bz2|xz))?$")             # secure-20261018


def rotation_key(path: str) -> Tuple[int, int, str]:
    """Sort key putting the oldest rotation first and the live file last."""
    numbered = ROTATED.search(path)
    if numbered:
        return (0, -int(numbered.group(1)), path)
    dated = DATED.search(path)
    if dated:
        return (1, int(dated.group(1)), path)
    return (2, 0, path)


def _event(state: State, rule: str, sev: Severity, kind: str, title: str, path: str,
           line: str, detail: str = "") -> None:
    key = (rule, line)
    if key in state.seen_events:        # rotated copies often repeat the same records
        return
    state.seen_events.add(key)
    state.events.append(Finding(NAME, rule, sev, kind, title, path, printable(line, 240), detail))


def _epoch(stamp: str) -> Optional[float]:
    """Syslog ('Oct 20 13:30:00', no year: assume the current year) or ISO timestamps."""
    try:
        if stamp[:1].isdigit():
            return datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
        return datetime.strptime("{} {}".format(time.localtime().tm_year, " ".join(stamp.split())),
                                 "%Y %b %d %H:%M:%S").timestamp()
    except ValueError:
        return None


def _recent_failures(state: State, ip: str, when: Optional[float]) -> int:
    times = state.failure_times.get(ip, [])
    if when is None:
        return len(times)
    return sum(1 for t in times if when - BRUTE_WINDOW <= t <= when)


def _login(state: State, disc: Discovery, path: str, line: str, msg: str, when: str) -> None:
    found = ACCEPTED.match(msg)
    if not found:
        return
    method, user, ip = found.group(1), found.group(2), found.group(3)
    key = Login(user, method, ip)
    state.logins[key] += 1
    first = state.login_times.get(key, (when, when))[0]
    state.login_times[key] = (first, when)
    if user in disc.web_users:
        account = next((u for u in disc.users if u.name == user), None)
        locked = account is None or not account.shell or NOLOGIN.search(account.shell)
        _event(state, "AUTH-WEBUSER-LOGIN", Severity.CRITICAL if locked else Severity.MEDIUM,
               Kind.COMPROMISE, "SSH login as web user '{}' from {}".format(user, ip), path, line,
               "This account has no login shell: someone planted a key or changed its shell."
               if locked else "This web/panel account has a login shell; verify the login.")
    failures = _recent_failures(state, ip, _epoch(when))
    if failures >= BRUTE_THRESHOLD:
        _event(state, "AUTH-BRUTEFORCE-SUCCESS", Severity.HIGH, Kind.COMPROMISE,
               "Successful SSH login after {} failures within an hour from {}".format(
                   failures, ip), path, line, "Looks like a guessed password. Verify this "
                                              "login was you.")


def _privilege(state: State, disc: Discovery, path: str, line: str, prog: str,
               msg: str) -> None:
    sudo = SUDO.match(msg) if prog == "sudo" else None
    if sudo and sudo.group(1) in disc.web_users:
        _event(state, "AUTH-WEBUSER-SUDO", Severity.CRITICAL, Kind.COMPROMISE,
               "Web user '{}' used sudo".format(sudo.group(1)), path, line)
    su = SU.search(msg) if prog == "su" else None
    if su:
        by = su.group(2) or su.group(4)
        if by in disc.web_users:
            _event(state, "AUTH-WEBUSER-SU", Severity.CRITICAL, Kind.COMPROMISE,
                   "Web user '{}' switched user with su".format(by), path, line)
    added = USERADD.match(msg) if prog == "useradd" else None
    if added:
        shell = SHELL_FIELD.search(msg)
        service = bool(shell and NOLOGIN.search(shell.group(1)))
        uid0 = added.group(2) == "0"
        severity = Severity.HIGH if uid0 else (Severity.LOW if service else Severity.MEDIUM)
        _event(state, "AUTH-NEW-ACCOUNT", severity, Kind.COMPROMISE,
               "{} '{}' created (UID {})".format("Service account" if service and not uid0
                                                else "Account", *added.groups()), path, line,
               "Confirm this account was created by an administrator or a package.")
    group = GROUP_ADD.match(msg) if prog in ("usermod", "gpasswd") else None
    if group:
        user, name = (group.group(1), group.group(2)) if group.group(1) else group.group(3, 4)
        if name in PRIV_GROUPS:
            _event(state, "AUTH-PRIV-GROUP-ADD", Severity.HIGH, Kind.COMPROMISE,
                   "'{}' added to privileged group '{}'".format(user, name), path, line)


def process_line(state: State, disc: Discovery, path: str, line: str) -> None:
    state.lines += 1
    if not any(t in line for t in TRIGGERS):
        return
    parsed = SYSLOG_LINE.match(line)
    if not parsed:
        return    # unknown format: never guess which program wrote it
    when, prog, msg = parsed.group("time"), parsed.group("prog"), parsed.group("msg")
    if prog in SSHD_PROGRAMS:
        failed = FAILED.match(msg)
        if failed:
            _failure(state, failed.group(1), when)
            return
        _login(state, disc, path, line, msg, when)
        return
    _privilege(state, disc, path, line, prog, msg)


def _failure(state: State, ip: str, when: str) -> None:
    state.failed[ip] += 1
    moment = _epoch(when)
    if moment is not None:
        times = state.failure_times.setdefault(ip, [])
        times.append(moment)
        del times[:-500]


def _summary(state: State) -> List[Finding]:
    findings = []
    if state.logins:
        rows = ["{} via {} from {} x{} ({} -> {})".format(
            k.user, k.method, k.ip, n, *state.login_times[k]) for k, n in state.logins.most_common(25)]
        findings.append(Finding(
            NAME, "AUTH-LOGINS", Severity.INFO, Kind.INFO,
            "{} distinct successful SSH login source(s) - verify they are yours".format(
                len(state.logins)), evidence=rows[0], meta={"paths": rows}))
        root_pw = [k for k in state.logins if k.user == "root" and k.method == "password"]
        if root_pw:
            findings.append(Finding(
                NAME, "AUTH-ROOT-PASSWORD-LOGIN", Severity.LOW, Kind.HARDENING,
                "root logged in with a password ({} source(s))".format(len(root_pw)),
                evidence=", ".join(sorted({k.ip for k in root_pw}))[:200]))
    attackers = [(ip, n) for ip, n in state.failed.most_common() if n >= BRUTE_THRESHOLD]
    if attackers:
        findings.append(Finding(
            NAME, "AUTH-BRUTEFORCE", Severity.LOW, Kind.HARDENING,
            "SSH brute force from {} source(s)".format(len(attackers)),
            evidence=", ".join("{} ({}x)".format(ip, n) for ip, n in attackers[:5]),
            detail="Disable password logins or use fail2ban/CrowdSec."))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    state = State()
    files: Set[str] = set()
    for pattern in AUTH_GLOBS:
        files.update(p for p in ctx.fs.glob(pattern) if ctx.fs.isfile(p))
    if not files:
        for pattern in FALLBACK_GLOBS:
            files.update(p for p in ctx.fs.glob(pattern) if ctx.fs.isfile(p))
    for path in sorted(files, key=rotation_key):
        try:
            for line in ctx.fs.iter_lines(path):
                process_line(state, disc, path, line)
        except Exception:  # pragma: no cover - iter_lines already contains read errors
            continue
    journal = run_tool(ctx, ["journalctl", "--no-pager", "-q", "-o", "short-iso", "-n", "200000",
                             "-t", "sshd", "-t", "sshd-session", "-t", "sudo", "-t", "su",
                             "-t", "useradd", "-t", "usermod"],
                       timeout=120) if not files else None
    for line in (journal[1].splitlines() if journal else []):
        process_line(state, disc, "journalctl", line)
    findings = state.events + _summary(state)
    findings.append(Finding(NAME, "AUTH-COVERAGE", Severity.INFO, Kind.INFO,
                            "Analysed {:,} auth log line(s) from {} file(s){}".format(
                                state.lines, len(files), " + journald" if journal else "")))
    return findings
