"""Verdict logic plus text and JSON rendering."""

import json
import textwrap
from typing import Any, Dict, Iterable, List, NamedTuple, TextIO

from php2shell_scanner import __version__
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable

TEXT_WIDTH = 4000  # sanitised fields are wrapped, not truncated, in the text report


def safe(value: Any) -> str:
    return printable(str(value), TEXT_WIDTH)


class Verdict(NamedTuple):
    code: int
    label: str
    summary: str


SECTIONS = (
    (Kind.COMPROMISE, "COMPROMISE INDICATORS - attacker activity on this host"),
    (Kind.ATTEMPT, "EXPLOITATION ATTEMPTS / EXPLOIT ARTEFACTS"),
    (Kind.EXPOSURE, "EXPOSURE - vulnerable software or risky configuration"),
    (Kind.HARDENING, "SECURITY BASELINE - hardening gaps (do not affect the verdict)"),
)
COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
RESET, BOLD = "\033[0m", "\033[1m"
META_KEYS = ("owner", "mode", "size", "mtime", "ctime", "user", "pid", "session_id", "count",
             "first_seen", "last_seen", "recent")
NEXT_STEPS = {
    3: [
        "Treat the host as fully compromised: the attacker had code execution.",
        "Isolate it from the network, but do NOT wipe it yet - take a disk image / snapshot.",
        "Rotate every secret the web user and MySQL could read (DB passwords, API keys, "
        "SSH keys, .env files) from a clean machine.",
        "Rebuild from a known-good image rather than cleaning in place; restore only data.",
        "Use the timestamps above to bound the intrusion window and review logs around them.",
    ],
    2: [
        "Strong signs of exploitation. Investigate each HIGH/CRITICAL item before trusting "
        "this host.",
        "Preserve evidence (copy logs, session files and flagged files) before cleaning.",
        "Check the timestamps/IPs above against your own activity; rotate DB credentials.",
    ],
    1: [
        "Review the MEDIUM items; most need a human decision (is that IP / file / key yours?).",
        "If PHP is still installed, patch to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ or set "
        "session.upload_progress.enabled = Off as a stop-gap.",
    ],
    0: [
        "No indicators found in the data available. This does not prove the host is clean: "
        "logs may have rotated away and a skilled attacker may have cleaned up.",
        "Keep PHP removed or patched, and delete leftover web roots / session directories "
        "you no longer need.",
    ],
}
LIMITATIONS = (
    "Access logs never contain POST bodies; the multipart exploit payload itself is invisible.",
    "Only what the current log retention window still holds can be analysed.",
    "A kernel or ld.so.preload rootkit can hide processes and files from live checks - scan a "
    "mounted disk image with --root for a trustworthy result.",
)


def compute_verdict(findings: Iterable[Finding]) -> Verdict:
    items = list(findings)

    def has(kinds: tuple, minimum: Severity) -> bool:
        return any(f.kind in kinds and f.severity >= minimum for f in items)

    if has((Kind.COMPROMISE,), Severity.CRITICAL):
        return Verdict(3, "COMPROMISED", "Critical evidence of attacker code execution or "
                                         "persistence was found.")
    if has((Kind.COMPROMISE,), Severity.HIGH) or has((Kind.ATTEMPT,), Severity.CRITICAL):
        return Verdict(2, "LIKELY COMPROMISED", "Exploitation evidence was found; successful "
                                                "compromise is likely.")
    if has((Kind.COMPROMISE, Kind.ATTEMPT), Severity.MEDIUM):
        return Verdict(1, "SUSPICIOUS", "Attack traffic or suspicious artefacts were found that "
                                        "need review.")
    if has((Kind.EXPOSURE,), Severity.MEDIUM):
        return Verdict(1, "EXPOSED", "No compromise indicators, but vulnerable software or "
                                     "risky configuration is present.")
    return Verdict(0, "NO INDICATORS FOUND", "No indicators of compromise were found in the "
                                             "available data.")


def counts(findings: Iterable[Finding]) -> Dict[str, int]:
    result = {s.name: 0 for s in sorted(Severity, reverse=True)}
    for finding in findings:
        result[finding.severity.name] += 1
    return result


def to_json(header: Dict[str, Any], disc: Discovery, findings: List[Finding], verdict: Verdict,
            errors: List[str]) -> str:
    payload = {
        "tool": "php2shell-scanner",
        "version": __version__,
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "scan": header,
        "verdict": {"code": verdict.code, "label": verdict.label, "summary": verdict.summary},
        "counts": counts(findings),
        "discovery": {
            "web_users": list(disc.web_users),
            "webroots": list(disc.webroots),
            "session_dirs": list(disc.session_dirs),
            "log_files": list(disc.log_files),
            "php_ini_files": list(disc.php_ini_files),
            "process_count": len(disc.processes),
            "containers": [{"id": c.id, "name": c.name, "image": c.image, "running": c.running,
                            "web": c.web, "upper_dir": c.upper_dir,
                            "mounts": [{"source": s, "destination": d} for s, d in c.mounts]}
                           for c in disc.containers],
            "notes": list(disc.notes),
        },
        "findings": [f.to_dict() for f in sort_findings(findings)],
        "errors": errors,
    }
    # ensure_ascii: undecodable file names (surrogates) and any locale stay valid output
    return json.dumps(payload, indent=2, ensure_ascii=True, default=str)


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.check, f.rule, f.path))


class TextReport:
    def __init__(self, out: TextIO, color: bool, min_severity: Severity, width: int = 100):
        self.out = out
        self.color = color
        self.min_severity = min_severity
        self.width = width

    def _c(self, code: str, text: str) -> str:
        return "{}{}{}".format(code, text, RESET) if self.color else text

    def _line(self, text: str = "") -> None:
        encoding = getattr(self.out, "encoding", None) or "utf-8"
        line = (text + "\n").encode(encoding, "backslashreplace").decode(encoding, "replace")
        self.out.write(line)

    def _wrap(self, label: str, text: str) -> None:
        prefix = "      {:<9}".format(label + ":")
        lines = textwrap.wrap(text, self.width - len(prefix)) or [""]
        self._line(prefix + lines[0])
        for line in lines[1:]:
            self._line(" " * len(prefix) + line)

    def header(self, header: Dict[str, Any], disc: Discovery) -> None:
        bar = "=" * self.width
        self._line(self._c(BOLD, bar))
        self._line(self._c(BOLD, " php2shell-scanner {} - compromise assessment for CVE-2026-109618 / "
                                 "CVE-2026-109619".format(__version__)))
        self._line(self._c(BOLD, bar))
        self._line(" Host: {}   Mode: {}   Root: {}   Started: {}".format(
            safe(header["host"]), header["mode"], safe(header["root"]), header["started"]))
        if header.get("since"):
            self._line(" Recency window (--since): {}".format(header["since"]))
        self._line(" Web users: {}".format(safe(", ".join(disc.web_users)) or "(none found)"))
        self._line(" Web roots: {}".format(safe(", ".join(disc.webroots)) or "(none found)"))
        self._line(" Session dirs: {}".format(safe(", ".join(disc.session_dirs)) or "(none found)"))
        self._line(" Log files: {}   PHP ini files: {}   Processes: {}   Containers: {}".format(
            len(disc.log_files), len(disc.php_ini_files), len(disc.processes),
            len(disc.containers)))
        for container in disc.containers:
            if container.web:
                self._line("   container {} ({}){}".format(
                    safe(container.name), safe(container.image),
                    "" if container.running else " [stopped]"))
        for note in disc.notes:
            self._line(self._c(COLORS[Severity.HIGH], " ! " + safe(note)))

    def finding(self, f: Finding) -> None:
        tag = self._c(COLORS[f.severity], "[{}]".format(f.severity.name))
        self._line("  {} {}  {}".format(tag, self._c(BOLD, f.rule), safe(f.title)))
        if f.path:
            self._wrap("path", safe(f.path))
        if f.evidence:
            self._wrap("evidence", safe(f.evidence))
        meta = f.meta or {}
        facts = ["{}={}".format(k, safe(meta[k])) for k in META_KEYS if k in meta]
        if facts:
            self._wrap("facts", "  ".join(facts))
        if f.detail:
            self._wrap("why", safe(f.detail))

    def body(self, findings: List[Finding]) -> None:
        visible = [f for f in findings if f.severity >= max(self.min_severity, Severity.LOW)]
        for kind, title in SECTIONS:
            items = sort_findings(f for f in visible if f.kind == kind)
            if not items:
                continue
            self._line()
            self._line(self._c(BOLD, "-- {} ({}) ".format(title, len(items)).ljust(self.width, "-")))
            for item in items:
                self.finding(item)
        context = [f for f in findings if f.severity == Severity.INFO or f.kind == Kind.INFO]
        if context and self.min_severity <= Severity.INFO:
            self._line()
            self._line(self._c(BOLD, "-- CONTEXT ".ljust(self.width, "-")))
            for item in sort_findings(context):
                suffix = "  ({})".format(item.evidence) if item.evidence else ""
                self._line(safe("  - {}{}".format(item.title, suffix))[: self.width * 2])

    def footer(self, findings: List[Finding], verdict: Verdict, errors: List[str],
               duration: float) -> None:
        self._line()
        self._line(self._c(BOLD, "=" * self.width))
        summary = "  ".join("{}: {}".format(k, v) for k, v in counts(findings).items())
        self._line(" Findings - " + summary + "   ({:.1f}s)".format(duration))
        color = COLORS[Severity.CRITICAL] if verdict.code >= 2 else (
            COLORS[Severity.MEDIUM] if verdict.code == 1 else "\033[1;32m")
        self._line(" VERDICT: " + self._c(color, " {} ".format(verdict.label)) + "  "
                   + verdict.summary)
        self._line()
        self._line(self._c(BOLD, " Next steps:"))
        for step in NEXT_STEPS[verdict.code]:
            self._wrap_bullet(step)
        if errors and verdict.code == 0:
            self._line(self._c(COLORS[Severity.HIGH],
                               " ! INCOMPLETE: a check failed, so 'no indicators' is not "
                               "established (exit code 70)."))
        for error in errors:
            self._line(self._c(COLORS[Severity.HIGH], " ! check error: " + safe(error)))
        self._line()
        self._line(self._c(BOLD, " Limitations:"))
        for item in LIMITATIONS:
            self._wrap_bullet(item)
        self._line(self._c(BOLD, "=" * self.width))

    def note(self, text: str) -> None:
        self._line(" " + safe(text))

    def _wrap_bullet(self, text: str) -> None:
        lines = textwrap.wrap(text, self.width - 5) or [""]
        self._line("  - " + lines[0])
        for line in lines[1:]:
            self._line("    " + line)
