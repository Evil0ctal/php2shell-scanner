"""Live processes: what is running as the web user right now, miners, fake kthreads."""

import os
from typing import List

from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, ProcInfo, Severity
from php2shell_scanner.paths import CONTAINERIZED_WEB_UIDS
from php2shell_scanner.signatures import printable, scan
from php2shell_scanner.signatures.system import (COMMAND_SIGNATURES, INTERPRETER_NAMES,
                                              NETTOOL_NAMES, SHELL_NAMES, is_web_server_name)

NAME = "processes"
DESCRIPTION = "Live processes: web-user shells, temp/deleted binaries, miners, fake kthreads"

TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")
MEMFD_PREFIXES = ("/memfd:", "memfd:")  # fileless: readlink shows "/memfd:name (deleted)"
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/")


def _base(proc: ProcInfo) -> str:
    exe = proc.exe.replace(" (deleted)", "")
    if exe:
        return os.path.basename(exe)
    first = proc.cmdline.split(" ", 1)[0] if proc.cmdline else proc.name
    return os.path.basename(first)


def _finding(rule: str, sev: Severity, title: str, proc: ProcInfo, disc: Discovery,
             detail: str = "") -> Finding:
    return Finding(
        NAME, rule, sev, Kind.COMPROMISE, title, proc.exe or proc.name,
        printable("pid={} user={} cmd={}".format(proc.pid, disc.owner_name(proc.uid),
                                                  proc.cmdline or proc.name), 220),
        detail,
        {"pid": proc.pid, "ppid": proc.ppid, "user": disc.owner_name(proc.uid),
         "exe": proc.exe, "cwd": proc.cwd, "cmdline": proc.cmdline[:500]})


def _web_user_findings(proc: ProcInfo, disc: Discovery) -> List[Finding]:
    base = _base(proc)
    cmd = proc.cmdline
    leading = [os.path.basename(tok) for tok in cmd.split()[:3]]
    if any(is_web_server_name(name) for name in [base, proc.name] + leading):
        return []
    if base in SHELL_NAMES or base in NETTOOL_NAMES:
        return [_finding(
            "PROC-WEBUSER-SHELL", Severity.CRITICAL,
            "Shell / network tool running as web user", proc, disc,
            "Web server accounts do not run shells or netcat on their own; this is what a "
            "webshell or reverse shell looks like. Capture it (ls -l /proc/{0}/fd, "
            "cat /proc/{0}/environ) before killing it.".format(proc.pid))]
    if base.rstrip("0123456789.") in INTERPRETER_NAMES:
        args = cmd.split()
        if any(flag in args for flag in ("-c", "-e", "-r")):
            return [_finding("PROC-WEBUSER-INLINE-CODE", Severity.CRITICAL,
                             "Interpreter running inline code as web user", proc, disc)]
        if any(arg.startswith(TMP_PREFIXES) for arg in args[1:]):
            return [_finding("PROC-WEBUSER-TMP-SCRIPT", Severity.CRITICAL,
                             "Web user runs a script from a temp/hidden location", proc, disc)]
    return [_finding(
        "PROC-WEBUSER-OTHER", Severity.MEDIUM, "Unexpected process running as web user",
        proc, disc, "If PHP and phpMyAdmin are removed, nothing but the web server itself "
                    "should run as this user.")]


def is_web_process(proc: ProcInfo, disc: Discovery) -> bool:
    """Host web users, or the usual web uids inside a container (1Panel/BT use 1000)."""
    return proc.uid in disc.web_uids or (proc.container and proc.uid in CONTAINERIZED_WEB_UIDS)


def check_process(proc: ProcInfo, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    exe = proc.exe
    is_kthread_name = proc.cmdline.startswith("[") and proc.cmdline.endswith("]")
    if is_kthread_name and exe:
        findings.append(_finding(
            "PROC-FAKE-KTHREAD", Severity.CRITICAL,
            "User process disguised as a kernel thread", proc, disc,
            "Real kernel threads have no executable; malware renames itself '[kworker/...]'."))
    plain_exe = exe.replace(" (deleted)", "")
    if exe.startswith(MEMFD_PREFIXES) or plain_exe.startswith(TMP_PREFIXES):
        findings.append(_finding(
            "PROC-TMP-EXE", Severity.CRITICAL,
            "Process running from a temp directory or from memory only (memfd)", proc, disc))
    elif is_web_process(proc, disc) and "/." in plain_exe:
        findings.append(_finding(
            "PROC-HIDDEN-EXE", Severity.HIGH,
            "Web-user process running a binary from a hidden directory", proc, disc))
    elif exe.endswith(" (deleted)"):
        system = exe.startswith(SYSTEM_PREFIXES)
        findings.append(_finding(
            "PROC-DELETED-EXE", Severity.LOW if system else Severity.HIGH,
            "Process binary was deleted from disk", proc, disc,
            "Usually a daemon not restarted after an upgrade" if system
            else "Malware deletes its own binary after starting."))
    for match in scan(COMMAND_SIGNATURES, proc.cmdline):
        if match.signature.severity >= Severity.HIGH:
            findings.append(_finding(match.signature.rule.replace("CMD-", "PROC-"),
                                     match.signature.severity,
                                     "Process command line: " + match.signature.title, proc, disc))
    if is_web_process(proc, disc) and not is_kthread_name:
        findings.extend(_web_user_findings(proc, disc))
        if proc.cwd.startswith(TMP_PREFIXES):
            findings.append(_finding("PROC-WEBUSER-TMP-CWD", Severity.MEDIUM,
                                     "Web-user process working in a temp directory", proc, disc))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    if not ctx.live:
        return []
    findings: List[Finding] = []
    own = os.getpid()
    for proc in disc.processes:
        if proc.pid == own:
            continue
        findings.extend(check_process(proc, disc))
    return findings
