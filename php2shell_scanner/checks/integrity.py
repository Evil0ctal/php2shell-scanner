"""Package-manager verification of the tools an attacker trojans to hide (ps, ls, ss...)."""

import os
import re
from typing import Callable, FrozenSet, List, Optional

from php2shell_scanner.context import ScanContext, find_tool, run_tool
from php2shell_scanner.models import Discovery, Finding, Kind, Severity

NAME = "integrity"
DESCRIPTION = "dpkg --verify / rpm -V of core system packages (trojaned binaries)"

DEB_PACKAGES = (
    "coreutils", "procps", "openssh-server", "openssh-client", "net-tools", "iproute2",
    "util-linux", "login", "passwd", "sudo", "findutils", "grep", "lsof", "cron", "bash",
    "libc-bin", "systemd",
)
RPM_PACKAGES = (
    "coreutils", "procps-ng", "openssh-server", "openssh-clients", "net-tools", "iproute",
    "util-linux", "shadow-utils", "sudo", "findutils", "grep", "lsof", "cronie", "bash",
    "glibc", "systemd",
)
VERIFY_LINE = re.compile(r"^([.?\w]{9})\s+([cdglr]?)\s*(/\S.*)$")
CRITICAL_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/", "/lib64/", "/usr/lib/",
                 "/usr/lib64/")


def parse_verify(output: str, package: str, diverted: FrozenSet[str] = frozenset(),
                 exists: Callable[[str], bool] = lambda path: True) -> List[Finding]:
    """Content mismatches of binaries/libraries only.

    Docs, man pages and configs change legitimately (minimised container images strip
    them), diverted files are replaced on purpose, and missing files are not trojans.
    """
    findings = []
    for line in output.splitlines():
        found = VERIFY_LINE.match(line.strip())
        if not found:
            continue
        flags, attr, path = found.groups()
        if attr == "c" or flags[2] != "5" or not path.startswith(CRITICAL_DIRS):
            continue
        if path in diverted or not exists(path):
            continue
        findings.append(Finding(
            NAME, "INTEGRITY-MODIFIED-BINARY", Severity.CRITICAL,
            Kind.COMPROMISE, "Package file content differs from the package ({})".format(package),
            path, line.strip(),
            "A modified ps/ls/netstat/sshd/libc is the hallmark of a rootkit. Treat every live "
            "result as untrustworthy and analyse a disk image offline."))
    return findings


DIVERSION = re.compile(r"diversion of (\S+) to ")


def _diversions(ctx: ScanContext) -> FrozenSet[str]:
    result = run_tool(ctx, ["dpkg-divert", "--list"], timeout=60) if find_tool("dpkg-divert") \
        else None
    return frozenset(DIVERSION.findall(result[1])) if result else frozenset()


def _verify_cmd(package: str) -> Optional[List[str]]:
    if find_tool("dpkg"):
        return ["dpkg", "--verify", package]
    if find_tool("rpm"):
        return ["rpm", "-V", package]
    return None


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    if not (ctx.live and ctx.allow_exec):
        return []
    packages = DEB_PACKAGES if find_tool("dpkg") else RPM_PACKAGES
    diverted = _diversions(ctx)
    findings: List[Finding] = []
    verified = 0
    for package in packages:
        argv = _verify_cmd(package)
        result = run_tool(ctx, argv, timeout=180) if argv else None
        if result is None:
            continue
        verified += 1
        findings.extend(parse_verify(result[1], package, diverted, os.path.isfile))
    findings.append(Finding(NAME, "INTEGRITY-COVERAGE", Severity.INFO, Kind.INFO,
                            "Verified {} core package(s) against the package database".format(
                                verified)))
    return findings
