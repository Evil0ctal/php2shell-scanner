"""Temp directories and web-user homes: dropped tools, PoC proof files, SUID drops."""

import os
import re
import stat
from typing import List, Optional

from php2shell_scanner.checks.common import TMP_DIRS, file_meta
from php2shell_scanner.containers import tmp_dirs as container_tmp_dirs
from php2shell_scanner.context import ScanContext
from php2shell_scanner.fs import ELF_MAGIC
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import scan, snippet_around
from php2shell_scanner.signatures import webshell as ws
from php2shell_scanner.signatures.system import COMMAND_SIGNATURES

NAME = "tmp"
DESCRIPTION = "/tmp, /var/tmp, /dev/shm, web-user homes: binaries, scripts, PoC artifacts"

# Per-service private tmp dirs belong to their services; everything else is walked.
SKIP_PREFIXES = ("systemd-private-", "snap-private-tmp")
# These hold only sockets on a healthy system; a regular file inside is a known miner trick.
WEB_SERVICE_TMP = re.compile(r"php|httpd|apache|nginx|lsws|litespeed|openresty|caddy", re.I)
SOCKET_DIRS = frozenset((".X11-unix", ".ICE-unix", ".font-unix", ".XIM-unix", ".Test-unix"))
POC_PROOF_NAMES = frozenset(("rce_proof.txt", "rce_proof", ".rce"))
ODD_DIR_NAME = re.compile(r"^(?:\.{3,}|\.+\s+|\s+|\.\s.*)$")
TEXT_LIMIT = 1024 * 1024


def _skip_dir(path: str) -> bool:
    """Skip private tmp dirs of unrelated services, but not those of the web stack:
    with systemd PrivateTmp, files a webshell writes to /tmp land in there."""
    name = os.path.basename(path)
    return name.startswith(SKIP_PREFIXES) and not WEB_SERVICE_TMP.search(name)


def _in_socket_dir(path: str) -> bool:
    return any(part in SOCKET_DIRS for part in path.split("/")[:-1])


def _f(rule: str, sev: Severity, title: str, path: str, evidence: str, ctx: ScanContext,
       disc: Discovery, st: os.stat_result, kind: str = Kind.COMPROMISE, detail: str = ""
       ) -> Finding:
    return Finding(NAME, rule, sev, kind, title, path, evidence, detail,
                   file_meta(ctx, disc, st))


def check_file(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result
               ) -> List[Finding]:
    name = os.path.basename(path)
    if name.startswith("sess_"):
        return []  # handled by the sessions check
    web_owned = st.st_uid in disc.web_uids
    findings: List[Finding] = []
    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
        findings.append(_f("TMP-SUID", Severity.CRITICAL, "SUID/SGID file in a temp directory",
                           path, stat.filemode(st.st_mode), ctx, disc, st,
                           detail="Typical privilege-escalation drop (e.g. a copied SUID shell)."))
    head = ctx.fs.read_bytes(path, min(st.st_size, TEXT_LIMIT)) or b""
    if name in POC_PROOF_NAMES or (st.st_size < 65536 and ws.ID_OUTPUT.search(head)):
        found = ws.ID_OUTPUT.search(head)
        evidence = snippet_around(head, found.start(), found.end()) if found else name
        findings.append(_f("TMP-COMMAND-OUTPUT", Severity.CRITICAL,
                           "Output of `id` as the web user saved to disk (RCE proof file)",
                           path, evidence, ctx, disc, st,
                           detail="Exploits write `id` output to a file to confirm code "
                                  "execution (e.g. /tmp/rce_proof.txt in the public PoC)."))
    if _in_socket_dir(path):
        findings.append(_f("TMP-FILE-IN-SOCKET-DIR", Severity.HIGH,
                           "Regular file hidden in an X11/ICE socket directory", path,
                           os.path.basename(path), ctx, disc, st,
                           detail="These directories only ever contain sockets; miners and "
                                  "droppers hide here because admins skip them."))
    if head.startswith(ELF_MAGIC):
        findings.append(_elf_finding(ctx, disc, path, st, web_owned))
        return findings
    findings.extend(_text_findings(ctx, disc, path, st, head))
    return findings


def _elf_finding(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result,
                 web_owned: bool) -> Finding:
    """Executable droppers are chmod +x; libraries that JNA/netty/snappy unpack are not."""
    name = os.path.basename(path)
    executable = bool(st.st_mode & 0o111) and not name.endswith((".so", ".tmp")) \
        and ".so." not in name
    if executable and (web_owned or name.startswith(".")):
        sev = Severity.CRITICAL
    elif executable:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM
    return _f("TMP-ELF", sev, "{} in a temp directory".format(
        "Executable binary" if executable else "Native library / ELF file"), path,
        "ELF, owner={}, mode={}".format(disc.owner_name(st.st_uid), stat.filemode(st.st_mode)),
        ctx, disc, st, detail="Malware droppers, miners and exploit binaries live here.")


def _text_findings(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result,
                   head: bytes) -> List[Finding]:
    findings = []
    tag = ws.PHP_OPEN_TAG.search(head)
    is_php = os.path.splitext(path)[1].lower() in ws.PHP_EXTENSIONS
    if tag or is_php:
        matches = scan(ws.CONTENT_SIGNATURES, head)
        if matches:
            sev = Severity.CRITICAL
        else:
            sev = Severity.HIGH if st.st_uid in disc.web_uids else Severity.MEDIUM
        evidence = matches[0].snippet if matches else (
            snippet_around(head, tag.start(), tag.end()) if tag else os.path.basename(path))
        findings.append(_f("TMP-PHP", sev, "PHP code in a temp directory", path, evidence,
                           ctx, disc, st, detail="Matched: " + ", ".join(
                               m.signature.rule for m in matches) if matches else ""))
    text = head.decode("latin-1")
    for match in scan(COMMAND_SIGNATURES, text):
        if match.signature.severity >= Severity.HIGH:
            findings.append(_f("TMP-" + match.signature.rule[4:], match.signature.severity,
                               "Script in temp dir: " + match.signature.title, path,
                               match.snippet, ctx, disc, st))
    return findings


def check_dir(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result
              ) -> Optional[Finding]:
    name = os.path.basename(path)
    if ODD_DIR_NAME.match(name):
        return _f("TMP-ODD-DIR", Severity.HIGH, "Directory with a deceptive name ('...', ' ')",
                  path, repr(name), ctx, disc, st,
                  detail="Names made of dots/spaces are used to hide attacker toolkits.")
    return None


def _scan_roots(disc: Discovery) -> List[str]:
    roots = list(TMP_DIRS)
    for container in disc.containers:
        roots.extend(container_tmp_dirs(container))
    for user in disc.users:
        if user.name in disc.web_users and user.home and user.home not in ("/", "/nonexistent"):
            if not any(user.home == r or user.home.startswith(r + "/") for r in disc.webroots):
                roots.append(user.home)
    return roots


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    for root in _scan_roots(disc):
        for path, st in ctx.fs.walk(root, max_depth=6, max_entries=ctx.max_files,
                                    include_dirs=True, skip_dir=_skip_dir):
            if stat.S_ISDIR(st.st_mode):
                found = check_dir(ctx, disc, path, st)
                if found:
                    findings.append(found)
                continue
            findings.extend(check_file(ctx, disc, path, st))
    return findings
