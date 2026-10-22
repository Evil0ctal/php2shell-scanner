"""PHP session files: the on-disk footprint of php2shell exploitation.

Chain A writes PHP code into a session through the upload filename, Chain C
writes a serialized object, Chain E inflates a session to tens of MB. Session
files usually survive uninstalling PHP, so they are prime evidence.
"""

import os
import re
from typing import List, Optional

from php2shell_scanner.checks.common import file_meta, in_tmp, info
from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable, snippet_around

NAME = "sessions"
DESCRIPTION = "PHP session files: injected code, serialized gadgets, PoC IDs, inflation"

SESSION_NAME = re.compile(r"^sess_([A-Za-z0-9,\-]+)$")
POC_SID = re.compile(r"^(?:exploit[0-9a-f]{20}|hugesession0{6,}|consumerpoisoned0{6,})$")
PHP_CODE = re.compile(rb"<\?(?:php|=)|<\?\s", re.I)
SERIALIZED_IN_NAME = re.compile(rb's:4:"name";s:\d+:"[^"]{0,200}?\|[OC]:\d+:"')
CODE_TOKENS = re.compile(
    rb"\b(?:system|passthru|shell_exec|exec|popen|proc_open|eval|assert|base64_decode"
    rb"|file_put_contents|fsockopen|create_function|call_user_func)\s*\(", re.I)
UPLOAD_PROGRESS = re.compile(rb"upload_progress_")
UPLOAD_FILENAME = re.compile(rb's:4:"name";s:\d+:"(.{0,120})')
PHP_EXT = re.compile(r"\.(?:php\d?|phtml|phar|inc)$", re.I)

SIZE_MEDIUM = 1024 * 1024
SIZE_HIGH = 10 * 1024 * 1024
READ_LIMIT = 4 * 1024 * 1024


def _read(ctx: ScanContext, path: str, size: int) -> Optional[bytes]:
    if size <= READ_LIMIT:
        return ctx.fs.read_bytes(path, READ_LIMIT)
    return ctx.fs.read_head_tail(path, size, READ_LIMIT // 2)


def _finding(rule: str, sev: Severity, title: str, path: str, evidence: str, detail: str,
             meta: dict) -> Finding:
    return Finding(NAME, rule, sev, Kind.ATTEMPT, title, path, evidence, detail, meta)


def check_session_file(ctx: ScanContext, disc: Discovery, path: str,
                       st: os.stat_result) -> List[Finding]:
    sid = SESSION_NAME.match(os.path.basename(path)).group(1)  # type: ignore[union-attr]
    meta = file_meta(ctx, disc, st, session_id=sid)
    findings = []
    if POC_SID.match(sid):
        findings.append(_finding(
            "SESS-POC-SID", Severity.CRITICAL,
            "Session ID matches the public php2shell exploit tool", path, sid,
            "The PoC scripts generate IDs like 'exploit<20 hex>' / 'hugesession000...'. "
            "This file was created by someone running the exploit against this host.", meta))
    if st.st_size >= SIZE_MEDIUM:
        sev = Severity.HIGH if st.st_size >= SIZE_HIGH else Severity.MEDIUM
        findings.append(_finding(
            "SESS-INFLATED", sev, "Oversized session file (session inflation, Chain E)", path,
            "{:.1f} MB".format(st.st_size / 1048576.0),
            "Chain E builds ~30 MB sessions to force an OOM during session decode.", meta))
    data = _read(ctx, path, st.st_size)
    if not data:
        return findings
    code = PHP_CODE.search(data)
    if code:
        findings.append(_finding(
            "SESS-PHP-CODE", Severity.CRITICAL, "PHP code inside a session file (Chain A poisoning)",
            path, snippet_around(data, code.start(), code.end()),
            "A session file never legitimately contains PHP open tags. Combined with any "
            "local file inclusion this executes as the web user.", meta))
    gadget = SERIALIZED_IN_NAME.search(data)
    if gadget:
        findings.append(_finding(
            "SESS-SERIALIZED-FILENAME", Severity.CRITICAL,
            "Serialized object injected via upload filename (Chain C)", path,
            snippet_around(data, gadget.start(), gadget.end()),
            "'|O:' inside an uploaded filename is the handler-mismatch gadget that fires "
            "__destruct() when the session is decoded with the other handler.", meta))
    tokens = CODE_TOKENS.search(data)
    if tokens and not code:
        findings.append(_finding(
            "SESS-CODE-TOKENS", Severity.HIGH, "Code-execution functions inside session data", path,
            snippet_around(data, tokens.start(), tokens.end()),
            "Session data containing system()/eval()-style calls is typical of injected "
            "payloads.", meta))
    if UPLOAD_PROGRESS.search(data):
        names = [printable(m.group(1), 80) for m in UPLOAD_FILENAME.finditer(data)][:3]
        findings.append(_finding(
            "SESS-UPLOAD-PROGRESS", Severity.MEDIUM,
            "Upload-progress entry persisted in a session", path,
            "filenames: " + (", ".join(names) if names else "(none recorded)"),
            "With the default session.upload_progress.cleanup=On these entries are deleted at "
            "the end of the request. A leftover entry means cleanup was disabled or the upload "
            "was deliberately stalled - the technique used by the Chain A exploit.", meta))
    return findings


def check_other_file(ctx: ScanContext, disc: Discovery, path: str,
                     st: os.stat_result) -> List[Finding]:
    """Non-session files inside a dedicated session directory."""
    data = ctx.fs.read_bytes(path, 256 * 1024) or b""
    code = PHP_CODE.search(data)
    if not (PHP_EXT.search(path) or code):
        return []
    evidence = snippet_around(data, code.start(), code.end()) if code else os.path.basename(path)
    return [Finding(NAME, "SESS-DIR-PHP-FILE", Severity.HIGH, Kind.COMPROMISE,
                    "PHP file planted in a session directory", path, evidence,
                    "Session directories only ever hold sess_* files.",
                    file_meta(ctx, disc, st))]


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    for directory in disc.session_dirs:
        dedicated = not in_tmp(directory)
        count = 0
        for path, st in ctx.fs.walk(directory, max_depth=3, max_entries=ctx.max_files):
            name = os.path.basename(path)
            if SESSION_NAME.match(name):
                count += 1
                findings.extend(check_session_file(ctx, disc, path, st))
            elif dedicated:
                findings.extend(check_other_file(ctx, disc, path, st))
        findings.append(info(NAME, "SESS-DIR", "Scanned {} session file(s) in {}".format(
            count, directory), directory=directory, session_files=count))
    return findings
