"""Web roots: webshells, backdoored config, hidden PHP and attacker-written files.

Even with PHP uninstalled these files are proof of what the attacker did while it
was installed, and they become live again the moment PHP is reinstalled.
"""

import os
import re
import stat
from typing import Dict, List, Optional, Set

from php2shell_scanner.checks.common import basename_ext, file_meta, info
from php2shell_scanner.checks.webconfig import CONFIG_NAMES, scan_config_file
from php2shell_scanner.context import ScanContext
from php2shell_scanner.fs import drop_cache
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import Match, Signature, scan, snippet_around
from php2shell_scanner.signatures import webshell as ws

NAME = "webroot"
DESCRIPTION = "Web roots: webshells, PHP in uploads/media, .user.ini/.htaccess backdoors"

# VCS metadata is searched for planted PHP, but its (compressed) object stores are not.
VCS_DIRS = ("/.git/", "/.svn/", "/.hg/")
VCS_STORES = ("/.git/objects", "/.svn/pristine", "/.hg/store")
MEDIA_CHUNK = 8 * 1024
MEDIA_FULL_LIMIT = 2 * 1024 * 1024   # media in upload dirs is read completely up to this
CHUNK = 4 * 1024 * 1024
CHUNK_OVERLAP = 64 * 1024
MAX_SCANNED_BYTES = 64 * 1024 * 1024
TINY = 400
IMAGE_EXTENSIONS = frozenset((".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp",
                              ".tif", ".tiff", ".svg"))
MEDIA_PHP_TAG = re.compile(rb"<\?php\b", re.I)
DOUBLE_EXT = re.compile(r"\.(?:php\d?|phtml)\.[a-z0-9]{2,5}$|\.(?:jpe?g|png|gif|txt|ico)\.php\d?$",
                        re.I)

_SPECIALS = {
    "blob": Signature("WEB-ENCODED-BLOB", Severity.HIGH, Kind.COMPROMISE,
                      "Large encoded blob executed by eval/assert", ws.LONG_BLOB),
    "xor": Signature("WEB-XOR-STRINGS", Severity.HIGH, Kind.COMPROMISE,
                     "String-XOR obfuscation (non-alphanumeric webshell)", ws.XOR_STRING),
    "phpinfo": Signature("WEB-PHPINFO-PROBE", Severity.LOW, Kind.EXPOSURE,
                         "Tiny phpinfo() file (probe / information leak)", ws.PHPINFO),
    "exec": Signature("WEB-TINY-EXEC", Severity.HIGH, Kind.COMPROMISE,
                      "Tiny file whose only job is running a command", ws.TINY_EXEC),
    "genlog": Signature("WEB-MYSQL-GENLOG", Severity.CRITICAL, Kind.COMPROMISE,
                        "MySQL general log written as PHP (phpMyAdmin general_log trick)",
                        ws.MYSQL_GENERAL_LOG),
}


def in_upload_dir(path: str) -> bool:
    if ws.UPLOAD_PATH_MARKERS.search(path):
        return True
    return any(part in ws.UPLOAD_DIR_NAMES for part in path.split("/")[:-1])


def _special_matches(data: bytes, size: int) -> List[Match]:
    found: List[Match] = []

    def add(key: str, regex_match: "re.Match") -> None:
        found.append(Match(_SPECIALS[key], snippet_around(data, regex_match.start(),
                                                          regex_match.end())))

    eval_like = ws.EVAL_LIKE.search(data)
    blob = ws.LONG_BLOB.search(data)
    if blob and eval_like:
        add("blob", eval_like)
    xors = list(ws.XOR_STRING.finditer(data))
    if len(xors) >= 3:
        add("xor", xors[0])
    if size <= TINY:
        probe = ws.PHPINFO.search(data)
        if probe:
            add("phpinfo", probe)
        exec_call = ws.TINY_EXEC.search(data)
        if exec_call:
            add("exec", exec_call)
    genlog = ws.MYSQL_GENERAL_LOG.search(data)
    if genlog and ws.PHP_OPEN_TAG.search(data):
        add("genlog", genlog)
    return found


def _location_matches(path: str, data: bytes) -> List[Match]:
    if b"(" not in data:  # "<?php // Silence is golden" style placeholders
        return []
    parts = path.split("/")
    name = parts[-1].lower()
    found = []
    if in_upload_dir(path):
        found.append(Match(Signature("WEB-PHP-IN-UPLOADS", Severity.MEDIUM, Kind.COMPROMISE,
                                     "Executable PHP inside an upload/media directory", None),
                           name))
    if name.startswith(".") and name not in (".user.ini", ".htaccess"):
        found.append(Match(Signature("WEB-HIDDEN-PHP", Severity.MEDIUM, Kind.COMPROMISE,
                                     "Hidden PHP file", None), name))
    if DOUBLE_EXT.search(name):
        found.append(Match(Signature("WEB-DOUBLE-EXT", Severity.MEDIUM, Kind.COMPROMISE,
                                     "Double-extension file name", None), name))
    return found


def _combine(path: str, matches: List[Match], meta: Dict,
             primary: Optional[Match] = None) -> Finding:
    ordered = sorted(matches, key=lambda m: -int(m.signature.severity))
    top = primary or ordered[0]
    severity = ordered[0].signature.severity
    strong = {m.signature.rule for m in ordered if m.signature.severity >= Severity.HIGH}
    if len(strong) >= 2:
        severity = Severity.CRITICAL
    rules = [m.signature.rule for m in ordered]
    detail = "Matched: " + ", ".join(rules)
    return Finding(NAME, top.signature.rule, severity, top.signature.kind, top.signature.title,
                   path, top.snippet, detail, dict(meta, rules=rules))


def _content_matches(ctx: ScanContext, path: str, st: os.stat_result) -> List[Match]:
    """Signature matches over the whole file; big files are scanned in overlapping chunks."""
    if st.st_size <= ctx.max_file_size:
        data = ctx.fs.read_bytes(path, ctx.max_file_size) or b""
        return scan(ws.CONTENT_SIGNATURES, data) + _special_matches(data, st.st_size) + \
            _location_matches(path, data)
    matches: Dict[str, Match] = {}
    try:
        with ctx.fs.open_binary(path) as handle:
            tail, scanned = b"", 0
            while scanned < MAX_SCANNED_BYTES:
                chunk = handle.read(CHUNK)
                if not chunk:
                    break
                window = tail + chunk
                for match in scan(ws.CONTENT_SIGNATURES, window) + _special_matches(window, 10**9):
                    matches.setdefault(match.signature.rule, match)
                tail, scanned = chunk[-CHUNK_OVERLAP:], scanned + len(chunk)
            drop_cache(handle)
    except (OSError, ValueError):
        return []
    return list(matches.values()) + _location_matches(path, b"(")


def scan_php_file(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result
                  ) -> Optional[Finding]:
    matches = _content_matches(ctx, path, st)
    if st.st_uid in disc.mysql_uids:
        matches.append(Match(Signature("WEB-OWNED-BY-MYSQL", Severity.HIGH, Kind.COMPROMISE,
                                       "PHP file written by the MySQL server (INTO OUTFILE)",
                                       None), "owner=" + disc.owner_name(st.st_uid)))
    if not matches:
        return None
    return _combine(path, matches, file_meta(ctx, disc, st))


def scan_media_file(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result
                    ) -> Optional[Finding]:
    """Non-PHP files: images must never hold PHP; text files only when suspicious."""
    uploads = in_upload_dir(path)
    if uploads and st.st_size <= MEDIA_FULL_LIMIT:
        data = ctx.fs.read_bytes(path, MEDIA_FULL_LIMIT)
    else:
        data = ctx.fs.read_head_tail(path, st.st_size, MEDIA_CHUNK)
    if not data or data.startswith(b"#!"):  # vendor/bin CLI scripts, artisan, ...
        return None
    tag = MEDIA_PHP_TAG.search(data)
    if not tag:
        return None
    sig_matches = scan(ws.CONTENT_SIGNATURES, data)
    if not (basename_ext(path) in IMAGE_EXTENSIONS or uploads or sig_matches):
        return None  # e.g. code samples in a plugin's readme.txt
    hidden = Signature("WEB-CODE-IN-MEDIA", Severity.HIGH, Kind.COMPROMISE,
                       "PHP code hidden inside a non-PHP file (polyglot / include target)", None)
    primary = Match(hidden, snippet_around(data, tag.start(), tag.end()))
    return _combine(path, [primary] + sig_matches, file_meta(ctx, disc, st), primary)


def _walk_root(ctx: ScanContext, disc: Discovery, root: str, handlers: Dict[str, Set[str]],
               recent: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for path, st in ctx.fs.walk(root, max_depth=24, max_entries=ctx.max_files,
                                skip_dir=lambda d: d.endswith(VCS_STORES)):
        name = os.path.basename(path)
        ext = basename_ext(path)
        if any(v in path for v in VCS_DIRS) and ext not in ws.PHP_EXTENSIONS:
            continue
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            findings.append(Finding(NAME, "WEB-SUID", Severity.CRITICAL, Kind.COMPROMISE,
                                    "SUID/SGID file inside a web root", path,
                                    stat.filemode(st.st_mode), "", file_meta(ctx, disc, st)))
        if name in CONFIG_NAMES:
            findings.extend(scan_config_file(ctx, disc, path, st, handlers))
        elif ext in ws.PHP_EXTENSIONS or DOUBLE_EXT.search(name):
            result = scan_php_file(ctx, disc, path, st)
            if result:
                findings.append(result)
            if ctx.recent(max(st.st_mtime, st.st_ctime)):
                recent.append(path)
        elif ext in ws.MEDIA_EXTENSIONS or (not ext and st.st_size < 1024 * 1024):
            result = scan_media_file(ctx, disc, path, st)
            if result:
                findings.append(result)
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    handlers: Dict[str, Set[str]] = {}
    recent: List[str] = []
    for root in disc.webroots:
        findings.extend(_walk_root(ctx, disc, root, handlers, recent))
    if len(handlers) > 1:
        detail = "; ".join("{} in {}".format(h, ", ".join(sorted(p)[:3]))
                           for h, p in sorted(handlers.items()))
        findings.append(Finding(
            NAME, "WEB-HANDLER-MISMATCH", Severity.MEDIUM, Kind.EXPOSURE,
            "Different session.serialize_handler per directory (Chain C precondition)",
            evidence=", ".join(sorted(handlers)), detail=detail))
    if recent:
        findings.append(Finding(
            NAME, "WEB-RECENT-PHP", Severity.INFO, Kind.INFO,
            "{} PHP file(s) created/modified after --since".format(len(recent)),
            detail="Review against your own deployments.", meta={"paths": sorted(recent)[:200]}))
    findings.append(info(NAME, "WEB-ROOTS", "Scanned {} web root(s)".format(len(disc.webroots)),
                         webroots=list(disc.webroots)))
    return findings
