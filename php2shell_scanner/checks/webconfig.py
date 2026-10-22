"""Per-directory web configuration: .user.ini / php.ini / .htaccess backdoors.

Helper module for the webroot check (not a check of its own). .htaccess is parsed
line by line instead of with multi-line regexes so hostile files cannot trigger
catastrophic backtracking.
"""

import fnmatch
import os
import re
from typing import Dict, List, Optional, Set, Tuple

from php2shell_scanner.checks.common import file_meta
from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable
from php2shell_scanner.signatures import webshell as ws

NAME = "webroot"
CONFIG_NAMES = (".user.ini", "php.ini", ".htaccess")
MAX_CONFIG_BYTES = 256 * 1024
MAX_LINES = 20000
INI_DIRECTIVE = re.compile(
    rb"^[ \t]*(?:php_(?:admin_)?value[ \t]+)?(auto_prepend_file|auto_append_file"
    rb"|session\.serialize_handler)[ \t]*=?[ \t]*[\"']?([^\s\"';=]+)", re.I | re.M)
DISABLED_VALUES = frozenset(("none", "off", "0", "false"))
FILES_OPEN = re.compile(rb"^<files(match)?\s+(~\s*)?([^>]{0,200})>", re.I)
EXEC_HANDLER_WORDS = (b"php", b"cgi", b"fcgid", b"perl", b"python")
# Names a legitimate script-handler block never needs to match: common upload stems
# combined with non-script extensions ("upload.*" or "\.(jpg|php)$" must be caught).
NON_SCRIPT_SAMPLES = tuple("{}.{}".format(stem, ext)
                           for stem in ("x", "upload", "image", "avatar", "shell", "index")
                           for ext in ("jpg", "png", "gif", "ico", "txt", "svg", "zip", "pdf"))
MAX_SELECTOR = 120
UNSAFE_SELECTOR = re.compile(r"\)[*+{]|\\[1-9]|\(\?[<=!P]")
# Legitimate selectors use at most one quantifier (".+\.ph(ar|p|tml)$"); with <= 3 the
# match against ~12-character sample names stays a few thousand steps at worst.
QUANTIFIER = re.compile(r"[*+?]|\{\d")
MAX_QUANTIFIERS = 3
LEGACY_PHP_EXTENSIONS = frozenset((".html", ".htm", ".shtml", ".tpl", ".phtm"))


def scan_config_file(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result,
                     handlers: Dict[str, Set[str]]) -> List[Finding]:
    data = ctx.fs.read_bytes(path, MAX_CONFIG_BYTES) or b""
    findings = []
    for found in INI_DIRECTIVE.finditer(data):
        key = found.group(1).decode("latin-1").lower()
        value = found.group(2).decode("latin-1")
        if key == "session.serialize_handler":
            handlers.setdefault(value, set()).add(path)
            continue
        if value.lower() in DISABLED_VALUES or _is_wordfence(ctx, path, value):
            continue
        findings.append(Finding(
            NAME, "WEB-AUTO-PREPEND", Severity.HIGH, Kind.COMPROMISE,
            "{} set in {} (runs on every request)".format(key, os.path.basename(path)), path,
            printable(found.group(0)),
            "auto_prepend_file/auto_append_file is a favourite persistence trick: every PHP "
            "request silently includes the attacker file. Inspect {}.".format(printable(value)),
            file_meta(ctx, disc, st, target=value)))
    if os.path.basename(path) == ".htaccess":
        findings.extend(_htaccess_findings(ctx, disc, path, st, data))
    return findings


def _is_wordfence(ctx: ScanContext, config_path: str, value: str) -> bool:
    """Wordfence installs wordfence-waf.php next to the .user.ini/.htaccess it configures."""
    if os.path.basename(value) != "wordfence-waf.php" \
            or os.path.dirname(value) != os.path.dirname(config_path):
        return False
    content = ctx.fs.read_bytes(value, 64 * 1024) or b""
    return b"wfWAF" in content or b"Wordfence" in content


def _block_hits_non_script(regex_mode: bool, pattern: bytes) -> bool:
    """Does a <Files>/<FilesMatch> selector match ordinary uploads such as avatar.jpg?"""
    text = pattern.decode("latin-1").strip().strip("\"'")
    if not regex_mode:
        return any(fnmatch.fnmatch(name, text) for name in NON_SCRIPT_SAMPLES)
    # The selector comes from a file an attacker may control. Python's regex engine
    # backtracks, so never run shapes that can explode (a quantified group, a back-
    # reference or a very long pattern): fail closed and report the block instead.
    if len(text) > MAX_SELECTOR or UNSAFE_SELECTOR.search(text) \
            or len(QUANTIFIER.findall(text)) > MAX_QUANTIFIERS:
        return True
    try:
        selector = re.compile(text, re.I)
    except re.error:
        return True   # unparsable selector in front of a script handler: report it
    return any(selector.search(name) for name in NON_SCRIPT_SAMPLES)


Issue = Tuple[Severity, str, str]   # severity, kind, detail


def _handler_line(tokens: List[bytes]) -> Optional[Issue]:
    """AddType/AddHandler mapping a non-script extension to an executing handler."""
    if len(tokens) < 3 or not any(w in tokens[1].lower() for w in EXEC_HANDLER_WORDS):
        return None
    exts = {"." + t.decode("latin-1").lower().lstrip(".") for t in tokens[2:]}
    odd = sorted(e for e in exts if e not in ws.PHP_EXTENSIONS | ws.CGI_EXTENSIONS)
    if not odd:
        return None
    if all(e in LEGACY_PHP_EXTENSIONS for e in odd):
        return (Severity.LOW, Kind.EXPOSURE, "Legacy setup: PHP runs for " + ", ".join(odd) +
                " files - make sure this is intended")
    return (Severity.HIGH, Kind.COMPROMISE, "Extensions mapped to an executing handler: " +
            ", ".join(odd))


def _sethandler_line(lower: bytes, block: Optional[Tuple[bool, bytes]]) -> Optional[Issue]:
    handler = lower.split(None, 1)[-1] if len(lower.split()) > 1 else b""
    if not any(w in handler for w in (b"php", b"cgi-script", b"fcgid")):
        return None  # e.g. "SetHandler none" is the recommended upload-dir hardening
    if handler.strip(b"\"'").startswith(b"proxy:") or b"fcgi://" in handler:
        return None  # PHP-FPM wiring; php-fpm's security.limit_extensions still applies
    if block is None:
        return (Severity.HIGH, Kind.COMPROMISE,
                "Every file in this directory is executed by " + printable(handler, 60))
    if _block_hits_non_script(*block):
        return (Severity.HIGH, Kind.COMPROMISE,
                "Files matching {} (including images/text) are executed".format(
                    printable(block[1], 60)))
    return None


def _htaccess_findings(ctx: ScanContext, disc: Discovery, path: str, st: os.stat_result,
                       data: bytes) -> List[Finding]:
    findings = []
    block: Optional[Tuple[bool, bytes]] = None
    for raw in data.splitlines()[:MAX_LINES]:
        line = raw.strip()[:1024]
        lower = line.lower()
        opened = FILES_OPEN.match(lower)
        if opened:
            regex_mode = bool(opened.group(1) or opened.group(2))
            block = (regex_mode, line[opened.start(3):opened.end(3)])
            continue
        if lower.startswith(b"</files"):
            block = None
            continue
        if lower.startswith((b"addtype", b"addhandler")):
            issue = _handler_line(line.split())
        elif lower.startswith((b"sethandler", b"forcetype")):
            issue = _sethandler_line(lower, block)
        else:
            issue = None
        if issue:
            severity, kind, detail = issue
            findings.append(Finding(
                NAME, "WEB-HTACCESS-HANDLER", severity, kind,
                ".htaccess makes non-script files executable", path, printable(line), detail,
                file_meta(ctx, disc, st)))
    return findings
