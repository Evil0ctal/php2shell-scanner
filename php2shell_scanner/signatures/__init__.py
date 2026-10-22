"""Signature primitives shared by all signature sets."""

from typing import Any, List, NamedTuple, Optional

from php2shell_scanner.models import Severity

EVIDENCE_WIDTH = 160


class Signature(NamedTuple):
    rule: str
    severity: Severity
    kind: str
    title: str
    pattern: Any  # compiled regex (bytes or str, depending on the set)


class Match(NamedTuple):
    signature: Signature
    snippet: str


# Bidirectional overrides can visually reorder a line ("Trojan Source").
BIDI_CONTROLS = frozenset(chr(c) for c in (0x200E, 0x200F, 0x061C, *range(0x202A, 0x202F),
                                           *range(0x2066, 0x206A)))


def _escape_char(ch: str, from_bytes: bool) -> str:
    code = ord(ch)
    if ch in "\t ":
        return " "
    if 32 <= code < 127:
        return ch
    if code < 32 or code == 127 or (from_bytes and code < 256) or 0x80 <= code < 0xA0:
        return "\\x{:02x}".format(code)
    if 0xDC80 <= code <= 0xDCFF:  # undecodable filename byte (surrogateescape)
        return "\\x{:02x}".format(code - 0xDC00)
    if 0xD800 <= code <= 0xDFFF or ch in BIDI_CONTROLS or not ch.isprintable():
        return "\\u{:04x}".format(code)
    return ch


def printable(raw: Any, width: int = EVIDENCE_WIDTH) -> str:
    """Render untrusted bytes/str as a single safe, bounded line.

    Control characters, escape sequences, bidi overrides and undecodable bytes are shown
    escaped, so hostile file names or log lines cannot rewrite the analyst's terminal.
    """
    from_bytes = isinstance(raw, bytes)
    text = raw.decode("latin-1") if from_bytes else str(raw)
    out = "".join(_escape_char(ch, from_bytes) for ch in text[: width * 4])
    return out if len(out) <= width else out[: width - 3] + "..."


def snippet_around(data: Any, start: int, end: int, width: int = EVIDENCE_WIDTH) -> str:
    pad = max(0, (width - (end - start)) // 2)
    lo = max(0, start - pad)
    hi = min(len(data), end + pad)
    return printable(data[lo:hi], width)


def scan(signatures: List[Signature], data: Any) -> List[Match]:
    matches = []
    for sig in signatures:
        found = sig.pattern.search(data)
        if found:
            matches.append(Match(sig, snippet_around(data, found.start(), found.end())))
    return matches


def first(signatures: List[Signature], data: Any) -> Optional[Match]:
    for sig in signatures:
        found = sig.pattern.search(data)
        if found:
            return Match(sig, snippet_around(data, found.start(), found.end()))
    return None
