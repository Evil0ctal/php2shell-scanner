"""Markdown rendering of the forensic report (for download, tickets and sharing).

All evidence is untrusted: it is sanitised with ``printable`` and placed in code
spans/fences whose delimiters are longer than any backtick run in the content, so
crafted file names or log lines cannot inject Markdown or HTML.
"""

import re
from typing import Any, Dict, Iterable, List

from php2shell_scanner import __version__
from php2shell_scanner.cli_common import DISCLAIMER
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.report import (LIMITATIONS, META_KEYS, NEXT_STEPS, SECTIONS, Verdict,
                                      counts, sort_findings)
from php2shell_scanner.signatures import printable

PROJECT_URL = "https://github.com/Evil0ctal/php2shell-scanner"
MAX_FIELD = 2000
VERDICT_ICON = {3: "🔴", 2: "🟠", 1: "🟡", 0: "🟢"}
SEVERITY_ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
                 Severity.LOW: "🔵", Severity.INFO: "⚪"}


def clean(value: Any, width: int = MAX_FIELD) -> str:
    return printable(str(value), width)


def code(value: Any, width: int = MAX_FIELD) -> str:
    """Inline code span that cannot be broken out of."""
    text = clean(value, width)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return "{0}{1}{2}{1}{0}".format(fence, pad, text)


def cell(value: Any, width: int = 300) -> str:
    """Table cell: code span with pipes escaped (GFM splits cells on '|' even in code)."""
    return code(value, width).replace("|", "\\|")


def fenced(value: Any, width: int = MAX_FIELD) -> List[str]:
    text = clean(value, width)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", text, fence]


def plain(value: Any, width: int = MAX_FIELD) -> str:
    """Prose from our own templates that may embed untrusted values: escape Markdown."""
    return re.sub(r"([\\`*_{}\[\]<>()#+!|~])", r"\\\1", clean(value, width))


def _finding_block(index: int, f: Finding) -> List[str]:
    lines = ["#### {}. {} {} `{}` - {}".format(
        index, SEVERITY_ICON[f.severity], f.severity.name, f.rule, plain(f.title, 300)), ""]
    if f.path:
        lines.append("- **Path:** {}".format(code(f.path)))
    meta = f.meta or {}
    facts = ["{}={}".format(k, clean(meta[k], 120)) for k in META_KEYS if k in meta]
    if facts:
        lines.append("- **Facts:** {}".format(code("  ".join(facts))))
    if meta.get("top_ips"):
        ips = ", ".join("{} ({}x)".format(clean(ip, 64), n)
                        for ip, n in list(meta["top_ips"].items())[:10])
        lines.append("- **Top sources:** {}".format(code(ips)))
    if f.detail:
        lines.append("- **Why it matters:** {}".format(plain(f.detail)))
    if f.evidence:
        lines += ["- **Evidence:**", ""] + ["  " + line for line in fenced(f.evidence)]
    samples = meta.get("samples") or []
    if len(samples) > 1:
        lines += ["- **Samples:**", ""]
        for sample in samples[:3]:
            lines += ["  " + line for line in fenced(sample, 600)]
    hidden = meta.get("hidden_paths") or meta.get("paths")
    if hidden:
        lines += ["- **Paths:**", ""] + ["  - {}".format(code(p, 300)) for p in hidden[:50]]
    lines.append("")
    return lines


def _summary_table(items: Iterable[Finding]) -> List[str]:
    lines = ["| # | Severity | Rule | Finding | Path |", "|---|---|---|---|---|"]
    for index, f in enumerate(items, 1):
        lines.append("| {} | {} {} | {} | {} | {} |".format(
            index, SEVERITY_ICON[f.severity], f.severity.name, cell(f.rule, 60),
            plain(f.title, 160), cell(f.path, 160) if f.path else ""))
    return lines + [""]


def _discovery(disc: Discovery) -> List[str]:
    rows = [
        ("Web users", ", ".join(disc.web_users)),
        ("Web roots", ", ".join(disc.webroots)),
        ("Session directories", ", ".join(disc.session_dirs)),
        ("Log files analysed", str(len(disc.log_files))),
        ("PHP ini files", ", ".join(disc.php_ini_files)),
        ("Processes inspected", str(len(disc.processes))),
        ("Containers", ", ".join("{} ({})".format(c.name, c.image) for c in disc.containers)),
    ]
    lines = ["## Discovery", "", "| Item | Value |", "|---|---|"]
    lines += ["| {} | {} |".format(name, cell(value, 1500) if value else "-") for name, value in rows]
    for note in disc.notes:
        lines.append("")
        lines.append("> **Note:** {}".format(plain(note)))
    return lines + [""]


def forensics_markdown(header: Dict[str, Any], disc: Discovery, findings: List[Finding],
                       verdict: Verdict, errors: List[str]) -> str:
    totals = counts(findings)
    lines = [
        "# php2shell-scanner forensic report",
        "",
        "> {}".format(DISCLAIMER),
        "",
        "| | |", "|---|---|",
        "| Host | {} |".format(cell(header["host"])),
        "| Mode | {} |".format(cell(header["mode"])),
        "| Root | {} |".format(cell(header["root"])),
        "| Started | {} |".format(cell(header["started"])),
        "| Recency window (--since) | {} |".format(cell(header.get("since") or "-")),
        "| Scanner | [php2shell-scanner {}]({}) |".format(__version__, PROJECT_URL),
        "",
        "## Verdict: {} {}".format(VERDICT_ICON[verdict.code], verdict.label),
        "",
        plain(verdict.summary),
        "",
        "| CRITICAL | HIGH | MEDIUM | LOW | INFO |", "|---|---|---|---|---|",
        "| {CRITICAL} | {HIGH} | {MEDIUM} | {LOW} | {INFO} |".format(**totals),
        "",
    ]
    if errors:
        lines += ["> **Incomplete:** {} check(s) failed - see *Errors* below.".format(len(errors)), ""]
    lines += ["### Next steps", ""] + ["{}. {}".format(i, plain(step))
                                       for i, step in enumerate(NEXT_STEPS[verdict.code], 1)]
    lines.append("")
    for kind, title in SECTIONS:
        items = sort_findings(f for f in findings if f.kind == kind and f.severity > Severity.INFO)
        if not items:
            continue
        lines += ["## {} ({})".format(title, len(items)), ""] + _summary_table(items)
        for index, item in enumerate(items, 1):
            lines += _finding_block(index, item)
    context = [f for f in findings if f.severity == Severity.INFO or f.kind == Kind.INFO]
    if context:
        lines += ["## Context", ""]
        lines += ["- {}{}".format(plain(f.title, 300), " - " + code(f.evidence, 300)
                                  if f.evidence else "") for f in sort_findings(context)]
        lines.append("")
    lines += _discovery(disc)
    if errors:
        lines += ["## Errors", ""] + ["- {}".format(code(e, 500)) for e in errors] + [""]
    lines += ["## Limitations", ""] + ["- {}".format(plain(item)) for item in LIMITATIONS]
    lines += ["", "---", "", "Generated by [php2shell-scanner]({}) - by "
              "[Evil0ctal](https://github.com/Evil0ctal).".format(PROJECT_URL), ""]
    return "\n".join(lines)
