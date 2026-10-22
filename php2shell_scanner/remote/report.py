"""Text, JSON and Markdown output for remote scans."""

import json
import time
from typing import Any, Dict, List, TextIO

from php2shell_scanner import __version__
from php2shell_scanner.cli_common import DISCLAIMER
from php2shell_scanner.markdown import PROJECT_URL, cell, code, plain
from php2shell_scanner.remote.verdict import (LIKELY, NOT_PHP, NOT_VULNERABLE, UNKNOWN,
                                              UNREACHABLE, VULNERABLE, TargetResult)
from php2shell_scanner.report import safe

COLORS = {VULNERABLE: "\033[1;97;41m", LIKELY: "\033[1;31m", UNKNOWN: "\033[1;33m",
          UNREACHABLE: "\033[2m", NOT_VULNERABLE: "\033[1;32m", NOT_PHP: "\033[32m"}
ICONS = {VULNERABLE: "🔴", LIKELY: "🟠", UNKNOWN: "🟡", UNREACHABLE: "⚪", NOT_VULNERABLE: "🟢",
         NOT_PHP: "🟢"}
ADVICE = {
    VULNERABLE: "Upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+ (EOL branches: move to a "
                "supported branch). Until then set session.upload_progress.enabled = Off. Then "
                "run `php2shell-scanner forensics` on the server to check for a compromise.",
    LIKELY: "Confirm on the server: `php -v` and the package changelog (distribution builds "
            "may contain the backported fix). Run `php2shell-scanner forensics` there.",
    UNKNOWN: "PHP is present but its version is hidden. Check `php -v` on the server or run "
             "`php2shell-scanner forensics` locally.",
    UNREACHABLE: "Target did not answer; check the address, port and firewall.",
    NOT_VULNERABLE: "No affected PHP version observed.",
    NOT_PHP: "No PHP observed. If PHP sits behind a proxy/CDN, scan the origin directly.",
}
LIMITS = ("A remote check cannot see distribution backports, hidden versions or origins "
          "behind a CDN; only `php -v` / the package database on the server is authoritative.")


def _lines(result: TargetResult) -> List[str]:
    out = ["  confidence: {}   requests sent: {}".format(result.confidence, result.requests)]
    for version, sources in result.versions.items():
        out.append("  PHP {} - seen via {}".format(safe(version), safe("; ".join(sources[:4]))))
    for title, items in (("evidence", result.reasons), ("mitigation", result.mitigations),
                         ("exposure", result.exposures), ("context", result.context)):
        out += ["  {:<10} {}".format(title + ":", safe(item)) for item in items]
    out.append("  advice:    " + ADVICE[result.status])
    return out


class TextOutput:
    def __init__(self, out: TextIO, color: bool) -> None:
        self.out = out
        self.color = color

    def write(self, text: str) -> None:
        encoding = getattr(self.out, "encoding", None) or "utf-8"
        self.out.write((text + "\n").encode(encoding, "backslashreplace").decode(encoding))

    def result(self, result: TargetResult) -> None:
        label = " {} ".format(result.status)
        if self.color:
            label = COLORS[result.status] + label + "\033[0m"
        self.write("")
        self.write("== {}  [{}]".format(safe(result.target), label))
        for line in _lines(result):
            self.write(line)

    def summary(self, results: List[TargetResult]) -> None:
        self.write("")
        self.write("=" * 78)
        for result in results:
            self.write(" {:<16} {:<8} {}".format(result.status, result.confidence,
                                                 safe(result.target)))
        self.write("=" * 78)
        self.write(" " + LIMITS)
        self.write(" " + DISCLAIMER)


def to_dict(result: TargetResult) -> Dict[str, Any]:
    data = result._asdict()
    data["exit_code"] = result.code
    return data


def to_json(results: List[TargetResult], header: Dict[str, Any]) -> str:
    return json.dumps({"tool": "php2shell-scanner", "version": __version__, "mode": "scan",
                       "scan": header, "results": [to_dict(r) for r in results]},
                      indent=2, ensure_ascii=True)


def to_markdown(results: List[TargetResult], header: Dict[str, Any]) -> str:
    lines = ["# php2shell-scanner vulnerability scan", "", "> " + DISCLAIMER, "",
             "| | |", "|---|---|",
             "| Started | {} |".format(cell(header.get("started", ""))),
             "| Targets | {} |".format(len(results)),
             "| Mode | {} |".format(cell(header.get("mode", ""))),
             "| Scanner | [php2shell-scanner {}]({}) |".format(__version__, PROJECT_URL), "",
             "## Summary", "", "| Target | Status | Confidence | PHP versions seen |",
             "|---|---|---|---|"]
    for result in results:
        lines.append("| {} | {} {} | {} | {} |".format(
            cell(result.target), ICONS[result.status], result.status, result.confidence,
            cell(", ".join(result.versions)) if result.versions else "-"))
    for result in results:
        lines += ["", "## {} {} - {}".format(ICONS[result.status], code(result.target),
                                             result.status), "",
                  "- **Confidence:** {}".format(result.confidence),
                  "- **Requests sent:** {}".format(result.requests)]
        for version, sources in result.versions.items():
            lines.append("- **PHP {}** seen via {}".format(code(version, 60),
                                                          plain("; ".join(sources[:6]))))
        for title, items in (("Evidence", result.reasons), ("Mitigations", result.mitigations),
                             ("Exposures", result.exposures), ("Context", result.context)):
            if items:
                lines += ["", "**{}:**".format(title), ""] + ["- " + plain(i) for i in items]
        lines += ["", "**Advice:** " + plain(ADVICE[result.status])]
    lines += ["", "## Limitations", "", "- " + plain(LIMITS), "", "---", "",
              "Generated by [php2shell-scanner]({}) - by [Evil0ctal](https://github.com/"
              "Evil0ctal) on {}.".format(PROJECT_URL, time.strftime("%Y-%m-%d %H:%M")), ""]
    return "\n".join(lines)
