"""`php2shell-scanner forensics`: read-only compromise assessment of this host / an image."""

import argparse
import logging
import os
import socket
import sys
import time
from typing import List, Optional, Sequence, Tuple

from php2shell_scanner.checks import ALL_CHECKS
from php2shell_scanner.checks.common import cap_per_rule, fmt_time
from php2shell_scanner.cli_common import (EXIT_INTERNAL, EXIT_USAGE, configure_logging,
                                          parse_severity, parse_since, positive_int,
                                          safe_filename, write_new_report, write_private)
from php2shell_scanner.context import ScanContext, make_context
from php2shell_scanner.discovery import discover
from php2shell_scanner.markdown import forensics_markdown
from php2shell_scanner.models import Discovery, Finding, Severity
from php2shell_scanner.report import TextReport, compute_verdict, to_json
from php2shell_scanner.throttle import lower_priority

LOG = logging.getLogger("php2shell_scanner")

EPILOG = """\
exit codes: 0 no indicators, 1 suspicious/exposed, 2 likely compromised,
            3 compromised, 64 usage error,
            70 incomplete (a check failed and nothing was found) or internal error

examples:
  sudo python3 php2shell-scanner.pyz forensics
  sudo python3 php2shell-scanner.pyz forensics --since 2026-10-01 --json report.json
  sudo python3 php2shell-scanner.pyz forensics --webroot /data/sites --log /data/logs
  python3 php2shell-scanner.pyz forensics --root /mnt/evidence   # offline: mounted disk image
"""


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", default="/",
                        help="scan a mounted disk image instead of the live host")
    parser.add_argument("--since", type=parse_since, metavar="DATE",
                        help="flag files/keys/units changed after DATE (YYYY-MM-DD or 30d)")
    parser.add_argument("--webroot", action="append", default=[], metavar="DIR",
                        help="extra web root to scan (repeatable)")
    parser.add_argument("--log", action="append", default=[], metavar="PATH",
                        help="extra log file or directory (repeatable)")
    parser.add_argument("--session-dir", action="append", default=[], metavar="DIR",
                        help="extra PHP session directory (repeatable)")
    parser.add_argument("--checks", metavar="A,B", help="run only these checks")
    parser.add_argument("--skip", metavar="A,B", help="skip these checks")
    parser.add_argument("--no-throttle", action="store_true",
                        help="run at normal CPU/IO priority (default: nice 19, lowest IO "
                             "priority, page-cache friendly reads)")
    parser.add_argument("--no-exec", action="store_true",
                        help="never run external programs (dpkg/rpm/iptables/journalctl/php -v)")
    parser.add_argument("--max-file-size", type=positive_int, default=5, metavar="MB",
                        help="read at most this much of each file in one go (default 5)")
    parser.add_argument("--max-files", type=positive_int, default=300000, metavar="N",
                        help="max directory entries walked per root (default 300000)")
    parser.add_argument("--max-per-rule", type=positive_int, default=20, metavar="N",
                        help="findings shown per rule, 0 = all (default 20)")
    parser.add_argument("--min-severity", type=parse_severity, default=Severity.INFO,
                        metavar="LEVEL", help="info|low|medium|high|critical (default info)")
    parser.add_argument("--json", metavar="FILE", help="also write a JSON report ('-' = stdout)")
    parser.add_argument("--markdown", metavar="FILE",
                        help="Markdown report path (default: php2shell-forensics-<host>-<time>.md)")
    parser.add_argument("--no-markdown", action="store_true", help="do not write a Markdown report")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--list-checks", action="store_true", help="list checks and exit")


def select_checks(only: Optional[str], skip: Optional[str]) -> Tuple[list, List[str]]:
    names = {module.NAME for module in ALL_CHECKS}
    wanted = {n.strip() for n in only.split(",")} if only else set(names)
    skipped = {n.strip() for n in skip.split(",")} if skip else set()
    unknown = sorted((wanted | skipped) - names)
    selected = [m for m in ALL_CHECKS if m.NAME in wanted and m.NAME not in skipped]
    return selected, unknown


def run_checks(ctx: ScanContext, disc: Discovery, modules: Sequence, limit: int
               ) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    errors: List[str] = []
    for module in modules:
        started = time.time()
        LOG.info("running %-12s %s", module.NAME, module.DESCRIPTION)
        try:
            results = module.run(ctx, disc)
        except Exception as exc:  # one broken check must not abort the assessment
            LOG.exception("check %s failed", module.NAME)
            errors.append("{}: {}: {}".format(module.NAME, type(exc).__name__, exc))
            continue
        findings.extend(cap_per_rule(results, limit))
        LOG.debug("%s finished in %.1fs with %d finding(s)", module.NAME,
                  time.time() - started, len(results))
    return findings, errors


def host_name(ctx: ScanContext) -> str:
    if ctx.fs.is_live:
        return socket.gethostname()
    text = ctx.fs.read_text("/etc/hostname", 256) or ""
    return text.strip() or "(image)"


def run(args: argparse.Namespace) -> int:
    if args.list_checks:
        for module in ALL_CHECKS:
            print("{:<12} {}".format(module.NAME, module.DESCRIPTION))
        return 0
    configure_logging(args.quiet, args.verbose)
    modules, unknown = select_checks(args.checks, args.skip)
    if unknown:
        sys.stderr.write("unknown check(s): {} (see --list-checks)\n".format(", ".join(unknown)))
        return EXIT_USAGE
    if not os.path.isdir(args.root):
        sys.stderr.write("--root {} is not a directory\n".format(args.root))
        return EXIT_USAGE
    if not args.no_throttle:
        applied = lower_priority()
        LOG.info("running politely: %s (use --no-throttle for full speed)",
                 ", ".join(applied) or "priority unchanged")
    ctx = make_context(
        root=args.root, since=args.since, allow_exec=not args.no_exec,
        max_file_size=max(1, args.max_file_size) * 1024 * 1024, max_files=args.max_files or 10**9,
        extra_webroots=tuple(args.webroot), extra_logs=tuple(args.log),
        extra_session_dirs=tuple(args.session_dir))
    try:
        return execute(ctx, args, modules)
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130
    except Exception:  # never let a crash look like an "exit 1 = suspicious" verdict
        LOG.exception("scan aborted by an internal error")
        return EXIT_INTERNAL


def _markdown_path(args: argparse.Namespace, header: dict) -> Optional[str]:
    if args.no_markdown or args.json == "-":
        return None
    if args.markdown:
        return args.markdown
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return "php2shell-forensics-{}-{}.md".format(safe_filename(header["host"]), stamp)


def execute(ctx: ScanContext, args: argparse.Namespace, modules: Sequence) -> int:
    started = time.time()
    LOG.info("discovering web users, web roots, containers, logs and session directories ...")
    disc = discover(ctx)
    findings, errors = run_checks(ctx, disc, modules, args.max_per_rule)
    verdict = compute_verdict(findings)
    header = {
        "host": host_name(ctx), "root": ctx.fs.root, "mode": "live" if ctx.live else "offline",
        "started": fmt_time(started), "since": fmt_time(ctx.since) if ctx.since else "",
        "checks": [m.NAME for m in modules], "duration_seconds": round(time.time() - started, 1),
    }
    # A failed check can hide evidence: never report "no indicators" in that case.
    exit_code = EXIT_INTERNAL if errors and verdict.code == 0 else verdict.code
    written: List[str] = []
    if args.json:
        payload = to_json(header, disc, findings, verdict, errors)
        if args.json == "-":
            sys.stdout.write(payload + "\n")
            return exit_code
        if not _write(args.json, payload, written):
            return EXIT_INTERNAL
    markdown_path = _markdown_path(args, header)
    if markdown_path and not _write(
            markdown_path, forensics_markdown(header, disc, findings, verdict, errors), written,
            auto_named=not args.markdown):
        return EXIT_INTERNAL
    color = sys.stdout.isatty() and not args.no_color
    report = TextReport(sys.stdout, color, args.min_severity)
    report.header(header, disc)
    report.body(findings)
    report.footer(findings, verdict, errors, time.time() - started)
    for path in written:
        report.note("Report written: {}".format(os.path.abspath(path)))
    return exit_code


def _write(path: str, content: str, written: List[str], auto_named: bool = False) -> bool:
    try:
        if auto_named:
            path = write_new_report(path, content)
        else:
            write_private(path, content)
    except OSError as exc:
        sys.stderr.write("cannot write report {}: {}\n".format(path, exc))
        return False
    written.append(path)
    return True
