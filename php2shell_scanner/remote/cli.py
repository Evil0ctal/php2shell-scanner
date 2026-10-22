"""`php2shell-scanner scan`: non-destructive remote vulnerability check."""

import argparse
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

from php2shell_scanner.checks.common import fmt_time
from php2shell_scanner.cli_common import (DISCLAIMER, EXIT_USAGE, bounded_int,
                                          configure_logging, positive_float, write_new_report,
                                          write_private)
from php2shell_scanner.remote import report
from php2shell_scanner.remote.http import Client
from php2shell_scanner.remote.probes import run_probes
from php2shell_scanner.remote.target import Target, parse_target, read_target_file
from php2shell_scanner.remote.verdict import UNREACHABLE, TargetResult, evaluate

LOG = logging.getLogger("php2shell_scanner")

EPILOG = """\
exit codes: 0 not vulnerable / no PHP, 1 unknown or unreachable,
            2 likely vulnerable, 3 vulnerable, 64 usage error

examples:
  php2shell-scanner.pyz scan example.com
  php2shell-scanner.pyz scan https://shop.example.com:8443/app --path /login.php
  php2shell-scanner.pyz scan -f targets.txt --threads 8 --json scan.json
  php2shell-scanner.pyz scan 203.0.113.10:8080 --passive        # GET/HEAD requests only

Only GET/HEAD requests plus (unless --passive) one control/probe pair of small multipart
POSTs without any session ID are sent. Nothing is exploited and no session is written.

""" + DISCLAIMER


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*", metavar="TARGET",
                        help="URL, domain or IP[:port][/path] (several allowed)")
    parser.add_argument("-f", "--file", metavar="FILE", help="read targets from a file")
    parser.add_argument("--path", action="append", default=[], metavar="PATH",
                        help="extra PHP page to fingerprint, e.g. /login.php (repeatable)")
    parser.add_argument("--passive", action="store_true",
                        help="GET/HEAD only: skip the multipart reachability check")
    parser.add_argument("--rounds", type=bounded_int(1, 10), default=2, metavar="N",
                        help="repeat the fingerprint N times, 1-10 (load balancers; default 2)")
    parser.add_argument("--threads", type=bounded_int(1, 32), default=4, metavar="N",
                        help="targets scanned in parallel, 1-32 (default 4)")
    parser.add_argument("--timeout", type=positive_float, default=10.0, metavar="SEC",
                        help="socket timeout; each request is capped at 3x this (default 10)")
    parser.add_argument("--budget", type=positive_float, default=300.0, metavar="SEC",
                        help="maximum time spent on one target (default 300)")
    parser.add_argument("--delay", type=float, default=0.2, metavar="SEC",
                        help="pause between requests to the same target (default 0.2)")
    parser.add_argument("--strict-tls", action="store_true",
                        help="fail instead of continuing when a TLS certificate is untrusted")
    parser.add_argument("--json", metavar="FILE", help="write a JSON report ('-' = stdout)")
    parser.add_argument("--markdown", metavar="FILE",
                        help="Markdown report path (default: php2shell-scan-<time>.md)")
    parser.add_argument("--no-markdown", action="store_true", help="do not write Markdown")
    parser.add_argument("--yes", action="store_true",
                        help="confirm you are authorised to test the targets (skips prompt)")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")


def _targets(args: argparse.Namespace) -> Tuple[List[List[Target]], List[str]]:
    raw = list(args.targets)
    if args.file:
        raw += read_target_file(args.file)
    parsed, errors = [], []
    for item in raw:
        try:
            parsed.append(parse_target(item))
        except ValueError as exc:
            errors.append(str(exc))
    return parsed, errors


def _consent(args: argparse.Namespace) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty():
        sys.stderr.write("refusing to scan without --yes in non-interactive mode\n")
        return False
    sys.stderr.write(DISCLAIMER + "\n")
    try:
        answer = input("I own these targets or am authorised to test them [y/N]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def _scan_target(target: Target, args: argparse.Namespace) -> Tuple[TargetResult, str]:
    client = Client(target, timeout=args.timeout, delay=max(0.0, args.delay),
                    allow_insecure_fallback=not args.strict_tls,
                    budget=getattr(args, "budget", 300.0))
    LOG.info("scanning %s", target.url)
    data = run_probes(client, args.path, args.rounds, active=not args.passive)
    return evaluate(target.url, data, client.requests), data.redirect_to


def scan_one(candidates: List[Target], args: argparse.Namespace) -> TargetResult:
    """Try https then http (when ambiguous); follow ONE same-host scheme/port redirect."""
    result: Optional[TargetResult] = None
    for target in candidates:
        result, redirect = _scan_target(target, args)
        if redirect:
            moved = parse_target(redirect)[0]
            LOG.info("%s redirects to %s", target.url, moved.url)
            result, _ = _scan_target(moved, args)
        if result.status != UNREACHABLE:
            return result
    return result  # type: ignore[return-value]


def _outputs(args: argparse.Namespace, results: List[TargetResult], header: dict) -> List[str]:
    written = []
    if args.json and args.json != "-":
        write_private(args.json, report.to_json(results, header))
        written.append(args.json)
    if not args.no_markdown and args.json != "-":
        content = report.to_markdown(results, header)
        if args.markdown:
            write_private(args.markdown, content)
            written.append(args.markdown)
        else:
            default = "php2shell-scan-{}.md".format(time.strftime("%Y%m%d-%H%M%S"))
            written.append(write_new_report(default, content))
    return written


def run(args: argparse.Namespace) -> int:
    configure_logging(args.quiet, args.verbose)
    targets, errors = _targets(args)
    for error in errors:
        sys.stderr.write("invalid target: {}\n".format(error))
    if not targets or errors:
        sys.stderr.write("usage: php2shell-scanner scan TARGET [TARGET ...] (see --help)\n")
        return EXIT_USAGE
    if not _consent(args):
        return EXIT_USAGE
    started = time.time()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        results = list(pool.map(lambda t: scan_one(t, args), targets))
    header = {"started": fmt_time(started), "duration_seconds": round(time.time() - started, 1),
              "mode": "passive" if args.passive else "passive + reachability check",
              "targets": [t[0].raw for t in targets]}
    if args.json == "-":
        sys.stdout.write(report.to_json(results, header) + "\n")
        return max(r.code for r in results)
    output = report.TextOutput(sys.stdout, sys.stdout.isatty() and not args.no_color)
    for result in results:
        output.result(result)
    output.summary(results)
    try:
        for path in _outputs(args, results, header):
            output.write(" Report written: " + os.path.abspath(path))
    except OSError as exc:
        sys.stderr.write("cannot write report: {}\n".format(exc))
    return max(r.code for r in results)
