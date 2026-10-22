"""Top-level entry point: sub-command dispatch and the interactive menu."""

import argparse
import os
import sys
from typing import Callable, List, Optional, Sequence

from php2shell_scanner import __version__
from php2shell_scanner.cli_common import DISCLAIMER, EXIT_USAGE, Parser
from php2shell_scanner import forensics_cli
from php2shell_scanner import rules_cli
from php2shell_scanner.remote import cli as remote_cli

# Re-exported for callers/tests that use the historic names.
EXIT_INTERNAL = forensics_cli.EXIT_INTERNAL
COMMANDS = ("forensics", "scan", "rules")
BANNER = """\
php2shell-scanner {version} - CVE-2026-109618 / CVE-2026-109619 (PHP session.upload_progress)
by Evil0ctal - https://github.com/Evil0ctal/php2shell-scanner
"""


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="php2shell-scanner",
        description="Vulnerability detection and intrusion forensics for the PHP "
                    "session.upload_progress RCE (CVE-2026-109618 / CVE-2026-109619).",
        epilog=DISCLAIMER)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="{forensics,scan,rules}")
    forensics = sub.add_parser(
        "forensics", help="read-only compromise assessment of this server (run as root)",
        description="Was this server compromised? Works even after PHP/phpMyAdmin were removed.",
        epilog=forensics_cli.EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    forensics_cli.add_arguments(forensics)
    scan = sub.add_parser(
        "scan", help="non-destructive remote check: is a target vulnerable?",
        description="Checks URLs/hosts for CVE-2026-109618/109619 without exploiting them.",
        epilog=remote_cli.EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    remote_cli.add_arguments(scan)
    rules = sub.add_parser(
        "rules", help="write the bundled IDS/WAF/SIEM detection rules to a directory",
        description="Extract the Suricata/Sigma/ModSecurity/OpenResty rules bundled in the "
                    "build, to deploy on your IDS/WAF/SIEM.",
        epilog=rules_cli.EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    rules_cli.add_arguments(rules)
    return parser


def _ask(prompt: str, reader: Callable[[str], str]) -> str:
    try:
        return reader(prompt).strip()
    except EOFError:
        return ""


def interactive(reader: Callable[[str], str] = input) -> int:
    sys.stdout.write(BANNER.format(version=__version__) + DISCLAIMER + "\n\n")
    sys.stdout.write("  1) Check remote server(s) for the vulnerability (non-destructive)\n"
                     "  2) Forensic scan of THIS server - was it compromised?\n"
                     "  3) Export the IDS/WAF/SIEM detection rules to a directory\n"
                     "  q) Quit\n\n")
    choice = _ask("Select [1/2/3/q]: ", reader).lower()
    if choice == "1":
        targets = _ask("Target URL, domain or IP[:port] (comma-separated): ", reader)
        if not targets:
            sys.stderr.write("no target given\n")
            return EXIT_USAGE
        paths = _ask("Extra paths that start a PHP session, e.g. /login.php (optional): ", reader)
        consent = _ask("I own these targets or am authorised to test them [y/N]: ", reader)
        if consent.lower() not in ("y", "yes"):
            sys.stderr.write("aborted: authorisation not confirmed\n")
            return EXIT_USAGE
        argv = ["scan", "--yes"] + [t.strip() for t in targets.split(",") if t.strip()]
        for path in (p.strip() for p in paths.split(",")):
            if path:
                argv += ["--path", path]
        return main(argv)
    if choice == "2":
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            sys.stdout.write("Warning: not running as root - most evidence will be unreadable.\n")
        return main(["forensics"])
    if choice == "3":
        out = _ask("Directory to write the detection rules into [{}]: ".format(
            rules_cli.DEFAULT_OUTPUT), reader) or rules_cli.DEFAULT_OUTPUT
        return main(["rules", "--output", out])
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args_list: List[str] = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        if sys.stdin.isatty():
            return interactive()
        build_parser().print_help()
        return EXIT_USAGE
    # Backwards compatible: options without a sub-command mean "forensics".
    if args_list[0] not in COMMANDS and args_list[0] not in ("-h", "--help", "--version"):
        args_list.insert(0, "forensics")
    args = build_parser().parse_args(args_list)
    if args.command == "scan":
        return remote_cli.run(args)
    if args.command == "rules":
        return rules_cli.run(args)
    return forensics_cli.run(args)
