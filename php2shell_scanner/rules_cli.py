"""`php2shell-scanner rules`: write the bundled detection rules to disk.

The Suricata / Sigma / ModSecurity / OpenResty rules under
``php2shell_scanner/detection`` are packaged into the single-file ``.pyz``, so an
operator can extract them on a server that only has the ``.pyz`` and no source
tree::

    python3 php2shell-scanner.pyz rules -o /etc/detection

``pkgutil.get_data`` reads the files whether we run from a source checkout (real
directory) or from inside the zipapp, so this stays zero-dependency.
"""

import argparse
import os
import pkgutil
import sys

from php2shell_scanner.cli_common import DISCLAIMER, EXIT_INTERNAL, EXIT_USAGE

PACKAGE = "php2shell_scanner"
RESOURCE_DIR = "detection"
# Kept in sync with php2shell_scanner/detection/ (tests/test_core_and_cli.py asserts it).
DETECTION_FILES = (
    "README.md",
    "php2shell.rules",
    "php2shell.yaml",
    "modsecurity.conf",
    "php2shell.lua",
)
DEFAULT_OUTPUT = "php2shell-detection"

EPILOG = """\
Writes the bundled IDS/WAF/SIEM detection rules (Suricata, Sigma, ModSecurity,
OpenResty) for CVE-2026-109618 / CVE-2026-109619 to a directory, so you can
deploy them straight from the single-file build without the source tree.

examples:
  php2shell-scanner.pyz rules                       # -> ./php2shell-detection/
  php2shell-scanner.pyz rules -o /etc/suricata/php2shell
  php2shell-scanner.pyz rules --list
  php2shell-scanner.pyz rules --stdout php2shell.rules > php2shell.rules

See the extracted README.md for deployment instructions.

""" + DISCLAIMER


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", metavar="DIR", default=DEFAULT_OUTPUT,
                        help="directory to write the rules into (default: ./" + DEFAULT_OUTPUT + ")")
    parser.add_argument("--list", action="store_true", dest="list_only",
                        help="list the bundled rule files and exit")
    parser.add_argument("--stdout", metavar="NAME",
                        help="print one rule file to stdout instead of writing files")


def _load(name: str) -> bytes:
    data = pkgutil.get_data(PACKAGE, RESOURCE_DIR + "/" + name)
    if data is None:
        raise FileNotFoundError("bundled rule not found: " + name)
    return data


def run(args: argparse.Namespace) -> int:
    if args.list_only:
        for name in DETECTION_FILES:
            sys.stdout.write(name + "\n")
        return 0
    if args.stdout:
        if args.stdout not in DETECTION_FILES:
            sys.stderr.write("unknown rule file: {} (see --list)\n".format(args.stdout))
            return EXIT_USAGE
        try:
            sys.stdout.write(_load(args.stdout).decode("utf-8"))
        except OSError as exc:
            sys.stderr.write("could not read bundled rule {}: {}\n".format(args.stdout, exc))
            return EXIT_INTERNAL
        return 0
    try:
        os.makedirs(args.output, exist_ok=True)
        for name in DETECTION_FILES:
            with open(os.path.join(args.output, name), "wb") as handle:
                handle.write(_load(name))
    except OSError as exc:
        sys.stderr.write("could not write rules to {}: {}\n".format(args.output, exc))
        return EXIT_INTERNAL
    sys.stdout.write("Wrote {} detection rule file(s) to {}\n".format(
        len(DETECTION_FILES), os.path.abspath(args.output)))
    sys.stdout.write("Deploy them per {}/README.md\n".format(args.output))
    return 0
