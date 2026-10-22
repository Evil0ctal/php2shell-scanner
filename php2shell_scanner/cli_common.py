"""Helpers shared by the sub-commands (argument types, exit codes, safe file output)."""

import argparse
import errno
import logging
import math
import os
import re
import stat
import sys
import time
from datetime import datetime
from typing import Callable

from php2shell_scanner.models import Severity

EXIT_USAGE = 64
EXIT_INTERNAL = 70
DISCLAIMER = (
    "php2shell-scanner is for vulnerability detection and intrusion forensics on systems you "
    "own or are explicitly authorised to test. Do not use it for any illegal purpose."
)


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        sys.stderr.write("{}: error: {}\n".format(self.prog, message))
        sys.exit(EXIT_USAGE)


def parse_since(value: str) -> float:
    relative = re.match(r"^(\d+)d$", value.strip())
    if relative:
        return time.time() - int(relative.group(1)) * 86400
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").timestamp()
    except ValueError:
        raise argparse.ArgumentTypeError("use YYYY-MM-DD or <N>d, e.g. 2026-10-01 or 30d")


def parse_severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: {}".format(value))
    if number < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return number


def bounded_int(low: int, high: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        number = positive_int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("must be between {} and {}".format(low, high))
        return number
    return parse


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: {}".format(value))
    if not (number > 0 and math.isfinite(number)):
        raise argparse.ArgumentTypeError("must be a positive number")
    return number


def configure_logging(quiet: bool, verbose: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(level=level, format="[*] %(message)s", stream=sys.stderr)


def write_private(path: str, content: str, exclusive: bool = False) -> None:
    """Write a report readable only by its owner (reports quote sensitive evidence).

    Never follows a symlink planted at the report path (we may run as root in a directory
    others can write) and forces mode 0600 even on a pre-existing file.
    """
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8", errors="backslashreplace")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        handle.write(content)


def write_new_report(path: str, content: str) -> str:
    """Create an auto-named report without ever overwriting: report.md, report-1.md, ..."""
    stem, ext = os.path.splitext(path)
    for attempt in range(100):
        candidate = path if attempt == 0 else "{}-{}{}".format(stem, attempt, ext)
        try:
            write_private(candidate, content, exclusive=True)
            return candidate
        except FileExistsError:
            continue
    raise OSError(errno.EEXIST, "could not find a free report name", path)


def safe_filename(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_") or "host"
