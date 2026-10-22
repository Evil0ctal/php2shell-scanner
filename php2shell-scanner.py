#!/usr/bin/env python3
"""Convenience launcher: `sudo python3 php2shell-scanner.py [options]`."""

import os
import sys

if sys.version_info < (3, 6, 1):  # typing.NamedTuple methods need 3.6.1
    sys.stderr.write("php2shell-scanner needs Python 3.6.1 or newer\n")
    sys.exit(64)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from php2shell_scanner.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
