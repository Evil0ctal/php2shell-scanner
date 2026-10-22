"""Run politely on production hosts: lowest CPU priority and lowest best-effort IO priority.

Both are best effort and never fatal. The IO priority is set with the ioprio_set
syscall directly (no external program), so it also works with --no-exec. It only has an
effect with IO schedulers that honour priorities (BFQ/CFQ); with mq-deadline/none the
page-cache hints in fs.py are what keeps the scan from disturbing other services.
"""

import ctypes
import ctypes.util
import logging
import os
import platform
from typing import List, Optional

LOG = logging.getLogger("php2shell_scanner")

IOPRIO_WHO_PROCESS = 1
IOPRIO_CLASS_BE = 2            # best-effort class, level 7 = lowest; never starves the scan
IOPRIO_CLASS_SHIFT = 13
LOWEST_BE_LEVEL = 7
IOPRIO_SET = {"x86_64": 251, "amd64": 251, "i386": 289, "i686": 289, "aarch64": 30,
              "arm64": 30, "armv7l": 314, "ppc64le": 273, "ppc64": 273, "s390x": 282,
              "riscv64": 30, "loongarch64": 30}


def _set_io_priority() -> Optional[str]:
    number = IOPRIO_SET.get(platform.machine().lower())
    if number is None or not platform.system() == "Linux":
        return None
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        value = (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | LOWEST_BE_LEVEL
        if libc.syscall(number, IOPRIO_WHO_PROCESS, 0, value) != 0:
            return None
    except (OSError, AttributeError, TypeError):
        return None
    return "best-effort IO priority 7"


def lower_priority() -> List[str]:
    """Drop to nice 19 and the lowest IO priority; returns what was applied."""
    applied = []
    try:
        current = os.nice(0)
        if current < 19:
            os.nice(19 - current)
        applied.append("CPU nice 19")
    except (OSError, AttributeError):
        LOG.debug("could not lower CPU priority")
    io = _set_io_priority()
    if io:
        applied.append(io)
    return applied
