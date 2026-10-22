"""Affected / fixed PHP versions for CVE-2026-109618 / CVE-2026-109619."""

import re
from typing import Optional, Tuple

FIXED_IN = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
FIRST_AFFECTED = (5, 4, 0)       # session.upload_progress appeared in PHP 5.4.0
SUPPORTED_BRANCHES = tuple(sorted(FIXED_IN))
FIXED_TEXT = "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"


def version_tuple(version: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:3])


def version_vulnerable(version: str) -> Optional[bool]:
    """True/False for a full x.y.z version, None if it cannot be decided."""
    parts = version_tuple(version)
    if len(parts) < 3:
        return None
    if parts < FIRST_AFFECTED:
        return False
    fixed = FIXED_IN.get(parts[:2])
    if fixed is not None:
        return parts < fixed
    return parts[:2] < (8, 2)    # EOL branches never got a fix; newer branches ship fixed


def branch_vulnerable(version: str) -> Optional[bool]:
    """For a branch-only version ('7.4', '8.2'): True when every release is affected."""
    parts = version_tuple(version)
    if len(parts) < 2:
        return None
    if parts[:2] < (5, 4):
        return False
    if parts[:2] < (8, 2):
        return True
    return None if parts[:2] in FIXED_IN else False
