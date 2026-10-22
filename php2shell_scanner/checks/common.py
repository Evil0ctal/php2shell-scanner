"""Helpers shared by check modules."""

import os
import stat
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, Severity

TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run/shm")


def fmt_time(epoch: Optional[float]) -> str:
    if epoch is None:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    except (OverflowError, OSError, ValueError):  # e.g. a planted mtime of 2**62
        return str(epoch)


def file_meta(ctx: ScanContext, disc: Discovery, st: Optional[os.stat_result],
              **extra: Any) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    if st is not None:
        meta.update({
            "size": st.st_size,
            "owner": disc.owner_name(st.st_uid),
            "mode": stat.filemode(st.st_mode),
            "mtime": fmt_time(st.st_mtime),
            "ctime": fmt_time(st.st_ctime),
        })
        if ctx.recent(max(st.st_mtime, st.st_ctime)):
            meta["recent"] = True
    meta.update({k: v for k, v in extra.items() if v not in (None, "", [], ())})
    return meta


def cap_per_rule(findings: List[Finding], limit: int) -> List[Finding]:
    """Keep the ``limit`` most severe findings per rule and summarise the rest."""
    if limit <= 0:
        return list(findings)
    groups: "OrderedDict[str, List[Finding]]" = OrderedDict()
    for finding in findings:
        groups.setdefault(finding.rule, []).append(finding)
    result: List[Finding] = []
    for rule, items in groups.items():
        ordered = sorted(items, key=lambda f: -int(f.severity))
        result.extend(ordered[:limit])
        hidden = ordered[limit:]
        if hidden:
            top = hidden[0]
            result.append(Finding(
                check=top.check, rule=rule, severity=top.severity, kind=top.kind,
                title="{} more '{}' finding(s) not shown".format(len(hidden), top.title),
                detail="Use --json for the complete list, or --max-per-rule 0.",
                meta={"hidden_paths": [f.path for f in hidden[:200]], "count": len(hidden)},
            ))
    return result


def info(check: str, rule: str, title: str, **meta: Any) -> Finding:
    return Finding(check, rule, Severity.INFO, Kind.INFO, title, meta=meta or None)


def basename_ext(path: str) -> str:
    return os.path.splitext(path)[1].lower()


def in_tmp(path: str) -> bool:
    return any(path == d or path.startswith(d + "/") for d in TMP_DIRS)
