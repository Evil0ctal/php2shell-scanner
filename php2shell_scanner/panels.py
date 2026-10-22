"""Panel/application-specific locations that must be derived from the host itself."""

import re
from typing import Iterable, List, Tuple

from php2shell_scanner.fs import RootFS
from php2shell_scanner.paths import (APP_SESSION_DIRS, ONEPANEL_APP_WEBROOTS, ONEPANEL_CTL,
                                     ONEPANEL_FPM, ONEPANEL_INI, ONEPANEL_LOGS, ONEPANEL_NGINX,
                                     ONEPANEL_WEBROOTS)

BASE_DIR_RE = re.compile(r"^\s*BASE_DIR=['\"]?(/[^'\"\s]*)", re.M)


def onepanel_roots(fs: RootFS) -> List[str]:
    """<BASE_DIR>/1panel for each install; BASE_DIR is recorded in 1pctl (default /opt)."""
    bases = []
    for ctl in ONEPANEL_CTL:
        found = BASE_DIR_RE.search(fs.read_text(ctl, 65536) or "")
        if found:
            bases.append(found.group(1).rstrip("/") or "/")
    bases.append("/opt")
    roots = []
    for base in bases:
        root = "{}/1panel".format(base if base != "/" else "")
        if root not in roots and fs.isdir(root):
            roots.append(root)
    return roots


def expand(fs: RootFS, roots: Iterable[str], patterns: Iterable[str]) -> List[str]:
    found: List[str] = []
    for root in roots:
        for pattern in patterns:
            found.extend(fs.glob("{}/{}".format(root, pattern)))
    return found


def onepanel_locations(fs: RootFS) -> Tuple[List[str], List[str], List[str], List[str], List[str]]:
    """(webroots, log dirs, php.ini files, nginx confs, fpm confs) of every 1Panel install."""
    roots = onepanel_roots(fs)
    app_roots = ["apps/{}/*/data".format(app) for app in ONEPANEL_APP_WEBROOTS]
    return (expand(fs, roots, ONEPANEL_WEBROOTS + tuple(app_roots)),
            expand(fs, roots, ONEPANEL_LOGS), expand(fs, roots, ONEPANEL_INI),
            expand(fs, roots, ONEPANEL_NGINX), expand(fs, roots, ONEPANEL_FPM))


def cpanel_docroots(fs: RootFS) -> List[str]:
    """/etc/userdatadomains: 'domain: user==owner==type==main==docroot==ip:port==...'."""
    roots = []
    for line in (fs.read_text("/etc/userdatadomains", 16 * 1024 * 1024) or "").splitlines():
        fields = line.split(": ", 1)[-1].split("==")
        if len(fields) > 4 and fields[4].startswith("/") and fields[4] not in roots:
            roots.append(fields[4])
    return roots


def app_session_dirs(fs: RootFS, webroots: Iterable[str]) -> List[str]:
    found: List[str] = []
    for root in webroots:
        for depth in ("", "*/", "*/*/"):
            for rel in APP_SESSION_DIRS:
                found.extend(p for p in fs.glob("{}/{}{}".format(root.rstrip("/"), depth, rel))
                             if fs.isdir(p))
    return found
