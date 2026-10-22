"""Registry of checks, in execution order (cheap, high-signal checks first)."""

from types import ModuleType
from typing import Tuple

from php2shell_scanner.checks import (accounts, apps, auth_logs, baseline, database, integrity, logs,
                                     network, persistence, php_remnants, processes, sessions,
                                     tmp_artifacts, webroot)

ALL_CHECKS: Tuple[ModuleType, ...] = (
    php_remnants,
    sessions,
    processes,
    network,
    persistence,
    accounts,
    auth_logs,
    tmp_artifacts,
    database,
    webroot,
    apps,
    logs,
    integrity,
    baseline,
)


def by_name() -> dict:
    return {module.NAME: module for module in ALL_CHECKS}
