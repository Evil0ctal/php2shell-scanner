"""Scan options and the guarded helper used to run trusted system tools."""

import logging
import os
import stat
import subprocess
import time
from typing import List, NamedTuple, Optional, Tuple

from php2shell_scanner.fs import RootFS

LOG = logging.getLogger("php2shell_scanner")

# System directories first: a root-run scanner must not pick up /usr/local/bin/dpkg.
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin"
DEFAULT_TIMEOUT = 60


class ScanContext(NamedTuple):
    fs: RootFS
    since: Optional[float]
    allow_exec: bool
    max_file_size: int
    max_files: int
    extra_webroots: Tuple[str, ...]
    extra_logs: Tuple[str, ...]
    extra_session_dirs: Tuple[str, ...]
    now: float

    @property
    def live(self) -> bool:
        """Live checks (/proc, running tools) only make sense on the host itself."""
        return self.fs.is_live and os.path.isdir("/proc/self")

    def recent(self, mtime: float) -> bool:
        return self.since is not None and mtime >= self.since


def make_context(
    root: str = "/",
    since: Optional[float] = None,
    allow_exec: bool = True,
    max_file_size: int = 5 * 1024 * 1024,
    max_files: int = 300000,
    extra_webroots: Tuple[str, ...] = (),
    extra_logs: Tuple[str, ...] = (),
    extra_session_dirs: Tuple[str, ...] = (),
) -> ScanContext:
    return ScanContext(
        fs=RootFS(root),
        since=since,
        allow_exec=allow_exec,
        max_file_size=max_file_size,
        max_files=max_files,
        extra_webroots=tuple(extra_webroots),
        extra_logs=tuple(extra_logs),
        extra_session_dirs=tuple(extra_session_dirs),
        now=time.time(),
    )


def trusted_binary(path: str) -> bool:
    """Root-owned and not writable by group/other (so nobody else could have replaced it)."""
    try:
        st = os.stat(path)
    except (OSError, ValueError):
        return False
    return (stat.S_ISREG(st.st_mode) and st.st_uid == 0
            and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and os.access(path, os.X_OK))


def find_tool(name: str) -> Optional[str]:
    for directory in SAFE_PATH.split(":"):
        candidate = os.path.join(directory, name)
        if trusted_binary(candidate):
            return candidate
    return None


def run_tool(ctx: ScanContext, argv: List[str], timeout: int = DEFAULT_TIMEOUT
             ) -> Optional[Tuple[int, str]]:
    """Run a trusted tool with a minimal environment; None if not allowed/failed.

    argv[0] may be a bare tool name (looked up only in SAFE_PATH) or an absolute
    path that the caller has already vetted.
    """
    if not (ctx.allow_exec and ctx.live):
        return None
    program = argv[0] if os.path.isabs(argv[0]) else find_tool(argv[0])
    if program is None:
        return None
    env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
    try:
        proc = subprocess.run(
            [program] + list(argv[1:]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        LOG.warning("could not run %s: %s", program, exc)
        return None
    return proc.returncode, proc.stdout.decode("utf-8", errors="replace")
