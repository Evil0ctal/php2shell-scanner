import gzip
import os
import sys
from typing import Optional

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell_scanner.context import make_context  # noqa: E402
from php2shell_scanner.discovery import discover  # noqa: E402

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:106:110:MySQL Server,,,:/nonexistent:/bin/false
alice:x:1000:1000:Alice:/home/alice:/bin/bash
"""
GROUP = """root:x:0:
sudo:x:27:alice
www-data:x:33:
"""


class Tree:
    """Builds a fake host filesystem under a temporary root."""

    def __init__(self, root: str) -> None:
        self.root = root

    def path(self, logical: str) -> str:
        return os.path.join(self.root, logical.lstrip("/"))

    def write(self, logical: str, content, mode: Optional[int] = None,
              mtime: Optional[float] = None, gz: bool = False) -> str:
        real = self.path(logical)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        data = content.encode("latin-1") if isinstance(content, str) else content
        if gz:
            with gzip.open(real, "wb") as handle:
                handle.write(data)
        else:
            with open(real, "wb") as handle:
                handle.write(data)
        if mode is not None:
            os.chmod(real, mode)
        if mtime is not None:
            os.utime(real, (mtime, mtime))
        return real

    def mkdir(self, logical: str) -> str:
        real = self.path(logical)
        os.makedirs(real, exist_ok=True)
        return real

    def symlink(self, target: str, logical: str) -> None:
        real = self.path(logical)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        os.symlink(target, real)

    def base_system(self) -> "Tree":
        self.write("/etc/passwd", PASSWD)
        self.write("/etc/group", GROUP)
        self.mkdir("/var/www/html")
        self.mkdir("/tmp")
        return self


@pytest.fixture(autouse=True)
def _no_renice(monkeypatch):
    """forensics lowers its own priority; never renice the pytest process itself."""
    monkeypatch.setattr("php2shell_scanner.forensics_cli.lower_priority", lambda: [])


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    """Reports default to the current directory: keep them out of the repository."""
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)


@pytest.fixture
def tree(tmp_path) -> Tree:
    return Tree(str(tmp_path / "root")).base_system()


@pytest.fixture
def scan_env(tree):
    """Returns a function building (ctx, disc) for the current tree."""

    def build(**kwargs):
        ctx = make_context(root=tree.root, allow_exec=False, **kwargs)
        return ctx, discover(ctx)

    return build


def rules(findings) -> set:
    return {f.rule for f in findings}
