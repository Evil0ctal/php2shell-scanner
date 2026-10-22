"""Read-only filesystem access that can be re-rooted onto a mounted disk image.

Every path handled by the checks is a *logical* path as it would appear on the
scanned host ("/var/www/html/x.php"). ``RootFS.real`` maps it to the path on the
machine running the scanner, resolving symlinks inside the root so that an
absolute link in an evidence image never escapes to the analyst's own files.

Files are opened with O_NOATIME (when permitted) so that reading evidence does not
rewrite access times, and only regular files are ever read (no FIFOs/devices).
"""

import bz2
import errno
import fnmatch
import glob
import gzip
import io
import logging
import os
import posixpath
import stat
import zlib
from typing import BinaryIO, Callable, FrozenSet, Iterator, List, Optional, Tuple

try:  # lzma is an optional build component on some minimal Pythons
    import lzma
except ImportError:  # pragma: no cover - depends on interpreter build
    lzma = None  # type: ignore

LOG = logging.getLogger("php2shell_scanner")

PSEUDO_PREFIXES = ("/proc/", "/sys/", "/dev/")
DEV_ALLOWED = ("/dev/shm", "/dev/mqueue")
MAX_LINK_HOPS = 40
ELF_MAGIC = b"\x7fELF"
MAX_LINE = 64 * 1024                       # longer log lines are truncated
MAX_DECOMPRESSED = 4 * 1024 * 1024 * 1024  # per compressed log (gzip-bomb guard)
BLOCKED = "/.php2shell-scanner-blocked/path"  # returned for paths that would escape --root
O_NOATIME = getattr(os, "O_NOATIME", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
DECOMPRESS_ERRORS: tuple = (zlib.error,) + ((lzma.LZMAError,) if lzma is not None else ())
READ_ERRORS: tuple = (OSError, EOFError, ValueError) + DECOMPRESS_ERRORS


class RootFS:
    def __init__(self, root: str = "/") -> None:
        self._root = os.path.abspath(root)
        self._root_real = os.path.realpath(self._root)

    @property
    def root(self) -> str:
        return self._root

    @property
    def is_live(self) -> bool:
        return self._root == "/"

    # ------------------------------------------------------------------ paths
    def _resolve(self, logical: str, hops: int) -> Optional[str]:
        parts = [p for p in posixpath.normpath("/" + logical).split("/") if p]
        current = "/"
        for index, part in enumerate(parts):
            candidate = posixpath.join(current, part)
            candidate_real = os.path.join(self._root, candidate.lstrip("/"))
            if os.path.islink(candidate_real):
                if hops >= MAX_LINK_HOPS:
                    return None
                try:
                    target = os.readlink(candidate_real)
                except OSError:
                    return None
                if not target.startswith("/"):
                    target = posixpath.join(current, target)
                rest = "/".join(parts[index + 1:])
                return self._resolve(posixpath.join(target, rest) if rest else target, hops + 1)
            current = candidate
        return os.path.join(self._root, current.lstrip("/"))

    def _contained(self, real: str) -> bool:
        check = os.path.realpath(real)
        return check == self._root_real or check.startswith(self._root_real.rstrip(os.sep) + os.sep)

    def real(self, logical: str) -> str:
        """Host path for ``logical`` with every symlink resolved inside the root."""
        if self.is_live:
            return logical
        resolved = self._resolve(logical, 0)
        if resolved is None or not self._contained(resolved):
            return BLOCKED
        return resolved

    def real_nofollow(self, logical: str) -> str:
        """Like ``real`` but the final component is not dereferenced (for lstat/readlink)."""
        if self.is_live:
            return logical
        normalized = posixpath.normpath("/" + logical)
        if normalized == "/":
            return self._root
        parent = self.real(posixpath.dirname(normalized))
        if parent == BLOCKED:
            return BLOCKED
        return os.path.join(parent, posixpath.basename(normalized))

    def logical(self, real: str) -> str:
        if self.is_live:
            return real
        rel = os.path.relpath(real, self._root)
        return "/" if rel == "." else "/" + rel.replace(os.sep, "/")

    # ------------------------------------------------------------- metadata
    def lstat(self, logical: str) -> Optional[os.stat_result]:
        try:
            return os.lstat(self.real_nofollow(logical))
        except (OSError, ValueError):
            return None

    def stat(self, logical: str) -> Optional[os.stat_result]:
        try:
            return os.stat(self.real(logical))
        except (OSError, ValueError):
            return None

    def isdir(self, logical: str) -> bool:
        st = self.stat(logical)
        return st is not None and stat.S_ISDIR(st.st_mode)

    def isfile(self, logical: str) -> bool:
        st = self.stat(logical)
        return st is not None and stat.S_ISREG(st.st_mode)

    def exists(self, logical: str) -> bool:
        return self.lstat(logical) is not None

    def readlink(self, logical: str) -> Optional[str]:
        try:
            return os.readlink(self.real_nofollow(logical))
        except (OSError, ValueError):
            return None

    def listdir(self, logical: str) -> List[str]:
        try:
            return sorted(os.listdir(self.real(logical)))
        except (OSError, ValueError):
            return []

    def glob(self, pattern: str) -> List[str]:
        if self.is_live:
            return sorted(glob.glob(pattern))
        # Component-wise so that every step goes through real() and stays inside the root.
        paths = ["/"]
        for part in [p for p in pattern.split("/") if p]:
            matched = []
            for base in paths:
                if any(ch in part for ch in "*?["):
                    for name in self.listdir(base):
                        if name.startswith(".") and not part.startswith("."):
                            continue
                        if fnmatch.fnmatchcase(name, part):
                            matched.append(posixpath.join(base, name))
                else:
                    candidate = posixpath.join(base, part)
                    if self.exists(candidate):
                        matched.append(candidate)
            paths = matched
        return sorted(p for p in paths if p != "/")

    # ---------------------------------------------------------------- reads
    def open_binary(self, logical: str) -> BinaryIO:
        """Open a regular file read-only without updating atime or blocking on FIFOs."""
        flags = os.O_RDONLY | O_NONBLOCK | O_NOATIME
        if not self.is_live:
            flags |= O_NOFOLLOW  # real() resolved every link; a link here is unexpected
        path = self.real(logical)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if not (exc.errno == errno.EPERM and O_NOATIME):
                raise
            fd = os.open(path, flags & ~O_NOATIME)  # O_NOATIME needs ownership/CAP_FOWNER
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "not a regular file", logical)
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def read_bytes(self, logical: str, limit: int) -> Optional[bytes]:
        try:
            with self.open_binary(logical) as handle:
                return handle.read(limit)
        except (OSError, ValueError):
            return None

    def read_head_tail(self, logical: str, size: int, chunk: int) -> Optional[bytes]:
        """Whole file when small, otherwise the first and last ``chunk`` bytes."""
        try:
            with self.open_binary(logical) as handle:
                if size <= chunk * 2:
                    return handle.read(chunk * 2)
                head = handle.read(chunk)
                handle.seek(max(size - chunk, chunk))
                return head + b"\n" + handle.read(chunk)
        except (OSError, ValueError):
            return None

    def read_text(self, logical: str, limit: int = 4 * 1024 * 1024) -> Optional[str]:
        data = self.read_bytes(logical, limit)
        return None if data is None else data.decode("utf-8", errors="replace")

    def _decompressor(self, logical: str, raw: BinaryIO) -> Tuple[BinaryIO, bool]:
        lower = logical.lower()
        if lower.endswith(".gz"):
            return gzip.GzipFile(fileobj=raw), True  # type: ignore[return-value]
        if lower.endswith(".bz2"):
            return bz2.BZ2File(raw), True  # type: ignore[return-value]
        if lower.endswith((".xz", ".lzma")) and lzma is not None:
            return lzma.LZMAFile(raw), True  # type: ignore[return-value]
        return raw, False

    def iter_lines(self, logical: str) -> Iterator[str]:
        """Stream a (possibly compressed) text file as latin-1 lines, bounded in size."""
        try:
            raw = self.open_binary(logical)
        except (OSError, ValueError) as exc:
            LOG.debug("cannot open %s: %s", logical, exc)
            return
        stream, compressed = self._decompressor(logical, raw)
        budget = MAX_DECOMPRESSED if compressed else None
        try:
            with io.TextIOWrapper(stream, encoding="latin-1") as text:  # type: ignore[arg-type]
                for line in _bounded_lines(text, budget):
                    yield line
        except READ_ERRORS as exc:
            LOG.warning("stopped reading %s early: %s", logical, exc)
        finally:
            raw.close()

    # ---------------------------------------------------------------- walk
    def walk(
        self,
        base: str,
        max_depth: int = 16,
        max_entries: int = 300000,
        skip_dir_names: FrozenSet[str] = frozenset(),
        include_dirs: bool = False,
        skip_dir: Optional[Callable[[str], bool]] = None,
    ) -> Iterator[Tuple[str, os.stat_result]]:
        """Yield (logical_path, lstat) for regular files (and dirs if asked).

        Symlinks are never followed and pseudo filesystems are never entered.
        """
        real_base = self.real(base)
        if not os.path.isdir(real_base):
            return
        stack = [(real_base, 0)]
        seen = 0
        while stack:
            current, depth = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = list(iterator)
            except OSError as exc:
                LOG.debug("cannot list %s: %s", self.logical(current), exc)
                continue
            for entry in entries:
                seen += 1
                if seen > max_entries:
                    LOG.warning(
                        "entry limit (%d) reached under %s; remaining files not scanned "
                        "(raise --max-files to scan everything)", max_entries, base)
                    return
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                logical = self.logical(entry.path)
                if stat.S_ISDIR(st.st_mode):
                    if include_dirs:
                        yield logical, st
                    if (depth < max_depth and entry.name not in skip_dir_names
                            and not is_pseudo_path(logical)
                            and not (skip_dir is not None and skip_dir(logical))):
                        stack.append((entry.path, depth + 1))
                elif stat.S_ISREG(st.st_mode):
                    yield logical, st


def _bounded_lines(text: io.TextIOWrapper, budget: Optional[int]) -> Iterator[str]:
    """Lines truncated to MAX_LINE; stops after ``budget`` characters if given."""
    consumed = 0
    while True:
        line = text.readline(MAX_LINE)
        if not line:
            return
        consumed += len(line)
        tail = line
        while not tail.endswith("\n"):  # over-long line: discard the remainder
            tail = text.readline(MAX_LINE)
            if not tail:
                break
            consumed += len(tail)
            if budget is not None and consumed > budget:
                break
        if budget is not None and consumed > budget:
            LOG.warning("decompressed size limit reached; rest of the log skipped")
            return
        yield line.rstrip("\r\n")


def is_pseudo_path(logical: str) -> bool:
    if logical.startswith(DEV_ALLOWED):
        return False
    return logical.startswith(PSEUDO_PREFIXES) or logical in ("/proc", "/sys", "/dev")


def path_under(path: str, parents: Tuple[str, ...]) -> bool:
    for parent in parents:
        parent = parent.rstrip("/") or "/"
        if path == parent or path.startswith(parent + "/") or parent == "/":
            return True
    return False


def dedupe_nested(paths: List[str]) -> Tuple[str, ...]:
    """Drop paths that are inside another path of the list."""
    result: List[str] = []
    for path in sorted({posixpath.normpath(p) for p in paths}, key=len):
        if not path_under(path, tuple(result)):
            result.append(path)
    return tuple(sorted(result))
