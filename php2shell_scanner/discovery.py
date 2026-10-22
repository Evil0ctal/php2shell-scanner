"""Builds the host inventory every check relies on.

Works from *leftover* configuration as well, so a host where PHP/phpMyAdmin were
uninstalled still yields their old web roots, log files and session paths.
"""

import errno
import os
import re
from typing import Dict, FrozenSet, Iterable, List, Set, Tuple

from php2shell_scanner import containers as ctr
from php2shell_scanner import panels
from php2shell_scanner.context import ScanContext
from php2shell_scanner.fs import RootFS, dedupe_nested
from php2shell_scanner.models import ContainerInfo, Discovery, ProcInfo, UserInfo
from php2shell_scanner.paths import (APACHE_CONF_GLOBS, CONTAINER_WEB_UIDS, FPM_CONF_GLOBS,
                                     LOG_DIRS, LOG_GLOBS, MYSQL_USER_NAMES, NGINX_CONF_GLOBS,
                                     PHP_INI_GLOBS, SESSION_DIR_CANDIDATES, SESSION_DIR_GLOBS,
                                     WEB_USER_NAMES, WEBROOT_CANDIDATES, WEBROOT_GLOBS)

SKIP_LOG_NAMES = re.compile(r"^(?:wtmp|btmp|lastlog|faillog|utmp)(?:[.\-].*)?$|\.(?:journal|pid|sock|lock)$")

RE_NGINX_ROOT = re.compile(r"^\s*(?:root|alias)\s+['\"]?([^;'\"\s]+)", re.M)
RE_NGINX_LOG = re.compile(r"^\s*(?:access_log|error_log)\s+['\"]?([^;'\"\s]+)", re.M)
RE_NGINX_USER = re.compile(r"^\s*user\s+([\w.\-]+)", re.M)
RE_APACHE_ROOT = re.compile(r"^\s*(?:DocumentRoot|Alias\s+\S+)\s+\"?([^\"\s]+)", re.M | re.I)
RE_APACHE_LOG = re.compile(r"^\s*(?:CustomLog|ErrorLog|TransferLog)\s+\"?([^\"\s|]+)", re.M | re.I)
RE_APACHE_USER = re.compile(r"^\s*User\s+([\w.\-]+)|APACHE_RUN_USER=([\w.\-]+)", re.M)
RE_FPM_USER = re.compile(r"^\s*user\s*=\s*([\w.\-]+)", re.M)
RE_FPM_LOG = re.compile(r"^\s*(?:error_log|slowlog|access\.log)\s*=\s*(\S+)", re.M)
RE_INI_SAVE_PATH = re.compile(
    r"^\s*(?:php_(?:admin_)?value\[)?session\.save_path\]?\s*=\s*"
    r"(?:\"([^\"\n]*)\"|'([^'\n]*)'|([^\s;\n]+))", re.M)
RE_INI_ERROR_LOG = re.compile(r"^\s*(?:php_(?:admin_)?value\[)?error_log\]?\s*=\s*\"?([^\"\n;]+)", re.M)


def read_configs(fs: RootFS, patterns: Iterable[str]) -> List[Tuple[str, str]]:
    result = []
    for pattern in patterns:
        for path in fs.glob(pattern):
            if fs.isfile(path):
                text = fs.read_text(path, 2 * 1024 * 1024)
                if text is not None:
                    result.append((path, text))
    return result


def parse_passwd(fs: RootFS) -> Tuple[UserInfo, ...]:
    users = []
    for line in (fs.read_text("/etc/passwd") or "").splitlines():
        parts = line.split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        try:
            users.append(UserInfo(parts[0], int(parts[2]), int(parts[3]), parts[5], parts[6]))
        except ValueError:
            continue
    return tuple(users)


def parse_groups(fs: RootFS) -> Dict[str, Tuple[str, ...]]:
    groups = {}
    for line in (fs.read_text("/etc/group") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            groups[parts[0]] = tuple(m for m in parts[3].split(",") if m)
    return groups


def _clean_path(raw: str) -> str:
    """Strip config variables: '/www/wwwroot/$host' -> '/www/wwwroot'."""
    path = raw.strip().strip("'\"")
    path = path.replace("${APACHE_LOG_DIR}", "/var/log/apache2")
    if "$" in path:
        path = path.split("$", 1)[0]
    if not path.startswith("/"):
        return ""
    return os.path.normpath(path)


def _matches(regex: "re.Pattern", texts: List[Tuple[str, str]]) -> List[str]:
    values = []
    for _, text in texts:
        for found in regex.finditer(text):
            value = next((g for g in found.groups() if g), "")
            if value:
                values.append(value)
    return values


def find_web_users(fs: RootFS, users: Tuple[UserInfo, ...], nginx: list, apache: list,
                   fpm: list) -> Tuple[str, ...]:
    names = {u.name for u in users}
    configured = set(_matches(RE_NGINX_USER, nginx) + _matches(RE_APACHE_USER, apache)
                     + _matches(RE_FPM_USER, fpm))
    candidates = (set(WEB_USER_NAMES) | configured) - {"root", "${APACHE_RUN_USER}"}
    return tuple(sorted(n for n in candidates if n in names))


def web_uids(users: Tuple[UserInfo, ...], web_users: Tuple[str, ...],
             containers: Tuple[ContainerInfo, ...]) -> FrozenSet[int]:
    """Host web users, plus the container web uids when PHP runs in containers.

    A container uid is only added if no unrelated host account owns it.
    """
    uids = {u.uid for u in users if u.name in web_users}
    if any(c.web for c in containers):
        owners = {u.uid: u.name for u in users}
        uids.update(uid for uid in CONTAINER_WEB_UIDS
                    if uid not in owners or owners[uid] in web_users)
    return frozenset(uids)


def find_webroots(ctx: ScanContext, nginx: list, apache: list,
                  containers: Tuple[ContainerInfo, ...] = (),
                  extra: Tuple[str, ...] = ()) -> Tuple[str, ...]:
    fs = ctx.fs
    paths: List[str] = list(WEBROOT_CANDIDATES) + list(extra)
    for container in containers:
        if container.web:
            paths.extend(ctr.web_dirs(container))
    for pattern in WEBROOT_GLOBS:
        paths.extend(fs.glob(pattern))
    for raw in _matches(RE_NGINX_ROOT, nginx) + _matches(RE_APACHE_ROOT, apache):
        cleaned = _clean_path(raw)
        if cleaned and cleaned not in ("/", "/usr", "/etc", "/home", "/var", "/opt"):
            paths.append(cleaned)
    paths.extend(ctx.extra_webroots)
    return dedupe_nested([p for p in paths if fs.isdir(p)])


def _looks_like_log(fs: RootFS, path: str) -> bool:
    name = os.path.basename(path)
    if SKIP_LOG_NAMES.search(name):
        return False
    if name.endswith((".gz", ".bz2", ".xz")):
        return True
    head = fs.read_bytes(path, 512)
    return bool(head) and b"\x00" not in head


def find_log_files(ctx: ScanContext, nginx: list, apache: list, fpm: list, ini: list,
                   containers: Tuple[ContainerInfo, ...] = (),
                   extra_dirs: Tuple[str, ...] = ()) -> Tuple[str, ...]:
    fs = ctx.fs
    files: Set[str] = set()
    dirs: List[str] = list(LOG_DIRS) + list(extra_dirs)
    for container in containers:
        if container.web:
            files.update(container.log_files)
            dirs.extend(ctr.log_dirs(container))
    configured: List[str] = []
    for pattern in LOG_GLOBS:
        for match in fs.glob(pattern):
            (dirs if fs.isdir(match) else configured).append(match)
    for raw in (_matches(RE_NGINX_LOG, nginx) + _matches(RE_APACHE_LOG, apache)
                + _matches(RE_FPM_LOG, fpm) + _matches(RE_INI_ERROR_LOG, ini)):
        cleaned = _clean_path(raw)
        if cleaned and not cleaned.startswith("/dev/"):
            configured.append(cleaned)
    for item in list(ctx.extra_logs):
        (dirs if fs.isdir(item) else configured).append(item)
    for path in configured:
        files.update(p for p in fs.glob(path + "*") if fs.isfile(p))
    for directory in dirs:
        for path, st in fs.walk(directory, max_depth=3, max_entries=20000):
            if st.st_size > 0:
                files.add(path)
    return tuple(sorted(p for p in files if _looks_like_log(fs, p)))


def find_session_dirs(ctx: ScanContext, fpm: list, ini: list,
                      containers: Tuple[ContainerInfo, ...] = (),
                      webroots: Tuple[str, ...] = ()) -> Tuple[str, ...]:
    fs = ctx.fs
    paths: List[str] = list(SESSION_DIR_CANDIDATES) + panels.app_session_dirs(fs, webroots)
    for container in containers:
        if container.web:
            paths.extend(ctr.session_dirs(container))
    for pattern in SESSION_DIR_GLOBS:
        paths.extend(fs.glob(pattern))
    for raw in _matches(RE_INI_SAVE_PATH, ini) + _matches(RE_INI_SAVE_PATH, fpm):
        # "N;MODE;/path" -> "/path"
        cleaned = _clean_path(raw.split(";")[-1])
        if cleaned:
            paths.append(cleaned)
    paths.extend(ctx.extra_session_dirs)
    return dedupe_nested([p for p in paths if fs.isdir(p)])


CONTAINER_CGROUP = re.compile(r"docker|containerd|libpod|kubepods|lxc|/machine\.slice/")


def _read_proc(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _readlink(path: str) -> Tuple[str, str]:
    try:
        return os.readlink(path), ""
    except OSError as exc:
        return "", errno.errorcode.get(exc.errno or 0, "EUNKNOWN")


def _socket_inodes(pid: int) -> FrozenSet[int]:
    inodes = set()
    fd_dir = "/proc/{}/fd".format(pid)
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return frozenset()
    for fd in fds:
        target, _ = _readlink(os.path.join(fd_dir, fd))
        if target.startswith("socket:["):
            try:
                inodes.add(int(target[8:-1]))
            except ValueError:
                continue
    return frozenset(inodes)


def snapshot_processes() -> Tuple[ProcInfo, ...]:
    procs = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        status = _read_proc("/proc/{}/status".format(pid))
        if not status:
            continue
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        try:
            uid = int(fields.get("Uid", "-1").split()[0])
            ppid = int(fields.get("PPid", "0").strip())
        except (ValueError, IndexError):
            continue
        cmdline = _read_proc("/proc/{}/cmdline".format(pid)).replace("\x00", " ").strip()
        in_container = bool(CONTAINER_CGROUP.search(_read_proc("/proc/{}/cgroup".format(pid))))
        exe, exe_error = _readlink("/proc/{}/exe".format(pid))
        cwd, _ = _readlink("/proc/{}/cwd".format(pid))
        procs.append(ProcInfo(pid, ppid, uid, fields.get("Name", "").strip(), cmdline, exe,
                              exe_error, cwd, _socket_inodes(pid), in_container))
    return tuple(procs)


def discover(ctx: ScanContext) -> Discovery:
    fs = ctx.fs
    users = parse_passwd(fs)
    groups = parse_groups(fs)
    panel_web, panel_logs, panel_ini, panel_nginx, panel_fpm = panels.onepanel_locations(fs)
    nginx = read_configs(fs, NGINX_CONF_GLOBS + tuple(panel_nginx))
    apache = read_configs(fs, APACHE_CONF_GLOBS)
    fpm = read_configs(fs, FPM_CONF_GLOBS + tuple(panel_fpm))
    ini = read_configs(fs, PHP_INI_GLOBS + tuple(panel_ini))
    web_users = find_web_users(fs, users, nginx, apache, fpm)
    containers = ctr.discover_containers(fs)
    webroots = find_webroots(ctx, nginx, apache, containers,
                             tuple(panel_web) + tuple(panels.cpanel_docroots(fs)))
    notes = []
    if ctx.live and hasattr(os, "geteuid") and os.geteuid() != 0:
        notes.append("Not running as root: many files, logs and /proc entries are unreadable; "
                     "results are INCOMPLETE. Re-run with sudo.")
    if not users:
        notes.append("/etc/passwd unreadable or empty: user-based checks are limited.")
    return Discovery(
        users=users,
        groups=groups,
        web_users=web_users,
        web_uids=web_uids(users, web_users, containers),
        mysql_uids=frozenset(u.uid for u in users if u.name in MYSQL_USER_NAMES),
        webroots=webroots,
        log_files=find_log_files(ctx, nginx, apache, fpm, ini, containers, tuple(panel_logs)),
        session_dirs=find_session_dirs(ctx, fpm, ini, containers, webroots),
        php_ini_files=tuple(path for path, _ in ini),
        processes=snapshot_processes() if ctx.live else (),
        notes=tuple(notes),
        containers=containers,
    )
