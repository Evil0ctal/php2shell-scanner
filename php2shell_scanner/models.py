"""Core immutable data types shared by every check."""

from enum import IntEnum
from typing import Any, Dict, FrozenSet, NamedTuple, Optional, Tuple


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError("unknown severity '{}' (valid: {})".format(name, valid))


class Kind:
    """What a finding says about the host."""

    COMPROMISE = "compromise"  # attacker already had code execution / persistence
    ATTEMPT = "attempt"        # exploitation traffic or a planted exploit stage
    EXPOSURE = "exposure"      # vulnerable software or configuration still present
    HARDENING = "hardening"    # security-baseline gap; never changes the verdict
    INFO = "info"              # context the analyst should know about

    ALL = (COMPROMISE, ATTEMPT, EXPOSURE, HARDENING, INFO)


class Finding(NamedTuple):
    check: str
    rule: str
    severity: Severity
    kind: str
    title: str
    path: str = ""
    evidence: str = ""
    detail: str = ""
    meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "rule": self.rule,
            "severity": self.severity.name,
            "kind": self.kind,
            "title": self.title,
            "path": self.path,
            "evidence": self.evidence,
            "detail": self.detail,
            "meta": dict(self.meta) if self.meta else {},
        }


class UserInfo(NamedTuple):
    name: str
    uid: int
    gid: int
    home: str
    shell: str


class ProcInfo(NamedTuple):
    pid: int
    ppid: int
    uid: int
    name: str
    cmdline: str
    exe: str          # "" when unreadable / kernel thread
    exe_error: str    # errno name when readlink failed, e.g. "ENOENT"
    cwd: str
    socket_inodes: FrozenSet[int]
    container: bool = False      # runs inside a Docker/containerd/Podman/k8s container


class ContainerInfo(NamedTuple):
    """A Docker/Podman container whose filesystem can be inspected from the host."""

    id: str
    name: str
    image: str
    running: bool
    upper_dir: str                  # writable layer: every file the container changed/added
    mounts: Tuple[Tuple[str, str], ...]   # (host source, container destination)
    log_files: Tuple[str, ...]
    web: bool                       # image/filesystem/mounts look like a web or PHP stack


class Discovery(NamedTuple):
    users: Tuple[UserInfo, ...]
    groups: Dict[str, Tuple[str, ...]]
    web_users: Tuple[str, ...]
    web_uids: FrozenSet[int]
    mysql_uids: FrozenSet[int]
    webroots: Tuple[str, ...]
    log_files: Tuple[str, ...]
    session_dirs: Tuple[str, ...]
    php_ini_files: Tuple[str, ...]
    processes: Tuple[ProcInfo, ...]
    notes: Tuple[str, ...]
    containers: Tuple[ContainerInfo, ...] = ()

    def user_by_uid(self, uid: int) -> Optional[UserInfo]:
        for user in self.users:
            if user.uid == uid:
                return user
        return None

    def owner_name(self, uid: int) -> str:
        user = self.user_by_uid(uid)
        return user.name if user else str(uid)
