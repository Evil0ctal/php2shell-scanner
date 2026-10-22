"""Docker / Podman container discovery from on-disk metadata (works live and offline).

Panels such as 1Panel run PHP inside containers. From the host we can still see:
- the container's writable layer ("upper"/"diff"): every file the container created or
  changed since it started, which is exactly where a dropped webshell or tool ends up;
- bind mounts and volumes (web roots, logs);
- json-file logs of nginx/OpenResty/Apache/php-fpm running inside.
"""

import json
import logging
import os
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from php2shell_scanner.fs import RootFS
from php2shell_scanner.models import ContainerInfo

LOG = logging.getLogger("php2shell_scanner")

DOCKER_DEFAULT_ROOT = "/var/lib/docker"
PODMAN_ROOTS = ("/var/lib/containers/storage",)
MAX_CONFIG = 8 * 1024 * 1024
WEB_IMAGE = re.compile(
    r"php|wordpress|drupal|joomla|nextcloud|magento|prestashop|matomo|mediawiki|laravel"
    r"|symfony|typecho|discuz|thinkphp|1panel|openresty|nginx|httpd|apache|lamp|lnmp|caddy"
    r"|litespeed|webdevops|bitnami|phpmyadmin|adminer", re.I)
PHP_MARKERS = ("usr/local/etc/php", "etc/php", "usr/local/lib/php", "usr/sbin/php-fpm")
NOT_WEB_SOURCES = ("/", "/etc", "/proc", "/sys", "/dev", "/run", "/var/run", "/usr", "/boot",
                   "/lib", "/lib64", "/bin", "/sbin", "/root", "/var", "/var/lib", "/home", "/opt")
SYSTEM_PREFIXES = ("/proc/", "/sys/", "/dev/", "/etc/", "/usr/", "/boot/", "/run/",
                   "/var/lib/docker/overlay", "/var/lib/docker/image")


def _load_json(fs: RootFS, path: str) -> Optional[Any]:
    text = fs.read_text(path, MAX_CONFIG)
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError, MemoryError):
        LOG.warning("unparsable container metadata %s", path)
        return None


def _dict(value: Any) -> Dict[str, Any]:
    """Metadata is untrusted: anything that is not an object becomes an empty one."""
    return value if isinstance(value, dict) else {}


def _str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def docker_root(fs: RootFS) -> str:
    config = _load_json(fs, "/etc/docker/daemon.json")
    if isinstance(config, dict):
        root = config.get("data-root") or config.get("graph")
        if isinstance(root, str) and root.startswith("/"):
            return root.rstrip("/")
    return DOCKER_DEFAULT_ROOT


def _is_web(fs: RootFS, image: str, upper: str, mounts: List[Tuple[str, str]]) -> bool:
    if WEB_IMAGE.search(image):
        return True
    if upper and any(fs.exists(os.path.join(upper, marker)) for marker in PHP_MARKERS):
        return True
    return any(dest.startswith(("/var/www", "/usr/share/nginx", "/www")) for _, dest in mounts)


def _docker_mounts(root: str, config: Dict[str, Any]) -> List[Tuple[str, str]]:
    mounts = []
    for point in _dict(config.get("MountPoints")).values():
        point = _dict(point)
        source = _str(point.get("Source"))
        name = _str(point.get("Name"))
        if not source and point.get("Type") == "volume" and re.match(r"^[\w.-]{1,255}$", name):
            source = "{}/volumes/{}/_data".format(root, name)
        if source.startswith("/"):
            mounts.append((posixpath.normpath(source), _str(point.get("Destination"))))
    return mounts


def docker_containers(fs: RootFS, root: str) -> List[ContainerInfo]:
    result = []
    for cid in fs.listdir(root + "/containers"):
        try:
            container = _docker_container(fs, root, cid)
        except Exception as exc:  # one corrupt container must not hide the others
            LOG.warning("skipping container %s: %s: %s", cid[:12], type(exc).__name__, exc)
            continue
        if container is not None:
            result.append(container)
    return result


def _docker_container(fs: RootFS, root: str, cid: str) -> Optional[ContainerInfo]:
    base = "{}/containers/{}".format(root, cid)
    config = _load_json(fs, base + "/config.v2.json")
    if not isinstance(config, dict):
        return None
    driver = _str(config.get("Driver"), "overlay2")
    if not re.match(r"^[\w.-]{1,32}$", driver):
        driver = "overlay2"
    mount_id = (fs.read_text("{}/image/{}/layerdb/mounts/{}/mount-id".format(
        root, driver, cid), 256) or "").strip()
    upper = "{}/{}/{}/diff".format(root, driver, mount_id) if re.match(r"^\w{1,128}$",
                                                                       mount_id) else ""
    if upper and not fs.isdir(upper):
        upper = ""
    if not upper and fs.is_live:   # containerd image store (Docker 29+): ask the kernel
        upper = _live_upper_dir(_dict(config.get("State")).get("Pid"))
    mounts = _docker_mounts(root, config)
    image = _str(_dict(config.get("Config")).get("Image")) or _str(config.get("Image"))
    return ContainerInfo(
        id=cid[:12], name=_str(config.get("Name"), cid[:12]).lstrip("/")[:128], image=image[:200],
        running=_dict(config.get("State")).get("Running") is True, upper_dir=upper,
        mounts=tuple(mounts), log_files=tuple(fs.glob(base + "/*-json.log*")),
        web=_is_web(fs, image, upper, mounts))


def upper_from_mountinfo(text: str) -> str:
    """upperdir= of the root ("/") overlay mount; mountinfo escapes ' ' etc. as \\ooo."""
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4] == "/" and " - overlay " in line:
            found = re.search(r"upperdir=([^,\s]+)", line)
            if found:
                return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), found.group(1))
    return ""


def _live_upper_dir(pid: Any) -> str:
    """Writable layer of a running container, straight from the kernel's mount table."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return ""
    try:
        with open("/proc/{}/mountinfo".format(pid), "r", encoding="utf-8",
                  errors="replace") as handle:
            return upper_from_mountinfo(handle.read(1024 * 1024))
    except OSError:
        return ""


def _podman_mounts(spec: Any) -> List[Tuple[str, str]]:
    mounts = []
    entries = _dict(spec).get("mounts")
    for mount in entries if isinstance(entries, list) else []:
        mount = _dict(mount)
        source = _str(mount.get("source"))
        if mount.get("type") in ("bind", None) and source.startswith("/"):
            mounts.append((posixpath.normpath(source), _str(mount.get("destination"))))
    return mounts


def podman_containers(fs: RootFS, root: str) -> List[ContainerInfo]:
    listing = _load_json(fs, root + "/overlay-containers/containers.json")
    result = []
    for item in listing if isinstance(listing, list) else []:
        try:
            container = _podman_container(fs, root, _dict(item))
        except Exception as exc:  # one corrupt entry must not hide the others
            LOG.warning("skipping podman container: %s: %s", type(exc).__name__, exc)
            continue
        if container is not None:
            result.append(container)
    return result


def _podman_container(fs: RootFS, root: str, item: Dict[str, Any]) -> Optional[ContainerInfo]:
    cid, layer = _str(item.get("id")), _str(item.get("layer"))
    if not re.match(r"^\w{1,128}$", cid):
        return None
    upper = "{}/overlay/{}/diff".format(root, layer) if re.match(r"^\w{1,128}$", layer) else ""
    userdata = "{}/overlay-containers/{}/userdata".format(root, cid)
    mounts = _podman_mounts(_load_json(fs, userdata + "/config.json"))
    image = ""
    metadata = item.get("metadata")
    if isinstance(metadata, str):
        try:
            image = _str(_dict(json.loads(metadata)).get("image-name"))
        except (ValueError, RecursionError):
            image = ""
    names = item.get("names")
    name = _str(names[0]) if isinstance(names, list) and names else cid[:12]
    return ContainerInfo(
        id=cid[:12], name=name[:128] or cid[:12], image=image[:200], running=False,
        upper_dir=upper if upper and fs.isdir(upper) else "", mounts=tuple(mounts),
        log_files=tuple(p for p in [userdata + "/ctr.log"] if fs.isfile(p)),
        web=_is_web(fs, image, upper, mounts))


def discover_containers(fs: RootFS) -> Tuple[ContainerInfo, ...]:
    containers: List[ContainerInfo] = []
    try:
        containers += docker_containers(fs, docker_root(fs))
        for root in PODMAN_ROOTS:
            containers += podman_containers(fs, root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        LOG.warning("container discovery incomplete: %s", exc)
    return tuple(containers)


def web_dirs(container: ContainerInfo) -> List[str]:
    """Host directories worth a webshell scan for one web container."""
    dirs = [container.upper_dir] if container.upper_dir else []
    for source, _ in container.mounts:
        normalized = posixpath.normpath(source)
        if normalized not in NOT_WEB_SOURCES and not normalized.endswith(".sock") \
                and not normalized.startswith(SYSTEM_PREFIXES):
            dirs.append(normalized)
    return dirs


def session_dirs(container: ContainerInfo) -> List[str]:
    if not container.upper_dir:
        return []
    return [os.path.join(container.upper_dir, rel) for rel in
            ("tmp", "var/lib/php/sessions", "var/lib/php/session", "var/lib/php")]


def tmp_dirs(container: ContainerInfo) -> List[str]:
    if not container.upper_dir:
        return []
    return [os.path.join(container.upper_dir, rel) for rel in ("tmp", "var/tmp")]


def log_dirs(container: ContainerInfo) -> List[str]:
    """Mounts whose container-side path has a 'log'/'logs' component (not '/blog')."""
    return [source for source, dest in container.mounts
            if any(part in ("log", "logs") for part in dest.lower().split("/"))]
