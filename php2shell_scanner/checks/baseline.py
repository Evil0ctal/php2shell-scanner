"""Security baseline: firewall, exposed services, SSH, Docker API, update/MAC posture.

Most results are HARDENING findings (shown separately, never change the verdict).
Directly exploitable exposures (open Docker API, unauthenticated Redis on all
interfaces, empty SSH passwords) are EXPOSURE findings.
"""

import json
import re
import stat
from typing import Dict, List, Optional, Set, Tuple

from php2shell_scanner.checks import network
from php2shell_scanner.context import ScanContext, run_tool
from php2shell_scanner.models import Discovery, Finding, Kind, Severity

NAME = "baseline"
DESCRIPTION = "Firewall, exposed ports, SSH config, Docker API, fail2ban, updates, SELinux"

C, H, M, L, I = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
                 Severity.INFO)
HARD, EXPO = Kind.HARDENING, Kind.EXPOSURE
# port -> (service, severity when bound to all interfaces)
RISKY_PORTS: Dict[int, Tuple[str, Severity]] = {
    2375: ("Docker API (no TLS)", C), 6379: ("Redis", H), 11211: ("Memcached", H),
    27017: ("MongoDB", H), 9200: ("Elasticsearch", H), 5984: ("CouchDB", H),
    3306: ("MySQL/MariaDB", M), 5432: ("PostgreSQL", M), 9000: ("PHP-FPM/FastCGI or admin UI", M),
    9001: ("PHP-FPM / supervisor", M), 888: ("BT Panel phpMyAdmin", M),
    8888: ("BT Panel / Jupyter", L), 7800: ("aaPanel", L), 8090: ("CyberPanel", L),
    8083: ("HestiaCP/VestaCP", L), 10000: ("Webmin", L), 2083: ("cPanel", L),
    2087: ("WHM", L), 8443: ("Plesk / admin UI", L), 2376: ("Docker API (TLS)", L),
}
FIREWALL_UNITS = ("firewalld", "ufw", "nftables", "iptables", "netfilter-persistent")
SSHD_INCLUDE = re.compile(r"^\s*Include\s+(.+)$", re.I | re.M)


def _f(rule: str, sev: Severity, kind: str, title: str, path: str = "", evidence: str = "",
       detail: str = "") -> Finding:
    return Finding(NAME, rule, sev, kind, title, path, evidence, detail)


def _enabled_unit(ctx: ScanContext, unit: str) -> bool:
    return bool(ctx.fs.glob("/etc/systemd/system/*.wants/{}.service".format(unit))
                or ctx.fs.exists("/etc/runlevels/default/" + unit))


def _nft_filters_input(ruleset: str) -> bool:
    """Only chains hooked to INPUT count (Docker's own forward/isolation drops do not)."""
    for chain in ruleset.split("chain ")[1:]:
        body = chain.split("}", 1)[0]
        if "hook input" in body and re.search(r"policy drop|\bdrop\b|\breject\b", body):
            return True
    return False


def _live_firewall(ctx: ScanContext) -> Optional[List[str]]:
    """Active firewalls according to the kernel / daemons; None if we cannot ask."""
    active = []
    ufw = run_tool(ctx, ["ufw", "status"], timeout=20)
    if ufw and "Status: active" in ufw[1]:
        active.append("ufw")
    firewalld = run_tool(ctx, ["firewall-cmd", "--state"], timeout=20)
    if firewalld and firewalld[1].strip() == "running":
        active.append("firewalld")
    rules = run_tool(ctx, ["iptables", "-S", "INPUT"], timeout=20)
    if rules and rules[0] == 0:
        text = rules[1]
        if "-P INPUT DROP" in text or re.search(r"-A INPUT .*-j (?:DROP|REJECT|ufw|f2b|IN_)", text):
            active.append("iptables")
    nft = run_tool(ctx, ["nft", "list", "ruleset"], timeout=20)
    if nft and nft[0] == 0 and _nft_filters_input(nft[1]):
        active.append("nftables")
    if ufw is None and firewalld is None and rules is None and nft is None:
        return None
    return sorted(set(active))


def _configured_firewall(ctx: ScanContext) -> List[str]:
    found = []
    if re.search(r"^ENABLED=yes", ctx.fs.read_text("/etc/ufw/ufw.conf", 65536) or "", re.M):
        found.append("ufw")
    for unit in ("firewalld", "nftables", "iptables", "netfilter-persistent", "awall"):
        if _enabled_unit(ctx, unit):
            found.append(unit)
    for path in ("/etc/iptables/rules.v4", "/etc/sysconfig/iptables"):
        text = ctx.fs.read_text(path, 1024 * 1024) or ""
        if ":INPUT DROP" in text or re.search(r"-A INPUT .*-j (?:DROP|REJECT)", text):
            found.append("iptables (saved rules)")
    return sorted(set(found))


def check_firewall(ctx: ScanContext) -> Tuple[List[Finding], bool]:
    live = _live_firewall(ctx) if ctx.live else None
    active = live if live is not None else _configured_firewall(ctx)
    basis = "running rules" if live is not None else "configuration files only"
    if active:
        return [_f("BASE-FIREWALL", I, Kind.INFO, "Host firewall active: " + ", ".join(active),
                   detail="Determined from " + basis + ".")], True
    return [_f("BASE-NO-FIREWALL", M, HARD, "No active host firewall detected",
               detail="Determined from {}. A cloud security group may still filter traffic; "
                      "otherwise every listening service below is reachable from the "
                      "Internet.".format(basis))], False


def check_listeners(ctx: ScanContext, disc: Discovery, firewalled: bool) -> List[Finding]:
    if not ctx.live:
        return []
    owners = {inode: proc for proc in disc.processes for inode in proc.socket_inodes}
    findings, seen = [], set()
    for path in network.PROC_NET:
        for sock in network.parse_proc_net(network.read_text(path)):
            if sock.state != "LISTEN" or network.is_loopback(sock.local_ip):
                continue
            if sock.local_port not in RISKY_PORTS or sock.local_port in seen:
                continue
            seen.add(sock.local_port)
            service, severity = RISKY_PORTS[sock.local_port]
            if firewalled and severity > L:
                severity = Severity(severity - 1)
            proc = owners.get(sock.inode)
            findings.append(_f(
                "BASE-EXPOSED-SERVICE", severity, EXPO if severity >= H else HARD,
                "{} listening on all interfaces (port {})".format(service, sock.local_port),
                evidence="{}:{} {}".format(sock.local_ip, sock.local_port,
                                          "pid={} {}".format(proc.pid, proc.name) if proc else ""),
                detail="Bind it to 127.0.0.1 or restrict it with a firewall."))
    return findings


MAX_INCLUDE_DEPTH = 16


def _sshd_config(ctx: ScanContext) -> Dict[str, Tuple[str, str]]:
    """Effective settings: first value wins and Include is expanded in place (like sshd).

    Include loops are cut by a visited set and the same depth limit sshd uses.
    """
    values: Dict[str, Tuple[str, str]] = {}
    seen: Set[str] = set()

    def parse(path: str, depth: int) -> bool:
        """False once a Match block in the main file ends the unconditional section."""
        if depth > MAX_INCLUDE_DEPTH or path in seen:
            return True
        seen.add(path)
        for line in (ctx.fs.read_text(path, 256 * 1024) or "").splitlines():
            parts = line.split(None, 1)
            if not parts or parts[0].startswith("#"):
                continue
            key = parts[0].lower()
            if key == "include" and len(parts) == 2:
                for pattern in parts[1].split():
                    pattern = pattern if pattern.startswith("/") else "/etc/ssh/" + pattern
                    for included in ctx.fs.glob(pattern):
                        if not parse(included, depth + 1):
                            return False
            elif key == "match":
                return depth > 0     # a Match inside an include only ends that file
            elif len(parts) == 2 and key not in values:
                values[key] = (parts[1].strip().lower(), path)
        return True

    parse("/etc/ssh/sshd_config", 0)
    return values


def check_ssh(ctx: ScanContext) -> List[Finding]:
    if not ctx.fs.exists("/etc/ssh/sshd_config"):
        return []
    cfg = _sshd_config(ctx)
    findings = []
    empty = cfg.get("permitemptypasswords", ("no", ""))
    if empty[0] == "yes":
        findings.append(_f("BASE-SSH-EMPTY-PASSWORDS", H, EXPO, "sshd permits empty passwords",
                           empty[1], "PermitEmptyPasswords yes"))
    root = cfg.get("permitrootlogin", ("prohibit-password", ""))
    if root[0] == "yes":
        findings.append(_f("BASE-SSH-ROOT-LOGIN", M, HARD, "sshd allows root login with a password",
                           root[1], "PermitRootLogin yes",
                           "Use 'prohibit-password' and key-based logins for root."))
    password = cfg.get("passwordauthentication", ("yes (default)", ""))
    if password[0].startswith("yes"):
        findings.append(_f("BASE-SSH-PASSWORD-AUTH", L, HARD, "sshd accepts password logins",
                           password[1], "PasswordAuthentication " + password[0],
                           "Keys only (+ fail2ban) removes the brute-force path."))
    return findings


DOCKER_HOST_FLAG = re.compile(r"(?:-H|--host)[= ]?\s*(tcp://\S+)")


def _docker_daemon(ctx: ScanContext) -> Tuple[List[str], bool]:
    """TCP listen addresses from daemon.json / systemd overrides, and whether TLS is on."""
    text = ctx.fs.read_text("/etc/docker/daemon.json", 256 * 1024) or ""
    try:
        config = json.loads(text) if text.strip() else {}
    except ValueError:
        config = {}
    config = config if isinstance(config, dict) else {}
    units = " ".join(ctx.fs.read_text(p, 65536) or "" for p in
                     ctx.fs.glob("/etc/systemd/system/docker.service.d/*.conf")
                     + ctx.fs.glob("/etc/systemd/system/docker.service"))
    hosts = [h for h in config.get("hosts") or [] if isinstance(h, str)]
    hosts += DOCKER_HOST_FLAG.findall(units)
    tls = bool(config.get("tlsverify")) or "--tlsverify" in units
    return [h for h in hosts if h.startswith("tcp://")], tls


def check_docker_api(ctx: ScanContext) -> List[Finding]:
    findings = []
    hosts, tls = _docker_daemon(ctx)
    for host in hosts:
        if not tls and not re.match(r"tcp://(?:127\.|localhost|\[::1\])", host):
            findings.append(_f("BASE-DOCKER-API-TCP", C, EXPO,
                               "Docker API exposed over TCP without TLS client auth",
                               "/etc/docker/daemon.json", host,
                               "Anyone reaching this port is root on the host."))
    st = ctx.fs.stat("/var/run/docker.sock")
    if st is not None and st.st_mode & stat.S_IWOTH:
        findings.append(_f("BASE-DOCKER-SOCK-WORLD", H, EXPO,
                           "docker.sock is world-writable (any user, incl. the web user, is root)",
                           "/var/run/docker.sock", stat.filemode(st.st_mode)))
    return findings


def check_redis_config(ctx: ScanContext) -> List[Finding]:
    findings = []
    for path in ctx.fs.glob("/etc/redis/*.conf") + ctx.fs.glob("/etc/redis.conf") + \
            ctx.fs.glob("/www/server/redis/redis.conf"):
        text = ctx.fs.read_text(path, 512 * 1024) or ""
        bind = re.search(r"^\s*bind\s+(.+)$", text, re.M)
        public = bind is None or re.search(r"\b0\.0\.0\.0\b|\*|::(?:\s|$)", bind.group(1))
        unprotected = re.search(r"^\s*protected-mode\s+no\b", text, re.M)
        no_auth = not re.search(r"^\s*requirepass\s+\S+", text, re.M)
        if public and unprotected and no_auth:
            findings.append(_f("BASE-REDIS-UNAUTH", H, EXPO,
                               "Redis configured for all interfaces without a password", path,
                               detail="Unauthenticated Redis is a classic way to write cron "
                                      "jobs, SSH keys or webshells onto a server."))
    return findings


def check_posture(ctx: ScanContext) -> List[Finding]:
    findings = []
    if not (ctx.fs.exists("/etc/fail2ban/jail.local") or ctx.fs.glob("/etc/fail2ban/jail.d/*")
            or _enabled_unit(ctx, "fail2ban") or _enabled_unit(ctx, "crowdsec")):
        findings.append(_f("BASE-NO-BRUTEFORCE-PROTECTION", L, HARD,
                           "No fail2ban/CrowdSec brute-force protection found"))
    apt = " ".join(ctx.fs.read_text(p, 65536) or "" for p in ctx.fs.glob("/etc/apt/apt.conf.d/*"))
    auto = re.search(r'Unattended-Upgrade\s+"1"', apt) or \
        ctx.fs.glob("/etc/systemd/system/timers.target.wants/dnf-automatic*.timer") or \
        ctx.fs.glob("/etc/systemd/system/timers.target.wants/yum-cron*") or \
        _enabled_unit(ctx, "yum-cron")
    if not auto and (ctx.fs.isdir("/etc/apt") or ctx.fs.isdir("/etc/yum.repos.d")):
        findings.append(_f("BASE-NO-AUTO-UPDATES", L, HARD,
                           "Automatic security updates are not enabled",
                           detail="unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL)."))
    selinux = re.search(r"^SELINUX=(\w+)", ctx.fs.read_text("/etc/selinux/config", 65536) or "",
                        re.M)
    apparmor = ctx.fs.isdir("/etc/apparmor.d")
    mac = "SELinux " + selinux.group(1) if selinux else ("AppArmor" if apparmor else "none")
    findings.append(_f("BASE-MAC", I, Kind.INFO, "Mandatory access control: " + mac))
    return findings


def check_webroot_permissions(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for root in disc.webroots:
        st = ctx.fs.stat(root)
        if st is not None and st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_ISVTX:
            findings.append(_f("BASE-WEBROOT-WORLD-WRITABLE", M, HARD,
                               "Web root is world-writable", root, stat.filemode(st.st_mode)))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    firewall, firewalled = check_firewall(ctx)
    return (firewall + check_listeners(ctx, disc, firewalled) + check_ssh(ctx)
            + check_docker_api(ctx) + check_redis_config(ctx) + check_posture(ctx)
            + check_webroot_permissions(ctx, disc))
