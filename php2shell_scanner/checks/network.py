"""Live sockets: reverse/bind shells and leftover PHP-FPM listeners (Linux /proc/net)."""

import ipaddress
import socket
import struct
import sys
from typing import Dict, List, NamedTuple, Optional

from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, ProcInfo, Severity
from php2shell_scanner.checks.processes import is_web_process
from php2shell_scanner.signatures import printable
from php2shell_scanner.signatures.system import (INTERPRETER_NAMES, MINING_PORTS, NETTOOL_NAMES,
                                              SHELL_NAMES, is_web_server_name)

NAME = "network"
DESCRIPTION = "Live sockets: shells holding connections, web-user listeners, exposed FPM"

TCP_STATES = {"01": "ESTABLISHED", "0A": "LISTEN"}
PROC_NET = ("/proc/net/tcp", "/proc/net/tcp6")


class Sock(NamedTuple):
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int


# /proc/net/tcp prints each 32-bit word of the address in host byte order.
HOST_ORDER = "<" if sys.byteorder == "little" else ">"


def _decode_addr(text: str) -> tuple:
    host, port = text.split(":")
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        ip = socket.inet_ntop(socket.AF_INET,
                              struct.pack(HOST_ORDER + "I", struct.unpack(">I", raw)[0]))
    else:
        words = struct.unpack(">4I", raw)
        ip = socket.inet_ntop(socket.AF_INET6, struct.pack(HOST_ORDER + "4I", *words))
        if ip.startswith("::ffff:"):
            ip = ip[7:]
    return ip, int(port, 16)


def parse_proc_net(text: str) -> List[Sock]:
    socks = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] not in TCP_STATES:
            continue
        try:
            local_ip, local_port = _decode_addr(fields[1])
            remote_ip, remote_port = _decode_addr(fields[2])
            socks.append(Sock(local_ip, local_port, remote_ip, remote_port,
                              TCP_STATES[fields[3]], int(fields[9])))
        except (ValueError, OSError, struct.error):
            continue
    return socks


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _proc_base(proc: ProcInfo) -> str:
    exe = proc.exe.replace(" (deleted)", "")
    return exe.rsplit("/", 1)[-1] if exe else proc.name


def _finding(rule: str, sev: Severity, kind: str, title: str, sock: Sock,
             proc: Optional[ProcInfo], disc: Discovery, detail: str = "") -> Finding:
    who = "pid={} {} user={}".format(proc.pid, proc.cmdline or proc.name,
                                     disc.owner_name(proc.uid)) if proc else "unknown process"
    evidence = "{} {}:{} -> {}:{} ({})".format(sock.state, sock.local_ip, sock.local_port,
                                              sock.remote_ip, sock.remote_port, who)
    return Finding(NAME, rule, sev, kind, title, proc.exe if proc else "", printable(evidence, 240),
                   detail, {"pid": proc.pid if proc else None, "local_port": sock.local_port,
                            "remote": "{}:{}".format(sock.remote_ip, sock.remote_port)})


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1"


def is_internal(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def check_socket(sock: Sock, proc: Optional[ProcInfo], disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    if proc is None:
        return findings
    base = _proc_base(proc)
    web = is_web_process(proc, disc)
    server = is_web_server_name(base) or is_web_server_name(proc.name)
    established = sock.state == "ESTABLISHED"
    if established and base in SHELL_NAMES:
        internal = is_loopback(sock.remote_ip)
        findings.append(_finding(
            "NET-SHELL-CONNECTION", Severity.MEDIUM if internal else Severity.CRITICAL,
            Kind.COMPROMISE, "Shell process holds a TCP connection (reverse shell)", sock, proc,
            disc, "Interactive shells talk through ttys, not TCP sockets."))
    elif established and web and base in NETTOOL_NAMES - {"curl", "wget"}:
        findings.append(_finding(
            "NET-WEBUSER-NETTOOL", Severity.CRITICAL, Kind.COMPROMISE,
            "netcat/socat/telnet connection owned by the web user", sock, proc, disc))
    elif established and web and not server and not is_internal(sock.remote_ip):
        interpreter = base.rstrip("0123456789.") in INTERPRETER_NAMES
        findings.append(_finding(
            "NET-WEBUSER-CONNECTION", Severity.MEDIUM, Kind.COMPROMISE,
            "{} of the web user holds an Internet connection".format(
                "Interpreter" if interpreter else "Non-webserver process"), sock, proc, disc,
            "Reverse shells, tunnels and droppers started from a webshell look like this; "
            "app workers calling external APIs do too - check the process."))
    if sock.state == "LISTEN" and web and not server:
        findings.append(_finding(
            "NET-WEBUSER-LISTENER", Severity.HIGH, Kind.COMPROMISE,
            "Non-webserver process of the web user is listening (bind shell)", sock, proc, disc))
    if sock.state == "LISTEN" and "fpm" in (base + proc.name) and not is_loopback(sock.local_ip):
        findings.append(_finding(
            "NET-FPM-EXPOSED", Severity.HIGH, Kind.EXPOSURE,
            "PHP-FPM listens on a non-loopback address", sock, proc, disc,
            "Anyone who can reach this port can run PHP code (FastCGI has no auth)."))
    if established and sock.remote_port in MINING_PORTS and not server \
            and not is_internal(sock.remote_ip):
        findings.append(_finding(
            "NET-MINING-PORT", Severity.MEDIUM, Kind.COMPROMISE,
            "Outbound connection to a typical mining-pool port", sock, proc, disc))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    if not ctx.live:
        return []
    # A socket inode can be shared (fork/exec inherits fds), so keep every owner.
    by_inode: Dict[int, List[ProcInfo]] = {}
    for proc in disc.processes:
        for inode in proc.socket_inodes:
            by_inode.setdefault(inode, []).append(proc)
    findings: List[Finding] = []
    for path in PROC_NET:
        for sock in parse_proc_net(read_text(path)):
            for owner in by_inode.get(sock.inode, []):
                findings.extend(check_socket(sock, owner, disc))
    return findings
