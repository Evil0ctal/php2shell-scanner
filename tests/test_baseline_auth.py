"""Security baseline and auth-log checks."""

import json

import pytest

from php2shell_scanner.checks import auth_logs, baseline
from php2shell_scanner.models import Kind, Severity
from php2shell_scanner.report import compute_verdict

from conftest import rules


# ----------------------------------------------------------------------- baseline
def test_no_firewall_is_hardening_and_does_not_change_verdict(tree, scan_env):
    ctx, disc = scan_env()
    found = baseline.run(ctx, disc)
    by_rule = {f.rule: f for f in found}
    assert by_rule["BASE-NO-FIREWALL"].kind == Kind.HARDENING
    assert compute_verdict(found).code == 0


def test_configured_firewalls_detected_offline(tree, scan_env):
    tree.write("/etc/ufw/ufw.conf", "ENABLED=yes\n")
    tree.symlink("/lib/systemd/system/firewalld.service",
                 "/etc/systemd/system/multi-user.target.wants/firewalld.service")
    ctx, disc = scan_env()
    by_rule = {f.rule: f for f in baseline.run(ctx, disc)}
    assert "ufw" in by_rule["BASE-FIREWALL"].title and "firewalld" in by_rule["BASE-FIREWALL"].title


def test_ssh_config_first_value_wins_and_includes(tree, scan_env):
    tree.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n"
                                       "PermitRootLogin yes\nPermitEmptyPasswords yes\n")
    tree.write("/etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication no\n")
    ctx, disc = scan_env()
    got = rules(baseline.run(ctx, disc))
    assert "BASE-SSH-EMPTY-PASSWORDS" in got
    # root login with keys only (passwords disabled in the drop-in) is not a password risk
    assert not {"BASE-SSH-PASSWORD-AUTH", "BASE-SSH-ROOT-LOGIN"} & got
    tree.write("/etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication yes\n")
    assert "BASE-SSH-ROOT-LOGIN" in rules(baseline.run(*scan_env()))


def test_docker_api_and_redis_exposures(tree, scan_env):
    tree.write("/etc/docker/daemon.json", json.dumps({"hosts": ["unix:///var/run/docker.sock",
                                                                "tcp://0.0.0.0:2375"]}))
    tree.write("/etc/redis/redis.conf", "bind 0.0.0.0\nprotected-mode no\n")
    ctx, disc = scan_env()
    by_rule = {f.rule: f for f in baseline.run(ctx, disc)}
    assert by_rule["BASE-DOCKER-API-TCP"].severity == Severity.CRITICAL
    assert by_rule["BASE-REDIS-UNAUTH"].kind == Kind.EXPOSURE


def test_docker_api_with_tls_or_loopback_is_fine(tree, scan_env):
    tree.write("/etc/docker/daemon.json", json.dumps({"hosts": ["tcp://127.0.0.1:2375"]}))
    ctx, disc = scan_env()
    assert "BASE-DOCKER-API-TCP" not in rules(baseline.run(ctx, disc))


def test_world_writable_webroot(tree, scan_env):
    import os
    os.chmod(tree.path("/var/www/html"), 0o777)
    ctx, disc = scan_env(extra_webroots=("/var/www/html",))
    disc = disc._replace(webroots=("/var/www/html",))
    assert "BASE-WEBROOT-WORLD-WRITABLE" in rules(baseline.run(ctx, disc))


# --------------------------------------------------------------------------- auth
AUTH_LOG = """\
Oct 19 02:00:01 web sshd[1]: Failed password for root from 198.51.100.7 port 4000 ssh2
Oct 20 13:30:00 web sshd[2]: Accepted publickey for www-data from 203.0.113.66 port 5000 ssh2
Oct 20 13:31:00 web sudo:  www-data : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
Oct 20 13:32:00 web useradd[9]: new user: name=sysupdate, UID=0, GID=0, home=/root, shell=/bin/bash
Oct 20 13:33:00 web usermod[10]: add 'backup' to group 'sudo'
Oct 20 13:34:00 web su[11]: pam_unix(su:session): session opened for user root(uid=0) by www-data(uid=33)
Oct 21 09:00:00 web sshd[3]: Accepted password for root from 192.0.2.10 port 6000 ssh2
"""


def test_auth_log_events(tree, scan_env):
    brute = "".join("Oct 21 09:00:{:02d} web sshd[1]: Failed password for root from "
                    "198.51.100.7 port 4000 ssh2\n".format(i % 60) for i in range(25))
    tree.write("/var/log/auth.log.1", brute)
    tree.write("/var/log/auth.log",
               AUTH_LOG + "Oct 21 09:05:00 web sshd[4]: Accepted password for root from "
                          "198.51.100.7 port 4100 ssh2\n")
    ctx, disc = scan_env()
    by_rule = {}
    for finding in auth_logs.run(ctx, disc):
        by_rule.setdefault(finding.rule, finding)
    assert by_rule["AUTH-WEBUSER-LOGIN"].severity == Severity.CRITICAL
    assert by_rule["AUTH-WEBUSER-SUDO"].kind == Kind.COMPROMISE
    assert by_rule["AUTH-WEBUSER-SU"].severity == Severity.CRITICAL
    assert by_rule["AUTH-NEW-ACCOUNT"].severity == Severity.HIGH        # UID 0
    assert "sudo" in by_rule["AUTH-PRIV-GROUP-ADD"].title
    assert by_rule["AUTH-BRUTEFORCE-SUCCESS"].severity == Severity.HIGH
    assert {"AUTH-LOGINS", "AUTH-ROOT-PASSWORD-LOGIN", "AUTH-BRUTEFORCE"} <= set(by_rule)


def test_rotation_order_oldest_first():
    paths = ["/var/log/auth.log", "/var/log/auth.log.1", "/var/log/auth.log.3.gz",
             "/var/log/auth.log.2.gz"]
    assert sorted(paths, key=auth_logs.rotation_key) == [
        "/var/log/auth.log.3.gz", "/var/log/auth.log.2.gz", "/var/log/auth.log.1",
        "/var/log/auth.log"]


def test_forged_usernames_cannot_fake_logins_or_failures(tree, scan_env):
    forged = (
        "Oct 21 09:00:00 web sshd[1]: Connection closed by invalid user Accepted password for "
        "www-data from 6.6.6.6 port 22 9.9.9.9 port 5 [preauth]\n"
        "Oct 21 09:00:01 web sshd[1]: Failed none for invalid user Accepted publickey for "
        "www-data from 6.6.6.6 port 22 ssh2 from 9.9.9.9 port 5 ssh2\n")
    framing = "".join("Oct 21 09:00:{:02d} web sshd[1]: Failed password for invalid user x from "
                      "10.0.0.5 port 1 from 8.8.8.8 port 22 ssh2\n".format(i) for i in range(25))
    real = "Oct 21 09:05:00 web sshd[2]: Accepted publickey for alice from 10.0.0.5 port 7 ssh2\n"
    tree.write("/var/log/auth.log", forged + framing + real)
    ctx, disc = scan_env()
    got = {f.rule for f in auth_logs.run(ctx, disc)}
    assert "AUTH-WEBUSER-LOGIN" not in got
    assert "AUTH-BRUTEFORCE-SUCCESS" not in got   # failures were from 8.8.8.8, not 10.0.0.5


def test_old_failures_do_not_make_a_later_login_brute_force(tree, scan_env):
    old = "".join("Oct 01 02:00:{:02d} web sshd[1]: Failed password for root from 10.0.0.9 "
                  "port 4000 ssh2\n".format(i) for i in range(30))
    tree.write("/var/log/auth.log",
               old + "Oct 21 09:05:00 web sshd[2]: Accepted password for root from 10.0.0.9 "
                     "port 7 ssh2\n")
    ctx, disc = scan_env()
    assert "AUTH-BRUTEFORCE-SUCCESS" not in {f.rule for f in auth_logs.run(ctx, disc)}


def test_openssh_98_sshd_session_name_and_shell_aware_severity(tree, scan_env):
    tree.write("/etc/passwd", open(tree.path("/etc/passwd")).read().replace(
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/bin/bash"))
    tree.write("/var/log/auth.log", "2026-10-21T09:05:00.1+00:00 web sshd-session[9]: Accepted "
                                    "publickey for www-data from 203.0.113.5 port 7 ssh2\n")
    ctx, disc = scan_env()
    found = [f for f in auth_logs.run(ctx, disc) if f.rule == "AUTH-WEBUSER-LOGIN"]
    assert found and found[0].severity == Severity.MEDIUM   # panel-style account with a shell


def test_sshd_include_loop_and_inline_precedence(tree, scan_env):
    tree.write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config\n"
                                       "Include sshd_config.d/*.conf\n"
                                       "PasswordAuthentication yes\n")
    tree.write("/etc/ssh/sshd_config.d/10-hardening.conf", "PasswordAuthentication no\n"
                                                         "Include /etc/ssh/sshd_config.d/*.conf\n")
    ctx, disc = scan_env()
    import time as _time
    started = _time.time()
    found = baseline.check_ssh(ctx)
    assert _time.time() - started < 2
    assert "BASE-SSH-PASSWORD-AUTH" not in {f.rule for f in found}   # drop-in wins, like sshd


def test_nft_docker_rules_are_not_an_input_firewall():
    docker_only = ("table ip filter {\n chain DOCKER-ISOLATION-STAGE-2 {\n  drop\n }\n"
                   " chain FORWARD {\n  type filter hook forward priority filter; policy drop;\n }\n}")
    real = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}"
    assert not baseline._nft_filters_input(docker_only)
    assert baseline._nft_filters_input(real)


def test_injected_privilege_records_inside_sshd_messages_are_ignored(tree, scan_env):
    tree.write("/var/log/auth.log", "".join([
        "Oct 21 09:00:00 web sshd[1]: Invalid user sudo: www-data : TTY=pts/0 ; COMMAND=/bin/bash"
        " from 6.6.6.6 port 22\n",
        "Oct 21 09:00:01 web sshd[1]: Invalid user useradd: new user: name=x, UID=0 from 6.6.6.6"
        " port 22\n",
        "Oct 21 09:00:02 web sshd[1]: Invalid user usermod: add 'x' to group 'sudo' from 6.6.6.6"
        " port 22\n",
        "Oct 21 09:00:03 web sshd[1]: Invalid user (to root) www-data on pts/1 from 6.6.6.6 port 2\n",
        "garbage line with sudo: www-data : COMMAND=/bin/sh\n",
    ]))
    ctx, disc = scan_env()
    got = {f.rule for f in auth_logs.run(ctx, disc)}
    assert not got & {"AUTH-WEBUSER-SUDO", "AUTH-NEW-ACCOUNT", "AUTH-PRIV-GROUP-ADD",
                      "AUTH-WEBUSER-SU"}


def test_busybox_syslog_format_with_facility(tree, scan_env):
    tree.write("/var/log/messages", "Oct 21 09:05:00 web authpriv.info sshd[9]: Accepted "
                                    "publickey for www-data from 203.0.113.5 port 7 ssh2\n")
    ctx, disc = scan_env()
    assert "AUTH-WEBUSER-LOGIN" in {f.rule for f in auth_logs.run(ctx, disc)}



# --------------------------------------------- formats seen on a real Ubuntu 24.04 host
REAL_AUTH = """\
2026-10-21T22:54:18.554342-07:00 web sshd[1934866]: Accepted publickey for root from 76.217.54.191 port 59560 ssh2: ED25519 SHA256:NZYQyg5jsTn1PBYFkxSmkJha5oIXJqXxgwn4CTfAqaY
2025-09-19T04:56:02.092694+00:00 web useradd[5553]: new user: name=www, UID=1000, GID=1000, home=/home/www, shell=/sbin/nologin, from=/dev/pts/0
2025-09-19T04:57:00.000000+00:00 web useradd[5554]: new user: name=deploy, UID=1003, GID=1003, home=/home/deploy, shell=/bin/bash, from=/dev/pts/0
"""


def test_real_world_auth_formats(tree, scan_env):
    tree.write("/var/log/auth.log", REAL_AUTH)
    tree.write("/var/log/auth.log.2", REAL_AUTH)            # rotated copy repeating records
    ctx, disc = scan_env()
    found = auth_logs.run(ctx, disc)
    logins = [f for f in found if f.rule == "AUTH-LOGINS"]
    assert logins and "76.217.54.191" in logins[0].evidence  # publickey suffix understood
    accounts = [f for f in found if f.rule == "AUTH-NEW-ACCOUNT"]
    assert len(accounts) == 2                                 # deduplicated across files
    by_name = {f.title.split("'")[1]: f.severity for f in accounts}
    assert by_name == {"www": Severity.LOW, "deploy": Severity.MEDIUM}


def test_recent_keys_are_a_review_item_with_fingerprints(tree, scan_env):
    import time as _time
    from php2shell_scanner.checks import accounts
    tree.write("/root/.ssh/authorized_keys",
               "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl me@mac\n")
    ctx, disc = scan_env(since=_time.time() - 60)
    recent = [f for f in accounts.run(ctx, disc) if f.rule == "ACCT-SSH-KEYS-RECENT"][0]
    assert recent.severity == Severity.MEDIUM and "SHA256:" in recent.detail


def test_ufw_allow_rules_parsing(monkeypatch, tree, scan_env):
    status = ("Status: active\n\nTo                         Action      From\n"
              "22/tcp                     ALLOW       Anywhere\n"
              "6379/tcp                   ALLOW       Anywhere\n"
              "39000:40000/tcp            ALLOW       Anywhere\n"
              "Anywhere                   REJECT      1.2.3.4\n")
    monkeypatch.setattr(baseline, "run_tool", lambda ctx, argv, timeout=0: (0, status))
    ctx, disc = scan_env()
    monkeypatch.setattr(type(ctx), "live", property(lambda self: True))
    assert baseline.open_ports(ctx) == {6379}


@pytest.mark.parametrize("logged_shell, passwd_shell, expected", [
    ("/sbin/nologin", None, Severity.LOW),
    ("/tmp/backdoor-nologin", None, Severity.MEDIUM),        # look-alike path
    ("/sbin/nologin", "/bin/bash", Severity.MEDIUM),         # shell changed afterwards
])
def test_service_account_downgrade_is_strict(tree, scan_env, logged_shell, passwd_shell, expected):
    if passwd_shell:
        tree.write("/etc/passwd", open(tree.path("/etc/passwd")).read()
                   + "svc:x:1500:1500::/home/svc:{}\n".format(passwd_shell))
    tree.write("/var/log/auth.log", "2026-10-21T09:00:00.0+00:00 web useradd[1]: new user: "
               "name=svc, UID=1500, GID=1500, home=/home/svc, shell={}, from=none\n"
               .format(logged_shell))
    ctx, disc = scan_env()
    found = [f for f in auth_logs.run(ctx, disc) if f.rule == "AUTH-NEW-ACCOUNT"]
    assert [f.severity for f in found] == [expected]
