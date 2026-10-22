"""Regression tests for issues found in code review (safety, ReDoS, FPs, detection gaps)."""

import gzip
import io
import os
import time

import pytest

from php2shell_scanner.checks import common, database, network, processes, tmp_artifacts, webroot
from php2shell_scanner.checks.webconfig import scan_config_file
from php2shell_scanner.fs import BLOCKED, MAX_LINE, RootFS
from php2shell_scanner.models import Finding, Kind, ProcInfo, Severity
from php2shell_scanner.report import TextReport, to_json
from php2shell_scanner.signatures import logs as log_sig
from php2shell_scanner.signatures import printable, scan
from php2shell_scanner.signatures.system import COMMAND_SIGNATURES
from php2shell_scanner.signatures.webshell import CONTENT_SIGNATURES

from conftest import rules
from test_system_checks import disc_with, proc


def hits(code: str) -> set:
    return {m.signature.rule for m in scan(CONTENT_SIGNATURES, code.encode())}


# ------------------------------------------------------------------- fs safety
def test_long_symlink_chain_is_blocked_not_followed_to_host(tree, tmp_path):
    secret = tmp_path / "host_secret"
    secret.write_text("HOST-SECRET")
    for i in range(45):
        tree.symlink("/l{}".format(i + 1), "/l{}".format(i))
    tree.symlink(str(secret), "/l45")
    fs = RootFS(tree.root)
    assert fs.real("/l0") == BLOCKED
    assert fs.read_bytes("/l0", 100) is None


def test_glob_lstat_readlink_stay_inside_root(tree, tmp_path):
    outside = tmp_path / "hostdir"
    (outside / "victim").mkdir(parents=True)
    tree.symlink(str(outside), "/home")      # absolute link that would point at the host
    tree.symlink("/etc/missing", "/etc/dangling")
    fs = RootFS(tree.root)
    assert fs.glob("/home/*") == []
    assert fs.readlink("/etc/dangling") == "/etc/missing"
    assert fs.lstat("/etc/dangling") is not None and fs.stat("/etc/dangling") is None


def test_fifo_is_never_opened(tree):
    fifo = tree.path("/tmp/pipe")
    os.mkfifo(fifo)
    assert RootFS(tree.root).read_bytes("/tmp/pipe", 10) is None  # would block forever


def test_corrupt_gzip_and_long_lines(tree):
    tree.write("/var/log/bad.gz", b"\x1f\x8b\x08\x00garbage-not-deflate" * 10)
    tree.write("/var/log/long.log", "A" * (MAX_LINE * 3) + "\nshort\n")
    fs = RootFS(tree.root)
    assert list(fs.iter_lines("/var/log/bad.gz")) == []
    lines = list(fs.iter_lines("/var/log/long.log"))
    assert lines == ["A" * MAX_LINE, "short"]


# ----------------------------------------------------------------------- ReDoS
@pytest.mark.parametrize("payload", [
    b"eval(" + b" " * 200000,
    (b"Q" * 3999 + b"\n") * 400,
    b"<?php " + b"system(" * 50000,
    b"$a=$_POST['x'];" * 20000,
])
def test_webshell_signatures_are_linear(payload):
    started = time.time()
    scan(CONTENT_SIGNATURES, payload)
    assert time.time() - started < 3


@pytest.mark.parametrize("payload", ["nc " * 40000, "curl " * 40000, "base64 -d " * 20000,
                                     "socat " * 40000, "python -c '" * 20000])
def test_command_signatures_are_linear(payload):
    started = time.time()
    scan(COMMAND_SIGNATURES, payload)
    assert time.time() - started < 3


def test_log_parsing_is_linear():
    started = time.time()
    log_sig.parse_access('1.2.3.4 - - [20/Oct/2026:13:22:01 +0000] "GET /' + " " * 60000)
    for rule in log_sig.ERROR_RULES:
        rule.pattern.search("include(" * 8000)
    assert time.time() - started < 3


def test_htaccess_with_unclosed_blocks_is_fast(tree, scan_env):
    tree.write("/var/www/html/.htaccess", "<Files a>\n" * 20000)
    ctx, disc = scan_env()
    started = time.time()
    webroot.run(ctx, disc)
    assert time.time() - started < 3


# ------------------------------------------------------------------- reporting
def test_printable_neutralises_terminal_attacks():
    text = printable("a\x1b[2Jb‮c\udcffd中", 100)
    assert "\x1b" not in text and "‮" not in text and "\udcff" not in text
    assert "\\x1b" in text and "\\u202e" in text and "\\xff" in text and "中" in text


def test_report_survives_hostile_names_and_ascii_terminal():
    raw = io.BytesIO()
    ascii_out = io.TextIOWrapper(raw, encoding="ascii")
    hostile = Finding("t", "R", Severity.CRITICAL, Kind.COMPROMISE, "t—itle",
                      "/var/www/\udcff\x1b[31m.php", "ev中", "d", {"owner": "w\udcfe"})
    TextReport(ascii_out, color=False, min_severity=Severity.INFO).body([hostile])
    ascii_out.flush()
    out = raw.getvalue().decode("ascii")
    assert "\\xff" in out and "\x1b" not in out
    to_json({}, disc_with(), [hostile], __import__("php2shell_scanner.report").report
            .compute_verdict([hostile]), []).encode("ascii")


def test_fmt_time_with_absurd_mtime():
    assert common.fmt_time(2 ** 62) == str(2 ** 62)


# -------------------------------------------------------------- detection gaps
@pytest.mark.parametrize("code, rule", [
    ("<?php \\system($_GET['c']);", "WEB-EXEC-INPUT"),
    ("<?php switch(1){case 1:system($_GET['c']);}", "WEB-EXEC-INPUT"),
    ("<?php system/**/($_GET['c']);", "WEB-EXEC-INPUT"),
    ("<?php eval(/**/$_POST[1]);", "WEB-EVAL-INPUT"),
    ("<?php $a=$_POST['x']; eval($a);", "WEB-TAINTED-EXEC"),
    ("<?php eval(\"?>\".base64_decode($_POST['x']));", "WEB-EVAL-CLOSETAG"),
    ("<?php echo `{$_GET['c']}`;", "WEB-BACKTICK-INPUT"),
    ("<?php eval(getallheaders()['x']);", "WEB-EVAL-INPUT"),
    ("<?php system($_SERVER['HTTP_X_CMD']);", "WEB-EXEC-INPUT"),
])
def test_evasive_variants(code, rule):
    assert rule in hits(code)


@pytest.mark.parametrize("code", [
    "<?php include($_SERVER['DOCUMENT_ROOT'] . '/inc/header.php');",
    "<?php exec($_SERVER['DOCUMENT_ROOT'] . '/bin/convert.sh');",
    "<?php $m = new FilesManager(); $x = $filesManager;",
    "<?php include 'inc/sess_handler.php';",
])
def test_review_false_positives(code):
    strong = {m.signature.rule for m in scan(CONTENT_SIGNATURES, code.encode())
              if m.signature.severity >= Severity.MEDIUM}
    assert strong == set()


@pytest.mark.parametrize("command", [
    "exec 3<>/dev/tcp/127.0.0.1/3306",
    "echo aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ= | base64",
])
def test_command_false_positives(command):
    assert scan(COMMAND_SIGNATURES, command) == []


def test_chattr_on_ordinary_file_is_only_medium():
    found = {m.signature.rule: m.signature.severity
             for m in scan(COMMAND_SIGNATURES, "chattr +i /etc/resolv.conf")}
    assert found == {"CMD-LOCK-FILE": Severity.MEDIUM}
    assert "CMD-LOCK-PERSISTENCE" in {
        m.signature.rule for m in scan(COMMAND_SIGNATURES, "chattr +i /root/.ssh/authorized_keys")}


def test_scanner_own_name_in_logs():
    _, by_rule = __import__("test_logs").run_lines(["sudo python3 -m php2shell_scanner --json x"])
    assert "ERR-IDS-PHP2SHELL" not in by_rule


def test_config_files(tree, scan_env):
    tree.write("/var/www/html/a/.user.ini", "auto_prepend_file =\nauto_append_file = \"\"\n")
    tree.write("/var/www/html/b/.htaccess", "php_value auto_prepend_file none\n"
                                            "<FilesMatch \".+\\.ph(ar|p|tml)$\">\n"
                                            "SetHandler application/x-httpd-php\n</FilesMatch>\n"
                                            "SetHandler none\n")
    tree.write("/var/www/html/c/.htaccess", "Options +ExecCGI\nAddHandler cgi-script .jpg\n")
    ctx, disc = scan_env()
    found = []
    for rel in ("a/.user.ini", "b/.htaccess", "c/.htaccess"):
        path = "/var/www/html/" + rel
        found += scan_config_file(ctx, disc, path, ctx.fs.lstat(path), {})
    assert [(f.rule, f.path) for f in found] == [
        ("WEB-HTACCESS-HANDLER", "/var/www/html/c/.htaccess")]


def test_grant_all_in_mysql_history_is_not_compromise(tree, scan_env):
    tree.write("/root/.mysql_history", "GRANT ALL PRIVILEGES ON wp.* TO 'wp'@'localhost';\n")
    ctx, disc = scan_env()
    assert "DB-HISTORY-ABUSE" not in rules(database.run(ctx, disc))


def test_php_shell_in_git_dir_and_vcs_objects_skipped(tree, scan_env):
    tree.write("/var/www/html/.git/hooks/x.php", "<?php system($_GET['c']);")
    tree.write("/var/www/html/.git/objects/ab/cdef", b"x\x9c" + b"<?php system($_GET[1]);")
    ctx, disc = scan_env()
    paths = {f.path for f in webroot.run(ctx, disc) if f.severity > Severity.INFO}
    assert paths == {"/var/www/html/.git/hooks/x.php"}


def test_payload_in_the_middle_of_a_big_file_is_found(tree, scan_env):
    filler = "<?php\n" + "// padding\n" * 900000
    tree.write("/var/www/html/big.php", filler + "eval($_POST['z']);\n" + "// x\n" * 200000)
    ctx, disc = scan_env(max_file_size=1024 * 1024)
    assert "WEB-EVAL-INPUT" in rules(webroot.run(ctx, disc))


def test_tmp_hiding_spots_and_elf_severity(tree, scan_env):
    tree.write("/tmp/.X11-unix/X0", "payload")
    tree.write("/tmp/.gitx/miner", b"\x7fELF" + b"\x00" * 20, mode=0o755)
    tree.write("/tmp/jna123.tmp", b"\x7fELF" + b"\x00" * 20, mode=0o600)
    tree.write("/tmp/systemd-private-abc/tmp/x.sh", "curl x | sh")
    ctx, disc = scan_env()
    found = {f.path: f for f in tmp_artifacts.run(ctx, disc)}
    assert found["/tmp/.X11-unix/X0"].rule == "TMP-FILE-IN-SOCKET-DIR"
    assert found["/tmp/.gitx/miner"].severity == Severity.HIGH
    assert found["/tmp/jna123.tmp"].severity == Severity.MEDIUM
    assert not any("systemd-private" in p for p in found)


# ------------------------------------------------------------ processes/network
def test_memfd_and_dev_tool_paths():
    memfd = proc(uid=0, name="x", cmd="x", exe="/memfd:payload (deleted)")
    vscode = proc(uid=0, name="node", cmd="node server.js",
                  exe="/root/.vscode-server/bin/abc/node")
    assert "PROC-TMP-EXE" in rules(processes.check_process(memfd, disc_with()))
    assert processes.check_process(vscode, disc_with()) == []


def test_network_internal_peers_not_critical():
    sock = network.Sock("10.0.0.5", 41000, "127.0.0.1", 6379, "ESTABLISHED", 1)
    worker = proc(name="php", cmd="php artisan queue:work", exe="/usr/bin/php8.2")
    shell = proc(name="bash", cmd="bash", exe="/usr/bin/bash")
    assert network.check_socket(sock, worker, disc_with()) == []
    found = network.check_socket(sock, shell, disc_with())
    assert [(f.rule, f.severity) for f in found] == [("NET-SHELL-CONNECTION", Severity.MEDIUM)]
    public = sock._replace(remote_ip="8.8.8.8", remote_port=443)
    assert rules(network.check_socket(public, worker, disc_with())) == {"NET-WEBUSER-CONNECTION"}


# ----------------------------------------------------------------- log logic
def test_404_flood_does_not_hide_real_shell():
    from test_logs import access, run_lines
    lines = [access(uri="/scan{}.php".format(i), status=404) for i in range(1000)]
    lines += [access(method="POST", uri="/uploads/s.php") for _ in range(6)]
    _, by_rule = run_lines(lines)
    assert "LOG-WEBSHELL-TRAFFIC" in by_rule


def test_normal_phpmyadmin_session_is_not_bruteforce():
    from test_logs import access, run_lines
    lines = [access(ip="192.0.2.1", method="POST", uri="/phpmyadmin/index.php")
             for _ in range(35)]
    lines += [access(ip="192.0.2.1", uri="/phpmyadmin/index.php?route=/database/structure")
              for _ in range(40)]
    _, by_rule = run_lines(lines)
    assert "LOG-PMA-BRUTEFORCE" not in by_rule


def test_corrupt_log_does_not_abort_log_check(tree, scan_env):
    from php2shell_scanner.checks import logs
    tree.write("/var/log/nginx/access.log.2.gz", b"\x1f\x8b\x08\x00garbage" * 50)
    tree.write("/var/log/nginx/access.log",
               '1.2.3.4 - - [20/Oct/2026:13:22:01 +0000] "GET /v.php?page=/tmp/sess_abcdef123 '
               'HTTP/1.1" 200 1 "-" "x"\n')
    with gzip.open(tree.path("/var/log/nginx/access.log.3.gz"), "wb") as handle:
        handle.write(b"ok\n")
    ctx, disc = scan_env()
    assert "LOG-LFI-SESSION" in rules(logs.run(ctx, disc))


# ------------------------------------------------------------- second review
@pytest.mark.parametrize("content, expected", [
    ('<FilesMatch "\\.(jpg|php)$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n', True),
    ('<FilesMatch "upload.*">\nSetHandler application/x-httpd-php\n</FilesMatch>\n', True),
    ('<Files "*.png">\nSetHandler application/x-httpd-php\n</Files>\n', True),
    ('<FilesMatch ".+\\.ph(ar|p|tml)$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n',
     False),
    ('SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n', False),
    ("AddType application/x-httpd-php .html\n", False),        # legacy: LOW exposure only
])
def test_htaccess_selector_semantics(tree, scan_env, content, expected):
    tree.write("/var/www/html/up/.htaccess", content)
    ctx, disc = scan_env()
    found = [f for f in webroot.run(ctx, disc) if f.rule == "WEB-HTACCESS-HANDLER"
             and f.severity >= Severity.HIGH]
    assert bool(found) is expected


def test_wordfence_exemption_requires_the_real_file(tree, scan_env):
    tree.write("/var/www/html/.user.ini", "auto_prepend_file = '/var/www/html/wordfence-waf.php'\n")
    tree.write("/var/www/html/wordfence-waf.php", "<?php // Wordfence WAF\n$wfWAF = 1;")
    tree.write("/var/www/html/uploads/.user.ini",
               "auto_prepend_file = '/var/www/html/uploads/wordfence-waf.php'\n")
    tree.write("/var/www/html/uploads/wordfence-waf.php", "<?php @eval($_POST[1]);")
    ctx, disc = scan_env()
    hits = [f.path for f in webroot.run(ctx, disc) if f.rule == "WEB-AUTO-PREPEND"]
    assert hits == ["/var/www/html/uploads/.user.ini"]


@pytest.mark.parametrize("config", [
    {"State": [1], "Config": "x"}, {"Name": ["x"], "MountPoints": [1, 2]},
    {"MountPoints": {"/a": {"Source": ["x"], "Type": "volume", "Name": "../../etc"}}},
])
def test_malformed_container_metadata_is_skipped(tree, config):
    import json as _json
    from php2shell_scanner.containers import discover_containers
    tree.write("/var/lib/docker/containers/a1/config.v2.json", _json.dumps(config))
    tree.write("/var/lib/docker/containers/b2/config.v2.json", "[" * 100000)
    tree.write("/var/lib/docker/containers/c3/config.v2.json",
               _json.dumps({"Name": "/ok", "Config": {"Image": "php:8.2"}}))
    found = discover_containers(RootFS(tree.root))
    names = {c.name for c in found}
    assert "ok" in names and all(isinstance(n, str) for n in names)
    for container in found:
        assert all(not src.startswith("/etc") for src, _ in container.mounts)


def test_root_mount_is_never_a_webroot():
    from php2shell_scanner.containers import log_dirs, web_dirs
    from php2shell_scanner.models import ContainerInfo
    c = ContainerInfo("i", "n", "php", True, "", (("/", "/host"), ("/srv/site", "/blog"),
                                                   ("/srv/logs", "/var/log/nginx")), (), True)
    assert web_dirs(c) == ["/srv/site", "/srv/logs"]
    assert log_dirs(c) == ["/srv/logs"]


def test_report_write_refuses_symlink_and_never_overwrites(tmp_path):
    from php2shell_scanner.cli_common import write_new_report, write_private
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "report.md"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        write_private(str(link), "evidence")
    assert victim.read_text() == "keep me"
    first = write_new_report(str(tmp_path / "auto.md"), "a")
    second = write_new_report(str(tmp_path / "auto.md"), "b")
    assert first != second and open(first).read() == "a"
    existing = tmp_path / "explicit.md"
    existing.write_text("old")
    existing.chmod(0o666)
    write_private(str(existing), "new")
    assert oct(existing.stat().st_mode & 0o777) == "0o600"
