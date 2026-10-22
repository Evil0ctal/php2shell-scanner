"""Log parsing and detection, including aggregation and stateful heuristics."""

import pytest

from php2shell_scanner.checks import logs
from php2shell_scanner.models import Kind, Severity
from php2shell_scanner.signatures import logs as sig

from conftest import rules


def access(ip="203.0.113.7", method="GET", uri="/", status=200,
           ua="Mozilla/5.0", time="20/Oct/2026:13:22:01 +0000"):
    return '{} - - [{}] "{} {} HTTP/1.1" {} 512 "-" "{}"'.format(ip, time, method, uri, status, ua)


def run_lines(lines):
    state = logs.State()
    for line in lines:
        logs.process_line(state, line, "/var/log/nginx/access.log")
    findings = logs._hit_findings(state) + logs._aggregate_findings(state)
    return findings, {f.rule: f for f in findings}


def test_parse_access_combined_and_vhost():
    entry = sig.parse_access(access(uri="/a.php?x=1", status=404))
    assert entry.ip == "203.0.113.7" and entry.status == 404 and entry.uri == "/a.php?x=1"
    vhost = sig.parse_access("example.com:443 " + access())
    assert vhost.ip == "203.0.113.7"
    assert sig.parse_access("2026/10/20 13:22:01 [error] 12#12: *1 boom") is None


def test_decode_uri_handles_double_encoding():
    assert sig.decode_uri("/index.php?target=db_sql.php%253f/../../etc/passwd") == \
        "/index.php?target=db_sql.php?/../../etc/passwd"


@pytest.mark.parametrize("uri, rule, severity", [
    ("/vuln.php?page=/tmp/sessions/sess_exploitab12cd34ef56ab78cd90", "LOG-POC-SID",
     Severity.CRITICAL),
    ("/vuln.php?page=/var/lib/php/sessions/sess_abcdef123456", "LOG-LFI-SESSION",
     Severity.CRITICAL),
    ("/phpmyadmin/index.php?target=db_sql.php%253f/../../../../tmp/sess_x1y2z3",
     "LOG-PMA-LFI", Severity.CRITICAL),
    ("/x.php?PHP_SESSION_UPLOAD_PROGRESS=1", "LOG-UPLOAD-PROGRESS", Severity.HIGH),
    ("/pma/import.php?sql_query=select+'<?php'+into+outfile+'/var/www/html/s.php'",
     "LOG-SQL-FILEWRITE", Severity.CRITICAL),
    ("/index.php?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
     "LOG-PHPCGI-ARGS", Severity.MEDIUM),
    ("/php-cgi/php-cgi.php?%ADd+allow_url_include%3d1", "LOG-PHPCGI-ARGS", Severity.HIGH),
    ("/uploads/s.php?cmd=id", "LOG-CMD-PARAM", Severity.HIGH),
    ("/?cmd=id", "LOG-CMD-PARAM", Severity.LOW),
    # generic Internet noise against "/" or index.php stays LOW even with a 200
    ("/index.php?page=../../../../etc/passwd", "LOG-LFI-WRAPPER", Severity.LOW),
    ("/page.php?file=../../../../etc/passwd", "LOG-LFI-WRAPPER", Severity.MEDIUM),
    ("/index.php?s=/index/\\think\\app/invokefunction&function=phpinfo", "LOG-APP-RCE-PROBE",
     Severity.LOW),
    ("/_ignition/execute-solution", "LOG-APP-RCE-PROBE", Severity.LOW),
])
def test_uri_rules(uri, rule, severity):
    _, by_rule = run_lines([access(uri=uri)])
    assert rule in by_rule
    assert by_rule[rule].severity == severity


def test_non_2xx_keeps_base_severity():
    _, by_rule = run_lines([access(uri="/vuln.php?page=/tmp/sess_abcdef123", status=404)])
    assert by_rule["LOG-LFI-SESSION"].severity == Severity.HIGH


def test_benign_requests_produce_nothing():
    findings, _ = run_lines([
        access(uri="/"), access(uri="/wp-login.php", method="POST"),
        access(uri="/index.php?orderby=id&order=asc"), access(uri="/static/app.js"),
        access(uri="/search?q=session+id"), access(uri="/?cmd=list"),
    ])
    assert findings == []


def test_aggregation_counts_ips_and_time_range():
    lines = [access(ip="198.51.100.{}".format(i % 2), uri="/v.php?page=/tmp/sess_abc12345",
                    time="2{}/Oct/2026:10:00:00 +0000".format(i)) for i in range(4)]
    _, by_rule = run_lines(lines)
    hit = by_rule["LOG-LFI-SESSION"]
    assert hit.meta["count"] == 4
    assert set(hit.meta["top_ips"]) == {"198.51.100.0", "198.51.100.1"}
    assert hit.meta["first_seen"].startswith("2026-10-20")
    assert hit.meta["last_seen"].startswith("2026-10-23")


def test_webshell_client_and_fake_crawler_user_agents():
    _, by_rule = run_lines([
        access(method="POST", uri="/uploads/x.php", ua="antSword/v2.1"),
        access(method="POST", uri="/a.php", ua="Mozilla/5.0 (compatible; Baiduspider/2.0)"),
    ])
    assert by_rule["LOG-WEBSHELL-CLIENT"].kind == Kind.COMPROMISE
    assert by_rule["LOG-FAKE-CRAWLER-POST"].severity == Severity.HIGH


def test_webshell_post_only_traffic():
    lines = [access(method="POST", uri="/wp-content/uploads/2026/10/x.php") for _ in range(6)]
    lines += [access(method="POST", uri="/wp-login.php") for _ in range(10)]
    _, by_rule = run_lines(lines)
    assert by_rule["LOG-WEBSHELL-TRAFFIC"].path == "/wp-content/uploads/2026/10/x.php"
    assert "wp-login" not in str(by_rule["LOG-WEBSHELL-TRAFFIC"].evidence)


def test_pma_bruteforce_then_sql_is_critical():
    lines = [access(ip="192.0.2.9", method="POST", uri="/phpmyadmin/index.php", status=200)
             for _ in range(35)]
    lines.append(access(ip="192.0.2.9", uri="/phpmyadmin/index.php?route=/sql&db=x"))
    _, by_rule = run_lines(lines)
    assert by_rule["LOG-PMA-BRUTEFORCE"].severity == Severity.CRITICAL
    assert "192.0.2.9" in by_rule["LOG-PMA-SQL-USAGE"].evidence


def test_pma_logged_in_actions_are_not_login_posts():
    lines = [access(method="POST", uri="/phpmyadmin/index.php?route=/sql") for _ in range(40)]
    _, by_rule = run_lines(lines)
    assert "LOG-PMA-BRUTEFORCE" not in by_rule


def test_post_5xx_burst():
    lines = [access(method="POST", uri="/index.php", status=502) for _ in range(12)]
    _, by_rule = run_lines(lines)
    assert "LOG-POST-5XX-BURST" in by_rule


@pytest.mark.parametrize("line, rule", [
    ("[20-Oct-2026 13:22:01 UTC] PHP Warning:  session_start(): Session object destruction "
     "failed in Unknown on line 0", "ERR-SESS-DESTROY"),
    ("[20-Oct-2026 13:22:01 UTC] PHP Warning:  include(/tmp/sessions/sess_exploit123): Failed "
     "to open stream", "ERR-INCLUDE-SESS"),
    ("PHP Fatal error:  Allowed memory size of 33554432 bytes exhausted (tried to allocate 4096 "
     "bytes) in Unknown on line 0", "ERR-OOM-SAPI"),
    ("PHP Warning:  system() has been disabled for security reasons in /x.php on line 1",
     "ERR-DISABLED-EXEC"),
    ("[20-Oct-2026 13:22:01] WARNING: [pool www] child 1234 exited on signal 11 (SIGSEGV) "
     "after 12.3 seconds from start", "ERR-WORKER-CRASH"),
    ('10/20/2026-13:22:01  [**] [1:9000001:1] ET WEB php2shell upload_progress exploit [**]',
     "ERR-IDS-PHP2SHELL"),
    ("DESTRUCT! cmd=id", "ERR-POC-MARKER"),
])
def test_error_rules(line, rule):
    _, by_rule = run_lines([line])
    assert rule in by_rule


def test_nginx_error_line_with_request_and_client_ip():
    line = ('2026/10/20 13:22:01 [error] 7#7: *9 FastCGI sent in stderr: "PHP message: PHP '
            'Warning:  include(/tmp/sess_abcdef1234): Failed to open stream" while reading, '
            'client: 203.0.113.50, server: _, request: "GET /v.php?page=/tmp/sess_abcdef1234 '
            'HTTP/1.1"')
    _, by_rule = run_lines([line])
    assert "203.0.113.50" in by_rule["ERR-INCLUDE-SESS"].meta["top_ips"]
    assert "LOG-LFI-SESSION" in by_rule


def test_scanner_own_name_is_not_an_ids_hit():
    _, by_rule = run_lines(["downloaded php2shell-scanner release"])
    assert "ERR-IDS-PHP2SHELL" not in by_rule


def test_run_reads_rotated_gzip_logs(tree, scan_env):
    tree.write("/var/log/nginx/access.log",
               access(uri="/v.php?page=/tmp/sess_abcdef123456") + "\n")
    tree.write("/var/log/nginx/access.log.2.gz",
               (access(uri="/v.php?page=/tmp/sess_abcdef654321") + "\n").encode(), gz=True)
    ctx, disc = scan_env()
    findings = logs.run(ctx, disc)
    lfi = [f for f in findings if f.rule == "LOG-LFI-SESSION"][0]
    assert lfi.meta["count"] == 2
    assert "LOG-COVERAGE" in rules(findings)


def test_parse_time_formats():
    assert sig.parse_time("20/Oct/2026:13:22:01 +0000") is not None
    assert sig.parse_time("2026-10-20T13:22:01.123+00:00") is not None
    assert sig.parse_time("Tue Oct 20 13:22:01.123456 2026") is not None
    assert sig.parse_time("garbage") is None


@pytest.mark.parametrize("line, rule", [
    ('--abc--C--\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"',
     "BODY-UPLOAD-PROGRESS"),
    ('Content-Disposition: form-data; name="f"; filename="<?php system($_GET[1]);?>"',
     "BODY-FILENAME-PHP"),
    ('Content-Disposition: form-data; name="f"; filename="x|O:4:\\"Evil\\":1:{}"',
     "BODY-FILENAME-SERIALIZED"),
    ('Content-Disposition: form-data; name="PHPSESSID"', "BODY-SESSID-FIELD"),
    ("Set-Cookie: PHPSESSID=" + "a" * 80 + "; path=/", "RESP-LONG-SESSID"),
    ("Content-Type: multipart/form-data, boundary=X", "BODY-CT-SEPARATOR"),
    ("Content-Type: multipart/form-data,boundary=X", "BODY-CT-SEPARATOR"),
    ("Content-Type: multipart/form-data boundary=X", "BODY-CT-SEPARATOR"),
])
def test_request_body_and_response_iocs(line, rule):
    _, by_rule = run_lines([line])
    assert rule in by_rule


def test_standard_multipart_separator_is_not_flagged():
    # The legitimate "; boundary=" separator must never trip the evasion rule.
    _, by_rule = run_lines(['Content-Type: multipart/form-data; boundary=----WebKitX'])
    assert "BODY-CT-SEPARATOR" not in by_rule


def test_sensitive_file_served_and_soft_404():
    _, by_rule = run_lines([access(uri="/", status=200).replace(" 512 ", " 900 "),
                            access(uri="/.env", status=200).replace(" 512 ", " 1337 ")])
    assert by_rule["LOG-SENSITIVE-FILE-SERVED"].kind == Kind.EXPOSURE
    # an SPA answering every path with the same index page is not a leak
    _, soft = run_lines([access(uri="/", status=200), access(uri="/.env", status=200)])
    assert "LOG-SENSITIVE-FILE-SERVED" not in soft


def test_docker_json_logs_are_unwrapped(tree, scan_env):
    import json as _json
    inner = access(uri="/v.php?page=/tmp/sess_abcdef123456")
    tree.write("/var/lib/docker/containers/abc/abc-json.log",
               _json.dumps({"log": inner + "\n", "stream": "stdout"}) + "\n")
    ctx, disc = scan_env(extra_logs=("/var/lib/docker/containers/abc/abc-json.log",))
    assert "LOG-LFI-SESSION" in rules(logs.run(ctx, disc))



def test_phpmyadmin_used_only_through_local_proxy_is_info():
    lines = [access(ip="127.0.0.1", uri="/phpmyadmin_41a2/index.php?route=/sql&db=x")
             for _ in range(3)]
    _, by_rule = run_lines(lines)
    assert by_rule["LOG-PMA-SQL-USAGE"].severity == Severity.INFO
