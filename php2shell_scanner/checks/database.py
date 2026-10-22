"""MySQL/MariaDB and phpMyAdmin: what an attacker does after getting into phpMyAdmin.

Typical post-exploitation: SELECT ... INTO OUTFILE webshells, the general_log
trick (point the query log at a .php file), and UDF libraries (sys_exec) for
command execution as the mysql user.
"""

import os
import re
from typing import List, Optional

from php2shell_scanner.checks.common import file_meta
from php2shell_scanner.context import ScanContext
from php2shell_scanner.discovery import read_configs
from php2shell_scanner.fs import path_under
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable, snippet_around
from php2shell_scanner.signatures import webshell as ws

NAME = "database"
DESCRIPTION = "MySQL UDF backdoors, general_log/OUTFILE webshells, phpMyAdmin remnants"

PLUGIN_GLOBS = (
    "/usr/lib/mysql/plugin", "/usr/lib64/mysql/plugin", "/usr/lib/*/mariadb*/plugin",
    "/usr/lib/mariadb/plugin", "/usr/lib64/mariadb/plugin", "/usr/local/mysql/lib/plugin",
    "/www/server/mysql/lib/plugin", "/usr/lib/*/mysql/plugin",
)
CNF_GLOBS = (
    "/etc/my.cnf", "/etc/mysql/my.cnf", "/etc/mysql/*.cnf", "/etc/mysql/*/*.cnf",
    "/etc/my.cnf.d/*.cnf", "/usr/local/mysql/my.cnf", "/www/server/mysql/my.cnf",
)
DATA_DIRS = ("/var/lib/mysql", "/www/server/data", "/usr/local/mysql/data", "/data/mysql")
PMA_DIRS = (
    "/usr/share/phpmyadmin", "/usr/share/phpMyAdmin", "/var/www/html/phpmyadmin",
    "/var/www/phpmyadmin", "/www/server/phpmyadmin", "/etc/phpmyadmin", "/var/lib/phpmyadmin",
    "/usr/local/phpmyadmin",
)
UDF_MARKERS = re.compile(rb"sys_exec|sys_eval|lib_mysqludf|do_system|raptor_udf")
UDF_NAME = re.compile(r"(?:lib_mysqludf|raptor_udf|^udf\d*\.(?:so|dll)$|mysqludf)", re.I)
LOG_FILE_SETTING = re.compile(
    r"^\s*(general[_-]log[_-]file|slow[_-]query[_-]log[_-]file|log[_-]error)\s*=\s*(\S+)",
    re.I | re.M)
SECURE_FILE_PRIV_EMPTY = re.compile(r"^\s*secure[_-]file[_-]priv\s*=\s*(?:\"\"|'')?\s*$", re.I | re.M)
HISTORY_ABUSE = re.compile(
    r"into\s{1,8}(?:out|dump)file|general_log|load_file\s{0,8}\(|sys_(?:exec|eval)"
    r"|create\s{1,8}function[^\n]{0,200}?soname", re.I)
PMA_VERSION_PATTERNS = (
    ("libraries/classes/Version.php", re.compile(r"VERSION\s*=\s*'([\d.]+)")),
    ("libraries/Config.php", re.compile(r"PMA_VERSION'\s*,\s*'([\d.]+)")),
    ("libraries/classes/Config.php", re.compile(r"PMA_VERSION'\s*,\s*'([\d.]+)")),
    ("ChangeLog", re.compile(r"^([\d.]+)\s*\(", re.M)),
)
ALLOW_NO_PASSWORD = re.compile(r"^\s*\$cfg\[[^\n]*\['AllowNoPassword'\]\s*=\s*true", re.I | re.M)


def check_udf(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for pattern in PLUGIN_GLOBS:
        for directory in ctx.fs.glob(pattern):
            for path, st in ctx.fs.walk(directory, max_depth=1, max_entries=5000):
                data = ctx.fs.read_bytes(path, ctx.max_file_size) or b""
                marker = UDF_MARKERS.search(data)
                if marker or UDF_NAME.search(os.path.basename(path)):
                    findings.append(Finding(
                        NAME, "DB-UDF-BACKDOOR", Severity.CRITICAL, Kind.COMPROMISE,
                        "MySQL UDF command-execution library in the plugin directory", path,
                        printable(marker.group(0)) if marker else os.path.basename(path),
                        "UDFs like sys_exec() let anyone with SQL access run OS commands. "
                        "Check mysql.func for registered functions.", file_meta(ctx, disc, st)))
    return findings


def check_mysql_config(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for path, text in read_configs(ctx.fs, CNF_GLOBS):
        for found in LOG_FILE_SETTING.finditer(text):
            target = found.group(2).strip("'\"")
            if target.lower().endswith((".php", ".phtml", ".phar")) or path_under(
                    target, disc.webroots):
                findings.append(Finding(
                    NAME, "DB-LOG-TO-WEBROOT", Severity.CRITICAL, Kind.COMPROMISE,
                    "MySQL log file pointed at a PHP file / web root", path,
                    printable(found.group(0)),
                    "Classic phpMyAdmin webshell trick: log queries containing PHP code into a "
                    "file the web server executes."))
        if SECURE_FILE_PRIV_EMPTY.search(text):
            findings.append(Finding(
                NAME, "DB-SECURE-FILE-PRIV", Severity.MEDIUM, Kind.EXPOSURE,
                "secure_file_priv is empty (INTO OUTFILE may write anywhere)", path,
                detail="Set secure_file_priv to a dedicated directory."))
    return findings


def check_datadir(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for directory in DATA_DIRS:
        for path, st in ctx.fs.walk(directory, max_depth=2, max_entries=200000):
            ext = os.path.splitext(path)[1].lower()
            if not (ext in ws.PHP_EXTENSIONS or ext in ("", ".txt")) or st.st_size > 1048576:
                continue
            data = ctx.fs.read_bytes(path, 65536) or b""
            tag = ws.PHP_OPEN_TAG.search(data)
            if tag:
                findings.append(Finding(
                    NAME, "DB-OUTFILE-IN-DATADIR", Severity.HIGH, Kind.COMPROMISE,
                    "PHP code written into the MySQL data directory (INTO OUTFILE)", path,
                    snippet_around(data, tag.start(), tag.end()), "",
                    file_meta(ctx, disc, st)))
    return findings


def check_history(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    homes = {u.home for u in disc.users if u.home and u.home != "/"} | {"/root"}
    for home in sorted(homes):
        for name in (".mysql_history", ".mariadb_history"):
            path = os.path.join(home, name)
            text = ctx.fs.read_text(path, 4 * 1024 * 1024)
            if not text:
                continue
            normalized = text.replace("\\040", " ")
            found = HISTORY_ABUSE.search(normalized)
            if found:
                findings.append(Finding(
                    NAME, "DB-HISTORY-ABUSE", Severity.HIGH, Kind.COMPROMISE,
                    "MySQL client history contains file-write/UDF/grant statements", path,
                    snippet_around(normalized, found.start(), found.end()),
                    "Verify these statements were run by you.",
                    file_meta(ctx, disc, ctx.fs.lstat(path))))
    return findings


def pma_version(ctx: ScanContext, directory: str) -> Optional[str]:
    for release in ctx.fs.glob(os.path.join(directory, "RELEASE-DATE-*")):
        return release.rsplit("RELEASE-DATE-", 1)[-1]
    for rel, regex in PMA_VERSION_PATTERNS:
        text = ctx.fs.read_text(os.path.join(directory, rel), 256 * 1024) or ""
        found = regex.search(text)
        if found:
            return found.group(1)
    return None


def _version_tuple(version: str) -> tuple:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:3])


def check_phpmyadmin(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    dirs = list(PMA_DIRS) + ctx.fs.glob("/www/server/phpmyadmin/phpmyadmin_*")
    seen = set()
    for directory in dirs:
        st = ctx.fs.stat(directory)  # follows symlinks: dedupe by inode, not by name
        if st is None or not ctx.fs.isdir(directory) or (st.st_dev, st.st_ino) in seen:
            continue
        seen.add((st.st_dev, st.st_ino))
        for config in ctx.fs.glob(os.path.join(directory, "config*.inc.php")) + ctx.fs.glob(
                os.path.join(directory, "config/config.inc.php")):
            if ALLOW_NO_PASSWORD.search(ctx.fs.read_text(config, 256 * 1024) or ""):
                findings.append(Finding(
                    NAME, "DB-PMA-NOPASSWORD", Severity.MEDIUM, Kind.EXPOSURE,
                    "phpMyAdmin allows login without password", config))
        if not ctx.fs.isfile(os.path.join(directory, "index.php")):
            continue  # config/state directory, not an installation
        version = pma_version(ctx, directory)
        findings.append(Finding(
            NAME, "DB-PMA-PRESENT", Severity.LOW, Kind.EXPOSURE,
            "phpMyAdmin installation present{}".format(" (version {})".format(version)
                                                       if version else ""), directory,
            detail="phpMyAdmin is the usual way in to MySQL and to an LFI. Delete it if you "
                   "no longer need it - it becomes reachable again whenever PHP is installed."))
        if version and _version_tuple(version)[:2] == (4, 8) and _version_tuple(version) < (4, 8, 2):
            findings.append(Finding(
                NAME, "DB-PMA-CVE-2018-12613", Severity.HIGH, Kind.EXPOSURE,
                "phpMyAdmin {} has CVE-2018-12613 LFI (session-file inclusion)".format(version),
                directory, detail="This LFI + a poisoned session file = php2shell Chain A RCE. "
                                  "Search logs for LOG-PMA-LFI hits."))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    return (check_udf(ctx, disc) + check_mysql_config(ctx, disc) + check_datadir(ctx, disc)
            + check_history(ctx, disc) + check_phpmyadmin(ctx, disc))
