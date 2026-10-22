"""Web server / PHP / WAF log signatures and parsing helpers."""

import re
from datetime import datetime
from functools import lru_cache
from typing import List, NamedTuple, Optional
from urllib.parse import unquote

from php2shell_scanner.models import Kind, Severity

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
A, K = Kind.ATTEMPT, Kind.COMPROMISE


class LogRule(NamedTuple):
    rule: str
    severity: Severity
    kind: str
    title: str
    pattern: "re.Pattern"
    severity_if_2xx: Optional[Severity] = None
    # False: only a 2xx on a specific (non-index) PHP file escalates. Generic Internet
    # scanner noise hits "/" or index.php and must not inflate the verdict.
    escalate_any_2xx: bool = False


def _rule(rule: str, sev: Severity, kind: str, title: str, pattern: str,
          sev_2xx: Optional[Severity] = None, any_2xx: bool = False) -> LogRule:
    return LogRule(rule, sev, kind, title, re.compile(pattern, re.I), sev_2xx, any_2xx)


# Single spaces inside the request field keep matching linear on hostile lines.
ACCESS_RE = re.compile(
    r'^(?:\S{1,255}:\d{1,5} )?(?P<ip>\S{1,64}) \S{1,64} \S{1,256} \[(?P<time>[^\]]{1,64})\] '
    r'"(?P<method>[A-Za-z]{3,12}) (?P<uri>[^\s"]*)(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?:[^"\\]|\\.)*" "(?P<ua>(?:[^"\\]|\\.)*)")?')


class AccessEntry(NamedTuple):
    ip: str
    time: str
    method: str
    uri: str
    status: int
    ua: str
    size: int = 0


def parse_access(line: str) -> Optional[AccessEntry]:
    found = ACCESS_RE.match(line)
    if not found:
        return None
    return AccessEntry(
        ip=found.group("ip"),
        time=found.group("time"),
        method=found.group("method").upper(),
        uri=found.group("uri"),
        status=int(found.group("status")),
        ua=found.group("ua") or "",
        size=int(found.group("size")) if found.group("size").isdigit() else 0,
    )


def decode_uri(uri: str, rounds: int = 3) -> str:
    """Iteratively percent-decode (double-encoding is common in exploits)."""
    current = uri
    for _ in range(rounds):
        decoded = unquote(current.replace("+", " "), encoding="latin-1")
        if decoded == current:
            break
        current = decoded
    return current


# Rules applied to the decoded request URI (or to raw lines in unknown formats).
# php2shell-specific rules keep their severity; generic exploit probes that every
# Internet-facing server receives daily start LOW (see LogRule.escalate_any_2xx).
URI_RULES: List[LogRule] = [
    _rule("LOG-POC-SID", C, A, "Public php2shell PoC session ID seen in a request",
          r"(?:sess_|phpsessid=)(?:exploit[0-9a-f]{20}\b|hugesession0{6,}|consumerpoisoned0{6,})"),
    _rule("LOG-LFI-SESSION", H, A,
          "Request tries to include a PHP session file (php2shell Chain A trigger)",
          r"(?:[=/\\]|\.\.)sess_[a-z0-9,\-]{5,}", C, True),
    _rule("LOG-PMA-LFI", H, A,
          "phpMyAdmin CVE-2018-12613 LFI (classic session-file inclusion vector)",
          r"[?&]target=[^&\s?]{0,300}\?[^&\s]{0,300}?\.\./", C, True),
    _rule("LOG-UPLOAD-PROGRESS", H, A, "PHP_SESSION_UPLOAD_PROGRESS passed in the URL",
          r"php_session_upload_progress"),
    _rule("LOG-SQL-FILEWRITE", H, A, "SQL file-write / MySQL UDF payload in request",
          r"into\s+(?:out|dump)file|general_log_file|set\s+global\s+general_log"
          r"|load_file\s*\(|sys_(?:exec|eval)\s*\(|lib_mysqludf", C, True),
    _rule("LOG-PHPCGI-ARGS", M, A,
          "PHP-CGI argument injection (CVE-2012-1823 / CVE-2024-4577)",
          r"(?:^|[?&\s])(?:-|\xad)d\s*(?:allow_url_include|auto_prepend_file|auto_append_file"
          r"|disable_functions|open_basedir|cgi\.force_redirect)", H),
    _rule("LOG-APP-RCE-PROBE", L, A,
          "Known PHP application RCE probe (ThinkPHP/Laravel/PHPUnit/WP plugins)",
          r"invokefunction|\\think\\(?:app|container|request)|think\\container"
          r"|/_ignition/execute-solution|/vendor/phpunit/phpunit/src/util/php/eval-stdin\.php"
          r"|/wp-file-manager/lib/php/connector\.minimal\.php|/wp-admin/admin-ajax\.php\?action="
          r"(?:revslider_show_image|duplicator_download)|/index\.php\?s=/?index/", M),
    _rule("LOG-CODE-INJECTION", L, A, "PHP code or execution function in request",
          r"<\?php|<\?=|\b(?:system|passthru|shell_exec|proc_open|popen|pcntl_exec|assert|eval"
          r"|create_function|call_user_func(?:_array)?|file_put_contents|base64_decode"
          r"|fsockopen)\s*\(|phpinfo\s*\(\s*\)", M),
    _rule("LOG-CMD-PARAM", L, A, "Shell command passed as a webshell-style parameter",
          r"[?&](?:cmd|command|exec|execute|shell|run|c|e|x|sh|system|passthru|z0|z1|ant|pwn)="
          r"(?:id|whoami|uname(?:\s+-a)?|pwd|ls(?:\s+-[a-z]+)?(?:\s+/\S*)?|cat\s+/\S+|ifconfig"
          r"|ip\s+a(?:ddr)?|netstat\s+-\w+|ps\s+(?:aux|-ef)|hostname|(?:wget|curl)\s+\S+"
          r"|(?:ba)?sh\s+-[ci]\b[^&]{0,200}|nc\s+[^&]{0,200}|python[23]?\s+-c[^&]{0,200}"
          r"|perl\s+-e[^&]{0,200}|echo\s+[^&]{0,200})(?:$|[&;|`\s])", H),
    _rule("LOG-LFI-WRAPPER", L, A, "Local file inclusion / stream wrapper probe",
          r"php://(?:filter|input)|(?:data|expect|phar|zip|glob)://|/proc/self/(?:environ|fd|cmdline)"
          r"|/etc/(?:passwd|shadow)\b|(?:\.\./){3,}|(?:\.\.\\){3,}", M),
]

# Secrets/config files: a 2xx with a body means they were downloaded by someone.
SENSITIVE_FILE = re.compile(
    r"^/(?:[\w.\-]+/)*(?:\.env(?:\.\w+)?|\.git/config|\.svn/entries|wp-config\.php"
    r"(?:\.(?:bak|old|orig|save|swp|txt)|~)|config(?:uration)?\.php\.(?:bak|old|orig|save|txt)"
    r"|\.DS_Store|database\.sql|dump\.sql|backup\.(?:zip|tar\.gz|sql))$", re.I)
# Request-body evidence (ModSecurity audit logs, $request_body in log_format, tcpdump text).
BODY_RULES: List[LogRule] = [
    _rule("BODY-FILENAME-PHP", C, A, "PHP code inside a multipart upload filename (Chain A)",
          r"filename=\\?\"[^\"\n]{0,300}?<\?(?:php|=)"),
    _rule("BODY-FILENAME-SERIALIZED", C, A,
          "Serialized object inside a multipart upload filename (Chain C)",
          r"filename=\\?\"[^\"\n]{0,300}?\|[OaCr]:\d{1,6}:"),
    _rule("BODY-UPLOAD-PROGRESS", H, A, "Multipart body carrying PHP_SESSION_UPLOAD_PROGRESS",
          r"name=\\?\"?php_session_upload_progress"),
    _rule("BODY-SESSID-FIELD", H, A, "PHPSESSID sent as a form field (session fixation)",
          r"name=\\?\"?phpsessid\\?\"?(?:\s|;|\\r|$)"),
    _rule("RESP-LONG-SESSID", H, A,
          "Abnormally long PHPSESSID issued by the server (heap memory leak indicator)",
          r"set-cookie:\s{0,4}phpsessid=[a-z0-9,\-]{64,}"),
]
BODY_TRIGGERS = ("php_session_upload_progress", "filename=", "phpsessid")

UA_TOOLS = re.compile(r"antsword|cknife|caidao|behinder|godzilla|weevely|altman|chopper", re.I)
UA_CRAWLER = re.compile(r"baiduspider|googlebot|bingbot|sogou|360spider|yandexbot", re.I)
UA_SCANNER = re.compile(
    r"sqlmap|nuclei|nikto|acunetix|wpscan|dirbuster|gobuster|fuzz faster|zgrab|masscan", re.I)

PHP_PATH = re.compile(r"\.(?:php\d?|phtml|pht|phar|inc)$", re.I)
PMA_PATH = re.compile(
    r"/(?:phpmyadmin[\w.\-]*|pma|myadmin|phpmy[\w\-]*|mysqladmin|sqladmin|dbadmin)/", re.I)
PMA_SQL_PAGE = re.compile(
    r"/(?:sql|import|export|tbl_sql|db_sql|server_sql|server_import|db_import|tbl_import"
    r"|server_privileges|user_password|server_variables)\.php"
    r"|[?&]route=/(?:sql|import|export|server/sql|server/privileges|server/variables"
    r"|database/sql|table/sql|user-password)", re.I)
PMA_SETUP = re.compile(r"/(?:setup/(?:index\.php|config\.php|frames/)|scripts/setup\.php)", re.I)
# Remainder of a phpMyAdmin URI after its directory that is the login form target.
PMA_LOGIN = re.compile(r"^(?:index\.php)?(?:$|\?(?:route=/?(?:&|$)|(?!.*route=)))", re.I)

# Rules applied to lines that are not access-log entries (error/WAF/IDS logs).
ERROR_RULES: List[LogRule] = [
    _rule("ERR-POC-MARKER", C, K, "php2shell PoC output marker in log",
          r"DESTRUCT!|___START___|TriggerUAF|UAF CONFIRMED|RCE CONFIRMED|rce_proof"),
    _rule("ERR-SESS-DESTROY", C, A,
          "\"Session object destruction failed\" (stale-state exploitation, Chain E)",
          r"Session object destruction failed"),
    _rule("ERR-INCLUDE-SESS", C, A, "PHP tried to include a session file (Chain A LFI)",
          r"(?:include|require)(?:_once)?\(\s{0,8}[^)]{0,300}?sess_"
          r"|Failed opening (?:required )?'[^']{0,300}?sess_|failed to open stream[^\n]{0,300}?sess_"),
    _rule("ERR-SESS-DECODE", H, A, "Session decode failure (handler mismatch / poisoned session)",
          r"Failed to decode session object|session_decode\(\): Failed"
          r"|session_start\(\): Failed to decode"),
    _rule("ERR-OOM-SAPI", H, A,
          "Out-of-memory during request startup (php2shell Chain D/E OOM pattern)",
          r"Allowed memory size of \d+ bytes exhausted[^\n]{0,300}?in Unknown on line 0"),
    _rule("ERR-DISABLED-EXEC", H, A, "Code tried to call a disabled command-execution function",
          r"\b(?:system|passthru|shell_exec|proc_open|popen|pcntl_exec)\(\) has been disabled "
          r"for security reasons"),
    _rule("ERR-BASEDIR-SENSITIVE", H, A, "open_basedir blocked access to a sensitive file",
          r"open_basedir restriction in effect\. File\((?:/etc/(?:passwd|shadow)|/proc/|/root"
          r"|/home/[^/)]+/\.ssh|[^)]*sess_)"),
    _rule("ERR-IDS-PHP2SHELL", H, A, "IDS/WAF alert mentioning php2shell",
          r"php2shell(?![-_]scan)"),
    _rule("ERR-DISABLED-OTHER", M, A, "Code tried to call a disabled dangerous function",
          r"\b(?:exec|putenv|dl|symlink|ini_alter|pcntl_fork)\(\) has been disabled "
          r"for security reasons"),
    _rule("ERR-WORKER-CRASH", M, A, "PHP worker crashed (memory corruption attempts crash workers)",
          r"exited on signal (?:11|6|7|4) \(SIG(?:SEGV|ABRT|BUS|ILL)"
          r"|exit signal (?:Segmentation fault|Aborted)"),
    _rule("ERR-STARTUP-SESSION", M, A, "Session/upload error during PHP request startup",
          r"Request Startup[^\n]{0,300}?(?:session|upload)"),
]

ERROR_TIME_RE = re.compile(
    r"(\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2})"            # PHP
    r"|(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"                    # nginx
    r"|([A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})"  # apache
    r"|(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")                # ISO / json
CLIENT_IP_RE = re.compile(r"client[:\s]+\[?([0-9a-fA-F:.]{7,45}?)(?::\d+)?[\],\s]")

TIME_FORMATS = (
    "%d/%b/%Y:%H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
)


@lru_cache(maxsize=8192)
def parse_time(text: str) -> Optional[float]:
    """Best-effort timestamp parse (timezone offsets ignored); None if unknown."""
    cleaned = re.sub(r"\.\d+", "", text.strip())
    cleaned = re.sub(r"\s*(?:Z|[+-]\d{2}:?\d{2})$", "", cleaned)
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(cleaned, fmt).timestamp()
        except ValueError:
            continue
    return None


def error_time(line: str) -> str:
    found = ERROR_TIME_RE.search(line)
    if not found:
        return ""
    return next(group for group in found.groups() if group)


def error_client_ip(line: str) -> str:
    found = CLIENT_IP_RE.search(line)
    return found.group(1) if found else ""
