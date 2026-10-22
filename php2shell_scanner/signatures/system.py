"""Patterns for malicious commands in cron, systemd units, shell rc files and cmdlines."""

import re
from typing import List

from php2shell_scanner.models import Kind, Severity
from php2shell_scanner.signatures import Signature

C, H, M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM
K = Kind.COMPROMISE


def _sig(rule: str, sev: Severity, title: str, pattern: str) -> Signature:
    return Signature(rule, sev, K, title, re.compile(pattern, re.I | re.M))


# Gaps are bounded ({0,300}) so repeated keywords cannot cause quadratic backtracking.
COMMAND_SIGNATURES: List[Signature] = [
    _sig("CMD-DOWNLOAD-EXEC", C, "Downloads and pipes a script into a shell",
         r"(?:curl|wget|fetch)\b[^\n|;]{0,300}\|\s{0,8}(?:sudo\s{1,8})?(?:ba|da|z|k)?sh\b"),
    _sig("CMD-DOWNLOAD-RUN", C, "Downloads a file then executes it",
         r"(?:curl|wget)\b[^\n]{0,300}?\s-[oO]\s{0,8}\S{1,200}[^\n]{0,300}?(?:;|&&)\s{0,8}"
         r"(?:chmod\s{1,8}[+0-7]{0,4}x?|sh\s|bash\s|\./)"),
    _sig("CMD-BASE64-EXEC", C, "Executes base64-decoded payload",
         r"base64\s{1,8}(?:-d|--decode|-D)[^\n]{0,300}?\|\s{0,8}(?:ba|da)?sh\b"),
    _sig("CMD-DEV-TCP", C, "Bash /dev/tcp reverse shell",
         r"/dev/(?:tcp|udp)/(?!127\.|localhost/)[\w.\-]{1,253}/\d{1,5}"),
    _sig("CMD-NC-EXEC", C, "netcat with -e/-c (reverse/bind shell)",
         r"\b(?:nc|ncat|netcat)\b[^\n]{0,300}?\s-(?:e|c)\s"),
    _sig("CMD-SCRIPT-SOCKET", C, "Inline Python/Perl/PHP/Ruby socket shell",
         r"(?:python[23]?|perl|ruby|php)\s{1,8}-[cerR]\s{0,8}['\"][^\n]{0,300}?"
         r"(?:socket|fsockopen|TCPSocket|pty\.spawn)"),
    _sig("CMD-SOCAT-EXEC", C, "socat exec shell", r"\bsocat\b[^\n]{0,300}?exec:"),
    _sig("CMD-MINER", C, "Cryptocurrency miner",
         r"stratum\+(?:tcp|ssl)://|\bxmrig\b|\bminerd\b|cpuminer|--donate-level|cryptonight"
         r"|supportxmr|c3pool|moneroocean|nanopool\.org|minexmr|hashvault"),
    _sig("CMD-LOCK-PERSISTENCE", H, "Makes persistence files immutable (chattr +i/+a)",
         r"chattr\s{1,8}\+[ia]\w{0,4}\s[^\n]{0,200}?(?:authorized_keys|cron|passwd|shadow"
         r"|ld\.so\.preload|/tmp/|/var/tmp/|/dev/shm/|\.service\b)"),
    _sig("CMD-ANTI-FORENSICS", H, "Disables shell history / wipes logs",
         r"history\s{1,8}-c|unset\s{1,8}HISTFILE|HISTFILE=/dev/null"
         r"|>\s{0,8}/var/log/(?:wtmp|btmp|lastlog|auth\.log|secure)\b"),
    _sig("CMD-LOCK-FILE", M, "Makes files immutable (chattr +i/+a)", r"chattr\s{1,8}\+[ia]\b"),
    _sig("CMD-TMP-EXEC", M, "Executes something from a temp directory",
         r"(?:^\s{0,16}|[;&|`]\s{0,8}|\b(?:ba|da)?sh\s{1,8}|\bnohup\s{1,8}|\bexec\s{1,8})"
         r"(?:/tmp|/var/tmp|/dev/shm)/[^\s;|&]{1,200}"),
    _sig("CMD-RAW-IP-URL", M, "Fetches from a raw IP address URL",
         r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
         r"\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?/"),
    _sig("CMD-PASTE-SITE", M, "Fetches from a paste/tunnel service",
         r"pastebin\.com/raw|transfer\.sh|ngrok\.io|termbin\.com|hastebin|paste\.ee"),
]

SHELL_NAMES = frozenset(("sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "busybox"))
NETTOOL_NAMES = frozenset(("nc", "ncat", "netcat", "socat", "telnet", "curl", "wget"))
INTERPRETER_NAMES = frozenset((
    "python", "python2", "python3", "perl", "ruby", "lua", "node", "php",
))
WEB_SERVER_NAMES = frozenset((
    "nginx", "apache2", "httpd", "lighttpd", "caddy", "litespeed", "lshttpd", "openlitespeed",
    "php-fpm", "php-cgi", "lsphp", "hhvm", "uwsgi", "gunicorn", "unitd", "frankenphp",
))
MINING_PORTS = frozenset((3333, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700))


def is_web_server_name(name: str) -> bool:
    base = name.split(":")[0].strip()
    if base in WEB_SERVER_NAMES:
        return True
    return bool(re.match(r"^(?:php[\d.]*-fpm[\d.]*|php-cgi[\d.]*|lsphp[\d.]*)$", base))
