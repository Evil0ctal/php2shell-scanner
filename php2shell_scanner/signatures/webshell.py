"""Byte-level signatures for PHP webshells, backdoors and exploit leftovers.

Signatures are deliberately structural (request input flowing into an
execution sink) rather than keyword based, to keep false positives low on large
CMS installs. A file matching two or more HIGH signatures is escalated to
CRITICAL by the caller.

Every quantifier that can meet attacker-controlled content is bounded, so a
crafted file cannot make the scanner backtrack for hours (ReDoS).
"""

import re
from typing import List

from php2shell_scanner.models import Kind, Severity
from php2shell_scanner.signatures import Signature

C, H, M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM

# Whitespace, "@" error suppression and short /* */ comments: `system/**/(@$_GET[1])`.
GAP = rb"(?:[\s@]|/\*[^*]{0,64}\*/){0,64}"
# Request input. $_SERVER only counts for client-controlled keys.
SG_ARR = (rb"(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
          rb"|\$\{\s{0,8}['\"]_(?:GET|POST|REQUEST|COOKIE)['\"]\s{0,8}\}"
          rb"|\$GLOBALS\s{0,8}\[\s{0,8}['\"]_(?:GET|POST|REQUEST|COOKIE)['\"]\s{0,8}\])")
SG_SERVER = (rb"\$_SERVER\s{0,8}\[\s{0,8}['\"](?:HTTP_\w{1,64}|QUERY_STRING|REQUEST_URI"
             rb"|PHP_AUTH_\w{1,16}|PATH_INFO|argv)['\"]\s{0,8}\]")
HEADERS = rb"(?:getallheaders|apache_request_headers)\s{0,8}\(\s{0,8}\)"
SG = rb"(?:" + SG_ARR + rb"|" + SG_SERVER + rb"|" + HEADERS + rb")"
INDEX = rb"\s{0,8}\[[^\]]{1,64}\]"
SG_ITEM = rb"(?:" + SG_ARR + INDEX + rb"|" + SG_SERVER + rb"|" + HEADERS + INDEX + rb")"
# Optional decoding wrappers between the sink and the input.
DECODERS = (rb"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|stripslashes"
            rb"|urldecode|rawurldecode|hex2bin|trim|html_entity_decode)")
WRAP = rb"(?:" + GAP + DECODERS + GAP + rb"\()*" + GAP
EXEC_SINKS = rb"(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)"
SINK_OPEN = GAP + rb"\("
# Backticks only execute in an expression (`<?=`, echo, assignment, call argument);
# docblocks use them as markdown ("coming from `$_POST['x']`").
BACKTICK_CONTEXT = rb"(?:<\?=|\becho\b|\bprint\b|\breturn\b|[=(.,])\s{0,16}"
# Not a method call or a variable function: "->exec(", "$exec(". A leading "\" (global
# namespace) or ":" (case label) still counts as a call.
NOT_MEMBER = rb"(?<![\w>$])"


def _sig(rule: str, sev: Severity, kind: str, title: str, pattern: bytes,
         flags: int = 0) -> Signature:
    return Signature(rule, sev, kind, title, re.compile(pattern, flags))


CK = Kind.COMPROMISE

CONTENT_SIGNATURES: List[Signature] = [
    _sig("WEB-EVAL-INPUT", C, CK, "eval/assert of HTTP request input",
         NOT_MEMBER + rb"\b(?:eval|assert)" + SINK_OPEN + WRAP + SG, re.I),
    _sig("WEB-EVAL-CLOSETAG", C, CK, "eval('?>' . <request input>)",
         NOT_MEMBER + rb"\beval" + SINK_OPEN + GAP + rb"['\"]\?>['\"]" + GAP + rb"\." + WRAP + SG,
         re.I),
    _sig("WEB-EXEC-INPUT", C, CK, "OS command execution of HTTP request input",
         NOT_MEMBER + rb"\b" + EXEC_SINKS + SINK_OPEN + WRAP + SG, re.I),
    _sig("WEB-BACKTICK-INPUT", C, CK, "Backtick shell execution of request input",
         BACKTICK_CONTEXT + rb"`\s{0,8}\{?\s{0,8}\$_(?:GET|POST|REQUEST|COOKIE)\s{0,8}"
         rb"\[[^\]`]{1,40}\]\s{0,8}\}?\s{0,8}`"),
    _sig("WEB-INPUT-AS-FUNC", C, CK, "Function name taken from request input",
         SG_ITEM + rb"\(", re.I),
    _sig("WEB-CALLBACK-INPUT", C, CK, "Callback taken from request input",
         rb"\b(?:call_user_func(?:_array)?|array_map|register_shutdown_function"
         rb"|register_tick_function|forward_static_call(?:_array)?)" + SINK_OPEN + WRAP + SG,
         re.I),
    _sig("WEB-CREATE-FUNC-INPUT", C, CK, "create_function() built from request input",
         rb"\bcreate_function\s{0,16}\([^;]{0,200}?" + SG, re.I),
    _sig("WEB-EVAL-PHPINPUT", C, CK, "eval of raw request body (php://input)",
         rb"\b(?:eval|assert)\s{0,16}\([^;]{0,200}?php://input", re.I),
    _sig("WEB-BEHINDER", C, CK, "Behinder webshell",
         rb"e45e329feb5d925b|\$_SESSION\[\s{0,8}['\"]k['\"]\s{0,8}\]\s{0,8}=\s{0,8}\$key"),
    _sig("WEB-GODZILLA", C, CK, "Godzilla webshell",
         rb"3c6e0b8a9c15224a|\$_SESSION\[\s{0,8}\$payloadName\s{0,8}\]"),
    _sig("WEB-REVSHELL", C, CK, "Reverse/bind shell code",
         rb"/bin/(?:ba)?sh\s{1,8}-i\b|/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    _sig("WEB-SESSION-INCLUDE", C, CK, "Code that includes a PHP session file",
         rb"\b(?:include|require)(?:_once)?[\s(]{0,8}[^;\n]{0,160}?/sess_(?:['\"]\s{0,8}\.|\$|\{)",
         re.I),
    _sig("WEB-INCLUDE-NONPHP", H, CK, "include/require of an image/text file (hidden payload)",
         rb"\b(?:include|require)(?:_once)?[\s(]{0,8}@?\s{0,8}['\"][^'\"\n]{1,300}\."
         rb"(?:ico|png|jpe?g|gif|bmp|txt|log|tmp|dat|bak|css|js|json|svg|zip|pdf|mp3|woff2?)['\"]",
         re.I),
    _sig("WEB-INCLUDE-ENCODED", H, CK, "include/require of a hex/octal-escaped path",
         rb"\b(?:include|require)(?:_once)?[\s(]{0,8}@?\s{0,8}\"(?:[^\"\n]{0,40}?"
         rb"(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3})){4}", re.I),
    _sig("WEB-POC-MARKER", C, CK, "php2shell PoC / exploit marker",
         rb"___START___|rce_proof|TriggerUAF"),
    _sig("WEB-FILE-WRITE-INPUT", H, CK, "Writes request input into a file",
         rb"\b(?:file_put_contents|fwrite|fputs)" + SINK_OPEN + WRAP + SG
         + rb"[^;]{0,160}?" + SG, re.I),
    _sig("WEB-TAINTED-EXEC", H, CK, "Request input stored in a variable, then executed",
         rb"\$(\w{1,30})\s{0,8}=" + WRAP + SG + rb"[^;]{0,100};.{0,300}?" + NOT_MEMBER
         + rb"\b(?:eval|assert|" + EXEC_SINKS[3:-1] + rb")" + SINK_OPEN + WRAP + rb"\$\1\b",
         re.I | re.S),
    _sig("WEB-VAR-FUNC-INPUT", H, CK, "Variable function name assigned from request input",
         rb"\$(\w{1,30})\s{0,8}=\s{0,8}" + SG_ITEM + rb"\s{0,8};[^\n]{0,200}?\$\1\s{0,8}\(", re.I),
    _sig("WEB-PREG-E", H, CK, "preg_replace() with /e (code-evaluating) modifier",
         rb"preg_replace\s{0,8}\(\s{0,8}(['\"])(.)(?:(?!\1)[^\n]){0,200}?\2[a-zA-Z]{0,8}e"
         rb"[a-zA-Z]{0,8}\1\s{0,8},", re.I),
    _sig("WEB-OBFUSCATED-EVAL", H, CK, "eval/assert of decoded/obfuscated data",
         rb"\b(?:eval|assert)" + SINK_OPEN + GAP + rb"(?:gzinflate|gzuncompress|gzdecode|str_rot13"
         rb"|base64_decode|strrev|convert_uudecode|hex2bin|pack|rawurldecode|urldecode)\s{0,8}\(",
         re.I),
    _sig("WEB-REVSHELL-SOCK", H, CK, "Socket connection combined with shell execution",
         rb"fsockopen\s{0,8}\([^;]{0,200};.{0,600}?(?:proc_open|shell_exec|\bexec\s{0,8}\("
         rb"|popen\s{0,8}\(|/bin/(?:ba)?sh)", re.I | re.S),
    _sig("WEB-KNOWN-KIT", H, CK, "Known webshell kit marker",
         rb"c99shell|r57shell|b374k|IndoXploit|\bFilesMan\b|\bWSO\s?[245]\.\d|ALFA_DATA|AlfaTeam"
         rb"|Alfa\s?Shell|phpspy|AnonymousFox|Mini\s?Shell\b|antSword|Cknife|\bcaidao\b", re.I),
    _sig("WEB-CHR-OBFUSCATION", H, CK, "Heavy chr() string obfuscation",
         rb"(?:chr\s{0,4}\(\s{0,4}\d{1,3}\s{0,4}\)\s{0,4}\.\s{0,4}){12,}", re.I),
    _sig("WEB-GLOBALS-HEX", H, CK, "Hex-encoded $GLOBALS access (obfuscated shell)",
         rb"\$\{\s{0,8}['\"]\\x47\\x4c\\x4f\\x42", re.I),
    _sig("WEB-POC-GADGET", H, CK, "php2shell lab gadget class (Evil::__destruct)",
         rb"class\s{1,8}Evil\b"),
    _sig("WEB-VAR-CALL-INPUT", M, CK, "Variable function called with request input",
         rb"\$(?!_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION|ENV)\b)\w{1,30}\s{0,8}\("
         + WRAP + SG, re.I),
    _sig("WEB-FILE-WRITE-ONE", M, CK, "File write sink fed by request input",
         rb"\b(?:file_put_contents|fwrite|fputs)\s{0,8}\([^;]{0,200}?" + SG, re.I),
    _sig("WEB-INCLUDE-INPUT", H, Kind.EXPOSURE, "include/require of request input (LFI sink)",
         rb"\b(?:include|require)(?:_once)?[\s(]{0,8}" + WRAP + SG, re.I),
]

# The look-behind anchors attempts at the start of a run, keeping this linear.
LONG_BLOB = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{4000,}")
EVAL_LIKE = re.compile(rb"\b(?:eval|assert|create_function)\s{0,8}\(", re.I)
XOR_STRING = re.compile(rb"(['\"])[^'\"\n]{1,10}\1\s{0,8}\^\s{0,8}(['\"])[^'\"\n]{1,10}\2")
PHP_OPEN_TAG = re.compile(rb"<\?(?:php\b|=)", re.I)
PHPINFO = re.compile(rb"\bphpinfo\s{0,8}\(", re.I)
TINY_EXEC = re.compile(NOT_MEMBER + rb"\b" + EXEC_SINKS + SINK_OPEN + rb"|" + BACKTICK_CONTEXT
                       + rb"`[^`\n]{1,200}`", re.I)
MYSQL_GENERAL_LOG = re.compile(rb"Tcp port: \d+\s+Unix socket:")
ID_OUTPUT = re.compile(
    rb"uid=\d+\((?:www-data|apache|nginx|www|nobody|http|httpd|daemon|wwwrun|lighttpd)\)")

PHP_EXTENSIONS = frozenset((
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phar",
    ".phps", ".inc",
))
CGI_EXTENSIONS = frozenset((".cgi", ".pl", ".py", ".fcgi", ".fpl", ".rb"))
MEDIA_EXTENSIONS = frozenset((
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tif", ".tiff",
    ".txt", ".log", ".tmp", ".dat", ".bak", ".css", ".zip", ".pdf", ".mp3", ".mp4",
    ".doc", ".docx", ".xls", ".xlsx", ".rar",
))
# Lower-case directory names used for user uploads. Matched case-sensitively so code
# namespaces such as "Plugins/Import/Upload/" are not mistaken for upload folders.
UPLOAD_DIR_NAMES = frozenset((
    "upload", "uploads", "uploaded", "user-uploads", "userfiles", "images", "img",
    "attachment", "attachments", "avatar", "avatars", "pictures", "photos",
))
# App-specific user-upload locations (Drupal multisite, Magento, Laravel, OpenCart,
# EmpireCMS, Discuz!, Typecho).
UPLOAD_PATH_MARKERS = re.compile(
    r"/sites/[^/]+/files/|/pub/media/|/storage/app/public/|/public/storage/|/image/catalog/"
    r"|/d/file/|/data/attachment/|/usr/uploads/|/wp-content/uploads/")
