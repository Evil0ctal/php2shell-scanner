"""Web server, PHP, WAF and IDS logs.

Access logs do not contain POST bodies, so the multipart payload itself is
invisible; what *is* visible is the LFI trigger, phpMyAdmin abuse, webshell
traffic and the errors exploitation leaves behind. All hits are aggregated per
rule with counts, time range, top source IPs and a few sample lines.
"""

import os
import json
import logging
from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Set

from php2shell_scanner.checks.common import fmt_time
from php2shell_scanner.context import ScanContext, run_tool
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable
from php2shell_scanner.signatures import logs as sig

NAME = "logs"
DESCRIPTION = "Web/PHP/WAF/IDS logs: LFI->session triggers, phpMyAdmin abuse, webshell traffic"

LOG = logging.getLogger("php2shell_scanner")
SAMPLES = 3
MAX_TRACKED_PATHS = 200000
MAX_TRACKED_HARD = 400000      # beyond the soft cap only successful POST targets are added
PMA_BRUTE_THRESHOLD = 30
PMA_BRUTE_RATIO = 0.8          # login POSTs must dominate the IP's phpMyAdmin traffic
OOM_5XX_THRESHOLD = 10
WEBSHELL_MIN_POSTS = 5
SUSPICIOUS_DIRS = ("upload", "uploads", "files", "images", "image", "img", "attachments",
                   "attachment", "avatars", "avatar", "media", "tmp", "temp",
                   "wp-content/uploads")
ROUTINE_POST_TARGETS = ("wp-login.php", "xmlrpc.php", "admin-ajax.php", "wp-cron.php",
                        "index.php", "login.php", "async-upload.php", "wp-comments-post.php")


class Hit:
    """Mutable aggregation bucket (local to one scan run)."""

    def __init__(self, rule: sig.LogRule) -> None:
        self.rule = rule
        self.severity = rule.severity
        self.count = 0
        self.first: Optional[float] = None
        self.last: Optional[float] = None
        self.ips: Counter = Counter()
        self.files: Set[str] = set()
        self.samples: List[str] = []

    def add(self, severity: Severity, when: Optional[float], ip: str, path: str,
            line: str) -> None:
        self.count += 1
        self.severity = max(self.severity, severity)
        if when is not None:
            self.first = when if self.first is None else min(self.first, when)
            self.last = when if self.last is None else max(self.last, when)
        if ip:
            self.ips[ip] += 1
        self.files.add(path)
        if len(self.samples) < SAMPLES:
            self.samples.append(printable(line, 300))


class PathStats(NamedTuple):
    posts_2xx: int
    gets: int
    ips: frozenset


class State:
    def __init__(self) -> None:
        self.hits: Dict[str, Hit] = {}
        self.pma_posts: Counter = Counter()
        self.pma_total: Counter = Counter()
        self.pma_sql_ips: Counter = Counter()
        self.oom_5xx: Counter = Counter()
        self.paths: Dict[str, PathStats] = {}
        self.root_sizes: Set[int] = set()   # soft-404 detection: size of "/" responses
        self.lines = 0

    def hit(self, rule: sig.LogRule, severity: Severity, when: Optional[float], ip: str,
            path: str, line: str) -> None:
        bucket = self.hits.get(rule.rule)
        if bucket is None:
            bucket = self.hits[rule.rule] = Hit(rule)
        bucket.add(severity, when, ip, path, line)


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


URI_TRIGGERS = ("?", "(", "..", "sess_", "://", "<", "/etc/", "/proc/", "_ignition",
                "eval-stdin", "connector.minimal", "think")


def _uri_rules(state: State, text: str, entry: Optional[sig.AccessEntry], path: str,
               line: str) -> None:
    if not any(t in text for t in URI_TRIGGERS):
        return
    matched = [rule for rule in sig.URI_RULES if rule.pattern.search(text)]
    if not matched:
        return
    if entry is not None:
        when, ip = sig.parse_time(entry.time), entry.ip
    else:
        when, ip = sig.parse_time(sig.error_time(line) or "-"), sig.error_client_ip(line)
    for rule in matched:
        severity = rule.severity
        if entry and rule.severity_if_2xx is not None and _is_2xx(entry.status):
            if rule.escalate_any_2xx or _is_specific_php(entry.uri):
                severity = rule.severity_if_2xx
        state.hit(rule, severity, when, ip, path, line)


def _is_specific_php(uri: str) -> bool:
    target = uri.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1].lower()
    return bool(sig.PHP_PATH.search(target)) and target != "index.php"


def _ua_rules(state: State, entry: sig.AccessEntry, when: Optional[float], path: str,
              line: str) -> None:
    ua = entry.ua
    if not ua:
        return
    ok = _is_2xx(entry.status)
    if sig.UA_TOOLS.search(ua):
        rule = sig.LogRule("LOG-WEBSHELL-CLIENT", Severity.HIGH if ok else Severity.MEDIUM,
                           Kind.COMPROMISE if ok else Kind.ATTEMPT,
                           "Webshell management client User-Agent (AntSword/Behinder/...)",
                           sig.UA_TOOLS)
        state.hit(rule, rule.severity, when, entry.ip, path, line)
    if entry.method == "POST" and sig.UA_CRAWLER.search(ua) and sig.PHP_PATH.search(
            entry.uri.split("?", 1)[0]):
        rule = sig.LogRule("LOG-FAKE-CRAWLER-POST", Severity.HIGH if ok else Severity.MEDIUM,
                           Kind.COMPROMISE if ok else Kind.ATTEMPT,
                           "POST to PHP with a search-engine User-Agent (China Chopper default)",
                           sig.UA_CRAWLER)
        state.hit(rule, rule.severity, when, entry.ip, path, line)
    if sig.UA_SCANNER.search(ua):
        rule = sig.LogRule("LOG-SCANNER-UA", Severity.LOW, Kind.ATTEMPT,
                           "Vulnerability scanner User-Agent", sig.UA_SCANNER)
        state.hit(rule, rule.severity, when, entry.ip, path, line)


def _stateful(state: State, entry: sig.AccessEntry, when: Optional[float], path: str,
              line: str) -> None:
    uri_path = entry.uri.split("?", 1)[0]
    is_php = bool(sig.PHP_PATH.search(uri_path))
    pma = sig.PMA_PATH.search(entry.uri)
    if pma:
        state.pma_total[entry.ip] += 1
        if entry.method == "POST" and sig.PMA_LOGIN.match(entry.uri[pma.end():]):
            state.pma_posts[entry.ip] += 1
        if _is_2xx(entry.status) and sig.PMA_SQL_PAGE.search(entry.uri):
            state.pma_sql_ips[entry.ip] += 1
        if sig.PMA_SETUP.search(entry.uri) and entry.method == "POST":
            rule = sig.LogRule("LOG-PMA-SETUP", Severity.HIGH if _is_2xx(entry.status)
                               else Severity.LOW, Kind.ATTEMPT,
                               "POST to phpMyAdmin setup script (config injection)", sig.PMA_SETUP)
            state.hit(rule, rule.severity, when, entry.ip, path, line)
    if entry.method == "POST" and is_php and entry.status in (500, 502, 503, 504):
        state.oom_5xx[entry.ip] += 1
    if is_php and entry.status < 400:  # 404 floods must not crowd out real targets
        key = uri_path.lower()
        stats = state.paths.get(key)
        post_ok = entry.method == "POST" and _is_2xx(entry.status)
        if stats is None:
            size = len(state.paths)
            if size >= MAX_TRACKED_HARD or (size >= MAX_TRACKED_PATHS and not post_ok):
                return
            stats = PathStats(0, 0, frozenset())
        posts = stats.posts_2xx + (1 if post_ok else 0)
        gets = stats.gets + (1 if entry.method == "GET" else 0)
        ips = stats.ips if len(stats.ips) > 5 else stats.ips | {entry.ip}
        state.paths[key] = PathStats(posts, gets, ips)


SENSITIVE_RULE = sig.LogRule(
    "LOG-SENSITIVE-FILE-SERVED", Severity.HIGH, Kind.EXPOSURE,
    "Secrets/config file was served to a client (.env, .git/config, config backups)",
    sig.SENSITIVE_FILE)


def _body_rules(state: State, line: str, lower: str, entry: Optional[sig.AccessEntry],
                path: str) -> None:
    if not any(t in lower for t in sig.BODY_TRIGGERS):
        return
    for rule in sig.BODY_RULES:
        if rule.pattern.search(line):
            when = sig.parse_time(entry.time if entry else (sig.error_time(line) or "-"))
            ip = entry.ip if entry else sig.error_client_ip(line)
            state.hit(rule, rule.severity, when, ip, path, line)


def _sensitive_file(state: State, entry: sig.AccessEntry, path: str, line: str) -> None:
    uri_path = entry.uri.split("?", 1)[0]
    if entry.method in ("GET", "HEAD") and entry.status == 200:
        if uri_path == "/" and len(state.root_sizes) < 50:
            state.root_sizes.add(entry.size)
        elif (entry.size > 0 and entry.size not in state.root_sizes
              and sig.SENSITIVE_FILE.match(uri_path)):
            state.hit(SENSITIVE_RULE, SENSITIVE_RULE.severity, sig.parse_time(entry.time),
                      entry.ip, path, line)


def _non_access_line(state: State, line: str, lower: str, path: str) -> None:
    for rule in sig.ERROR_RULES:
        if rule.pattern.search(line):
            state.hit(rule, rule.severity, sig.parse_time(sig.error_time(line) or "-"),
                      sig.error_client_ip(line), path, line)
    looks_like_request = any(t in lower for t in ("get /", "post /", '"uri"', '"url"'))
    if looks_like_request and any(
            k in lower for k in ("sess_", "php_session_upload_progress", "target=")):
        _uri_rules(state, sig.decode_uri(line).lower(), None, path, line)


def process_line(state: State, line: str, path: str) -> None:
    state.lines += 1
    lower = line.lower()
    entry = sig.parse_access(line)
    _body_rules(state, line, lower, entry, path)
    if entry is None:
        _non_access_line(state, line, lower, path)
        return
    decoded = sig.decode_uri(entry.uri).lower()
    _uri_rules(state, decoded, entry, path, line)
    _sensitive_file(state, entry, path, line)
    when = sig.parse_time(entry.time)
    _ua_rules(state, entry, when, path, line)
    _stateful(state, entry, when, path, line)


def _suspicious_shell_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    stem = name.split(".", 1)[0]
    if name in ROUTINE_POST_TARGETS:
        return False
    if any("/{}/".format(d) in path for d in SUSPICIOUS_DIRS):
        return True
    if name.startswith(".") or "/." in path:
        return True
    return len(stem) <= 2 or stem.isdigit() or (len(stem) >= 8 and all(
        c in "0123456789abcdef" for c in stem))


def _aggregate_findings(state: State) -> List[Finding]:
    findings = []
    for ip, count in state.pma_posts.items():
        if count >= PMA_BRUTE_THRESHOLD and count >= PMA_BRUTE_RATIO * state.pma_total[ip]:
            used = state.pma_sql_ips.get(ip, 0)
            findings.append(Finding(
                NAME, "LOG-PMA-BRUTEFORCE", Severity.CRITICAL if used else Severity.HIGH,
                Kind.ATTEMPT, "phpMyAdmin login brute force{}".format(
                    " followed by SQL page access" if used else ""),
                evidence="{} POSTs to the login from {}".format(count, ip),
                detail="An IP that hammers the login and then reaches SQL/import pages most "
                       "likely got in. Rotate all MySQL passwords.",
                meta={"ip": ip, "login_posts": count, "sql_page_hits": used}))
    if state.pma_sql_ips:
        top = state.pma_sql_ips.most_common(20)
        findings.append(Finding(
            NAME, "LOG-PMA-SQL-USAGE", Severity.MEDIUM, Kind.ATTEMPT,
            "phpMyAdmin SQL/import/privilege pages were used - confirm these IPs are yours",
            evidence=", ".join("{} ({}x)".format(ip, n) for ip, n in top[:5]),
            detail="Attackers with phpMyAdmin access write webshells with SELECT ... INTO "
                   "OUTFILE or the general_log trick and create MySQL accounts.",
            meta={"ips": dict(top)}))
    for ip, count in state.oom_5xx.items():
        if count >= OOM_5XX_THRESHOLD:
            findings.append(Finding(
                NAME, "LOG-POST-5XX-BURST", Severity.MEDIUM, Kind.ATTEMPT,
                "Burst of POST requests to PHP answered with 5xx",
                evidence="{} failing POSTs from {}".format(count, ip),
                detail="Chain D/E exhaust memory_limit during multipart parsing; workers then "
                       "return 500/502. Correlate with ERR-OOM-SAPI.",
                meta={"ip": ip, "count": count}))
    for path, stats in state.paths.items():
        if (stats.posts_2xx >= WEBSHELL_MIN_POSTS and stats.gets == 0 and len(stats.ips) <= 3
                and _suspicious_shell_path(path)):
            findings.append(Finding(
                NAME, "LOG-WEBSHELL-TRAFFIC", Severity.HIGH, Kind.COMPROMISE,
                "POST-only traffic to an odd PHP file (webshell usage pattern)", path,
                "{} successful POSTs, 0 GETs, from {}".format(
                    stats.posts_2xx, ", ".join(sorted(stats.ips))),
                "Webshell clients only ever POST to the shell. Check whether this file "
                "exists (or existed) and when it was created.",
                meta={"posts": stats.posts_2xx, "ips": sorted(stats.ips)}))
    return findings


def _hit_findings(state: State) -> List[Finding]:
    findings = []
    for bucket in state.hits.values():
        ip_text = ", ".join("{} ({}x)".format(ip, n) for ip, n in bucket.ips.most_common(5))
        when = ""
        if bucket.first is not None:
            when = "{} -> {}".format(_fmt(bucket.first), _fmt(bucket.last))
        findings.append(Finding(
            NAME, bucket.rule.rule, bucket.severity, bucket.rule.kind,
            "{} [{}x]".format(bucket.rule.title, bucket.count),
            path=sorted(bucket.files)[0] if len(bucket.files) == 1 else "",
            evidence=bucket.samples[0] if bucket.samples else "",
            detail=("Time range: {}. ".format(when) if when else "")
            + ("Top sources: {}.".format(ip_text) if ip_text else ""),
            meta={"count": bucket.count, "first_seen": _fmt(bucket.first),
                  "last_seen": _fmt(bucket.last), "top_ips": dict(bucket.ips.most_common(20)),
                  "files": sorted(bucket.files)[:50], "samples": bucket.samples}))
    return findings


def _fmt(epoch: Optional[float]) -> str:
    return fmt_time(epoch)


def _unwrap_docker(line: str) -> str:
    """Docker json-file driver: {"log":"<line>\\n","stream":"stdout","time":"..."}."""
    if not line.startswith("{"):
        return line
    try:
        record = json.loads(line)
    except ValueError:
        return line
    value = record.get("log") if isinstance(record, dict) else None
    return value.rstrip("\r\n") if isinstance(value, str) else line


def _journal(ctx: ScanContext, state: State) -> None:
    result = run_tool(ctx, ["journalctl", "--no-pager", "-q", "-o", "short-iso",
                            "-u", "php*", "-u", "nginx*", "-u", "apache2*", "-u", "httpd*"],
                      timeout=120)
    if result is None:
        return
    for line in result[1].splitlines():
        process_line(state, line, "journalctl")


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    state = State()
    for path in disc.log_files:
        docker_json = "-json.log" in path
        try:
            for line in ctx.fs.iter_lines(path):
                process_line(state, _unwrap_docker(line) if docker_json else line, path)
        except Exception as exc:  # one unreadable/corrupt log must not lose the others
            LOG.warning("log %s skipped: %s: %s", path, type(exc).__name__, exc)
    _journal(ctx, state)
    findings = _hit_findings(state) + _aggregate_findings(state)
    findings.append(Finding(
        NAME, "LOG-COVERAGE", Severity.INFO, Kind.INFO,
        "Analysed {:,} log lines from {} file(s)".format(state.lines, len(disc.log_files)),
        detail="Logs older than your rotation window are gone; absence of hits is not proof "
               "of absence.", meta={"files": [os.path.basename(p) for p in disc.log_files][:300]}))
    return findings
