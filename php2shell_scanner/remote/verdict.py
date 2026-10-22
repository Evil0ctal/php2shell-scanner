"""Fuse independent evidence into one result per target.

Rules (conservative - a single weak signal never yields VULNERABLE):
- phpinfo() version is authoritative; header versions are trusted unless they carry a
  distribution suffix (backported fixes are invisible in the upstream version string);
- branch-only or composer constraints only narrow things down;
- mixed versions across repeated requests mean several backends: the worst one counts;
- mitigations (upload_progress off, edge WAF) are reported, they do not hide the result,
  because the var_destroy UAF and OOM chains do not depend on upload_progress.
"""

import re
from collections import OrderedDict
from typing import Dict, List, NamedTuple, Optional

from php2shell_scanner.remote.fingerprint import PRERELEASE, is_backport
from php2shell_scanner.remote.probes import ProbeData
from php2shell_scanner.versions import (FIXED_IN, FIXED_TEXT, branch_vulnerable,
                                        version_vulnerable)

VULNERABLE, LIKELY, NOT_VULNERABLE, UNKNOWN, NOT_PHP, UNREACHABLE = (
    "VULNERABLE", "LIKELY VULNERABLE", "NOT VULNERABLE", "UNKNOWN", "NO PHP DETECTED",
    "UNREACHABLE")
VERSION_SPLIT = re.compile(r"^(\d+\.\d+\.\d+)(.*)$")
FIXED_VERSIONS = frozenset(".".join(map(str, v)) for v in FIXED_IN.values())
EXIT_CODES = {VULNERABLE: 3, LIKELY: 2, UNKNOWN: 1, UNREACHABLE: 1, NOT_VULNERABLE: 0,
              NOT_PHP: 0}


class TargetResult(NamedTuple):
    target: str
    status: str
    confidence: str
    versions: Dict[str, List[str]]      # version -> where it was seen
    reasons: List[str]
    mitigations: List[str]
    exposures: List[str]
    context: List[str]
    requests: int

    @property
    def code(self) -> int:
        return EXIT_CODES[self.status]


def _version_sources(data: ProbeData) -> "OrderedDict[str, List[str]]":
    seen: "OrderedDict[str, List[str]]" = OrderedDict()
    if data.phpinfo:
        seen.setdefault(data.phpinfo.version, []).append("phpinfo() at " + data.phpinfo_path)
    for item in data.versions:
        label = item.version + item.suffix
        sources = seen.setdefault(label, [])
        if item.source not in sources:
            sources.append(item.source)
    return seen


def _judge(version: str, suffix: str, source: str, backport: bool, prerelease: bool,
           distro: str, reasons: List[str]) -> Optional[str]:
    vulnerable = version_vulnerable(version)
    if vulnerable is None:
        return None
    label = version + suffix
    if vulnerable and backport:
        reasons.append("{} reports distribution build PHP {}: the upstream version is affected, "
                       "but the vendor may have backported the fix".format(source, label))
        return LIKELY
    if vulnerable and distro:
        # The token describes the web server's packaging; PHP itself may be an upstream build
        # (e.g. the official php Docker images on Debian). Under-reporting is the worse error.
        reasons.append("{} reports PHP {} (affected; fixed in {}). The Server header says {}: if "
                       "PHP comes from {} packages, confirm the vendor's fix status".format(
                           source, label, FIXED_TEXT, distro, distro))
        return VULNERABLE
    if vulnerable:
        reasons.append("{} reports PHP {} (affected; fixed in {})".format(source, label,
                                                                          FIXED_TEXT))
        return VULNERABLE
    if prerelease and version in FIXED_VERSIONS:
        reasons.append("{} reports a pre-release build PHP {} of the first fixed version; "
                       "pre-release snapshots may predate the fix".format(source, label))
        return LIKELY
    reasons.append("{} reports PHP {} (fixed or not affected)".format(source, label))
    return NOT_VULNERABLE


def _from_full_versions(data: ProbeData, reasons: List[str]) -> List[str]:
    """Statuses implied by every full x.y.z version observed."""
    statuses = []
    distro = ", ".join(sorted(data.distro))
    if data.phpinfo:
        found = VERSION_SPLIT.match(data.phpinfo.version)
        version, suffix = (found.group(1), found.group(2)) if found else (data.phpinfo.version, "")
        statuses.append(_judge(version, suffix, "phpinfo() at " + data.phpinfo_path,
                               is_backport(suffix), bool(PRERELEASE.search(suffix)), "", reasons))
    seen = set()
    for item in data.versions:
        if item.branch_only or (item.version, item.suffix) in seen:
            continue
        seen.add((item.version, item.suffix))
        statuses.append(_judge(item.version, item.suffix, item.source, item.backport,
                               item.prerelease, distro, reasons))
    return [status for status in statuses if status]


def _from_hints(data: ProbeData, reasons: List[str]) -> List[str]:
    statuses = []
    for item in data.versions:
        if item.branch_only:
            affected = branch_vulnerable(item.version)
            if affected:
                statuses.append(LIKELY)
                reasons.append("{} reports PHP {} - every release of that EOL branch is "
                               "affected".format(item.source, item.version))
            else:
                reasons.append("{} reports only the branch PHP {}".format(item.source,
                                                                           item.version))
    if data.legacy_egg:
        reasons.append("PHP easter-egg GUID answered: PHP < 5.5 (5.4 is affected, 5.3 is not; "
                       "both are long unsupported)")
    if data.composer_php:
        reasons.append("composer.json requires PHP {} (narrows the branch only)".format(
            data.composer_php))
    return statuses


def _decide(statuses: List[str], data: ProbeData, reasons: List[str]) -> str:
    for status in (VULNERABLE, LIKELY):
        if status in statuses:
            return status
    if NOT_VULNERABLE in statuses:
        return NOT_VULNERABLE
    if not 200 <= data.home_status < 400 and not data.signals:
        reasons.append("The site answered HTTP {} and showed no PHP evidence; it could not be "
                       "assessed (try --path with a PHP page)".format(data.home_status))
        return UNKNOWN
    if data.signals or data.long_session_ids:
        reasons.append("PHP detected ({}) but its version is hidden".format(
            ", ".join(sorted(data.signals)) or "session cookie"))
        return UNKNOWN
    reasons.append("No PHP signals in headers, cookies, pages or common paths")
    return NOT_PHP


def _confidence(status: str, data: ProbeData, versions: Dict[str, List[str]]) -> str:
    if data.phpinfo:
        return "high"
    if status == VULNERABLE and data.distro:
        return "medium"     # possible distribution backport, see the reason text
    observations = sum(len(v) for v in versions.values())
    if status in (VULNERABLE, NOT_VULNERABLE) and observations >= 2 and len(versions) == 1:
        return "high"
    if status in (VULNERABLE, NOT_VULNERABLE, NOT_PHP):
        return "medium"
    return "low"


def _mitigations(data: ProbeData) -> List[str]:
    found = []
    directives = data.phpinfo.directives if data.phpinfo else {}
    if directives.get("session.upload_progress.enabled", "").lower() in ("off", "0"):
        found.append("session.upload_progress.enabled = Off (blocks the session-injection "
                     "chains; the var_destroy UAF / OOM chains remain - still upgrade)")
    if directives.get("file_uploads", "").lower() in ("off", "0"):
        found.append("file_uploads = Off (multipart parsing of files disabled)")
    if data.reachability == "blocked-at-edge":
        found.append("An edge WAF/proxy blocks multipart requests carrying "
                     "PHP_SESSION_UPLOAD_PROGRESS (the origin may still be reachable directly)")
    return found


def _context(data: ProbeData, versions: Dict[str, List[str]]) -> List[str]:
    lines = []
    if len([v for v in versions if "." in v]) > 1:
        lines.append("Different PHP versions answered repeated requests: several backends "
                     "behind a load balancer; the worst one decides the status")
    if data.edge:
        lines.append("Served through {} - headers may describe the edge, not the origin".format(
            ", ".join(sorted(data.edge))))
    lines += sorted(data.sapi)
    if data.session_endpoints:
        lines.append("Pages that start a PHP session: " + ", ".join(data.session_endpoints[:5]))
    if data.reachability == "reachable":
        lines.append("Multipart requests with PHP_SESSION_UPLOAD_PROGRESS reach the "
                     "application (no edge filtering observed)")
    elif data.reachability == "multipart-blocked":
        lines.append("All multipart POSTs were rejected - reachability inconclusive")
    return lines + data.notes


def evaluate(url: str, data: ProbeData, requests: int) -> TargetResult:
    if not data.reachable:
        return TargetResult(url, UNREACHABLE, "high", {}, [data.error or "no response"], [], [],
                            data.notes, requests)
    reasons: List[str] = []
    statuses = _from_full_versions(data, reasons) + _from_hints(data, reasons)
    status = _decide(statuses, data, reasons)
    exposures = list(data.exposed)
    if data.long_session_ids:
        exposures.insert(0, "Malformed oversized PHPSESSID issued (possible heap memory leak, "
                            "CVE-2026-109618 symptom): " + "; ".join(data.long_session_ids[:3]))
    versions = _version_sources(data)
    context = _context(data, versions)
    if status == NOT_VULNERABLE:
        context.append(
            "Patched for the CVEs, but note: upload_progress stores the upload filename "
            "verbatim in the session file on every PHP version (Chain A), so if any application "
            "on this host has a local file inclusion, that path can still reach code execution. "
            "This does not change the verdict - it is a reason to also fix LFI sinks.")
    return TargetResult(url, status, _confidence(status, data, versions), dict(versions),
                        reasons, _mitigations(data), exposures, context, requests)
