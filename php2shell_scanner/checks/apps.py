"""Mainstream PHP applications in the web roots: inventory plus app-specific risks.

Webshell signatures already run over every PHP file; this check adds what is
specific to an application: its version, auto-loaded persistence locations
(WordPress mu-plugins), leaked secrets (Laravel .env) and other well-known pre-auth
RCEs that attackers use to drop webshells (ThinkPHP).
"""

import os
import re
from typing import List, NamedTuple, Optional, Tuple

from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, Severity

NAME = "apps"
DESCRIPTION = "PHP apps (WordPress, Laravel, ThinkPHP, Drupal, Joomla, Magento, ...): risks"

MAX_DEPTH_GLOBS = ("{root}/{marker}", "{root}/*/{marker}", "{root}/*/*/{marker}")


class AppSpec(NamedTuple):
    name: str
    marker: str                       # file relative to the app root
    version_file: str = ""
    version_regex: str = ""


APPS: Tuple[AppSpec, ...] = (
    AppSpec("WordPress", "wp-includes/version.php", "wp-includes/version.php",
            r"\$wp_version\s*=\s*'([^']+)'"),
    AppSpec("Laravel", "artisan", "vendor/laravel/framework/src/Illuminate/Foundation/Application.php",
            r"const VERSION = '([^']+)'"),
    AppSpec("ThinkPHP 5.0", "thinkphp/base.php", "thinkphp/base.php",
            r"THINK_VERSION'\s*,\s*'([^']+)'"),
    AppSpec("ThinkPHP 5.1+/6", "vendor/topthink/framework/src/think/App.php",
            "vendor/topthink/framework/src/think/App.php", r"const VERSION = '([^']+)'"),
    AppSpec("Drupal", "core/lib/Drupal.php", "core/lib/Drupal.php", r"const VERSION = '([^']+)'"),
    AppSpec("Joomla", "libraries/src/Version.php", "libraries/src/Version.php",
            r"MAJOR_VERSION = (\d+);"),
    AppSpec("Magento 2", "app/etc/env.php", "composer.json", r'"version":\s*"([^"]+)"'),
    AppSpec("Nextcloud/ownCloud", "occ", "version.php", r"\$OC_VersionString = '([^']+)'"),
    AppSpec("MediaWiki", "includes/Defines.php", "includes/Defines.php",
            r"MW_VERSION', '([^']+)'"),
    AppSpec("Discuz!", "source/class/discuz/discuz_application.php",
            "source/discuz_version.php", r"DISCUZ_VERSION', '([^']+)'"),
    AppSpec("Typecho", "var/Typecho/Common.php", "var/Typecho/Common.php",
            r"const VERSION = '([^']+)'"),
    AppSpec("PrestaShop", "classes/PrestaShopAutoload.php", "app/AppKernel.php",
            r"const VERSION = '([^']+)'"),
    AppSpec("OpenCart", "system/startup.php", "index.php", r"VERSION', '([^']+)'"),
    AppSpec("phpBB", "includes/constants.php", "includes/constants.php",
            r"PHPBB_VERSION', '([^']+)'"),
    AppSpec("DedeCMS", "include/common.inc.php", "data/admin/ver.txt", r"(\S+)"),
    AppSpec("EmpireCMS", "e/class/connect.php", "e/class/EmpireCMS_version.php",
            r"EmpireCMS_VERSION','([^']+)'"),
)
VULNERABLE_THINKPHP = re.compile(r"^5\.(?:0\.(?:\d|1\d|2[0-3])|1\.(?:\d|[12]\d|30))$")


def _app_roots(ctx: ScanContext, webroot: str, marker: str) -> List[str]:
    roots = []
    for template in MAX_DEPTH_GLOBS:
        for path in ctx.fs.glob(template.format(root=webroot.rstrip("/"), marker=marker)):
            roots.append(path[: -len(marker)].rstrip("/") or "/")
    return roots


def _version(ctx: ScanContext, root: str, spec: AppSpec) -> Optional[str]:
    if not spec.version_file:
        return None
    text = ctx.fs.read_text(os.path.join(root, spec.version_file), 512 * 1024) or ""
    found = re.search(spec.version_regex, text)
    return found.group(1)[:40] if found else None


def inventory(ctx: ScanContext, disc: Discovery) -> List[Tuple[AppSpec, str, Optional[str]]]:
    apps, seen = [], set()
    for webroot in disc.webroots:
        for spec in APPS:
            for root in _app_roots(ctx, webroot, spec.marker):
                if (spec.name, root) not in seen:
                    seen.add((spec.name, root))
                    apps.append((spec, root, _version(ctx, root, spec)))
    return apps


def _wordpress(ctx: ScanContext, root: str) -> List[Finding]:
    plugins = [p for p in ctx.fs.glob(root + "/wp-content/mu-plugins/*.php")]
    if not plugins:
        return []
    return [Finding(NAME, "APP-WP-MU-PLUGINS", Severity.INFO, Kind.INFO,
                    "WordPress must-use plugins (auto-loaded on every request): {}".format(
                        len(plugins)), root + "/wp-content/mu-plugins",
                    ", ".join(os.path.basename(p) for p in plugins[:10]),
                    "A favourite persistence spot; make sure you recognise each file.",
                    {"paths": plugins[:100]})]


def _laravel(ctx: ScanContext, root: str) -> List[Finding]:
    findings = []
    env = ctx.fs.read_text(root + "/.env", 256 * 1024) or ""
    if re.search(r"^\s*APP_DEBUG\s*=\s*\"?true", env, re.M | re.I):
        findings.append(Finding(NAME, "APP-LARAVEL-DEBUG", Severity.MEDIUM, Kind.EXPOSURE,
                                "Laravel APP_DEBUG=true", root + "/.env",
                                detail="Debug pages leak secrets and, with old Ignition "
                                       "(CVE-2021-3129), give remote code execution."))
    if ctx.fs.isfile(root + "/public/.env"):
        findings.append(Finding(NAME, "APP-LARAVEL-PUBLIC-ENV", Severity.HIGH, Kind.EXPOSURE,
                                ".env inside the public web root (downloadable secrets)",
                                root + "/public/.env",
                                detail="Rotate APP_KEY and every credential in it: a leaked "
                                       "APP_KEY allows deserialization RCE."))
    return findings


def _thinkphp(spec: AppSpec, root: str, version: Optional[str]) -> List[Finding]:
    if version and VULNERABLE_THINKPHP.match(version):
        return [Finding(NAME, "APP-THINKPHP-RCE", Severity.HIGH, Kind.EXPOSURE,
                        "ThinkPHP {} has a known pre-auth RCE (CVE-2018-20062/CVE-2019-9082)"
                        .format(version), root,
                        detail="Mass-exploited to plant webshells; upgrade to 5.0.24+/5.1.31+.")]
    return []


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    apps = inventory(ctx, disc)
    for spec, root, version in apps:
        if spec.name == "WordPress":
            findings += _wordpress(ctx, root)
        elif spec.name == "Laravel":
            findings += _laravel(ctx, root)
        elif spec.name.startswith("ThinkPHP"):
            findings += _thinkphp(spec, root, version)
    rows = ["{} {} at {}".format(spec.name, version or "(version unknown)", root)
            for spec, root, version in apps]
    findings.append(Finding(
        NAME, "APP-INVENTORY", Severity.INFO, Kind.INFO,
        "Detected {} PHP application(s){}".format(
            len(apps), ": " + ", ".join(sorted({s.name for s, _, _ in apps})) if apps else ""),
        meta={"paths": rows[:200]}))
    return findings
