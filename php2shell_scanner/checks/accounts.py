"""Accounts and access: backdoor users, sudo rights, SSH keys planted by an attacker."""

import os
import re
from typing import List

from php2shell_scanner.checks.common import file_meta
from php2shell_scanner.context import ScanContext
from php2shell_scanner.models import Discovery, Finding, Kind, Severity
from php2shell_scanner.signatures import printable, scan
from php2shell_scanner.signatures.system import COMMAND_SIGNATURES

NAME = "accounts"
DESCRIPTION = "UID-0 users, web-user shells/sudo/groups, SSH authorized_keys, sshd_config"

LOGIN_SHELLS = re.compile(r"/(?:ba|da|z|k|c|tc|a)?sh$")
PRIV_GROUPS = {"sudo": Severity.CRITICAL, "wheel": Severity.CRITICAL, "root": Severity.CRITICAL,
               "admin": Severity.CRITICAL, "docker": Severity.CRITICAL, "lxd": Severity.CRITICAL,
               "disk": Severity.HIGH, "adm": Severity.MEDIUM, "shadow": Severity.HIGH}
KEY_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")
KEY_LINE = re.compile(r"(?:^|\s)(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s+(\S+)(?:\s+(.*))?$")
AUTH_KEYS_FILE = re.compile(r"^\s*AuthorizedKeysFile\s+(.+)$", re.M | re.I)
DEFAULT_AUTH_KEYS = {".ssh/authorized_keys", ".ssh/authorized_keys2",
                     "%h/.ssh/authorized_keys", "%h/.ssh/authorized_keys2"}


def check_users(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for user in disc.users:
        if user.uid == 0 and user.name != "root":
            findings.append(Finding(
                NAME, "ACCT-UID0", Severity.CRITICAL, Kind.COMPROMISE,
                "Additional UID 0 (root-equivalent) account '{}'".format(user.name),
                "/etc/passwd", printable(":".join(map(str, user))),
                "Backdoor root accounts are a standard persistence technique."))
        if user.name in disc.web_users and LOGIN_SHELLS.search(user.shell):
            findings.append(Finding(
                NAME, "ACCT-WEBUSER-SHELL", Severity.MEDIUM, Kind.COMPROMISE,
                "Web user '{}' has an interactive login shell".format(user.name),
                "/etc/passwd", user.shell,
                "Distributions ship web users with nologin/false. A real shell is often set by "
                "attackers to log in with planted SSH keys."))
    return findings


def check_shadow(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    shells = {u.name: u.shell for u in disc.users}
    for line in (ctx.fs.read_text("/etc/shadow") or "").splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name, password = parts[0], parts[1]
        if password == "" and LOGIN_SHELLS.search(shells.get(name, "")):
            findings.append(Finding(
                NAME, "ACCT-EMPTY-PASSWORD", Severity.HIGH, Kind.COMPROMISE,
                "Account '{}' has an empty password and a login shell".format(name),
                "/etc/shadow", name + "::..."))
        if name in disc.web_users and password not in ("", "*", "!", "!!", "!*", "x") \
                and not password.startswith("!"):
            findings.append(Finding(
                NAME, "ACCT-WEBUSER-PASSWORD", Severity.HIGH, Kind.COMPROMISE,
                "Web user '{}' has a usable password".format(name), "/etc/shadow",
                name + ":<hash>:...", "Web users should be locked ('*' or '!')."))
    return findings


def check_groups(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for group, severity in PRIV_GROUPS.items():
        for member in disc.groups.get(group, ()):
            if member in disc.web_users:
                findings.append(Finding(
                    NAME, "ACCT-WEBUSER-PRIV-GROUP", severity, Kind.COMPROMISE,
                    "Web user '{}' is a member of privileged group '{}'".format(member, group),
                    "/etc/group", "{}:...:{}".format(group, member)))
    return findings


def check_sudoers(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings = []
    for path in ["/etc/sudoers"] + ctx.fs.glob("/etc/sudoers.d/*"):
        text = ctx.fs.read_text(path, 256 * 1024)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "Defaults")):
                continue
            who = stripped.split()[0]
            if who in disc.web_users or who.lstrip("%") in disc.web_users:
                findings.append(Finding(
                    NAME, "ACCT-WEBUSER-SUDO", Severity.CRITICAL, Kind.COMPROMISE,
                    "sudo rule for web user '{}'".format(who), path, printable(stripped)))
        st = ctx.fs.lstat(path)
        if path != "/etc/sudoers" and st is not None and ctx.recent(st.st_mtime):
            findings.append(Finding(
                NAME, "ACCT-SUDOERS-RECENT", Severity.MEDIUM, Kind.COMPROMISE,
                "sudoers drop-in created/modified after --since", path,
                detail="Confirm you added it.", meta=file_meta(ctx, disc, st)))
    return findings


def _key_findings(ctx: ScanContext, disc: Discovery, user_name: str, is_web: bool,
                  path: str) -> List[Finding]:
    text = ctx.fs.read_text(path, 512 * 1024) or ""
    st = ctx.fs.lstat(path)
    keys = []
    for line in text.splitlines():
        found = KEY_LINE.search(line.strip())
        if found and not line.strip().startswith("#"):
            keys.append((found.group(1), (found.group(3) or "").strip(), line.strip()))
    if not keys:
        return []
    comments = ", ".join(c or "(no comment)" for _, c, _ in keys[:5])
    findings = []
    if is_web:
        findings.append(Finding(
            NAME, "ACCT-WEBUSER-SSH-KEY", Severity.CRITICAL, Kind.COMPROMISE,
            "SSH authorized_keys for web user '{}'".format(user_name), path, comments,
            "A webshell can write ~/.ssh/authorized_keys for the web user to get a real "
            "SSH login. Remove the key and audit auth logs.",
            file_meta(ctx, disc, st, keys=len(keys))))
    elif st is not None and ctx.recent(max(st.st_mtime, st.st_ctime)):
        findings.append(Finding(
            NAME, "ACCT-SSH-KEYS-RECENT", Severity.HIGH, Kind.COMPROMISE,
            "authorized_keys of '{}' changed after --since".format(user_name), path, comments,
            "Verify every key is yours.", file_meta(ctx, disc, st, keys=len(keys))))
    else:
        findings.append(Finding(
            NAME, "ACCT-SSH-KEYS", Severity.INFO, Kind.INFO,
            "{} authorized SSH key(s) for '{}' - verify they are yours".format(len(keys), user_name),
            path, comments, meta=file_meta(ctx, disc, st, keys=len(keys))))
    for _, _, line in keys:
        if line.startswith(("command=", "from=")) or ",command=" in line:
            for match in scan(COMMAND_SIGNATURES, line):
                findings.append(Finding(
                    NAME, "ACCT-SSH-FORCED-CMD", match.signature.severity, Kind.COMPROMISE,
                    "Malicious forced command in authorized_keys", path, match.snippet))
    return findings


def check_ssh_keys(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()
    for user in disc.users:
        if not user.home or user.home in ("/", "/nonexistent") or user.home in seen:
            continue
        seen.add(user.home)
        for rel in KEY_FILES:
            path = os.path.join(user.home, rel)
            if ctx.fs.isfile(path):
                findings.extend(_key_findings(ctx, disc, user.name, user.name in disc.web_users,
                                              path))
    text = ctx.fs.read_text("/etc/ssh/sshd_config", 256 * 1024) or ""
    for found in AUTH_KEYS_FILE.finditer(text):
        values = set(found.group(1).split())
        if not values <= DEFAULT_AUTH_KEYS:
            findings.append(Finding(
                NAME, "ACCT-SSHD-KEYFILE", Severity.MEDIUM, Kind.COMPROMISE,
                "Non-default AuthorizedKeysFile in sshd_config", "/etc/ssh/sshd_config",
                printable(found.group(0)), "Attackers redirect key lookup to a hidden file."))
    return findings


def run(ctx: ScanContext, disc: Discovery) -> List[Finding]:
    return (check_users(ctx, disc) + check_shadow(ctx, disc) + check_groups(ctx, disc)
            + check_sudoers(ctx, disc) + check_ssh_keys(ctx, disc))
