# php2shell-scanner

**English** | [简体中文](README.zh-CN.md)

Vulnerability detection **and** intrusion forensics for the PHP `session.upload_progress`
remote code execution vulnerabilities **CVE-2026-109618 / CVE-2026-109619** ("php2shell").

Author: **[Evil0ctal](https://github.com/Evil0ctal)** ·
Repository: <https://github.com/Evil0ctal/php2shell-scanner> · License: [MIT](LICENSE)

> [!WARNING]
> **Legal notice.** This tool is for vulnerability detection and intrusion forensics on systems
> you own or are explicitly authorised to test. Do not use it for any illegal purpose. You are
> responsible for complying with applicable laws; the author accepts no liability for misuse.

## One tool, the whole loop

| Step | Command | Answers |
|---|---|---|
| 1. Detect | `php2shell-scanner scan <url / domain / ip:port>` | *Is this server vulnerable?* — remote and **non-destructive** |
| 2. Investigate | `sudo php2shell-scanner forensics` (on the server) | *Was it already compromised?* — works even after PHP / phpMyAdmin were uninstalled |
| 3. Report | automatic | Terminal summary, a **Markdown report** to download/share, optional JSON |

- **Zero dependencies** — Python 3.6.1+ standard library only; one portable `.pyz` file.
- **Safe by design** — the remote scanner never exploits anything; forensics is strictly
  read-only (files opened with `O_NOATIME`, nothing modified, nothing found is executed).
- **Real-world coverage** — WordPress, Laravel, ThinkPHP, Drupal, Joomla, Magento and other
  PHP apps; BT Panel (宝塔), 1Panel, cPanel, Plesk and other panels; PHP in Docker/Podman;
  Ubuntu, Debian, RHEL/Rocky/Alma, Amazon Linux, Alpine, openSUSE, Arch.

## Quick start

Download the single-file build from [Releases](https://github.com/Evil0ctal/php2shell-scanner/releases)
(no installation, only Python 3.6.1+ is needed):

```bash
curl -fLO https://github.com/Evil0ctal/php2shell-scanner/releases/latest/download/php2shell-scanner.pyz
curl -fLO https://github.com/Evil0ctal/php2shell-scanner/releases/latest/download/php2shell-scanner.pyz.sha256
sha256sum -c php2shell-scanner.pyz.sha256
sudo python3 php2shell-scanner.pyz forensics          # or: python3 php2shell-scanner.pyz scan <target>
```

Or build it from source:

```bash
git clone https://github.com/Evil0ctal/php2shell-scanner && cd php2shell-scanner
./build_pyz.sh                              # -> dist/php2shell-scanner.pyz (single file)

python3 dist/php2shell-scanner.pyz          # interactive menu: remote scan or local forensics
```

```bash
# 1) remote, non-destructive vulnerability check
python3 php2shell-scanner.pyz scan example.com
python3 php2shell-scanner.pyz scan https://shop.example.com:8443 --path /login.php
python3 php2shell-scanner.pyz scan -f targets.txt --threads 8 --json scan.json

# 2) on the server: was it compromised? (root needed to read the evidence)
scp dist/php2shell-scanner.pyz root@server:/root/
sudo python3 /root/php2shell-scanner.pyz forensics --since 2026-09-01

# offline, against a mounted snapshot of a suspect disk (most trustworthy)
python3 php2shell-scanner.pyz forensics --root /mnt/suspect-disk
```

Without building: `python3 php2shell-scanner.py <command>` from a checkout. No `python3` on the
server? BT Panel / aaPanel ship one (`/www/server/panel/pyenv/bin/python3`, also `btpython`);
RHEL/Alma/Rocky 8 have `/usr/libexec/platform-python`; on CentOS 7 run `yum install python3`.

## Remote scan (`scan`)

Several **independent** techniques are combined and cross-checked; one weak signal never makes
a target "vulnerable":

| # | Technique | Signal |
|---|---|---|
| 1 | Version fingerprint over several pages, repeated (`--rounds`) | `X-Powered-By` / `Server` / `X-PHP-Version`; mixed versions reveal several backends behind a load balancer; distribution suffixes (`-1ubuntu2.14`, `~deb12u1`, `.el8`) are flagged as possible backports |
| 2 | Exposed `phpinfo()` (11 common paths) | Authoritative version and SAPI, plus `session.upload_progress.enabled`, `use_only_cookies`, `use_strict_mode`, `file_uploads` |
| 3 | Version hints | `composer.json` PHP constraint, PHP < 5.5 easter-egg GUIDs, PHP cookies/apps (WordPress, Laravel, ThinkPHP, Discuz! ...) |
| 4 | Reachability check | One control multipart POST and the same POST plus a `PHP_SESSION_UPLOAD_PROGRESS` field — **without any session ID**, so PHP never writes upload progress anywhere — shows whether an edge WAF filters the vulnerable feature |
| 5 | Passive anomaly | A `PHPSESSID` of 64+ characters (heap-leak symptom of CVE-2026-109618), CDN/edge detection, SAPI inference |

**Never sent:** session IDs (cookie or form field), crafted filenames, large / stalled /
chunked bodies, anything that writes a session, crashes a worker or executes code.
`--passive` restricts the scan to GET/HEAD requests only. Requests identify themselves with a
`php2shell-scanner/<version>` User-Agent. About 20–30 requests per target; redirects are followed
at most once and only within the same host; every request is capped at 3 × `--timeout` and every
target at `--budget` seconds, so hostile or slow servers cannot stall a scan.

| Result | Meaning | Exit code |
|---|---|---|
| **VULNERABLE** | An affected version was observed (phpinfo, or a header without distro suffix) | 3 |
| **LIKELY VULNERABLE** | Affected upstream version in a distro build, EOL branch, or leak symptom | 2 |
| **UNKNOWN** / **UNREACHABLE** | PHP present but version hidden / target did not answer | 1 |
| **NOT VULNERABLE** / **NO PHP DETECTED** | Only fixed versions observed / no PHP seen | 0 |

Mitigations (upload_progress disabled, edge WAF) are reported next to the result but do not
hide it, because the var_destroy UAF and OOM chains do not depend on upload_progress.
A remote check cannot see backported fixes, hidden versions or origins behind a CDN — confirm
with `php -v` and then run `forensics` on the server.

| Option | Meaning |
|---|---|
| `TARGET ...`, `-f FILE` | URLs, domains, `ip:port[/path]`; scheme-less targets try https then http |
| `--path /x.php` | extra PHP page to fingerprint (repeatable) |
| `--passive` | GET/HEAD only, skip the reachability check |
| `--rounds N`, `--threads N`, `--delay SEC`, `--timeout SEC`, `--budget SEC` | pacing, parallelism and time limits |
| `--strict-tls` | do not continue when a certificate is untrusted (default: continue and note it) |
| `--json FILE`, `--markdown FILE`, `--no-markdown` | reports (Markdown written by default) |
| `--yes` | confirm authorisation non-interactively (otherwise you are asked) |

## Forensics (`forensics`)

Removing PHP closes the hole but not what an attacker left behind. The forensic scan looks
for exactly that — on the live host or on a mounted image (`--root`).

| Check | Looks for |
|---|---|
| `sessions` | PHP code / serialized gadgets / public-exploit session IDs / leftover `upload_progress_` entries / inflated sessions in PHP session files (host **and containers**) |
| `logs` | LFI requests to `sess_*`, phpMyAdmin CVE-2018-12613, `PHP_SESSION_UPLOAD_PROGRESS` and crafted filenames in request bodies (WAF/ModSecurity logs), webshell traffic and client User-Agents, phpMyAdmin brute force, served `.env`/backups, OOM/`Session object destruction failed` errors, worker crashes, Docker/Kubernetes container logs, rotated `.gz/.bz2/.xz` logs, journald |
| `webroot` | Webshells (request input into eval/exec, Behinder, Godzilla, AntSword, China Chopper, obfuscation, reverse shells), PHP in uploads/images, hidden & double-extension PHP, `include` of `.ico`/hex-encoded paths, `auto_prepend_file`, malicious `.htaccess`, MySQL-written PHP, SUID files, PHP in `.git` |
| `apps` | WordPress, Laravel, ThinkPHP, Drupal, Joomla, Magento 2, Nextcloud, MediaWiki, Discuz!, Typecho, PrestaShop, OpenCart, phpBB, DedeCMS, EmpireCMS: inventory and versions, WordPress mu-plugins, Laravel `APP_DEBUG` / public `.env`, vulnerable ThinkPHP |
| `persistence` | Cron (incl. web-user and in-container crontabs), systemd, rc/profile files, `ld.so.preload` |
| `accounts` / `auth` | Extra UID-0 users, web-user shells/sudo/groups/SSH keys; SSH logins as the web user, web-user sudo/su, brute force followed by success, new accounts, privileged-group changes |
| `processes` / `network` | Shells/netcat run by the web user, binaries from `/tmp` or memfd, fake `[kworker]`, miners, reverse/bind shells, exposed PHP-FPM |
| `tmp` | Droppers, scripts, saved `id` output, SUID files in temp dirs, web-user homes, X11/ICE socket dirs and container temp dirs |
| `database` | MySQL UDF backdoors, `general_log_file` → PHP, `INTO OUTFILE` artefacts, `.mysql_history`, phpMyAdmin installs/versions |
| `php` | PHP binaries (version read without executing them), packages (dpkg / apk / pacman / rpm), running PHP, php.ini backdoors |
| `integrity` | `dpkg --verify` / `rpm -V` of ps, ls, sshd, libc ... (trojaned system tools) |
| `baseline` | Firewall (ufw / firewalld / nftables / iptables), exposed Redis/MySQL/Docker API/panel ports, SSH settings, fail2ban, automatic updates, SELinux/AppArmor |

**Environments.** Path knowledge covers Debian/Ubuntu, RHEL/CentOS/Rocky/Alma/Amazon (incl.
Remi/SCL), Alpine, openSUSE, Arch; BT Panel/aaPanel, 1Panel, cPanel (EA-PHP), Plesk, CyberPanel /
OpenLiteSpeed, HestiaCP/VestaCP, ISPConfig, DirectAdmin, Virtualmin, LNMP.org, OneinStack,
Bitnami, XAMPP. 1Panel is found wherever it was installed (`BASE_DIR` from `1pctl`, v1 and v2
layouts, PHP runtimes and app-store sites); BT Panel's Docker projects (`/www/dk_project`) too.
**Docker and Podman** containers are discovered from their on-disk metadata (also offline): each
container's writable layer, bind mounts, volumes and json-file logs are scanned, so a webshell
dropped inside a 1Panel PHP container is found from the host. Docker 29's containerd image store
is handled through the kernel mount table, processes inside containers are attributed correctly
(1Panel/BT run PHP as uid 1000), systemd `PrivateTmp` directories of php-fpm/httpd are searched,
and application-managed session directories (ThinkPHP `runtime/session`, DedeCMS, OpenCart,
Magento) are scanned like PHP's own.

### Reading the result

Each finding has a severity (`CRITICAL … INFO`) and a kind: **compromise** (attacker had code
execution or persistence), **attempt** (exploitation traffic or an exploit stage), **exposure**
(vulnerable or dangerous configuration), **hardening** (baseline gap — shown separately, never
changes the verdict).

| Verdict | Condition | Exit code |
|---|---|---|
| **COMPROMISED** | any CRITICAL compromise finding | 3 |
| **LIKELY COMPROMISED** | HIGH compromise or CRITICAL attempt | 2 |
| **SUSPICIOUS** / **EXPOSED** | MEDIUM+ compromise/attempt / only MEDIUM+ exposure | 1 |
| **NO INDICATORS FOUND** | nothing above | 0 |
| *incomplete* | a check failed and nothing was found | 70 |

Generic Internet noise (scanners probing `/?cmd=id` or `../../etc/passwd`) is reported as LOW
and does not change the verdict; php2shell-specific evidence keeps its full weight.

A **Markdown report** (`php2shell-forensics-<host>-<time>.md`, mode 0600) is written by default
with the verdict, next steps, a summary table and the evidence of every finding (owner,
mtime/ctime, first/last seen, source IPs). Untrusted content is escaped so file names or log
lines cannot inject Markdown, HTML or terminal escape sequences.

| Option | Meaning |
|---|---|
| `--root DIR` | scan a mounted disk image (disables live process/socket/package checks) |
| `--since DATE` | `YYYY-MM-DD` or `30d`: flag files, keys, units, sudoers changed after it |
| `--webroot / --log / --session-dir` | extra locations (repeatable) |
| `--checks a,b` / `--skip a,b` | choose checks (`--list-checks`) |
| `--markdown FILE` / `--no-markdown`, `--json FILE` | reports |
| `--no-exec` | never run an external program (dpkg, rpm, iptables, journalctl, php -v) |
| `--min-severity`, `--max-per-rule`, `--max-file-size`, `--max-files` | output and limits |

### Impact on production servers

Forensics is designed to run on live production hosts:

- **Read-only.** It never connects to MySQL/Redis or any other service, never takes locks,
  never reads database table files, never modifies or executes anything it finds; the only
  writes are its own report files.
- **Polite by default.** It lowers itself to CPU nice 19 and the lowest best-effort IO
  priority, and tells the kernel to drop the page cache of every large file it has read, so
  scanning gigabytes of logs does not evict what your database and web server keep cached.
  `--no-throttle` runs at full speed instead.
- **Bounded.** Single-threaded (at most one CPU core), streaming reads with size caps;
  memory stays in the tens of megabytes.
- **Measured** on a 4 vCPU / 8 GB BT Panel production server with MySQL, Redis and nginx:
  one core busy, 50 MB peak memory, no IO pressure, MySQL unaffected ). A complete scan of
  its 272 log files and web roots took 29 seconds and read about 60 MB from disk.

### "I already removed PHP and phpMyAdmin — am I safe?"

Not necessarily. Session files, web roots and logs usually stay behind (don't delete them
before scanning — they are evidence). A webshell's first job is persistence — cron, SSH keys,
background binaries — which keeps working without PHP. MySQL is still there; rotate its
passwords if phpMyAdmin was reachable. On **COMPROMISED / LIKELY COMPROMISED**: isolate the
host, image the disk before cleaning, rotate all credentials from a clean machine, rebuild.

### Limitations

- Access logs never contain POST bodies; detection relies on side effects unless a WAF or
  `$request_body` logging recorded them.
- Only evidence inside the log retention window can be found; *no indicators* is not proof.
- A kernel or `ld.so.preload` rootkit can lie to live checks — use `--root` on a disk image.
- Distribution packages may carry backported fixes; version checks say so.
- File access times are preserved, but listing a directory on the live host can still update
  that directory's own access time.

## Tested on

Forensics was run on each distribution in Docker (`tests/e2e/distros.sh`) with a planted
webshell; every run returned **COMPROMISED** with no check errors.

| Distribution | Python | | Distribution | Python |
|---|---|---|---|---|
| Ubuntu 20.04 | 3.8.10 | | Amazon Linux 2023 | 3.9.25 |
| Ubuntu 24.04 | 3.12.3 | | Alpine 3.20 | 3.12.13 |
| Debian 12 | 3.11.2 | | openSUSE Leap 15.6 | 3.6.15 |
| Rocky Linux 9 | 3.9.18 | | Arch Linux | 3.14.8 |
| AlmaLinux 8 (platform-python) | 3.6.8 | | macOS (unit tests, `--root` mode) | 3.10 |

The remote scanner was verified against real `php:7.4`, `php:8.2.34`, `php:8.3` and
`wordpress` containers (`tests/e2e/remote_real.sh`), and the forensic scanner against a real
nginx + php-fpm + phpMyAdmin + WordPress install for false positives
(`tests/e2e/false_positive_lamp.sh`).

## Development

```bash
python3 -m pytest tests -q                   # unit tests + offline end-to-end tests
bash tests/e2e/run.sh                        # Docker: clean host vs host with planted IOCs
bash tests/e2e/false_positive_lamp.sh        # Docker: real nginx + php-fpm + phpMyAdmin + WordPress
bash tests/e2e/remote_real.sh                # Docker: remote scan of real PHP 7.4 / 8.2 / 8.3 stacks
bash tests/e2e/distros.sh                    # Docker: forensics on 9 Linux distributions
./build_pyz.sh                               # dist/php2shell-scanner.pyz
```

## Author & license

Made by **[Evil0ctal](https://github.com/Evil0ctal)**. Released under the [MIT License](LICENSE).
Issues and pull requests are welcome at
<https://github.com/Evil0ctal/php2shell-scanner>.
