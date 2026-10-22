# php2shell Detection Rules

Drop-in network / WAF / SIEM detection and blocking rules for
**CVE-2026-109618 / CVE-2026-109619** ("php2shell"), shipped alongside
[`php2shell-scanner`](../README.md). The scanner tells you whether a host is
*vulnerable* (`scan`) or was *already compromised* (`forensics`); these rules
give you *ongoing* detection and blocking in your IDS, WAF and SIEM.

## Provenance

These rules were ported and hardened from two public research repositories:

| Source | Contribution |
|---|---|
| [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) `detection/` | Base Suricata, Sigma, ModSecurity and OpenResty rules (author: Qi Deng) |
| [dinosn/php-cve-2026-10961x-lab-poc](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) `docs/WAF-BYPASS.md` | Content-Type separator bypass, Lua 64 KB-prefix gap, rule-defect analysis |

Hardening and integration by the php2shell-scanner project (Evil0ctal). Only
**detection** material was ported; no exploit code from either repository is
included here or anywhere in this project.

## Files

| File | Format | Use case |
|------|--------|----------|
| `php2shell.rules` | Suricata / Snort | Network IDS - request-side, response-side and recon |
| `php2shell.yaml` | Sigma | SIEM log detection - web-server logs and host process/file events |
| `modsecurity.conf` | ModSecurity v2/v3 | WAF - drop-in rules for Apache/Nginx with ModSecurity |
| `php2shell.lua` | OpenResty / Nginx Lua | Reverse proxy - lightweight Lua module |

## Quick start

These files ship inside the single-file build. To extract them on a server that
only has the `.pyz`:

```bash
python3 php2shell-scanner.pyz rules -o php2shell-detection   # writes all files here
python3 php2shell-scanner.pyz rules --list                   # list bundled files
python3 php2shell-scanner.pyz rules --stdout php2shell.rules # print one to stdout
```

**Suricata**
```bash
cp php2shell.rules /etc/suricata/rules/
echo "  - php2shell.rules" >> /etc/suricata/suricata.yaml   # under rule-files
suricatasc -c reload-rules
```

**ModSecurity**
```bash
cp modsecurity.conf /etc/modsecurity/conf.d/php2shell.conf
systemctl reload apache2   # or nginx
```

**OpenResty**
```nginx
# In your server block:
access_by_lua_block { require("php2shell").check() }
```

## Coverage matrix

| ID | What it detects | Severity |
|----|-----------------|----------|
| **Request-side** | | |
| Suricata 2026100 / MS 9900100 | `PHP_SESSION_UPLOAD_PROGRESS` in a multipart body | HIGH |
| Suricata 2026107 | Same, on any HTTP method (PHP 8.4 `request_parse_body`) | HIGH |
| Suricata 2026101 / MS 9900101 | `PHPSESSID` as a form field (session fixation) | HIGH |
| Suricata 2026102 / MS 9900102 | `<?php` in an upload filename (session injection) | CRITICAL |
| Suricata 2026103 / MS 9900103 | Serialized object in a filename (`\|O:` handler mismatch) | CRITICAL |
| Suricata 2026104 | Oversized filename (session inflation) | MEDIUM |
| Suricata 2026105 / MS 9900106 | Chunked multipart (`post_max_size` bypass) | MEDIUM |
| Suricata 2026106 | Session file path in the URL (LFI trigger) | HIGH |
| Suricata 2026108 / MS 9900107 | Non-standard multipart Content-Type separator (WAF bypass) | MEDIUM |
| **Response-side** | | |
| Suricata 2026110 / MS 9900104 | PHP OOM "memory exhausted" in the response | HIGH |
| Suricata 2026111 / MS 9900105 | "Session object destruction failed" | CRITICAL |
| Suricata 2026112 / MS 9900108 | Anomalous PHPSESSID cookie length (heap leak) | CRITICAL |
| **Recon / inventory** | | |
| Suricata 2026115 | Small upload-progress probes (3 / 60 s by source) | LOW |
| Suricata 2026116 | Vulnerable PHP version in a response header | INFO |

## The Content-Type separator bypass (read this)

PHP's SAPI parser trims the media type at `;`, `,` **and** space (`SAPI.c`),
and `rfc1867` finds the boundary with `strpbrk(",;")`. So all of these parse
identically and still trigger the bug:

```
Content-Type: multipart/form-data; boundary=X     (standard)
Content-Type: multipart/form-data, boundary=X      (comma - accepted)
Content-Type: multipart/form-data,boundary=X       (comma, no space)
Content-Type: multipart/form-data boundary=X       (space)
```

Any signature anchored on `; boundary=` is evadable with a one-character change.
These rules avoid that trap:

- **Suricata** matches the plain substring `multipart/form-data` and scans the
  **raw** request body, so the separator is irrelevant; rule 2026108 flags the
  non-standard separator explicitly.
- **ModSecurity** gates on `^[[:space:]]*multipart/form-data([;,[:space:]]|$)`
  (the full separator class PHP accepts) and matches `REQUEST_BODY`, not just
  parsed parts.
- **OpenResty Lua** accepts the same separator class, reads up to **1 MB** of
  body by default (the upstream 64 KB default let attackers pad the trigger
  past the inspection window), and warns on a multipart body with no parsable
  part in the inspected prefix.

## Important limitations

- **These rules complement patching, they do not replace it.** Upgrade PHP to
  **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** or later (8.0-8.1 / 7.x / 5.x are EOL
  with no official fix).
- The **OOM-corruption chains** (large plain fields, `max_input_vars` trip,
  cookie-carry arming) send *none* of these strings. They are only visible on
  the response side (5xx / OOM) and via behaviour. Keep the Sigma
  process-creation rule (PHP spawning a shell) - it is unaffected by any
  request-side bypass.
- **Three impact paths survive the 8.5.12 patch** (`var_destroy` re-entry UAF,
  serialize-handler mismatch, upload-progress filename injection). Filename /
  serialized-object rules still matter on "patched" hosts.
- WAFs that cap body inspection (often 64 KB) can be padded past. Raise the
  inspection window where you can, and rely on PHP-level mitigation
  (`session.upload_progress.enabled = Off` is partial; the OOM path does not
  need it) plus patching for completeness.

## References

- GHSA-w8hw-w9fx-j79w (CVE-2026-109618), GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- ikow/php2shell-poc - `docs/ANALYSIS.md`, `docs/PATCH_ANALYSIS.md`
- dinosn/php-cve-2026-10961x-lab-poc - `docs/WAF-BYPASS.md`
- Sansec research on the PHPSESSID memory leak; JFrog full technical analysis
