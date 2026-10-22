#!/bin/bash
# False-positive check on a REAL stack: nginx + php-fpm + phpMyAdmin + WordPress on
# Debian 12. Expected verdict: EXPOSED (vulnerable PHP present) — never COMPROMISED /
# LIKELY COMPROMISED / SUSPICIOUS. Needs network access for apt and wordpress.org.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCANNER="$(cd "$HERE/../.." && pwd)"

docker run --rm --cap-add SYS_PTRACE -v "$SCANNER:/scanner:ro" debian:bookworm bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq nginx php-fpm php-mysql phpmyadmin curl python3 procps >/dev/null 2>&1
curl -fsSL https://wordpress.org/latest.tar.gz | tar xz -C /var/www/html
mkdir -p /var/www/html/wordpress/wp-content/uploads/2026/10
printf "\x89PNG\r\n\x1a\nIHDR" > /var/www/html/wordpress/wp-content/uploads/2026/10/photo.png
ln -s /usr/share/phpmyadmin /var/www/html/phpmyadmin
service php8.2-fpm start >/dev/null; service nginx start >/dev/null
curl -s -o /dev/null http://127.0.0.1/ ; curl -s -o /dev/null http://127.0.0.1/phpmyadmin/
curl -s -o /dev/null -X POST -d "log=a&pwd=b" http://127.0.0.1/wordpress/wp-login.php
sleep 1
python3 /scanner/php2shell-scanner.py --no-color -q --since 1d --json /tmp/fp.json
code=$?
python3 - <<EOF
import json
d = json.load(open("/tmp/fp.json"))
print("verdict:", d["verdict"]["label"], "| counts:", d["counts"])
for f in d["findings"]:
    if f["severity"] != "INFO":
        print("  ", f["severity"], f["kind"], f["rule"], f["path"], "|", f["title"][:90])
EOF
exit $code
'
code=$?
echo "scanner exit code: $code (expected 1 = EXPOSED)"
[ "$code" -le 1 ] && echo "FP CHECK PASSED" || { echo "FP CHECK FAILED"; exit 1; }
