#!/bin/bash
# Remote scanner against real PHP stacks in Docker (needs Docker + network to pull images).
#   php:8.2.34-apache  vulnerable, version in X-Powered-By            -> VULNERABLE
#   php:7.4-apache     EOL branch                                     -> VULNERABLE
#   php:8.3-apache     8.3.36 (fixed)                                 -> NOT VULNERABLE
#   php:8.2.34-apache  expose_php=Off, phpinfo exposed, upload_progress Off
#                                                                    -> VULNERABLE (+ mitigation)
#   wordpress:latest   real WordPress (no DB)                         -> by its PHP version
#   nginx:alpine       static site                                    -> NO PHP DETECTED
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX=p2s-remote
fail=0

cleanup() { docker rm -f $(docker ps -aq --filter "name=$PREFIX") >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

start_php() {  # name image port [ini]
  docker run -d --name "$PREFIX-$1" -p "127.0.0.1:$3:80" "$2" >/dev/null
  docker exec "$PREFIX-$1" sh -c 'echo "<?php session_start(); echo \"hello\";" > /var/www/html/index.php'
  if [ -n "${4:-}" ]; then
    docker exec "$PREFIX-$1" sh -c "printf '$4' > /usr/local/etc/php/conf.d/zz-test.ini && \
      echo '<?php phpinfo();' > /var/www/html/info.php && apache2ctl -k graceful"
  fi
}

start_php vuln   php:8.2.34-apache 18101
start_php eol    php:7.4-apache    18102
start_php fixed  php:8.3-apache    18103
start_php hidden php:8.2.34-apache 18104 'expose_php=Off\nsession.upload_progress.enabled=Off\n'
docker run -d --name "$PREFIX-wp" -p 127.0.0.1:18105:80 wordpress:latest >/dev/null
docker run -d --name "$PREFIX-static" -p 127.0.0.1:18106:80 nginx:alpine >/dev/null
sleep 6

expect() {  # port expected-status
  out=$(python3 "$ROOT/php2shell-scanner.py" scan --yes -q --no-markdown --delay 0 \
        --json - "http://127.0.0.1:$1/")
  status=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["results"][0]["status"])')
  detail=$(printf '%s' "$out" | python3 -c 'import json,sys; r=json.load(sys.stdin)["results"][0]; print(list(r["versions"]), r["confidence"], r["mitigations"][:1])')
  printf '%-6s %-18s %s\n' "$1" "$status" "$detail"
  [ "$status" = "$2" ] || { echo "  FAIL: expected $2"; fail=1; }
}

expect 18101 "VULNERABLE"
expect 18102 "VULNERABLE"
expect 18103 "NOT VULNERABLE"
expect 18104 "VULNERABLE"
wp_version=$(docker exec "$PREFIX-wp" php -r 'echo PHP_VERSION;')
wp_expect=$(python3 -c "import sys; sys.path.insert(0, '$ROOT'); from php2shell_scanner.versions import version_vulnerable as v; print('VULNERABLE' if v('$wp_version') else 'NOT VULNERABLE')")
echo "wordpress image runs PHP $wp_version"
expect 18105 "$wp_expect"
expect 18106 "NO PHP DETECTED"

[ "$fail" -eq 0 ] && echo "REMOTE E2E PASSED" || echo "REMOTE E2E FAILED"
exit "$fail"
