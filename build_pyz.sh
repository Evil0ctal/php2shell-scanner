#!/bin/bash
# Builds dist/php2shell-scanner.pyz: one self-contained file to copy onto servers.
#   scp dist/php2shell-scanner.pyz server:/tmp/ && ssh server sudo python3 /tmp/php2shell-scanner.pyz
set -euo pipefail
cd "$(dirname "$0")"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp -R php2shell_scanner "$stage/"
find "$stage" -name '__pycache__' -type d -prune -exec rm -rf {} +
cat > "$stage/__main__.py" <<'EOF'
import sys

from php2shell_scanner.cli import main

sys.exit(main())
EOF
mkdir -p dist
python3 -m zipapp "$stage" -p "/usr/bin/env python3" -o dist/php2shell-scanner.pyz
echo "built dist/php2shell-scanner.pyz ($(wc -c < dist/php2shell-scanner.pyz) bytes)"
shasum -a 256 dist/php2shell-scanner.pyz 2>/dev/null || sha256sum dist/php2shell-scanner.pyz
