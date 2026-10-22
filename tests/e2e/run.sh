#!/bin/bash
# End-to-end test in throwaway Debian containers:
#   1. a pristine host must come back clean (false-positive check)
#   2. a host with planted php2shell IOCs must come back COMPROMISED (exit 3)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCANNER="$(cd "$HERE/../.." && pwd)"
IMAGE="${IMAGE:-python:3.11-slim-bookworm}"
OUT="${OUT:-$(mktemp -d)}"
fail=0

echo "== clean host ($IMAGE)"
# SYS_PTRACE: Docker drops it, but root on a real host has it (needed for /proc/<pid>/fd)
docker run --rm --cap-add SYS_PTRACE -v "$SCANNER:/scanner:ro" "$IMAGE" \
  python3 /scanner/php2shell-scanner.py --no-color -q > "$OUT/clean.txt"
code=$?
tail -25 "$OUT/clean.txt"
[ "$code" -eq 0 ] || { echo "FAIL: clean host exit code $code (expected 0)"; fail=1; }

echo "== compromised host ($IMAGE)"
docker run --rm --cap-add SYS_PTRACE -v "$SCANNER:/scanner:ro" "$IMAGE" bash -c \
  "bash /scanner/tests/e2e/plant_iocs.sh >/dev/null && \
   python3 /scanner/php2shell-scanner.py --no-color -q --json /tmp/r.json; \
   code=\$?; cat /tmp/r.json > /dev/stderr; exit \$code" \
  > "$OUT/compromised.txt" 2> "$OUT/compromised.json"
code=$?
cat "$OUT/compromised.txt"
[ "$code" -eq 3 ] || { echo "FAIL: compromised host exit code $code (expected 3)"; fail=1; }

expected="SESS-PHP-CODE SESS-POC-SID LOG-POC-SID LOG-LFI-SESSION LOG-PMA-BRUTEFORCE \
LOG-WEBSHELL-TRAFFIC LOG-WEBSHELL-CLIENT ERR-SESS-DESTROY ERR-WORKER-CRASH WEB-EVAL-INPUT \
DB-UDF-BACKDOOR PERSIST-WEBUSER-CRON ACCT-WEBUSER-SSH-KEY TMP-COMMAND-OUTPUT \
NET-SHELL-CONNECTION PROC-WEBUSER-SHELL PROC-FAKE-KTHREAD PROC-TMP-EXE \
INTEGRITY-MODIFIED-BINARY"
for rule in $expected; do
  grep -q "\"rule\": \"$rule\"" "$OUT/compromised.json" || { echo "FAIL: missing $rule"; fail=1; }
done
echo "reports in $OUT"
[ "$fail" -eq 0 ] && echo "E2E PASSED" || echo "E2E FAILED"
exit "$fail"
