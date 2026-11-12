#!/usr/bin/env bash
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8080}"
pass(){ echo "PASS $1"; }
expect(){ local path="$1" wanted="$2" actual; actual="$(curl -sS --max-time 15 -o /tmp/cloudshield-smoke.$$ -w '%{http_code}' "$BASE$path")"; if [[ "$actual" == "$wanted" ]]; then pass "$path returned $wanted"; else echo "FAIL $path expected $wanted got $actual"; cat /tmp/cloudshield-smoke.$$; rm -f /tmp/cloudshield-smoke.$$; exit 1; fi; }
trap 'rm -f /tmp/cloudshield-smoke.$$' EXIT
expect /healthz 200
expect /target/health 200
expect /target/data 200
expect /api/status 200
if [[ "${CHECK_WAF:-1}" == "1" ]]; then
  actual="$(curl -sS -G --max-time 15 -o /tmp/cloudshield-smoke.$$ -w '%{http_code}' --data-urlencode "q=1' OR '1'='1" "$BASE/target/echo")"
  if [[ "$actual" == "403" ]]; then pass 'Coraza WAF denied benign SQLi-shaped probe';
  else echo "WARN WAF response was $actual (expected 403). Inspect CRS container logs and tuning."; fi
fi
echo 'Smoke checks finished.'
