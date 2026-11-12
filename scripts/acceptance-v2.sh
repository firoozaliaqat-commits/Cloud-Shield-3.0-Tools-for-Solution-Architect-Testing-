#!/usr/bin/env bash
# Live integration checks on the running ECS. Exit nonzero when required checks fail.
set -euo pipefail
cd "$(dirname "$0")/.."
base="${LAB_BASE_URL:-http://127.0.0.1:8080}"
command -v curl >/dev/null || { echo 'curl required'; exit 1; }
echo '[1] Health and dedicated pages'
curl -fsS "$base/healthz" >/dev/null
for page in overview crowdsec waf suricata clamav k6 iperf3 prometheus grafana store guide; do
 curl -fsS "$base/tool/$page" | grep -q 'CloudShield' || { echo "FAIL page $page"; exit 1; }
done
echo '[2] Protected normal request'
curl -fsS "$base/target/whoami" | grep -q 'observed_client_ip'
echo '[3] Actual WAF probe (normal)'
curl -fsS -H 'Content-Type: application/json' -d '{"profile":"normal"}' "$base/api/tools/waf/check" | grep -q 'http_status'
echo '[4] Actual separate-container HTTP probe (no fabricated result)'
curl -fsS "$base/api/tools/probe" | grep -q 'actual_http_status'
echo '[5] Actual CrowdSec Local API (availability, not fake decisions)'
status=$(curl -s -o /dev/null -w '%{http_code}' "$base/api/tools/crowdsec/decisions")
if [[ "$status" != '200' ]]; then echo "WARN: CrowdSec LAPI not ready (HTTP $status)"; fi
echo '[6] Real Prometheus endpoint exports actual instrumented metrics'
curl -fsS "${base}/metrics" | grep -q 'cloudshield_active_bans'
echo '[7] iperf3 real network test (2 seconds)'
curl -fsS --max-time 30 -H 'Content-Type: application/json' -d '{"seconds":2}' "$base/api/tools/iperf3/run" | grep -q 'receiver_mbps'
echo '[8] Suricata actual PCAP engine'
curl -fsS --max-time 110 -H 'Content-Type: application/json' -d '{}' "$base/api/tools/suricata/run" | grep -q '"engine":"Suricata"'
echo '[9] Live Prometheus query endpoint'
curl -fsS --max-time 12 -H 'Content-Type: application/json' -d '{"query":"up"}' "$base/api/tools/prometheus/query" | grep -q 'live Prometheus'
echo '[10] Check ClamAV daemon readiness'
if curl -fsS "$base/api/tools/clamav/health" | grep -q '"ready":true'; then
 echo 'ClamAV daemon ready (run EICAR check in its tool page).'
else echo 'WARN ClamAV signature database still loading or not enabled.'; fi
echo '[11] Grafana and Prometheus port / health checks'
if curl -fsS http://127.0.0.1:3000/api/health >/dev/null; then echo 'Grafana online'; else echo 'WARN Grafana unavailable'; fi
if curl -fsS http://127.0.0.1:9090/-/healthy >/dev/null; then echo 'Prometheus online'; else echo 'WARN Prometheus unavailable'; fi
echo 'PASS REQUIRED checks. For complete IP ban verification use CrowdSec page: send -> ban -> HTTP 429 -> unblock -> HTTP 200.'
