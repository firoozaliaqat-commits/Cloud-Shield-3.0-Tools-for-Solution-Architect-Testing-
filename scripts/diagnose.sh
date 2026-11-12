#!/usr/bin/env bash
# Collect useful status without printing the secret .env values.
set -uo pipefail
cd "$(dirname "$0")/.."
echo '== CloudShield v2.1 diagnostics =='
echo '== Docker and Compose versions =='
docker --version || true
docker compose version || true
echo '== Container status =='
docker compose --profile security --profile monitoring --profile antivirus ps || true
echo '== Toolbox binaries and worker health =='
docker compose exec -T toolbox sh -c 'command -v suricata; suricata --build-info | head -4; command -v iperf3; iperf3 --version | head -1' || true
echo '== Last container errors (no .env disclosure) =='
docker compose --profile security --profile monitoring --profile antivirus logs --tail 35 labapp toolbox waf crowdsec grafana prometheus || true
echo '== CloudShield HTTP health =='
curl -sS -m 5 -i http://127.0.0.1:8080/healthz || true
