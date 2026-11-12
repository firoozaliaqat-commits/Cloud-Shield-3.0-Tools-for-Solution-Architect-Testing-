#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if docker info >/dev/null 2>&1; then d=(docker); else d=(sudo docker); fi
"${d[@]}" compose --profile security --profile monitoring --profile antivirus ps
port="$(sed -n 's/^LAB_PORT=//p' .env 2>/dev/null | head -1)"; port="${port:-8080}"
printf '\nApp HTTP readiness: '
curl -fsS --max-time 5 http://127.0.0.1:$port/healthz || true
printf '\n\nRecent application logs:\n'
"${d[@]}" compose logs --tail 10 labapp
