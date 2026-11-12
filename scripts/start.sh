#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v docker >/dev/null; then echo 'Docker missing. Ubuntu: sudo bash scripts/install-docker-ubuntu.sh'; exit 1; fi
DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then DOCKER=(sudo docker)
  else echo 'Docker permission denied. Run sudo bash scripts/start.sh or log into the docker group.'; exit 1; fi
fi
if ! "${DOCKER[@]}" compose version >/dev/null 2>&1; then echo 'Docker Compose v2 is required'; exit 1; fi
bash scripts/generate-env.sh
"${DOCKER[@]}" compose --profile security --profile monitoring config --quiet
"${DOCKER[@]}" compose --profile security --profile monitoring up -d --build
port="$(sed -n 's/^LAB_PORT=//p' .env | head -1)"; port="${port:-8080}"
echo
echo "Lab startup requested. On ECS: curl -I http://127.0.0.1:$port/"
echo 'For secure browser access from your laptop, run locally:'
echo "  ssh -L $port:127.0.0.1:$port ubuntu@ECS_PUBLIC_IP"
echo "  open http://localhost:$port/"
echo 'Grafana with an additional SSH tunnel: ssh -L 3000:127.0.0.1:3000 ubuntu@ECS_PUBLIC_IP'
echo 'Optional antivirus: docker compose --profile antivirus up -d clamav'
echo 'Show status: bash scripts/status.sh'
