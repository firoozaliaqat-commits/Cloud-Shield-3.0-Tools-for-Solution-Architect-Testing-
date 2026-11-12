#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" != 0 ]]; then echo 'Use: sudo bash scripts/install-docker-ubuntu.sh'; exit 1; fi
if ! grep -qi ubuntu /etc/os-release; then echo 'This installer is designed for Ubuntu 22.04/24.04.'; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl unzip docker.io
if ! apt-get install -y docker-compose-v2; then
  apt-get install -y docker-compose-plugin || { echo 'Docker Compose v2 missing. Install Docker Compose v2 from docs.docker.com.'; exit 1; }
fi
systemctl enable --now docker
docker compose version
echo 'Docker ready. Next: bash scripts/start.sh'
