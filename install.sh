#!/usr/bin/env bash
# One-command idempotent Docker Compose deployment for Ubuntu 22.04/24.04 on ECS.
set -euo pipefail
cd "$(dirname "$0")"
if [[ "$(id -u)" != 0 ]]; then echo 'Run sudo bash install.sh'; exit 1; fi
if [[ "$(uname -m)" != 'x86_64' ]]; then echo 'This release is validated for linux/amd64. Please use an amd64 ECS.'; exit 1; fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo '[1/5] Installing Docker Engine and Docker Compose v2 from Ubuntu packages…'
  bash scripts/install-docker-ubuntu.sh
fi
if ! docker info >/dev/null 2>&1; then systemctl enable --now docker; fi
if ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl; fi
# Preserve the previously working v2.1 LAPI/bouncer credentials when upgrading.
if [[ ! -f .env && -f ../CloudShield_KooLab_v2/.env ]]; then
  cp ../CloudShield_KooLab_v2/.env .env
  chmod 600 .env
  echo 'Preserved existing v2 secrets to prevent CrowdSec LAPI mismatches.'
fi
bash scripts/generate-env.sh
profiles=(--profile security --profile monitoring)
ram_kib="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
if [[ "${ram_kib:-0}" -ge 6800000 ]]; then
  profiles+=(--profile antivirus)
  echo '[2/5] 7+ GiB detected: including real ClamAV antivirus daemon.'
else
  echo '[2/5] Less than 7 GiB RAM: ClamAV not auto-started to prevent ECS OOM.'
  echo '       Enable it later: sudo docker compose --profile antivirus up -d clamav'
fi
echo '[3/5] Validating configuration and building v3 images BEFORE changing running containers…'
docker compose "${profiles[@]}" config --quiet
# Preserve all persistent volumes but recreate the Docker network with a fixed probe-client IP.
# This is needed when upgrading from v1.1, whose bridge used an automatic subnet.
# Build before stopping existing containers so a build failure doesn't take the lab offline.
if ! docker compose "${profiles[@]}" build; then
  echo 'ERROR: Image build failed. Existing containers were NOT stopped.' >&2
  echo 'Try: sudo docker compose build toolbox' >&2
  exit 1
fi
docker compose "${profiles[@]}" down --remove-orphans
docker compose "${profiles[@]}" up -d --no-build --remove-orphans
echo '[4/5] Checking HTTP gateway…'
healthy=0
for i in $(seq 1 55); do
  if curl -fsS --max-time 3 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then healthy=1; break; fi
  sleep 3
done
if [[ "$healthy" != 1 ]]; then
  echo 'Application not yet ready. Inspect: sudo docker compose ps && sudo docker compose logs --tail 100 labapp waf'
  docker compose ps
  exit 1
fi
echo '[5/5] Application responding. Container status:'
docker compose "${profiles[@]}" ps
printf '\nCLOUDSHIELD v3 READY\n'
echo '  ECS local: http://127.0.0.1:8080'
echo '  Grafana:   http://127.0.0.1:3000'
echo '  ECS2 receiver: ECS1_PRIVATE_IP:9108 (allow ONLY ECS2 private IP in Huawei SG)'
echo '  ECS2 agent token: sudo grep ^TELEMETRY_TOKEN= .env (instructor only)'
echo '  Student PC SSH tunnel: ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 ubuntu@YOUR_ECS_PUBLIC_IP'
echo '  Then open http://localhost:8080'
echo '  Validation: bash scripts/acceptance-v3.sh'
echo '  Diagnostics: bash scripts/diagnose.sh'
echo '  ClamAV definitions may still be updating after the main UI is ready.'
