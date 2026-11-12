#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v openssl >/dev/null || { echo 'openssl missing'; exit 1; }
if [[ ! -f .env ]]; then
  (umask 077; cat > .env <<EOF
LAB_BIND_IP=127.0.0.1
LAB_PORT=8080
MAX_VUS=30
MAX_SECONDS=120
CROWDSEC_BOUNCER_KEY=$(openssl rand -hex 32)
GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 24)
TOOLBOX_TOKEN=$(openssl rand -hex 32)
TELEMETRY_TOKEN=$(openssl rand -hex 32)
TELEMETRY_BIND_IP=0.0.0.0
EOF
  )
  echo 'New lab credentials generated.'
else
  # Upgrade existing 1.1 deployment without losing instructor VPC settings or volume state.
  for field in CROWDSEC_BOUNCER_KEY GRAFANA_ADMIN_PASSWORD TOOLBOX_TOKEN TELEMETRY_TOKEN; do
    if ! grep -q "^${field}=" .env; then echo "${field}=$(openssl rand -hex 32)" >> .env; fi
  done
  if ! grep -q '^TELEMETRY_BIND_IP=' .env; then echo 'TELEMETRY_BIND_IP=0.0.0.0' >> .env; fi
  chmod 600 .env
  echo 'Existing .env retained and missing v2 credentials added.'
fi
chmod 600 .env
