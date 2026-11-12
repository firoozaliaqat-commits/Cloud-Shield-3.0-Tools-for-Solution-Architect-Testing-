#!/usr/bin/env bash
# Installs CloudShield 3.0 into an EXISTING single-node K3s cluster.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v k3s >/dev/null || { echo 'K3s not found. Install K3s on this ECS first.'; exit 1; }
command -v docker >/dev/null || { echo 'Docker needed for local image build/import.'; exit 1; }
if [[ "$(id -u)" != 0 ]]; then echo 'Run sudo bash scripts/k3s-deploy.sh'; exit 1; fi
bash scripts/generate-env.sh
if docker compose ps --services --filter status=running | grep -Eq '^(waf|labapp)$'; then
  echo 'Stop Docker Compose first: sudo docker compose --profile security --profile monitoring --profile antivirus down'
  echo 'K3s + Compose should not compete for 8 GiB ECS resources.'
  exit 1
fi
key="$(sed -n 's/^CROWDSEC_BOUNCER_KEY=//p' .env | head -1)"
telemetry="$(sed -n 's/^TELEMETRY_TOKEN=//p' .env | head -1)"
token="$(sed -n 's/^TOOLBOX_TOKEN=//p' .env | head -1)"
[[ -n "$key" && -n "$token" ]] || { echo 'Credentials missing'; exit 1; }
for item in 'app/Dockerfile:cloudshield-lab:3.0.0' 'tools/Dockerfile:cloudshield-toolbox:3.0.0' 'config/iperf3.Dockerfile:cloudshield-iperf3:2.0.0' 'tools/client.Dockerfile:cloudshield-client:3.0.0' 'tools/k6-agent.Dockerfile:cloudshield-k6-agent:3.0.0'; do
  f="${item%%:*}"; img="${item#*:}"
  echo "Building and importing $img …"
  docker build -f "$f" -t "$img" .
  docker save "$img" | k3s ctr images import -
done
k3s kubectl apply -f k8s/00-core.yaml
k3s kubectl -n cloudshield create secret generic cloudshield-key \
  --from-literal=key="$key" --from-literal=toolboxToken="$token" --from-literal=telemetryToken="$telemetry" \
  --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl -n cloudshield create configmap grafana-provisioning \
  --from-file=prometheus.yaml=config/grafana/provisioning/datasources/prometheus.yaml \
  --from-file=provider.yaml=config/grafana/provisioning/dashboards/provider.yaml \
  --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl -n cloudshield create configmap grafana-dashboard \
  --from-file=config/grafana/dashboards \
  --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl apply -f k8s/10-monitoring.yaml -f k8s/20-security.yaml -f k8s/40-tools.yaml -f k8s/30-antivirus.yaml
k3s kubectl apply -f k8s/50-v3-agents.yaml -f k8s/60-v3-gateway.yaml -f k8s/70-v3-telemetry.yaml
for name in labapp waf toolbox iperf3-server gateway client-a client-b client-c load-1 load-2 load-3; do
 k3s kubectl -n cloudshield rollout status deployment/"$name" --timeout=240s
done
k3s kubectl -n cloudshield get pods
printf '\nK3s services are internal. In separate ECS shells run:\n'
echo '  sudo k3s kubectl -n cloudshield port-forward --address 127.0.0.1 svc/gateway 8080:8080'
echo '  sudo k3s kubectl -n cloudshield port-forward --address 127.0.0.1 svc/grafana 3000:3000'
echo 'Then tunnel from student PC: ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 ubuntu@ECS_PUBLIC_IP'
