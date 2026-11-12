# Validation and release status

**Static checks completed in the build environment:** Python compilation, JavaScript parser (`node --check`), shell syntax, Compose/YAML parsing, all Kubernetes YAML parsing, 11 Grafana JSON dashboards parsing, and dedicated v3 FastAPI contract tests (18 passing).

**Not available in the build environment:** Docker Engine, Docker Compose runtime, K3s runtime, Huawei ECS, actual CrowdSec/Coraza/Suricata/ClamAV/iperf3 container execution, and live ECS2 telemetry. Therefore these are *implementation packages with reproducible acceptance scripts*, **not certified error-free images or proven Huawei deployments**.

After installer finishes on ECS1, run `sudo bash scripts/acceptance-v3.sh`. A real failure must be corrected before classroom use. The script tests real HTTP source addresses, ban/unban with control clients, WAF, Suricata status, local iperf3 and distributed k6. On ECS2, inspect `sudo docker compose ps` and `sudo docker compose logs --tail=40 agent` and run `curl http://127.0.0.1:8081/health`.

**Limits:** Suricata live IDS only sees a dedicated namespace. Optional IPS is Linux NFQUEUE-dependent and never alters the ECS host firewall. The classroom UI has no password and is bound to loopback; do not expose it publicly. ECS2 metrics use token-authenticated ingestion over HTTP inside a controlled VPC; restrict SG rules carefully. Per-pod IP != necessarily VPC-visible IP due NAT. CrowdSec LAPI bans != CloudShield application bans.
