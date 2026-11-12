# CloudShield KooLab v3.0 — ECS1 All-in-One Security and Performance Lab

**What you get:** one Ubuntu ECS running CloudShield Operations, protected Demo Store 1, Coraza WAF, CrowdSec, actual isolated application-guard bans, three individually addressed security-test clients, continuous Suricata IDS capture on the toolbox namespace (Start/Stop), optional isolated NFQUEUE IPS, real ClamAV, normal + distributed k6, local + remote iperf3, Prometheus, Grafana (all 8 original dashboards plus 3 new), and an authenticated optional ECS2 telemetry collector. All core practicals work **without ECS2**.

**Hardware:** Ubuntu 24.04 amd64, Docker Engine with Compose v2. Target 4 vCPU/8 GiB **minimum for light classroom exercises**, preferably 8 vCPU/16 GiB when ClamAV, Suricata and parallel k6 agents are all active. This package contains source code; Docker downloads/builds images on first installation, requiring internet access and free disk space.

## One command — ECS1

Upload `CloudShield_ECS1_v3.zip` to `/root` and run:

```bash
unzip -oq CloudShield_ECS1_v3.zip && sudo bash CloudShield_ECS1_v3/install.sh
```

The script installs Docker if missing, preserves existing v2 credentials from `../CloudShield_KooLab_v2/.env` when present, compiles images, preserves named data volumes and starts services. Running it again is supported. **Do not delete volumes or use `docker compose down -v` during upgrades.**

Browser from the **student workstation** (SSH tunnel):

```bash
ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 ubuntu@ECS1_PUBLIC_IP
```

Open `http://localhost:8080` (CloudShield), `http://localhost:8080/target/store` (Demo Store 1), `http://localhost:3000` (Grafana). Management bypasses the Coraza WAF via a private gateway; only `/target/*` routes pass through the WAF. Keep port 8080/3000 loopback-bound and accessible by SSH tunnel. **This classroom app has no browser login and is not safe to expose to the public internet.**

## One-command smoke / live acceptance test

```bash
cd /root/CloudShield_ECS1_v3
sudo bash scripts/acceptance-v3.sh
```

This checks real HTTP health, three distinct source addresses, bans only B while A/C continue, releases bans, verifies a Coraza request, checks Suricata status, transfers bytes via iperf3, and runs a short real k6 workload. It prints PASS/FAIL; it is not a mocked test. Run it on ECS before giving the ZIP to students. If it fails, preserve logs and share them; a static build check is not proof of cloud runtime success.

## ECS2 optional companion

Deploy `CloudShield_ECS2_Target_v3.zip` on second Ubuntu ECS. Includes **only** Demo Store 2, an iperf3 receiver and an outbound lightweight host-metrics agent. The ECS2 package operates alone without ECS1, but optionally pushes real CPU/RAM/network/health every 10 s to ECS1 telemetry receiver via VPC.

On ECS1, the instructor reads (do not post this secret publicly):

```bash
sudo grep '^TELEMETRY_TOKEN=' /root/CloudShield_ECS1_v3/.env
```

On ECS2, replace IP and token:

```bash
unzip -oq CloudShield_ECS2_Target_v3.zip && cd CloudShield_ECS2_Target_v3 && \
sudo CLOUDSHIELD_RECEIVER=http://ECS1_PRIVATE_IP:9108 TELEMETRY_TOKEN=THE_ECS1_TOKEN bash install.sh
```

Huawei security groups: ECS1 inbound **TCP 9108 only from ECS2 private IP**. ECS2 inbound **TCP 8081 and TCP/UDP 5201 only from ECS1 private IP**. SSH limited to instructor. The telemetry receiver only forwards `POST /api/telemetry/ingest`, protected by a token. Use TLS if this leaves a controlled private VPC.

To test ECS2, from CloudShield k6 page select Remote, enter ECS2 private IP, port `8081` path `/health` or `/api/products`, set VUs, duration, number of agents and max request rate. For iperf3 set ECS2 IP, port `5201`, TCP/UDP and direction. **An HTTP server is not an iperf3 server**; both are provided on ECS2.

## Genuine vs non-genuine claims

- **Real independent clients:** three Docker containers have distinct private IPs `172.30.56.61/62/63`; the dashboard verifies IP observed by the protected application. Kubernetes mode uses distinct *pod* IPs; Huawei VPC outbound NAT may translate them to the node IP. Do not claim distinct cross-ECS source IPs unless ECS2 observes them.
- **CloudShield application guard (HTTP 429):** real HTTP enforcement for A/B/C, with manual unban, TTL expiry and emergency reset. **Not** a host-wide firewall drop. **Not** a CrowdSec LAPI decision. Actual CrowdSec decisions have a separate live panel and an independently queried bouncer check.
- **Coraza WAF:** genuine inspection via OWASP CRS. The output displays HTTP result, request content, and audit rule evidence *when available*. HTTP 403 alone does not prove which service blocked.
- **Suricata IDS:** real persistent process on `toolbox eth0`; captures the traffic visible to that container, **not the whole VPC**. Start/Stop frees CPU. Offline PCAP exercise preserved. Optional **isolated NFQUEUE IPS** queues only toolbox TCP 8096, never host SSH or CloudShield management. Linux kernel NFQUEUE support is required; unsupported environments show a real error rather than success.
- **k6:** real requests with per-agent report; `1–100` total VUs, `1–3` independent container workers, 5–120s, global cap 1–150 req/s. Original k6 exercises retained, but the older single-process runner still has the existing safety cap from `.env`. Tests are classroom load, not high-volume DDoS software.
- **iperf3:** actual TCP or UDP byte transfer. Local Docker bridge throughput is not a Huawei cloud 41 Gbit/s benchmark. Remote iperf measures real ECS-to-ECS connectivity only when receiver is installed and security groups allow port 5201.
- **Grafana:** the previous eight dashboards are unchanged (same files and UIDs); three new dashboards display real v3 Prometheus metrics. No data means no sample collected, not zero.
- **ClamAV:** real scanning, optional first-run signature initialization. EICAR is harmless; no real malware is shipped.

## Advanced Kubernetes mode

Docker Compose is the primary verified-from-source mode. Optional K3s native manifests are in `k8s/` with **three distinct k6 runner Pods + three client Pods**, gateway, telemetry, and the original tool deployments. Deploy on an existing single-node K3s host with `sudo bash scripts/k3s-deploy.sh` only after stopping Compose to avoid 8 GiB RAM contention. Pod IPs change; the app validates actual observed source IP before enabling per-client ban. The Kubernetes files have been structurally validated but **not live-deployed in this build environment**.

## Troubleshooting

```bash
sudo docker compose ps -a
sudo docker compose logs --no-color --tail=100 gateway waf labapp toolbox
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/target/store/api/products
curl -sS http://127.0.0.1:8080/api/v3/clients
sudo bash scripts/acceptance-v3.sh
```

If CrowdSec enforcement is unavailable, never claim its LAPI issued a ban merely because CloudShield's app guard returned 429. For a verified CrowdSec scenario, inspect `sudo docker compose exec crowdsec cscli decisions list` and associated logs. Always keep the instructor management route available.
