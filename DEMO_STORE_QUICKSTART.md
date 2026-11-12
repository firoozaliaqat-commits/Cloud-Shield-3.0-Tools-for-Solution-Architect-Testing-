# CloudShield Demo Store — Five-minute student practical

The **KooLab Demo Store** is built into CloudShield v1.1. Students can use one Ubuntu ECS. All store endpoints are under `/target/*`, so CloudShield's lab IP bans and its Coraza WAF gateway can evaluate requests. No real users, payment credentials or customer information are involved.

## Start on Huawei ECS

```bash
unzip CloudShield_Huawei_KooLab_v1_1_DemoStore.zip
cd CloudShield_Huawei_KooLab
sudo bash scripts/install-docker-ubuntu.sh  # only if Docker Compose is missing
sudo bash scripts/start.sh
sudo docker compose ps
bash scripts/smoke-test.sh
```

A first startup needs outbound internet for Docker image downloads. The app may take additional time while image layers are pulled. Use `sudo docker compose logs -f --tail 100 labapp waf` if containers do not start.

From your Windows workstation, create the secure tunnel to the ECS (replace IP/user/key):

```bash
ssh -L 8080:127.0.0.1:8080 -L 3000:127.0.0.1:3000 ubuntu@ECS_PUBLIC_IP
```

Open:

- Demo Store: `http://localhost:8080/target/store`
- CloudShield Dashboard: `http://localhost:8080/`
- Grafana: `http://localhost:3000/`

Do not expose ports 8080/3000 publicly; they lack production-grade authentication.

## Six activities

1. **HTTP 200:** Browse products, search for `cloud`, add a hoodie to the cart, complete a dummy order.
2. **Normal load:** In CloudShield choose **Demo Store journey**, 5 VUs, 30 seconds. Click Start. Review the request count and p95 latency.
3. **Scaling:** Run 10 and 20 VUs separately, each for 30 seconds. Compare how p95 latency changes; note that VUs are simulated clients, not guaranteed requests/second.
4. **Time-limited IP ban:** Choose **Auto-ban duration = 1 min** and Save. Run **Failed logins**, 1 VU, 10 seconds. Verify the private client IP appears under **Temporary IP Bans** and `/target/*` calls from that same client get HTTP 429. The block should expire automatically. Note that other client IPs may remain allowed.
5. **WAF check:** Run **WAF signature** with 1 VU for 10 seconds. Look for HTTP 403 and inspect `sudo docker compose logs --tail 80 waf`. A WAF result is only verified if 403 occurs; ruleset compatibility can vary.
6. **Recovery:** Check that ban TTL expired or manually Unblock; replay **Demo Store journey** and verify successful requests. Capture the run result, ban and event screenshots.

## API checks from ECS

```bash
curl -i http://127.0.0.1:8080/target/store/api/products
curl -i 'http://127.0.0.1:8080/target/store/api/search?q=cloud'
curl -i -X POST http://127.0.0.1:8080/target/store/api/checkout \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"product_id":101,"quantity":1}]}'
```

**Correct interpretation:** These curls traverse the WAF and should return HTTP 200 when it is healthy and no active block applies. They do not by themselves demonstrate a CrowdSec ban. The `Failed logins` demo uses CloudShield Lab Guard's SQLite-backed TTL rules. CrowdSec's independent decisions must be checked with `cscli`, and Suricata is an offline PCAP exercise in this version.

## Instructor acceptance checks

- `sudo docker compose ps`: `labapp` and `waf` are healthy/up; optional services in their appropriate profiles.
- CloudShield and storefront both render through an SSH tunnel.
- Dummy checkout returns `LAB-...` with HTTP 200 and creates synthetic SQLite order.
- Demo Store k6 run creates a run ID and summary file; metrics visible in dashboard/Grafana.
- A failed-login demo blocks only the source IP it observed, returns 429 to that source, and automatically expires.
- WAF signature produces 403 if the active CRS recognizes the pattern; otherwise investigate the WAF config rather than pretending the test passed.
- `bash scripts/test-suricata.sh` is an optional separate PCAP lab; `clamav` optional profile is a separate antivirus lab.

**Constraint:** This integrated store is the only app whose `/target/*` routes receive all the local CloudShield protections. The private VPC GET profile to a second ECS is load-only and does not proxy its requests through CloudShield WAF.

**Verification status:** Python FastAPI integration tests have passed; full Docker/K3s runtime cannot be executed in this build environment. Perform the instructor checks above on the actual Huawei ECS before using the ZIP for a full class.
