# CloudShield v2 live acceptance gates

Run on Huawei ECS after `sudo bash install.sh`:

```bash
bash scripts/acceptance-v2.sh
bash scripts/verify-ip-ban.sh
```

**Mandatory gates:** 11 tool pages open; backend responds; WAF normal check works; separate toolbox client gives real HTTP code; iperf3 returns numeric measured Mbps; Suricata returns real engine output plus alert log; Grafana/Prometheus reachable; ban test produces actual HTTP 200→429→200. ClamAV must respond to daemon PING and to EICAR before marking antivirus lesson complete. CrowdSec LAPI must return live decisions; if no decisions exist, show an empty list rather than fabricated blocks.

If any gate fails, examine:

```bash
sudo docker compose --profile security --profile monitoring --profile antivirus ps
sudo docker compose logs --tail 150 labapp waf toolbox crowdsec prometheus grafana clamav
```

A missing live test is NOT an acceptance pass. Offline unit tests only establish code behavior, not Docker image start compatibility or actual ECS network paths.
