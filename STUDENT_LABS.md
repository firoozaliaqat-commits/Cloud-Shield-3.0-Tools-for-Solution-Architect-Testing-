# CloudShield v2 — student practical checklist

Student goal: produce evidence of **what really happened**, not screenshots of a pretend switch.

| Session | Tool URL | Action | Evidence to record |
|---|---|---|---|
| 1 | `/tool/crowdsec` | Check real source; ban; recheck; unban | Actual 200→429→200 HTTP status, IP and TTL |
| 2 | `/tool/waf` | Compare 4 real Coraza requests | Real 200 or 403 status and WAF log excerpt |
| 3 | `/tool/suricata` | Run real Suricata PCAP check | `eve.json` signature and src IP, engine exit code |
| 4 | `/tool/clamav` | Scan safe text and EICAR | Real `OK` and `FOUND` from clamd |
| 5 | `/tool/k6` | Run demo store journey at 1/5/10 VUs | Requests, p95, error ratio, bytes, resource chart |
| 6 | `/tool/iperf3` | Run real 2/4/10s TCP tests | Actual Mbps, byte count, retransmits |
| 7 | `/tool/prometheus` | Query live targets and PromQL | Actual returned instant samples and scrape status |
| 8 | `/tool/grafana` | Inspect 8 dashboards | Real charts and 'No data' explanations |

Never upload malicious executables, target public services, or perform unapproved heavy loads. Data used in the Demo Store is synthetic.
