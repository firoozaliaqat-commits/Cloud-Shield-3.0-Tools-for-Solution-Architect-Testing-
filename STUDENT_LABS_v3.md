# Student practical workbook (CloudShield v3)

Students submit evidence of actual HTTP/engine results and the matching Grafana time range, not just a successful button click.

1. **Demo Store 1 baseline:** Browse products, search, submit a dummy checkout. Record HTTP 200 and order ID (synthetic).
2. **Independent IP clients:** On CrowdSec page prove A/B/C have different IPs *observed by the protected application*. If not, report the fault instead of continuing.
3. **Temporary IP block:** Ban B for one minute. Record actual HTTP 429 for B and HTTP 200 for A/C. Unban B manually, verify HTTP 200. Repeat using automatic TTL.
4. **Behavioral abuse:** Generate five failed logins *from client B*. Check separate local application-guard decision and CrowdSec LAPI. Explain the difference; never call a local ban a CrowdSec detection.
5. **Coraza WAF:** Submit ordinary text, harmless SQL-shaped, script-shaped, and traversal-shaped input. Record text, HTTP status, real rule ID from audit if present, and explanation for each. Explain false positives.
6. **Suricata live IDS:** Inspect status and current alerts. Send benign `LAB_TEST_MARKER` request on isolated monitored namespace. Check EVE signature. Stop sensor and observe monitoring OFF; restart.
7. **Suricata offline analysis:** Read the supplied harmless PCAP; identify one real Suricata alert and source IP.
8. **Optional NFQUEUE IPS:** Start isolated IPS on TCP 8096. Verify normal request succeeds, harmless marker request is dropped *and backed by EVE action evidence*. If NFQUEUE unsupported, record the real error. Stop IPS and restore normal access.
9. **ClamAV:** Scan a harmless file; run EICAR scan with live daemon; compare statuses.
10. **Classic k6:** Run normal, store journey, controlled spike, download, failed login and WAF signature scenarios against the local store; inspect summaries.
11. **Distributed k6 on one ECS:** Use 6 VUs across 3 containers for 10 seconds at 12 req/s cap. Compare per-agent reports and Grafana. Explain how source IP differs from VU identity.
12. **Local iperf3:** Run TCP forward and reverse tests. Record actual Mbps and retransmissions. Explain Docker bridge limitation.
13. **Optional remote k6:** Enter ECS2 private IP and port 8081 in UI; test `/health` then `/api/products` and compare p95 latency with local store.
14. **Optional remote iperf3:** Set ECS2 private IP and port 5201. Run TCP upload/download and bounded UDP. Report Mbps, jitter and packet loss where returned.
15. **Optional ECS2 telemetry:** Configure telemetry token and port 9108. Confirm fresh real ECS2 CPU/RAM samples on Remote ECS page and Grafana dashboard 10.
16. **Grafana:** Review 8 original + 3 new dashboards. Interpret trends; a missing metric is not zero.
17. **Reliability:** Emergency-stop a running k6 test, stop/restart Suricata, restore B access, and verify admin UI remains reachable.

Instructor safety: open only scoped private VPC security-group ports. All tests are authorized and resource bounded; avoid production targets. Use K3s on a separate deployment mode if RAM is limited.
