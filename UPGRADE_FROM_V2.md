# Upgrading the existing v2.1 ECS safely

1. Upload `CloudShield_ECS1_v3.zip` to `/root`.
2. Run `unzip -oq CloudShield_ECS1_v3.zip && sudo bash CloudShield_ECS1_v3/install.sh`.
3. The installer copies `../CloudShield_KooLab_v2/.env` if available to preserve existing CrowdSec LAPI bouncer and Grafana credentials, adds missing v3 telemetry token, builds images **before** stopping old Compose services, and restarts the same Compose project (named volumes preserved).
4. Verify `sudo bash CloudShield_ECS1_v3/scripts/acceptance-v3.sh`. Do **not** run `docker compose down -v` or delete named volumes.
5. New security architecture sends `/api/*` and the student UI directly to the backend gateway while only `/target/*` is routed through Coraza. This prevents a WAF rule or test-client IP ban from locking out the instructor page.
6. A previously saved v2 ban on the Docker gateway address 172.30.56.1 is automatically cleared at app start. Other bans are preserved. Use per-client unban/emergency reset for lab clients.
7. The prior eight Grafana dashboards and their UIDs remain unchanged; 3 new dashboards are added.

If any previous custom static IP networks overlap your actual VPC network, resolve that overlap before installing. Source code testing is not equivalent to a full Docker deployment test; preserve logs for a reproducible repair.
