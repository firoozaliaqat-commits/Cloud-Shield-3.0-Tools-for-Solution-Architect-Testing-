# CloudShield v2.1 — Suricata build hotfix (Huawei ECS)

## Failure reported on Ubuntu 24.04

The v2 toolbox Dockerfile was based on `python:3.12-slim-bookworm`, but Debian 12 Bookworm's configured APT repositories did not include the `suricata` package. `docker compose up --build` therefore failed with `E: Package 'suricata' has no installation candidate` (exit 100).

## Fix

The v2.1 toolbox image uses `ubuntu:24.04`, where `suricata` is distributed in the Ubuntu universe repository, and installs `python3` and `iperf3` too. It retains the original worker API, PCAP lab exercise, Docker networks and project image names. The installer now builds images **before** stopping existing containers, preserving any running application when a new image build fails.

Official package listing: https://packages.ubuntu.com/noble/net/suricata

## Upgrade existing project (keep .env and named volumes)

Upload the fixed ZIP into the parent of your project folder and run:

```bash
cd ~
unzip -oq CloudShield_KooLab_v2_1_Fixed.zip
cd CloudShield_KooLab_v2
sudo bash install.sh
```

No need to install Docker again; the installer detects it. Do not use `docker compose down -v`, which deletes stored data.

## Check actual functions

```bash
sudo docker compose ps
bash scripts/acceptance-v2.sh
bash scripts/verify-ip-ban.sh
bash scripts/diagnose.sh
```

If the build fails with another message, include the last 60 lines of `sudo docker compose --profile security --profile monitoring --profile antivirus logs --tail 60` and the build output. `buildx isn't installed` is a performance warning, not the error shown in the original log.

## Known validation limitation

This hotfix has been syntax-, archive- and source-test-checked in the build environment, but we cannot start a real Docker daemon or Huawei ECS here. Do not call the entire deployment verified until the ECS acceptance checks pass.
