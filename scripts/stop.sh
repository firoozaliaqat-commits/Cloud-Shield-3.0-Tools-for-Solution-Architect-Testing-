#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if docker info >/dev/null 2>&1; then d=(docker); else d=(sudo docker); fi
"${d[@]}" compose --profile security --profile monitoring --profile antivirus --profile ids --profile network down
echo 'Stopped. Volumes retained (bans and reports survive restarts).'
