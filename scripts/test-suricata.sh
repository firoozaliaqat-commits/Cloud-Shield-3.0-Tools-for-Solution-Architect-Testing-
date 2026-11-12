#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if docker info >/dev/null 2>&1; then d=(docker); else d=(sudo docker); fi
"${d[@]}" compose exec -T labapp python -c "from pathlib import Path;Path('/data/suricata').mkdir(exist_ok=True)"
"${d[@]}" compose --profile ids run --rm suricata
printf '\nAlert read-back:\n'
"${d[@]}" compose exec -T labapp python -c "import json;from pathlib import Path;p=Path('/data/suricata/eve.json');print('\\n'.join(str(o.get('alert',{}).get('signature')) for line in p.read_text().splitlines() if (o:=json.loads(line)).get('event_type')=='alert') if p.exists() else 'No eve.json generated')"
echo 'View the dashboard Suricata alerts panel to inspect detected packets.'
