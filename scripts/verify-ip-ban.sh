#!/usr/bin/env bash
# Exact end-to-end proof: separate Docker client -> Coraza -> app -> HTTP decision.
set -euo pipefail
base="${LAB_BASE_URL:-http://127.0.0.1:8080}"
command -v python3 >/dev/null || { echo 'python3 required on Ubuntu ECS'; exit 1; }
BASE="$base" python3 - <<'PY'
import json,os,time,urllib.error,urllib.request
base=os.environ['BASE'].rstrip('/')
def send(path,method='GET',obj=None):
    raw=json.dumps(obj).encode() if obj is not None else None
    request=urllib.request.Request(base+path,method=method,data=raw,headers={'Content-Type':'application/json'} if obj is not None else {})
    try:
        with urllib.request.urlopen(request,timeout=15) as resp:return resp.status,json.loads(resp.read())
    except urllib.error.HTTPError as e:return e.code,json.loads(e.read())
print('[1] Real unblocked probe, expected HTTP 200')
_,r=send('/api/tools/probe')
assert r.get('actual_http_status')==200, f'Expected initial 200, got {r}. Release local and CrowdSec decisions before testing.'
ip=r['response'].get('observed_client_ip');assert ip, r
print('   Actual observed client source:',ip,'HTTP',r['actual_http_status'])
print('[2] Set 1 minute ban TTL and enforce for this exact source')
_,setr=send('/api/settings','POST',{'ban_minutes':1});assert setr.get('ok'),setr
_,ban=send('/api/tools/probe/ban','POST',{});assert ban.get('ok'),ban
assert ban['probe_ip']==ip,f'Proxy IP mismatch: {ip} vs {ban["probe_ip"]}'
print('   Enforced real app-layer ban:',ban['probe_ip'])
try:
    print('[3] Real blocked probe, expected HTTP 429 from the protected app')
    _,blocked=send('/api/tools/probe')
    assert blocked['actual_http_status']==429,f'BAN NOT ENFORCED: {blocked}'
    assert blocked['response'].get('ip')==ip,blocked
    print('   PASS: HTTP 429 confirmed with actual request from separate container')
finally:
    print('[4] Release only the classroom app-level ban')
    _,done=send('/api/tools/probe/ban','DELETE')
    print('   Unblock:',done)
print('[5] Final real request must return HTTP 200')
_,restored=send('/api/tools/probe')
assert restored['actual_http_status']==200,f'Access did not recover: {restored}'
print('   PASS: actual HTTP 200 restored after rule deletion')
print('SUCCESS: 200 -> 429 -> 200 verified. CrowdSec decisions and WAF are separate mechanisms.')
PY
