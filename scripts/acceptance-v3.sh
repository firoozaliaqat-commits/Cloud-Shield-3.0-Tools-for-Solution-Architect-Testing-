#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json,sys,time,urllib.request,urllib.error
BASE='http://127.0.0.1:8080'
fails=[]
def call(route,method='GET',payload=None):
    raw=json.dumps(payload).encode() if payload is not None else None
    req=urllib.request.Request(BASE+route,data=raw,method=method,headers={'Content-Type':'application/json'} if raw else {})
    try:
        with urllib.request.urlopen(req,timeout=12) as r:return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:return e.code,json.loads(e.read())
        except Exception:return e.code,{}

def check(name,pred):
    print(('PASS' if pred else 'FAIL')+' | '+name)
    if not pred:fails.append(name)

check('CloudShield health endpoint',call('/healthz')[0]==200)
check('Demo Store 1 actual product API',call('/target/store/api/products')[0]==200)
check('Admin UI accessible separate from WAF',urllib.request.urlopen(BASE+'/tool/overview',timeout=5).status==200)
status,clients=call('/api/v3/clients');print('Actual client probes: '+json.dumps(clients,indent=2)[:1800])
values={x.get('client'):x for x in clients.get('clients',[])}
check('three clients responded over actual HTTP',status==200 and len(values)==3 and all('http_status' in x for x in values.values()))
check('three distinct source IPs observed at application',len({x.get('body',{}).get('observed_client_ip') for x in values.values()})==3 and all(x.get('source_ip_verified') for x in values.values()))
try:
    check('isolated B ban created',call('/api/v3/clients/ban','POST',{'client':'B','minutes':1})[0]==200)
    time.sleep(.5)
    _,banned=call('/api/v3/clients')
    now={x.get('client'):x for x in banned.get('clients',[])}
    print('After ban:',{k:v.get('http_status') for k,v in now.items()})
    check('B really denied with HTTP 429',now.get('B',{}).get('http_status')==429)
    check('A and C still permitted',now.get('A',{}).get('http_status')==200 and now.get('C',{}).get('http_status')==200)
finally:
    print('Restoring isolated test access:',call('/api/v3/clients/reset','POST',{}))
    time.sleep(.3)
    _,restored=call('/api/v3/clients')
    check('B actually restored',next((x.get('http_status') for x in restored.get('clients',[]) if x.get('client')=='B'),None)==200)
# Test an actual WAF request but do not assume all suspicious signatures are blocked.
code,waf=call('/api/tools/waf/check','POST',{'profile':'normal'})
check('Coraza normal probe executed',code==200 and waf.get('http_status') in (200,403))
print('WAF evidence:',{'http':waf.get('http_status'),'rules':waf.get('rules'),'verdict':waf.get('verdict')})
code,ids=call('/api/v3/ids/status')
check('Suricata sensor reports its real process status',code==200 and 'running' in ids)
print('Suricata actually running:',ids.get('running'),'last error:',str(ids.get('last_error'))[-200:])
code,ipf=call('/api/tools/iperf3/run','POST',{'seconds':2})
check('local iperf3 transfer completes',code==200 and ipf.get('receiver_mbps',0)>0)
print('Actual measured local iperf3 Mbps:',ipf.get('receiver_mbps'))
code,load=call('/api/v3/load/start','POST',{'mode':'store','vus':2,'agents':1,'seconds':5,'max_rps':6})
check('distributed k6 worker starts',code==200 and bool(load.get('ok')))
if load.get('ok'):
    final={}
    for i in range(18):
        time.sleep(1)
        _,final=call('/api/v3/load/status')
        if not final.get('running'):break
    agents=final.get('agents',[])
    check('real k6 agent completes',bool(agents) and agents[0].get('state')=='completed')
    print('Distributed k6 state:',[(x.get('agent'),x.get('state')) for x in agents])
print('\nAcceptance summary:',len(fails),'failure(s).')
if fails:
    print('FAILED:',', '.join(fails));sys.exit(1)
PY
