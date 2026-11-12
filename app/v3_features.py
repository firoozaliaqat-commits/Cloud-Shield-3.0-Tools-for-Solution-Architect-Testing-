"""CloudShield v3 additions. Only lab-controlled client IPs are bannable from the UI.
Remote load destinations require literal RFC1918 IPv4 addresses and bounded test parameters.
"""
import ipaddress, json, os, socket, time, threading, urllib.parse
from concurrent.futures import ThreadPoolExecutor
import httpx
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from prometheus_client import Gauge, Counter

CLIENTS = {'A':('client-a','172.30.56.61'),'B':('client-b','172.30.56.62'),'C':('client-c','172.30.56.63')}
CIDRS=(ipaddress.ip_network('10.0.0.0/8'),ipaddress.ip_network('172.16.0.0/12'),ipaddress.ip_network('192.168.0.0/16'))
BLOCKED = (ipaddress.ip_network('169.254.0.0/16'), ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('0.0.0.0/8'),ipaddress.ip_network('100.64.0.0/10'))

def valid_target(host,port,protocol='http'):
    try: ip=ipaddress.IPv4Address(host)
    except Exception: raise HTTPException(422,'Use a literal private IPv4 address, not a domain name')
    if not any(ip in n for n in CIDRS) or any(ip in n for n in BLOCKED): raise HTTPException(422,'Only private VPC IPv4 destinations are allowed')
    if not isinstance(port,int) or isinstance(port,bool) or not 1024<=port<=65535: raise HTTPException(422,'Use application port 1024–65535')
    if protocol not in ('http','https','tcp','udp'): raise HTTPException(422,'Unsupported protocol')
    return str(ip)

class ClientCommand(BaseModel):
    client: str = Field(pattern='^[ABC]$')
    minutes: int = Field(default=1,ge=1,le=240)

class TargetSpec(BaseModel):
    ip: str
    port: int=Field(default=8080,ge=1024,le=65535)
    path: str=Field(default='/health',max_length=120)
    protocol: str=Field(default='http',pattern='^https?$')

class RemoteIperf(BaseModel):
    ip: str
    port: int=Field(default=5201,ge=1024,le=65535)
    seconds: int=Field(default=5,ge=2,le=30)
    protocol: str=Field(default='tcp',pattern='^(tcp|udp)$')
    direction: str=Field(default='upload',pattern='^(upload|download|both)$')
    streams: int=Field(default=1,ge=1,le=4)
    mbps: int=Field(default=10,ge=1,le=100)

class Telemetry(BaseModel):
    name: str=Field(default='ecs2',max_length=32,pattern='^[a-zA-Z0-9_-]+$')
    timestamp: float
    cpu_pct: float=Field(ge=0,le=100)
    mem_pct: float=Field(ge=0,le=100)
    net_rx_bytes: int=Field(ge=0)
    net_tx_bytes: int=Field(ge=0)
    store_http: int=Field(default=0,ge=0,le=599)


def attach(app, scope):
    set_ban=scope['set_ban']; db=scope['connect']; event=scope['event']; worker=scope['worker_call']; registry=scope['REGISTRY']
    TOKEN=os.getenv('TOOLBOX_TOKEN','')
    METRIC_TOKEN=os.getenv('TELEMETRY_TOKEN','')
    client_checks=Counter('cloudshield_v3_client_checks_total','Real HTTP probes per independent container',['client','status'],registry=registry)
    remote_tests=Counter('cloudshield_v3_remote_tests_total','Real remote network tests',['tool','outcome'],registry=registry)
    remote_cpu=Gauge('cloudshield_remote_ecs_cpu_percent','Actual ECS2 agent CPU percent',['agent'],registry=registry)
    remote_mem=Gauge('cloudshield_remote_ecs_memory_percent','Actual ECS2 agent memory percent',['agent'],registry=registry)
    remote_rx=Gauge('cloudshield_remote_ecs_net_rx_bytes','Actual ECS2 agent network received bytes',['agent'],registry=registry)
    remote_tx=Gauge('cloudshield_remote_ecs_net_tx_bytes','Actual ECS2 agent network transmitted bytes',['agent'],registry=registry)
    remote_age=Gauge('cloudshield_remote_ecs_last_sample_unixtime','ECS2 latest measurement timestamp',['agent'],registry=registry)
    v3_ids=Gauge('cloudshield_v3_ids_live','Suricata sensor live state from active process',registry=registry)
    ids_count=Gauge('cloudshield_v3_ids_live_alerts','Suricata live sensor alert count',registry=registry)
    remote_iperf=Gauge('cloudshield_v3_iperf_remote_mbps','Last measured remote ECS iperf result',registry=registry)
    targets={}
    last_telemetry={}

    async def call_client(name):
        host,known_ip=CLIENTS[name]
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                r=await c.get(f'http://{host}:8098/probe',headers={'X-Lab-Token':TOKEN})
                r.raise_for_status()
                data=r.json()
                observed=data.get('body',{}).get('observed_client_ip')
                if os.getenv('KUBERNETES_SERVICE_HOST'):
                    # Pod addresses are dynamic; compare the source seen by the WAF with pod identity.
                    known_ip=data.get('container_ip') or known_ip
                data['expected_ip']=known_ip
                data['source_ip_verified']=(observed==known_ip)
                # WAF reverse proxy may SNAT: report evidence, never falsify independent IP proof.
                client_checks.labels(client=name,status=str(data.get('http_status',0))).inc()
                return data
        except Exception as e: return {'client':name,'error':str(e)[:160],'expected_ip':known_ip}

    @app.get('/api/v3/clients')
    async def clients():
        # Network probes are actual requests; responses may be blocked by WAF or the app.
        outcomes=await __import__('asyncio').gather(*(call_client(n) for n in CLIENTS))
        with db() as sql: rows={row['ip']:dict(row) for row in sql.execute('SELECT * FROM bans')}
        now=time.time()
        for x in outcomes:
            x['ban']=rows.get(x['expected_ip']); x['seconds_left']=max(0,round(rows[x['expected_ip']]['expires']-now)) if x['expected_ip'] in rows else 0
        return {'clients':outcomes,'warning':'Different Docker IPs are not necessarily different VPC egress IPs. Verify observed_client_ip.'}

    @app.post('/api/v3/clients/login-abuse')
    async def client_login_abuse(body:ClientCommand):
        # Five actual HTTP POSTs from the isolated client. The app guard may
        # issue a 429 and CrowdSec may separately issue a genuine LAPI decision.
        async with httpx.AsyncClient(timeout=26) as c:
            r=await c.get(f'http://{CLIENTS[body.client][0]}:8098/failed-login',headers={'X-Lab-Token':TOKEN})
            r.raise_for_status()
            return r.json()

    @app.post('/api/v3/clients/ban')
    def ban_client(body:ClientCommand):
        ip=CLIENTS[body.client][1]
        if os.getenv('KUBERNETES_SERVICE_HOST'):
            try:
                with httpx.Client(timeout=5) as c:
                    x=c.get(f'http://{CLIENTS[body.client][0]}:8098/probe',headers={'X-Lab-Token':TOKEN}).json()
                ip=x.get('body',{}).get('observed_client_ip','')
                if ip != x.get('container_ip') or not ipaddress.ip_address(ip).is_private:
                    raise HTTPException(409,'K3s source IP is not verified as the actual client pod IP')
            except httpx.HTTPError:raise HTTPException(503,'Client pod unreachable')
        set_ban(ip,body.minutes,'Instructor-isolated client ban','v3-lab')
        return {'ok':True,'client':body.client,'ip':ip,'minutes':body.minutes,'engine':'CloudShield app guard','crowdsec_lapi_decision':False}

    @app.post('/api/v3/clients/unban')
    def unban_client(body:ClientCommand):
        ip=CLIENTS[body.client][1]
        if os.getenv('KUBERNETES_SERVICE_HOST'):
            with httpx.Client(timeout=5) as c:
                x=c.get(f'http://{CLIENTS[body.client][0]}:8098/probe',headers={'X-Lab-Token':TOKEN}).json()
            ip=x.get('container_ip') or ip
        with db() as sql:
            removed=sql.execute('DELETE FROM bans WHERE ip=?',(ip,)).rowcount
            sql.execute('DELETE FROM failed_login WHERE ip=?',(ip,))
        event('v3_manual_unban',ip,'Student manually released isolated client')
        return {'ok':True,'removed':removed,'ip':ip,'note':'Removes app-guard ban; CrowdSec LAPI decisions remain independent'}

    @app.post('/api/v3/clients/reset')
    def reset_clients():
        # Never remove arbitrary bans / outside IPs.
        with db() as sql:
            # Only lab-isolated v3 bans, not instructor or external decisions.
            if os.getenv('KUBERNETES_SERVICE_HOST'):
                sql.execute("DELETE FROM bans WHERE source='v3-lab'")
            else:
                sql.executemany('DELETE FROM bans WHERE ip=?',[(v[1],) for v in CLIENTS.values()])
            sql.executemany('DELETE FROM failed_login WHERE ip=?',[(v[1],) for v in CLIENTS.values()])
        event('v3_emergency_reset','','All three isolated lab bans released')
        return {'ok':True,'note':'Released A/B/C application-guard bans. CrowdSec LAPI decisions are separate.'}

    @app.get('/api/v3/targets')
    def list_targets():
        with db() as sql:
            sql.execute('CREATE TABLE IF NOT EXISTS v3_targets (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, path TEXT, protocol TEXT)')
            data=[dict(x) for x in sql.execute('SELECT * FROM v3_targets ORDER BY id DESC LIMIT 20')]
        return data

    @app.post('/api/v3/targets')
    def add_target(body:TargetSpec):
        valid_target(body.ip,body.port,body.protocol)
        if not body.path.startswith('/') or any(c in body.path for c in '?&#@\\') or '..' in body.path: raise HTTPException(422,'Use a simple absolute path')
        with db() as sql:
            sql.execute('CREATE TABLE IF NOT EXISTS v3_targets (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, path TEXT, protocol TEXT)')
            sql.execute('INSERT INTO v3_targets(ip,port,path,protocol) VALUES(?,?,?,?)',(body.ip,body.port,body.path,body.protocol))
        event('target_added',body.ip,'Saved approved target '+str(body.port))
        return {'ok':True,'url':f'{body.protocol}://{body.ip}:{body.port}{body.path}'}

    @app.post('/api/v3/targets/check')
    async def check_target(body:TargetSpec):
        valid_target(body.ip,body.port,body.protocol)
        if not body.path.startswith('/') or '..' in body.path or any(x in body.path for x in '?&#@\\'):
            raise HTTPException(422,'Invalid path')
        t=time.monotonic()
        url=f'{body.protocol}://{body.ip}:{body.port}{body.path}'
        try:
            async with httpx.AsyncClient(timeout=4,follow_redirects=False,trust_env=False) as c:
                r=await c.get(url,headers={'User-Agent':'CloudShield-Target-Check'})
            return {'reachable':True,'http_status':r.status_code,'ms':round((time.monotonic()-t)*1000,1),'url':url}
        except httpx.HTTPError as exc:
            return {'reachable':False,'error':type(exc).__name__,'url':url}

    @app.post('/api/v3/iperf3')
    async def iperf3_remote(body:RemoteIperf):
        if body.ip: valid_target(body.ip,body.port,'tcp')
        payload=body.model_dump()
        data=await worker('POST','/iperf3',payload,timeout=body.seconds+25)
        remote_tests.labels(tool='iperf3',outcome='ok').inc()
        remote_iperf.set(float(data.get('receiver_mbps',0)))
        event('v3_remote_iperf',body.ip,f"{data.get('receiver_mbps')} Mbps")
        return data

    @app.get('/api/v3/ids/status')
    async def ids_status():
        data=await worker('GET','/suricata/status')
        v3_ids.set(1 if data.get('running') else 0)
        ids_count.set(len(data.get('alerts',[])))
        return data

    @app.post('/api/v3/ids/start')
    async def ids_start():
        return await worker('POST','/suricata/start',{})

    @app.post('/api/v3/ids/stop')
    async def ids_stop():
        return await worker('POST','/suricata/stop',{})

    @app.post('/api/v3/ids/generate')
    async def ids_generate():
        return await worker('POST','/suricata/traffic',{})

    @app.get('/api/v3/ips/status')
    async def ips_status():return await worker('GET','/suricata/ips/status')

    @app.post('/api/v3/ips/start')
    async def ips_start():return await worker('POST','/suricata/ips/start',{},timeout=9)

    @app.post('/api/v3/ips/stop')
    async def ips_stop():return await worker('POST','/suricata/ips/stop',{},timeout=9)

    @app.get('/api/v3/ips/probe')
    async def ips_probe(attack:int=0):
        if attack not in (0,1):raise HTTPException(422,'Use attack=0 or 1')
        async with httpx.AsyncClient(timeout=7) as c:
            r=await c.get(f'http://client-a:8098/ips-probe?attack={attack}',headers={'X-Lab-Token':TOKEN})
            r.raise_for_status();res=r.json()
        state=await worker('GET','/suricata/ips/status')
        evidence=any(x.get('action') in ('blocked','drop') for x in state.get('alerts',[]))
        return {'request':res,'real_suricata_eve_drop_evidence':evidence,'ips_state':state,'confirmed_blocked':bool(attack and evidence and res.get('blocked_by_network'))}

    @app.post('/api/telemetry/ingest')
    def ingest(request:Request,body:Telemetry):
        import hmac
        if not METRIC_TOKEN or not hmac.compare_digest(request.headers.get('X-Telemetry-Token',''),METRIC_TOKEN):
            raise HTTPException(403,'Telemetry token invalid')
        if abs(time.time()-body.timestamp)>180: raise HTTPException(422,'Telemetry timestamp too old')
        remote_cpu.labels(agent=body.name).set(body.cpu_pct); remote_mem.labels(agent=body.name).set(body.mem_pct)
        remote_rx.labels(agent=body.name).set(body.net_rx_bytes); remote_tx.labels(agent=body.name).set(body.net_tx_bytes)
        remote_age.labels(agent=body.name).set(time.time())
        last_telemetry[body.name]={'cpu_pct':body.cpu_pct,'mem_pct':body.mem_pct,'store_http':body.store_http,'timestamp':body.timestamp}
        return {'ok':True}

    @app.get('/api/v3/telemetry')
    def telemetry_status():
        return {'agents':last_telemetry,'note':'Real measurements pushed by ECS2 agent. No agent means no data.'}
    def poll_sensor():
        while True:
            try:
                with httpx.Client(timeout=3) as c:
                    resp=c.get(os.getenv('TOOLBOX_URL','http://toolbox:8099')+'/suricata/status',headers={'X-Lab-Token':TOKEN})
                    if resp.status_code==200:
                        state=resp.json()
                        v3_ids.set(1 if state.get('running') else 0)
                        ids_count.set(len(state.get('alerts',[])))
            except Exception:pass
            time.sleep(12)
    threading.Thread(target=poll_sensor,daemon=True).start()
