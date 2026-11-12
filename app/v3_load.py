"""Distributed, bounded load coordinator for three independently networked k6 agents."""
import asyncio, ipaddress, json, os, time, threading, uuid
import httpx
from fastapi import HTTPException
from pydantic import BaseModel, Field
from prometheus_client import Gauge
from v3_features import valid_target

class LoadSpec(BaseModel):
    mode:str=Field(default='store',pattern='^(store|remote)$')
    ip:str=''
    port:int=Field(default=8080,ge=1024,le=65535)
    path:str=Field(default='/health',max_length=120)
    protocol:str=Field(default='http',pattern='^https?$')
    vus:int=Field(default=5,ge=1,le=100)
    agents:int=Field(default=1,ge=1,le=3)
    seconds:int=Field(default=15,ge=5,le=120)
    max_rps:int=Field(default=15,ge=1,le=150)


def attach_load(app,registry,event):
    TOKEN=os.getenv('TOOLBOX_TOKEN','')
    latest={'id':None,'agents':[],'started':None,'finished':None,'target':None}
    active_agents=Gauge('cloudshield_v3_k6_active_agents','Current number of running distributed k6 agents',registry=registry)
    total_vus=Gauge('cloudshield_v3_k6_distributed_vus','VUs allocated across independent clients',registry=registry)
    last_rps=Gauge('cloudshield_v3_k6_requested_rps_cap','k6 requested global RPS cap',registry=registry)
    agent_count=Gauge('cloudshield_v3_k6_last_agents','Number of agent containers requested in latest run',registry=registry)
    async def request(name,path,body=None):
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r=await c.request('POST' if body is not None else 'GET',f'http://{name}:8097{path}',json=body,headers={'X-Lab-Token':TOKEN})
                data=r.json()
                if r.status_code>=400: raise HTTPException(503,f'{name}: {data.get("error",r.status_code)}')
                return data
        except httpx.HTTPError as exc: raise HTTPException(503,f'{name} unavailable: {type(exc).__name__}')

    @app.post('/api/v3/load/start')
    async def start(body:LoadSpec):
        if latest['id'] and latest['agents']:
            states=await asyncio.gather(*(request(n,'/status') for n in latest['agents']),return_exceptions=True)
            if any(isinstance(x,dict) and x.get('state')=='running' for x in states):raise HTTPException(409,'Another distributed test is running; stop it first')
        if body.mode=='store': target='http://waf:8080/target/store/api/products'
        else:
            valid_target(body.ip,body.port,body.protocol)
            if not body.path.startswith('/') or '..' in body.path or any(c in body.path for c in '?&#@\\'):raise HTTPException(422,'Invalid HTTP path')
            target=f'{body.protocol}://{body.ip}:{body.port}{body.path}'
        counts=[body.vus//body.agents+(1 if i<body.vus%body.agents else 0) for i in range(body.agents)]
        names=[f'load-{i+1}' for i,v in enumerate(counts) if v]
        if body.agents>body.vus:raise HTTPException(422,'Agents cannot exceed virtual users')
        rps=[body.max_rps//len(names)+(1 if i<body.max_rps%len(names) else 0) for i in range(len(names))]
        if body.max_rps<len(names):raise HTTPException(422,'Max requests/sec must be >= agent count')
        started=[]
        try:
            for idx,name in enumerate(names):
                await request(name,'/start',{'url':target,'vus':counts[idx],'seconds':body.seconds,'rps':max(1,rps[idx])})
                started.append(name)
        except Exception:
            for name in started:
                try:await request(name,'/stop',{})
                except Exception:pass
            raise
        latest.update({'id':uuid.uuid4().hex[:12],'agents':names,'started':time.time(),'target':target,'finished':None,'requested_vus':body.vus,'seconds':body.seconds,'rps_cap':body.max_rps})
        active_agents.set(len(names));total_vus.set(body.vus);last_rps.set(body.max_rps);agent_count.set(len(names))
        event('distributed_k6_started','',f'{body.vus} VU across {len(names)} real containers, target {target}')
        return {'ok':True,'run':latest,'note':'Each independent agent has a separate Docker source IP; remote ECS may observe NAT node IP.'}

    @app.post('/api/v3/load/stop')
    async def stop():
        data=await asyncio.gather(*(request(n,'/stop',{}) for n in latest.get('agents',[])),return_exceptions=True)
        event('distributed_k6_stop','','Emergency stop requested')
        return {'ok':True,'agent_responses':[str(x)[:200] if isinstance(x,Exception) else x for x in data]}

    @app.get('/api/v3/load/status')
    async def status():
        if not latest['id']:return {'run':None,'agents':[]}
        results=await asyncio.gather(*(request(n,'/status') for n in latest['agents']),return_exceptions=True)
        responses=[{'agent':n,'error':str(x)} if isinstance(x,Exception) else x for n,x in zip(latest['agents'],results)]
        running=sum(1 for x in responses if x.get('state')=='running')
        active_agents.set(running)
        if not running and latest['finished'] is None:latest['finished']=time.time()
        return {'run':latest,'agents':responses,'running':bool(running)}
