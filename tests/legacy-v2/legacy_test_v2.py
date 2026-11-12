"""Source tests for CloudShield v2; do NOT substitute for live Docker acceptance."""
import importlib.util
import json
import os
import re
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def lab(tmp_path,monkeypatch):
    monkeypatch.setenv('LAB_DATA_DIR',str(tmp_path))
    monkeypatch.setenv('CROWDSEC_BOUNCER_KEY','')
    monkeypatch.setenv('TOOLBOX_TOKEN','test-secret-only')
    monkeypatch.setenv('LAB_TARGET_URL','http://waf:8080')
    spec=importlib.util.spec_from_file_location('cloudshield_v2_'+tmp_path.name,ROOT/'app/main.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module,TestClient(module.app,client=('172.30.56.20',40100))

def test_separate_tool_pages(lab):
    _,cli=lab
    for page in ['overview','crowdsec','waf','suricata','clamav','k6','iperf3','prometheus','grafana','store','guide']:
        r=cli.get('/tool/'+page)
        assert r.status_code==200
        assert 'data-page="'+page+'"' in r.text
        assert 'CloudShield' in r.text
    assert cli.get('/tool/illegal').status_code==404
    assert cli.get('/static/legacy.js').status_code==404
    assert cli.get('/healthz').json()['version']=='2.0.0'

def test_real_middleware_enforces_probe_ip_and_unban(lab,monkeypatch):
    module,cli=lab
    async def actual_probe(method,path,payload=None,timeout=8):
        assert path=='/probe'
        return {'actual_http_status':200,'response':{'observed_client_ip':'172.30.56.50'}}
    monkeypatch.setattr(module,'worker_call',actual_probe)
    assert cli.get('/target/whoami').json()['observed_client_ip']=='172.30.56.20'
    probe=TestClient(module.app,client=('172.30.56.50',2341))
    assert probe.get('/target/whoami').status_code==200
    assert cli.post('/api/settings',json={'ban_minutes':1}).status_code==200
    ban=cli.post('/api/tools/probe/ban').json()
    assert ban['probe_ip']=='172.30.56.50'
    response=probe.get('/target/whoami')
    assert response.status_code==429
    assert response.json()['ip']=='172.30.56.50'
    assert cli.delete('/api/tools/probe/ban').json()['removed']
    assert probe.get('/target/whoami').status_code==200

def test_cannot_rename_preset_into_remote_attack(lab):
    _,cli=lab
    assert cli.post('/api/tools/waf/check',json={'profile':'https://example.com'}).status_code==422
    assert cli.post('/api/tools/iperf3/run',json={'seconds':9999}).status_code==422
    assert cli.post('/api/runs',json={'profile':'my-host', 'vus':1,'seconds':5}).status_code==422
    assert cli.post('/api/bans',json={'ip':'1.1.1.1','minutes':20}).status_code==422
    assert cli.get('/api/tools/crowdsec/decisions').status_code==503
    assert cli.post('/api/tools/prometheus/query',json={'query':''}).status_code==422

def test_metrics_are_exposed_not_hardcoded_dummy_values(lab):
    _,cli=lab
    s=cli.get('/metrics').text
    for sample in ['cloudshield_active_bans','cloudshield_failed_logins_total','cloudshield_iperf_last_receiver_mbps','cloudshield_suricata_alerts','cloudshield_k6_last_vus','cloudshield_probe_last_http_status']:
        assert sample in s

def test_grafana_88_real_promql_panels():
    dashboard_files=sorted((ROOT/'config/grafana/dashboards').glob('*.json'))
    assert len(dashboard_files)==8
    panels=0
    for path in dashboard_files:
        d=json.loads(path.read_text())
        assert d['uid'].startswith('cs2-')
        assert d['title'].startswith('CloudShield')
        assert d['refresh']=='5s'
        metric_panels=[x for x in d['panels'] if x['type']=='timeseries']
        assert all(x['targets'][0]['expr'] for x in metric_panels)
        assert all(x['datasource']['uid']=='cloudshield-prom' for x in metric_panels)
        panels+=len(metric_panels)
    assert panels==88

def test_compose_has_worker_and_built_in_protection():
    data=yaml.safe_load((ROOT/'compose.yaml').read_text())
    services=data['services']
    assert data['name']=='cloudshield-koolab'
    assert services['waf']['environment']['CORAZA_RULE_ENGINE']=='On'
    assert services['labapp']['environment']['TOOLBOX_URL']=='http://toolbox:8099'
    assert services['toolbox']['networks']['labnet']['ipv4_address']=='172.30.56.50'
    assert 'ports' not in services['toolbox']
    assert 'ports' not in services['iperf3-server']
    assert 'node-exporter' in services
    assert all('docker.sock' not in json.dumps(s) for s in services.values())
    assert any('LAB_BIND_IP:-127.0.0.1' in str(x) for x in services['waf']['ports'])

def test_all_k3s_manifests_parse_and_images_match():
    docs=[]
    for f in sorted((ROOT/'k8s').glob('*.yaml')):
        docs.extend(d for d in yaml.safe_load_all(f.read_text()) if d)
    assert len(docs)>20
    deployments={d['metadata']['name']:d for d in docs if d.get('kind')=='Deployment'}
    for name in ['labapp','waf','grafana','prometheus','crowdsec','clamav','toolbox','iperf3-server']:
        assert name in deployments
    assert deployments['toolbox']['spec']['template']['spec']['containers'][0]['image']=='cloudshield-toolbox:2.0.0'
    assert deployments['labapp']['spec']['template']['spec']['containers'][0]['image']=='cloudshield-lab:2.0.0'
    assert deployments['iperf3-server']['spec']['template']['spec']['containers'][0]['image']=='cloudshield-iperf3:2.0.0'

def test_workers_enforce_fixed_internal_targets():
    t=(ROOT/'tools/worker.py').read_text()
    assert 'http://waf:8080/target/whoami' in t
    assert "'-c', 'iperf3-server'" in t
    assert 'shell=True' not in t
    assert "'-r', '/lab/lab-demo.pcap'" in t

def test_eicar_signature_length(lab):
    module,_=lab
    assert len(module.EICAR)==68
    assert module.EICAR.startswith(b'X5O!P%@AP')
