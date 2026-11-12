"""Offline, repeatable v3 contract tests. Live integration acceptance runs on ECS."""
import importlib.util, os,sys,tempfile,json, pathlib
import pytest,yaml
from fastapi.testclient import TestClient
ROOT=pathlib.Path(__file__).resolve().parents[2]
@pytest.fixture
def app(monkeypatch,tmp_path):
    monkeypatch.setenv('LAB_DATA_DIR',str(tmp_path))
    monkeypatch.setenv('LAB_TARGET_URL','http://waf:8080')
    monkeypatch.setenv('TOOLBOX_TOKEN','unit-token')
    monkeypatch.setenv('TELEMETRY_TOKEN','telemetry-secret')
    sys.path.insert(0,str(ROOT/'app'))
    # unique import to isolate DB and metric registries
    spec=importlib.util.spec_from_file_location('cloudshield_test_'+tmp_path.name,ROOT/'app/main.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with TestClient(module.app) as c: yield c
    if str(ROOT/'app') in sys.path:sys.path.remove(str(ROOT/'app'))

def test_api_version(app):assert app.get('/healthz').json()['version']=='3.0.0'
def test_ui_all_pages(app):
    for slug in ('overview','crowdsec','waf','suricata','clamav','k6','iperf3','prometheus','grafana','store','guide','remoteecs'):
        assert app.get('/tool/'+slug).status_code==200
    assert app.get('/tool/unknown').status_code==404
def test_static_js_serves(app):
    r=app.get('/static/app.js');assert r.status_code==200
    assert 'function iperf3()' in r.text
    assert 'function iperf()' not in r.text
def test_public_admin_not_blocked_by_old_gateway_ban(app):
    assert app.post('/api/bans',json={'ip':'172.30.56.1','minutes':2,'reason':'bad'}).status_code==422
    assert app.post('/api/bans',json={'ip':'127.0.0.1','minutes':2,'reason':'bad'}).status_code==422
def test_real_ban_lifecycle_local_guard(app):
    r=app.post('/api/v3/clients/ban',json={'client':'B','minutes':1});assert r.status_code==200
    assert r.json()['engine']=='CloudShield app guard'
    bans=app.get('/api/bans').json();assert len(bans)==1 and bans[0]['ip']=='172.30.56.62'
    assert app.post('/api/v3/clients/unban',json={'client':'B','minutes':1}).json()['removed']==1
    assert app.get('/api/bans').json()==[]
def test_emergency_reset_scope(app):
    app.post('/api/v3/clients/ban',json={'client':'A','minutes':5});app.post('/api/v3/clients/ban',json={'client':'C','minutes':5})
    assert len(app.get('/api/bans').json())==2
    assert app.post('/api/v3/clients/reset').status_code==200
    assert app.get('/api/bans').json()==[]
def test_invalid_client_rejected(app):assert app.post('/api/v3/clients/ban',json={'client':'Z','minutes':1}).status_code==422
def test_remote_targets_require_private_ip(app):
    for ip in ('169.254.169.254','127.0.0.1','8.8.8.8','example.com'):
        r=app.post('/api/v3/targets',json={'ip':ip,'port':8081,'path':'/health','protocol':'http'})
        assert r.status_code==422, ip
def test_remote_target_list_and_path(app):
    data={'ip':'192.168.11.25','port':8081,'path':'/health','protocol':'http'}
    assert app.post('/api/v3/targets',json=data).status_code==200
    assert app.get('/api/v3/targets').json()[0]['ip']=='192.168.11.25'
    data['path']='/../private'
    assert app.post('/api/v3/targets',json=data).status_code==422
def test_telemetry_auth(app):
    payload={'name':'ecs2','timestamp':__import__('time').time(),'cpu_pct':12,'mem_pct':34,'net_rx_bytes':100,'net_tx_bytes':200,'store_http':200}
    assert app.post('/api/telemetry/ingest',json=payload).status_code==403
    assert app.post('/api/telemetry/ingest',json=payload,headers={'X-Telemetry-Token':'telemetry-secret'}).status_code==200
    assert app.get('/api/v3/telemetry').json()['agents']['ecs2']['cpu_pct']==12
def test_outdated_telemetry_rejected(app):
    payload={'name':'ecs2','timestamp':1,'cpu_pct':12,'mem_pct':34,'net_rx_bytes':100,'net_tx_bytes':200,'store_http':200}
    assert app.post('/api/telemetry/ingest',json=payload,headers={'X-Telemetry-Token':'telemetry-secret'}).status_code==422
def test_load_validation(app):
    x={'mode':'remote','ip':'169.254.169.254','port':8081,'path':'/','vus':5,'agents':1,'seconds':5,'max_rps':5}
    assert app.post('/api/v3/load/start',json=x).status_code==422
    x.update(mode='store',vus=101)
    assert app.post('/api/v3/load/start',json=x).status_code==422
def test_iperf_invalid_target(app):
    r=app.post('/api/v3/iperf3',json={'ip':'8.8.8.8','port':5201,'seconds':2})
    assert r.status_code==422
def test_compose_services_and_narrow_proxy():
    d=yaml.safe_load((ROOT/'compose.yaml').read_text());s=d['services']
    assert all(x in s for x in ('labapp','gateway','waf','crowdsec','toolbox','grafana','client-a','client-b','client-c','load-1','load-2','load-3','telemetry-receiver'))
    assert 'ports' not in s['waf'] and 'ports' not in s['toolbox']
    assert 'ports' in s['gateway']
    assert 'docker.sock' not in json.dumps(d)
    expected={s[x]['networks']['labnet']['ipv4_address'] for x in ('client-a','client-b','client-c')}
    assert len(expected)==3
def test_grafana_original_preserved():
    files=list((ROOT/'config/grafana/dashboards').glob('*.json'))
    assert len(files)==11
    assert len([x for x in files if x.name[:2] in [f'{n:02}' for n in range(1,9)]])==8
    assert all(json.loads(x.read_text())['panels'] for x in files)
def test_k8s_manifests_parse():
    docs=[x for path in (ROOT/'k8s').glob('*.yaml') for x in yaml.safe_load_all(path.read_text()) if x]
    names={x['metadata']['name'] for x in docs if x['kind']=='Deployment'}
    assert all(n in names for n in ('load-1','load-2','load-3','client-a','client-b','client-c','gateway','labapp','waf'))
def test_telemetry_gateway_narrow():
    config=(ROOT/'config/telemetry/Caddyfile').read_text()
    assert '/api/telemetry/ingest' in config and 'Not found' in config
def test_companion_optional():
    comp=ROOT.parent/'CloudShield_ECS2_Target_v3'
    if comp.exists():
        x=yaml.safe_load((comp/'compose.yaml').read_text())
        assert all(y in x['services'] for y in ('store','receiver','agent'))
