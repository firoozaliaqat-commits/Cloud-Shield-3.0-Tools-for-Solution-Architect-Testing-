"""Run locally from repository root: python -m pytest -q tests/
No Docker engine needed for the application/control logic checks.
"""
import importlib.util
import os
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("LAB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CROWDSEC_BOUNCER_KEY", "")
    monkeypatch.setenv("LAB_TARGET_URL", "http://waf:8080")
    spec = importlib.util.spec_from_file_location("cloudshield_main", ROOT / "app" / "main.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, TestClient(module.app, client=("172.20.10.3", 5000))


def test_health_and_api(lab):
    mod, cli = lab
    assert cli.get("/healthz").status_code == 200
    assert cli.get("/target/data").status_code == 200
    assert cli.get("/api/status").json()["ban_minutes"] == 240
    assert cli.get("/metrics").status_code == 200


def test_demo_auth_bans_and_manual_unban(lab):
    mod, cli = lab
    correct = cli.post("/target/login", json={"username":"student", "password":"classroom-demo"})
    assert correct.status_code == 200
    for i in range(5):
        response = cli.post("/target/login", json={"username":"student", "password":"wrong"})
        assert response.status_code == 401
    bans = cli.get("/api/bans").json()
    assert len(bans)==1
    assert bans[0]["ip"] == "172.20.10.3"
    assert bans[0]["source"] == "lab_guard"
    assert cli.get("/target/health").status_code == 429
    assert cli.delete("/api/bans/172.20.10.3").json()["ok"]
    assert cli.get("/target/health").status_code == 200
    assert len(cli.get("/api/events").json()) >= 7


def test_ban_expiry_restores_access(lab):
    mod, cli = lab
    assert cli.post("/api/bans", json={"ip":"172.20.10.3","minutes":1}).status_code == 200
    with sqlite3.connect(mod.DB) as db:
        db.execute("UPDATE bans SET expires=?", (time.time()-1,))
    assert cli.get("/target/data").status_code == 200
    assert cli.get("/api/bans").json() == []


def test_external_ip_ban_rejected_and_protects_target(lab):
    mod, cli = lab
    assert cli.post("/api/bans", json={"ip":"8.8.8.8","minutes":60}).status_code == 422
    assert cli.post("/api/bans", json={"ip":"not-an-ip","minutes":60}).status_code == 422
    assert cli.post("/api/settings", json={"ban_minutes":1}).status_code == 200
    assert cli.get("/api/status").json()["ban_minutes"] == 1
    assert cli.get("/target/download?mb=17").status_code == 422


def test_bounded_load_and_no_arbitrary_target(lab):
    mod, cli = lab
    assert cli.post("/api/runs", json={"profile":"arbitrary-url", "vus":1,"seconds":10}).status_code == 422
    assert cli.post("/api/runs", json={"profile":"normal", "vus":90,"seconds":10}).status_code == 422
    assert cli.post("/api/runs", json={"profile":"normal", "vus":1,"seconds":200}).status_code == 422
    assert cli.post("/api/runs", json={"profile":"normal", "vus":1,"seconds":10}).status_code == 503
    assert cli.post("/api/runs/stop").json()["ok"] is False


def test_upload_requires_real_antivirus(lab):
    mod, cli = lab
    res = cli.post("/target/upload", files={"file": ("safe.txt", b"This is normal text")})
    assert res.status_code == 503


def test_client_cannot_change_ban_with_body_outside_private_range(lab):
    mod, cli = lab
    res = cli.post("/api/bans", json={"ip":"9.9.9.9", "minutes":1440})
    assert res.status_code == 422


def test_demo_store_browsing_and_dummy_checkout(lab):
    _, cli = lab
    assert cli.get('/target/store').status_code == 200
    assert 'KOOLAB' in cli.get('/target/store').text
    assert cli.get('/target/store/assets/store.css').status_code == 200
    assert cli.get('/target/store/assets/store.js').status_code == 200
    assert cli.get('/target/store/assets/unknown.txt').status_code == 404
    catalog = cli.get('/target/store/api/products').json()
    assert catalog['total'] == 6
    assert cli.get('/target/store/api/search?q=cloud').json()['total'] >= 1
    product = cli.get('/target/store/api/products/101')
    assert product.status_code == 200
    assert cli.get('/target/store/api/products/9999').status_code == 404
    checkout = cli.post('/target/store/api/checkout', json={'items':[
        {'product_id': 101, 'quantity': 1}, {'product_id': 102, 'quantity': 2}]})
    assert checkout.status_code == 200
    order = checkout.json()
    assert order['total_cents'] == 6000
    assert order['order_id'].startswith('LAB-')
    assert cli.get('/target/store/api/orders/' + order['order_id']).json()['total_cents'] == 6000
    assert cli.post('/target/store/api/checkout', json={'items':[{'product_id': 900, 'quantity': 1}]}).status_code == 422
    assert cli.post('/target/store/api/checkout', json={'items':[{'product_id': 101, 'quantity': 20}]}).status_code == 422
    assert cli.get('/target/store/api/slow?ms=500').status_code == 422
    assert cli.get('/target/store/api/slow?ms=15').status_code == 200


def test_demo_store_enforces_timed_ip_bans(lab):
    _, cli = lab
    assert cli.get('/target/store/api/products').status_code == 200
    assert cli.post('/api/bans', json={'ip':'172.20.10.3','minutes':1}).status_code == 200
    for url in ['/target/store','/target/store/api/products','/target/store/assets/store.js']:
        response = cli.get(url)
        assert response.status_code == 429
        assert response.json()['engine'] == 'Lab Guard'
    assert cli.delete('/api/bans/172.20.10.3').json()['ok'] is True
    assert cli.get('/target/store/api/products').status_code == 200


def test_demo_store_load_profile_is_present(lab):
    module, cli = lab
    assert module.RUNNERS['store'] == 'store.js'
    assert (ROOT / 'k6/store.js').is_file()
    assert cli.post('/api/runs',json={'profile':'store','vus':2,'seconds':15}).status_code == 503
