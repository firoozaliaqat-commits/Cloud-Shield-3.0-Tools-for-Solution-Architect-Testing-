"""CloudShield KooLab: bounded, local-only lab orchestrator.

This intentionally does not offer arbitrary-target load generation, remote shell,
packet flooding, Docker socket access, or public firewall rule changes.
"""
import ipaddress
import json
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Histogram, Gauge, generate_latest
from starlette.responses import Response

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("LAB_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "lab.sqlite3"
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
(LOG_DIR / "nginx-access.log").touch(exist_ok=True)
LAB_TARGET = os.getenv("LAB_TARGET_URL", "http://waf:8080")
# Internal DNS target ONLY. Do not let HTTP users substitute a host or URL.
if LAB_TARGET != "http://waf:8080" and os.getenv("LAB_ALLOW_LOCAL_TEST_TARGET") != "1":
    raise RuntimeError("LAB_TARGET_URL must be http://waf:8080")
CROWDSEC_URL = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080")
CROWDSEC_KEY = os.getenv("CROWDSEC_BOUNCER_KEY", "")
K6_PATH = os.getenv("K6_PATH", "/usr/local/bin/k6")
K6_SCRIPTS = Path(os.getenv("K6_SCRIPTS", "/app/k6"))
MAX_VUS = max(1, min(100, int(os.getenv("MAX_VUS", "40"))))
MAX_SECONDS = max(5, min(300, int(os.getenv("MAX_SECONDS", "180"))))
MAX_MB = 16
RUNNERS = {"normal": "normal.js", "store": "store.js", "spike": "spike.js", "auth": "auth.js", "transfer": "transfer.js", "waf": "waf.js", "vpc_get": "vpc_get.js"}
VPC_TARGET_URL = os.getenv("VPC_TARGET_URL", "").strip()
if VPC_TARGET_URL:
    parsed = urlsplit(VPC_TARGET_URL)
    try:
        target_ip = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise RuntimeError("VPC_TARGET_URL must use a literal RFC1918 private IP address")
    rfc1918 = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or parsed.fragment or parsed.query or not any(target_ip in r for r in rfc1918):
        raise RuntimeError("VPC_TARGET_URL must be http(s) to an RFC1918 private IPv4 address (path allowed; no query/credentials)")


app = FastAPI(title="CloudShield KooLab", version="3.0.0", docs_url=None, redoc_url=None)
REGISTRY = CollectorRegistry()
ENGINE_CALLS = Counter("cloudshield_tool_operations_total", "Actual tool operations", ["tool", "outcome"], registry=REGISTRY)
LOGIN_FAILS = Counter("cloudshield_failed_logins_total", "Real failed login attempts", registry=REGISTRY)
LAB_BANS = Gauge("cloudshield_active_bans", "Current active local application-layer bans", registry=REGISTRY)
SECURITY_EVENTS = Gauge("cloudshield_recent_events", "Events recorded in previous hour", registry=REGISTRY)
STORE_ORDERS = Gauge("cloudshield_store_orders", "Synthetic store orders", registry=REGISTRY)
K6_RUNNING = Gauge("cloudshield_k6_running", "Whether k6 job is active", registry=REGISTRY)
K6_LAST_VUS = Gauge("cloudshield_k6_last_vus", "Virtual users in last test", registry=REGISTRY)
K6_LAST_P95 = Gauge("cloudshield_k6_last_p95_milliseconds", "Last k6 p95 HTTP duration in milliseconds", registry=REGISTRY)
K6_LAST_RPS = Gauge("cloudshield_k6_last_requests_per_second", "Last k6 observed request rate", registry=REGISTRY)
K6_LAST_ERROR = Gauge("cloudshield_k6_last_failed_ratio", "Last k6 observed HTTP failure ratio", registry=REGISTRY)
K6_LAST_BYTES = Gauge("cloudshield_k6_last_received_bytes", "Last k6 received bytes", registry=REGISTRY)
IPERF_LAST_MBPS = Gauge("cloudshield_iperf_last_receiver_mbps", "Last actual Docker bridge iperf throughput in Mbit/s", registry=REGISTRY)
SURICATA_ALERTS = Gauge("cloudshield_suricata_alerts", "Count of real offline PCAP IDS alerts", registry=REGISTRY)
CLAMAV_SCANS = Counter("cloudshield_clamav_scans_total", "Real clamav scan outcomes", ["result"], registry=REGISTRY)
WAF_PROBES = Counter("cloudshield_waf_checks_total", "HTTP status of actual Coraza probe requests", ["profile", "status"], registry=REGISTRY)
PROBE_HTTP_CODE = Gauge("cloudshield_probe_last_http_status", "Last real HTTP status observed by separate test container", registry=REGISTRY)
REQS = Counter("cloudshield_requests_total", "Target requests", ["method", "path", "status"], registry=REGISTRY)
BLOCKED = Counter("cloudshield_blocks_total", "Blocked test requests", ["engine"], registry=REGISTRY)
DURATION = Histogram("cloudshield_request_seconds", "Target handler duration", buckets=(.005,.01,.025,.05,.1,.25,.5,1,2,5,10), registry=REGISTRY)
lock = threading.RLock()
process = None
active_run = None
bouncer_cache = {}


@contextmanager
def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA busy_timeout=15000")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS bans (
            ip TEXT PRIMARY KEY, source TEXT NOT NULL, reason TEXT NOT NULL,
            created REAL NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS failed_login (ip TEXT NOT NULL, at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_fail_time ON failed_login(at);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
            event TEXT NOT NULL, ip TEXT, info TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS configs (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS store_orders (
            order_id TEXT PRIMARY KEY, created REAL NOT NULL, total_cents INTEGER NOT NULL, items_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY, profile TEXT NOT NULL, vus INTEGER NOT NULL,
            seconds INTEGER NOT NULL, started REAL NOT NULL, ended REAL,
            status TEXT NOT NULL, exit_code INTEGER, summary TEXT, log TEXT);
        INSERT OR IGNORE INTO configs(key, value) VALUES ('ban_minutes','240');
        """)


init_db()
# v2 could inadvertently ban the shared bridge gateway. Never carry that lockout into v3.
with connect() as _upgrade_db:
    _upgrade_db.execute("DELETE FROM bans WHERE ip IN ('172.30.56.1','127.0.0.1')")


def stamp(t=None):
    return datetime.fromtimestamp(t or time.time(), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def event(kind, ip="", info=""):
    with connect() as db:
        db.execute("INSERT INTO events(at,event,ip,info) VALUES (?,?,?,?)", (time.time(), kind, ip, str(info)[:400]))
        db.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)")


def expire_bans():
    now = time.time()
    with connect() as db:
        old = db.execute("SELECT ip FROM bans WHERE expires<=?", (now,)).fetchall()
        db.execute("DELETE FROM bans WHERE expires<=?", (now,))
    for item in old:
        event("unblocked_expiry", item["ip"], "TTL expired; access restored")


def active_ban(ip):
    expire_bans()
    with connect() as db:
        row = db.execute("SELECT * FROM bans WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None


def set_ban(ip, minutes, reason, source="lab_guard"):
    try:
        value = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "Invalid IP address")
    if not (value.is_private or value.is_loopback):
        raise HTTPException(422, "Lab can only ban private or loopback addresses")
    if not 1 <= minutes <= 1440:
        raise HTTPException(422, "Ban duration must be 1–1440 minutes")
    now = time.time()
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO bans(ip,source,reason,created,expires) VALUES(?,?,?,?,?)",
                   (str(value), source, reason[:140], now, now + minutes*60))
    event("ip_banned", str(value), f"{source}: {reason}; {minutes} minutes")


def get_minutes():
    with connect() as db:
        item = db.execute("SELECT value FROM configs WHERE key='ban_minutes'").fetchone()
    return int(item[0]) if item else 240


def client_ip(request: Request):
    # Internal WAF-to-app topology is an explicit trust boundary. The app is
    # never published directly; do not reuse this logic for an Internet proxy.
    peer = request.client.host if request.client else "127.0.0.1"
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        try:
            if ipaddress.ip_address(peer).is_private:
                raw = forwarded.split(",")[0].strip()
                return str(ipaddress.ip_address(raw))
        except ValueError:
            pass
    return peer


def check_crowdsec(ip):
    if not CROWDSEC_KEY:
        return False
    now = time.time()
    cached = bouncer_cache.get(ip)
    if cached and now - cached[0] < 5:
        return cached[1]
    try:
        resp = httpx.get(f"{CROWDSEC_URL}/v1/decisions", params={"ip": ip},
                         headers={"X-Api-Key": CROWDSEC_KEY}, timeout=0.55)
        blocked = resp.status_code == 200 and any(
            x.get("type") == "ban" for x in (resp.json() or []) if isinstance(x, dict)
        )
        bouncer_cache[ip] = (now, blocked)
        return blocked
    except (httpx.HTTPError, ValueError, TypeError):
        return False


def log_access(ip, method, path, code, user_agent=""):
    safe_path = path.replace('"', '').replace("\n", '')[:180]
    ua = user_agent.replace('"', '').replace("\n", '')[:120]
    line = f'{ip} - - [{datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {safe_path} HTTP/1.1" {code} 0 "-" "{ua}"\n'
    with lock:
        with (LOG_DIR / "nginx-access.log").open("a", encoding="utf-8") as f:
            f.write(line)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Enforcement is scoped to the built-in demonstration application.
    if not request.url.path.startswith("/target/"):
        return await call_next(request)
    start = time.monotonic()
    ip = client_ip(request)
    state = active_ban(ip)
    if state:
        result = JSONResponse({"blocked": True, "engine": "Lab Guard", "ip": ip,
                               "reason": state["reason"], "expires": state["expires"]}, status_code=429)
        BLOCKED.labels(engine="lab_guard").inc()
    elif check_crowdsec(ip):
        result = JSONResponse({"blocked": True, "engine": "CrowdSec bouncer", "ip": ip}, status_code=403)
        BLOCKED.labels(engine="crowdsec").inc()
    else:
        result = await call_next(request)
    DURATION.observe(time.monotonic() - start)
    path = request.url.path
    REQS.labels(method=request.method, path=path, status=str(result.status_code)).inc()
    log_access(ip, request.method, path, result.status_code, request.headers.get("user-agent", ""))
    return result


@app.get("/")
def ui():
    return FileResponse(APP_DIR / "static" / "index.html")


@app.get("/static/{name}")
def static(name: str):
    if name not in {"app.js", "style.css"}:
        raise HTTPException(404)
    return FileResponse(APP_DIR / "static" / name)


@app.get("/tool/{slug}")
def tool_page(slug: str):
    if slug not in {"overview","crowdsec","waf","suricata","clamav","k6","iperf3","grafana","prometheus","store","guide","remoteecs"}:
        raise HTTPException(404)
    return FileResponse(APP_DIR / "static" / "index.html")


@app.get("/healthz")
def health():
    return {"status": "ok", "project": "CloudShield KooLab", "version": "3.0.0"}


@app.get("/metrics")
def metrics():
    expire_bans()
    with connect() as db:
        LAB_BANS.set(db.execute("SELECT COUNT(*) FROM bans").fetchone()[0])
        SECURITY_EVENTS.set(db.execute("SELECT COUNT(*) FROM events WHERE at > ?", (time.time()-3600,)).fetchone()[0])
        STORE_ORDERS.set(db.execute("SELECT COUNT(*) FROM store_orders").fetchone()[0])
    with lock:
        K6_RUNNING.set(1 if process is not None and process.poll() is None else 0)
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/target/health")
def target_health():
    return {"ok": True, "service": "protected-demonstration-app"}


@app.get("/target/whoami")
def target_whoami(request: Request):
    return {"ok": True, "observed_client_ip": client_ip(request), "engine": "protected FastAPI route", "real_request": True}


@app.get("/target/data")
def target_data():
    return {"message": "Protected sample workload", "items": [{"id": i, "value": i*7} for i in range(8)]}


@app.get("/target/echo")
def target_echo(q: str = "sample"):
    return {"query": q[:160], "note": "Display-only echo; never interpreted as SQL or commands"}


@app.post("/target/login")
async def target_login(request: Request):
    # Intentionally fake authentication, no real credentials or accounts.
    body = await request.json()
    ip = client_ip(request)
    if body.get("username") == "student" and body.get("password") == "classroom-demo":
        return {"ok": True, "message": "Demo credentials accepted"}
    now = time.time()
    with connect() as db:
        db.execute("DELETE FROM failed_login WHERE at < ?", (now - 90,))
        db.execute("INSERT INTO failed_login(ip,at) VALUES (?,?)", (ip, now))
        count = db.execute("SELECT COUNT(*) FROM failed_login WHERE ip=?", (ip,)).fetchone()[0]
        if count >= 5:
            db.execute("DELETE FROM failed_login WHERE ip=?", (ip,))
    LOGIN_FAILS.inc()
    event("login_failed", ip, "Incorrect demonstration credential")
    if count >= 5 and ip in {"172.30.56.61","172.30.56.62","172.30.56.63","172.30.56.50"}:
        set_ban(ip, get_minutes(), "5 failed demo logins within 90 seconds")
    return JSONResponse({"ok": False, "attempts_in_window": count,
                         "message": "Demo login failed"}, status_code=401)


@app.get("/target/download")
def target_download(mb: int = 1):
    if not 1 <= mb <= MAX_MB:
        raise HTTPException(422, f"mb must be 1–{MAX_MB}")
    def blocks():
        chunk = b"CloudShield-Lab-Data\n" * 3276  # ~65 KB
        todo = mb * 1048576
        while todo:
            data = chunk[:min(len(chunk), todo)]
            todo -= len(data)
            yield data
    return StreamingResponse(blocks(), media_type="application/octet-stream",
                             headers={"Content-Disposition": 'attachment; filename="lab-data.bin"'})


def clam_scan(raw: bytes):
    host = os.getenv("CLAMAV_HOST", "clamav")
    try:
        with socket.create_connection((host, 3310), timeout=3) as s:
            s.settimeout(12)
            s.sendall(b"zINSTREAM\0")
            for start in range(0, len(raw), 32768):
                chunk = raw[start:start + 32768]
                s.sendall(struct.pack("!I", len(chunk)) + chunk)
            s.sendall(struct.pack("!I", 0))
            result = s.recv(2048).decode("utf-8", errors="replace").strip("\x00\n")
            return result
    except (OSError, TimeoutError):
        raise HTTPException(503, "ClamAV unavailable; start the antivirus profile and allow signatures to load")


@app.post("/target/upload")
async def target_upload(request: Request, file: UploadFile = File(...)):
    # Stream capped input; reject oversized files instead of loading arbitrary blobs.
    raw = await file.read(1_048_577)
    if len(raw) > 1_048_576:
        raise HTTPException(413, "Maximum 1 MiB per lab scan")
    result = clam_scan(raw)
    ip = client_ip(request)
    if "FOUND" in result:
        CLAMAV_SCANS.labels(result="detected").inc()
        event("malware_test_detected", ip, result)
        return JSONResponse({"safe": False, "scan": result}, status_code=422)
    if "OK" not in result:
        raise HTTPException(503, "ClamAV returned a scan error: " + result[:120])
    CLAMAV_SCANS.labels(result="clean").inc()
    event("clean_file", ip, "ClamAV scan clean")
    return {"safe": True, "scan": result, "bytes": len(raw)}



# Demo Store: intentionally synthetic products and orders, with NO payment, personal data,
# external checkout, or real stock inventory. All paths are behind /target/ protection.
STORE_PRODUCTS = [
    {"id": 101, "name": "Cloud Lab Hoodie", "category": "Apparel", "price_cents": 3500, "emoji": "🧥", "inventory": 10000},
    {"id": 102, "name": "Network Engineer Mug", "category": "Accessories", "price_cents": 1250, "emoji": "☕", "inventory": 10000},
    {"id": 103, "name": "KooLab Backpack", "category": "Accessories", "price_cents": 4800, "emoji": "🎒", "inventory": 10000},
    {"id": 104, "name": "Cyber Defense Notebook", "category": "Stationery", "price_cents": 850, "emoji": "📘", "inventory": 10000},
    {"id": 105, "name": "DevOps Water Bottle", "category": "Accessories", "price_cents": 2200, "emoji": "🧴", "inventory": 10000},
    {"id": 106, "name": "Security Lab T-Shirt", "category": "Apparel", "price_cents": 2900, "emoji": "👕", "inventory": 10000},
]
STORE_BY_ID = {p["id"]: p for p in STORE_PRODUCTS}


@app.get("/target/store")
@app.get("/target/store/")
def store_ui():
    return FileResponse(APP_DIR / "static" / "store.html")


@app.get("/target/store/assets/{name}")
def store_asset(name: str):
    if name not in ("store.css", "store.js"):
        raise HTTPException(404, "Unknown demo asset")
    return FileResponse(APP_DIR / "static" / name)


@app.get("/target/store/api/products")
def store_products(category: str = ""):
    value = category.lower()[:40]
    items = [p for p in STORE_PRODUCTS if not value or p["category"].lower() == value]
    return {"items": items, "total": len(items), "note": "Synthetic training catalog"}


@app.get("/target/store/api/search")
def store_search(q: str = ""):
    value = q.strip().lower()[:80]
    items = [p for p in STORE_PRODUCTS if value in p["name"].lower() or value in p["category"].lower()]
    return {"items": items, "total": len(items), "query": q[:80]}


@app.get("/target/store/api/products/{product_id}")
def store_product(product_id: int):
    product = STORE_BY_ID.get(product_id)
    if product is None:
        raise HTTPException(404, "Product not found")
    return product


class StoreCartItem(BaseModel):
    product_id: int = Field(ge=1, le=99999)
    quantity: int = Field(ge=1, le=10)


class StoreCheckout(BaseModel):
    items: list[StoreCartItem] = Field(min_length=1, max_length=8)


@app.post("/target/store/api/checkout")
def store_checkout(body: StoreCheckout):
    normalized = {}
    for entry in body.items:
        if entry.product_id not in STORE_BY_ID:
            raise HTTPException(422, f"Unknown synthetic product {entry.product_id}")
        normalized[entry.product_id] = normalized.get(entry.product_id, 0) + entry.quantity
    if any(n > 10 for n in normalized.values()):
        raise HTTPException(422, "Maximum 10 of each item per demo order")
    order_items = [{"product_id": pid, "quantity": qty, "unit_price_cents": STORE_BY_ID[pid]["price_cents"]} for pid, qty in normalized.items()]
    total = sum(entry["quantity"] * entry["unit_price_cents"] for entry in order_items)
    order_id = "LAB-" + uuid.uuid4().hex[:10].upper()
    with connect() as db:
        db.execute("INSERT INTO store_orders(order_id,created,total_cents,items_json) VALUES(?,?,?,?)",
                   (order_id, time.time(), total, json.dumps(order_items)))
    event("store_order", "", f"Synthetic order {order_id} for {total/100:.2f} demo dollars")
    return {"ok": True, "order_id": order_id, "total_cents": total, "items": order_items, "message": "Synthetic checkout complete — no payment collected"}


@app.get("/target/store/api/orders/{order_id}")
def store_order(order_id: str):
    if not re.fullmatch(r"LAB-[A-F0-9]{10}", order_id):
        raise HTTPException(404, "Demo order not found")
    with connect() as db:
        row = db.execute("SELECT * FROM store_orders WHERE order_id=?", (order_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Demo order not found")
    return {"order_id": row["order_id"], "created": row["created"],
            "total_cents": row["total_cents"], "items": json.loads(row["items_json"])}


@app.get("/target/store/api/slow")
def store_slow(ms: int = 100):
    if not 1 <= ms <= 300:
        raise HTTPException(422, "ms must be 1–300")
    time.sleep(ms / 1000)
    return {"ok": True, "simulated_database_ms": ms, "note": "Bounded latency demo; not actual database profiling"}

@app.get("/api/status")
def status():
    expire_bans()
    with connect() as db:
        bans = db.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
        recent = db.execute("SELECT COUNT(*) FROM events WHERE at>?", (time.time()-3600,)).fetchone()[0]
    with lock:
        running = active_run is not None and process is not None and process.poll() is None
    return {"project": "CloudShield KooLab", "bans": bans, "events_last_hour": recent,
            "running": running, "max_vus": MAX_VUS, "max_seconds": MAX_SECONDS,
            "ban_minutes": get_minutes(), "crowdsec_configured": bool(CROWDSEC_KEY),
            "clamav": os.getenv("CLAMAV_HOST", "clamav"), "vpc_target_configured": bool(VPC_TARGET_URL), "time": time.time()}


@app.get("/api/bans")
def bans():
    expire_bans()
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM bans ORDER BY expires DESC")]


class BanReq(BaseModel):
    ip: str
    minutes: int = Field(default=60, ge=1, le=1440)
    reason: str = Field(default="Instructor demonstration", max_length=140)


@app.post("/api/bans")
def ban_manual(body: BanReq):
    if body.ip not in {"172.30.56.61", "172.30.56.62", "172.30.56.63", "172.30.56.50"}:
        raise HTTPException(422, "UI bans restricted to independent lab clients; cannot ban gateway or management traffic")
    set_ban(body.ip, body.minutes, body.reason, "manual")
    return {"ok": True}


@app.delete("/api/bans/{ip}")
def unban(ip: str):
    with connect() as db:
        affected = db.execute("DELETE FROM bans WHERE ip=?", (ip,)).rowcount
    if affected:
        event("unblocked_manual", ip, "Instructor removed lab ban")
    return {"ok": bool(affected), "note": "CrowdSec decisions, if any, require separate removal via cscli"}


class SettingsReq(BaseModel):
    ban_minutes: int = Field(ge=1, le=1440)


@app.post("/api/settings")
def settings(body: SettingsReq):
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO configs(key,value) VALUES('ban_minutes',?)", (str(body.ban_minutes),))
    event("settings_changed", "", f"Automatic lab bans now {body.ban_minutes} minutes")
    return {"ok": True, "ban_minutes": body.ban_minutes}


@app.get("/api/events")
def events():
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 80")]


class RunReq(BaseModel):
    profile: str
    vus: int = Field(default=5, ge=1, le=100)
    seconds: int = Field(default=30, ge=5, le=300)


def finish_run(run_id, proc):
    try:
        stdout, _ = proc.communicate(timeout=MAX_SECONDS + 40)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        stdout, _ = proc.communicate()
        code = 124
    summary_path = DATA_DIR / "results" / f"{run_id}.json"
    summary = None
    try:
        if summary_path.exists():
            summary = json.loads(summary_path.read_text())
    except (ValueError, OSError):
        pass
    status_text = "completed" if code == 0 else "stopped" if code in (-15, 143) else "failed"
    if summary:
        m = summary.get("metrics", {})
        try:
            K6_LAST_P95.set(float(m.get("http_req_duration", {}).get("values", {}).get("p(95)", 0)))
            K6_LAST_RPS.set(float(m.get("http_reqs", {}).get("values", {}).get("rate", 0)))
            K6_LAST_ERROR.set(float(m.get("http_req_failed", {}).get("values", {}).get("rate", 0)))
            K6_LAST_BYTES.set(float(m.get("data_received", {}).get("values", {}).get("count", 0)))
        except (TypeError, ValueError):
            pass
    with connect() as db:
        db.execute("UPDATE runs SET ended=?, status=?, exit_code=?, summary=?, log=? WHERE id=?",
                   (time.time(), status_text, code, json.dumps(summary) if summary else None, stdout[-14000:], run_id))
    event("test_finished", "", f"{run_id} {status_text} (exit {code})")
    global active_run, process
    with lock:
        if active_run == run_id:
            active_run = None
            process = None
            K6_RUNNING.set(0)


@app.post("/api/runs")
def start_run(body: RunReq):
    if body.profile not in RUNNERS:
        raise HTTPException(422, "Unknown profile")
    if body.vus > MAX_VUS or body.seconds > MAX_SECONDS:
        raise HTTPException(422, f"Limit: {MAX_VUS} VUs and {MAX_SECONDS} seconds")
    if body.profile == "vpc_get":
        if not VPC_TARGET_URL:
            raise HTTPException(422, "Instructor has not configured VPC_TARGET_URL in .env")
        if body.vus > 20 or body.seconds > 120:
            raise HTTPException(422, "Private VPC target limit: 20 VUs and 120 seconds")
    script = K6_SCRIPTS / RUNNERS[body.profile]
    if not script.is_file() or not Path(K6_PATH).is_file():
        raise HTTPException(503, "k6 binary or profile script is missing")
    global active_run, process
    with lock:
        if process is not None and process.poll() is None:
            raise HTTPException(409, "Another test is already running")
        run_id = uuid.uuid4().hex[:12]
        (DATA_DIR / "results").mkdir(exist_ok=True)
        effective_target = VPC_TARGET_URL if body.profile == "vpc_get" else LAB_TARGET
        args = [K6_PATH, "run", "--no-color", "--vus", str(body.vus),
                "--duration", f"{body.seconds}s", "--summary-export",
                str(DATA_DIR / "results" / f"{run_id}.json"),
                "-e", f"BASE_URL={effective_target}", str(script)]
        try:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, start_new_session=True)
        except OSError as e:
            raise HTTPException(503, f"Could not start k6: {e}")
        process = p
        active_run = run_id
        K6_LAST_VUS.set(body.vus)
        K6_RUNNING.set(1)
        with connect() as db:
            db.execute("INSERT INTO runs(id,profile,vus,seconds,started,status) VALUES(?,?,?,?,?,?)",
                       (run_id, body.profile, body.vus, body.seconds, time.time(), "running"))
        threading.Thread(target=finish_run, args=(run_id, p), daemon=True).start()
    event("test_started", "", f"{body.profile}, {body.vus} VUs, {body.seconds}s, id {run_id}")
    return {"ok": True, "id": run_id, "target": "instructor-approved private VPC URL" if body.profile == "vpc_get" else "internal demo app through WAF"}


@app.post("/api/runs/stop")
def stop_run():
    with lock:
        if process is None or process.poll() is not None:
            return {"ok": False, "message": "No active test"}
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    event("test_stop_requested", "", "Student pressed emergency stop")
    return {"ok": True}


@app.get("/api/runs")
def list_runs():
    with connect() as db:
        rows = db.execute("SELECT id, profile,vus,seconds,started,ended,status,exit_code FROM runs ORDER BY started DESC LIMIT 30").fetchall()
    return [dict(row) for row in rows]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str):
    if not re.fullmatch(r"[a-f0-9]{12}", run_id):
        raise HTTPException(404)
    with connect() as db:
        row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        raise HTTPException(404)
    result = dict(row)
    if result["summary"]:
        result["summary"] = json.loads(result["summary"])
    return result


@app.get("/api/ids/alerts")
def ids_alerts():
    path = DATA_DIR / "suricata" / "eve.json"
    if not path.exists():
        return {"available": False, "alerts": [], "note": "Run scripts/test-suricata.sh to analyze a lab PCAP"}
    items = []
    for line in path.read_text(errors="replace").splitlines()[-400:]:
        try:
            o = json.loads(line)
            if o.get("event_type") == "alert":
                items.append({"timestamp": o.get("timestamp"), "src_ip": o.get("src_ip"),
                              "signature": o.get("alert", {}).get("signature")})
        except ValueError:
            continue
    return {"available": True, "alerts": items[-30:]}


# ----------------- CloudShield v2 real tool integrations -----------------
# No Docker socket, no network scan, no arbitrary-target traffic generation.
TOOLBOX = os.getenv("TOOLBOX_URL", "http://toolbox:8099")
TOOLBOX_TOKEN = os.getenv("TOOLBOX_TOKEN", "")
LAB_PROBE_IP = os.getenv("LAB_PROBE_IP", "172.30.56.50")


async def worker_call(method: str, path: str, payload=None, timeout=8):
    if not TOOLBOX_TOKEN:
        raise HTTPException(503, "Toolbox token missing; service not configured")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.request(method, TOOLBOX + path, json=payload,
                                     headers={"X-Lab-Token": TOOLBOX_TOKEN})
    except httpx.HTTPError as exc:
        raise HTTPException(503, f"Toolbox unavailable: {type(exc).__name__}")
    try:
        data = r.json()
    except ValueError:
        raise HTTPException(502, "Toolbox gave invalid response")
    if r.status_code >= 400:
        raise HTTPException(r.status_code, data.get("error", "Toolbox error"))
    return data


@app.get("/api/tools/runtime")
async def runtime_engines():
    checks = {"labapp": {"ok": True, "mode": "running"}}
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            for name, url in (("waf","http://waf:8080/target/health"),
                              ("prometheus","http://prometheus:9090/-/healthy"),
                              ("grafana","http://grafana:3000/api/health"),
                              ("toolbox",TOOLBOX+"/health"),
                              ("crowdsec",CROWDSEC_URL+"/v1/decisions")):
                try:
                    headers = {"X-Api-Key": CROWDSEC_KEY} if name == "crowdsec" and CROWDSEC_KEY else {}
                    r = await c.get(url, headers=headers)
                    checks[name] = {"ok": r.status_code < 500, "http_status": r.status_code}
                    if name == "toolbox" and r.status_code == 200:
                        checks[name].update(r.json())
                except (httpx.HTTPError, ValueError):
                    checks[name] = {"ok": False, "detail": "unreachable"}
    except Exception:
        pass
    # Actual ClamAV PING; do not report ready merely because the container exists.
    try:
        with socket.create_connection((os.getenv("CLAMAV_HOST", "clamav"), 3310),timeout=0.7) as sock:
            sock.settimeout(1)
            sock.sendall(b"zPING\0")
            checks["clamav"] = {"ok": b"PONG" in sock.recv(128)}
    except (OSError, TimeoutError):
        checks["clamav"] = {"ok": False, "detail": "daemon not ready"}
    return checks


class WafCheck(BaseModel):
    profile: str


WAF_SAMPLES = {
    "normal": "healthy classroom request",
    "sqli": "1' OR '1'='1",
    "xss": "<script>alert(1)</script>",
    "traversal": "../../etc/passwd",
}


@app.post("/api/tools/waf/check")
async def waf_check(body: WafCheck):
    if body.profile not in WAF_SAMPLES:
        raise HTTPException(422, "Choose one of the four preset classroom probes")
    trace = uuid.uuid4().hex[:16]
    try:
        async with httpx.AsyncClient(timeout=6, follow_redirects=False) as c:
            r = await c.get("http://waf:8080/target/echo", params={"q": WAF_SAMPLES[body.profile], "lab_trace":trace})
        status_code = r.status_code
    except httpx.HTTPError:
        raise HTTPException(503, "Coraza WAF is not reachable")
    WAF_PROBES.labels(profile=body.profile,status=str(status_code)).inc()
    ENGINE_CALLS.labels(tool="coraza", outcome="blocked" if status_code == 403 else "allowed").inc()
    event("waf_probe", "", f"real Coraza request: {body.profile}, HTTP {status_code}")
    # Look for the real rule messages in the shared Coraza JSON audit log.
    # Never fabricate a rule ID if the log is missing or inaccessible.
    await __import__('asyncio').sleep(.12)
    matched_rules=[]
    audit_file=Path('/waf_audit/audit.log')
    try:
        with audit_file.open(encoding='utf-8',errors='replace') as fd:
            for line in fd.readlines()[-120:]:
                try: x=json.loads(line)
                except ValueError: continue
                tx=x.get('transaction',x)
                req=tx.get('request',{})
                if trace not in str(req.get('uri','')):continue
                for msg in tx.get('messages',[]):
                    details=msg.get('details',{}) if isinstance(msg,dict) else {}
                    matched_rules.append({'message':str(msg.get('message',''))[:180], 'rule_id':details.get('ruleId') or details.get('id'), 'severity':details.get('severity')})
    except (OSError,TypeError):pass
    explanations={'normal':'Ordinary text sent as a query parameter. A normal rule set usually allows it.',
      'sqli':'This harmless text resembles a database query trick; OWASP CRS may match SQL injection rules.',
      'xss':'This harmless text resembles browser script content; OWASP CRS may match XSS rules.',
      'traversal':'This text resembles a request to access folders outside the intended web path.'}
    if status_code == 200: verdict='allowed'; why='No active Coraza blocking rule threshold was reached. A warning rule may still have matched.'
    elif status_code == 403 and matched_rules:verdict='blocked';why='Coraza produced matching audit evidence. Review the listed real rule identifiers.'
    elif status_code == 403:verdict='403_observed';why='HTTP 403 was returned, but rule evidence was unavailable. Verify Coraza audit before attributing the block.'
    else:verdict='other';why='Review the real response and Coraza rule configuration; no block is assumed.'
    return {'engine':'Coraza + OWASP CRS','profile':body.profile,'request_text':WAF_SAMPLES[body.profile], 'explanation':explanations[body.profile],
      'http_status':status_code,'blocked':status_code==403,'verdict':verdict,'why':why,'rules':matched_rules[-8:],
      'trace':trace,'backend_echo':r.json() if status_code==200 and 'json' in r.headers.get('content-type','') else None,
      'note':'This was a real WAF request; matched rule IDs appear only when supported by the audit log.'}


@app.get("/api/tools/probe")
async def probe_actual():
    result = await worker_call("GET", "/probe")
    PROBE_HTTP_CODE.set(result.get("actual_http_status", 0))
    ENGINE_CALLS.labels(tool="probe", outcome="blocked" if result.get("actual_http_status") in (403,429) else "allowed").inc()
    event("probe_checked", LAB_PROBE_IP, f"real separate-container HTTP response {result['actual_http_status']}")
    return result


@app.post("/api/tools/probe/ban")
async def ban_probe():
    # Derive the actual source IP from a real WAF-mediated request.
    # This supports Docker fixed IP and Kubernetes dynamic Pod IP.
    sample = await worker_call("GET", "/probe")
    observed = sample.get("response", {})
    if sample.get("actual_http_status") != 200 or not isinstance(observed, dict):
        raise HTTPException(409, "Probe already blocked or unreachable; release earlier bans first")
    ip = observed.get("observed_client_ip")
    if not ip:
        raise HTTPException(503, "Unable to determine the test client's actual source IP")
    if ip != "172.30.56.50" and not os.getenv('KUBERNETES_SERVICE_HOST'):
        raise HTTPException(409, "Safety: old probe IP differs from the isolated toolbox client; cannot ban gateway")
    set_ban(ip, get_minutes(), "Instructor probe lab — genuine app-layer HTTP enforcement", "lab_guard")
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO configs(key,value) VALUES('last_probe_ip',?)", (ip,))
    return {"ok": True, "probe_ip":ip, "minutes":get_minutes(),
            "note":"Real application-layer ban for /target/* endpoints; not a Linux host firewall drop."}


@app.delete("/api/tools/probe/ban")
async def clear_probe_ban():
    with connect() as db:
        row = db.execute("SELECT value FROM configs WHERE key='last_probe_ip'").fetchone()
        ip = row[0] if row else LAB_PROBE_IP
        count = db.execute("DELETE FROM bans WHERE ip=?", (ip,)).rowcount
    if count:
        event("unblocked_manual", ip, "Student ended real application ban")
    return {"removed": bool(count), "ip":ip, "note":"Local application ban removed; separate CrowdSec decisions unaffected"}


@app.get("/api/tools/crowdsec/decisions")
async def get_crowdsec_decisions():
    if not CROWDSEC_KEY:
        raise HTTPException(503, "CrowdSec bouncer key not configured")
    try:
        async with httpx.AsyncClient(timeout=3) as c:
            r = await c.get(CROWDSEC_URL+"/v1/decisions", headers={"X-Api-Key":CROWDSEC_KEY})
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError,ValueError) as e:
        raise HTTPException(503, f"CrowdSec Local API unavailable: {type(e).__name__}")
    return {"engine":"real CrowdSec LAPI", "decisions":data if isinstance(data,list) else [],
            "note":"LAPI decisions are distinct from CloudShield's local application-layer bans."}


@app.get("/api/tools/clamav/health")
async def clamav_ping():
    try:
        with socket.create_connection((os.getenv("CLAMAV_HOST", "clamav"),3310),timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(b"zPING\0")
            data = sock.recv(128)
        return {"ready":b"PONG" in data,"engine":"real ClamAV clamd"}
    except (OSError, TimeoutError):
        return {"ready":False,"engine":"real ClamAV clamd","note":"Signatures still loading or antivirus service is offline"}


EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


@app.post("/api/tools/clamav/eicar")
async def scan_eicar():
    verdict = clam_scan(EICAR)
    detected = 'FOUND' in verdict
    CLAMAV_SCANS.labels(result="detected" if detected else "clean").inc()
    ENGINE_CALLS.labels(tool="clamav",outcome="detected" if detected else "not_detected").inc()
    event("clamav_eicar_check", "", verdict)
    return {"real_scan":True,"safe_test_file":True,"detected":detected,"daemon_verdict":verdict,
            "note":"Harmless EICAR industry-standard antivirus test string sent to running clamd"}


@app.post("/api/tools/suricata/run")
async def run_ids_pcap():
    result = await worker_call("POST","/suricata", {}, timeout=90)
    SURICATA_ALERTS.set(len(result.get('alerts', [])))
    ENGINE_CALLS.labels(tool="suricata",outcome="processed").inc()
    event("suricata_pcap", "", f"Real engine parsed PCAP, {len(result.get('alerts', []))} alerts")
    return result


class IperfReq(BaseModel):
    seconds: int = Field(default=4,ge=2,le=10)


@app.post("/api/tools/iperf3/run")
async def run_iperf3(body: IperfReq):
    result = await worker_call("POST", "/iperf3", {"seconds": body.seconds}, timeout=body.seconds+19)
    IPERF_LAST_MBPS.set(result.get("receiver_mbps", 0))
    ENGINE_CALLS.labels(tool="iperf3", outcome="completed").inc()
    event("iperf3_result", "", f"Docker bridge measured {result.get('receiver_mbps')} Mbit/s")
    return result


@app.get("/api/tools/lessons")
def tool_lessons():
    return {"target_scope":"Built-in demo app through Coraza on a private Docker network",
            "crowdsec_scope":"CrowdSec LAPI decisions and separate local application-layer bans",
            "suricata_scope":"Real offline packet inspection of packaged harmless test PCAP",
            "iperf3_scope":"Real TCP transfer inside one Docker bridge, not across Huawei VPC ECS",
            "safety":"All tests target authorized fixed lab services. Do not expose classroom UI publicly."}


# Dedicated Prometheus practical: actual instant queries, never synthetic values.
class PromQuery(BaseModel):
    query: str = Field(min_length=1, max_length=180)


@app.post("/api/tools/prometheus/query")
async def prom_query(body: PromQuery):
    # Local lab PromQL only. Fixed service endpoint, timeout prevents hung requests.
    # Prometheus data retention is bounded to one day in Docker Compose.
    if "\n" in body.query or "\r" in body.query:
        raise HTTPException(422,"Single-line PromQL only")
    try:
        async with httpx.AsyncClient(timeout=6) as c:
            r = await c.get("http://prometheus:9090/api/v1/query", params={"query":body.query,"timeout":"4s"})
        data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise HTTPException(503, f"Prometheus unavailable or invalid response: {type(e).__name__}")
    if r.status_code != 200 or data.get("status") != "success":
        raise HTTPException(422, data.get("error", "PromQL query failed")[:200])
    ENGINE_CALLS.labels(tool="prometheus",outcome="query").inc()
    return {"engine":"live Prometheus", "promql":body.query, "result":data.get("data",{}),
            "note":"Actual instant query result from the Prometheus API; not a fabricated measurement."}


@app.get("/api/tools/prometheus/targets")
async def prom_targets():
    try:
        async with httpx.AsyncClient(timeout=4) as c:
            r = await c.get("http://prometheus:9090/api/v1/targets")
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        raise HTTPException(503,f"Prometheus targets unavailable: {type(e).__name__}")
    targets = data.get("data",{}).get("activeTargets",[])
    return {"targets":[{"job":x.get("labels",{}).get("job"),"health":x.get("health"),
             "lastScrape":x.get("lastScrape"),"lastError":x.get("lastError","")} for x in targets],
            "engine":"live Prometheus scrape targets"}


# V3 endpoints are mounted after the original lab routes, keeping v2 compatibility.
from v3_features import attach as _install_v3
from v3_load import attach_load as _install_load
_install_v3(app, globals())
_install_load(app, REGISTRY, event)
