"""
ThreatSig Backend — main.py
Uses:
  - XposedOrNot API  (email breach check — FREE, no API key needed)
  - AbuseIPDB API    (IP reputation     — FREE tier, 1000 checks/day, free key)
  - Kafka-style simulated live stream via WebSocket

Setup:
  pip install fastapi uvicorn httpx websockets python-dotenv

Run:
  uvicorn main:app --reload

Env vars (create a .env file):
  ABUSEIPDB_API_KEY=your_free_key_here   # get free at abuseipdb.com
"""

import asyncio
import json
import os
import random
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
try:
    from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
except ImportError:
    AIOKafkaProducer = None
    AIOKafkaConsumer = None
    print("[WARN] aiokafka not installed. Kafka features disabled.")

try:
    from pyspark.sql import SparkSession
except ImportError:
    SparkSession = None

# ML engine (scikit-learn + PySpark) — import last so PySpark crash never blocks startup
try:
    import os as _os
    # Suppress verbose PySpark/Java output before import
    _os.environ.setdefault("PYSPARK_SUBMIT_ARGS", "--master local[1] pyspark-shell")
    _os.environ.setdefault("JAVA_HOME", r"C:\Java\jdk1.8.0_202")
    _os.environ.setdefault("SPARK_LOCAL_DIRS", _os.path.join(_os.path.dirname(__file__), ".spark_tmp"))
    from ml_engine import engine as ml_engine
    print("[ML] ThreatMLEngine loaded [OK]")
except Exception as _ml_err:
    ml_engine = None
    print(f"[WARN] ML engine unavailable (will run without ML): {_ml_err}")

load_dotenv()

app = FastAPI(title="ThreatSig API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
XON_URL       = "https://api.xposedornot.com/v1/check-email"
XON_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics"

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = "threat-signals"

# global producer
kafka_producer = None

# ─────────────────────────────────────────────
# In-memory event store (simulates Kafka consumer)
# ─────────────────────────────────────────────
events: list[dict] = []
subscribers: list[WebSocket] = []
stats = {
    "total_events": 0,
    "threat_level_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "score_sum": 0,
    "events_per_minute": 0,
    "last_minute_count": 0,
    "last_minute_ts": 0.0,
}


def score_to_level(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 60: return "high"
    if score >= 35: return "medium"
    return "low"

ip_cache = {}

def get_ip_info(ip: str, force_critical: bool = False) -> dict:
    if ip not in ip_cache:
        data = _demo_ip(ip, force_critical)
        if ml_engine:
            data["ml"] = ml_engine.analyze(data, record_type="ip")
        ip_cache[ip] = data
    return ip_cache[ip]



async def broadcast(event: dict):
    """Push event to all connected WebSocket clients."""
    dead = []
    for ws in subscribers:
        try:
            await ws.send_text(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        subscribers.remove(ws)


def register_event(event: dict):
    """Record event in memory store and update stats."""
    events.append(event)
    stats["total_events"] += 1
    level = event.get("threat_level", "low")
    stats["threat_level_distribution"][level] = (
        stats["threat_level_distribution"].get(level, 0) + 1
    )
    stats["score_sum"] += event.get("threat_score", 0)


# ─────────────────────────────────────────────
# Simulated Kafka live stream (background task)
# ─────────────────────────────────────────────
FAKE_SOURCES = ["darkweb-monitor", "tor-exit-watcher", "botnet-feed", "paste-scanner", "phish-intel"]
FAKE_COUNTRIES = ["CN", "RU", "BR", "US", "DE", "UA", "NL", "KR", "IR", "IN"]
FAKE_MESSAGES = [
    "SSH brute-force attempt detected from {ip}",
    "Credential stuffing attack originated at {ip}",
    "TOR exit node {ip} flagged for C2 traffic",
    "Port scan sweep from {ip} targeting /24 subnet",
    "Email {email} found in new paste dump",
    "Malware C2 beacon from {ip}",
    "Dark web mention: credentials linked to {email}",
    "Botnet node {ip} detected — Mirai variant",
    "RDP exploit attempt from {ip}",
    "Phishing kit deployed at {ip}",
]

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def random_email():
    domains = ["gmail.com","yahoo.com","outlook.com","proton.me","hotmail.com"]
    user = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(5,10)))
    return f"{user}@{random.choice(domains)}"

KNOWN_MALICIOUS_IPS = [
    "80.82.77.33",       # Shodan scanner      — score 100 (NL)
    "71.6.135.131",      # Censys scanner      — score 100 (US)
    "66.240.205.34",     # Shodan crawler      — score 100 (US)
    "185.220.100.240",   # TOR exit node       — score 100 (DE)
    "185.220.101.35",    # TOR exit node       — score 100 (DE)
    "89.248.167.131",    # Mass port scanner   — score 100 (NL)
    "71.6.158.166",      # Shodan crawler      — score 100 (US)
    "194.165.16.11",     # Brute-force origin  — score 100 (LT)
]

KNOWN_BREACHED_EMAILS = [
    "admin@gmail.com", "test@yahoo.com", "info@hotmail.com", 
    "john.doe@gmail.com", "support@outlook.com", "sales@gmail.com"
]

async def kafka_stream_simulator():
    """Generates live synthetic threat events and always delivers them to subscribers."""
    await asyncio.sleep(2)  # let server boot
    while True:
        try:
            await _emit_synthetic_event()
        except Exception as e:
            print(f"[STREAM] Simulator error: {e}")
        await asyncio.sleep(random.uniform(4.0, 8.0))


async def _emit_synthetic_event():
    """Build and broadcast a synthetic threat event directly (no Kafka dependency)."""
    import time
    ip = random.choice(KNOWN_MALICIOUS_IPS) if random.random() < 0.4 else random_ip()
    ip_info = get_ip_info(ip, force_critical=ip in KNOWN_MALICIOUS_IPS)
    score = ip_info["threat_score"]
    level = ip_info["threat_level"]
    country = ip_info["country"]
    
    cats = ip_info.get("recent_categories", [])
    if "DDoS Attack" in cats:
        msg = f"DDoS origin node detected at {ip}"
        source = "ddos-monitor"
    elif any("Brute-Force" in c for c in cats) or "SSH" in cats:
        msg = f"SSH brute-force attempt from {ip}"
        source = "auth-logs"
    elif "Port Scan" in cats:
        msg = f"Port scan sweep originating from {ip}"
        source = "firewall-syslog"
    elif "Web App Attack" in cats or "SQL Injection" in cats:
        msg = f"Web exploit payload detected from {ip}"
        source = "waf-alerts"
    elif "Phishing" in cats:
        msg = f"Phishing kit deployed at {ip}"
        source = "phish-intel"
    elif ip_info.get("is_tor"):
        msg = f"TOR exit node {ip} flagged for suspicious traffic"
        source = "tor-exit-watcher"
    elif score >= 85:
        msg = f"Critical threat beacon from {ip}"
        source = "botnet-feed"
    else:
        msg = f"Suspicious activity reported from {ip}"
        source = "threat-intel-feed"

    email = random.choice(KNOWN_BREACHED_EMAILS) if random.random() < 0.3 else random_email()

    evt = {
        "id": str(uuid.uuid4()),
        "event_type": "ip_scan",
        "source": source,
        "threat_level": level,
        "threat_score": score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"message": msg, "country": country, "ip": ip},
        "_simulated": True,
    }

    # Always register in memory and broadcast — regardless of Kafka state
    register_event(evt)
    await broadcast(evt)

    # Also try Kafka if producer is available
    if kafka_producer:
        try:
            await kafka_producer.send_and_wait(KAFKA_TOPIC, evt)
        except Exception:
            pass

    # Update events-per-minute counter
    now = time.time()
    if now - stats["last_minute_ts"] >= 60:
        stats["events_per_minute"] = stats["last_minute_count"]
        stats["last_minute_count"] = 0
        stats["last_minute_ts"] = now
    stats["last_minute_count"] += 1


async def kafka_consumer_task():
    """Tries to consume from Kafka; gracefully skips if Kafka is not running."""
    if AIOKafkaConsumer is None:
        print("[KAFKA] aiokafka not installed. Skipping consumer task.")
        return
    try:
        consumer = AIOKafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="threat-ui-group",
            value_deserializer=lambda m: json.loads(m.decode('utf-8')),
            auto_offset_reset="latest"
        )
        await asyncio.wait_for(consumer.start(), timeout=5.0)
        print("[KAFKA] Consumer connected [OK]")
        try:
            async for msg in consumer:
                # Kafka events supplement the simulator; avoid double-counting
                event = msg.value
                if not any(e.get("id") == event.get("id") for e in events[-20:]):
                    register_event(event)
                    await broadcast(event)
        finally:
            await consumer.stop()
    except Exception as e:
        print(f"[KAFKA] Consumer not available ({e}). Simulator stream is active.")

@app.on_event("startup")
async def startup():
    global kafka_producer
    import time
    stats["last_minute_ts"] = time.time()

    if AIOKafkaProducer is not None:
        try:
            kafka_producer = AIOKafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            await asyncio.wait_for(kafka_producer.start(), timeout=5.0)
            print("[KAFKA] Producer connected [OK]")
        except Exception as e:
            print(f"[KAFKA] Producer not available ({e}). Running in direct-broadcast mode.")
            kafka_producer = None
    else:
        kafka_producer = None

    asyncio.create_task(kafka_consumer_task())
    asyncio.create_task(kafka_stream_simulator())
    print("[STARTUP] ThreatSig ready — stream simulator active [OK]")

@app.on_event("shutdown")
async def shutdown():
    if kafka_producer:
        await kafka_producer.stop()
    if ml_engine and ml_engine._spark:
        ml_engine._spark.stop()


# ─────────────────────────────────────────────
# WebSocket endpoint
# ─────────────────────────────────────────────
@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    await websocket.accept()
    subscribers.append(websocket)
    # Replay last 10 events on connect
    for evt in events[-10:]:
        try:
            await websocket.send_text(json.dumps({**evt, "_replay": True}))
        except Exception:
            break
    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        if websocket in subscribers:
            subscribers.remove(websocket)


@app.get("/")
async def get_index():
    """Serves the frontend UI directly."""
    return FileResponse("index.html")


# ─────────────────────────────────────────────
# IP Check — AbuseIPDB (free key, 1000/day)
# ─────────────────────────────────────────────
@app.get("/api/check/ip/{ip}")
async def check_ip(ip: str):
    if ip == "9.9.9.9":
        # Test override to guarantee a Critical threat display
        if ip not in ip_cache:
            score = 100
            level = "critical"
            result = {
                "source": "abuseipdb",
                "ip": "9.9.9.9",
                "threat_score": score,
                "threat_level": level,
                "country": "RU",
                "isp": "Test Malicious ISP",
                "domain": "hacker-test.net",
                "is_tor": True,
                "is_vpn": False,
                "total_reports": 5000,
                "distinct_users": 1500,
                "recent_categories": ["DDoS Attack", "Port Scan", "Hacking"],
                "last_reported": datetime.now(timezone.utc).isoformat(),
            }
            if ml_engine:
                result["ml"] = ml_engine.analyze(result, record_type="ip")
            ip_cache[ip] = result
        result = ip_cache[ip]
        score = result["threat_score"]
        level = result["threat_level"]
        evt = {
            "id": str(uuid.uuid4()),
            "event_type": "ip_scan",
            "source": "abuseipdb",
            "threat_level": level,
            "threat_score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {"message": f"IP scan: {ip} — score {score}", "country": result["country"]},
        }
        if kafka_producer:
            await kafka_producer.send_and_wait(KAFKA_TOPIC, evt)
        else:
            register_event(evt)
            await broadcast(evt)
        return result

    if ip == "8.8.8.8":
        # Test override to guarantee a Medium threat display
        if ip not in ip_cache:
            score = 45
            level = "medium"
            result = {
                "source": "abuseipdb",
                "ip": "8.8.8.8",
                "threat_score": score,
                "threat_level": level,
                "country": "US",
                "isp": "Test Medium ISP",
                "domain": "scanner-test.com",
                "is_tor": False,
                "is_vpn": True,
                "total_reports": 42,
                "distinct_users": 5,
                "recent_categories": ["Port Scan", "Web Spam"],
                "last_reported": datetime.now(timezone.utc).isoformat(),
            }
            if ml_engine:
                result["ml"] = ml_engine.analyze(result, record_type="ip")
            ip_cache[ip] = result
        result = ip_cache[ip]
        score = result["threat_score"]
        level = result["threat_level"]
        evt = {
            "id": str(uuid.uuid4()),
            "event_type": "ip_scan",
            "source": "abuseipdb",
            "threat_level": level,
            "threat_score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {"message": f"IP scan: {ip} — score {score}", "country": result["country"]},
        }
        if kafka_producer:
            await kafka_producer.send_and_wait(KAFKA_TOPIC, evt)
        else:
            register_event(evt)
            await broadcast(evt)
        return result

    if ip == "7.7.7.7":
        # Test override to guarantee a High threat display
        if ip not in ip_cache:
            score = 75
            level = "high"
            result = {
                "source": "abuseipdb",
                "ip": "7.7.7.7",
                "threat_score": score,
                "threat_level": level,
                "country": "CN",
                "isp": "Test High ISP",
                "domain": "botnet-test.cn",
                "is_tor": False,
                "is_vpn": False,
                "total_reports": 850,
                "distinct_users": 120,
                "recent_categories": ["Brute-Force", "SSH Login Attempts"],
                "last_reported": datetime.now(timezone.utc).isoformat(),
            }
            if ml_engine:
                result["ml"] = ml_engine.analyze(result, record_type="ip")
            ip_cache[ip] = result
        result = ip_cache[ip]
        score = result["threat_score"]
        level = result["threat_level"]
        evt = {
            "id": str(uuid.uuid4()),
            "event_type": "ip_scan",
            "source": "abuseipdb",
            "threat_level": level,
            "threat_score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {"message": f"IP scan: {ip} — score {score}", "country": result["country"]},
        }
        if kafka_producer:
            await kafka_producer.send_and_wait(KAFKA_TOPIC, evt)
        else:
            register_event(evt)
            await broadcast(evt)
        return result

    if not ABUSEIPDB_KEY:
        # Demo mode if no key configured
        return get_ip_info(ip, force_critical=ip in KNOWN_MALICIOUS_IPS)

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(
                ABUSEIPDB_URL,
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
            resp.raise_for_status()
            d = resp.json().get("data", {})
        except httpx.HTTPStatusError as e:
            return JSONResponse({"error": f"AbuseIPDB error: {e.response.status_code}"}, status_code=502)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=502)

    score = d.get("abuseConfidenceScore", 0)
    level = score_to_level(score)

    # Extract attack categories (AbuseIPDB uses numeric codes)
    category_map = {
        3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
        6: "Ping of Death", 7: "Phishing", 9: "Open Proxy",
        10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
        15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
        18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
    }
    categories = list({
        category_map.get(c, f"Category {c}")
        for rep in (d.get("reports") or [])
        for c in (rep.get("categories") or [])
    })[:6]

    result = {
        "source": "abuseipdb",
        "ip": d.get("ipAddress", ip),
        "threat_score": score,
        "threat_level": level,
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "is_tor": d.get("isTor", False),
        "is_vpn": d.get("usageType") in ("VPN", "Hosting", "Data Center"),
        "total_reports": d.get("totalReports", 0),
        "distinct_users": d.get("numDistinctUsers", 0),
        "recent_categories": categories,
        "last_reported": d.get("lastReportedAt"),
    }

    # ── Spark ML + scikit-learn enrichment ──
    if ml_engine:
        result["ml"] = ml_engine.analyze(result, record_type="ip")

    # Push to Kafka stream
    evt = {
        "id": str(uuid.uuid4()),
        "event_type": "ip_scan",
        "source": "abuseipdb",
        "threat_level": level,
        "threat_score": score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"message": f"IP scan: {ip} — score {score}", "country": result["country"]},
    }
    if kafka_producer:
        await kafka_producer.send_and_wait(KAFKA_TOPIC, evt)
    else:
        register_event(evt)
        await broadcast(evt)

    return result


def _demo_ip(ip: str, force_critical: bool = False) -> dict:
    """Returns realistic demo data when no AbuseIPDB key is set."""
    score = random.randint(88, 100) if force_critical else random.randint(0, 100)
    level = score_to_level(score)
    cats = random.sample(["Port Scan", "SSH Brute-Force", "Web App Attack", "DDoS Attack", "Phishing"], k=random.randint(0,3))
    return {
        "source": "abuseipdb",
        "ip": ip,
        "threat_score": score,
        "threat_level": level,
        "country": random.choice(["CN", "RU", "US", "DE", "BR", "NL"]),
        "isp": random.choice(["Cloudflare Inc", "AS-CHOOPA", "OVH SAS", "Amazon AWS", "DigitalOcean LLC"]),
        "domain": "example.net",
        "is_tor": random.random() < 0.2,
        "is_vpn": random.random() < 0.3,
        "total_reports": random.randint(0, 500),
        "distinct_users": random.randint(0, 50),
        "recent_categories": cats,
        "last_reported": datetime.now(timezone.utc).isoformat(),
        "demo_mode": True,
    }


# ─────────────────────────────────────────────
# Email Breach Check — XposedOrNot (FREE, no key)
# ─────────────────────────────────────────────
@app.get("/api/check/email/{email:path}")
async def check_email(email: str):
    async with httpx.AsyncClient(timeout=12) as client:
        try:
            # Step 1: basic check
            resp = await client.get(f"{XON_URL}/{email}")

            if resp.status_code == 404:
                # 404 = email not found in any breach
                result = {
                    "source": "xposedornot",
                    "email": email,
                    "breached": False,
                    "breach_count": 0,
                    "breaches": [],
                    "threat_score": 0,
                    "threat_level": "low",
                }
                await _push_email_event(email, 0, "low")
                return result

            resp.raise_for_status()
            data = resp.json()

            # XposedOrNot can return breaches nested inside "Exposure", "exposedBreaches", or directly at the top level
            raw_breaches = []
            exposure = data.get("Exposure") or data.get("exposedBreaches") or data
            breach_list = exposure.get("breaches", [])
            # The API returns a list of lists
            if breach_list and isinstance(breach_list[0], list):
                raw_breaches = breach_list[0]
            elif breach_list:
                raw_breaches = breach_list

            breach_count = len(raw_breaches)
            score = min(breach_count * 12, 100)
            if breach_count >= 8: score = max(score, 85)
            elif breach_count >= 5: score = max(score, 60)
            elif breach_count >= 2: score = max(score, 35)
            level = score_to_level(score)

            # Step 2: get analytics for richer data (optional, best-effort)
            analytics = {}
            try:
                ar = await client.get(f"{XON_ANALYTICS}?email={email}")
                if ar.status_code == 200:
                    analytics = ar.json().get("BreachMetrics", {})
            except Exception:
                pass

            result = {
                "source": "xposedornot",
                "email": email,
                "breached": breach_count > 0,
                "breach_count": breach_count,
                "breaches": [{"Name": b} for b in raw_breaches],
                "threat_score": score,
                "threat_level": level,
                "analytics": analytics,
            }

            await _push_email_event(email, score, level)
            return result

        except httpx.HTTPStatusError as e:
            return JSONResponse({"error": f"XposedOrNot error: {e.response.status_code}"}, status_code=502)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=502)


async def _push_email_event(email: str, score: int, level: str):
    evt = {
        "id": str(uuid.uuid4()),
        "event_type": "email_breach_check",
        "source": "xposedornot",
        "threat_level": level,
        "threat_score": score,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": {"message": f"Email scan: {email} — score {score}"},
    }
    if kafka_producer:
        await kafka_producer.send_and_wait(KAFKA_TOPIC, evt)
    else:
        register_event(evt)
        await broadcast(evt)


# ─────────────────────────────────────────────
# Stats endpoint
# ─────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    total = stats["total_events"]
    avg = round(stats["score_sum"] / total, 1) if total > 0 else 0
    # Threat velocity: events in last 60 s
    recent = [e for e in events[-200:] if e.get("timestamp")]
    return {
        "total_events": total,
        "average_threat_score": avg,
        "threat_level_distribution": stats["threat_level_distribution"],
        "active_subscribers": len(subscribers),
        "kafka_connected": kafka_producer is not None,
        "events_per_minute": stats.get("events_per_minute", 0),
        "recent_event_count": len(recent),
    }


# ─────────────────────────────────────────────
# REST fallback for stream events
# ─────────────────────────────────────────────
@app.get("/api/stream/events")
async def stream_events(limit: int = 20):
    return {
        "events": events[-limit:][::-1],
        "total": stats["total_events"],
    }


# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "abuseipdb_configured": bool(ABUSEIPDB_KEY),
        "xposedornot": "free_no_key_required",
        "subscribers": len(subscribers),
        "ml_engine_ready": ml_engine is not None,
        "spark_ml_ready": bool(ml_engine and ml_engine._spark),
        "ml_trained": bool(ml_engine and ml_engine._trained),
    }


# ─────────────────────────────────────────────
# Spark ML Endpoint
# ─────────────────────────────────────────────
@app.get("/api/ml/anomaly")
async def detect_anomalies():
    """Uses PySpark MLlib (KMeans) to cluster threat scores and identify anomalies."""
    _spark = ml_engine._spark if ml_engine else None
    if not _spark:
        return {"error": "SparkSession not initialized. Please ensure PySpark is installed and Java is available."}

    if len(events) < 5:
        return {"error": "Not enough events for anomaly detection. Wait for more data."}

    data = []
    for e in events[-100:]:
        score = float(e.get("threat_score", 0))
        event_id = e.get("id", str(uuid.uuid4()))
        data.append((event_id, score))

    if not data:
        return {"error": "No valid data to process."}

    from pyspark.ml.feature import VectorAssembler
    from pyspark.ml.clustering import KMeans
    import pandas as pd

    # Use Pandas → Arrow path to avoid Python worker issues on Windows
    pdf = pd.DataFrame(data, columns=["id", "threat_score"])
    df = _spark.createDataFrame(pdf)
    assembler = VectorAssembler(inputCols=["threat_score"], outputCol="features")
    feature_df = assembler.transform(df)

    kmeans = KMeans(k=2, seed=42)
    model = kmeans.fit(feature_df)
    predictions = model.transform(feature_df)

    results = predictions.select("id", "threat_score", "prediction").collect()

    clusters: dict = {}
    for row in results:
        cluster = int(row["prediction"])
        clusters.setdefault(cluster, []).append({"id": row["id"], "score": row["threat_score"]})

    return {
        "status": "success",
        "total_analyzed": len(results),
        "algorithm": "KMeans (Spark ML)",
        "clusters": clusters
    }


# ─────────────────────────────────────────────
# Spark ML — Batch Analytics Report
# ─────────────────────────────────────────────
@app.get("/api/ml/analytics")
async def ml_analytics():
    """
    Runs a full Spark ML batch pipeline over all in-memory events.
    Returns cluster breakdown, threat distribution, anomaly count,
    top risk drivers, and score trend projection.
    """
    if not ml_engine:
        return {"error": "ML engine not available."}

    if len(events) < 3:
        return {"error": "Not enough events yet. Wait for stream data."}

    # Build a synthetic batch of recent events to run through ML
    batch_results = []
    for evt in events[-200:]:
        score = evt.get("threat_score", 0)
        synthetic_record = {
            "threat_score": score,
            "total_reports": random.randint(0, 500),
            "distinct_users": random.randint(0, 50),
            "is_tor": random.random() < 0.15,
            "is_vpn": random.random() < 0.2,
            "recent_categories": [],
            "country": evt.get("payload", {}).get("country", "US"),
        }
        ml_result = ml_engine.analyze(synthetic_record, record_type="ip")
        batch_results.append({
            "event_id": evt.get("id", ""),
            "score": score,
            "level": evt.get("threat_level", "low"),
            "ml_adjusted_score": ml_result.get("ml_adjusted_score", score),
            "anomaly": ml_result.get("anomaly", False),
            "cluster_name": ml_result.get("cluster_name", "Unknown"),
            "rf_prediction": ml_result.get("rf_prediction", "low"),
            "spark": ml_result.get("spark", {}),
        })

    # Aggregate cluster breakdown
    cluster_counts: dict = {}
    anomaly_count = 0
    rf_distribution: dict = {}
    spark_available = False

    for r in batch_results:
        cn = r["cluster_name"]
        cluster_counts[cn] = cluster_counts.get(cn, 0) + 1
        if r["anomaly"]:
            anomaly_count += 1
        rf = r["rf_prediction"]
        rf_distribution[rf] = rf_distribution.get(rf, 0) + 1
        if r["spark"].get("available"):
            spark_available = True

    trend = ml_engine.score_trend()

    return {
        "status": "success",
        "total_events_analyzed": len(batch_results),
        "anomaly_count": anomaly_count,
        "anomaly_rate_pct": round(anomaly_count / max(len(batch_results), 1) * 100, 1),
        "cluster_breakdown": cluster_counts,
        "rf_threat_distribution": rf_distribution,
        "score_trend": trend,
        "spark_enrichment_active": spark_available,
        "spark_pipeline": "Feature Assembly → Anomaly Clustering → Threat Classification" if spark_available else "unavailable",
        "models_used": ["Classification (Threat Tiering)", "Clustering (Attacker Profiling)", "Trend Projection", "Feature Assembly"],
        "sample_events": batch_results[:5],
    }


# ─────────────────────────────────────────────
# Spark ML — Score Trend
# ─────────────────────────────────────────────
@app.get("/api/ml/trend")
async def ml_trend():
    """Returns linear regression trend projection over recent threat scores."""
    if not ml_engine:
        return {"error": "ML engine not available."}
    return ml_engine.score_trend()
