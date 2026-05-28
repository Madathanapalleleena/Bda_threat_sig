# ThreatSig — Real-Time Threat Intelligence Dashboard

A Big Data Analytics (BDA) project that detects, classifies, and visualizes cyber threats in real time using **PySpark MLlib**, **FastAPI**, **Kafka**, and live threat intelligence APIs.

---

## Features

- **Live threat stream** — WebSocket-based event feed with simulated Kafka pipeline
- **IP reputation check** — AbuseIPDB API (threat score, country, ISP, TOR/VPN detection)
- **Email breach check** — XposedOrNot API (breach count, affected services)
- **Geo intelligence** — IP geolocation + ASN risk scoring (ip-api.com / ipinfo.io)
- **PySpark ML pipelines**:
  - KMeans clustering (Attacker / Scanner / Spammer / Clean)
  - Random Forest classification (threat tier prediction)
  - Anomaly detection (distance from cluster center)
  - Linear regression (score trend projection)
  - Feature Assembly with VectorAssembler & StandardScaler

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, Uvicorn, Python 3.10+ |
| Big Data / ML | PySpark 3.4, scikit-learn, pandas, NumPy |
| Streaming | WebSocket, aiokafka (optional) |
| Threat Intel | AbuseIPDB API, XposedOrNot API |
| Geo Intel | ip-api.com, ipinfo.io |
| Container | Docker + Docker Compose (Kafka/Zookeeper) |

---

## Project Structure

```
bda/
├── main.py          # FastAPI app, REST + WebSocket endpoints, Kafka integration
├── ml_engine.py     # PySpark MLlib pipelines (KMeans, RF, regression)
├── geo_intel.py     # IP geolocation + ASN risk enrichment
├── requirements.txt
├── commands.txt     # Quick-start run guide
└── .env             # API keys (do NOT commit)
```

---

## Setup

### Prerequisites

- Python 3.10+
- Java 8+ (required for PySpark) — set `JAVA_HOME`
- Docker (only for Kafka mode)

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure environment

Create a `.env` file:

```
ABUSEIPDB_API_KEY=your_free_key_here
```

Get a free key at [abuseipdb.com](https://www.abuseipdb.com) (1000 checks/day, no cost).

---

## Running

### Option A — Without Kafka (simplest)

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open `index.html` in your browser or visit `http://localhost:8000`.  
Stream events appear automatically within ~5 seconds.

### Option B — With Kafka (full pipeline)

```bash
# 1. Start Kafka + Zookeeper
docker-compose up -d

# 2. Start backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/check/ip/{ip}` | IP reputation scan (AbuseIPDB + ML) |
| GET | `/api/check/email/{email}` | Email breach lookup (XposedOrNot) |
| GET | `/api/stream/events` | Recent threat events (REST fallback) |
| GET | `/api/stats` | Live stats and threat distribution |
| GET | `/api/ml/anomaly` | KMeans anomaly detection on live events |
| GET | `/api/ml/analytics` | Full ML batch report (all pipelines) |
| GET | `/api/ml/trend` | Linear regression score trend |
| GET | `/health` | Health check (API keys, ML, Spark status) |
| WS  | `/ws/stream` | WebSocket live threat feed |

### Quick test scans

```bash
# Threat levels
curl http://localhost:8000/api/check/ip/9.9.9.9     # Critical
curl http://localhost:8000/api/check/ip/7.7.7.7     # High
curl http://localhost:8000/api/check/ip/8.8.8.8     # Medium

# Email breach
curl "http://localhost:8000/api/check/email/test@yahoo.com"

# ML reports
curl http://localhost:8000/api/ml/analytics
curl http://localhost:8000/api/ml/trend
```

---

## Threat Score Levels

| Score | Level |
|---|---|
| 85 – 100 | Critical |
| 60 – 84 | High |
| 35 – 59 | Medium |
| 0 – 34 | Low |

---

## Notes

- Kafka is **optional** — the app runs a built-in stream simulator if Kafka is unavailable.
- PySpark is **optional** — the ML engine gracefully degrades to scikit-learn if Java/Spark is not available.
- Never commit your `.env` file — add it to `.gitignore`.
