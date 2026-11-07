# HellGuardian // Multi-Honeypot Threat Intelligence & Persistent Cloud Platform

[![Deploy to GitHub Pages](https://github.com/b-satwik/HellGuardian/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/b-satwik/HellGuardian/actions/workflows/deploy-pages.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-T--Pot%2024.04-blue.svg?logo=docker&logoColor=white)](https://github.com/telekom-security/tpotce)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

HellGuardian is an academic-grade, persistent cyber threat intelligence platform and SOC workspace. It integrates heterogeneous honeypot telemetry (AdaptiveCowrie SSH/Telnet, Suricata IDS, Dionaea malware traps, Conpot ICS/SCADA, and Heralding credential decoders), correlates attacker behavior across multi-stage campaigns, performs XGBoost ML classification, generates live threat graphs, and serves persistent analytics through a public **GitHub Pages** interface backed by a **Render Cloud API** and **PostgreSQL database**.

---

## 1. System Architecture & 5-Layer Separation

HellGuardian decouples local sensor infrastructure from public threat intelligence consumption, ensuring the dashboard remains **100% accessible even when the honeypot VM is shut down**.

```
                      +-------------------------------------------------------------+
                      |                      PUBLIC INTERNET                        |
                      |                                                             |
                      |   [ Faculty / Analyst Browser ]                              |
                      |           │                                                 |
                      |           ▼                                                 |
                      |   +──────────────────────────────+                          |
                      |   | Layer 5: GitHub Pages HUD    |                          |
                      |   | (b-satwik.github.io)         |                          |
                      |   +──────────────┬───────────────+                          |
                      |                  │ HTTPS Queries                            |
                      |                  ▼                                          |
                      |   +──────────────────────────────+                          |
                      |   | Layer 3: Render FastAPI API  |                          |
                      |   | (hellguardian-api.onrender)  |                          |
                      |   +──────────────┬───────────────+                          |
                      |                  │ Reads / Writes                           |
                      |                  ▼                                          |
                      |   +──────────────────────────────+                          |
                      |   | Layer 4: Cloud PostgreSQL DB |                          |
                      |   | (Persistent Telemetry Store) |                          |
                      |   +──────────────▲───────────────+                          |
                      +──────────────────┼──────────────────────────────────────────+
                                         │ Outbound Secure HTTPS Sync (X-Ingest-Key)
                                         │ (Zero Inbound Ports / No Tunnels)
+────────────────────────────────────────┴──────────────────────────────────────────+
| LOCAL SENSOR VM (Ubuntu Linux)                                                   |
|                                                                                   |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  | Layer 1: T-Pot Honeypot Docker Fleet                                        |  |
|  |   [Cowrie SSH/Telnet] [Suricata IDS] [Dionaea Malware] [Conpot ICS]          |  |
|  |   [Heralding Auth]    [T-Pot Init]                                          |  |
|  +──────────────────────────────────────┬──────────────────────────────────────+  |
|                                         │ Raw Telemetry & SQLite/JSON Logs        |
|                                         ▼                                         |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  | Layer 2: Local Telemetry Publisher Agent (cloud_sync/)                      |  |
|  |   • Watermark Tracking & Deduplication (sync_state.db)                      |  |
|  |   • Credential Sanitization (Passwords masked as '*****')                   |  |
|  |   • Periodic Heartbeats & Exponential Backoff Retry Buffer                  |  |
|  |   • Outbound Ingestion Payloads to Render Cloud API                         |  |
|  +─────────────────────────────────────────────────────────────────────────────+  |
+───────────────────────────────────────────────────────────────────────────────────+
```

### The 5 Architecture Layers
1. **Layer 1: Docker Honeypot Fleet (Local VM)**: Isolated containers running Cowrie, Suricata, Dionaea, Conpot, and Heralding under T-Pot CE. Captures live adversary interactions and records them to local volumes (`~/tpotce/data/cowrie/log/adaptive_cowrie.db`, `cowrie.json`, PCAPs, binary drops).
2. **Layer 2: Telemetry Publisher Agent (Local VM)**: Python agent running in `~/HellGuardian/cloud_sync/`. Extracts new events, correlates attacker sessions, queries the ML model and threat graph, sanitizes all credentials (`*****`), and securely pushes batches over HTTPS.
3. **Layer 3: Cloud Backend API (Render.com)**: High-performance FastAPI backend deployed on Render (`https://hellguardian-api.onrender.com`). Enforces `X-Ingest-Key` authentication, provides CORS headers for GitHub Pages, and computes sensor online/offline status based on heartbeat freshness.
4. **Layer 4: Persistent Cloud Database (PostgreSQL / SQLite)**: Hosted PostgreSQL database on Render. Persists all session records, ML classifications, feature importances, threat graph nodes/edges, and MITRE ATT&CK matrices indefinitely.
5. **Layer 5: Public Threat Intelligence HUD (GitHub Pages)**: Static web application hosted at `https://b-satwik.github.io/HellGuardian/`. Directly queries the cloud backend for real-time telemetry or historical archives.

---

## 2. Distinction: AdaptiveCowrie vs HellGuardian

| Feature / Responsibility | AdaptiveCowrie (`~/AdaptiveCowrie`) | HellGuardian (`~/HellGuardian`) |
| :--- | :--- | :--- |
| **Purpose** | Honeypot engine, ML training & deception logic | Cloud telemetry platform & public SOC dashboard |
| **Execution Host** | Local Ubuntu VM only | GitHub Pages + Render Cloud Backend |
| **Components** | Honeypot containers, XGBoost training, local DBs | Static HUD, FastAPI cloud backend, sync publisher |
| **Git Repository** | Private research repository | `https://github.com/b-satwik/HellGuardian` |
| **Public Exposure** | Strictly isolated / internal ports only | Publicly accessible at `b-satwik.github.io` |

---

## 3. Local Docker & Honeypot Prerequisites

The local sensor infrastructure requires Docker and Docker Compose installed on the Ubuntu VM.

### 1. Verify Docker Daemon
```bash
docker --version
docker compose version
sudo systemctl status docker
```

### 2. Required Honeypot Containers
The following T-Pot containers must be running in `~/tpotce`:
* `cowrie`: High-interaction SSH/Telnet emulation (Ports 22, 23)
* `suricata`: High-performance Network IDS and packet inspection
* `dionaea`: Malware capture and SMB/FTP/MSSQL trap (Ports 21, 42, 135, 445, 1433, etc.)
* `heralding`: Multi-protocol credential harvest trap (Ports 110, 143, 465, 993, 995, 1080, 5432, 5900)
* `conpot_kamstrup_382`, `conpot_guardian_ast`, `conpot_iec104`, `conpot_ipmi`: Industrial control system honeypots
* `tpotinit`: Environmental preparation and interface initialization

### 3. Start Honeypots
```bash
cd ~/tpotce
docker compose up -d
```
Check running containers:
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

---

## 4. Local Publisher Installation & Configuration

The telemetry publisher transmits honeypot telemetry from your local machine to the cloud backend.

### 1. Configure Local Environment (`.env`)
Create `/home/balasatwik/HellGuardian/.env` (ignored by git):
```ini
# Cloud Backend Configuration
CLOUD_API_URL=https://hellguardian-api.onrender.com
INGEST_API_KEY=your_secure_ingest_key_here

# Telemetry Sync Cadence
OFFLINE_TIMEOUT_SECONDS=300
SYNC_INTERVAL_SECONDS=30
HEARTBEAT_INTERVAL_SECONDS=60

# Local Honeypot & DB Paths
ADAPTIVECOWRIE_DIR=/home/balasatwik/AdaptiveCowrie
COWRIE_DB_PATH=/home/balasatwik/tpotce/data/cowrie/log/adaptive_cowrie.db
ML_DB_PATH=/home/balasatwik/tpotce/data/cowrie/log/adaptive_cowrie.db
THREAT_GRAPH_PATH=/home/balasatwik/ML_Deployment/graph/live_threat_graph.pkl
DOWNLOADS_DIR=/home/balasatwik/tpotce/data/cowrie/downloads
TTY_DIR=/home/balasatwik/tpotce/data/cowrie/log/tty
```

### 2. Operational CLI Commands
The platform management script `start_hellguardian.sh` provides complete control:

```bash
cd ~/HellGuardian

# Run a single batch synchronization (verifies ingestion & auth)
./start_hellguardian.sh sync-once

# Execute a full historical re-sync (resets sync_state.db watermarks)
./start_hellguardian.sh full-sync

# Start the publisher agent continuously in the background
./start_hellguardian.sh start-sync

# Check publisher and backend process status
./start_hellguardian.sh status

# Tail real-time publisher logs
tail -f publisher_output.log

# Stop the background publisher agent
./start_hellguardian.sh stop-sync
```

### 3. Optional: Configure Systemd Daemon
To ensure the publisher starts automatically whenever the Ubuntu VM boots:
```bash
sudo cp cloud_sync/hellguardian-publisher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hellguardian-publisher
sudo systemctl start hellguardian-publisher
sudo systemctl status hellguardian-publisher
```

---

## 5. Persistent Cloud Backend Deployment (Render.com)

The backend provides persistent storage and API endpoints for the GitHub Pages frontend.

### 1. Render Deployment via Blueprint
1. Sign in to [Render.com](https://render.com).
2. Click **New +** -> **Blueprint**.
3. Connect your `https://github.com/b-satwik/HellGuardian` repository.
4. Render automatically applies `cloud_backend/render.yaml` to deploy:
   * **Web Service**: FastAPI Python backend (`hellguardian-cloud-backend`)
   * **Database**: Managed PostgreSQL instance

### 2. Environment Variables on Render
Configure these in the Render dashboard under **Environment**:
* `DATABASE_URL`: Connection string to Render PostgreSQL (`postgresql://...`)
* `INGEST_API_KEY`: Secret token for authorization (must match `INGEST_API_KEY` in VM `.env`)
* `OFFLINE_TIMEOUT_SECONDS`: `300` (threshold in seconds before marking sensors offline)

### 3. Health Check
Verify the deployed backend:
```bash
curl -s https://hellguardian-api.onrender.com/health
```
Expected response:
```json
{
  "status": "ok",
  "database": "connected",
  "sensor_status": "Online",
  "last_heartbeat": 1794034912.0
}
```

---

## 6. GitHub Pages Frontend Deployment

The frontend HUD is automatically built and deployed to GitHub Pages via GitHub Actions.

### 1. Frontend API Configuration
Verify `hellguardian/assets/js/config.js` points to your Render backend:
```javascript
window.HELLGUARDIAN_CONFIG = {
  API_BASE_URL: "https://hellguardian-api.onrender.com",
  SENSOR_OFFLINE_THRESHOLD_SECONDS: 300,
  STATUS_POLL_INTERVAL_MS: 30000
};
```

### 2. GitHub Pages Settings
1. Go to repository **Settings** -> **Pages**.
2. Set **Build and deployment > Source** to **GitHub Actions**.
3. Pushing any change to `main` triggering `.github/workflows/deploy-pages.yml` deploys the site to:
   `https://b-satwik.github.io/HellGuardian/`

---

## 7. Troubleshooting & Common Issues

### 1. HTTP 401 Unauthorized (`Invalid or missing X-Ingest-Key`)
* **Cause**: The `INGEST_API_KEY` in the local VM `.env` file does not match the `INGEST_API_KEY` configured in the Render Dashboard Environment settings.
* **Fix**: Check the Render Dashboard under **Environment**, copy the exact `INGEST_API_KEY` value, paste it into `/home/balasatwik/HellGuardian/.env`, and re-run `./start_hellguardian.sh sync-once`.

### 2. Free Tier Render Backend Cold Starts
* **Symptom**: First request to `https://hellguardian-api.onrender.com` takes 30-50 seconds to respond.
* **Explanation**: Render's free tier spins down instances after 15 minutes of inactivity. Once spun up, subsequent requests respond in under 100ms.
* **Fix**: The publisher agent includes automatic retry backoff (2s, 4s, 8s, up to 60s) so sync resumes cleanly once the backend wakes up.

### 3. Sensor Status Stuck in "Offline (Historical Archive)"
* **Cause**: More than 300 seconds have elapsed since the last received heartbeat, or the publisher daemon is stopped.
* **Fix**: Verify the publisher agent is running with `./start_hellguardian.sh status`. Start it with `./start_hellguardian.sh start-sync`.

### 4. Honeypot Containers Missing or Offline
* **Cause**: Docker service stopped or containers exited.
* **Fix**: Run `docker ps -a` to inspect container states. Restart T-Pot with `cd ~/tpotce && docker compose up -d`.

---

## 8. Security & Hardening Checklist

- [x] **Zero Plaintext Passwords**: Attacker-supplied passwords in authentication histories and credential logs are masked as `*****`.
- [x] **No Private Keys**: SSH host keys (`etc/ssh_host_*`) remain isolated on the honeypot host.
- [x] **No Binary Malware Uploads**: Only file metadata and SHA256/MD5 cryptographic hashes are transmitted.
- [x] **Strict Ingestion Authentication**: Ingestion and heartbeat endpoints reject all requests lacking a valid `X-Ingest-Key`.
- [x] **Idempotent Synchronization**: `sync_state.db` on the VM and `ON CONFLICT` constraints in PostgreSQL prevent duplicated records.
- [x] **Outbound-Only Communication**: The honeypot VM initiates outbound HTTPS requests; zero inbound ports or reverse tunnels are exposed.
