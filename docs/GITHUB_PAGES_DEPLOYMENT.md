# HellGuardian — GitHub Pages Deployment & Persistent Cloud Telemetry

This guide explains how to deploy the **HellGuardian SOC Threat Intelligence Platform** to **GitHub Pages** while retaining persistent cloud telemetry, historical attacker profiles, and ML classifications even when your local Ubuntu honeypot VM is switched off.

---

## 1. Architectural Overview

```
                      +-------------------------------------------------------------+
                      |                      PUBLIC INTERNET                        |
                      |                                                             |
                      |   [ Analyst Browser ]                                        |
                      |           │                                                 |
                      |           ▼                                                 |
                      |   +──────────────────────────────+                          |
                      |   |   GitHub Pages Frontend      |                          |
                      |   |   (b-satwik.github.io)       |                          |
                      |   +──────────────┬───────────────+                          |
                      |                  │ HTTPS Queries                            |
                      |                  ▼                                          |
                      |   +──────────────────────────────+                          |
                      |   | Persistent Cloud Backend API |                          |
                      |   | (Render / Railway / Supabase)|                          |
                      |   +──────────────▲───────────────+                          |
                      +──────────────────┼──────────────────────────────────────────+
                                         │ Secure HTTPS Ingestion (X-Ingest-Key)
                                         │ (Outbound Only — No Port Forwarding)
+────────────────────────────────────────┴──────────────────────────────────────────+
| LOCAL UBUNTU VM (Can be powered off anytime without losing historical analytics)    |
|                                                                                   |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  |                       T-Pot Honeypot Docker Fleet                           |  |
|  |   [Cowrie SSH]   [Suricata IDS]   [Dionaea Malware]   [Conpot ICS]          |  |
|  +──────────────────────────────────────┬──────────────────────────────────────+  |
|                                         │ Raw Event Streams                       |
|                                         ▼                                         |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  |                   Local Telemetry & ML Runtime Pipeline                     |  |
|  |   • Event Normalization & Regex Parsers                                     |  |
|  |   • XGBoost Behavior Classification & SHAP/LIME Local Explanations          |  |
|  |   • NetworkX Live Threat Graph & MITRE ATT&CK Mapping                       |  |
|  |   • Adaptive Memory & Virtual Filesystem Persistence                        |  |
|  +──────────────────────────────────────┬──────────────────────────────────────+  |
|                                         │ Sanitized Processed Intel               |
|                                         ▼                                         |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  |                  HellGuardian Cloud Publishing Agent                        |  |
|  |   • Watermark State Tracking & Deduplication (sync_state.db)                |  |
|  |   • Strict Credential Sanitization (Passwords masked as '*****')            |  |
|  |   • Periodic Heartbeats & Exponential Backoff Resilience                    |  |
|  +─────────────────────────────────────────────────────────────────────────────+  |
+───────────────────────────────────────────────────────────────────────────────────+
```

### Key Operational Characteristics:
1. **VM Independence**: When your Ubuntu VM is powered off, the GitHub Pages dashboard remains 100% accessible, serving historical attacker profiles, charts, IOCs, and graphs from persistent cloud storage.
2. **Transparent Sensor State**: If the cloud backend has not received a heartbeat within 5 minutes (`300s`), the dashboard displays `STATUS: OFFLINE (HISTORICAL ARCHIVE)` with the exact `[Last Sync: <timestamp>]`.
3. **Automatic Reconnection**: As soon as the VM powers on, the local publisher agent resumes sending heartbeats, synchronizes queued events, and the dashboard transitions to `STATUS: ONLINE (LIVE SENSORS)`.
4. **Zero VM Attack Surface**: The VM initiates outbound HTTPS requests only. No inbound ports, SSH tunnels, or honeypot services are ever exposed directly to the public internet.
5. **Strict Data Sanitization**: Honeypot passwords are automatically masked (`*****`), and private keys or raw malware binaries are never uploaded.

---

## 2. Deploying the Persistent Cloud Backend

The cloud backend is a standalone FastAPI service with an authenticated ingestion endpoint (`POST /api/ingest`), heartbeat tracking (`POST /api/heartbeat`), and public read endpoints.

### Option A: Free One-Click Deployment on Render.com (Recommended)

1. Sign up or log into [Render.com](https://render.com).
2. Click **New +** -> **Blueprint**.
3. Connect your GitHub repository: `https://github.com/b-satwik/HellGuardian`.
4. Render detects `cloud_backend/render.yaml` automatically:
   - **Build Command**: `pip install -r cloud_backend/requirements.txt`
   - **Start Command**: `python3 -m uvicorn cloud_backend.main:app --host 0.0.0.0 --port $PORT`
5. In the Environment Variables settings, configure:
   - `INGEST_API_KEY`: Generate a secure random token (e.g., `hg_sec_token_9f82d1a4e76c`).
   - `OFFLINE_TIMEOUT_SECONDS`: `300` (5 minutes).
6. Click **Apply**. Once deployed, Render will provide your public URL:
   `https://hellguardian-api.onrender.com`

### Option B: Deploying via Docker or Railway / Fly.io

A production-ready `Dockerfile` is provided in `cloud_backend/Dockerfile`:
```bash
docker build -t hellguardian-cloud -f cloud_backend/Dockerfile .
docker run -d -p 8090:8090 -e INGEST_API_KEY="your-secret-key" hellguardian-cloud
```

### Option C: Using an External PostgreSQL Database (Supabase / Neon)

By default, the backend uses a local SQLite database (`hellguardian_cloud.db`). To use a managed cloud PostgreSQL database:
1. Create a free PostgreSQL instance on [Supabase](https://supabase.com) or [Neon](https://neon.tech).
2. Set the environment variable on your cloud host:
   ```bash
   DATABASE_URL="postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres"
   ```
3. The backend automatically creates all required tables and indexes on startup.

---

## 3. Configuring the Local VM Publishing Agent

The local publishing agent extracts processed telemetry from Cowrie's SQLite database, ML predictors, and honeypot parsers, and uploads batches to your cloud backend.

### 1. Configure VM Environment Variables
Create or update `/home/balasatwik/AdaptiveCowrie/.env`:
```bash
CLOUD_API_URL=https://hellguardian-api.onrender.com
INGEST_API_KEY=hg_sec_token_9f82d1a4e76c
SYNC_INTERVAL_SECONDS=30
HEARTBEAT_INTERVAL_SECONDS=60
```

### 2. Verify Sync with a One-Time Batch
Run a single sync to verify authentication and ingest historical honeypot records:
```bash
cd /home/balasatwik/AdaptiveCowrie
./start_platform.sh sync-once
```
*Expected output:*
```
==> Triggering One-Time Telemetry Sync Batch...
[Publisher] Heartbeat sent successfully to https://hellguardian-api.onrender.com
[Publisher] Sync successful! Persisted counts: {'overview_stats': 1, 'timeline_events': 50, 'cowrie_sessions': 51, 'ml_profiles': 41, ...}
```

### 3. Run the Publisher Daemon
To keep telemetry syncing continuously in the background:
```bash
./start_platform.sh start-sync
```

To stop the agent:
```bash
./start_platform.sh stop-sync
```

### 4. Optional: Install as an Automated Linux System Service
To start the publisher automatically when the Ubuntu VM boots:
```bash
sudo cp cloud_sync/hellguardian-publisher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hellguardian-publisher
sudo systemctl start hellguardian-publisher
```

---

## 4. Deploying the Frontend to GitHub Pages

### 1. Configure the Cloud API Base URL
Open `hellguardian/assets/js/config.js` and set your cloud backend URL:
```javascript
window.HELLGUARDIAN_CONFIG = {
  API_BASE_URL: "https://hellguardian-api.onrender.com",
  SENSOR_OFFLINE_THRESHOLD_SECONDS: 300,
  STATUS_POLL_INTERVAL_MS: 30000
};
```

> **Dynamic URL Override**: You can also test or demonstrate different backends dynamically in any browser without rebuilding:
> `https://b-satwik.github.io/HellGuardian/?api=https://hellguardian-api.onrender.com`

### 2. Enable GitHub Pages in your GitHub Repository
1. Navigate to your repository on GitHub: `https://github.com/b-satwik/HellGuardian`.
2. Go to **Settings** -> **Pages**.
3. Under **Build and deployment**:
   - **Source**: Select **GitHub Actions**.

### 3. Trigger Automatic Deployment
The repository includes `.github/workflows/deploy-pages.yml`.
Any push to `main` affecting `hellguardian/**` will automatically build and publish your dashboard.

To push changes to GitHub:
```bash
git add hellguardian/ .github/workflows/deploy-pages.yml cloud_backend/ cloud_sync/ docs/
git commit -m "feat(cloud): add GitHub Pages deployment and persistent cloud telemetry sync"
git push origin main
```

Your dashboard will be live at:
`https://b-satwik.github.io/HellGuardian/`

---

## 5. Offline Simulation & Verification Testing

To test and demonstrate the offline archive behavior during an academic or technical presentation:

### Test 1: Full Online Operation
1. Start the platform and publisher on your VM:
   ```bash
   ./start_platform.sh start
   ./start_platform.sh start-sync
   ```
2. Open `https://b-satwik.github.io/HellGuardian/`.
3. The top navigation bar displays:
   - Green pulsing dot: `STATUS: ONLINE (LIVE SENSORS)`
   - Subtitle: `(Live Telemetry Stream)`
4. Launch an attack from another terminal:
   ```bash
   ssh -p 22 root@127.0.0.1
   ```
5. Within 30 seconds, the new session appears in the dashboard.

### Test 2: VM Shutdown / Offline Archive Mode
1. Stop the local publisher agent (simulating VM power-off):
   ```bash
   ./start_platform.sh stop-sync
   ```
2. After 5 minutes (or immediately if you reduce `OFFLINE_TIMEOUT_SECONDS=10` in test), refresh the dashboard.
3. The top navigation bar smoothly transitions to:
   - Amber dot (no pulse): `STATUS: OFFLINE (HISTORICAL ARCHIVE)`
   - Metadata: `[Last Sync: 2026-11-07 12:30:15]`
4. **Verify Persistence**:
   - All 51 Cowrie SSH sessions remain readable.
   - All 41 ML profile classifications and SHAP feature importance charts remain interactive.
   - The interactive Threat Graph (263 nodes, 607 edges) renders completely.
   - Suricata alerts, Conpot ICS scans, and IOC records remain fully queryable.
   - No fake or fabricated events are shown.

### Test 3: Sensor Reconnection
1. Start the publisher again:
   ```bash
   ./start_platform.sh start-sync
   ```
2. Refresh the dashboard. The badge immediately returns to `STATUS: ONLINE (LIVE SENSORS)`.

---

## 6. Security & Hardening Checklist

- [x] **Zero Raw Passwords**: Passwords in `auth_history`, `timeline_events`, and `heralding_credentials` are masked as `*****`.
- [x] **No Private Keys**: SSH host keys (`etc/ssh_host_*`) remain isolated on the VM.
- [x] **No Binary Malware Uploads**: Only file metadata and SHA256/MD5 hashes are uploaded.
- [x] **Ingestion Authentication**: Cloud endpoints require a cryptographically random `X-Ingest-Key` header.
- [x] **Deduplication**: `sync_state.db` on the VM and `ON CONFLICT` constraints in the cloud database prevent duplicate records.
- [x] **CORS Restricted**: Browser queries are limited to safe HTTP GET methods.
