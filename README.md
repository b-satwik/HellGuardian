# HellGuardian // Multi-Honeypot Threat Intelligence & Persistent Cloud Platform

[![Deploy to GitHub Pages](https://github.com/b-satwik/HellGuardian/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/b-satwik/HellGuardian/actions/workflows/deploy-pages.yml)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

HellGuardian is an academic-grade, persistent cyber threat intelligence platform and SOC workspace. It integrates heterogeneous honeypot telemetry (AdaptiveCowrie, Suricata IDS, Dionaea malware traps, Conpot ICS, and Heralding credential decoders), correlates attacker behavior across multi-stage campaigns, and serves real-time and historical analytics through a public **GitHub Pages** interface.

---

## 1. System Architecture

```
                      +-------------------------------------------------------------+
                      |                      PUBLIC INTERNET                        |
                      |                                                             |
                      |   [ Faculty / Analyst Browser ]                              |
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
                                         │ Outbound Secure HTTPS Sync (X-Ingest-Key)
                                         │ (Zero Inbound Ports / No Tunnels)
+────────────────────────────────────────┴──────────────────────────────────────────+
| LOCAL UBUNTU VM (Can be powered off anytime without losing historical dashboard)    |
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
|                                         │ Processed Intelligence                   |
|                                         ▼                                         |
|  +─────────────────────────────────────────────────────────────────────────────+  |
|  |                  HellGuardian Cloud Publishing Agent                        |  |
|  |   • Watermark State Tracking & Deduplication (sync_state.db)                |  |
|  |   • Strict Credential Sanitization (Passwords masked as '*****')            |  |
|  |   • Periodic Heartbeats & Exponential Backoff Retry Queue                   |  |
|  +─────────────────────────────────────────────────────────────────────────────+  |
+───────────────────────────────────────────────────────────────────────────────────+
```

### Key Operational Capabilities
* **Persistent Historical Intelligence**: When your sensor VM is turned off, the public dashboard remains **100% accessible**, serving real historical attacker profiles, threat scores, MITRE ATT&CK techniques, and threat graphs from persistent cloud storage.
* **Transparent Sensor Health**:
  * VM Online: Displays green pulsing dot `STATUS: ONLINE (LIVE SENSORS)`
  * VM Offline: Displays amber dot `STATUS: OFFLINE (HISTORICAL ARCHIVE)` with the exact `[Last Sync: <timestamp>]`
* **Zero Attack Surface on Local VM**: The publishing agent uses strictly outbound HTTPS requests. No inbound ports, SSH tunnels, or honeypot services are exposed to the public internet.
* **Strict Privacy & Sanitization**: Passwords in telemetry, auth histories, and credential logs are automatically masked as `*****`. No private keys or raw malware binaries are uploaded.

---

## 2. Directory Layout

```
.
├── hellguardian/             # Frontend Static Website (GitHub Pages Compatible)
│   ├── index.html            # Main HUD layout with dynamic Online/Offline sensor badge
│   ├── .nojekyll             # Bypasses Jekyll processing on GitHub Pages
│   ├── assets/
│   │   ├── js/config.js      # Cloud API URL & timeout configuration
│   │   ├── js/app.js         # HUD Controller (getApiUrl helper & status polling)
│   │   └── css/style.css     # SOC Light System UI Stylesheet
│   └── pages/                # High-Density Kippo-style view templates
│       ├── home.html         # Overview dashboard
│       ├── cowrie.html       # Cowrie SSH session table & keystrokes
│       ├── suricata.html     # IDS network alerts
│       ├── heralding.html    # Credential spraying telemetry
│       ├── dionaea.html      # Malware capture records
│       ├── conpot.html       # SCADA/ICS Modbus events
│       ├── sandbox.html      # Sandbox execution analysis
│       ├── ml.html           # XGBoost predictions, SHAP & LIME explanations
│       ├── graph.html        # Interactive D3 Threat Graph
│       ├── mitre.html        # MITRE ATT&CK technique matrix
│       ├── ioc.html          # Indicators of Compromise (IoC) feed
│       ├── memory.html       # Adaptive Deception memory & persistent VFS
│       ├── investigate.html  # Forensic inspection workspace & TTY playback
│       ├── reports.html      # Threat reports list
│       └── settings.html     # Fleet health and container statuses
├── cloud_backend/            # Standalone Persistent Cloud Telemetry API
│   ├── main.py               # FastAPI application (authenticated ingest & public query)
│   ├── database.py           # Persistent Database Layer (SQLite WAL / PostgreSQL)
│   ├── security.py           # Ingestion Key authentication & credential masking
│   ├── schemas.py            # Pydantic models for ingest & heartbeat
│   ├── config.py             # Server configurations & timeout settings
│   ├── requirements.txt      # Python dependencies
│   ├── Dockerfile            # Container definition
│   ├── render.yaml           # 1-Click Render.com deployment Blueprint
│   └── .env.example          # Backend environment template
├── cloud_sync/               # Local VM Telemetry Publishing Agent
│   ├── telemetry_publisher.py # Batch extractor, sanitizer, and offline retry queue
│   ├── run_publisher.py      # Agent CLI runner (--daemon, --once, --reset-state)
│   └── hellguardian-publisher.service # Linux systemd service unit
├── .github/workflows/        # Automated GitHub Actions
│   └── deploy-pages.yml      # CI/CD workflow deploying hellguardian/ to GitHub Pages
├── docs/                     # Documentation
│   ├── GITHUB_PAGES_DEPLOYMENT.md # Complete deployment & cloud setup guide
│   └── DASHBOARD_ARCHITECTURE.md  # Frontend UI design and layout reference
├── start_hellguardian.sh     # Master management script for backend & publisher
└── .env.example              # Environment variables template
```

---

## 3. Quick Start Guide

### Step 1: Deploy the Cloud Backend
Deploy the `cloud_backend` to any cloud provider:
* **Render.com**: Connect this repository and select **Blueprint** (`cloud_backend/render.yaml`).
* **Docker / Fly.io / Railway**: Build and run `cloud_backend/Dockerfile`:
  ```bash
  docker build -t hellguardian-cloud -f cloud_backend/Dockerfile .
  docker run -d -p 8090:8090 -e INGEST_API_KEY="your-secret-key" hellguardian-cloud
  ```

### Step 2: Configure and Deploy GitHub Pages
1. In `hellguardian/assets/js/config.js`, set your deployed cloud backend URL:
   ```javascript
   window.HELLGUARDIAN_CONFIG = {
     API_BASE_URL: "https://your-cloud-backend.onrender.com",
     SENSOR_OFFLINE_THRESHOLD_SECONDS: 300,
     STATUS_POLL_INTERVAL_MS: 30000
   };
   ```
2. In your GitHub repository settings, go to **Settings** -> **Pages**, and set **Source** to **GitHub Actions**.
3. Push to `main`. The included workflow `.github/workflows/deploy-pages.yml` will automatically build and publish your dashboard at `https://<username>.github.io/HellGuardian/`.

### Step 3: Run the Local Telemetry Publisher
On your honeypot host (where AdaptiveCowrie and T-Pot are installed):
```bash
# Configure environment
cp .env.example .env
nano .env  # Set CLOUD_API_URL and INGEST_API_KEY

# Test a single batch synchronization
./start_hellguardian.sh sync-once

# Start publisher daemon in background
./start_hellguardian.sh start-sync

# Check status
./start_hellguardian.sh status
```

---

## 4. Documentation

* [Full GitHub Pages & Cloud Deployment Guide](docs/GITHUB_PAGES_DEPLOYMENT.md)
* [Dashboard Architecture & Layout Reference](docs/DASHBOARD_ARCHITECTURE.md)

---

## 5. Security & Verification

* **Authentication**: All ingestion and heartbeat API calls require an `X-Ingest-Key` HTTP header matching `INGEST_API_KEY`.
* **Sanitization**: Password values in credentials and session histories are sanitized to `*****` before ingestion.
* **Integrity**: Local synchronization uses unique hash-based event identifiers and local watermark tracking in `sync_state.db` to prevent duplicates.
