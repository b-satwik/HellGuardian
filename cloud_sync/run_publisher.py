#!/usr/bin/env python3
import os
import sys
import argparse

# Resolve paths
WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKSPACE_DIR not in sys.path:
    sys.path.insert(0, WORKSPACE_DIR)

# Load .env if present
env_path = os.path.join(WORKSPACE_DIR, '.env')
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k not in os.environ:
                    os.environ[k] = v

from cloud_sync.telemetry_publisher import TelemetryPublisher

def main():
    parser = argparse.ArgumentParser(description="HellGuardian Cloud Telemetry Publisher Agent")
    parser.add_argument("--url", default=os.getenv("CLOUD_API_URL", "http://localhost:8090"), help="Cloud API Base URL")
    parser.add_argument("--key", default=os.getenv("INGEST_API_KEY", "hg_sec_token_9f82d1a4e76c"), help="Ingestion API Key")
    parser.add_argument("--once", action="store_true", help="Execute single sync run and exit")
    parser.add_argument("--daemon", action="store_true", help="Run continuously as background daemon")
    parser.add_argument("--reset-state", action="store_true", help="Clear sync state database and re-sync all data")
    parser.add_argument("--sync-interval", type=int, default=30, help="Interval between sync batches in seconds")
    parser.add_argument("--hb-interval", type=int, default=60, help="Heartbeat interval in seconds")

    args = parser.parse_args()

    publisher = TelemetryPublisher(cloud_api_url=args.url, ingest_api_key=args.key)

    if args.reset_state:
        publisher.reset_state()

    if args.once:
        success = publisher.sync_once(full_resync=args.reset_state)
        sys.exit(0 if success else 1)
    else:
        # Default to daemon mode
        publisher.run_daemon(sync_interval=args.sync_interval, heartbeat_interval=args.hb_interval)

if __name__ == "__main__":
    main()
