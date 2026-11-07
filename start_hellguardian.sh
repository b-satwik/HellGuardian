#!/usr/bin/env bash
# ==============================================================================
# HellGuardian - Platform Management & Telemetry Synchronization Script
# Controls Cloud Backend API and Local Telemetry Publishing Agent
# ==============================================================================

set -e

HELLGUARDIAN_DIR="/home/balasatwik/HellGuardian"
ADAPTIVECOWRIE_DIR="${ADAPTIVECOWRIE_DIR:-/home/balasatwik/AdaptiveCowrie}"

# Source local .env if present
if [ -f "${HELLGUARDIAN_DIR}/.env" ]; then
    set -a
    . "${HELLGUARDIAN_DIR}/.env"
    set +a
fi
CLOUD_PID_FILE="/tmp/hellguardian_cloud.pid"
PUBLISHER_PID_FILE="/tmp/hellguardian_publisher.pid"
CLOUD_LOG="/tmp/hellguardian_cloud.log"
PUBLISHER_LOG="${HELLGUARDIAN_DIR}/publisher_output.log"
PYTHON_BIN="/usr/bin/python3"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Setup PYTHONPATH to include HellGuardian and AdaptiveCowrie libraries if present
export PYTHONPATH="${HELLGUARDIAN_DIR}:${ADAPTIVECOWRIE_DIR}/.venv/lib/python3.12/site-packages:${ADAPTIVECOWRIE_DIR}:${PYTHONPATH}"

start_cloud() {
    echo -e "${CYAN}==> Starting HellGuardian Cloud Backend API (Port 8090)...${NC}"
    if curl -s -m 1 http://127.0.0.1:8090/health >/dev/null 2>&1; then
        echo -e "    ${GREEN}✓ Cloud Backend API is already running on Port 8090.${NC}"
        return 0
    fi
    nohup "${PYTHON_BIN}" -m uvicorn cloud_backend.main:app --host 0.0.0.0 --port 8090 </dev/null > "${CLOUD_LOG}" 2>&1 &
    local cpid=$!
    disown "$cpid" 2>/dev/null || true
    echo "$cpid" > "$CLOUD_PID_FILE"
    sleep 2
    if curl -s -m 2 http://127.0.0.1:8090/health >/dev/null 2>&1; then
        echo -e "    ${GREEN}✓ Cloud Backend API started successfully (PID: ${cpid}) on Port 8090.${NC}"
    else
        echo -e "    ${YELLOW}Cloud Backend started (PID: ${cpid}). See ${CLOUD_LOG}.${NC}"
    fi
}

stop_cloud() {
    echo -e "${CYAN}==> Stopping Cloud Backend API...${NC}"
    if [ -f "$CLOUD_PID_FILE" ]; then
        local pid
        pid=$(cat "$CLOUD_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            rm -f "$CLOUD_PID_FILE"
            echo -e "    ${GREEN}✓ Cloud Backend (PID $pid) stopped.${NC}"
        fi
    fi
    local pids
    pids=$(fuser 8090/tcp 2>/dev/null || true)
    if [ -n "$pids" ]; then
        kill -9 $pids 2>/dev/null || true
        echo -e "    ${GREEN}✓ Cleared Port 8090.${NC}"
    fi
}

start_sync() {
    echo -e "${CYAN}==> Launching Telemetry Publisher Agent...${NC}"
    if [ -f "$PUBLISHER_PID_FILE" ]; then
        local pid
        pid=$(cat "$PUBLISHER_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo -e "    ${GREEN}✓ Publisher Agent already running (PID: $pid).${NC}"
            return 0
        fi
    fi
    nohup "${PYTHON_BIN}" "${HELLGUARDIAN_DIR}/cloud_sync/run_publisher.py" --daemon </dev/null > "${PUBLISHER_LOG}" 2>&1 &
    local ppid=$!
    disown "$ppid" 2>/dev/null || true
    echo "$ppid" > "$PUBLISHER_PID_FILE"
    echo -e "    ${GREEN}✓ Telemetry Publisher launched (PID: ${ppid}). Logging to ${PUBLISHER_LOG}.${NC}"
}

stop_sync() {
    echo -e "${CYAN}==> Stopping Telemetry Publisher Agent...${NC}"
    if [ -f "$PUBLISHER_PID_FILE" ]; then
        local pid
        pid=$(cat "$PUBLISHER_PID_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            rm -f "$PUBLISHER_PID_FILE"
            echo -e "    ${GREEN}✓ Publisher Agent (PID $pid) stopped.${NC}"
        fi
    fi
}

sync_once() {
    echo -e "${CYAN}==> Executing One-Time Telemetry Sync...${NC}"
    "${PYTHON_BIN}" "${HELLGUARDIAN_DIR}/cloud_sync/run_publisher.py" --once "$@"
}

status() {
    echo -e "${BOLD}${CYAN}=== HellGuardian Service Status ===${NC}"
    echo ""
    if curl -s -m 1 http://127.0.0.1:8090/health >/dev/null 2>&1; then
        echo -e "  [${GREEN}ACTIVE${NC}] Cloud Backend API (Port 8090)"
    else
        echo -e "  [${YELLOW}INACTIVE${NC}] Cloud Backend API (Port 8090)"
    fi

    if [ -f "$PUBLISHER_PID_FILE" ] && kill -0 "$(cat "$PUBLISHER_PID_FILE" 2>/dev/null)" 2>/dev/null; then
        echo -e "  [${GREEN}ACTIVE${NC}] Telemetry Publisher Agent (PID: $(cat "$PUBLISHER_PID_FILE"))"
    else
        echo -e "  [${YELLOW}INACTIVE${NC}] Telemetry Publisher Agent"
    fi
    echo ""
}

case "${1:-status}" in
    start)
        start_cloud
        start_sync
        ;;
    stop)
        stop_sync
        stop_cloud
        ;;
    restart)
        stop_sync
        stop_cloud
        start_cloud
        start_sync
        ;;
    status)
        status
        ;;
    start-cloud)
        start_cloud
        ;;
    stop-cloud)
        stop_cloud
        ;;
    start-sync)
        start_sync
        ;;
    stop-sync)
        stop_sync
        ;;
    sync-once)
        shift
        sync_once "$@"
        ;;
    full-sync)
        sync_once --reset-state
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|start-cloud|stop-cloud|start-sync|stop-sync|sync-once|full-sync}"
        exit 1
        ;;
esac
