#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: DNS Server Startup Script
#
# Launches the Authoritative DNS server (NSD or lightweight Python fallback),
# pinned to CPU Core 1 with Response Rate Limiting (RRL) explicitly disabled.
#
# Supports both network namespace isolation (--netns srv) and physical host
# bare-metal deployment (--host / --no-netns).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS_SRV="${NS_SRV:-srv}"
TARGET_IP="10.99.0.2"
TARGET_PORT=53
CORE_PIN=1
USE_HOST=false

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host|--no-netns) USE_HOST=true; NS_SRV=""; shift ;;
        --netns) NS_SRV="$2"; USE_HOST=false; shift 2 ;;
        --iface) shift 2 ;; # Optional interface descriptor for parity with testbed scripts
        --ip) TARGET_IP="$2"; shift 2 ;;
        --port) TARGET_PORT="$2"; shift 2 ;;
        --core) CORE_PIN="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--host] [--iface <dev>] [--netns <name>] [--ip <listen_ip>] [--port <port>] [--core <cpu>]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script requires root privileges: sudo $0"
    exit 1
fi

# Detect whether namespace exists or host mode is needed
if [[ "$USE_HOST" == false && -n "$NS_SRV" ]]; then
    if ! ip netns list 2>/dev/null | grep -qw "$NS_SRV"; then
        echo -e "${YELLOW}[WARN]${NC} Namespace '$NS_SRV' does not exist; defaulting to host mode."
        USE_HOST=true
        NS_SRV=""
    fi
fi

# 1. Stop any existing DNS server
if [[ "$USE_HOST" == true ]]; then
    "$SCRIPT_DIR/stop_dns.sh" --host >/dev/null 2>&1 || true
    EXEC_CMD=(taskset -c "$CORE_PIN")
    SS_CMD=(ss -unl)
    MODE_LABEL="host network stack"
else
    "$SCRIPT_DIR/stop_dns.sh" --netns "$NS_SRV" >/dev/null 2>&1 || true
    EXEC_CMD=(ip netns exec "$NS_SRV" taskset -c "$CORE_PIN")
    SS_CMD=(ip netns exec "$NS_SRV" ss -unl)
    MODE_LABEL="namespace '$NS_SRV'"
fi

echo -e "${BLUE}[INFO]${NC} Starting Authoritative DNS Server on ${MODE_LABEL} (${TARGET_IP}:${TARGET_PORT}, Core: ${CORE_PIN})..."

# 2. Check for official NSD daemon
if command -v nsd >/dev/null 2>&1; then
    echo -e "${GREEN}[INFO]${NC} Found NSD daemon. Preparing runtime environment..."
    mkdir -p /tmp/kavach_nsd/zones
    cp "$SCRIPT_DIR/nsd.conf" /tmp/kavach_nsd/nsd.conf
    cp "$SCRIPT_DIR/zones/lab.test.zone" /tmp/kavach_nsd/zones/lab.test.zone

    # Launch NSD pinned to Core in background
    "${EXEC_CMD[@]}" nsd -c /tmp/kavach_nsd/nsd.conf -d >/tmp/kavach_nsd/nsd.stdout 2>&1 &
    DNS_PID=$!
    echo "$DNS_PID" > /tmp/kavach_dns.pid
    echo -e "${GREEN}[SUCCESS]${NC} NSD launched (PID: $DNS_PID, CPU Core: $CORE_PIN, RRL: OFF)"
else
    echo -e "${YELLOW}[INFO]${NC} 'nsd' binary not found on host."
    echo -e "${BLUE}[INFO]${NC} Starting built-in authoritative Python DNS server as lightweight fallback..."

    "${EXEC_CMD[@]}" python3 "$SCRIPT_DIR/mock_dns.py" \
        --ip "$TARGET_IP" --port "$TARGET_PORT" --ans-ip "$TARGET_IP" >/tmp/kavach_mock_dns.log 2>&1 &
    DNS_PID=$!
    echo "$DNS_PID" > /tmp/kavach_dns.pid
    echo -e "${GREEN}[SUCCESS]${NC} Fallback DNS server launched (PID: $DNS_PID, CPU Core: $CORE_PIN, RRL: OFF)"
fi

# 3. Wait for server to listen
sleep 0.5
echo -e "${BLUE}[INFO]${NC} Verifying DNS server status..."
if "${SS_CMD[@]}" | grep -q ":$TARGET_PORT"; then
    echo -e "${GREEN}[SUCCESS]${NC} DNS Server is active and listening on ${TARGET_IP}:${TARGET_PORT}!"
else
    echo -e "${YELLOW}[WARN]${NC} Waiting for port $TARGET_PORT to appear..."
    sleep 1.0
    if "${SS_CMD[@]}" | grep -q ":$TARGET_PORT"; then
        echo -e "${GREEN}[SUCCESS]${NC} DNS Server is active and listening on ${TARGET_IP}:${TARGET_PORT}!"
    else
        echo -e "${RED}[ERROR]${NC} DNS Server failed to bind to ${TARGET_IP}:${TARGET_PORT}."
        cat /tmp/kavach_mock_dns.log 2>/dev/null || cat /tmp/kavach_nsd/nsd.stdout 2>/dev/null || true
        exit 1
    fi
fi
