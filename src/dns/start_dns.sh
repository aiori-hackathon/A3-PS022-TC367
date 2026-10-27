#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: DNS Server Startup Script
#
# Launches the Authoritative DNS server inside the 'srv' network namespace,
# pinned to CPU Core 1 with Response Rate Limiting (RRL) explicitly disabled.
#
# Prefers official NSD daemon if installed; falls back to pure-Python mock DNS.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS_SRV="${NS_SRV:-srv}"
TARGET_IP="10.99.0.2"
TARGET_PORT=53
CORE_PIN=1

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script requires root privileges to manage namespace services."
    echo "Please run: sudo $0"
    exit 1
fi

# 1. Verify that 'srv' namespace exists
if ! ip netns list | grep -qw "$NS_SRV"; then
    echo -e "${RED}[ERROR]${NC} Namespace '$NS_SRV' does not exist."
    echo -e "${YELLOW}Please initialize the testbed first: sudo ./src/scripts/setup_env.sh${NC}"
    exit 1
fi

# 2. Stop any existing DNS server inside 'srv'
"$SCRIPT_DIR/stop_dns.sh" >/dev/null 2>&1 || true

echo -e "${BLUE}[INFO]${NC} Starting Authoritative DNS Server in namespace '$NS_SRV' on ${TARGET_IP}:${TARGET_PORT}..."

# 3. Check for official NSD daemon
if command -v nsd >/dev/null 2>&1; then
    echo -e "${GREEN}[INFO]${NC} Found NSD daemon. Preparing runtime environment..."
    mkdir -p /tmp/kavach_nsd/zones
    cp "$SCRIPT_DIR/nsd.conf" /tmp/kavach_nsd/nsd.conf
    cp "$SCRIPT_DIR/zones/lab.test.zone" /tmp/kavach_nsd/zones/lab.test.zone

    # Launch NSD pinned to Core 1 in background
    ip netns exec "$NS_SRV" taskset -c "$CORE_PIN" nsd -c /tmp/kavach_nsd/nsd.conf -d >/tmp/kavach_nsd/nsd.stdout 2>&1 &
    DNS_PID=$!
    echo "$DNS_PID" > /tmp/kavach_dns.pid
    echo -e "${GREEN}[SUCCESS]${NC} NSD launched (PID: $DNS_PID, CPU Core: $CORE_PIN, RRL: OFF)"
else
    echo -e "${YELLOW}[INFO]${NC} 'nsd' binary not found on host."
    echo -e "${BLUE}[INFO]${NC} Starting built-in authoritative Python DNS server as lightweight fallback..."
    echo -e "${YELLOW}[NOTE]${NC} On Arch: 'sudo pacman -S nsd' | On Ubuntu: 'sudo apt install nsd'"

    ip netns exec "$NS_SRV" taskset -c "$CORE_PIN" python3 "$SCRIPT_DIR/mock_dns.py" \
        --ip "$TARGET_IP" --port "$TARGET_PORT" --ans-ip "$TARGET_IP" >/tmp/kavach_mock_dns.log 2>&1 &
    DNS_PID=$!
    echo "$DNS_PID" > /tmp/kavach_dns.pid
    echo -e "${GREEN}[SUCCESS]${NC} Fallback DNS server launched (PID: $DNS_PID, CPU Core: $CORE_PIN, RRL: OFF)"
fi

# 4. Wait for server to listen
sleep 0.5
echo -e "${BLUE}[INFO]${NC} Verifying DNS server status..."
if ip netns exec "$NS_SRV" ss -unl | grep -q ":$TARGET_PORT"; then
    echo -e "${GREEN}[SUCCESS]${NC} DNS Server is active and listening on ${TARGET_IP}:${TARGET_PORT}!"
else
    echo -e "${YELLOW}[WARN]${NC} Waiting for port $TARGET_PORT to appear..."
    sleep 1.0
    if ip netns exec "$NS_SRV" ss -unl | grep -q ":$TARGET_PORT"; then
        echo -e "${GREEN}[SUCCESS]${NC} DNS Server is active and listening on ${TARGET_IP}:${TARGET_PORT}!"
    else
        echo -e "${RED}[ERROR]${NC} DNS Server failed to bind to ${TARGET_IP}:${TARGET_PORT}."
        cat /tmp/kavach_mock_dns.log 2>/dev/null || cat /tmp/kavach_nsd/nsd.stdout 2>/dev/null || true
        exit 1
    fi
fi

