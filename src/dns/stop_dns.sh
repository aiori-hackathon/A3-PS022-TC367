#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: DNS Server Stop Script
#
# Terminates the running DNS server (NSD or Python fallback) inside 'srv'.
# ==============================================================================

set -euo pipefail

NS_SRV="${NS_SRV:-srv}"
BLUE='\033[1;34m'
GREEN='\033[1;32m'
NC='\033[0m'

echo -e "${BLUE}[INFO]${NC} Stopping DNS Server in namespace '$NS_SRV'..."

# Terminate recorded PID if file exists
if [[ -f /tmp/kavach_dns.pid ]]; then
    PID=$(cat /tmp/kavach_dns.pid 2>/dev/null || true)
    if [[ -n "$PID" ]]; then
        kill "$PID" 2>/dev/null || true
    fi
    rm -f /tmp/kavach_dns.pid
fi

# Terminate any NSD or mock_dns processes in srv namespace
if ip netns list 2>/dev/null | grep -qw "$NS_SRV"; then
    pids=$(ip netns pids "$NS_SRV" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        for pid in $pids; do
            comm=$(ps -p "$pid" -o comm= 2>/dev/null || true)
            if [[ "$comm" =~ nsd|python3 ]]; then
                kill "$pid" 2>/dev/null || true
            fi
        done
    fi
fi

# Clean up NSD runtime directory
rm -rf /tmp/kavach_nsd /tmp/kavach_mock_dns.log

echo -e "${GREEN}[SUCCESS]${NC} DNS Server stopped."

