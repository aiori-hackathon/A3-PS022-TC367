#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: DNS Server Stop Script
#
# Terminates the running DNS server (NSD or Python fallback) inside the
# specified namespace or on the physical host.
# ==============================================================================

set -euo pipefail

NS_SRV="${NS_SRV:-srv}"
USE_HOST=false

BLUE='\033[1;34m'
GREEN='\033[1;32m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host|--no-netns) USE_HOST=true; NS_SRV=""; shift ;;
        --netns) NS_SRV="$2"; USE_HOST=false; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--host] [--netns <name>]"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ "$USE_HOST" == true || -z "$NS_SRV" ]]; then
    echo -e "${BLUE}[INFO]${NC} Stopping DNS Server on host..."
else
    echo -e "${BLUE}[INFO]${NC} Stopping DNS Server in namespace '$NS_SRV'..."
fi

# Terminate recorded PID if file exists
if [[ -f /tmp/kavach_dns.pid ]]; then
    PID=$(cat /tmp/kavach_dns.pid 2>/dev/null || true)
    if [[ -n "$PID" ]]; then
        kill "$PID" 2>/dev/null || true
    fi
    rm -f /tmp/kavach_dns.pid
fi

# Terminate processes
if [[ "$USE_HOST" == false && -n "$NS_SRV" ]] && ip netns list 2>/dev/null | grep -qw "$NS_SRV"; then
    pids=$(ip netns pids "$NS_SRV" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        for pid in $pids; do
            comm=$(ps -p "$pid" -o comm= 2>/dev/null || true)
            if [[ "$comm" =~ nsd|python3 ]]; then
                kill "$pid" 2>/dev/null || true
            fi
        done
    fi
else
    # Host mode
    pkill -f 'mock_dns.py.*10.99.0.2' 2>/dev/null || true
    killall nsd 2>/dev/null || true
fi

# Clean up NSD runtime directory
rm -rf /tmp/kavach_nsd /tmp/kavach_mock_dns.log

echo -e "${GREEN}[SUCCESS]${NC} DNS Server stopped."
