#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: DNS Server Test Script
#
# Issues test queries from the 'gen' namespace to 'srv' (10.99.0.2:53)
# and checks that valid RFC 1035 responses are returned.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS_GEN="${NS_GEN:-gen}"
TARGET_IP="10.99.0.2"
TARGET_PORT=53
DOMAIN="www.lab.test"

BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

echo -e "${BLUE}=== Testing DNS Resolution from '$NS_GEN' -> ${TARGET_IP}:${TARGET_PORT} ===${NC}"

# 1. Enforce generator guard check before query
source "$SCRIPT_DIR/../traffic/guard.sh"
guard_enforce_all "$TARGET_IP" "10.99.0.1"

# 2. Check if 'dig' is available, otherwise use query_test.py
if command -v dig >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${NC} Querying using 'dig'..."
    RESP=$(sudo ip netns exec "$NS_GEN" dig @"$TARGET_IP" "$DOMAIN" +short)
    if [[ "$RESP" == "10.99.0.2" ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} dig resolved $DOMAIN -> $RESP"
    else
        echo -e "${RED}[ERROR]${NC} Unexpected dig response: '$RESP' (expected 10.99.0.2)"
        exit 1
    fi
else
    echo -e "${BLUE}[INFO]${NC} 'dig' not found; querying using built-in query_test.py..."
    sudo ip netns exec "$NS_GEN" python3 "$SCRIPT_DIR/query_test.py" \
        --server "$TARGET_IP" --domain "$DOMAIN" --port "$TARGET_PORT"
fi

echo -e "${GREEN}=== DNS Resolution Verified Successfully ===${NC}"

