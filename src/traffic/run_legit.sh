#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Run Legitimate Client Wrapper
#
# Runs the legitimate client from inside the 'gen' namespace against 10.99.0.2:53.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS_GEN="${NS_GEN:-gen}"
TARGET_IP="10.99.0.2"
TARGET_PORT=53
SRC_IP="10.99.0.1"
QPS="${QPS:-100}"
DURATION="${DURATION:-10}"
OUTPUT="${OUTPUT:-/tmp/kavach_legit_sample.csv}"

# 1. Enforce Generator Safety Guard
source "$SCRIPT_DIR/guard.sh"
guard_enforce_all "$TARGET_IP" "$SRC_IP"

echo "[INFO] Running Legitimate Client inside namespace '$NS_GEN'..."
sudo ip netns exec "$NS_GEN" python3 "$SCRIPT_DIR/legit_client.py" \
    --server "$TARGET_IP" \
    --port "$TARGET_PORT" \
    --source-ip "$SRC_IP" \
    --qps "$QPS" \
    --duration "$DURATION" \
    --output "$OUTPUT"

