#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Generator Host Ceiling Benchmark
# Submission ID: A3-PS022-TC367
#
# Measures the generator's own transmission ceiling in packets/sec to verify
# that the traffic generation host is not a bottleneck during benchmark runs.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETNS="${NETNS:-gen}"
TARGET_IP="10.99.0.2"
DURATION="${1:-5.0}"

BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Raw socket generation requires root privileges: sudo $0"
    exit 1
fi

echo -e "${BLUE}[INFO]${NC} Running Generator Ceiling Test (${DURATION}s)..."

# Ensure binary exists
make -C "$SCRIPT_DIR" >/dev/null

if ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    echo -e "${BLUE}[INFO]${NC} Executing inside namespace '$NETNS'..."
    ip netns exec "$NETNS" "$SCRIPT_DIR/kavach_gen" ceiling --target "$TARGET_IP" --duration "$DURATION"
else
    echo -e "${BLUE}[INFO]${NC} Executing on host..."
    "$SCRIPT_DIR/kavach_gen" ceiling --target "$TARGET_IP" --duration "$DURATION"
fi

echo -e "${GREEN}[SUCCESS]${NC} Generator ceiling test completed."

