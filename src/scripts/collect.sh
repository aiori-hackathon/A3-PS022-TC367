#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Metric Collection Wrapper Script (v0)
#
# Runs telemetry metric collection across CPU, interface statistics,
# kernel socket drops, softnet drops, and XDP map counters.
#
# Usage:
#   sudo ./collect.sh [--duration 60] [--output-dir results/raw/S1_B0_1x_1] [--netns srv] [--iface vsrv]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DURATION="${DURATION:-60}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/kavach_metrics}"
NETNS="${NETNS:-srv}"
IFACE="${IFACE:-vsrv}"
CORE="${CORE:-1}"
INTERVAL="${INTERVAL:-1.0}"

# Parse optional command-line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--duration) DURATION="$2"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        -n|--netns) NETNS="$2"; shift 2 ;;
        -i|--iface) IFACE="$2"; shift 2 ;;
        -c|--core) CORE="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

# Launch parallel mpstat if available
MPSTAT_PID=""
if command -v mpstat >/dev/null 2>&1; then
    echo "[INFO] Recording detailed per-core mpstat..."
    mpstat -P ALL -u 1 "$DURATION" > "$OUTPUT_DIR/mpstat_raw.txt" 2>&1 &
    MPSTAT_PID=$!
fi

# Run core telemetry collector
if [[ -n "$NETNS" ]] && ip netns list 2>/dev/null | grep -qw "$NETNS"; then
    echo "[INFO] Running collector in namespace '$NETNS' on interface '$IFACE'..."
    sudo ip netns exec "$NETNS" python3 "$SCRIPT_DIR/collect_metrics.py" \
        --duration "$DURATION" \
        --output-dir "$OUTPUT_DIR" \
        --iface "$IFACE" \
        --core "$CORE" \
        --interval "$INTERVAL"
else
    echo "[INFO] Running collector on host root namespace on interface '$IFACE'..."
    python3 "$SCRIPT_DIR/collect_metrics.py" \
        --duration "$DURATION" \
        --output-dir "$OUTPUT_DIR" \
        --iface "$IFACE" \
        --core "$CORE" \
        --interval "$INTERVAL"
fi

# Wait for parallel mpstat to finish if running
if [[ -n "$MPSTAT_PID" ]]; then
    wait "$MPSTAT_PID" 2>/dev/null || true
fi

echo "[SUCCESS] Metric collection completed. Results stored in: $OUTPUT_DIR"

