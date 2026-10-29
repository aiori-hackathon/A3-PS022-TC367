#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Smoke Test Runner Wrapper (PC 2)
# Submission ID: A3-PS022-TC367
#
# Runs one smoke test per configuration (B0, B1, B2, X) under Scenario S1.
# Automatically connects to target_daemon on PC 1 if running, or prompts
# the user for manual twin-console synchronization.
#
# Usage:
#   sudo ./run_smoke.sh [--target 10.99.0.2] [--configs B0,B1,B2,X]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_IP="10.99.0.2"
CONFIGS="B0,B1,B2,X"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_IP="$2"; shift 2 ;;
        --configs) CONFIGS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges: sudo $0"
    exit 1
fi

python3 "$SCRIPT_DIR/smoke_runner.py" --target "$TARGET_IP" --configs "$CONFIGS"

