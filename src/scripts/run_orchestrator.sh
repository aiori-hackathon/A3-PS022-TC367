#!/usr/bin/env bash
# ==============================================================================
# Kavach PS-022: Benchmark Matrix Orchestrator Runner Wrapper
# Submission ID: A3-PS022-TC367
#
# Usage:
#   sudo ./run_orchestrator.sh [--dry-run] [--seed 42]
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PARAMS_FILE="$REPO_ROOT/src/params.yaml"

if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m Benchmark orchestration requires root privileges: sudo $0"
    exit 1
fi

python3 "$SCRIPT_DIR/orchestrator.py" --params "$PARAMS_FILE" "$@"

